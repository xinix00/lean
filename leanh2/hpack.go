package leanh2

// hpack.go is HPACK (RFC 7541) in the shape one role needs. It lives in this
// package and not next to it: HPACK exists only for HTTP/2, and a building
// block that needs another building block is no longer a building block.
//
// Decoding must be complete, because what the peer sends is not ours to choose:
// the static table, all four literal forms, Huffman literals, and the dynamic
// table with its size updates.
//
// Encoding may be minimal. An exact static-table match uses its index; every
// other response field goes out as "literal without indexing" (§6.2.2). That
// removes the encoder half of the Huffman alphabet and a second dynamic table,
// and costs a few dozen bytes per response.

import (
	"errors"
	"fmt"
)

// field is one header field. Names are lowercase on the wire (RFC 9113 §8.2.1).
type field struct {
	name, value string
}

// staticTable is Appendix A of RFC 7541. Index 1 is the first field: index zero
// does not exist, so it holds an empty placeholder.
var staticTable = []field{
	{},
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

// decoder holds the peer's dynamic table. It belongs to the connection, not to
// one block: the table lives across header blocks.
//
// The table exists even though this side announces a table size of zero. The
// announcement only takes effect once the peer has seen it, and a peer that
// indexed before that must still be decodable — refusing there would be
// refusing correct HPACK.
type decoder struct {
	dyn  []field // newest first, matching the index order
	size int     // sum of the entry sizes (§4.1)
	// capacity is the table size in force; allowed is the ceiling this side
	// announced. Keeping them apart matters: a peer may shrink and grow within
	// the ceiling, and conflating the two would let one update raise it.
	capacity int
	allowed  int
	// limit bounds one decoded header list. Without a ceiling a peer can grow
	// this side's memory with a single frame, which on a 32 MB node is fatal.
	limit int
	// atBlockStart is true until the first field of a block is decoded: a table
	// size update may only appear there (RFC 7541 §4.2).
	atBlockStart bool
}

func newDecoder(allowed, listLimit int) *decoder {
	return &decoder{capacity: allowed, allowed: allowed, limit: listLimit}
}

// setAllowed applies our acknowledged SETTINGS_HEADER_TABLE_SIZE. Frames are
// ordered, so after the acknowledgement no later header block can legitimately
// depend on the old capacity.
func (d *decoder) setAllowed(n int) {
	d.allowed = n
	if d.capacity > n {
		d.capacity = n
		d.evict()
	}
}

var (
	// errTruncated means the block ended mid-instruction. CONTINUATION frames
	// are joined before decoding, so this is a protocol error by the peer.
	errTruncated = errors.New("leanh2: header block ended mid-instruction")
	// errEOS covers EOS inside a literal (§5.2), padding longer than seven bits,
	// and padding that is not a prefix of EOS.
	errEOS = errors.New("leanh2: EOS in huffman literal")
)

// decode reads one complete header block.
func (d *decoder) decode(block []byte) ([]field, error) {
	var out []field
	total := 0
	p := block
	d.atBlockStart = true
	for len(p) > 0 {
		b := p[0]
		switch {
		case b&0x80 != 0: // 1xxxxxxx — indexed field (§6.1)
			idx, rest, err := readInt(p, 7)
			if err != nil {
				return nil, err
			}
			p = rest
			f, err := d.at(idx)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
			total += len(f.name) + len(f.value) + 32

		case b&0xc0 == 0x40: // 01xxxxxx — literal WITH indexing (§6.2.1)
			f, rest, err := d.literal(p, 6)
			if err != nil {
				return nil, err
			}
			p = rest
			d.add(f)
			out = append(out, f)
			total += len(f.name) + len(f.value) + 32

		case b&0xe0 == 0x20: // 001xxxxx — table size update (§6.3)
			if !d.atBlockStart {
				return nil, errors.New("leanh2: table size update after a field")
			}
			size, rest, err := readInt(p, 5)
			if err != nil {
				return nil, err
			}
			p = rest
			if size > d.allowed {
				return nil, fmt.Errorf("leanh2: table size %d above the announced %d", size, d.allowed)
			}
			d.capacity = size
			d.evict()
			continue // still at the start: several updates may follow each other

		default: // 0000xxxx / 0001xxxx — literal without, or never with, indexing
			f, rest, err := d.literal(p, 4)
			if err != nil {
				return nil, err
			}
			p = rest
			out = append(out, f)
			total += len(f.name) + len(f.value) + 32
		}
		d.atBlockStart = false
		if d.limit > 0 && total > d.limit {
			return nil, fmt.Errorf("leanh2: header list above the %d byte limit", d.limit)
		}
	}
	return out, nil
}

// at reads from the static or the dynamic table; the index runs through both.
func (d *decoder) at(idx int) (field, error) {
	if idx == 0 {
		return field{}, errors.New("leanh2: index 0 is not a field")
	}
	if idx < len(staticTable) {
		return staticTable[idx], nil
	}
	i := idx - len(staticTable)
	if i >= len(d.dyn) {
		return field{}, fmt.Errorf("leanh2: index %d beyond the table", idx)
	}
	return d.dyn[i], nil
}

// literal reads both literal forms: the name is either an index or a string.
func (d *decoder) literal(p []byte, prefix uint8) (field, []byte, error) {
	idx, rest, err := readInt(p, prefix)
	if err != nil {
		return field{}, nil, err
	}
	var f field
	if idx == 0 {
		f.name, rest, err = readString(rest)
		if err != nil {
			return field{}, nil, err
		}
	} else {
		known, err := d.at(idx)
		if err != nil {
			return field{}, nil, err
		}
		f.name = known.name
	}
	f.value, rest, err = readString(rest)
	if err != nil {
		return field{}, nil, err
	}
	return f, rest, nil
}

// add puts a field at the front and evicts until it fits. A field that does not
// fit on its own empties the table (§4.4) — which is exactly what a table size
// of zero does, so it is not a special case.
func (d *decoder) add(f field) {
	d.dyn = append([]field{f}, d.dyn...)
	d.size += len(f.name) + len(f.value) + 32
	d.evict()
}

func (d *decoder) evict() {
	for d.size > d.capacity && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.size -= len(last.name) + len(last.value) + 32
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
	if len(d.dyn) == 0 {
		d.size = 0
	}
}

// readInt reads an integer with an N-bit prefix (§5.1).
func readInt(p []byte, prefix uint8) (int, []byte, error) {
	if len(p) == 0 {
		return 0, nil, errTruncated
	}
	mask := int(1)<<prefix - 1
	v := int(p[0]) & mask
	p = p[1:]
	if v < mask {
		return v, p, nil
	}
	// Continuation octets, seven bits each. The bound keeps a hostile run away
	// from an overflow: header lists of megabytes do not exist.
	for shift := 0; shift <= 21; shift += 7 {
		if len(p) == 0 {
			return 0, nil, errTruncated
		}
		b := p[0]
		p = p[1:]
		v += int(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, p, nil
		}
	}
	return 0, nil, errors.New("leanh2: integer too long")
}

// readString reads a string literal; one bit says whether it is Huffman coded.
func readString(p []byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", nil, errTruncated
	}
	huff := p[0]&0x80 != 0
	n, rest, err := readInt(p, 7)
	if err != nil {
		return "", nil, err
	}
	if n > len(rest) {
		return "", nil, errTruncated
	}
	raw := rest[:n]
	rest = rest[n:]
	if !huff {
		return string(raw), rest, nil
	}
	s, err := huffmanDecode(raw)
	if err != nil {
		return "", nil, err
	}
	return s, rest, nil
}

// encodeFields uses an exact static-table index when one exists and otherwise
// writes "literal without indexing" (§6.2.2), without Huffman.
func encodeFields(dst []byte, fields []field) []byte {
	for _, f := range fields {
		if idx := staticIndexed(f); idx != 0 {
			dst = append(dst, byte(0x80|idx))
			continue
		}
		if idx := staticName(f.name); idx != 0 {
			dst = appendInt(dst, 0x00, 4, idx)
		} else {
			dst = append(dst, 0x00)
			dst = appendString(dst, f.name)
		}
		dst = appendString(dst, f.value)
	}
	return dst
}

func staticIndexed(f field) int {
	for i := 1; i < len(staticTable); i++ {
		if staticTable[i] == f {
			return i
		}
	}
	return 0
}

func staticName(name string) int {
	for i := 1; i < len(staticTable); i++ {
		if staticTable[i].name == name {
			return i
		}
	}
	return 0
}

func appendInt(dst []byte, flags byte, prefix uint8, v int) []byte {
	mask := 1<<prefix - 1
	if v < mask {
		return append(dst, flags|byte(v))
	}
	dst = append(dst, flags|byte(mask))
	v -= mask
	for v >= 0x80 {
		dst = append(dst, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendString(dst []byte, s string) []byte {
	dst = appendInt(dst, 0x00, 7, len(s))
	return append(dst, s...)
}
