package leantls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimal helpers for TLS length-prefixed wire data: a builder that backfills
// lengths and a reader that returns errors instead of crossing its buffer.
// Keeping these forty lines avoids a non-standard cryptobyte dependency.

// builder creates a byte stream with backfilled length prefixes.
type builder struct {
	buf []byte
}

func (b *builder) u8(v byte)      { b.buf = append(b.buf, v) }
func (b *builder) u16(v uint16)   { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *builder) bytes(p []byte) { b.buf = append(b.buf, p...) }

// u8len, u16len, and u24len reserve a prefix, let f append content, then backfill
// its actual length to avoid error-prone manual size calculations.
func (b *builder) u8len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0)
	f()
	n := len(b.buf) - at - 1
	if n > 0xff {
		panic("leantls: u8-length block overflow")
	}
	b.buf[at] = byte(n)
}

func (b *builder) u16len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0, 0)
	f()
	n := len(b.buf) - at - 2
	if n > 0xffff {
		panic("leantls: u16-length block overflow")
	}
	binary.BigEndian.PutUint16(b.buf[at:], uint16(n))
}

func (b *builder) u24len(f func()) {
	at := len(b.buf)
	b.buf = append(b.buf, 0, 0, 0)
	f()
	n := len(b.buf) - at - 3
	if n > 0xffffff {
		panic("leantls: u24-length block overflow")
	}
	b.buf[at] = byte(n >> 16)
	b.buf[at+1] = byte(n >> 8)
	b.buf[at+2] = byte(n)
}

// errShort is the sentinel for every truncated read.
var errShort = errors.New("leantls: truncated message")

// reader consumes length-prefixed fields without crossing its buffer.
type reader struct {
	buf []byte
}

func (r *reader) len() int    { return len(r.buf) }
func (r *reader) empty() bool { return len(r.buf) == 0 }

func (r *reader) u8() (byte, error) {
	if len(r.buf) < 1 {
		return 0, errShort
	}
	v := r.buf[0]
	r.buf = r.buf[1:]
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if len(r.buf) < 2 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint16(r.buf)
	r.buf = r.buf[2:]
	return v, nil
}

func (r *reader) u24() (uint32, error) {
	if len(r.buf) < 3 {
		return 0, errShort
	}
	v := uint32(r.buf[0])<<16 | uint32(r.buf[1])<<8 | uint32(r.buf[2])
	r.buf = r.buf[3:]
	return v, nil
}

// take returns n bytes backed by the reader buffer; callers consume or copy them
// immediately.
func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || len(r.buf) < n {
		return nil, errShort
	}
	v := r.buf[:n]
	r.buf = r.buf[n:]
	return v, nil
}

// vec8, vec16, and vec24 return a length-prefixed block as its own reader.
func (r *reader) vec8() (reader, error) {
	n, err := r.u8()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

func (r *reader) vec16() (reader, error) {
	n, err := r.u16()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

func (r *reader) vec24() (reader, error) {
	n, err := r.u24()
	if err != nil {
		return reader{}, err
	}
	p, err := r.take(int(n))
	return reader{buf: p}, err
}

// eachExtension visits every extension type and body. Callers may ignore unknown
// extensions because TLS explicitly permits them.
func eachExtension(r reader, f func(typ uint16, body reader) error) error {
	for !r.empty() {
		typ, err := r.u16()
		if err != nil {
			return err
		}
		body, err := r.vec16()
		if err != nil {
			return fmt.Errorf("leantls: extension %d: %w", typ, err)
		}
		if err := f(typ, body); err != nil {
			return err
		}
	}
	return nil
}
