// Package leanelf reads the parts of an ELF64 image that a loader needs:
// program headers, bytes at load addresses, and selected symbols by name.
//
// It replaces debug/elf, whose DWARF and compressed-section support pulled
// debug/dwarf, compress/zlib, and internal/zstd into the HopOS kernel. On
// cmd/hopos arm64 with -w -trimpath (2026-08-12), the image shrank from
// 6,302,520 to 6,136,123 bytes with identical placement.
//
// Unsupported features fail loudly: ELF32, big-endian files, relocations,
// named-section lookup, DWARF, and complete symbol dumps. [File.Lookup] avoids
// allocating tens of thousands of names when a loader needs only a few.
// Untrusted header values are bounded and overflow-checked against file size.
package leanelf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Fixed ELF64 ABI sizes. Files repeat these in e_phentsize and e_shentsize;
// conflicting values describe an unsupported format.
const (
	ehdrSize = 64 // Elf64_Ehdr
	phdrSize = 56 // Elf64_Phdr
	shdrSize = 64 // Elf64_Shdr
	symSize  = 24 // Elf64_Sym
)

// Segment types. Only PTLoad has loader semantics here; other values remain raw
// in [Segment.Type] so callers can decide without a name table.
const (
	PTNull = 0
	PTLoad = 1
)

// Machine values used by supported environments, allowing early architecture
// checks before a loader moves segments.
const (
	MachineX86_64  = 62
	MachineAArch64 = 183
	MachineRISCV   = 243
)

// Bounds for untrusted files. They exceed ordinary Go binaries while preventing
// fabricated headers from becoming unbounded allocations.
const (
	maxPhnum = 1024
	maxShnum = 4096
	maxTable = 64 << 20 // each of symtab and strtab
)

// ErrNotELF reports a missing ELF magic. It remains distinct so multi-format
// callers can separate non-ELF data from unsupported or malformed ELF data.
var ErrNotELF = errors.New("leanelf: not an ELF file")

// Segment is one program header.
type Segment struct {
	Type   uint32
	Flags  uint32
	Off    uint64 // file offset
	Vaddr  uint64 // virtual address
	Paddr  uint64 // load address
	Filesz uint64 // bytes in the file
	Memsz  uint64 // bytes in memory; the difference is BSS
	Align  uint64
}

// Symbol is one .symtab entry: its name and location.
type Symbol struct {
	Name  string
	Value uint64
	Size  uint64
	Info  byte
	Shndx uint16
}

// File is a parsed ELF64. [Open] reads program headers; symbols are lazy.
type File struct {
	Machine  uint16 // e_machine; see MachineAArch64 and related constants
	Type     uint16 // e_type (2 = ET_EXEC, 3 = ET_DYN)
	Entry    uint64
	Segments []Segment

	r    io.ReaderAt
	size int64 // -1 when the caller supplied no size

	shoff     uint64
	shnum     uint16
	shentsize uint16
}

// Open reads the ELF header and program headers. size is the image size in
// bytes, or -1 when unknown. A known size lets Open reject out-of-file headers
// directly instead of surfacing an unrelated I/O error later.
func Open(r io.ReaderAt, size int64) (*File, error) {
	// Read magic separately so a four-byte non-ELF blob returns ErrNotELF rather
	// than an error about the missing remainder of the header.
	var h [ehdrSize]byte
	if err := readFull(r, h[:4], 0); err != nil {
		return nil, fmt.Errorf("leanelf: read magic: %w", err)
	}
	if h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' {
		return nil, ErrNotELF
	}
	if err := readFull(r, h[4:], 4); err != nil {
		return nil, fmt.Errorf("leanelf: read header: %w", err)
	}
	switch h[4] { // EI_CLASS
	case 2:
	case 1:
		return nil, errors.New("leanelf: 32-bit ELF (ELFCLASS32); only ELFCLASS64 is supported")
	default:
		return nil, fmt.Errorf("leanelf: unknown ELF class %d", h[4])
	}
	if h[5] != 1 { // EI_DATA
		return nil, errors.New("leanelf: big-endian ELF; only little-endian is supported")
	}
	if h[6] != 1 { // EI_VERSION
		return nil, fmt.Errorf("leanelf: unknown ELF version %d", h[6])
	}

	f := &File{
		Type:      binary.LittleEndian.Uint16(h[16:]),
		Machine:   binary.LittleEndian.Uint16(h[18:]),
		Entry:     binary.LittleEndian.Uint64(h[24:]),
		r:         r,
		size:      size,
		shoff:     binary.LittleEndian.Uint64(h[40:]),
		shentsize: binary.LittleEndian.Uint16(h[58:]),
		shnum:     binary.LittleEndian.Uint16(h[60:]),
	}

	phoff := binary.LittleEndian.Uint64(h[32:])
	phentsize := binary.LittleEndian.Uint16(h[54:])
	phnum := binary.LittleEndian.Uint16(h[56:])
	switch {
	case phnum == 0:
		return f, nil // no program headers: no segments, otherwise valid
	case phnum == 0xffff:
		return nil, errors.New("leanelf: extended program header count (PN_XNUM) is not supported")
	case phnum > maxPhnum:
		return nil, fmt.Errorf("leanelf: %d program headers exceeds the %d we are willing to read", phnum, maxPhnum)
	case phentsize != phdrSize:
		return nil, fmt.Errorf("leanelf: program header size %d, expected %d", phentsize, phdrSize)
	}

	tab := make([]byte, uint64(phnum)*phdrSize)
	if err := f.readAtOff(tab, phoff); err != nil {
		return nil, fmt.Errorf("leanelf: read program headers: %w", err)
	}
	f.Segments = make([]Segment, phnum)
	for i := range f.Segments {
		e := tab[i*phdrSize:]
		f.Segments[i] = Segment{
			Type:   binary.LittleEndian.Uint32(e[0:]),
			Flags:  binary.LittleEndian.Uint32(e[4:]),
			Off:    binary.LittleEndian.Uint64(e[8:]),
			Vaddr:  binary.LittleEndian.Uint64(e[16:]),
			Paddr:  binary.LittleEndian.Uint64(e[24:]),
			Filesz: binary.LittleEndian.Uint64(e[32:]),
			Memsz:  binary.LittleEndian.Uint64(e[40:]),
			Align:  binary.LittleEndian.Uint64(e[48:]),
		}
	}
	return f, nil
}

// ReadAtPaddr reads len(p) bytes at load address pa, locating them through the
// containing segment. It intentionally uses physical rather than virtual load
// addresses. Reads outside PT_LOAD file data, including its BSS tail, fail.
func (f *File) ReadAtPaddr(p []byte, pa uint64) error {
	n := uint64(len(p))
	for _, s := range f.Segments {
		if s.Type != PTLoad || pa < s.Paddr || n > s.Filesz || pa-s.Paddr > s.Filesz-n {
			continue
		}
		return f.readAtOff(p, s.Off+(pa-s.Paddr))
	}
	return fmt.Errorf("leanelf: address %#x+%d is not inside any loaded segment", pa, n)
}

// Lookup returns requested symbols found in .symtab; absent names are omitted
// because loaders may request both required and optional symbols. The first
// definition wins and SHN_UNDEF entries are skipped. A missing .symtab is an
// error, typically indicating an image linked with -s.
func (f *File) Lookup(names ...string) (map[string]Symbol, error) {
	if len(names) == 0 {
		return map[string]Symbol{}, nil
	}
	symtab, strtab, err := f.symtab()
	if err != nil {
		return nil, err
	}

	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := make(map[string]Symbol, len(names))

	// Entry zero is the all-zero ABI sentinel.
	for off := symSize; off+symSize <= len(symtab); off += symSize {
		e := symtab[off:]
		shndx := binary.LittleEndian.Uint16(e[6:])
		if shndx == 0 {
			continue
		}
		nameOff := binary.LittleEndian.Uint32(e[0:])
		raw, ok := cstr(strtab, nameOff)
		if !ok || len(raw) == 0 {
			continue
		}
		// The compiler avoids allocating string(raw) for this map lookup.
		if !want[string(raw)] {
			continue
		}
		name := string(raw)
		if _, seen := out[name]; seen {
			continue
		}
		out[name] = Symbol{
			Name:  name,
			Value: binary.LittleEndian.Uint64(e[8:]),
			Size:  binary.LittleEndian.Uint64(e[16:]),
			Info:  e[4],
			Shndx: shndx,
		}
		if len(out) == len(want) {
			break
		}
	}
	return out, nil
}

// symtab reads .symtab and its linked string table together; either is useless
// without the other.
func (f *File) symtab() (symtab, strtab []byte, err error) {
	const (
		shtSymtab = 2
		shtStrtab = 3
	)
	switch {
	case f.shnum == 0 || f.shoff == 0:
		return nil, nil, errors.New("leanelf: no section headers, so no symbol table (linked with -s?)")
	case f.shnum > maxShnum:
		return nil, nil, fmt.Errorf("leanelf: %d section headers exceeds the %d we are willing to read", f.shnum, maxShnum)
	case f.shentsize != shdrSize:
		return nil, nil, fmt.Errorf("leanelf: section header size %d, expected %d", f.shentsize, shdrSize)
	}

	tab := make([]byte, uint64(f.shnum)*shdrSize)
	if err := f.readAtOff(tab, f.shoff); err != nil {
		return nil, nil, fmt.Errorf("leanelf: read section headers: %w", err)
	}
	for i := range int(f.shnum) {
		e := tab[i*shdrSize:]
		if binary.LittleEndian.Uint32(e[4:]) != shtSymtab {
			continue
		}
		if es := binary.LittleEndian.Uint64(e[56:]); es != symSize {
			return nil, nil, fmt.Errorf("leanelf: symbol size %d, expected %d", es, symSize)
		}
		link := binary.LittleEndian.Uint32(e[40:])
		if uint64(link) >= uint64(f.shnum) {
			return nil, nil, fmt.Errorf("leanelf: symbol table links to section %d of %d", link, f.shnum)
		}
		str := tab[int(link)*shdrSize:]
		if binary.LittleEndian.Uint32(str[4:]) != shtStrtab {
			return nil, nil, errors.New("leanelf: symbol table does not link to a string table")
		}
		if symtab, err = f.section(e); err != nil {
			return nil, nil, fmt.Errorf("leanelf: read symbol table: %w", err)
		}
		if strtab, err = f.section(str); err != nil {
			return nil, nil, fmt.Errorf("leanelf: read symbol string table: %w", err)
		}
		return symtab, strtab, nil
	}
	return nil, nil, errors.New("leanelf: no symbol table (linked with -s?)")
}

// section reads one section's contents. SHT_NOBITS has no file data and is
// therefore malformed for either table read by this package.
func (f *File) section(shdr []byte) ([]byte, error) {
	const shtNobits = 8
	if binary.LittleEndian.Uint32(shdr[4:]) == shtNobits {
		return nil, errors.New("section has no contents in the file (SHT_NOBITS)")
	}
	off := binary.LittleEndian.Uint64(shdr[24:])
	size := binary.LittleEndian.Uint64(shdr[32:])
	if size > maxTable {
		return nil, fmt.Errorf("section is %d bytes, over the %d-byte cap", size, maxTable)
	}
	b := make([]byte, size)
	if err := f.readAtOff(b, off); err != nil {
		return nil, err
	}
	return b, nil
}

// readAtOff reads len(p) bytes at off, enforcing a known file size and checking
// off+len without overflow.
func (f *File) readAtOff(p []byte, off uint64) error {
	n := uint64(len(p))
	if off > 1<<63 || n > 1<<63-off {
		return fmt.Errorf("offset %#x+%d overflows", off, n)
	}
	if f.size >= 0 && off+n > uint64(f.size) {
		return fmt.Errorf("offset %#x+%d is past the end of the %d-byte image", off, n, f.size)
	}
	return readFull(f.r, p, int64(off))
}

// readFull fills p; a short read is io.ErrUnexpectedEOF.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if err == io.EOF && n == len(p) {
		return nil
	}
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// cstr returns the NUL-terminated string at off. Missing termination makes the
// table malformed and returns (nil, false).
func cstr(tab []byte, off uint32) ([]byte, bool) {
	if uint64(off) >= uint64(len(tab)) {
		return nil, false
	}
	s := tab[off:]
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i], true
		}
	}
	return nil, false
}
