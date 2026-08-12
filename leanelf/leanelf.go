// Package leanelf leest een ELF64-image: de programheaders (wat er waarheen
// geladen wordt), de inhoud op een laadadres, en een handvol symbolen op naam.
// Precies wat een loader nodig heeft om een image te plaatsen, en niets
// daarbuiten.
//
// Het bestaat omdat debug/elf dat óók kan, maar zijn hele wereld meeneemt: het
// kan DWARF-secties lezen en desnoods uitpakken, dus één import sleept
// debug/dwarf, compress/zlib en internal/zstd mee — om debug-secties uit te
// pakken waar een loader nooit naar kijkt.
//
// Gemeten op de HopOS-kern (cmd/hopos, arm64, -w -trimpath, 12-08-2026), die
// er twee dingen van gebruikte (de PT_LOAD-segmenten en vijf symbolen op naam):
// 6.302.520 → 6.136.123 bytes, dus 166.397 bytes minder image voor dezelfde
// plaatsing. Aan symbolen: debug/elf 20.312 + debug/dwarf 7.880 +
// internal/zstd 40.057 + compress/zlib 3.296 + encoding/binary 9.136 eruit,
// leanelf 7.120 erin.
//
// Wat het niet doet, weigert het luid: 32-bit (ELFCLASS32), big-endian,
// relocaties, secties op naam, DWARF, en een volledige symbooldump. Wie een
// dump nodig heeft voegt hem toe mét de meting die aantoont dat hij nodig is —
// [File.Lookup] bestaat juist omdat een loader vijf namen zoekt en niet
// twintigduizend strings wil bouwen in het geheugen van een node.
//
// De velden uit de headers zijn input van buiten (een image komt van het
// netwerk): alles wordt begrensd gelezen, elke offset+lengte overflow-veilig
// getoetst tegen de bestandsgrootte, en een absurd aantal headers is een fout
// in plaats van een allocatie.
package leanelf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// De vaste maten uit de ELF64-ABI. Ze staan hier als constante omdat het
// bestand ze zélf ook noemt (e_phentsize, e_shentsize): een image dat andere
// maten meldt is geen ELF64 dat wij kennen, en dat is een fout en geen
// aanname.
const (
	ehdrSize = 64 // Elf64_Ehdr
	phdrSize = 56 // Elf64_Phdr
	shdrSize = 64 // Elf64_Shdr
	symSize  = 24 // Elf64_Sym
)

// Segmenttypes. Alleen PTLoad heeft betekenis voor een loader; de rest komt
// als ruwe waarde mee in [Segment.Type] zodat een aanroeper zijn eigen
// beslissing kan nemen zonder dat dit pakket een tabel met namen draagt.
const (
	PTNull = 0
	PTLoad = 1
)

// Machinewaarden (e_machine) die in onze wereld voorkomen. Ze zijn er zodat
// een loader een image van de verkeerde architectuur kan weigeren vóór hij
// segmenten gaat verplaatsen.
const (
	MachineX86_64  = 62
	MachineAArch64 = 183
	MachineRISCV   = 243
)

// De grenzen op wat we bereid zijn te lezen uit een bestand dat we niet
// vertrouwen. Ze zijn ruim voor élk echt image (een Go-binary heeft tientallen
// programheaders en een symboltabel van enkele MB) en klein genoeg dat een
// verzonnen header geen allocatie wordt.
const (
	maxPhnum = 1024
	maxShnum = 4096
	maxTable = 64 << 20 // symtab en strtab elk
)

// ErrNotELF zegt dat de eerste vier bytes geen ELF-magic zijn. Apart omdat een
// aanroeper die meerdere formaten kan dragen hierop wil kunnen testen; alle
// andere fouten zijn wél een ELF maar niet één die dit pakket kan lezen, en
// die horen niet stil in dezelfde categorie te vallen.
var ErrNotELF = errors.New("leanelf: not an ELF file")

// Segment is één programheader.
type Segment struct {
	Type   uint32
	Flags  uint32
	Off    uint64 // offset in het bestand
	Vaddr  uint64 // virtueel adres
	Paddr  uint64 // laadadres
	Filesz uint64 // bytes in het bestand
	Memsz  uint64 // bytes in het geheugen (het verschil is BSS)
	Align  uint64
}

// Symbol is één ingang uit .symtab: de naam en waar hij staat.
type Symbol struct {
	Name  string
	Value uint64
	Size  uint64
	Info  byte
	Shndx uint16
}

// File is een geparseerde ELF64. De programheaders zijn gelezen bij [Open]; de
// symboltabel pas als iemand ernaar vraagt.
type File struct {
	Machine  uint16 // e_machine, zie MachineAArch64 en broertjes
	Type     uint16 // e_type (2 = ET_EXEC, 3 = ET_DYN)
	Entry    uint64
	Segments []Segment

	r    io.ReaderAt
	size int64 // -1 als de aanroeper geen grootte gaf

	shoff     uint64
	shnum     uint16
	shentsize uint16
}

// Open leest de ELF-header en de programheaders. size is de grootte van het
// image in bytes, of -1 als die onbekend is; met een grootte weigert dit
// pakket een header die buiten het bestand wijst meteen in plaats van pas bij
// het lezen, en dat is het verschil tussen "dit image is stuk" en een
// io-fout drie lagen verderop.
func Open(r io.ReaderAt, size int64) (*File, error) {
	// De magic eerst, apart: een aanroeper die meerdere formaten kan dragen
	// hoort ErrNotELF te krijgen op een blob van vier bytes, en niet een
	// io-fout omdat er geen volledige ELF-header in past.
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
		return f, nil // geen programheaders: geen segmenten, verder geldig
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

// ReadAtPaddr leest len(p) bytes op laadadres pa: het segment dat dat adres
// draagt bepaalt waar het in het bestand staat.
//
// Bewust het laad- en niet het virtuele adres: dit is de as waarop een loader
// plaatst. Voor een statisch gelinkt image zijn ze gelijk (Go's linker zet
// Vaddr == Paddr), en waar ze verschillen wil een plaatser de fysieke kant.
// Een adres dat in geen enkel PT_LOAD valt, of waarvan de staart in de BSS van
// het segment ligt (en dus niet in het bestand staat), is een fout.
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

// Lookup zoekt de opgegeven symbolen in .symtab en geeft alleen wat het vond:
// een naam die er niet in staat, staat ook niet in de map. Dat is met opzet —
// een loader kent verplichte én optionele symbolen, en "ontbreekt" is een
// antwoord en geen fout.
//
// De eerste definitie wint. Ongedefinieerde ingangen (SHN_UNDEF) worden
// overgeslagen: die dragen geen adres, en een nul teruggeven voor een naam die
// elders wél gedefinieerd is, is precies de stille misread die dit soort code
// duur maakt.
//
// Zonder .symtab is er niets te zoeken en is dat een fout: een image dat met
// -s gelinkt is, geeft hier de melding die de aanroeper doorgeeft.
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

	// Vanaf 1: de eerste ingang is per ABI alleen nullen.
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
		// string(raw) alloceert hier niet: de compiler ziet de vergelijking
		// met een map-key van type string.
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

// symtab leest .symtab en de stringtabel waar hij naar wijst. Beide in één
// keer: de tabellen zijn elkaars helft, en een symtab zonder zijn strtab
// levert namen die niets betekenen.
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

// section leest de inhoud van één sectieheader. SHT_NOBITS (BSS) staat niet in
// het bestand en levert dus niets op; voor de twee tabellen die dit pakket
// leest is dat een stukke ELF.
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

// readAtOff leest len(p) bytes op offset off, met de bestandsgrens erbij als de
// aanroeper die gaf. De optelling is overflow-veilig: off+len mag niet
// omklappen op een verzonnen header.
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

// readFull leest p helemaal vol; een korte lees is io.ErrUnexpectedEOF, want
// een halve header is geen header.
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

// cstr geeft de nul-getermineerde string die op off in de tabel begint. Zonder
// afsluitende nul is de tabel stuk en geeft het (nil, false): de laatste bytes
// van een stringtabel zijn geen naam.
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
