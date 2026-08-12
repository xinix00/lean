package leanelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// De testen bouwen hun eigen ELF64's en leggen het resultaat naast debug/elf.
// Dat is het punt: dit pakket bestaat om debug/elf niet te linken, niet om
// iets anders te lezen dan debug/elf leest. Waar ze van elkaar afwijken op een
// geldig image, is dit pakket fout.

// segSpec is één PT_LOAD zoals de builder hem legt: content komt in het
// bestand, memsz-filesz is BSS.
type segSpec struct {
	paddr   uint64
	content []byte
	memsz   uint64
}

// symSpec is één ingang in .symtab.
type symSpec struct {
	name  string
	value uint64
	size  uint64
	shndx uint16
}

// build zet een geldige, kleine ELF64 in elkaar: header, programheaders, de
// segmentinhoud, en (als er symbolen zijn) .symtab + .strtab + .shstrtab met
// hun sectieheaders. Alles little-endian, class 64 — precies wat onze images
// zijn.
func build(t *testing.T, entry uint64, segs []segSpec, syms []symSpec) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(make([]byte, ehdrSize+phdrSize*len(segs)))

	// De segmentinhoud, elk op een eigen 16-uitgelijnde offset.
	offs := make([]uint64, len(segs))
	for i, s := range segs {
		for buf.Len()%16 != 0 {
			buf.WriteByte(0)
		}
		offs[i] = uint64(buf.Len())
		buf.Write(s.content)
	}

	// .symtab en .strtab. De eerste symtab-ingang is per ABI nul, en de
	// strtab begint met een nulbyte zodat naam-offset 0 de lege naam is.
	var symtab, strtab bytes.Buffer
	symtab.Write(make([]byte, symSize))
	strtab.WriteByte(0)
	for _, s := range syms {
		nameOff := uint32(strtab.Len())
		strtab.WriteString(s.name)
		strtab.WriteByte(0)

		var e [symSize]byte
		binary.LittleEndian.PutUint32(e[0:], nameOff)
		e[4] = 0x12 // STB_GLOBAL | STT_FUNC
		binary.LittleEndian.PutUint16(e[6:], s.shndx)
		binary.LittleEndian.PutUint64(e[8:], s.value)
		binary.LittleEndian.PutUint64(e[16:], s.size)
		symtab.Write(e[:])
	}

	shstrtab := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")
	nameSymtab, nameStrtab, nameShstrtab := uint32(1), uint32(9), uint32(17)

	var symOff, strOff, shstrOff, shoff uint64
	if len(syms) > 0 {
		for buf.Len()%8 != 0 {
			buf.WriteByte(0)
		}
		symOff = uint64(buf.Len())
		buf.Write(symtab.Bytes())
		strOff = uint64(buf.Len())
		buf.Write(strtab.Bytes())
		shstrOff = uint64(buf.Len())
		buf.Write(shstrtab)

		for buf.Len()%8 != 0 {
			buf.WriteByte(0)
		}
		shoff = uint64(buf.Len())
		// 0: SHT_NULL, 1: .symtab, 2: .strtab, 3: .shstrtab.
		buf.Write(make([]byte, shdrSize))
		buf.Write(shdr(nameSymtab, 2 /*SHT_SYMTAB*/, symOff, uint64(symtab.Len()), 2 /*link*/, symSize))
		buf.Write(shdr(nameStrtab, 3 /*SHT_STRTAB*/, strOff, uint64(strtab.Len()), 0, 0))
		buf.Write(shdr(nameShstrtab, 3, shstrOff, uint64(len(shstrtab)), 0, 0))
	}

	img := buf.Bytes()

	// De header.
	copy(img, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(img[16:], 2)              // ET_EXEC
	binary.LittleEndian.PutUint16(img[18:], MachineAArch64) //
	binary.LittleEndian.PutUint32(img[20:], 1)              // EV_CURRENT
	binary.LittleEndian.PutUint64(img[24:], entry)
	binary.LittleEndian.PutUint64(img[32:], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint64(img[40:], shoff)
	binary.LittleEndian.PutUint16(img[52:], ehdrSize)
	binary.LittleEndian.PutUint16(img[54:], phdrSize)
	binary.LittleEndian.PutUint16(img[56:], uint16(len(segs)))
	binary.LittleEndian.PutUint16(img[58:], shdrSize)
	if shoff != 0 {
		binary.LittleEndian.PutUint16(img[60:], 4) // e_shnum
		binary.LittleEndian.PutUint16(img[62:], 3) // e_shstrndx
	}

	// De programheaders.
	for i, s := range segs {
		e := img[ehdrSize+i*phdrSize:]
		binary.LittleEndian.PutUint32(e[0:], PTLoad)
		binary.LittleEndian.PutUint32(e[4:], 5) // PF_R|PF_X
		binary.LittleEndian.PutUint64(e[8:], offs[i])
		binary.LittleEndian.PutUint64(e[16:], s.paddr) // vaddr == paddr
		binary.LittleEndian.PutUint64(e[24:], s.paddr)
		binary.LittleEndian.PutUint64(e[32:], uint64(len(s.content)))
		memsz := s.memsz
		if memsz < uint64(len(s.content)) {
			memsz = uint64(len(s.content))
		}
		binary.LittleEndian.PutUint64(e[40:], memsz)
		binary.LittleEndian.PutUint64(e[48:], 0x1000)
	}
	return img
}

func shdr(name, typ uint32, off, size uint64, link uint32, entsize uint64) []byte {
	var e [shdrSize]byte
	binary.LittleEndian.PutUint32(e[0:], name)
	binary.LittleEndian.PutUint32(e[4:], typ)
	binary.LittleEndian.PutUint64(e[24:], off)
	binary.LittleEndian.PutUint64(e[32:], size)
	binary.LittleEndian.PutUint32(e[40:], link)
	binary.LittleEndian.PutUint64(e[56:], entsize)
	return e[:]
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// open is de gewone weg in de testen: met bestandsgrootte, zoals een loader
// die een image in handen heeft hem ook kent.
func open(t *testing.T, img []byte) *File {
	t.Helper()
	f, err := Open(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

func TestSegmentsMatchDebugELF(t *testing.T) {
	img := build(t, 0x50010000, []segSpec{
		{paddr: 0x50010000, content: bytes.Repeat([]byte{0xaa}, 128)},
		{paddr: 0x50020000, content: []byte("data"), memsz: 4096}, // met BSS
	}, []symSpec{{name: "runtime.text", value: 0x50010000, shndx: 1}})

	want, err := elf.NewFile(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("debug/elf leest onze eigen ELF niet: %v", err)
	}
	got := open(t, img)

	if got.Entry != want.Entry {
		t.Errorf("Entry = %#x, debug/elf zegt %#x", got.Entry, want.Entry)
	}
	if uint16(want.Machine) != got.Machine {
		t.Errorf("Machine = %d, debug/elf zegt %d", got.Machine, want.Machine)
	}
	if len(got.Segments) != len(want.Progs) {
		t.Fatalf("%d segmenten, debug/elf ziet %d", len(got.Segments), len(want.Progs))
	}
	for i, ph := range want.Progs {
		s := got.Segments[i]
		if uint32(ph.Type) != s.Type || ph.Off != s.Off || ph.Vaddr != s.Vaddr ||
			ph.Paddr != s.Paddr || ph.Filesz != s.Filesz || ph.Memsz != s.Memsz || ph.Align != s.Align {
			t.Errorf("segment %d wijkt af:\n leanelf   %+v\n debug/elf %+v", i, s, ph.ProgHeader)
		}
	}
}

func TestLookupMatchesDebugELF(t *testing.T) {
	syms := []symSpec{
		{name: "runtime/goos.RamStart", value: 0x50011000, size: 8, shndx: 1},
		{name: "runtime/goos.RamSize", value: 0x50011008, size: 8, shndx: 1},
		{name: "applib.abiVersion", value: 0x50011010, size: 8, shndx: 1},
		{name: "een.ongebruikte", value: 0x50011018, shndx: 1},
	}
	img := build(t, 0x50010000, []segSpec{{paddr: 0x50010000, content: bytes.Repeat([]byte{1}, 64)}}, syms)

	got, err := open(t, img).Lookup("runtime/goos.RamStart", "runtime/goos.RamSize", "applib.abiVersion", "staat.er.niet")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("%d symbolen gevonden, wilde 3: %v", len(got), got)
	}
	if _, ok := got["staat.er.niet"]; ok {
		t.Error("een naam die niet in de tabel staat, staat wél in het antwoord")
	}

	ref, err := elf.NewFile(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	all, err := ref.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range all {
		s, ok := got[want.Name]
		if !ok {
			continue
		}
		if s.Value != want.Value || s.Size != want.Size || s.Info != want.Info {
			t.Errorf("%s: leanelf %+v, debug/elf value=%#x size=%d info=%#x",
				want.Name, s, want.Value, want.Size, want.Info)
		}
	}
}

func TestLookupSkipsUndefined(t *testing.T) {
	img := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: []byte("x")}}, []symSpec{
		{name: "dubbel", value: 0, shndx: 0},      // SHN_UNDEF: geen adres
		{name: "dubbel", value: 0x1234, shndx: 1}, // de echte definitie
	})
	got, err := open(t, img).Lookup("dubbel")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got["dubbel"].Value != 0x1234 {
		t.Errorf("value = %#x, wilde %#x — een SHN_UNDEF-ingang won", got["dubbel"].Value, 0x1234)
	}
}

func TestLookupZonderSymtab(t *testing.T) {
	img := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: []byte("x")}}, nil)
	if _, err := open(t, img).Lookup("wat.dan.ook"); err == nil {
		t.Fatal("een image zonder symboltabel gaf geen fout")
	}
}

func TestReadAtPaddr(t *testing.T) {
	body := append(u64(0xdeadbeefcafebabe), bytes.Repeat([]byte{0x11}, 24)...)
	img := build(t, 0x50010000, []segSpec{
		{paddr: 0x50010000, content: body, memsz: uint64(len(body)) + 4096}, // staart = BSS
		{paddr: 0x60000000, content: u64(7)},
	}, nil)
	f := open(t, img)

	var b [8]byte
	if err := f.ReadAtPaddr(b[:], 0x50010000); err != nil {
		t.Fatalf("ReadAtPaddr: %v", err)
	}
	if v := binary.LittleEndian.Uint64(b[:]); v != 0xdeadbeefcafebabe {
		t.Errorf("las %#x", v)
	}
	if err := f.ReadAtPaddr(b[:], 0x60000000); err != nil {
		t.Fatalf("tweede segment: %v", err)
	}
	if v := binary.LittleEndian.Uint64(b[:]); v != 7 {
		t.Errorf("tweede segment: las %d", v)
	}

	// Buiten élk segment, en in de BSS-staart (bestaat in het geheugen, niet
	// in het bestand): beide een fout en geen nullen.
	if err := f.ReadAtPaddr(b[:], 0x40000000); err == nil {
		t.Error("adres buiten alle segmenten gaf geen fout")
	}
	if err := f.ReadAtPaddr(b[:], 0x50010000+uint64(len(body))); err == nil {
		t.Error("adres in de BSS-staart gaf geen fout")
	}
	// Een lees die halverwege het bestandsdeel begint en erover heen loopt.
	if err := f.ReadAtPaddr(b[:], 0x50010000+uint64(len(body))-4); err == nil {
		t.Error("lees die over het einde van het segment loopt gaf geen fout")
	}
}

func TestOpenWeigert(t *testing.T) {
	valid := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: []byte("hallo")}}, nil)

	patch := func(f func(img []byte)) []byte {
		img := append([]byte(nil), valid...)
		f(img)
		return img
	}

	cases := []struct {
		naam string
		img  []byte
	}{
		{"geen ELF-magic", []byte("MZ\x90\x00 dit is een PE-tje")},
		{"leeg", nil},
		{"halve header", valid[:32]},
		{"32-bit", patch(func(b []byte) { b[4] = 1 })},
		{"onbekende class", patch(func(b []byte) { b[4] = 9 })},
		{"big-endian", patch(func(b []byte) { b[5] = 2 })},
		{"onbekende versie", patch(func(b []byte) { b[6] = 2 })},
		{"phentsize klopt niet", patch(func(b []byte) { binary.LittleEndian.PutUint16(b[54:], 32) })},
		{"PN_XNUM", patch(func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 0xffff) })},
		{"te veel programheaders", patch(func(b []byte) { binary.LittleEndian.PutUint16(b[56:], maxPhnum+1) })},
		{"phoff buiten het bestand", patch(func(b []byte) { binary.LittleEndian.PutUint64(b[32:], 1<<40) })},
		{"phoff klapt om", patch(func(b []byte) { binary.LittleEndian.PutUint64(b[32:], ^uint64(0)-8) })},
	}
	for _, c := range cases {
		t.Run(c.naam, func(t *testing.T) {
			if _, err := Open(bytes.NewReader(c.img), int64(len(c.img))); err == nil {
				t.Fatal("geen fout")
			}
		})
	}

	// ErrNotELF is apart, want daarop test een aanroeper die meer formaten kan.
	if _, err := Open(bytes.NewReader([]byte("MZ...")), 5); !errors.Is(err, ErrNotELF) {
		t.Errorf("magic-fout = %v, wilde ErrNotELF", err)
	}
}

func TestSymtabWeigert(t *testing.T) {
	valid := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: []byte("hallo")}},
		[]symSpec{{name: "iets", value: 0x1000, shndx: 1}})
	shoff := binary.LittleEndian.Uint64(valid[40:])

	cases := []struct {
		naam string
		f    func(img []byte)
	}{
		{"shentsize klopt niet", func(b []byte) { binary.LittleEndian.PutUint16(b[58:], 32) }},
		{"te veel sectieheaders", func(b []byte) { binary.LittleEndian.PutUint16(b[60:], maxShnum+1) }},
		{"geen sectieheaders", func(b []byte) { binary.LittleEndian.PutUint16(b[60:], 0) }},
		{"shoff buiten het bestand", func(b []byte) { binary.LittleEndian.PutUint64(b[40:], 1<<40) }},
		{"symtab-entsize klopt niet", func(b []byte) {
			binary.LittleEndian.PutUint64(b[shoff+shdrSize+56:], 16)
		}},
		{"symtab-link buiten bereik", func(b []byte) {
			binary.LittleEndian.PutUint32(b[shoff+shdrSize+40:], 99)
		}},
		{"symtab linkt niet naar een strtab", func(b []byte) {
			binary.LittleEndian.PutUint32(b[shoff+2*shdrSize+4:], 1) // .strtab → SHT_PROGBITS
		}},
		{"symtab buiten het bestand", func(b []byte) {
			binary.LittleEndian.PutUint64(b[shoff+shdrSize+24:], 1<<40)
		}},
		{"symtab te groot", func(b []byte) {
			binary.LittleEndian.PutUint64(b[shoff+shdrSize+32:], maxTable+1)
		}},
		{"symtab is SHT_NOBITS", func(b []byte) {
			binary.LittleEndian.PutUint32(b[shoff+shdrSize+4:], 2)
			binary.LittleEndian.PutUint32(b[shoff+2*shdrSize+4:], 3)
			// .symtab als NOBITS herschrijven kan niet (dan is het geen
			// symtab meer); dus doe het op de strtab waar hij naar wijst.
			binary.LittleEndian.PutUint32(b[shoff+2*shdrSize+4:], 3)
			binary.LittleEndian.PutUint64(b[shoff+2*shdrSize+24:], 1<<40)
		}},
	}
	for _, c := range cases {
		t.Run(c.naam, func(t *testing.T) {
			img := append([]byte(nil), valid...)
			c.f(img)
			f, err := Open(bytes.NewReader(img), int64(len(img)))
			if err != nil {
				return // ook goed: dan viel hij al bij Open om
			}
			if _, err := f.Lookup("iets"); err == nil {
				t.Fatal("geen fout")
			}
		})
	}
}

func TestStrtabZonderAfsluitendeNul(t *testing.T) {
	// Een naam die tot het einde van de stringtabel doorloopt is geen naam:
	// hij wordt overgeslagen in plaats van dat er over de tabelgrens gelezen
	// wordt.
	if got, ok := cstr([]byte("abc"), 0); ok {
		t.Errorf("cstr zonder nul gaf %q, ok", got)
	}
	if _, ok := cstr([]byte("abc\x00"), 9); ok {
		t.Error("offset buiten de tabel gaf ok")
	}
	if got, ok := cstr([]byte("\x00abc\x00"), 1); !ok || string(got) != "abc" {
		t.Errorf("cstr = %q, %v", got, ok)
	}
}

func TestZonderBestandsgrootte(t *testing.T) {
	// size < 0: de aanroeper kent de grootte niet, en dan is de io.ReaderAt de
	// enige grens. Een geldig image moet gewoon werken.
	img := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: u64(42)}}, nil)
	f, err := Open(bytes.NewReader(img), -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var b [8]byte
	if err := f.ReadAtPaddr(b[:], 0x1000); err != nil {
		t.Fatalf("ReadAtPaddr: %v", err)
	}
	if v := binary.LittleEndian.Uint64(b[:]); v != 42 {
		t.Errorf("las %d", v)
	}
}

func TestGeenProgramheaders(t *testing.T) {
	// Een object zonder programheaders is geldig — er valt alleen niets te
	// laden, en dat merkt de aanroeper aan een lege Segments.
	img := build(t, 0, nil, []symSpec{{name: "iets", value: 8, shndx: 1}})
	f := open(t, img)
	if len(f.Segments) != 0 {
		t.Fatalf("%d segmenten", len(f.Segments))
	}
	if _, err := f.Lookup("iets"); err != nil {
		t.Errorf("Lookup: %v", err)
	}
	var b [8]byte
	if err := f.ReadAtPaddr(b[:], 8); err == nil {
		t.Error("lezen zonder segmenten gaf geen fout")
	}
}

// io.ReaderAt-implementaties mogen (n, io.EOF) teruggeven voor een lees die
// precies tot het einde loopt; dat is geen fout.
type eofAtEnd struct{ b []byte }

func (r eofAtEnd) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, io.EOF
}

func TestReaderDieEOFMeldtBijDeLaatsteByte(t *testing.T) {
	img := build(t, 0x1000, []segSpec{{paddr: 0x1000, content: u64(99)}}, nil)
	f, err := Open(eofAtEnd{img}, int64(len(img)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var b [8]byte
	if err := f.ReadAtPaddr(b[:], 0x1000); err != nil {
		t.Fatalf("ReadAtPaddr: %v", err)
	}
	if v := binary.LittleEndian.Uint64(b[:]); v != 99 {
		t.Errorf("las %d", v)
	}
}
