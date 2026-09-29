//! ELF64 voor een loader: PT_LOAD-segmenten, de bytes op een laadadres, symbolen op naam.
//!
//! Deze crate leest de delen van een ELF64-image die een loader nodig heeft:
//! de programmaheaders, bytes op een laadadres, en een paar symbolen op naam.
//! Hij werkt puur over een `&[u8]` dat de aanroeper bezit: geen I/O, geen
//! kopie, geen allocatie. Wat hij teruggeeft, leent uit dat image.
//!
//! De Go-versie verving `debug/elf`, waarvan de DWARF- en
//! compressie-ondersteuning `debug/dwarf`, `compress/zlib` en `internal/zstd`
//! de HopOS-kern in trok. Op cmd/hopos arm64 met `-w -trimpath` (12-08-2026)
//! kromp het image van 6.302.520 naar 6.136.123 bytes, met gelijke plaatsing.
//!
//! Wat niet ondersteund wordt, faalt luid: ELF32, big-endian, relocaties,
//! secties op naam, DWARF, en een volledige symboldump. [`File::lookup`]
//! zoekt alleen de namen die de loader vraagt, in plaats van tienduizenden
//! namen te maken. Elke waarde uit een header is onvertrouwd: hij wordt
//! begrensd en zonder overflow tegen de maat van het image getoetst.
//!
//! # Examples
//!
//! ```no_run
//! # fn demo(image: &[u8]) -> leanelf::Result {
//! let f = leanelf::File::parse(image)?;
//! for seg in f.segments().filter(|s| s.kind == leanelf::PT_LOAD) {
//!     let _bytes = f.at_paddr(seg.paddr, 16)?;
//! }
//! let [start] = f.lookup(["runtime/goos.RamStart"])?;
//! # let _ = start;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![forbid(unsafe_code)]

use core::fmt;

/// De maat van `Elf64_Ehdr`. Het bestand herhaalt de volgende maten in
/// `e_phentsize` en `e_shentsize`; een andere waarde is een ander formaat.
const EHDR_SIZE: usize = 64;
/// De maat van `Elf64_Phdr`.
const PHDR_SIZE: usize = 56;
/// De maat van `Elf64_Shdr`.
const SHDR_SIZE: usize = 64;
/// De maat van `Elf64_Sym`.
const SYM_SIZE: usize = 24;

/// Segmenttype `PT_NULL`: een ongebruikte ingang.
pub const PT_NULL: u32 = 0;
/// Segmenttype `PT_LOAD`: het enige type met loader-betekenis hier. Andere
/// waarden blijven rauw in [`Segment::kind`], zodat een aanroeper zonder
/// namentabel zelf beslist.
pub const PT_LOAD: u32 = 1;

/// `e_machine` voor x86-64; voor een architectuurtoets vóór het laden.
pub const MACHINE_X86_64: u16 = 62;
/// `e_machine` voor AArch64.
pub const MACHINE_AARCH64: u16 = 183;
/// `e_machine` voor RISC-V.
pub const MACHINE_RISCV: u16 = 243;

/// Het maximum aantal programmaheaders. Ruim boven een gewone Go-binary,
/// maar een verzonnen header kan zo geen onbegrensde lus worden.
pub const MAX_PHNUM: u16 = 1024;
/// Het maximum aantal sectieheaders, met dezelfde reden als [`MAX_PHNUM`].
pub const MAX_SHNUM: u16 = 4096;
/// De maximummaat van elk van `.symtab` en `.strtab`: 64 MiB.
///
/// In Go was dit een grens op een allocatie; hier wordt niets gekopieerd,
/// maar de grens blijft, want een tabel van die maat is geen image dat wij
/// gebouwd hebben.
pub const MAX_TABLE: u64 = 64 << 20;

/// `SHT_SYMTAB`.
const SHT_SYMTAB: u32 = 2;
/// `SHT_STRTAB`.
const SHT_STRTAB: u32 = 3;

/// Het deel van het image dat gelezen werd toen een fout optrad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// De vier bytes ELF-magic.
    Magic,
    /// De rest van de ELF-header.
    Header,
    /// De tabel met programmaheaders.
    ProgramHeaders,
    /// De tabel met sectieheaders.
    SectionHeaders,
    /// De inhoud van `.symtab`.
    Symtab,
    /// De inhoud van de stringtabel van `.symtab`.
    Strtab,
    /// Bestandsdata van een segment.
    Segment,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Magic => "magic",
            Self::Header => "header",
            Self::ProgramHeaders => "program headers",
            Self::SectionHeaders => "section headers",
            Self::Symtab => "symbol table",
            Self::Strtab => "symbol string table",
            Self::Segment => "segment data",
        })
    }
}

/// Een fout uit deze crate.
///
/// [`Error::NotElf`] staat apart, zodat een aanroeper met meer formaten
/// "geen ELF" kan scheiden van "kapotte of niet-ondersteunde ELF".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// De ELF-magic ontbreekt.
    NotElf,
    /// Een deel reikt voorbij het einde van het image.
    Truncated {
        /// Wat er gelezen werd.
        part: Part,
        /// De offset in het image.
        off: u64,
        /// Het aantal gevraagde bytes.
        len: u64,
        /// De maat van het image.
        size: u64,
    },
    /// Offset plus lengte loopt over.
    Overflow {
        /// Wat er gelezen werd.
        part: Part,
        /// De offset in het image.
        off: u64,
        /// Het aantal gevraagde bytes.
        len: u64,
    },
    /// Een 32-bit ELF (`ELFCLASS32`).
    Class32,
    /// Een onbekende `EI_CLASS`.
    UnknownClass(u8),
    /// Een big-endian ELF.
    BigEndian,
    /// Een onbekende `EI_VERSION`.
    UnknownVersion(u8),
    /// Een uitgebreid aantal programmaheaders (`PN_XNUM`).
    PhXnum,
    /// Meer programmaheaders dan [`MAX_PHNUM`].
    TooManyPhdrs(u16),
    /// `e_phentsize` is niet 56.
    PhentSize(u16),
    /// Een laadadres dat in geen enkel PT_LOAD-segment valt.
    NotLoaded {
        /// Het laadadres.
        paddr: u64,
        /// Het aantal gevraagde bytes.
        len: u64,
    },
    /// Geen sectieheaders, dus geen symbooltabel (gelinkt met `-s`?).
    NoSectionHeaders,
    /// Meer sectieheaders dan [`MAX_SHNUM`].
    TooManyShdrs(u16),
    /// `e_shentsize` is niet 64.
    ShentSize(u16),
    /// `sh_entsize` van `.symtab` is niet 24.
    SymEntSize(u64),
    /// `.symtab` linkt naar een sectie die niet bestaat.
    SymtabLink {
        /// De gelinkte sectie.
        link: u32,
        /// Het aantal secties.
        count: u16,
    },
    /// `.symtab` linkt niet naar een stringtabel.
    LinkNotStrtab,
    /// Een tabel groter dan [`MAX_TABLE`].
    TableTooBig {
        /// Welke tabel.
        part: Part,
        /// De maat uit de header.
        size: u64,
    },
    /// Geen `.symtab` (gelinkt met `-s`?).
    NoSymtab,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotElf => f.write_str("leanelf: not an ELF file"),
            Self::Truncated {
                part,
                off,
                len,
                size,
            } => write!(
                f,
                "leanelf: {part}: offset {off:#x}+{len} is past the end of the {size}-byte image"
            ),
            Self::Overflow { part, off, len } => {
                write!(f, "leanelf: {part}: offset {off:#x}+{len} overflows")
            }
            Self::Class32 => {
                f.write_str("leanelf: 32-bit ELF (ELFCLASS32); only ELFCLASS64 is supported")
            }
            Self::UnknownClass(c) => write!(f, "leanelf: unknown ELF class {c}"),
            Self::BigEndian => {
                f.write_str("leanelf: big-endian ELF; only little-endian is supported")
            }
            Self::UnknownVersion(v) => write!(f, "leanelf: unknown ELF version {v}"),
            Self::PhXnum => {
                f.write_str("leanelf: extended program header count (PN_XNUM) is not supported")
            }
            Self::TooManyPhdrs(n) => write!(
                f,
                "leanelf: {n} program headers exceeds the {MAX_PHNUM} we are willing to read"
            ),
            Self::PhentSize(n) => {
                write!(f, "leanelf: program header size {n}, expected {PHDR_SIZE}")
            }
            Self::NotLoaded { paddr, len } => write!(
                f,
                "leanelf: address {paddr:#x}+{len} is not inside any loaded segment"
            ),
            Self::NoSectionHeaders => {
                f.write_str("leanelf: no section headers, so no symbol table (linked with -s?)")
            }
            Self::TooManyShdrs(n) => write!(
                f,
                "leanelf: {n} section headers exceeds the {MAX_SHNUM} we are willing to read"
            ),
            Self::ShentSize(n) => {
                write!(f, "leanelf: section header size {n}, expected {SHDR_SIZE}")
            }
            Self::SymEntSize(n) => {
                write!(f, "leanelf: symbol size {n}, expected {SYM_SIZE}")
            }
            Self::SymtabLink { link, count } => write!(
                f,
                "leanelf: symbol table links to section {link} of {count}"
            ),
            Self::LinkNotStrtab => {
                f.write_str("leanelf: symbol table does not link to a string table")
            }
            Self::TableTooBig { part, size } => write!(
                f,
                "leanelf: {part} is {size} bytes, over the {MAX_TABLE}-byte cap"
            ),
            Self::NoSymtab => f.write_str("leanelf: no symbol table (linked with -s?)"),
        }
    }
}

impl core::error::Error for Error {}

/// Het resultaat van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Eén programmaheader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// `p_type`; zie [`PT_LOAD`].
    pub kind: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`: de offset in het image.
    pub off: u64,
    /// `p_vaddr`: het virtuele adres.
    pub vaddr: u64,
    /// `p_paddr`: het laadadres.
    pub paddr: u64,
    /// `p_filesz`: het aantal bytes in het image.
    pub filesz: u64,
    /// `p_memsz`: het aantal bytes in geheugen; het verschil is BSS.
    pub memsz: u64,
    /// `p_align`.
    pub align: u64,
}

/// Eén ingang uit `.symtab`: zijn naam en plek.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol<'a> {
    /// De naam, geleend uit de stringtabel van het image.
    pub name: &'a str,
    /// `st_value`.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_info`.
    pub info: u8,
    /// `st_shndx`.
    pub shndx: u16,
}

/// Een geparste ELF64 die uit het image leent.
///
/// [`File::parse`] toetst de header en de tabel met programmaheaders;
/// symbolen worden pas bij [`File::lookup`] gelezen.
///
/// # Invariants
///
/// `phdrs` is precies `phnum * 56` bytes uit `data`, met `phnum` hoogstens
/// [`MAX_PHNUM`].
#[derive(Debug, Clone, Copy)]
pub struct File<'a> {
    /// `e_machine`; zie [`MACHINE_AARCH64`] en verwanten.
    pub machine: u16,
    /// `e_type` (2 = `ET_EXEC`, 3 = `ET_DYN`).
    pub kind: u16,
    /// `e_entry`.
    pub entry: u64,

    /// Het hele image.
    data: &'a [u8],
    /// De tabel met programmaheaders.
    phdrs: &'a [u8],
    /// `e_shoff`.
    shoff: u64,
    /// `e_shnum`.
    shnum: u16,
    /// `e_shentsize`.
    shentsize: u16,
}

impl<'a> File<'a> {
    /// Leest de ELF-header en de programmaheaders uit `data`.
    ///
    /// De magic wordt eerst los getoetst, zodat een blob van vier bytes die
    /// geen ELF is [`Error::NotElf`] geeft en geen fout over de ontbrekende
    /// rest van de header.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let magic = slice_at(data, 0, 4, Part::Magic)?;
        if magic != b"\x7fELF" {
            return Err(Error::NotElf);
        }
        let h = slice_at(data, 0, EHDR_SIZE as u64, Part::Header)?;
        match byte(h, 4) {
            2 => {}
            1 => return Err(Error::Class32),
            c => return Err(Error::UnknownClass(c)),
        }
        if byte(h, 5) != 1 {
            return Err(Error::BigEndian);
        }
        let version = byte(h, 6);
        if version != 1 {
            return Err(Error::UnknownVersion(version));
        }

        let mut f = File {
            kind: le16(h, 16),
            machine: le16(h, 18),
            entry: le64(h, 24),
            data,
            phdrs: &[],
            shoff: le64(h, 40),
            shentsize: le16(h, 58),
            shnum: le16(h, 60),
        };

        let phoff = le64(h, 32);
        let phentsize = le16(h, 54);
        let phnum = le16(h, 56);
        if phnum == 0 {
            // Geen programmaheaders: geen segmenten, maar verder geldig.
            return Ok(f);
        }
        if phnum == 0xffff {
            return Err(Error::PhXnum);
        }
        if phnum > MAX_PHNUM {
            return Err(Error::TooManyPhdrs(phnum));
        }
        if usize::from(phentsize) != PHDR_SIZE {
            return Err(Error::PhentSize(phentsize));
        }
        let len = u64::from(phnum) * PHDR_SIZE as u64;
        // INVARIANT: phnum <= MAX_PHNUM en de tabel is precies phnum * 56 bytes.
        f.phdrs = slice_at(data, phoff, len, Part::ProgramHeaders)?;
        Ok(f)
    }

    /// Geeft de programmaheaders, in de volgorde van het image.
    pub fn segments(&self) -> Segments<'a> {
        Segments {
            rest: self.phdrs.chunks_exact(PHDR_SIZE),
        }
    }

    /// Geeft de `len` bytes op laadadres `paddr`, geleend uit het image.
    ///
    /// Het segment dat ze bevat wijst de weg; bewust het fysieke laadadres,
    /// niet het virtuele. Wat buiten de bestandsdata van een PT_LOAD valt,
    /// ook de BSS-staart, is een fout.
    pub fn at_paddr(&self, paddr: u64, len: u64) -> Result<&'a [u8]> {
        for s in self.segments() {
            if s.kind != PT_LOAD
                || paddr < s.paddr
                || len > s.filesz
                || paddr - s.paddr > s.filesz - len
            {
                continue;
            }
            // Geen overflow: paddr - s.paddr <= s.filesz - len, dus de som
            // is hoogstens s.filesz; slice_at toetst off + filesz.
            let delta = paddr - s.paddr;
            let off = s.off.checked_add(delta).ok_or(Error::Overflow {
                part: Part::Segment,
                off: s.off,
                len: delta,
            })?;
            return slice_at(self.data, off, len, Part::Segment);
        }
        Err(Error::NotLoaded { paddr, len })
    }

    /// Kopieert `buf.len()` bytes van laadadres `paddr` naar `buf`.
    ///
    /// De vorm van de Go-versie; [`File::at_paddr`] doet hetzelfde zonder
    /// kopie.
    pub fn read_at_paddr(&self, buf: &mut [u8], paddr: u64) -> Result {
        let src = self.at_paddr(paddr, buf.len() as u64)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    /// Zoekt de gevraagde symbolen in `.symtab`; elk antwoord staat op de plek
    /// van zijn naam.
    ///
    /// Een naam die er niet staat, geeft `None`, want een loader vraagt
    /// zowel verplichte als optionele symbolen. De eerste definitie wint en
    /// `SHN_UNDEF`-ingangen tellen niet. Een ontbrekende `.symtab` is een
    /// fout, meestal een image dat met `-s` gelinkt is.
    pub fn lookup<const N: usize>(&self, names: [&str; N]) -> Result<[Option<Symbol<'a>>; N]> {
        let mut out = [None; N];
        self.lookup_into(&names, &mut out)?;
        Ok(out)
    }

    /// Als [`File::lookup`], voor een lijst die pas bij het draaien bekend is.
    ///
    /// `out[i]` krijgt het symbool van `names[i]`; is `out` korter, dan
    /// worden de overige namen niet gezocht.
    pub fn lookup_into(&self, names: &[&str], out: &mut [Option<Symbol<'a>>]) -> Result {
        for o in out.iter_mut() {
            *o = None;
        }
        let want = names.len().min(out.len());
        if want == 0 {
            return Ok(());
        }
        let (symtab, strtab) = self.symtab()?;
        let mut found = 0;

        // Ingang nul is de ABI-schildwacht van allemaal nullen.
        for e in symtab.chunks_exact(SYM_SIZE).skip(1) {
            let shndx = le16(e, 6);
            if shndx == 0 {
                continue;
            }
            let Some(raw) = cstr(strtab, le32(e, 0)) else {
                continue;
            };
            if raw.is_empty() {
                continue;
            }
            for (name, slot) in names.iter().zip(out.iter_mut()) {
                if slot.is_some() || name.as_bytes() != raw {
                    continue;
                }
                // Gelijk aan een &str, dus geldige UTF-8; de Err-tak is dood.
                let Ok(name) = core::str::from_utf8(raw) else {
                    continue;
                };
                *slot = Some(Symbol {
                    name,
                    value: le64(e, 8),
                    size: le64(e, 16),
                    info: byte(e, 4),
                    shndx,
                });
                found += 1;
            }
            if found == want {
                break;
            }
        }
        Ok(())
    }

    /// Leest `.symtab` en de stringtabel waar hij naar linkt, samen: de een is
    /// zonder de ander niets waard.
    fn symtab(&self) -> Result<(&'a [u8], &'a [u8])> {
        if self.shnum == 0 || self.shoff == 0 {
            return Err(Error::NoSectionHeaders);
        }
        if self.shnum > MAX_SHNUM {
            return Err(Error::TooManyShdrs(self.shnum));
        }
        if usize::from(self.shentsize) != SHDR_SIZE {
            return Err(Error::ShentSize(self.shentsize));
        }
        let len = u64::from(self.shnum) * SHDR_SIZE as u64;
        let tab = slice_at(self.data, self.shoff, len, Part::SectionHeaders)?;
        for e in tab.chunks_exact(SHDR_SIZE) {
            if le32(e, 4) != SHT_SYMTAB {
                continue;
            }
            let entsize = le64(e, 56);
            if entsize != SYM_SIZE as u64 {
                return Err(Error::SymEntSize(entsize));
            }
            let link = le32(e, 40);
            let str = usize::try_from(link)
                .ok()
                .and_then(|i| tab.chunks_exact(SHDR_SIZE).nth(i))
                .ok_or(Error::SymtabLink {
                    link,
                    count: self.shnum,
                })?;
            if le32(str, 4) != SHT_STRTAB {
                return Err(Error::LinkNotStrtab);
            }
            // SHT_NOBITS (geen data in het bestand) toetste Go hier ook, maar
            // die toets was dood: beide typen zijn hierboven al vastgepind op
            // SYMTAB en STRTAB. De grens op maat en bestand blijft.
            let symtab = self.section(e, Part::Symtab)?;
            let strtab = self.section(str, Part::Strtab)?;
            return Ok((symtab, strtab));
        }
        Err(Error::NoSymtab)
    }

    /// Geeft de inhoud van één sectie, begrensd op [`MAX_TABLE`].
    fn section(&self, shdr: &[u8], part: Part) -> Result<&'a [u8]> {
        let off = le64(shdr, 24);
        let size = le64(shdr, 32);
        if size > MAX_TABLE {
            return Err(Error::TableTooBig { part, size });
        }
        slice_at(self.data, off, size, part)
    }
}

/// De programmaheaders van een [`File`], één [`Segment`] per stap.
#[derive(Debug, Clone)]
pub struct Segments<'a> {
    /// De nog niet gelezen headers, elk precies 56 bytes.
    rest: core::slice::ChunksExact<'a, u8>,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Segment> {
        let e = self.rest.next()?;
        Some(Segment {
            kind: le32(e, 0),
            flags: le32(e, 4),
            off: le64(e, 8),
            vaddr: le64(e, 16),
            paddr: le64(e, 24),
            filesz: le64(e, 32),
            memsz: le64(e, 40),
            align: le64(e, 48),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.rest.size_hint()
    }
}

impl ExactSizeIterator for Segments<'_> {}

/// Geeft `len` bytes op `off` uit `data`, met de maat en overflow getoetst.
///
/// De grens van 2^63 is die van de Go-versie (een `int64`-offset); hij houdt
/// `off + len` ver van de rand van `u64`.
fn slice_at(data: &[u8], off: u64, len: u64, part: Part) -> Result<&[u8]> {
    const LIMIT: u64 = 1 << 63;
    if off > LIMIT || len > LIMIT - off {
        return Err(Error::Overflow { part, off, len });
    }
    let size = data.len() as u64;
    let truncated = Error::Truncated {
        part,
        off,
        len,
        size,
    };
    if off + len > size {
        return Err(truncated);
    }
    let start = usize::try_from(off).map_err(|_| truncated)?;
    let end = usize::try_from(off + len).map_err(|_| truncated)?;
    data.get(start..end).ok_or(truncated)
}

/// Geeft de NUL-afgesloten string op `off`; zonder afsluitende NUL is de
/// tabel kapot en is het antwoord `None`.
fn cstr(tab: &[u8], off: u32) -> Option<&[u8]> {
    let s = tab.get(usize::try_from(off).ok()?..)?;
    let end = s.iter().position(|&c| c == 0)?;
    s.get(..end)
}

/// Leest één byte op `off`.
///
/// De lezers hieronder krijgen alleen ingangen die al op hun volle maat
/// getoetst zijn (header, programma-, sectie- en symboolheader), met
/// constante offsets daarbinnen; de 0 voor "buiten de ingang" is dus een
/// dode tak die een panic vervangt.
fn byte(b: &[u8], off: usize) -> u8 {
    b.get(off).copied().unwrap_or(0)
}

/// Leest een little-endian `u16` op `off`; zie [`byte`] voor de grens.
fn le16(b: &[u8], off: usize) -> u16 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u16::from_le_bytes(*a))
}

/// Leest een little-endian `u32` op `off`; zie [`byte`] voor de grens.
fn le32(b: &[u8], off: usize) -> u32 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u32::from_le_bytes(*a))
}

/// Leest een little-endian `u64` op `off`; zie [`byte`] voor de grens.
fn le64(b: &[u8], off: usize) -> u64 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u64::from_le_bytes(*a))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Een wijziging op een geldig image, voor de weiger-tabellen.
    type Patch = Box<dyn Fn(&mut [u8])>;

    /// Eén segment voor [`build`].
    struct SegSpec<'s> {
        paddr: u64,
        content: &'s [u8],
        memsz: u64,
    }

    /// Eén symbool voor [`build`].
    struct SymSpec<'s> {
        name: &'s str,
        value: u64,
        size: u64,
        shndx: u16,
    }

    fn put16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn pad(buf: &mut Vec<u8>, to: usize) {
        while !buf.len().is_multiple_of(to) {
            buf.push(0);
        }
    }

    /// Bouwt een klein maar echt ELF64-image, zoals de Go-test het deed.
    fn build(entry: u64, segs: &[SegSpec<'_>], syms: &[SymSpec<'_>]) -> Vec<u8> {
        let mut buf = vec![0u8; EHDR_SIZE + PHDR_SIZE * segs.len()];

        let mut offs = Vec::new();
        for s in segs {
            pad(&mut buf, 16);
            offs.push(buf.len() as u64);
            buf.extend_from_slice(s.content);
        }

        let mut symtab = vec![0u8; SYM_SIZE];
        let mut strtab = vec![0u8];
        for s in syms {
            let name_off = strtab.len() as u32;
            strtab.extend_from_slice(s.name.as_bytes());
            strtab.push(0);
            let mut e = [0u8; SYM_SIZE];
            put32(&mut e, 0, name_off);
            e[4] = 0x12;
            put16(&mut e, 6, s.shndx);
            put64(&mut e, 8, s.value);
            put64(&mut e, 16, s.size);
            symtab.extend_from_slice(&e);
        }

        let shstrtab = b"\x00.symtab\x00.strtab\x00.shstrtab\x00";
        let mut shoff = 0u64;
        if !syms.is_empty() {
            pad(&mut buf, 8);
            let sym_off = buf.len() as u64;
            buf.extend_from_slice(&symtab);
            let str_off = buf.len() as u64;
            buf.extend_from_slice(&strtab);
            let shstr_off = buf.len() as u64;
            buf.extend_from_slice(shstrtab);
            pad(&mut buf, 8);
            shoff = buf.len() as u64;
            buf.extend_from_slice(&[0u8; SHDR_SIZE]);
            buf.extend_from_slice(&shdr(
                1,
                2,
                sym_off,
                symtab.len() as u64,
                2,
                SYM_SIZE as u64,
            ));
            buf.extend_from_slice(&shdr(9, 3, str_off, strtab.len() as u64, 0, 0));
            buf.extend_from_slice(&shdr(17, 3, shstr_off, shstrtab.len() as u64, 0, 0));
        }

        buf[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        put16(&mut buf, 16, 2);
        put16(&mut buf, 18, MACHINE_AARCH64);
        put32(&mut buf, 20, 1);
        put64(&mut buf, 24, entry);
        put64(&mut buf, 32, EHDR_SIZE as u64);
        put64(&mut buf, 40, shoff);
        put16(&mut buf, 52, EHDR_SIZE as u16);
        put16(&mut buf, 54, PHDR_SIZE as u16);
        put16(&mut buf, 56, segs.len() as u16);
        put16(&mut buf, 58, SHDR_SIZE as u16);
        if shoff != 0 {
            put16(&mut buf, 60, 4);
            put16(&mut buf, 62, 3);
        }

        for (i, s) in segs.iter().enumerate() {
            let e = EHDR_SIZE + i * PHDR_SIZE;
            put32(&mut buf, e, PT_LOAD);
            put32(&mut buf, e + 4, 5);
            put64(&mut buf, e + 8, offs[i]);
            put64(&mut buf, e + 16, s.paddr);
            put64(&mut buf, e + 24, s.paddr);
            put64(&mut buf, e + 32, s.content.len() as u64);
            put64(&mut buf, e + 40, s.memsz.max(s.content.len() as u64));
            put64(&mut buf, e + 48, 0x1000);
        }
        buf
    }

    fn shdr(name: u32, kind: u32, off: u64, size: u64, link: u32, entsize: u64) -> [u8; SHDR_SIZE] {
        let mut e = [0u8; SHDR_SIZE];
        put32(&mut e, 0, name);
        put32(&mut e, 4, kind);
        put64(&mut e, 24, off);
        put64(&mut e, 32, size);
        put32(&mut e, 40, link);
        put64(&mut e, 56, entsize);
        e
    }

    fn seg(paddr: u64, content: &[u8], memsz: u64) -> SegSpec<'_> {
        SegSpec {
            paddr,
            content,
            memsz,
        }
    }

    fn sym(name: &str, value: u64, size: u64, shndx: u16) -> SymSpec<'_> {
        SymSpec {
            name,
            value,
            size,
            shndx,
        }
    }

    // Go vergeleek hier met debug/elf. Die referentie bestaat zonder externe
    // crate niet; de verwachting komt nu rechtstreeks uit de bouwspec, die
    // debug/elf in de Go-test bevestigde.
    #[test]
    fn test_segments_match_debug_elf() -> Result {
        let data = [0xaau8; 128];
        let img = build(
            0x5001_0000,
            &[seg(0x5001_0000, &data, 0), seg(0x5002_0000, b"data", 4096)],
            &[sym("runtime.text", 0x5001_0000, 0, 1)],
        );
        let f = File::parse(&img)?;
        assert_eq!(f.entry, 0x5001_0000);
        assert_eq!(f.machine, MACHINE_AARCH64);
        assert_eq!(f.kind, 2);
        let segs: Vec<Segment> = f.segments().collect();
        assert_eq!(f.segments().len(), 2);
        assert_eq!(
            segs[0],
            Segment {
                kind: PT_LOAD,
                flags: 5,
                off: 176,
                vaddr: 0x5001_0000,
                paddr: 0x5001_0000,
                filesz: 128,
                memsz: 128,
                align: 0x1000,
            }
        );
        assert_eq!(
            segs[1],
            Segment {
                kind: PT_LOAD,
                flags: 5,
                off: 304,
                vaddr: 0x5002_0000,
                paddr: 0x5002_0000,
                filesz: 4,
                memsz: 4096,
                align: 0x1000,
            }
        );
        assert_eq!(&img[176..304], &data[..]);
        Ok(())
    }

    #[test]
    fn test_lookup_matches_debug_elf() -> Result {
        let body = [1u8; 64];
        let img = build(
            0x5001_0000,
            &[seg(0x5001_0000, &body, 0)],
            &[
                sym("runtime/goos.RamStart", 0x5001_1000, 8, 1),
                sym("runtime/goos.RamSize", 0x5001_1008, 8, 1),
                sym("applib.abiVersion", 0x5001_1010, 8, 1),
                sym("een.ongebruikte", 0x5001_1018, 0, 1),
            ],
        );
        let got = File::parse(&img)?.lookup([
            "runtime/goos.RamStart",
            "runtime/goos.RamSize",
            "applib.abiVersion",
            "staat.er.niet",
        ])?;
        assert_eq!(got.iter().flatten().count(), 3);
        assert!(
            got[3].is_none(),
            "een naam die niet in de tabel staat, staat wél in het antwoord"
        );
        let want = [
            ("runtime/goos.RamStart", 0x5001_1000, 8),
            ("runtime/goos.RamSize", 0x5001_1008, 8),
            ("applib.abiVersion", 0x5001_1010, 8),
        ];
        for (s, (name, value, size)) in got.iter().zip(want) {
            assert_eq!(
                *s,
                Some(Symbol {
                    name,
                    value,
                    size,
                    info: 0x12,
                    shndx: 1,
                })
            );
        }
        Ok(())
    }

    #[test]
    fn test_lookup_skips_undefined() -> Result {
        let img = build(
            0x1000,
            &[seg(0x1000, b"x", 0)],
            &[sym("dubbel", 0, 0, 0), sym("dubbel", 0x1234, 0, 1)],
        );
        let [got] = File::parse(&img)?.lookup(["dubbel"])?;
        assert_eq!(
            got.map(|s| s.value),
            Some(0x1234),
            "een SHN_UNDEF-ingang won"
        );
        Ok(())
    }

    #[test]
    fn test_lookup_zonder_symtab() -> Result {
        let img = build(0x1000, &[seg(0x1000, b"x", 0)], &[]);
        assert_eq!(
            File::parse(&img)?.lookup(["wat.dan.ook"]),
            Err(Error::NoSectionHeaders)
        );
        Ok(())
    }

    #[test]
    fn test_read_at_paddr() -> Result {
        let mut body = 0xdead_beef_cafe_babe_u64.to_le_bytes().to_vec();
        body.extend_from_slice(&[0x11; 24]);
        let seven = 7u64.to_le_bytes();
        let img = build(
            0x5001_0000,
            &[
                seg(0x5001_0000, &body, body.len() as u64 + 4096),
                seg(0x6000_0000, &seven, 0),
            ],
            &[],
        );
        let f = File::parse(&img)?;

        let mut b = [0u8; 8];
        f.read_at_paddr(&mut b, 0x5001_0000)?;
        assert_eq!(u64::from_le_bytes(b), 0xdead_beef_cafe_babe);
        f.read_at_paddr(&mut b, 0x6000_0000)?;
        assert_eq!(u64::from_le_bytes(b), 7, "tweede segment");

        assert!(
            f.read_at_paddr(&mut b, 0x4000_0000).is_err(),
            "adres buiten alle segmenten gaf geen fout"
        );
        let end = 0x5001_0000 + body.len() as u64;
        assert!(
            f.read_at_paddr(&mut b, end).is_err(),
            "adres in de BSS-staart gaf geen fout"
        );
        assert_eq!(
            f.read_at_paddr(&mut b, end - 4),
            Err(Error::NotLoaded {
                paddr: end - 4,
                len: 8
            }),
            "lees die over het einde van het segment loopt gaf geen fout"
        );
        Ok(())
    }

    #[test]
    fn test_open_weigert() {
        let valid = build(0x1000, &[seg(0x1000, b"hallo", 0)], &[]);
        let patch = |f: &dyn Fn(&mut [u8])| {
            let mut img = valid.clone();
            f(&mut img);
            img
        };

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("geen ELF-magic", b"MZ\x90\x00 dit is een PE-tje".to_vec()),
            ("leeg", Vec::new()),
            ("halve header", valid[..32].to_vec()),
            ("32-bit", patch(&|b| b[4] = 1)),
            ("onbekende class", patch(&|b| b[4] = 9)),
            ("big-endian", patch(&|b| b[5] = 2)),
            ("onbekende versie", patch(&|b| b[6] = 2)),
            ("phentsize klopt niet", patch(&|b| put16(b, 54, 32))),
            ("PN_XNUM", patch(&|b| put16(b, 56, 0xffff))),
            (
                "te veel programheaders",
                patch(&|b| put16(b, 56, MAX_PHNUM + 1)),
            ),
            (
                "phoff buiten het bestand",
                patch(&|b| put64(b, 32, 1 << 40)),
            ),
            ("phoff klapt om", patch(&|b| put64(b, 32, u64::MAX - 8))),
        ];
        for (name, img) in &cases {
            assert!(File::parse(img).is_err(), "{name}: geen fout");
        }

        assert_eq!(File::parse(b"MZ...").err(), Some(Error::NotElf));
    }

    #[test]
    fn test_symtab_weigert() {
        let valid = build(
            0x1000,
            &[seg(0x1000, b"hallo", 0)],
            &[sym("iets", 0x1000, 0, 1)],
        );
        let shoff = u64::from_le_bytes(valid[40..48].try_into().unwrap()) as usize;
        let sh = SHDR_SIZE;

        let cases: Vec<(&str, Patch)> = vec![
            ("shentsize klopt niet", Box::new(|b| put16(b, 58, 32))),
            (
                "te veel sectieheaders",
                Box::new(|b| put16(b, 60, MAX_SHNUM + 1)),
            ),
            ("geen sectieheaders", Box::new(|b| put16(b, 60, 0))),
            (
                "shoff buiten het bestand",
                Box::new(|b| put64(b, 40, 1 << 40)),
            ),
            (
                "symtab-entsize klopt niet",
                Box::new(move |b| put64(b, shoff + sh + 56, 16)),
            ),
            (
                "symtab-link buiten bereik",
                Box::new(move |b| put32(b, shoff + sh + 40, 99)),
            ),
            (
                "symtab linkt niet naar een strtab",
                Box::new(move |b| put32(b, shoff + 2 * sh + 4, 1)),
            ),
            (
                "symtab buiten het bestand",
                Box::new(move |b| put64(b, shoff + sh + 24, 1 << 40)),
            ),
            (
                "symtab te groot",
                Box::new(move |b| put64(b, shoff + sh + 32, MAX_TABLE + 1)),
            ),
            (
                // Dezelfde bytes als de Go-test: de strtab wijst buiten het
                // bestand (zie de noot over SHT_NOBITS in File::symtab).
                "symtab is SHT_NOBITS",
                Box::new(move |b| {
                    put32(b, shoff + sh + 4, 2);
                    put32(b, shoff + 2 * sh + 4, 3);
                    put64(b, shoff + 2 * sh + 24, 1 << 40);
                }),
            ),
        ];
        for (name, f) in &cases {
            let mut img = valid.clone();
            f(&mut img);
            let Ok(file) = File::parse(&img) else {
                continue;
            };
            assert!(file.lookup(["iets"]).is_err(), "{name}: geen fout");
        }
    }

    #[test]
    fn test_strtab_zonder_afsluitende_nul() {
        assert_eq!(cstr(b"abc", 0), None, "cstr zonder nul gaf iets");
        assert_eq!(cstr(b"abc\x00", 9), None, "offset buiten de tabel gaf iets");
        assert_eq!(cstr(b"\x00abc\x00", 1), Some(&b"abc"[..]));
    }

    // TestZonderBestandsgrootte (Go) is niet geport: over een `&[u8]` is de
    // maat altijd bekend, dus de "grootte onbekend"-tak bestaat niet meer.

    // Go: een ReaderAt die io.EOF samen met de laatste byte meldt, is geen
    // fout. Over een slice is de bedoeling: een lees die precies op het
    // einde van het image eindigt, slaagt.
    #[test]
    fn test_reader_die_eof_meldt_bij_de_laatste_byte() -> Result {
        let v = 99u64.to_le_bytes();
        let img = build(0x1000, &[seg(0x1000, &v, 0)], &[]);
        assert_eq!(
            &img[img.len() - 8..],
            &v[..],
            "het segment sluit het image af"
        );
        let f = File::parse(&img)?;
        let mut b = [0u8; 8];
        f.read_at_paddr(&mut b, 0x1000)?;
        assert_eq!(u64::from_le_bytes(b), 99);
        // Eén byte verder is afgekapt, dus een fout.
        let short = &img[..img.len() - 1];
        let f = File::parse(short)?;
        assert!(matches!(
            f.read_at_paddr(&mut b, 0x1000),
            Err(Error::Truncated { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_geen_programheaders() -> Result {
        let img = build(0, &[], &[sym("iets", 8, 0, 1)]);
        let f = File::parse(&img)?;
        assert_eq!(f.segments().len(), 0);
        let [s] = f.lookup(["iets"])?;
        assert_eq!(s.map(|s| s.value), Some(8));
        let mut b = [0u8; 8];
        assert!(
            f.read_at_paddr(&mut b, 8).is_err(),
            "lezen zonder segmenten gaf geen fout"
        );
        Ok(())
    }

    #[test]
    fn test_lookup_into_dubbele_en_lege_namen() -> Result {
        let img = build(0x1000, &[seg(0x1000, b"x", 0)], &[sym("a", 1, 0, 1)]);
        let f = File::parse(&img)?;
        let mut out = [None; 2];
        f.lookup_into(&["a", "a"], &mut out)?;
        assert_eq!(out.map(|s| s.map(|s| s.value)), [Some(1), Some(1)]);
        // Zonder namen wordt de symbooltabel niet eens gelezen.
        let bare = build(0x1000, &[seg(0x1000, b"x", 0)], &[]);
        assert_eq!(File::parse(&bare)?.lookup([]), Ok([]));
        Ok(())
    }
}
