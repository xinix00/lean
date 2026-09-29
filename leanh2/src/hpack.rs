//! HPACK (RFC 7541) in de vorm die één rol nodig heeft.
//!
//! Deze module bezit de dynamische tabel van de peer en de codering van onze
//! antwoordvelden. Hij woont in deze crate en niet ernaast: HPACK bestaat
//! alleen voor HTTP/2, en een bouwsteen die een andere bouwsteen nodig heeft is
//! geen bouwsteen meer.
//!
//! Decoderen moet compleet zijn, want wat de peer stuurt kiezen wij niet: de
//! statische tabel, alle vier literal-vormen, Huffman-literals en de dynamische
//! tabel met zijn grootte-updates. Coderen mag minimaal: een exacte treffer in
//! de statische tabel gebruikt zijn index, elk ander veld gaat als "literal
//! zonder indexering" (§6.2.2). Dat schrapt de encoder-helft van het
//! Huffman-alfabet en een tweede dynamische tabel, en kost een paar dozijn
//! bytes per antwoord.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::huffman;

/// Eén kopveld. Namen zijn op de draad in kleine letters (RFC 9113 §8.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    /// De naam.
    pub(crate) name: String,
    /// De waarde.
    pub(crate) value: String,
}

impl Field {
    /// De grootte volgens §4.1: naam, waarde en 32 bytes overhead.
    fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

/// Bijlage A van RFC 7541. Index 1 is het eerste veld; index nul bestaat niet.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Wat er mis is met een kopblok.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    /// Het blok eindigde midden in een instructie. CONTINUATION-frames zijn
    /// dan al samengevoegd, dus dit is een protocolfout van de peer.
    Truncated,
    /// EOS in een Huffman-literal, opvulling langer dan zeven bits, of
    /// opvulling die geen voorvoegsel van EOS is.
    Eos,
    /// Index nul is geen veld.
    IndexZero,
    /// Een index voorbij de tabel.
    IndexBeyond {
        /// De index.
        index: usize,
    },
    /// Een grootte-update na het eerste veld van een blok (§4.2).
    TableSizeAfterField,
    /// Een tabelgrootte boven wat wij aankondigden.
    TableSizeAbove {
        /// De gevraagde grootte.
        size: usize,
        /// De aangekondigde grens.
        allowed: usize,
    },
    /// Een geheel getal met te veel vervolgbytes.
    IntegerTooLong,
    /// Een gedecodeerde koplijst boven de grens.
    ListTooLarge {
        /// De grens in bytes.
        limit: usize,
    },
    /// Een naam of waarde die geen UTF-8 is.
    NotUtf8,
    /// De heap weigerde.
    OutOfMemory,
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("header block ended mid-instruction"),
            Self::Eos => f.write_str("EOS in huffman literal"),
            Self::IndexZero => f.write_str("index 0 is not a field"),
            Self::IndexBeyond { index } => write!(f, "index {index} beyond the table"),
            Self::TableSizeAfterField => f.write_str("table size update after a field"),
            Self::TableSizeAbove { size, allowed } => {
                write!(f, "table size {size} above the announced {allowed}")
            }
            Self::IntegerTooLong => f.write_str("integer too long"),
            Self::ListTooLarge { limit } => write!(f, "header list above the {limit} byte limit"),
            Self::NotUtf8 => f.write_str("header field is not UTF-8"),
            Self::OutOfMemory => f.write_str("out of memory in the HPACK decoder"),
        }
    }
}

/// De dynamische tabel van de peer. Hij hoort bij de verbinding, niet bij één
/// blok: de tabel leeft over blokken heen.
///
/// De tabel bestaat ook al kondigen wij grootte nul aan. Die aankondiging
/// werkt pas als de peer haar gezien heeft, en een peer die daarvoor
/// indexeerde moet nog steeds leesbaar zijn; daar weigeren zou correcte HPACK
/// weigeren.
pub(crate) struct Decoder {
    /// Nieuwste eerst, in indexvolgorde.
    dynamic: VecDeque<Field>,
    /// De som van de veldgroottes (§4.1).
    size: usize,
    /// De geldende tabelgrootte.
    capacity: usize,
    /// Het plafond dat wij aankondigden. Die twee apart houden telt: een peer
    /// mag binnen het plafond krimpen en groeien, en één getal zou een update
    /// het plafond laten verhogen.
    allowed: usize,
    /// De grens op één gedecodeerde koplijst; nul is onbegrensd. Zonder
    /// plafond laat één frame het geheugen van een node van 32 MB groeien.
    limit: usize,
}

impl Decoder {
    /// Een decoder met plafond `allowed` en lijstgrens `limit`.
    pub(crate) fn new(allowed: usize, limit: usize) -> Self {
        Self {
            dynamic: VecDeque::new(),
            size: 0,
            capacity: allowed,
            allowed,
            limit,
        }
    }

    /// Past onze bevestigde SETTINGS_HEADER_TABLE_SIZE toe. Frames zijn
    /// geordend, dus na de bevestiging kan geen blok nog op de oude grootte
    /// leunen.
    pub(crate) fn set_allowed(&mut self, n: usize) {
        self.allowed = n;
        if self.capacity > n {
            self.capacity = n;
            self.evict();
        }
    }

    /// Leest één compleet kopblok.
    pub(crate) fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>, HpackError> {
        let mut out: Vec<Field> = Vec::new();
        let mut total = 0usize;
        let mut p = block;
        let mut at_start = true;
        while let Some(&b) = p.first() {
            let field = if b & 0x80 != 0 {
                // 1xxxxxxx: geïndexeerd veld (§6.1).
                let (idx, rest) = read_int(p, 7)?;
                p = rest;
                self.at(idx)?
            } else if b & 0xc0 == 0x40 {
                // 01xxxxxx: literal mét indexering (§6.2.1).
                let (f, rest) = self.literal(p, 6)?;
                p = rest;
                self.add(f.clone())?;
                f
            } else if b & 0xe0 == 0x20 {
                // 001xxxxx: tabelgrootte-update (§6.3), alleen aan het begin.
                if !at_start {
                    return Err(HpackError::TableSizeAfterField);
                }
                let (size, rest) = read_int(p, 5)?;
                p = rest;
                if size > self.allowed {
                    return Err(HpackError::TableSizeAbove {
                        size,
                        allowed: self.allowed,
                    });
                }
                self.capacity = size;
                self.evict();
                // Nog steeds aan het begin: updates mogen elkaar opvolgen.
                continue;
            } else {
                // 0000xxxx en 0001xxxx: literal zonder, of nooit met, indexering.
                let (f, rest) = self.literal(p, 4)?;
                p = rest;
                f
            };
            at_start = false;
            total += field.size();
            if self.limit > 0 && total > self.limit {
                return Err(HpackError::ListTooLarge { limit: self.limit });
            }
            out.try_reserve(1).map_err(|_| HpackError::OutOfMemory)?;
            out.push(field);
        }
        Ok(out)
    }

    /// Leest uit de statische of de dynamische tabel; de index loopt door beide.
    fn at(&self, index: usize) -> Result<Field, HpackError> {
        if index == 0 {
            return Err(HpackError::IndexZero);
        }
        if let Some((name, value)) = STATIC.get(index - 1) {
            return Ok(Field {
                name: owned(name)?,
                value: owned(value)?,
            });
        }
        let f = self
            .dynamic
            .get(index - 1 - STATIC.len())
            .ok_or(HpackError::IndexBeyond { index })?;
        Ok(Field {
            name: owned(&f.name)?,
            value: owned(&f.value)?,
        })
    }

    /// Leest beide literal-vormen: de naam is een index of een string.
    fn literal<'b>(&self, p: &'b [u8], prefix: u8) -> Result<(Field, &'b [u8]), HpackError> {
        let (idx, rest) = read_int(p, prefix)?;
        let (name, rest) = if idx == 0 {
            read_string(rest)?
        } else {
            (self.at(idx)?.name, rest)
        };
        let (value, rest) = read_string(rest)?;
        Ok((Field { name, value }, rest))
    }

    /// Zet een veld vooraan en ruimt op tot het past. Een veld dat in zijn
    /// eentje niet past, leegt de tabel (§4.4); precies wat grootte nul doet,
    /// dus geen apart geval.
    fn add(&mut self, f: Field) -> Result<(), HpackError> {
        self.size += f.size();
        self.dynamic
            .try_reserve(1)
            .map_err(|_| HpackError::OutOfMemory)?;
        self.dynamic.push_front(f);
        self.evict();
        Ok(())
    }

    /// Ruimt de oudste velden op tot de tabel binnen zijn grootte valt.
    fn evict(&mut self) {
        while self.size > self.capacity {
            let Some(last) = self.dynamic.pop_back() else {
                break;
            };
            self.size -= last.size();
        }
        if self.dynamic.is_empty() {
            self.size = 0;
        }
    }
}

/// Leest een geheel getal met een voorvoegsel van `prefix` bits (§5.1).
fn read_int(p: &[u8], prefix: u8) -> Result<(usize, &[u8]), HpackError> {
    let (&first, mut p) = p.split_first().ok_or(HpackError::Truncated)?;
    let mask = (1usize << prefix) - 1;
    let mut v = usize::from(first) & mask;
    if v < mask {
        return Ok((v, p));
    }
    // Vervolgbytes van zeven bits. De grens houdt een vijandige reeks weg van
    // een overflow: koplijsten van megabytes bestaan niet.
    let mut shift = 0;
    while shift <= 21 {
        let (&b, rest) = p.split_first().ok_or(HpackError::Truncated)?;
        p = rest;
        v += usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((v, p));
        }
        shift += 7;
    }
    Err(HpackError::IntegerTooLong)
}

/// Leest een string-literal; één bit zegt of hij Huffman-gecodeerd is.
fn read_string(p: &[u8]) -> Result<(String, &[u8]), HpackError> {
    let huff = p.first().ok_or(HpackError::Truncated)? & 0x80 != 0;
    let (n, rest) = read_int(p, 7)?;
    if n > rest.len() {
        return Err(HpackError::Truncated);
    }
    let (raw, rest) = rest.split_at(n);
    let mut bytes = Vec::new();
    if huff {
        huffman::decode(raw, &mut bytes)?;
    } else {
        bytes.try_reserve(n).map_err(|_| HpackError::OutOfMemory)?;
        bytes.extend_from_slice(raw);
    }
    let s = String::from_utf8(bytes).map_err(|_| HpackError::NotUtf8)?;
    Ok((s, rest))
}

/// Een eigen kopie van een string, faalbaar gealloceerd.
fn owned(s: &str) -> Result<String, HpackError> {
    let mut out = String::new();
    out.try_reserve(s.len())
        .map_err(|_| HpackError::OutOfMemory)?;
    out.push_str(s);
    Ok(out)
}

/// Codeert velden: een exacte statische index waar die bestaat, anders een
/// "literal zonder indexering" (§6.2.2), zonder Huffman.
pub(crate) fn encode(dst: &mut Vec<u8>, name: &str, value: &str) -> Result<(), HpackError> {
    dst.try_reserve(name.len() + value.len() + 8)
        .map_err(|_| HpackError::OutOfMemory)?;
    if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
        // Index 1..=61 past in zeven bits.
        dst.push(0x80 | (i as u8 + 1));
        return Ok(());
    }
    match STATIC.iter().position(|&(n, _)| n == name) {
        Some(i) => append_int(dst, 0x00, 4, i + 1),
        None => {
            dst.push(0x00);
            append_string(dst, name);
        }
    }
    append_string(dst, value);
    Ok(())
}

/// Schrijft een geheel getal met voorvoegsel (§5.1).
pub(crate) fn append_int(dst: &mut Vec<u8>, flags: u8, prefix: u8, mut v: usize) {
    let mask = (1usize << prefix) - 1;
    if v < mask {
        dst.push(flags | v as u8);
        return;
    }
    dst.push(flags | mask as u8);
    v -= mask;
    while v >= 0x80 {
        dst.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

/// Schrijft een string-literal zonder Huffman.
fn append_string(dst: &mut Vec<u8>, s: &str) {
    append_int(dst, 0x00, 7, s.len());
    dst.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn f(name: &str, value: &str) -> Field {
        Field {
            name: name.into(),
            value: value.into(),
        }
    }

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn encode_fields(fields: &[Field]) -> Vec<u8> {
        let mut out = Vec::new();
        for field in fields {
            encode(&mut out, &field.name, &field.value).unwrap();
        }
        out
    }

    // De voorbeelden uit RFC 7541 bijlage C: dat is de enige toets die niet
    // meebeweegt met onze eigen aannames.
    #[test]
    fn rfc7541_examples() {
        let cases = [
            (
                "C.2.1 literal met indexering",
                "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
                vec![f("custom-key", "custom-header")],
            ),
            (
                "C.2.2 literal zonder indexering",
                "040c2f73616d706c652f70617468",
                vec![f(":path", "/sample/path")],
            ),
            ("C.2.4 geindexeerd", "82", vec![f(":method", "GET")]),
            (
                "C.3.1 verzoek zonder huffman",
                "828684410f7777772e6578616d706c652e636f6d",
                vec![
                    f(":method", "GET"),
                    f(":scheme", "http"),
                    f(":path", "/"),
                    f(":authority", "www.example.com"),
                ],
            ),
            (
                "C.4.1 verzoek met huffman",
                "828684418cf1e3c2e5f23a6ba0ab90f4ff",
                vec![
                    f(":method", "GET"),
                    f(":scheme", "http"),
                    f(":path", "/"),
                    f(":authority", "www.example.com"),
                ],
            ),
        ];
        for (name, hex, want) in cases {
            let got = Decoder::new(4096, 0).decode(&unhex(hex)).unwrap();
            assert_eq!(got, want, "{name}");
        }
    }

    // De dynamische tabel over blokken heen: C.3 stuurt drie verzoeken achter
    // elkaar en het derde leunt volledig op wat de eerste twee indexeerden.
    #[test]
    fn dynamic_table_across_blocks() {
        let mut dec = Decoder::new(4096, 0);
        let cases = [
            (
                "828684410f7777772e6578616d706c652e636f6d",
                vec![
                    f(":method", "GET"),
                    f(":scheme", "http"),
                    f(":path", "/"),
                    f(":authority", "www.example.com"),
                ],
            ),
            (
                "828684be58086e6f2d6361636865",
                vec![
                    f(":method", "GET"),
                    f(":scheme", "http"),
                    f(":path", "/"),
                    f(":authority", "www.example.com"),
                    f("cache-control", "no-cache"),
                ],
            ),
            (
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
                vec![
                    f(":method", "GET"),
                    f(":scheme", "https"),
                    f(":path", "/index.html"),
                    f(":authority", "www.example.com"),
                    f("custom-key", "custom-value"),
                ],
            ),
        ];
        for (i, (hex, want)) in cases.into_iter().enumerate() {
            assert_eq!(dec.decode(&unhex(hex)).unwrap(), want, "verzoek {}", i + 1);
        }
    }

    // Het echte blok dat de Cloudflare-edge stuurde toen hij zijn control-stream
    // opende (spike 19-08-2026, 87 bytes van region1.v2.argotunnel.com). Dit is
    // de enige test die bewijst dat we de peer aankunnen die ons echt belt.
    #[test]
    fn cloudflare_control_stream_headers() {
        let block = "419521ea4d87a16426c28e95c941ed925a0761645c87a7828487409c24ab1283db24\
                     b40ec2c8b5761fcfa5887aaa291263d4b5b5cd60e42f8a21ea4d87a16426c28e9f\
                     50839bd9ab7a8dc475a74a6b589418b525812e0f";
        let got = Decoder::new(4096, 1 << 20).decode(&unhex(block)).unwrap();
        // Niet op de exacte lijst toetsen: dit is een opname en de edge mag zijn
        // koppen veranderen. Wat vast staat: dit moet de control-stream zijn.
        let get = |n: &str| got.iter().find(|x| x.name == n).map(|x| x.value.as_str());
        assert_eq!(
            get("cf-cloudflared-proxy-connection-upgrade"),
            Some("control-stream"),
            "{got:?}"
        );
        assert!(get(":authority").is_some_and(|a| !a.is_empty()), "{got:?}");
    }

    // Opvulling die geen voorvoegsel van EOS is, en een halve code die te lang
    // doorloopt: beide horen te weigeren in plaats van stil af te ronden.
    #[test]
    fn huffman_rejects_bad_padding() {
        for (name, hex) in [
            ("padding met een nul erin", "8100"),
            ("te lange staart", "83ffffff"),
        ] {
            // Een literal-naam met Huffman: 0x00, dan de string.
            let mut block = vec![0x00];
            block.extend(unhex(hex));
            block.extend([0x00]);
            assert!(Decoder::new(4096, 0).decode(&block).is_err(), "{name}");
        }
    }

    // Wat wij schrijven moet elke HPACK-decoder kunnen lezen; toets het dus met
    // onze eigen decoder, die de RFC-voorbeelden al haalt.
    #[test]
    fn encode_round_trip() {
        let fields = vec![
            f(":status", "200"),
            f("content-type", "image/jpeg"),
            f("cf-ray", "8f3a1b2c4d5e6f70-AMS"),
            f("x-leeg", ""),
        ];
        let block = encode_fields(&fields);
        assert_eq!(Decoder::new(4096, 0).decode(&block).unwrap(), fields);
        // :status 200 hoort één byte te zijn (statische index 8).
        assert_eq!(block[0], 0x88);
    }

    // De grens op de koplijst moet dichtklappen, anders laat één frame ons
    // geheugen groeien op een node die 32 MB heeft.
    #[test]
    fn header_list_limit() {
        let fields = vec![f("x-vulling", "0123456789012345678901234567890123456789"); 64];
        assert!(
            Decoder::new(4096, 1024)
                .decode(&encode_fields(&fields))
                .is_err()
        );
    }
}
