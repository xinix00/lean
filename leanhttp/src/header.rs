//! Headervelden en de kleine grammatica eromheen: tokens, veldwaarden,
//! kale getallen, de `Connection`-lijst en de statusteksten.
//!
//! De grammatica is streng waar Go's `net/http` mild is, omdat twee parsers
//! die het oneens zijn over framing de klassieke smokkelroute zijn.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Een geordende verzameling headervelden.
///
/// `get`, `set` en `remove` zijn hoofdletterongevoelig en bewaren de spelling
/// van de zender. De volgorde is die van invoegen, zodat een antwoord op de
/// draad staat zoals de handler het schreef.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    fields: Vec<(String, String)>,
}

impl Header {
    /// Een lege verzameling; alloceert niets.
    pub const fn new() -> Self {
        Header { fields: Vec::new() }
    }

    /// De waarde van `name`, of `None` als hij ontbreekt.
    ///
    /// Een exacte spelling wint; anders de eerste hoofdletterongevoelige match.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .or_else(|| {
                self.fields
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
            })
            .map(|(_, v)| v.as_str())
    }

    /// De waarde van `name`, of `""` als hij ontbreekt; zo leest Go's
    /// `Header.Get`, en zo toetst de framing "afwezig of leeg".
    pub(crate) fn value(&self, name: &str) -> &str {
        self.get(name).unwrap_or("")
    }

    /// Zet `name` op `value` en haalt anders gespelde varianten weg.
    pub fn set(&mut self, name: &str, value: &str) -> Result {
        let field = (try_string(name)?, try_string(value)?);
        self.remove(name);
        self.fields
            .try_reserve(1)
            .map_err(|_| Error::Alloc { bytes: 1 })?;
        self.fields.push(field);
        Ok(())
    }

    /// Voegt een veld toe zonder bestaande varianten weg te halen.
    ///
    /// Op een antwoord voegt de schrijver varianten van één naam samen als ze
    /// gelijk zijn, en laat ze allemaal vallen (en sluit de verbinding) als ze
    /// verschillen: een conflict over framing mag de draad niet op.
    pub fn append(&mut self, name: &str, value: &str) -> Result {
        let field = (try_string(name)?, try_string(value)?);
        self.fields
            .try_reserve(1)
            .map_err(|_| Error::Alloc { bytes: 1 })?;
        self.fields.push(field);
        Ok(())
    }

    /// Haalt `name` weg, in elke spelling.
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Vouwt een herhaald veld in een kommalijst (RFC 9110 §5.3).
    pub(crate) fn add(&mut self, name: &str, value: &str) -> Result {
        let cur = self.value(name);
        if cur.is_empty() {
            return self.set(name, value);
        }
        let mut joined = String::new();
        let len = cur.len() + 2 + value.len();
        joined
            .try_reserve(len)
            .map_err(|_| Error::Alloc { bytes: len })?;
        joined.push_str(cur);
        joined.push_str(", ");
        joined.push_str(value);
        self.set(name, &joined)
    }

    /// Alle velden, in volgorde.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Aantal velden.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Zegt of er geen velden zijn.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Voegt hoofdletter-varianten van één naam samen voor de draad: gelijke
    /// waarden worden één regel, verschillende verdwijnen allemaal.
    ///
    /// Geeft `true` als er een conflict was; de schrijver sluit dan de
    /// verbinding, zodat EOF de enige ondubbelzinnige framing is.
    pub(crate) fn collapse_variants(&mut self) -> bool {
        let mut conflict = false;
        let mut i = 0;
        while i < self.fields.len() {
            let (mut dup, mut differs) = (false, false);
            if let Some((name, value)) = self.fields.get(i) {
                for (k, v) in self.fields.iter().skip(i + 1) {
                    if k.eq_ignore_ascii_case(name) {
                        dup = true;
                        differs |= v != value;
                    }
                }
            }
            if dup {
                let mut j = self.fields.len();
                while j > i + 1 {
                    j -= 1;
                    let same = self
                        .fields
                        .get(j)
                        .zip(self.fields.get(i))
                        .is_some_and(|(a, b)| a.0.eq_ignore_ascii_case(&b.0));
                    if same {
                        self.fields.remove(j);
                    }
                }
                if differs {
                    self.fields.remove(i);
                    conflict = true;
                    continue;
                }
            }
            i += 1;
        }
        conflict
    }
}

/// Kopieert `s` in een nieuwe `String`, faalbaar.
pub(crate) fn try_string(s: &str) -> Result<String> {
    let mut out = String::new();
    out.try_reserve(s.len())
        .map_err(|_| Error::Alloc { bytes: s.len() })?;
    out.push_str(s);
    Ok(out)
}

/// RFC 9110 §5.6.2: een token, zonder de witruimte die een framingheader voor
/// zijn dubbele punt kan verstoppen.
pub(crate) fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// RFC 9110 §5.5 voor lezers en schrijvers: HTAB, zichtbaar ASCII en
/// obs-text; andere controlebytes niet.
pub(crate) fn valid_field_value(s: &[u8]) -> bool {
    s.iter().all(|&c| (c >= 0x20 || c == b'\t') && c != 0x7f)
}

/// Haalt alleen SP en HTAB weg (RFC 9110 §5.6.3), geen bredere witruimte.
pub(crate) fn trim_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// Alleen ASCII-cijfers, hoogstens 18 zodat het in een `u64` past en geen
/// teken of alternatieve schrijfwijze de framing kan laten verschillen.
pub(crate) fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 18 {
        return None;
    }
    s.bytes().try_fold(0u64, |n, c| {
        c.is_ascii_digit().then(|| n * 10 + u64::from(c - b'0'))
    })
}

/// Kale hex voor chunkgroottes, hoogstens 15 cijfers.
pub(crate) fn parse_hex(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 15 {
        return None;
    }
    s.bytes().try_fold(0u64, |n, c| {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        Some(n << 4 | u64::from(d))
    })
}

/// Zoekt `token` in een `Connection`-kommalijst, hoofdletterongevoelig.
pub(crate) fn connection_has(header: &str, token: &str) -> bool {
    header
        .split(',')
        .any(|part| trim_ows(part).eq_ignore_ascii_case(token))
}

/// Statussen zonder body: informatief, 204, 205 en 304.
///
/// 205 krijgt wel een expliciete `Content-Length: 0`, omdat RFC 9112 §6.3 hem
/// voor framing niet vanzelf bodyloos maakt.
pub(crate) fn body_allowed(status: u16) -> bool {
    status >= 200 && status != 204 && status != 205 && status != 304
}

/// De redentekst bij de statussen die deze crate en zijn gebruikers sturen.
pub(crate) fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        205 => "Reset Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        417 => "Expectation Failed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Schrijft `n` decimaal in `buf` en geeft de tekst terug; alloceert niets.
pub(crate) fn fmt_dec(mut n: u64, buf: &mut [u8; 20]) -> &str {
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 || i == 0 {
            break;
        }
    }
    core::str::from_utf8(buf.get(i..).unwrap_or(&[])).unwrap_or("0")
}

/// Schrijft `n` als kleine hex in `buf` en geeft de tekst terug; alloceert niets.
pub(crate) fn fmt_hex(mut n: u64, buf: &mut [u8; 20]) -> &str {
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            *slot = b"0123456789abcdef"[(n & 0xf) as usize];
        }
        n >>= 4;
        if n == 0 || i == 0 {
            break;
        }
    }
    core::str::from_utf8(buf.get(i..).unwrap_or(&[])).unwrap_or("0")
}
