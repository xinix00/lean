//! Precies genoeg URL voor deze crate: een absolute `http(s)`-URL ontleden,
//! een `Location` tegen de vorige hop oplossen, origins vergelijken, en een
//! requestpad decoderen en canoniek verklaren.
//!
//! Wat er niet is: userinfo (geweigerd), IDNA, het normaliseren van een pad
//! naar een andere betekenis. Een fragment valt weg, zoals op de draad.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::error::{Error, Result};
use crate::io::{FmtBuf, try_extend};

/// Een ontlede absolute URL; alles leent uit de bron.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Url<'a> {
    /// Schema zoals geschreven (`http`, `HTTPS`).
    pub(crate) scheme: &'a str,
    /// De authority, `host[:poort]`: de waarde van de `Host`-header.
    pub(crate) authority: &'a str,
    /// De hostnaam zonder poort en zonder IPv6-haken.
    pub(crate) hostname: &'a str,
    /// De poort als hij er stond.
    pub(crate) port: Option<u16>,
    /// Het pad zoals geschreven; leeg betekent `/`.
    pub(crate) path: &'a str,
    /// De query zonder `?`, als er een `?` stond.
    pub(crate) query: Option<&'a str>,
}

impl<'a> Url<'a> {
    /// Ontleedt `raw` als `schema://authority/pad?query#fragment`.
    ///
    /// Bytes tot en met de spatie en DEL zijn geen URL; userinfo wordt
    /// geweigerd omdat geen gebruiker hem meegeeft en hij een host kan
    /// vermommen.
    pub(crate) fn parse(raw: &'a str) -> Result<Self> {
        if raw.bytes().any(|c| c <= b' ' || c == 0x7f) {
            return Err(Error::BadUrl);
        }
        let raw = raw.split('#').next().unwrap_or("");
        let (scheme, rest) = raw.split_once(':').ok_or(Error::BadUrl)?;
        if !valid_scheme(scheme) {
            return Err(Error::BadUrl);
        }
        let Some(rest) = rest.strip_prefix("//") else {
            // Geen authority: voor http(s) is dat een URL zonder host.
            return Ok(Url {
                scheme,
                authority: "",
                hostname: "",
                port: None,
                path: rest,
                query: None,
            });
        };
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(cut);
        if authority.contains('@') {
            return Err(Error::BadUrl);
        }
        let (hostname, port) = split_host_port(authority)?;
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        Ok(Url {
            scheme,
            authority,
            hostname,
            port,
            path,
            query,
        })
    }

    /// Zegt of dit `https` is, hoofdletterongevoelig.
    pub(crate) fn is_https(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("https")
    }

    /// De poort, of de standaard van het schema.
    pub(crate) fn effective_port(&self) -> u16 {
        match self.port {
            Some(p) => p,
            None if self.is_https() => 443,
            None => 80,
        }
    }

    /// Schrijft pad en query zoals ze op de requestregel horen.
    pub(crate) fn write_request_uri(&self, out: &mut Vec<u8>) -> Result {
        try_extend(
            out,
            if self.path.is_empty() {
                b"/"
            } else {
                self.path.as_bytes()
            },
        )?;
        if let Some(q) = self.query {
            try_extend(out, b"?")?;
            try_extend(out, q.as_bytes())?;
        }
        Ok(())
    }
}

/// Zegt of `a` en `b` dezelfde origin zijn: schema, host en poort, met de
/// standaardpoort ingevuld en zonder hoofdletterverschil.
pub(crate) fn same_origin(a: &Url<'_>, b: &Url<'_>) -> bool {
    a.scheme.eq_ignore_ascii_case(b.scheme)
        && a.hostname.eq_ignore_ascii_case(b.hostname)
        && a.effective_port() == b.effective_port()
}

/// RFC 3986 §3.1: een letter, dan letters, cijfers, `+`, `-` en `.`.
fn valid_scheme(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic())
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.')
}

/// Splitst een authority in hostnaam en poort; `[v6]` mag.
fn split_host_port(authority: &str) -> Result<(&str, Option<u16>)> {
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (inner, after) = v6.split_once(']').ok_or(Error::BadUrl)?;
        match after {
            "" => (inner, None),
            p => (inner, Some(p.strip_prefix(':').ok_or(Error::BadUrl)?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|c| c.is_ascii_digit()) => {
            Some(p.parse::<u16>().map_err(|_| Error::BadUrl)?)
        }
        Some(_) => return Err(Error::BadUrl),
    };
    Ok((host, port))
}

/// Lost `reference` (een `Location`) op tegen `base` (RFC 3986 §5.2).
pub(crate) fn resolve(base: &Url<'_>, reference: &str) -> Result<String> {
    let reference = reference.split('#').next().unwrap_or("");
    let mut out = Vec::new();
    let is_absolute = reference
        .split_once(':')
        .is_some_and(|(s, _)| valid_scheme(s) && !s.contains('/'));
    if is_absolute {
        try_extend(&mut out, reference.as_bytes())?;
    } else if let Some(rest) = reference.strip_prefix("//") {
        write!(FmtBuf(&mut out), "{}://{}", base.scheme, rest).map_err(|_| alloc_err())?;
    } else {
        write!(FmtBuf(&mut out), "{}://{}", base.scheme, base.authority)
            .map_err(|_| alloc_err())?;
        let (rpath, rquery) = match reference.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (reference, None),
        };
        if rpath.is_empty() {
            try_extend(&mut out, base.path.as_bytes())?;
            let q = if reference.is_empty() {
                base.query
            } else {
                rquery
            };
            if let Some(q) = q {
                try_extend(&mut out, b"?")?;
                try_extend(&mut out, q.as_bytes())?;
            }
        } else {
            let mut merged = Vec::new();
            if !rpath.starts_with('/') {
                let dir = base.path.rfind('/').map_or("/", |i| &base.path[..=i]);
                try_extend(&mut merged, dir.as_bytes())?;
            }
            try_extend(&mut merged, rpath.as_bytes())?;
            remove_dot_segments(&merged, &mut out)?;
            if let Some(q) = rquery {
                try_extend(&mut out, b"?")?;
                try_extend(&mut out, q.as_bytes())?;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::BadUrl)
}

fn alloc_err() -> Error {
    Error::Alloc { bytes: 0 }
}

/// RFC 3986 §5.2.4 op een pad dat met `/` begint.
fn remove_dot_segments(path: &[u8], out: &mut Vec<u8>) -> Result {
    let mut segs: Vec<&[u8]> = Vec::new();
    let mut parts = path.split(|&c| c == b'/').skip(1).peekable();
    let mut trailing = false;
    while let Some(seg) = parts.next() {
        let last = parts.peek().is_none();
        match seg {
            b"." => trailing = last,
            b".." => {
                segs.pop();
                trailing = last;
            }
            s => {
                segs.try_reserve(1).map_err(|_| alloc_err())?;
                segs.push(s);
                trailing = false;
            }
        }
    }
    for s in &segs {
        try_extend(out, b"/")?;
        try_extend(out, s)?;
    }
    if trailing || segs.is_empty() {
        try_extend(out, b"/")?;
    }
    Ok(())
}

/// Zegt of een ge-escapet pad geen escapes heeft die tot pad-structuur
/// decoderen, en geen rauwe punt-segmenten.
///
/// Een `/admin/.` of `/admin/x/..` normaliseren naar `/admin` kan de grens
/// tussen een beveiligde subtree en een publieke exacte route oversteken; een
/// `%2F` of `%2E%2E` zou middleware en de Mux het pad anders laten lezen.
pub(crate) fn clean_escapes(escaped: &str) -> bool {
    escaped.split('/').all(|seg| {
        if seg == "." || seg == ".." {
            return false;
        }
        if !seg.contains('%') {
            return true;
        }
        let mut n = 0;
        let mut dots = true;
        let mut bytes = seg.bytes();
        while let Some(c) = bytes.next() {
            let d = if c == b'%' {
                match (bytes.next().and_then(hex), bytes.next().and_then(hex)) {
                    (Some(h), Some(l)) => h << 4 | l,
                    _ => return false,
                }
            } else {
                c
            };
            if d == b'/' {
                return false;
            }
            dots &= d == b'.';
            n += 1;
        }
        !(dots && (n == 1 || n == 2))
    })
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodeert percent-escapes; een kapotte escape of geen UTF-8 is `None`.
pub(crate) fn percent_decode(s: &str, plus_is_space: bool) -> Result<Option<String>> {
    let mut out = Vec::new();
    out.try_reserve(s.len())
        .map_err(|_| Error::Alloc { bytes: s.len() })?;
    let mut bytes = s.bytes();
    while let Some(c) = bytes.next() {
        let d = match c {
            b'%' => match (bytes.next().and_then(hex), bytes.next().and_then(hex)) {
                (Some(h), Some(l)) => h << 4 | l,
                _ => return Ok(None),
            },
            b'+' if plus_is_space => b' ',
            c => c,
        };
        out.push(d);
    }
    Ok(String::from_utf8(out).ok())
}

/// Eén spelling per pad: een leidende slash, geen lege of punt-segmenten,
/// alleen een leeg laatste segment voor de wortel van een subtree.
///
/// De parser en de Mux delen dit predicaat, zodat er nooit een tweede
/// interpretatiestap is.
pub(crate) fn canonical_path(p: &str) -> bool {
    let Some(rest) = p.strip_prefix('/') else {
        return false;
    };
    let mut segs = rest.split('/').peekable();
    while let Some(seg) = segs.next() {
        if seg == "." || seg == ".." {
            return false;
        }
        if seg.is_empty() && segs.peek().is_some() {
            return false;
        }
    }
    true
}
