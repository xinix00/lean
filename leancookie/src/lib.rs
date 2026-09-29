//! Een cookie-jar (RFC 6265), host-only tenzij anders gevraagd.
//!
//! Deze crate bezit de cookies van één client: hij bewaart `Set-Cookie`-velden
//! en kiest de `Cookie`-waarden op domein, pad, vervaldatum en `Secure`,
//! zonder iets van HTTP te weten. Hij bezit ook het kleine stuk URL-parsing
//! dat de jar nodig heeft ([`Url`]): schema, host en pad. Wat hij NIET
//! bezit: de klok. Op bare metal is er geen wandklok die de crate zelf kan
//! lezen, dus de aanroeper geeft `now` mee, in Unix-seconden.
//!
//! De Go-versie verving `net/http/cookiejar`, dat `net/http` en `crypto/tls`
//! een bare-metal image in trok. Op tamago/riscv64 (12-08-2026) voegden
//! `net/http` + `crypto/tls` + een CA-bundel ongeveer 3,2 MB toe boven een
//! board-basis van 2,09 MB.
//!
//! # Bewuste grenzen
//!
//! Er is geen public suffix list: die kost honderden KiB en verandert elke
//! maand. Zonder die lijst is `a.co.uk` → `co.uk` (onveilig) niet te scheiden
//! van `sub.example.com` → `example.com` (goed). Een cookie is daarom
//! host-only; een `Domain`-attribuut wordt geweigerd en geteld in
//! [`Jar::rejected`], tenzij de aanroeper met een [`DomainPolicy`] zegt dat
//! het mag.
//!
//! SameSite hoort bij navigatiebeleid van een browser en ontbreekt, net als
//! `__Host-`/`__Secure-`-prefixen en grenzen per domein naast de totale grens
//! van de jar. Hosts worden alleen in ASCII naar kleine letters gebracht
//! (een IDN komt als punycode binnen), en het pad wordt niet
//! procent-gedecodeerd.
//!
//! # Examples
//!
//! ```
//! use leancookie::{Jar, Url};
//!
//! let now = 1_790_000_000; // Unix-seconden, van de klok van de aanroeper.
//! let mut jar = Jar::new(0);
//! let u = Url::parse("https://example.com/login")?;
//! // Na een antwoord:
//! jar.set_from(&u, ["sid=abc; Path=/; Secure"], now)?;
//! // Bij het volgende verzoek:
//! let h = jar.header(&Url::parse("https://example.com/api")?, now)?;
//! assert_eq!(h, "sid=abc");
//! # Ok::<(), leancookie::Error>(())
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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Het standaardmaximum aan cookies.
///
/// Begrenst geheugen dat een server bepaalt, en is ruim boven wat een
/// gewone browsersessie van een node gebruikt.
pub const DEFAULT_MAX: usize = 256;

/// De langste host die de jar aan een [`DomainPolicy`] voorlegt.
///
/// Een DNS-naam is hoogstens 253 tekens (RFC 1035); de kleine-letterkopie
/// voor het beleid staat op de stack, dus er is een grens.
const MAX_HOST: usize = 253;

/// Een fout uit deze crate.
///
/// Een kromme `Set-Cookie` is geen fout maar een telling (zie
/// [`Jar::rejected`]): één kapotte cookie mag geen verzoek laten falen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// De heap kon `bytes` bytes niet leveren.
    Alloc {
        /// Het gevraagde aantal bytes.
        bytes: usize,
    },
    /// De URL heeft geen geldig schema vóór `://`.
    Scheme,
    /// De URL heeft een lege of ongeldige host.
    Host,
    /// De URL heeft een poort die geen getal is.
    Port,
    /// De URL bevat een stuurteken op byte `at`.
    Control {
        /// De positie van het teken.
        at: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Alloc { bytes } => write!(f, "leancookie: cannot allocate {bytes} bytes"),
            Self::Scheme => f.write_str("leancookie: url has no valid scheme"),
            Self::Host => f.write_str("leancookie: url has an empty or invalid host"),
            Self::Port => f.write_str("leancookie: url has a non-numeric port"),
            Self::Control { at } => {
                write!(f, "leancookie: url has a control character at byte {at}")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Het resultaat van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// De delen van een URL die een cookie-jar nodig heeft.
///
/// Geen volledige URL-parser: alleen schema, host en pad. Alles leent uit de
/// ruwe string. Een aanroeper die de delen al heeft, vult de velden zelf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Url<'a> {
    /// Het schema is `https`; dan gaan ook `Secure`-cookies mee.
    pub https: bool,
    /// De host, zonder poort, gebruikersdeel of IPv6-haken.
    pub host: &'a str,
    /// Het pad, ruw (niet procent-gedecodeerd), zonder query en fragment;
    /// leeg als de URL geen pad heeft.
    pub path: &'a str,
}

impl<'a> Url<'a> {
    /// Leest schema, host en pad uit een absolute URL als
    /// `https://user@host:8443/pad?q#f`.
    pub fn parse(raw: &'a str) -> Result<Self> {
        if let Some(at) = raw.bytes().position(|c| c < 0x20 || c == 0x7f) {
            return Err(Error::Control { at });
        }
        let (scheme, rest) = raw.split_once("://").ok_or(Error::Scheme)?;
        let valid_scheme = scheme
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'));
        if !valid_scheme {
            return Err(Error::Scheme);
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at_checked(end).ok_or(Error::Host)?;
        let path = if tail.starts_with('/') {
            let stop = tail.find(['?', '#']).unwrap_or(tail.len());
            tail.get(..stop).ok_or(Error::Host)?
        } else {
            ""
        };
        Ok(Url {
            https: scheme.eq_ignore_ascii_case("https"),
            host: host_of(authority)?,
            path,
        })
    }
}

/// Haalt de host uit een authority: zonder gebruikersdeel, poort en haken.
fn host_of(authority: &str) -> Result<&str> {
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or(Error::Host)?;
        if !after.is_empty() && !after.starts_with(':') {
            return Err(Error::Host);
        }
        (host, after.get(1..).unwrap_or(""))
    } else {
        hostport.split_once(':').unwrap_or((hostport, ""))
    };
    if !port.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Port);
    }
    if host.is_empty() || host.contains(' ') {
        return Err(Error::Host);
    }
    Ok(host)
}

/// Beslist of een `Domain`-attribuut mag, en neemt daarmee de verantwoording
/// voor de public suffix over.
///
/// `host` en `domain` komen in kleine letters, zonder punt vooraan. Het
/// beleid wordt alleen gevraagd als `domain` al op een labelgrens een
/// achtervoegsel van `host` is: ook met een ruim beleid kan een server geen
/// cookies voor een andere host zetten. Een veilig eenvoudig beleid noemt de
/// domeinen die de aanroeper bezit:
///
/// ```
/// let jar = leancookie::Jar::with_policy(0, |_host: &str, domain: &str| {
///     domain == "example.com" || domain == "gethop.org"
/// });
/// # let _ = jar;
/// ```
pub trait DomainPolicy {
    /// Geeft `true` als `host` een cookie voor `domain` mag zetten.
    fn allow(&self, host: &str, domain: &str) -> bool;
}

/// Het standaardbeleid: elke cookie blijft host-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostOnly;

impl DomainPolicy for HostOnly {
    fn allow(&self, _host: &str, _domain: &str) -> bool {
        false
    }
}

impl<F: Fn(&str, &str) -> bool> DomainPolicy for F {
    fn allow(&self, host: &str, domain: &str) -> bool {
        self(host, domain)
    }
}

/// Eén bewaarde cookie.
///
/// Naam, waarde, host en pad staan achter elkaar in één `String`: één
/// allocatie per cookie in plaats van vier.
///
/// # Invariants
///
/// `text` is `name ++ value ++ host ++ path`, met `host` in ASCII-kleine
/// letters en de lengtes in `name_len`, `value_len` en `host_len`.
#[derive(Debug)]
struct Cookie {
    /// De vier delen, achter elkaar.
    text: String,
    /// De lengte van de naam.
    name_len: usize,
    /// De lengte van de waarde.
    value_len: usize,
    /// De lengte van de host.
    host_len: usize,
    /// De vervaltijd in Unix-seconden; `None` is een sessiecookie.
    expires: Option<i64>,
    /// `Domain` stond subdomeinen toe.
    subdomains: bool,
    /// Alleen over https.
    secure: bool,
}

impl Cookie {
    /// Bouwt een cookie uit een geparste regel; de enige allocatie.
    fn build(p: &Parsed<'_>) -> Result<Self> {
        let parts = [p.name, p.value, p.host, p.path];
        let len = parts.iter().map(|s| s.len()).sum();
        let mut text = String::new();
        text.try_reserve_exact(len)
            .map_err(|_| Error::Alloc { bytes: len })?;
        for s in parts {
            // De capaciteit staat al vast: dit groeit niet.
            text.push_str(s);
        }
        let host_start = p.name.len() + p.value.len();
        if let Some(h) = text.get_mut(host_start..host_start + p.host.len()) {
            h.make_ascii_lowercase();
        }
        // INVARIANT: text is de vier delen achter elkaar, host in kleine letters.
        Ok(Cookie {
            text,
            name_len: p.name.len(),
            value_len: p.value.len(),
            host_len: p.host.len(),
            expires: p.expires,
            subdomains: p.subdomains,
            secure: p.secure,
        })
    }

    /// De naam.
    fn name(&self) -> &str {
        self.text.get(..self.name_len).unwrap_or("")
    }

    /// De waarde.
    fn value(&self) -> &str {
        let start = self.name_len;
        self.text.get(start..start + self.value_len).unwrap_or("")
    }

    /// De host, in kleine letters, zonder punt vooraan.
    fn host(&self) -> &str {
        let start = self.name_len + self.value_len;
        self.text.get(start..start + self.host_len).unwrap_or("")
    }

    /// Het pad.
    fn path(&self) -> &str {
        let start = self.name_len + self.value_len + self.host_len;
        self.text.get(start..).unwrap_or("")
    }

    /// Is verlopen op `now`.
    fn is_expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|t| t <= now)
    }

    /// Hoort bij een verzoek naar `host` (ASCII, willekeurige letters).
    fn host_matches(&self, host: &str) -> bool {
        host.eq_ignore_ascii_case(self.host())
            || (self.subdomains && is_subdomain(host, self.host()))
    }

    /// Heeft dezelfde RFC-identiteit (naam, host, pad) als `p`.
    fn is_same(&self, p: &Parsed<'_>) -> bool {
        self.name() == p.name && self.host().eq_ignore_ascii_case(p.host) && self.path() == p.path
    }
}

/// Eén geparste `Set-Cookie`, nog geleend uit de regel en de URL.
#[derive(Debug)]
struct Parsed<'l> {
    /// De naam.
    name: &'l str,
    /// De waarde, zonder omringende aanhalingstekens.
    value: &'l str,
    /// De host, nog niet in kleine letters.
    host: &'l str,
    /// Het pad.
    path: &'l str,
    /// De vervaltijd in Unix-seconden.
    expires: Option<i64>,
    /// `Domain` stond subdomeinen toe.
    subdomains: bool,
    /// Alleen over https.
    secure: bool,
}

/// Een cookie-jar voor één eigenaar.
///
/// Geen slot: de Go-versie had een mutex omdat meer goroutines één jar
/// deelden; hier bezit één taak de jar en roept hem aan met `&mut`.
#[derive(Debug)]
pub struct Jar<P = HostOnly> {
    /// Het maximum aantal cookies.
    max: usize,
    /// De cookies, stabiel gesorteerd op padlengte, langste eerst.
    ///
    /// RFC 6265 §5.4 wil de langste paden eerst in de `Cookie`-header, en
    /// bij gelijke lengte de volgorde van aanmaken. Door de lijst zo te
    /// houden, hoeft [`Jar::header`] niets te sorteren of te verzamelen.
    list: Vec<Cookie>,
    /// Het aantal geweigerde cookies.
    rejected: u64,
    /// Het beleid voor `Domain`.
    policy: P,
}

impl Jar<HostOnly> {
    /// Maakt een host-only jar; `max == 0` kiest [`DEFAULT_MAX`].
    ///
    /// Alloceert nog niets: de lijst groeit per cookie, faalbaar, tot `max`.
    pub fn new(max: usize) -> Self {
        Self::with_policy(max, HostOnly)
    }
}

impl<P: DomainPolicy> Jar<P> {
    /// Maakt een jar die `Domain`-attributen aan `policy` voorlegt; `max == 0`
    /// kiest [`DEFAULT_MAX`].
    pub fn with_policy(max: usize, policy: P) -> Self {
        Jar {
            max: if max == 0 { DEFAULT_MAX } else { max },
            list: Vec::new(),
            rejected: 0,
            policy,
        }
    }

    /// Het aantal bewaarde cookies.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Er is geen enkele cookie bewaard.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Het aantal geweigerde cookies: krom, verboden domein, al verlopen, of
    /// boven het maximum.
    ///
    /// Zonder deze teller is een mislukte login stil.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Verwerkt de `Set-Cookie`-velden van één antwoord van `url`.
    ///
    /// Een onbruikbaar veld wordt geteld, niet teruggegeven. Alleen een
    /// allocatie die faalt is een fout; de velden daarna worden dan niet
    /// meer verwerkt.
    pub fn set_from<'l, I>(&mut self, url: &Url<'_>, lines: I, now: i64) -> Result
    where
        I: IntoIterator<Item = &'l str>,
    {
        for line in lines {
            match self.parse(line, url, now) {
                Some(p) => self.store(&p, now)?,
                None => self.reject(),
            }
        }
        Ok(())
    }

    /// Geeft het `Cookie`-veld voor `url`, of een lege string als er geen
    /// cookie geldt.
    ///
    /// Verlopen cookies worden onderweg opgeruimd. De langste paden komen
    /// eerst (RFC 6265 §5.4).
    pub fn header(&mut self, url: &Url<'_>, now: i64) -> Result<String> {
        self.list.retain(|c| !c.is_expired(now));
        let path = if url.path.is_empty() { "/" } else { url.path };
        let hits = || {
            self.list.iter().filter(move |c| {
                (!c.secure || url.https) && c.host_matches(url.host) && path_matches(path, c.path())
            })
        };
        let mut len = 0usize;
        for (i, c) in hits().enumerate() {
            let sep = if i > 0 { 2 } else { 0 };
            len = len.saturating_add(sep + c.name().len() + 1 + c.value().len());
        }
        let mut out = String::new();
        out.try_reserve_exact(len)
            .map_err(|_| Error::Alloc { bytes: len })?;
        for (i, c) in hits().enumerate() {
            if i > 0 {
                out.push_str("; ");
            }
            out.push_str(c.name());
            out.push('=');
            out.push_str(c.value());
        }
        Ok(out)
    }

    /// Telt één geweigerde cookie.
    fn reject(&mut self) {
        self.rejected = self.rejected.saturating_add(1);
    }

    /// Voegt toe of vervangt op de RFC-identiteit (naam, host, pad).
    fn store(&mut self, p: &Parsed<'_>, now: i64) -> Result {
        let expired = p.expires.is_some_and(|t| t <= now);
        if let Some(i) = self.list.iter().position(|c| c.is_same(p)) {
            if p.value.is_empty() && expired {
                // Verlopen zonder waarde is de manier om te wissen.
                self.list.remove(i);
                return Ok(());
            }
            // Eerst bouwen, dan wisselen: faalt de allocatie, dan staat de
            // oude cookie er nog. Zelfde pad, dus de volgorde blijft goed.
            let c = Cookie::build(p)?;
            if let Some(slot) = self.list.get_mut(i) {
                *slot = c;
            }
            return Ok(());
        }
        // Een onbekende cookie die al verlopen is, wist niets.
        if expired || self.list.len() >= self.max {
            self.reject();
            return Ok(());
        }
        self.list.try_reserve(1).map_err(|_| Error::Alloc {
            bytes: core::mem::size_of::<Cookie>(),
        })?;
        let c = Cookie::build(p)?;
        // Na alle cookies met een even lang of langer pad: stabiel.
        let at = self
            .list
            .iter()
            .position(|o| o.path().len() < p.path.len())
            .unwrap_or(self.list.len());
        self.list.insert(at, c);
        Ok(())
    }

    /// Leest één `Set-Cookie`-veld tegen de URL waar het vandaan kwam.
    fn parse<'l>(&self, line: &'l str, url: &Url<'l>, now: i64) -> Option<Parsed<'l>> {
        let (first, mut rest) = line.split_once(';').unwrap_or((line, ""));
        let (name, value) = first.split_once('=')?;
        let name = name.trim();
        let mut value = value.trim();
        if name.is_empty() || name.contains([' ', '\t', '\r', '\n', ';']) {
            return None;
        }
        // Aanhalingstekens eromheen begrenzen de waarde; ze horen er niet bij.
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = value.get(1..value.len() - 1)?;
        }
        if value.contains(['\r', '\n', ';']) {
            return None;
        }

        let mut c = Parsed {
            name,
            value,
            host: url.host,
            path: default_path(url.path),
            expires: None,
            subdomains: false,
            secure: false,
        };
        let mut max_age = false;
        while !rest.is_empty() {
            let (attr, next) = rest.split_once(';').unwrap_or((rest, ""));
            rest = next;
            let (k, v) = attr.split_once('=').unwrap_or((attr, ""));
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("path") {
                if v.starts_with('/') {
                    c.path = v;
                }
            } else if k.eq_ignore_ascii_case("domain") {
                let d = v.strip_prefix('.').unwrap_or(v);
                if !self.domain_ok(url.host, d) {
                    return None; // Host-only, tenzij het beleid het toestaat.
                }
                c.host = d;
                c.subdomains = true;
            } else if k.eq_ignore_ascii_case("expires") {
                if let Some(t) = parse_time(v).filter(|_| !max_age) {
                    c.expires = Some(t);
                }
            } else if k.eq_ignore_ascii_case("max-age") {
                // Max-Age wint van Expires (RFC 6265 §5.3 stap 3).
                if let Ok(n) = v.parse::<i64>() {
                    max_age = true;
                    c.expires = Some(if n <= 0 {
                        now.saturating_sub(1)
                    } else {
                        now.saturating_add(n)
                    });
                }
            } else if k.eq_ignore_ascii_case("secure") {
                c.secure = true;
            }
        }
        Some(c)
    }

    /// Accepteert de host zelf; anders een achtervoegsel op een labelgrens
    /// plus instemming van het beleid.
    ///
    /// Zo kan een server nooit de cookies van een andere host zetten, ook
    /// niet met een ruim beleid.
    fn domain_ok(&self, host: &str, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        if domain.eq_ignore_ascii_case(host) {
            return true; // Domain = de bronhost blijft veilig.
        }
        if !is_subdomain(host, domain) {
            return false; // Nooit over een labelgrens heen.
        }
        let mut hbuf = [0u8; MAX_HOST];
        let mut dbuf = [0u8; MAX_HOST];
        match (lower(host, &mut hbuf), lower(domain, &mut dbuf)) {
            (Some(h), Some(d)) => self.policy.allow(h, d),
            _ => false, // Langer dan een DNS-naam kan zijn.
        }
    }
}

/// Kopieert `s` in kleine ASCII-letters naar `buf`; `None` als het niet past.
fn lower<'b>(s: &str, buf: &'b mut [u8; MAX_HOST]) -> Option<&'b str> {
    let out = buf.get_mut(..s.len())?;
    out.copy_from_slice(s.as_bytes());
    out.make_ascii_lowercase();
    core::str::from_utf8(out).ok()
}

/// `host` eindigt op `.` + `domain`, zonder op hoofdletters te letten.
fn is_subdomain(host: &str, domain: &str) -> bool {
    let (h, d) = (host.as_bytes(), domain.as_bytes());
    let Some(dot) = h.len().checked_sub(d.len() + 1) else {
        return false;
    };
    h.get(dot) == Some(&b'.') && h.get(dot + 1..).is_some_and(|t| t.eq_ignore_ascii_case(d))
}

/// Het padregel van RFC 6265 §5.1.4: gelijk, of een voorvoegsel dat op `/`
/// eindigt of waar een `/` op volgt.
fn path_matches(path: &str, cookie_path: &str) -> bool {
    if path == cookie_path {
        return true;
    }
    if !path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// De map van het verzoekpad (RFC 6265 §5.1.4).
fn default_path(path: &str) -> &str {
    if !path.starts_with('/') {
        return "/";
    }
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => path.get(..i).unwrap_or("/"),
    }
}

/// Leest de datumvormen van een server: RFC 1123, RFC 850 en asctime (RFC
/// 2616 §3.3.1), als Unix-seconden.
///
/// De zone is een afkorting van drie tot vijf hoofdletters en telt als UTC,
/// zoals Go's `time.Parse` een onbekende afkorting ook op nul zet; een
/// server hoort `GMT` te sturen.
fn parse_time(v: &str) -> Option<i64> {
    rfc1123(v, b' ')
        .or_else(|| rfc1123(v, b'-'))
        .or_else(|| rfc850(v))
        .or_else(|| asctime(v))
}

/// `Mon, 02 Jan 2006 15:04:05 GMT`, of met `-` tussen dag, maand en jaar.
fn rfc1123(v: &str, sep: u8) -> Option<i64> {
    let mut c = Cursor(v.as_bytes());
    c.weekday(false)?;
    c.lit(b", ")?;
    let day = c.digits(2, 2)?;
    c.lit(&[sep])?;
    let month = c.month()?;
    c.lit(&[sep])?;
    let year = c.digits(4, 4)?;
    c.lit(b" ")?;
    let (h, m, s) = c.clock()?;
    c.lit(b" ")?;
    c.zone()?;
    c.end()?;
    civil_seconds(i64::from(year), month, day, h, m, s)
}

/// `Monday, 02-Jan-06 15:04:05 GMT`; een jaar van twee cijfers is
/// 1969..=2068, zoals in Go.
fn rfc850(v: &str) -> Option<i64> {
    let mut c = Cursor(v.as_bytes());
    c.weekday(true)?;
    c.lit(b", ")?;
    let day = c.digits(2, 2)?;
    c.lit(b"-")?;
    let month = c.month()?;
    c.lit(b"-")?;
    let yy = c.digits(2, 2)?;
    let year = if yy >= 69 { 1900 + yy } else { 2000 + yy };
    c.lit(b" ")?;
    let (h, m, s) = c.clock()?;
    c.lit(b" ")?;
    c.zone()?;
    c.end()?;
    civil_seconds(i64::from(year), month, day, h, m, s)
}

/// `Mon Jan  2 15:04:05 2006`: de dag met een spatie aangevuld.
fn asctime(v: &str) -> Option<i64> {
    let mut c = Cursor(v.as_bytes());
    c.weekday(false)?;
    c.lit(b" ")?;
    let month = c.month()?;
    c.lit(b" ")?;
    // Go's `_2`: één aanvullende spatie mag, dan één of twee cijfers.
    let _ = c.lit(b" ");
    let day = c.digits(1, 2)?;
    c.lit(b" ")?;
    let (h, m, s) = c.clock()?;
    c.lit(b" ")?;
    let year = c.digits(4, 4)?;
    c.end()?;
    civil_seconds(i64::from(year), month, day, h, m, s)
}

/// Een lezer over de bytes van een datum.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    /// Slikt precies `t`.
    fn lit(&mut self, t: &[u8]) -> Option<()> {
        self.0 = self.0.strip_prefix(t)?;
        Some(())
    }

    /// Leest `min..=max` cijfers.
    fn digits(&mut self, min: usize, max: usize) -> Option<u32> {
        let n = self
            .0
            .iter()
            .take(max)
            .take_while(|c| c.is_ascii_digit())
            .count();
        if n < min {
            return None;
        }
        let (d, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(d.iter().fold(0, |acc, &c| acc * 10 + u32::from(c - b'0')))
    }

    /// Leest een rij letters.
    fn word(&mut self) -> &[u8] {
        let n = self
            .0
            .iter()
            .take_while(|c| c.is_ascii_alphabetic())
            .count();
        let (w, rest) = self.0.split_at(n.min(self.0.len()));
        self.0 = rest;
        w
    }

    /// Leest een weekdag, kort (`Mon`) of lang (`Monday`).
    fn weekday(&mut self, long: bool) -> Option<()> {
        const DAYS: [&str; 7] = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ];
        let w = self.word();
        DAYS.iter()
            .any(|d| {
                let want = if long {
                    Some(d.as_bytes())
                } else {
                    d.as_bytes().get(..3)
                };
                want.is_some_and(|want| w.eq_ignore_ascii_case(want))
            })
            .then_some(())
    }

    /// Leest een maand (`Jan`) als 1..=12.
    fn month(&mut self) -> Option<u32> {
        const MONTHS: [&[u8]; 12] = [
            b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
            b"Dec",
        ];
        let w = self.word();
        let i = MONTHS.iter().position(|m| w.eq_ignore_ascii_case(m))?;
        u32::try_from(i + 1).ok()
    }

    /// Leest `15:04:05`.
    fn clock(&mut self) -> Option<(u32, u32, u32)> {
        let h = self.digits(1, 2)?;
        self.lit(b":")?;
        let m = self.digits(2, 2)?;
        self.lit(b":")?;
        let s = self.digits(2, 2)?;
        Some((h, m, s))
    }

    /// Leest een zone-afkorting van drie tot vijf hoofdletters.
    fn zone(&mut self) -> Option<()> {
        let w = self.word();
        ((3..=5).contains(&w.len()) && w.iter().all(u8::is_ascii_uppercase)).then_some(())
    }

    /// Alles is gelezen.
    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

/// Zet een UTC-datum om naar Unix-seconden, met de bereiken getoetst.
fn civil_seconds(year: i64, month: u32, day: u32, h: u32, m: u32, s: u32) -> Option<i64> {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days_in || h > 23 || m > 59 || s > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + i64::from(h * 3600 + m * 60 + s))
}

/// Het aantal dagen sinds 1970-01-01 voor een proleptisch-gregoriaanse
/// datum (het algoritme van Howard Hinnant).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Een vaste "nu": 2026-09-21 02:13:20 UTC.
    const NOW: i64 = 1_790_000_000;

    fn url(raw: &str) -> Url<'_> {
        Url::parse(raw).unwrap()
    }

    fn header<P: DomainPolicy>(j: &mut Jar<P>, raw: &str) -> String {
        j.header(&url(raw), NOW).unwrap()
    }

    fn set<P: DomainPolicy>(j: &mut Jar<P>, raw: &str, lines: &[&str]) {
        j.set_from(&url(raw), lines.iter().copied(), NOW).unwrap();
    }

    /// Formatteert Unix-seconden in een van de drie Go-layouts uit de test.
    fn format(t: i64, layout: usize) -> String {
        const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let days = t.div_euclid(86_400);
        let secs = t.rem_euclid(86_400);
        let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
        // Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mo = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(mo <= 2);
        let wd = DAYS[days.rem_euclid(7) as usize];
        let mn = MONTHS[(mo - 1) as usize];
        match layout {
            0 => format!("{wd}, {d:02} {mn} {y} {h:02}:{m:02}:{s:02} GMT"),
            1 => format!("{wd}, {d:02}-{mn}-{y} {h:02}:{m:02}:{s:02} GMT"),
            _ => format!("{wd} {mn} {d:>2} {h:02}:{m:02}:{s:02} {y}"),
        }
    }

    #[test]
    fn test_zetten_en_terugsturen() {
        let mut j = Jar::new(0);
        set(
            &mut j,
            "http://example.com/app/page",
            &["sid=abc123; Path=/", "theme=dark; Path=/app"],
        );
        assert_eq!(
            header(&mut j, "http://example.com/app/other"),
            "theme=dark; sid=abc123"
        );
        assert_eq!(
            header(&mut j, "http://example.com/elders"),
            "sid=abc123",
            "buiten /app"
        );
    }

    #[test]
    fn test_pad_regels() {
        let mut j = Jar::new(0);
        set(&mut j, "http://example.com/a/b/page", &["x=1"]);
        for (path, want) in [
            ("/a/b/page", "x=1"),
            ("/a/b/", "x=1"),
            ("/a/b", "x=1"),
            ("/a/bc", ""),
            ("/a", ""),
        ] {
            let got = header(&mut j, &format!("http://example.com{path}"));
            assert_eq!(got, want, "pad {path}");
        }
    }

    #[test]
    fn test_domain_default_is_host_only() {
        for (host, domain, ok) in [
            ("example.com", "example.com", true),
            ("sub.example.com", "example.com", false),
            ("a.co.uk", "co.uk", false),
            ("example.com", "com", false),
            ("example.com", "other.com", false),
            ("example.com", "ample.com", false),
        ] {
            let mut j = Jar::new(0);
            set(
                &mut j,
                &format!("http://{host}/"),
                &[&format!("x=1; Domain={domain}")],
            );
            assert_eq!(j.len() == 1, ok, "host {host} + Domain={domain}");
            if !ok {
                assert_ne!(
                    j.rejected(),
                    0,
                    "host {host} + Domain={domain}: geweigerd maar niet geteld"
                );
            }
        }
    }

    #[test]
    fn test_allow_domain_hook() {
        let all = |_: &str, _: &str| true;

        let mut j = Jar::with_policy(0, all);
        set(
            &mut j,
            "http://www.example.com/",
            &["a=1; Domain=example.com"],
        );
        assert_eq!(
            header(&mut j, "http://api.example.com/"),
            "a=1",
            "met hook, op het subdomein"
        );

        for d in ["other.com", "ample.com"] {
            let mut j2 = Jar::with_policy(0, all);
            set(
                &mut j2,
                "http://www.example.com/",
                &[&format!("x=1; Domain={d}")],
            );
            assert_eq!(
                j2.len(),
                0,
                "Domain={d} werd toegestaan ondanks de labelgrens-regel"
            );
        }

        let mut j3 = Jar::with_policy(0, |_: &str, domain: &str| domain == "gethop.org");
        set(
            &mut j3,
            "http://www.gethop.org/",
            &["a=1; Domain=gethop.org"],
        );
        set(&mut j3, "http://a.co.uk/", &["b=2; Domain=co.uk"]);
        assert_eq!(j3.len(), 1, "alleen het eigen domein");
    }

    #[test]
    fn test_subdomein_bereik() {
        let mut j = Jar::with_policy(0, |_: &str, domain: &str| domain == "example.com");
        set(
            &mut j,
            "http://www.example.com/",
            &["a=1; Domain=example.com", "b=2"],
        );
        assert_eq!(
            header(&mut j, "http://api.example.com/"),
            "a=1",
            "api-subdomein"
        );
        let own = header(&mut j, "http://www.example.com/");
        assert!(
            own.contains("a=1") && own.contains("b=2"),
            "eigen host: {own:?}"
        );
        assert_eq!(header(&mut j, "http://example.org/"), "", "ander domein");
    }

    #[test]
    fn test_secure() {
        let mut j = Jar::new(0);
        set(&mut j, "https://example.com/", &["s=1; Secure", "p=2"]);
        assert_eq!(
            header(&mut j, "http://example.com/"),
            "p=2",
            "een Secure-cookie mag niet over http"
        );
        assert!(header(&mut j, "https://example.com/").contains("s=1"));
    }

    #[test]
    fn test_verval_en_verwijderen() {
        let mut j = Jar::new(0);
        let u = "http://example.com/";
        set(&mut j, u, &["a=1; Max-Age=3600", "b=2; Max-Age=0", "c=3"]);
        let got = header(&mut j, u);
        assert!(!got.contains("b=2"), "Max-Age=0 werd bewaard: {got:?}");
        assert!(
            got.contains("a=1") && got.contains("c=3"),
            "Cookie = {got:?}"
        );

        set(&mut j, u, &["a=1; Expires=Mon, 02 Jan 2006 15:04:05 GMT"]);
        let got = header(&mut j, u);
        assert!(!got.contains("a=1"), "verlopen cookie leeft nog: {got:?}");

        set(
            &mut j,
            u,
            &["d=4; Expires=Mon, 02 Jan 2006 15:04:05 GMT; Max-Age=600"],
        );
        let got = header(&mut j, u);
        assert!(got.contains("d=4"), "Max-Age verloor van Expires: {got:?}");

        // En de tijd loopt: na 600 seconden is d weg.
        let later = j.header(&url(u), NOW + 600).unwrap();
        assert!(!later.contains("d=4"), "{later:?}");
    }

    #[test]
    fn test_expires_vormen() {
        let future = NOW + 24 * 3600;
        for layout in 0..3 {
            let mut j = Jar::new(0);
            let u = "http://example.com/";
            let date = format(future, layout);
            set(&mut j, u, &[&format!("x=1; Expires={date}")]);
            assert_ne!(
                header(&mut j, u),
                "",
                "datumvorm {date:?} werd niet begrepen"
            );
            assert_eq!(parse_time(&date), Some(future), "{date:?}");
        }
    }

    #[test]
    fn test_overschrijven() {
        let mut j = Jar::new(0);
        let u = "http://example.com/";
        set(&mut j, u, &["sid=oud"]);
        set(&mut j, u, &["sid=nieuw"]);
        assert_eq!(
            header(&mut j, u),
            "sid=nieuw",
            "een tweede login moet de eerste vervangen"
        );
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn test_kromme_regels() {
        let mut j = Jar::new(0);
        set(
            &mut j,
            "http://example.com/",
            &[
                "",
                "geenisgelijkteken",
                "=leeg",
                "na me=1",
                "x=met\nnieuweregel",
            ],
        );
        assert_eq!(j.len(), 0, "kromme regels opgeslagen");
        assert_eq!(j.rejected(), 5, "geweigerde regels moeten zichtbaar zijn");
    }

    #[test]
    fn test_quoted_value() {
        let mut j = Jar::new(0);
        set(&mut j, "http://example.com/", &[r#"x="met spaties""#]);
        assert_eq!(header(&mut j, "http://example.com/"), "x=met spaties");
    }

    #[test]
    fn test_max_cookies() {
        let mut j = Jar::new(2);
        set(&mut j, "http://example.com/", &["a=1", "b=2", "c=3"]);
        assert_eq!(j.len(), 2);
        assert_eq!(j.rejected(), 1);
    }

    // Go toetste hier dat net/http en crypto/tls niet in de import-graaf
    // zaten. In Rust zegt Cargo.toml dat (geen dependencies) en bewijst de
    // no_std-build het; de test houdt het basisgeval.
    #[test]
    fn test_geen_net_http() {
        let mut j = Jar::new(0);
        set(&mut j, "http://example.com/", &["x=1"]);
        assert_eq!(
            header(&mut j, "http://example.com/"),
            "x=1",
            "basisgeval werkt niet"
        );
    }

    #[test]
    fn test_url_delen() {
        let u = url("HTTPS://user:pw@Example.COM:8443/a/b?q=1#f");
        assert_eq!(
            u,
            Url {
                https: true,
                host: "Example.COM",
                path: "/a/b"
            }
        );
        assert_eq!(url("http://[::1]:80/x").host, "::1");
        assert_eq!(url("http://example.com").path, "");
        assert_eq!(url("http://example.com?x=/y").path, "");
        assert_eq!(Url::parse("example.com/x"), Err(Error::Scheme));
        assert_eq!(Url::parse("http:///x"), Err(Error::Host));
        assert_eq!(Url::parse("http://h:8o/"), Err(Error::Port));
        assert_eq!(Url::parse("http://h/\n"), Err(Error::Control { at: 9 }));
    }

    #[test]
    fn test_host_hoofdletters() {
        // Hoofdletters in de URL-host maken geen andere cookie.
        let mut j = Jar::new(0);
        set(&mut j, "http://Example.com/", &["a=1"]);
        set(&mut j, "http://EXAMPLE.com/", &["a=2"]);
        assert_eq!(j.len(), 1);
        assert_eq!(header(&mut j, "http://example.COM/"), "a=2");
    }

    #[test]
    fn test_kromme_datums() {
        for v in [
            "",
            "Mon, 32 Jan 2026 00:00:00 GMT",
            "Mon, 29 Feb 2026 00:00:00 GMT",
            "Mon, 01 Jan 2026 24:00:00 GMT",
            "Mon, 01 Foo 2026 00:00:00 GMT",
            "Xyz, 01 Jan 2026 00:00:00 GMT",
            "Mon, 01 Jan 2026 00:00:00 gmt",
            "Mon, 01 Jan 2026 00:00:00 GMT extra",
        ] {
            assert_eq!(parse_time(v), None, "{v:?}");
        }
        assert_eq!(parse_time("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_time("Thursday, 01-Jan-70 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_time("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(parse_time("Sun Nov  6 08:49:37 1994"), Some(784_111_777));
        assert_eq!(
            parse_time("Tue, 29 Feb 2028 00:00:00 GMT"),
            Some(1_835_395_200)
        );
    }
}
