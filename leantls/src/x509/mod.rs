//! Ketenverificatie voor de Web-PKI: de Rust-vorm van Go's `x509verify`.
//!
//! [`ChainVerifier`] implementeert [`VerifyPeer`], zodat
//! `Trust::Chain(&verifier)` een publieke HTTPS-server kan toetsen. Hij bezit
//! niets: de wortels ([`Roots`]) en de tijd komen van de aanroeper. Er is
//! geen ingebakken bundel en geen klok, omdat een node zonder NTP anders
//! stil in 1970 zou toetsen en een ingebakken bundel stil zou verouderen.
//!
//! Wat hij toetst, in deze volgorde:
//!
//! 1. de DNS-naam of het IP-adres staat in de bijbehorende tag van de
//!    SubjectAltName van het blad, wildcard alleen links (zie `name`);
//! 2. elk certificaat is strikte DER en het blad heeft een sleutel die hier
//!    bestaat (P-256, P-384, RSA 2048-4096, Ed25519);
//! 3. een pad van het blad naar een van de wortels: issuer gelijk aan
//!    subject, AuthorityKeyIdentifier gelijk aan SubjectKeyIdentifier als
//!    beide er zijn, en per schakel de handtekening;
//! 4. per certificaat op het pad: geldig op `now`, geen onverwerkte kritieke
//!    extensie, ExtendedKeyUsage (als aanwezig) staat serverAuth toe;
//! 5. per CA: BasicConstraints `cA`, KeyUsage keyCertSign (als aanwezig),
//!    en pathLenConstraint.
//!
//! De server bepaalt de volgorde van zijn keten niet: de certificaten na het
//! blad zijn kandidaten, en het pad wordt gezocht (met terugkrabbelen voor
//! kruiselings ondertekende CA's), net als in Go.
//!
//! Wat hij níet doet: intrekking (CRL, OCSP), Certificate Transparency,
//! NameConstraints (een CA die ze draagt wordt geweigerd), beleid
//! (certificatePolicies), RSA-PSS ín certificaten, P-521, en een terugval
//! op de CommonName.

mod cert;
mod der;
mod name;

#[cfg(test)]
mod tests;

use core::fmt;

use crate::crypto::{ecdsa, ed25519, hash::HashAlg, rsa};
use crate::error::{Error, Result};
use crate::trust::{CertChain, VerifyPeer};
use cert::{Cert, PublicKey, SigAlg, key_usage};

/// Meeste certificaten die een server mag sturen. Echte ketens zijn 2 tot 4
/// lang (GitHub stuurt er 3); 8 laat ruimte voor kruis-ondertekening en
/// begrenst het zoekwerk. De lijst van wie meer stuurt, wordt geweigerd in
/// plaats van afgekapt: een stille afkapping zou een ander pad kunnen kiezen.
pub const MAX_CHAIN: usize = 8;

/// Langste pad, blad en wortel meegeteld. Publieke paden zijn hooguit 4
/// (blad, twee tussen-CA's, wortel); 6 laat een extra kruisschakel toe en
/// begrenst de recursie van de padzoeker.
pub const MAX_DEPTH: usize = 6;

/// Meeste wortels. De Mozilla-set heeft er ongeveer 150; 1024 is ruim en
/// houdt het zoeken naar een issuer lineair en klein.
pub const MAX_ROOTS: usize = 1024;

/// Meeste handtekeningcontroles per keten. Een kwaadwillige server kan veel
/// kandidaten met dezelfde naam sturen; Go begrenst dit op 100. Met
/// [`MAX_CHAIN`] van 8 is 32 genoeg voor elk echt pad met terugkrabbelen.
pub const MAX_SIGNATURE_CHECKS: usize = 32;

/// De TLS 1.3-handtekeningcodes (RFC 8446 §4.2.3) die [`ChainVerifier`]
/// kan controleren, goedkoopste eerst. De server kiest hieruit.
///
/// PKCS#1 v1.5 staat er niet in: TLS 1.3 verbiedt het in CertificateVerify.
/// In certificaten zelf wordt het wel geaccepteerd.
pub const SIGNATURE_ALGORITHMS: [u16; 6] = [
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    crate::handshake::SIG_ED25519,
];

/// ecdsa_secp256r1_sha256.
const ECDSA_P256_SHA256: u16 = 0x0403;
/// ecdsa_secp384r1_sha384.
const ECDSA_P384_SHA384: u16 = 0x0503;
/// rsa_pss_rsae_sha256.
const RSA_PSS_SHA256: u16 = 0x0804;
/// rsa_pss_rsae_sha384.
const RSA_PSS_SHA384: u16 = 0x0805;
/// rsa_pss_rsae_sha512.
const RSA_PSS_SHA512: u16 = 0x0806;

/// Welk certificaat een fout betreft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRef {
    /// Plaats in de keten van de server; 0 is het blad.
    Chain(u8),
    /// Plaats in de [`Roots`].
    Root(u16),
}

impl fmt::Display for CertRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CertRef::Chain(i) => write!(f, "certificate {i}"),
            CertRef::Root(i) => write!(f, "root {i}"),
        }
    }
}

/// Waarom een keten of een wortelset geweigerd werd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum X509Error {
    /// Geen geldige X.509-DER; `field` noemt het veld.
    Malformed {
        /// Welk certificaat.
        cert: CertRef,
        /// Het veld dat niet klopte.
        field: &'static str,
    },
    /// Een sleutel of algoritme dat deze verifier niet heeft.
    Unsupported {
        /// Welk certificaat.
        cert: CertRef,
        /// Wat er ontbreekt.
        what: &'static str,
    },
    /// De server stuurde meer certificaten dan [`MAX_CHAIN`].
    TooManyCertificates(usize),
    /// Meer wortels dan [`MAX_ROOTS`], of geen enkele.
    RootCount(usize),
    /// Een IP-achtig adres heeft geen geldige binaire vorm.
    IpAddress,
    /// De servernaam is geen geldige DNS-naam.
    ServerName,
    /// De naam staat niet in de SubjectAltName van het blad.
    NameMismatch {
        /// Aantal DNS-namen in het blad.
        dns_names: usize,
    },
    /// Verlopen op `now`.
    Expired {
        /// Welk certificaat.
        cert: CertRef,
        /// notAfter, seconden sinds 1970.
        not_after: i64,
        /// De tijd van de toets.
        now: i64,
    },
    /// Nog niet geldig op `now`.
    NotYetValid {
        /// Welk certificaat.
        cert: CertRef,
        /// notBefore, seconden sinds 1970.
        not_before: i64,
        /// De tijd van de toets.
        now: i64,
    },
    /// Geen pad naar een van de wortels.
    UnknownAuthority,
    /// Een handtekening in de keten klopt niet.
    BadCertSignature {
        /// Het ondertekende certificaat.
        cert: CertRef,
    },
    /// Een uitgever is geen CA (BasicConstraints).
    NotCa {
        /// De uitgever.
        cert: CertRef,
    },
    /// Een uitgever mag geen certificaten tekenen (KeyUsage).
    NoCertSign {
        /// De uitgever.
        cert: CertRef,
    },
    /// Het pad is langer dan de pathLenConstraint van een CA toestaat.
    PathLen {
        /// De CA.
        cert: CertRef,
        /// Zijn pathLenConstraint.
        max: u32,
    },
    /// ExtendedKeyUsage staat serverAuth niet toe.
    ExtKeyUsage {
        /// Welk certificaat.
        cert: CertRef,
    },
    /// Het blad mag niet tekenen (KeyUsage zonder digitalSignature).
    LeafKeyUsage,
    /// Een kritieke extensie die hier niet verwerkt wordt, of NameConstraints.
    Unhandled {
        /// Welk certificaat.
        cert: CertRef,
    },
    /// Geen pad binnen [`MAX_DEPTH`] of [`MAX_SIGNATURE_CHECKS`].
    Limit(&'static str),
    /// De gekozen CertificateVerify-code past niet bij de sleutel van het blad.
    KeyMismatch(u16),
    /// De server koos een code die [`SIGNATURE_ALGORITHMS`] niet aanbiedt.
    Algorithm(u16),
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            X509Error::Malformed { cert, field } => write!(f, "{cert}: malformed {field}"),
            X509Error::Unsupported { cert, what } => write!(f, "{cert}: unsupported {what}"),
            X509Error::TooManyCertificates(n) => {
                write!(f, "server sent {n} certificates, limit is {MAX_CHAIN}")
            }
            X509Error::RootCount(n) => {
                write!(f, "{n} roots; need between 1 and {MAX_ROOTS}")
            }
            X509Error::IpAddress => f.write_str("invalid IP address in certificate validation"),
            X509Error::ServerName => f.write_str("server name is not a valid DNS name"),
            X509Error::NameMismatch { dns_names } => write!(
                f,
                "certificate is not valid for the requested name ({dns_names} DNS names in \
                 SubjectAltName)"
            ),
            X509Error::Expired {
                cert,
                not_after,
                now,
            } => write!(
                f,
                "{cert} has expired (notAfter {not_after}, now {now}, seconds since 1970)"
            ),
            X509Error::NotYetValid {
                cert,
                not_before,
                now,
            } => write!(
                f,
                "{cert} is not yet valid (notBefore {not_before}, now {now}, seconds since 1970)"
            ),
            X509Error::UnknownAuthority => f.write_str("certificate signed by unknown authority"),
            X509Error::BadCertSignature { cert } => {
                write!(f, "{cert}: signature by its issuer is invalid")
            }
            X509Error::NotCa { cert } => write!(f, "{cert} is not a CA (basicConstraints)"),
            X509Error::NoCertSign { cert } => {
                write!(
                    f,
                    "{cert} may not sign certificates (keyUsage without keyCertSign)"
                )
            }
            X509Error::PathLen { cert, max } => {
                write!(f, "{cert}: path longer than its pathLenConstraint {max}")
            }
            X509Error::ExtKeyUsage { cert } => {
                write!(f, "{cert}: extKeyUsage does not allow serverAuth")
            }
            X509Error::LeafKeyUsage => {
                f.write_str("certificate 0: keyUsage without digitalSignature")
            }
            X509Error::Unhandled { cert } => {
                write!(f, "{cert}: unhandled critical extension or nameConstraints")
            }
            X509Error::Limit(what) => write!(f, "no path within the {what} limit"),
            X509Error::KeyMismatch(alg) => write!(
                f,
                "server chose signature algorithm {alg:#06x}, which does not match the key in \
                 its certificate"
            ),
            X509Error::Algorithm(alg) => write!(
                f,
                "server chose signature algorithm {alg:#06x}, which this verifier does not offer"
            ),
        }
    }
}

impl From<X509Error> for Error {
    fn from(e: X509Error) -> Self {
        Error::X509(e)
    }
}

/// De vertrouwde wortels, als DER van de aanroeper. Geleend, niet gekopieerd.
///
/// Elke wortel is bij het aanmaken één keer volledig gelezen; een
/// misvormde wortel is een fout met zijn nummer, geen stille overslag.
#[derive(Debug, Clone, Copy)]
pub struct Roots<'a> {
    /// Waar de DER staat.
    src: RootSource<'a>,
    /// Aantal wortels.
    len: usize,
}

/// De twee vormen waarin een aanroeper wortels heeft.
#[derive(Debug, Clone, Copy)]
enum RootSource<'a> {
    /// Certificaten direct achter elkaar, zoals `include_bytes!` van een
    /// bestand met aaneengeschakelde DER.
    Concat(&'a [u8]),
    /// Losse certificaten.
    List(&'a [&'a [u8]]),
}

impl<'a> Roots<'a> {
    /// Wortels uit aaneengeschakelde DER-certificaten.
    pub fn from_concatenated_der(bytes: &'a [u8]) -> Result<Self> {
        Self::checked(RootSource::Concat(bytes))
    }

    /// Wortels uit een lijst van DER-certificaten.
    pub fn from_list(list: &'a [&'a [u8]]) -> Result<Self> {
        Self::checked(RootSource::List(list))
    }

    /// Leest elke wortel één keer en telt ze.
    fn checked(src: RootSource<'a>) -> Result<Self> {
        let mut roots = Self { src, len: 0 };
        for (i, der) in roots.iter_raw().enumerate() {
            let cert = CertRef::Root(u16::try_from(i).unwrap_or(u16::MAX));
            let der = der.map_err(|field| X509Error::Malformed { cert, field })?;
            Cert::parse(der).map_err(|field| X509Error::Malformed { cert, field })?;
            roots.len = i + 1;
            if roots.len > MAX_ROOTS {
                return Err(X509Error::RootCount(roots.len).into());
            }
        }
        if roots.len == 0 {
            return Err(X509Error::RootCount(0).into());
        }
        Ok(roots)
    }

    /// Aantal wortels.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Altijd `false`: een lege set bestaat niet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// De DER van elke wortel, of het veld waar het splitsen faalde.
    fn iter_raw(self) -> impl Iterator<Item = core::result::Result<&'a [u8], &'static str>> {
        let (mut concat, list) = match self.src {
            RootSource::Concat(b) => (der::Der::new(b), &[][..]),
            RootSource::List(l) => (der::Der::new(&[]), l),
        };
        let from_concat = core::iter::from_fn(move || {
            if concat.is_empty() {
                return None;
            }
            Some(
                concat
                    .tlv(der::SEQUENCE)
                    .map(|t| t.raw)
                    .map_err(|_| "Certificate"),
            )
        });
        from_concat.chain(list.iter().map(|d| Ok(*d)))
    }

    /// Elke wortel met haar nummer; al gecontroleerd bij het aanmaken.
    fn iter(self) -> impl Iterator<Item = (u16, Cert<'a>)> {
        (0u16..)
            .zip(self.iter_raw())
            .filter_map(|(i, d)| Some((i, Cert::parse(d.ok()?).ok()?)))
    }
}

/// Ketenverificatie tegen een set wortels op een gegeven tijd.
///
/// Goedkoop om te maken (twee verwijzingen en een getal): maak er een per
/// verbinding, met de tijd van dat moment.
///
/// # Examples
///
/// ```
/// use leantls::{ChainVerifier, Roots, Trust};
/// # let root: &[u8] = include_bytes!("../../testdata/chain/ecdsa-root.der");
/// let roots = Roots::from_concatenated_der(root)?;
/// let verifier = ChainVerifier::new(roots, 1_790_640_000); // 2026-09-29
/// let trust = Trust::Chain(&verifier);
/// # let _ = trust;
/// # Ok::<(), leantls::Error>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ChainVerifier<'a> {
    /// De vertrouwde wortels.
    roots: Roots<'a>,
    /// De tijd van de toets, in seconden sinds 1970.
    now: i64,
}

impl<'a> ChainVerifier<'a> {
    /// Een verifier voor `roots` op tijdstip `now_unix` (seconden sinds 1970,
    /// UTC). De tijd komt van de aanroeper; een node zonder betrouwbare klok
    /// heeft geen betrouwbare ketenverificatie.
    pub fn new(roots: Roots<'a>, now_unix: u64) -> Self {
        Self {
            roots,
            now: i64::try_from(now_unix).unwrap_or(i64::MAX),
        }
    }

    /// Toetst de keten (de kern van [`VerifyPeer::verify_chain`]).
    fn check(
        &self,
        chain: CertChain<'_>,
        server_name: &str,
    ) -> core::result::Result<(), X509Error> {
        if name::is_ip(server_name) && server_name.parse::<core::net::IpAddr>().is_err() {
            return Err(X509Error::IpAddress);
        }
        if !name::is_ip(server_name) && !name::is_valid_host(server_name) {
            return Err(X509Error::ServerName);
        }
        let mut wire: [&[u8]; MAX_CHAIN] = [&[]; MAX_CHAIN];
        let mut n = 0;
        for der in chain.iter() {
            *wire
                .get_mut(n)
                .ok_or(X509Error::TooManyCertificates(chain.iter().count()))? = der;
            n += 1;
        }
        let wire = wire.get(..n).unwrap_or(&[]);
        // Alles moet lezen, ook wat later geen schakel blijkt: zoals Go.
        for (i, der) in (0u8..).zip(wire) {
            Cert::parse(der).map_err(|field| X509Error::Malformed {
                cert: CertRef::Chain(i),
                field,
            })?;
        }
        let leaf_der = wire.first().ok_or(X509Error::UnknownAuthority)?;
        let leaf = Cert::parse(leaf_der).map_err(|field| X509Error::Malformed {
            cert: CertRef::Chain(0),
            field,
        })?;
        check_leaf(&leaf, server_name)?;
        valid_at(&leaf, CertRef::Chain(0), self.now)?;

        // Een blad dat zelf een wortel is: vertrouwd zoals het is.
        if self.roots.iter().any(|(_, r)| r.raw == leaf.raw) {
            return Ok(());
        }
        let mut search = Search {
            now: self.now,
            roots: self.roots,
            wire,
            checks: 0,
            first_error: None,
        };
        search.issuer_of(&leaf, CertRef::Chain(0), 1, 0, 1)
    }
}

/// De eisen aan het blad die niet van het pad afhangen.
fn check_leaf(leaf: &Cert<'_>, server_name: &str) -> core::result::Result<(), X509Error> {
    let cert = CertRef::Chain(0);
    let matches = match server_name.parse::<core::net::IpAddr>() {
        Ok(ip) => leaf
            .ip_addresses()
            .any(|address| name::matches_ip(address, ip)),
        Err(_) => leaf.dns_names().any(|p| name::matches(p, server_name)),
    };
    if !matches {
        return Err(X509Error::NameMismatch {
            dns_names: leaf.dns_names().count(),
        });
    }
    if leaf.unhandled {
        return Err(X509Error::Unhandled { cert });
    }
    if leaf.server_auth == Some(false) {
        return Err(X509Error::ExtKeyUsage { cert });
    }
    // RFC 8446 §4.4.2.2: de sleutel tekent de CertificateVerify.
    if !leaf.allows(key_usage::DIGITAL_SIGNATURE) {
        return Err(X509Error::LeafKeyUsage);
    }
    leaf.public_key()
        .map_err(|what| X509Error::Unsupported { cert, what })?;
    Ok(())
}

/// Is `c` geldig op `now`?
fn valid_at(c: &Cert<'_>, cert: CertRef, now: i64) -> core::result::Result<(), X509Error> {
    if now < c.not_before {
        return Err(X509Error::NotYetValid {
            cert,
            not_before: c.not_before,
            now,
        });
    }
    if now > c.not_after {
        return Err(X509Error::Expired {
            cert,
            not_after: c.not_after,
            now,
        });
    }
    Ok(())
}

/// De padzoeker: diepte-eerst, begrensd in diepte en in handtekeningen.
struct Search<'a, 'c> {
    /// De tijd van de toets.
    now: i64,
    /// De wortels.
    roots: Roots<'a>,
    /// De keten van de server; 0 is het blad.
    wire: &'c [&'c [u8]],
    /// Gedane handtekeningcontroles.
    checks: usize,
    /// De eerste fout bij een kandidaat die wel de juiste naam had: die
    /// zegt meer dan "onbekende uitgever".
    first_error: Option<X509Error>,
}

impl Search<'_, '_> {
    /// Zoekt een uitgever voor `child` op diepte `depth` (het blad is 1).
    /// `below` telt de niet-zelfuitgegeven tussen-CA's onder de kandidaat,
    /// voor pathLenConstraint; `used` zijn de ketenposities op het pad.
    fn issuer_of(
        &mut self,
        child: &Cert<'_>,
        child_ref: CertRef,
        depth: usize,
        below: u32,
        used: u16,
    ) -> core::result::Result<(), X509Error> {
        // Eerst een wortel: het kortste pad wint.
        let (roots, wire) = (self.roots, self.wire);
        for (i, root) in roots.iter() {
            let r = CertRef::Root(i);
            if !self.links(child, &root) {
                continue;
            }
            match self.step(child, child_ref, &root, r, below, true) {
                Ok(()) => return Ok(()),
                Err(e) => self.note(e)?,
            }
        }
        for (i, der) in (0u8..).zip(wire).skip(1) {
            if used & (1 << i) != 0 {
                continue;
            }
            let Ok(cand) = Cert::parse(der) else { continue };
            if !self.links(child, &cand) {
                continue;
            }
            let r = CertRef::Chain(i);
            if let Err(e) = self.step(child, child_ref, &cand, r, below, false) {
                self.note(e)?;
                continue;
            }
            if depth + 1 >= MAX_DEPTH {
                self.note(X509Error::Limit("path depth"))?;
                continue;
            }
            let below = below + u32::from(!cand.is_self_issued());
            match self.issuer_of(&cand, r, depth + 1, below, used | 1 << i) {
                Ok(()) => return Ok(()),
                Err(e) => self.note(e)?,
            }
        }
        Err(self.first_error.unwrap_or(X509Error::UnknownAuthority))
    }

    /// Kan `issuer` de uitgever van `child` zijn, op naam en sleutel-id?
    fn links(&self, child: &Cert<'_>, issuer: &Cert<'_>) -> bool {
        child.issuer == issuer.subject
            && match (child.aki, issuer.ski) {
                (Some(a), Some(s)) => a == s,
                _ => true,
            }
    }

    /// Onthoudt de eerste fout; een overschreden handtekeninggrens stopt
    /// het hele zoeken.
    fn note(&mut self, e: X509Error) -> core::result::Result<(), X509Error> {
        if let X509Error::Limit("signature checks") = e {
            return Err(e);
        }
        self.first_error.get_or_insert(e);
        Ok(())
    }

    /// Eén schakel: `issuer` tekende `child` en mag dat.
    fn step(
        &mut self,
        child: &Cert<'_>,
        child_ref: CertRef,
        issuer: &Cert<'_>,
        issuer_ref: CertRef,
        below: u32,
        anchor: bool,
    ) -> core::result::Result<(), X509Error> {
        self.checks += 1;
        if self.checks > MAX_SIGNATURE_CHECKS {
            return Err(X509Error::Limit("signature checks"));
        }
        signed_by(child, child_ref, issuer, issuer_ref)?;
        valid_at(issuer, issuer_ref, self.now)?;
        let cert = issuer_ref;
        if issuer.unhandled {
            return Err(X509Error::Unhandled { cert });
        }
        // Een tussen-CA moet v3 zijn met cA; een wortel is een anker en mag
        // BasicConstraints missen (oude v1-wortels), maar niet ontkennen.
        let ca_ok = if anchor {
            issuer.basic.is_none_or(|b| b.ca)
        } else {
            issuer.version == 3 && issuer.is_ca()
        };
        if !ca_ok {
            return Err(X509Error::NotCa { cert });
        }
        if !issuer.allows(key_usage::KEY_CERT_SIGN) {
            return Err(X509Error::NoCertSign { cert });
        }
        if let Some(max) = issuer.basic.and_then(|b| b.path_len)
            && below > max
        {
            return Err(X509Error::PathLen { cert, max });
        }
        if issuer.server_auth == Some(false) {
            return Err(X509Error::ExtKeyUsage { cert });
        }
        Ok(())
    }
}

/// Controleert dat `issuer` de handtekening op `child` zette.
fn signed_by(
    child: &Cert<'_>,
    child_ref: CertRef,
    issuer: &Cert<'_>,
    issuer_ref: CertRef,
) -> core::result::Result<(), X509Error> {
    let key = issuer.public_key().map_err(|what| X509Error::Unsupported {
        cert: issuer_ref,
        what,
    })?;
    let bad = X509Error::BadCertSignature { cert: child_ref };
    let ok = match (child.sig_alg, key) {
        (SigAlg::Ecdsa(h), PublicKey::Ec(curve, point)) => {
            let d = h.digest(&[child.tbs]);
            let (r, s) = ecdsa_sig(child.signature).ok_or(bad)?;
            ecdsa::verify(curve, point, d.as_slice(), r, s)
        }
        (SigAlg::RsaPkcs1(h), PublicKey::Rsa { n, e }) => {
            let k = rsa::PublicKey::new(n, e).ok_or(X509Error::Unsupported {
                cert: issuer_ref,
                what: "RSA key (size outside 2048-4096 bits or bad exponent)",
            })?;
            k.verify_pkcs1(h, h.digest(&[child.tbs]).as_slice(), child.signature)
        }
        (SigAlg::Ed25519, PublicKey::Ed25519(k)) => {
            let sig: &[u8; 64] = child.signature.try_into().map_err(|_| bad)?;
            ed25519::verify(k, child.tbs, sig)
        }
        (SigAlg::Unknown, _) => {
            return Err(X509Error::Unsupported {
                cert: child_ref,
                what: "signature algorithm",
            });
        }
        // Een algoritme dat niet bij de sleutel van de uitgever past.
        _ => false,
    };
    if ok { Ok(()) } else { Err(bad) }
}

/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (RFC 3279 §2.2.3).
fn ecdsa_sig(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let seq = der::single(sig, der::SEQUENCE).ok()?;
    let mut d = der::Der::new(seq.body);
    let r = der::uint(d.read(der::INTEGER).ok()?).ok()?;
    let s = der::uint(d.read(der::INTEGER).ok()?).ok()?;
    d.end().ok()?;
    Some((r, s))
}

impl VerifyPeer for ChainVerifier<'_> {
    fn signature_algorithms(&self) -> &[u16] {
        &SIGNATURE_ALGORITHMS
    }

    fn verify_chain(&self, chain: CertChain<'_>, server_name: &str) -> Result {
        if server_name.is_empty() {
            return Err(Error::ServerNameRequired);
        }
        Ok(self.check(chain, server_name)?)
    }

    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result {
        let cert = Cert::parse(leaf).map_err(|field| X509Error::Malformed {
            cert: CertRef::Chain(0),
            field,
        })?;
        let key = cert.public_key().map_err(|what| X509Error::Unsupported {
            cert: CertRef::Chain(0),
            what,
        })?;
        let ok = match (alg, key) {
            (ECDSA_P256_SHA256, PublicKey::Ec(ecdsa::Curve::P256, point)) => {
                verify_ecdsa(point, ecdsa::Curve::P256, HashAlg::Sha256, signed, sig)
            }
            (ECDSA_P384_SHA384, PublicKey::Ec(ecdsa::Curve::P384, point)) => {
                verify_ecdsa(point, ecdsa::Curve::P384, HashAlg::Sha384, signed, sig)
            }
            (RSA_PSS_SHA256 | RSA_PSS_SHA384 | RSA_PSS_SHA512, PublicKey::Rsa { n, e }) => {
                let h = match alg {
                    RSA_PSS_SHA256 => HashAlg::Sha256,
                    RSA_PSS_SHA384 => HashAlg::Sha384,
                    _ => HashAlg::Sha512,
                };
                let k = rsa::PublicKey::new(n, e).ok_or(X509Error::Unsupported {
                    cert: CertRef::Chain(0),
                    what: "RSA key (size outside 2048-4096 bits or bad exponent)",
                })?;
                k.verify_pss(h, h.digest(&[signed]).as_slice(), sig)
            }
            (crate::handshake::SIG_ED25519, PublicKey::Ed25519(k)) => {
                let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
                ed25519::verify(k, signed, sig)
            }
            (a, _) if SIGNATURE_ALGORITHMS.contains(&a) => {
                return Err(X509Error::KeyMismatch(a).into());
            }
            (a, _) => return Err(X509Error::Algorithm(a).into()),
        };
        if ok { Ok(()) } else { Err(Error::BadSignature) }
    }
}

/// CertificateVerify met ECDSA: hash, DER-handtekening, verificatie.
fn verify_ecdsa(point: &[u8], curve: ecdsa::Curve, h: HashAlg, signed: &[u8], sig: &[u8]) -> bool {
    let Some((r, s)) = ecdsa_sig(sig) else {
        return false;
    };
    ecdsa::verify(curve, point, h.digest(&[signed]).as_slice(), r, s)
}
