//! Een X.509-certificaat (RFC 5280 §4.1), gelezen tot wat de padvalidatie
//! nodig heeft en niet verder.
//!
//! [`Cert`] leent alles uit de DER van de aanroeper. Namen blijven ruwe
//! bytes: issuer en subject worden byte voor byte vergeleken, zoals Go's
//! `crypto/x509` bij het bouwen van een pad ook doet. De publieke sleutel
//! wordt pas ontleed als er een handtekening mee gecontroleerd moet worden
//! ([`Cert::public_key`]), zodat een wortel met een sleutel die hier niet
//! bestaat de rest van de set niet ongeldig maakt.
//!
//! Extensies die hier betekenis hebben: BasicConstraints, KeyUsage,
//! ExtendedKeyUsage, SubjectAltName, Authority- en SubjectKeyIdentifier.
//! Elke andere kritieke extensie maakt het certificaat onbruikbaar
//! (RFC 5280 §4.2); NameConstraints ook als hij niet kritiek is, omdat hier
//! geen naambeperking wordt afgedwongen en een beperkte CA dus niet als
//! onbeperkt mag gelden.

use super::der::{
    self, BIT_STRING, BOOLEAN, Der, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE, explicit, implicit,
};
use crate::crypto::ecdsa::Curve;
use crate::crypto::hash::HashAlg;

/// De OID-inhoud (zonder tag en lengte) van de algoritmen en extensies.
mod oid {
    /// ecdsa-with-SHA256, 1.2.840.10045.4.3.2.
    pub(super) const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384, 1.2.840.10045.4.3.3.
    pub(super) const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// ecdsa-with-SHA512, 1.2.840.10045.4.3.4.
    pub(super) const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    /// sha256WithRSAEncryption, 1.2.840.113549.1.1.11.
    pub(super) const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// sha384WithRSAEncryption, 1.2.840.113549.1.1.12.
    pub(super) const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// sha512WithRSAEncryption, 1.2.840.113549.1.1.13.
    pub(super) const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// Ed25519, 1.3.101.112 (RFC 8410).
    pub(super) const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
    /// id-ecPublicKey, 1.2.840.10045.2.1.
    pub(super) const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1, 1.2.840.10045.3.1.7.
    pub(super) const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1, 1.3.132.0.34.
    pub(super) const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// rsaEncryption, 1.2.840.113549.1.1.1.
    pub(super) const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// subjectKeyIdentifier, 2.5.29.14.
    pub(super) const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
    /// keyUsage, 2.5.29.15.
    pub(super) const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// subjectAltName, 2.5.29.17.
    pub(super) const SAN: &[u8] = &[0x55, 0x1d, 0x11];
    /// basicConstraints, 2.5.29.19.
    pub(super) const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// nameConstraints, 2.5.29.30.
    pub(super) const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
    /// authorityKeyIdentifier, 2.5.29.35.
    pub(super) const AKI: &[u8] = &[0x55, 0x1d, 0x23];
    /// extKeyUsage, 2.5.29.37.
    pub(super) const EKU: &[u8] = &[0x55, 0x1d, 0x25];
    /// anyExtendedKeyUsage, 2.5.29.37.0.
    pub(super) const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    /// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1.
    pub(super) const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
}

/// Een handtekeningalgoritme uit een certificaat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigAlg {
    /// ECDSA met de genoemde hash.
    Ecdsa(HashAlg),
    /// RSA PKCS#1 v1.5 met de genoemde hash.
    RsaPkcs1(HashAlg),
    /// Ed25519.
    Ed25519,
    /// Iets anders (RSA-PSS in een certificaat, SHA-1, DSA, ...). Mag in een
    /// wortel staan, want die handtekening wordt niet gecontroleerd; in een
    /// schakel van het pad weigert de verificatie hem.
    Unknown,
}

/// Een ontlede publieke sleutel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicKey<'a> {
    /// Een ongecomprimeerd EC-punt op een van de twee curves.
    Ec(Curve, &'a [u8]),
    /// RSA: modulus en exponent, big-endian zonder tekenbyte.
    Rsa {
        /// De modulus.
        n: &'a [u8],
        /// De publieke exponent.
        e: &'a [u8],
    },
    /// Een Ed25519-sleutel van 32 bytes.
    Ed25519(&'a [u8; 32]),
}

/// De KeyUsage-bits die hier tellen (RFC 5280 §4.2.1.3), als masker op de
/// eerste twee bytes van de BIT STRING, big-endian.
pub(crate) mod key_usage {
    /// digitalSignature (bit 0).
    pub(crate) const DIGITAL_SIGNATURE: u16 = 0x8000;
    /// keyCertSign (bit 5).
    pub(crate) const KEY_CERT_SIGN: u16 = 0x0400;
}

/// BasicConstraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Basic {
    /// cA.
    pub(crate) ca: bool,
    /// pathLenConstraint, als hij er is.
    pub(crate) path_len: Option<u32>,
}

/// Een gelezen certificaat.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cert<'a> {
    /// De hele DER.
    pub(crate) raw: &'a [u8],
    /// tbsCertificate als ruwe TLV: de ondertekende bytes.
    pub(crate) tbs: &'a [u8],
    /// Het handtekeningalgoritme (binnen en buiten gelijk).
    pub(crate) sig_alg: SigAlg,
    /// De handtekening, zonder de opvulbyte van de BIT STRING.
    pub(crate) signature: &'a [u8],
    /// 1, 2 of 3.
    pub(crate) version: u8,
    /// De issuer-Name als ruwe TLV.
    pub(crate) issuer: &'a [u8],
    /// De subject-Name als ruwe TLV.
    pub(crate) subject: &'a [u8],
    /// notBefore in seconden sinds 1970.
    pub(crate) not_before: i64,
    /// notAfter in seconden sinds 1970.
    pub(crate) not_after: i64,
    /// SubjectPublicKeyInfo als ruwe TLV.
    spki: &'a [u8],
    /// BasicConstraints, als aanwezig.
    pub(crate) basic: Option<Basic>,
    /// KeyUsage als masker, als aanwezig.
    pub(crate) key_usage: Option<u16>,
    /// ExtendedKeyUsage: `Some(true)` als serverAuth of anyExtendedKeyUsage
    /// erin staat, `Some(false)` als dat niet zo is, `None` zonder extensie.
    pub(crate) server_auth: Option<bool>,
    /// De inhoud van de GeneralNames uit SubjectAltName.
    pub(crate) san: Option<&'a [u8]>,
    /// SubjectKeyIdentifier.
    pub(crate) ski: Option<&'a [u8]>,
    /// De keyIdentifier uit AuthorityKeyIdentifier.
    pub(crate) aki: Option<&'a [u8]>,
    /// Een kritieke extensie die hier niet verwerkt wordt, of
    /// NameConstraints: het certificaat mag dan in geen pad staan.
    pub(crate) unhandled: bool,
}

/// Een fout bij het lezen: het veld dat niet klopte.
pub(crate) type ParseResult<T> = Result<T, &'static str>;

/// Koppelt een DER-fout aan het veld waarin hij zat.
trait Field<T> {
    /// Geeft het veld mee.
    fn field(self, name: &'static str) -> ParseResult<T>;
}

impl<T> Field<T> for der::Result<T> {
    fn field(self, name: &'static str) -> ParseResult<T> {
        self.map_err(|_| name)
    }
}

impl<'a> Cert<'a> {
    /// Leest een certificaat. Een fout noemt het veld.
    pub(crate) fn parse(raw: &'a [u8]) -> ParseResult<Self> {
        let outer = der::single(raw, SEQUENCE).field("Certificate")?;
        let mut c = Der::new(outer.body);
        let tbs = c.tlv(SEQUENCE).field("tbsCertificate")?;
        let alg_outer = c.tlv(SEQUENCE).field("signatureAlgorithm")?.raw;
        let signature =
            der::octets(c.read(BIT_STRING).field("signatureValue")?).field("signatureValue")?;
        c.end().field("Certificate")?;

        let mut t = Der::new(tbs.body);
        let version = match t.optional(explicit(0)).field("version")? {
            None => 1,
            Some(v) => match der::small_uint(der::single(v, INTEGER).field("version")?.body) {
                Ok(n @ 0..=2) => n as u8 + 1,
                _ => return Err("version"),
            },
        };
        t.read(INTEGER).field("serialNumber")?;
        // RFC 5280 §4.1.1.2: het algoritme binnen en buiten de handtekening
        // moet gelijk zijn, anders kan een aanvaller er een omwisselen.
        if t.tlv(SEQUENCE).field("signature")?.raw != alg_outer {
            return Err("signature algorithm (inner and outer differ)");
        }
        let issuer = t.tlv(SEQUENCE).field("issuer")?.raw;
        let mut validity = t.nested(SEQUENCE).field("validity")?;
        let not_before = der::time(validity.any().field("notBefore")?).field("notBefore")?;
        let not_after = der::time(validity.any().field("notAfter")?).field("notAfter")?;
        validity.end().field("validity")?;
        let subject = t.tlv(SEQUENCE).field("subject")?.raw;
        let spki = t.tlv(SEQUENCE).field("subjectPublicKeyInfo")?.raw;
        // issuerUniqueID en subjectUniqueID: toegestaan, niet gebruikt.
        t.optional(implicit(1)).field("issuerUniqueID")?;
        t.optional(implicit(2)).field("subjectUniqueID")?;

        let mut cert = Cert {
            raw,
            tbs: tbs.raw,
            sig_alg: sig_alg(alg_outer),
            signature,
            version,
            issuer,
            subject,
            not_before,
            not_after,
            spki,
            basic: None,
            key_usage: None,
            server_auth: None,
            san: None,
            ski: None,
            aki: None,
            unhandled: false,
        };
        if let Some(exts) = t.optional(explicit(3)).field("extensions")? {
            if version != 3 {
                return Err("extensions (only in version 3)");
            }
            cert.extensions(exts)?;
        }
        t.end().field("tbsCertificate")?;
        Ok(cert)
    }

    /// Leest de extensies (RFC 5280 §4.2). Elke bekende extensie mag er één
    /// keer in staan.
    fn extensions(&mut self, body: &'a [u8]) -> ParseResult<()> {
        let list = der::single(body, SEQUENCE).field("extensions")?;
        let mut exts = Der::new(list.body);
        if exts.is_empty() {
            return Err("extensions (empty)");
        }
        let mut seen = 0u8;
        while !exts.is_empty() {
            let mut e = exts.nested(SEQUENCE).field("extension")?;
            let id = e.read(OID).field("extension id")?;
            let critical = match e.optional(BOOLEAN).field("extension critical")? {
                Some(b) => der::boolean(b).field("extension critical")?,
                None => false,
            };
            let value = e.read(OCTET_STRING).field("extension value")?;
            e.end().field("extension")?;
            let bit = match id {
                oid::BASIC_CONSTRAINTS => {
                    self.basic = Some(basic_constraints(value)?);
                    1
                }
                oid::KEY_USAGE => {
                    self.key_usage = Some(key_usage_bits(value)?);
                    2
                }
                oid::EKU => {
                    self.server_auth = Some(ext_key_usage(value)?);
                    4
                }
                oid::SAN => {
                    self.san = Some(subject_alt_name(value)?);
                    8
                }
                oid::SKI => {
                    self.ski = Some(
                        der::single(value, OCTET_STRING)
                            .field("subjectKeyIdentifier")?
                            .body,
                    );
                    16
                }
                oid::AKI => {
                    self.aki = authority_key_id(value)?;
                    32
                }
                oid::NAME_CONSTRAINTS => {
                    self.unhandled = true;
                    64
                }
                _ => {
                    self.unhandled |= critical;
                    0
                }
            };
            if seen & bit != 0 {
                return Err("extensions (duplicate)");
            }
            seen |= bit;
        }
        Ok(())
    }

    /// De publieke sleutel, als hij een van de ondersteunde soorten is.
    pub(crate) fn public_key(&self) -> ParseResult<PublicKey<'a>> {
        let spki = der::single(self.spki, SEQUENCE).field("subjectPublicKeyInfo")?;
        let mut s = Der::new(spki.body);
        let mut alg = s.nested(SEQUENCE).field("public key algorithm")?;
        let key = der::octets(s.read(BIT_STRING).field("public key")?).field("public key")?;
        s.end().field("subjectPublicKeyInfo")?;
        let id = alg.read(OID).field("public key algorithm")?;
        match id {
            oid::EC_PUBLIC_KEY => {
                let curve = match alg.read(OID).field("curve")? {
                    oid::P256 => Curve::P256,
                    oid::P384 => Curve::P384,
                    _ => return Err("public key (curve other than P-256 or P-384)"),
                };
                alg.end().field("public key algorithm")?;
                Ok(PublicKey::Ec(curve, key))
            }
            oid::RSA => {
                // De parameters zijn NULL (RFC 3279 §2.3.1); afwezig laten we
                // toe omdat het niets anders kan betekenen.
                alg.optional(NULL).field("public key algorithm")?;
                alg.end().field("public key algorithm")?;
                let rsa = der::single(key, SEQUENCE).field("RSA public key")?;
                let mut r = Der::new(rsa.body);
                let n = der::uint(r.read(INTEGER).field("RSA modulus")?).field("RSA modulus")?;
                let e = der::uint(r.read(INTEGER).field("RSA exponent")?).field("RSA exponent")?;
                r.end().field("RSA public key")?;
                Ok(PublicKey::Rsa { n, e })
            }
            oid::ED25519 => {
                alg.end().field("public key algorithm")?;
                key.try_into()
                    .map(PublicKey::Ed25519)
                    .map_err(|_| "public key (Ed25519 is 32 bytes)")
            }
            _ => Err("public key (algorithm other than EC, RSA or Ed25519)"),
        }
    }

    /// De DNS-namen uit SubjectAltName, als ruwe bytes.
    pub(crate) fn dns_names(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let mut d = Der::new(self.san.unwrap_or(&[]));
        core::iter::from_fn(move || {
            while let Ok(t) = d.any() {
                if t.tag == implicit(2) {
                    return Some(t.body);
                }
            }
            None
        })
    }

    /// IP-adressen uit de eigen SAN-tag, nooit uit dNSName of CommonName.
    pub(crate) fn ip_addresses(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let mut d = Der::new(self.san.unwrap_or(&[]));
        core::iter::from_fn(move || {
            while let Ok(t) = d.any() {
                if t.tag == implicit(7) {
                    return Some(t.body);
                }
            }
            None
        })
    }

    /// Heeft de KeyUsage dit bit, of ontbreekt de extensie (dan mag alles)?
    pub(crate) fn allows(&self, usage: u16) -> bool {
        self.key_usage.is_none_or(|ku| ku & usage != 0)
    }

    /// Is dit een CA volgens BasicConstraints?
    pub(crate) fn is_ca(&self) -> bool {
        self.basic.is_some_and(|b| b.ca)
    }

    /// Is issuer gelijk aan subject (RFC 5280 §6.1: "self-issued")?
    pub(crate) fn is_self_issued(&self) -> bool {
        self.issuer == self.subject
    }
}

/// Het handtekeningalgoritme uit een ruwe AlgorithmIdentifier.
fn sig_alg(raw: &[u8]) -> SigAlg {
    let Ok(t) = der::single(raw, SEQUENCE) else {
        return SigAlg::Unknown;
    };
    let mut d = Der::new(t.body);
    let Ok(id) = d.read(OID) else {
        return SigAlg::Unknown;
    };
    // RSA draagt een NULL-parameter (RFC 4055 §5); ECDSA en Ed25519 geen.
    let rsa_params = d.optional(NULL).is_ok() && d.is_empty();
    let none = d.is_empty();
    match id {
        oid::ECDSA_SHA256 if none => SigAlg::Ecdsa(HashAlg::Sha256),
        oid::ECDSA_SHA384 if none => SigAlg::Ecdsa(HashAlg::Sha384),
        oid::ECDSA_SHA512 if none => SigAlg::Ecdsa(HashAlg::Sha512),
        oid::RSA_SHA256 if rsa_params => SigAlg::RsaPkcs1(HashAlg::Sha256),
        oid::RSA_SHA384 if rsa_params => SigAlg::RsaPkcs1(HashAlg::Sha384),
        oid::RSA_SHA512 if rsa_params => SigAlg::RsaPkcs1(HashAlg::Sha512),
        oid::ED25519 if none => SigAlg::Ed25519,
        _ => SigAlg::Unknown,
    }
}

/// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }.
fn basic_constraints(value: &[u8]) -> ParseResult<Basic> {
    let seq = der::single(value, SEQUENCE).field("basicConstraints")?;
    let mut d = Der::new(seq.body);
    // Een expliciete FALSE is strikt genomen geen DER, maar komt in echte
    // certificaten voor en betekent hetzelfde; Go accepteert hem ook.
    let ca = match d.optional(BOOLEAN).field("basicConstraints")? {
        Some(b) => der::boolean(b).field("basicConstraints")?,
        None => false,
    };
    let path_len = match d.optional(INTEGER).field("pathLenConstraint")? {
        Some(n) => Some(der::small_uint(n).field("pathLenConstraint")?),
        None => None,
    };
    d.end().field("basicConstraints")?;
    Ok(Basic { ca, path_len })
}

/// KeyUsage ::= BIT STRING, als masker op de eerste twee bytes.
fn key_usage_bits(value: &[u8]) -> ParseResult<u16> {
    let body = der::single(value, BIT_STRING).field("keyUsage")?.body;
    let (bits, _) = der::bit_string(body).field("keyUsage")?;
    let b0 = bits.first().copied().unwrap_or(0);
    let b1 = bits.get(1).copied().unwrap_or(0);
    Ok(u16::from(b0) << 8 | u16::from(b1))
}

/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId.
fn ext_key_usage(value: &[u8]) -> ParseResult<bool> {
    let seq = der::single(value, SEQUENCE).field("extKeyUsage")?;
    let mut d = Der::new(seq.body);
    if d.is_empty() {
        return Err("extKeyUsage (empty)");
    }
    let mut server = false;
    while !d.is_empty() {
        let id = d.read(OID).field("extKeyUsage")?;
        server |= id == oid::EKU_SERVER_AUTH || id == oid::EKU_ANY;
    }
    Ok(server)
}

/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName; elke naam moet
/// een geldige TLV zijn, zodat [`Cert::dns_names`] later niets mist.
fn subject_alt_name(value: &[u8]) -> ParseResult<&[u8]> {
    let seq = der::single(value, SEQUENCE).field("subjectAltName")?;
    let mut d = Der::new(seq.body);
    if d.is_empty() {
        return Err("subjectAltName (empty)");
    }
    while !d.is_empty() {
        let name = d.any().field("subjectAltName")?;
        if name.tag == implicit(7) && !matches!(name.body.len(), 4 | 16) {
            return Err("subjectAltName (invalid IP length)");
        }
    }
    Ok(seq.body)
}

/// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, ... }.
fn authority_key_id(value: &[u8]) -> ParseResult<Option<&[u8]>> {
    let seq = der::single(value, SEQUENCE).field("authorityKeyIdentifier")?;
    let mut d = Der::new(seq.body);
    let id = d.optional(implicit(0)).field("authorityKeyIdentifier")?;
    // authorityCertIssuer [1] en authorityCertSerialNumber [2] mogen, maar
    // doen voor de padbouw niets.
    while !d.is_empty() {
        d.any().field("authorityKeyIdentifier")?;
    }
    Ok(id)
}
