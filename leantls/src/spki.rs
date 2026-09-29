//! Een Ed25519-sleutel uit een X.509-certificaat halen zonder X.509-parser.
//!
//! De gepinde modus hoeft alleen te weten of het certificaat de pin draagt;
//! hij controleert geen keten, naam, geldigheid of intrekking en kan dus
//! geen willekeurige publieke server verifiëren.
//!
//! De DER-wandeling gaat naar subjectPublicKeyInfo en eist de exacte vorm
//! van RFC 8410 §4: OID 1.3.101.112, geen parameters, een sleutel van 32
//! bytes:
//!
//! ```text
//! 30 2a          SEQUENCE, 42 bytes            (SubjectPublicKeyInfo)
//!    30 05       SEQUENCE, 5 bytes             (AlgorithmIdentifier)
//!       06 03 2b 65 70                         (OID 1.3.101.112 = Ed25519)
//!    03 21 00    BIT STRING, 33 bytes, 0 unused
//!    <32 bytes>
//! ```
//!
//! RSA- en ECDSA-certificaten falen met een duidelijke melding. De begrensde
//! DER-lezer weigert onbepaalde lengtes en elke afwijking van de zes velden.

use crate::crypto::ed25519::PUBLIC_KEY_LEN;
use crate::error::{Error, Result};

/// De vaste inhoud van een Ed25519-SubjectPublicKeyInfo vóór de sleutel.
const ED25519_SPKI_BODY: [u8; 10] = [
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: OID 1.3.101.112
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 ongebruikte bits
];

/// DER-tag SEQUENCE.
const DER_SEQUENCE: u8 = 0x30;
/// DER-tag INTEGER.
const DER_INTEGER: u8 = 0x02;
/// `[0] EXPLICIT`, het optionele versieveld.
const DER_CONTEXT0: u8 = 0xa0;

/// Leest één TLV en geeft tag, inhoud en rest.
pub(crate) fn der_value(p: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let [tag, first, rest @ ..] = p else {
        return Err(Error::Der);
    };
    let mut p = rest;
    let n = match *first {
        // Korte vorm: de lengte staat in deze byte.
        n @ 0..0x80 => usize::from(n),
        // DER verbiedt de onbepaalde lengte.
        0x80 => return Err(Error::Der),
        long => {
            let count = usize::from(long & 0x7f);
            if count > 4 || p.len() < count {
                return Err(Error::Der);
            }
            let (len_bytes, tail) = p.split_at(count);
            p = tail;
            len_bytes
                .iter()
                .fold(0usize, |n, b| n << 8 | usize::from(*b))
        }
    };
    if p.len() < n {
        return Err(Error::Der);
    }
    let (body, rest) = p.split_at(n);
    Ok((*tag, body, rest))
}

/// Eist een SEQUENCE vooraan en geeft de inhoud.
fn der_seq(p: &[u8]) -> Result<&[u8]> {
    match der_value(p)? {
        (DER_SEQUENCE, body, _) => Ok(body),
        _ => Err(Error::Der),
    }
}

/// Haalt de Ed25519-sleutel uit een DER-certificaat.
pub(crate) fn peer_key_from_cert(der: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let cert = der_seq(der)?; // Certificate ::= SEQUENCE
    let tbs = der_seq(cert)?; // tbsCertificate ::= SEQUENCE

    // Sla de velden van RFC 5280 §4.1 vóór subjectPublicKeyInfo over: de
    // optionele expliciete versie, dan serialNumber, signature, issuer,
    // validity en subject.
    let mut rest = tbs;
    if rest.first() == Some(&DER_CONTEXT0) {
        rest = der_value(rest)?.2;
    }
    let fields = [
        DER_INTEGER,
        DER_SEQUENCE,
        DER_SEQUENCE,
        DER_SEQUENCE,
        DER_SEQUENCE,
    ];
    for (index, want) in (0u8..).zip(fields) {
        let (tag, _, tail) = der_value(rest)?;
        if tag != want {
            return Err(Error::DerField { index, tag, want });
        }
        rest = tail;
    }

    // Eis de exacte Ed25519-inhoud; de lengtecodering is aan de DER-lezer.
    let (tag, spki, _) = der_value(rest)?;
    let body = spki.get(..ED25519_SPKI_BODY.len());
    let key = spki.get(ED25519_SPKI_BODY.len()..);
    match (tag, body, key) {
        (DER_SEQUENCE, Some(body), Some(key))
            if body == ED25519_SPKI_BODY && key.len() == PUBLIC_KEY_LEN =>
        {
            let mut out = [0u8; PUBLIC_KEY_LEN];
            out.copy_from_slice(key);
            Ok(out)
        }
        _ => Err(Error::NotEd25519 {
            len: spki.len(),
            tag,
        }),
    }
}
