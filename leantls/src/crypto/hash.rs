//! De keuze tussen SHA-256, SHA-384 en SHA-512 als waarde.
//!
//! Een certificaat of een CertificateVerify noemt zijn hash; de verificatie
//! kiest hem hier. Geen trait-object: drie varianten en een vaste buffer van
//! 64 bytes, zodat er niets gealloceerd wordt.

use super::sha256::Sha256;
use super::sha512::{LEN384, Sha512};

/// Een hashfunctie uit de SHA-2-familie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Grootste digest in bytes (SHA-512).
pub(crate) const MAX_DIGEST: usize = 64;

/// Een digest van hooguit [`MAX_DIGEST`] bytes.
#[derive(Clone, Copy)]
pub(crate) struct Digest {
    /// De bytes; alleen de eerste `len` tellen.
    bytes: [u8; MAX_DIGEST],
    /// De lengte van deze digest.
    len: usize,
}

impl Digest {
    /// De digest als slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// Een lopende hash van een van de drie.
enum Running {
    /// SHA-256.
    S256(Sha256),
    /// SHA-384 of SHA-512: dezelfde machine.
    S512(Sha512),
}

impl HashAlg {
    /// De lengte van de digest in bytes.
    pub(crate) const fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => LEN384,
            HashAlg::Sha512 => 64,
        }
    }

    /// Hasht de aaneenschakeling van `parts`; zo hoeft PSS en MGF1 niets aan
    /// elkaar te plakken in een buffer.
    pub(crate) fn digest(self, parts: &[&[u8]]) -> Digest {
        let mut h = match self {
            HashAlg::Sha256 => Running::S256(Sha256::new()),
            HashAlg::Sha384 => Running::S512(Sha512::new384()),
            HashAlg::Sha512 => Running::S512(Sha512::new()),
        };
        for p in parts {
            match &mut h {
                Running::S256(h) => h.update(p),
                Running::S512(h) => h.update(p),
            }
        }
        let mut bytes = [0u8; MAX_DIGEST];
        match h {
            Running::S256(h) => {
                let d = h.finish();
                bytes[..d.len()].copy_from_slice(&d);
            }
            Running::S512(h) => bytes = h.finish(),
        }
        Digest {
            bytes,
            len: self.len(),
        }
    }
}
