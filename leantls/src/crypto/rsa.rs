//! RSA-verificatie: PKCS#1 v1.5 voor certificaten en PSS voor de handshake
//! (RFC 8017 §8.2.2 en §9.1.2).
//!
//! TLS 1.3 verbiedt PKCS#1 v1.5 in CertificateVerify (RFC 8446 §4.2.3), maar
//! de Web-PKI tekent certificaten er nog steeds mee (Let's Encrypt, ISRG
//! Root X1). Deze module doet dus allebei, en de aanroeper kiest per plek.
//!
//! Alleen verificatie, alleen publieke data: variabele tijd is hier bewust
//! (zie [`super::bignum`]). De modulus is 2048 tot 4096 bits; de exponent is
//! klein, oneven en minstens 3.
//!
//! PKCS#1 v1.5 wordt niet ontleed maar opnieuw opgebouwd en byte voor byte
//! vergeleken. Zo bestaat de klasse van Bleichenbacher-2006-fouten niet,
//! waarin een parser rommel achter de DigestInfo liet staan.

use super::bignum::{Monty, Uint};
use super::hash::HashAlg;

/// Kleinste modulus. De CA/Browser Forum-eisen staan sinds 2014 niets
/// kleiners toe, en 1024 bits is te breken.
pub(crate) const MIN_BITS: usize = 2048;
/// Grootste modulus. Wortels van 4096 bits zijn gewoon (ISRG Root X1); een
/// grotere komt in de Mozilla-set niet voor en zou de vaste buffers
/// verdubbelen.
pub(crate) const MAX_BITS: usize = 4096;
/// Limbs voor [`MAX_BITS`].
const LIMBS: usize = MAX_BITS / 64;
/// Bytes voor [`MAX_BITS`].
const MAX_BYTES: usize = MAX_BITS / 8;

/// Grootste publieke exponent: `2^32 - 1`. Go weigert boven `2^31 - 1`;
/// in de praktijk is hij 65537.
const MAX_E: u64 = 0xffff_ffff;

/// De DigestInfo-voorvoegsels van RFC 8017 §9.2 noot 1, met de NULL-parameter.
const DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// Zie [`DIGEST_INFO_SHA256`].
const DIGEST_INFO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
/// Zie [`DIGEST_INFO_SHA256`].
const DIGEST_INFO_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Een gecontroleerde publieke RSA-sleutel.
///
/// # Invariants
///
/// De modulus is oneven en heeft [`MIN_BITS`] tot [`MAX_BITS`] bits; `e` is
/// oneven en ligt in `[3, MAX_E]`.
pub(crate) struct PublicKey {
    /// Rekenen modulo n.
    n: Monty<LIMBS>,
    /// Aantal bits van n.
    bits: usize,
    /// De publieke exponent.
    e: u64,
}

impl PublicKey {
    /// Een sleutel uit big-endian `n` en `e`; `None` buiten de grenzen.
    pub(crate) fn new(n: &[u8], e: &[u8]) -> Option<Self> {
        let n = Uint::<LIMBS>::from_be(n)?;
        let bits = n.bits();
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return None;
        }
        let e = Uint::<1>::from_be(e)?.0[0];
        if !(3..=MAX_E).contains(&e) || e & 1 == 0 {
            return None;
        }
        // INVARIANT: Monty::new weigert een even modulus; bits en e zijn
        // hierboven begrensd.
        Some(Self {
            n: Monty::new(n)?,
            bits,
            e,
        })
    }

    /// Lengte van de modulus in bytes.
    fn len(&self) -> usize {
        self.bits.div_ceil(8)
    }

    /// `sig^e mod n` in `out[..k]`, met de controles van RSAVP1: de
    /// handtekening heeft precies `k` bytes en is kleiner dan `n`.
    fn open<'o>(&self, sig: &[u8], out: &'o mut [u8; MAX_BYTES]) -> Option<&'o [u8]> {
        let k = self.len();
        if sig.len() != k {
            return None;
        }
        let s = Uint::<LIMBS>::from_be(sig)?;
        if s.cmp(self.n.modulus()) != core::cmp::Ordering::Less {
            return None;
        }
        let m = self.n.plain(&self.n.pow(&self.n.mont(&s), &[self.e]));
        let em = out.get_mut(..k)?;
        m.write_be(em).then_some(&*em)
    }

    /// RSASSA-PKCS1-v1_5-VERIFY over een al berekende `digest`.
    pub(crate) fn verify_pkcs1(&self, hash: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let prefix: &[u8] = match hash {
            HashAlg::Sha256 => &DIGEST_INFO_SHA256,
            HashAlg::Sha384 => &DIGEST_INFO_SHA384,
            HashAlg::Sha512 => &DIGEST_INFO_SHA512,
        };
        if digest.len() != hash.len() {
            return false;
        }
        let mut buf = [0u8; MAX_BYTES];
        let Some(em) = self.open(sig, &mut buf) else {
            return false;
        };
        // EM = 00 01 FF…FF 00 || DigestInfo || digest, met minstens 8 keer FF.
        let t_len = prefix.len() + digest.len();
        let Some(ps_len) = em.len().checked_sub(t_len + 3) else {
            return false;
        };
        if ps_len < 8 {
            return false;
        }
        let mut want = [0u8; MAX_BYTES];
        let Some(w) = want.get_mut(..em.len()) else {
            return false;
        };
        w[1] = 0x01;
        w[2..2 + ps_len].fill(0xff);
        let t = 3 + ps_len;
        w[t..t + prefix.len()].copy_from_slice(prefix);
        w[t + prefix.len()..].copy_from_slice(digest);
        em == w
    }

    /// RSASSA-PSS-VERIFY met MGF1 over dezelfde hash en een zoutlengte gelijk
    /// aan de hashlengte, zoals TLS 1.3 voorschrijft (RFC 8446 §4.2.3).
    pub(crate) fn verify_pss(&self, hash: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let mut buf = [0u8; MAX_BYTES];
        let Some(m) = self.open(sig, &mut buf) else {
            return false;
        };
        pss_check(m, self.bits - 1, hash, digest).unwrap_or(false)
    }
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) op het geopende getal `m` van `k`
/// bytes, met `em_bits = modBits - 1`.
fn pss_check(m: &[u8], em_bits: usize, hash: HashAlg, digest: &[u8]) -> Option<bool> {
    let h_len = hash.len();
    let s_len = h_len;
    if digest.len() != h_len {
        return Some(false);
    }
    // Als modBits - 1 een veelvoud van 8 is, is EM één byte korter dan k en
    // moet de voorste byte nul zijn.
    let em_len = em_bits.div_ceil(8);
    let (lead, em) = m.split_at(m.len().checked_sub(em_len)?);
    if lead.iter().any(|b| *b != 0) || em_len < h_len + s_len + 2 {
        return Some(false);
    }
    let (&last, rest) = em.split_last()?;
    if last != 0xbc {
        return Some(false);
    }
    let (masked_db, h) = rest.split_at(em_len - h_len - 1);
    // De bits boven em_bits moeten nul zijn.
    let top_mask = 0xffu8 >> (8 * em_len - em_bits);
    if masked_db.first()? & !top_mask != 0 {
        return Some(false);
    }
    let mut db = [0u8; MAX_BYTES];
    let db = db.get_mut(..masked_db.len())?;
    db.copy_from_slice(masked_db);
    mgf1_xor(hash, h, db);
    *db.first_mut()? &= top_mask;
    // DB = 00…00 01 || salt.
    let (pad, salt) = db.split_at(db.len() - s_len);
    let (&one, zeros) = pad.split_last()?;
    if one != 0x01 || zeros.iter().any(|b| *b != 0) {
        return Some(false);
    }
    let h2 = hash.digest(&[&[0u8; 8], digest, salt]);
    Some(h2.as_slice() == h)
}

/// `out ^= MGF1(seed)` over de lengte van `out`.
fn mgf1_xor(hash: HashAlg, seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(hash.len())) {
        let mask = hash.digest(&[seed, &counter.to_be_bytes()]);
        for (o, m) in chunk.iter_mut().zip(mask.as_slice()) {
            *o ^= m;
        }
    }
}

#[cfg(test)]
mod tests;
