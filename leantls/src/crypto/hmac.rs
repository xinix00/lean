//! HMAC-SHA256 (RFC 2104) en HKDF-SHA256 (RFC 5869).
//!
//! Alleen SHA-256: de sleutelschema's van TLS 1.3 met
//! `TLS_AES_128_GCM_SHA256` gebruiken niets anders. HKDF-Expand neemt de
//! `info` in stukken, zodat HKDF-Expand-Label zijn label niet eerst in een
//! buffer hoeft te bouwen.

use super::ct::wipe;
use super::sha256::{BLOCK, LEN, Sha256};

/// Een lopende HMAC-SHA256.
#[derive(Clone)]
pub(crate) struct HmacSha256 {
    /// De hash over `K ^ ipad || tekst`.
    inner: Sha256,
    /// De hash over `K ^ opad`, nog zonder de binnenste digest.
    outer: Sha256,
}

impl HmacSha256 {
    /// Begint een HMAC met `key`; een sleutel langer dan een blok wordt eerst
    /// gehasht (RFC 2104 §2).
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut d = Sha256::digest(key);
            k0[..LEN].copy_from_slice(&d);
            wipe(&mut d);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut pad = [0u8; BLOCK];
        for (p, k) in pad.iter_mut().zip(k0) {
            *p = k ^ 0x36;
        }
        let mut inner = Sha256::new();
        inner.update(&pad);
        for (p, k) in pad.iter_mut().zip(k0) {
            *p = k ^ 0x5c;
        }
        let mut outer = Sha256::new();
        outer.update(&pad);
        wipe(&mut pad);
        wipe(&mut k0);
        Self { inner, outer }
    }

    /// Voegt tekst toe.
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Geeft de MAC.
    pub(crate) fn finish(self) -> [u8; LEN] {
        let Self { inner, mut outer } = self;
        let mut d = inner.finish();
        outer.update(&d);
        wipe(&mut d);
        outer.finish()
    }

    /// HMAC in één keer.
    pub(crate) fn mac(key: &[u8], data: &[u8]) -> [u8; LEN] {
        let mut m = Self::new(key);
        m.update(data);
        m.finish()
    }
}

/// HKDF-Extract: `PRK = HMAC(salt, IKM)`. Een leeg zout is gelijk aan 32
/// nullen, omdat HMAC een korte sleutel toch met nullen aanvult.
pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> [u8; LEN] {
    HmacSha256::mac(salt, ikm)
}

/// HKDF-Expand met `info` als aaneenschakeling van `info_parts`.
///
/// Geeft `false` als `out` langer is dan 255 blokken; RFC 5869 §2.3 verbiedt
/// dat, en de TLS-schema's vragen nooit meer dan 32 bytes.
#[must_use]
pub(crate) fn expand(prk: &[u8], info_parts: &[&[u8]], out: &mut [u8]) -> bool {
    if out.len() > 255 * LEN {
        return false;
    }
    let base = HmacSha256::new(prk);
    let mut prev = [0u8; LEN];
    let mut prev_len = 0;
    for (i, chunk) in out.chunks_mut(LEN).enumerate() {
        let mut m = base.clone();
        m.update(&prev[..prev_len]);
        for part in info_parts {
            m.update(part);
        }
        // De teller loopt van 1 tot hoogstens 255, gecontroleerd hierboven.
        m.update(&[(i as u8).wrapping_add(1)]);
        prev = m.finish();
        prev_len = LEN;
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
    wipe(&mut prev);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::unhex;

    /// RFC 4231 §4.2 tot en met §4.8, testgevallen 1 tot en met 7.
    #[test]
    fn rfc4231_vectors() {
        let cases: [(Vec<u8>, Vec<u8>, &str); 7] = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                (1..=25).collect(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                vec![0x0c; 20],
                b"Test With Truncation".to_vec(),
                "a3b6167473100ee06e0c796c2955552b",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm."
                    .to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (i, (key, data, want)) in cases.iter().enumerate() {
            let want = unhex(want);
            let got = HmacSha256::mac(key, data);
            assert_eq!(
                &got[..want.len()],
                &want[..],
                "RFC 4231 testgeval {}",
                i + 1
            );
        }
    }

    /// IKM, zout, info, PRK, OKM.
    type Case = (Vec<u8>, Vec<u8>, Vec<u8>, &'static str, &'static str);

    /// RFC 5869 bijlage A, testgevallen 1 tot en met 3 (SHA-256).
    #[test]
    fn rfc5869_vectors() {
        let cases: [Case; 3] = [
            (
                vec![0x0b; 22],
                (0x00..=0x0c).collect(),
                (0xf0..=0xf9).collect(),
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                (0x00..=0x4f).collect(),
                (0x60..=0xaf).collect(),
                (0xb0..=0xff).collect(),
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                vec![0x0b; 22],
                Vec::new(),
                Vec::new(),
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (i, (ikm, salt, info, prk, okm)) in cases.iter().enumerate() {
            let got_prk = extract(salt, ikm);
            assert_eq!(got_prk.to_vec(), unhex(prk), "RFC 5869 PRK {}", i + 1);
            let want = unhex(okm);
            let mut out = vec![0u8; want.len()];
            // Info in twee stukken, om de gesplitste invoer mee te testen.
            let (a, b) = info.split_at(info.len() / 2);
            assert!(expand(&got_prk, &[a, b], &mut out));
            assert_eq!(out, want, "RFC 5869 OKM {}", i + 1);
        }
    }

    #[test]
    fn expand_refuses_too_long() {
        let mut out = vec![0u8; 255 * LEN + 1];
        assert!(!expand(&[0u8; 32], &[], &mut out));
    }
}
