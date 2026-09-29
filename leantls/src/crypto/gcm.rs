//! AES-128-GCM (NIST SP 800-38D) met een nonce van 96 bits.
//!
//! GHASH vermenigvuldigt bit voor bit met maskers, zonder tabel en zonder
//! sprong op de sleutel H of de data: constant-time. De tag wordt
//! constant-time vergeleken, en bij een foute tag wordt niets ontsleuteld.

use super::aes::Aes128;
use super::ct;

/// Lengte van de tag.
pub(crate) const TAG_LEN: usize = 16;

/// Een AES-128-GCM-sleutel.
pub(crate) struct Gcm {
    /// De blokcijfer.
    aes: Aes128,
    /// De hashsleutel H = E(K, 0^128), big-endian gelezen.
    h: u128,
}

/// De tag klopte niet; de data is onaangeroerd.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TagMismatch;

impl Gcm {
    /// Zet een sleutel op.
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        let mut h = [0u8; 16];
        aes.encrypt(&mut h);
        let hv = u128::from_be_bytes(h);
        ct::wipe(&mut h);
        Self { aes, h: hv }
    }

    /// Versleutelt `data` op zijn plek en geeft de tag.
    pub(crate) fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        self.ctr(nonce, data);
        self.tag(nonce, aad, data)
    }

    /// Controleert de tag en ontsleutelt daarna `data` op zijn plek.
    pub(crate) fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TagMismatch> {
        let want = self.tag(nonce, aad, data);
        if !ct::eq(&want, tag) {
            return Err(TagMismatch);
        }
        self.ctr(nonce, data);
        Ok(())
    }

    /// De tellermodus vanaf teller 2 (teller 1 is voor de tag).
    fn ctr(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut counter = 2u32;
        for chunk in data.chunks_mut(16) {
            let mut ks = [0u8; 16];
            ks[..12].copy_from_slice(nonce);
            ks[12..].copy_from_slice(&counter.to_be_bytes());
            self.aes.encrypt(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks) {
                *d ^= k;
            }
            counter = counter.wrapping_add(1);
        }
    }

    /// De tag: E(K, J0) xor GHASH(H, A, C).
    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        let mut y = 0u128;
        for part in [aad, ct] {
            for chunk in part.chunks(16) {
                let mut b = [0u8; 16];
                b[..chunk.len()].copy_from_slice(chunk);
                y = gf128_mul(y ^ u128::from_be_bytes(b), self.h);
            }
        }
        let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        y = gf128_mul(y ^ lens, self.h);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        self.aes.encrypt(&mut j0);
        (u128::from_be_bytes(j0) ^ y).to_be_bytes()
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        let mut h = [self.h];
        ct::wipe(&mut h);
        self.h = h[0];
    }
}

/// x * y in GF(2^128) met de GCM-bitvolgorde (SP 800-38D algoritme 1).
fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        let bit = (x >> i) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let lsb = v & 1;
        v = (v >> 1) ^ ((0xe1u128 << 120) & 0u128.wrapping_sub(lsb));
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::unhex;

    fn key(hex: &str) -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&unhex(hex));
        k
    }

    fn iv(hex: &str) -> [u8; 12] {
        let mut k = [0u8; 12];
        k.copy_from_slice(&unhex(hex));
        k
    }

    /// Sleutel, nonce, klaartekst, AAD, ciphertext, tag.
    type Case = (
        &'static str,
        &'static str,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        &'static str,
    );

    /// De GCM-testgevallen 1 tot en met 4 (AES-128) uit McGrew en Viega,
    /// "The Galois/Counter Mode of Operation", bijlage B.
    #[test]
    fn gcm_spec_vectors() {
        let p3 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                  1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let c3 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                  21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let cases: [Case; 4] = [
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                "58e2fccefa7e3061367f1d57a4e7455a",
            ),
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                vec![0; 16],
                Vec::new(),
                unhex("0388dace60b6a392f328c2b971b2fe78"),
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                "feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                unhex(p3),
                Vec::new(),
                unhex(c3),
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (
                "feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                unhex(p3)[..60].to_vec(),
                unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
                unhex(c3)[..60].to_vec(),
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
        ];
        for (i, (k, n, p, a, c, t)) in cases.iter().enumerate() {
            let g = Gcm::new(&key(k));
            let mut buf = p.clone();
            let tag = g.seal(&iv(n), a, &mut buf);
            assert_eq!(&buf, c, "testgeval {}: ciphertext", i + 1);
            assert_eq!(tag.to_vec(), unhex(t), "testgeval {}: tag", i + 1);
            assert_eq!(g.open(&iv(n), a, &mut buf, &tag), Ok(()));
            assert_eq!(&buf, p, "testgeval {}: terug naar klaartekst", i + 1);
        }
    }

    /// Een omgedraaide bit in tag, data of AAD: weigeren en niets ontsleutelen.
    #[test]
    fn open_rejects_tampering() {
        let g = Gcm::new(&[7u8; 16]);
        let n = [1u8; 12];
        let mut buf = b"leantls record".to_vec();
        let tag = g.seal(&n, b"hdr", &mut buf);
        let sealed = buf.clone();

        let mut bad_tag = tag;
        bad_tag[15] ^= 1;
        assert_eq!(g.open(&n, b"hdr", &mut buf, &bad_tag), Err(TagMismatch));
        assert_eq!(buf, sealed, "data aangeraakt ondanks foute tag");

        buf[0] ^= 1;
        assert_eq!(g.open(&n, b"hdr", &mut buf, &tag), Err(TagMismatch));
        buf[0] ^= 1;
        assert_eq!(g.open(&n, b"hdX", &mut buf, &tag), Err(TagMismatch));
        assert_eq!(g.open(&n, b"hdr", &mut buf, &tag), Ok(()));
        assert_eq!(buf, b"leantls record");
    }
}
