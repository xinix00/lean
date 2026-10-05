//! AES-128-GCM (NIST SP 800-38D) met een nonce van 96 bits.
//!
//! GHASH is BearSSL's `ghash_ctmul64` (Thomas Pornin, MIT,
//! <https://www.bearssl.org/constanttime.html#ghash-for-gcm>): de
//! carry-less vermenigvuldiging als vier gewone 64-bitsvermenigvuldigingen
//! met om de vier bits gemaskeerde operanden, en de reductie met schuiven.
//! Geen tabel en geen sprong op H of de data, dus constant-time zolang de
//! vermenigvuldiginstructie dat is (op de C906 en ARMv8 wel). Tot 03-10
//! vermenigvuldigde deze module bit voor bit: 128 rondes per blok. De
//! tellermodus versleutelt vier blokken per AES-aanroep. De tag wordt
//! constant-time vergeleken, en bij een foute tag wordt niets ontsleuteld.

use crate::aes::{Aes128, Blocks};
use crate::ct;

/// Lengte van de tag.
pub const TAG_LEN: usize = 16;

/// Een AES-128-GCM-sleutel.
pub struct Gcm {
    /// De blokcijfer.
    aes: Aes128,
    /// De hashsleutel H = E(K, 0^128), big-endian gelezen.
    h: u128,
}

/// De tag klopte niet; de data is onaangeroerd.
#[derive(Debug, PartialEq, Eq)]
pub struct TagMismatch;

impl Gcm {
    /// Zet een sleutel op.
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        let mut h = [0u8; 16];
        aes.encrypt(&mut h);
        let hv = u128::from_be_bytes(h);
        ct::wipe(&mut h);
        Self { aes, h: hv }
    }

    /// Versleutelt `data` op zijn plek en geeft de tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        self.ctr(nonce, data);
        self.tag(nonce, aad, data)
    }

    /// Controleert de tag en ontsleutelt daarna `data` op zijn plek.
    pub fn open(
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

    /// De tellermodus vanaf teller 2 (teller 1 is voor de tag), vier blokken
    /// per AES-aanroep.
    fn ctr(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut counter = 2u32;
        for chunk in data.chunks_mut(64) {
            let mut ks: Blocks = [[0u8; 16]; 4];
            for block in &mut ks {
                block[..12].copy_from_slice(nonce);
                block[12..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);
            }
            self.aes.encrypt4(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter().flatten()) {
                *d ^= k;
            }
            ct::wipe(ks.as_flattened_mut());
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

/// x * y in GF(2^128) met de GCM-bitvolgorde: BearSSL's `ghash_ctmul64`
/// voor één blok (`x` is het al ge-xorde blok, `y` is H).
fn gf128_mul(x: u128, y: u128) -> u128 {
    let (x1, x0) = ((x >> 64) as u64, x as u64);
    let (h1, h0) = ((y >> 64) as u64, y as u64);
    let (h0r, h1r) = (rev64(h0), rev64(h1));
    let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
    let (x0r, x1r) = (rev64(x0), rev64(x1));
    let (x2, x2r) = (x0 ^ x1, x0r ^ x1r);
    let z0 = bmul64(x0, h0);
    let z1 = bmul64(x1, h1);
    let mut z2 = bmul64(x2, h2);
    let mut z0h = bmul64(x0r, h0r);
    let mut z1h = bmul64(x1r, h1r);
    let mut z2h = bmul64(x2r, h2r);
    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;
    let (mut v0, mut v1, mut v2, mut v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
    // Het product van twee bitomgekeerde polynomen van 128 bits is het
    // omgekeerde over 255 bits: één bit terugschuiven (BearSSL).
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 <<= 1;
    // Reductie modulo x^128 + x^7 + x^2 + x + 1.
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    (u128::from(v3) << 64) | u128::from(v2)
}

/// Carry-less 64x64 (onderste 64 bits) met gewone vermenigvuldigingen: elke
/// operand in vier delen met om de vier bits een gat, zodat de dragers van de
/// gewone vermenigvuldiging in de gaten vallen en weggemaskeerd worden.
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// De bits van een woord omgekeerd.
fn rev64(x: u64) -> u64 {
    x.reverse_bits()
}

/// De vorige vermenigvuldiger (SP 800-38D algoritme 1, bit voor bit), als
/// onafhankelijke referentie voor de tests.
#[cfg(test)]
fn gf128_mul_reference(x: u128, y: u128) -> u128 {
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

    /// Doorvoer van seal over 1 MiB; draai met
    /// `cargo test -p leantls --release -- --ignored seal_throughput --nocapture`.
    #[test]
    #[ignore = "meting, geen toets"]
    fn seal_throughput() {
        let g = Gcm::new(&[7u8; 16]);
        let mut data = vec![0x5au8; 1 << 20];
        let t0 = std::time::Instant::now();
        let rounds: u32 = 8;
        for _ in 0..rounds {
            let _ = g.seal(&[1u8; 12], b"aad", &mut data);
        }
        let dt = t0.elapsed().as_secs_f64();
        std::println!("seal: {:.1} MB/s", f64::from(rounds) / dt);
    }

    /// De nieuwe vermenigvuldiger tegen de oude bit-voor-bit, op willekeurige
    /// en randwaarden.
    #[test]
    fn ctmul64_matches_the_bitwise_reference() {
        let mut seed = 0x0123_4567_89ab_cdef_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut wide = || (u128::from(next()) << 64) | u128::from(next());
        let edges = [
            0,
            1,
            u128::MAX,
            1 << 127,
            1 << 64,
            (1 << 64) - 1,
            0xe1 << 120,
        ];
        for x in edges {
            for y in edges {
                assert_eq!(
                    gf128_mul(x, y),
                    gf128_mul_reference(x, y),
                    "{x:#x} * {y:#x}"
                );
            }
        }
        for _ in 0..20_000 {
            let (x, y) = (wide(), wide());
            assert_eq!(
                gf128_mul(x, y),
                gf128_mul_reference(x, y),
                "{x:#x} * {y:#x}"
            );
        }
    }
    use crate::testutil::unhex;

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
