//! SHA-512 (FIPS 180-4), alleen omdat Ed25519 hem voorschrijft.
//!
//! De suite zelf gebruikt SHA-256; deze hash komt alleen in de
//! handtekening-verificatie voor, over publieke data.

/// Lengte van een SHA-512-digest in bytes.
pub(crate) const LEN: usize = 64;

/// Blokgrootte van SHA-512.
const BLOCK: usize = 128;

/// De ronde-constanten: de eerste 64 bits van de breukdelen van de
/// derdemachtswortels van de eerste 80 priemgetallen.
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// De begintoestand van SHA-512.
const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Een lopende SHA-512.
pub(crate) struct Sha512 {
    /// De kettingwaarde.
    h: [u64; 8],
    /// Het nog onvolledige blok.
    buf: [u8; BLOCK],
    /// Aantal geldige bytes in `buf`.
    fill: usize,
    /// Totaal aantal verwerkte bytes. Een handtekening gaat over hooguit een
    /// paar honderd bytes, dus 64 bits lengte is ruim; de padding schrijft
    /// het als 128 bits met een nul-bovenhelft.
    total: u64,
}

impl Sha512 {
    /// Begint een nieuwe hash.
    pub(crate) const fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK],
            fill: 0,
            total: 0,
        }
    }

    /// Voegt `data` toe.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (BLOCK - self.fill).min(data.len());
            let (head, rest) = data.split_at(take);
            self.buf[self.fill..self.fill + take].copy_from_slice(head);
            self.fill += take;
            data = rest;
            if self.fill == BLOCK {
                compress(&mut self.h, &self.buf);
                self.fill = 0;
            }
        }
    }

    /// Sluit af en geeft de digest.
    pub(crate) fn finish(mut self) -> [u8; LEN] {
        let bits = u128::from(self.total).wrapping_mul(8);
        self.buf[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > BLOCK - 16 {
            self.buf[self.fill..].fill(0);
            compress(&mut self.h, &self.buf);
            self.fill = 0;
        }
        self.buf[self.fill..BLOCK - 16].fill(0);
        self.buf[BLOCK - 16..].copy_from_slice(&bits.to_be_bytes());
        compress(&mut self.h, &self.buf);
        let mut out = [0u8; LEN];
        for (o, w) in out.chunks_exact_mut(8).zip(self.h) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// Verwerkt één blok van 128 bytes.
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK]) {
    let mut w = [0u64; 80];
    for (wi, c) in w.iter_mut().zip(block.chunks_exact(8)) {
        *wi = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for (k, wi) in K.iter().zip(w) {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::unhex;

    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Sha512::new();
        h.update(data);
        h.finish().to_vec()
    }

    /// RFC 6234 §8.5 (TEST1, TEST2_2, TEST3) voor SHA-512.
    #[test]
    fn rfc6234_vectors() {
        assert_eq!(
            digest(b"abc"),
            unhex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        assert_eq!(
            digest(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            unhex(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                 501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            )
        );
        let mut h = Sha512::new();
        let block = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&block);
        }
        assert_eq!(
            h.finish().to_vec(),
            unhex(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                 de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }
}
