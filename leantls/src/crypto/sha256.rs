//! SHA-256 (FIPS 180-4), de hash van de ene suite.
//!
//! Bezit alleen de toestand van één lopende hash. `Clone` is goedkoop (ruim
//! honderd bytes), en daarmee maakt de handshake zijn tussenstanden van het
//! transcript zonder het transcript zelf te bewaren.

/// Lengte van een SHA-256-digest in bytes.
pub(crate) const LEN: usize = 32;

/// Blokgrootte van SHA-256, nodig voor HMAC.
pub(crate) const BLOCK: usize = 64;

/// De ronde-constanten: de eerste 32 bits van de breukdelen van de
/// derdemachtswortels van de eerste 64 priemgetallen.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// De begintoestand: breukdelen van de vierkantswortels van de eerste acht
/// priemgetallen.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Een lopende SHA-256.
#[derive(Clone)]
pub(crate) struct Sha256 {
    /// De kettingwaarde.
    h: [u32; 8],
    /// Het nog onvolledige blok.
    buf: [u8; BLOCK],
    /// Aantal geldige bytes in `buf`.
    fill: usize,
    /// Totaal aantal verwerkte bytes, voor de lengte in de padding.
    total: u64,
}

impl Sha256 {
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

    /// Sluit af met padding en lengte en geeft de digest.
    pub(crate) fn finish(mut self) -> [u8; LEN] {
        let bits = self.total.wrapping_mul(8);
        self.buf[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > BLOCK - 8 {
            self.buf[self.fill..].fill(0);
            compress(&mut self.h, &self.buf);
            self.fill = 0;
        }
        self.buf[self.fill..BLOCK - 8].fill(0);
        self.buf[BLOCK - 8..].copy_from_slice(&bits.to_be_bytes());
        compress(&mut self.h, &self.buf);
        let mut out = [0u8; LEN];
        for (o, w) in out.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Hasht `data` in één keer.
    pub(crate) fn digest(data: &[u8]) -> [u8; LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // Een HMAC-toestand bevat de afgeleide sleutel; wis altijd.
        super::ct::wipe(&mut self.h);
        super::ct::wipe(&mut self.buf);
    }
}

/// Verwerkt één blok van 64 bytes.
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK]) {
    let mut w = [0u32; 64];
    for (wi, c) in w.iter_mut().zip(block.chunks_exact(4)) {
        *wi = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for (k, wi) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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

    /// RFC 6234 §8.5 (TEST1, TEST2_1, TEST3) voor SHA-256.
    #[test]
    fn rfc6234_vectors() {
        assert_eq!(
            Sha256::digest(b"abc").to_vec(),
            unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
            unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
        let mut h = Sha256::new();
        let block = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&block);
        }
        assert_eq!(
            h.finish().to_vec(),
            unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    /// Een lege invoer en een invoer die precies de padding-grens raakt.
    #[test]
    fn padding_edges() {
        assert_eq!(
            Sha256::digest(b"").to_vec(),
            unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // 55 en 56 bytes: de ene past met lengte in één blok, de andere niet.
        let one = Sha256::digest(&[0u8; 55]);
        let mut split = Sha256::new();
        split.update(&[0u8; 30]);
        split.update(&[0u8; 25]);
        assert_eq!(one, split.finish());
        assert_ne!(Sha256::digest(&[0u8; 56]), one);
    }
}
