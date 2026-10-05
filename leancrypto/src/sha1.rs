//! SHA-1 (FIPS 180-4), alleen voor protocollen die hem voorschrijven.
//!
//! SHA-1 is gebroken als hash tegen botsingen; gebruik hem nooit om iets te
//! vertrouwen. Hij staat hier omdat protocollen hem eisen zonder dat er een
//! geheim aan hangt: `Sec-WebSocket-Accept` (RFC 6455) en de sleutelafleiding
//! van oudere schijfformaten. Eén implementatie in plaats van een kopie per
//! app.

/// Lengte van een SHA-1-digest in bytes.
pub const LEN: usize = 20;

/// Blokgrootte van SHA-1.
const BLOCK: usize = 64;

/// De begintoestand.
const H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Een lopende SHA-1.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; BLOCK],
    fill: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Begint een nieuwe hash.
    pub const fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK],
            fill: 0,
            total: 0,
        }
    }

    /// Voegt `data` toe.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.fill > 0 {
            let take = (BLOCK - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill < BLOCK {
                return;
            }
            let block = self.buf;
            self.compress(&block);
            self.fill = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK);
        for block in &mut blocks {
            let mut b = [0u8; BLOCK];
            b.copy_from_slice(block);
            self.compress(&b);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.fill = rest.len();
    }

    /// Sluit af met de padding en geeft de digest.
    pub fn finish(mut self) -> [u8; LEN] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.fill != BLOCK - 8 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; LEN];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// De digest van `data` in één keer.
    pub fn digest(data: &[u8]) -> [u8; LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut w = [0u32; 80];
        for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.h;
        for (t, &word) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (h, v) in self.h.iter_mut().zip([a, b, c, d, e]) {
            *h = h.wrapping_add(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unhex;

    #[test]
    fn fips_vectors() {
        assert_eq!(
            Sha1::digest(b"abc").to_vec(),
            unhex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            Sha1::digest(b"").to_vec(),
            unhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
            unhex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    #[test]
    fn streaming_equals_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut h = Sha1::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), Sha1::digest(&data));
    }

    #[test]
    fn websocket_accept_from_rfc_6455() {
        // RFC 6455 §1.3: de sleutel uit het voorbeeld en zijn Accept.
        let mut h = Sha1::new();
        h.update(b"dGhlIHNhbXBsZSBub25jZQ==");
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(
            h.finish().to_vec(),
            unhex("b37a4f2cc0624f1690f64606cf385945b2bec4ea")
        );
    }
}
