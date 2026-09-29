//! SHA-256 (FIPS 180-4), alleen wat SigV4 nodig heeft.
//!
//! Deze module bezit de hashfunctie en niets anders. Hij staat hier en niet in
//! een gedeelde crate omdat elke lean-crate op zichzelf staat: leans3 mag
//! leantls niet importeren voor één hash, want dan linkt een MinIO-klant over
//! gewoon HTTP alsnog de hele TLS-stapel.

/// De begintoestand uit FIPS 180-4 §5.3.3.
const INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// De rondeconstanten uit FIPS 180-4 §4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Lengte van een digest in bytes.
pub(crate) const DIGEST_LEN: usize = 32;

/// Blokgrootte in bytes; HMAC heeft hem nodig voor zijn sleutelvulling.
pub(crate) const BLOCK_LEN: usize = 64;

/// Een lopende SHA-256-berekening.
#[derive(Clone)]
pub(crate) struct Sha256 {
    /// De acht werkwoorden na het laatste volle blok.
    state: [u32; 8],
    /// Het onvolledige blok dat nog op meer invoer wacht.
    buf: [u8; BLOCK_LEN],
    /// Hoeveel bytes van `buf` gevuld zijn; altijd kleiner dan een blok.
    fill: usize,
    /// Het totale aantal bytes invoer, voor de lengte in de vulling.
    total: u64,
}

impl Sha256 {
    /// Begint een nieuwe berekening.
    pub(crate) const fn new() -> Self {
        Self {
            state: INIT,
            buf: [0; BLOCK_LEN],
            fill: 0,
            total: 0,
        }
    }

    /// Voegt `data` toe.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        // Wrap is hier de bedoeling: FIPS 180-4 rekent de lengte modulo 2^64.
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.fill > 0 {
            let room = BLOCK_LEN - self.fill;
            let take = room.min(data.len());
            let (head, rest) = data.split_at(take);
            if let Some(dst) = self.buf.get_mut(self.fill..self.fill + take) {
                dst.copy_from_slice(head);
            }
            self.fill += take;
            data = rest;
            if self.fill < BLOCK_LEN {
                return;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.fill = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK_LEN);
        for block in &mut blocks {
            compress(&mut self.state, block);
        }
        let tail = blocks.remainder();
        if let Some(dst) = self.buf.get_mut(..tail.len()) {
            dst.copy_from_slice(tail);
        }
        self.fill = tail.len();
    }

    /// Sluit de berekening af en geeft de digest.
    pub(crate) fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.total.wrapping_mul(8);
        // Vulling uit §5.1.1: één 1-bit, nullen, dan de lengte in 64 bits.
        let mut pad = [0u8; BLOCK_LEN + 8];
        pad[0] = 0x80;
        let zeros = (BLOCK_LEN + BLOCK_LEN - 8 - self.fill - 1) % BLOCK_LEN;
        let end = 1 + zeros;
        let total = self.total;
        if let Some(dst) = pad.get_mut(end..end + 8) {
            dst.copy_from_slice(&bits.to_be_bytes());
        }
        if let Some(padding) = pad.get(..end + 8) {
            self.update(padding);
        }
        // De vulling telt niet mee in de lengte; update hierboven deed dat wel,
        // maar de lengte stond al vast voordat die aanroep kwam.
        self.total = total;
        let mut out = [0u8; DIGEST_LEN];
        for (dst, word) in out.chunks_exact_mut(4).zip(self.state) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Berekent de digest van `data` in één keer.
pub(crate) fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// Verwerkt één blok van 64 bytes (§6.2.2).
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (dst, src) in w.iter_mut().zip(block.chunks_exact(4)) {
        *dst = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wt) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(wt);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // De voorbeelden uit FIPS 180-4 (NIST CSRC "SHA256.pdf") plus de lege
    // invoer, die SigV4 voor elke GET, DELETE en LIST tekent.
    #[test]
    fn nist_vectoren() {
        let cases: [(&[u8], &str); 3] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex(&digest(input)), want);
        }
    }

    // Een miljoen keer 'a', in stukken die niet op een blokgrens vallen: dat
    // toetst het samenvoegen van onvolledige blokken.
    #[test]
    fn miljoen_a_in_scheve_stukken() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 997];
        let mut left = 1_000_000usize;
        while left > 0 {
            let n = left.min(chunk.len());
            h.update(&chunk[..n]);
            left -= n;
        }
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
