//! AES-128 (FIPS 197), alleen versleutelen: GCM heeft de inverse niet nodig.
//!
//! Zonder opzoektabel. Een S-box-tabel lekt de sleutel via de cache; hier
//! wordt de S-box uitgerekend als inverse in GF(2^8) (x^254) plus de affiene
//! afbeelding, voor alle zestien bytes tegelijk in één `u128` (SWAR). Geen
//! index en geen sprong hangt van sleutel of tekst af, dus constant-time
//! zolang de vermenigvuldiger dat is. Het kost ongeveer 450 bewerkingen per
//! byte; voor een node die een paar megabyte per verbinding haalt is dat
//! genoeg, en het is de prijs van geen tabel.

use super::ct::wipe;

/// Eén `0x01` in elke byte-baan.
const LO: u128 = 0x0101_0101_0101_0101_0101_0101_0101_0101;
/// `0xfe` in elke baan: wat na een schuif naar links binnen de baan blijft.
const HI7: u128 = LO * 0xfe;

/// x * 2 in GF(2^8), per baan.
fn xtime(x: u128) -> u128 {
    ((x << 1) & HI7) ^ (((x >> 7) & LO) * 0x1b)
}

/// a * b in GF(2^8), per baan, zonder sprong.
fn gf_mul(mut a: u128, b: u128) -> u128 {
    let mut r = 0;
    for i in 0..8 {
        let m = ((b >> i) & LO) * 0xff;
        r ^= a & m;
        a = xtime(a);
    }
    r
}

/// x^254 = x^-1 in GF(2^8) (en 0 blijft 0), per baan.
fn gf_inv(x: u128) -> u128 {
    let x2 = gf_mul(x, x);
    let x3 = gf_mul(x2, x);
    let x6 = gf_mul(x3, x3);
    let x12 = gf_mul(x6, x6);
    let x15 = gf_mul(x12, x3);
    let x30 = gf_mul(x15, x15);
    let x60 = gf_mul(x30, x30);
    let x120 = gf_mul(x60, x60);
    let x126 = gf_mul(x120, x6);
    let x127 = gf_mul(x126, x);
    gf_mul(x127, x127)
}

/// Draait elke baan `k` bits naar links.
fn rotl(x: u128, k: u32) -> u128 {
    let hi = LO * ((0xffu128 << k) & 0xff);
    let lo = LO * (0xffu128 >> (8 - k));
    ((x << k) & hi) | ((x >> (8 - k)) & lo)
}

/// SubBytes op zestien banen.
fn sub_bytes(x: u128) -> u128 {
    let b = gf_inv(x);
    b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ (LO * 0x63)
}

/// x * 2 in GF(2^8) voor één byte.
fn xtime8(b: u8) -> u8 {
    (b << 1) ^ ((b >> 7) * 0x1b)
}

/// AES-128 met uitgerolde rondesleutels.
pub(crate) struct Aes128 {
    /// Elf rondesleutels van zestien bytes.
    rk: [[u8; 16]; 11],
}

impl Aes128 {
    /// Zet de sleutel uit (FIPS 197 §5.2).
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for (wi, c) in w.iter_mut().zip(key.chunks_exact(4)) {
            wi.copy_from_slice(c);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [t[1], t[2], t[3], t[0]];
                let s = sub_bytes(u128::from(u32::from_le_bytes(t))).to_le_bytes();
                t = [s[0] ^ rcon, s[1], s[2], s[3]];
                rcon = xtime8(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for (r, k) in rk.iter_mut().enumerate() {
            for c in 0..4 {
                k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        for wi in w.iter_mut() {
            wipe(wi);
        }
        Self { rk }
    }

    /// Versleutelt één blok.
    pub(crate) fn encrypt(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.rk[0]);
        for r in 1..10 {
            *block = sub_bytes(u128::from_le_bytes(*block)).to_le_bytes();
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.rk[r]);
        }
        *block = sub_bytes(u128::from_le_bytes(*block)).to_le_bytes();
        shift_rows(block);
        add_round_key(block, &self.rk[10]);
    }
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        for k in self.rk.iter_mut() {
            wipe(k);
        }
    }
}

/// XOR met een rondesleutel.
fn add_round_key(s: &mut [u8; 16], k: &[u8; 16]) {
    for (x, y) in s.iter_mut().zip(k) {
        *x ^= y;
    }
}

/// ShiftRows: rij r schuift r kolommen naar links (toestand kolom-voor-kolom).
fn shift_rows(s: &mut [u8; 16]) {
    let o = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[r + 4 * c] = o[r + 4 * ((c + r) % 4)];
        }
    }
}

/// MixColumns per kolom.
fn mix_columns(s: &mut [u8; 16]) {
    for col in s.chunks_exact_mut(4) {
        let [a0, a1, a2, a3] = [col[0], col[1], col[2], col[3]];
        let all = a0 ^ a1 ^ a2 ^ a3;
        col[0] = a0 ^ all ^ xtime8(a0 ^ a1);
        col[1] = a1 ^ all ^ xtime8(a1 ^ a2);
        col[2] = a2 ^ all ^ xtime8(a2 ^ a3);
        col[3] = a3 ^ all ^ xtime8(a3 ^ a0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::unhex;

    /// FIPS 197 bijlage C.1, AES-128.
    #[test]
    fn fips197_vector() {
        let mut key = [0u8; 16];
        key.copy_from_slice(&unhex("000102030405060708090a0b0c0d0e0f"));
        let mut block = [0u8; 16];
        block.copy_from_slice(&unhex("00112233445566778899aabbccddeeff"));
        Aes128::new(&key).encrypt(&mut block);
        assert_eq!(block.to_vec(), unhex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    /// De uitgerekende S-box tegen een paar bekende waarden uit FIPS 197 fig. 7.
    #[test]
    fn sbox_spot_checks() {
        let known = [
            (0x00u8, 0x63u8),
            (0x01, 0x7c),
            (0x53, 0xed),
            (0xff, 0x16),
            (0x10, 0xca),
        ];
        for (x, want) in known {
            assert_eq!(sub_bytes(u128::from(x)) as u8, want, "S({x:#04x})");
        }
    }
}
