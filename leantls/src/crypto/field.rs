//! Rekenen modulo p = 2^255 - 19, het veld onder X25519 en Ed25519.
//!
//! Vijf ledematen van 51 bits met 128-bits producten: eenvoudig, snel genoeg
//! voor één sleuteluitwisseling en een paar handtekeningen per handshake, en
//! zonder sprongen die van de waarde afhangen. Machten gebruiken een vaste,
//! publieke exponent, dus hun verloop is ook onafhankelijk van het geheim.
//!
//! Constant-time onder de aanname dat de vermenigvuldiger van de CPU dat is
//! (op aarch64 en x86-64 het geval); `is_zero` en `is_negative` zijn dat ook,
//! maar worden alleen op publieke waarden gebruikt.

/// Masker voor één lidmaat van 51 bits.
const MASK: u64 = (1 << 51) - 1;

/// Een veldelement. Ledematen zijn na elke bewerking zwak gereduceerd (net
/// boven 2^51 hooguit), niet noodzakelijk canoniek; `to_bytes` reduceert
/// volledig.
#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    /// Nul.
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    /// Een.
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Een klein getal als veldelement.
    pub(crate) const fn from_u64(v: u64) -> Fe {
        Fe([v & MASK, v >> 51, 0, 0, 0])
    }

    /// Leest 32 bytes little-endian en negeert bit 255, zoals RFC 7748 en
    /// RFC 8032 voorschrijven. Waarden tussen p en 2^255 blijven geldig als
    /// niet-gereduceerde representatie.
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(w)
        };
        Fe([
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            (load(24) >> 12) & MASK,
        ])
    }

    /// Canonieke 32-byte-codering (volledig gereduceerd, bit 255 nul).
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut h = carry(self.0).0;
        // q = 1 als h >= p: tel 19 op en kijk of er een bit 255 ontstaat.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        h[2] += h[1] >> 51;
        h[1] &= MASK;
        h[3] += h[2] >> 51;
        h[2] &= MASK;
        h[4] += h[3] >> 51;
        h[3] &= MASK;
        h[4] &= MASK;
        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (o, w) in out.chunks_exact_mut(8).zip(words) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// a + b.
    pub(crate) fn add(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        carry([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    /// a - b. Telt eerst 4p op, zodat geen lidmaat onder nul komt: de
    /// ledematen van `b` zijn na `carry` kleiner dan 2^52.
    pub(crate) fn sub(self, b: Fe) -> Fe {
        let a = self.0;
        let b = b.0;
        const P4_0: u64 = 4 * ((1 << 51) - 19);
        const P4_N: u64 = 4 * ((1 << 51) - 1);
        carry([
            a[0] + P4_0 - b[0],
            a[1] + P4_N - b[1],
            a[2] + P4_N - b[2],
            a[3] + P4_N - b[3],
            a[4] + P4_N - b[4],
        ])
    }

    /// -a.
    pub(crate) fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// a * b.
    pub(crate) fn mul(self, b: Fe) -> Fe {
        let a = self.0.map(u128::from);
        let b = b.0.map(u128::from);
        let b19 = [b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let c = [
            a[0] * b[0] + a[4] * b19[0] + a[3] * b19[1] + a[2] * b19[2] + a[1] * b19[3],
            a[1] * b[0] + a[0] * b[1] + a[4] * b19[1] + a[3] * b19[2] + a[2] * b19[3],
            a[2] * b[0] + a[1] * b[1] + a[0] * b[2] + a[4] * b19[2] + a[3] * b19[3],
            a[3] * b[0] + a[2] * b[1] + a[1] * b[2] + a[0] * b[3] + a[4] * b19[3],
            a[4] * b[0] + a[3] * b[1] + a[2] * b[2] + a[1] * b[3] + a[0] * b[4],
        ];
        carry_wide(c)
    }

    /// a^2.
    pub(crate) fn square(self) -> Fe {
        self.mul(self)
    }

    /// a * een kleine constante (zoals a24 = 121665 in de ladder).
    pub(crate) fn mul_small(self, k: u32) -> Fe {
        let k = u128::from(k);
        carry_wide(self.0.map(|l| u128::from(l) * k))
    }

    /// a^e met een publieke exponent van 32 bytes little-endian.
    ///
    /// Kwadrateren en vermenigvuldigen per bit: het patroon hangt alleen van
    /// de exponent af, en die is overal een constante (p-2, (p-5)/8, (p-1)/4).
    pub(crate) fn pow(self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for byte in e.iter().rev() {
            for bit in (0..8).rev() {
                r = r.square();
                if (byte >> bit) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }

    /// 1/a via a^(p-2); nul geeft nul.
    pub(crate) fn invert(self) -> Fe {
        // p - 2 = 2^255 - 21, little-endian.
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        self.pow(&e)
    }

    /// Of a nul is (mod p).
    pub(crate) fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    /// Of a "negatief" is in de zin van RFC 8032: de laagste bit van de
    /// canonieke codering.
    pub(crate) fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Of twee elementen gelijk zijn (mod p).
    pub(crate) fn equals(self, b: Fe) -> bool {
        super::ct::eq(&self.to_bytes(), &b.to_bytes())
    }

    /// Verwisselt a en b als `bit` 1 is, zonder sprong.
    pub(crate) fn cswap(a: &mut Fe, b: &mut Fe, bit: u64) {
        let mask = 0u64.wrapping_sub(bit);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}

/// Draagt de overlopen door naar boven en vouwt de bovenste terug met 19
/// (want 2^255 = 19 mod p). Invoer-ledematen kleiner dan 2^63.
fn carry(mut l: [u64; 5]) -> Fe {
    l[1] += l[0] >> 51;
    l[0] &= MASK;
    l[2] += l[1] >> 51;
    l[1] &= MASK;
    l[3] += l[2] >> 51;
    l[2] &= MASK;
    l[4] += l[3] >> 51;
    l[3] &= MASK;
    let top = l[4] >> 51;
    l[4] &= MASK;
    l[0] += top * 19;
    l[1] += l[0] >> 51;
    l[0] &= MASK;
    Fe(l)
}

/// Als `carry`, maar voor 128-bits kolommen uit een vermenigvuldiging.
fn carry_wide(mut c: [u128; 5]) -> Fe {
    let m = u128::from(MASK);
    c[1] += c[0] >> 51;
    c[0] &= m;
    c[2] += c[1] >> 51;
    c[1] &= m;
    c[3] += c[2] >> 51;
    c[2] &= m;
    c[4] += c[3] >> 51;
    c[3] &= m;
    let top = c[4] >> 51;
    c[4] &= m;
    // Hier in 128 bits: `top * 19` past niet altijd in 64.
    c[0] += top * 19;
    c[1] += c[0] >> 51;
    c[0] &= m;
    // Alle kolommen zijn nu kleiner dan 2^52 en passen in u64.
    Fe(c.map(|v| v as u64))
}
