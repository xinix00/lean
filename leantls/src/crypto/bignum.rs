//! Getallen van vaste maat en Montgomery-rekenen, voor handtekening-verificatie.
//!
//! Eén implementatie voor RSA (tot 4096 bits, `N = 64`) en voor de velden en
//! groepsordes van P-256 (`N = 4`) en P-384 (`N = 6`). Limbs zijn `u64`,
//! little-endian; een product loopt via `u128`.
//!
//! **Variabele tijd, bewust.** Hier gaan alleen publieke waarden doorheen:
//! een publieke sleutel, een handtekening en een digest van publieke data.
//! Machtsverheffen met een publieke exponent en vroeg stoppende
//! vergelijkingen lekken dus niets. Gebruik deze module nooit voor een
//! geheime sleutel.

use core::cmp::Ordering;

/// Een niet-negatief getal van `64 * N` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Uint<const N: usize>(pub(crate) [u64; N]);

impl<const N: usize> Uint<N> {
    /// Nul.
    pub(crate) const ZERO: Self = Self([0; N]);

    /// Een klein getal.
    pub(crate) const fn small(v: u64) -> Self {
        let mut l = [0u64; N];
        if N > 0 {
            l[0] = v;
        }
        Self(l)
    }

    /// Een constante uit big-endian hex, voor curveparameters. Een teken dat
    /// geen hex is telt als nul; de tests toetsen elke constante (het
    /// basispunt ligt op de curve), zodat een tikfout niet stil blijft.
    pub(crate) const fn from_hex(s: &str) -> Self {
        let b = s.as_bytes();
        let mut out = [0u64; N];
        let mut i = 0;
        while i < b.len() {
            let c = b[b.len() - 1 - i];
            let v: u64 = match c {
                b'0'..=b'9' => (c - b'0') as u64,
                b'a'..=b'f' => (c - b'a' + 10) as u64,
                b'A'..=b'F' => (c - b'A' + 10) as u64,
                _ => 0,
            };
            let limb = i / 16;
            if limb < N {
                out[limb] |= v << ((i % 16) * 4);
            }
            i += 1;
        }
        Self(out)
    }

    /// Leest een big-endian getal; voorloopnullen mogen. `None` als het niet
    /// in `64 * N` bits past.
    pub(crate) fn from_be(bytes: &[u8]) -> Option<Self> {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let bytes = bytes.get(start..)?;
        if bytes.len() > 8 * N {
            return None;
        }
        let mut out = [0u64; N];
        for (i, b) in bytes.iter().rev().enumerate() {
            let limb = out.get_mut(i / 8)?;
            *limb |= u64::from(*b) << ((i % 8) * 8);
        }
        Some(Self(out))
    }

    /// Schrijft het getal big-endian in precies `out.len()` bytes. `false`
    /// als het daar niet in past.
    pub(crate) fn write_be(&self, out: &mut [u8]) -> bool {
        out.fill(0);
        let len = out.len();
        for (i, o) in out.iter_mut().rev().enumerate() {
            let Some(limb) = self.0.get(i / 8) else {
                return true;
            };
            *o = (limb >> ((i % 8) * 8)) as u8;
        }
        // Alles boven de uitvoer moet nul zijn.
        (8 * len..64 * N).all(|bit| !self.bit(bit))
    }

    /// Is dit nul?
    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|l| *l == 0)
    }

    /// Bit `i` (0 is het minst significante); buiten bereik is nul.
    pub(crate) fn bit(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }

    /// Aantal significante bits.
    pub(crate) fn bits(&self) -> usize {
        for (i, l) in self.0.iter().enumerate().rev() {
            if *l != 0 {
                return 64 * i + 64 - l.leading_zeros() as usize;
            }
        }
        0
    }

    /// Vergelijkt, van het meest significante limb af.
    pub(crate) fn cmp(&self, o: &Self) -> Ordering {
        for (a, b) in self.0.iter().zip(o.0.iter()).rev() {
            match a.cmp(b) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// Optellen met de uitgaande carry.
    pub(crate) fn adc(&self, o: &Self) -> (Self, bool) {
        let mut out = [0u64; N];
        let mut carry = false;
        for ((r, a), b) in out.iter_mut().zip(self.0).zip(o.0) {
            let (s1, c1) = a.overflowing_add(b);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *r = s2;
            carry = c1 | c2;
        }
        (Self(out), carry)
    }

    /// Aftrekken met de uitgaande borrow.
    pub(crate) fn sbb(&self, o: &Self) -> (Self, bool) {
        let mut out = [0u64; N];
        let mut borrow = false;
        for ((r, a), b) in out.iter_mut().zip(self.0).zip(o.0) {
            let (d1, b1) = a.overflowing_sub(b);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *r = d2;
            borrow = b1 | b2;
        }
        (Self(out), borrow)
    }
}

/// Een oneven modulus met alles wat Montgomery-vermenigvuldigen nodig heeft.
///
/// Getallen "in Montgomery-vorm" zijn `a·R mod m` met `R = 2^(64N)`. Werkt
/// voor elke oneven `m < R`, dus ook voor een RSA-modulus van 2048 bits in
/// een `Uint<64>`.
///
/// # Invariants
///
/// `m` is oneven en groter dan 1; `inv · m ≡ -1 (mod 2^64)`; `r2 = R² mod m`;
/// `one = R mod m`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Monty<const N: usize> {
    /// De modulus.
    m: Uint<N>,
    /// `-m⁻¹ mod 2^64`.
    inv: u64,
    /// `R² mod m`, om naar Montgomery-vorm te gaan.
    r2: Uint<N>,
    /// `R mod m`: de één in Montgomery-vorm.
    one: Uint<N>,
}

impl<const N: usize> Monty<N> {
    /// Bereidt `m` voor; `None` als `m` even is of kleiner dan 3.
    pub(crate) fn new(m: Uint<N>) -> Option<Self> {
        let m0 = *m.0.first()?;
        let bits = m.bits();
        if m0 & 1 == 0 || bits < 2 {
            return None;
        }
        // Newton-iteratie: elke stap verdubbelt het aantal juiste bits;
        // 1 → 2 → … → 64 in zes stappen.
        let mut x_inv: u64 = 1;
        for _ in 0..6 {
            x_inv = x_inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(x_inv)));
        }
        // R mod m: begin bij de hoogste macht van twee onder m en verdubbel
        // tot 2^(64N). Voor een modulus die R vult is dat één stap.
        let mut one = Uint::ZERO;
        *one.0.get_mut((bits - 1) / 64)? = 1 << ((bits - 1) % 64);
        for _ in bits - 1..64 * N {
            one = double_mod(&one, &m);
        }
        let mut monty = Self {
            m,
            inv: x_inv.wrapping_neg(),
            r2: Uint::ZERO,
            one,
        };
        // R² mod m zonder deling: verdubbel R tot R·2^o en kwadrateer dan s
        // keer in Montgomery-vorm (mul(x, x) = x²/R, dus R·2^k wordt
        // R·2^(2k)), met 64N = o·2^s. Zo kost het o + s stappen in plaats
        // van 64N verdubbelingen.
        let total = 64 * N;
        let s = total.trailing_zeros();
        let mut x = one;
        for _ in 0..total >> s {
            x = double_mod(&x, &m);
        }
        for _ in 0..s {
            x = monty.mul(&x, &x);
        }
        // INVARIANT: m oneven en >= 3, x_inv·m0 ≡ 1 dus -x_inv·m0 ≡ -1,
        // one = R mod m, en nu r2 = R·2^(64N) = R² mod m.
        monty.r2 = x;
        Some(monty)
    }

    /// De modulus.
    pub(crate) fn modulus(&self) -> &Uint<N> {
        &self.m
    }

    /// De één in Montgomery-vorm.
    pub(crate) fn one(&self) -> Uint<N> {
        self.one
    }

    /// `a·b·R⁻¹ mod m` (CIOS). Invoer kleiner dan `m`, uitvoer ook.
    pub(crate) fn mul(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        // `t` is het lopende resultaat van N+2 limbs: `t` plus `hi` en `top`.
        let mut t = [0u64; N];
        let mut hi: u64 = 0;
        for bi in b.0 {
            // t += a · b[i]
            let mut c: u128 = 0;
            for (tj, aj) in t.iter_mut().zip(a.0) {
                let s = u128::from(*tj) + u128::from(aj) * u128::from(bi) + c;
                *tj = s as u64;
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            hi = s as u64;
            let top = (s >> 64) as u64;

            // t = (t + q·m) / 2^64, zodat de onderste limb wegvalt.
            let q = t.first().copied().unwrap_or(0).wrapping_mul(self.inv);
            let mut c: u128 = 0;
            for j in 0..N {
                let s = u128::from(t[j]) + u128::from(q) * u128::from(self.m.0[j]) + c;
                if j > 0 {
                    t[j - 1] = s as u64;
                }
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            if let Some(last) = t.last_mut() {
                *last = s as u64;
            }
            hi = top + (s >> 64) as u64;
        }
        // Het resultaat is kleiner dan 2m; hooguit één keer aftrekken.
        let r = Uint(t);
        if hi != 0 || r.cmp(&self.m) != Ordering::Less {
            r.sbb(&self.m).0
        } else {
            r
        }
    }

    /// Naar Montgomery-vorm; `a` moet kleiner zijn dan `m`.
    pub(crate) fn mont(&self, a: &Uint<N>) -> Uint<N> {
        self.mul(a, &self.r2)
    }

    /// Uit Montgomery-vorm.
    pub(crate) fn plain(&self, a: &Uint<N>) -> Uint<N> {
        self.mul(a, &Uint::small(1))
    }

    /// `a + b mod m`.
    pub(crate) fn add(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        let (s, carry) = a.adc(b);
        if carry || s.cmp(&self.m) != Ordering::Less {
            s.sbb(&self.m).0
        } else {
            s
        }
    }

    /// `a - b mod m`.
    pub(crate) fn sub(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        let (d, borrow) = a.sbb(b);
        if borrow { d.adc(&self.m).0 } else { d }
    }

    /// `base^exp` met `base` in Montgomery-vorm en `exp` als limbs,
    /// little-endian. Links-naar-rechts kwadrateren en vermenigvuldigen, in
    /// variabele tijd (alleen publieke exponenten, zie de moduledoc).
    pub(crate) fn pow(&self, base: &Uint<N>, exp: &[u64]) -> Uint<N> {
        let mut acc = self.one;
        for limb in exp.iter().rev() {
            for bit in (0..64).rev() {
                acc = self.mul(&acc, &acc);
                if (limb >> bit) & 1 == 1 {
                    acc = self.mul(&acc, base);
                }
            }
        }
        acc
    }

    /// De inverse van `a` (Montgomery-vorm) via Fermat, `a^(m-2)`; alleen
    /// geldig voor een priem `m`. Nul geeft nul, en de aanroeper weigert nul
    /// al eerder.
    pub(crate) fn inv_prime(&self, a: &Uint<N>) -> Uint<N> {
        let (e, _) = self.m.sbb(&Uint::small(2));
        self.pow(a, &e.0)
    }
}

/// `2a mod m` voor `a < m`.
fn double_mod<const N: usize>(a: &Uint<N>, m: &Uint<N>) -> Uint<N> {
    let (d, carry) = a.adc(a);
    if carry || d.cmp(m) != Ordering::Less {
        d.sbb(m).0
    } else {
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Een klein priemgetal in één limb: alles narekenbaar met `u128`.
    #[test]
    fn monty_matches_u128_reference() {
        let p: u64 = 0xffff_ffff_ffff_ffc5; // 2^64 - 59, priem
        for m in [p, 0xffff_fffb, 65537, 3] {
            let mont = Monty::<1>::new(Uint([m])).unwrap();
            let vals = [
                0u64,
                1,
                2,
                12345 % m,
                m - 1,
                m / 2,
                0xdead_beef_cafe_f00d % m,
            ];
            for a in vals {
                for b in vals {
                    let want = (u128::from(a) * u128::from(b) % u128::from(m)) as u64;
                    let am = mont.mont(&Uint([a]));
                    let bm = mont.mont(&Uint([b]));
                    assert_eq!(
                        mont.plain(&mont.mul(&am, &bm)).0[0],
                        want,
                        "{a}·{b} mod {m}"
                    );
                    let s = (u128::from(a) + u128::from(b)) % u128::from(m);
                    assert_eq!(u128::from(mont.add(&Uint([a]), &Uint([b])).0[0]), s);
                    let d = (u128::from(a) + u128::from(m) - u128::from(b)) % u128::from(m);
                    assert_eq!(u128::from(mont.sub(&Uint([a]), &Uint([b])).0[0]), d);
                }
            }
        }
        // Fermat: a · a⁻¹ = 1.
        let m = Monty::<1>::new(Uint([p])).unwrap();
        let a = m.mont(&Uint([0x1234_5678_9abc_def0]));
        let one = m.mul(&a, &m.inv_prime(&a));
        assert_eq!(m.plain(&one).0[0], 1);
    }

    /// Meer limbs, en een modulus die R niet vult: (2^128 - 159) is priem,
    /// en in `Uint<3>` is hij een derde kleiner dan R.
    #[test]
    fn monty_multi_limb() {
        let p = Uint::<2>([0xffff_ffff_ffff_ff61, 0xffff_ffff_ffff_ffff]);
        let m = Monty::new(p).unwrap();
        let x = m.mont(&Uint([7, 3]));
        // x^(p-1) = 1 voor priem p.
        let (e, _) = p.sbb(&Uint::small(1));
        assert_eq!(m.plain(&m.pow(&x, &e.0)), Uint::small(1));
        // (p-1)² = 1.
        let pm1 = m.mont(&e);
        assert_eq!(m.plain(&m.mul(&pm1, &pm1)), Uint::small(1));

        let p3 = Uint::<3>([p.0[0], p.0[1], 0]);
        let m3 = Monty::new(p3).unwrap();
        let x3 = m3.mont(&Uint([7, 3, 0]));
        let (e3, _) = p3.sbb(&Uint::small(1));
        assert_eq!(m3.plain(&m3.pow(&x3, &e3.0)), Uint::small(1));
        assert_eq!(m3.plain(&m3.mont(&Uint([5, 6, 0]))), Uint([5, 6, 0]));
    }

    #[test]
    fn even_or_tiny_modulus_refused() {
        assert!(Monty::<1>::new(Uint([10])).is_none());
        assert!(Monty::<1>::new(Uint([1])).is_none());
        assert!(Monty::<1>::new(Uint([0])).is_none());
    }

    #[test]
    fn bytes_round_trip_and_bounds() {
        let v = Uint::<2>::from_be(&[0, 0, 1, 2, 3]).unwrap();
        assert_eq!(v, Uint([0x010203, 0]));
        let mut out = [0u8; 4];
        assert!(v.write_be(&mut out));
        assert_eq!(out, [0, 1, 2, 3]);
        let mut short = [0u8; 2];
        assert!(!v.write_be(&mut short), "0x010203 past niet in 2 bytes");
        assert!(Uint::<1>::from_be(&[1; 9]).is_none());
        assert!(Uint::<1>::from_be(&[0, 0, 1, 1, 1, 1, 1, 1, 1, 1]).is_some());
        assert_eq!(
            Uint::<2>::from_hex("0102030405060708090a"),
            Uint([0x030405060708090a, 0x0102])
        );
        assert_eq!(v.bits(), 17);
    }
}
