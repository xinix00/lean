//! Ed25519-verificatie (RFC 8032 §5.1.7), alleen de verificatie.
//!
//! Een client tekent niets: hij controleert de CertificateVerify van de
//! server. Alles hier werkt op publieke data (sleutel, bericht,
//! handtekening), dus variabele tijd is toegestaan en eenvoudiger: dubbelen
//! en optellen per bit, zonder vensters of tabellen. De constanten `d`,
//! `sqrt(-1)` en het basispunt worden uit kleine getallen berekend in plaats
//! van overgetypt, zodat een tikfout onmogelijk is.
//!
//! Semantiek zoals Go's `crypto/ed25519`: S moet kleiner dan L zijn, A moet
//! een geldig punt zijn, en de controle is cofactorloos:
//! `[S]B - [k]A` gecodeerd moet exact gelijk zijn aan R.

use super::field::Fe;
use super::sha512::Sha512;

/// Lengte van een publieke sleutel.
pub(crate) const PUBLIC_KEY_LEN: usize = 32;
/// Lengte van een handtekening.
pub(crate) const SIGNATURE_LEN: usize = 64;

/// De groepsorde L = 2^252 + 27742317777372353535851937790883648493, als vier
/// woorden little-endian.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0,
    0x1000000000000000,
];

/// Een punt in uitgebreide coördinaten (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// De curveconstanten, eenmaal per verificatie berekend.
struct Curve {
    /// d = -121665/121666.
    d: Fe,
    /// 2d, voor de optelformule.
    d2: Fe,
    /// Een wortel van -1: 2^((p-1)/4).
    sqrt_m1: Fe,
}

impl Curve {
    /// Berekent de constanten uit hun definitie.
    fn new() -> Self {
        let d = Fe::from_u64(121_665)
            .neg()
            .mul(Fe::from_u64(121_666).invert());
        // (p-1)/4 = 2^253 - 5, little-endian.
        let mut e = [0xffu8; 32];
        e[0] = 0xfb;
        e[31] = 0x1f;
        let sqrt_m1 = Fe::from_u64(2).pow(&e);
        Self {
            d,
            d2: d.add(d),
            sqrt_m1,
        }
    }

    /// Het neutrale element.
    fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// Het basispunt B: y = 4/5, x even.
    fn base(&self) -> Option<Point> {
        let y = Fe::from_u64(4).mul(Fe::from_u64(5).invert());
        self.decode(&y.to_bytes())
    }

    /// Decodeert een punt volgens RFC 8032 §5.1.3. Een niet-canonieke y
    /// (y >= p) wordt geweigerd.
    fn decode(&self, b: &[u8; 32]) -> Option<Point> {
        let sign = b[31] >> 7;
        let mut yb = *b;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None;
        }
        let yy = y.square();
        let u = yy.sub(Fe::ONE);
        let v = self.d.mul(yy).add(Fe::ONE);
        // x = u v^3 (u v^7)^((p-5)/8).
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut e = [0xffu8; 32];
        e[0] = 0xfd;
        e[31] = 0x0f;
        let mut x = u.mul(v3).mul(u.mul(v7).pow(&e));
        let vxx = v.mul(x.square());
        if !vxx.equals(u) {
            if vxx.equals(u.neg()) {
                x = x.mul(self.sqrt_m1);
            } else {
                return None;
            }
        }
        if x.is_zero() && sign == 1 {
            return None;
        }
        if u8::from(x.is_negative()) != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// Optellen (en dubbelen) met de uniforme formule voor a = -1
    /// ("add-2008-hwcd-3").
    fn add(&self, p: &Point, q: &Point) -> Point {
        let a = p.y.sub(p.x).mul(q.y.sub(q.x));
        let b = p.y.add(p.x).mul(q.y.add(q.x));
        let c = p.t.mul(self.d2).mul(q.t);
        let d = p.z.add(p.z).mul(q.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// `[s]P` met dubbelen en optellen per bit, van boven naar beneden.
    fn mul(&self, p: &Point, s: &[u8; 32]) -> Point {
        let mut r = Self::identity();
        for byte in s.iter().rev() {
            for bit in (0..8).rev() {
                r = self.add(&r, &r);
                if (byte >> bit) & 1 == 1 {
                    r = self.add(&r, p);
                }
            }
        }
        r
    }
}

/// -P.
fn negate(p: &Point) -> Point {
    Point {
        x: p.x.neg(),
        y: p.y,
        z: p.z,
        t: p.t.neg(),
    }
}

/// De canonieke codering van een punt.
fn encode(p: &Point) -> [u8; 32] {
    let zi = p.z.invert();
    let x = p.x.mul(zi);
    let y = p.y.mul(zi);
    let mut out = y.to_bytes();
    out[31] |= u8::from(x.is_negative()) << 7;
    out
}

/// Leest 32 bytes little-endian als vier woorden.
fn words(b: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (wi, c) in w.iter_mut().zip(b.chunks_exact(8)) {
        let mut x = [0u8; 8];
        x.copy_from_slice(c);
        *wi = u64::from_le_bytes(x);
    }
    w
}

/// a >= b voor getallen van vier woorden.
fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a -= b, met a >= b.
fn sub_in_place(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for (x, y) in a.iter_mut().zip(b) {
        let (d1, b1) = x.overflowing_sub(*y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = u64::from(b1 | b2);
    }
}

/// Reduceert een 512-bits hash modulo L, bit voor bit (schuiven en aftrekken).
///
/// Traag vergeleken met Barrett, maar het zijn 512 kleine stappen per
/// verificatie, en er is geen constante om fout over te typen.
fn reduce512(h: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for byte in h.iter().rev() {
        for bit in (0..8).rev() {
            // r < L < 2^253, dus 2r + 1 past in vier woorden.
            let mut carry = u64::from((byte >> bit) & 1);
            for w in r.iter_mut() {
                let next = *w >> 63;
                *w = (*w << 1) | carry;
                carry = next;
            }
            if ge(&r, &L) {
                sub_in_place(&mut r, &L);
            }
        }
    }
    let mut out = [0u8; 32];
    for (o, w) in out.chunks_exact_mut(8).zip(r) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Controleert een Ed25519-handtekening. Geeft `false` bij elke fout:
/// ongeldige sleutel, S buiten bereik, of een handtekening die niet klopt.
pub(crate) fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    let curve = Curve::new();
    let Some(a) = curve.decode(public_key) else {
        return false;
    };
    let Some(base) = curve.base() else {
        return false;
    };
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..]);
    // S >= L is een kneedbare handtekening (RFC 8032 §5.1.7 stap 1).
    if ge(&words(&s_bytes), &L) {
        return false;
    }
    let mut h = Sha512::new();
    h.update(&r_bytes);
    h.update(public_key);
    h.update(msg);
    let k = reduce512(&h.finish());
    let sb = curve.mul(&base, &s_bytes);
    let ka = curve.mul(&negate(&a), &k);
    encode(&curve.add(&sb, &ka)) == r_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::{arr32, unhex};

    fn sig(hex: &str) -> [u8; 64] {
        let v = unhex(hex);
        let mut s = [0u8; 64];
        s.copy_from_slice(&v);
        s
    }

    /// RFC 8032 §7.1: TEST 1, 2, 3 en TEST SHA(abc).
    #[test]
    fn rfc8032_vectors() {
        let mut abc = Sha512::new();
        abc.update(b"abc");
        let abc = abc.finish();
        let cases: [(&str, Vec<u8>, &str); 4] = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                Vec::new(),
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                vec![0x72],
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                vec![0xaf, 0x82],
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            (
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                abc.to_vec(),
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ];
        for (i, (pk, msg, s)) in cases.iter().enumerate() {
            let pk = arr32(pk);
            let s = sig(s);
            assert!(
                verify(&pk, msg, &s),
                "RFC 8032 vector {} verifieert niet",
                i + 1
            );
            // Eén bit om in het bericht, de R of de S: altijd weigeren.
            let mut bad = msg.clone();
            bad.push(0);
            assert!(
                !verify(&pk, &bad, &s),
                "vector {}: ander bericht geaccepteerd",
                i + 1
            );
            let mut bad_r = s;
            bad_r[0] ^= 1;
            assert!(
                !verify(&pk, msg, &bad_r),
                "vector {}: andere R geaccepteerd",
                i + 1
            );
            let mut bad_s = s;
            bad_s[32] ^= 1;
            assert!(
                !verify(&pk, msg, &bad_s),
                "vector {}: andere S geaccepteerd",
                i + 1
            );
        }
    }

    /// S + L is dezelfde handtekening modulo L, maar kneedbaar: weigeren.
    #[test]
    fn rejects_s_not_reduced() {
        let pk = arr32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let mut s = sig(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let mut sw = [0u8; 32];
        sw.copy_from_slice(&s[32..]);
        let mut w = words(&sw);
        let mut carry = 0u64;
        for (x, y) in w.iter_mut().zip(L) {
            let (a, c1) = x.overflowing_add(y);
            let (b, c2) = a.overflowing_add(carry);
            *x = b;
            carry = u64::from(c1 | c2);
        }
        for (o, x) in s[32..].chunks_exact_mut(8).zip(w) {
            o.copy_from_slice(&x.to_le_bytes());
        }
        assert!(!verify(&pk, b"", &s));
    }

    /// Het basispunt moet de bekende codering 0x58 0x66.. hebben.
    #[test]
    fn base_point_encoding() {
        let c = Curve::new();
        let b = c.base().expect("basispunt");
        assert_eq!(
            encode(&b).to_vec(),
            unhex("5866666666666666666666666666666666666666666666666666666666666666")
        );
    }

    #[test]
    fn reduce_mod_l() {
        // L zelf reduceert naar nul, L+1 naar een.
        let mut h = [0u8; 64];
        for (o, w) in h.chunks_exact_mut(8).zip(L) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(reduce512(&h), [0u8; 32]);
        h[0] += 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(reduce512(&h), one);
    }
}
