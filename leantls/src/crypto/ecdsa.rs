//! ECDSA-verificatie op P-256 en P-384 (FIPS 186-5, SEC 1 §4.1.4).
//!
//! Alleen verificatie: er gaat nooit een geheim doorheen, alleen een
//! publieke sleutel, een digest van publieke data en een handtekening. Deze
//! implementatie is daarom **niet constant-time**, bewust: Shamirs truc met
//! vroege uitstap, Fermat-inversie met publieke exponent, en vergelijkingen
//! die bij het eerste verschil stoppen. Gebruik haar nooit om te tekenen.
//!
//! De rekenkunde is die van [`super::bignum`]: velden en groepsorde in
//! Montgomery-vorm, punten in Jacobi-coördinaten met `a = -3`, zodat de
//! verdubbeling de korte formule "dbl-2001-b" kan gebruiken.

use core::cmp::Ordering;

use super::bignum::{Monty, Uint};

/// De twee curves die publieke CA's en servers gebruiken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

/// De domeinparameters van een curve `y² = x³ - 3x + b` over `F_p`.
struct Params<const N: usize> {
    /// Het priemgetal van het veld.
    p: Uint<N>,
    /// De orde van het basispunt (priem; cofactor 1).
    n: Uint<N>,
    /// De constante `b`.
    b: Uint<N>,
    /// Het basispunt.
    gx: Uint<N>,
    /// Het basispunt.
    gy: Uint<N>,
}

/// P-256 uit FIPS 186-5 / SEC 2 §2.4.2.
const P256: Params<4> = Params {
    p: Uint::from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    n: Uint::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    b: Uint::from_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    gx: Uint::from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    gy: Uint::from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
};

/// P-384 uit FIPS 186-5 / SEC 2 §2.5.1.
const P384: Params<6> = Params {
    p: Uint::from_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
         ffffffff0000000000000000ffffffff",
    ),
    n: Uint::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52973",
    ),
    b: Uint::from_hex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
         c656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    gx: Uint::from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
         5502f25dbf55296c3a545e3872760ab7",
    ),
    gy: Uint::from_hex(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
         0a60b1ce1d7e819d7a431d7c90ea0e5f",
    ),
};

/// Controleert een ECDSA-handtekening `(r, s)` over `digest`.
///
/// `point` is de publieke sleutel in de ongecomprimeerde vorm `04 || X || Y`
/// (SEC 1 §2.3.3); de gecomprimeerde vorm komt in de Web-PKI niet voor en
/// wordt geweigerd. `r` en `s` zijn big-endian, voorloopnullen toegestaan.
/// Elke fout, van een punt buiten de curve tot `r = 0`, geeft `false`.
pub(crate) fn verify(curve: Curve, point: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    match curve {
        Curve::P256 => verify_on(&P256, point, digest, r, s),
        Curve::P384 => verify_on(&P384, point, digest, r, s),
    }
}

/// Een punt in Jacobi-coördinaten `(X/Z², Y/Z³)`, velden in Montgomery-vorm.
/// `Z = 0` is het punt op oneindig.
#[derive(Clone, Copy)]
struct Jac<const N: usize> {
    /// X.
    x: Uint<N>,
    /// Y.
    y: Uint<N>,
    /// Z.
    z: Uint<N>,
}

/// Het veld met de curveconstante, klaar om mee te rekenen.
struct Field<const N: usize> {
    /// Rekenen modulo p.
    f: Monty<N>,
    /// `b` in Montgomery-vorm.
    b: Uint<N>,
}

impl<const N: usize> Field<N> {
    /// `a·b`.
    fn mul(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        self.f.mul(a, b)
    }

    /// `a²`.
    fn sqr(&self, a: &Uint<N>) -> Uint<N> {
        self.f.mul(a, a)
    }

    /// `a + b`.
    fn add(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        self.f.add(a, b)
    }

    /// `a - b`.
    fn sub(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        self.f.sub(a, b)
    }

    /// Het punt op oneindig.
    fn infinity(&self) -> Jac<N> {
        Jac {
            x: self.f.one(),
            y: self.f.one(),
            z: Uint::ZERO,
        }
    }

    /// Ligt het affiene punt `(x, y)` (Montgomery-vorm) op de curve?
    fn on_curve(&self, x: &Uint<N>, y: &Uint<N>) -> bool {
        let x3 = self.mul(&self.sqr(x), x);
        let three_x = self.add(&self.add(x, x), x);
        let rhs = self.add(&self.sub(&x3, &three_x), &self.b);
        self.sqr(y) == rhs
    }

    /// `2P`, "dbl-2001-b" (a = -3).
    fn double(&self, p: &Jac<N>) -> Jac<N> {
        if p.z.is_zero() || p.y.is_zero() {
            return self.infinity();
        }
        let delta = self.sqr(&p.z);
        let gamma = self.sqr(&p.y);
        let beta = self.mul(&p.x, &gamma);
        let t = self.mul(&self.sub(&p.x, &delta), &self.add(&p.x, &delta));
        let alpha = self.add(&self.add(&t, &t), &t);
        let beta4 = self.add(&self.add(&beta, &beta), &self.add(&beta, &beta));
        let beta8 = self.add(&beta4, &beta4);
        let x3 = self.sub(&self.sqr(&alpha), &beta8);
        let yz = self.add(&p.y, &p.z);
        let z3 = self.sub(&self.sub(&self.sqr(&yz), &gamma), &delta);
        let g2 = self.sqr(&gamma);
        let g4 = self.add(&g2, &g2);
        let g8 = self.add(&g4, &g4);
        let y3 = self.sub(
            &self.mul(&alpha, &self.sub(&beta4, &x3)),
            &self.add(&g8, &g8),
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `P + Q`, de klassieke Jacobi-optelling met de randgevallen apart:
    /// `P = Q` wordt een verdubbeling, `P = -Q` het punt op oneindig.
    fn add_points(&self, p: &Jac<N>, q: &Jac<N>) -> Jac<N> {
        if p.z.is_zero() {
            return *q;
        }
        if q.z.is_zero() {
            return *p;
        }
        let z1z1 = self.sqr(&p.z);
        let z2z2 = self.sqr(&q.z);
        let u1 = self.mul(&p.x, &z2z2);
        let u2 = self.mul(&q.x, &z1z1);
        let s1 = self.mul(&self.mul(&p.y, &q.z), &z2z2);
        let s2 = self.mul(&self.mul(&q.y, &p.z), &z1z1);
        let h = self.sub(&u2, &u1);
        let r = self.sub(&s2, &s1);
        if h.is_zero() {
            return if r.is_zero() {
                self.double(p)
            } else {
                self.infinity()
            };
        }
        let h2 = self.sqr(&h);
        let h3 = self.mul(&h2, &h);
        let u1h2 = self.mul(&u1, &h2);
        let x3 = self.sub(&self.sub(&self.sqr(&r), &h3), &self.add(&u1h2, &u1h2));
        let y3 = self.sub(&self.mul(&r, &self.sub(&u1h2, &x3)), &self.mul(&s1, &h3));
        let z3 = self.mul(&self.mul(&p.z, &q.z), &h);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// De affiene x-coördinaat, gewoon (niet Montgomery); `None` op oneindig.
    fn affine_x(&self, p: &Jac<N>) -> Option<Uint<N>> {
        if p.z.is_zero() {
            return None;
        }
        let zinv = self.f.inv_prime(&p.z);
        Some(self.f.plain(&self.mul(&p.x, &self.sqr(&zinv))))
    }
}

/// Leest een scalar in `[1, n-1]`.
fn scalar<const N: usize>(bytes: &[u8], n: &Uint<N>) -> Option<Uint<N>> {
    let v = Uint::<N>::from_be(bytes)?;
    (!v.is_zero() && v.cmp(n) == Ordering::Less).then_some(v)
}

/// `bits2int(digest) mod n` (SEC 1 §4.1.3 stap 5): de linker `bits(n)` bits
/// van de digest. Beide curves hebben een orde van een heel aantal bytes, dus
/// afkappen is bytes weglaten.
fn digest_scalar<const N: usize>(digest: &[u8], n: &Uint<N>) -> Option<Uint<N>> {
    let nbytes = n.bits().div_ceil(8);
    let e = Uint::<N>::from_be(digest.get(..nbytes.min(digest.len()))?)?;
    // e < 2^bits(n) < 2n, dus één keer aftrekken volstaat.
    Some(if e.cmp(n) == Ordering::Less {
        e
    } else {
        e.sbb(n).0
    })
}

/// De verificatie op één curve.
fn verify_on<const N: usize>(
    c: &Params<N>,
    point: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> bool {
    verify_inner(c, point, digest, r, s).unwrap_or(false)
}

/// Als [`verify_on`], met `None` voor elke ongeldige invoer.
fn verify_inner<const N: usize>(
    c: &Params<N>,
    point: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> Option<bool> {
    let field = Field {
        f: Monty::new(c.p)?,
        b: Uint::ZERO,
    };
    let field = Field {
        b: field.f.mont(&c.b),
        ..field
    };
    let order = Monty::new(c.n)?;
    let len = 8 * N;

    // De sleutel: 04 || X || Y, beide kleiner dan p en op de curve. Omdat de
    // cofactor 1 is, is "op de curve en niet oneindig" genoeg.
    let (&tag, xy) = point.split_first()?;
    if tag != 0x04 || xy.len() != 2 * len {
        return None;
    }
    let (xb, yb) = xy.split_at(len);
    let qx = Uint::<N>::from_be(xb)?;
    let qy = Uint::<N>::from_be(yb)?;
    if qx.cmp(&c.p) != Ordering::Less || qy.cmp(&c.p) != Ordering::Less {
        return None;
    }
    let (qx, qy) = (field.f.mont(&qx), field.f.mont(&qy));
    if !field.on_curve(&qx, &qy) {
        return None;
    }

    let r = scalar(r, &c.n)?;
    let s = scalar(s, &c.n)?;
    let e = digest_scalar(digest, &c.n)?;

    // w = s⁻¹, u1 = e·w, u2 = r·w (mod n).
    let w = order.inv_prime(&order.mont(&s));
    let u1 = order.plain(&order.mul(&order.mont(&e), &w));
    let u2 = order.plain(&order.mul(&order.mont(&r), &w));

    // R = u1·G + u2·Q met Shamirs truc: één gezamenlijke ladder.
    let one = field.f.one();
    let g = Jac {
        x: field.f.mont(&c.gx),
        y: field.f.mont(&c.gy),
        z: one,
    };
    let q = Jac {
        x: qx,
        y: qy,
        z: one,
    };
    let gq = field.add_points(&g, &q);
    let mut acc = field.infinity();
    for i in (0..u1.bits().max(u2.bits())).rev() {
        acc = field.double(&acc);
        acc = match (u1.bit(i), u2.bit(i)) {
            (true, true) => field.add_points(&acc, &gq),
            (true, false) => field.add_points(&acc, &g),
            (false, true) => field.add_points(&acc, &q),
            (false, false) => acc,
        };
    }

    // v = x(R) mod n; p < 2n op beide curves, dus één keer aftrekken.
    let x = field.affine_x(&acc)?;
    let v = if x.cmp(&c.n) == Ordering::Less {
        x
    } else {
        x.sbb(&c.n).0
    };
    Some(v == r)
}

#[cfg(test)]
mod tests;
