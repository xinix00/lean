//! X25519 (RFC 7748): de ene sleuteluitwisseling.
//!
//! De Montgomery-ladder uit RFC 7748 §5, met een wissel zonder sprong per
//! bit: de volgorde van bewerkingen is gelijk voor elke scalar. Alleen de
//! laatste inversie gebruikt een vaste, publieke exponent.

use super::field::Fe;

/// a24 = (486662 - 2) / 4, RFC 7748 §5.
const A24: u32 = 121_665;

/// Het basispunt u = 9.
pub(crate) const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Berekent X25519(k, u).
pub(crate) fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(A24)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    super::ct::wipe(&mut k);
    let out = x2.mul(z2.invert()).to_bytes();
    // De tussenwaarden dragen het geheim; wis ze.
    for fe in [&mut x2, &mut z2, &mut x3, &mut z3] {
        super::ct::wipe(&mut fe.0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::{arr32, unhex};

    /// RFC 7748 §5.2, de twee losse vectoren.
    #[test]
    fn rfc7748_vectors() {
        let cases = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (k, u, want) in cases {
            assert_eq!(x25519(&arr32(k), &arr32(u)).to_vec(), unhex(want));
        }
    }

    /// RFC 7748 §5.2, de herhaalde toepassing na 1 en 1000 rondes.
    #[test]
    fn rfc7748_iterated() {
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k.to_vec(),
                    unhex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k.to_vec(),
            unhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    /// RFC 7748 §6.1, de Diffie-Hellman-uitwisseling tussen Alice en Bob.
    #[test]
    fn rfc7748_diffie_hellman() {
        let a = arr32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = arr32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let pa = x25519(&a, &BASEPOINT);
        let pb = x25519(&b, &BASEPOINT);
        assert_eq!(
            pa.to_vec(),
            unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            pb.to_vec(),
            unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let want = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &pb).to_vec(), want);
        assert_eq!(x25519(&b, &pa).to_vec(), want);
    }
}
