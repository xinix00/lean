//! Vectoren voor ECDSA-verificatie.
//!
//! RFC 6979 §A.2.5 en §A.2.6 (bericht "sample"), vóór gebruik tegen
//! `openssl dgst -verify` gecontroleerd, plus zelf uitgeschreven randgevallen
//! in de geest van Wycheproof: sleutel gelijk aan `G` en `-G` (de
//! voorberekende `G + Q` wordt dan een verdubbeling of oneindig), `r` en `s`
//! op en buiten de grenzen, punten naast de curve, en kneedbaarheid.

use super::*;
use crate::crypto::hash::HashAlg;
use crate::crypto::testutil::unhex;

/// RFC 6979 §A.2.5, publieke sleutel van P-256.
const U256: &str = "04\
    60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
    7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
/// RFC 6979 §A.2.6, publieke sleutel van P-384.
const U384: &str = "04\
    EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
    DEF8F0EA9055866064A254515480BC13\
    8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1\
    288B231C3AE0D4FE7344FD2533264720";

fn ok(curve: Curve, q: &str, h: HashAlg, msg: &[u8], r: &str, s: &str) -> bool {
    let d = h.digest(&[msg]);
    verify(curve, &unhex(q), d.as_slice(), &unhex(r), &unhex(s))
}

#[test]
fn base_points_on_curve() {
    let f = Field {
        f: Monty::new(P256.p).unwrap(),
        b: Uint::ZERO,
    };
    let f = Field {
        b: f.f.mont(&P256.b),
        ..f
    };
    assert!(f.on_curve(&f.f.mont(&P256.gx), &f.f.mont(&P256.gy)));
    let f = Field {
        f: Monty::new(P384.p).unwrap(),
        b: Uint::ZERO,
    };
    let f = Field {
        b: f.f.mont(&P384.b),
        ..f
    };
    assert!(f.on_curve(&f.f.mont(&P384.gx), &f.f.mont(&P384.gy)));
}

#[test]
fn rfc6979_p256_sha256() {
    assert!(ok(
        Curve::P256,
        U256,
        HashAlg::Sha256,
        b"sample",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ));
    // Een ander bericht met dezelfde handtekening moet falen.
    assert!(!ok(
        Curve::P256,
        U256,
        HashAlg::Sha256,
        b"sample!",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ));
}

/// Een digest langer dan de orde: bits2int kapt SHA-384 af tot 256 bits.
#[test]
fn rfc6979_p256_sha384_truncates() {
    assert!(ok(
        Curve::P256,
        U256,
        HashAlg::Sha384,
        b"sample",
        "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
        "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
    ));
}

#[test]
fn rfc6979_p384_sha384() {
    assert!(ok(
        Curve::P384,
        U384,
        HashAlg::Sha384,
        b"sample",
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
         81A648152E44ACF96E36DD1E80FABE46",
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F\
         A329C145786E679E7B82C71A38628AC8",
    ));
}

/// Een digest korter dan de orde (SHA-256 op P-384).
#[test]
fn rfc6979_p384_sha256_short_digest() {
    assert!(ok(
        Curve::P384,
        U384,
        HashAlg::Sha256,
        b"sample",
        "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33\
         BDE1E888E63355D92FA2B3C36D8FB2CD",
        "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEB\
         EFDC63ECCD1AC42EC0CB8668A4FA0AB0",
    ));
}

/// Sleutel `G` (d = 1) en `-G` (d = n-1): de voorberekende `G + Q` is dan
/// een verdubbeling respectievelijk het punt op oneindig. Getekend met een
/// Python-referentie en tegen openssl gecontroleerd.
#[test]
fn key_is_plus_or_minus_generator() {
    let cases = [
        (
            Curve::P256,
            HashAlg::Sha256,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "26efcebd0ee9e34a669187e18b3a9122b2f733945b649cc9f9f921e9f9dad812",
            "843c7c10cb7b2ccd171065b2b3146319ef522b7f65c5c269aee6662f8cd5a63e",
        ),
        (
            Curve::P256,
            HashAlg::Sha256,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            "9db6eb62700691c3580fbda8fc7ee33f6cfdd5b43203507c1b0533b15d0d1b7e",
            "a7154a179bc7982fcfafd08fb702686c6da273b4c34b965ddf95b932e614c18e",
        ),
        (
            Curve::P384,
            HashAlg::Sha384,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8\
             f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "572c77284c06125140282034d3c7530d1627b131a7fc852418a79cf5a7b7861f\
             637702db11da4e8d44fc208560e035fd",
            "b95aebf3f0388209c41b78299ddd0392d6cd0d0e2e0368a23c1ac8c0eeb93008\
             74e4ed480652407d76ffca62e97dfd82",
        ),
        (
            Curve::P384,
            HashAlg::Sha384,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d607\
             0be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0",
            "46fa665be07f909eaf450c7f6b1b3b7f1ed007505e552bccb659c3f4f57471e0\
             72d76d77ab977069499b660a3b1287bd",
            "f985801cd621cbce991c4a2a372c9eb0af8e25f6359a89bd774e8cddab338cfc\
             bbb0b106c473ac13595fc2af9ab5fb82",
        ),
    ];
    for (curve, h, q, r, s) in cases {
        assert!(ok(curve, q, h, b"edge", r, s), "{q}");
        assert!(!ok(curve, q, h, b"edgE", r, s), "{q}");
    }
}

/// `(r, n - s)` is wiskundig even geldig; Go en OpenSSL accepteren hem ook.
/// Dat hij hier klopt, toetst de rekenkunde met een tweede waarde van `s`.
#[test]
fn negated_s_also_verifies() {
    let n = P256.n;
    let s = Uint::<4>::from_be(&unhex(
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ))
    .unwrap();
    let mut neg = [0u8; 32];
    assert!(n.sbb(&s).0.write_be(&mut neg));
    let d = HashAlg::Sha256.digest(&[b"sample"]);
    let r = unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    assert!(verify(Curve::P256, &unhex(U256), d.as_slice(), &r, &neg));
}

#[test]
fn out_of_range_scalars_refused() {
    let q = unhex(U256);
    let d = HashAlg::Sha256.digest(&[b"sample"]);
    let r = unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = unhex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    let n = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let zero = [0u8; 32];
    let too_long = [1u8; 33];
    assert!(verify(Curve::P256, &q, d.as_slice(), &r, &s));
    for (rr, ss) in [
        (&zero[..], &s[..]),
        (&r[..], &zero[..]),
        (&n[..], &s[..]),
        (&r[..], &n[..]),
        (&too_long[..], &s[..]),
        (&[][..], &s[..]),
    ] {
        assert!(!verify(Curve::P256, &q, d.as_slice(), rr, ss));
    }
    // Elke omgeklapte bit in r, s of de digest.
    for i in 0..32 {
        let mut r2 = r.clone();
        r2[i] ^= 1;
        assert!(!verify(Curve::P256, &q, d.as_slice(), &r2, &s));
        let mut s2 = s.clone();
        s2[i] ^= 0x80;
        assert!(!verify(Curve::P256, &q, d.as_slice(), &r, &s2));
        let mut d2 = d.as_slice().to_vec();
        d2[i] ^= 0x10;
        assert!(!verify(Curve::P256, &q, &d2, &r, &s));
    }
}

#[test]
fn bad_points_refused() {
    let d = HashAlg::Sha256.digest(&[b"sample"]);
    let r = unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = unhex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    let q = unhex(U256);
    // Naast de curve: y + 1.
    let mut off = q.clone();
    off[64] ^= 1;
    // Gecomprimeerd, oneindig, te kort, te lang, verkeerde curve.
    let mut compressed = q[..33].to_vec();
    compressed[0] = 0x03;
    let mut x_is_p = q.clone();
    x_is_p[1..33].copy_from_slice(&unhex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ));
    for bad in [
        off,
        compressed,
        vec![0x00],
        q[..64].to_vec(),
        [q.as_slice(), &[0]].concat(),
        x_is_p,
        vec![],
    ] {
        assert!(!verify(Curve::P256, &bad, d.as_slice(), &r, &s));
    }
    assert!(
        !verify(Curve::P384, &q, d.as_slice(), &r, &s),
        "P-256-sleutel op P-384"
    );
}
