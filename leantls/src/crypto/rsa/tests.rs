//! Vectoren voor RSA-verificatie, gemaakt met OpenSSL 3.6 (`openssl dgst
//! -sign`, zie `testdata/vectors`). De misvormde PKCS#1-blokken zijn met de
//! hand opgebouwd en met de ruwe privésleutel "getekend" (`pkeyutl -decrypt
//! -pkeyopt rsa_padding_mode:none`): zo zijn het geldige RSA-getallen met een
//! foute opvulling, precies wat een parser-fout zou doorlaten.

use super::*;

const E: [u8; 3] = [1, 0, 1];
const MSG: &[u8] = include_bytes!("../../../testdata/vectors/rsa-msg.txt");
const N2048: &[u8] = include_bytes!("../../../testdata/vectors/r2048.n");
const N2049: &[u8] = include_bytes!("../../../testdata/vectors/r2049.n");
const N1024: &[u8] = include_bytes!("../../../testdata/vectors/r1024.n");

fn key() -> PublicKey {
    PublicKey::new(N2048, &E).unwrap()
}

fn d(h: HashAlg) -> crate::crypto::hash::Digest {
    h.digest(&[MSG])
}

macro_rules! sig {
    ($f:literal) => {
        include_bytes!(concat!("../../../testdata/vectors/", $f)).as_slice()
    };
}

#[test]
fn pkcs1_all_hashes() {
    let k = key();
    for (h, s) in [
        (HashAlg::Sha256, sig!("pkcs1-256.sig")),
        (HashAlg::Sha384, sig!("pkcs1-384.sig")),
        (HashAlg::Sha512, sig!("pkcs1-512.sig")),
    ] {
        assert!(k.verify_pkcs1(h, d(h).as_slice(), s), "{h:?}");
        assert!(
            !k.verify_pss(h, d(h).as_slice(), s),
            "PKCS#1 als PSS: {h:?}"
        );
    }
    // De verkeerde hash bij een goede handtekening.
    assert!(!k.verify_pkcs1(
        HashAlg::Sha384,
        d(HashAlg::Sha384).as_slice(),
        sig!("pkcs1-256.sig")
    ));
}

#[test]
fn pss_all_hashes() {
    let k = key();
    for (h, s) in [
        (HashAlg::Sha256, sig!("pss-256.sig")),
        (HashAlg::Sha384, sig!("pss-384.sig")),
        (HashAlg::Sha512, sig!("pss-512.sig")),
    ] {
        assert!(k.verify_pss(h, d(h).as_slice(), s), "{h:?}");
        assert!(
            !k.verify_pkcs1(h, d(h).as_slice(), s),
            "PSS als PKCS#1: {h:?}"
        );
        let mut other = d(h).as_slice().to_vec();
        other[0] ^= 1;
        assert!(!k.verify_pss(h, &other, s));
    }
}

/// modBits = 2049: EM is één byte korter dan k (RFC 8017 §9.1.2 stap 3).
#[test]
fn pss_em_shorter_than_modulus() {
    let k = PublicKey::new(N2049, &E).unwrap();
    let h = HashAlg::Sha256;
    assert!(k.verify_pss(h, d(h).as_slice(), sig!("pss2049-256.sig")));
}

/// TLS 1.3 eist een zout zo lang als de hash; 20 bytes bij SHA-256 is geldig
/// PSS maar niet hier.
#[test]
fn pss_wrong_salt_length_refused() {
    let h = HashAlg::Sha256;
    assert!(!key().verify_pss(h, d(h).as_slice(), sig!("pss-256-salt20.sig")));
}

#[test]
fn crafted_pkcs1_blocks() {
    let k = key();
    let h = HashAlg::Sha256;
    let dg = d(h);
    assert!(k.verify_pkcs1(h, dg.as_slice(), sig!("craft-good.sig")));
    for bad in [
        sig!("craft-nonull.sig"),  // DigestInfo zonder NULL-parameter
        sig!("craft-garbage.sig"), // rommel achter de digest (Bleichenbacher 2006)
        sig!("craft-bt2.sig"),     // bloktype 2 (versleuteling) in plaats van 1
        sig!("craft-psbyte.sig"),  // een opvulbyte die geen FF is
    ] {
        assert!(!k.verify_pkcs1(h, dg.as_slice(), bad));
    }
}

#[test]
fn signature_representative_bounds() {
    let k = key();
    let h = HashAlg::Sha256;
    let dg = d(h);
    let good = sig!("pkcs1-256.sig");
    // Een byte te kort of te lang, ook met een voorloopnul.
    assert!(!k.verify_pkcs1(h, dg.as_slice(), &good[1..]));
    assert!(!k.verify_pkcs1(h, dg.as_slice(), &[&[0], good].concat()));
    // s = n en s > n.
    assert!(!k.verify_pkcs1(h, dg.as_slice(), N2048));
    assert!(!k.verify_pkcs1(h, dg.as_slice(), &[0xff; 256]));
    // Elke omgeklapte byte.
    for i in (0..256).step_by(17) {
        let mut s = good.to_vec();
        s[i] ^= 0x01;
        assert!(!k.verify_pkcs1(h, dg.as_slice(), &s));
    }
}

#[test]
fn key_bounds() {
    assert!(PublicKey::new(N1024, &E).is_none(), "1024 bits");
    assert!(PublicKey::new(N2048, &[1]).is_none(), "e = 1");
    assert!(PublicKey::new(N2048, &[2]).is_none(), "e even");
    assert!(
        PublicKey::new(N2048, &[1, 0, 0, 0, 1]).is_none(),
        "e > 2^32"
    );
    assert!(PublicKey::new(N2048, &[3]).is_some());
    let mut even = N2048.to_vec();
    *even.last_mut().unwrap() &= 0xfe;
    assert!(PublicKey::new(&even, &E).is_none(), "even modulus");
    assert!(PublicKey::new(&[0xff; 513], &E).is_none(), "4104 bits");
    let n4096 = [0xffu8; 512];
    assert!(PublicKey::new(&n4096, &E).is_some(), "4096 bits");
}
