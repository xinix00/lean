//! Tests voor de ketenverificatie.
//!
//! Drie bronnen: echte ketens van GitHub (augustus 2026, uit de Go-versie)
//! tegen de Mozilla-wortels van juli 2026; de eigen testketens uit
//! `testdata/chain/gen.sh` (P-256 en RSA-2048, plus één kapotte variant per
//! regel); en de weigeringen uit Go's `x509verify_test.go`, geport.

use super::*;
use crate::trust::CertChain;

/// Dinsdag 29 september 2026, 00:00 UTC: binnen elke testketen.
const NOW: u64 = 1_790_640_000;

macro_rules! chain_file {
    ($f:literal) => {
        include_bytes!(concat!("../../testdata/chain/", $f)).as_slice()
    };
}

macro_rules! github_file {
    ($f:literal) => {
        include_bytes!(concat!("../../testdata/github/", $f)).as_slice()
    };
}

const ECDSA_ROOT: &[u8] = chain_file!("ecdsa-root.der");
const ECDSA_INTER: &[u8] = chain_file!("ecdsa-inter.der");
const ECDSA_LEAF: &[u8] = chain_file!("ecdsa-leaf.der");
const RSA_ROOT: &[u8] = chain_file!("rsa-root.der");
const RSA_INTER: &[u8] = chain_file!("rsa-inter.der");
const RSA_LEAF: &[u8] = chain_file!("rsa-leaf.der");
const MOZILLA: &[u8] = crate::MOZILLA_ROOTS;

/// Bouwt de inhoud van een TLS 1.3 Certificate-bericht.
fn message(certs: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in certs {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
        list.extend_from_slice(&[0, 0]);
    }
    let mut body = vec![0];
    body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    body.extend(list);
    body
}

/// Toetst `certs` tegen `roots` op `now` voor `host`.
fn check(
    roots: &[&[u8]],
    certs: &[&[u8]],
    host: &str,
    now: u64,
) -> core::result::Result<(), X509Error> {
    let roots = Roots::from_list(roots).unwrap();
    let body = message(certs);
    let chain = CertChain::parse(&body).unwrap();
    ChainVerifier::new(roots, now).check(chain, host)
}

/// Splitst aaneengeschakelde DER.
fn split(mut b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let t = der::Der::new(b).any().unwrap();
        out.push(t.raw);
        b = &b[t.raw.len()..];
    }
    out
}

// --- Echte ketens --------------------------------------------------------------

#[test]
fn real_github_chains() {
    let roots = Roots::from_concatenated_der(MOZILLA).unwrap();
    assert_eq!(
        roots.len(),
        119,
        "de Mozilla-set van juli 2026 leest helemaal"
    );
    for (host, der) in [
        ("github.com", github_file!("chain-github.com.der")),
        ("api.github.com", github_file!("chain-api.github.com.der")),
        (
            "objects.githubusercontent.com",
            github_file!("chain-objects.githubusercontent.com.der"),
        ),
    ] {
        let certs = split(der);
        let body = message(&certs);
        let chain = CertChain::parse(&body).unwrap();
        let leaf = Cert::parse(certs[0]).unwrap();
        // Zoals Go: een uur na notBefore van het blad.
        let at = (leaf.not_before + 3600) as u64;
        let v = ChainVerifier::new(roots, at);
        v.check(chain, host)
            .unwrap_or_else(|e| panic!("{host}: {e}"));
        assert_eq!(v.verify_chain(chain, host), Ok(()), "{host} via VerifyPeer");
        assert!(
            matches!(
                v.check(chain, "attacker.example"),
                Err(X509Error::NameMismatch { .. })
            ),
            "{host}: keten geldig voor een naam die er niet in staat"
        );
        let late = ChainVerifier::new(roots, (leaf.not_after + 1) as u64);
        assert!(matches!(
            late.check(chain, host),
            Err(X509Error::Expired {
                cert: CertRef::Chain(0),
                ..
            })
        ));
        // Zonder de juiste wortel: geen pad.
        let own = Roots::from_list(&[ECDSA_ROOT]).unwrap();
        assert_eq!(
            ChainVerifier::new(own, at).check(chain, host),
            Err(X509Error::UnknownAuthority)
        );
    }
}

/// De padwortels die GitHub nodig heeft: P-384/SHA-384 (USERTrust ECC →
/// Sectigo E46 → E36) en RSA-4096 PKCS#1 (ISRG Root X1 → Root YR → YR2).
#[test]
fn github_chains_exercise_p384_and_rsa4096() {
    let gh = split(github_file!("chain-github.com.der"));
    let e36 = Cert::parse(gh[1]).unwrap();
    assert_eq!(e36.sig_alg, SigAlg::Ecdsa(HashAlg::Sha384));
    assert!(matches!(
        Cert::parse(gh[2]).unwrap().public_key(),
        Ok(PublicKey::Ec(ecdsa::Curve::P384, _))
    ));
    let objects = split(github_file!("chain-objects.githubusercontent.com.der"));
    let yr = Cert::parse(objects[2]).unwrap();
    assert_eq!(yr.sig_alg, SigAlg::RsaPkcs1(HashAlg::Sha256));
    let Ok(PublicKey::Rsa { n, .. }) = yr.public_key() else {
        panic!("Root YR is RSA");
    };
    assert_eq!(n.len(), 512, "4096 bits");
}

// --- De eigen testketens -------------------------------------------------------

#[test]
fn valid_ecdsa_and_rsa_chains() {
    assert_eq!(
        check(
            &[ECDSA_ROOT],
            &[ECDSA_LEAF, ECDSA_INTER],
            "leantls.test",
            NOW
        ),
        Ok(())
    );
    assert_eq!(
        check(&[RSA_ROOT], &[RSA_LEAF, RSA_INTER], "leantls.test", NOW),
        Ok(())
    );
    // Beide wortels in de set, hoofdletters in de naam, een punt erachter.
    assert_eq!(
        check(
            &[RSA_ROOT, ECDSA_ROOT],
            &[ECDSA_LEAF, ECDSA_INTER],
            "LeanTLS.test.",
            NOW
        ),
        Ok(())
    );
}

#[test]
fn server_order_does_not_matter() {
    // Een ongerelateerd certificaat ertussen, en de wortel zelf erbij.
    assert_eq!(
        check(
            &[ECDSA_ROOT],
            &[ECDSA_LEAF, RSA_INTER, ECDSA_ROOT, ECDSA_INTER],
            "leantls.test",
            NOW
        ),
        Ok(())
    );
}

#[test]
fn leaf_in_roots_is_trusted_as_is() {
    assert_eq!(
        check(&[ECDSA_LEAF], &[ECDSA_LEAF], "leantls.test", NOW),
        Ok(())
    );
}

#[test]
fn wildcard_only_one_left_label() {
    let ok = |h| check(&[ECDSA_ROOT], &[ECDSA_LEAF, ECDSA_INTER], h, NOW);
    assert_eq!(ok("a.wild.leantls.test"), Ok(()));
    for bad in ["a.b.wild.leantls.test", "wild.leantls.test", "other.test"] {
        assert_eq!(
            ok(bad),
            Err(X509Error::NameMismatch { dns_names: 2 }),
            "{bad}"
        );
    }
}

#[test]
fn validity_window() {
    let at = |t| check(&[ECDSA_ROOT], &[ECDSA_LEAF, ECDSA_INTER], "leantls.test", t);
    // 2026-06-01 en 2027-06-01 zijn de randen van het blad, inclusief.
    assert_eq!(at(1_780_272_000), Ok(()));
    assert_eq!(at(1_811_808_000), Ok(()));
    assert!(matches!(
        at(1_811_808_001),
        Err(X509Error::Expired {
            cert: CertRef::Chain(0),
            ..
        })
    ));
    assert!(matches!(
        at(1_780_271_999),
        Err(X509Error::NotYetValid {
            cert: CertRef::Chain(0),
            ..
        })
    ));
}

#[test]
fn wrong_root() {
    assert_eq!(
        check(&[RSA_ROOT], &[ECDSA_LEAF, ECDSA_INTER], "leantls.test", NOW),
        Err(X509Error::UnknownAuthority)
    );
    // Een wortel met dezelfde naam en een andere sleutel: de
    // AuthorityKeyIdentifier van de tussen-CA wijst hem al af, zonder
    // handtekeningcontrole. Een kapotte handtekening bij een passende
    // sleutel-id staat in `broken_signatures`.
    assert_eq!(
        check(
            &[chain_file!("evil-root.der")],
            &[ECDSA_LEAF, ECDSA_INTER],
            "leantls.test",
            NOW
        ),
        Err(X509Error::UnknownAuthority)
    );
    // Zonder tussenschakel.
    assert_eq!(
        check(&[ECDSA_ROOT], &[ECDSA_LEAF], "leantls.test", NOW),
        Err(X509Error::UnknownAuthority)
    );
}

#[test]
fn broken_signatures() {
    for (root, leaf, inter) in [
        (ECDSA_ROOT, ECDSA_LEAF, ECDSA_INTER),
        (RSA_ROOT, RSA_LEAF, RSA_INTER),
    ] {
        // De laatste byte van een certificaat is de laatste byte van de
        // handtekening: de DER blijft geldig, de handtekening niet.
        let mut bad_leaf = leaf.to_vec();
        *bad_leaf.last_mut().unwrap() ^= 1;
        assert_eq!(
            check(&[root], &[&bad_leaf, inter], "leantls.test", NOW),
            Err(X509Error::BadCertSignature {
                cert: CertRef::Chain(0)
            })
        );
        let mut bad_inter = inter.to_vec();
        *bad_inter.last_mut().unwrap() ^= 1;
        assert_eq!(
            check(&[root], &[leaf, &bad_inter], "leantls.test", NOW),
            Err(X509Error::BadCertSignature {
                cert: CertRef::Chain(1)
            })
        );
        // Een omgeklapte byte in de ondertekende bytes (het serienummer).
        let mut tbs = leaf.to_vec();
        let serial = tbs
            .windows(3)
            .position(|w| w == [0x02, 0x01, 0x03])
            .unwrap();
        tbs[serial + 2] = 0x04;
        assert_eq!(
            check(&[root], &[&tbs, inter], "leantls.test", NOW),
            Err(X509Error::BadCertSignature {
                cert: CertRef::Chain(0)
            })
        );
    }
}

#[test]
fn ca_rules() {
    let run = |inter: &[u8], leaf: &[u8]| check(&[ECDSA_ROOT], &[leaf, inter], "leantls.test", NOW);
    assert_eq!(
        run(chain_file!("nocs-inter.der"), chain_file!("nocs-leaf.der")),
        Err(X509Error::NoCertSign {
            cert: CertRef::Chain(1)
        })
    );
    assert_eq!(
        run(
            chain_file!("notca-inter.der"),
            chain_file!("notca-leaf.der")
        ),
        Err(X509Error::NotCa {
            cert: CertRef::Chain(1)
        })
    );
    assert_eq!(
        run(chain_file!("nc-inter.der"), chain_file!("nc-leaf.der")),
        Err(X509Error::Unhandled {
            cert: CertRef::Chain(1)
        })
    );
    // ecdsa-inter heeft pathlen 0; deep-inter eronder mag dus niet tekenen.
    assert_eq!(
        check(
            &[ECDSA_ROOT],
            &[
                chain_file!("deep-leaf.der"),
                chain_file!("deep-inter.der"),
                ECDSA_INTER
            ],
            "leantls.test",
            NOW
        ),
        Err(X509Error::PathLen {
            cert: CertRef::Chain(2),
            max: 0
        })
    );
}

// --- Go's TestRejects, geport ----------------------------------------------------

#[test]
fn go_rejects() {
    let eku = check(
        &[ECDSA_ROOT],
        &[chain_file!("eku-leaf.der"), ECDSA_INTER],
        "leantls.test",
        NOW,
    );
    assert_eq!(
        eku,
        Err(X509Error::ExtKeyUsage {
            cert: CertRef::Chain(0)
        })
    );
    // Een zelfondertekend certificaat dat niet in de set staat.
    let own = check(&[RSA_ROOT], &[ECDSA_ROOT], "leantls.test", NOW);
    assert!(own.is_err());
    let unknown = check(&[RSA_ROOT], &[ECDSA_LEAF], "leantls.test", NOW).unwrap_err();
    assert!(
        unknown.to_string().contains("unknown authority"),
        "{unknown}"
    );
    // Rommel in plaats van DER.
    let junk = check(&[ECDSA_ROOT], &[&[1, 2, 3]], "leantls.test", NOW).unwrap_err();
    assert!(junk.to_string().contains("certificate 0"), "{junk}");
    let wrong = check(
        &[ECDSA_ROOT],
        &[ECDSA_LEAF, ECDSA_INTER],
        "evil.example",
        NOW,
    )
    .unwrap_err();
    assert!(wrong.to_string().contains("valid for"), "{wrong}");
    let expired = check(
        &[ECDSA_ROOT],
        &[ECDSA_LEAF, ECDSA_INTER],
        "leantls.test",
        1_900_000_000,
    )
    .unwrap_err();
    assert!(expired.to_string().contains("expired"), "{expired}");
    let early = check(
        &[ECDSA_ROOT],
        &[ECDSA_LEAF, ECDSA_INTER],
        "leantls.test",
        1_700_000_000,
    )
    .unwrap_err();
    assert!(early.to_string().contains("not yet valid"), "{early}");
    // Een lege keten bestaat niet: het Certificate-bericht weigert hem al.
    assert_eq!(
        CertChain::parse(&message(&[])).err(),
        Some(Error::EmptyCertificateList)
    );
}

#[test]
fn server_name_rules() {
    let run = |h| check(&[ECDSA_ROOT], &[ECDSA_LEAF, ECDSA_INTER], h, NOW);
    assert!(matches!(
        run("127.0.0.1"),
        Err(X509Error::NameMismatch { .. })
    ));
    assert!(matches!(run("::1"), Err(X509Error::NameMismatch { .. })));
    assert_eq!(run("a..b"), Err(X509Error::ServerName));
    let roots = Roots::from_list(&[ECDSA_ROOT]).unwrap();
    let body = message(&[ECDSA_LEAF, ECDSA_INTER]);
    let chain = CertChain::parse(&body).unwrap();
    assert_eq!(
        ChainVerifier::new(roots, NOW).verify_chain(chain, ""),
        Err(Error::ServerNameRequired)
    );
}

#[test]
fn chain_length_limit() {
    let many = [ECDSA_INTER; MAX_CHAIN];
    let mut certs = vec![ECDSA_LEAF];
    certs.extend(many);
    assert_eq!(
        check(&[ECDSA_ROOT], &certs, "leantls.test", NOW),
        Err(X509Error::TooManyCertificates(MAX_CHAIN + 1))
    );
    // Precies de grens mag, ook met herhalingen.
    assert_eq!(
        check(&[ECDSA_ROOT], &certs[..MAX_CHAIN], "leantls.test", NOW),
        Ok(())
    );
}

// --- VerifyPeer::verify_signature -----------------------------------------------

#[test]
fn certificate_verify_signatures() {
    let roots = Roots::from_list(&[ECDSA_ROOT]).unwrap();
    let v = ChainVerifier::new(roots, NOW);
    let msg = chain_file!("cv.msg");
    let ec = chain_file!("cv-ecdsa.sig");
    let pss = chain_file!("cv-rsa-pss.sig");

    assert_eq!(v.verify_signature(ECDSA_LEAF, 0x0403, msg, ec), Ok(()));
    assert_eq!(v.verify_signature(RSA_LEAF, 0x0804, msg, pss), Ok(()));
    assert_eq!(
        v.verify_signature(ECDSA_LEAF, 0x0403, b"other", ec),
        Err(Error::BadSignature)
    );
    assert_eq!(
        v.verify_signature(RSA_LEAF, 0x0804, b"other", pss),
        Err(Error::BadSignature)
    );
    // Go's TestVerifierAlgorithmMismatch.
    let mismatch = [
        (ECDSA_LEAF, 0x0804), // RSA-code met een ECDSA-sleutel
        (RSA_LEAF, 0x0403),   // ECDSA-code met een RSA-sleutel
        (ECDSA_LEAF, 0x0503), // P-384-code met een P-256-sleutel
        (ECDSA_LEAF, 0x0807), // Ed25519-code met een ECDSA-sleutel
    ];
    for (leaf, alg) in mismatch {
        assert_eq!(
            v.verify_signature(leaf, alg, msg, ec),
            Err(Error::X509(X509Error::KeyMismatch(alg))),
            "{alg:#06x}"
        );
    }
    // rsa_pkcs1_sha256 is in een TLS 1.3-handshake verboden.
    assert_eq!(
        v.verify_signature(RSA_LEAF, 0x0401, msg, pss),
        Err(Error::X509(X509Error::Algorithm(0x0401)))
    );
    assert_eq!(v.signature_algorithms(), &SIGNATURE_ALGORITHMS);
}

// --- Wortels en robuustheid -----------------------------------------------------

#[test]
fn roots_are_checked_up_front() {
    assert_eq!(
        Roots::from_list(&[]).err(),
        Some(Error::X509(X509Error::RootCount(0)))
    );
    assert!(matches!(
        Roots::from_list(&[ECDSA_ROOT, &[0x30, 0x00]]),
        Err(Error::X509(X509Error::Malformed {
            cert: CertRef::Root(1),
            ..
        }))
    ));
    let mut cat = ECDSA_ROOT.to_vec();
    cat.extend_from_slice(RSA_ROOT);
    assert_eq!(Roots::from_concatenated_der(&cat).unwrap().len(), 2);
    cat.push(0x30);
    assert!(Roots::from_concatenated_der(&cat).is_err());
}

/// Elke afgekapte versie en elke omgeklapte byte van een blad: nooit een
/// paniek, en een afgekapt certificaat is nooit geldig.
#[test]
fn truncation_and_bit_flips_never_panic() {
    let roots = Roots::from_list(&[ECDSA_ROOT, RSA_ROOT]).unwrap();
    let v = ChainVerifier::new(roots, NOW);
    for leaf in [ECDSA_LEAF, RSA_LEAF] {
        for n in 0..leaf.len() {
            assert!(Cert::parse(&leaf[..n]).is_err(), "prefix {n}");
        }
        for i in 0..leaf.len() {
            let mut m = leaf.to_vec();
            m[i] ^= 0x41;
            if let Ok(c) = Cert::parse(&m) {
                let _ = c.public_key();
                let _ = c.dns_names().count();
            }
            // De volle toets kost een handtekening per poging; elke
            // zevende byte houdt de debug-test onder een paar seconden.
            let body = message(&[&m, ECDSA_INTER, RSA_INTER]);
            if i % 7 == 0
                && let Ok(chain) = CertChain::parse(&body)
            {
                // Een omgeklapte byte kan nooit een geldige keten opleveren.
                assert!(v.check(chain, "leantls.test").is_err(), "flip {i}");
            }
            let _ = v.verify_signature(&m, 0x0403, b"x", &[0x30, 0x00]);
        }
    }
}

#[test]
fn parsed_fields() {
    let leaf = Cert::parse(ECDSA_LEAF).unwrap();
    assert_eq!(leaf.version, 3);
    assert_eq!(leaf.sig_alg, SigAlg::Ecdsa(HashAlg::Sha256));
    assert_eq!(
        leaf.basic,
        Some(cert::Basic {
            ca: false,
            path_len: None
        })
    );
    assert_eq!(leaf.server_auth, Some(true));
    assert!(leaf.allows(key_usage::DIGITAL_SIGNATURE));
    assert!(!leaf.allows(key_usage::KEY_CERT_SIGN));
    let names: Vec<&[u8]> = leaf.dns_names().collect();
    assert_eq!(names, [&b"leantls.test"[..], b"*.wild.leantls.test"]);
    let inter = Cert::parse(ECDSA_INTER).unwrap();
    assert_eq!(
        inter.basic,
        Some(cert::Basic {
            ca: true,
            path_len: Some(0)
        })
    );
    assert_eq!(leaf.aki, inter.ski);
    assert!(inter.ski.is_some());
    assert_eq!(leaf.issuer, inter.subject);
    assert!(Cert::parse(ECDSA_ROOT).unwrap().is_self_issued());
    assert!(matches!(
        Cert::parse(RSA_LEAF).unwrap().public_key(),
        Ok(PublicKey::Rsa { n, e: [1, 0, 1] }) if n.len() == 256
    ));
}
