//! De primitieven van de ene suite, en niets meer.
//!
//! `TLS_AES_128_GCM_SHA256` met X25519 en Ed25519 vraagt: SHA-256, HMAC en
//! HKDF daarover, AES-128-GCM, X25519, en voor Ed25519-verificatie SHA-512.
//! Elke primitieve is getest tegen de officiële vectoren (RFC 6234, 4231,
//! 5869, 7748, 8032, FIPS 197 en de GCM-specificatie).
//!
//! Wat constant-time is en wat niet:
//!
//! - constant-time: AES (geen tabel), GHASH, X25519-ladder en het veld,
//!   HMAC, het vergelijken van tags en Finished-MAC's, het wissen;
//! - variabele tijd, bewust: Ed25519-verificatie (alleen publieke sleutel,
//!   bericht en handtekening), de reductie modulo L daarin, en de codering
//!   van veldelementen die alleen op publieke punten wordt gebruikt.

pub(crate) mod aes;
pub(crate) mod ct;
pub(crate) mod ed25519;
pub(crate) mod field;
pub(crate) mod gcm;
pub(crate) mod hmac;
pub(crate) mod sha256;
pub(crate) mod sha512;
pub(crate) mod x25519;

#[cfg(test)]
pub(crate) mod testutil {
    //! Hulpjes voor de vectortests.

    /// Hex naar bytes; spaties en regeleinden worden overgeslagen.
    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(digits.len().is_multiple_of(2), "oneven aantal hexcijfers");
        digits
            .chunks(2)
            .map(|p| {
                let s = std::str::from_utf8(p).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    /// Hex naar precies 32 bytes.
    pub(crate) fn arr32(s: &str) -> [u8; 32] {
        let v = unhex(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }
}
