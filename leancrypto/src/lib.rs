//! De primitieven die meer dan één crate nodig heeft, één keer.
//!
//! Uit leantls gehaald, waar ze de TLS 1.3-suite dragen; leans3 tekent er
//! SigV4 mee, en apps hashen er artifacts en back-ups mee. Wat alleen TLS
//! gebruikt (X25519, Ed25519, ECDSA, RSA en hun rekenkunde), blijft daar.
//!
//! - [`sha256`] en [`sha512`] (met SHA-384), stromend of in één keer;
//! - [`sha1`]: alleen voor protocollen die hem eisen (WebSocket);
//! - [`hmac`]: HMAC-SHA256 en HKDF (RFC 5869);
//! - [`hash`]: één digest over SHA-256, -384 en -512 gekozen tijdens het lopen;
//! - [`aes`] en [`gcm`]: AES-128 zonder opzoektabel en AES-128-GCM;
//! - [`ct`]: constant-time vergelijken en het wissen van geheimen.
//!
//! # Constant-time
//!
//! AES zonder tabel, GHASH en HMAC zijn constant-time; de vergelijking van
//! tags ook. Lengtes zijn publiek.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
// Geen `forbid`: de enige `unsafe` is het vluchtige wissen van geheimen in
// `ct`, daar toegestaan met een `expect` en een SAFETY-regel.
#![deny(unsafe_code)]

pub mod aes;
pub mod ct;
pub mod gcm;
pub mod hash;
pub mod hmac;
pub mod sha1;
pub mod sha256;
pub mod sha512;

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
}
