//! TLS 1.3 voor een netwerk dat je bezit: een versie, een suite, een gepinde
//! Ed25519-peer of een echte keten.
//!
//! Een client, zonder std en zonder externe crates. Precies één combinatie:
//! TLS 1.3, `TLS_AES_128_GCM_SHA256`, X25519, en in gepinde modus Ed25519.
//! Geen downgrade, hervatting, PSK, 0-RTT, clientcertificaat,
//! HelloRetryRequest of renegotiatie; wat de server anders kiest, faalt luid.
//! Het weglaten van downgrade, compressie, CBC en RSA-PKCS#1v1.5 haalt de
//! gebruikelijke gevaarlijke toestandsruimte van TLS weg.
//!
//! # Vertrouwen
//!
//! Gewone HTTPS delegeert identiteit aan een CA-keten. Een pin verspreidt in
//! plaats daarvan een bekende Ed25519-sleutel van 32 bytes met de node: de
//! handshake eist dat de certificaatsleutel daaraan gelijk is en controleert
//! de handtekening over het transcript met die sleutel. Geen CA-, naam- of
//! datumdubbelzinnigheid, ten koste van nieuwe pins als sleutels roteren;
//! dat past bij een eigen vloot, niet bij publieke hosts. Voor die laatste
//! levert de aanroeper een [`VerifyPeer`]. Zie [`Trust`]: er is altijd
//! precies één model.
//!
//! # Waarom een eigen TLS
//!
//! Gemeten met de Go-voorganger op dezelfde tamago/riscv64-main
//! (2026-08-12): het board met fmt was 1,69 MB, met deze package in gepinde
//! modus 2,51 MB, met ketenverificatie 3,73 MB, en met `crypto/tls` plus een
//! CA-bundel 4,09 MB. Gepinde modus bespaarde dus 1,57 MB, omdat hij geen
//! X.509, ASN.1, bignums, RSA, NIST-curves of CA-bundel meeneemt. Die
//! verhouding is de reden dat deze crate bestaat; de Rust-maat is nog niet
//! gemeten.
//!
//! # Gebruik
//!
//! ```no_run
//! # use leantls::{connect, AsyncRead, AsyncWrite, ConnError, Entropy, PeerKey, Trust};
//! # use core::{pin::Pin, task::{Context, Poll}};
//! # struct Tcp;
//! # impl AsyncRead for Tcp {
//! #     type Error = ();
//! #     fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, ()>> { Poll::Pending }
//! # }
//! # impl AsyncWrite for Tcp {
//! #     type Error = ();
//! #     fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<Result<usize, ()>> { Poll::Pending }
//! # }
//! # async fn demo(tcp: Tcp, leader_key: [u8; 32], seed: [u8; 96]) -> Result<(), ConnError<()>> {
//! // Een peer waarvan de sleutel al bekend is (32 bytes uit je eigen configuratie).
//! let trust = Trust::Pinned(PeerKey::new(leader_key));
//! let mut conn = connect(tcp, &trust, "leader", Entropy::new(seed)).await?;
//! // ... lezen en schrijven via AsyncRead en AsyncWrite ...
//! conn.close_notify().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`connect`] neemt een transport dat [`AsyncRead`] en [`AsyncWrite`]
//! implementeert en geeft een [`Conn`] die dat zelf ook doet. De crate weet
//! niets van HTTP of van de netstack eronder.
//!
//! # Constant-time
//!
//! AES zonder tabel, GHASH, X25519 en HMAC zijn constant-time; de
//! vergelijking van tags en Finished ook. Ed25519-verificatie werkt alleen op
//! publieke data en is dat bewust niet.

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
// `crypto::ct`, daar toegestaan met een `expect` en een SAFETY-regel.
#![deny(unsafe_code)]

extern crate alloc;

mod conn;
pub(crate) mod crypto;
mod error;
mod handshake;
mod io;
mod record;
mod schedule;
mod spki;
mod trust;
mod wire;

#[cfg(test)]
mod tests;

pub use conn::Conn;
pub use error::{ConnError, Error, Result};
pub use handshake::connect;
pub use io::{AsyncRead, AsyncWrite};
pub use trust::{CertChain, CertIter, Entropy, PeerKey, Trust, VerifyPeer};
