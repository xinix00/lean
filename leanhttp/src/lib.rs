//! HTTP/1.1 zonder TLS: client en server, sequentiele keep-alive, chunked antwoorden.
//!
//! Deze crate praat niet met een netstack maar met een verbinding: alles wat
//! [`AsyncRead`], [`AsyncWrite`] en [`Close`] implementeert (een leannet-socket,
//! een leantls-sessie, een pijp in een test). Hij bezit geen klok: een fase-
//! termijn gaat als relatieve `Duration` naar de
//! verbinding, en een totaaltermijn is een `select` van de aanroeper rond de
//! future. Een future laten vallen is annuleren; de verbinding gaat dan mee.
//!
//! Waarom een eigen HTTP en niet die van de standaardbibliotheek: in de
//! Go-generatie linkte `net/http` altijd `crypto/tls` mee, ook zonder één
//! HTTPS-URL. Gemeten in HopOS-app-images op 26-07-2026:
//!
//! ```text
//! applib alleen ................. 1.71 MB
//! + appnet (gVisor) ............. 4.70 MB
//! + net/http .................... 7.99 MB
//! + dit pakket .................. 5.06 MB
//! ```
//!
//! Ongeveer 54% van wat `net/http` toevoegde was TLS/PKI; drie apps (display,
//! launcher, taskman) werden elk zo'n 2.9 MB kleiner. De grens blijft: HTTPS
//! kan alleen via een [`Dial`] die zelf versleutelt en dat zegt.
//!
//! Wat de crate bezit:
//!
//! - de server ([`serve`]): één verbinding, sequentieel, met [`Exchange`] als
//!   de ene plek waar een handler het verzoek leest en het antwoord schrijft;
//! - de [`Mux`]: methode plus pad, exact of subtree, `{segment}` en
//!   `{rest...}`, `GET` dat ook `HEAD` bedient, 404 en 405 met `Allow`;
//! - de client ([`send`] voor één hop op een gegeven verbinding, [`fetch`] en
//!   [`get`] met redirects, [`Client`] met een keep-alive-[`Pool`]).
//!
//! Wat hij niet bezit: TLS, HTTP/2 (dat is `leanh2`), decompressie, cookies
//! (dat is `leancookie`), een listener. KAM.md in de repository-root is het
//! contract; waar deze crate ervan afwijkt, staat dat bij het item.

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
#![forbid(unsafe_code)]

extern crate alloc;

mod client;
mod error;
mod header;
mod io;
mod mux;
mod pool;
mod server;
mod url;

#[cfg(test)]
mod tests;

use core::time::Duration;

pub use client::{Call, Dial, Response, Target, fetch, get, send};
pub use error::{Error, PatternError, Result};
pub use header::Header;
pub use io::{AsyncRead, AsyncWrite, Close, Conn, IoError, close, flush, read, write_all};
pub use mux::{Found, Mux};
pub use pool::{Client, Pool};
pub use server::{Exchange, Hijacked, Next, Outcome, Raw, Request, Source, serve};

/// Leesbuffer per verbinding, en daarmee ook de grens van één headerregel.
///
/// KAM: 8 KiB per regel. Eén buffer bewaakt beide, zodat een regel nooit
/// langer kan zijn dan wat de parser in één keer overziet.
pub const BUF_SIZE: usize = 8 << 10;

/// Grens voor alle headers van één bericht samen, tussenantwoorden inbegrepen.
///
/// KAM: 64 KiB. Veel kleine regels die elk geldig zijn, mogen samen de
/// verbinding niet vasthouden.
pub const MAX_HEADER_BYTES: usize = 64 << 10;

/// Grootste request-body die de server aanneemt.
///
/// KAM: 1 MiB. Deze server is er voor API's en kleine formulieren, niet voor
/// uploads; groter is een 413 nog voor de handler draait.
pub const MAX_BODY_BYTES: u64 = 1 << 20;

/// Grens waarboven een antwoord zonder lengte overgaat op chunked.
///
/// KAM: 64 KiB. Een vergeten `Content-Length` mag nooit onbegrensd bufferen.
pub const AUTO_CHUNK_BYTES: usize = 64 << 10;

/// Maximaal aantal redirects dat de client volgt; gelijk aan de standaard van
/// Go's `net/http`.
pub const MAX_REDIRECTS: usize = 10;

/// Termijn voor de eerste requestkop op een verse verbinding.
///
/// Een verbinding die niets zegt, houdt anders een taak uit de pool vast.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Termijn tussen twee verzoeken op een keep-alive-verbinding.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Termijn per schrijfactie op de socket, niet per antwoord: een lange stroom
/// overleeft, een client die niet leest niet.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Termijn om een ongelezen body weg te lezen vóór sluiten of hergebruik, zodat
/// het antwoord aankomt in plaats van een RST.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Termijn voor het lezen van een request-body.
///
/// Een client die een `Content-Length` belooft en dan zwijgt, gijzelt anders
/// een taak en een verbinding voor onbepaalde tijd.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// Termijn voor het oordeel op `Expect: 100-continue` bij een gestroomde
/// upload, als `header_timeout` ruimer of afwezig is.
///
/// Stilte is een fout; de body wordt dan niet verstuurd.
pub const EXPECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Hoe lang één sondering van de leeskant door [`Exchange::reader_gone`]
/// duurt voordat "de lezer is er nog" het antwoord is.
///
/// Een lange response (SSE, een log-tail) merkt anders pas aan een
/// mislukte schrijf dat zijn lezer wegging, en op een stack die een
/// schrijf naar een weggevallen lezer niet laat falen is dat nooit. Kort,
/// want de sondering staat in de lus van de stroom; lang genoeg om op een
/// blokkerende verbinding één `read` met termijn te zijn.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1);

/// Statuscodes die deze crate of zijn gebruikers sturen.
///
/// Een code komt erbij zodra een gebruiker hem stuurt; dit is geen volledige
/// lijst.
pub mod status {
    /// 200.
    pub const OK: u16 = 200;
    /// 201.
    pub const CREATED: u16 = 201;
    /// 202.
    pub const ACCEPTED: u16 = 202;
    /// 204: altijd zonder body en zonder `Content-Length`.
    pub const NO_CONTENT: u16 = 204;
    /// 205: altijd zonder body, met `Content-Length: 0`.
    pub const RESET_CONTENT: u16 = 205;
    /// 301.
    pub const MOVED_PERMANENTLY: u16 = 301;
    /// 302.
    pub const FOUND: u16 = 302;
    /// 304: zonder body; een `Content-Length` is informatief.
    pub const NOT_MODIFIED: u16 = 304;
    /// 400.
    pub const BAD_REQUEST: u16 = 400;
    /// 401.
    pub const UNAUTHORIZED: u16 = 401;
    /// 404.
    pub const NOT_FOUND: u16 = 404;
    /// 405, altijd met `Allow`.
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    /// 406.
    pub const NOT_ACCEPTABLE: u16 = 406;
    /// 409.
    pub const CONFLICT: u16 = 409;
    /// 413.
    pub const REQUEST_ENTITY_TOO_LARGE: u16 = 413;
    /// 417.
    pub const EXPECTATION_FAILED: u16 = 417;
    /// 500.
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    /// 501.
    pub const NOT_IMPLEMENTED: u16 = 501;
    /// 502.
    pub const BAD_GATEWAY: u16 = 502;
    /// 503.
    pub const SERVICE_UNAVAILABLE: u16 = 503;
    /// 505.
    pub const HTTP_VERSION_NOT_SUPPORTED: u16 = 505;
}

/// Methodes als constanten, zodat routetabellen geen losse strings dragen.
///
/// Methode-tokens zijn hoofdlettergevoelig (RFC 9110 §9.1): `head` is geen
/// `HEAD`.
pub mod method {
    /// GET.
    pub const GET: &str = "GET";
    /// HEAD.
    pub const HEAD: &str = "HEAD";
    /// POST.
    pub const POST: &str = "POST";
    /// PUT.
    pub const PUT: &str = "PUT";
    /// PATCH.
    pub const PATCH: &str = "PATCH";
    /// DELETE.
    pub const DELETE: &str = "DELETE";
}
