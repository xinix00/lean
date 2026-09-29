//! HTTP/2 in de serverrol op een verbinding die de aanroeper al koos.
//!
//! Deze crate bezit één HTTP/2-verbinding: de framing, de streams, HPACK en
//! beide niveaus van flow control. De verbinding zelf (TCP, TLS, deadlines)
//! bezit hij niet; die komt binnen als [`AsyncRead`] plus [`AsyncWrite`].
//!
//! Hij bestaat omdat het alternatief niet los te gebruiken is. In Go nam
//! `x/net/http2` een `http.Handler`, dus HTTP/2 trok `net/http` mee, en dat
//! linkt `crypto/tls` en `crypto/x509` of de verbinding nu versleuteld is of
//! niet. Twee gelijke mains met één verbinding (`-ldflags="-s -w"`, CGO uit,
//! 19-08-2026): 5,10 MB tegen 2,22 MB, 56% kleiner.
//!
//! # Alleen de serverrol
//!
//! Geen listener, geen dialer, geen clienthelft, en geen onderhandeling over
//! de protocolversie: de aanroeper heeft al gekozen. Dat is de vorm die de ene
//! gemeten gebruiker nodig heeft: een Cloudflare Tunnel belt naar buiten, en de
//! edge gedraagt zich daarna als HTTP/2-client op die uitgaande verbinding. Hij
//! stuurt de preface, opent elke stream en verwacht nooit een verzoek van deze
//! kant. Wie de keus heeft, gebruikt leanhttp; hier wordt niet gesnuffeld
//! tussen versies, want vier bytes bewijzen geen preface (`PRI` is een geldige
//! HTTP-methode).
//!
//! # Eén eigenaar
//!
//! [`Conn::serve`] is de enige taak die de verbindingsstaat aanraakt. De
//! handlers draaien als futures die `serve` zelf pollt, hoogstens 32 tegelijk;
//! ze praten met de verbinding via een brievenbus per stream (zie
//! `stream.rs`). Alle vensterrekenkunde gebeurt in `serve`, op één plek: twee
//! antwoorden kunnen hetzelfde verbindingskrediet dus niet twee keer uitgeven,
//! en een header-blok gaat altijd in één stuk de draad op.
//!
//! # Bewuste grenzen
//!
//! Geweigerd, elk met een fout die de vergissing van de peer noemt: een
//! verkeerde preface, een frame boven het aangekondigde maximum, kapotte
//! opvulling, DATA of HEADERS op stream 0, een PING die geen acht bytes op
//! stream 0 is, een SETTINGS-bevestiging met inhoud, een even, hergebruikte of
//! lagere stream-id, meer streams dan aangekondigd, een onderbroken header-blok,
//! te veel gecomprimeerde of gedecodeerde kopbytes, verkeerde pseudo-koppen,
//! een veldnaam met hoofdletters, een verbindingsspecifiek veld, een
//! WINDOW_UPDATE van nul of een die overloopt, en EOS in een Huffman-literal.
//! Afwezig, met de toestandsruimte weggehaald: de clientrol, TLS, ALPN, h2c,
//! push, CONNECT, trailers, 1xx, prioriteitstoestand en de dynamische tabel van
//! de encoder (KAM.md, leanh2).

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

mod conn;
mod hpack;
mod huffman;
mod stream;
#[cfg(test)]
mod tests;

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};

pub use conn::{Conn, GoAway};
pub use hpack::HpackError;
pub use stream::{Body, Handler, Request, RequestError, Response};

/// De resultaat-alias van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Wat de peer als eerste stuurt (RFC 9113 §3.4).
const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frametypes (RFC 9113 §6).
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PUSH_PROMISE: u8 = 0x5;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

/// Framevlaggen.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// De enige twee streamcodes die deze kant stuurt: NO_ERROR voor "stop met
/// sturen, het antwoord is compleet", INTERNAL_ERROR voor een handler die niet
/// kon afmaken. Protocolfouten van de peer beëindigen `serve`.
const CODE_NO_ERROR: u32 = 0x0;
const CODE_INTERNAL_ERROR: u32 = 0x2;

/// Wat deze kant aankondigt, en dus moet overleven.
///
/// Het ontvangstvenster is de bodybuffer: een peer mag hoogstens zoveel
/// ongelezen body per stream hebben, en krediet komt terug als de handler leest.
/// Samen met de streamcap begrenst dat het geheugen van één verbinding
/// (32 × 64 KiB) in plaats van het aan de peer te laten. Tabelgrootte nul houdt
/// de peer weg van een dynamische tabel; 16 KiB frames is de RFC-vloer en dus
/// de kleinste buffers.
const OUR_HEADER_TABLE_SIZE: u32 = 0;
/// Ons ontvangstvenster per stream.
const OUR_INITIAL_WINDOW: u32 = 64 << 10;
/// Onze maximale framegrootte, en ook die van alles wat wij sturen.
const OUR_MAX_FRAME: usize = 1 << 14;
/// Onze grens op een gedecodeerde koplijst.
const OUR_MAX_HEADER_LIST: usize = 1 << 16;
/// Hoeveel streams tegelijk.
pub const MAX_CONCURRENT_STREAMS: usize = 32;
/// De grens op de gecomprimeerde bytes van één header-blok.
const MAX_COMPRESSED_HEADERS: usize = 64 << 10;
/// Eén keer bovenop het standaardvenster van de verbinding. Dat begrenst alle
/// ongelezen body over streams heen en laat toch meerdere vensters van 64 KiB
/// tegelijk vorderen.
const CONNECTION_WINDOW_INCREMENT: u32 = 1 << 20;

/// SETTINGS-identifiers.
const SETTING_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTING_ENABLE_PUSH: u16 = 0x2;
const SETTING_MAX_CONCURRENT: u16 = 0x3;
const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTING_MAX_FRAME_SIZE: u16 = 0x5;
const SETTING_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// Het grootste venster dat mag bestaan (RFC 9113 §6.9.1).
const WINDOW_MAX: i64 = (1 << 31) - 1;

/// Een leesbare bytestroom, poll-gebaseerd zoals leanhttp: `Ok(0)` is het
/// einde.
pub trait AsyncRead {
    /// De fout van het transport.
    type Error;
    /// Leest in `buf`, of geeft `Pending` en registreert de wekker.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>>;
}

/// Een schrijfbare bytestroom, poll-gebaseerd zoals leanhttp.
pub trait AsyncWrite {
    /// De fout van het transport.
    type Error;
    /// Schrijft uit `buf` en geeft het aantal aangenomen bytes.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>>;
    /// Sluit het transport; een lezer en schrijver die wachten, worden wakker.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}

/// Waarom [`Conn::serve`] stopte: een protocolkwestie, of het transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError<E> {
    /// De verbinding eindigde om een reden die deze crate benoemt.
    Protocol(Error),
    /// Het transport faalde.
    Transport(E),
}

impl<E: fmt::Display> fmt::Display for ServeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Transport(e) => write!(f, "leanh2: transport: {e}"),
        }
    }
}

impl<E> From<Error> for ServeError<E> {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

/// Alles wat een verbinding of stream kan laten mislukken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `serve` werd een tweede keer aangeroepen.
    ServedTwice,
    /// De peer sloot voordat de preface compleet was.
    PrefaceEof,
    /// De eerste 24 bytes waren niet de client-preface.
    BadPreface,
    /// De peer sloot de verbinding.
    PeerClosed,
    /// Een frame boven de aangekondigde 16 KiB.
    FrameTooLarge {
        /// De lengte uit de framekop.
        len: usize,
    },
    /// Het eerste frame na de preface was geen SETTINGS zonder ACK op stream 0.
    FirstFrameNotSettings,
    /// Een ander frame midden in een open header-blok.
    HeaderBlockInterrupted {
        /// Het frametype.
        frame: u8,
        /// De stream van dat frame.
        stream: u32,
        /// De stream met het open blok.
        open: u32,
    },
    /// CONTINUATION zonder open header-blok.
    ContinuationWithoutBlock,
    /// SETTINGS op een stream.
    SettingsOnStream,
    /// Een SETTINGS-bevestiging met inhoud.
    SettingsAckPayload,
    /// Een tweede SETTINGS-bevestiging.
    SettingsAckDuplicate,
    /// Een SETTINGS-inhoud die geen veelvoud van zes is.
    SettingsMalformed,
    /// INITIAL_WINDOW_SIZE boven 2^31-1.
    InitialWindowTooLarge,
    /// Een nieuwe INITIAL_WINDOW_SIZE die een streamvenster laat overlopen.
    InitialWindowOverflow {
        /// De stream.
        stream: u32,
    },
    /// ENABLE_PUSH anders dan 0 of 1.
    EnablePushInvalid,
    /// MAX_FRAME_SIZE buiten het RFC-bereik.
    MaxFrameSizeInvalid,
    /// Een PING die geen acht bytes op stream 0 is.
    BadPing {
        /// De lengte.
        len: usize,
        /// De stream.
        stream: u32,
    },
    /// Een WINDOW_UPDATE die geen vier bytes is.
    WindowUpdateMalformed,
    /// Een WINDOW_UPDATE van nul.
    WindowUpdateZero,
    /// Een WINDOW_UPDATE die het verbindingsvenster laat overlopen.
    ConnectionWindowOverflow,
    /// Een WINDOW_UPDATE die een streamvenster laat overlopen.
    StreamWindowOverflow {
        /// De stream.
        stream: u32,
    },
    /// Een WINDOW_UPDATE op een stream die nooit geopend werd.
    WindowUpdateIdle {
        /// De stream.
        stream: u32,
    },
    /// HEADERS op stream 0.
    HeadersOnStreamZero,
    /// Een prioriteitsveld in HEADERS korter dan vijf bytes.
    HeadersPriorityMalformed,
    /// Een opgevuld frame zonder opvullengte.
    PadLengthMissing,
    /// Opvulling voorbij het einde van het frame.
    PaddingBeyondFrame,
    /// Een nieuwe stream na onze GOAWAY.
    StreamAfterGoAway,
    /// Een even stream-id.
    NotClientInitiated {
        /// De stream.
        stream: u32,
    },
    /// Een stream-id die niet boven de laatste geaccepteerde ligt.
    StreamNotIncreasing {
        /// De stream.
        stream: u32,
        /// De laatst geaccepteerde.
        last: u32,
    },
    /// Meer dan 32 streams tegelijk.
    TooManyStreams,
    /// Een header-blok boven 64 KiB gecomprimeerd.
    HeaderBlockTooLarge {
        /// De stream.
        stream: u32,
    },
    /// Een onleesbaar header-blok.
    HeaderBlock {
        /// De stream.
        stream: u32,
        /// De HPACK-fout.
        cause: HpackError,
    },
    /// Een verzoek dat de regels van RFC 9113 §8 breekt.
    Request {
        /// De stream.
        stream: u32,
        /// De regel.
        cause: RequestError,
    },
    /// END_STREAM op HEADERS terwijl content-length meer belooft.
    EndedBeforeContentLength {
        /// De stream.
        stream: u32,
        /// De beloofde lengte.
        len: u64,
    },
    /// DATA op stream 0.
    DataOnStreamZero,
    /// DATA op een stream die nooit geopend werd.
    DataOnIdle {
        /// De stream.
        stream: u32,
    },
    /// DATA na END_STREAM.
    DataAfterEndStream {
        /// De stream.
        stream: u32,
    },
    /// Meer body dan content-length.
    BodyExceedsLength {
        /// De stream.
        stream: u32,
        /// De beloofde lengte.
        len: u64,
    },
    /// Minder body dan content-length bij END_STREAM.
    BodyShort {
        /// De stream.
        stream: u32,
        /// Ontvangen bytes.
        got: u64,
        /// De beloofde lengte.
        len: u64,
    },
    /// Het ontvangstvenster van de verbinding overschreden.
    ConnectionReceiveWindow,
    /// DATA op een gesloten stream.
    DataOnClosed {
        /// De stream.
        stream: u32,
    },
    /// Het restvenster van een net gereset stream overschreden.
    ResetStreamWindow {
        /// De stream.
        stream: u32,
    },
    /// Het ontvangstvenster van een stream overschreden.
    StreamReceiveWindow {
        /// De stream.
        stream: u32,
    },
    /// Teruggegeven krediet zou een venster laten overlopen.
    CreditOverflow,
    /// Een RST_STREAM die geen vier bytes op een stream is.
    BadRstStream {
        /// De lengte.
        len: usize,
        /// De stream.
        stream: u32,
    },
    /// RST_STREAM op een stream die nooit geopend werd.
    RstOnIdle {
        /// De stream.
        stream: u32,
    },
    /// PUSH_PROMISE van een client.
    PushPromise,
    /// De peer stuurde GOAWAY.
    PeerGoAway {
        /// De foutcode van de peer.
        code: u32,
    },
    /// Een GOAWAY korter dan acht bytes of op een stream.
    BadGoAway {
        /// De lengte.
        len: usize,
        /// De stream.
        stream: u32,
    },
    /// Een PRIORITY die geen vijf bytes op een stream is.
    BadPriority {
        /// De lengte.
        len: usize,
        /// De stream.
        stream: u32,
    },
    /// Het transport nam nul bytes aan.
    WriteZero,
    /// De heap weigerde.
    OutOfMemory,
    /// De peer resette deze stream.
    StreamReset,
    /// De stream is al afgerond of gereset.
    StreamClosed,
    /// De verbinding eindigde.
    ConnectionClosed,
    /// De handler sloot de body zelf.
    BodyClosed,
    /// Een antwoordstatus buiten 200..=599.
    StatusOutOfRange {
        /// De status.
        status: u16,
    },
    /// Een ongeldige antwoordveldnaam.
    ResponseFieldName,
    /// Een antwoordveld dat niet mag: pseudo, verbindingsspecifiek, trailer.
    ResponseFieldForbidden,
    /// Een content-length in het antwoord; DATA plus END_STREAM is de lengte.
    ResponseContentLength,
    /// Een ongeldige antwoordveldwaarde.
    ResponseFieldValue,
    /// Een antwoordkoplijst boven 64 KiB.
    ResponseHeaderTooLarge,
    /// WriteHeader na de koppen.
    HeadersAlreadySent,
    /// Body voor HEAD, 204, 205 of 304.
    BodylessResponse,
    /// Een GOAWAY-reden langer dan in één frame past.
    GoAwayReasonTooLong {
        /// De lengte.
        len: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("leanh2: ")?;
        match *self {
            Self::ServedTwice => f.write_str("Serve called more than once"),
            Self::PrefaceEof => f.write_str("reading the client preface: unexpected end"),
            Self::BadPreface => f.write_str("peer did not send the HTTP/2 client preface"),
            Self::PeerClosed => f.write_str("the peer closed the connection"),
            Self::FrameTooLarge { len } => write!(
                f,
                "peer sent a {len} byte frame above the announced {OUR_MAX_FRAME}"
            ),
            Self::FirstFrameNotSettings => f.write_str(
                "the first peer frame after the preface is not non-ACK SETTINGS on stream 0",
            ),
            Self::HeaderBlockInterrupted {
                frame,
                stream,
                open,
            } => write!(
                f,
                "frame type 0x{frame:02x} on stream {stream} interrupted the header block of stream {open}"
            ),
            Self::ContinuationWithoutBlock => {
                f.write_str("CONTINUATION without an open header block")
            }
            Self::SettingsOnStream => f.write_str("SETTINGS on a stream"),
            Self::SettingsAckPayload => f.write_str("SETTINGS acknowledgement with a payload"),
            Self::SettingsAckDuplicate => f.write_str("duplicate SETTINGS acknowledgement"),
            Self::SettingsMalformed => f.write_str("malformed SETTINGS"),
            Self::InitialWindowTooLarge => f.write_str("INITIAL_WINDOW_SIZE too large"),
            Self::InitialWindowOverflow { stream } => write!(
                f,
                "INITIAL_WINDOW_SIZE would overflow the window of stream {stream}"
            ),
            Self::EnablePushInvalid => f.write_str("ENABLE_PUSH is not 0 or 1"),
            Self::MaxFrameSizeInvalid => f.write_str("MAX_FRAME_SIZE out of range"),
            Self::BadPing { len, stream } => write!(f, "PING of {len} bytes on stream {stream}"),
            Self::WindowUpdateMalformed => f.write_str("malformed WINDOW_UPDATE"),
            Self::WindowUpdateZero => f.write_str("WINDOW_UPDATE of zero"),
            Self::ConnectionWindowOverflow => {
                f.write_str("WINDOW_UPDATE would overflow the connection window")
            }
            Self::StreamWindowOverflow { stream } => write!(
                f,
                "WINDOW_UPDATE would overflow the window of stream {stream}"
            ),
            Self::WindowUpdateIdle { stream } => {
                write!(f, "WINDOW_UPDATE on idle stream {stream}")
            }
            Self::HeadersOnStreamZero => f.write_str("HEADERS on stream 0"),
            Self::HeadersPriorityMalformed => f.write_str("malformed HEADERS priority"),
            Self::PadLengthMissing => f.write_str("padded frame without a pad length"),
            Self::PaddingBeyondFrame => f.write_str("padding beyond the frame"),
            Self::StreamAfterGoAway => f.write_str("the peer opened a stream after GOAWAY"),
            Self::NotClientInitiated { stream } => {
                write!(f, "stream {stream} is not client-initiated")
            }
            Self::StreamNotIncreasing { stream, last } => {
                write!(f, "stream {stream} is not above the last accepted {last}")
            }
            Self::TooManyStreams => write!(
                f,
                "peer opened more than the announced {MAX_CONCURRENT_STREAMS} concurrent streams"
            ),
            Self::HeaderBlockTooLarge { stream } => write!(
                f,
                "header block of stream {stream} above the {MAX_COMPRESSED_HEADERS} byte limit"
            ),
            Self::HeaderBlock { stream, cause } => {
                write!(f, "header block on stream {stream}: {cause}")
            }
            Self::Request { stream, cause } => write!(f, "request on stream {stream}: {cause}"),
            Self::EndedBeforeContentLength { stream, len } => write!(
                f,
                "request on stream {stream} ended before its content-length of {len}"
            ),
            Self::DataOnStreamZero => f.write_str("DATA on stream 0"),
            Self::DataOnIdle { stream } => write!(f, "DATA on idle stream {stream}"),
            Self::DataAfterEndStream { stream } => {
                write!(f, "DATA after END_STREAM on stream {stream}")
            }
            Self::BodyExceedsLength { stream, len } => {
                write!(f, "stream {stream} body exceeds content-length {len}")
            }
            Self::BodyShort { stream, got, len } => write!(
                f,
                "stream {stream} ended after {got} body bytes, content-length is {len}"
            ),
            Self::ConnectionReceiveWindow => {
                f.write_str("peer exceeded the announced connection receive window")
            }
            Self::DataOnClosed { stream } => write!(f, "DATA on closed stream {stream}"),
            Self::ResetStreamWindow { stream } => write!(
                f,
                "peer exceeded the remaining receive window of reset stream {stream}"
            ),
            Self::StreamReceiveWindow { stream } => write!(
                f,
                "peer exceeded the announced receive window of stream {stream}"
            ),
            Self::CreditOverflow => f.write_str("receive-window credit would overflow"),
            Self::BadRstStream { len, stream } => {
                write!(f, "RST_STREAM of {len} bytes on stream {stream}")
            }
            Self::RstOnIdle { stream } => write!(f, "RST_STREAM on idle stream {stream}"),
            Self::PushPromise => f.write_str("PUSH_PROMISE is not supported by this server"),
            Self::PeerGoAway { code } => write!(f, "the peer sent GOAWAY (code {code})"),
            Self::BadGoAway { len, stream } => {
                write!(f, "GOAWAY of {len} bytes on stream {stream}")
            }
            Self::BadPriority { len, stream } => {
                write!(f, "PRIORITY of {len} bytes on stream {stream}")
            }
            Self::WriteZero => f.write_str("writing a frame: short write"),
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::StreamReset => f.write_str("the peer reset this stream"),
            Self::StreamClosed => f.write_str("stream closed"),
            Self::ConnectionClosed => f.write_str("the connection ended"),
            Self::BodyClosed => f.write_str("body closed by the handler"),
            Self::StatusOutOfRange { status } => {
                write!(f, "response status {status} is outside 200..599")
            }
            Self::ResponseFieldName => f.write_str("response field name is invalid"),
            Self::ResponseFieldForbidden => f.write_str("response field is not permitted"),
            Self::ResponseContentLength => f.write_str("response content-length is not supported"),
            Self::ResponseFieldValue => f.write_str("response field has an invalid value"),
            Self::ResponseHeaderTooLarge => write!(
                f,
                "response header list above the {OUR_MAX_HEADER_LIST} byte limit"
            ),
            Self::HeadersAlreadySent => f.write_str("headers already sent"),
            Self::BodylessResponse => f.write_str("this response status or method has no body"),
            Self::GoAwayReasonTooLong { len } => write!(
                f,
                "GOAWAY reason is {len} bytes, maximum is {}",
                OUR_MAX_FRAME - 8
            ),
        }
    }
}
