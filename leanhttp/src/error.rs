//! De foutsoort van de crate: één kleine `enum` die in `Display` de getallen
//! meegeeft, en `Copy` is zodat een schrijffout kleverig bewaard kan worden.

use core::fmt;

use crate::io::IoError;

/// Resultaat met [`Error`] als standaardfout.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Alles wat in leanhttp mis kan gaan.
///
/// De server zet een parsefout om in een statuscode (400, 413, 417, 501,
/// 505); de client geeft hem terug aan de aanroeper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// De verbinding gaf een fout.
    Io(IoError),
    /// De verbinding eindigde netjes voordat er iets begon.
    Eof,
    /// De verbinding eindigde midden in een bericht met een bekende lengte.
    UnexpectedEof,
    /// Een allocatie van zoveel bytes mislukte.
    Alloc {
        /// Gevraagde bytes.
        bytes: usize,
    },
    /// Een headerregel was langer dan de leesbuffer.
    LineTooLong {
        /// De grens in bytes.
        limit: usize,
    },
    /// Alle headers samen waren groter dan de grens.
    HeadersTooLarge {
        /// De grens in bytes.
        limit: usize,
    },
    /// Een regel eindigde niet op CRLF (een kale LF telt niet).
    NotCrlf,
    /// Een regel bevatte een controlebyte.
    ControlByte,
    /// Een regel was geen UTF-8.
    NotUtf8,
    /// Een headerregel had geen `:`.
    MalformedHeader,
    /// Een headernaam was geen token (bijvoorbeeld een spatie voor de `:`).
    InvalidHeaderName,
    /// De requestregel had niet de vorm `METHODE doel HTTP/1.1`.
    MalformedRequestLine,
    /// De methode was geen token.
    InvalidMethod,
    /// `CONNECT` vraagt een tunnel, en die bestaat hier niet.
    Connect,
    /// Het verzoek was geen HTTP/1.1.
    UnsupportedVersion,
    /// Het requestdoel was niet in origin-form.
    NotOriginForm,
    /// Het requestdoel was geen geldige URI.
    BadTarget,
    /// Een percent-escape decodeerde tot `/`, `.` of `..`.
    AmbiguousEscape,
    /// Het pad was niet canoniek (lege of punt-segmenten).
    NonCanonicalPath,
    /// Er was niet precies één niet-lege `Host`.
    HostCount {
        /// Aantal `Host`-regels.
        got: usize,
    },
    /// Een verzoek met `Expect`; daar is geen toestandsmachine voor.
    ExpectUnsupported,
    /// Een framingheader kwam meer dan eens voor.
    RepeatedFraming,
    /// `Transfer-Encoding` en `Content-Length` samen.
    BothFramings,
    /// Een request met `Transfer-Encoding`; alleen `Content-Length` bestaat.
    RequestTransferEncoding,
    /// `Content-Length` was geen kaal decimaal getal.
    BadContentLength,
    /// Een body boven de grens.
    BodyTooLarge {
        /// Aangekondigde lengte.
        len: u64,
        /// De grens.
        limit: u64,
    },
    /// Een status buiten 200..=599; 101 bestaat alleen via hijack.
    InvalidStatus(u16),
    /// De handler schreef meer dan zijn eigen `Content-Length`.
    WroteTooMuch {
        /// De beloofde lengte.
        declared: u64,
    },
    /// De verbinding is overgenomen; de gewone schrijver is dicht.
    Hijacked,
    /// Het antwoord was al begonnen (kop, status of gebufferde bytes).
    ResponseStarted,
    /// `done` heeft de leeskant al; een tweede eigenaar kan niet.
    DoneClaimed,
    /// `done` kwam nadat de kop al op de draad stond.
    DoneAfterStart,
    /// De URL was niet te parsen.
    BadUrl,
    /// De URL had geen host.
    NoHost,
    /// Alleen `http://` en `https://` bestaan.
    UnsupportedScheme,
    /// `https://` zonder een dialer die versleutelt.
    HttpsNeedsTls,
    /// `body` en `body_reader` samen.
    BodyConflict,
    /// Een uitgaande headernaam was geen token.
    IllegalHeaderName,
    /// Een uitgaande headerwaarde bevatte een controlebyte.
    IllegalHeaderValue,
    /// Een header die de crate zelf zet (`Host`, framing, `Connection`, `Expect`).
    PackageOwnedHeader,
    /// De statusregel was geen `HTTP/x.y ddd ...`.
    MalformedStatusLine,
    /// Een protocolversie anders dan HTTP/1.0 of HTTP/1.1.
    UnsupportedProtocol,
    /// De server antwoordde 101; deze client spreekt alleen HTTP/1.1.
    SwitchedProtocols,
    /// Twee `Content-Length`-regels in een antwoord.
    DuplicateContentLength,
    /// Twee `Transfer-Encoding`-regels in een antwoord.
    DuplicateTransferEncoding,
    /// Een `Transfer-Encoding` anders dan `chunked`.
    UnsupportedTransferEncoding,
    /// Een chunkgrootte die geen kale hex was.
    MalformedChunkSize,
    /// Een chunk-extensie; die weigeren we allemaal.
    ChunkExtension,
    /// Een chunk eindigde niet op CRLF.
    ChunkNotCrlf,
    /// Een trailerregel was geen header.
    MalformedTrailer,
    /// Een trailer die framing, routering of authenticatie raakt.
    ForbiddenTrailer,
    /// De `body_reader` leverde niet precies `body_len` bytes.
    StreamBody {
        /// Verstuurd.
        sent: u64,
        /// Beloofd.
        want: u64,
    },
    /// Geen `100` en geen eindstatus binnen de beslistermijn van `Expect`.
    NoVerdict,
    /// Meer redirects dan de grens.
    TooManyRedirects {
        /// De grens.
        max: usize,
    },
    /// Een redirect van `https://` naar `http://`.
    HttpsDowngrade,
    /// [`get`](crate::get) wil precies 200 en kreeg dit.
    Status(u16),
    /// [`get`](crate::get) wil een bekende lengte en kreeg chunked.
    ChunkedNotAllowed,
    /// [`get`](crate::get) wil een bekende lengte en kreeg er geen.
    NoContentLength,
    /// Een routepatroon was fout.
    Pattern(PatternError),
}

/// Waarom een routepatroon geweigerd werd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// Het pad was niet canoniek: geen leidende slash, of lege of punt-segmenten.
    NotCanonical,
    /// De methode was geen token.
    BadMethod,
    /// `{$}` bestaat hier niet.
    Dollar,
    /// Een lege of dubbele wildcardnaam.
    BadName,
    /// Een segment na `{rest...}`.
    SegmentAfterRest,
    /// Een segment dat half een wildcard is.
    MalformedWildcard,
    /// Een percent-escape in een literal; schrijf het teken zelf.
    EscapedLiteral,
    /// Overlap zonder strikte deelverzameling met de route op deze index.
    Conflict {
        /// Index van de eerder geregistreerde route.
        with: usize,
    },
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::Io(e)
    }
}

impl From<PatternError> for Error {
    fn from(e: PatternError) -> Self {
        Error::Pattern(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Io(e) => write!(f, "connection: {e}"),
            Error::Eof => f.write_str("connection closed"),
            Error::UnexpectedEof => f.write_str("unexpected EOF"),
            Error::Alloc { bytes } => write!(f, "allocation of {bytes} bytes failed"),
            Error::LineTooLong { limit } => write!(f, "header line exceeds {limit} bytes"),
            Error::HeadersTooLarge { limit } => write!(f, "headers exceed {limit} bytes"),
            Error::NotCrlf => f.write_str("line not terminated by CRLF"),
            Error::ControlByte => f.write_str("control byte in line"),
            Error::NotUtf8 => f.write_str("line is not UTF-8"),
            Error::MalformedHeader => f.write_str("malformed header"),
            Error::InvalidHeaderName => f.write_str("invalid header name"),
            Error::MalformedRequestLine => f.write_str("malformed request line"),
            Error::InvalidMethod => f.write_str("invalid method"),
            Error::Connect => f.write_str("CONNECT is not supported (never a tunnel)"),
            Error::UnsupportedVersion => f.write_str("unsupported protocol version"),
            Error::NotOriginForm => f.write_str("only origin-form request targets are supported"),
            Error::BadTarget => f.write_str("bad request target"),
            Error::AmbiguousEscape => f.write_str("ambiguous percent-escape in path"),
            Error::NonCanonicalPath => f.write_str("non-canonical request path"),
            Error::HostCount { got } => write!(
                f,
                "HTTP/1.1 requires exactly one non-empty Host header (got {got})"
            ),
            Error::ExpectUnsupported => f.write_str("Expect is not supported"),
            Error::RepeatedFraming => f.write_str("repeated framing header"),
            Error::BothFramings => f.write_str("both Transfer-Encoding and Content-Length"),
            Error::RequestTransferEncoding => f.write_str(
                "Transfer-Encoding is not supported for requests; send a Content-Length",
            ),
            Error::BadContentLength => f.write_str("bad Content-Length"),
            Error::BodyTooLarge { len, limit } => {
                write!(f, "body of {len} bytes exceeds the {limit}-byte limit")
            }
            Error::InvalidStatus(s) => write!(f, "status {s} is not a final status 200-599"),
            Error::WroteTooMuch { declared } => {
                write!(
                    f,
                    "handler wrote past its declared Content-Length {declared}"
                )
            }
            Error::Hijacked => f.write_str("connection was hijacked"),
            Error::ResponseStarted => f.write_str("hijack after the response already started"),
            Error::DoneClaimed => {
                f.write_str("hijack after done: the read side already has an owner")
            }
            Error::DoneAfterStart => {
                f.write_str("done after the response started: claim it before the first flush")
            }
            Error::BadUrl => f.write_str("bad URL"),
            Error::NoHost => f.write_str("URL has no host"),
            Error::UnsupportedScheme => f.write_str("only http:// and https:// are supported"),
            Error::HttpsNeedsTls => f.write_str(
                "https:// needs a Dial that returns an encrypted connection \
                 (this crate links no TLS): use leanhttps",
            ),
            Error::BodyConflict => f.write_str("set body or body_reader, not both"),
            Error::IllegalHeaderName => f.write_str("illegal header name"),
            Error::IllegalHeaderValue => f.write_str("illegal header value"),
            Error::PackageOwnedHeader => {
                f.write_str("header is set by the package, not by the caller")
            }
            Error::MalformedStatusLine => f.write_str("malformed status line"),
            Error::UnsupportedProtocol => f.write_str("unsupported protocol in status line"),
            Error::SwitchedProtocols => {
                f.write_str("server switched protocols (101); this crate speaks HTTP/1.1 only")
            }
            Error::DuplicateContentLength => f.write_str("duplicate Content-Length"),
            Error::DuplicateTransferEncoding => f.write_str("duplicate Transfer-Encoding"),
            Error::UnsupportedTransferEncoding => {
                f.write_str("unsupported Transfer-Encoding in response")
            }
            Error::MalformedChunkSize => f.write_str("malformed chunk size"),
            Error::ChunkExtension => f.write_str("chunk extensions are not supported"),
            Error::ChunkNotCrlf => f.write_str("chunk not terminated by CRLF"),
            Error::MalformedTrailer => f.write_str("malformed trailer line"),
            Error::ForbiddenTrailer => f.write_str("forbidden trailer field"),
            Error::StreamBody { sent, want } => {
                write!(f, "stream body gave {sent} of {want} bytes")
            }
            Error::NoVerdict => {
                f.write_str("no verdict on Expect: 100-continue (want 100 or a final status)")
            }
            Error::TooManyRedirects { max } => write!(f, "too many redirects (>{max})"),
            Error::HttpsDowngrade => {
                f.write_str("refusing redirect: https must not degrade to plain http")
            }
            Error::Status(s) => write!(f, "HTTP {s}"),
            Error::ChunkedNotAllowed => f.write_str(
                "chunked transfer is not supported here: serve it with a Content-Length",
            ),
            Error::NoContentLength => f.write_str("no Content-Length in response"),
            Error::Pattern(p) => write!(f, "route pattern: {p}"),
        }
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PatternError::NotCanonical => {
                f.write_str("not canonical (leading slash, no empty or dot segments)")
            }
            PatternError::BadMethod => f.write_str("malformed method token"),
            PatternError::Dollar => f.write_str(
                "{$} is not carried: use a fixed path (no trailing slash) \
                 or a subtree (trailing slash)",
            ),
            PatternError::BadName => f.write_str("empty or duplicate wildcard name"),
            PatternError::SegmentAfterRest => f.write_str("segments after {rest...}"),
            PatternError::MalformedWildcard => f.write_str("malformed wildcard segment"),
            PatternError::EscapedLiteral => f.write_str("%-escape in a literal segment"),
            PatternError::Conflict { with } => write!(f, "conflicts with route {with}"),
        }
    }
}
