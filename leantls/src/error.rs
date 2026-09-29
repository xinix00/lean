//! De fouten van leantls: een kleine `enum` met de getallen erin.
//!
//! [`Error`] is `Copy`, zodat een record-fout "plakt": de verbinding bewaart
//! hem en geeft hem bij elke volgende aanroep terug. [`ConnError`] voegt daar
//! de fout van het onderliggende transport aan toe, die niet `Copy` hoeft te
//! zijn.

use core::fmt;

/// Een TLS-fout. De tekst in `Display` volgt de Go-versie, zodat logregels
/// en tests hetzelfde blijven zeggen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Een allocatie mislukte.
    Alloc,
    /// Een interne grens werd geraakt die de code zelf zou moeten bewaken.
    Internal(&'static str),
    /// Een bericht was korter dan zijn lengtevelden beloofden.
    Truncated,
    /// Een certificaat is geen geldige DER.
    Der,
    /// Een certificaatveld heeft een onverwachte tag.
    DerField {
        /// Het hoeveelste veld na de versie.
        index: u8,
        /// De gevonden tag.
        tag: u8,
        /// De verwachte tag.
        want: u8,
    },
    /// Het certificaat draagt geen Ed25519-sleutel.
    NotEd25519 {
        /// Lengte van de SubjectPublicKeyInfo.
        len: usize,
        /// Tag van de SubjectPublicKeyInfo.
        tag: u8,
    },
    /// Een pin heeft de verkeerde lengte.
    PeerKeySize(usize),
    /// Ketenverificatie zonder servernaam.
    ServerNameRequired,
    /// Een servernaam past niet in SNI.
    ServerNameTooLong(usize),
    /// Een handshake-bericht is groter dan de grens.
    HandshakeTooLarge(usize),
    /// Een recordtype dat hier niet thuishoort.
    UnexpectedRecord(u8),
    /// Een handshake-bericht van het verkeerde type.
    UnexpectedMessage {
        /// Het verwachte type.
        want: u8,
        /// Het ontvangen type.
        got: u8,
    },
    /// De server vraagt om een clientcertificaat.
    ClientAuthRequested,
    /// De server stuurde een HelloRetryRequest.
    HelloRetryRequest,
    /// De server echode een andere sessie-id.
    SessionIdMismatch,
    /// De server koos een andere suite.
    CipherSuite(u16),
    /// De server koos compressie.
    Compression(u8),
    /// De server koos een andere versie.
    Version(u16),
    /// De ServerHello mist `supported_versions`.
    NotTls13,
    /// De server koos een andere groep.
    Group(u16),
    /// De ServerHello mist een sleuteldeel.
    NoKeyShare,
    /// Het sleuteldeel van de server is ongeldig.
    KeyShare,
    /// De keten bevat een leeg certificaat.
    EmptyCertificate,
    /// De keten is leeg.
    EmptyCertificateList,
    /// De sleutel van de server is niet de pin.
    PinMismatch {
        /// De sleutel uit het certificaat.
        got: [u8; 32],
        /// De pin.
        want: [u8; 32],
    },
    /// De server tekende met een algoritme dat hier niet mag.
    SignatureAlgorithm(u16),
    /// De CertificateVerify-handtekening klopt niet.
    BadSignature,
    /// De ketenverificatie weigerde de peer.
    PeerRejected(&'static str),
    /// De Finished van de server klopt niet.
    FinishedMismatch,
    /// Een record kondigt meer bytes aan dan toegestaan.
    RecordTooLarge(usize),
    /// Een ontsleuteld record is groter dan 2^14.
    RecordOverflow(usize),
    /// Een record ontsleutelde niet.
    Decrypt(u64),
    /// Een versleuteld record zonder inhoudstype.
    NoContentType,
    /// De peer stuurde een alert.
    Alert {
        /// Het niveau.
        level: u8,
        /// De code.
        code: u8,
    },
    /// Een alert van de verkeerde lengte.
    MalformedAlert,
    /// De peer sloot af (`close_notify`) midden in de handshake.
    CloseNotify,
    /// Het transport sloot zonder `close_notify`: de stroom kan afgekapt zijn.
    Eof,
    /// Een eerdere leesfout van het transport maakte de leesrichting onbruikbaar.
    ReadBroken,
    /// Een eerdere schrijffout maakte de schrijfrichting onbruikbaar.
    WriteBroken,
    /// Het transport accepteerde nul bytes.
    WriteZero,
    /// Schrijven na `close_notify`.
    Closed,
    /// Een onverwacht handshake-bericht na de handshake.
    PostHandshake(u8),
    /// Een KeyUpdate met een ongeldige waarde.
    KeyUpdateValue(u8),
    /// Er staat te veel onverzonden in de schrijfbuffer.
    WriteBacklog,
    /// De recordteller is op; de verbinding moet opnieuw.
    SequenceExhausted,
    /// De ketenverificatie van [`crate::ChainVerifier`] weigerde.
    X509(crate::x509::X509Error),
}

/// Een fout van de verbinding: van het transport of van TLS.
#[derive(Debug)]
pub enum ConnError<E> {
    /// Het onderliggende transport faalde.
    Transport(E),
    /// Het TLS-protocol faalde.
    Tls(Error),
}

impl<E> From<Error> for ConnError<E> {
    fn from(e: Error) -> Self {
        ConnError::Tls(e)
    }
}

impl<E> PartialEq<Error> for ConnError<E> {
    fn eq(&self, other: &Error) -> bool {
        matches!(self, ConnError::Tls(e) if e == other)
    }
}

/// Het resultaat van leantls, met [`Error`] als standaardfout.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Schrijft bytes als hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Namen van de gangbare alerts uit RFC 8446 §6; de rest blijft een getal.
pub(crate) fn alert_name(code: u8) -> &'static str {
    match code {
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        109 => "missing_extension",
        112 => "unrecognized_name",
        _ => "unnamed",
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("leantls: ")?;
        match *self {
            Error::Alloc => f.write_str("out of memory"),
            Error::Internal(what) => write!(f, "internal limit: {what}"),
            Error::Truncated => f.write_str("truncated message"),
            Error::Der => f.write_str("malformed certificate (DER)"),
            Error::DerField { index, tag, want } => write!(
                f,
                "malformed certificate (DER): field {index} has tag {tag:#x}, expected {want:#x}"
            ),
            Error::NotEd25519 { len, tag } => write!(
                f,
                "server certificate does not carry an Ed25519 key - this package only speaks \
                 Ed25519 (SubjectPublicKeyInfo is {len} bytes, tag {tag:#x})"
            ),
            Error::PeerKeySize(n) => write!(
                f,
                "Config.PeerKey is {n} bytes, an Ed25519 public key is {}",
                crate::crypto::ed25519::PUBLIC_KEY_LEN
            ),
            Error::ServerNameRequired => f.write_str(
                "Config.ServerName is required with VerifyPeer - a chain that is not checked \
                 against a name proves nothing about who you reached",
            ),
            Error::ServerNameTooLong(n) => {
                write!(
                    f,
                    "server name of {n} bytes does not fit in SNI (limit 255)"
                )
            }
            Error::HandshakeTooLarge(n) => {
                write!(f, "handshake message larger than {n} bytes")
            }
            Error::UnexpectedRecord(t) => write!(f, "unexpected record type {t}"),
            Error::UnexpectedMessage { want, got } => {
                write!(f, "expected handshake type {want}, got {got}")
            }
            Error::ClientAuthRequested => f.write_str(
                "the server asks for a client certificate - this package does not do client \
                 authentication",
            ),
            Error::HelloRetryRequest => f.write_str(
                "the server sent a HelloRetryRequest - it wants a key exchange group other than \
                 X25519, which is the only one this package offers",
            ),
            Error::SessionIdMismatch => f.write_str("the server echoed a different session id"),
            Error::CipherSuite(s) => write!(
                f,
                "the server chose cipher suite {s:#06x}; this package only has \
                 TLS_AES_128_GCM_SHA256 (0x1301)"
            ),
            Error::Compression(c) => write!(
                f,
                "the server selected compression method {c}; TLS 1.3 has none"
            ),
            Error::Version(v) => {
                write!(f, "the server selected version {v:#06x}, not TLS 1.3")
            }
            Error::NotTls13 => f.write_str(
                "the server did not select TLS 1.3 (no supported_versions in ServerHello) - this \
                 package speaks TLS 1.3 only",
            ),
            Error::Group(g) => write!(f, "the server chose group {g:#06x}, not X25519"),
            Error::NoKeyShare => f.write_str("the server sent no key share"),
            Error::KeyShare => f.write_str("server key share: invalid X25519 value"),
            Error::EmptyCertificate => {
                f.write_str("the server sent an empty certificate in its chain")
            }
            Error::EmptyCertificateList => f.write_str("the server sent an empty certificate list"),
            Error::PinMismatch { got, want } => write!(
                f,
                "server key does not match the pin\n got  {}\n want {}",
                Hex(&got),
                Hex(&want)
            ),
            Error::SignatureAlgorithm(a) => write!(
                f,
                "the server signed with algorithm {a:#06x}; a pinned Ed25519 peer must sign \
                 with Ed25519 (0x0807)"
            ),
            Error::BadSignature => {
                f.write_str("the server's CertificateVerify signature is invalid")
            }
            Error::PeerRejected(why) => write!(f, "peer rejected: {why}"),
            Error::FinishedMismatch => f.write_str(
                "server Finished does not verify - the key exchange was tampered with, or we \
                 disagree about the transcript",
            ),
            Error::RecordTooLarge(n) => write!(
                f,
                "record of {n} bytes announced, limit is {}",
                crate::record::MAX_CIPHER
            ),
            Error::RecordOverflow(n) => write!(
                f,
                "decrypted record of {n} bytes, limit is {}",
                crate::record::MAX_PLAIN
            ),
            Error::Decrypt(seq) => write!(f, "record {seq} failed to decrypt"),
            Error::NoContentType => f.write_str("encrypted record carries no content type"),
            Error::Alert { level, code } => write!(
                f,
                "peer sent alert level {level} code {code} ({})",
                alert_name(code)
            ),
            Error::MalformedAlert => f.write_str("malformed alert"),
            Error::CloseNotify => f.write_str("peer closed the connection during the handshake"),
            Error::Eof => {
                f.write_str("transport closed without close_notify - the stream may be truncated")
            }
            Error::ReadBroken => {
                f.write_str("an earlier transport read failed; the connection is unusable")
            }
            Error::WriteBroken => {
                f.write_str("an earlier record write failed; the TLS stream cannot be resumed")
            }
            Error::WriteZero => f.write_str("transport accepted zero bytes"),
            Error::Closed => f.write_str("write after close_notify"),
            Error::PostHandshake(t) => {
                write!(f, "unexpected post-handshake message type {t}")
            }
            Error::KeyUpdateValue(v) => write!(f, "KeyUpdate with invalid request value {v}"),
            Error::WriteBacklog => f.write_str("write buffer full of unsent records"),
            Error::SequenceExhausted => f.write_str("record sequence number exhausted"),
            Error::X509(e) => write!(f, "x509: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl<E: fmt::Display> fmt::Display for ConnError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnError::Transport(e) => write!(f, "leantls: transport: {e}"),
            ConnError::Tls(e) => e.fmt(f),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for ConnError<E> {}
