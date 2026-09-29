//! S3: SigV4-ondertekening plus de object-operaties die echt gebruikt worden.
//!
//! Deze crate bezit de S3-kant van een verzoek: de adressering (virtual-hosted
//! of path-style), de canonieke vorm en de handtekening, en de uitleg van het
//! antwoord (status, ETag, de LIST-XML). Het transport bezit hij niet. Een
//! verzoek gaat de deur uit via [`Transport`], dat de aanroeper implementeert
//! met leanhttp of leanhttps; zo linkt leans3 geen HTTP- en geen TLS-code, en
//! blijft er één eigenaar van de verbinding: de aanroeper.
//!
//! De Go-voorganger verving twee eigen SigV4-implementaties in één stapel
//! (hoplock/s3, ~200 regels, en hop/internal/runner, ~100 regels, alleen GET).
//! De kleinste kopie liet URI-escaping, sessietokens en path-style weg, zodat
//! een sleutel met een spatie of `+` een ongeldige handtekening kreeg. Hier gaat
//! het pad over de draad in precies de vorm die getekend wordt.
//!
//! # Bewuste grenzen
//!
//! Geen streaming-handtekeningen, geen SigV4a, geen presigned URL's, geen
//! IMDS/IAM, geen multipart, geen versies, object lock of tags (KAM.md,
//! TLS/S3). Elke PUT heeft een bekende lengte en payload-hash;
//! [`Client::put_from`] weigert een ontbrekende hash in plaats van stil
//! [`UNSIGNED_PAYLOAD`] te kiezen. Een getekend verzoek volgt nooit een
//! redirect: oorsprong, pad en koppen zitten in de handtekening, en een
//! [`Transport`] dat toch volgt zou een sessietoken bij een andere host
//! afleveren. Eén object is één verzoek; herhalen en orkestratie horen erboven.
//!
//! # Annuleren
//!
//! Een operatie is een future. Wie hem laat vallen, annuleert: voordat hij
//! gepold is gebeurt er niets, en daarna laat hij het lopende verzoek van het
//! transport vallen. De voortgangs-timeout per socket-operatie die de Go-versie
//! om zijn verbindingen legde, hoort nu bij het transport, want dat bezit de
//! socket.

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

mod hmac;
mod listparse;
mod sha256;
mod sigv4;
#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::future::{Future, poll_fn};
use core::pin::Pin;
use core::task::{Context, Poll};

pub use listparse::XmlError;

/// Markeert een payload die buiten de handtekening valt. Alleen voor
/// [`Client::put_from`] over HTTPS met een bron die niet twee keer gelezen kan
/// worden: zonder TLS is de body onderweg te wijzigen, en diverse providers
/// weigeren hem dan voor schrijfacties.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// De grens van [`Client::get`]: 4 MiB. Grotere objecten gaan via
/// [`Client::get_to`].
pub const MAX_BUFFERED_GET: u64 = 4 << 20;

/// Hoeveel van een foutbody bewaard en gelezen wordt. Een verwachte 404 of
/// CAS-race heeft een kleine XML-body; die binnen deze grens uitlezen houdt de
/// verbinding herbruikbaar, een grotere body sluit hem.
const MAX_ERROR_BODY: usize = 4 << 10;

/// Een LIST-pagina heeft hoogstens 1.000 sleutels van hoogstens 1 KiB. Lezen
/// wordt vóór het parsen begrensd, zodat een haperend of vijandig antwoord de
/// heap niet onbegrensd laat groeien.
const MAX_LIST_PAGE: usize = 4 << 20;

/// Brokgrootte voor het stromen van bodies.
const CHUNK: usize = 4 << 10;

/// De resultaat-alias van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// De S3-operatie waar een fout bij hoort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Een GET van een object.
    Get,
    /// Een HEAD van een object.
    Head,
    /// Een PUT van een object.
    Put,
    /// Een DELETE van een object.
    Delete,
    /// Een ListObjectsV2-pagina.
    List,
}

impl Op {
    /// De naam zoals hij in foutmeldingen staat.
    const fn name(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::List => "LIST",
        }
    }
}

/// Waarom een bytestroom stopte, zoals de implementatie van een stroom het
/// vertaalt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    /// De verbinding of stroom is gesloten.
    Closed,
    /// Een deadline verliep.
    TimedOut,
    /// De stroom eindigde voor zijn aangekondigde lengte.
    UnexpectedEof,
    /// Een schrijfactie nam nul bytes aan.
    WriteZero,
    /// Iets anders, met een vaste omschrijving van de implementatie.
    Other(&'static str),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("closed"),
            Self::TimedOut => f.write_str("timed out"),
            Self::UnexpectedEof => f.write_str("unexpected end of stream"),
            Self::WriteZero => f.write_str("write accepted zero bytes"),
            Self::Other(what) => f.write_str(what),
        }
    }
}

/// Een onsuccesvol antwoord dat geen verwachte uitkomst is. De body houdt een
/// begrensd begin vast, want S3 meldt oorzaken als SignatureDoesNotMatch en
/// AccessDenied in XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusError {
    /// De operatie.
    pub op: Op,
    /// De sleutel of het voorvoegsel.
    pub key: String,
    /// De statuscode, zoals 403.
    pub code: u16,
    /// De reden-tekst, zoals "Forbidden".
    pub reason: String,
    /// Het getrimde begin van de body, hoogstens 4 KiB.
    pub body: Vec<u8>,
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "leans3: {} {}: status {} {}: ",
            self.op.name(),
            self.key,
            self.code,
            self.reason
        )?;
        for chunk in self.body.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{fffd}")?;
            }
        }
        Ok(())
    }
}

/// Alles wat een operatie kan laten mislukken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Een 404: de sleutel bestaat niet.
    NotFound,
    /// Een 412, of de 409 die sommige providers geven bij een If-None-Match-race.
    /// Er is niets geschreven.
    PreconditionFailed,
    /// [`Client::get`] passeerde zijn grens van [`MAX_BUFFERED_GET`].
    ObjectTooLarge {
        /// De aangekondigde lengte, als die er was.
        length: Option<u64>,
    },
    /// Elk ander onsuccesvol antwoord.
    Status(StatusError),
    /// `Client::endpoint` is leeg.
    EndpointRequired,
    /// `Client::bucket` is leeg.
    BucketRequired,
    /// De sleutel is leeg.
    KeyRequired,
    /// Het endpoint heeft geen schema of geen host.
    EndpointIncomplete,
    /// Het endpoint-schema is geen http of https.
    EndpointScheme,
    /// Er is geen klok ingesteld om mee te tekenen.
    ClockRequired,
    /// [`Client::list`] kreeg een cap van nul.
    ListMaxZero,
    /// [`Client::put_from`] kreeg geen payload-hash.
    PayloadHashRequired,
    /// [`UNSIGNED_PAYLOAD`] over een http-endpoint.
    UnsignedOverHttp,
    /// Een HEAD-antwoord zonder ETag.
    MissingEtag,
    /// Het transport faalde.
    Transport {
        /// De operatie.
        op: Op,
        /// De oorzaak.
        source: IoError,
    },
    /// De schrijver van [`Client::get_to`] faalde; lokaal, niet onderweg.
    Sink {
        /// Hoeveel bytes de schrijver al had aangenomen.
        written: u64,
        /// De oorzaak.
        source: IoError,
    },
    /// Een LIST-pagina groter dan 4 MiB.
    ListPageTooLarge,
    /// Een afgekapte LIST-pagina zonder vervolgtoken.
    ListMissingToken,
    /// Een afgekapte LIST-pagina zonder één sleutel.
    ListNoProgress,
    /// Een vervolgtoken dat gelijk bleef.
    ListTokenStuck,
    /// De LIST-XML was onleesbaar.
    Xml(XmlError),
    /// De heap weigerde.
    OutOfMemory,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("leans3: no such key"),
            Self::PreconditionFailed => f.write_str("leans3: precondition failed"),
            Self::ObjectTooLarge { length: Some(n) } => write!(
                f,
                "leans3: object exceeds buffered GET limit: {n} bytes; limit is {MAX_BUFFERED_GET}"
            ),
            Self::ObjectTooLarge { length: None } => write!(
                f,
                "leans3: object exceeds buffered GET limit of {MAX_BUFFERED_GET} bytes"
            ),
            Self::Status(e) => e.fmt(f),
            Self::EndpointRequired => f.write_str("leans3: Endpoint is required"),
            Self::BucketRequired => f.write_str("leans3: Bucket is required"),
            Self::KeyRequired => f.write_str("leans3: key is required"),
            Self::EndpointIncomplete => {
                f.write_str("leans3: Endpoint must include scheme and host")
            }
            Self::EndpointScheme => f.write_str("leans3: Endpoint scheme must be http or https"),
            Self::ClockRequired => f.write_str("leans3: no clock to sign with (Client::now)"),
            Self::ListMaxZero => f.write_str("leans3: List max must be positive"),
            Self::PayloadHashRequired => f.write_str(
                "leans3: put_from needs the payload's sha256 (it cannot be computed without \
                 buffering the object); pass UNSIGNED_PAYLOAD if the source cannot be read twice",
            ),
            Self::UnsignedOverHttp => f.write_str(
                "leans3: UNSIGNED_PAYLOAD over a plain-http endpoint would be silently \
                 modifiable in transit; use https, or pass the payload's sha256",
            ),
            Self::MissingEtag => f.write_str("leans3: HEAD: response has no ETag"),
            Self::Transport { op, source } => write!(f, "leans3: {}: {source}", op.name()),
            Self::Sink { written, source } => {
                write!(f, "leans3: stream GET body after {written} bytes: {source}")
            }
            Self::ListPageTooLarge => {
                write!(f, "leans3: LIST response exceeds {MAX_LIST_PAGE} bytes")
            }
            Self::ListMissingToken => {
                f.write_str("leans3: LIST: truncated page without a continuation token")
            }
            Self::ListNoProgress => {
                f.write_str("leans3: LIST: truncated page made no key progress")
            }
            Self::ListTokenStuck => f.write_str("leans3: LIST: continuation token did not advance"),
            Self::Xml(e) => write!(f, "leans3: parse LIST response: {e}"),
            Self::OutOfMemory => f.write_str("leans3: out of memory"),
        }
    }
}

/// Een leesbare bytestroom, poll-gebaseerd zoals leanhttp: `Ok(0)` is het
/// einde.
pub trait AsyncRead {
    /// Leest in `buf` en geeft het aantal bytes, of `Pending` met een wekker.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>>;
}

/// Een schrijfbare bytestroom, poll-gebaseerd zoals leanhttp.
pub trait AsyncWrite {
    /// Schrijft uit `buf` en geeft het aantal aangenomen bytes.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>>;
}

/// Eén kop van een uitgaand verzoek. De namen zijn vaste teksten; Host,
/// Content-Length en Connection staan er nooit in, want die bezit het
/// transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// De naam, zoals `X-Amz-Date`.
    pub name: &'static str,
    /// De waarde.
    pub value: String,
}

/// De body van een uitgaand verzoek.
pub enum Body<'a> {
    /// Geen body: geen Content-Length (GET, HEAD, DELETE, LIST).
    None,
    /// Een body in het geheugen; een lege slice betekent `Content-Length: 0`,
    /// wat S3 voor een lege PUT eist.
    Bytes(&'a [u8]),
    /// Precies `len` bytes uit een stroom. De stroom levert een
    /// [`IoError::UnexpectedEof`] als hij eerder op is, en nooit meer dan `len`.
    Stream {
        /// De bron.
        source: &'a mut (dyn AsyncRead + Unpin),
        /// De exacte lengte, voor Content-Length.
        len: u64,
    },
}

/// Eén ondertekend verzoek, klaar voor de draad. `'b` is de levensduur van de
/// body, los van de rest: een stroom leent de bron van de aanroeper.
pub struct Request<'a, 'b> {
    /// De methode: GET, HEAD, PUT of DELETE.
    pub method: &'static str,
    /// Of het endpoint https is.
    pub https: bool,
    /// De host (met eventuele poort) voor verbinding, SNI en de Host-kop.
    pub host: &'a str,
    /// Het request-target: geëscapet pad plus query, precies zoals getekend.
    pub target: &'a str,
    /// De koppen, inclusief Authorization.
    pub headers: &'a [Header],
    /// De body.
    pub body: Body<'b>,
}

/// Het antwoord van een [`Transport`]: status, koppen en de body als stroom.
///
/// Een bodyloos antwoord (HEAD, 204, 304) meldt meteen het einde.
pub trait Response: AsyncRead + Unpin {
    /// De statuscode.
    fn status(&self) -> u16;
    /// De reden-tekst, zoals "Forbidden"; mag leeg zijn.
    fn reason(&self) -> &str;
    /// De eerste waarde van een kop, hoofdletterongevoelig.
    fn header(&self, name: &str) -> Option<&str>;
    /// De aangekondigde bodylengte, als die bekend is.
    fn content_length(&self) -> Option<u64>;
}

/// De deur naar buiten: verstuurt één verzoek en geeft het antwoord.
///
/// De aanroeper implementeert dit met leanhttp of leanhttps en bezit daarmee
/// de verbindingen, de pool en de deadlines. Twee plichten horen erbij: volg
/// **nooit** een redirect (de handtekening dekt host en pad, en de koppen
/// kunnen een sessietoken dragen), en behandel een afgekapte body als fout.
pub trait Transport {
    /// Het antwoordtype.
    type Response: Response;

    /// Verstuurt `request`. Een 3xx komt als gewoon antwoord terug.
    fn send(
        &mut self,
        request: Request<'_, '_>,
    ) -> impl Future<Output = Result<Self::Response, IoError>>;
}

/// Voorwaarden en metadata van één PUT. De standaard is een onvoorwaardelijke
/// `application/octet-stream`. `if_match` en `if_none_match` zijn ruwe
/// kopwaarden, omdat providers het oneens zijn over geciteerde ETags.
#[derive(Debug, Clone, Copy, Default)]
pub struct PutOptions<'a> {
    /// Het inhoudstype; leeg is `application/octet-stream`.
    pub content_type: &'a str,
    /// Schrijf alleen als de opgeslagen ETag overeenkomt.
    pub if_match: &'a str,
    /// Schrijf alleen als hij niet overeenkomt; `"*"` maakt alleen aan als het
    /// object nog niet bestaat, voor CAS-protocollen.
    pub if_none_match: &'a str,
}

/// De voorwaarde van één DELETE. De standaard is onvoorwaardelijk.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeleteOptions<'a> {
    /// Verwijder alleen als de opgeslagen ETag overeenkomt.
    pub if_match: &'a str,
}

/// Een verzoek-URL in de adresseringsvorm van de [`Client`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Of het schema https is.
    https: bool,
    /// De host, bij virtual-hosted met de bucket ervoor.
    host: String,
    /// Het ongeëscapete pad.
    path: String,
    /// De query, al in canonieke SigV4-vorm.
    query: String,
}

impl Url {
    /// Of het schema https is.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// De host (met eventuele poort).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Het ongeëscapete pad.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Het request-target voor de draad: pad en query in precies de vorm die
    /// getekend wordt.
    pub fn target(&self) -> Result<String> {
        let mut t = sigv4::canonical_uri(&self.path)?;
        if !self.query.is_empty() {
            push_str(&mut t, "?")?;
            push_str(&mut t, &self.query)?;
        }
        Ok(t)
    }
}

/// Toegang tot één bucket op één endpoint.
///
/// Dit is alleen configuratie; de verbinding komt per operatie binnen als
/// [`Transport`]. Zo is er één eigenaar van de verbinding, en kan een `Client`
/// gewoon gekopieerd of gedeeld worden.
#[derive(Clone, Default)]
pub struct Client {
    /// De basis-URL van de dienst, zoals `https://s3.us-east-1.amazonaws.com`
    /// of `https://<account>.r2.cloudflarestorage.com`. Verplicht.
    pub endpoint: String,
    /// De bucketnaam. Verplicht.
    pub bucket: String,
    /// De regio van de credential-scope; "auto" voor R2. Verplicht.
    pub region: String,
    /// De sleutel-id. Verplicht.
    pub access_key_id: String,
    /// Het geheim. Verplicht.
    pub secret_access_key: String,
    /// Het STS-sessietoken; gaat als X-Amz-Security-Token mee als het gezet is.
    pub session_token: String,
    /// Zet de bucket in het pad in plaats van de hostnaam. MinIO en de meeste
    /// niet-AWS-providers eisen dit; R2 kan beide.
    pub path_style: bool,
    /// De klok om mee te tekenen, in Unix-seconden. Zonder klok faalt elke
    /// operatie luid: een handtekening met een verzonnen tijd weigert S3 toch.
    pub now: Option<fn() -> u64>,
}

/// Laat het geheim en het sessietoken weg: een `Client` in een logregel mag
/// geen sleutel lekken.
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("path_style", &self.path_style)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Geeft de URL voor `key` in de adresseringsvorm van deze client, voor
    /// eigen operaties zonder de host- of padlogica te dupliceren.
    pub fn url_for(&self, key: &str) -> Result<Url> {
        if key.is_empty() {
            return Err(Error::KeyRequired);
        }
        let mut u = self.bucket_url()?;
        push_str(&mut u.path, key.strip_prefix('/').unwrap_or(key))?;
        Ok(u)
    }

    /// De bucket-URL met afsluitende slash en zonder sleutel.
    fn bucket_url(&self) -> Result<Url> {
        if self.endpoint.is_empty() {
            return Err(Error::EndpointRequired);
        }
        if self.bucket.is_empty() {
            return Err(Error::BucketRequired);
        }
        let (https, host) = parse_endpoint(&self.endpoint)?;
        let mut u = Url {
            https,
            host: String::new(),
            path: String::new(),
            query: String::new(),
        };
        if self.path_style {
            push_str(&mut u.host, host)?;
            for part in ["/", &self.bucket, "/"] {
                push_str(&mut u.path, part)?;
            }
        } else {
            for part in [&self.bucket, ".", host] {
                push_str(&mut u.host, part)?;
            }
            push_str(&mut u.path, "/")?;
        }
        Ok(u)
    }

    /// Geeft de bytes en ETag van een object, of [`Error::NotFound`]. Buffert
    /// hoogstens [`MAX_BUFFERED_GET`]; grotere objecten gaan via
    /// [`Client::get_to`].
    pub async fn get<T: Transport>(
        &self,
        t: &mut T,
        key: &str,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let url = self.url_for(key)?;
        let mut resp = self
            .send(
                t,
                Op::Get,
                "GET",
                &url,
                Vec::new(),
                Body::None,
                sigv4::EMPTY_PAYLOAD_HASH,
            )
            .await?;
        if resp.status() != 200 {
            return Err(fail(Op::Get, key, resp).await);
        }
        let length = resp.content_length();
        if length.is_some_and(|n| n > MAX_BUFFERED_GET) {
            return Err(Error::ObjectTooLarge { length });
        }
        let etag = etag(&resp)?;
        // Eén byte boven de grens lezen bewijst de overschrijding ook zonder
        // aangekondigde lengte (chunked).
        let limit = usize::try_from(MAX_BUFFERED_GET).unwrap_or(usize::MAX);
        let data = read_bounded(&mut resp, limit + 1)
            .await
            .map_err(|source| Error::Transport {
                op: Op::Get,
                source,
            })?;
        if data.len() > limit {
            return Err(Error::ObjectTooLarge { length: None });
        }
        check_length(length, data.len() as u64, Op::Get)?;
        Ok((data, etag))
    }

    /// Geeft de ETag van een object zonder body, of [`Error::NotFound`].
    ///
    /// Dit is de tweede mening voor een opslag die GET en HEAD verschillend
    /// beantwoordt: een half verwijderd object op een gerepliceerde opslag
    /// (gezien op Bunny Storage, 08-09-2026) is 404 op GET maar 200 met ETag op
    /// HEAD en in listings, en juist die ETag heeft een voorwaardelijke PUT
    /// nodig om erlangs te komen.
    pub async fn head<T: Transport>(&self, t: &mut T, key: &str) -> Result<String> {
        let url = self.url_for(key)?;
        let resp = self
            .send(
                t,
                Op::Head,
                "HEAD",
                &url,
                Vec::new(),
                Body::None,
                sigv4::EMPTY_PAYLOAD_HASH,
            )
            .await?;
        if resp.status() != 200 {
            return Err(fail(Op::Head, key, resp).await);
        }
        etag(&resp)?.ok_or(Error::MissingEtag)
    }

    /// Stroomt een object naar `sink` en geeft het aantal bytes en de ETag. Een
    /// afwezige sleutel geeft [`Error::NotFound`] voordat er iets geschreven is.
    /// Een fout van de schrijver is [`Error::Sink`], zodat een aanroeper een
    /// lokale opslagfout van een transportfout kan onderscheiden.
    pub async fn get_to<T: Transport, W: AsyncWrite + Unpin + ?Sized>(
        &self,
        t: &mut T,
        key: &str,
        sink: &mut W,
    ) -> Result<(u64, Option<String>)> {
        let url = self.url_for(key)?;
        let mut resp = self
            .send(
                t,
                Op::Get,
                "GET",
                &url,
                Vec::new(),
                Body::None,
                sigv4::EMPTY_PAYLOAD_HASH,
            )
            .await?;
        if resp.status() != 200 {
            return Err(fail(Op::Get, key, resp).await);
        }
        let etag = etag(&resp)?;
        let length = resp.content_length();
        let mut buf = [0u8; CHUNK];
        let mut written = 0u64;
        loop {
            let n = read(&mut resp, &mut buf)
                .await
                .map_err(|source| Error::Transport {
                    op: Op::Get,
                    source,
                })?;
            let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
                break;
            };
            write_all(sink, chunk, &mut written).await?;
        }
        check_length(length, written, Op::Get)?;
        Ok((written, etag))
    }

    /// Schrijft `data` naar `key` en geeft de ETag van de server, als die er
    /// is. De payload-hash wordt zonder extra kopie berekend. Een mislukte
    /// voorwaarde is [`Error::PreconditionFailed`] en heeft niets geschreven.
    pub async fn put<T: Transport>(
        &self,
        t: &mut T,
        key: &str,
        data: &[u8],
        opt: &PutOptions<'_>,
    ) -> Result<Option<String>> {
        let url = self.url_for(key)?;
        let hash = sigv4::hex_sha256(data);
        let headers = put_headers(opt)?;
        // Een lege slice wordt Content-Length: 0, wat S3 voor een lege PUT eist.
        let resp = self
            .send(
                t,
                Op::Put,
                "PUT",
                &url,
                headers,
                Body::Bytes(data),
                sigv4::hex_str(&hash),
            )
            .await?;
        finish_write(Op::Put, key, resp).await
    }

    /// Stroomt precies `size` bytes uit `source` naar `key` en geeft de ETag,
    /// zonder de payload te bufferen.
    ///
    /// `payload_sha256` is de hash in kleine letters die de eigenaar van de bron
    /// levert; [`UNSIGNED_PAYLOAD`] alleen voor een bron die niet twee keer
    /// gelezen kan worden, en alleen over https. Een lege hash wordt geweigerd in
    /// plaats van de integriteit stil te verzwakken. Een te korte bron faalt
    /// hier; een inhoud die niet bij de hash past faalt bij S3 als BadDigest.
    pub async fn put_from<T: Transport>(
        &self,
        t: &mut T,
        key: &str,
        source: &mut (dyn AsyncRead + Unpin),
        size: u64,
        payload_sha256: &str,
        opt: &PutOptions<'_>,
    ) -> Result<Option<String>> {
        if payload_sha256.is_empty() {
            return Err(Error::PayloadHashRequired);
        }
        let https = self
            .endpoint
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
        if payload_sha256 == UNSIGNED_PAYLOAD && !https {
            // Een ongetekende, onversleutelde payload is onderweg stil te wijzigen.
            return Err(Error::UnsignedOverHttp);
        }
        let url = self.url_for(key)?;
        let headers = put_headers(opt)?;
        let resp = if size == 0 {
            // Nul bytes nemen het gewone Content-Length: 0-pad, zonder een
            // overbodige Expect-uitwisseling. S3 toetst de hash alsnog.
            self.send(
                t,
                Op::Put,
                "PUT",
                &url,
                headers,
                Body::Bytes(&[]),
                payload_sha256,
            )
            .await?
        } else {
            // Een bekende lengte; zonder die eist S3 chunking plus een
            // streaming-handtekening, beide buiten de scope.
            let mut exact = Exact {
                inner: source,
                left: size,
            };
            let body = Body::Stream {
                source: &mut exact,
                len: size,
            };
            self.send(t, Op::Put, "PUT", &url, headers, body, payload_sha256)
                .await?
        };
        finish_write(Op::Put, key, resp).await
    }

    /// Verwijdert `key`. Een ontbrekend object is [`Error::NotFound`], dat een
    /// idempotente aanroeper mag negeren; een mislukte `if_match` is
    /// [`Error::PreconditionFailed`].
    pub async fn delete<T: Transport>(
        &self,
        t: &mut T,
        key: &str,
        opt: &DeleteOptions<'_>,
    ) -> Result {
        let url = self.url_for(key)?;
        let mut headers = Vec::new();
        if !opt.if_match.is_empty() {
            sigv4::set_header(&mut headers, "If-Match", opt.if_match)?;
        }
        let resp = self
            .send(
                t,
                Op::Delete,
                "DELETE",
                &url,
                headers,
                Body::None,
                sigv4::EMPTY_PAYLOAD_HASH,
            )
            .await?;
        match resp.status() {
            200 | 204 => {
                drain(resp).await;
                Ok(())
            }
            _ => Err(fail(Op::Delete, key, resp).await),
        }
    }

    /// Geeft de sleutels met `prefix` in de lexicale volgorde van S3 en volgt
    /// de paginering. `max` begrenst het resultaat en moet positief zijn; de
    /// vlag is waar als de cap bereikt werd terwijl er meer was. Groottes en
    /// datums vallen weg, want de huidige gebruikers hebben alleen een
    /// sleutelkaart nodig.
    pub async fn list<T: Transport>(
        &self,
        t: &mut T,
        prefix: &str,
        max: usize,
    ) -> Result<(Vec<String>, bool)> {
        if max == 0 {
            return Err(Error::ListMaxZero);
        }
        let mut keys: Vec<String> = Vec::new();
        let mut token = String::new();
        loop {
            let page = self.list_page(t, prefix, &token).await?;
            let progressed = !page.keys.is_empty();
            for key in page.keys {
                if keys.len() >= max {
                    return Ok((keys, true));
                }
                keys.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
                keys.push(key);
            }
            if keys.len() == max && page.is_truncated {
                return Ok((keys, true));
            }
            if !page.is_truncated {
                return Ok((keys, false));
            }
            if page.next_token.is_empty() {
                return Err(Error::ListMissingToken);
            }
            if !progressed {
                return Err(Error::ListNoProgress);
            }
            if page.next_token == token {
                return Err(Error::ListTokenStuck);
            }
            token = page.next_token;
        }
    }

    /// Haalt één ListObjectsV2-pagina op.
    async fn list_page<T: Transport>(
        &self,
        t: &mut T,
        prefix: &str,
        token: &str,
    ) -> Result<listparse::ListPage> {
        let mut url = self.bucket_url()?;
        // De query staat meteen in canonieke vorm, gesorteerd op sleutel; dan
        // is wat over de draad gaat gelijk aan wat getekend wordt.
        if !token.is_empty() {
            push_str(&mut url.query, "continuation-token=")?;
            sigv4::uri_escape(&mut url.query, token.as_bytes(), true)?;
            push_str(&mut url.query, "&")?;
        }
        push_str(&mut url.query, "list-type=2")?;
        if !prefix.is_empty() {
            push_str(&mut url.query, "&prefix=")?;
            sigv4::uri_escape(&mut url.query, prefix.as_bytes(), true)?;
        }
        let mut resp = self
            .send(
                t,
                Op::List,
                "GET",
                &url,
                Vec::new(),
                Body::None,
                sigv4::EMPTY_PAYLOAD_HASH,
            )
            .await?;
        if resp.status() != 200 {
            return Err(fail(Op::List, prefix, resp).await);
        }
        let length = resp.content_length();
        let body = read_bounded(&mut resp, MAX_LIST_PAGE + 1)
            .await
            .map_err(|source| Error::Transport {
                op: Op::List,
                source,
            })?;
        if body.len() > MAX_LIST_PAGE {
            return Err(Error::ListPageTooLarge);
        }
        check_length(length, body.len() as u64, Op::List)?;
        listparse::parse_list_page(&body).map_err(Error::Xml)
    }

    /// Tekent en verstuurt één verzoek.
    #[expect(
        clippy::too_many_arguments,
        reason = "één plek die alle delen samenbrengt"
    )]
    async fn send<T: Transport>(
        &self,
        t: &mut T,
        op: Op,
        method: &'static str,
        url: &Url,
        mut headers: Vec<Header>,
        body: Body<'_>,
        payload_hash: &str,
    ) -> Result<T::Response> {
        let now = self.now.ok_or(Error::ClockRequired)?;
        sigv4::sign_request(
            method,
            url,
            &mut headers,
            &sigv4::Credentials {
                access_key_id: &self.access_key_id,
                secret_access_key: &self.secret_access_key,
                session_token: &self.session_token,
                region: &self.region,
            },
            payload_hash,
            now(),
        )?;
        let target = url.target()?;
        t.send(Request {
            method,
            https: url.https,
            host: &url.host,
            target: &target,
            headers: &headers,
            body,
        })
        .await
        .map_err(|source| Error::Transport { op, source })
    }
}

/// Splitst een endpoint in schema en host; een eventueel pad valt weg, want de
/// adresseringsvorm bepaalt het pad.
fn parse_endpoint(endpoint: &str) -> Result<(bool, &str)> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or(Error::EndpointIncomplete)?;
    let https = if scheme.eq_ignore_ascii_case("https") {
        true
    } else if scheme.eq_ignore_ascii_case("http") {
        false
    } else if scheme.is_empty() {
        return Err(Error::EndpointIncomplete);
    } else {
        return Err(Error::EndpointScheme);
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return Err(Error::EndpointIncomplete);
    }
    Ok((https, host))
}

/// De koppen van een PUT: inhoudstype en voorwaarden. Content-Length bezit het
/// transport, en de handtekening laat hem bewust weg.
fn put_headers(opt: &PutOptions<'_>) -> Result<Vec<Header>> {
    let mut headers = Vec::new();
    if !opt.if_match.is_empty() {
        sigv4::set_header(&mut headers, "If-Match", opt.if_match)?;
    }
    if !opt.if_none_match.is_empty() {
        sigv4::set_header(&mut headers, "If-None-Match", opt.if_none_match)?;
    }
    let content_type = if opt.content_type.is_empty() {
        "application/octet-stream"
    } else {
        opt.content_type
    };
    sigv4::set_header(&mut headers, "Content-Type", content_type)?;
    Ok(headers)
}

/// Rondt een PUT af: bij succes de body uitlezen, zodat het transport de
/// verbinding kan hergebruiken, en de ETag teruggeven.
async fn finish_write<R: Response>(op: Op, key: &str, resp: R) -> Result<Option<String>> {
    match resp.status() {
        200 | 201 | 204 => {
            let tag = etag(&resp)?;
            drain(resp).await;
            Ok(tag)
        }
        _ => Err(fail(op, key, resp).await),
    }
}

/// Vertaalt een onsuccesvol antwoord naar zijn fout en leest de body daarbij
/// begrensd. Verwachte missers en CAS-races zijn gewoon; hun kleine body binnen
/// de grens uitlezen houdt de TLS-verbinding herbruikbaar.
async fn fail<R: Response>(op: Op, key: &str, mut resp: R) -> Error {
    let code = resp.status();
    if matches!(code, 404 | 409 | 412) {
        let _ = read_bounded(&mut resp, MAX_ERROR_BODY).await;
        return if code == 404 {
            Error::NotFound
        } else {
            Error::PreconditionFailed
        };
    }
    let body = read_bounded(&mut resp, MAX_ERROR_BODY)
        .await
        .unwrap_or_default();
    let trimmed = body.trim_ascii();
    let mut status = StatusError {
        op,
        key: String::new(),
        code,
        reason: String::new(),
        body: Vec::new(),
    };
    let copied = push_str(&mut status.key, key)
        .and_then(|()| push_str(&mut status.reason, resp.reason()))
        .and_then(|()| {
            status
                .body
                .try_reserve(trimmed.len())
                .map_err(|_| Error::OutOfMemory)
        });
    if let Err(e) = copied {
        return e;
    }
    status.body.extend_from_slice(trimmed);
    Error::Status(status)
}

/// Leest een succesvolle body tot het einde en gooit hem weg. HEAD, 204 en 304
/// zijn bewezen bodyloos en worden niet gelezen: wachten op het einde daarvan
/// zou een DELETE tot de idle-timeout van de server laten hangen.
async fn drain<R: Response>(mut resp: R) {
    if matches!(resp.status(), 204 | 304) {
        return;
    }
    let mut buf = [0u8; CHUNK];
    while let Ok(n) = read(&mut resp, &mut buf).await {
        if n == 0 {
            break;
        }
    }
}

/// De ETag van een antwoord, als die er is.
fn etag<R: Response>(resp: &R) -> Result<Option<String>> {
    match resp.header("ETag") {
        Some(v) => {
            let mut s = String::new();
            push_str(&mut s, v)?;
            Ok(Some(s))
        }
        None => Ok(None),
    }
}

/// Een body die eindigt voor zijn aangekondigde lengte is een fout, nooit een
/// kleiner object.
fn check_length(announced: Option<u64>, got: u64, op: Op) -> Result {
    match announced {
        Some(n) if got < n => Err(Error::Transport {
            op,
            source: IoError::UnexpectedEof,
        }),
        _ => Ok(()),
    }
}

/// Leest tot het einde of tot `limit` bytes, faalbaar gealloceerd.
async fn read_bounded<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    limit: usize,
) -> Result<Vec<u8>, IoError> {
    let mut out: Vec<u8> = Vec::new();
    while out.len() < limit {
        let want = CHUNK.min(limit - out.len());
        out.try_reserve(want)
            .map_err(|_| IoError::Other("out of memory"))?;
        let start = out.len();
        out.resize(start + want, 0);
        let n = read(r, out.get_mut(start..).unwrap_or(&mut [])).await;
        let n = match n {
            Ok(n) => n,
            Err(e) => {
                out.truncate(start);
                return Err(e);
            }
        };
        out.truncate(start + n);
        if n == 0 {
            break;
        }
    }
    Ok(out)
}

/// Eén leesactie als future.
fn read<'a, R: AsyncRead + Unpin + ?Sized>(
    r: &'a mut R,
    buf: &'a mut [u8],
) -> impl Future<Output = Result<usize, IoError>> + 'a {
    poll_fn(move |cx| Pin::new(&mut *r).poll_read(cx, buf))
}

/// Schrijft alles naar `sink` en telt wat aangenomen is.
async fn write_all<W: AsyncWrite + Unpin + ?Sized>(
    sink: &mut W,
    mut data: &[u8],
    written: &mut u64,
) -> Result {
    while !data.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *sink).poll_write(cx, data))
            .await
            .map_err(|source| Error::Sink {
                written: *written,
                source,
            })?;
        if n == 0 {
            return Err(Error::Sink {
                written: *written,
                source: IoError::WriteZero,
            });
        }
        *written += n as u64;
        data = data.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

/// Geeft precies `left` bytes uit `inner` door: nooit meer, en een bron die
/// eerder op is wordt [`IoError::UnexpectedEof`]. Zo kan geen transport een
/// afgekapte upload als volledig versturen.
struct Exact<'a> {
    /// De bron van de aanroeper.
    inner: &'a mut (dyn AsyncRead + Unpin),
    /// Hoeveel bytes er nog moeten komen.
    left: u64,
}

impl AsyncRead for Exact<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        if self.left == 0 || buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let cap = usize::try_from(self.left)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let dst = buf.get_mut(..cap).unwrap_or(&mut []);
        match Pin::new(&mut *self.inner).poll_read(cx, dst) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(IoError::UnexpectedEof)),
            Poll::Ready(Ok(n)) => {
                self.left -= n.min(cap) as u64;
                Poll::Ready(Ok(n.min(cap)))
            }
            other => other,
        }
    }
}

/// Voegt tekst toe, faalbaar gealloceerd.
pub(crate) fn push_str(dst: &mut String, s: &str) -> Result {
    dst.try_reserve(s.len()).map_err(|_| Error::OutOfMemory)?;
    dst.push_str(s);
    Ok(())
}
