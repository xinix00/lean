//! De client: een verzoek schrijven, het antwoord framen, redirects volgen.
//!
//! [`send`] doet één hop op een verbinding die de aanroeper geeft. [`fetch`]
//! en [`get`] volgen redirects met een [`Dial`] en een verse verbinding per hop
//! (`Connection: close`); [`Client`](crate::Client) is de keep-alive-vorm met
//! een [`Pool`](crate::Pool).
//!
//! Een totaaltermijn (Go's `Call.Timeout` en `Context`) bestaat hier niet als
//! veld: de aanroeper legt een `select` met zijn eigen timer rond de future,
//! en een future die valt, sluit de verbinding die hij bezit. Alleen de
//! fasetermijnen die een verbinding moet dragen, gaan naar de verbinding:
//! `header_timeout` en het `Expect`-oordeel.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::future::Future;
use core::time::Duration;

use crate::error::{Error, Result};
use crate::header::{
    Header, body_allowed, connection_has, parse_decimal, try_string, valid_field_value, valid_token,
};
use crate::io::{
    AsyncRead, Conn, FmtBuf, IoError, ReadBuf, close, eof_is_unexpected, flush, next_chunk, read,
    try_extend, write_all,
};
use crate::pool::Pool;
use crate::url::{Url, resolve, same_origin};
use crate::{BUF_SIZE, EXPECT_TIMEOUT, MAX_HEADER_BYTES, MAX_REDIRECTS};

/// Waar een [`Dial`] heen moet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target<'a> {
    /// `https://`: de verbinding moet versleuteld zijn.
    pub https: bool,
    /// De hostnaam uit de URL, zonder poort en haken; voor SNI.
    pub host: &'a str,
    /// De poort, met de standaard van het schema ingevuld.
    pub port: u16,
}

/// Maakt verbindingen voor de client: een netstack, een TLS-compositie, een
/// testdubbel.
///
/// De hostnaam verandert per redirect; de dialer ziet elke hop.
pub trait Dial {
    /// De verbinding die hij geeft.
    type Conn: Conn;

    /// Opent een verbinding naar `target`.
    fn dial(&mut self, target: Target<'_>) -> impl Future<Output = Result<Self::Conn>>;

    /// Zegt of deze dialer versleutelt; alleen dan mag `https://`.
    ///
    /// De standaard is `false`: een kale netstack stuurt nooit plaintext naar
    /// poort 443, ook niet na een redirect van http naar https.
    fn is_encrypted(&self) -> bool {
        false
    }
}

/// Eén uitgaand verzoek.
///
/// De crate bezit `Host`, `Content-Length`, `Connection`, `Expect` en de
/// standaard `Accept-Encoding: identity`; die zet de aanroeper niet.
#[derive(Default)]
pub struct Call<'a> {
    /// Leeg betekent GET.
    pub method: &'a str,
    /// `http://...`, of `https://...` met een versleutelende [`Dial`].
    pub url: &'a str,
    /// Extra requestheaders.
    ///
    /// `Accept-Encoding` is de uitzondering op "van de crate": wie hem zet,
    /// leest [`Response::encoding`] en decomprimeert zelf.
    pub header: Header,
    /// Een kleine body; `None` betekent geen body.
    pub body: Option<&'a [u8]>,
    /// Een gestroomde body van precies `body_len` bytes, in plaats van `body`.
    ///
    /// Er is geen request-chunking, dus de lengte is verplicht. Een stroom is
    /// niet opnieuw af te spelen: er gaat eerst `Expect: 100-continue`, een
    /// vroege weigering spaart de upload, stilte is een fout, en een redirect
    /// komt terug bij de aanroeper.
    pub body_reader: Option<&'a mut dyn AsyncRead>,
    /// De lengte van `body_reader`.
    pub body_len: u64,
    /// Grens voor het wachten op de antwoordkop, niet voor de body: een grote
    /// download blijft onbegrensd, een zwijgende server niet.
    pub header_timeout: Option<Duration>,
    /// Geeft een 3xx aan de aanroeper in plaats van hem te volgen; nodig voor
    /// wie cookies per hop bijhoudt.
    pub no_follow: bool,
}

impl Call<'_> {
    fn method(&self) -> &str {
        if self.method.is_empty() {
            "GET"
        } else {
            self.method
        }
    }

    /// GET en HEAD zonder gestroomde body zijn opnieuw af te spelen.
    fn is_replay_safe(&self) -> bool {
        self.body_reader.is_none() && matches!(self.method, "" | "GET" | "HEAD")
    }
}

/// Hoe de body van een antwoord eindigt.
#[derive(Clone, Copy, Debug)]
enum Framing {
    /// Bewezen leeg: HEAD, 204, 205, 304.
    Empty,
    /// Nog zoveel bytes.
    Length(u64),
    /// Chunked: nog zoveel bytes in de huidige chunk.
    Chunked { left: u64, finished: bool },
    /// Tot de verbinding sluit; nooit herbruikbaar.
    Eof,
}

/// Een antwoord, met de verbinding waar de body nog op staat.
///
/// Lees de body met [`Response::read`] en geef de verbinding terug met
/// [`Response::release`]: alleen een bewezen volledig gelezen antwoord levert
/// een herbruikbare verbinding op.
pub struct Response<C> {
    /// De status, 100 tot en met 599 (1xx komt hier nooit).
    pub status: u16,
    /// De redentekst na de code, zoals de server hem stuurde.
    pub reason: String,
    /// De headers, zonder `Set-Cookie`.
    pub header: Header,
    /// `Content-Length`, of `None` voor chunked en EOF-begrensd.
    ///
    /// Op HEAD en 304 is een geadverteerde lengte informatief.
    pub length: Option<u64>,
    /// De URL van deze hop, na redirects; om relatieve links op te lossen.
    pub url: String,
    /// Elke `Set-Cookie` apart: waarden en `Expires` bevatten komma's, dus
    /// vouwen kan niet. Daarom staan ze niet in `header`.
    pub set_cookie: Vec<String>,
    chunked: bool,
    conn: C,
    rbuf: ReadBuf,
    framing: Framing,
    done: bool,
    reuse: bool,
    pub(crate) addr: String,
}

impl<C> core::fmt::Debug for Response<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("length", &self.length)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl<C: Conn> Response<C> {
    /// `Content-Encoding`, als de server er een stuurde.
    pub fn encoding(&self) -> Option<&str> {
        self.header.get("Content-Encoding")
    }

    /// Zegt of de body chunked komt.
    pub fn is_chunked(&self) -> bool {
        self.chunked
    }

    /// Zegt of het einde van de body bewezen is.
    pub fn is_complete(&self) -> bool {
        self.done
    }

    /// Leest body-bytes; `Ok(0)` is het bewezen einde.
    ///
    /// Een verbinding die eindigt voor de lengte of voor de nul-chunk geeft
    /// [`Error::UnexpectedEof`].
    pub async fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        match self.framing {
            Framing::Empty => {
                self.done = true;
                Ok(0)
            }
            Framing::Length(0) => {
                self.done = true;
                Ok(0)
            }
            Framing::Length(left) => {
                let lim = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                let dst = out.get_mut(..lim).unwrap_or(&mut []);
                let n = self.rbuf.read(&mut self.conn, dst).await?;
                if n == 0 {
                    return Err(Error::UnexpectedEof);
                }
                let left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
                self.framing = Framing::Length(left);
                self.done = left == 0;
                Ok(n)
            }
            Framing::Chunked { .. } => self.read_chunked(out).await,
            Framing::Eof => {
                let n = self.rbuf.read(&mut self.conn, out).await?;
                self.done = n == 0;
                Ok(n)
            }
        }
    }

    /// Leest de rest van de body, tot hoogstens `limit` bytes.
    pub async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = self.read(&mut chunk).await?;
            if n == 0 {
                return Ok(body);
            }
            if body.len() + n > limit {
                return Err(Error::BodyTooLarge {
                    len: u64::try_from(body.len() + n).unwrap_or(u64::MAX),
                    limit: u64::try_from(limit).unwrap_or(u64::MAX),
                });
            }
            try_extend(&mut body, chunk.get(..n).unwrap_or(&[]))?;
        }
    }

    /// Geeft de verbinding terug als hij het volgende verzoek mag dragen, en
    /// sluit hem anders.
    ///
    /// Herbruikbaar is: body bewezen gelezen, beide kanten keep-alive, en geen
    /// ongevraagde bytes achter het antwoord (die zouden de volgende
    /// statusregel worden).
    pub async fn release(mut self) -> Option<C> {
        if self.done && self.reuse && self.rbuf.buffered().is_empty() {
            return Some(self.conn);
        }
        let _ = close(&mut self.conn).await;
        None
    }

    async fn read_chunked(&mut self, out: &mut [u8]) -> Result<usize> {
        let Framing::Chunked { left, finished } = self.framing else {
            return Ok(0);
        };
        if finished {
            return Ok(0);
        }
        let left = match left {
            0 => match next_chunk(&mut self.rbuf, &mut self.conn).await? {
                None => {
                    self.framing = Framing::Chunked {
                        left: 0,
                        finished: true,
                    };
                    self.done = true;
                    return Ok(0);
                }
                Some(n) => n,
            },
            n => n,
        };
        let lim = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let dst = out.get_mut(..lim).unwrap_or(&mut []);
        let n = self.rbuf.read(&mut self.conn, dst).await?;
        if n == 0 {
            // Elke EOF voor de nul-chunk is onvolledig (RFC 9112 §8).
            return Err(Error::UnexpectedEof);
        }
        let left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        self.framing = Framing::Chunked {
            left,
            finished: false,
        };
        if left == 0 {
            // De CRLF na de chunk; EOF ervoor is afgekapt, ook als alle
            // databytes er waren.
            let mut budget = BUF_SIZE;
            let crlf = self
                .rbuf
                .read_line(&mut self.conn, &mut budget)
                .await
                .map_err(eof_is_unexpected)?;
            if !crlf.is_empty() {
                return Err(Error::ChunkNotCrlf);
            }
        }
        Ok(n)
    }
}

/// Doet één hop op `conn`: het verzoek schrijven en de antwoordkop lezen.
///
/// Geen redirects, geen pool. Het verzoek draagt `Connection: keep-alive`;
/// na een volledig gelezen body geeft [`Response::release`] de verbinding
/// terug. Het schema van de URL bepaalt alleen de standaardpoort in `Host`:
/// of `conn` versleuteld is, weet de aanroeper.
pub async fn send<C: Conn>(conn: C, mut call: Call<'_>) -> Result<Response<C>> {
    let mut conn = conn;
    let prepared = Url::parse(call.url).and_then(|url| {
        check_url(&url, true)?;
        build_request(&call, &url, true)
    });
    let head = match prepared {
        Ok(h) => h,
        Err(e) => {
            let _ = close(&mut conn).await;
            return Err(e);
        }
    };
    let url = call.url;
    hop(conn, &mut call, url, &head, true, false)
        .await
        .map_err(|h| h.err)
}

/// Doet een verzoek met redirects en een verse verbinding per hop.
///
/// Geeft elke eindstatus terug, ook 4xx en 5xx: een foutstatus is geen
/// transportfout. Volgt alleen 301, 302, 303, 307 en 308, alleen voor GET en
/// HEAD zonder body, hoogstens [`MAX_REDIRECTS`] keer. Een cross-origin
/// redirect gooit alle headers van de aanroeper weg (alleen hij weet welke
/// gevoelig zijn); `https` naar `http` wordt geweigerd.
pub async fn fetch<D: Dial>(dialer: &mut D, call: Call<'_>) -> Result<Response<D::Conn>> {
    follow(dialer, None, call).await
}

/// GET met redirects, dat precies 200 en een bekende `Content-Length` eist.
///
/// Artefacten vragen een bekende lengte; een chunked of EOF-begrensd antwoord
/// faalt vóór er half werk is.
pub async fn get<D: Dial>(dialer: &mut D, url: &str) -> Result<Response<D::Conn>> {
    let resp = fetch(
        dialer,
        Call {
            url,
            ..Call::default()
        },
    )
    .await?;
    check_get(resp).await
}

/// Het contract van [`get`]: 200 plus `Content-Length`.
pub(crate) async fn check_get<C: Conn>(resp: Response<C>) -> Result<Response<C>> {
    let err = if resp.status != 200 {
        Error::Status(resp.status)
    } else if resp.chunked {
        Error::ChunkedNotAllowed
    } else if resp.length.is_none() {
        Error::NoContentLength
    } else {
        return Ok(resp);
    };
    let _ = resp.release().await;
    Err(err)
}

/// Een hopfout, en of hij op een hergebruikte verbinding viel vóór er een
/// antwoordbyte was: dan mag GET of HEAD één keer opnieuw.
pub(crate) struct HopError {
    pub(crate) err: Error,
    pub(crate) stale: bool,
}

fn fail(err: Error) -> HopError {
    HopError { err, stale: false }
}

/// De redirectlus, met of zonder pool.
pub(crate) async fn follow<D: Dial>(
    dialer: &mut D,
    mut pool: Option<(&mut Pool<D::Conn>, Duration)>,
    mut call: Call<'_>,
) -> Result<Response<D::Conn>> {
    let mut loc = try_string(call.url)?;
    for _ in 0..=MAX_REDIRECTS {
        let resp = match one_hop(dialer, reborrow(&mut pool), &mut call, &loc, false).await {
            Ok(r) => r,
            // Een verlopen pool-verbinding krijgt één verse herkansing, alleen
            // voor opnieuw af te spelen GET/HEAD, en niet na een termijn.
            Err(h) if h.stale && call.is_replay_safe() && h.err != Error::Io(IoError::TimedOut) => {
                one_hop(dialer, reborrow(&mut pool), &mut call, &loc, true)
                    .await
                    .map_err(|h| h.err)?
            }
            Err(h) => return Err(h.err),
        };
        // Alleen de redirectstatussen van RFC 9110 §15.4, alleen voor GET en
        // HEAD zonder body; andere methodes zijn niet veilig te herhalen.
        let follows = !call.no_follow
            && call.body.is_none()
            && call.is_replay_safe()
            && matches!(resp.status, 301 | 302 | 303 | 307 | 308);
        let next = match resp.header.get("Location") {
            Some(l) if follows && !l.is_empty() => try_string(l)?,
            _ => return Ok(resp),
        };
        // De 3xx-body is niet nodig; sluit of pool vóór de volgende hop.
        match reborrow(&mut pool) {
            Some((p, now)) => p.finish(resp, now).await,
            None => {
                let _ = resp.release().await;
            }
        }
        let base = Url::parse(&loc)?;
        let dest = resolve(&base, &next)?;
        let dest_url = Url::parse(&dest)?;
        // Nooit https naar http: het doel zelf kan een pad, query of getekend
        // token bevatten. Met no_follow beslist de aanroeper.
        if base.is_https() && !dest_url.is_https() {
            return Err(Error::HttpsDowngrade);
        }
        if !same_origin(&base, &dest_url) {
            call.header = Header::new();
        }
        loc = dest;
    }
    Err(Error::TooManyRedirects { max: MAX_REDIRECTS })
}

/// Leent de pool opnieuw uit voor één hop.
fn reborrow<'a, C>(
    p: &'a mut Option<(&mut Pool<C>, Duration)>,
) -> Option<(&'a mut Pool<C>, Duration)> {
    p.as_mut().map(|(p, now)| (&mut **p, *now))
}

fn check_url(url: &Url<'_>, https_ok: bool) -> Result {
    if url.is_https() {
        if !https_ok {
            return Err(Error::HttpsNeedsTls);
        }
    } else if !url.scheme.eq_ignore_ascii_case("http") {
        return Err(Error::UnsupportedScheme);
    }
    if url.hostname.is_empty() {
        return Err(Error::NoHost);
    }
    Ok(())
}

/// Eén hop via de pool of de dialer.
async fn one_hop<D: Dial>(
    dialer: &mut D,
    pool: Option<(&mut Pool<D::Conn>, Duration)>,
    call: &mut Call<'_>,
    loc: &str,
    fresh: bool,
) -> core::result::Result<Response<D::Conn>, HopError> {
    let url = Url::parse(loc).map_err(fail)?;
    // Elke hop opnieuw, zodat een redirect van http naar https nooit
    // plaintext naar poort 443 stuurt.
    check_url(&url, dialer.is_encrypted()).map_err(fail)?;
    let keep_alive = pool.is_some();
    let head = build_request(call, &url, keep_alive).map_err(fail)?;
    let port = url.effective_port();
    let mut addr = Vec::new();
    write!(FmtBuf(&mut addr), "{}", url.authority).map_err(|_| fail(Error::Alloc { bytes: 0 }))?;
    if url.port.is_none() {
        write!(FmtBuf(&mut addr), ":{port}").map_err(|_| fail(Error::Alloc { bytes: 0 }))?;
    }
    let addr = String::from_utf8(addr).map_err(|_| fail(Error::BadUrl))?;
    let target = Target {
        https: url.is_https(),
        host: url.hostname,
        port,
    };
    let pooled = match pool {
        Some((p, now)) if !fresh => p.take(&addr, now).await,
        _ => None,
    };
    let (conn, pooled) = match pooled {
        Some(c) => (c, true),
        None => (dialer.dial(target).await.map_err(fail)?, false),
    };
    let mut resp = hop(conn, call, loc, &head, keep_alive, pooled).await?;
    resp.addr = addr;
    Ok(resp)
}

/// Bouwt de requestkop en weigert injectiesyntax, vóór er gedialed wordt.
fn build_request(call: &Call<'_>, url: &Url<'_>, keep_alive: bool) -> Result<Vec<u8>> {
    let method = call.method();
    if !valid_token(method) {
        // Witruimte of CRLF in een methode is injectie van de requestregel.
        return Err(Error::InvalidMethod);
    }
    if method == "CONNECT" {
        // CONNECT vraagt na 2xx een rauwe tunnel die deze client niet heeft;
        // hem als gewoon verzoek versturen is onveilig.
        return Err(Error::Connect);
    }
    if call.body.is_some() && call.body_reader.is_some() {
        return Err(Error::BodyConflict);
    }
    // identity is de standaard omdat deze crate niet decomprimeert.
    let enc = call
        .header
        .get("Accept-Encoding")
        .filter(|v| !v.is_empty())
        .unwrap_or("identity");
    let mut b = Vec::new();
    let alloc = |_| Error::Alloc { bytes: 0 };
    write!(FmtBuf(&mut b), "{method} ").map_err(alloc)?;
    url.write_request_uri(&mut b)?;
    write!(
        FmtBuf(&mut b),
        " HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: {enc}\r\nConnection: {}\r\n",
        url.authority,
        if keep_alive { "keep-alive" } else { "close" }
    )
    .map_err(alloc)?;
    if call.body_reader.is_some() {
        // Een stroom die niet opnieuw kan, vraagt eerst een oordeel
        // (RFC 9110 §10.1.1).
        write!(
            FmtBuf(&mut b),
            "Content-Length: {}\r\nExpect: 100-continue\r\n",
            call.body_len
        )
        .map_err(alloc)?;
    } else if let Some(body) = call.body {
        write!(FmtBuf(&mut b), "Content-Length: {}\r\n", body.len()).map_err(alloc)?;
    }
    for (k, v) in call.header.iter() {
        if !valid_token(k) {
            // Tabs en controlebytes in een naam zijn injectie, geen syntax.
            return Err(Error::IllegalHeaderName);
        }
        if !valid_field_value(v.as_bytes()) {
            return Err(Error::IllegalHeaderValue);
        }
        let owned = [
            "Host",
            "Content-Length",
            "Connection",
            "Transfer-Encoding",
            "Expect",
        ];
        if owned.iter().any(|o| o.eq_ignore_ascii_case(k)) {
            return Err(Error::PackageOwnedHeader);
        }
        if k.eq_ignore_ascii_case("Accept-Encoding") {
            continue;
        }
        for part in [k, ": ", v, "\r\n"] {
            try_extend(&mut b, part.as_bytes())?;
        }
    }
    try_extend(&mut b, b"\r\n")?;
    Ok(b)
}

/// Het deel van een antwoord dat [`exchange`] oplevert, zonder verbinding.
struct Head {
    status: u16,
    reason: String,
    header: Header,
    length: Option<u64>,
    set_cookie: Vec<String>,
    chunked: bool,
    framing: Framing,
    done: bool,
    reuse: bool,
}

/// Doet de hop en bindt het resultaat aan de verbinding; bij een fout gaat
/// de verbinding dicht.
async fn hop<C: Conn>(
    mut conn: C,
    call: &mut Call<'_>,
    loc: &str,
    head: &[u8],
    keep_alive: bool,
    pooled: bool,
) -> core::result::Result<Response<C>, HopError> {
    let mut rbuf = match ReadBuf::new() {
        Ok(r) => r,
        Err(e) => {
            let _ = close(&mut conn).await;
            return Err(fail(e));
        }
    };
    let res = exchange(&mut conn, &mut rbuf, call, head, keep_alive, pooled).await;
    let url = try_string(loc);
    match (res, url) {
        (Ok(h), Ok(url)) => Ok(Response {
            status: h.status,
            reason: h.reason,
            header: h.header,
            length: h.length,
            url,
            set_cookie: h.set_cookie,
            chunked: h.chunked,
            conn,
            rbuf,
            framing: h.framing,
            done: h.done,
            reuse: h.reuse,
            addr: String::new(),
        }),
        (res, url) => {
            let _ = close(&mut conn).await;
            Err(match (res, url) {
                (Err(h), _) => h,
                (_, Err(e)) => fail(e),
                (Ok(_), Ok(_)) => fail(Error::Eof),
            })
        }
    }
}

/// Schrijft het verzoek (met `Expect`-dans voor een stroom) en leest de kop.
async fn exchange<C: Conn>(
    conn: &mut C,
    rbuf: &mut ReadBuf,
    call: &mut Call<'_>,
    head: &[u8],
    keep_alive: bool,
    pooled: bool,
) -> core::result::Result<Head, HopError> {
    // Een hergebruikte verbinding die faalt vóór de eerste antwoordbyte, mag
    // veilig opnieuw.
    let stale = |err: Error| HopError { err, stale: pooled };
    let io = |e: IoError| fail(Error::Io(e));
    write_all(conn, head).await.map_err(|e| stale(e.into()))?;
    let streaming = call.body_reader.is_some();
    if streaming {
        // Eén absolute beslistermijn voor een complete 100 of eindkop; het
        // oordeel is een kop, dus header_timeout geldt ook.
        let wait = call
            .header_timeout
            .map_or(EXPECT_TIMEOUT, |h| h.min(EXPECT_TIMEOUT));
        conn.set_read_timeout(Some(wait)).map_err(io)?;
        flush(conn).await.map_err(|e| stale(e.into()))?;
    } else {
        if let Some(body) = call.body.filter(|b| !b.is_empty()) {
            write_all(conn, body).await.map_err(io)?;
        }
        flush(conn).await.map_err(io)?;
        arm_header(conn, call)?;
    }
    let mut budget = MAX_HEADER_BYTES;
    let mut body_sent = !streaming;
    let mut first = true;
    // 1xx-koppen overslaan onder één cumulatief budget; een interim teruggeven
    // zou keep-alive desynchroniseren. 101 is een protocolwissel die hier niet
    // bestaat.
    let (status, is_10, reason) = loop {
        let line = match rbuf.read_line(conn, &mut budget).await {
            Ok(l) => l,
            Err(_) if first && !body_sent => return Err(fail(Error::NoVerdict)),
            Err(e) if first => return Err(stale(e)),
            Err(e) => return Err(fail(e)),
        };
        first = false;
        let (status, is_10) = status_code(&line).map_err(fail)?;
        if !(100..=199).contains(&status) {
            let reason = line.splitn(3, ' ').nth(2).unwrap_or("");
            break (status, is_10, try_string(reason).map_err(fail)?);
        }
        if status == 101 {
            return Err(fail(Error::SwitchedProtocols));
        }
        rbuf.read_header_block(conn, &mut budget, |_, _| Ok(()))
            .await
            .map_err(fail)?;
        if status == 100 && !body_sent {
            // 100 geeft de upload vrij: termijn uit tijdens het stromen,
            // daarna header_timeout opnieuw.
            conn.set_read_timeout(None).map_err(io)?;
            stream_body(conn, call).await.map_err(fail)?;
            flush(conn).await.map_err(io)?;
            body_sent = true;
            arm_header(conn, call)?;
        }
    };

    let mut header = Header::new();
    let mut set_cookie = Vec::new();
    let mut length = None;
    let mut chunked = false;
    rbuf.read_header_block(conn, &mut budget, |k, v| {
        if k.eq_ignore_ascii_case("Content-Length") {
            // Dubbele lengtes zijn dubbelzinnige framing, nooit last-wins.
            if length.is_some() {
                return Err(Error::DuplicateContentLength);
            }
            length = Some(parse_decimal(v).ok_or(Error::BadContentLength)?);
        } else if k.eq_ignore_ascii_case("Transfer-Encoding") {
            // Precies één chunked; al het andere maakt de framing dubbelzinnig
            // en mag nooit de pool in.
            if chunked {
                return Err(Error::DuplicateTransferEncoding);
            }
            if !v.eq_ignore_ascii_case("chunked") {
                return Err(Error::UnsupportedTransferEncoding);
            }
            chunked = true;
        } else if k.eq_ignore_ascii_case("Set-Cookie") {
            set_cookie
                .try_reserve(1)
                .map_err(|_| Error::Alloc { bytes: 1 })?;
            set_cookie.push(try_string(v)?);
            return Ok(());
        }
        header.add(k, v)
    })
    .await
    .map_err(fail)?;
    // RFC 9112 §6.1 verbiedt beide; weigeren in plaats van kiezen.
    if chunked && length.is_some() {
        return Err(fail(Error::BothFramings));
    }

    // HEAD heeft geen body maar houdt een informatieve lengte (§6.3). 204 en
    // 304 zijn bodyloos wat de framing ook zegt; op EOF wachten zou op een
    // keep-alive-verbinding blijven hangen.
    let is_head = call.method == "HEAD";
    let framing = if is_head {
        chunked = false;
        Framing::Empty
    } else if !body_allowed(status) {
        chunked = false;
        if status == 204 || status == 205 {
            length = Some(0);
        }
        Framing::Empty
    } else if chunked {
        length = None;
        Framing::Chunked {
            left: 0,
            finished: false,
        }
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::Eof
    };
    // Na de kop de fasetermijnen weer uit.
    if call.header_timeout.is_some() || streaming {
        conn.set_read_timeout(None).map_err(io)?;
    }
    // Hergebruik vraagt een geframed einde en een server die blijft. HTTP/1.0
    // sluit, tenzij hij expliciet keep-alive zegt (RFC 9112 §9.3).
    let conn_hdr = header.value("Connection");
    let keep_ok = !is_10 || connection_has(conn_hdr, "keep-alive");
    let bodyless = matches!(framing, Framing::Empty);
    let reuse = keep_alive
        && keep_ok
        && (bodyless || chunked || length.is_some())
        && !connection_has(conn_hdr, "close")
        && body_sent;
    let done = bodyless || (!chunked && length == Some(0));
    Ok(Head {
        status,
        reason,
        header,
        length,
        set_cookie,
        chunked,
        framing,
        done,
        reuse,
    })
}

/// Zet `header_timeout` voor de kopfase, nooit tijdens de upload.
fn arm_header<C: Conn>(conn: &mut C, call: &Call<'_>) -> core::result::Result<(), HopError> {
    if let Some(t) = call.header_timeout {
        conn.set_read_timeout(Some(t))
            .map_err(|e| fail(Error::Io(e)))?;
    }
    Ok(())
}

/// Stuurt precies `body_len` bytes; een korte lezer liet de server anders
/// eeuwig wachten.
async fn stream_body<C: Conn>(conn: &mut C, call: &mut Call<'_>) -> Result {
    let want = call.body_len;
    let Some(reader) = call.body_reader.as_deref_mut() else {
        return Ok(());
    };
    let mut buf = Vec::new();
    buf.try_reserve_exact(BUF_SIZE)
        .map_err(|_| Error::Alloc { bytes: BUF_SIZE })?;
    buf.resize(BUF_SIZE, 0);
    let mut sent = 0u64;
    while sent < want {
        let lim = buf
            .len()
            .min(usize::try_from(want - sent).unwrap_or(usize::MAX));
        let dst = buf.get_mut(..lim).unwrap_or(&mut []);
        let n = match read(reader, dst).await {
            Ok(0) | Err(_) => return Err(Error::StreamBody { sent, want }),
            Ok(n) => n,
        };
        write_all(conn, buf.get(..n).unwrap_or(&[])).await?;
        sent += u64::try_from(n).unwrap_or(u64::MAX);
    }
    Ok(())
}

/// Code en "is HTTP/1.0" uit een statusregel.
fn status_code(line: &str) -> Result<(u16, bool)> {
    let (proto, rest) = line.split_once(' ').ok_or(Error::MalformedStatusLine)?;
    // Onderscheid kapotte niet-HTTP-invoer van een onbekende versie.
    if !proto.starts_with("HTTP/") {
        return Err(Error::MalformedStatusLine);
    }
    if proto != "HTTP/1.0" && proto != "HTTP/1.1" {
        // Onbekende versies hebben onbekende framing en persistentie.
        return Err(Error::UnsupportedProtocol);
    }
    // RFC 9112 §4: precies drie kale cijfers.
    let num = rest.split(' ').next().unwrap_or("");
    let code = parse_decimal(num)
        .filter(|c| num.len() == 3 && (100..=599).contains(c))
        .ok_or(Error::MalformedStatusLine)?;
    Ok((
        u16::try_from(code).map_err(|_| Error::MalformedStatusLine)?,
        proto == "HTTP/1.0",
    ))
}
