//! De server: één verbinding, sequentieel bediend zolang beide kanten
//! keep-alive toestaan.
//!
//! Het model is bewust klein: één handler, `Content-Length`-antwoorden tot
//! een flush of 64 KiB overgaat op chunked, en [`Exchange::hijack`] voor
//! protocollen als WebSocket. Geen HTTP/2 (dat is `leanh2`, apart zodat wie
//! alleen dit importeert er niets van linkt), geen TLS, geen pipelining.
//!
//! Wat deze module bezit: de verbinding voor de duur van [`serve`], de lees-
//! en schrijfbuffer, en de toestand van het ene antwoord dat openstaat. Wat
//! niet: de listener (een verbinding is een taak uit de vaste pool van de
//! aanroeper) en de klok (termijnen gaan relatief naar de verbinding).
//!
//! In Go was een handler-panic fataal en werd hij niet opgevangen; hier geeft
//! een handler een [`Result`], en een fout sluit de verbinding.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::task::{Context, Poll};
use core::time::Duration;

use crate::error::{Error, Result};
use crate::header::{
    Header, body_allowed, connection_has, fmt_dec, fmt_hex, parse_decimal, status_text, try_string,
    valid_field_value, valid_token,
};
use crate::io::{
    AsyncRead, AsyncWrite, Conn, FmtBuf, IoError, ReadBuf, close, flush, try_extend, write_all,
};
use crate::url::{canonical_path, clean_escapes, percent_decode};
use crate::{
    AUTO_CHUNK_BYTES, BODY_TIMEOUT, BUF_SIZE, DRAIN_TIMEOUT, IDLE_TIMEOUT, MAX_BODY_BYTES,
    MAX_HEADER_BYTES, REQUEST_TIMEOUT, WRITE_TIMEOUT,
};

/// Eén binnenkomend verzoek, zonder de body: die leest de handler via
/// [`Exchange::read_body`].
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// De methode, hoofdlettergevoelig (`GET`, `POST`, ...).
    pub method: String,
    /// Het gedecodeerde, canonieke pad.
    ///
    /// De parser weigert escapes die tot `/`, `.` of `..` decoderen, punt-
    /// segmenten en dubbele slashes, zodat middleware, de Mux en de handler
    /// één interpretatie delen. Middleware mag hem herschrijven; een niet-
    /// canoniek pad routeert dan nergens heen (404).
    pub path: String,
    /// Alles na de `?`, niet gedecodeerd; zie [`Request::query`].
    pub raw_query: String,
    /// De requestheaders; herhaalde velden zijn tot een kommalijst gevouwen.
    pub header: Header,
    /// De aangekondigde body-lengte, of `None` zonder `Content-Length`.
    pub content_length: Option<u64>,
    values: Vec<(String, String)>,
    keep_alive: bool,
}

impl Request {
    /// Bouwt een verzoek zoals de server het zou aannemen, voor tests en
    /// middleware; `target` is `/pad?query`.
    ///
    /// Een doel dat de server zou weigeren (niet canoniek, ambigue escapes),
    /// is hier ook een fout: een synthetisch verzoek mag geen vorm hebben die
    /// over de draad nooit binnenkomt.
    pub fn new(method: &str, target: &str) -> Result<Self> {
        let mut line = Vec::new();
        for part in [method, " ", target, " HTTP/1.1"] {
            try_extend(&mut line, part.as_bytes())?;
        }
        let line = core::str::from_utf8(&line).map_err(|_| Error::BadTarget)?;
        let mut req = parse_request_line(line).map_err(|r| match r {
            Reject::Bad { err, .. } => err,
            Reject::Gone => Error::BadTarget,
        })?;
        req.keep_alive = true;
        Ok(req)
    }

    /// De waarde van wildcard `name` die de Mux vond.
    pub fn path_value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Zet de wildcardwaarden, zoals de Mux doet; voor tests en middleware.
    pub fn set_path_values(&mut self, values: Vec<(String, String)>) {
        self.values = values;
    }

    /// De eerste waarde van `key` in de query, gedecodeerd (`+` is spatie).
    ///
    /// Een kapot paar wordt overgeslagen, zoals Go's `ParseQuery` met
    /// genegeerde fout: een kromme query levert lege waarden, geen 400.
    pub fn query(&self, key: &str) -> Result<Option<String>> {
        for pair in self.raw_query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if percent_decode(k, true)?.as_deref() == Some(key)
                && let Some(v) = percent_decode(v, true)?
            {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
}

/// Wat [`serve`] teruggeeft als de verbinding klaar is.
#[derive(Debug)]
pub enum Outcome<C> {
    /// De verbinding is gesloten (door de client, een termijn, of `close`).
    Closed,
    /// Een handler nam de verbinding over; de aanroeper is nu eigenaar.
    Hijacked(Hijacked<C>),
}

/// Een overgenomen verbinding, met de bytes die al gelezen maar nog niet
/// verbruikt waren.
#[derive(Debug)]
pub struct Hijacked<C> {
    /// De verbinding; wie hem heeft, sluit hem.
    pub conn: C,
    /// Bytes die de client al stuurde na de requestkop.
    pub buffered: Vec<u8>,
}

/// De verbinding met zijn buffers, zolang [`serve`] loopt.
struct Wire<C> {
    conn: C,
    rbuf: ReadBuf,
    out: Vec<u8>,
    /// De handler bezit de verbinding.
    hijacked: bool,
    /// `done` bezit de leeskant; niet hergebruiken.
    watched: bool,
    /// De kop van dit antwoord staat op de draad; `done` is nu te laat.
    head_sent: bool,
}

impl<C: Conn> Wire<C> {
    /// Schrijft met [`WRITE_TIMEOUT`] per socketwrite, zodat een client die
    /// niet leest geen taak vasthoudt; daarna gaat de termijn weer uit, zodat
    /// hij niet stil verloopt terwijl de handler rekent.
    async fn timed_write(&mut self, data: &[u8]) -> Result {
        // Een setterfout is geen HTTP-antwoord (KAM); de write faalt dan vanzelf.
        let _ = self.conn.set_write_timeout(Some(WRITE_TIMEOUT));
        let res = write_all(&mut self.conn, data).await;
        let _ = self.conn.set_write_timeout(None);
        Ok(res?)
    }

    /// Buffert zoals `bufio.Writer`: vol is wegschrijven, groot gaat direct.
    async fn put(&mut self, data: &[u8]) -> Result {
        if self.out.len() + data.len() > BUF_SIZE {
            self.flush_buf().await?;
        }
        if data.len() >= BUF_SIZE {
            return self.timed_write(data).await;
        }
        try_extend(&mut self.out, data)
    }

    async fn flush_buf(&mut self) -> Result {
        if self.out.is_empty() {
            return Ok(());
        }
        let out = core::mem::take(&mut self.out);
        let res = self.timed_write(&out).await;
        self.out = out;
        self.out.clear();
        res
    }

    async fn flush(&mut self) -> Result {
        self.flush_buf().await?;
        Ok(flush(&mut self.conn).await?)
    }

    fn set_read_timeout(&mut self, t: Option<Duration>) {
        // KAM: een setterfout wordt geen apart antwoord; een verbinding die
        // geen termijn kan zetten, faalt vanzelf op de volgende read.
        let _ = self.conn.set_read_timeout(t);
    }

    /// Leest en verwerpt hoogstens `max` bytes, tot einde of fout.
    async fn discard(&mut self, mut max: u64) {
        while max > 0 {
            match self.rbuf.fill_some(&mut self.conn).await {
                Ok(true) => {
                    let n = self.rbuf.buffered().len().min(usize_of(max));
                    self.rbuf.consume(n);
                    max -= u64_of(n);
                }
                _ => return,
            }
        }
    }
}

fn u64_of(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn usize_of(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Bedient één verbinding tot hij sluit of een handler hem overneemt.
///
/// Verzoeken komen één voor één; het volgende wordt pas gelezen als het
/// antwoord af is en de body van het vorige leeg is. De fasetermijnen uit KAM
/// gaan relatief naar de verbinding: [`REQUEST_TIMEOUT`] voor de eerste kop,
/// [`IDLE_TIMEOUT`] tussen verzoeken, [`BODY_TIMEOUT`] voor de body,
/// [`WRITE_TIMEOUT`] per socketwrite, [`DRAIN_TIMEOUT`] voor het wegvegen.
///
/// Een kapot verzoek krijgt een kaal foutantwoord (400, 413, 417, 501, 505) en
/// daarna een gesloten verbinding. Geeft de handler een fout, dan krijgt de
/// client een 500 als het antwoord nog niet begonnen was, en gaat de
/// verbinding dicht; die fout komt hier terug zodat de aanroeper hem logt.
///
/// De verbinding is gesloten als dit `Ok(Outcome::Closed)` of een fout geeft;
/// bij [`Outcome::Hijacked`] is de aanroeper eigenaar.
pub async fn serve<C, H>(conn: C, mut handler: H) -> Result<Outcome<C>>
where
    C: Conn,
    H: AsyncFnMut(&mut Exchange<'_, C>) -> Result,
{
    let mut conn = conn;
    let bufs = ReadBuf::new().and_then(|r| {
        let mut out = Vec::new();
        out.try_reserve_exact(BUF_SIZE)
            .map_err(|_| Error::Alloc { bytes: BUF_SIZE })?;
        Ok((r, out))
    });
    let (rbuf, out) = match bufs {
        Ok(b) => b,
        Err(e) => {
            let _ = close(&mut conn).await;
            return Err(e);
        }
    };
    let mut wire = Wire {
        conn,
        rbuf,
        out,
        hijacked: false,
        watched: false,
        head_sent: false,
    };
    let mut first = true;
    let result = loop {
        wire.set_read_timeout(Some(if first { REQUEST_TIMEOUT } else { IDLE_TIMEOUT }));
        first = false;
        let (req, body_len) = match read_request(&mut wire).await {
            Ok(r) => r,
            Err(Reject::Gone) => break Ok(()),
            Err(Reject::Bad { status, err, drain }) => {
                let _ = write_bare(&mut wire, status, err).await;
                // Alleen als de kop een body aankondigde: dan komt het antwoord
                // aan in plaats van een RST, zonder dat een kale syntaxfout
                // middelen vasthoudt.
                if drain {
                    wire.set_read_timeout(Some(DRAIN_TIMEOUT));
                    wire.discard(MAX_BODY_BYTES).await;
                }
                break Ok(());
            }
        };
        // Een body houdt zijn termijn; zonder body gaat hij uit, zodat een
        // SSE-handler onbeperkt kan stromen.
        wire.set_read_timeout((body_len > 0).then_some(BODY_TIMEOUT));
        wire.head_sent = false;
        let head = req.method == "HEAD";
        let keep_alive = req.keep_alive;
        let mut ex = Exchange {
            req,
            wire: &mut wire,
            body_left: body_len,
            resp: Resp::new(keep_alive, head),
        };
        let res = handler(&mut ex).await;
        if ex.wire.hijacked {
            return Ok(Outcome::Hijacked(Hijacked {
                conn: wire.conn,
                buffered: wire.rbuf.into_unread(),
            }));
        }
        // Houd de capaciteit voor dit hele verzoek, en sluit dan een gegroeide
        // (bulk)verbinding: praterige verbindingen blijven klein en herbruikbaar,
        // een gegroeide geeft zijn budget in één keer terug.
        if ex.wire.conn.has_grown() {
            ex.resp.keep_alive = false;
        }
        match res {
            Ok(()) => match ex.settle().await {
                Ok(true) => continue,
                Ok(false) => break Ok(()),
                Err(e) => break Err(e),
            },
            Err(e) => {
                ex.fail().await;
                break Err(e);
            }
        }
    };
    let _ = close(&mut wire.conn).await;
    result.map(|()| Outcome::Closed)
}

/// Waarom er geen verzoek is.
enum Reject {
    /// De client ging weg (EOF, termijn, verbroken): stil sluiten.
    Gone,
    /// Een kapot verzoek: antwoorden met `status`, en eventueel de
    /// aangekondigde body kort wegvegen.
    Bad {
        status: u16,
        err: Error,
        drain: bool,
    },
}

fn bad(err: Error) -> Reject {
    Reject::Bad {
        status: 400,
        err,
        drain: false,
    }
}

/// Leest één requestregel, het kopblok en de framing van de body.
async fn read_request<C: Conn>(wire: &mut Wire<C>) -> core::result::Result<(Request, u64), Reject> {
    // EOF, een termijn of een verbroken verbinding: de client ging weg. Een
    // aanwezige maar kapotte requestregel verdient een 400.
    let classify = |e: Error| match e {
        Error::Eof | Error::Io(_) => Reject::Gone,
        e => bad(e),
    };
    let mut budget = MAX_HEADER_BYTES;
    let mut line = wire
        .rbuf
        .read_line(&mut wire.conn, &mut budget)
        .await
        .map_err(classify)?;
    if line.is_empty() {
        // RFC 9112 §2.2 staat één leidende CRLF toe.
        line = wire
            .rbuf
            .read_line(&mut wire.conn, &mut budget)
            .await
            .map_err(classify)?;
    }
    let mut req = parse_request_line(&line)?;

    let (mut hosts, mut cls, mut tes) = (0usize, 0usize, 0usize);
    let header = &mut req.header;
    wire.rbuf
        .read_header_block(&mut wire.conn, &mut budget, |k, v| {
            // Tel framingheaders per fysieke regel vóór het vouwen; anders
            // verdwijnt een lege eerste Content-Length in een geldige tweede.
            if k.eq_ignore_ascii_case("Host") {
                hosts += 1;
            } else if k.eq_ignore_ascii_case("Content-Length") {
                cls += 1;
            } else if k.eq_ignore_ascii_case("Transfer-Encoding") {
                tes += 1;
            }
            header.add(k, v)
        })
        .await
        .map_err(bad)?;

    // RFC 9112 §3.2: precies één niet-lege Host. Ontbrekend, leeg of dubbel
    // geeft proxy's ruimte om anders te routeren. Deze server routeert niet op
    // Host; komt dat ooit, dan hoort daar een expliciete allowlist bij.
    if hosts != 1 || req.header.value("Host").is_empty() {
        return Err(bad(Error::HostCount { got: hosts }));
    }
    // HTTP/1.1 blijft open tenzij de Connection-lijst close bevat.
    req.keep_alive = !connection_has(req.header.value("Connection"), "close");

    // Elke Expect krijgt 417 (RFC 9110 §10.1.1 staat dat toe); geen enkele
    // gebruiker heeft de 100-continue-toestandsmachine nodig. Niet vegen: een
    // Expect-client wacht met zijn body.
    if !req.header.value("Expect").is_empty() {
        return Err(Reject::Bad {
            status: 417,
            err: Error::ExpectUnsupported,
            drain: false,
        });
    }
    let reject = |status, err| Reject::Bad {
        status,
        err,
        drain: true,
    };
    let body_len = match (cls, tes) {
        // Herhaalde framing, ook lege regels (RFC 9112 §6).
        (c, t) if c > 1 || t > 1 => return Err(reject(400, Error::RepeatedFraming)),
        // TE plus CL laat tussenstations het oneens zijn over de grens (§6.1).
        (1, 1) => return Err(reject(400, Error::BothFramings)),
        // Request-bodies vragen Content-Length; geen gebruiker stuurt chunked.
        (_, 1) => return Err(reject(501, Error::RequestTransferEncoding)),
        (1, _) => {
            // Streng decimaal: "+5" leest een proxy misschien anders.
            let n = parse_decimal(req.header.value("Content-Length"))
                .ok_or_else(|| reject(400, Error::BadContentLength))?;
            if n > MAX_BODY_BYTES {
                return Err(reject(
                    413,
                    Error::BodyTooLarge {
                        len: n,
                        limit: MAX_BODY_BYTES,
                    },
                ));
            }
            req.content_length = Some(n);
            n
        }
        _ => 0,
    };
    Ok((req, body_len))
}

/// Ontleedt `METHODE doel HTTP/1.1` tot een verzoek zonder headers.
fn parse_request_line(line: &str) -> core::result::Result<Request, Reject> {
    let (method, rest) = line
        .split_once(' ')
        .ok_or(bad(Error::MalformedRequestLine))?;
    if !valid_token(method) {
        // Strenge methode-tokens: geen routeringsverschil met een proxy.
        return Err(bad(Error::InvalidMethod));
    }
    if method == "CONNECT" {
        // Een tunnel bestaat hier niet.
        return Err(Reject::Bad {
            status: 501,
            err: Error::Connect,
            drain: false,
        });
    }
    let (target, proto) = rest
        .split_once(' ')
        .ok_or(bad(Error::MalformedRequestLine))?;
    if !proto.starts_with("HTTP/") {
        return Err(bad(Error::MalformedRequestLine));
    }
    if proto != "HTTP/1.1" {
        // Serverinvoer is precies HTTP/1.1; de client leest wel 1.0-antwoorden.
        return Err(Reject::Bad {
            status: 505,
            err: Error::UnsupportedVersion,
            drain: false,
        });
    }
    if !target.starts_with('/') {
        // Alleen origin-form (RFC 9112 §3.2.1): asterisk verzint een route,
        // absolute-form verdubbelt de Host-autoriteit.
        return Err(bad(Error::NotOriginForm));
    }
    let (escaped, query) = target.split_once('?').unwrap_or((target, ""));
    if !clean_escapes(escaped) {
        return Err(bad(Error::AmbiguousEscape));
    }
    let path = percent_decode(escaped, false)
        .map_err(bad)?
        .ok_or(bad(Error::BadTarget))?;
    if !canonical_path(&path) {
        // Weigeren, niet normaliseren: geen tweede interpretatie.
        return Err(bad(Error::NonCanonicalPath));
    }
    Ok(Request {
        method: try_string(method).map_err(bad)?,
        path,
        raw_query: try_string(query).map_err(bad)?,
        ..Request::default()
    })
}

/// Antwoordt op een onleesbaar verzoek en laat de verbinding sluiten.
async fn write_bare<C: Conn>(wire: &mut Wire<C>, status: u16, err: Error) -> Result {
    let mut msg = Vec::new();
    writeln!(FmtBuf(&mut msg), "{err}").map_err(|_| Error::Alloc { bytes: 0 })?;
    let mut out = Vec::new();
    write!(
        FmtBuf(&mut out),
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        status_text(status),
        msg.len()
    )
    .map_err(|_| Error::Alloc { bytes: 0 })?;
    try_extend(&mut out, &msg)?;
    wire.put(&out).await?;
    wire.flush().await
}

/// De toestand van het ene antwoord dat openstaat.
struct Resp {
    hdr: Header,
    status: u16,
    status_set: bool,
    /// Gebufferd tot `finish` de lengte kent, of tot 64 KiB.
    pending: Vec<u8>,
    /// De kop staat op de draad.
    started: bool,
    chunked: bool,
    /// Verstuurde body-bytes, om de lengte te toetsen.
    written: u64,
    /// De `Content-Length` die op de draad staat bij het directe pad.
    declared: Option<u64>,
    keep_alive: bool,
    /// HEAD: de kop van GET, geen body-bytes.
    head: bool,
    /// De eerste schrijffout; daarna faalt elke write met dezelfde.
    err: Option<Error>,
}

impl Resp {
    fn new(keep_alive: bool, head: bool) -> Self {
        Resp {
            hdr: Header::new(),
            status: 200,
            status_set: false,
            pending: Vec::new(),
            started: false,
            chunked: false,
            written: 0,
            declared: None,
            keep_alive,
            head,
            err: None,
        }
    }

    /// Kop houden, body-bytes weggooien: HEAD en de bodyloze statussen.
    fn suppress_body(&self) -> bool {
        self.head || !body_allowed(self.status)
    }

    fn remember(&mut self, e: Error) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }
}

/// Eén verzoek en zijn antwoord: de enige plek waar een handler leest en
/// schrijft.
///
/// `req` is het verzoek; de body leest de handler met [`read_body`]. Het
/// antwoord begint met [`header_mut`] en [`write_header`] en gaat de draad op
/// met [`write`] en [`flush`]. Zonder bekende lengte buffert de schrijver tot
/// [`AUTO_CHUNK_BYTES`] en gaat daarna over op chunked; de eerste flush zonder
/// lengte kiest meteen chunked.
///
/// [`read_body`]: Exchange::read_body
/// [`header_mut`]: Exchange::header_mut
/// [`write_header`]: Exchange::write_header
/// [`write`]: Exchange::write
/// [`flush`]: Exchange::flush
pub struct Exchange<'c, C> {
    /// Het verzoek; de Mux zet er de wildcardwaarden in.
    pub req: Request,
    wire: &'c mut Wire<C>,
    body_left: u64,
    resp: Resp,
}

impl<'c, C: Conn> Exchange<'c, C> {
    /// De antwoordheaders; wijzig ze voor de eerste write.
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.resp.hdr
    }

    /// Zet de status; de standaard is 200 en alleen de eerste telt.
    ///
    /// Alleen eindstatussen 200 tot en met 599; 1xx bestaat niet en 101 gaat
    /// via [`Exchange::hijack`]. Een gebufferde write legt de status ook vast.
    /// 205 blijft 205, bodyloos met `Content-Length: 0`.
    pub fn write_header(&mut self, status: u16) -> Result {
        if !(200..=599).contains(&status) {
            return Err(Error::InvalidStatus(status));
        }
        let r = &mut self.resp;
        if !(r.status_set || r.started || !r.pending.is_empty()) {
            r.status = status;
            r.status_set = true;
        }
        Ok(())
    }

    /// Schrijft body-bytes.
    ///
    /// Zonder `Content-Length` en zonder flush buffert de schrijver en rekent
    /// hij de lengte zelf uit. Met een `Content-Length` gaat alles direct, en
    /// wie meer schrijft dan hij beloofde krijgt [`Error::WroteTooMuch`]: het
    /// surplus komt niet op de draad, waar het het volgende antwoord zou worden.
    pub async fn write(&mut self, p: &[u8]) -> Result<usize> {
        if self.wire.hijacked {
            return Err(Error::Hijacked);
        }
        if let Some(e) = self.resp.err {
            return Err(e);
        }
        if !self.resp.started {
            if self.resp.hdr.value("Content-Length").is_empty() {
                if self.resp.pending.len() + p.len() <= AUTO_CHUNK_BYTES {
                    try_extend(&mut self.resp.pending, p)?;
                    return Ok(p.len());
                }
                // Boven de drempel: chunked in plaats van onbegrensd bufferen.
                self.start_chunked().await?;
                return self.write_body(p).await;
            }
            self.write_head().await?;
        }
        self.write_body(p).await
    }

    /// Stuurt wat klaarstaat naar de client.
    ///
    /// De eerste flush zonder `Content-Length` kiest chunked; wat gebufferd
    /// was, wordt de eerste chunk. Dit is de naad voor frame-stromen en SSE.
    pub async fn flush(&mut self) -> Result {
        if self.wire.hijacked {
            return Err(Error::Hijacked);
        }
        if let Some(e) = self.resp.err {
            return Err(e);
        }
        if !self.resp.started {
            if self.resp.hdr.value("Content-Length").is_empty() {
                self.start_chunked().await?;
            } else {
                // Een beloofde lengte blijft de framing.
                self.flush_head().await?;
            }
        }
        let res = self.wire.flush().await;
        if let Err(e) = res {
            self.resp.remember(e);
        }
        res
    }

    /// Neemt de rauwe verbinding over, voordat het antwoord begon.
    ///
    /// De overnemer schrijft zelf de `101` en bezit daarna bytes, framing en
    /// levensloop; termijnen zijn gewist. Na de handler geeft [`serve`] de
    /// verbinding terug als [`Outcome::Hijacked`]. Na een write, een status of
    /// [`Exchange::done`] kan het niet meer.
    pub fn hijack(&mut self) -> Result<Raw<'_, C>> {
        let r = &self.resp;
        if r.started || !r.pending.is_empty() || r.status_set {
            // Ook een gebufferde write of een status is een commit.
            return Err(Error::ResponseStarted);
        }
        if self.wire.watched {
            // De leeskant heeft al een eigenaar.
            return Err(Error::DoneClaimed);
        }
        if self.wire.hijacked {
            return Err(Error::Hijacked);
        }
        self.wire.hijacked = true;
        self.wire.set_read_timeout(None);
        let _ = self.wire.conn.set_write_timeout(None);
        Ok(Raw {
            wire: &mut *self.wire,
        })
    }

    /// Leest body-bytes; `Ok(0)` is het einde van de body.
    ///
    /// Een verbinding die eindigt voordat `Content-Length` bereikt is, geeft
    /// [`Error::UnexpectedEof`], nooit een stil kort succes.
    pub async fn read_body(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.wire.hijacked {
            return Err(Error::Hijacked);
        }
        if self.body_left == 0 || out.is_empty() {
            return Ok(0);
        }
        let lim = out.len().min(usize_of(self.body_left));
        let dst = out.get_mut(..lim).unwrap_or(&mut []);
        let n = self.wire.rbuf.read(&mut self.wire.conn, dst).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        self.body_left -= u64_of(n);
        Ok(n)
    }

    /// Leest de hele body; hij is door de parser al begrensd op
    /// [`MAX_BODY_BYTES`].
    pub async fn read_body_to_end(&mut self) -> Result<Vec<u8>> {
        let len = usize_of(self.body_left);
        let mut body = Vec::new();
        body.try_reserve_exact(len)
            .map_err(|_| Error::Alloc { bytes: len })?;
        body.resize(len, 0);
        let mut at = 0;
        while at < len {
            let n = self
                .read_body(body.get_mut(at..).unwrap_or(&mut []))
                .await?;
            at += n;
        }
        Ok(body)
    }

    /// Claimt de leeskant voor [`Exchange::done`], zonder te wachten.
    ///
    /// Daarna zegt het antwoord `Connection: close`, want de wachter verbruikt
    /// de verbinding. Een ongelezen body is invoer van de client, geen fout van
    /// de handler: die wordt hier begrensd weggeveegd. Claim vóór de eerste
    /// write of flush; herhalen mag.
    pub async fn claim_done(&mut self) -> Result {
        if self.wire.watched {
            return Ok(());
        }
        if self.wire.hijacked {
            return Err(Error::Hijacked);
        }
        if self.wire.head_sent {
            return Err(Error::DoneAfterStart);
        }
        if self.body_left > 0 {
            self.wire.set_read_timeout(Some(DRAIN_TIMEOUT));
            let _ = self.discard_body().await;
        }
        self.wire.watched = true;
        // De bodytermijn gaat uit, zodat de wachter zijn verloop niet voor
        // een weggelopen client aanziet.
        self.wire.set_read_timeout(None);
        Ok(())
    }

    /// Wacht tot de client weggaat: de disconnect-naad voor een lange stroom.
    ///
    /// Leest en verwerpt tot FIN, RST of sluiting, en is annuleerbaar: leg hem
    /// in een `select` naast het eigen werk. Claimt eerst de leeskant (zie
    /// [`Exchange::claim_done`]); lees de body dus vóór `done`. `done` en
    /// [`Exchange::hijack`] sluiten elkaar uit.
    pub async fn done(&mut self) -> Result {
        self.claim_done().await?;
        loop {
            match self.wire.rbuf.fill_some(&mut self.wire.conn).await {
                Ok(true) => {
                    let n = self.wire.rbuf.buffered().len();
                    self.wire.rbuf.consume(n);
                }
                _ => return Ok(()),
            }
        }
    }

    /// Stuurt een status met een platte-tekstuitleg.
    pub async fn error(&mut self, status: u16, msg: &str) -> Result {
        self.resp
            .hdr
            .set("Content-Type", "text/plain; charset=utf-8")?;
        self.write_header(status)?;
        self.write(msg.as_bytes()).await?;
        self.write(b"\n").await?;
        Ok(())
    }

    /// Stuurt een redirect naar `location` met de gevraagde status.
    pub async fn redirect(&mut self, location: &str, status: u16) -> Result {
        self.resp.hdr.set("Location", location)?;
        self.write_header(status)?;
        self.write(b"redirecting to ").await?;
        self.write(location.as_bytes()).await?;
        self.write(b"\n").await?;
        Ok(())
    }

    async fn discard_body(&mut self) -> Result {
        while self.body_left > 0 {
            if !self.wire.rbuf.fill_some(&mut self.wire.conn).await? {
                return Err(Error::UnexpectedEof);
            }
            let n = self
                .wire
                .rbuf
                .buffered()
                .len()
                .min(usize_of(self.body_left));
            self.wire.rbuf.consume(n);
            self.body_left -= u64_of(n);
        }
        Ok(())
    }

    async fn start_chunked(&mut self) -> Result {
        self.resp.chunked = true;
        self.flush_head().await
    }

    /// Stuurt de kop en wat gebufferd was, en geeft de buffer vrij.
    async fn flush_head(&mut self) -> Result {
        let pending = core::mem::take(&mut self.resp.pending);
        self.write_head().await?;
        if !pending.is_empty() {
            self.write_body(&pending).await?;
        }
        Ok(())
    }

    /// Zet de statusregel en de headers in de schrijfbuffer.
    async fn write_head(&mut self) -> Result {
        let watched = self.wire.watched;
        let r = &mut self.resp;
        r.started = true;
        self.wire.head_sent = true;
        // Varianten van één naam: gelijk wordt één, verschillend verdwijnt en
        // sluit, zodat EOF de enige ondubbelzinnige framing is.
        if r.hdr.collapse_variants() {
            r.keep_alive = false;
        }
        // De schrijver bezit de framing: een Transfer-Encoding van de handler
        // zou naast een Content-Length met een ongechunkte body komen.
        r.hdr.remove("Transfer-Encoding");
        if connection_has(r.hdr.value("Connection"), "close") {
            r.keep_alive = false;
        }
        let suppress = r.suppress_body();
        if suppress {
            r.chunked = false;
            if r.status == 204 {
                // 204 draagt geen lengte; 304 en HEAD mogen hem als metadata.
                r.hdr.remove("Content-Length");
            }
            if r.status == 205 && !r.head {
                // RFC 9112 §6.3 wil voor 205 een expliciete nul.
                r.hdr.set("Content-Length", "0")?;
            }
        }
        if r.chunked {
            r.hdr.set("Transfer-Encoding", "chunked")?;
            // Chunked framet zichzelf; ook een lege lengte gaat weg.
            r.hdr.remove("Content-Length");
        }
        // Elke Content-Length streng, ook HEAD-metadata. Een ongeldige gaat
        // weg en dwingt EOF-framing in plaats van onveilige keep-alive.
        if let Some(cl) = r.hdr.get("Content-Length") {
            match parse_decimal(cl) {
                Some(n) if !r.chunked && !suppress => r.declared = Some(n),
                Some(_) => {}
                None => {
                    let empty = cl.is_empty();
                    r.hdr.remove("Content-Length");
                    r.keep_alive &= empty;
                }
            }
        }
        // De done-wachter verbruikt de verbinding na dit antwoord; zeg dat,
        // in plaats van een dode verbinding in de pool van een client te laten.
        let conn = if r.keep_alive && !watched {
            "keep-alive"
        } else {
            "close"
        };
        r.hdr.set("Connection", conn)?;
        let mut head = Vec::new();
        write!(
            FmtBuf(&mut head),
            "HTTP/1.1 {} {}\r\n",
            r.status,
            status_text(r.status)
        )
        .map_err(|_| Error::Alloc { bytes: 0 })?;
        for (k, v) in r.hdr.iter() {
            // Een ongeldige naam of een waarde met controlebytes zou een
            // tweede antwoord kunnen injecteren: overslaan.
            if !valid_token(k) || !valid_field_value(v.as_bytes()) {
                continue;
            }
            for part in [k, ": ", v, "\r\n"] {
                try_extend(&mut head, part.as_bytes())?;
            }
        }
        try_extend(&mut head, b"\r\n")?;
        let res = self.wire.put(&head).await;
        if let Err(e) = res {
            self.resp.remember(e);
        }
        res
    }

    /// Schrijft body-bytes in de gekozen framing, begrensd door de lengte.
    async fn write_body(&mut self, p: &[u8]) -> Result<usize> {
        if p.is_empty() {
            return self.resp.err.map_or(Ok(0), Err);
        }
        if self.resp.suppress_body() {
            // Gedeelde GET/HEAD-handlers schrijven gewoon; de bytes vallen weg.
            return Ok(p.len());
        }
        if let Some(declared) = self.resp.declared {
            let allowed = declared.saturating_sub(self.resp.written);
            if u64_of(p.len()) > allowed {
                // Het afgekapte antwoord klopt nog met zijn belofte, dus de
                // verbinding blijft bruikbaar; de handler hoort de fout.
                let cut = p.get(..usize_of(allowed)).unwrap_or(&[]);
                if !cut.is_empty() {
                    let _ = self.write_body_raw(cut).await;
                }
                return Err(Error::WroteTooMuch { declared });
            }
        }
        self.write_body_raw(p).await
    }

    async fn write_body_raw(&mut self, p: &[u8]) -> Result<usize> {
        let res = self.put_framed(p).await;
        if let Err(e) = res {
            self.resp.remember(e);
        }
        res.map(|()| p.len())
    }

    async fn put_framed(&mut self, p: &[u8]) -> Result {
        if self.resp.chunked {
            let mut buf = [0u8; 20];
            let size = fmt_hex(u64_of(p.len()), &mut buf);
            self.wire.put(size.as_bytes()).await?;
            self.wire.put(b"\r\n").await?;
        }
        self.wire.put(p).await?;
        self.resp.written += u64_of(p.len());
        if self.resp.chunked {
            self.wire.put(b"\r\n").await?;
        }
        Ok(())
    }

    /// Sluit het antwoord af: lengte voor een gebufferd antwoord, de nul-chunk
    /// voor een gechunkt, en de lengtetoets voor het directe pad.
    async fn finish(&mut self) -> Result {
        if self.wire.hijacked {
            return Ok(());
        }
        if !self.resp.started {
            let body = core::mem::take(&mut self.resp.pending);
            let r = &mut self.resp;
            // HEAD meldt de lengte van de GET (RFC 9110 §9.3.2), maar een
            // expliciete lengte zonder body-bytes blijft staan.
            let explicit = !r.hdr.value("Content-Length").is_empty();
            if body_allowed(r.status) && (!r.head || !explicit) {
                let mut buf = [0u8; 20];
                r.hdr
                    .set("Content-Length", fmt_dec(u64_of(body.len()), &mut buf))?;
            }
            self.write_head().await?;
            let _ = self.write_body(&body).await;
        } else if self.resp.chunked {
            if let Err(e) = self.wire.put(b"0\r\n\r\n").await {
                self.resp.remember(e);
            }
        } else if !self.resp.suppress_body() && self.resp.declared != Some(self.resp.written) {
            // Het directe pad week af van de belofte op de draad: niet
            // hergebruiken. Latere wijzigingen aan de headermap tellen niet.
            self.resp.keep_alive = false;
        }
        if let Err(e) = self.wire.flush().await {
            self.resp.remember(e);
        }
        self.resp.err.map_or(Ok(()), Err)
    }

    /// Rondt het verzoek af en zegt of de verbinding het volgende mag dragen.
    async fn settle(&mut self) -> Result<bool> {
        let fin = self.finish().await;
        if fin.is_err() || !self.resp.keep_alive || self.wire.watched {
            // Veeg vóór een nette close een ongelezen geldige body kort weg:
            // sluiten met ongelezen TCP-data kan resetten en het antwoord uit
            // de zendrij gooien.
            if fin.is_ok() && !self.wire.watched && self.body_left > 0 {
                self.wire.set_read_timeout(Some(DRAIN_TIMEOUT));
                let _ = self.discard_body().await;
            }
            return fin.map(|()| false);
        }
        // Veeg vóór hergebruik, zodat het volgende verzoek op zijn eigen regel
        // begint; lukt dat niet binnen de termijn, dan is hergebruik onveilig.
        if self.body_left > 0 {
            self.wire.set_read_timeout(Some(DRAIN_TIMEOUT));
            if self.discard_body().await.is_err() {
                return Ok(false);
            }
            self.wire.set_read_timeout(None);
        }
        Ok(true)
    }

    /// Na een handlerfout: een 500 als er nog niets verstuurd was, anders
    /// niets (een afgebroken chunked-stroom zegt de client genoeg).
    async fn fail(&mut self) {
        if self.resp.started || self.wire.hijacked {
            return;
        }
        let head = self.resp.head;
        self.resp = Resp::new(false, head);
        let _ = self.error(500, "internal server error").await;
        let _ = self.finish().await;
    }
}

/// De rauwe verbinding na [`Exchange::hijack`], zolang de handler loopt.
///
/// Lezen geeft eerst de bytes die de server al gebufferd had; schrijven gaat
/// direct naar de verbinding, zonder de termijn per write van de server.
pub struct Raw<'e, C> {
    wire: &'e mut Wire<C>,
}

impl<C: Conn> AsyncRead for Raw<'_, C> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        let have = self.wire.rbuf.buffered();
        if !have.is_empty() {
            let n = have.len().min(buf.len());
            buf.get_mut(..n)
                .unwrap_or(&mut [])
                .copy_from_slice(have.get(..n).unwrap_or(&[]));
            self.wire.rbuf.consume(n);
            return Poll::Ready(Ok(n));
        }
        self.wire.conn.poll_read(cx, buf)
    }

    fn set_read_timeout(&mut self, t: Option<Duration>) -> core::result::Result<(), IoError> {
        self.wire.conn.set_read_timeout(t)
    }
}

impl<C: Conn> AsyncWrite for Raw<'_, C> {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        self.wire.conn.poll_write(cx, buf)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        self.wire.conn.poll_flush(cx)
    }

    fn set_write_timeout(&mut self, t: Option<Duration>) -> core::result::Result<(), IoError> {
        self.wire.conn.set_write_timeout(t)
    }
}
