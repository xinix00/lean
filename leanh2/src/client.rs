//! De clientrol, minimaal: één verzoek per verbinding.
//!
//! Er is één gemeten gebruiker: een push via APNs (`api.push.apple.com`),
//! dat alleen HTTP/2 spreekt en ALPN `h2` eist. Een push is één verzoek met
//! een body van hoogstens 4 KiB en een kort antwoord. Daarvoor volstaat één
//! stream op een verbinding die de aanroeper al opende, met TLS en ALPN `h2`
//! (`leantls::connect_with`); deze crate weet van TLS niets.
//!
//! [`send`] schrijft de preface en SETTINGS, wacht op de SETTINGS van de
//! server zodat het venster telt dat die echt geeft, stuurt HEADERS en DATA
//! op stream 1 in één keer, en leest tot het antwoord op stream 1 compleet
//! is. Daarna gaat er een beleefde GOAWAY uit; de verbinding is dan op en de
//! aanroeper sluit haar.
//!
//! Bewust weg: meer verzoeken of streams per verbinding, push, een
//! verzoekbody die op flow control zou moeten wachten (die faalt vooraf in
//! plaats van te blokkeren), betekenis voor trailers (ze worden gedecodeerd
//! voor de HPACK-tabel en weggegooid) en elke vorm van herhalen. Wat de
//! server stuurt, wordt even streng gelezen als in de serverrol.
//!
//! Een deadline zet de aanroeper door de future te laten vallen: een server
//! die blijft pingen zonder te antwoorden, houdt [`send`] anders vast.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::future::poll_fn;
use core::pin::Pin;

use crate::conn::{push_head, strip_padding};
use crate::hpack::{self, Decoder, Field};
use crate::stream::{
    content_length, is_connection_field, valid_field_value, valid_lower_token, valid_token,
};
use crate::{
    AsyncRead, AsyncWrite, CLIENT_PREFACE, CODE_NO_ERROR, Error, FLAG_ACK, FLAG_END_HEADERS,
    FLAG_END_STREAM, FLAG_PRIORITY, FRAME_CONTINUATION, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS,
    FRAME_PING, FRAME_PRIORITY, FRAME_PUSH_PROMISE, FRAME_RST_STREAM, FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE, MAX_COMPRESSED_HEADERS, OUR_MAX_FRAME, OUR_MAX_HEADER_LIST,
    SETTING_ENABLE_PUSH, SETTING_INITIAL_WINDOW_SIZE, SETTING_MAX_FRAME_SIZE,
    SETTING_MAX_HEADER_LIST_SIZE, WINDOW_MAX,
};

/// De enige stream van deze client.
const STREAM: u32 = 1;

/// Het standaardvenster (RFC 9113 §6.9.2). Deze client kondigt geen ander
/// aan, en het verbindingsvenster van de server begint ook hier.
const DEFAULT_WINDOW: i64 = 65_535;

/// Eén verzoek. `:scheme` is altijd `https`: HTTP/2 zonder TLS (`h2c`) is
/// er niet.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// De methode, zoals `POST`. `CONNECT` wordt geweigerd.
    pub method: &'a str,
    /// De host, eventueel met poort, zoals `api.push.apple.com`.
    pub authority: &'a str,
    /// Het pad met eventuele query; begint met `/`.
    pub path: &'a str,
    /// De gewone velden. Namen gaan in kleine letters de draad op;
    /// verbindingsspecifieke velden en `host` worden geweigerd.
    pub header: &'a [(&'a str, &'a str)],
    /// De body; moet in het beginvenster van de server passen.
    pub body: &'a [u8],
}

/// Grenzen op het antwoord. Wat erboven komt, is een fout en geen afgekapt
/// antwoord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// De gedecodeerde koplijst in bytes, geteld zoals HPACK (naam, waarde
    /// en 32 per veld); hoogstens 64 KiB, en minstens 1.
    pub header_list: usize,
    /// De body in bytes.
    pub body: usize,
}

impl Default for Limits {
    /// 16 KiB koppen en 64 KiB body: ruim voor een APNs-antwoord, dat
    /// hoogstens een korte JSON-reden draagt.
    fn default() -> Self {
        Self {
            header_list: 16 << 10,
            body: 64 << 10,
        }
    }
}

/// Het antwoord op stream 1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// De eindstatus, 200 tot en met 599; 1xx-tussenantwoorden zijn al
    /// overgeslagen.
    pub status: u16,
    /// De gewone velden, namen in kleine letters, in ontvangstvolgorde.
    pub header: Vec<(String, String)>,
    /// De body.
    pub body: Vec<u8>,
}

impl Response {
    /// De eerste waarde van een veld (naam in kleine letters), als die er is.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.header
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Waarom [`send`] geen antwoord gaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError<E> {
    /// Het transport faalde.
    Transport(E),
    /// Een regel van de verbinding die deze crate ook als server bewaakt:
    /// framing, SETTINGS, PING, HPACK, vensters, of een peer die sloot.
    Protocol(Error),
    /// De server stopt de verbinding voordat het antwoord compleet was.
    /// `last_stream` 0 betekent dat het verzoek niet verwerkt is en veilig
    /// opnieuw kan; een GOAWAY met NO_ERROR die stream 1 nog belooft af te
    /// maken, is geen fout.
    GoAway {
        /// De foutcode van de server.
        code: u32,
        /// De hoogste stream die de server nog afmaakt.
        last_stream: u32,
    },
    /// De server resette stream 1.
    Reset {
        /// De foutcode van de server, zoals REFUSED_STREAM (7).
        code: u32,
    },
    /// Een frame op een stream die deze client niet opende, of op stream 1
    /// in een toestand waarin het niet kan komen.
    Unexpected {
        /// Het frametype.
        frame: u8,
        /// De stream.
        stream: u32,
    },
    /// Een antwoord dat de regels van RFC 9113 §8 breekt.
    Malformed(&'static str),
    /// De body van het antwoord is groter dan [`Limits::body`].
    BodyTooLarge {
        /// De grens.
        limit: usize,
    },
    /// Het verzoek kan zo niet de draad op; er is niets verstuurd.
    Request(&'static str),
    /// De verzoekbody past niet in het venster dat de server gaf, en deze
    /// client wacht niet op meer. Er ging geen HEADERS uit.
    BodyAboveWindow {
        /// De lengte van de body.
        len: usize,
        /// Het venster.
        window: u32,
    },
}

impl<E> From<Error> for SendError<E> {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

impl<E: fmt::Display> fmt::Display for SendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "leanh2: transport: {e}"),
            Self::Protocol(e) => e.fmt(f),
            Self::GoAway { code, last_stream } => write!(
                f,
                "leanh2: the server sent GOAWAY (code {code}, last stream {last_stream})"
            ),
            Self::Reset { code } => write!(f, "leanh2: the server reset the stream (code {code})"),
            Self::Unexpected { frame, stream } => write!(
                f,
                "leanh2: unexpected frame type 0x{frame:02x} on stream {stream}"
            ),
            Self::Malformed(why) => write!(f, "leanh2: malformed response: {why}"),
            Self::BodyTooLarge { limit } => {
                write!(f, "leanh2: response body above the {limit} byte limit")
            }
            Self::Request(why) => write!(f, "leanh2: request refused: {why}"),
            Self::BodyAboveWindow { len, window } => write!(
                f,
                "leanh2: request body of {len} bytes does not fit the window of {window}"
            ),
        }
    }
}

/// De transportfout van `T`.
type IoError<T> = <T as AsyncRead>::Error;

/// Stuurt één verzoek over `io` en geeft het antwoord.
///
/// `io` is een open verbinding waarop de aanroeper HTTP/2 al koos, voor TLS
/// met ALPN `h2`. Na de terugkeer is de verbinding op: er ging een GOAWAY uit
/// (of het antwoord was er al en die poging faalde), en de aanroeper sluit
/// het transport, met een TLS close_notify als hij die wil.
///
/// Elke fout eindigt de verbinding; er gaat dan niets meer uit. Een
/// verzoekfout ([`SendError::Request`]) valt vóór de eerste byte.
pub async fn send<T>(
    io: &mut T,
    request: &Request<'_>,
    limits: &Limits,
) -> Result<Response, SendError<IoError<T>>>
where
    T: AsyncRead + AsyncWrite<Error = <T as AsyncRead>::Error> + Unpin,
{
    let block = encode_request(request)?;
    let mut c = Client::new(limits, request.method == "HEAD")?;
    c.start(limits)?;
    c.drive(io, |c| c.peer_settings).await?;
    c.request(&block, request.body)?;
    c.drive(io, |c| c.done).await?;
    // Beleefd afsluiten. Het antwoord is compleet; een schrijffout hier
    // verandert daar niets meer aan.
    let mut goaway = [0u8; 8];
    goaway[4..].copy_from_slice(&CODE_NO_ERROR.to_be_bytes());
    if c.frame(FRAME_GOAWAY, 0, 0, &goaway).is_ok() {
        let _ = c.flush(io).await;
    }
    Ok(core::mem::take(&mut c.response))
}

/// De toestand van één verbinding met één stream.
struct Client {
    /// Invoerbuffer: precies één maximaal frame met kop.
    inbuf: Vec<u8>,
    /// Hoeveel van `inbuf` gevuld is.
    in_len: usize,
    /// Uitvoer die op het transport wacht.
    out: Vec<u8>,
    /// De HPACK-tabel van de server.
    dec: Decoder,
    /// De grens op de body.
    body_limit: usize,
    /// Het verzoek was HEAD: content-length beschrijft dan geen DATA.
    head: bool,
    /// De SETTINGS van de server zijn binnen.
    peer_settings: bool,
    /// De server bevestigde onze SETTINGS.
    settings_acked: bool,
    /// De INITIAL_WINDOW_SIZE van de server.
    peer_initial_window: i64,
    /// HEADERS van stream 1 is de deur uit.
    sent: bool,
    /// Er is een header-blok open; alleen CONTINUATION op stream 1 mag.
    open_block: bool,
    /// Het open blok eindigt de stream.
    block_end_stream: bool,
    /// Het gecomprimeerde blok dat nog groeit.
    header_buf: Vec<u8>,
    /// De eindkoppen zijn binnen; nu DATA of trailers.
    final_headers: bool,
    /// Stream 1 is compleet.
    done: bool,
    /// Ons ontvangstvenster op stream 1.
    recv_stream: i64,
    /// Ons ontvangstvenster op de verbinding.
    recv_conn: i64,
    /// De content-length van het antwoord, als die er was.
    content_length: Option<u64>,
    /// Het antwoord tot nu toe.
    response: Response,
}

impl Client {
    /// Een verse toestand met de invoerbuffer gealloceerd.
    fn new(limits: &Limits, head: bool) -> Result<Self, Error> {
        let mut inbuf = Vec::new();
        inbuf
            .try_reserve_exact(9 + OUR_MAX_FRAME)
            .map_err(|_| Error::OutOfMemory)?;
        inbuf.resize(9 + OUR_MAX_FRAME, 0);
        Ok(Self {
            inbuf,
            in_len: 0,
            out: Vec::new(),
            // Nul zou de decoder onbegrensd maken.
            dec: Decoder::new(4096, limits.header_list.clamp(1, OUR_MAX_HEADER_LIST)),
            body_limit: limits.body,
            head,
            peer_settings: false,
            settings_acked: false,
            peer_initial_window: DEFAULT_WINDOW,
            sent: false,
            open_block: false,
            block_end_stream: false,
            header_buf: Vec::new(),
            final_headers: false,
            done: false,
            recv_stream: DEFAULT_WINDOW,
            recv_conn: DEFAULT_WINDOW,
            content_length: None,
            response: Response::default(),
        })
    }

    /// De preface en onze SETTINGS: geen push, en de koplijstgrens.
    fn start(&mut self, limits: &Limits) -> Result<(), Error> {
        self.out
            .try_reserve(CLIENT_PREFACE.len())
            .map_err(|_| Error::OutOfMemory)?;
        self.out.extend_from_slice(CLIENT_PREFACE);
        let list = limits.header_list.clamp(1, OUR_MAX_HEADER_LIST) as u32;
        let mut body = [0u8; 12];
        let settings = [
            (SETTING_ENABLE_PUSH, 0),
            (SETTING_MAX_HEADER_LIST_SIZE, list),
        ];
        for (dst, (id, v)) in body.chunks_exact_mut(6).zip(settings) {
            dst[..2].copy_from_slice(&id.to_be_bytes());
            dst[2..].copy_from_slice(&v.to_be_bytes());
        }
        self.frame(FRAME_SETTINGS, 0, 0, &body)
    }

    /// Zet HEADERS (met CONTINUATION) en DATA voor stream 1 klaar, of weigert
    /// een body die niet in het venster past.
    fn request<E>(&mut self, block: &[u8], body: &[u8]) -> Result<(), SendError<E>> {
        let window = self.peer_initial_window.min(DEFAULT_WINDOW);
        if i64::try_from(body.len()).map_or(true, |n| n > window) {
            return Err(SendError::BodyAboveWindow {
                len: body.len(),
                window: u32::try_from(window).unwrap_or(0),
            });
        }
        let end = if body.is_empty() { FLAG_END_STREAM } else { 0 };
        // Elke peer neemt frames tot 16 KiB, de RFC-vloer.
        let mut chunks = block.chunks(OUR_MAX_FRAME).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let last = chunks.peek().is_none();
        self.frame(
            FRAME_HEADERS,
            end | if last { FLAG_END_HEADERS } else { 0 },
            STREAM,
            first,
        )?;
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let flags = if last { FLAG_END_HEADERS } else { 0 };
            self.frame(FRAME_CONTINUATION, flags, STREAM, chunk)?;
        }
        let mut parts = body.chunks(OUR_MAX_FRAME).peekable();
        while let Some(part) = parts.next() {
            let flags = if parts.peek().is_none() {
                FLAG_END_STREAM
            } else {
                0
            };
            self.frame(FRAME_DATA, flags, STREAM, part)?;
        }
        self.sent = true;
        Ok(())
    }

    /// Verwerkt, schrijft en leest tot `until` waar is.
    async fn drive<T>(
        &mut self,
        io: &mut T,
        until: fn(&Self) -> bool,
    ) -> Result<(), SendError<IoError<T>>>
    where
        T: AsyncRead + AsyncWrite<Error = <T as AsyncRead>::Error> + Unpin,
    {
        loop {
            self.parse(until)?;
            self.flush(io).await?;
            if until(self) {
                return Ok(());
            }
            self.fill(io).await?;
        }
    }

    /// Leest wat het transport heeft; het einde van de stroom is een fout.
    async fn fill<T>(&mut self, io: &mut T) -> Result<(), SendError<IoError<T>>>
    where
        T: AsyncRead + Unpin,
    {
        // `parse` laat hoogstens een half frame staan, dus er is altijd plek.
        let Some(spare) = self.inbuf.get_mut(self.in_len..).filter(|s| !s.is_empty()) else {
            return Err(Error::FrameTooLarge { len: self.in_len }.into());
        };
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_read(cx, spare))
            .await
            .map_err(SendError::Transport)?;
        if n == 0 {
            return Err(Error::PeerClosed.into());
        }
        self.in_len += n;
        Ok(())
    }

    /// Schrijft de uitvoer helemaal weg.
    async fn flush<T>(&mut self, io: &mut T) -> Result<(), SendError<<T as AsyncWrite>::Error>>
    where
        T: AsyncWrite + Unpin,
    {
        let mut pos = 0;
        while let Some(rest) = self.out.get(pos..).filter(|r| !r.is_empty()) {
            let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, rest))
                .await
                .map_err(SendError::Transport)?;
            if n == 0 {
                return Err(Error::WriteZero.into());
            }
            pos += n.min(rest.len());
        }
        self.out.clear();
        Ok(())
    }

    /// Verwerkt complete frames uit de invoerbuffer tot `until` waar is. Wat
    /// na de SETTINGS van de server al binnen is, wacht zo tot het verzoek
    /// de deur uit is.
    fn parse<E>(&mut self, until: fn(&Self) -> bool) -> Result<(), SendError<E>> {
        // De buffer even lenen, zodat een frame-inhoud en `self` samen kunnen.
        let inbuf = core::mem::take(&mut self.inbuf);
        let r = self.parse_from(&inbuf, until);
        self.inbuf = inbuf;
        let at = r?;
        self.inbuf.copy_within(at..self.in_len, 0);
        self.in_len -= at;
        Ok(())
    }

    /// Het werk van [`Client::parse`]; geeft de verwerkte bytes.
    fn parse_from<E>(
        &mut self,
        inbuf: &[u8],
        until: fn(&Self) -> bool,
    ) -> Result<usize, SendError<E>> {
        let mut at = 0usize;
        while !until(self) {
            let avail = inbuf.get(at..self.in_len).unwrap_or(&[]);
            let Some(head) = avail.get(..9) else { break };
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            // Wij kondigen geen grotere frames aan dan de RFC-vloer.
            if len > OUR_MAX_FRAME {
                return Err(Error::FrameTooLarge { len }.into());
            }
            let Some(payload) = avail.get(9..9 + len) else {
                break;
            };
            let (typ, flags) = (head[3], head[4]);
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            self.dispatch(typ, flags, stream, payload)?;
            at += 9 + len;
        }
        Ok(at)
    }

    /// Verwerkt één frame van de server.
    fn dispatch<E>(
        &mut self,
        typ: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> Result<(), SendError<E>> {
        // De preface van de server is één SETTINGS-frame (RFC 9113 §3.4).
        if !self.peer_settings {
            if typ != FRAME_SETTINGS || stream != 0 || flags & FLAG_ACK != 0 {
                return Err(Error::FirstFrameNotSettings.into());
            }
            self.peer_settings = true;
        }
        // Een header-blok is één eenheid: zolang het open is, mag er niets anders.
        if self.open_block {
            if typ != FRAME_CONTINUATION || stream != STREAM {
                return Err(Error::HeaderBlockInterrupted {
                    frame: typ,
                    stream,
                    open: STREAM,
                }
                .into());
            }
        } else if typ == FRAME_CONTINUATION {
            return Err(Error::ContinuationWithoutBlock.into());
        }
        match typ {
            FRAME_SETTINGS => self.on_settings(flags, stream, payload),
            FRAME_PING => {
                if stream != 0 || payload.len() != 8 {
                    return Err(Error::BadPing {
                        len: payload.len(),
                        stream,
                    }
                    .into());
                }
                if flags & FLAG_ACK == 0 {
                    self.frame(FRAME_PING, FLAG_ACK, 0, payload)?;
                }
                Ok(())
            }
            // Na de body stuurt deze client niets meer: krediet is betekenisloos.
            FRAME_WINDOW_UPDATE => {
                if payload.len() != 4 {
                    return Err(Error::WindowUpdateMalformed.into());
                }
                Ok(())
            }
            FRAME_PRIORITY => {
                if stream == 0 || payload.len() != 5 {
                    return Err(Error::BadPriority {
                        len: payload.len(),
                        stream,
                    }
                    .into());
                }
                Ok(())
            }
            FRAME_PUSH_PROMISE => Err(Error::PushPromise.into()),
            FRAME_GOAWAY => {
                let (Some(last), Some(code), 0) = (payload.get(..4), payload.get(4..8), stream)
                else {
                    return Err(Error::BadGoAway {
                        len: payload.len(),
                        stream,
                    }
                    .into());
                };
                let last = u32::from_be_bytes([last[0], last[1], last[2], last[3]]) & 0x7fff_ffff;
                let code = u32::from_be_bytes([code[0], code[1], code[2], code[3]]);
                // Een nette stop die stream 1 nog afmaakt: verder lezen.
                if code == CODE_NO_ERROR && last >= STREAM && self.sent {
                    return Ok(());
                }
                Err(SendError::GoAway {
                    code,
                    last_stream: last,
                })
            }
            FRAME_RST_STREAM => {
                let ([a, b, c, d], false) = (payload, stream == 0) else {
                    return Err(Error::BadRstStream {
                        len: payload.len(),
                        stream,
                    }
                    .into());
                };
                if stream != STREAM || !self.sent {
                    return Err(Error::RstOnIdle { stream }.into());
                }
                Err(SendError::Reset {
                    code: u32::from_be_bytes([*a, *b, *c, *d]),
                })
            }
            FRAME_HEADERS => self.on_headers(flags, stream, payload),
            FRAME_CONTINUATION => self.on_block(flags, payload),
            FRAME_DATA => self.on_data(flags, stream, payload),
            // Onbekende types worden genegeerd, zoals de RFC eist.
            _ => Ok(()),
        }
    }

    /// SETTINGS van de server, of zijn bevestiging van de onze.
    fn on_settings<E>(
        &mut self,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> Result<(), SendError<E>> {
        if stream != 0 {
            return Err(Error::SettingsOnStream.into());
        }
        if flags & FLAG_ACK != 0 {
            if !payload.is_empty() {
                return Err(Error::SettingsAckPayload.into());
            }
            if self.settings_acked {
                return Err(Error::SettingsAckDuplicate.into());
            }
            self.settings_acked = true;
            return Ok(());
        }
        if !payload.len().is_multiple_of(6) {
            return Err(Error::SettingsMalformed.into());
        }
        for entry in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let v = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                SETTING_INITIAL_WINDOW_SIZE => {
                    if i64::from(v) > WINDOW_MAX {
                        return Err(Error::InitialWindowTooLarge.into());
                    }
                    self.peer_initial_window = i64::from(v);
                }
                SETTING_ENABLE_PUSH if v > 1 => return Err(Error::EnablePushInvalid.into()),
                SETTING_MAX_FRAME_SIZE if !(16_384..=(1 << 24) - 1).contains(&v) => {
                    return Err(Error::MaxFrameSizeInvalid.into());
                }
                // Onze uitvoer blijft op 16 KiB en onze encoder heeft geen
                // dynamische tabel; de rest raakt deze client niet.
                _ => {}
            }
        }
        self.frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
        Ok(())
    }

    /// HEADERS: het begin van een header-blok op stream 1.
    fn on_headers<E>(&mut self, flags: u8, stream: u32, raw: &[u8]) -> Result<(), SendError<E>> {
        if stream == 0 {
            return Err(Error::HeadersOnStreamZero.into());
        }
        if stream != STREAM || !self.sent {
            return Err(SendError::Unexpected {
                frame: FRAME_HEADERS,
                stream,
            });
        }
        let mut block = strip_padding(raw, flags)?;
        if flags & FLAG_PRIORITY != 0 {
            // Het prioriteitsveld wordt gelezen en genegeerd.
            block = block.get(5..).ok_or(Error::HeadersPriorityMalformed)?;
        }
        self.header_buf.clear();
        self.open_block = true;
        self.block_end_stream = flags & FLAG_END_STREAM != 0;
        self.on_block(flags, block)
    }

    /// Een stuk header-blok; bij END_HEADERS wordt het gedecodeerd.
    fn on_block<E>(&mut self, flags: u8, part: &[u8]) -> Result<(), SendError<E>> {
        if self.header_buf.len() + part.len() > MAX_COMPRESSED_HEADERS {
            return Err(Error::HeaderBlockTooLarge { stream: STREAM }.into());
        }
        self.header_buf
            .try_reserve(part.len())
            .map_err(|_| Error::OutOfMemory)?;
        self.header_buf.extend_from_slice(part);
        if flags & FLAG_END_HEADERS == 0 {
            return Ok(());
        }
        self.open_block = false;
        let fields = self
            .dec
            .decode(&self.header_buf)
            .map_err(|cause| Error::HeaderBlock {
                stream: STREAM,
                cause,
            })?;
        self.header_buf.clear();
        let end = self.block_end_stream;
        if self.final_headers {
            // Trailers: alleen als slot van de stream, en zonder betekenis hier.
            if !end {
                return Err(SendError::Malformed("trailers without END_STREAM"));
            }
            if fields.iter().any(|f| f.name.starts_with(':')) {
                return Err(SendError::Malformed("a pseudo-header in trailers"));
            }
            return self.complete();
        }
        let (status, header) = response_head(fields)?;
        match status {
            101 => return Err(SendError::Malformed("101 does not exist in HTTP/2")),
            100..=199 => {
                // Een tussenantwoord; het eindantwoord volgt nog.
                if end {
                    return Err(SendError::Malformed("an interim response ended the stream"));
                }
                return Ok(());
            }
            200..=599 => {}
            _ => return Err(SendError::Malformed("a status outside 100..599")),
        }
        self.content_length = content_length(&header)
            .map_err(|_| SendError::Malformed("an invalid content-length"))?;
        self.response.status = status;
        self.response.header = header;
        self.final_headers = true;
        if end {
            return self.complete();
        }
        Ok(())
    }

    /// DATA op stream 1: eerst beide vensters, dan de grens, dan pas aannemen.
    fn on_data<E>(&mut self, flags: u8, stream: u32, raw: &[u8]) -> Result<(), SendError<E>> {
        if stream == 0 {
            return Err(Error::DataOnStreamZero.into());
        }
        if stream != STREAM || !self.final_headers {
            return Err(SendError::Unexpected {
                frame: FRAME_DATA,
                stream,
            });
        }
        let content = strip_padding(raw, flags)?;
        // Het flow-gecontroleerde deel is de hele inhoud, met opvulling.
        let n = raw.len() as i64;
        if n > self.recv_conn {
            return Err(Error::ConnectionReceiveWindow.into());
        }
        if n > self.recv_stream {
            return Err(Error::StreamReceiveWindow { stream }.into());
        }
        self.recv_conn -= n;
        self.recv_stream -= n;
        let body = &mut self.response.body;
        if body.len() + content.len() > self.body_limit {
            return Err(SendError::BodyTooLarge {
                limit: self.body_limit,
            });
        }
        body.try_reserve(content.len())
            .map_err(|_| Error::OutOfMemory)?;
        body.extend_from_slice(content);
        if flags & FLAG_END_STREAM != 0 {
            return self.complete();
        }
        // Krediet meteen terug: de grens op de body begrenst het geheugen al.
        if n > 0 {
            let inc = (n as u32).to_be_bytes();
            self.frame(FRAME_WINDOW_UPDATE, 0, STREAM, &inc)?;
            self.frame(FRAME_WINDOW_UPDATE, 0, 0, &inc)?;
            self.recv_conn += n;
            self.recv_stream += n;
        }
        Ok(())
    }

    /// Stream 1 is af. Een content-length moet dan precies kloppen.
    fn complete<E>(&mut self) -> Result<(), SendError<E>> {
        let bodyless = self.head || matches!(self.response.status, 204 | 304);
        if let Some(len) = self.content_length
            && !bodyless
            && len != self.response.body.len() as u64
        {
            return Err(SendError::Malformed(
                "content-length does not match the body",
            ));
        }
        self.done = true;
        Ok(())
    }

    /// Zet één frame in de uitvoer.
    fn frame(&mut self, typ: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<(), Error> {
        self.out
            .try_reserve(9 + payload.len())
            .map_err(|_| Error::OutOfMemory)?;
        push_head(&mut self.out, payload.len(), typ, flags, stream);
        self.out.extend_from_slice(payload);
        Ok(())
    }
}

/// Gewone velden: naam in kleine letters en waarde.
type Fields = Vec<(String, String)>;

/// Status en gewone velden uit een antwoordblok: precies één `:status`,
/// vooraan, en verder alleen geldige gewone velden (RFC 9113 §8.3.2).
fn response_head<E>(fields: Vec<Field>) -> Result<(u16, Fields), SendError<E>> {
    let mut status = None;
    let mut header: Fields = Vec::new();
    header
        .try_reserve(fields.len())
        .map_err(|_| Error::OutOfMemory)?;
    for f in fields {
        if let Some(pseudo) = f.name.strip_prefix(':') {
            if !header.is_empty() {
                return Err(SendError::Malformed(
                    "a pseudo-header after a regular field",
                ));
            }
            if pseudo != "status" {
                return Err(SendError::Malformed("a pseudo-header other than :status"));
            }
            if status.is_some() {
                return Err(SendError::Malformed("more than one :status"));
            }
            status =
                Some(parse_status(&f.value).ok_or(SendError::Malformed("an invalid :status"))?);
            continue;
        }
        if !valid_lower_token(&f.name) {
            return Err(SendError::Malformed(
                "a field name that is not a lowercase token",
            ));
        }
        if !valid_field_value(&f.value) {
            return Err(SendError::Malformed("an invalid field value"));
        }
        if is_connection_field(&f.name) {
            return Err(SendError::Malformed("a connection-specific field"));
        }
        header.push((f.name, f.value));
    }
    let status = status.ok_or(SendError::Malformed("no :status"))?;
    Ok((status, header))
}

/// Precies drie cijfers, 100 tot en met 999.
fn parse_status(s: &str) -> Option<u16> {
    let [a, b, c] = s.as_bytes() else {
        return None;
    };
    if !(b'1'..=b'9').contains(a) || !b.is_ascii_digit() || !c.is_ascii_digit() {
        return None;
    }
    Some(u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'))
}

/// Controleert en codeert het verzoek, voordat er een byte de draad op gaat.
fn encode_request<E>(r: &Request<'_>) -> Result<Vec<u8>, SendError<E>> {
    if !valid_token(r.method) || r.method == "CONNECT" {
        return Err(SendError::Request(
            "the method is not a token, or is CONNECT",
        ));
    }
    if r.authority.is_empty() || r.authority.contains(' ') || !valid_field_value(r.authority) {
        return Err(SendError::Request("the authority is empty or invalid"));
    }
    if !r.path.starts_with('/') || r.path.contains(' ') || !valid_field_value(r.path) {
        return Err(SendError::Request(
            "the path must start with / and hold no space",
        ));
    }
    let mut block = Vec::new();
    let mut total = 0usize;
    let mut field = |name: &str, value: &str| -> Result<(), SendError<E>> {
        total += name.len() + value.len() + 32;
        if total > OUR_MAX_HEADER_LIST {
            return Err(SendError::Request("the header list is above 64 KiB"));
        }
        hpack::encode(&mut block, name, value).map_err(|_| Error::OutOfMemory)?;
        Ok(())
    };
    field(":method", r.method)?;
    field(":scheme", "https")?;
    field(":authority", r.authority)?;
    field(":path", r.path)?;
    let mut name = String::new();
    for &(raw, value) in r.header {
        name.clear();
        name.try_reserve(raw.len())
            .map_err(|_| Error::OutOfMemory)?;
        name.push_str(raw);
        name.make_ascii_lowercase();
        if !valid_lower_token(&name) {
            return Err(SendError::Request("a field name is not a token"));
        }
        // `host` hoort in `:authority`; twee bronnen voor één naam bestaan niet.
        if is_connection_field(&name) || name == "host" {
            return Err(SendError::Request("a connection-specific or host field"));
        }
        if name == "te" && value != "trailers" {
            return Err(SendError::Request("te other than trailers"));
        }
        if !valid_field_value(value) {
            return Err(SendError::Request("a field value is invalid"));
        }
        if name == "content-length" && value.parse::<u64>().ok() != Some(r.body.len() as u64) {
            return Err(SendError::Request("content-length does not match the body"));
        }
        field(&name, value)?;
    }
    Ok(block)
}
