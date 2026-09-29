//! De verbinding: één taak die de draad, de streams en beide niveaus van flow
//! control bezit.
//!
//! [`Conn::serve`] leest frames, pollt de handler-futures, leegt hun
//! brievenbussen naar frames en schrijft die weg, in die volgorde, tot er
//! niets meer te doen is. Omdat alles in die ene lus gebeurt, zijn drie
//! beloftes uit KAM.md geen slotdiscipline maar bouw:
//!
//! - Een header-blok (HEADERS plus CONTINUATION) wordt in één keer aan de
//!   uitvoer toegevoegd; er kan niets tussen.
//! - Een DATA-frame claimt hetzelfde aantal bytes uit het streamvenster en het
//!   verbindingsvenster in één stap; twee streams kunnen hetzelfde krediet niet
//!   twee keer uitgeven, en een SETTINGS die het venster verlaagt valt altijd
//!   vóór of ná een claim, nooit ertussen.
//! - Een handler blokkeert de lus nooit: hij geeft `Pending` en de lus gaat
//!   door met PING, SETTINGS en de andere streams.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll};

use crate::hpack::Decoder;
use crate::stream::{self, Body, Handler, Mailbox, Request, Response};
use crate::{
    AsyncRead, AsyncWrite, CLIENT_PREFACE, CODE_INTERNAL_ERROR, CODE_NO_ERROR,
    CONNECTION_WINDOW_INCREMENT, Error, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PADDED,
    FLAG_PRIORITY, FRAME_CONTINUATION, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS, FRAME_PING,
    FRAME_PRIORITY, FRAME_PUSH_PROMISE, FRAME_RST_STREAM, FRAME_SETTINGS, FRAME_WINDOW_UPDATE,
    MAX_COMPRESSED_HEADERS, MAX_CONCURRENT_STREAMS, OUR_HEADER_TABLE_SIZE, OUR_INITIAL_WINDOW,
    OUR_MAX_FRAME, OUR_MAX_HEADER_LIST, Result, SETTING_ENABLE_PUSH, SETTING_HEADER_TABLE_SIZE,
    SETTING_INITIAL_WINDOW_SIZE, SETTING_MAX_CONCURRENT, SETTING_MAX_FRAME_SIZE,
    SETTING_MAX_HEADER_LIST_SIZE, ServeError, WINDOW_MAX,
};

/// Hoeveel ongeschreven uitvoer er mag staan voordat de lus stopt met lezen en
/// met het vullen van DATA. Zo groeit de uitvoer niet als de peer niet leest.
const OUT_HIGH: usize = 32 << 10;

/// Rondes per poll voordat de lus zichzelf wekt en de executor laat ademen.
const MAX_ROUNDS: usize = 64;

/// Een aankondiging dat deze kant stopt. Hij meldt de hoogste stream die hij
/// accepteerde en nog kan afmaken, en daarna komt er geen nieuwe stream meer
/// bij. Minder melden kan de peer werk laten herhalen dat hier nog
/// bijwerkingen heeft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAway {
    /// De foutcode, meestal NO_ERROR (0).
    code: u32,
    /// Een leesbare reden voor de logs van de peer.
    reason: &'static str,
}

impl GoAway {
    /// Een GOAWAY met code en reden; de reden moet in één frame passen.
    pub fn new(code: u32, reason: &'static str) -> Result<Self> {
        if reason.len() > OUR_MAX_FRAME - 8 {
            return Err(Error::GoAwayReasonTooLong { len: reason.len() });
        }
        Ok(Self { code, reason })
    }
}

/// Eén HTTP/2-verbinding in de serverrol.
///
/// Het transport moet één lezer en één schrijver tegelijk toestaan, en sluiten
/// moet beide wekken. De aanroeper kiest de verbinding, bezit het
/// deadlinebeleid en mag het transport zelf sluiten om te stoppen.
pub struct Conn<T, H> {
    /// Het transport.
    io: T,
    /// De handler voor elke stream.
    handler: H,
    /// `serve` draait precies één keer.
    served: bool,
}

/// De transportfout van `T`.
type IoError<T> = <T as AsyncRead>::Error;

impl<T, H> Conn<T, H>
where
    T: AsyncRead + AsyncWrite<Error = <T as AsyncRead>::Error> + Unpin,
    H: Handler,
{
    /// Omhult een volledig-duplex verbinding die al open is.
    pub fn new(io: T, handler: H) -> Self {
        Self {
            io,
            handler,
            served: false,
        }
    }

    /// Geeft transport en handler terug, bijvoorbeeld om te inspecteren.
    pub fn into_inner(self) -> (T, H) {
        (self.io, self.handler)
    }

    /// Leest de preface, wisselt SETTINGS uit en bedient frames tot de
    /// verbinding eindigt; geeft de reden. Een `Conn` bedient precies één keer.
    ///
    /// `shutdown` is de sierlijke stop: zodra hij klaar is, gaat er één GOAWAY
    /// uit en wordt geen nieuwe stream meer geaccepteerd. Hij wordt pas gepold
    /// nadat de preface gelezen en onze SETTINGS verstuurd zijn, zodat geen
    /// GOAWAY het eerste frame kan zijn. Wie nooit sierlijk stopt, geeft
    /// `core::future::pending()`.
    ///
    /// Voordat deze functie terugkeert, sluit hij het transport, krijgt elke
    /// levende handler nog één poll om de reden te zien, en worden alle streams
    /// losgelaten.
    pub async fn serve<S>(&mut self, shutdown: S) -> Result<(), ServeError<IoError<T>>>
    where
        S: Future<Output = GoAway>,
    {
        if self.served {
            return Err(ServeError::Protocol(Error::ServedTwice));
        }
        self.served = true;
        let boxes: [Mailbox; MAX_CONCURRENT_STREAMS] = core::array::from_fn(|_| Mailbox::default());
        let mut tasks: [Option<H::Future<'_>>; MAX_CONCURRENT_STREAMS] =
            core::array::from_fn(|_| None);
        let mut shutdown = pin!(shutdown);
        let io = &mut self.io;
        let handler = &mut self.handler;
        let result = match State::new() {
            Ok(mut state) => {
                let r = poll_fn(|cx| {
                    state.drive(
                        cx,
                        &mut *io,
                        &mut *handler,
                        &boxes,
                        &mut tasks,
                        shutdown.as_mut(),
                    )
                })
                .await;
                state.end_all(&boxes);
                r
            }
            Err(e) => Err(ServeError::Protocol(e)),
        };
        // Sluiten voordat er gewacht wordt: een schrijver die in het transport
        // hangt, komt pas vrij als het dicht is.
        let _ = poll_fn(|cx| Pin::new(&mut *io).poll_close(cx)).await;
        poll_fn(|cx| {
            for f in tasks.iter_mut().flatten() {
                let _ = Pin::new(f).poll(cx);
            }
            Poll::Ready(())
        })
        .await;
        for t in &mut tasks {
            *t = None;
        }
        result
    }
}

/// De draadtoestand van één stream.
#[derive(Clone, Copy)]
struct Wire {
    /// De stream-id.
    id: u32,
    /// Het venster dat de peer ons gaf; kan negatief worden na een verlaagde
    /// INITIAL_WINDOW_SIZE.
    send_win: i64,
    /// Het venster dat wij de peer gaven.
    recv_win: i64,
    /// De peer stuurde END_STREAM.
    remote_ended: bool,
    /// De content-length, als die er was.
    expected: Option<u64>,
    /// Ontvangen bodybytes zonder opvulling.
    received: u64,
    /// De handler sloot de body: de stream krijgt geen krediet meer.
    discarding: bool,
    /// De antwoordkoppen staan op de draad.
    header_out: bool,
    /// De handler is klaar: `Some(true)` netjes, `Some(false)` met een fout.
    done: Option<bool>,
}

/// Alles wat de verbinding bezit, behalve het transport en de handlers.
struct State {
    /// Invoerbuffer: precies één maximaal frame met kop.
    inbuf: Vec<u8>,
    /// Hoeveel van `inbuf` gevuld is.
    in_len: usize,
    /// Uitvoer die op het transport wacht, vanaf `out_pos`.
    out: Vec<u8>,
    /// Waar de ongeschreven uitvoer begint.
    out_pos: usize,
    /// De preface is gelezen en onze SETTINGS staan klaar.
    started: bool,
    /// Het eerste frame van de peer (SETTINGS) is binnen.
    peer_settings: bool,
    /// De peer bevestigde onze SETTINGS.
    settings_acked: bool,
    /// Wij stuurden GOAWAY: geen nieuwe streams meer.
    going_away: bool,
    /// De stop-future is afgehandeld en wordt niet meer gepold.
    shutdown_done: bool,
    /// De hoogste geaccepteerde stream-id; GOAWAY meldt hem, en hij maakt
    /// hergebruik zichtbaar.
    last_stream_id: u32,
    /// De slot-index van een open header-blok; dan is alleen CONTINUATION op
    /// die stream welkom.
    pending: Option<usize>,
    /// Het gecomprimeerde blok dat nog groeit.
    header_buf: Vec<u8>,
    /// Het verbindingsvenster dat de peer ons gaf.
    conn_send_win: i64,
    /// De INITIAL_WINDOW_SIZE van de peer.
    peer_initial_window: i64,
    /// Het verbindingsvenster dat wij de peer gaven.
    recv_win: i64,
    /// De draadtoestand per slot.
    wires: [Option<Wire>; MAX_CONCURRENT_STREAMS],
    /// Recent door ons gereset streams met hun restvenster: DATA die al
    /// onderweg was mag nog binnen dat restant landen, begrensd tot 32.
    resets: VecDeque<(u32, i64)>,
    /// De HPACK-tabel van de peer.
    dec: Decoder,
    /// Waar de volgende pomp-ronde begint, voor eerlijkheid tussen streams.
    rr: usize,
}

impl State {
    /// Een verse toestand met de buffers gealloceerd.
    fn new() -> Result<Self> {
        let mut inbuf = Vec::new();
        inbuf
            .try_reserve_exact(9 + OUR_MAX_FRAME)
            .map_err(|_| Error::OutOfMemory)?;
        inbuf.resize(9 + OUR_MAX_FRAME, 0);
        Ok(Self {
            inbuf,
            in_len: 0,
            out: Vec::new(),
            out_pos: 0,
            started: false,
            peer_settings: false,
            settings_acked: false,
            going_away: false,
            shutdown_done: false,
            last_stream_id: 0,
            pending: None,
            header_buf: Vec::new(),
            conn_send_win: 65535,
            peer_initial_window: 65535,
            recv_win: 65535,
            wires: [None; MAX_CONCURRENT_STREAMS],
            resets: VecDeque::new(),
            // De peer mag de standaardtabel gebruiken tot hij onze SETTINGS zag.
            dec: Decoder::new(4096, OUR_MAX_HEADER_LIST),
            rr: 0,
        })
    }

    /// Draait rondes tot er niets meer te doen is.
    fn drive<'b, T, H, S>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut T,
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
        mut shutdown: Pin<&mut S>,
    ) -> Poll<Result<(), ServeError<IoError<T>>>>
    where
        T: AsyncRead + AsyncWrite<Error = <T as AsyncRead>::Error> + Unpin,
        H: Handler,
        S: Future<Output = GoAway>,
    {
        for _ in 0..MAX_ROUNDS {
            match self.round(cx, io, handler, boxes, tasks, shutdown.as_mut()) {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(false) => return Poll::Pending,
                Ok(true) => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Eén ronde: lezen, frames verwerken, stoppen als dat gevraagd is,
    /// handlers pollen, brievenbussen legen, schrijven. Geeft of er iets
    /// veranderde.
    fn round<'b, T, H, S>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut T,
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
        shutdown: Pin<&mut S>,
    ) -> Result<bool, ServeError<IoError<T>>>
    where
        T: AsyncRead + AsyncWrite<Error = <T as AsyncRead>::Error> + Unpin,
        H: Handler,
        S: Future<Output = GoAway>,
    {
        let mut progress = false;
        if self.out.len() - self.out_pos < OUT_HIGH {
            progress |= self.fill(cx, io)?;
        }
        progress |= self.parse(handler, boxes, tasks)?;
        if self.started
            && !self.shutdown_done
            && let Poll::Ready(g) = shutdown.poll(cx)
        {
            self.shutdown_done = true;
            self.go_away(g)?;
            progress = true;
        }
        for (i, slot) in tasks.iter_mut().enumerate() {
            let Some(f) = slot else { continue };
            if let Poll::Ready(r) = Pin::new(f).poll(cx) {
                *slot = None;
                progress = true;
                if let Some(w) = self.wires.get_mut(i).and_then(Option::as_mut) {
                    w.done = Some(r.is_ok());
                }
            }
        }
        progress |= self.pump(boxes)?;
        progress |= self.flush(cx, io)?;
        Ok(progress)
    }

    /// Leest wat het transport heeft. Het einde van de stroom is een fout: een
    /// verbinding eindigt hier nooit "gewoon".
    fn fill<T>(&mut self, cx: &mut Context<'_>, io: &mut T) -> Result<bool, ServeError<IoError<T>>>
    where
        T: AsyncRead + Unpin,
    {
        let Some(spare) = self.inbuf.get_mut(self.in_len..).filter(|s| !s.is_empty()) else {
            return Ok(false);
        };
        match Pin::new(io).poll_read(cx, spare) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(e)) => Err(ServeError::Transport(e)),
            Poll::Ready(Ok(0)) if self.started => Err(Error::PeerClosed.into()),
            Poll::Ready(Ok(0)) => Err(Error::PrefaceEof.into()),
            Poll::Ready(Ok(n)) => {
                self.in_len += n;
                Ok(true)
            }
        }
    }

    /// Verwerkt elk compleet frame in de invoerbuffer.
    fn parse<'b, H: Handler>(
        &mut self,
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result<bool> {
        // De buffer even lenen, zodat een frame-inhoud en `self` samen kunnen.
        let inbuf = core::mem::take(&mut self.inbuf);
        let r = self.parse_from(&inbuf, handler, boxes, tasks);
        self.inbuf = inbuf;
        let (consumed, progress) = r?;
        self.inbuf.copy_within(consumed..self.in_len, 0);
        self.in_len -= consumed;
        Ok(progress)
    }

    /// Het werk van [`State::parse`]; geeft verwerkte bytes en of er iets was.
    fn parse_from<'b, H: Handler>(
        &mut self,
        inbuf: &[u8],
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result<(usize, bool)> {
        let mut at = 0usize;
        let mut progress = false;
        loop {
            let avail = inbuf.get(at..self.in_len).unwrap_or(&[]);
            if !self.started {
                let Some(preface) = avail.get(..CLIENT_PREFACE.len()) else {
                    break;
                };
                if preface != CLIENT_PREFACE {
                    return Err(Error::BadPreface);
                }
                at += CLIENT_PREFACE.len();
                self.start()?;
                progress = true;
                continue;
            }
            let Some(head) = avail.get(..9) else { break };
            let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            if len > OUR_MAX_FRAME {
                return Err(Error::FrameTooLarge { len });
            }
            let Some(payload) = avail.get(9..9 + len) else {
                break;
            };
            let (typ, flags) = (head[3], head[4]);
            let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            self.dispatch(typ, flags, stream, payload, handler, boxes, tasks)?;
            at += 9 + len;
            progress = true;
        }
        Ok((at, progress))
    }

    /// Na de preface: onze SETTINGS, en één keer het verbindingsvenster omhoog.
    /// De streamvensters zijn klein met opzet; zonder die ophoging wordt het
    /// verbindingsniveau de flessenhals voor gelijktijdige uploads.
    fn start(&mut self) -> Result {
        let mut body = [0u8; 36];
        let settings: [(u16, u32); 6] = [
            (SETTING_HEADER_TABLE_SIZE, OUR_HEADER_TABLE_SIZE),
            (SETTING_ENABLE_PUSH, 0),
            (SETTING_MAX_CONCURRENT, MAX_CONCURRENT_STREAMS as u32),
            (SETTING_INITIAL_WINDOW_SIZE, OUR_INITIAL_WINDOW),
            (SETTING_MAX_FRAME_SIZE, OUR_MAX_FRAME as u32),
            (SETTING_MAX_HEADER_LIST_SIZE, OUR_MAX_HEADER_LIST as u32),
        ];
        for (dst, (id, v)) in body.chunks_exact_mut(6).zip(settings) {
            dst[..2].copy_from_slice(&id.to_be_bytes());
            dst[2..].copy_from_slice(&v.to_be_bytes());
        }
        self.frame(FRAME_SETTINGS, 0, 0, &body)?;
        self.frame(
            FRAME_WINDOW_UPDATE,
            0,
            0,
            &CONNECTION_WINDOW_INCREMENT.to_be_bytes(),
        )?;
        self.recv_win += i64::from(CONNECTION_WINDOW_INCREMENT);
        self.started = true;
        Ok(())
    }

    /// Stuurt onze GOAWAY met de hoogste geaccepteerde stream.
    fn go_away(&mut self, g: GoAway) -> Result {
        self.going_away = true;
        let mut body = Vec::new();
        body.try_reserve(8 + g.reason.len())
            .map_err(|_| Error::OutOfMemory)?;
        body.extend_from_slice(&(self.last_stream_id & 0x7fff_ffff).to_be_bytes());
        body.extend_from_slice(&g.code.to_be_bytes());
        body.extend_from_slice(g.reason.as_bytes());
        self.frame(FRAME_GOAWAY, 0, 0, &body)
    }

    /// Verwerkt één frame van de peer.
    #[expect(
        clippy::too_many_arguments,
        reason = "de frame-velden plus de drie eigenaren"
    )]
    fn dispatch<'b, H: Handler>(
        &mut self,
        typ: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result {
        if !self.peer_settings {
            if typ != FRAME_SETTINGS || stream != 0 || flags & FLAG_ACK != 0 {
                return Err(Error::FirstFrameNotSettings);
            }
            self.peer_settings = true;
        }
        // Een header-blok is één eenheid: zolang het open is, mag er niets anders.
        if let Some(open) = self.pending.and_then(|i| self.wire(i)).map(|w| w.id) {
            if typ != FRAME_CONTINUATION || stream != open {
                return Err(Error::HeaderBlockInterrupted {
                    frame: typ,
                    stream,
                    open,
                });
            }
        } else if typ == FRAME_CONTINUATION {
            return Err(Error::ContinuationWithoutBlock);
        }
        match typ {
            FRAME_SETTINGS => self.on_settings(flags, stream, payload),
            FRAME_PING => {
                if stream != 0 || payload.len() != 8 {
                    return Err(Error::BadPing {
                        len: payload.len(),
                        stream,
                    });
                }
                if flags & FLAG_ACK != 0 {
                    return Ok(());
                }
                // Antwoorden telt zwaarder dan het lijkt: een peer die zo leven
                // meet, kan alle streams achterhouden tot hij de ACK ziet. De
                // Cloudflare-edge is zo'n peer (gemeten 19-08-2026).
                self.frame(FRAME_PING, FLAG_ACK, 0, payload)
            }
            FRAME_WINDOW_UPDATE => self.on_window_update(stream, payload),
            FRAME_HEADERS => self.on_headers(flags, stream, payload, handler, boxes, tasks),
            FRAME_CONTINUATION => {
                self.on_continuation(flags, stream, payload, handler, boxes, tasks)
            }
            FRAME_DATA => self.on_data(flags, stream, payload, boxes),
            FRAME_RST_STREAM => {
                if payload.len() != 4 || stream == 0 {
                    return Err(Error::BadRstStream {
                        len: payload.len(),
                        stream,
                    });
                }
                self.on_reset(stream, boxes)
            }
            FRAME_PUSH_PROMISE => Err(Error::PushPromise),
            FRAME_GOAWAY => {
                let code = payload
                    .get(4..8)
                    .filter(|_| stream == 0)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
                match code {
                    Some(code) => Err(Error::PeerGoAway { code }),
                    None => Err(Error::BadGoAway {
                        len: payload.len(),
                        stream,
                    }),
                }
            }
            FRAME_PRIORITY => {
                if stream == 0 || payload.len() != 5 {
                    return Err(Error::BadPriority {
                        len: payload.len(),
                        stream,
                    });
                }
                // Geaccepteerd en genegeerd: hier wordt niets geroosterd.
                Ok(())
            }
            // Onbekende types worden genegeerd, zoals de RFC eist.
            _ => Ok(()),
        }
    }

    /// SETTINGS van de peer, of zijn bevestiging van de onze.
    fn on_settings(&mut self, flags: u8, stream: u32, payload: &[u8]) -> Result {
        if stream != 0 {
            return Err(Error::SettingsOnStream);
        }
        if flags & FLAG_ACK != 0 {
            if !payload.is_empty() {
                return Err(Error::SettingsAckPayload);
            }
            if self.settings_acked {
                return Err(Error::SettingsAckDuplicate);
            }
            self.settings_acked = true;
            // Vanaf hier geldt onze tabelgrootte nul voor elk volgend blok.
            self.dec.set_allowed(OUR_HEADER_TABLE_SIZE as usize);
            return Ok(());
        }
        if !payload.len().is_multiple_of(6) {
            return Err(Error::SettingsMalformed);
        }
        for entry in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([entry[0], entry[1]]);
            let v = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match id {
                SETTING_INITIAL_WINDOW_SIZE => self.set_initial_window(v)?,
                SETTING_ENABLE_PUSH if v > 1 => return Err(Error::EnablePushInvalid),
                SETTING_MAX_FRAME_SIZE if !(16_384..=(1 << 24) - 1).contains(&v) => {
                    return Err(Error::MaxFrameSizeInvalid);
                }
                // Onze uitvoer blijft op de RFC-vloer van 16 KiB, ook als de
                // peer grotere frames toestaat.
                _ => {}
            }
        }
        self.frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])
    }

    /// Een nieuwe INITIAL_WINDOW_SIZE verschuift elk levend streamvenster met
    /// hetzelfde verschil (RFC 9113 §6.9.2).
    fn set_initial_window(&mut self, v: u32) -> Result {
        let v = i64::from(v);
        if v > WINDOW_MAX {
            return Err(Error::InitialWindowTooLarge);
        }
        let delta = v - self.peer_initial_window;
        if delta > 0
            && let Some(w) = self
                .wires
                .iter()
                .flatten()
                .find(|w| w.send_win > WINDOW_MAX - delta)
        {
            return Err(Error::InitialWindowOverflow { stream: w.id });
        }
        self.peer_initial_window = v;
        for w in self.wires.iter_mut().flatten() {
            w.send_win += delta;
        }
        Ok(())
    }

    /// Krediet van de peer, voor de verbinding of één stream.
    fn on_window_update(&mut self, stream: u32, payload: &[u8]) -> Result {
        let [a, b, c, d] = payload else {
            return Err(Error::WindowUpdateMalformed);
        };
        let inc = i64::from(u32::from_be_bytes([*a, *b, *c, *d]) & 0x7fff_ffff);
        if inc == 0 {
            return Err(Error::WindowUpdateZero);
        }
        if stream == 0 {
            if self.conn_send_win + inc > WINDOW_MAX {
                return Err(Error::ConnectionWindowOverflow);
            }
            self.conn_send_win += inc;
            return Ok(());
        }
        let Some(i) = self.find(stream) else {
            if stream.is_multiple_of(2) || stream > self.last_stream_id {
                return Err(Error::WindowUpdateIdle { stream });
            }
            // Een venster voor een gesloten stream is geen fout.
            return Ok(());
        };
        let Some(w) = self.wire_mut(i) else {
            return Ok(());
        };
        if w.send_win + inc > WINDOW_MAX {
            return Err(Error::StreamWindowOverflow { stream });
        }
        w.send_win += inc;
        Ok(())
    }

    /// Een nieuwe stream: identiteitsdiscipline, de cap, en het blok.
    fn on_headers<'b, H: Handler>(
        &mut self,
        flags: u8,
        stream: u32,
        raw: &[u8],
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result {
        if stream == 0 {
            return Err(Error::HeadersOnStreamZero);
        }
        let mut block = strip_padding(raw, flags)?;
        if flags & FLAG_PRIORITY != 0 {
            // Het prioriteitsveld wordt gelezen en genegeerd.
            block = block.get(5..).ok_or(Error::HeadersPriorityMalformed)?;
        }
        if self.going_away {
            return Err(Error::StreamAfterGoAway);
        }
        if stream.is_multiple_of(2) {
            return Err(Error::NotClientInitiated { stream });
        }
        if stream <= self.last_stream_id {
            return Err(Error::StreamNotIncreasing {
                stream,
                last: self.last_stream_id,
            });
        }
        let free = (0..MAX_CONCURRENT_STREAMS)
            .find(|&i| tasks.get(i).is_some_and(Option::is_none) && self.wire(i).is_none());
        let Some(i) = free else {
            return Err(Error::TooManyStreams);
        };
        self.last_stream_id = stream;
        if let Some(slot) = self.wires.get_mut(i) {
            *slot = Some(Wire {
                id: stream,
                send_win: self.peer_initial_window,
                recv_win: i64::from(OUR_INITIAL_WINDOW),
                remote_ended: flags & FLAG_END_STREAM != 0,
                expected: None,
                received: 0,
                discarding: false,
                header_out: false,
                done: None,
            });
        }
        self.header_buf.clear();
        append(&mut self.header_buf, block)?;
        if flags & FLAG_END_HEADERS == 0 {
            self.pending = Some(i);
            return Ok(());
        }
        self.start_stream(i, handler, boxes, tasks)
    }

    /// Het vervolg van een open header-blok.
    fn on_continuation<'b, H: Handler>(
        &mut self,
        flags: u8,
        stream: u32,
        block: &[u8],
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result {
        let Some(i) = self.pending else {
            return Err(Error::ContinuationWithoutBlock);
        };
        if self.header_buf.len() + block.len() > MAX_COMPRESSED_HEADERS {
            return Err(Error::HeaderBlockTooLarge { stream });
        }
        append(&mut self.header_buf, block)?;
        if flags & FLAG_END_HEADERS == 0 {
            return Ok(());
        }
        self.pending = None;
        self.start_stream(i, handler, boxes, tasks)
    }

    /// Decodeert het blok, toetst het verzoek en zet de handler aan het werk.
    fn start_stream<'b, H: Handler>(
        &mut self,
        i: usize,
        handler: &mut H,
        boxes: &'b [Mailbox; MAX_CONCURRENT_STREAMS],
        tasks: &mut [Option<H::Future<'b>>; MAX_CONCURRENT_STREAMS],
    ) -> Result {
        let Some(w) = self.wire(i) else {
            return Err(Error::StreamClosed);
        };
        let id = w.id;
        let fields = self
            .dec
            .decode(&self.header_buf)
            .map_err(|cause| Error::HeaderBlock { stream: id, cause })?;
        self.header_buf.clear();
        let parts =
            stream::request_from(fields).map_err(|cause| Error::Request { stream: id, cause })?;
        if w.remote_ended && parts.content_length.is_some_and(|n| n > 0) {
            return Err(Error::EndedBeforeContentLength {
                stream: id,
                len: parts.content_length.unwrap_or(0),
            });
        }
        if let Some(w) = self.wire_mut(i) {
            w.expected = parts.content_length;
        }
        let (Some(mb), Some(task)) = (boxes.get(i), tasks.get_mut(i)) else {
            return Err(Error::StreamClosed);
        };
        mb.reset(parts.method == "HEAD");
        if w.remote_ended {
            mb.with(|s| s.body_end = Some(Ok(())));
        }
        let request = Request {
            method: parts.method,
            path: parts.path,
            scheme: parts.scheme,
            authority: parts.authority,
            header: parts.header,
            stream_id: id,
            body: Body { mb },
        };
        *task = Some(handler.call(request, Response { mb }));
        Ok(())
    }

    /// DATA van de peer: eerst beide vensters debiteren, dan pas aannemen.
    fn on_data(
        &mut self,
        flags: u8,
        stream: u32,
        raw: &[u8],
        boxes: &[Mailbox; MAX_CONCURRENT_STREAMS],
    ) -> Result {
        if stream == 0 {
            return Err(Error::DataOnStreamZero);
        }
        let content = strip_padding(raw, flags)?;
        // Het flow-gecontroleerde deel is de hele inhoud, met opvullengte en
        // opvulling; een frame is hoogstens 16 KiB.
        let n = raw.len() as i64;
        let end = flags & FLAG_END_STREAM != 0;
        let slot = self.find(stream);
        if slot.is_none() && (stream.is_multiple_of(2) || stream > self.last_stream_id) {
            return Err(Error::DataOnIdle { stream });
        }
        if n > self.recv_win {
            return Err(Error::ConnectionReceiveWindow);
        }
        let Some(i) = slot else {
            // Een reset kan kruisen met DATA die al onderweg was. Die bytes
            // kostten wel verbindingskrediet; weggooien en precies dat niveau
            // teruggeven.
            let Some(entry) = self.resets.iter_mut().find(|(id, _)| *id == stream) else {
                return Err(Error::DataOnClosed { stream });
            };
            if n > entry.1 {
                return Err(Error::ResetStreamWindow { stream });
            }
            entry.1 -= n;
            self.recv_win -= n;
            if end {
                self.resets.retain(|(id, _)| *id != stream);
            }
            return self.credit(None, n);
        };
        let Some(w) = self.wire_mut(i) else {
            return Err(Error::DataOnClosed { stream });
        };
        if w.remote_ended {
            return Err(Error::DataAfterEndStream { stream });
        }
        let next = w.received + content.len() as u64;
        if let Some(len) = w.expected {
            if next > len {
                return Err(Error::BodyExceedsLength { stream, len });
            }
            if end && next != len {
                return Err(Error::BodyShort {
                    stream,
                    got: next,
                    len,
                });
            }
        }
        if n > w.recv_win {
            return Err(Error::StreamReceiveWindow { stream });
        }
        w.received = next;
        w.remote_ended |= end;
        w.recv_win -= n;
        let discarding = w.discarding;
        self.recv_win -= n;
        if discarding {
            // De handler sloot de body: weggooien en alleen de verbinding
            // crediteren. Een nette peer stopt dan bij zijn bestaande venster.
            return self.credit(None, n);
        }
        let mb = boxes.get(i).ok_or(Error::StreamClosed)?;
        let delivered = mb.with(|s| {
            if s.body_end.is_some() {
                // De handler stopte bewust met lezen; afronden reset de rest.
                return Ok(false);
            }
            if s.unread() + content.len() > stream::BODY_LIMIT {
                // Alleen bereikbaar als de peer zijn venster negeerde.
                return Err(Error::StreamReceiveWindow { stream });
            }
            if s.body_pos > 0 {
                let pos = s.body_pos;
                s.body.drain(..pos);
                s.body_pos = 0;
            }
            s.body
                .try_reserve(content.len())
                .map_err(|_| Error::OutOfMemory)?;
            s.body.extend_from_slice(content);
            if end {
                s.body_end = Some(Ok(()));
            }
            Ok(true)
        })?;
        // Krediet komt terug als de handler leest, niet bij aankomst: zo blokt
        // deze lus nooit op een handler, en begrenst het venster wat één stream
        // vasthoudt. Opvulling leest niemand, die gaat meteen terug.
        let pad = n - content.len() as i64;
        if pad > 0 {
            self.credit(Some(i), pad)?;
        }
        if !delivered {
            self.credit(None, content.len() as i64)?;
        }
        Ok(())
    }

    /// Een RST_STREAM van de peer.
    fn on_reset(&mut self, stream: u32, boxes: &[Mailbox; MAX_CONCURRENT_STREAMS]) -> Result {
        let Some(i) = self.find(stream) else {
            if stream.is_multiple_of(2) || stream > self.last_stream_id {
                return Err(Error::RstOnIdle { stream });
            }
            // Een reset voor een al gesloten stream kan op de draad kruisen.
            self.resets.retain(|(id, _)| *id != stream);
            return Ok(());
        };
        let n = self.detach(i, Error::StreamReset, false, boxes);
        self.credit(None, n)
    }

    /// Leegt de brievenbussen: krediet voor gelezen bytes, kopblokken,
    /// DATA binnen beide vensters, en afronding van klare handlers.
    fn pump(&mut self, boxes: &[Mailbox; MAX_CONCURRENT_STREAMS]) -> Result<bool> {
        let mut progress = false;
        for k in 0..MAX_CONCURRENT_STREAMS {
            let i = (self.rr + k) % MAX_CONCURRENT_STREAMS;
            let Some(mb) = boxes.get(i) else { continue };
            let (consumed, discarded, closed) = mb.with(|s| {
                (
                    core::mem::take(&mut s.consumed),
                    core::mem::take(&mut s.discarded),
                    s.body_closed,
                )
            });
            if consumed > 0 {
                progress = true;
                self.credit(Some(i), i64::from(consumed))?;
            }
            if discarded > 0 {
                progress = true;
                self.credit(None, i64::from(discarded))?;
            }
            let Some(w) = self.wire_mut(i) else { continue };
            w.discarding |= closed;
            let id = w.id;
            if let Some(block) = mb.with(|s| s.header.take()) {
                self.header_block(id, &block)?;
                if let Some(w) = self.wire_mut(i) {
                    w.header_out = true;
                }
                progress = true;
            }
            progress |= self.send_data(i, mb)?;
            if let Some(ok) = self.wire(i).and_then(|w| w.done) {
                progress |= self.finish(i, ok, boxes)?;
            }
        }
        self.rr = (self.rr + 1) % MAX_CONCURRENT_STREAMS;
        Ok(progress)
    }

    /// Eén DATA-frame uit de brievenbus, met dezelfde claim uit beide vensters.
    /// Eerst uit de stream claimen en achteraf krimpen zou het verschil voorgoed
    /// verliezen, en dat zet een volkomen geldige stream stil.
    fn send_data(&mut self, i: usize, mb: &Mailbox) -> Result<bool> {
        if self.out.len() - self.out_pos >= OUT_HIGH {
            return Ok(false);
        }
        let Some(w) = self.wire(i) else {
            return Ok(false);
        };
        if !w.header_out || self.conn_send_win <= 0 || w.send_win <= 0 {
            return Ok(false);
        }
        let want = mb.with(|s| s.data.len());
        if want == 0 {
            return Ok(false);
        }
        let n = (want as i64).min(self.conn_send_win).min(w.send_win);
        let len = usize::try_from(n).unwrap_or(0).min(OUR_MAX_FRAME);
        let out = &mut self.out;
        mb.with(|s| {
            out.try_reserve(9 + len).map_err(|_| Error::OutOfMemory)?;
            push_head(out, len, FRAME_DATA, 0, w.id);
            out.extend(s.data.drain(..len));
            Ok::<(), Error>(())
        })?;
        self.conn_send_win -= len as i64;
        if let Some(w) = self.wire_mut(i) {
            w.send_win -= len as i64;
        }
        Ok(true)
    }

    /// Rondt een stream af waarvan de handler klaar is. Een body die de handler
    /// nooit uitlas, wordt afgebroken in plaats van half open gelaten: de peer
    /// moet horen dat hij kan stoppen.
    fn finish(
        &mut self,
        i: usize,
        ok: bool,
        boxes: &[Mailbox; MAX_CONCURRENT_STREAMS],
    ) -> Result<bool> {
        let (Some(w), Some(mb)) = (self.wire(i), boxes.get(i)) else {
            return Ok(false);
        };
        let (sent, failed, waiting, clean) = mb.with(|s| {
            (
                s.header_sent,
                s.failed.is_some(),
                s.header.is_some() || !s.data.is_empty(),
                s.clean_eof(),
            )
        });
        if !ok || failed {
            self.fail(i, CODE_INTERNAL_ERROR, boxes)?;
            return Ok(true);
        }
        if !sent {
            // Zonder koppen van de handler gaat er een kale 200 uit.
            let mut block = Vec::new();
            crate::hpack::encode(&mut block, ":status", "200").map_err(|_| Error::OutOfMemory)?;
            mb.with(|s| {
                s.header_sent = true;
                s.body_allowed = !s.head;
                s.header = Some(block);
            });
            return Ok(true);
        }
        if waiting {
            return Ok(false);
        }
        self.frame(FRAME_DATA, FLAG_END_STREAM, w.id, &[])?;
        let reset = !clean && !w.remote_ended;
        if reset {
            self.frame(FRAME_RST_STREAM, 0, w.id, &CODE_NO_ERROR.to_be_bytes())?;
        }
        let n = self.detach(i, Error::StreamClosed, reset, boxes);
        self.credit(None, n)?;
        Ok(true)
    }

    /// Reset een stream voor een handler die niet kon afmaken.
    fn fail(&mut self, i: usize, code: u32, boxes: &[Mailbox; MAX_CONCURRENT_STREAMS]) -> Result {
        let Some(w) = self.wire(i) else {
            return Ok(());
        };
        self.frame(FRAME_RST_STREAM, 0, w.id, &code.to_be_bytes())?;
        let n = self.detach(i, Error::StreamClosed, !w.remote_ended, boxes);
        self.credit(None, n)
    }

    /// Haalt de draadtoestand van een stream weg en gooit zijn body weg. Geeft
    /// het verbindingskrediet dat daarmee vrijkomt en precies één keer terug
    /// moet: ongelezen bytes plus wat de handler las maar nog niet gemeld was.
    fn detach(
        &mut self,
        i: usize,
        why: Error,
        remember: bool,
        boxes: &[Mailbox; MAX_CONCURRENT_STREAMS],
    ) -> i64 {
        let Some(w) = self.wires.get_mut(i).and_then(Option::take) else {
            return 0;
        };
        if remember {
            self.remember_reset(w.id, w.recv_win);
        }
        let Some(mb) = boxes.get(i) else { return 0 };
        mb.with(|s| {
            let n = s.discard(why) as i64
                + i64::from(core::mem::take(&mut s.consumed))
                + i64::from(core::mem::take(&mut s.discarded));
            s.gone.get_or_insert(why);
            s.data.clear();
            s.header = None;
            n
        })
    }

    /// Onthoudt het restvenster van een stream die wij resetten.
    fn remember_reset(&mut self, id: u32, remaining: i64) {
        if let Some(entry) = self.resets.iter_mut().find(|(r, _)| *r == id) {
            entry.1 = remaining;
            return;
        }
        if self.resets.len() == MAX_CONCURRENT_STREAMS {
            self.resets.pop_front();
        }
        if self.resets.try_reserve(1).is_ok() {
            self.resets.push_back((id, remaining));
        }
    }

    /// Stuurt WINDOW_UPDATE voor verbruikte of bewust weggegooide bytes; met
    /// `Some(i)` ook op die stream, tenzij hij geen krediet meer krijgt.
    fn credit(&mut self, i: Option<usize>, n: i64) -> Result {
        if n <= 0 {
            return Ok(());
        }
        let stream = i
            .and_then(|i| self.wire(i))
            .filter(|w| !w.discarding)
            .map(|w| (w.id, w.recv_win));
        let over_stream = stream.is_some_and(|(_, win)| win + n > WINDOW_MAX);
        if self.recv_win + n > WINDOW_MAX || over_stream {
            return Err(Error::CreditOverflow);
        }
        let inc = u32::try_from(n).map_err(|_| Error::CreditOverflow)?;
        if let Some((id, _)) = stream {
            self.frame(FRAME_WINDOW_UPDATE, 0, id, &inc.to_be_bytes())?;
            if let Some(w) = i.and_then(|i| self.wire_mut(i)) {
                w.recv_win += n;
            }
        }
        self.frame(FRAME_WINDOW_UPDATE, 0, 0, &inc.to_be_bytes())?;
        self.recv_win += n;
        Ok(())
    }

    /// Schrijft een kopblok als HEADERS plus CONTINUATION, aaneengesloten.
    fn header_block(&mut self, id: u32, block: &[u8]) -> Result {
        let mut chunks = block.chunks(OUR_MAX_FRAME).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let flags = if chunks.peek().is_none() {
            FLAG_END_HEADERS
        } else {
            0
        };
        self.frame(FRAME_HEADERS, flags, id, first)?;
        while let Some(chunk) = chunks.next() {
            let flags = if chunks.peek().is_none() {
                FLAG_END_HEADERS
            } else {
                0
            };
            self.frame(FRAME_CONTINUATION, flags, id, chunk)?;
        }
        Ok(())
    }

    /// Zet één frame in de uitvoer.
    fn frame(&mut self, typ: u8, flags: u8, stream: u32, payload: &[u8]) -> Result {
        self.out
            .try_reserve(9 + payload.len())
            .map_err(|_| Error::OutOfMemory)?;
        push_head(&mut self.out, payload.len(), typ, flags, stream);
        self.out.extend_from_slice(payload);
        Ok(())
    }

    /// Schrijft de uitvoer weg zover het transport wil.
    fn flush<T>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut T,
    ) -> Result<bool, ServeError<<T as AsyncWrite>::Error>>
    where
        T: AsyncWrite + Unpin,
    {
        let mut progress = false;
        while let Some(rest) = self.out.get(self.out_pos..).filter(|r| !r.is_empty()) {
            match Pin::new(&mut *io).poll_write(cx, rest) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Err(ServeError::Transport(e)),
                Poll::Ready(Ok(0)) => return Err(Error::WriteZero.into()),
                Poll::Ready(Ok(n)) => {
                    self.out_pos += n.min(rest.len());
                    progress = true;
                }
            }
        }
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        } else if self.out_pos >= OUT_HIGH {
            self.out.drain(..self.out_pos);
            self.out_pos = 0;
        }
        Ok(progress)
    }

    /// De verbinding is voorbij: elke stream hoort het, elke body faalt.
    fn end_all(&mut self, boxes: &[Mailbox; MAX_CONCURRENT_STREAMS]) {
        for (w, mb) in self.wires.iter_mut().zip(boxes) {
            *w = None;
            mb.with(|s| {
                s.discard(Error::ConnectionClosed);
                s.gone.get_or_insert(Error::ConnectionClosed);
            });
        }
    }

    /// De slot-index van een levende stream.
    fn find(&self, id: u32) -> Option<usize> {
        self.wires
            .iter()
            .position(|w| w.is_some_and(|w| w.id == id))
    }

    /// De draadtoestand in slot `i`.
    fn wire(&self, i: usize) -> Option<Wire> {
        self.wires.get(i).copied().flatten()
    }

    /// De draadtoestand in slot `i`, veranderbaar.
    fn wire_mut(&mut self, i: usize) -> Option<&mut Wire> {
        self.wires.get_mut(i).and_then(Option::as_mut)
    }
}

/// Haalt padlengte en opvulling van een opgevuld frame af.
fn strip_padding(raw: &[u8], flags: u8) -> Result<&[u8]> {
    if flags & FLAG_PADDED == 0 {
        return Ok(raw);
    }
    let (&pad, rest) = raw.split_first().ok_or(Error::PadLengthMissing)?;
    let keep = rest
        .len()
        .checked_sub(usize::from(pad))
        .ok_or(Error::PaddingBeyondFrame)?;
    Ok(rest.get(..keep).unwrap_or(&[]))
}

/// Een framekop van negen bytes.
fn push_head(out: &mut Vec<u8>, len: usize, typ: u8, flags: u8, stream: u32) {
    let len = (len as u32).to_be_bytes();
    out.extend_from_slice(&len[1..]);
    out.push(typ);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
}

/// Voegt bytes toe, faalbaar gealloceerd.
fn append(dst: &mut Vec<u8>, src: &[u8]) -> Result {
    dst.try_reserve(src.len()).map_err(|_| Error::OutOfMemory)?;
    dst.extend_from_slice(src);
    Ok(())
}
