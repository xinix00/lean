//! De verbindingstests uit leanh2_test.go en adversarial_test.go.
//!
//! De peer spreekt de draad, niet de binnenkant van deze crate: alleen zo kan
//! een framingtest een framingfout vangen. De verbinding draait op een pijp in
//! het geheugen; de test pollt `serve` tot er niets meer gebeurt en leest dan
//! wat er de draad op ging. Waar Go op een klok wachtte ("150 ms lang komt er
//! niets"), kijkt deze test naar een verbinding die niets meer te doen heeft:
//! wat dan niet in de pijp staat, komt ook niet meer.

use super::*;
use crate::hpack::tests::{encode_fields, f};
use crate::hpack::{Decoder, Field, append_int};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::task::Waker;

type BoxFut<'s> = Pin<Box<dyn Future<Output = Result> + 's>>;

/// Een handler uit een closure, voor de tests.
struct FnHandler<F>(F);

impl<F> Handler for FnHandler<F>
where
    F: for<'s> FnMut(Request<'s>, Response<'s>) -> BoxFut<'s>,
{
    type Future<'s>
        = BoxFut<'s>
    where
        Self: 's;

    fn call<'s>(&mut self, request: Request<'s>, response: Response<'s>) -> BoxFut<'s> {
        (self.0)(request, response)
    }
}

fn handler<F>(f: F) -> FnHandler<F>
where
    F: for<'s> FnMut(Request<'s>, Response<'s>) -> BoxFut<'s>,
{
    FnHandler(f)
}

/// Wacht tot `flag` waar is; de verbinding pollt opnieuw na elke verandering.
async fn wait(flag: Rc<Cell<bool>>) {
    std::future::poll_fn(|_| {
        if flag.get() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

/// Leest de body tot het einde.
async fn read_all(body: &mut Body<'_>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = body.read(&mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PipeError;

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pipe closed")
    }
}

/// De pijp tussen peer en server.
#[derive(Default)]
struct Pipe {
    to_server: VecDeque<u8>,
    to_peer: VecDeque<u8>,
    peer_closed: bool,
    closes: u32,
    writes: u32,
    /// Hoogstens zoveel bytes per schrijfactie (0 is onbeperkt).
    chunk: usize,
    /// De zoveelste schrijfactie neemt nul bytes aan.
    short_at: Option<u32>,
    /// Na zoveel schrijfacties blijft elke volgende hangen.
    block_after: Option<u32>,
}

struct ServerEnd(Rc<RefCell<Pipe>>);

impl AsyncRead for ServerEnd {
    type Error = PipeError;
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, PipeError>> {
        let mut p = self.0.borrow_mut();
        if p.to_server.is_empty() {
            return if p.peer_closed || p.closes > 0 {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
            };
        }
        let n = buf.len().min(p.to_server.len());
        for (dst, src) in buf.iter_mut().zip(p.to_server.drain(..n)) {
            *dst = src;
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for ServerEnd {
    type Error = PipeError;
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, PipeError>> {
        let mut p = self.0.borrow_mut();
        if p.closes > 0 {
            return Poll::Ready(Err(PipeError));
        }
        if p.block_after.is_some_and(|n| p.writes >= n) {
            return Poll::Pending;
        }
        p.writes += 1;
        if p.short_at == Some(p.writes) {
            return Poll::Ready(Ok(0));
        }
        let n = if p.chunk > 0 {
            buf.len().min(p.chunk)
        } else {
            buf.len()
        };
        p.to_peer.extend(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), PipeError>> {
        self.0.borrow_mut().closes += 1;
        Poll::Ready(Ok(()))
    }
}

type Outcome = Result<(), ServeError<PipeError>>;

/// De peer: drijft frames met de hand.
struct Peer {
    pipe: Rc<RefCell<Pipe>>,
    serve: Pin<Box<dyn Future<Output = Outcome>>>,
    outcome: Option<Outcome>,
    goaway: Rc<Cell<Option<GoAway>>>,
}

fn new_peer<H: Handler + 'static>(h: H) -> Peer {
    new_peer_with_settings(h, true)
}

/// Laat het verplichte eerste SETTINGS-frame alleen weg voor de tests die
/// bewijzen dat de server precies dat weigert.
fn new_peer_with_settings<H: Handler + 'static>(h: H, send_settings: bool) -> Peer {
    let mut p = raw_peer(h, Pipe::default());
    p.write(CLIENT_PREFACE);
    if send_settings {
        p.frame(FRAME_SETTINGS, 0, 0, &[]);
    }
    p
}

fn raw_peer<H: Handler + 'static>(h: H, pipe: Pipe) -> Peer {
    let pipe = Rc::new(RefCell::new(pipe));
    let goaway: Rc<Cell<Option<GoAway>>> = Rc::default();
    let stop = goaway.clone();
    let mut conn = Conn::new(ServerEnd(pipe.clone()), h);
    let serve = Box::pin(async move {
        conn.serve(std::future::poll_fn(move |_| match stop.take() {
            Some(g) => Poll::Ready(g),
            None => Poll::Pending,
        }))
        .await
    });
    let mut p = Peer {
        pipe,
        serve,
        outcome: None,
        goaway,
    };
    p.run();
    p
}

impl Peer {
    /// Pollt `serve` tot er niets meer gebeurt.
    fn run(&mut self) {
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..200 {
            if self.outcome.is_some() {
                return;
            }
            if let Poll::Ready(r) = self.serve.as_mut().poll(&mut cx) {
                self.outcome = Some(r);
            }
        }
    }

    fn write(&mut self, b: &[u8]) {
        self.pipe.borrow_mut().to_server.extend(b);
        self.run();
    }

    fn frame(&mut self, typ: u8, flags: u8, stream: u32, body: &[u8]) {
        self.write(&frame_bytes(typ, flags, stream, body));
    }

    /// Het volgende frame dat de server schreef, als dat er is.
    fn try_read(&mut self) -> Option<(u8, u8, u32, Vec<u8>)> {
        self.run();
        let mut p = self.pipe.borrow_mut();
        if p.to_peer.len() < 9 {
            return None;
        }
        let head: Vec<u8> = p.to_peer.iter().take(9).copied().collect();
        let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        if p.to_peer.len() < 9 + len {
            return None;
        }
        p.to_peer.drain(..9);
        let body: Vec<u8> = p.to_peer.drain(..len).collect();
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        Some((head[3], head[4], stream, body))
    }

    fn read(&mut self) -> (u8, u8, u32, Vec<u8>) {
        self.try_read().expect("geen frame van de server")
    }

    /// Slaat frames over tot er een van type `typ` komt.
    fn read_until(&mut self, typ: u8) -> (u8, u32, Vec<u8>) {
        for _ in 0..40 {
            let (t, fl, s, b) = self.read();
            if t == typ {
                return (fl, s, b);
            }
        }
        panic!("geen frame van type 0x{typ:02x} binnen veertig frames");
    }

    /// De uitkomst van `serve`, als die er is.
    fn done(&mut self) -> Option<&Outcome> {
        self.run();
        self.outcome.as_ref()
    }

    /// Wacht tot `serve` eindigt en toetst dat de reden de fout van de peer
    /// noemt. Een weigering die stil eindigt, is geen weigering.
    fn assert_connection_error(&mut self, want: &str) {
        match self.done() {
            None => panic!("de verbinding bleef staan (wilde {want:?})"),
            Some(Ok(())) => panic!("de verbinding eindigde zonder fout"),
            Some(Err(e)) => {
                let msg = e.to_string();
                assert!(msg.contains(want), "fout = {msg:?}, wil {want:?}");
            }
        }
    }

    /// De client-helft van de SETTINGS-uitwisseling.
    fn handshake(&mut self, settings: Option<&[u8]>) {
        self.read_until(FRAME_SETTINGS);
        let (flags, stream, _) = self.read_until(FRAME_SETTINGS);
        assert!(flags & FLAG_ACK != 0 && stream == 0);
        if let Some(s) = settings {
            self.frame(FRAME_SETTINGS, 0, 0, s);
            let (flags, _, _) = self.read_until(FRAME_SETTINGS);
            assert!(flags & FLAG_ACK != 0);
        }
        self.frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]);
    }

    /// Alles wat er nu nog staat, als frames.
    fn drain(&mut self) -> Vec<(u8, u8, u32, Vec<u8>)> {
        std::iter::from_fn(|| self.try_read()).collect()
    }
}

fn frame_bytes(typ: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
    let len = (body.len() as u32).to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], typ, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn setting(id: u16, v: u32) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(&v.to_be_bytes());
    out
}

/// Een minimaal GET-blok voor `path`.
fn header_block(path: &str) -> Vec<u8> {
    encode_fields(&[
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":path", path),
        f(":authority", "example.test"),
    ])
}

fn decode(block: &[u8]) -> Vec<Field> {
    Decoder::new(4096, 0).decode(block).unwrap()
}

/// Een handler die meteen 204 geeft.
fn no_content() -> impl Handler + 'static {
    handler(|_, mut res| {
        Box::pin(async move {
            res.write_header(204, &[])?;
            Ok(())
        })
    })
}

/// Een handler die niets doet.
fn idle() -> impl Handler + 'static {
    handler(|_, _| Box::pin(async { Ok(()) }))
}

// De SETTINGS-uitwisseling in beide richtingen plus de ACK. Al het andere hier
// neemt aan dat dit werkt.
#[test]
fn settings_handshake() {
    let mut p = new_peer(idle());
    let (typ, flags, stream, body) = p.read();
    assert_eq!((typ, flags, stream), (FRAME_SETTINGS, 0, 0));
    assert_eq!(body.len(), 36, "precies zes instellingen");
    let mut seen = std::collections::HashMap::new();
    for e in body.chunks(6) {
        let id = u16::from_be_bytes([e[0], e[1]]);
        assert!(
            seen.insert(id, u32::from_be_bytes([e[2], e[3], e[4], e[5]]))
                .is_none()
        );
    }
    for (id, want) in [
        (SETTING_HEADER_TABLE_SIZE, OUR_HEADER_TABLE_SIZE),
        (SETTING_ENABLE_PUSH, 0),
        (SETTING_MAX_CONCURRENT, MAX_CONCURRENT_STREAMS as u32),
        (SETTING_INITIAL_WINDOW_SIZE, OUR_INITIAL_WINDOW),
        (SETTING_MAX_FRAME_SIZE, OUR_MAX_FRAME as u32),
        (SETTING_MAX_HEADER_LIST_SIZE, OUR_MAX_HEADER_LIST as u32),
    ] {
        assert_eq!(seen.get(&id), Some(&want), "instelling 0x{id:x}");
    }
    let (flags, _, _) = p.read_until(FRAME_SETTINGS);
    assert!(flags & FLAG_ACK != 0, "SETTINGS van de peer niet bevestigd");
}

// Een PING hoort met zijn inhoud beantwoord te worden. Sommige peers openen
// geen stream voordat ze de ACK zien.
#[test]
fn ping_is_answered() {
    let mut p = new_peer(idle());
    p.read_until(FRAME_SETTINGS);
    p.frame(FRAME_PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let (flags, _, body) = p.read_until(FRAME_PING);
    assert!(flags & FLAG_ACK != 0);
    assert_eq!(body, [1, 2, 3, 4, 5, 6, 7, 8]);
}

// PRIORITY is verouderd in RFC 9113. De twee geldige draadvormen blijven
// onschuldige invoer, zonder toestand en zonder roostering.
#[test]
fn priority_is_accepted_and_ignored() {
    let reached = Rc::new(Cell::new(false));
    let r = reached.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        r.set(true);
        Box::pin(async move {
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    let priority = [0, 0, 0, 0, 15];
    p.frame(FRAME_PRIORITY, 0, 1, &priority);
    let mut block = priority.to_vec();
    block.extend(header_block("/priority"));
    p.frame(
        FRAME_HEADERS,
        FLAG_PRIORITY | FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    );
    assert!(reached.get(), "geldige PRIORITY hield het verzoek tegen");
    assert!(p.done().is_none());
}

// Een verzoek zonder body bereikt de handler met de pseudo-koppen apart, en
// het antwoord komt terug als HEADERS plus DATA plus END_STREAM.
#[test]
fn request_and_response() {
    type Seen = (String, String, String, u32, bool);
    let got: Rc<RefCell<Option<Seen>>> = Rc::default();
    let g = got.clone();
    let mut p = new_peer(handler(move |mut req, mut res| {
        let g = g.clone();
        Box::pin(async move {
            read_all(&mut req.body).await?;
            *g.borrow_mut() = Some((
                req.method.clone(),
                req.path.clone(),
                req.authority.clone(),
                req.stream_id,
                req.header.iter().any(|(n, _)| n.starts_with(':')),
            ));
            res.write_header(200, &[("content-type", "text/plain")])?;
            res.write(b"hallo").await?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/pad?q=1"),
    );
    let (method, path, authority, id, leaked) = got.borrow().clone().unwrap();
    assert_eq!(
        (method.as_str(), path.as_str(), authority.as_str()),
        ("GET", "/pad?q=1", "example.test")
    );
    assert_eq!(id, 1);
    assert!(!leaked, "pseudo-kop lekte in de velden");

    let (flags, stream, block) = p.read_until(FRAME_HEADERS);
    assert!(flags & FLAG_END_HEADERS != 0 && stream == 1);
    let fields = decode(&block);
    assert_eq!(fields[0], f(":status", "200"));
    let (_, _, data) = p.read_until(FRAME_DATA);
    assert_eq!(data, b"hallo");
    let (end, _, _) = p.read_until(FRAME_DATA);
    assert!(end & FLAG_END_STREAM != 0);
}

// Een verzoekbody komt binnen via Body, en elk DATA-frame hoort beantwoord te
// worden met WINDOW_UPDATE op stream en verbinding.
#[test]
fn request_body_returns_window() {
    let body: Rc<RefCell<Vec<u8>>> = Rc::default();
    let b = body.clone();
    let mut p = new_peer(handler(move |mut req, mut res| {
        let b = b.clone();
        Box::pin(async move {
            *b.borrow_mut() = read_all(&mut req.body).await?;
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block("/upload"));
    p.frame(FRAME_DATA, 0, 1, b"twaalf bytes");
    p.frame(FRAME_DATA, FLAG_END_STREAM, 1, &[]);
    assert_eq!(&*body.borrow(), b"twaalf bytes");
    let (mut on_stream, mut on_conn) = (false, false);
    for (typ, _, stream, body) in p.drain() {
        if typ != FRAME_WINDOW_UPDATE {
            continue;
        }
        let inc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if inc == CONNECTION_WINDOW_INCREMENT {
            continue;
        }
        assert_eq!(inc, 12);
        if stream == 0 {
            on_conn = true;
        } else {
            on_stream = true;
        }
    }
    assert!(
        on_stream && on_conn,
        "stream={on_stream} verbinding={on_conn}"
    );
}

// Flow control is waar een fout pas onder last zichtbaar wordt: een schrijver
// moet stoppen als het venster op is en verder na WINDOW_UPDATE, en nooit een
// frame groter dan het maximum van de peer.
#[test]
fn write_respects_window_and_frame_size() {
    const PAYLOAD: usize = 40_000;
    const WINDOW: u32 = 10_000;
    let written = Rc::new(Cell::new(false));
    let w = written.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let w = w.clone();
        Box::pin(async move {
            res.write_header(200, &[])?;
            res.write(&vec![b'x'; PAYLOAD]).await?;
            w.set(true);
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    let mut settings = setting(SETTING_INITIAL_WINDOW_SIZE, WINDOW);
    settings.extend(setting(SETTING_MAX_FRAME_SIZE, 16_384));
    p.frame(FRAME_SETTINGS, 0, 0, &settings);
    p.read_until(FRAME_SETTINGS);
    p.read_until(FRAME_SETTINGS);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/blob"),
    );
    p.read_until(FRAME_HEADERS);

    let data_len = |frames: &[(u8, u8, u32, Vec<u8>)]| -> usize {
        frames
            .iter()
            .filter(|f| f.0 == FRAME_DATA)
            .inspect(|f| assert!(f.3.len() <= 16_384, "DATA-frame van {} bytes", f.3.len()))
            .map(|f| f.3.len())
            .sum()
    };
    let got = data_len(&p.drain());
    assert_eq!(got, WINDOW as usize, "binnen het venster");
    assert!(
        !written.get(),
        "Write keerde terug voordat alles verstuurd kon worden"
    );

    let inc = (PAYLOAD as u32).to_be_bytes();
    p.frame(FRAME_WINDOW_UPDATE, 0, 1, &inc);
    p.frame(FRAME_WINDOW_UPDATE, 0, 0, &inc);
    let got = got + data_len(&p.drain());
    assert_eq!(got, PAYLOAD);
    assert!(written.get(), "Write keerde niet terug");
}

// Een blok over CONTINUATION is één blok: de handler ziet het hele verzoek.
#[test]
fn continuation_joins_the_block() {
    let path: Rc<RefCell<String>> = Rc::default();
    let pa = path.clone();
    let mut p = new_peer(handler(move |req, mut res| {
        *pa.borrow_mut() = req.path.clone();
        Box::pin(async move {
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    let block = header_block("/gesplitst");
    let cut = block.len() / 2;
    p.frame(FRAME_HEADERS, 0, 1, &block[..cut]);
    p.frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, &block[cut..]);
    assert_eq!(&*path.borrow(), "/gesplitst");
}

// In Go ving de verbinding een paniek van de handler op. Hier geeft een handler
// die niet kan afmaken een fout terug; die doodt zijn eigen stream en niets
// anders, en het volgende verzoek wordt bediend.
#[test]
fn panic_kills_only_its_stream() {
    let second: Rc<RefCell<String>> = Rc::default();
    let s2 = second.clone();
    let mut p = new_peer(handler(move |req, mut res| {
        let s2 = s2.clone();
        Box::pin(async move {
            if req.path == "/klap" {
                return Err(Error::StreamClosed);
            }
            *s2.borrow_mut() = req.path.clone();
            res.write_header(200, &[])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/klap"),
    );
    let (_, stream, body) = p.read_until(FRAME_RST_STREAM);
    assert_eq!(stream, 1);
    assert_eq!(body, CODE_INTERNAL_ERROR.to_be_bytes());
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        &header_block("/verder"),
    );
    assert_eq!(&*second.borrow(), "/verder");
    assert!(p.done().is_none());
}

// De weigeringen: elk een vergissing van de peer die de verbinding moet
// beëindigen met een benoemde fout.
#[test]
fn refusals() {
    type Send = Box<dyn Fn(&mut Peer)>;
    let cases: Vec<(&str, Send, &str)> = vec![
        (
            "frame boven ons maximum",
            Box::new(|p| p.write(&[0, 0x80, 0x01, FRAME_DATA, 0, 0, 0, 0, 1])),
            "above the announced",
        ),
        (
            "WINDOW_UPDATE van nul",
            Box::new(|p| p.frame(FRAME_WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0])),
            "WINDOW_UPDATE of zero",
        ),
        (
            "HEADERS op stream 0",
            Box::new(|p| p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 0, &header_block("/"))),
            "HEADERS on stream 0",
        ),
        (
            "kapotte opgevulde DATA",
            Box::new(|p| {
                p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block("/"));
                p.frame(FRAME_DATA, FLAG_PADDED, 1, &[0xff, 1, 2]);
            }),
            "padding beyond the frame",
        ),
        (
            "onleesbaar kopblok",
            Box::new(|p| p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0xff; 5])),
            "header block on stream",
        ),
        (
            "GOAWAY",
            Box::new(|p| {
                let mut body = vec![0u8; 8];
                body.extend(b"genoeg");
                p.frame(FRAME_GOAWAY, 0, 0, &body);
            }),
            "GOAWAY",
        ),
    ];
    for (name, send, want) in cases {
        let mut p = new_peer(handler(|mut req, _| {
            Box::pin(async move {
                read_all(&mut req.body).await?;
                Ok(())
            })
        }));
        p.read_until(FRAME_SETTINGS);
        send(&mut p);
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

// Een verkeerde preface wordt geweigerd voordat er iets anders gebeurt.
#[test]
fn wrong_preface() {
    let mut p = raw_peer(idle(), Pipe::default());
    p.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    p.assert_connection_error("client preface");
    assert_eq!(
        p.pipe.borrow().to_peer.len(),
        0,
        "iets geschreven voor de preface"
    );
}

// GOAWAY kondigt het stoppen één keer aan; er komt geen tweede frame.
#[test]
fn go_away_only_once() {
    let mut p = new_peer(idle());
    p.read_until(FRAME_SETTINGS);
    p.read_until(FRAME_SETTINGS);
    p.goaway.set(Some(GoAway::new(0, "stoppen").unwrap()));
    let (_, _, body) = p.read_until(FRAME_GOAWAY);
    assert!(body.ends_with(b"stoppen"));
    // De stop is afgehandeld; een tweede aanvraag wordt niet meer gezien.
    p.goaway.set(Some(GoAway::new(0, "nogmaals").unwrap()));
    p.frame(FRAME_PING, 0, 0, &[9; 8]);
    let (typ, _, _, _) = p.read();
    assert_eq!(typ, FRAME_PING, "frame na de tweede GoAway");
}

// De discipline van stream-id's: door de client, oneven, strikt stijgend.
#[test]
fn stream_identifier_discipline() {
    let cases: [(&str, &[u32], &str); 3] = [
        ("even id", &[2], "not client-initiated"),
        ("hergebruikt id", &[3, 3], "not above the last accepted"),
        ("lager id", &[5, 3], "not above the last accepted"),
    ];
    for (name, ids, want) in cases {
        let mut p = new_peer(no_content());
        p.read_until(FRAME_SETTINGS);
        for &id in ids {
            p.frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                id,
                &header_block("/"),
            );
        }
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

// Inkomend: tussen HEADERS en zijn CONTINUATION mag niets komen (RFC 9113 §6.2
// maakt dit een verbindingsfout).
#[test]
fn header_block_is_indivisible_inbound() {
    let block = header_block("/half");
    let half = block.len() / 2;
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        (
            "ander frame in het blok",
            vec![
                frame_bytes(FRAME_HEADERS, 0, 1, &block[..half]),
                frame_bytes(FRAME_PING, 0, 0, &[1; 8]),
            ],
            "interrupted the header block",
        ),
        (
            "CONTINUATION op een andere stream",
            vec![
                frame_bytes(FRAME_HEADERS, 0, 1, &block[..half]),
                frame_bytes(FRAME_CONTINUATION, FLAG_END_HEADERS, 3, &block[half..]),
            ],
            "interrupted the header block",
        ),
        (
            "CONTINUATION zonder blok",
            vec![frame_bytes(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, &block)],
            "without an open header block",
        ),
    ];
    for (name, frames, want) in cases {
        let mut p = new_peer(no_content());
        p.read_until(FRAME_SETTINGS);
        for fr in frames {
            p.write(&fr);
        }
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

// Uitgaand: twee streams die tegelijk antwoorden, mogen hun blokken niet
// verweven. Het blok is groter dan een frame, dus elk antwoord beslaat HEADERS
// plus CONTINUATION en een verweving zou zichtbaar zijn.
#[test]
fn header_block_is_indivisible_outbound() {
    let release = Rc::new(Cell::new(false));
    let r = release.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let r = r.clone();
        Box::pin(async move {
            wait(r).await;
            let big = "a".repeat(20_000);
            res.write_header(200, &[("x-big", &big)])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/een"),
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        &header_block("/twee"),
    );
    release.set(true);
    let (mut open, mut blocks) = (0u32, 0);
    for (typ, flags, stream, _) in p.drain() {
        match typ {
            FRAME_HEADERS => {
                assert_eq!(open, 0, "HEADERS voor {stream} terwijl {open} open was");
                if flags & FLAG_END_HEADERS == 0 {
                    open = stream;
                } else {
                    blocks += 1;
                }
            }
            FRAME_CONTINUATION => {
                assert_eq!(stream, open);
                if flags & FLAG_END_HEADERS != 0 {
                    open = 0;
                    blocks += 1;
                }
            }
            _ => assert_eq!(open, 0, "frame 0x{typ:02x} midden in het blok van {open}"),
        }
    }
    assert_eq!(blocks, 2);
}

// Meer streams dan aangekondigd wordt geweigerd: de cap begrenst wat één peer
// aan futures en buffers kan claimen.
#[test]
fn concurrent_stream_cap() {
    let hold = Rc::new(Cell::new(false));
    let h = hold.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let h = h.clone();
        Box::pin(async move {
            wait(h).await;
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.read_until(FRAME_SETTINGS);
    for i in 0..=MAX_CONCURRENT_STREAMS as u32 {
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1 + 2 * i,
            &header_block("/vast"),
        );
    }
    p.assert_connection_error("more than the announced");
}

// GOAWAY moet de hoogste geaccepteerde stream noemen. Nul zou uitnodigen tot
// het herhalen van werk dat hier nog bijwerkingen kan hebben.
#[test]
fn go_away_reports_last_stream() {
    let mut p = new_peer(no_content());
    p.read_until(FRAME_SETTINGS);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/een"),
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        5,
        &header_block("/twee"),
    );
    p.goaway.set(Some(GoAway::new(0, "klaar").unwrap()));
    let (_, _, body) = p.read_until(FRAME_GOAWAY);
    assert_eq!(
        u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7fff_ffff,
        5
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        7,
        &header_block("/na"),
    );
    p.assert_connection_error("after GOAWAY");
}

// De verzoekregels van RFC 9113 §8.3 en §8.2.2. Een toegeeflijke implementatie
// laat elk hiervan bij een handler komen, en dat is de klasse fouten die als
// request-smuggling-advisory eindigt.
#[test]
fn invalid_requests_are_refused() {
    let base = || vec![f(":method", "GET"), f(":scheme", "https"), f(":path", "/")];
    let with = |extra: &[(&str, &str)]| {
        let mut v = base();
        v.extend(extra.iter().map(|(n, x)| f(n, x)));
        v
    };
    let cases: Vec<(&str, Vec<Field>, &str)> = vec![
        (
            "geen :method",
            vec![f(":scheme", "https"), f(":path", "/")],
            "missing :method",
        ),
        (
            "geen :path",
            vec![f(":method", "GET"), f(":scheme", "https")],
            "missing :path",
        ),
        (
            "lege :path",
            vec![f(":method", "GET"), f(":scheme", "https"), f(":path", "")],
            "empty :path",
        ),
        (
            "dubbele :method",
            vec![
                f(":method", "GET"),
                f(":method", "POST"),
                f(":scheme", "https"),
                f(":path", "/"),
            ],
            "duplicate :method",
        ),
        (
            "onbekende pseudo-kop",
            with(&[(":protocol", "websocket")]),
            "unknown pseudo-header",
        ),
        (
            "pseudo-kop na een veld",
            vec![
                f(":method", "GET"),
                f(":scheme", "https"),
                f("x-a", "1"),
                f(":path", "/"),
            ],
            "after a regular field",
        ),
        (
            "veldnaam met hoofdletters",
            with(&[("X-Upper", "1")]),
            "not lowercase",
        ),
        (
            "connection-veld",
            with(&[("connection", "keep-alive")]),
            "connection-specific",
        ),
        (
            "transfer-encoding",
            with(&[("transfer-encoding", "chunked")]),
            "connection-specific",
        ),
        ("te anders dan trailers", with(&[("te", "gzip")]), "te:"),
        (
            "twee content-lengths",
            with(&[("content-length", "1"), ("content-length", "2")]),
            "more than one content-length",
        ),
    ];
    for (name, fields, want) in cases {
        let reached = Rc::new(Cell::new(false));
        let r = reached.clone();
        let mut p = new_peer(handler(move |_, _| {
            r.set(true);
            Box::pin(async { Ok(()) })
        }));
        p.read_until(FRAME_SETTINGS);
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode_fields(&fields),
        );
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
        assert!(!reached.get(), "{name}: de handler werd bereikt");
    }
}

// Vormcontroles op frameniveau: een peer die dit fout doet is kapot, en
// meegaan verbergt dat.
#[test]
fn frame_shape_refusals() {
    let max = (0x7fff_ffffu32).to_be_bytes();
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        (
            "PING van de verkeerde lengte",
            vec![frame_bytes(FRAME_PING, 0, 0, &[1, 2, 3])],
            "PING of 3 bytes",
        ),
        (
            "PING op een stream",
            vec![frame_bytes(FRAME_PING, 0, 1, &[1; 8])],
            "on stream 1",
        ),
        (
            "SETTINGS-ACK met inhoud",
            vec![frame_bytes(
                FRAME_SETTINGS,
                FLAG_ACK,
                0,
                &[0, 3, 0, 0, 0, 1],
            )],
            "acknowledgement with a payload",
        ),
        (
            "SETTINGS op een stream",
            vec![frame_bytes(FRAME_SETTINGS, 0, 1, &[])],
            "SETTINGS on a stream",
        ),
        (
            "DATA op stream 0",
            vec![frame_bytes(FRAME_DATA, 0, 0, b"x")],
            "DATA on stream 0",
        ),
        (
            "RST_STREAM van de verkeerde lengte",
            vec![frame_bytes(FRAME_RST_STREAM, 0, 1, &[0, 0])],
            "RST_STREAM of 2 bytes",
        ),
        (
            "WINDOW_UPDATE die overloopt",
            vec![
                frame_bytes(FRAME_WINDOW_UPDATE, 0, 0, &max),
                frame_bytes(FRAME_WINDOW_UPDATE, 0, 0, &max),
            ],
            "would overflow",
        ),
    ];
    for (name, frames, want) in cases {
        let mut p = new_peer(no_content());
        p.read_until(FRAME_SETTINGS);
        for fr in frames {
            p.write(&fr);
        }
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

// Een handler die antwoordt zonder de body te lezen, laat de stream niet half
// open: de peer moet horen dat hij kan stoppen.
#[test]
fn unread_body_is_cancelled() {
    let mut p = new_peer(no_content());
    p.read_until(FRAME_SETTINGS);
    p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block("/upload"));
    p.frame(FRAME_DATA, 0, 1, b"blijft staan");
    let (_, stream, _) = p.read_until(FRAME_RST_STREAM);
    assert_eq!(stream, 1);
}

// Twee streams mogen hetzelfde verbindingskrediet zien, maar één mag het
// claimen. De Go-test zette het venster via de binnenkant op één byte; hier
// verbruikt een derde stream er legitiem 65.534 van.
#[test]
fn adversarial_concurrent_responses_share_connection_window() {
    let mut p = new_peer(handler(|req, mut res| {
        Box::pin(async move {
            res.write_header(200, &[])?;
            if req.path == "/vuller" {
                res.write(&vec![0u8; 65_534]).await?;
            } else {
                res.write(b"x").await?;
            }
            Ok(())
        })
    }));
    p.handshake(Some(&setting(SETTING_INITIAL_WINDOW_SIZE, 0)));
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/one"),
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        &header_block("/two"),
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        5,
        &header_block("/vuller"),
    );
    p.frame(FRAME_WINDOW_UPDATE, 0, 5, &65_534u32.to_be_bytes());
    let data_on = |frames: &[(u8, u8, u32, Vec<u8>)], s: u32| -> usize {
        frames
            .iter()
            .filter(|f| f.0 == FRAME_DATA && f.2 == s)
            .map(|f| f.3.len())
            .sum()
    };
    let frames = p.drain();
    assert_eq!(
        data_on(&frames, 5),
        65_534,
        "de vuller liet één byte verbindingsvenster over"
    );

    p.frame(FRAME_WINDOW_UPDATE, 0, 1, &1u32.to_be_bytes());
    let frames = p.drain();
    assert_eq!(
        data_on(&frames, 1),
        1,
        "stream 1 schreef niet na zijn krediet"
    );
    p.frame(FRAME_WINDOW_UPDATE, 0, 3, &1u32.to_be_bytes());
    let frames = p.drain();
    assert_eq!(
        data_on(&frames, 3),
        0,
        "beide streams claimden dezelfde ene byte verbindingsvenster"
    );
    p.frame(FRAME_WINDOW_UPDATE, 0, 0, &1u32.to_be_bytes());
    let frames = p.drain();
    assert_eq!(
        data_on(&frames, 3),
        1,
        "de tweede schrijver ging niet door na verbindingskrediet"
    );
}

#[test]
fn adversarial_initial_window_shift_cannot_overflow_stream() {
    let release = Rc::new(Cell::new(false));
    let r = release.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let r = r.clone();
        Box::pin(async move {
            wait(r).await;
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/held"),
    );
    let inc = ((WINDOW_MAX - 65_535) as u32).to_be_bytes();
    p.frame(FRAME_WINDOW_UPDATE, 0, 1, &inc);
    p.frame(
        FRAME_SETTINGS,
        0,
        0,
        &setting(SETTING_INITIAL_WINDOW_SIZE, 65_536),
    );
    p.assert_connection_error("overflow");
}

#[test]
fn adversarial_receive_windows_are_enforced() {
    let hold = || {
        handler(|_, _| {
            Box::pin(async {
                std::future::pending::<()>().await;
                Ok(())
            })
        })
    };
    // Stream.
    let mut p = new_peer(hold());
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        1,
        &header_block("/stream-window"),
    );
    let chunk = vec![0u8; OUR_MAX_FRAME];
    for _ in 0..OUR_INITIAL_WINDOW as usize / OUR_MAX_FRAME {
        p.frame(FRAME_DATA, 0, 1, &chunk);
    }
    p.frame(FRAME_DATA, 0, 1, &[1]);
    p.assert_connection_error("receive window of stream");

    // Verbinding over streams heen: zestien volle streamvensters plus 65.535
    // bytes is precies het aangekondigde verbindingsvenster.
    let mut p = new_peer(hold());
    p.handshake(None);
    for stream in (1..=31).step_by(2) {
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            stream,
            &header_block("/connection-window"),
        );
        for _ in 0..OUR_INITIAL_WINDOW as usize / OUR_MAX_FRAME {
            p.frame(FRAME_DATA, 0, stream, &chunk);
        }
    }
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        33,
        &header_block("/connection-window"),
    );
    for _ in 0..3 {
        p.frame(FRAME_DATA, 0, 33, &chunk);
    }
    p.frame(FRAME_DATA, 0, 33, &vec![0u8; OUR_MAX_FRAME - 1]);
    assert!(p.done().is_none(), "binnen het venster geweigerd");
    p.frame(FRAME_DATA, 0, 33, &[1]);
    p.assert_connection_error("connection receive window");
}

#[test]
fn adversarial_unread_body_returns_connection_credit() {
    let release = Rc::new(Cell::new(false));
    let r = release.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let r = r.clone();
        Box::pin(async move {
            wait(r).await;
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        1,
        &header_block("/discard"),
    );
    let payload = b"unread but still flow-controlled";
    p.frame(FRAME_DATA, 0, 1, payload);
    assert!(
        p.drain().iter().all(|f| f.0 != FRAME_WINDOW_UPDATE),
        "krediet voor ongelezen bytes"
    );
    release.set(true);
    let frames = p.drain();
    let reset = frames.iter().any(|f| f.0 == FRAME_RST_STREAM && f.2 == 1);
    let credit = frames.iter().any(|f| {
        f.0 == FRAME_WINDOW_UPDATE && f.2 == 0 && f.3 == (payload.len() as u32).to_be_bytes()
    });
    assert!(reset && credit, "reset={reset} verbindingskrediet={credit}");
}

#[test]
fn adversarial_peer_reset_emits_no_later_stream_frame() {
    let read_err: Rc<Cell<Option<bool>>> = Rc::default();
    let re = read_err.clone();
    let mut p = new_peer(handler(move |mut req, _| {
        let re = re.clone();
        Box::pin(async move {
            re.set(Some(read_all(&mut req.body).await.is_err()));
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block("/cancel"));
    p.frame(FRAME_RST_STREAM, 0, 1, &[0, 0, 0, 0]);
    assert_eq!(
        read_err.get(),
        Some(true),
        "reset van de peer leek een schoon einde"
    );
    p.frame(FRAME_PING, 0, 0, b"12345678");
    for (typ, _, stream, _) in p.drain() {
        assert_ne!(stream, 1, "frame 0x{typ:02x} na RST_STREAM van de peer");
    }
}

#[test]
fn adversarial_data_after_fully_closed_stream_is_refused() {
    let mut p = new_peer(no_content());
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/closed"),
    );
    let (flags, _, _) = p.read_until(FRAME_DATA);
    assert!(flags & FLAG_END_STREAM != 0);
    p.frame(FRAME_DATA, 0, 1, b"late");
    p.assert_connection_error("DATA on closed stream");
}

// De Go-test hield de schrijfvergrendeling vast om een DATA-claim tussen een
// verlagende SETTINGS en zijn ACK te wringen. Hier is een claim één stap van
// dezelfde lus; de SETTINGS komt ervoor of erna. Toets dat er na de ACK geen
// DATA meer komt tot er nieuw streamkrediet is.
#[test]
fn adversarial_reserved_data_is_rechecked_after_initial_window_decrease() {
    let start = Rc::new(Cell::new(false));
    let s = start.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        let s = s.clone();
        Box::pin(async move {
            res.write_header(200, &[])?;
            wait(s).await;
            res.write(&vec![0u8; OUR_MAX_FRAME]).await?;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/window-shift"),
    );
    p.read_until(FRAME_HEADERS);
    start.set(true);
    p.write(&frame_bytes(
        FRAME_SETTINGS,
        0,
        0,
        &setting(SETTING_INITIAL_WINDOW_SIZE, 0),
    ));
    let frames = p.drain();
    let ack = frames
        .iter()
        .position(|f| f.0 == FRAME_SETTINGS && f.1 & FLAG_ACK != 0)
        .expect("geen ACK");
    assert!(
        frames[ack..]
            .iter()
            .all(|f| f.0 != FRAME_DATA || f.3.is_empty()),
        "DATA volgde de verlagende SETTINGS-ACK"
    );
    p.frame(
        FRAME_WINDOW_UPDATE,
        0,
        1,
        &(OUR_MAX_FRAME as u32).to_be_bytes(),
    );
    let sent: usize = p
        .drain()
        .iter()
        .filter(|f| f.0 == FRAME_DATA)
        .map(|f| f.3.len())
        .sum();
    assert_eq!(
        sent, OUR_MAX_FRAME,
        "Write ging niet verder onder het nieuwe venster"
    );
}

#[test]
fn adversarial_public_control_waits_for_startup() {
    let mut p = raw_peer(
        idle(),
        Pipe {
            peer_closed: true,
            ..Pipe::default()
        },
    );
    p.goaway.set(Some(GoAway::new(0, "too early").unwrap()));
    assert!(matches!(p.done(), Some(Err(_))));
    assert_eq!(
        p.pipe.borrow().writes,
        0,
        "een stop voor de start schreef iets"
    );
}

#[test]
fn adversarial_terminal_close_is_once() {
    for short_at in [1, 2] {
        let mut pipe = Pipe {
            chunk: 9,
            short_at: Some(short_at),
            ..Pipe::default()
        };
        pipe.to_server.extend(CLIENT_PREFACE);
        let mut p = raw_peer(idle(), pipe);
        match p.done() {
            Some(Err(ServeError::Protocol(Error::WriteZero))) => {}
            other => panic!("write-{short_at}: {other:?}"),
        }
        assert_eq!(p.pipe.borrow().closes, 1, "write-{short_at}");
    }
}

#[test]
fn adversarial_peer_eof_releases_blocked_credit_write() {
    let mut pipe = Pipe::default();
    for fr in [
        CLIENT_PREFACE.to_vec(),
        frame_bytes(FRAME_SETTINGS, 0, 0, &[]),
        frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS, 1, &header_block("/credit")),
        frame_bytes(FRAME_DATA, FLAG_END_STREAM, 1, b"x"),
    ] {
        pipe.to_server.extend(fr);
    }
    pipe.peer_closed = true;
    // Na de eerste schrijfactie (SETTINGS en venster) hangt elke volgende.
    pipe.block_after = Some(1);
    let mut p = raw_peer(
        handler(|mut req, _| {
            Box::pin(async move {
                read_all(&mut req.body).await?;
                Ok(())
            })
        }),
        pipe,
    );
    assert!(
        matches!(p.done(), Some(Err(_))),
        "serve wachtte op een externe Close terwijl WINDOW_UPDATE hing"
    );
    assert_eq!(p.pipe.borrow().closes, 1);
}

#[test]
fn adversarial_close_after_body_eof_stays_clean() {
    let served: Rc<Cell<Option<bool>>> = Rc::default();
    let s = served.clone();
    let mut p = new_peer(handler(move |mut req, mut res| {
        let s = s.clone();
        Box::pin(async move {
            let r = read_all(&mut req.body).await;
            req.body.close();
            res.write_header(204, &[])?;
            s.set(Some(r.is_ok()));
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        1,
        &header_block("/clean-close"),
    );
    p.frame(FRAME_DATA, FLAG_END_STREAM, 1, b"body");
    assert_eq!(served.get(), Some(true));
    p.frame(FRAME_PING, 0, 0, b"abcdefgh");
    for (typ, _, stream, _) in p.drain() {
        assert!(
            !(typ == FRAME_RST_STREAM && stream == 1),
            "lezen tot het einde plus Body.close gaf RST_STREAM"
        );
    }
}

#[test]
fn adversarial_first_peer_frame_must_be_settings() {
    let mut p = new_peer_with_settings(idle(), false);
    p.read_until(FRAME_SETTINGS);
    p.frame(FRAME_PING, 0, 0, b"12345678");
    p.assert_connection_error("SETTINGS");
}

#[test]
fn adversarial_client_push_promise_is_refused() {
    let mut p = new_peer(handler(|_, _| {
        Box::pin(async {
            std::future::pending::<()>().await;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/open"),
    );
    let mut body = 2u32.to_be_bytes().to_vec();
    body.extend(header_block("/pushed"));
    p.frame(FRAME_PUSH_PROMISE, FLAG_END_HEADERS, 1, &body);
    p.assert_connection_error("PUSH");
}

#[test]
fn adversarial_request_headers_are_refused_before_handler() {
    let cases = [
        (
            "CONNECT in origin-vorm",
            vec![
                f(":method", "CONNECT"),
                f(":scheme", "https"),
                f(":path", "/"),
                f(":authority", "example.test"),
            ],
            "CONNECT",
        ),
        (
            "niet-numerieke content-length",
            vec![
                f(":method", "POST"),
                f(":scheme", "https"),
                f(":path", "/"),
                f(":authority", "example.test"),
                f("content-length", "not-a-number"),
            ],
            "content-length",
        ),
    ];
    for (name, fields, want) in cases {
        let reached = Rc::new(Cell::new(false));
        let r = reached.clone();
        let mut p = new_peer(handler(move |_, _| {
            r.set(true);
            Box::pin(async { Ok(()) })
        }));
        p.handshake(None);
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode_fields(&fields),
        );
        assert!(!reached.get(), "{name}: handler bereikt");
        p.assert_connection_error(want);
    }
}

#[test]
fn adversarial_content_length_must_match_data() {
    let read_err: Rc<Cell<Option<bool>>> = Rc::default();
    let re = read_err.clone();
    let mut p = new_peer(handler(move |mut req, mut res| {
        let re = re.clone();
        Box::pin(async move {
            re.set(Some(read_all(&mut req.body).await.is_err()));
            res.write_header(204, &[])?;
            Ok(())
        })
    }));
    p.handshake(None);
    let fields = [
        f(":method", "POST"),
        f(":scheme", "https"),
        f(":path", "/"),
        f(":authority", "example.test"),
        f("content-length", "2"),
    ];
    p.frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &encode_fields(&fields));
    p.frame(FRAME_DATA, FLAG_END_STREAM, 1, b"x");
    assert_eq!(
        read_err.get(),
        Some(true),
        "één DATA-byte voldeed aan content-length 2"
    );
}

#[test]
fn adversarial_data_after_remote_end_stream_is_refused() {
    let mut p = new_peer(handler(|_, _| {
        Box::pin(async {
            std::future::pending::<()>().await;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/ended"),
    );
    p.frame(FRAME_DATA, 0, 1, b"late");
    p.assert_connection_error("after END_STREAM");
}

#[test]
fn adversarial_frames_on_idle_stream_are_refused() {
    for (name, typ, body, want) in [
        ("DATA", FRAME_DATA, &b"idle"[..], "DATA on idle stream"),
        (
            "RST_STREAM",
            FRAME_RST_STREAM,
            &[0, 0, 0, 0][..],
            "RST_STREAM on idle stream",
        ),
    ] {
        let mut p = new_peer(idle());
        p.handshake(None);
        p.frame(typ, 0, 1, body);
        match p.done() {
            Some(Err(e)) => assert!(e.to_string().contains(want), "{name}: {e}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn adversarial_response_rejects_informational_status() {
    let refused: Rc<Cell<Option<bool>>> = Rc::default();
    let r = refused.clone();
    let mut p = new_peer(handler(move |_, mut res| {
        r.set(Some(res.write_header(103, &[]).is_err()));
        Box::pin(async { Ok(()) })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &header_block("/early"),
    );
    assert_eq!(refused.get(), Some(true), "WriteHeader nam een 1xx aan");
}

#[test]
fn adversarial_response_rejects_invalid_headers() {
    let cases: [(&str, (&'static str, &'static str)); 6] = [
        ("pseudo-kop injectie", (":status", "201")),
        ("verbindingsspecifiek veld", ("connection", "keep-alive")),
        ("trailer-veld", ("trailer", "x-checksum")),
        ("content-length in het antwoord", ("content-length", "1")),
        ("ongeldige veldnaam", ("bad name", "value")),
        ("newline in de waarde", ("x-value", "ok\r\nsmuggled: yes")),
    ];
    for (name, field) in cases {
        let refused: Rc<Cell<Option<bool>>> = Rc::default();
        let r = refused.clone();
        let mut p = new_peer(handler(move |_, mut res| {
            r.set(Some(res.write_header(200, &[field]).is_err()));
            Box::pin(async { Ok(()) })
        }));
        p.handshake(None);
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &header_block("/headers"),
        );
        assert_eq!(
            refused.get(),
            Some(true),
            "{name}: ongeldig antwoordveld aangenomen"
        );
        // Een afgewezen kop maakt het afronden een RST_STREAM, nooit kapotte bytes.
        let (_, stream, _) = p.read_until(FRAME_RST_STREAM);
        assert_eq!(stream, 1, "{name}");
    }
}

#[test]
fn adversarial_request_trailers_are_refused() {
    let mut p = new_peer(handler(|_, _| {
        Box::pin(async {
            std::future::pending::<()>().await;
            Ok(())
        })
    }));
    p.handshake(None);
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        1,
        &header_block("/trailers"),
    );
    p.frame(
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &encode_fields(&[f("x-checksum", "done")]),
    );
    p.assert_connection_error("not above the last accepted");
}

#[test]
fn adversarial_bodyless_responses_suppress_data() {
    for (name, method, status) in [
        ("HEAD", "HEAD", 200),
        ("204", "GET", 204),
        ("205", "GET", 205),
        ("304", "GET", 304),
    ] {
        let refused: Rc<Cell<Option<bool>>> = Rc::default();
        let r = refused.clone();
        let mut p = new_peer(handler(move |_, mut res| {
            let r = r.clone();
            Box::pin(async move {
                res.write_header(status, &[])?;
                r.set(Some(res.write(b"body").await.is_err()));
                Ok(())
            })
        }));
        p.handshake(None);
        let fields = [
            f(":method", method),
            f(":scheme", "https"),
            f(":path", "/bodyless"),
            f(":authority", "example.test"),
        ];
        p.frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &encode_fields(&fields),
        );
        assert_eq!(
            refused.get(),
            Some(true),
            "{name}: body op een bodyloos antwoord"
        );
        let payload: usize = p
            .drain()
            .iter()
            .filter(|f| f.0 == FRAME_DATA && f.2 == 1)
            .map(|f| f.3.len())
            .sum();
        assert_eq!(payload, 0, "{name}");
    }
}

#[test]
fn adversarial_hpack_table_is_zero_after_settings_ack() {
    let reached = Rc::new(Cell::new(false));
    let r = reached.clone();
    let mut p = new_peer_with_settings(
        handler(move |_, mut res| {
            r.set(true);
            Box::pin(async move {
                res.write_header(204, &[])?;
                Ok(())
            })
        }),
        false,
    );
    p.frame(FRAME_SETTINGS, 0, 0, &[]);
    p.read_until(FRAME_SETTINGS);
    let (flags, _, _) = p.read_until(FRAME_SETTINGS);
    assert!(flags & FLAG_ACK != 0);
    p.frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]);
    let mut block = Vec::new();
    append_int(&mut block, 0x20, 5, 1); // tabelgrootte-update naar 1
    block.extend(header_block("/after-ack"));
    p.frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block);
    assert!(
        !reached.get(),
        "handler bereikt nadat de tabel boven nul groeide"
    );
    p.assert_connection_error("table size");
}

// --- Clientrol ------------------------------------------------------------------

/// De clientkant van dezelfde pijp: leest wat de server schreef. Leeg is
/// `Pending`, tenzij de server sloot of het script op is (`peer_closed`).
struct ClientEnd(Rc<RefCell<Pipe>>);

impl AsyncRead for ClientEnd {
    type Error = PipeError;
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, PipeError>> {
        let mut p = self.0.borrow_mut();
        if p.to_peer.is_empty() {
            return if p.peer_closed || p.closes > 0 {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
            };
        }
        let n = buf.len().min(p.to_peer.len());
        for (dst, src) in buf.iter_mut().zip(p.to_peer.drain(..n)) {
            *dst = src;
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for ClientEnd {
    type Error = PipeError;
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, PipeError>> {
        self.0.borrow_mut().to_server.extend(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), PipeError>> {
        Poll::Ready(Ok(()))
    }
}

type Frame = (u8, u8, u32, Vec<u8>);
type ClientOutcome = Result<client::Response, client::SendError<PipeError>>;

/// Knipt een bytestroom in frames.
fn split_frames(mut b: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    while b.len() >= 9 {
        let len = usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]);
        let stream = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff;
        out.push((b[3], b[4], stream, b[9..9 + len].to_vec()));
        b = &b[9 + len..];
    }
    assert!(b.is_empty(), "half frame van de client");
    out
}

/// Speelt een script van serverframes af tegen `client::send`, met het einde
/// van de stroom erachter. Geeft de uitkomst en de frames van de client.
fn scripted(
    script: &[Vec<u8>],
    request: &client::Request<'_>,
    limits: &client::Limits,
) -> (ClientOutcome, Vec<Frame>) {
    let pipe = Rc::new(RefCell::new(Pipe {
        peer_closed: true,
        ..Pipe::default()
    }));
    for f in script {
        pipe.borrow_mut().to_peer.extend(f);
    }
    let mut io = ClientEnd(pipe.clone());
    let outcome = {
        let mut fut = std::pin::pin!(client::send(&mut io, request, limits));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(r) => r,
            Poll::Pending => panic!("de client wacht op een script dat op is"),
        }
    };
    let written: Vec<u8> = pipe.borrow().to_server.iter().copied().collect();
    if written.is_empty() {
        return (outcome, Vec::new());
    }
    assert_eq!(&written[..24], CLIENT_PREFACE);
    (outcome, split_frames(&written[24..]))
}

/// Een push zoals APNs hem verwacht.
const PUSH: client::Request<'static> = client::Request {
    method: "POST",
    authority: "api.push.apple.com",
    path: "/3/device/00fc13adff785122",
    header: &[
        ("Apns-Topic", "nl.example.app"),
        ("apns-push-type", "alert"),
    ],
    body: br#"{"aps":{"alert":"hallo"}}"#,
};

fn settings_frame(body: &[u8]) -> Vec<u8> {
    frame_bytes(FRAME_SETTINGS, 0, 0, body)
}

fn status(code: &str) -> Vec<u8> {
    encode_fields(&[f(":status", code)])
}

/// Een literal zonder indexering met Huffman-gecodeerde naam en waarde; onze
/// eigen encoder maakt geen Huffman, een echte server wel.
fn huffman_field(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x00];
    for s in [name, value] {
        let h = crate::huffman::tests::encode(s.as_bytes());
        append_int(&mut out, 0x80, 7, h.len());
        out.extend(h);
    }
    out
}

fn goaway_frame(last: u32, code: u32, debug: &[u8]) -> Vec<u8> {
    let mut body = last.to_be_bytes().to_vec();
    body.extend(code.to_be_bytes());
    body.extend(debug);
    frame_bytes(FRAME_GOAWAY, 0, 0, &body)
}

// De client tegen de eigen server: verzoek met body en velden, een antwoord
// groter dan het standaardvenster (dat kan alleen met ons krediet), en de
// beleefde GOAWAY aan het eind.
#[test]
fn client_round_trip_with_own_server() {
    type Seen = (String, String, String, String, Option<String>, Vec<u8>);
    let seen: Rc<RefCell<Option<Seen>>> = Rc::default();
    let s = seen.clone();
    let answer: Vec<u8> = (0..100 << 10).map(|i| (i % 251) as u8).collect();
    let reply = answer.clone();
    let h = handler(move |mut req, mut res| {
        let s = s.clone();
        let reply = reply.clone();
        Box::pin(async move {
            let body = read_all(&mut req.body).await?;
            *s.borrow_mut() = Some((
                req.method.clone(),
                req.scheme.clone(),
                req.authority.clone(),
                req.path.clone(),
                req.get("apns-topic").map(str::to_owned),
                body,
            ));
            res.write_header(200, &[("apns-id", "eabeae54-14a8-11e5-b60b-1697f925ec7b")])?;
            res.write(&reply).await?;
            Ok(())
        })
    });
    let body: Vec<u8> = (0..20_000).map(|i| (i % 7) as u8).collect();
    let header = [
        ("apns-topic", "nl.example.app"),
        ("content-length", "20000"),
    ];
    let request = client::Request {
        body: &body,
        header: &header,
        ..PUSH
    };
    let limits = client::Limits {
        body: 128 << 10,
        ..client::Limits::default()
    };

    let pipe = Rc::new(RefCell::new(Pipe::default()));
    let mut conn = Conn::new(ServerEnd(pipe.clone()), h);
    let mut serve = std::pin::pin!(conn.serve(std::future::pending()));
    let mut io = ClientEnd(pipe.clone());
    let mut send = std::pin::pin!(client::send(&mut io, &request, &limits));
    let mut cx = Context::from_waker(Waker::noop());
    let mut served = None;
    let mut sent = None;
    for _ in 0..10_000 {
        if served.is_none()
            && let Poll::Ready(r) = serve.as_mut().poll(&mut cx)
        {
            served = Some(r);
        }
        if sent.is_none()
            && let Poll::Ready(r) = send.as_mut().poll(&mut cx)
        {
            sent = Some(r);
        }
        if sent.is_some() && served.is_some() {
            break;
        }
    }
    let response = sent
        .expect("de client bleef hangen")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(response.status, 200);
    assert_eq!(
        response.get("apns-id"),
        Some("eabeae54-14a8-11e5-b60b-1697f925ec7b")
    );
    assert!(response.body == answer, "antwoordbody verschilt");
    let (method, scheme, authority, path, topic, got) = seen.borrow_mut().take().unwrap();
    assert_eq!(
        (method.as_str(), scheme.as_str(), authority.as_str()),
        ("POST", "https", "api.push.apple.com")
    );
    assert_eq!(path, PUSH.path);
    assert_eq!(topic.as_deref(), Some("nl.example.app"));
    assert!(got == body, "verzoekbody verschilt");
    // De server zag de GOAWAY van de client: zo eindigt een beleefde client.
    let served = served.expect("de server stopte niet");
    assert_eq!(
        served,
        Err(ServeError::Protocol(Error::PeerGoAway { code: 0 }))
    );
}

// Huffman-literals, een blok over HEADERS en CONTINUATION, een 1xx vooraf,
// opgevulde DATA, PING en SETTINGS: alles wat een echte server kan sturen.
#[test]
fn client_reads_huffman_continuation_and_interim() {
    let mut block = status("200");
    block.extend(huffman_field("apns-id", "eabeae54-14a8-11e5"));
    block.extend(huffman_field("x-reden", "Gelukt, met spaties"));
    let (first, rest) = block.split_at(5);
    let script = [
        settings_frame(&setting(SETTING_MAX_CONCURRENT, 1000)),
        frame_bytes(FRAME_SETTINGS, FLAG_ACK, 0, &[]),
        frame_bytes(FRAME_PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]),
        frame_bytes(FRAME_WINDOW_UPDATE, 0, 0, &1000u32.to_be_bytes()),
        frame_bytes(FRAME_PRIORITY, 0, 1, &[0, 0, 0, 0, 15]),
        frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS, 1, &status("103")),
        frame_bytes(FRAME_HEADERS, 0, 1, first),
        frame_bytes(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, rest),
        frame_bytes(FRAME_DATA, FLAG_PADDED, 1, &[2, b'h', b'e', b'l', 0, 0]),
        frame_bytes(FRAME_DATA, FLAG_END_STREAM, 1, b"lo"),
    ];
    let (outcome, written) = scripted(&script, &PUSH, &client::Limits::default());
    let response = outcome.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(response.status, 200);
    assert_eq!(response.get("apns-id"), Some("eabeae54-14a8-11e5"));
    assert_eq!(response.get("x-reden"), Some("Gelukt, met spaties"));
    assert_eq!(response.body, b"hello");

    let kinds: Vec<(u8, u8, u32)> = written.iter().map(|f| (f.0, f.1, f.2)).collect();
    assert_eq!(
        kinds,
        [
            (FRAME_SETTINGS, 0, 0),
            (FRAME_SETTINGS, FLAG_ACK, 0),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1),
            (FRAME_DATA, FLAG_END_STREAM, 1),
            (FRAME_PING, FLAG_ACK, 0),
            (FRAME_WINDOW_UPDATE, 0, 1),
            (FRAME_WINDOW_UPDATE, 0, 0),
            (FRAME_GOAWAY, 0, 0),
        ]
    );
    // Onze SETTINGS: geen push, en de koplijstgrens.
    assert_eq!(
        written[0].3,
        [
            setting(SETTING_ENABLE_PUSH, 0),
            setting(SETTING_MAX_HEADER_LIST_SIZE, 16 << 10)
        ]
        .concat()
    );
    assert_eq!(
        decode(&written[2].3),
        [
            f(":method", "POST"),
            f(":scheme", "https"),
            f(":authority", "api.push.apple.com"),
            f(":path", PUSH.path),
            f("apns-topic", "nl.example.app"),
            f("apns-push-type", "alert"),
        ]
    );
    assert_eq!(written[3].3, PUSH.body);
    assert_eq!(written[4].3, [1, 2, 3, 4, 5, 6, 7, 8]);
    // Krediet voor de hele opgevulde inhoud: zes bytes.
    assert_eq!(written[5].3, 6u32.to_be_bytes());
    assert_eq!(written[7].3, [0; 8], "GOAWAY: stream 0, NO_ERROR");
}

#[test]
fn client_reports_goaway_and_reset() {
    let limits = client::Limits::default();
    let settings = settings_frame(&[]);
    // Stream 1 niet verwerkt: veilig opnieuw, en dat zegt `last_stream`.
    let (outcome, _) = scripted(&[settings.clone(), goaway_frame(0, 0, b"")], &PUSH, &limits);
    assert_eq!(
        outcome.err(),
        Some(client::SendError::GoAway {
            code: 0,
            last_stream: 0
        })
    );
    let (outcome, _) = scripted(
        &[
            settings.clone(),
            goaway_frame(1, 2, br#"{"reason":"Shutdown"}"#),
        ],
        &PUSH,
        &limits,
    );
    assert_eq!(
        outcome.err(),
        Some(client::SendError::GoAway {
            code: 2,
            last_stream: 1
        })
    );
    let (outcome, written) = scripted(
        &[
            settings.clone(),
            frame_bytes(FRAME_RST_STREAM, 0, 1, &7u32.to_be_bytes()),
        ],
        &PUSH,
        &limits,
    );
    assert_eq!(outcome.err(), Some(client::SendError::Reset { code: 7 }));
    assert!(
        written.iter().all(|f| f.0 != FRAME_GOAWAY),
        "na een fout ging er toch nog iets uit"
    );
    // Een nette stop die stream 1 nog afmaakt, is geen fout.
    let (outcome, _) = scripted(
        &[
            settings,
            goaway_frame(1, 0, b""),
            frame_bytes(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                &status("200"),
            ),
        ],
        &PUSH,
        &limits,
    );
    assert_eq!(outcome.unwrap().status, 200);
}

#[test]
fn client_limits_overflow() {
    let settings = settings_frame(&[]);
    let headers = frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS, 1, &status("400"));
    let limits = client::Limits {
        body: 4,
        ..client::Limits::default()
    };
    let (outcome, _) = scripted(
        &[
            settings.clone(),
            headers,
            frame_bytes(FRAME_DATA, FLAG_END_STREAM, 1, br#"{"reason":"x"}"#),
        ],
        &PUSH,
        &limits,
    );
    assert_eq!(
        outcome.err(),
        Some(client::SendError::BodyTooLarge { limit: 4 })
    );

    let mut block = status("200");
    block.extend(encode_fields(&[f("x-lang", &"a".repeat(100))]));
    let limits = client::Limits {
        header_list: 64,
        ..client::Limits::default()
    };
    let (outcome, _) = scripted(
        &[
            settings,
            frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block),
        ],
        &PUSH,
        &limits,
    );
    assert_eq!(
        outcome.err(),
        Some(client::SendError::Protocol(Error::HeaderBlock {
            stream: 1,
            cause: HpackError::ListTooLarge { limit: 64 },
        }))
    );
}

// Een body groter dan het venster wacht niet: hij faalt vóór HEADERS.
#[test]
fn client_body_above_window_is_refused() {
    let small = settings_frame(&setting(SETTING_INITIAL_WINDOW_SIZE, 10));
    let (outcome, written) = scripted(&[small], &PUSH, &client::Limits::default());
    assert_eq!(
        outcome.err(),
        Some(client::SendError::BodyAboveWindow {
            len: PUSH.body.len(),
            window: 10
        })
    );
    assert!(
        written
            .iter()
            .all(|f| f.0 != FRAME_HEADERS && f.0 != FRAME_DATA)
    );

    // Zonder instelling geldt het standaardvenster van de verbinding.
    let body = vec![0u8; 65_536];
    let request = client::Request {
        body: &body,
        ..PUSH
    };
    let (outcome, _) = scripted(
        &[settings_frame(&setting(
            SETTING_INITIAL_WINDOW_SIZE,
            1 << 20,
        ))],
        &request,
        &client::Limits::default(),
    );
    assert_eq!(
        outcome.err(),
        Some(client::SendError::BodyAboveWindow {
            len: 65_536,
            window: 65_535
        })
    );
}

#[test]
fn client_refuses_malformed_responses() {
    let ends = FLAG_END_HEADERS | FLAG_END_STREAM;
    let headers = |fields: &[Field]| frame_bytes(FRAME_HEADERS, ends, 1, &encode_fields(fields));
    let cases: Vec<(&str, Vec<Vec<u8>>, &str)> = vec![
        (
            "geen status",
            vec![headers(&[f("server", "x")])],
            "no :status",
        ),
        (
            "pseudo na gewoon veld",
            vec![headers(&[f("server", "x"), f(":status", "200")])],
            "pseudo-header after",
        ),
        (
            "verzoek-pseudo",
            vec![headers(&[f(":status", "200"), f(":path", "/")])],
            "other than :status",
        ),
        (
            "hoofdletters",
            vec![headers(&[f(":status", "200"), f("X-Up", "1")])],
            "lowercase token",
        ),
        (
            "verbindingsveld",
            vec![headers(&[f(":status", "200"), f("connection", "close")])],
            "connection-specific",
        ),
        ("status 101", vec![headers(&[f(":status", "101")])], "101"),
        (
            "tussenantwoord met END_STREAM",
            vec![headers(&[f(":status", "100")])],
            "interim",
        ),
        (
            "DATA voor HEADERS",
            vec![frame_bytes(FRAME_DATA, FLAG_END_STREAM, 1, b"x")],
            "frame type 0x00 on stream 1",
        ),
        (
            "HEADERS op een andere stream",
            vec![frame_bytes(FRAME_HEADERS, ends, 3, &status("200"))],
            "on stream 3",
        ),
        (
            "PUSH_PROMISE",
            vec![frame_bytes(
                FRAME_PUSH_PROMISE,
                FLAG_END_HEADERS,
                1,
                &[0, 0, 0, 2],
            )],
            "PUSH_PROMISE",
        ),
        (
            "content-length klopt niet",
            vec![
                frame_bytes(
                    FRAME_HEADERS,
                    FLAG_END_HEADERS,
                    1,
                    &encode_fields(&[f(":status", "200"), f("content-length", "5")]),
                ),
                frame_bytes(FRAME_DATA, FLAG_END_STREAM, 1, b"abc"),
            ],
            "content-length does not match",
        ),
        (
            "trailers zonder END_STREAM",
            vec![
                frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS, 1, &status("200")),
                frame_bytes(
                    FRAME_HEADERS,
                    FLAG_END_HEADERS,
                    1,
                    &encode_fields(&[f("x", "y")]),
                ),
            ],
            "trailers without END_STREAM",
        ),
        (
            "onderbroken blok",
            vec![
                frame_bytes(FRAME_HEADERS, 0, 1, &status("200")),
                frame_bytes(FRAME_PING, 0, 0, &[0; 8]),
            ],
            "interrupted the header block",
        ),
        (
            "einde voor het antwoord",
            vec![frame_bytes(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                1,
                &status("200"),
            )],
            "closed the connection",
        ),
        (
            "frame te groot",
            vec![{
                let mut big = frame_bytes(FRAME_DATA, 0, 1, &[]);
                big[..3].copy_from_slice(&[0, 0x40, 0x01]);
                big
            }],
            "16385 byte frame",
        ),
    ];
    for (name, frames, want) in cases {
        let mut script = vec![settings_frame(&[])];
        script.extend(frames);
        let (outcome, _) = scripted(&script, &PUSH, &client::Limits::default());
        let err = outcome
            .err()
            .unwrap_or_else(|| panic!("{name}: geaccepteerd"));
        assert!(err.to_string().contains(want), "{name}: {err}");
    }
    // De preface van de server is SETTINGS, niets anders.
    let (outcome, _) = scripted(
        &[frame_bytes(FRAME_PING, 0, 0, &[0; 8])],
        &PUSH,
        &client::Limits::default(),
    );
    assert_eq!(
        outcome.err(),
        Some(client::SendError::Protocol(Error::FirstFrameNotSettings))
    );
    // Trailers die netjes eindigen, worden gelezen en weggegooid.
    let (outcome, _) = scripted(
        &[
            settings_frame(&[]),
            frame_bytes(FRAME_HEADERS, FLAG_END_HEADERS, 1, &status("200")),
            frame_bytes(FRAME_DATA, 0, 1, b"ok"),
            frame_bytes(FRAME_HEADERS, ends, 1, &encode_fields(&[f("x-check", "1")])),
        ],
        &PUSH,
        &client::Limits::default(),
    );
    let response = outcome.unwrap();
    assert_eq!(
        (response.status, response.body.as_slice()),
        (200, &b"ok"[..])
    );
    assert_eq!(response.get("x-check"), None);
}

// Een verzoek dat zo niet de draad op kan, faalt vóór de eerste byte.
#[test]
fn client_refuses_bad_requests_before_writing() {
    let cases: [(&str, client::Request<'static>); 8] = [
        (
            "CONNECT",
            client::Request {
                method: "CONNECT",
                ..PUSH
            },
        ),
        ("geen methode", client::Request { method: "", ..PUSH }),
        (
            "lege authority",
            client::Request {
                authority: "",
                ..PUSH
            },
        ),
        (
            "pad zonder slash",
            client::Request {
                path: "3/device",
                ..PUSH
            },
        ),
        (
            "verbindingsveld",
            client::Request {
                header: &[("Connection", "close")],
                ..PUSH
            },
        ),
        (
            "host",
            client::Request {
                header: &[("host", "api.push.apple.com")],
                ..PUSH
            },
        ),
        (
            "te",
            client::Request {
                header: &[("te", "gzip")],
                ..PUSH
            },
        ),
        (
            "content-length",
            client::Request {
                header: &[("content-length", "3")],
                ..PUSH
            },
        ),
    ];
    for (name, request) in cases {
        let (outcome, written) =
            scripted(&[settings_frame(&[])], &request, &client::Limits::default());
        assert!(
            matches!(outcome, Err(client::SendError::Request(_))),
            "{name}: {outcome:?}"
        );
        assert!(written.is_empty(), "{name}: er ging iets de draad op");
    }
}
