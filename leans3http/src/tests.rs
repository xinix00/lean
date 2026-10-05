//! De brug tegen een server in het geheugen: per verbinding een rij
//! antwoorden, die pas klaarstaat als het verzoek geschreven is.

use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::ToString;
use std::task::Waker;

/// Een antwoord, of een server die nooit antwoordt.
#[derive(Clone)]
enum Turn {
    Answer(&'static [u8]),
    Hang,
}

struct Wire {
    turns: VecDeque<Turn>,
    ready: Vec<u8>,
    at: usize,
    seen: usize,
    written: Rc<RefCell<Vec<u8>>>,
}

impl leanhttp::AsyncRead for Wire {
    fn poll_read(
        &mut self,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, leanhttp::IoError>> {
        if self.at == self.ready.len() {
            let written = self.written.borrow().len();
            if written == self.seen {
                // Geen nieuw verzoek: niets te zeggen. Een keep-alive-
                // verbinding zonder verzoek wacht, net als een echte.
                return Poll::Pending;
            }
            self.seen = written;
            match self.turns.pop_front() {
                Some(Turn::Answer(bytes)) => {
                    self.ready = bytes.to_vec();
                    self.at = 0;
                }
                Some(Turn::Hang) => return Poll::Pending,
                None => return Poll::Ready(Ok(0)),
            }
        }
        let n = buf.len().min(self.ready.len() - self.at);
        buf[..n].copy_from_slice(&self.ready[self.at..self.at + n]);
        self.at += n;
        Poll::Ready(Ok(n))
    }
}

impl leanhttp::AsyncWrite for Wire {
    fn poll_write(
        &mut self,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, leanhttp::IoError>> {
        self.written.borrow_mut().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
}

impl leanhttp::Close for Wire {
    fn poll_close(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), leanhttp::IoError>> {
        Poll::Ready(Ok(()))
    }
}

/// Per dial de volgende verbinding met zijn antwoorden.
#[derive(Clone, Default)]
struct Net {
    conns: Rc<RefCell<VecDeque<Vec<Turn>>>>,
    dials: Rc<Cell<u32>>,
    written: Rc<RefCell<Vec<u8>>>,
}

impl Dial for Net {
    type Conn = Wire;

    async fn dial(&mut self, _: leanhttp::Target<'_>) -> leanhttp::Result<Wire> {
        self.dials.set(self.dials.get() + 1);
        let turns = self
            .conns
            .borrow_mut()
            .pop_front()
            .ok_or(leanhttp::Error::Connect)?;
        Ok(Wire {
            turns: turns.into(),
            ready: Vec::new(),
            at: 0,
            seen: 0,
            written: self.written.clone(),
        })
    }
}

/// Een klok die niet loopt en elke wachttijd noteert; wachten is direct klaar.
#[derive(Clone, Default)]
struct Still(Rc<RefCell<Vec<Duration>>>);

impl Clock for Still {
    fn now(&self) -> Duration {
        Duration::from_secs(100)
    }
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> {
        self.0.borrow_mut().push(duration);
        core::future::ready(())
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("future hangs");
}

fn client() -> leans3::Client {
    leans3::Client {
        endpoint: "http://s3.example.test".into(),
        bucket: "b".into(),
        region: "us-east-1".into(),
        access_key_id: "AK".into(),
        secret_access_key: "SK".into(),
        session_token: String::new(),
        path_style: true,
        now: Some(|| 1_790_000_000),
    }
}

fn net(conns: Vec<Vec<Turn>>) -> Net {
    let net = Net::default();
    *net.conns.borrow_mut() = conns.into();
    net
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"e1\"\r\n\r\nhello";
const BUSY: &[u8] = b"HTTP/1.1 503 Slow Down\r\nContent-Length: 0\r\n\r\n";
const MISSING: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

#[test]
fn get_keeps_one_connection_and_reports_the_body() {
    let net = net(vec![vec![Turn::Answer(OK), Turn::Answer(MISSING)]]);
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = seen.clone();
    let mut http = Http::new(net.clone(), Still::default())
        .observe(move |target, n| log.borrow_mut().push((target.to_string(), n)));
    let (body, etag) = block_on(client().get(&mut http, "data/a")).unwrap();
    assert_eq!(
        (body.as_slice(), etag.as_deref()),
        (&b"hello"[..], Some("\"e1\""))
    );
    assert_eq!(
        block_on(client().get(&mut http, "data/b")),
        Err(leans3::Error::NotFound)
    );
    // Eén verbinding voor beide verzoeken, en SigV4 ging mee.
    assert_eq!(net.dials.get(), 1);
    let written = String::from_utf8(net.written.borrow().clone()).unwrap();
    assert!(
        written.starts_with("GET /b/data/a HTTP/1.1\r\n"),
        "{written}"
    );
    assert!(written.contains("Authorization: AWS4-HMAC-SHA256 "));
    assert_eq!(seen.borrow()[0], ("/b/data/a".to_string(), 5));
}

#[test]
fn get_retries_busy_and_broken_with_growing_waits() {
    // 503, dan een verbinding die niets zegt, dan het antwoord.
    let net = net(vec![
        vec![Turn::Answer(BUSY)],
        vec![],
        vec![Turn::Answer(OK)],
    ]);
    let clock = Still::default();
    let mut http = Http::new(net.clone(), clock.clone());
    let (body, _) = block_on(client().get(&mut http, "data/a")).unwrap();
    assert_eq!(body, b"hello");
    // Per poging een termijn van 60 s, en daartussen 1 en 2 s wachten.
    let waits = clock.0.borrow().clone();
    let pauses: Vec<_> = waits.iter().filter(|d| d.as_secs() < 60).collect();
    assert_eq!(pauses, [&Duration::from_secs(1), &Duration::from_secs(2)]);
}

#[test]
fn put_is_never_repeated_and_a_silent_server_times_out() {
    let net = net(vec![vec![Turn::Answer(BUSY)], vec![Turn::Hang]]);
    let mut http = Http::new(net.clone(), Still::default());
    let err = block_on(client().put(&mut http, "k", b"x", &leans3::PutOptions::default()));
    assert!(matches!(err, Err(leans3::Error::Status(ref s)) if s.code == 503));
    assert_eq!(net.dials.get(), 1);
    // Een server die zwijgt: de termijn van de poging beslist, niet de server.
    http.limits.attempts = 1;
    let err = block_on(client().get(&mut http, "k")).unwrap_err();
    assert!(matches!(err, leans3::Error::Transport { .. }), "{err:?}");
    assert_eq!(
        http.last_error(),
        Some(leanhttp::Error::Io(leanhttp::IoError::TimedOut))
    );
}

#[test]
fn streamed_put_sends_its_body_after_continue() {
    const CONTINUE: &[u8] =
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"e2\"\r\n\r\n";
    let net = net(vec![vec![Turn::Answer(CONTINUE)]]);
    let mut http = Http::new(net.clone(), Still::default());
    let payload = vec![7u8; 100_000];
    let mut source = Source(&payload);
    let etag = block_on(client().put_from(
        &mut http,
        "big",
        &mut source,
        payload.len() as u64,
        // De nepserver toetst de handtekening niet; het formaat telt.
        &"ab".repeat(32),
        &leans3::PutOptions::default(),
    ))
    .unwrap();
    assert_eq!(etag.as_deref(), Some("\"e2\""));
    let written = net.written.borrow();
    assert!(written.ends_with(&payload));
}

/// Een bron uit het geheugen.
struct Source<'a>(&'a [u8]);

impl leans3::AsyncRead for Source<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Poll::Ready(Ok(n))
    }
}

/// Een schrijver die alleen telt.
#[derive(Default)]
struct Count(u64);

impl leans3::AsyncWrite for Count {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.0 += buf.len() as u64;
        Poll::Ready(Ok(buf.len()))
    }
}

#[test]
fn a_body_above_the_old_buffer_limit_streams_and_counts() {
    // 40 MiB: meer dan de 32 MiB die in het geheugen paste.
    let len = 40usize << 20;
    let mut answer =
        std::format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nETag: \"big\"\r\n\r\n")
            .into_bytes();
    answer.resize(answer.len() + len, 7);
    let answer: &'static [u8] = Box::leak(answer.into_boxed_slice());
    let net = net(vec![vec![Turn::Answer(answer), Turn::Answer(OK)]]);
    let seen = Rc::new(Cell::new(0usize));
    let total = seen.clone();
    let mut http =
        Http::new(net.clone(), Still::default()).observe(move |_, n| total.set(total.get() + n));
    let mut sink = Count::default();
    let (n, etag) = block_on(client().get_to(&mut http, "data/big", &mut sink)).unwrap();
    assert_eq!(
        (n, sink.0, etag.as_deref()),
        (len as u64, len as u64, Some("\"big\""))
    );
    // De teller liep mee per stuk, niet in één keer aan het eind.
    assert_eq!(seen.get(), len);
    // De verbinding ging na de laatste byte terug in de pool.
    let (body, _) = block_on(client().get(&mut http, "data/a")).unwrap();
    assert_eq!(body, b"hello");
    assert_eq!(net.dials.get(), 1);
}
