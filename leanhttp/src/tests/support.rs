//! Testgereedschap: een in-memory pijp met virtuele tijd, een executor van
//! een paar tientallen regels, en een testnetwerk dat als [`Dial`] werkt.
//!
//! Zoals de Go-tests een `net.Pipe` en echte listeners gebruikten, draait hier
//! alles in één thread. De tijd is discreet: staat elke taak stil zonder dat er
//! een byte bewoog, dan springt de klok naar de vroegste termijn die iemand
//! wacht. Zo loopt een test van "15 seconden stilte" in microseconden, en
//! deterministisch.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::{
    AsyncRead, AsyncWrite, Close, Dial, Error, Exchange, IoError, Result, Target, close, read,
    serve, write_all,
};

type Task = Pin<Box<dyn Future<Output = ()>>>;

thread_local! {
    static NOW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static PROGRESS: Cell<u64> = const { Cell::new(0) };
    static NEXT: Cell<Option<Duration>> = const { Cell::new(None) };
    static SPAWNED: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
}

/// De virtuele tijd.
pub(crate) fn now() -> Duration {
    NOW.with(Cell::get)
}

fn bump() {
    PROGRESS.with(|p| p.set(p.get() + 1));
}

fn wake_at(t: Duration) {
    NEXT.with(|n| n.set(Some(n.get().map_or(t, |c| c.min(t)))));
}

/// Start een achtergrondtaak op de executor.
pub(crate) fn spawn(f: impl Future<Output = ()> + 'static) {
    SPAWNED.with(|s| s.borrow_mut().push(Box::pin(f)));
}

/// Draait `main` tot hij klaar is, met alle gespawnde taken ernaast.
pub(crate) fn block_on<F: Future>(main: F) -> F::Output {
    NOW.with(|n| n.set(Duration::ZERO));
    SPAWNED.with(|s| s.borrow_mut().clear());
    let mut cx = Context::from_waker(Waker::noop());
    let mut main = std::pin::pin!(main);
    let mut tasks: Vec<Option<Task>> = Vec::new();
    for _ in 0..5_000_000 {
        let before = PROGRESS.with(Cell::get);
        NEXT.with(|n| n.set(None));
        let mut finished = false;
        if let Poll::Ready(v) = main.as_mut().poll(&mut cx) {
            tasks.clear();
            SPAWNED.with(|s| s.borrow_mut().clear());
            return v;
        }
        SPAWNED.with(|s| tasks.extend(s.borrow_mut().drain(..).map(Some)));
        let mut i = 0;
        while i < tasks.len() {
            if let Some(t) = tasks[i].as_mut()
                && t.as_mut().poll(&mut cx).is_ready()
            {
                tasks[i] = None;
                finished = true;
            }
            SPAWNED.with(|s| tasks.extend(s.borrow_mut().drain(..).map(Some)));
            i += 1;
        }
        if PROGRESS.with(Cell::get) == before && !finished {
            match NEXT.with(Cell::get) {
                Some(t) => NOW.with(|n| n.set(t.max(n.get()))),
                None => panic!("deadlock: every task waits without a deadline"),
            }
        }
    }
    panic!("test did not finish");
}

/// Wacht `d` virtuele tijd.
pub(crate) async fn sleep(d: Duration) {
    let until = now() + d;
    std::future::poll_fn(|_| {
        if now() >= until {
            Poll::Ready(())
        } else {
            wake_at(until);
            Poll::Pending
        }
    })
    .await;
}

/// Welke van twee futures eerst klaar is.
pub(crate) enum Either<A, B> {
    Left(A),
    Right(B),
}

/// Twee futures, één wint; de ander valt.
pub(crate) async fn select<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

#[derive(Default)]
struct Dir {
    buf: VecDeque<u8>,
    /// De schrijver sloot: de lezer ziet EOF na de buffer.
    eof: bool,
    /// De lezer sloot: de schrijver krijgt een reset.
    gone: bool,
}

struct Shared {
    dirs: [Dir; 2],
    cap: usize,
}

/// Wat een pijpkant bijhoudt voor asserties.
#[derive(Default, Debug)]
pub(crate) struct Stats {
    /// Socketwrites zonder schrijftermijn.
    pub(crate) unarmed_writes: usize,
    /// De schrijftermijn staat nu.
    pub(crate) write_armed: bool,
    /// De kant is gesloten.
    pub(crate) closed: bool,
}

/// Eén kant van een in-memory verbinding.
pub(crate) struct End {
    shared: Rc<RefCell<Shared>>,
    side: usize,
    read_deadline: Option<Duration>,
    write_deadline: Option<Duration>,
    closed: bool,
    pub(crate) stats: Rc<RefCell<Stats>>,
    /// Doet alsof de buffers groeiden (leannet).
    pub(crate) grown: bool,
    /// Weigert termijnen te zetten.
    pub(crate) refuse_timeouts: bool,
}

/// Een pijp met onbegrensde buffers.
pub(crate) fn pipe() -> (End, End) {
    pipe_cap(usize::MAX)
}

/// Een pijp met hoogstens `cap` bytes onderweg per richting.
pub(crate) fn pipe_cap(cap: usize) -> (End, End) {
    let shared = Rc::new(RefCell::new(Shared {
        dirs: [Dir::default(), Dir::default()],
        cap,
    }));
    let end = |side| End {
        shared: shared.clone(),
        side,
        read_deadline: None,
        write_deadline: None,
        closed: false,
        stats: Rc::default(),
        grown: false,
        refuse_timeouts: false,
    };
    (end(0), end(1))
}

impl End {
    fn shut(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.stats.borrow_mut().closed = true;
        let mut sh = self.shared.borrow_mut();
        sh.dirs[1 - self.side].eof = true;
        sh.dirs[self.side].gone = true;
        sh.dirs[self.side].buf.clear();
        bump();
    }

    /// Zegt of deze kant gesloten is.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for End {
    fn drop(&mut self) {
        self.shut();
    }
}

impl AsyncRead for End {
    fn poll_read(&mut self, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, IoError>> {
        if self.closed {
            return Poll::Ready(Err(IoError::Closed));
        }
        let mut sh = self.shared.borrow_mut();
        let d = &mut sh.dirs[self.side];
        if !d.buf.is_empty() {
            let n = d.buf.len().min(buf.len());
            for (slot, b) in buf.iter_mut().zip(d.buf.drain(..n)) {
                *slot = b;
            }
            bump();
            return Poll::Ready(Ok(n));
        }
        if d.eof {
            return Poll::Ready(Ok(0));
        }
        match self.read_deadline {
            Some(t) if now() >= t => Poll::Ready(Err(IoError::TimedOut)),
            Some(t) => {
                wake_at(t);
                Poll::Pending
            }
            None => Poll::Pending,
        }
    }

    fn set_read_timeout(&mut self, t: Option<Duration>) -> Result<(), IoError> {
        if self.refuse_timeouts {
            return Err(IoError::Other);
        }
        self.read_deadline = t.map(|t| now() + t);
        Ok(())
    }
}

impl AsyncWrite for End {
    fn poll_write(&mut self, _: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IoError>> {
        if self.closed {
            return Poll::Ready(Err(IoError::Closed));
        }
        if self.write_deadline.is_none() {
            self.stats.borrow_mut().unarmed_writes += 1;
        }
        let mut sh = self.shared.borrow_mut();
        let cap = sh.cap;
        let d = &mut sh.dirs[1 - self.side];
        if d.gone {
            return Poll::Ready(Err(IoError::Reset));
        }
        let room = cap.saturating_sub(d.buf.len());
        if room == 0 {
            return match self.write_deadline {
                Some(t) if now() >= t => Poll::Ready(Err(IoError::TimedOut)),
                Some(t) => {
                    wake_at(t);
                    Poll::Pending
                }
                None => Poll::Pending,
            };
        }
        let n = room.min(buf.len());
        d.buf.extend(&buf[..n]);
        bump();
        Poll::Ready(Ok(n))
    }

    fn set_write_timeout(&mut self, t: Option<Duration>) -> Result<(), IoError> {
        if self.refuse_timeouts {
            return Err(IoError::Other);
        }
        self.write_deadline = t.map(|t| now() + t);
        self.stats.borrow_mut().write_armed = t.is_some();
        Ok(())
    }
}

impl Close for End {
    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.shut();
        Poll::Ready(Ok(()))
    }

    fn has_grown(&self) -> bool {
        self.grown
    }
}

/// Leest tot EOF, een fout of een termijn, en geeft wat er kwam.
pub(crate) async fn read_all(c: &mut End) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match read(c, &mut buf).await {
            Ok(0) | Err(_) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Leest één regel (tot en met LF).
pub(crate) async fn read_line(c: &mut End) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match read(c, &mut b).await {
            Ok(1) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    return Some(String::from_utf8_lossy(&line).into_owned());
                }
            }
            _ => {
                return if line.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&line).into_owned())
                };
            }
        }
    }
}

/// Leest een requestkop tot de lege regel en geeft hem terug.
pub(crate) async fn read_head(c: &mut End) -> Option<String> {
    let mut head = String::new();
    loop {
        let line = read_line(c).await?;
        head.push_str(&line);
        if line == "\r\n" {
            return Some(head);
        }
    }
}

/// Een test-handler zoals `serve` hem wil, gedeeld over verbindingen.
pub(crate) type Handler = Rc<dyn Fn(End)>;

/// Maakt een accept-functie die elke verbinding met `serve` bedient.
pub(crate) fn lean<H>(h: H) -> Handler
where
    H: AsyncFn(&mut Exchange<'_, End>) -> Result + 'static,
{
    let h = Rc::new(h);
    Rc::new(move |conn: End| {
        let h = h.clone();
        spawn(async move {
            let _ = serve(conn, &*h).await;
        });
    })
}

/// Een rauwe server: leest wat er komt (één keer), schrijft `answer`, sluit.
pub(crate) fn raw(answer: &'static str) -> Handler {
    Rc::new(move |mut conn: End| {
        spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = read(&mut conn, &mut buf).await;
            let _ = write_all(&mut conn, answer.as_bytes()).await;
            let _ = close(&mut conn).await;
        });
    })
}

/// Een script-server: `f` krijgt de verbinding.
pub(crate) fn script<F, Fut>(f: F) -> Handler
where
    F: Fn(End) -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    Rc::new(move |conn: End| spawn(f(conn)))
}

/// Een testnetwerk: hosts op naam, en een teller per host.
#[derive(Clone, Default)]
pub(crate) struct Net {
    hosts: Rc<RefCell<HashMap<String, Handler>>>,
    accepts: Rc<RefCell<HashMap<String, usize>>>,
    /// Laat de dialer zeggen dat hij versleutelt.
    pub(crate) tls: bool,
    /// Elke gedialde kant krijgt deze vlag (leannet-groei).
    pub(crate) grown: bool,
    /// De laatst gedialde target als `host:poort`.
    pub(crate) last: Rc<RefCell<String>>,
}

impl Net {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Zet `h` op `addr` (`host:poort`).
    pub(crate) fn add(&self, addr: &str, h: Handler) {
        self.hosts.borrow_mut().insert(addr.to_string(), h);
    }

    /// Aantal verbindingen dat `addr` aannam.
    pub(crate) fn accepted(&self, addr: &str) -> usize {
        self.accepts.borrow().get(addr).copied().unwrap_or(0)
    }

    /// Opent een verbinding met de host op `addr`, als rauwe client.
    pub(crate) fn connect(&self, addr: &str) -> End {
        let h = self
            .hosts
            .borrow()
            .get(addr)
            .cloned()
            .expect("no such host");
        *self
            .accepts
            .borrow_mut()
            .entry(addr.to_string())
            .or_default() += 1;
        let (a, b) = pipe();
        h(b);
        a
    }
}

impl Dial for Net {
    type Conn = End;

    async fn dial(&mut self, t: Target<'_>) -> Result<End> {
        let addr = format!("{}:{}", t.host, t.port);
        *self.last.borrow_mut() = addr.clone();
        if !self.hosts.borrow().contains_key(&addr) {
            return Err(Error::Io(IoError::Reset));
        }
        let mut c = self.connect(&addr);
        c.grown = self.grown;
        Ok(c)
    }

    fn is_encrypted(&self) -> bool {
        self.tls
    }
}

/// Een dialer die nooit gebruikt mag worden: de fout moest vóór de dial.
pub(crate) struct NoDial;

impl Dial for NoDial {
    type Conn = End;

    async fn dial(&mut self, _: Target<'_>) -> Result<End> {
        panic!("dial happened, but the error should have come first");
    }
}

/// Stuurt `request` naar een verse verbinding met `h`, en leest tot de server
/// sluit of 2 seconden stil is (zoals `rawRoundTrip` in Go).
pub(crate) async fn round_trip(h: &Handler, request: &str) -> String {
    let (mut a, b) = pipe();
    h(b);
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let _ = write_all(&mut a, request.as_bytes()).await;
    String::from_utf8_lossy(&read_all(&mut a).await).into_owned()
}

/// Synchrone vorm van [`round_trip`].
pub(crate) fn rt(h: &Handler, request: &str) -> String {
    block_on(round_trip(h, request))
}
