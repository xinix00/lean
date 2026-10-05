//! TCP van een host als leanhttp-verbinding (feature `std`).
//!
//! Iedere hostapp die over HTTP praatte, schreef dezelfde brug: een
//! std-`TcpStream` met de termijnen van leanhttp, en een dialer die een naam
//! opzoekt en de adressen afloopt. Die staat hier één keer. TLS komt erboven
//! (`leanhttps::WebDial`), net als op HopOS boven `applib::tcp::Dialer`.
//!
//! Twee manieren van wachten, gekozen met de [`Reactor`]:
//!
//! - [`Blocking`]: een blokkerende socket; elke lees of schrijf krijgt de
//!   resterende tijd als sockettermijn. Voor een eigenaar die per verzoek een
//!   thread of een eigen lus heeft.
//! - een eigen reactor: een niet-blokkerende socket; bij `WouldBlock` meldt
//!   de verbinding haar interesse ([`Reactor::wait`]) en geeft `Pending`. De
//!   termijnen worden bij elke poll getoetst.

use core::fmt;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Instant;

use crate::client::{Dial, Target};
use crate::error::{Error, Result};
use crate::io::{AsyncRead, AsyncWrite, Close, IoError};

/// Hoe een [`TcpConn`] wacht.
pub trait Reactor {
    /// `true`: een blokkerende socket met sockettermijnen; [`Reactor::wait`]
    /// wordt dan nooit aangeroepen.
    const BLOCKING: bool;

    /// Een niet-blokkerende socket kon niet verder; meld interesse in lezen
    /// (`write == false`) of schrijven, en wek `waker` als het kan.
    fn wait(&self, socket: &TcpStream, write: bool, waker: &Waker);
}

/// Blokkerende sockets met termijnen.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blocking;

impl Reactor for Blocking {
    const BLOCKING: bool = true;

    fn wait(&self, _: &TcpStream, _: bool, _: &Waker) {}
}

/// De kortste sockettermijn: een termijn van nul betekent bij std "geen".
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// Een std-TCP-verbinding met de termijnen van leanhttp.
///
/// Een termijn van leanhttp ("vanaf nu plus zoveel", zoals Go's
/// `SetReadDeadline`) wordt een deadline. Zonder termijn geldt `idle` per
/// lees of schrijf, en nooit iets voorbij de totale grens van
/// [`TcpConn::set_limit`].
pub struct TcpConn<R: Reactor = Blocking> {
    socket: Option<TcpStream>,
    reactor: R,
    idle: Option<Duration>,
    read_at: Option<Instant>,
    write_at: Option<Instant>,
    limit: Option<Instant>,
}

impl<R: Reactor> TcpConn<R> {
    /// Neemt een verbonden socket over: niet-blokkerend als de reactor dat
    /// vraagt, en zonder Nagle.
    pub fn new(socket: TcpStream, reactor: R, idle: Option<Duration>) -> io::Result<Self> {
        socket.set_nonblocking(!R::BLOCKING)?;
        socket.set_nodelay(true)?;
        Ok(Self {
            socket: Some(socket),
            reactor,
            idle,
            read_at: None,
            write_at: None,
            limit: None,
        })
    }

    /// Een totale grens: na `at` faalt elke lees en schrijf met `TimedOut`.
    pub fn set_limit(&mut self, at: Option<Instant>) {
        self.limit = at;
    }

    /// De socket, zolang de verbinding open is.
    pub fn socket(&self) -> Option<&TcpStream> {
        self.socket.as_ref()
    }

    /// De termijn van de volgende lees of schrijf, of `TimedOut` als een
    /// deadline voorbij is.
    fn left(&self, at: Option<Instant>) -> core::result::Result<Option<Duration>, IoError> {
        let now = Instant::now();
        let until = |deadline: Instant| {
            let left = deadline.saturating_duration_since(now);
            if left.is_zero() {
                Err(IoError::TimedOut)
            } else {
                Ok(left.max(MIN_TIMEOUT))
            }
        };
        let phase = match at {
            Some(at) => Some(until(at)?),
            None => self.idle,
        };
        match self.limit {
            None => Ok(phase),
            Some(limit) => {
                let limit = until(limit)?;
                Ok(Some(phase.map_or(limit, |p| p.min(limit))))
            }
        }
    }

    /// Eén lees of schrijf op de socket, met wachten volgens de reactor.
    fn step<T>(
        &mut self,
        cx: &mut Context<'_>,
        write: bool,
        mut op: impl FnMut(&mut TcpStream) -> io::Result<T>,
    ) -> Poll<core::result::Result<T, IoError>> {
        let at = if write { self.write_at } else { self.read_at };
        let left = match self.left(at) {
            Ok(left) => left,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let Some(socket) = self.socket.as_mut() else {
            return Poll::Ready(Err(IoError::Closed));
        };
        if R::BLOCKING {
            let set = if write {
                socket.set_write_timeout(left)
            } else {
                socket.set_read_timeout(left)
            };
            if set.is_err() {
                return Poll::Ready(Err(IoError::Other));
            }
        }
        loop {
            match op(socket) {
                Ok(v) => return Poll::Ready(Ok(v)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && !R::BLOCKING => {
                    self.reactor.wait(socket, write, cx.waker());
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(io_error(&e))),
            }
        }
    }
}

/// Een std-fout als verbindingsfout.
fn io_error(e: &io::Error) -> IoError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IoError::TimedOut,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => IoError::Reset,
        io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected => IoError::Closed,
        _ => IoError::Other,
    }
}

/// Een termijn van leanhttp als deadline; `None` is geen deadline.
fn deadline(t: Option<Duration>) -> Option<Instant> {
    t.and_then(|d| Instant::now().checked_add(d))
}

impl<R: Reactor> AsyncRead for TcpConn<R> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        self.step(cx, false, |s| s.read(buf))
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> core::result::Result<(), IoError> {
        self.read_at = deadline(timeout);
        Ok(())
    }
}

impl<R: Reactor> AsyncWrite for TcpConn<R> {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        self.step(cx, true, |s| s.write(buf))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        self.step(cx, true, Write::flush)
    }

    fn set_write_timeout(
        &mut self,
        timeout: Option<Duration>,
    ) -> core::result::Result<(), IoError> {
        self.write_at = deadline(timeout);
        Ok(())
    }
}

impl<R: Reactor> Close for TcpConn<R> {
    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        // Twee keer sluiten is één keer; een peer die al weg is, is geen fout.
        if let Some(socket) = self.socket.take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        Poll::Ready(Ok(()))
    }
}

/// Waarom een [`TcpDial`] geen verbinding kreeg, voor de logregel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// De naam kon niet worden opgezocht.
    Resolve(io::ErrorKind),
    /// De naam gaf geen enkel adres.
    NoAddress,
    /// Het laatste adres dat geprobeerd werd, en waarom het niet lukte.
    Connect(SocketAddr, io::ErrorKind),
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(kind) => write!(f, "resolve: {kind}"),
            Self::NoAddress => f.write_str("resolve: no address"),
            Self::Connect(addr, kind) => write!(f, "connect {addr}: {kind}"),
        }
    }
}

/// De kale TCP-dial van een host: de naam opzoeken en hoogstens `addresses`
/// adressen proberen, ieder met `connect` als termijn.
pub struct TcpDial<R: Reactor + Clone = Blocking> {
    /// Termijn per adres.
    pub connect: Duration,
    /// Hoeveel adressen hoogstens.
    pub addresses: usize,
    /// De termijn per lees of schrijf als leanhttp er geen zet.
    pub idle: Option<Duration>,
    reactor: R,
    last_error: Option<DialError>,
}

impl<R: Reactor + Clone> TcpDial<R> {
    /// Een dialer met 10 s per adres, hoogstens 16 adressen en geen
    /// stiltetermijn.
    pub fn new(reactor: R) -> Self {
        Self {
            connect: Duration::from_secs(10),
            addresses: 16,
            idle: None,
            reactor,
            last_error: None,
        }
    }

    /// Waarom de laatste dial mislukte, als dat zo was.
    pub fn last_error(&self) -> Option<&DialError> {
        self.last_error.as_ref()
    }

    fn connect(&mut self, target: Target<'_>) -> core::result::Result<TcpStream, DialError> {
        let addresses = (target.host, target.port)
            .to_socket_addrs()
            .map_err(|e| DialError::Resolve(e.kind()))?;
        let mut last = DialError::NoAddress;
        for address in addresses.take(self.addresses.max(1)) {
            match TcpStream::connect_timeout(&address, self.connect) {
                Ok(socket) => return Ok(socket),
                Err(e) => last = DialError::Connect(address, e.kind()),
            }
        }
        Err(last)
    }
}

impl<R: Reactor + Clone> Dial for TcpDial<R> {
    type Conn = TcpConn<R>;

    async fn dial(&mut self, target: Target<'_>) -> Result<TcpConn<R>> {
        let socket = match self.connect(target) {
            Ok(socket) => socket,
            Err(e) => {
                self.last_error = Some(e);
                return Err(Error::Connect);
            }
        };
        self.last_error = None;
        TcpConn::new(socket, self.reactor.clone(), self.idle).map_err(|_| Error::Connect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Call, Client};
    use std::cell::Cell;
    use std::future::Future;
    use std::net::TcpListener;
    use std::rc::Rc;
    use std::vec::Vec;

    /// Pollt tot klaar, zoals een host-executor die elke ronde opnieuw pollt.
    fn spin<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
                return v;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Een server die `answers` keer hetzelfde antwoord geeft op één verbinding.
    fn serve(answers: usize, body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            for _ in 0..answers {
                let mut seen = Vec::new();
                let mut b = [0u8; 1];
                while !seen.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).unwrap() == 0 {
                        return;
                    }
                    seen.push(b[0]);
                }
                // Even wachten: zo ziet een niet-blokkerende lezer eerst niets.
                std::thread::sleep(Duration::from_millis(20));
                let head =
                    std::format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                s.write_all(head.as_bytes()).unwrap();
                s.write_all(body.as_bytes()).unwrap();
            }
        });
        port
    }

    async fn get<D: Dial>(client: &mut Client<D>, url: &str) -> Vec<u8> {
        let mut resp = client
            .send(
                Call {
                    url,
                    ..Call::default()
                },
                Duration::ZERO,
            )
            .await
            .unwrap();
        let body = resp.read_to_end(1 << 20).await.unwrap();
        client.finish(resp, Duration::ZERO).await;
        body
    }

    #[test]
    fn blocking_get_keeps_its_connection() {
        let port = serve(2, "hallo");
        let url = std::format!("http://127.0.0.1:{port}/");
        let mut client = Client::new(TcpDial::new(Blocking));
        assert_eq!(spin(get(&mut client, &url)), b"hallo");
        assert_eq!(client.pool.idle_count(), 1);
        assert_eq!(spin(get(&mut client, &url)), b"hallo");
    }

    /// Een reactor die telt hoe vaak een socket moest wachten.
    #[derive(Clone, Default)]
    struct Count(Rc<Cell<u32>>);

    impl Reactor for Count {
        const BLOCKING: bool = false;
        fn wait(&self, _: &TcpStream, _: bool, _: &Waker) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn non_blocking_waits_through_the_reactor() {
        let port = serve(1, "niet blokkerend");
        let url = std::format!("http://127.0.0.1:{port}/");
        let waits = Count::default();
        let mut client = Client::new(TcpDial::new(waits.clone()));
        assert_eq!(spin(get(&mut client, &url)), b"niet blokkerend");
        assert!(
            waits.0.get() > 0,
            "de kop kwam niet meteen; de reactor moest wachten"
        );
    }

    #[test]
    fn dial_errors_name_the_step() {
        let refused = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = refused.local_addr().unwrap().port();
        drop(refused);
        let mut dial = TcpDial::new(Blocking);
        let target = Target {
            https: false,
            host: "127.0.0.1",
            port,
        };
        assert!(spin(dial.dial(target)).is_err());
        let reason = dial
            .last_error()
            .map(|e| std::format!("{e}"))
            .unwrap_or_default();
        assert!(
            reason.starts_with(&std::format!("connect 127.0.0.1:{port}:")),
            "{reason}"
        );
        let target = Target {
            https: false,
            host: "does-not-exist.invalid",
            port: 80,
        };
        assert!(spin(dial.dial(target)).is_err());
        assert!(matches!(dial.last_error(), Some(DialError::Resolve(_))));
    }
}
