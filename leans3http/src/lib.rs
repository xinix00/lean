//! Een compositie: `leans3` over `leanhttp`, en niets anders.
//!
//! [`leans3::Transport`] laat de verbinding aan de aanroeper; iedere app die
//! S3 sprak, schreef daarom dezelfde brug. Die staat hier één keer: één
//! keep-alive-verbinding per [`Http`] (een verbinding draagt één verzoek
//! tegelijk; wie tegelijk wil, neemt er meer en gebruikt
//! [`leans3::Client::get_to_all`]), nooit een redirect (de handtekening dekt
//! host en pad), en voor GET en HEAD een paar herkansingen met een
//! oplopende wachttijd.
//!
//! De body stroomt: [`Reply`] leest hem van de verbinding terwijl de
//! aanroeper leest, dus een object van honderden MB kost niet meer geheugen
//! dan de buffer van wie het wegschrijft. Na de laatste byte gaat de
//! verbinding terug in de pool. De termijnen volgen KAM: één totaaltermijn
//! voor het verzoek tot en met de kop, daarna een voortgangstermijn per read,
//! zodat een lange download zo lang mag duren als hij vordert.
//!
//! De klok is van de aanroeper ([`Clock`]): de pool rekent er de leeftijd van
//! verbindingen mee, en de termijn en de herkansing wachten erop.

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

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll};
use core::time::Duration;

use leanhttp::{Call, Dial, Header};
use leans3::{Body, IoError, Request};

/// De klok van de aanroeper.
pub trait Clock {
    /// Monotone tijd sinds een vast punt.
    fn now(&self) -> Duration;
    /// Wacht `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;
}

/// De grenzen van één [`Http`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Totaaltermijn van één poging tot en met de antwoordkop: verbinden,
    /// TLS, het verzoek met zijn body, en wachten op de kop.
    pub deadline: Duration,
    /// Termijn op de antwoordkop zelf.
    pub header: Duration,
    /// Voortgangstermijn van de body: zo lang mag één read zonder bytes
    /// duren.
    pub progress: Duration,
    /// Pogingen voor GET en HEAD, de eerste meegeteld; nooit minder dan één.
    pub attempts: u32,
    /// De grootste foutbody die bij een herkansing gelezen wordt.
    pub error_body: usize,
}

impl Default for Limits {
    /// 60 s tot de kop, 30 s op de kop, 30 s voortgang, vier pogingen.
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(60),
            header: Duration::from_secs(30),
            progress: Duration::from_secs(30),
            attempts: 4,
            error_body: 64 << 10,
        }
    }
}

/// Telt ontvangen bodybytes per request-target, terwijl ze binnenkomen;
/// bijvoorbeeld voor een voortgangsbalk tijdens een herstel.
pub type Observer = Box<dyn FnMut(&str, usize)>;

/// Een verbinding die een [`Reply`] na zijn laatste byte teruggeeft.
struct Back<C> {
    addr: String,
    conn: C,
    at: Duration,
}

/// Het bakje tussen een [`Reply`] en zijn [`Http`]: zo leent niemand de
/// client over een `await`.
type Returned<C> = Rc<RefCell<Vec<Back<C>>>>;

/// Een [`leans3::Transport`] over één keep-alive-verbinding van `D`.
pub struct Http<D: Dial, K> {
    client: leanhttp::Client<D>,
    returned: Returned<D::Conn>,
    clock: K,
    /// De grenzen; aan te passen na [`Http::new`].
    pub limits: Limits,
    observer: Option<Rc<RefCell<Observer>>>,
    last_error: Option<leanhttp::Error>,
}

impl<D: Dial, K: Clock + Clone> Http<D, K> {
    /// Een transport over `dialer` met [`Limits::default`] en één verbinding
    /// in de pool.
    pub fn new(dialer: D, clock: K) -> Self {
        let mut client = leanhttp::Client::new(dialer);
        client.pool.max_idle_per_host = 1;
        client.pool.max_idle_total = 1;
        Self {
            client,
            returned: Rc::default(),
            clock,
            limits: Limits::default(),
            observer: None,
            last_error: None,
        }
    }

    /// Meldt ontvangen bodybytes met hun request-target, per stuk.
    #[must_use]
    pub fn observe(mut self, observer: impl FnMut(&str, usize) + 'static) -> Self {
        self.observer = Some(Rc::new(RefCell::new(Box::new(observer))));
        self
    }

    /// De HTTP-fout van de laatste mislukte poging, met meer detail dan
    /// [`IoError`] kan dragen.
    pub fn last_error(&self) -> Option<leanhttp::Error> {
        self.last_error
    }

    /// De dialer, bijvoorbeeld voor `WebDial::last_error`: de reden van een
    /// mislukte TLS-handshake.
    pub fn dialer(&self) -> &D {
        &self.client.dialer
    }

    /// Neemt de verbindingen terug die antwoorden na hun laatste byte
    /// teruglegden.
    fn reclaim(&mut self) {
        let back = match self.returned.try_borrow_mut() {
            Ok(mut returned) => core::mem::take(&mut *returned),
            Err(_) => return,
        };
        for b in back {
            self.client.pool.put_now(&b.addr, b.conn, b.at);
        }
    }

    /// Eén poging tot en met de kop, binnen [`Limits::deadline`].
    async fn attempt(
        &mut self,
        request: &Parts<'_>,
        upload: Option<(&mut Upload<'_>, u64)>,
    ) -> leanhttp::Result<leanhttp::Response<D::Conn>> {
        self.reclaim();
        let sleep = self.clock.sleep(self.limits.deadline);
        let mut sleep = pin!(sleep);
        let mut header = Header::new();
        for item in request.headers {
            header.set(item.name, &item.value)?;
        }
        let (body_reader, body_len) = match upload {
            Some((upload, len)) => (Some(upload as &mut dyn leanhttp::AsyncRead), len),
            None => (None, 0),
        };
        let call = Call {
            method: request.method,
            url: request.url,
            header,
            body: request.bytes,
            body_reader,
            body_len,
            header_timeout: Some(self.limits.header),
            no_follow: true,
        };
        let attempt = self.client.send(call, self.clock.now());
        let mut attempt = pin!(attempt);
        poll_fn(|cx| {
            if let Poll::Ready(result) = attempt.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            match sleep.as_mut().poll(cx) {
                // Het verzoek valt en sluit zijn verbinding.
                Poll::Ready(()) => {
                    Poll::Ready(Err(leanhttp::Error::Io(leanhttp::IoError::TimedOut)))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    /// Leest een korte foutbody en geeft de verbinding terug, vóór een
    /// herkansing.
    async fn drain(&mut self, mut response: leanhttp::Response<D::Conn>) {
        if response.read_to_end(self.limits.error_body).await.is_ok() {
            self.client.finish(response, self.clock.now()).await;
        }
    }
}

/// Wat van een [`Request`] over is zonder zijn gestroomde body.
struct Parts<'a> {
    method: &'static str,
    url: &'a str,
    headers: &'a [leans3::Header],
    bytes: Option<&'a [u8]>,
}

/// Statussen waarop een GET of HEAD het opnieuw mag proberen.
fn busy(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Fouten waarop een GET of HEAD het opnieuw mag proberen: de verbinding,
/// niet het antwoord.
fn broken(error: &leanhttp::Error) -> bool {
    matches!(
        error,
        leanhttp::Error::Connect
            | leanhttp::Error::Io(_)
            | leanhttp::Error::Eof
            | leanhttp::Error::UnexpectedEof
    )
}

fn io(error: leanhttp::Error) -> IoError {
    match error {
        leanhttp::Error::Io(leanhttp::IoError::TimedOut) => IoError::TimedOut,
        leanhttp::Error::Io(leanhttp::IoError::Closed | leanhttp::IoError::Reset) => {
            IoError::Closed
        }
        leanhttp::Error::UnexpectedEof | leanhttp::Error::Eof => IoError::UnexpectedEof,
        leanhttp::Error::Connect => IoError::Other("leans3http: connect failed"),
        _ => IoError::Other("leans3http: HTTP failed"),
    }
}

impl<D: Dial, K: Clock + Clone + Unpin> leans3::Transport for Http<D, K> {
    type Response = Reply<D::Conn, K>;

    async fn send(&mut self, request: Request<'_, '_>) -> Result<Reply<D::Conn, K>, IoError> {
        let mut url = String::new();
        let scheme = if request.https { "https://" } else { "http://" };
        url.try_reserve_exact(scheme.len() + request.host.len() + request.target.len())
            .map_err(|_| IoError::Other("leans3http: out of memory"))?;
        url.push_str(scheme);
        url.push_str(request.host);
        url.push_str(request.target);
        let mut target = String::new();
        target
            .try_reserve_exact(request.target.len())
            .map_err(|_| IoError::Other("leans3http: out of memory"))?;
        target.push_str(request.target);
        let replay = matches!(request.method, "GET" | "HEAD");
        let attempts = if replay {
            self.limits.attempts.max(1)
        } else {
            1
        };
        let (bytes, mut upload) = match request.body {
            Body::None => (None, None),
            Body::Bytes(bytes) => (Some(bytes), None),
            Body::Stream { source, len } => (None, Some((Upload(source), len))),
        };
        let parts = Parts {
            method: request.method,
            url: &url,
            headers: request.headers,
            bytes,
        };
        let mut wait = Duration::from_secs(1);
        for attempt in 1..=attempts {
            let stream = upload.as_mut().map(|(source, len)| (source, *len));
            let result = self.attempt(&parts, stream).await;
            let last = attempt == attempts;
            match result {
                Ok(response) if !last && busy(response.status) => self.drain(response).await,
                Ok(mut response) => {
                    self.last_error = None;
                    let _ = response.set_read_timeout(Some(self.limits.progress));
                    return Ok(Reply {
                        status: response.status,
                        reason: core::mem::take(&mut response.reason),
                        header: core::mem::take(&mut response.header),
                        length: response.length,
                        body: Some(Box::new(response)),
                        returned: self.returned.clone(),
                        clock: self.clock.clone(),
                        progress: self.limits.progress,
                        target,
                        observer: self.observer.clone(),
                    });
                }
                Err(error) if !last && broken(&error) => self.last_error = Some(error),
                Err(error) => {
                    self.last_error = Some(error);
                    return Err(io(error));
                }
            }
            self.clock.sleep(wait).await;
            wait = wait.saturating_mul(2);
        }
        Err(IoError::Other("leans3http: no attempt"))
    }
}

/// Een gestroomde PUT-body van leans3 als leanhttp-bron.
struct Upload<'s>(&'s mut (dyn leans3::AsyncRead + Unpin));

impl leanhttp::AsyncRead for Upload<'_> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, leanhttp::IoError>> {
        Pin::new(&mut *self.0)
            .poll_read(cx, buf)
            .map_err(|e| match e {
                IoError::TimedOut => leanhttp::IoError::TimedOut,
                IoError::Closed => leanhttp::IoError::Closed,
                _ => leanhttp::IoError::Other,
            })
    }
}

/// Een S3-antwoord waarvan de body nog op de verbinding staat.
///
/// Lezen haalt hem van de verbinding; na de laatste byte gaat de verbinding
/// terug in de pool. Wie loslaat voor het einde, sluit hem.
pub struct Reply<C, K> {
    status: u16,
    reason: String,
    header: Header,
    length: Option<u64>,
    body: Option<Box<leanhttp::Response<C>>>,
    returned: Returned<C>,
    clock: K,
    progress: Duration,
    target: String,
    observer: Option<Rc<RefCell<Observer>>>,
}

impl<C: leanhttp::Conn, K: Clock + Unpin> leans3::AsyncRead for Reply<C, K> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let this = self.get_mut();
        let Some(body) = this.body.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        match body.poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => {
                if let Some(body) = this.body.take()
                    && let Some((addr, conn)) = body.into_reusable()
                    && !addr.is_empty()
                    && let Ok(mut returned) = this.returned.try_borrow_mut()
                {
                    let at = this.clock.now();
                    if returned.try_reserve(1).is_ok() {
                        returned.push(Back { addr, conn, at });
                    }
                }
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Ok(n)) => {
                let _ = body.set_read_timeout(Some(this.progress));
                if let Some(observer) = &this.observer
                    && let Ok(mut observe) = observer.try_borrow_mut()
                {
                    observe(&this.target, n);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                this.body = None;
                Poll::Ready(Err(io(error)))
            }
        }
    }
}

impl<C: leanhttp::Conn, K: Clock + Unpin> leans3::Response for Reply<C, K> {
    fn status(&self) -> u16 {
        self.status
    }
    fn reason(&self) -> &str {
        &self.reason
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.header.get(name)
    }
    fn content_length(&self) -> Option<u64> {
        self.length
    }
}

#[cfg(test)]
mod tests;
