//! Een compositie: `leans3` over `leanhttp`, en niets anders.
//!
//! [`leans3::Transport`] laat de verbinding aan de aanroeper; iedere app die
//! S3 sprak, schreef daarom dezelfde brug. Die staat hier één keer: één
//! keep-alive-verbinding per [`Http`] (een verbinding draagt één verzoek
//! tegelijk; wie tegelijk wil, neemt er meer en gebruikt
//! [`leans3::Client::get_to_all`]), nooit een redirect (de handtekening dekt
//! host en pad), een begrensde body, een totaaltermijn per poging, en voor
//! GET en HEAD een paar herkansingen met een oplopende wachttijd.
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
use alloc::string::String;
use alloc::vec::Vec;
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
    /// Totaaltermijn van één poging: verbinden, verzoek en hele body.
    pub deadline: Duration,
    /// Termijn op de antwoordkop.
    pub header: Duration,
    /// De grootste body die in het geheugen komt.
    pub body: usize,
    /// Pogingen voor GET en HEAD, de eerste meegeteld; nooit minder dan één.
    pub attempts: u32,
}

impl Default for Limits {
    /// 60 s per poging, 30 s op de kop, 32 MiB body, vier pogingen.
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(60),
            header: Duration::from_secs(30),
            body: 32 << 20,
            attempts: 4,
        }
    }
}

/// Telt ontvangen bodybytes per request-target, bijvoorbeeld voor een
/// voortgangsbalk tijdens een herstel.
pub type Observer = Box<dyn FnMut(&str, usize)>;

/// Een [`leans3::Transport`] over één keep-alive-verbinding van `D`.
pub struct Http<D: Dial, K> {
    client: leanhttp::Client<D>,
    clock: K,
    /// De grenzen; aan te passen na [`Http::new`].
    pub limits: Limits,
    observer: Option<Observer>,
    last_error: Option<leanhttp::Error>,
}

impl<D: Dial, K: Clock> Http<D, K> {
    /// Een transport over `dialer` met [`Limits::default`] en één verbinding
    /// in de pool.
    pub fn new(dialer: D, clock: K) -> Self {
        let mut client = leanhttp::Client::new(dialer);
        client.pool.max_idle_per_host = 1;
        client.pool.max_idle_total = 1;
        Self {
            client,
            clock,
            limits: Limits::default(),
            observer: None,
            last_error: None,
        }
    }

    /// Meldt iedere ontvangen body met zijn request-target.
    #[must_use]
    pub fn observe(mut self, observer: impl FnMut(&str, usize) + 'static) -> Self {
        self.observer = Some(Box::new(observer));
        self
    }

    /// De HTTP-fout van de laatste mislukte poging, met meer detail dan
    /// [`IoError`] kan dragen.
    pub fn last_error(&self) -> Option<leanhttp::Error> {
        self.last_error
    }

    /// Eén poging binnen [`Limits::deadline`].
    async fn attempt(
        &mut self,
        request: &Parts<'_>,
        upload: Option<(&mut Upload<'_>, u64)>,
    ) -> leanhttp::Result<Reply> {
        let deadline = self.limits.deadline;
        let sleep = self.clock.sleep(deadline);
        let mut sleep = pin!(sleep);
        let attempt = exchange(
            &mut self.client,
            &self.clock,
            &self.limits,
            &mut self.observer,
            request,
            upload,
        );
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
}

/// Wat van een [`Request`] over is zonder zijn gestroomde body.
struct Parts<'a> {
    method: &'static str,
    target: &'a str,
    url: &'a str,
    headers: &'a [leans3::Header],
    bytes: Option<&'a [u8]>,
}

/// Verzoek, hele body en de verbinding terug naar de pool.
async fn exchange<D: Dial, K: Clock>(
    client: &mut leanhttp::Client<D>,
    clock: &K,
    limits: &Limits,
    observer: &mut Option<Observer>,
    request: &Parts<'_>,
    upload: Option<(&mut Upload<'_>, u64)>,
) -> leanhttp::Result<Reply> {
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
        header_timeout: Some(limits.header),
        no_follow: true,
    };
    let mut response = client.send(call, clock.now()).await?;
    let body = response.read_to_end(limits.body).await?;
    if let Some(observe) = observer.as_mut() {
        observe(request.target, body.len());
    }
    let reply = Reply {
        status: response.status,
        reason: core::mem::take(&mut response.reason),
        header: core::mem::take(&mut response.header),
        body,
        offset: 0,
    };
    client.finish(response, clock.now()).await;
    Ok(reply)
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
        leanhttp::Error::BodyTooLarge { .. } => IoError::Other("leans3http: body too large"),
        _ => IoError::Other("leans3http: HTTP failed"),
    }
}

impl<D: Dial, K: Clock> leans3::Transport for Http<D, K> {
    type Response = Reply;

    async fn send(&mut self, request: Request<'_, '_>) -> Result<Reply, IoError> {
        let mut url = String::new();
        let scheme = if request.https { "https://" } else { "http://" };
        url.try_reserve_exact(scheme.len() + request.host.len() + request.target.len())
            .map_err(|_| IoError::Other("leans3http: out of memory"))?;
        url.push_str(scheme);
        url.push_str(request.host);
        url.push_str(request.target);
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
            target: request.target,
            url: &url,
            headers: request.headers,
            bytes,
        };
        let mut wait = Duration::from_secs(1);
        for attempt in 1..=attempts {
            let stream = upload.as_mut().map(|(source, len)| (source, *len));
            let result = self.attempt(&parts, stream).await;
            let again = attempt < attempts
                && match &result {
                    Ok(reply) => busy(reply.status),
                    Err(error) => broken(error),
                };
            if !again {
                return match result {
                    Ok(reply) => {
                        self.last_error = None;
                        Ok(reply)
                    }
                    Err(error) => {
                        self.last_error = Some(error);
                        Err(io(error))
                    }
                };
            }
            if let Err(error) = result {
                self.last_error = Some(error);
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

/// Een S3-antwoord met de hele body in het geheugen.
pub struct Reply {
    status: u16,
    reason: String,
    header: Header,
    body: Vec<u8>,
    offset: usize,
}

impl leans3::AsyncRead for Reply {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, IoError>> {
        let this = self.get_mut();
        let rest = this.body.get(this.offset..).unwrap_or_default();
        let n = buf.len().min(rest.len());
        buf.get_mut(..n)
            .unwrap_or_default()
            .copy_from_slice(rest.get(..n).unwrap_or_default());
        this.offset += n;
        Poll::Ready(Ok(n))
    }
}

impl leans3::Response for Reply {
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
        u64::try_from(self.body.len()).ok()
    }
}

#[cfg(test)]
mod tests;
