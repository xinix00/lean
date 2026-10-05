//! De gewone webclient: `http://` kaal, `https://` met een echte keten.
//!
//! Iedere app die een webdienst of S3 aanspreekt, deed hetzelfde: DNS en
//! TCP, en voor `https://` een handshake met ketenverificatie tegen de
//! Mozilla-wortels op de wandklok, met verse entropie per verbinding. Dat
//! staat hier één keer, boven elke kale [`leanhttp::Dial`].

use core::task::{Context, Poll};
use core::time::Duration;

use leanhttp::{AsyncRead, AsyncWrite, Close, IoError, Target};
use leantls::{ChainVerifier, Entropy, Roots, Trust};

use crate::{Error, TlsConn, is_ip, wrap};

/// Een verbinding van [`WebDial`]: kaal voor `http://`, TLS voor `https://`.
#[allow(clippy::large_enum_variant)] // Eén eigenaar van de hele verbinding, zonder extra heapobject.
pub enum Link<C> {
    /// `http://`: de kale verbinding.
    Plain(C),
    /// `https://`: een geverifieerde TLS-sessie.
    Tls(TlsConn<C>),
}

/// Een [`leanhttp::Dial`] voor gewone webdiensten.
///
/// `http://` gaat kaal over `inner`; `https://` krijgt TLS met
/// ketenverificatie tegen `roots` (bijvoorbeeld `leantls::MOZILLA_ROOTS`)
/// op de wandklok van `unix_seconds`, met verse `entropy` per handshake.
/// Zonder klok of entropie faalt de dial; nooit een handshake met een
/// verzonnen tijd of nul-entropie.
pub struct WebDial<D, N, R> {
    pub(crate) inner: D,
    roots: &'static [u8],
    unix_seconds: N,
    entropy: R,
    /// De termijn op het transport tijdens de handshake; daarna geen.
    pub handshake: Duration,
    last_error: Option<Error>,
}

impl<D, N, R> WebDial<D, N, R>
where
    D: leanhttp::Dial,
    D::Conn: Unpin,
    N: FnMut() -> Option<u64>,
    R: FnMut() -> Option<Entropy>,
{
    /// Een webdialer over `inner`, met een handshaketermijn van 20 seconden.
    pub fn new(inner: D, roots: &'static [u8], unix_seconds: N, entropy: R) -> Self {
        Self {
            inner,
            roots,
            unix_seconds,
            entropy,
            handshake: Duration::from_secs(20),
            last_error: None,
        }
    }

    /// De reden van de laatst mislukte TLS-handshake, als die er is.
    pub fn last_error(&self) -> Option<Error> {
        self.last_error
    }
}

impl<D, N, R> leanhttp::Dial for WebDial<D, N, R>
where
    D: leanhttp::Dial,
    D::Conn: Unpin,
    N: FnMut() -> Option<u64>,
    R: FnMut() -> Option<Entropy>,
{
    type Conn = Link<D::Conn>;

    async fn dial(&mut self, target: Target<'_>) -> leanhttp::Result<Link<D::Conn>> {
        if !target.https {
            return Ok(Link::Plain(self.inner.dial(target).await?));
        }
        let host = target.host.strip_suffix('.').unwrap_or(target.host);
        if is_ip(host) {
            self.last_error = Some(Error::ChainWithoutName);
            return Err(leanhttp::Error::NoHost);
        }
        let roots =
            Roots::from_concatenated_der(self.roots).map_err(|_| leanhttp::Error::Connect)?;
        let now = (self.unix_seconds)().ok_or(leanhttp::Error::Connect)?;
        let entropy = (self.entropy)().ok_or(leanhttp::Error::Connect)?;
        let verifier = ChainVerifier::new(roots, now);
        let mut raw = self.inner.dial(target).await?;
        raw.set_read_timeout(Some(self.handshake))?;
        raw.set_write_timeout(Some(self.handshake))?;
        let mut conn = match wrap(raw, &Trust::Chain(&verifier), host, entropy).await {
            Ok(conn) => conn,
            Err((mine, theirs)) => {
                self.last_error = Some(mine);
                return Err(leanhttp::Error::Io(theirs));
            }
        };
        self.last_error = None;
        conn.set_read_timeout(None)?;
        conn.set_write_timeout(None)?;
        Ok(Link::Tls(conn))
    }

    fn is_encrypted(&self) -> bool {
        true
    }
}

impl<C: leanhttp::Conn + Unpin> AsyncRead for Link<C> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        match self {
            Self::Plain(c) => c.poll_read(cx, buf),
            Self::Tls(c) => c.poll_read(cx, buf),
        }
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> core::result::Result<(), IoError> {
        match self {
            Self::Plain(c) => c.set_read_timeout(timeout),
            Self::Tls(c) => c.set_read_timeout(timeout),
        }
    }
}

impl<C: leanhttp::Conn + Unpin> AsyncWrite for Link<C> {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        match self {
            Self::Plain(c) => c.poll_write(cx, buf),
            Self::Tls(c) => c.poll_write(cx, buf),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        match self {
            Self::Plain(c) => c.poll_flush(cx),
            Self::Tls(c) => c.poll_flush(cx),
        }
    }

    fn set_write_timeout(
        &mut self,
        timeout: Option<Duration>,
    ) -> core::result::Result<(), IoError> {
        match self {
            Self::Plain(c) => c.set_write_timeout(timeout),
            Self::Tls(c) => c.set_write_timeout(timeout),
        }
    }
}

impl<C: leanhttp::Conn + Unpin> Close for Link<C> {
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        match self {
            Self::Plain(c) => c.poll_close(cx),
            Self::Tls(c) => c.poll_close(cx),
        }
    }

    fn has_grown(&self) -> bool {
        match self {
            Self::Plain(c) => c.has_grown(),
            Self::Tls(c) => c.has_grown(),
        }
    }
}
