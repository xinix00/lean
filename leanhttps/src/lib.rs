//! Een compositie: leanhttp over leantls, en niets anders.
//!
//! Deze crate bezit de naad tussen de twee en voegt geen protocol toe. Hij
//! regelt drie integratiedetails die makkelijk misgaan:
//!
//! 1. SNI volgt elke dial-host, ook na een redirect naar een andere host: de
//!    naam komt per verbinding uit [`leanhttp::Target`], nooit uit een vaste
//!    configuratie.
//! 2. Het vertrouwensmodel van de aanroeper (een gepinde sleutel of een
//!    ketenverificatie) gaat ongewijzigd naar leantls. Een [`Trust`] heeft geen
//!    standaardwaarde, dus "geen model" compileert niet, en omdat hij geleend
//!    wordt kan de dialer hem niet muteren.
//! 3. leanhttp roept de dialer per verzoek aan; [`TlsDial::is_encrypted`] is
//!    waar, en alleen dan staat leanhttp `https://` toe.
//!
//! leanhttp zelf linkt geen TLS; deze crate is de enige plek waar ze elkaar
//! ontmoeten. In de Go-voorganger (tamago/riscv64, 12-08-2026) was dezelfde
//! main met `net/http` plus `crypto/tls` 5,77 MB, met deze compositie en
//! ketenverificatie 3,75 MB, en met een gepinde sleutel 2,65 MB.
//!
//! # Gebruik
//!
//! ```no_run
//! # use leanhttps::TlsDial;
//! # fn demo<D: leanhttp::Dial<Conn: Unpin>>(tcp: D, key: [u8; 32], seed: fn() -> [u8; 96]) {
//! let trust = leantls::Trust::Pinned(leantls::PeerKey::new(key));
//! let mut https = TlsDial::new(tcp, trust, move || leantls::Entropy::new(seed()));
//! // leanhttp::get(&mut https, "https://leader.internal/v1/jobs")
//! # let _ = &mut https;
//! # }
//! ```
//!
//! Een dialer zonder vertrouwensmodel bestaat niet:
//!
//! ```compile_fail
//! # fn demo<D: leanhttp::Dial<Conn: Unpin>>(tcp: D, seed: [u8; 96]) {
//! let https = leanhttps::TlsDial::new(tcp, leantls::Trust::default(), move || {
//!     leantls::Entropy::new(seed)
//! });
//! # }
//! ```

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

use core::cell::Cell;
use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use leanhttp::{Close, IoError, Target};
use leantls::{ConnError, Entropy, Trust};

/// Hoe lang een close_notify mag duren voordat het transport toch dichtgaat.
/// Een peer die niet meer leest, mag het sluiten niet gijzelen; de Go-versie
/// koos 250 ms en KAM.md legt die grens vast.
pub const CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_millis(250);

/// De resultaat-alias van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Waarom een TLS-dial mislukte, voor wie meer wil weten dan leanhttp's
/// algemene [`leanhttp::Error`] kan dragen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ketenverificatie tegen een kaal IP-adres: er is geen naam om de keten
    /// tegen te toetsen. Gebruik een hostnaam, of pin de sleutel.
    ChainWithoutName,
    /// Het transport onder TLS faalde.
    Transport(IoError),
    /// De handshake of een record faalde.
    Tls(leantls::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainWithoutName => f.write_str(
                "leanhttps: the host is an IP address, so there is no name to verify a chain \
                 against; use a hostname, or pin the peer's key",
            ),
            Self::Transport(e) => write!(f, "leanhttps: transport: {e}"),
            Self::Tls(e) => write!(f, "leanhttps: {e}"),
        }
    }
}

/// Een [`leanhttp::Dial`] die elke verbinding van `inner` in TLS verpakt.
///
/// `entropy` levert per handshake 96 verse willekeurige bytes (uit leanrand
/// of de hardware); deze crate heeft geen eigen bron.
pub struct TlsDial<'t, D, R> {
    /// De dialer die kale verbindingen maakt.
    inner: D,
    /// Het vertrouwensmodel, voor elke verbinding hetzelfde.
    trust: Trust<'t>,
    /// De bron van handshake-willekeur.
    entropy: R,
    /// De reden van de laatst mislukte dial, met meer detail dan leanhttp's
    /// fouttype heeft.
    last_error: Option<Error>,
}

impl<'t, D, R> TlsDial<'t, D, R>
where
    D: leanhttp::Dial,
    D::Conn: Unpin,
    R: FnMut() -> Entropy,
{
    /// Een TLS-dialer over `inner` met vertrouwensmodel `trust`.
    pub fn new(inner: D, trust: Trust<'t>, entropy: R) -> Self {
        Self {
            inner,
            trust,
            entropy,
            last_error: None,
        }
    }

    /// De reden van de laatst mislukte dial, als die er is.
    pub fn last_error(&self) -> Option<Error> {
        self.last_error
    }
}

impl<D, R> leanhttp::Dial for TlsDial<'_, D, R>
where
    D: leanhttp::Dial,
    D::Conn: Unpin,
    R: FnMut() -> Entropy,
{
    type Conn = TlsConn<D::Conn>;

    /// Opent een kale verbinding en doet de handshake met SNI uit de
    /// dial-host van deze hop.
    async fn dial(&mut self, target: Target<'_>) -> leanhttp::Result<TlsConn<D::Conn>> {
        let host = target.host.strip_suffix('.').unwrap_or(target.host);
        // Een keten heeft een naam nodig; een pin levert de identiteit zelf.
        if matches!(self.trust, Trust::Chain(_)) && is_ip(host) {
            self.last_error = Some(Error::ChainWithoutName);
            return Err(leanhttp::Error::NoHost);
        }
        let raw = self.inner.dial(target).await?;
        let wire = Wire {
            conn: raw,
            pending: Cell::new(Pending::default()),
        };
        match leantls::connect(wire, &self.trust, host, (self.entropy)()).await {
            Ok(tls) => {
                self.last_error = None;
                Ok(TlsConn {
                    state: State::Open(tls),
                })
            }
            Err(e) => {
                let (mine, theirs) = split(e);
                self.last_error = Some(mine);
                Err(leanhttp::Error::Io(theirs))
            }
        }
    }

    fn is_encrypted(&self) -> bool {
        true
    }
}

/// Een termijnwijziging die leanhttp vroeg en die bij de volgende
/// transportoperatie ingaat.
#[derive(Debug, Clone, Copy, Default)]
struct Pending {
    /// `Some` als de leestermijn moet veranderen.
    read: Option<Option<Duration>>,
    /// `Some` als de schrijftermijn moet veranderen.
    write: Option<Option<Duration>>,
}

/// Een kale leanhttp-verbinding in de vorm die leantls leest en schrijft.
///
/// De termijnen van leanhttp moeten het transport onder de TLS-sessie
/// bereiken, maar `leantls::Conn` geeft alleen een gedeelde verwijzing naar
/// zijn transport (`get_ref`). Daarom staat de wijziging in een `Cell` die hier
/// bij de volgende operatie wordt toegepast. Eén taak bezit de verbinding;
/// de `Cell` is alleen de brievenbus tussen twee lagen van die ene eigenaar.
pub struct Wire<C> {
    /// De kale verbinding.
    conn: C,
    /// Termijnen die nog moeten ingaan.
    pending: Cell<Pending>,
}

impl<C: leanhttp::Conn> Wire<C> {
    /// Past uitstaande termijnwijzigingen toe.
    fn apply(&mut self) -> core::result::Result<(), IoError> {
        let p = self.pending.take();
        if let Some(t) = p.read {
            self.conn.set_read_timeout(t)?;
        }
        if let Some(t) = p.write {
            self.conn.set_write_timeout(t)?;
        }
        Ok(())
    }
}

impl<C: leanhttp::Conn + Unpin> leantls::AsyncRead for Wire<C> {
    type Error = IoError;

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        let this = self.get_mut();
        this.apply()?;
        this.conn.poll_read(cx, buf)
    }
}

impl<C: leanhttp::Conn + Unpin> leantls::AsyncWrite for Wire<C> {
    type Error = IoError;

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        let this = self.get_mut();
        this.apply()?;
        this.conn.poll_write(cx, buf)
    }
}

/// De levensloop van een [`TlsConn`].
#[expect(
    clippy::large_enum_variant,
    reason = "de open sessie is de gewone toestand; boxen kost een extra allocatie per verbinding"
)]
enum State<C> {
    /// De sessie is open.
    Open(leantls::Conn<Wire<C>>),
    /// De close_notify is weg of opgegeven; het transport gaat dicht.
    Closing(C),
    /// Alles is dicht.
    Closed,
}

/// Een TLS-sessie als leanhttp-verbinding.
pub struct TlsConn<C> {
    /// Waar de verbinding in haar levensloop staat.
    state: State<C>,
}

impl<C: leanhttp::Conn + Unpin> leanhttp::AsyncRead for TlsConn<C> {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        match &mut self.state {
            State::Open(tls) => {
                leantls::AsyncRead::poll_read(Pin::new(tls), cx, buf).map_err(|e| split(e).1)
            }
            _ => Poll::Ready(Err(IoError::Closed)),
        }
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> core::result::Result<(), IoError> {
        let State::Open(tls) = &self.state else {
            return Err(IoError::Closed);
        };
        let wire = tls.get_ref();
        let mut p = wire.pending.get();
        p.read = Some(timeout);
        wire.pending.set(p);
        Ok(())
    }
}

impl<C: leanhttp::Conn + Unpin> leanhttp::AsyncWrite for TlsConn<C> {
    /// Schrijft applicatiedata. leantls meldt bytes pas als geschreven als hun
    /// record het transport heeft; een aparte flush is dus niet nodig.
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoError>> {
        match &mut self.state {
            State::Open(tls) => {
                leantls::AsyncWrite::poll_write(Pin::new(tls), cx, buf).map_err(|e| split(e).1)
            }
            _ => Poll::Ready(Err(IoError::Closed)),
        }
    }

    fn set_write_timeout(
        &mut self,
        timeout: Option<Duration>,
    ) -> core::result::Result<(), IoError> {
        let State::Open(tls) = &self.state else {
            return Err(IoError::Closed);
        };
        let wire = tls.get_ref();
        let mut p = wire.pending.get();
        p.write = Some(timeout);
        wire.pending.set(p);
        Ok(())
    }
}

impl<C: leanhttp::Conn + Unpin> Close for TlsConn<C> {
    /// Stuurt een close_notify binnen [`CLOSE_NOTIFY_TIMEOUT`] en sluit daarna
    /// altijd het transport. Mislukt de close_notify, dan gaat het transport
    /// toch dicht; een schrijffout vóór het sluiten was al terminaal.
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<core::result::Result<(), IoError>> {
        loop {
            match &mut self.state {
                State::Open(tls) => {
                    let wire = tls.get_ref();
                    if wire.pending.get().write != Some(Some(CLOSE_NOTIFY_TIMEOUT)) {
                        let mut p = wire.pending.get();
                        p.write = Some(Some(CLOSE_NOTIFY_TIMEOUT));
                        wire.pending.set(p);
                    }
                    if tls.poll_close_notify(cx).is_pending() {
                        return Poll::Pending;
                    }
                    let State::Open(tls) = core::mem::replace(&mut self.state, State::Closed)
                    else {
                        return Poll::Ready(Err(IoError::Closed));
                    };
                    self.state = State::Closing(tls.into_inner().conn);
                }
                State::Closing(conn) => {
                    let r = core::task::ready!(conn.poll_close(cx));
                    self.state = State::Closed;
                    return Poll::Ready(r);
                }
                State::Closed => return Poll::Ready(Ok(())),
            }
        }
    }

    fn has_grown(&self) -> bool {
        match &self.state {
            State::Open(tls) => tls.get_ref().conn.has_grown(),
            State::Closing(conn) => conn.has_grown(),
            State::Closed => false,
        }
    }
}

/// Splitst een verbindingsfout in de rijke vorm van deze crate en de vorm die
/// leanhttp kan dragen.
fn split(e: ConnError<IoError>) -> (Error, IoError) {
    match e {
        ConnError::Transport(io) => (Error::Transport(io), io),
        // Een TLS-stroom die zonder close_notify eindigt, kan afgekapt zijn:
        // dat is een afgebroken verbinding, geen schoon einde.
        ConnError::Tls(t) => (Error::Tls(t), IoError::Reset),
    }
}

/// Of `host` een IPv4- of IPv6-adres is. Een hostnaam bevat nooit een `:`,
/// en een naam uit alleen cijfers en punten in vier delen is IPv4.
fn is_ip(host: &str) -> bool {
    if host.contains(':') {
        return true;
    }
    let mut parts = 0;
    for part in host.split('.') {
        parts += 1;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u16>().map_or(true, |v| v > 255) {
            return false;
        }
    }
    parts == 4
}

#[cfg(test)]
mod tests;
