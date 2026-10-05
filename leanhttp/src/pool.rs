//! Keep-alive aan de clientkant: een kleine pool die de aanroeper voedt, en
//! een [`Client`] die hem gebruikt.
//!
//! De centrale veiligheidsregel staat in [`Response::release`]: een verbinding
//! komt alleen terug na een bewezen volledig gelezen body. Anders leest het
//! volgende verzoek de ongelezen staart als zijn statusregel. Bij twijfel:
//! sluiten.
//!
//! De pool heeft geen klok en geen timer. De aanroeper geeft `now` mee (een
//! monotone tijd sinds boot) en roept [`Pool::sweep`] vanuit zijn eigen timer
//! aan; `take` veegt zelf ook, vóór het dialen. Er is geen permanente leeslus
//! per ruststaande verbinding: het contract neemt een protocol-correcte origin
//! aan die in rust geen bytes stuurt (KAM).

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::client::{Call, Dial, Response, check_get, follow};
use crate::error::Result;
use crate::header::try_string;
use crate::io::{Conn, close};

/// Twee ruststaande verbindingen per host dragen parallelle paginabronnen
/// zonder de server te overspoelen.
const DEFAULT_MAX_IDLE_PER_HOST: usize = 2;

/// Een grens over alle hosts, zodat een burst unieke hosts niet het hele
/// bufferbudget van leannet vasthoudt tot de idle-termijn.
const DEFAULT_MAX_IDLE_TOTAL: usize = 8;

/// Dertig seconden blijft ruim onder gangbare idle-termijnen van servers.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Ruststaande verbindingen per `host:poort`.
#[derive(Debug)]
pub struct Pool<C> {
    idle: Vec<Idle<C>>,
    /// Grens per host.
    pub max_idle_per_host: usize,
    /// Grens over alle hosts.
    pub max_idle_total: usize,
    /// Hoe lang een verbinding mag rusten.
    pub idle_timeout: Duration,
}

#[derive(Debug)]
struct Idle<C> {
    addr: String,
    conn: C,
    since: Duration,
}

impl<C: Conn> Default for Pool<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Conn> Pool<C> {
    /// Een lege pool met de standaardgrenzen: 2 per host, 8 totaal, 30 s.
    pub const fn new() -> Self {
        Pool {
            idle: Vec::new(),
            max_idle_per_host: DEFAULT_MAX_IDLE_PER_HOST,
            max_idle_total: DEFAULT_MAX_IDLE_TOTAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Geeft de warmste verbinding voor `addr`, na eerst alle hosts te vegen.
    ///
    /// Vegen vóór het dialen: verlopen verbindingen kunnen het netwerkbudget
    /// opmaken en de dial laten falen, en dan komt een veeg erna nooit.
    pub async fn take(&mut self, addr: &str, now: Duration) -> Option<C> {
        self.sweep(now).await;
        let i = self.idle.iter().rposition(|ic| ic.addr == addr)?;
        Some(self.idle.remove(i).conn)
    }

    /// Neemt een volledig gelezen verbinding aan; `false` betekent dat hij
    /// geweigerd en gesloten is.
    ///
    /// Geweigerd wordt: een gegroeide verbinding (zie
    /// [`Close::has_grown`](crate::Close::has_grown)), een verbinding die zijn
    /// termijnen niet kan wissen, en alles boven de grenzen.
    pub async fn put(&mut self, addr: &str, conn: C, now: Duration) -> bool {
        match self.admit(addr, conn, now) {
            Ok(()) => true,
            Err(mut conn) => {
                let _ = close(&mut conn).await;
                false
            }
        }
    }

    /// Als [`Pool::put`] zonder te wachten: een verbinding die niet past,
    /// valt zonder nette afsluiting. Voor wie geen async heeft op het moment
    /// dat een body ophoudt, zoals een `AsyncRead` die een antwoord stroomt.
    pub fn put_now(&mut self, addr: &str, conn: C, now: Duration) -> bool {
        self.admit(addr, conn, now).is_ok()
    }

    /// Neemt `conn` op, of geeft hem terug als hij er niet in mag.
    fn admit(&mut self, addr: &str, mut conn: C, now: Duration) -> core::result::Result<(), C> {
        // Een termijn van het vorige verzoek mag nooit in het volgende lekken;
        // een verbinding die hem niet kan wissen, is niet herbruikbaar.
        let fresh = conn.set_read_timeout(None).is_ok() && conn.set_write_timeout(None).is_ok();
        let room = self.idle_for(addr) < self.max_idle_per_host
            && self.idle.len() < self.max_idle_total
            && self.idle.try_reserve(1).is_ok();
        let addr = match try_string(addr) {
            Ok(a) if fresh && room && !conn.has_grown() => a,
            _ => return Err(conn),
        };
        self.idle.push(Idle {
            addr,
            conn,
            since: now,
        });
        Ok(())
    }

    /// Sluit alle verbindingen die langer rusten dan `idle_timeout`, voor elke
    /// host.
    ///
    /// Alleen de gevraagde host vegen lekte verbindingen naar hosts die nooit
    /// meer gebeld werden. Op leannet, waar een open verbinding zijn buffers
    /// houdt, putte dat eens het budget van een LicheeRV-node uit na image-
    /// downloads, en kon de watchdog zijn hartslagverbinding niet meer openen.
    pub async fn sweep(&mut self, now: Duration) {
        let timeout = self.idle_timeout;
        let mut i = 0;
        while i < self.idle.len() {
            let expired = self
                .idle
                .get(i)
                .is_some_and(|ic| now.saturating_sub(ic.since) >= timeout);
            if expired {
                let mut ic = self.idle.remove(i);
                let _ = close(&mut ic.conn).await;
            } else {
                i += 1;
            }
        }
    }

    /// Sluit alle ruststaande verbindingen.
    pub async fn close_idle(&mut self) {
        for mut ic in core::mem::take(&mut self.idle) {
            let _ = close(&mut ic.conn).await;
        }
    }

    /// Geeft de verbinding van een antwoord terug aan de pool als hij
    /// herbruikbaar is, en sluit hem anders.
    pub async fn finish(&mut self, mut resp: Response<C>, now: Duration) {
        let addr = core::mem::take(&mut resp.addr);
        if let Some(conn) = resp.release().await {
            if addr.is_empty() {
                let mut conn = conn;
                let _ = close(&mut conn).await;
                return;
            }
            self.put(&addr, conn, now).await;
        }
    }

    /// Als [`Pool::finish`] zonder te wachten: een herbruikbaar antwoord
    /// komt terug in de pool, de rest valt.
    pub fn finish_now(&mut self, resp: Response<C>, now: Duration) {
        if let Some((addr, conn)) = resp.into_reusable()
            && !addr.is_empty()
        {
            self.put_now(&addr, conn, now);
        }
    }

    /// Aantal ruststaande verbindingen.
    pub fn idle_count(&self) -> usize {
        self.idle.len()
    }

    /// Aantal ruststaande verbindingen naar `addr`.
    pub fn idle_for(&self, addr: &str) -> usize {
        self.idle.iter().filter(|ic| ic.addr == addr).count()
    }
}

/// Een client met keep-alive: een [`Dial`] en een [`Pool`].
///
/// Zonder `Client` krijgt elk verzoek een eigen verbinding ([`fetch`](crate::fetch)).
pub struct Client<D: Dial> {
    /// Maakt verbindingen als de pool er geen heeft.
    pub dialer: D,
    /// De ruststaande verbindingen.
    pub pool: Pool<D::Conn>,
}

impl<D: Dial> Client<D> {
    /// Een client met een lege pool.
    pub const fn new(dialer: D) -> Self {
        Client {
            dialer,
            pool: Pool::new(),
        }
    }

    /// Doet een verzoek via de pool, met redirects zoals [`fetch`](crate::fetch).
    ///
    /// Een verlopen pool-verbinding die faalt vóór de eerste antwoordbyte,
    /// krijgt voor GET en HEAD één verse herkansing. Geef het antwoord na het
    /// lezen terug met [`Client::finish`].
    pub async fn send(&mut self, call: Call<'_>, now: Duration) -> Result<Response<D::Conn>> {
        follow(&mut self.dialer, Some((&mut self.pool, now)), call).await
    }

    /// Als [`get`](crate::get), via de pool.
    pub async fn get(&mut self, url: &str, now: Duration) -> Result<Response<D::Conn>> {
        let resp = self
            .send(
                Call {
                    url,
                    ..Call::default()
                },
                now,
            )
            .await?;
        check_get(resp).await
    }

    /// Geeft de verbinding van een gelezen antwoord terug aan de pool.
    pub async fn finish(&mut self, resp: Response<D::Conn>, now: Duration) {
        self.pool.finish(resp, now).await;
    }
}
