//! Het onderhoud: een lease verlengen na de bring-up (RFC 2131 §4.4.5).
//!
//! De [`Keeper`] bezit de lease, de fase, de xid-teller en de zendbuffer. Hij
//! bezit geen socket en geen klok. Na de bring-up hebben de lock-vrije
//! RX-ringen van de NIC één eigenaar nodig, de netstack; daarom spreekt de
//! keeper UDP-payloads en zendt de stack ze vanaf `<lease-ip>:68`.
//!
//! Vanaf T1 renewt hij unicast bij de lessor, met halverende pogingen. Vanaf
//! T2 rebindt hij per broadcast, zodat een andere server de lease kan redden
//! als de oorspronkelijke verdwijnt. Bij het verlopen stopt hij hardop.

use core::fmt;
use core::net::Ipv4Addr;
use core::time::Duration;

use crate::lease::Lease;
use crate::time::Instant;
use crate::wire::{self, BOOTP_LEN, MSG_ACK, MSG_NAK, MSG_REQUEST};
use crate::{Error, Result};

/// Hoe lang één poging op een ACK wacht.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// De minimale tijd tussen twee pogingen (RFC 2131 §4.4.5), tegen
/// retry-stormen.
const RETRY_FLOOR: Duration = Duration::from_secs(60);

/// Het voorvoegsel van de xid bij verlengen: "HOP" en `R`, plus een teller per
/// poging. Een teller blijft uniek als de wandklok springt; het voorvoegsel
/// helpt bij een pakketopname.
const XID_PREFIX: u32 = 0x484F_5200;

/// Een lease-toestand uit RFC 2131.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Geldig adres, niets te doen.
    Bound,
    /// Vanaf T1: unicast naar de lessor.
    Renewing,
    /// Vanaf T2: broadcast naar elke server.
    Rebinding,
    /// Het adres is niet meer van ons: verlopen, geweigerd of verhuisd.
    Expired,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bound => "bound",
            Self::Renewing => "renewing",
            Self::Rebinding => "rebinding",
            Self::Expired => "expired",
        })
    }
}

/// Iets dat in de log hoort; de keeper gaat daarna gewoon door.
///
/// `Display` geeft de logregel, Engels en op één regel; de regels met een
/// marker (`HOPOS_DHCP_*`) zijn waar de soak-scripts op greppen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Een poging kreeg binnen de time-out geen ACK.
    Unanswered {
        /// De fase van de poging.
        state: State,
        /// Hoe lang er gewacht is.
        timeout: Duration,
    },
    /// De aanroeper meldde dat zenden faalde; dat telt als een mislukte poging.
    SendFailed {
        /// De fase van de poging.
        state: State,
    },
    /// De lessor antwoordde niet voor T2; vanaf nu per broadcast.
    Rebinding {
        /// De lessor die zweeg.
        server: Ipv4Addr,
    },
    /// De lease is verlengd; dit is de nieuwe.
    Extended {
        /// De fase waarin de ACK kwam.
        state: State,
        /// De samengevoegde lease.
        lease: Lease,
    },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Unanswered { state, timeout } => {
                write!(f, "dhcp {state}: no ACK within {} s", timeout.as_secs())
            }
            Self::SendFailed { state } => write!(f, "dhcp {state}: TX failed"),
            Self::Rebinding { server } => write!(
                f,
                "dhcp: no answer from {server} before T2; rebinding by broadcast HOPOS_DHCP_REBIND"
            ),
            Self::Extended { state, lease } => write!(
                f,
                "dhcp: lease extended ({state}); {}, {}s to go HOPOS_DHCP_RENEW",
                lease.ip, lease.lease_secs
            ),
        }
    }
}

/// Wat de aanroeper nu moet doen.
#[derive(Debug)]
pub enum KeepAction<'a> {
    /// Zend deze BOOTP-payload als UDP van `<lease-ip>:68` naar `to:67` en
    /// poll daarna opnieuw.
    Send {
        /// De lessor bij renewen, 255.255.255.255 bij rebinden.
        to: Ipv4Addr,
        /// De BOOTP-payload.
        payload: &'a [u8],
    },
    /// Voer UDP-payloads van poort 68 toe met [`Keeper::receive`] en poll
    /// opnieuw, uiterlijk op dit tijdstip.
    Wait(Instant),
    /// Log dit en poll meteen opnieuw.
    Event(Event),
    /// Niets te onderhouden: de lease is oneindig of onbekend.
    Done,
}

/// De drie momenten van de lopende lease, als tijdstip.
#[derive(Clone, Copy, Debug)]
struct Schedule {
    t1: Instant,
    t2: Instant,
    expiry: Instant,
}

/// Waar het onderhoud staat.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// Gebonden; wacht op T1.
    Bound(Schedule),
    /// Een poging gaat bij de volgende poll de deur uit.
    Attempt(State, Schedule),
    /// Een poging wacht tot `until` op een ACK.
    Waiting {
        state: State,
        sched: Schedule,
        until: Instant,
    },
    /// Tussen twee pogingen.
    Backoff {
        state: State,
        sched: Schedule,
        until: Instant,
    },
    /// T2 is voorbij zonder ACK; de volgende poll meldt de overstap.
    Rebind(Schedule),
    /// Niets te onderhouden.
    Done,
    /// Het adres is niet meer van ons; blijvend.
    Lost(Error),
}

/// Houdt een lease in leven volgens RFC 2131 §4.4.5.
#[derive(Debug)]
pub struct Keeper {
    mac: [u8; 6],
    lease: Lease,
    attempts: u32,
    xid: u32,
    event: Option<Event>,
    phase: Phase,
    payload: [u8; BOOTP_LEN],
}

impl Keeper {
    /// Een keeper voor `lease`, die op `now` met een ACK binnenkwam.
    ///
    /// De timers lopen vanaf `now`. Een oneindige of onbekende lease geeft een
    /// keeper die meteen [`KeepAction::Done`] zegt.
    pub fn new(mac: [u8; 6], lease: Lease, now: Instant) -> Self {
        Self {
            mac,
            lease,
            attempts: 0,
            xid: 0,
            event: None,
            phase: bind(&lease, now),
            payload: [0; BOOTP_LEN],
        }
    }

    /// De lease zoals hij nu is, na elke verlenging.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// De RFC 2131-toestand van de lease.
    pub fn state(&self) -> State {
        match self.phase {
            Phase::Bound(_) | Phase::Done => State::Bound,
            Phase::Attempt(state, _)
            | Phase::Waiting { state, .. }
            | Phase::Backoff { state, .. } => state,
            Phase::Rebind(_) => State::Rebinding,
            Phase::Lost(_) => State::Expired,
        }
    }

    /// Zegt wat er nu moet gebeuren.
    ///
    /// Geeft een fout als het adres niet meer van ons is: [`Error::Refused`]
    /// na een NAK, [`Error::Expired`] na het verlopen, [`Error::Moved`] als een
    /// server een ander adres gaf. Die fouten zijn blijvend; een reboot haalt
    /// een nieuw adres.
    pub fn poll(&mut self, now: Instant) -> Result<KeepAction<'_>> {
        loop {
            if let Some(e) = self.event.take() {
                return Ok(KeepAction::Event(e));
            }
            match self.phase {
                Phase::Bound(sched) => {
                    if now < sched.t1 {
                        return Ok(KeepAction::Wait(sched.t1));
                    }
                    self.phase = Phase::Attempt(State::Renewing, sched);
                }
                Phase::Attempt(state, sched) => return Ok(self.send(state, sched, now)),
                Phase::Waiting {
                    state,
                    sched,
                    until,
                } => {
                    if now < until {
                        return Ok(KeepAction::Wait(until));
                    }
                    let timeout = REQUEST_TIMEOUT;
                    self.failed(state, sched, now, Event::Unanswered { state, timeout });
                }
                Phase::Backoff {
                    state,
                    sched,
                    until,
                } => {
                    if now < until {
                        return Ok(KeepAction::Wait(until));
                    }
                    self.phase = Phase::Attempt(state, sched);
                }
                Phase::Rebind(sched) => {
                    self.phase = Phase::Attempt(State::Rebinding, sched);
                    let server = self.lease.server;
                    return Ok(KeepAction::Event(Event::Rebinding { server }));
                }
                Phase::Done => return Ok(KeepAction::Done),
                Phase::Lost(err) => return Err(err),
            }
        }
    }

    /// Voert één UDP-payload toe die op poort 68 binnenkwam.
    ///
    /// Alleen een ACK of NAK op de lopende poging telt; ander of laat verkeer
    /// op poort 68 wordt genegeerd. Na elke payload hoort een poll.
    pub fn receive(&mut self, payload: &[u8], now: Instant) {
        let Phase::Waiting { state, .. } = self.phase else {
            return;
        };
        let Some((msg_type, fresh)) = wire::parse_bootp(payload, &self.mac, self.xid) else {
            return;
        };
        match msg_type {
            MSG_ACK => self.acked(state, fresh, now),
            MSG_NAK => {
                // Het adres is niet meer van ons: opnieuw proberen zou actief
                // fout zijn.
                let ip = self.lease.ip;
                self.phase = Phase::Lost(Error::Refused { state, ip });
            }
            _ => {}
        }
    }

    /// Meldt dat zenden van de laatste payload faalde; dat telt als een
    /// mislukte poging.
    pub fn transmit_failed(&mut self, now: Instant) {
        if let Phase::Waiting { state, sched, .. } = self.phase {
            self.failed(state, sched, now, Event::SendFailed { state });
        }
    }

    /// Bouwt een REQUEST met ciaddr op het lease-adres en zonder de opties 50
    /// en 54 (RFC 2131 §4.3.2).
    ///
    /// De broadcast-vlag blijft uit, ook bij rebinden: met een geldig ciaddr
    /// mag het antwoord unicast komen, en onze eigen ingress negeert bewust
    /// IP-broadcast.
    fn send(&mut self, state: State, sched: Schedule, now: Instant) -> KeepAction<'_> {
        self.attempts = self.attempts.wrapping_add(1);
        self.xid = XID_PREFIX | (self.attempts & 0xff);
        let ip = self.lease.ip;
        wire::write_bootp(
            &mut self.payload,
            &self.mac,
            self.xid,
            MSG_REQUEST,
            ip,
            false,
            None,
        );
        let to = match state {
            // Zonder bekende lessor is unicast onmogelijk; broadcast bereikt
            // hem dan toch.
            State::Renewing if !self.lease.server.is_unspecified() => self.lease.server,
            _ => Ipv4Addr::BROADCAST,
        };
        self.phase = Phase::Waiting {
            state,
            sched,
            until: now + REQUEST_TIMEOUT,
        };
        KeepAction::Send {
            to,
            payload: &self.payload,
        }
    }

    /// Een ACK: samenvoegen, controleren dat het adres hetzelfde bleef, en
    /// opnieuw binden vanaf nu.
    fn acked(&mut self, state: State, fresh: Lease, now: Instant) {
        let fresh = self.lease.merge(fresh);
        if fresh.ip != self.lease.ip {
            // Bij rebinden kan een andere server een ander adres geven. De
            // draaiende stack kan dat niet toepassen, en doorgaan zou een adres
            // gebruiken dat de server aan een ander kan geven.
            let (from, to) = (self.lease.ip, fresh.ip);
            self.phase = Phase::Lost(Error::Moved { from, to });
            return;
        }
        self.lease = fresh;
        self.event = Some(Event::Extended {
            state,
            lease: fresh,
        });
        self.phase = bind(&fresh, now);
    }

    /// Een poging mislukte: wacht de helft van de resterende tijd, stap op T2
    /// over op broadcast, of geef het adres op bij het verlopen.
    fn failed(&mut self, state: State, sched: Schedule, now: Instant, event: Event) {
        self.event = Some(event);
        let limit = match state {
            State::Renewing => sched.t2,
            _ => sched.expiry,
        };
        let left = limit.saturating_duration_since(now);
        self.phase = if !left.is_zero() {
            Phase::Backoff {
                state,
                sched,
                until: now + retry_after(left),
            }
        } else if state == State::Renewing {
            Phase::Rebind(sched)
        } else {
            Phase::Lost(Error::Expired { ip: self.lease.ip })
        };
    }
}

/// De fase na een ACK op `now`: gebonden tot T1, of klaar als er niets te
/// plannen is.
fn bind(lease: &Lease, now: Instant) -> Phase {
    match lease.timers() {
        Some(t) => Phase::Bound(Schedule {
            t1: now + t.t1,
            t2: now + t.t2,
            expiry: now + t.expiry,
        }),
        None => Phase::Done,
    }
}

/// De helft van de tijd tot de volgende fase, minstens de RFC-ondergrens en
/// hoogstens de grens zelf, zodat rebinden nooit te laat begint.
fn retry_after(left: Duration) -> Duration {
    (left / 2).max(RETRY_FLOOR).min(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{LESSOR, bootp_reply, bound, has_option, has_option_code};
    use std::fmt::Write as _;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const T0: Instant = Instant::from_millis(5_000_000);

    /// Wat een nagebootste run van de keeper liet zien.
    #[derive(Default)]
    struct Proef {
        slept: Vec<Duration>,
        renews: u32,
        rebinds: u32,
        sent: Vec<(Ipv4Addr, Vec<u8>)>,
        first_rebind: Option<Duration>,
        log: String,
        end: Option<Result>,
    }

    impl Proef {
        fn totaal(&self) -> Duration {
            self.slept.iter().sum()
        }
    }

    /// Welke kant een REQUEST op ging.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kant {
        Renew,
        Rebind,
    }

    /// Draait de keeper op een nagebootste klok. `server` krijgt elke REQUEST
    /// met het volgnummer binnen zijn kant en mag een antwoord teruggeven.
    fn draai(lease: Lease, mut server: impl FnMut(Kant, u32, &[u8]) -> Vec<Vec<u8>>) -> Proef {
        let mut p = Proef::default();
        let mut k = Keeper::new(MAC, lease, T0);
        let mut now = T0;
        let mut na_zenden = false;
        for _ in 0..100_000 {
            match k.poll(now) {
                Ok(KeepAction::Send { to, payload }) => {
                    let payload = payload.to_vec();
                    let (kant, n) = if to == Ipv4Addr::BROADCAST {
                        p.rebinds += 1;
                        p.first_rebind
                            .get_or_insert(now.saturating_duration_since(T0));
                        (Kant::Rebind, p.rebinds)
                    } else {
                        p.renews += 1;
                        (Kant::Renew, p.renews)
                    };
                    p.sent.push((to, payload.clone()));
                    for antwoord in server(kant, n, &payload) {
                        k.receive(&antwoord, now);
                    }
                    na_zenden = true;
                }
                Ok(KeepAction::Wait(until)) => {
                    // Het wachten direct na een REQUEST is de time-out van de
                    // poging; al het andere wachten is slapen.
                    if !na_zenden {
                        p.slept.push(until.saturating_duration_since(now));
                    }
                    na_zenden = false;
                    now = now.max(until);
                }
                Ok(KeepAction::Event(e)) => {
                    na_zenden = false;
                    writeln!(p.log, "{e}").unwrap();
                }
                Ok(KeepAction::Done) => {
                    p.end = Some(Ok(()));
                    return p;
                }
                Err(e) => {
                    writeln!(p.log, "{e}").unwrap();
                    p.end = Some(Err(e));
                    return p;
                }
            }
        }
        panic!("de keeper stopte niet");
    }

    fn ack(req: &[u8], yiaddr: [u8; 4], extra: &[u8]) -> Vec<Vec<u8>> {
        vec![bootp_reply(req, MSG_ACK, yiaddr, extra)]
    }

    const IP: [u8; 4] = [192, 168, 1, 33];
    const ONEINDIG: &[u8] = &[51, 4, 0xff, 0xff, 0xff, 0xff];

    #[test]
    fn retry_after() {
        let s = Duration::from_secs;
        for (left, want) in [
            (s(3600), s(1800)),
            (s(240), s(120)),
            (s(180), s(90)),
            (s(100), RETRY_FLOOR),
            (s(90), RETRY_FLOOR),
            (s(30), s(30)),
            (s(1), s(1)),
        ] {
            assert_eq!(super::retry_after(left), want, "retry_after({left:?})");
        }
    }

    #[test]
    fn keeper_renewt_op_t1() {
        let p = draai(bound(), |kant, n, req| {
            assert_eq!(
                kant,
                Kant::Renew,
                "rebind werd gebruikt terwijl de lessor antwoordde"
            );
            if n == 3 {
                ack(req, IP, ONEINDIG)
            } else {
                ack(req, IP, LESSOR)
            }
        });
        assert_eq!(p.renews, 3);
        for (i, d) in p.slept[..2].iter().enumerate() {
            assert_eq!(
                *d,
                Duration::from_secs(1800),
                "slaapje {i} hoort T1 te zijn"
            );
        }
        assert_eq!(p.log.matches("HOPOS_DHCP_RENEW").count(), 3, "{}", p.log);
        assert_eq!(p.end, Some(Ok(())));
    }

    #[test]
    fn keeper_rebindt_op_t2() {
        let p = draai(bound(), |kant, _, req| match kant {
            Kant::Renew => Vec::new(),
            Kant::Rebind => ack(req, IP, ONEINDIG),
        });
        assert!(p.renews > 0, "er is nooit een unicast-renew geprobeerd");
        assert_eq!(p.rebinds, 1, "de rebind-fase werd niet bereikt");

        let t = bound().timers().unwrap();
        let besteed = p.first_rebind.unwrap();
        assert!(
            besteed >= t.t2,
            "overgestapt na {besteed:?}, terwijl T2 op {:?} ligt",
            t.t2
        );
        assert!(
            besteed <= t.t2 + RETRY_FLOOR,
            "pas na {besteed:?} overgestapt"
        );
        assert_eq!(p.slept[0], t.t1, "eerste slaapje hoort T1 te zijn");
        assert!(p.log.contains("HOPOS_DHCP_REBIND"), "{}", p.log);
    }

    #[test]
    fn keeper_verloopt_en_zwijgt_niet() {
        let p = draai(bound(), |_, _, _| Vec::new());
        assert!(
            p.renews > 0 && p.rebinds > 0,
            "beide fasen horen geprobeerd te zijn"
        );
        let t = bound().timers().unwrap();
        let besteed = p.totaal() + REQUEST_TIMEOUT * (p.renews + p.rebinds);
        assert!(
            besteed <= t.expiry + RETRY_FLOOR,
            "bleef {besteed:?} proberen"
        );
        assert_eq!(p.end, Some(Err(Error::Expired { ip: IP.into() })));
        assert!(p.log.contains("HOPOS_DHCP_EXPIRED"), "{}", p.log);
        assert!(
            p.log.contains("192.168.1.33"),
            "de melding noemt het adres niet"
        );
    }

    #[test]
    fn keeper_nak_stopt_meteen() {
        let p = draai(bound(), |kant, _, req| {
            assert_eq!(kant, Kant::Renew, "rebind na een NAK");
            vec![bootp_reply(req, MSG_NAK, IP, &[])]
        });
        assert_eq!(p.renews, 1, "pogingen na een NAK");
        assert!(p.log.contains("HOPOS_DHCP_NAK"), "{}", p.log);
    }

    #[test]
    fn keeper_ander_adres_stopt() {
        let p = draai(bound(), |_, _, req| ack(req, [192, 168, 1, 99], LESSOR));
        assert_eq!(p.renews, 1);
        assert!(p.log.contains("HOPOS_DHCP_MOVED"), "{}", p.log);
        assert!(
            p.log.contains("192.168.1.99") && p.log.contains("192.168.1.33"),
            "{}",
            p.log
        );
    }

    #[test]
    fn keeper_oneindige_lease() {
        let l = Lease {
            lease_secs: u32::MAX,
            t1_secs: 0,
            t2_secs: 0,
            ..bound()
        };
        let p = draai(l, |_, _, _| panic!("een oneindige lease werd vernieuwd"));
        assert!(
            p.slept.is_empty(),
            "er is {:?} geslapen op een oneindige lease",
            p.slept
        );
        assert_eq!(p.end, Some(Ok(())));
    }

    #[test]
    fn keep_alive_zonder_lease() {
        let mut k = Keeper::new(MAC, Lease::default(), T0);
        assert!(matches!(k.poll(T0), Ok(KeepAction::Done)));
    }

    #[test]
    fn state_string() {
        for (s, want) in [
            (State::Bound, "bound"),
            (State::Renewing, "renewing"),
            (State::Rebinding, "rebinding"),
            (State::Expired, "expired"),
        ] {
            assert_eq!(s.to_string(), want);
        }
    }

    #[test]
    fn renew_request_vorm() {
        let p = draai(bound(), |_, _, _| vec![]);
        let l = bound();
        let bp = &p.sent[0].1;
        assert_eq!(bp.len(), BOOTP_LEN);
        assert_eq!(bp[0], 1, "geen BOOTREQUEST");
        assert_eq!(
            bp[10] & 0x80,
            0,
            "broadcast-flag staat aan in een renew; het antwoord komt dan als broadcast en dat negeert onze eigen ingress"
        );
        assert_eq!(
            bp[12..16],
            l.ip.octets(),
            "ciaddr hoort het lease-IP te zijn"
        );
        assert_eq!(bp[28..34], MAC, "chaddr is niet ons MAC");

        let mut frame = vec![0u8; 42];
        frame.extend_from_slice(bp);
        for code in [50, 54] {
            assert!(
                !has_option_code(&frame, code),
                "optie {code} staat in een renew-REQUEST"
            );
        }
        assert!(
            has_option(&frame, 53, &[MSG_REQUEST]),
            "optie 53 zegt niet REQUEST"
        );
    }

    #[test]
    fn renew_gaat_naar_de_lessor() {
        let p = draai(bound(), |_, _, _| vec![]);
        assert_eq!(
            p.sent[0].0,
            bound().server,
            "renew hoort naar de lessor te gaan"
        );
        assert!(
            p.end.unwrap().is_err(),
            "een stille server gaf toch een lease"
        );
    }

    #[test]
    fn rebind_gaat_broadcast() {
        let p = draai(bound(), |_, _, _| vec![]);
        let (to, bp) = p
            .sent
            .iter()
            .find(|(to, _)| *to == Ipv4Addr::BROADCAST)
            .expect("er werd nooit gerebind");
        assert_eq!(*to, Ipv4Addr::BROADCAST);
        assert_eq!(bp[12..16], IP, "ciaddr hoort het lease-IP te zijn");
        assert_eq!(bp[10] & 0x80, 0, "broadcast-flag staat aan");
    }

    #[test]
    fn request_ack() {
        let l = bound();
        let mut k = Keeper::new(MAC, l, T0);
        let t1 = T0 + Duration::from_secs(1800);
        let Ok(KeepAction::Wait(at)) = k.poll(T0) else {
            panic!("geen wachten op T1");
        };
        assert_eq!(at, t1);
        let Ok(KeepAction::Send { payload, .. }) = k.poll(t1) else {
            panic!("geen renew op T1");
        };
        let antwoord = bootp_reply(payload, MSG_ACK, IP, &[51, 4, 0, 0, 0x1c, 0x20]);
        k.receive(&antwoord, t1);
        let Ok(KeepAction::Event(Event::Extended { lease: got, .. })) = k.poll(t1) else {
            panic!("de ACK verlengde de lease niet");
        };
        assert_eq!(
            got.lease_secs, 7200,
            "de looptijd hoort uit de ACK te komen"
        );
        assert_eq!(
            (got.mask, got.gateway, got.server, got.dns),
            (l.mask, l.gateway, l.server, l.dns),
            "de karige ACK wiste velden"
        );
        assert_eq!(*k.lease(), got);
        assert_eq!(k.state(), State::Bound);
    }

    #[test]
    fn request_nak() {
        let p = draai(bound(), |_, _, req| {
            vec![bootp_reply(req, MSG_NAK, IP, &[])]
        });
        let err = p.end.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                Error::Refused {
                    state: State::Renewing,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("renewing"),
            "de fase hoort in het bericht: {err}"
        );
    }

    #[test]
    fn request_slaat_vreemd_verkeer_over() {
        let mut andere = vec![0u8; 300];
        andere[0] = 2;
        andere[4] = 0xff;
        let p = draai(bound(), move |_, _, req| {
            vec![
                vec![0u8; 10],
                vec![0u8; 300],
                andere.clone(),
                bootp_reply(req, MSG_ACK, IP, ONEINDIG),
            ]
        });
        assert_eq!(
            p.end,
            Some(Ok(())),
            "vreemd verkeer op :68 verpestte de renew: {}",
            p.log
        );
        assert_eq!(p.renews, 1);
        assert!(p.log.contains("HOPOS_DHCP_RENEW"));
    }

    #[test]
    fn zendfout_telt_als_poging() {
        let mut k = Keeper::new(MAC, bound(), T0);
        let t1 = T0 + Duration::from_secs(1800);
        assert!(matches!(k.poll(t1), Ok(KeepAction::Send { .. })));
        k.transmit_failed(t1);
        assert!(matches!(
            k.poll(t1),
            Ok(KeepAction::Event(Event::SendFailed {
                state: State::Renewing
            }))
        ));
        assert!(matches!(k.poll(t1), Ok(KeepAction::Wait(_))));
        assert_eq!(k.state(), State::Renewing);
    }
}
