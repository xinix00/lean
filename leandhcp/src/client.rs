//! De bring-up: een lease ophalen over rauwe ethernet-frames (DORA).
//!
//! De [`Client`] bezit de ronde, de xid, het venster en de zendbuffer. Hij
//! bezit geen NIC en geen klok: de aanroeper zendt wat [`Client::poll`]
//! teruggeeft, voert ontvangen frames toe met [`Client::receive`] en levert de
//! tijd.

use core::time::Duration;

use crate::lease::Lease;
use crate::time::Instant;
use crate::wire::{self, Confirm, FRAME_LEN, MSG_ACK, MSG_DISCOVER, MSG_OFFER, MSG_REQUEST};
use crate::{Error, Result};

/// Hoe lang één wachtfase van een DORA-ronde hoogstens duurt.
const ROUND_WINDOW: Duration = Duration::from_secs(3);

/// Het minimale venster voor de ACK, ook voorbij de totale deadline.
///
/// Een REQUEST reserveert het adres voor dit MAC. Zonder ondergrens melden we
/// een time-out terwijl de router een lease vasthoudt die de node nooit
/// gebruikt.
const ACK_GRACE: Duration = Duration::from_secs(1);

/// Hoeveel frames na het sluiten van het venster nog gelezen worden.
///
/// Genoeg voor gewoon verkeer dat al in de ring stond, te weinig om een
/// broadcast-storm de bring-up eindeloos te laten rekken.
const GRACE_FRAMES: u8 = 64;

/// Het voorvoegsel van elke xid: "HOP" plus het rondenummer, zodat een
/// pakketopname laat zien van wie en uit welke ronde een bericht is.
const XID_PREFIX: u32 = 0x484F_5000;

/// Wat de aanroeper nu moet doen.
#[derive(Debug)]
pub enum Action<'a> {
    /// Zend dit ethernet-frame en poll daarna opnieuw.
    Transmit(&'a [u8]),
    /// Voer ontvangen frames toe met [`Client::receive`] en poll opnieuw,
    /// uiterlijk op dit tijdstip.
    ///
    /// Is de ring leeg, dan mag de aanroeper slapen tot het tijdstip of tot er
    /// een frame binnenkomt. Het tijdstip kan al voorbij zijn: dan wil de
    /// client weten of er nog iets in de ring staat voordat hij de ronde
    /// sluit. Poll na elk toegevoerd frame, zoals de Go-lus deed.
    Wait(Instant),
    /// Klaar: dit is de lease. Verdere polls geven hem opnieuw.
    Bound(Lease),
}

/// Waar een ronde staat.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// Een nieuwe ronde begint bij de volgende poll, als de deadline dat toelaat.
    Start,
    /// Het REQUEST staat klaar in de zendbuffer en gaat bij de volgende poll.
    Request,
    /// Wachten op een antwoord van één type.
    Await(Await),
    /// Een ACK is binnen.
    Bound(Lease),
    /// Mislukt; blijvend.
    Failed(Error),
}

/// Het wachten op één antwoord.
#[derive(Clone, Copy, Debug)]
struct Await {
    /// Het berichttype dat telt (OFFER of ACK).
    expect: u8,
    /// Tot hier wacht de ronde.
    window: Instant,
    /// Frames die na het venster nog gelezen mogen worden.
    grace: u8,
    /// Er kwam een frame binnen sinds de vorige poll: de ring was toen niet
    /// leeg, dus er kan nog een antwoord achter staan.
    fed: bool,
    /// De grace is op; de volgende poll sluit de ronde.
    closed: bool,
}

/// Een DHCPv4-client voor de bring-up over rauwe frames.
///
/// Elke ronde krijgt een verse xid, zodat een laat OFFER uit een vorige ronde
/// nooit bij een latere poging past. Binnen de totale time-out begint na een
/// mislukte ronde meteen de volgende.
#[derive(Debug)]
pub struct Client {
    mac: [u8; 6],
    timeout: Duration,
    deadline: Instant,
    round: u32,
    xid: u32,
    rx_errors: u32,
    phase: Phase,
    frame: [u8; FRAME_LEN],
}

impl Client {
    /// Een client voor `mac` die tot `now + timeout` rondes mag beginnen.
    pub fn new(mac: [u8; 6], now: Instant, timeout: Duration) -> Self {
        Self {
            mac,
            timeout,
            deadline: now + timeout,
            round: 0,
            xid: 0,
            rx_errors: 0,
            phase: Phase::Start,
            frame: [0; FRAME_LEN],
        }
    }

    /// Zegt wat er nu moet gebeuren.
    ///
    /// Geeft een [`Error::NoLease`] als de deadline verstreek zonder lease, en
    /// [`Error::Transmit`] na [`Client::transmit_failed`]. Beide zijn blijvend.
    pub fn poll(&mut self, now: Instant) -> Result<Action<'_>> {
        loop {
            match self.phase {
                Phase::Start => {
                    if now >= self.deadline {
                        let err = Error::NoLease {
                            timeout: self.timeout,
                            rx_errors: self.rx_errors,
                        };
                        self.phase = Phase::Failed(err);
                        return Err(err);
                    }
                    self.round = self.round.wrapping_add(1);
                    self.xid = XID_PREFIX | (self.round & 0xff);
                    wire::write_frame(&mut self.frame, &self.mac, self.xid, MSG_DISCOVER, None);
                    // Een DISCOVER bindt niets, dus de totale deadline mag dit
                    // wachten afbreken.
                    self.phase = Phase::Await(self.await_for(MSG_OFFER, now, Duration::ZERO));
                    return Ok(Action::Transmit(&self.frame));
                }
                Phase::Request => {
                    self.phase = Phase::Await(self.await_for(MSG_ACK, now, ACK_GRACE));
                    return Ok(Action::Transmit(&self.frame));
                }
                Phase::Await(ref mut a) => {
                    // De tijd telt pas als de ring leeg was: een antwoord dat al
                    // klaarstond blijft geldig, ook als het venster net sloot.
                    if now < a.window || (a.fed && !a.closed) {
                        a.fed = false;
                        return Ok(Action::Wait(a.window));
                    }
                    self.phase = Phase::Start;
                }
                Phase::Bound(lease) => return Ok(Action::Bound(lease)),
                Phase::Failed(err) => return Err(err),
            }
        }
    }

    /// Voert één ontvangen ethernet-frame toe.
    ///
    /// Alles wat geen antwoord op de lopende ronde is (ander MAC, andere xid,
    /// ander type, rommel), wordt genegeerd. Na elk frame hoort een poll.
    pub fn receive(&mut self, frame: &[u8], now: Instant) {
        let Phase::Await(ref mut a) = self.phase else {
            return;
        };
        if frame.is_empty() || a.closed {
            return;
        }
        a.fed = true;
        let expect = a.expect;
        let window = a.window;
        match wire::parse_frame(frame, &self.mac, self.xid) {
            Some((t, lease)) if t == expect && expect == MSG_OFFER => self.request(lease),
            Some((t, lease)) if t == expect => self.phase = Phase::Bound(lease),
            _ if now >= window => {
                if a.grace == 0 {
                    a.closed = true;
                } else {
                    a.grace -= 1;
                }
            }
            _ => {}
        }
    }

    /// Meldt dat de NIC een ontvangstfout gaf.
    ///
    /// Zo'n fout is per frame niet fataal, maar telt mee in de eindfout: een
    /// kapotte NIC mag niet als "geen server" worden gemeld.
    pub fn receive_failed(&mut self) {
        self.rx_errors = self.rx_errors.saturating_add(1);
    }

    /// Meldt dat zenden faalde; de volgende poll geeft [`Error::Transmit`].
    ///
    /// Een lease die al binnen is, blijft staan.
    pub fn transmit_failed(&mut self) {
        if !matches!(self.phase, Phase::Bound(_)) {
            self.phase = Phase::Failed(Error::Transmit);
        }
    }

    /// Bouwt het REQUEST dat het OFFER bevestigt (optie 50 is het adres,
    /// optie 54 de server), in dezelfde ronde en met dezelfde xid.
    fn request(&mut self, offer: Lease) {
        let confirm = Confirm {
            ip: offer.ip,
            server: offer.server,
        };
        wire::write_frame(
            &mut self.frame,
            &self.mac,
            self.xid,
            MSG_REQUEST,
            Some(confirm),
        );
        self.phase = Phase::Request;
    }

    /// Het wachten op `expect`: tot het rondevenster of de deadline, maar
    /// minstens `least`.
    fn await_for(&self, expect: u8, now: Instant, least: Duration) -> Await {
        let window = (now + ROUND_WINDOW).min(self.deadline).max(now + least);
        Await {
            expect,
            window,
            grace: GRACE_FRAMES,
            fed: false,
            closed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{LESSOR, be32, has_option, msg_type_of, reply};
    use crate::wire::{MSG_NAK, checksum};
    use core::net::Ipv4Addr;
    use std::collections::VecDeque;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const T0: Instant = Instant::from_millis(1_000_000);

    /// Een nagebootste NIC met een klok: frames komen binnen op een tijdstip.
    #[derive(Default)]
    struct Nic {
        now: Instant,
        rx: VecDeque<(Instant, Vec<u8>)>,
        tx: Vec<Vec<u8>>,
        rx_err: bool,
        tx_err: bool,
        flood: Option<Vec<u8>>,
    }

    impl Nic {
        fn push(&mut self, f: Vec<u8>) {
            let now = self.now;
            self.push_at(now, f);
        }

        fn push_at(&mut self, at: Instant, f: Vec<u8>) {
            self.rx.push_back((at, f));
        }

        fn receive(&mut self) -> Option<Vec<u8>> {
            if let Some(f) = &self.flood {
                return Some(f.clone());
            }
            match self.rx.front() {
                Some((at, _)) if *at <= self.now => self.rx.pop_front().map(|(_, f)| f),
                _ => None,
            }
        }
    }

    type Server = Box<dyn FnMut(&mut Nic, &[u8])>;

    /// Een DHCP-server die op alles antwoordt met `yiaddr`.
    fn dhcp_server(yiaddr: [u8; 4]) -> Server {
        Box::new(move |n, frame| match msg_type_of(frame) {
            MSG_DISCOVER => n.push(reply(frame, MSG_OFFER, yiaddr, LESSOR)),
            MSG_REQUEST => n.push(reply(frame, MSG_ACK, yiaddr, LESSOR)),
            _ => {}
        })
    }

    /// De lus van de aanroeper, zoals hop-os hem draait, op een nagebootste klok.
    /// Geeft de uitkomst en de verstreken tijd.
    fn acquire(
        nic: &mut Nic,
        mut server: Option<Server>,
        timeout: Duration,
    ) -> (Result<Lease>, Duration) {
        nic.now = T0;
        let mut c = Client::new(MAC, T0, timeout);
        for _ in 0..1_000_000 {
            match c.poll(nic.now) {
                Ok(Action::Transmit(f)) => {
                    if nic.tx_err {
                        c.transmit_failed();
                        continue;
                    }
                    let f = f.to_vec();
                    nic.tx.push(f.clone());
                    if let Some(s) = server.as_mut() {
                        s(nic, &f);
                    }
                }
                Ok(Action::Wait(until)) => {
                    if nic.rx_err {
                        c.receive_failed();
                    }
                    match nic.receive() {
                        Some(f) => c.receive(&f, nic.now),
                        None => {
                            // Slapen tot het venster of het volgende frame.
                            let next = nic.rx.front().map_or(until, |(at, _)| (*at).min(until));
                            nic.now = nic.now.max(next);
                        }
                    }
                }
                Ok(Action::Bound(l)) => return (Ok(l), nic.now.saturating_duration_since(T0)),
                Err(e) => return (Err(e), nic.now.saturating_duration_since(T0)),
            }
        }
        panic!("de lus eindigde niet");
    }

    #[test]
    fn acquire_dora() {
        let mut nic = Nic::default();
        let (l, _) = acquire(
            &mut nic,
            Some(dhcp_server([192, 168, 1, 33])),
            Duration::from_secs(3),
        );
        let l = l.unwrap();
        assert_eq!(l.cidr().to_string(), "192.168.1.33/24");
        assert_eq!(l.gateway.to_string(), "192.168.1.1");
        assert_eq!(l.dns.to_string(), "192.168.1.1");
        assert_eq!(l.server, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!((l.lease_secs, l.t1_secs, l.t2_secs), (3600, 1800, 3150));

        assert_eq!(nic.tx.len(), 2, "twee pakketten verwacht");
        assert_eq!(msg_type_of(&nic.tx[0]), MSG_DISCOVER);
        assert_eq!(msg_type_of(&nic.tx[1]), MSG_REQUEST);
        assert_eq!(
            be32(&nic.tx[0][46..50]),
            be32(&nic.tx[1][46..50]),
            "REQUEST gebruikte een andere xid dan de DISCOVER van dezelfde ronde"
        );
        assert!(
            has_option(&nic.tx[1], 50, &[192, 168, 1, 33]),
            "optie 50 ontbreekt"
        );
        assert!(
            has_option(&nic.tx[1], 54, &[192, 168, 1, 1]),
            "optie 54 ontbreekt"
        );
    }

    #[test]
    fn discover_vorm() {
        let mut nic = Nic::default();
        let _ = acquire(&mut nic, None, Duration::from_millis(10));
        let f = nic.tx.first().expect("niets verstuurd");
        assert_eq!(f.len(), FRAME_LEN);
        assert_eq!(f[..6], [0xff; 6], "dst hoort broadcast te zijn");
        assert_eq!(f[6..12], [2, 0, 0, 0, 0, 1], "src hoort ons MAC te zijn");
        assert_eq!(f[12..14], [0x08, 0x00], "ethertype hoort IPv4 te zijn");
        assert_eq!(checksum(&f[14..34]), 0, "IP-header-checksum klopt niet");
        assert_eq!(usize::from(f[16]) << 8 | usize::from(f[17]), f.len() - 14);
        assert_eq!(
            (f[35], f[37]),
            (68, 67),
            "UDP-poorten horen 68 naar 67 te zijn"
        );
        assert_eq!(
            f[42..45],
            [1, 1, 6],
            "BOOTP-kop is geen BOOTREQUEST over ethernet"
        );
        assert_ne!(
            f[52] & 0x80,
            0,
            "broadcast-flag staat uit; het antwoord komt dan als unicast en kan op het RX-filter stuklopen"
        );
        assert_eq!(
            f[42 + 236..42 + 240],
            [99, 130, 83, 99],
            "DHCP-magic ontbreekt"
        );
        assert!(
            has_option(f, 55, &[1, 3, 6, 51, 58, 59]),
            "optie 55 vraagt niet om 1/3/6/51/58/59"
        );
    }

    #[test]
    fn acquire_geen_server() {
        let mut nic = Nic::default();
        let (res, elapsed) = acquire(&mut nic, None, Duration::from_millis(200));
        let err = res.expect_err("lease uit een leeg segment");
        assert!(err.to_string().contains("no server answered"), "{err}");
        assert!(
            elapsed <= Duration::from_secs(3),
            "Acquire duurde {elapsed:?} op 200ms"
        );
    }

    #[test]
    fn acquire_nic_fout() {
        let mut nic = Nic {
            rx_err: true,
            ..Nic::default()
        };
        let (res, _) = acquire(&mut nic, None, Duration::from_millis(150));
        match res {
            Err(Error::NoLease { rx_errors, .. }) if rx_errors > 0 => {}
            other => panic!("{other:?}: de RX-fout van de NIC hoort mee naar boven"),
        }
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("NIC receive errors") && !err.contains("no server"),
            "{err}"
        );
    }

    #[test]
    fn acquire_tx_fout() {
        let mut nic = Nic {
            tx_err: true,
            ..Nic::default()
        };
        let (res, elapsed) = acquire(&mut nic, None, Duration::from_secs(10));
        assert_eq!(res, Err(Error::Transmit));
        assert!(
            elapsed < Duration::from_secs(1),
            "Acquire bleef pollen terwijl zenden faalde"
        );
        assert!(nic.tx.is_empty());
    }

    #[test]
    fn acquire_laatste_tick() {
        let mut nic = Nic::default();
        let server: Server = Box::new(|n, frame| match msg_type_of(frame) {
            MSG_DISCOVER => n.push(reply(frame, MSG_OFFER, [192, 168, 1, 44], LESSOR)),
            MSG_REQUEST => {
                let at = n.now + Duration::from_millis(120);
                n.push_at(at, reply(frame, MSG_ACK, [192, 168, 1, 44], LESSOR));
            }
            _ => {}
        });
        let (res, elapsed) = acquire(&mut nic, Some(server), Duration::from_millis(50));
        let l = res.expect("een verkregen lease werd als timeout gemeld");
        assert_eq!(l.ip, Ipv4Addr::new(192, 168, 1, 44));
        assert!(
            elapsed <= Duration::from_millis(50) + ACK_GRACE + Duration::from_secs(1),
            "Acquire duurde {elapsed:?}; de grace hoort begrensd te zijn"
        );

        // En de grace is echt begrensd: een ACK na de grace telt niet meer.
        let mut nic = Nic::default();
        let server: Server = Box::new(|n, frame| match msg_type_of(frame) {
            MSG_DISCOVER => n.push(reply(frame, MSG_OFFER, [192, 168, 1, 44], LESSOR)),
            MSG_REQUEST => {
                let at = n.now + ACK_GRACE + Duration::from_millis(100);
                n.push_at(at, reply(frame, MSG_ACK, [192, 168, 1, 44], LESSOR));
            }
            _ => {}
        });
        let (res, _) = acquire(&mut nic, Some(server), Duration::from_millis(50));
        assert!(res.is_err(), "een ACK na de grace werd toch aangenomen");
    }

    #[test]
    fn await_leest_wat_er_al_ligt() {
        let mut c = Client::new(MAC, T0, Duration::from_millis(10));
        let Ok(Action::Transmit(d)) = c.poll(T0) else {
            panic!("geen DISCOVER");
        };
        let d = d.to_vec();
        // Een uur later, maar het OFFER lag al in de ring voordat we pollden.
        let laat = T0 + Duration::from_secs(3600);
        c.receive(&reply(&d, MSG_OFFER, [10, 1, 2, 3], LESSOR), laat);
        let Ok(Action::Transmit(r)) = c.poll(laat) else {
            panic!("await negeerde een OFFER dat al in de ring lag");
        };
        let r = r.to_vec();
        let later = laat + Duration::from_secs(3600);
        c.receive(&reply(&r, MSG_ACK, [10, 1, 2, 3], LESSOR), later);
        match c.poll(later) {
            Ok(Action::Bound(l)) => assert_eq!(l.ip, Ipv4Addr::new(10, 1, 2, 3)),
            other => panic!("await negeerde een ACK dat al in de ring lag: {other:?}"),
        }
    }

    #[test]
    fn await_storm_loopt() {
        let mut c = Client::new(MAC, T0, Duration::from_millis(10));
        assert!(matches!(c.poll(T0), Ok(Action::Transmit(_))));
        let laat = T0 + Duration::from_secs(3600);
        let junk = vec![0u8; 300];
        for i in 0..1000 {
            c.receive(&junk, laat);
            match c.poll(laat) {
                Ok(Action::Wait(_)) => continue,
                Err(_) => {
                    assert!(
                        i <= usize::from(GRACE_FRAMES) + 1,
                        "{i} frames voorbij het venster"
                    );
                    return;
                }
                Ok(other) => panic!("{other:?}"),
            }
        }
        panic!("await bleef hangen op een frame-storm voorbij zijn window");
    }

    #[test]
    fn acquire_tweede_ronde() {
        let mut nic = Nic::default();
        let mut rondes = 0;
        let server: Server = Box::new(move |n, frame| {
            if msg_type_of(frame) == MSG_DISCOVER {
                rondes += 1;
                if rondes == 1 {
                    return;
                }
                let oud = n.tx[0].clone();
                n.push(reply(&oud, MSG_OFFER, [10, 9, 9, 9], LESSOR));
                n.push(reply(frame, MSG_OFFER, [192, 168, 1, 55], LESSOR));
                return;
            }
            n.push(reply(frame, MSG_ACK, [192, 168, 1, 55], LESSOR));
        });
        let (res, _) = acquire(&mut nic, Some(server), Duration::from_secs(8));
        let l = res.unwrap();
        assert_eq!(
            l.ip,
            Ipv4Addr::new(192, 168, 1, 55),
            "een laat OFFER van de vorige ronde werd aangenomen"
        );
        let rondes = nic
            .tx
            .iter()
            .filter(|f| msg_type_of(f) == MSG_DISCOVER)
            .count();
        assert!(rondes >= 2, "{rondes} rondes, want minstens 2");
    }

    #[test]
    fn acquire_negeert_vreemde_frames() {
        let mut nic = Nic::default();
        let server: Server = Box::new(|n, frame| {
            if msg_type_of(frame) != MSG_DISCOVER {
                n.push(reply(frame, MSG_ACK, [192, 168, 1, 66], LESSOR));
                return;
            }
            let goed = reply(frame, MSG_OFFER, [192, 168, 1, 66], LESSOR);
            let mut verkeerde_xid = goed.clone();
            verkeerde_xid[46] ^= 0xff;
            let mut verkeerd_mac = goed.clone();
            verkeerd_mac[42 + 28] ^= 0xff;
            let verkeerd_type = reply(frame, MSG_NAK, [192, 168, 1, 66], LESSOR);
            let afgekapt = goed[..60].to_vec();
            let rommel: Vec<u8> = (0..100u8).map(|i| i.wrapping_mul(3)).collect();
            for f in [
                rommel,
                afgekapt,
                verkeerde_xid,
                verkeerd_mac,
                verkeerd_type,
                goed,
            ] {
                n.push(f);
            }
        });
        let (res, _) = acquire(&mut nic, Some(server), Duration::from_secs(3));
        assert_eq!(res.unwrap().ip, Ipv4Addr::new(192, 168, 1, 66));
    }
}
