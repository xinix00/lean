//! De stack: één eigenaar van alle verbindingen, de ARP-tabel, de pot, de
//! wachtrijen en de timers.
//!
//! Deze module verbindt de pure protocolmachines met frames: ingress-demux,
//! de zendpomp, ARP-routering, poorttabellen en loopback. Hij doet geen I/O:
//! de eigenaar-taak geeft frames aan [`Stack::receive`], haalt ze op met
//! [`Stack::poll_transmit`] en slaapt tot [`Stack::next_timeout`]. De
//! socket-API voor handvatten staat in [`crate::socket`].
//!
//! Waar de Go-versie één mutex en één pomp-goroutine had, is er hier geen van
//! beide: `&mut self` is het slot, en de aanroeper is de pomp.

use alloc::vec::Vec;
use core::task::Waker;

use crate::arp::{ARP_CACHE_CAP, ArpOut, ArpTable};
use crate::icmp;
use crate::multicast::{is_link_local_multicast, is_multicast_ip, is_multicast_mac, multicast_mac};
use crate::queue::RecordQueue;
use crate::ring::{Budget, Ring, TxRing, alloc_zeroed};
use crate::tcp::{Seg, TCP_RTO_MIN, TcpConn, TcpState};
use crate::udp::UdpTable;
use crate::waker::WakerSlot;
use crate::wire::{
    self, BCAST_IP, BCAST_MAC, ETHERTYPE_ARP, ETHERTYPE_IPV4, MIN_FRAME, PROTO_ICMP, PROTO_TCP,
    PROTO_UDP, SIZE_ETH, SIZE_IPV4, SIZE_TCP, TcpFlags, TcpHeader,
};
use crate::{ArpStats, Error, Result, SEC};

/// De klassieke Ethernet-MTU.
pub const MTU: usize = 1500;
/// Grootte van een Ethernet-header.
pub const ETHERNET_HEADER_SIZE: usize = SIZE_ETH;
/// Header plus FCS-marge: een frame is hoogstens `mtu + ETHERNET_MAXIMUM_SIZE`.
pub const ETHERNET_MAXIMUM_SIZE: usize = 18;

/// Eerste efemere poort (RFC 6335). Dit bereik blijft los van `hopswitch.MasqEnd`.
pub(crate) const EPHEMERAL_BASE: u16 = 49152;
/// Laatste efemere poort.
pub(crate) const EPHEMERAL_END: u16 = 65535;

/// Een handshake plus een venster aan segmenten; meer valt weg.
pub(crate) const LOOPBACK_MAX: usize = 64;
/// Begrenst verbindingsloze antwoorden, zodat SYNs naar gesloten poorten of
/// echovloeden geen geheugen kweken.
pub(crate) const OUT_QUEUE_CAP: usize = 32;
/// Uitgaande UDP-frames die op de pomp wachten; vol is terugdruk, geen drop.
const UDP_OUT_FRAMES: usize = 16;

/// Beginmaat van een ontvangstring. Een peer mag zo het RFC 6928-beginvenster
/// van tien segmenten sturen zonder dat ons venster stop-and-wait afdwingt;
/// een snelle lezer zou anders groei nooit laten triggeren.
pub(crate) const TCP_FLOOR_RX: usize = 16 << 10;
/// Beginmaat van een zendring; die groeit als applicatiewrites druk maken.
pub(crate) const TCP_FLOOR_TX: usize = 4 << 10;
/// De minimale reservering per verbinding.
pub(crate) const TCP_FLOOR_RING: usize = TCP_FLOOR_RX + TCP_FLOOR_TX;

/// Voltooide handshakes die op `accept` wachten. Overloop krijgt een RST in
/// plaats van een onzichtbare verbindingsplek.
pub(crate) const TCP_BACKLOG: usize = 8;
/// Een voltooide handshake heeft geen applicatie-eigenaar tot `accept` hem
/// teruggeeft. Die overdracht is begrensd los van peerverkeer, zodat een
/// vergeten listener de tupels en vloerbuffers niet eeuwig vasthoudt.
pub(crate) const TCP_BACKLOG_WAIT_DUR: u64 = 30 * SEC;
/// Begrenst dials zonder eigen deadline tegen stille hosts.
pub(crate) const DIAL_TIMEOUT_DEFAULT: u64 = 30 * SEC;

/// Stackidentiteit en het totale verbindingsbufferbudget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Het ene IPv4-adres van deze stack.
    pub ip: [u8; 4],
    /// Subnetprefix voor routering en seedvalidatie.
    pub prefix: u8,
    /// Het MAC-adres van de interface.
    pub mac: [u8; 6],
    /// De gateway; nul betekent geen route buiten het subnet.
    pub gw: [u8; 4],
    /// Bytes voor alle verbindingsbuffers samen.
    pub budget: usize,
    /// Klemt de groei van één verbinding per ring; nul betekent `budget / 4`.
    pub max_buf_per_conn: usize,
    /// De geadverteerde window-scale-shift. Nul is geldig (RFC 7323).
    pub adv_ws: u8,
    /// De link-MTU (nul is 1500). Geldt voor peers op `mtu_net` (nul: het eigen
    /// prefix); elke andere peer ligt achter een gateway en krijgt altijd 1500.
    /// De geadverteerde MSS en de klem op de MSS van de peer volgen de
    /// bestemming, zodat een jumbo-LAN nooit een jumboframe naar een 1500-byte
    /// uplink duwt.
    pub mtu: usize,
    /// Het net waarop `mtu` en `link_trusted` gelden.
    pub mtu_net: [u8; 4],
    /// Prefix van `mtu_net`; nul betekent het eigen subnet.
    pub mtu_prefix: u8,
    /// De link naar `mtu_net` is geheugen, geen draad: frames daar kunnen niet
    /// corrumperen, dus TCP- en UDP-checksums worden voor die peers niet
    /// berekend en niet gecontroleerd. Beide stacks moeten het eens zijn.
    pub link_trusted: bool,
}

/// Een momentopname van de tellers voor logging en telemetrie.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Verbindingen geweigerd omdat het budget op was.
    pub refused_no_budget: usize,
    /// Frames korter dan een Ethernet-header.
    pub drop_short_frame: usize,
    /// Datagrammen zonder gebonden poort of met een volle rij.
    pub drop_no_port: usize,
    /// Misvormde, corrupte of te grote frames.
    pub drop_bad_frame: usize,
    /// Verbindingsloze antwoorden of loopbackframes die bij overloop vielen.
    pub drop_reply_full: usize,
    /// RTO-hertransmissies, opgeteld over de levende verbindingen.
    pub tcp_retransmits: usize,
    /// Fast retransmits (drie duplicate ACKs).
    pub tcp_fast_retransmits: usize,
    /// Verstuurde zero-window-probes.
    pub tcp_persist_probes: usize,
    /// Keren dat een peer een nulvenster adverteerde.
    pub tcp_zero_windows: usize,
    /// Ontvangstringen die groeiden omdat de zender venster-beperkt was.
    pub tcp_rx_grown: usize,
    /// Groei die nodig was maar geweigerd werd (pot, `max_buf_per_conn`,
    /// heap): de verbinding bleef op haar venster hangen.
    pub tcp_rx_grow_refused: usize,
    /// Verstuurde datasegmenten.
    pub tcp_segs_out: usize,
    /// Verstuurde databytes.
    pub tcp_bytes_out: usize,
    /// Ontvangen datasegmenten.
    pub tcp_segs_in: usize,
    /// Ontvangen databytes.
    pub tcp_bytes_in: usize,
    /// Een volledige kopie van de ARP-tellers.
    pub arp: ArpStats,
}

/// Het vier-tupel zonder ons eigen adres (dat is er maar één).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnKey {
    pub(crate) lport: u16,
    pub(crate) rip: [u8; 4],
    pub(crate) rport: u16,
}

/// Een TCP-verbinding, via [`Stack`].
///
/// Een handvat is een plek plus een generatie: een verouderd handvat wijst
/// nooit naar een latere verbinding op dezelfde plek, maar geeft
/// [`Error::Closed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpHandle {
    pub(crate) idx: usize,
    pub(crate) generation: u32,
}

/// Een TCP-listener, via [`Stack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListenHandle {
    pub(crate) idx: usize,
    pub(crate) generation: u32,
}

/// Een UDP-socket, via [`Stack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpHandle {
    pub(crate) idx: usize,
    pub(crate) generation: u32,
}

/// Een lopende dial en de ARP-uitkomst die hem bestuurt.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dial {
    pub(crate) deadline: u64,
    pub(crate) hop: [u8; 4],
    pub(crate) via_arp: bool,
}

/// Een TCP-machine plus stackidentiteit en socketstaat.
#[derive(Debug)]
pub(crate) struct Conn {
    pub(crate) generation: u32,
    pub(crate) key: ConnKey,
    pub(crate) tcp: TcpConn,
    /// Gezet op embryo's en gewist door `accept`.
    pub(crate) listener: Option<ListenHandle>,
    /// Begrenst een gevestigde verbinding zolang ze voor `accept` in de rij
    /// staat en geen applicatie-eigenaar heeft. Absoluut; peerverkeer vernieuwt
    /// hem nooit; `accept` wist hem. Nul is "geen".
    pub(crate) handoff_deadline: u64,
    /// In de demux (de Go-versie: `s.conns[key] == c`).
    pub(crate) live: bool,
    /// De applicatie houdt een handvat vast.
    pub(crate) app_owned: bool,
    pub(crate) dial: Option<Dial>,
    pub(crate) rd_deadline: Option<u64>,
    pub(crate) wr_deadline: Option<u64>,
    pub(crate) read_waker: WakerSlot,
    pub(crate) write_waker: WakerSlot,
}

impl Conn {
    /// Wekt beide kanten.
    pub(crate) fn wake(&mut self) {
        self.read_waker.wake();
        self.write_waker.wake();
    }
}

/// Een listener en zijn backlog.
#[derive(Debug)]
pub(crate) struct Listener {
    pub(crate) generation: u32,
    pub(crate) port: u16,
    pub(crate) backlog: [Option<TcpHandle>; TCP_BACKLOG],
    pub(crate) len: usize,
    pub(crate) waker: WakerSlot,
}

impl Listener {
    /// Haalt de oudste backlogentry.
    pub(crate) fn pop(&mut self) -> Option<TcpHandle> {
        if self.len == 0 {
            return None;
        }
        let h = self.backlog[0].take();
        self.backlog.rotate_left(1);
        self.len -= 1;
        h
    }

    /// Zet een entry achteraan; `false` bij een volle backlog.
    pub(crate) fn push(&mut self, h: TcpHandle) -> bool {
        match self.backlog.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(h);
                self.len += 1;
                true
            }
            None => false,
        }
    }
}

/// Waar een gebouwd frame heen ging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    /// Klaar voor de draad, zoveel bytes.
    Wire(usize),
    /// In de loopbackrij voor onze eigen ingress.
    Looped,
    /// Weggevallen en geteld (geen route, of een interne maatfout).
    Dropped,
}

/// De TCP/IP-stack: één eigenaar van alle protocoltoestand.
///
/// Zie de crate-documentatie voor hoe een eigenaar-taak hem drijft.
#[derive(Debug)]
pub struct Stack {
    pub(crate) cfg: Config,
    /// De link-MTU; zie [`Config::mtu`].
    pub(crate) mtu: usize,
    pub(crate) arp: ArpTable,
    pub(crate) pot: Budget,
    pub(crate) conns: Vec<Option<Conn>>,
    pub(crate) listeners: Vec<Option<Listener>>,
    pub(crate) udp: UdpTable,
    pub(crate) v6: Option<crate::ipv6::State>,
    pub(crate) ndp_closed: crate::NdpStats,
    /// Verbindingsloze antwoorden: `[dst 4][proto 1][IP-payload]`.
    pub(crate) out: RecordQueue,
    /// Draadklare UDP-frames.
    pub(crate) udp_out: RecordQueue,
    /// Frames naar ons eigen MAC, voor onze eigen ingress.
    pub(crate) loopback: RecordQueue,
    /// Gejoinde link-local multicastgroepen; lui gealloceerd.
    pub(crate) groups: Vec<[u8; 4]>,
    /// Een statisch geplande gateway.
    pub(crate) gw_mac: Option<[u8; 6]>,
    pub(crate) closed: bool,
    pub(crate) next_eph: u16,
    pub(crate) iss_seed: u32,
    next_generation: u32,
    /// Een frame-grote kladbuffer voor loopback-ingress en UDP-bouw.
    pub(crate) scratch: Vec<u8>,
    /// Een UDP-schrijver wacht op ruimte in `udp_out`.
    udp_out_waiters: bool,
    pub(crate) stats: Stats,
    driver: WakerSlot,
}

/// Of `a` en `b` in hetzelfde `/prefix` liggen.
pub(crate) fn same_subnet(a: [u8; 4], b: [u8; 4], prefix: u8) -> bool {
    let mask = mask_of(prefix);
    u32::from_be_bytes(a) & mask == u32::from_be_bytes(b) & mask
}

/// Het netmasker van een prefix.
fn mask_of(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p => u32::MAX << (32 - u32::from(p.min(32))),
    }
}

/// Herkent limited en lokale directed broadcast. RFC 3021 kent geen
/// broadcastadres voor /31 en /32.
pub(crate) fn is_broadcast_ip(dst: [u8; 4], ip: [u8; 4], prefix: u8) -> bool {
    if dst == BCAST_IP {
        return true;
    }
    if prefix >= 31 {
        return false;
    }
    let mask = mask_of(prefix);
    let d = u32::from_be_bytes(dst);
    d & mask == u32::from_be_bytes(ip) & mask && d & !mask == !mask
}

impl Stack {
    /// Maakt een stack. `iss_seed` hoort uit een echte entropiebron van de
    /// aanroeper te komen.
    pub fn new(mut cfg: Config, iss_seed: u32) -> Result<Stack> {
        if cfg.prefix > 32 {
            return Err(Error::InvalidPrefix { prefix: cfg.prefix });
        }
        if cfg.mtu_prefix > 32 {
            return Err(Error::InvalidPrefix {
                prefix: cfg.mtu_prefix,
            });
        }
        // RFC 7323 kapt window scaling op 14; meer zou elk venster naar nul schuiven.
        cfg.adv_ws = cfg.adv_ws.min(14);
        if cfg.max_buf_per_conn == 0 {
            cfg.max_buf_per_conn = cfg.budget / 4;
        }
        cfg.max_buf_per_conn = cfg.max_buf_per_conn.max(TCP_FLOOR_RING);
        let mtu = if cfg.mtu == 0 {
            MTU
        } else {
            cfg.mtu.min(usize::from(u16::MAX))
        };
        let frame = mtu + ETHERNET_MAXIMUM_SIZE;
        let span = u32::from(EPHEMERAL_END - EPHEMERAL_BASE) + 1;
        // Een vervangende stack mag niet altijd het eerste tupel hergebruiken:
        // peers houden TIME_WAIT vast over een kernel-FLIP van de node.
        let eph = u16::try_from(iss_seed % span).unwrap_or(0);
        Ok(Stack {
            cfg,
            mtu,
            arp: ArpTable::new(cfg.ip, cfg.mac)?,
            pot: Budget::new(cfg.budget),
            conns: Vec::new(),
            listeners: Vec::new(),
            udp: UdpTable::new(),
            v6: None,
            ndp_closed: crate::NdpStats::default(),
            out: RecordQueue::new(OUT_QUEUE_CAP, OUT_QUEUE_CAP * 256 + 2 * frame),
            udp_out: RecordQueue::new(
                UDP_OUT_FRAMES,
                UDP_OUT_FRAMES * (MTU + ETHERNET_MAXIMUM_SIZE + 2),
            ),
            loopback: RecordQueue::new(LOOPBACK_MAX, LOOPBACK_MAX * (frame + 2)),
            groups: Vec::new(),
            gw_mac: None,
            closed: false,
            next_eph: EPHEMERAL_BASE + eph,
            iss_seed,
            next_generation: 1,
            scratch: alloc_zeroed(frame)?,
            udp_out_waiters: false,
            stats: Stats::default(),
            driver: WakerSlot::default(),
        })
    }

    /// De buffermaat die [`Stack::poll_transmit`] en [`Stack::receive`] minimaal
    /// aankunnen: `mtu + 18`.
    pub fn frame_len(&self) -> usize {
        self.mtu + ETHERNET_MAXIMUM_SIZE
    }

    /// De configuratie na normalisatie.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Een kopie van alle tellers.
    pub fn stats(&self) -> Stats {
        let mut st = self.stats;
        for c in self.conns.iter().flatten().filter(|c| c.live) {
            let n = &c.tcp.cnt;
            st.tcp_retransmits += n.retrans;
            st.tcp_fast_retransmits += n.fast_retrans;
            st.tcp_persist_probes += n.persist;
            st.tcp_zero_windows += n.zero_wnd;
            st.tcp_rx_grown += n.rx_grown;
            st.tcp_rx_grow_refused += n.rx_grow_refused;
            st.tcp_segs_out += n.segs_out;
            st.tcp_bytes_out += n.bytes_out;
            st.tcp_segs_in += n.segs_in;
            st.tcp_bytes_in += n.bytes_in;
        }
        st.arp = self.arp.cnt;
        st
    }

    /// Vrije bytes in de pot.
    pub fn budget_free(&self) -> usize {
        self.pot.free()
    }

    /// Registreert de taak die de stack pompt. Hij wordt gewekt zodra er
    /// nieuw uitgaand werk kan zijn (een write, een close, een ARP-antwoord).
    pub fn register_driver_waker(&mut self, w: &Waker) {
        self.driver.register(w);
    }

    /// Meldt de pomp dat er werk kan zijn.
    pub(crate) fn notify(&mut self) {
        self.driver.wake();
    }

    /// Een nieuwe generatie voor een handvat.
    pub(crate) fn new_generation(&mut self) -> u32 {
        let g = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        g
    }

    /// Sluit de stack: breekt verbindingen af en ruimt ze op, sluit
    /// listeners en geeft UDP-poorten vrij. Elk handvat geeft daarna
    /// [`Error::Closed`]; wachters worden gewekt.
    ///
    /// Tellers blijven leesbaar, maar dynamische protocolopslag (tabellen,
    /// rijen, loopbackbuffers) gaat meteen terug naar de allocator, zodat een
    /// bewaarde gesloten stack zijn hoogwaterstand niet vasthoudt.
    ///
    /// Er gaat niets meer de draad op: de resets van de afgebroken
    /// verbindingen verdwijnen met de rijen en [`Stack::poll_transmit`] geeft
    /// `None`. Een nette afronding is `tcp_close` per verbinding en pompen
    /// tot [`Stack::tcp_unacked`] nul of [`Error::Closed`] geeft.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        for i in 0..self.conns.len() {
            if let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) {
                c.tcp.abort();
            }
            self.reap(i);
            if let Some(c) = self.conns.get_mut(i).and_then(Option::take) {
                let mut c = c;
                c.wake();
            }
        }
        for l in self.listeners.iter_mut().flatten() {
            l.waker.wake();
        }
        for i in 0..self.udp.ports.len() {
            if let Some(mut u) = self.udp.close(i, &mut self.pot) {
                u.read_waker.wake();
                u.write_waker.wake();
            }
        }
        self.ndp_closed = self.ndp_stats();
        if let Some(mut v) = self.v6.take() {
            for i in 0..v.udp.ports.len() {
                if let Some(mut u) = v.udp.close(i, &mut self.pot) {
                    u.read_waker.wake();
                    u.write_waker.wake();
                }
            }
        }
        self.conns = Vec::new();
        self.listeners = Vec::new();
        self.udp = UdpTable::new();
        self.arp.nt.entries = Vec::new();
        self.arp.clear_replies();
        self.groups = Vec::new();
        self.out.release();
        self.udp_out.release();
        self.loopback.release();
        self.scratch = Vec::new();
        self.driver.wake();
    }

    /// Of de stack gesloten is.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Installeert een statische buur. Seeds buiten het subnet (behalve de
    /// gateway) worden geweigerd, want de routering zou ze nooit raadplegen.
    pub fn seed_neighbor(&mut self, ip: [u8; 4], mac: [u8; 6], now: u64) -> Result {
        if self.closed {
            return Err(Error::StackClosed);
        }
        if ip == self.cfg.gw {
            self.gw_mac = Some(mac);
            // Een statische gateway maakt een lopende query overbodig; wek zijn
            // wachters, want de timer van die query bestaat niet meer.
            self.arp.nt.remove(ip);
            self.wake_route_waiters();
            return Ok(());
        }
        if !same_subnet(ip, self.cfg.ip, self.cfg.prefix) {
            return Err(Error::SeedOffSubnet { ip });
        }
        // Statische entries ontlopen verloop en verdringing, dus ze krijgen
        // hoogstens de halve tabel. Een bestaande static bijwerken kost geen plek.
        let existing = self.arp.nt.get(ip);
        if !existing.is_some_and(|e| e.is_static) {
            let statics = self
                .arp
                .nt
                .entries
                .iter()
                .filter(|(_, e)| e.is_static)
                .count();
            if statics >= ARP_CACHE_CAP / 2 {
                return Err(Error::SeedCap {
                    cap: ARP_CACHE_CAP / 2,
                });
            }
        }
        // Seeds gehoorzamen ook het totaalplafond; een bestaand adres groeit niet.
        if existing.is_none() && !self.arp.nt.make_room(now) {
            return Err(Error::NeighborTableFull { ip });
        }
        if self.arp.seed(ip, mac)? {
            // Wek wachters wier query en timer de seed verving.
            self.wake_route_waiters();
        }
        Ok(())
    }

    /// Wekt iedereen die op een route wacht: lopende dials en UDP-schrijvers.
    pub(crate) fn wake_route_waiters(&mut self) {
        for c in self.conns.iter_mut().flatten() {
            if c.dial.is_some() {
                c.write_waker.wake();
            }
        }
        for u in self.udp.ports.iter_mut().flatten() {
            u.write_waker.wake();
        }
        self.notify();
    }

    // ---- de tabel voor wie doorstuurt ----

    /// De MAC van de next-hop naar `dst`, uit dezelfde tabel als de eigen
    /// verbindingen, voor een eigenaar die frames doorstuurt (Linux heeft één
    /// neighbour-tabel, ook voor forwarding): de gateway buiten het subnet,
    /// anders `dst` zelf. Onbekend is `None` en start één ontdubbelde vraag,
    /// die [`Stack::poll_transmit`] verstuurt.
    pub fn neighbor(&mut self, dst: [u8; 4], now: u64) -> Option<[u8; 6]> {
        if self.closed {
            return None;
        }
        let mac = self.route(dst, now, true);
        if mac.is_none() {
            self.notify();
        }
        mac
    }

    /// Twijfel aan de bekende next-hop van `dst`: één broadcast-vraag,
    /// hoogstens één per seconde, en de MAC blijft gelden tot het antwoord
    /// hem ververst (Linux: `NUD_PROBE`). Een buur of gateway die stil van
    /// MAC wisselde, is zo terug op het eerste antwoord in plaats van pas na
    /// het verloop.
    pub fn probe_neighbor(&mut self, dst: [u8; 4], now: u64) {
        let (hop, via_arp) = self.next_hop(dst);
        if self.closed || !via_arp || hop == [0; 4] {
            return;
        }
        self.arp.nt.probe(hop, now);
        self.notify();
    }

    /// Een hint uit doorgestuurd verkeer (Linux: `neigh_confirm`): een
    /// unicast-IPv4-frame aan ons van `src` met bron-MAC `mac` hoorde bij
    /// een flow van de eigenaar. On-link telt het als eigen verkeer (scheppen
    /// of verversen, nooit een MAC wisselen); van buiten het subnet kwam het
    /// door de gateway en ververst het alleen die, met zijn bekende MAC. Zo
    /// blijft de next-hop van een levende flow vers, en zet een buurman met
    /// een vreemd bronadres nooit de gateway.
    pub fn confirm_neighbor(&mut self, src: [u8; 4], mac: [u8; 6], now: u64) {
        if self.closed {
            return;
        }
        if same_subnet(src, self.cfg.ip, self.cfg.prefix) {
            self.learn(src, mac, now);
        } else if self.arp.peek(self.cfg.gw, now) == Some(mac) {
            self.arp.learn(self.cfg.gw, mac, now);
        }
    }

    // ---- ingress ----

    /// Verwerkt één onvertrouwd Ethernet-frame. Korte, verkeerd geadresseerde
    /// of corrupte invoer wordt geteld en valt weg, zonder panic.
    pub fn receive(&mut self, frame: &[u8], now: u64) -> Result {
        if self.closed {
            return Err(Error::StackClosed);
        }
        let Ok(eth) = wire::parse_eth(frame) else {
            self.stats.drop_short_frame += 1;
            return Ok(());
        };
        if frame.len() > self.frame_len() {
            // Weiger jumboframes voordat een antwoord de zendbuffer overloopt.
            self.stats.drop_bad_frame += 1;
            return Ok(());
        }
        self.ingress(&eth, now);
        Ok(())
    }

    /// Losgemaakt zodat de pomp loopback door dezelfde demux voert.
    fn ingress(&mut self, eth: &wire::Eth<'_>, now: u64) {
        let to_us = eth.dst() == self.cfg.mac;
        match eth.ether_type() {
            ETHERTYPE_ARP => {
                let Ok(f) = wire::parse_arp(eth.payload()) else {
                    self.stats.drop_bad_frame += 1;
                    return;
                };
                if self.arp.recv(&f, now) {
                    self.wake_route_waiters();
                }
                self.notify(); // Een antwoord kan nu klaarstaan.
            }
            ETHERTYPE_IPV4 => {
                if !to_us {
                    // Gejoinde multicast is de enige uitzondering op "aan ons".
                    // Alleen UDP: RFC 1122 §3.2.2.6 ontraadt echo-antwoorden op
                    // multicast en TCP betekent daar niets. De rest is gewone
                    // LAN-ruis en verdwijnt stil; tellen zou de tellers die
                    // ertoe doen verdrinken.
                    if !is_multicast_mac(eth.dst()) {
                        return;
                    }
                    let Ok(ip) = wire::parse_ipv4(eth.payload()) else {
                        return;
                    };
                    if !ip.checksum_ok() || !self.joined(ip.dst()) || ip.proto() != PROTO_UDP {
                        return;
                    }
                    self.recv_ipv4(&ip, eth.src(), now);
                    return;
                }
                match wire::parse_ipv4(eth.payload()) {
                    Ok(ip) if ip.checksum_ok() && ip.dst() == self.cfg.ip => {
                        // Passief leren gebeurt na de transportchecksum, zodat
                        // een vervalste IP-header alleen geen cacheplek wint.
                        self.recv_ipv4(&ip, eth.src(), now);
                    }
                    _ => self.stats.drop_bad_frame += 1,
                }
            }
            wire::ETHERTYPE_IPV6 => {
                if let Some(v) = &mut self.v6 {
                    match crate::wire6::parse(eth.payload()) {
                        Ok(p)
                            if (p.dst[0] != 255 && eth.dst() == self.cfg.mac)
                                || (p.dst[0] == 255
                                    && eth.dst() == crate::wire6::multicast_mac(p.dst)) =>
                        {
                            if !v.receive(&p, eth.src(), now) {
                                self.stats.drop_bad_frame += 1;
                            }
                            self.notify();
                        }
                        _ => self.stats.drop_bad_frame += 1,
                    }
                }
            }
            // Niet-ondersteunde EtherTypes blijven stille LAN-ruis.
            _ => {}
        }
    }

    /// Leert de bron passief, na transportvalidatie.
    fn learn(&mut self, src: [u8; 4], src_mac: [u8; 6], now: u64) {
        // De checksum is geen authenticatie; het plafond van `learn` blijft de
        // veiligheidsgrens.
        if same_subnet(src, self.cfg.ip, self.cfg.prefix) && self.arp.learn(src, src_mac, now) {
            // Wek routewachters nu, want latere verwerking kan vroeg terugkeren
            // en het oplossen van de query haalde zijn timer weg.
            self.wake_route_waiters();
        }
    }

    /// Verdeelt een gevalideerd IPv4-pakket over de transporten.
    fn recv_ipv4(&mut self, ip: &wire::Ipv4<'_>, src_mac: [u8; 6], now: u64) {
        let src = ip.src();
        // Een multicast-bronadres is nooit geldig (RFC 1112 §7.2): weg, vóór
        // elk transportwerk en elk antwoord.
        if is_multicast_ip(src) {
            self.stats.drop_bad_frame += 1;
            return;
        }
        match ip.proto() {
            PROTO_TCP => {
                let f = match wire::parse_tcp(ip.payload()) {
                    Ok(f) if self.trusted(src) || f.checksum_ok(src, self.cfg.ip) => f,
                    _ => {
                        self.stats.drop_bad_frame += 1;
                        return;
                    }
                };
                self.learn(src, src_mac, now);
                self.recv_tcp(&f, src, now);
            }
            PROTO_UDP => {
                // De pseudo-header draagt de eigen bestemming van het frame:
                // ons unicastadres (door ingress gegarandeerd) of een gejoinde groep.
                let f = match wire::parse_udp(ip.payload()) {
                    Ok(f) if self.trusted(src) || f.checksum_ok(src, ip.dst()) => f,
                    _ => {
                        self.stats.drop_bad_frame += 1;
                        return;
                    }
                };
                self.learn(src, src_mac, now);
                // Verbonden UDP deelt de poorttabel; `deliver` past het filter toe.
                match self
                    .udp
                    .deliver(f.dst_port(), src, f.src_port(), f.payload())
                {
                    Some(i) => {
                        if let Some(u) = self.udp.get_mut(i) {
                            u.read_waker.wake();
                        }
                    }
                    None => self.stats.drop_no_port += 1,
                }
            }
            PROTO_ICMP => {
                // Bouw een echo-antwoord voor de pomp.
                if self.out.len() >= OUT_QUEUE_CAP {
                    self.stats.drop_reply_full += 1;
                    return;
                }
                let req = ip.payload();
                let mut scratch = core::mem::take(&mut self.scratch);
                if let Some(n) = scratch
                    .get_mut(..req.len())
                    .and_then(|b| icmp::icmp_echo(req, b))
                {
                    self.learn(src, src_mac, now); // `icmp_echo` controleerde de checksum.
                    self.queue_out(src, PROTO_ICMP, scratch.get(..n).unwrap_or(&[]));
                    self.notify();
                }
                self.scratch = scratch;
            }
            _ => {}
        }
    }

    /// Zoekt de levende verbinding voor `key`.
    pub(crate) fn find_conn(&self, key: ConnKey) -> Option<usize> {
        self.conns
            .iter()
            .position(|c| matches!(c, Some(c) if c.live && c.key == key))
    }

    /// De verbinding op plek `i`.
    pub(crate) fn conn_mut(&mut self, i: usize) -> Option<&mut Conn> {
        self.conns.get_mut(i).and_then(Option::as_mut)
    }

    /// De verbinding op plek `i`.
    pub(crate) fn conn(&self, i: usize) -> Option<&Conn> {
        self.conns.get(i).and_then(Option::as_ref)
    }

    /// Verwerkt een TCP-segment: een bestaande verbinding, een SYN naar een
    /// listener, of een reset.
    fn recv_tcp(&mut self, f: &wire::Tcp<'_>, src: [u8; 4], now: u64) {
        let Some(seg) = parse_tcp_seg(f) else {
            self.stats.drop_bad_frame += 1;
            return;
        };
        let data = f.payload();
        let key = ConnKey {
            lport: f.dst_port(),
            rip: src,
            rport: f.src_port(),
        };
        if let Some(i) = self.find_conn(key) {
            if let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) {
                c.tcp.recv(&seg, data, now, &mut self.pot);
                c.wake();
            }
            self.maybe_accept(i, now);
            self.reap(i);
            self.notify();
            return;
        }
        // Zonder verbinding opent een SYN naar een listener een embryo. Al het
        // andere behalve een RST krijgt een RFC 9293 §3.10.7.1-reset, zodat een
        // dial naar een gesloten poort snel faalt. Een SYN|RST wordt geweigerd
        // vóór er een embryo is dat de machine zou negeren: 20 KiB zonder
        // timer of reaper.
        let listener = self.find_listener(f.dst_port());
        let is_open = seg.flags.has(TcpFlags::SYN)
            && !seg.flags.has(TcpFlags::ACK)
            && !seg.flags.has(TcpFlags::RST);
        let Some(lh) = listener.filter(|_| is_open) else {
            if !seg.flags.has(TcpFlags::RST) {
                if seg.flags.has(TcpFlags::ACK) {
                    // <SEQ=SEG.ACK><CTL=RST> zonder ACK-vlag: strikte
                    // SYN-SENT-peers gooien RST|ACK met ack=0 weg.
                    self.queue_rst(src, key.lport, key.rport, seg.ack, 0, false);
                } else {
                    // ACK dekt SEG.LEN; SYN en FIN nemen elk één volgnummer.
                    let mut seg_len = u32::try_from(data.len()).unwrap_or(0);
                    if seg.flags.has(TcpFlags::SYN) {
                        seg_len = seg_len.wrapping_add(1);
                    }
                    if seg.flags.has(TcpFlags::FIN) {
                        seg_len = seg_len.wrapping_add(1);
                    }
                    self.queue_rst(
                        src,
                        key.lport,
                        key.rport,
                        0,
                        seg.seq.wrapping_add(seg_len),
                        true,
                    );
                }
                self.notify();
            }
            return;
        };
        let i = match self.new_conn(key) {
            Ok(i) => i,
            Err(_) => {
                // Weiger meteen met een RST als het budget op is.
                self.stats.refused_no_budget += 1;
                self.queue_rst(src, key.lport, key.rport, 0, seg.seq.wrapping_add(1), true);
                self.notify();
                return;
            }
        };
        let iss = self.next_iss();
        let adv_mss = self.adv_mss(src);
        let adv_ws = self.cfg.adv_ws;
        if let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) {
            c.tcp.open_passive(iss, adv_mss, adv_ws);
            c.tcp.recv(&seg, data, now, &mut self.pot);
            // `emit` stuurt een wachtende reset eerst; reap bewaart hem als de
            // verbinding sterft.
            c.listener = Some(lh);
        }
        self.notify();
    }

    /// De geadverteerde MSS naar `dst`: de link-MTU min IP- en TCP-header.
    pub(crate) fn adv_mss(&self, dst: [u8; 4]) -> u16 {
        u16::try_from(self.link_mtu(dst).saturating_sub(SIZE_IPV4 + SIZE_TCP)).unwrap_or(u16::MAX)
    }

    /// De listener op `port`.
    fn find_listener(&self, port: u16) -> Option<ListenHandle> {
        self.listeners
            .iter()
            .enumerate()
            .find_map(|(idx, l)| match l {
                Some(l) if l.port == port => Some(ListenHandle {
                    idx,
                    generation: l.generation,
                }),
                _ => None,
            })
    }

    /// De listener achter `h`, als het handvat nog geldt.
    pub(crate) fn listener_mut(&mut self, h: ListenHandle) -> Option<&mut Listener> {
        self.listeners
            .get_mut(h.idx)
            .and_then(Option::as_mut)
            .filter(|l| l.generation == h.generation)
    }

    /// Biedt een vers gevestigd embryo aan zijn listener aan. De handshake is
    /// af bij ontvangst en hoeft geen uitgaand segment te maken.
    pub(crate) fn maybe_accept(&mut self, i: usize, now: u64) {
        let Some(c) = self.conn_mut(i) else {
            return;
        };
        // CLOSE-WAIT telt mee, want de finale handshake-ACK kan ook data en
        // FIN dragen en zo in één ontvangst door ESTABLISHED heen gaan.
        let Some(lh) = c.listener else {
            return;
        };
        if c.handoff_deadline != 0
            || !matches!(c.tcp.state, TcpState::Established | TcpState::CloseWait)
        {
            return;
        }
        c.handoff_deadline = now + TCP_BACKLOG_WAIT_DUR;
        let h = TcpHandle {
            idx: i,
            generation: c.generation,
        };
        self.offer(lh, h);
    }

    /// Geeft een voltooide handshake aan `accept`. Backlogoverloop breekt hem af.
    pub(crate) fn offer(&mut self, lh: ListenHandle, h: TcpHandle) {
        // Weiger handshakes die na de close van de listener afronden, zodat
        // ze geen budget in een ongelezen backlog houden.
        if self.listener_mut(lh).is_none() {
            self.abort_and_reap(h.idx);
            return;
        }
        self.prune_stale(lh);
        let pushed = self.listener_mut(lh).is_some_and(|l| {
            let ok = l.push(h);
            if ok {
                l.waker.wake();
            }
            ok
        });
        if !pushed {
            self.abort_and_reap(h.idx);
        }
    }

    /// Of `h` een levende verbinding in de demux is.
    pub(crate) fn is_live(&self, h: TcpHandle) -> bool {
        self.conn(h.idx)
            .is_some_and(|c| c.generation == h.generation && c.live)
    }

    /// Haalt verouderde backlogentries fysiek weg vóór het plafond geldt.
    /// Reap haalt een verbinding meteen uit de demux, maar een backlogentry
    /// hield anders zijn plek tot een `accept`; dan kon een verder lege
    /// listener gezonde handshakes voorgoed weigeren.
    pub(crate) fn prune_stale(&mut self, lh: ListenHandle) {
        let Some(l) = self.listeners.get(lh.idx).and_then(Option::as_ref) else {
            return;
        };
        let mut keep: [Option<TcpHandle>; TCP_BACKLOG] = [None; TCP_BACKLOG];
        let mut n = 0;
        for h in l.backlog.iter().take(l.len).flatten() {
            if self.is_live(*h)
                && let Some(slot) = keep.get_mut(n)
            {
                *slot = Some(*h);
                n += 1;
            }
        }
        if let Some(l) = self.listener_mut(lh) {
            l.backlog = keep;
            l.len = n;
        }
    }

    /// Breekt verbinding `i` af en ruimt haar op.
    pub(crate) fn abort_and_reap(&mut self, i: usize) {
        if let Some(c) = self.conn_mut(i) {
            c.tcp.abort();
        }
        self.reap(i);
    }

    /// Haalt een gesloten verbinding uit de demux en geeft haar buffers terug.
    ///
    /// Een wachtende RST gaat eerst naar de verbindingsloze rij, anders kan
    /// afbreken-en-opruimen hem wissen voordat de pomp hem zag. Houdt de
    /// applicatie geen handvat meer vast, dan komt de plek vrij.
    pub(crate) fn reap(&mut self, i: usize) {
        let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) else {
            return;
        };
        if c.tcp.state != TcpState::Closed || !c.live {
            return;
        }
        let rst = core::mem::take(&mut c.tcp.rst);
        let key = c.key;
        c.live = false;
        if c.tcp.budgeted {
            self.pot.release(c.tcp.rx.size() + c.tcp.tx.size());
        }
        // Ontkoppel de boekhouding zodat latere reads dezelfde capaciteit niet
        // twee keer teruggeven, en laat de echte buffers los.
        c.tcp.budgeted = false;
        c.tcp.rx = Ring::default();
        c.tcp.tx = TxRing::default();
        // Wek geblokkeerde operaties als een timer, niet ingress, de
        // verbinding doodde.
        c.wake();
        let free = !c.app_owned;
        if free && let Some(slot) = self.conns.get_mut(i) {
            *slot = None;
        }
        if rst.set {
            self.queue_rst(
                key.rip,
                key.lport,
                key.rport,
                rst.seq,
                rst.ack,
                rst.with_ack,
            );
        }
        self.notify();
    }

    /// Reserveert en maakt een verbinding op de vloermaten.
    pub(crate) fn new_conn(&mut self, key: ConnKey) -> Result<usize> {
        if !self.pot.reserve(TCP_FLOOR_RING) {
            return Err(Error::NoBudget {
                need: TCP_FLOOR_RING,
                free: self.pot.free(),
            });
        }
        let mut tcp = match TcpConn::with_rings(TCP_FLOOR_RX, TCP_FLOOR_TX) {
            Ok(t) => t,
            Err(e) => {
                self.pot.release(TCP_FLOOR_RING);
                return Err(e);
            }
        };
        tcp.budgeted = true;
        tcp.max_buf = self.cfg.max_buf_per_conn;
        tcp.congestion = !self.trusted(key.rip);
        let c = Conn {
            generation: self.new_generation(),
            key,
            tcp,
            listener: None,
            handoff_deadline: 0,
            live: true,
            app_owned: false,
            dial: None,
            rd_deadline: None,
            wr_deadline: None,
            read_waker: WakerSlot::default(),
            write_waker: WakerSlot::default(),
        };
        if let Some(i) = self.conns.iter().position(Option::is_none) {
            if let Some(slot) = self.conns.get_mut(i) {
                *slot = Some(c);
            }
            return Ok(i);
        }
        if let Err(e) = crate::try_push(&mut self.conns, Some(c)) {
            self.pot.release(TCP_FLOOR_RING);
            return Err(e);
        }
        Ok(self.conns.len() - 1)
    }

    /// Schuift per verbinding op, zodat snel poorthergebruik niet op oude
    /// segmenten past. De priemstap loopt de hele ruimte door.
    pub(crate) fn next_iss(&mut self) -> u32 {
        self.iss_seed = self.iss_seed.wrapping_add(64007);
        self.iss_seed
    }

    /// Kiest de volgende vrije dynamische poort. `in_use` levert de
    /// naamruimte, want TCP- en UDP-poorten zijn onafhankelijk.
    pub(crate) fn ephemeral_port(&mut self, in_use: impl Fn(&Stack, u16) -> bool) -> Result<u16> {
        for _ in 0..=u32::from(EPHEMERAL_END - EPHEMERAL_BASE) {
            let p = self.next_eph;
            self.next_eph = if p == EPHEMERAL_END {
                EPHEMERAL_BASE
            } else {
                p + 1
            };
            if !in_use(self, p) {
                return Ok(p);
            }
        }
        Err(Error::PortsInUse)
    }

    /// Of een TCP-poort bezet is door een listener of verbinding (ook TIME-WAIT).
    pub(crate) fn tcp_port_in_use(&self, p: u16) -> bool {
        self.find_listener(p).is_some()
            || self
                .conns
                .iter()
                .flatten()
                .any(|c| c.live && c.key.lport == p)
    }

    // ---- zendpomp ----

    /// Schrijft het volgende klare frame in `frame` en geeft zijn lengte, of
    /// `None` als er niets te versturen is. Roep aan tot `None`, stuur elk
    /// frame naar het device, en slaap dan tot [`Stack::next_timeout`] of een
    /// wek van de driver-waker.
    ///
    /// `frame` hoort [`Stack::frame_len`] bytes te hebben; korter werkt, maar
    /// wat niet past valt weg en wordt geteld.
    pub fn poll_transmit(&mut self, now: u64, frame: &mut [u8]) -> Option<usize> {
        if self.closed {
            return None;
        }
        self.maintain(now);
        // Loopback kan een direct antwoord maken; begrens de rondes zodat één
        // aanroep nooit eindeloos draait.
        for _ in 0..4 * LOOPBACK_MAX {
            if let Some(n) = self.next_wire_frame(now, frame) {
                return Some(n);
            }
            if !self.feed_loopback(now) {
                return None;
            }
        }
        self.notify();
        None
    }

    /// Voert één loopbackframe door de ingress; `false` als de rij leeg was.
    fn feed_loopback(&mut self, now: u64) -> bool {
        let mut buf = core::mem::take(&mut self.scratch);
        let got = self.loopback.pop(&mut buf);
        if let Some(n) = got
            && let Ok(eth) = wire::parse_eth(buf.get(..n).unwrap_or(&[]))
        {
            self.ingress(&eth, now);
        }
        self.scratch = buf;
        got.is_some()
    }

    /// Het volgende frame voor de draad, in de volgorde van de Go-pomp:
    /// verbindingsloze antwoorden, UDP, ARP, dan TCP.
    fn next_wire_frame(&mut self, now: u64, frame: &mut [u8]) -> Option<usize> {
        while let Some(sent) = self.drain_out(now, frame) {
            if let Sent::Wire(n) = sent {
                return Some(n);
            }
        }
        if let Some(n) = self.udp_out.pop(frame) {
            if self.udp_out_waiters {
                self.udp_out_waiters = false;
                if let Some(v) = &mut self.v6 {
                    for u in v.udp.ports.iter_mut().flatten() {
                        u.write_waker.wake();
                    }
                }
                for u in self.udp.ports.iter_mut().flatten() {
                    u.write_waker.wake();
                }
            }
            return Some(n);
        }
        if let Some(n) = self.drain_arp(now, frame) {
            return Some(n);
        }
        if let Some(v) = &mut self.v6
            && let Some(n) = v.emit(now, frame)
        {
            return Some(n);
        }
        self.drain_tcp(now, frame)
    }

    /// Eén verbindingsloos antwoord. `None` als de rij leeg is.
    fn drain_out(&mut self, now: u64, frame: &mut [u8]) -> Option<Sent> {
        let mut rec = core::mem::take(&mut self.scratch);
        let got = self.out.pop(&mut rec);
        let sent = got.map(|n| {
            let r = rec.get(..n).unwrap_or(&[]);
            let (dst, rest) = r.split_at(r.len().min(4));
            let (proto, payload) = rest.split_at(rest.len().min(1));
            let dst: [u8; 4] = dst.try_into().unwrap_or([0; 4]);
            let proto = proto.first().copied().unwrap_or(0);
            // Routeer naar beste vermogen zonder ARP te starten. Legitieme
            // bronnen zijn net geleerd; gespoofde bronnen bevragen zou echte
            // cache-entries verdringen.
            match self.route(dst, now, false) {
                Some(mac) => self.send_ipv4(frame, mac, dst, proto, payload),
                None => Sent::Dropped, // Geen route: weg, naar beste vermogen.
            }
        });
        self.scratch = rec;
        sent
    }

    /// Eén ARP-antwoord of -vraag.
    fn drain_arp(&mut self, now: u64, frame: &mut [u8]) -> Option<usize> {
        let before = self.arp.cnt.gave_up;
        let out = self
            .arp
            .emit(frame.get_mut(SIZE_ETH..).unwrap_or(&mut []), now);
        if self.arp.cnt.gave_up != before {
            // Een query gaf op: wek routewachters, hun timer is weg.
            self.wake_route_waiters();
            self.wake_all_conns();
        }
        let (n, kind) = out?;
        let dst = match kind {
            ArpOut::Reply(hw) => hw,
            ArpOut::Request => BCAST_MAC,
        };
        match self.send_eth(frame, dst, ETHERTYPE_ARP, n) {
            Ok(Sent::Wire(len)) => Some(len),
            _ => self.drain_arp(now, frame),
        }
    }

    /// Wekt de wachters van elke verbinding (een route viel weg).
    fn wake_all_conns(&mut self) {
        for c in self.conns.iter_mut().flatten() {
            c.wake();
        }
    }

    /// Het volgende TCP-segment van een verbinding met een route. `emit` is
    /// lui: een ontbrekende MAC kost geen volgnummertoestand zolang ARP loopt.
    fn drain_tcp(&mut self, now: u64, frame: &mut [u8]) -> Option<usize> {
        let payload_at = SIZE_ETH + SIZE_IPV4 + SIZE_TCP;
        for i in 0..self.conns.len() {
            loop {
                let Some(c) = self.conn(i).filter(|c| c.live) else {
                    break;
                };
                let key = c.key;
                let Some(mac) = self.route(key.rip, now, true) else {
                    break;
                };
                let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) else {
                    break;
                };
                let seg = c
                    .tcp
                    .emit(frame.get_mut(payload_at..).unwrap_or(&mut []), now);
                let Some(seg) = seg else {
                    self.reap(i);
                    break;
                };
                if let Sent::Wire(n) = self.send_tcp(frame, mac, key, &seg) {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Onderhoud vóór het zenden: socketdeadlines wekken, eigenaarloze en
    /// verlopen verbindingen opruimen, en verbindingen zonder route afbreken.
    fn maintain(&mut self, now: u64) {
        if let Some(v) = &mut self.v6 {
            v.tick(now);
        }
        for c in self.conns.iter_mut().flatten() {
            if c.rd_deadline.is_some_and(|d| now >= d) {
                c.read_waker.wake();
            }
            let dial_due = c.dial.is_some_and(|d| now >= d.deadline);
            if dial_due || c.wr_deadline.is_some_and(|d| now >= d) {
                c.write_waker.wake();
            }
        }
        for u in self.udp.ports.iter_mut().flatten() {
            if u.rd_deadline.is_some_and(|d| now >= d) {
                u.read_waker.wake();
            }
            if u.wr_deadline.is_some_and(|d| now >= d) {
                u.write_waker.wake();
            }
        }
        for i in 0..self.conns.len() {
            let Some(c) = self.conn(i).filter(|c| c.live) else {
                continue;
            };
            // Eigendomsgrenzen hangen niet van bereikbaarheid af. Eerst
            // opruimen; de RST blijft naar beste vermogen als de route weg is.
            let expired = (c.handoff_deadline != 0 && now >= c.handoff_deadline)
                || c.tcp.lifecycle_expired(now);
            if c.tcp.state == TcpState::Closed || expired {
                self.abort_and_reap(i);
                continue;
            }
            let rip = c.key.rip;
            if self.route(rip, now, true).is_some() {
                continue;
            }
            // Breek af zodra ARP opgaf of er geen gateway is. Anders wapent
            // `emit` nooit hertransmissie en houdt de verbinding haar budget
            // voorgoed. Statische gatewayroutes komen hier nooit.
            let (hop, via_arp) = self.next_hop(rip);
            if via_arp && (hop == [0; 4] || self.arp.no_answer(hop, now)) {
                self.abort_and_reap(i); // Reads en writes falen nu expliciet.
            }
        }
    }

    /// De vroegste deadline waarop de pomp weer moet draaien, of `None` als er
    /// niets te wachten valt. Een verstreken deadline komt terug als
    /// `now + 200 ms`: een ontbrekende route kan er een laten hangen, en een
    /// herhaling na 10 ms gaf 100 lege wekken per seconde.
    pub fn next_timeout(&mut self, now: u64) -> Option<u64> {
        if self.closed {
            return None;
        }
        if !self.out.is_empty() || !self.udp_out.is_empty() || !self.loopback.is_empty() {
            return Some(now);
        }
        let mut d: Option<u64> = None;
        let mut add = |t: Option<u64>| {
            let Some(t) = t.filter(|t| *t != 0) else {
                return;
            };
            let t = if t <= now { now + TCP_RTO_MIN } else { t };
            if d.is_none_or(|cur| t < cur) {
                d = Some(t);
            }
        };
        for c in self.conns.iter().flatten() {
            if c.live {
                add(c.tcp.next_deadline());
                add(Some(c.handoff_deadline));
            }
            add(c
                .dial
                .map(|d| d.deadline)
                .filter(|_| c.write_waker.is_set()));
            add(c.rd_deadline.filter(|_| c.read_waker.is_set()));
            add(c.wr_deadline.filter(|_| c.write_waker.is_set()));
        }
        for u in self.udp.ports.iter().flatten() {
            add(u.rd_deadline.filter(|_| u.read_waker.is_set()));
            add(u.wr_deadline.filter(|_| u.write_waker.is_set()));
        }
        add(self.arp.nt.next_deadline());
        if let Some(v) = &self.v6
            && let Some(t) = v.deadline()
        {
            if t <= now {
                return Some(now);
            }
            add(Some(t));
        }
        d
    }

    /// Het adres wiens ARP-toestand `dst` bestuurt. `via_arp == false` is een
    /// statische gatewayroute die geen ARP-falen mag blokkeren. Dial, UDP en
    /// de pomp delen deze beslissing.
    pub(crate) fn next_hop(&self, dst: [u8; 4]) -> ([u8; 4], bool) {
        if is_link_local_multicast(dst) {
            return (dst, false); // Link-local: nooit de gateway, nooit ARP.
        }
        let on_link = same_subnet(dst, self.cfg.ip, self.cfg.prefix);
        if self.gw_mac.is_some() && (dst == self.cfg.gw || !on_link) {
            return (dst, false); // Het statische plan heeft geen ARP-uitkomst.
        }
        if !on_link {
            return (self.cfg.gw, true); // Nul betekent: geen route geconfigureerd.
        }
        (dst, true)
    }

    /// Lost de next-hop-MAC op, direct of via de gateway. `query == false`
    /// kijkt alleen, voor antwoorden naar beste vermogen.
    pub(crate) fn route(&mut self, dst: [u8; 4], now: u64, query: bool) -> Option<[u8; 6]> {
        // Ons eigen adres gaat naar loopback. Voor onszelf ARP'en kan niet
        // slagen: een switch spiegelt de broadcast niet naar de bron.
        if dst == self.cfg.ip {
            return Some(self.cfg.mac);
        }
        // Link-local multicast gaat direct naar zijn Ethernet-adres (RFC 1112
        // §6.4): geen resolutie en nooit de gateway.
        if is_link_local_multicast(dst) {
            return Some(multicast_mac(dst));
        }
        // Limited en directed broadcast gaan naar het broadcast-MAC; DHCP-rebind
        // heeft dat nodig (RFC 2131 §4.4.5); antwoorden komen unicast.
        if is_broadcast_ip(dst, self.cfg.ip, self.cfg.prefix) {
            return Some(BCAST_MAC);
        }
        // Een geseede gateway dekt ook verkeer naar de gateway zelf.
        if let Some(gw) = self.gw_mac
            && (dst == self.cfg.gw || !same_subnet(dst, self.cfg.ip, self.cfg.prefix))
        {
            return Some(gw);
        }
        let mut target = dst;
        let mut query = query;
        if !same_subnet(dst, self.cfg.ip, self.cfg.prefix) {
            if self.cfg.gw == [0; 4] {
                return None;
            }
            target = self.cfg.gw;
            // Ook antwoorden naar beste vermogen mogen de gateway oplossen: dat
            // schept alleen die ene vertrouwde entry en maakt off-subnet
            // weigeringsresets mogelijk.
            query = true;
        }
        if query {
            self.arp.resolve(target, now)
        } else {
            self.arp.peek(target, now)
        }
    }

    // ---- draadschrijvers ----

    /// Zet een begrensd verbindingsloos pakket in de rij en telt overloop.
    pub(crate) fn queue_out(&mut self, dst: [u8; 4], proto: u8, pkt: &[u8]) {
        if !self.out.push(&[&dst, &[proto], pkt]) {
            self.stats.drop_reply_full += 1;
        }
    }

    /// Serialiseert en rijt een reset. `with_ack` kiest RST|ACK of RFC 9293
    /// §3.10.7.1's kale `<SEQ=SEG.ACK><RST>`.
    pub(crate) fn queue_rst(
        &mut self,
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        with_ack: bool,
    ) {
        let mut flags = TcpFlags::RST;
        if with_ack {
            flags |= TcpFlags::ACK;
        }
        let mut buf = [0u8; SIZE_TCP];
        let h = TcpHeader {
            src_port: sport,
            dst_port: dport,
            seq,
            ack,
            flags,
            wnd: 0,
            opts: &[],
        };
        if let Ok(n) = wire::put_tcp_sum(&mut buf, &h, self.cfg.ip, dst, 0, !self.trusted(dst)) {
            self.queue_out(dst, PROTO_TCP, buf.get(..n).unwrap_or(&[]));
        }
    }

    /// Zet de Ethernet-header, vult aan tot 60 bytes en beslist: draad,
    /// loopback of beide (multicast naar een gejoinde groep).
    pub(crate) fn send_eth(
        &mut self,
        frame: &mut [u8],
        dst: [u8; 6],
        ether_type: u16,
        payload_len: usize,
    ) -> Result<Sent> {
        wire::put_eth(frame, dst, self.cfg.mac, ether_type)?;
        let mut n = SIZE_ETH + payload_len;
        if n > frame.len() {
            self.stats.drop_bad_frame += 1;
            return Err(Error::ShortFrame {
                len: frame.len(),
                need: n,
            });
        }
        if n < MIN_FRAME && frame.len() >= MIN_FRAME {
            // Nullen tot de minimale framelengte, zodat oude data niet lekt.
            if let Some(pad) = frame.get_mut(n..MIN_FRAME) {
                pad.fill(0);
            }
            n = MIN_FRAME;
        }
        let bytes = frame.get(..n).unwrap_or(&[]);
        // Een gejoinde groep hoort zijn eigen zendingen (IP_MULTICAST_LOOP):
        // kopie naar loopback én naar de draad. mDNS-responders rekenen erop
        // hun eigen vragen te horen. Overloop verliest alleen de lokale kopie.
        if is_multicast_mac(dst) && ether_type == ETHERTYPE_IPV4 {
            let joined = wire::parse_ipv4(bytes.get(SIZE_ETH..).unwrap_or(&[]))
                .is_ok_and(|ip| self.joined(ip.dst()));
            if joined {
                if self.loopback.push(&[bytes]) {
                    self.notify();
                } else {
                    self.stats.drop_reply_full += 1;
                }
            }
        }
        if ether_type == wire::ETHERTYPE_IPV6 && dst[..2] == [51, 51] {
            let joined = crate::wire6::parse(bytes.get(SIZE_ETH..).unwrap_or(&[]))
                .is_ok_and(|p| self.v6.as_ref().is_some_and(|v| v.accepts(p.dst)));
            if joined && !self.loopback.push(&[bytes]) {
                self.stats.drop_reply_full += 1;
            }
        }
        // Frames naar ons eigen MAC gaan naar de lokale ingress in plaats van
        // de draad: loopback voor elk adres van deze interface. Overloop valt
        // weg en wordt gemeld: TCP herstelt door hertransmissie, UDP niet.
        if dst == self.cfg.mac {
            if !self.loopback.push(&[bytes]) {
                self.stats.drop_reply_full += 1;
                return Err(Error::LoopbackFull);
            }
            self.notify();
            return Ok(Sent::Looped);
        }
        Ok(Sent::Wire(n))
    }

    /// Bouwt een IPv4-pakket rond een klare payload.
    fn send_ipv4(
        &mut self,
        frame: &mut [u8],
        mac: [u8; 6],
        dst: [u8; 4],
        proto: u8,
        payload: &[u8],
    ) -> Sent {
        let off = SIZE_ETH + SIZE_IPV4;
        let Some(dstbuf) = frame.get_mut(off..off + payload.len()) else {
            self.stats.drop_bad_frame += 1;
            return Sent::Dropped;
        };
        dstbuf.copy_from_slice(payload);
        let Ok(n) = wire::put_ipv4(
            frame.get_mut(SIZE_ETH..).unwrap_or(&mut []),
            proto,
            self.cfg.ip,
            dst,
            payload.len(),
        ) else {
            self.stats.drop_bad_frame += 1;
            return Sent::Dropped;
        };
        self.send_eth(frame, mac, ETHERTYPE_IPV4, n + payload.len())
            .unwrap_or(Sent::Dropped)
    }

    /// Zet een geëmit segment op de draad; de payload staat al op zijn plek.
    fn send_tcp(&mut self, frame: &mut [u8], mac: [u8; 6], key: ConnKey, seg: &Seg) -> Sent {
        // MSS plus NOP en window scale nemen één uitgelijnd blok van acht bytes.
        // Een SYN draagt hier geen payload, dus de opties overlappen niets.
        let mut opts = [0u8; 8];
        let mut olen = 0;
        if seg.flags.has(TcpFlags::SYN) {
            let [hi, lo] = seg.mss.to_be_bytes();
            opts[..4].copy_from_slice(&[2, 4, hi, lo]);
            olen = 4;
            if seg.ws_ok {
                opts[4..].copy_from_slice(&[1, 3, 3, seg.ws]);
                olen = 8;
            }
        }
        let h = TcpHeader {
            src_port: key.lport,
            dst_port: key.rport,
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            wnd: seg.wnd,
            opts: opts.get(..olen).unwrap_or(&[]),
        };
        let off = SIZE_ETH + SIZE_IPV4;
        let sum = !self.trusted(key.rip);
        let Ok(n) = wire::put_tcp_sum(
            frame.get_mut(off..).unwrap_or(&mut []),
            &h,
            self.cfg.ip,
            key.rip,
            seg.len,
            sum,
        ) else {
            self.stats.drop_bad_frame += 1; // Een interne maatfout, expliciet geteld.
            return Sent::Dropped;
        };
        if wire::put_ipv4(
            frame.get_mut(SIZE_ETH..).unwrap_or(&mut []),
            PROTO_TCP,
            self.cfg.ip,
            key.rip,
            n,
        )
        .is_err()
        {
            self.stats.drop_bad_frame += 1;
            return Sent::Dropped;
        }
        self.send_eth(frame, mac, ETHERTYPE_IPV4, SIZE_IPV4 + n)
            .unwrap_or(Sent::Dropped)
    }

    /// Of `ip` op de vertrouwde geheugenlink ligt ([`Config::link_trusted`]).
    pub(crate) fn trusted(&self, ip: [u8; 4]) -> bool {
        if !self.cfg.link_trusted {
            return false;
        }
        let (net, pfx) = self.mtu_net();
        same_subnet(ip, net, pfx)
    }

    /// Het net waarop de link-MTU geldt.
    fn mtu_net(&self) -> ([u8; 4], u8) {
        if self.cfg.mtu_prefix == 0 {
            (self.cfg.ip, self.cfg.prefix)
        } else {
            (self.cfg.mtu_net, self.cfg.mtu_prefix)
        }
    }

    /// De MTU naar `dst`: de geconfigureerde link-MTU op het lokale prefix, en
    /// nooit meer dan de klassieke 1500 daarbuiten (de uplink van de gateway).
    pub(crate) fn link_mtu(&self, dst: [u8; 4]) -> usize {
        let (net, pfx) = self.mtu_net();
        if same_subnet(dst, net, pfx) {
            return self.mtu;
        }
        self.mtu.min(MTU)
    }

    /// Bouwt een UDP-frame in de kladbuffer en zet het op weg. Gedeeld door
    /// de socketlaag.
    pub(crate) fn send_udp_frame(
        &mut self,
        mac: [u8; 6],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Result {
        let off = SIZE_ETH + SIZE_IPV4;
        let mut buf = core::mem::take(&mut self.scratch);
        let res = self.build_udp(&mut buf, off, mac, sport, dst, dport, payload);
        self.scratch = buf;
        res
    }

    /// Het eigenlijke bouwwerk van [`Stack::send_udp_frame`].
    #[expect(
        clippy::too_many_arguments,
        reason = "één frame, alle velden van de kop"
    )]
    fn build_udp(
        &mut self,
        buf: &mut [u8],
        off: usize,
        mac: [u8; 6],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        payload: &[u8],
    ) -> Result {
        let pstart = off + wire::SIZE_UDP;
        let max = buf.len().saturating_sub(pstart);
        buf.get_mut(pstart..pstart + payload.len())
            .ok_or(Error::DatagramTooLarge {
                len: payload.len(),
                max,
            })?
            .copy_from_slice(payload);
        let sum = !self.trusted(dst);
        let n = wire::put_udp_sum(
            buf.get_mut(off..).unwrap_or(&mut []),
            sport,
            dport,
            self.cfg.ip,
            dst,
            payload.len(),
            sum,
        )?;
        wire::put_ipv4(
            buf.get_mut(SIZE_ETH..).unwrap_or(&mut []),
            PROTO_UDP,
            self.cfg.ip,
            dst,
            n,
        )?;
        match self.send_eth(buf, mac, ETHERTYPE_IPV4, SIZE_IPV4 + n)? {
            Sent::Looped => Ok(()),
            // `send_eth` meldt een drop als fout; dit pad bestaat alleen voor
            // de volledigheid van de match.
            Sent::Dropped => Err(Error::QueueFull),
            Sent::Wire(len) => {
                if self.udp_out.push(&[buf.get(..len).unwrap_or(&[])]) {
                    self.notify();
                    Ok(())
                } else {
                    Err(Error::QueueFull)
                }
            }
        }
    }

    /// Of er ruimte is voor nog een uitgaand UDP-frame; zo niet, dan wacht de
    /// schrijver op de pomp.
    pub(crate) fn udp_out_has_room(&mut self) -> bool {
        let ok = self.udp_out.can_fit(MTU + ETHERNET_MAXIMUM_SIZE);
        if !ok {
            self.udp_out_waiters = true;
            self.notify();
        }
        ok
    }
}

/// Zet een gevalideerd frame en zijn MSS/WS-opties om naar machinevorm.
/// `None` bij misvormde opties.
pub(crate) fn parse_tcp_seg(f: &wire::Tcp<'_>) -> Option<Seg> {
    let mut seg = Seg {
        seq: f.seq(),
        ack: f.ack(),
        flags: f.flags(),
        wnd: f.window(),
        len: f.payload().len(),
        ..Seg::default()
    };
    if !seg.flags.has(TcpFlags::SYN) {
        return Some(seg);
    }
    let mut opts = f.options();
    while let Some(&kind) = opts.first() {
        match kind {
            0 => return Some(seg), // EOL.
            1 => {
                opts = opts.get(1..).unwrap_or(&[]); // NOP.
                continue;
            }
            _ => {}
        }
        let len = usize::from(opts.get(1).copied().unwrap_or(0));
        if len < 2 || len > opts.len() {
            return None; // Weiger misvormde opties.
        }
        match (kind, len) {
            (2, 4) => seg.mss = u16::from_be_bytes([opts[2], opts[3]]),
            (3, 3) => {
                seg.ws_ok = true;
                seg.ws = opts[2];
            }
            _ => {}
        }
        opts = opts.get(len..).unwrap_or(&[]);
    }
    Some(seg)
}
