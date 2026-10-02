//! Opt-in IPv6: dezelfde begrensde UDP/NDP/SLAAC/RIO-baan als de Go-leannet (tag v1.2.0).
use crate::{
    Error, Result, SEC, Stack,
    neighbor::NeighborTable,
    queue::RecordQueue,
    stack::Sent,
    udp::{UdpPort, UdpTable},
    wire, wire6 as w,
};
use alloc::vec::Vec;
use core::task::Waker;
const PREFIXES: usize = 4;
const ROUTES: usize = 8;
const GROUPS: usize = 4;
const QUEUE: usize = 64 * 1024;
/// Een IPv6-eindpunt op de ene interface van deze stack; scopes horen bij de adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint6 {
    /// Netwerkadres.
    pub ip: [u8; 16],
    /// UDP-poort.
    pub port: u16,
}
/// Een generatiegecontroleerd IPv6-UDP-handvat, los van de IPv4-poorttabel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Udp6Handle {
    idx: usize,
    generation: u32,
}
/// De begrensde NDP-baan rapporteert degradatie zonder per-pakketlogs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NdpStats {
    /// Queries die na vijf pogingen opgaven.
    pub gave_up: usize,
    /// Passief leren geweigerd door capaciteit.
    pub learn_drop: usize,
    /// Queries geweigerd door capaciteit.
    pub full_drop: usize,
    /// Antwoorden geweigerd door de rij.
    pub reply_drop: usize,
    /// Nieuwe PIO-identiteiten geweigerd.
    pub prefix_drop: usize,
    /// Nieuwe RIO-identiteiten geweigerd.
    pub route_drop: usize,
    /// Gevalideerde wijzigingen van een bestaande MAC.
    pub mac_changed: usize,
    /// Aankondigingen zonder bestaande entry.
    pub ignored: usize,
    /// Ongeldige NDP-pakketten.
    pub bad_ndp: usize,
}
#[derive(Clone, Copy, Debug)]
struct Prefix {
    ip: [u8; 16],
    bits: u8,
    on_link: u64,
    valid: u64,
    preferred: u64,
}
#[derive(Clone, Copy, Debug)]
struct Route {
    ip: [u8; 16],
    bits: u8,
    router: [u8; 16],
    until: u64,
}
#[derive(Debug)]
pub(crate) struct State {
    ll: [u8; 16],
    global: Option<[u8; 16]>,
    mac: [u8; 6],
    nt: NeighborTable<[u8; 16]>,
    pub(crate) udp: UdpTable<16>,
    groups: Vec<[u8; 16]>,
    prefixes: [Option<Prefix>; PREFIXES],
    routes: [Option<Route>; ROUTES],
    router: Option<([u8; 16], u64)>,
    rs_due: u64,
    rs_tries: u8,
    rs_done: bool,
    replies: RecordQueue,
    stats: NdpStats,
}
fn lease(now: u64, seconds: u32) -> u64 {
    now.saturating_add(u64::from(seconds.min(7200)) * SEC)
}
impl State {
    fn new(mac: [u8; 6], now: u64) -> Result<Self> {
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(GROUPS)
            .map_err(|_| Error::OutOfMemory { bytes: GROUPS * 16 })?;
        Ok(Self {
            ll: w::link_local(mac),
            global: None,
            mac,
            nt: NeighborTable::new(128)?,
            udp: UdpTable::new(),
            groups,
            prefixes: [None; PREFIXES],
            routes: [None; ROUTES],
            router: None,
            rs_due: now,
            rs_tries: 0,
            rs_done: false,
            replies: RecordQueue::new(8, 8 * (w::MTU + 14 + 2)),
            stats: NdpStats::default(),
        })
    }
    fn owns(&self, a: [u8; 16]) -> bool {
        a == self.ll || self.global == Some(a)
    }
    pub(crate) fn accepts(&self, a: [u8; 16]) -> bool {
        self.owns(a)
            || a == w::ALL_NODES
            || a == w::solicited(self.ll)
            || self.global.is_some_and(|g| a == w::solicited(g))
            || self.groups.contains(&a)
    }
    fn slaac(&self, p: Prefix) -> [u8; 16] {
        let mut a = p.ip;
        a[8..].copy_from_slice(&self.ll[8..]);
        a
    }
    fn select_global(&mut self, now: u64) {
        let current = self
            .prefixes
            .iter()
            .flatten()
            .copied()
            .find(|p| p.valid > now && self.global == Some(self.slaac(*p)));
        if current.is_some_and(|p| p.preferred > now) {
            return;
        }
        let best = self
            .prefixes
            .iter()
            .flatten()
            .copied()
            .find(|p| p.valid > now && p.preferred > now)
            .or(current)
            .or_else(|| {
                self.prefixes
                    .iter()
                    .flatten()
                    .copied()
                    .find(|p| p.valid > now)
            });
        self.global = best.map(|p| self.slaac(p));
    }
    pub(crate) fn expire(&mut self, now: u64) {
        let old = self.global;
        let mut changed = false;
        if self.router.is_some_and(|(_, d)| now >= d) {
            self.router = None;
            changed = true;
        }
        for entry in &mut self.prefixes {
            if let Some(p) = entry {
                for d in [&mut p.on_link, &mut p.valid, &mut p.preferred] {
                    if *d != 0 && now >= *d {
                        *d = 0;
                        changed = true;
                    }
                }
                if p.on_link == 0 && p.valid == 0 {
                    *entry = None;
                }
            }
        }
        for r in &mut self.routes {
            if r.is_some_and(|r| now >= r.until) {
                *r = None;
                changed = true;
            }
        }
        self.select_global(now);
        let configured = self.router.is_some()
            || self.prefixes.iter().any(Option::is_some)
            || self.routes.iter().any(Option::is_some);
        if configured {
            self.rs_done = true;
        } else if self.rs_done {
            self.rs_done = false;
            self.rs_tries = 0;
            self.rs_due = now;
        }
        if changed || old != self.global {
            self.wake();
        }
    }
    fn on_link(&self, a: [u8; 16]) -> bool {
        w::is_link_local(a)
            || self
                .prefixes
                .iter()
                .flatten()
                .any(|p| p.on_link != 0 && w::matches(a, p.ip, p.bits))
    }
    fn next_hop(&self, a: [u8; 16]) -> Option<[u8; 16]> {
        if self.on_link(a) {
            return Some(a);
        }
        self.routes
            .iter()
            .flatten()
            .filter(|r| w::matches(a, r.ip, r.bits))
            .max_by_key(|r| r.bits)
            .map(|r| r.router)
            .or(self.router.map(|r| r.0))
    }
    fn source(&self, dst: [u8; 16]) -> Option<[u8; 16]> {
        if w::is_link_local(dst) || w::is_link_group(dst) {
            Some(self.ll)
        } else {
            self.global
        }
    }
    fn route(&mut self, dst: [u8; 16], now: u64) -> Result<[u8; 6]> {
        self.expire(now);
        if self.owns(dst) {
            return Ok(self.mac);
        }
        if w::is_link_group(dst) {
            return Ok(w::multicast_mac(dst));
        }
        let hop = self.next_hop(dst).ok_or(Error::NoRoute6)?;
        let (mac, refused) = self.nt.resolve(hop, now);
        if refused {
            self.stats.full_drop += 1;
        }
        if let Some(mac) = mac {
            return Ok(mac);
        }
        if self.nt.no_answer(hop, now) {
            Err(Error::Unreachable6)
        } else {
            Err(Error::WouldBlock)
        }
    }
    fn learn(&mut self, ip: [u8; 16], mac: [u8; 6], now: u64) {
        let (wake, drop) = self.nt.learn(ip, mac, now);
        self.stats.learn_drop += usize::from(drop);
        if wake {
            self.wake();
        }
    }
    fn passive(&mut self, p: &w::Packet<'_>, mac: [u8; 6], now: u64) {
        if self.owns(p.dst) && !self.owns(p.src) && self.on_link(p.src) && w::mac_ok(mac) {
            self.learn(p.src, mac, now);
        }
    }
    fn wake(&mut self) {
        for u in self.udp.ports.iter_mut().flatten() {
            u.write_waker.wake();
        }
    }
    pub(crate) fn deadline(&self) -> Option<u64> {
        let mut d = self.nt.next_deadline();
        let mut add = |t: u64| {
            if d.is_none_or(|v| t < v) {
                d = Some(t);
            }
        };
        if !self.replies.is_empty() {
            add(0);
        }
        if !self.rs_done && self.rs_tries < 3 {
            add(self.rs_due);
        }
        if let Some((_, t)) = self.router {
            add(t);
        }
        for p in self.prefixes.iter().flatten() {
            for t in [p.on_link, p.valid, p.preferred] {
                if t != 0 {
                    add(t);
                }
            }
        }
        for r in self.routes.iter().flatten() {
            add(r.until);
        }
        for u in self.udp.ports.iter().flatten() {
            if u.read_waker.is_set()
                && let Some(t) = u.rd_deadline
            {
                add(t);
            }
            if u.write_waker.is_set()
                && let Some(t) = u.wr_deadline
            {
                add(t);
            }
        }
        d
    }
    pub(crate) fn tick(&mut self, now: u64) {
        self.expire(now);
        for u in self.udp.ports.iter_mut().flatten() {
            if u.rd_deadline.is_some_and(|t| now >= t) {
                u.read_waker.wake();
            }
            if u.wr_deadline.is_some_and(|t| now >= t) {
                u.write_waker.wake();
            }
        }
    }
    fn queue_icmp(&mut self, mac: [u8; 6], src: [u8; 16], dst: [u8; 16], hop: u8, p: &[u8]) {
        let mut head = [0; 54];
        if wire::put_eth(&mut head, mac, self.mac, wire::ETHERTYPE_IPV6).is_err()
            || w::put(&mut head[14..], src, dst, w::ICMP, hop, p.len()).is_err()
            || !self.replies.push(&[&head, p])
        {
            self.stats.reply_drop += 1;
        }
    }
    fn receive_ns(&mut self, p: &w::Packet<'_>, mac: [u8; 6], now: u64) -> bool {
        let b = p.payload;
        if b.len() < 24 || b[1] != 0 || !w::mac_ok(mac) {
            return false;
        }
        let target = w::addr(&b[8..]);
        let mut source = None;
        if !w::options(&b[24..], |t, o| {
            if t == 1 {
                if source.is_some() || o.len() != 8 {
                    return false;
                }
                source = Some([o[2], o[3], o[4], o[5], o[6], o[7]]);
            }
            true
        }) || !w::is_unicast(target)
        {
            return false;
        }
        let dad = p.src == [0; 16];
        if dad {
            if source.is_some() || p.dst != w::solicited(target) {
                return false;
            }
        } else if !w::is_unicast(p.src)
            || (p.dst != target && p.dst != w::solicited(target))
            || (p.dst[0] == 255 && source.is_none())
        {
            return false;
        }
        if source.is_some_and(|s| !w::mac_ok(s) || s != mac) {
            return false;
        }
        if !self.owns(target) {
            return true;
        }
        if !dad && source.is_some() && !self.owns(p.src) {
            self.learn(p.src, mac, now);
        }
        let dst = if dad { w::ALL_NODES } else { p.src };
        let hw = if dad { w::multicast_mac(dst) } else { mac };
        let mut b = [0; 32];
        b[0] = 136;
        b[4] = if dad { 0x20 } else { 0x60 };
        b[8..24].copy_from_slice(&target);
        b[24] = 2;
        b[25] = 1;
        b[26..].copy_from_slice(&self.mac);
        let sum = w::checksum(target, dst, w::ICMP, &b);
        b[2..4].copy_from_slice(&sum.to_be_bytes());
        self.queue_icmp(hw, target, dst, 255, &b);
        true
    }
    fn receive_na(&mut self, p: &w::Packet<'_>, mac: [u8; 6], now: u64) -> bool {
        let b = p.payload;
        if b.len() < 24 || b[1] != 0 || !w::mac_ok(mac) {
            return false;
        }
        let target = w::addr(&b[8..]);
        let mut advertised = None;
        if !w::options(&b[24..], |t, o| {
            if t == 2 {
                if advertised.is_some() || o.len() != 8 {
                    return false;
                }
                advertised = Some([o[2], o[3], o[4], o[5], o[6], o[7]]);
            }
            true
        }) {
            return false;
        }
        if !w::is_unicast(p.src)
            || !w::is_unicast(target)
            || (b[4] & 0x40 != 0 && p.dst[0] == 255)
            || advertised.is_some_and(|m| !w::mac_ok(m) || m != mac)
        {
            return false;
        }
        if advertised.is_none() {
            return true;
        }
        if self.nt.resolve_pending(target, mac, now) {
            self.wake();
        } else {
            let (refreshed, changed) = self.nt.refresh(target, mac, now);
            self.stats.ignored += usize::from(!refreshed);
            self.stats.mac_changed += usize::from(changed);
        }
        true
    }
    fn receive_ra(&mut self, p: &w::Packet<'_>, mac: [u8; 6], now: u64) -> bool {
        let b = p.payload;
        if b.len() < 16
            || b[1] != 0
            || !w::is_link_local(p.src)
            || !w::mac_ok(mac)
            || (p.dst[0] == 255 && p.dst != w::ALL_NODES)
        {
            return false;
        }
        let opts = &b[16..];
        let mut has_mac = false;
        let mut consumed = 0;
        // Eerst de volledige advertentie toetsen; een slechte staart mag geen route publiceren.
        if !w::options(opts, |t, o| {
            let valid = match t {
                1 => {
                    let fresh = !has_mac;
                    has_mac = true;
                    fresh && o.len() == 8 && o[2..8] == mac
                }
                3 => {
                    o.len() == 32
                        && o[2] <= 128
                        && w::be32(&o[8..]) <= w::be32(&o[4..])
                        && w::canonical(w::addr(&o[16..]), o[2])
                            .is_ok_and(|a| !w::is_link_local(a) && a[0] != 255)
                }
                24 => {
                    matches!(o.len(), 8 | 16 | 24)
                        && o[2] <= 128
                        && (o.len() != 8 || o[2] == 0)
                        && (o.len() != 16 || o[2] <= 64)
                        && o[3] & 0x18 != 0x10
                        && rio_prefix(o)
                            .is_ok_and(|a| o[2] == 0 || (!w::is_link_local(a) && a[0] != 255))
                }
                _ => true,
            };
            if !valid {
                return false;
            }
            if matches!(t, 3 | 24) {
                let ip = if t == 3 {
                    w::canonical(w::addr(&o[16..]), o[2])
                } else {
                    rio_prefix(o)
                };
                if !w::options(&opts[..consumed], |pt, po| {
                    pt != t
                        || po[2] != o[2]
                        || if t == 3 {
                            w::canonical(w::addr(&po[16..]), po[2]) != ip
                        } else {
                            rio_prefix(po) != ip
                        }
                }) {
                    return false;
                }
            }
            consumed += o.len();
            true
        }) {
            return false;
        }
        self.expire(now);
        // Sommige Thread-borderrouters adverteren alleen een RIO, zonder
        // SLLAO, en beantwoorden multicast-NS niet. Het gevalideerde frame
        // draagt hun linkadres al. Leer dat passief, ook zonder de optionele
        // SLLAO; een aanwezige optie moet hierboven nog steeds overeenkomen.
        // `learn` overschrijft geen bestaande opgeloste buur met een andere MAC.
        self.learn(p.src, mac, now);
        let life = u16::from_be_bytes([b[6], b[7]]);
        if life != 0 {
            self.router = Some((p.src, lease(now, u32::from(life))));
        } else if self.router.is_some_and(|r| r.0 == p.src) {
            self.router = None;
        }
        w::options(opts, |t, o| {
            if t == 3 {
                self.pio(o, now);
            } else if t == 24 {
                self.rio(o, p.src, now);
            }
            true
        });
        self.expire(now);
        self.wake();
        true
    }
    fn pio(&mut self, o: &[u8], now: u64) {
        let Ok(ip) = w::canonical(w::addr(&o[16..]), o[2]) else {
            return;
        };
        let bits = o[2];
        let life = w::be32(&o[4..]);
        let preferred = w::be32(&o[8..]);
        let l = o[3] & 0x80 != 0;
        let a = o[3] & 0x40 != 0 && bits == 64;
        if !l && !a {
            return;
        }
        let found = self
            .prefixes
            .iter()
            .position(|p| p.is_some_and(|p| p.ip == ip && p.bits == bits));
        let idx = found.or_else(|| {
            if life != 0 {
                self.prefixes.iter().position(Option::is_none)
            } else {
                None
            }
        });
        let Some(i) = idx else {
            if life != 0 {
                self.stats.prefix_drop += 1;
            }
            return;
        };
        let p = self.prefixes[i].get_or_insert(Prefix {
            ip,
            bits,
            on_link: 0,
            valid: 0,
            preferred: 0,
        });
        if l {
            p.on_link = if life == 0 { 0 } else { lease(now, life) };
        }
        if a {
            p.valid = if life == 0 { 0 } else { lease(now, life) };
            p.preferred = if preferred == 0 {
                0
            } else {
                lease(now, preferred)
            };
        }
        if p.on_link == 0 && p.valid == 0 {
            self.prefixes[i] = None;
        }
    }
    fn rio(&mut self, o: &[u8], router: [u8; 16], now: u64) {
        let Ok(ip) = rio_prefix(o) else {
            return;
        };
        let bits = o[2];
        let life = w::be32(&o[4..]);
        let found = self
            .routes
            .iter()
            .position(|r| r.is_some_and(|r| r.ip == ip && r.bits == bits));
        if life == 0 {
            if let Some(i) = found
                && self.routes[i].is_some_and(|r| r.router == router)
            {
                self.routes[i] = None;
            }
            return;
        }
        if let Some(i) = found.or_else(|| self.routes.iter().position(Option::is_none)) {
            self.routes[i] = Some(Route {
                ip,
                bits,
                router,
                until: lease(now, life),
            });
        } else {
            self.stats.route_drop += 1;
        }
    }
    pub(crate) fn receive(&mut self, p: &w::Packet<'_>, mac: [u8; 6], now: u64) -> bool {
        self.expire(now);
        if !self.accepts(p.dst) {
            return true;
        }
        if p.src[0] == 255 {
            return false;
        }
        let b = p.payload;
        if p.next == 17 {
            if !w::is_unicast(p.src)
                || b.len() < 8
                || b[6..8] == [0, 0]
                || usize::from(u16::from_be_bytes([b[4], b[5]])) != b.len()
                || w::checksum(p.src, p.dst, 17, b) != 0
            {
                return false;
            }
            self.passive(p, mac, now);
            if let Some(i) = self.udp.deliver(
                u16::from_be_bytes([b[2], b[3]]),
                p.src,
                u16::from_be_bytes([b[0], b[1]]),
                &b[8..],
            ) && let Some(u) = self.udp.get_mut(i)
            {
                u.read_waker.wake();
            }
            return true;
        }
        if b.len() < 4 || w::checksum(p.src, p.dst, w::ICMP, b) != 0 {
            return false;
        }
        if matches!(b[0], 134..=136) {
            let valid = p.hop == 255
                && match b[0] {
                    134 => self.receive_ra(p, mac, now),
                    135 => self.receive_ns(p, mac, now),
                    136 => self.receive_na(p, mac, now),
                    _ => false,
                };
            if !valid {
                self.stats.bad_ndp += 1;
            }
            return true;
        }
        if b[0] == 128 {
            if b[1] != 0 || b.len() < 8 || b.len() > w::MTU - w::HEADER || !w::is_unicast(p.src) {
                return false;
            }
            if self.owns(p.dst) {
                self.passive(p, mac, now);
                if let Ok(hw) = self.route(p.src, now) {
                    let mut copy = [0; w::MTU - w::HEADER];
                    copy[..b.len()].copy_from_slice(b);
                    copy[0] = 129;
                    copy[2..4].fill(0);
                    let sum = w::checksum(p.dst, p.src, w::ICMP, &copy[..b.len()]);
                    copy[2..4].copy_from_slice(&sum.to_be_bytes());
                    self.queue_icmp(hw, p.dst, p.src, 64, &copy[..b.len()]);
                }
            }
        }
        true
    }
    pub(crate) fn emit(&mut self, now: u64, out: &mut [u8]) -> Option<usize> {
        while let Some(n) = self.replies.pop(out) {
            if w::parse(out.get(14..n)?).is_ok_and(|p| self.owns(p.src)) {
                return Some(n);
            }
        }
        let (query, gave_up) = self.nt.poll(now);
        self.stats.gave_up += gave_up;
        if gave_up != 0 {
            self.wake();
        }
        let mut b = [0; 32];
        let (dst, n) = if let Some(ip) = query {
            b[0] = 135;
            b[8..24].copy_from_slice(&ip);
            b[24] = 1;
            b[25] = 1;
            b[26..].copy_from_slice(&self.mac);
            (w::solicited(ip), 32)
        } else if !self.rs_done && self.rs_tries < 3 && now >= self.rs_due {
            self.rs_tries += 1;
            self.rs_due = now.saturating_add(4 * SEC);
            b[0] = 133;
            b[8] = 1;
            b[9] = 1;
            b[10..16].copy_from_slice(&self.mac);
            (w::ALL_ROUTERS, 16)
        } else {
            return None;
        };
        let sum = w::checksum(self.ll, dst, w::ICMP, &b[..n]);
        b[2..4].copy_from_slice(&sum.to_be_bytes());
        wire::put_eth(out, w::multicast_mac(dst), self.mac, wire::ETHERTYPE_IPV6).ok()?;
        w::put(out.get_mut(14..)?, self.ll, dst, w::ICMP, 255, n).ok()?;
        out.get_mut(54..54 + n)?.copy_from_slice(&b[..n]);
        Some(54 + n)
    }
}
fn rio_prefix(o: &[u8]) -> Result<[u8; 16]> {
    let mut a = [0; 16];
    let b = o.get(8..).ok_or(Error::InvalidIpv6)?;
    let dst = a.get_mut(..b.len()).ok_or(Error::InvalidIpv6)?;
    dst.copy_from_slice(b);
    w::canonical(a, *o.get(2).ok_or(Error::InvalidIpv6)?)
}

impl Stack {
    /// Activeert IPv6 op eerste gebruik; ongebruikte stacks alloceren geen IPv6-tabellen.
    pub fn enable_ipv6(&mut self, now: u64) -> Result {
        if self.closed {
            return Err(Error::StackClosed);
        }
        if self.v6.is_none() {
            self.v6 = Some(State::new(self.cfg.mac, now)?);
            self.notify();
        }
        Ok(())
    }
    /// De huidige link-local- en optionele SLAAC-identiteit, na leaseverloop.
    pub fn ipv6_addresses(&mut self, now: u64) -> Option<([u8; 16], Option<[u8; 16]>)> {
        let v = self.v6.as_mut()?;
        v.expire(now);
        Some((v.ll, v.global))
    }
    /// De meetlat van de optionele IPv6-baan.
    pub fn ndp_stats(&self) -> NdpStats {
        self.v6.as_ref().map_or(self.ndp_closed, |v| v.stats)
    }
    /// Joint uitsluitend link-scoped multicast; geldt tot de stack sluit.
    pub fn join_group6(&mut self, group: [u8; 16], now: u64) -> Result {
        if !w::is_link_group(group) {
            return Err(Error::InvalidIpv6);
        }
        self.enable_ipv6(now)?;
        let v = self.v6.as_mut().ok_or(Error::StackClosed)?;
        if v.groups.contains(&group) {
            return Ok(());
        }
        if v.groups.len() == GROUPS {
            return Err(Error::GroupsFull { cap: GROUPS });
        }
        v.groups.push(group);
        Ok(())
    }
    /// Bindt een afzonderlijke IPv6-poort; nul kiest een efemere poort.
    pub fn udp6_bind(&mut self, port: u16, now: u64) -> Result<Udp6Handle> {
        self.enable_ipv6(now)?;
        let port = if port == 0 {
            self.ephemeral_port(|s, p| s.v6.as_ref().is_some_and(|v| v.udp.bound(p)))?
        } else {
            port
        };
        let generation = self.new_generation();
        let idx = self.v6.as_mut().ok_or(Error::StackClosed)?.udp.bind(
            port,
            QUEUE,
            &mut self.pot,
            generation,
        )?;
        Ok(Udp6Handle { idx, generation })
    }
    fn udp6_port(&mut self, h: Udp6Handle) -> Result<&mut UdpPort<16>> {
        self.v6
            .as_mut()
            .and_then(|v| v.udp.get_mut(h.idx))
            .filter(|u| u.generation == h.generation)
            .ok_or(Error::Closed)
    }
    /// De wildcard-binding; het bronadres wordt per bestemming gekozen.
    pub fn udp6_local(&mut self, h: Udp6Handle) -> Result<Endpoint6> {
        let port = self.udp6_port(h)?.port;
        let ip = [0; 16];
        Ok(Endpoint6 { ip, port })
    }
    /// Verbindt een IPv6-socket aan één peer en filtert andere afzenders voor de rij.
    pub fn udp6_connect(&mut self, to: Endpoint6, now: u64) -> Result<Udp6Handle> {
        if to.port == 0 {
            return Err(Error::InvalidPort);
        }
        if !w::is_unicast(to.ip) && !w::is_link_group(to.ip) {
            return Err(Error::InvalidIpv6);
        }
        let h = self.udp6_bind(0, now)?;
        self.udp6_port(h)?.peer = Some((to.ip, to.port));
        Ok(h)
    }
    /// Ontvangt één volledig record; een korte buffer kapt uitsluitend dat record af.
    pub fn udp6_recv_from(
        &mut self,
        h: Udp6Handle,
        buf: &mut [u8],
        now: u64,
    ) -> Result<(usize, Endpoint6)> {
        let u = self.udp6_port(h)?;
        if u.rd_deadline.is_some_and(|d| now >= d) {
            return Err(Error::DeadlineExceeded);
        }
        let (n, ip, port) = u.recv_from(buf).ok_or(Error::WouldBlock)?;
        Ok((n, Endpoint6 { ip, port }))
    }
    /// Of er een datagram klaarligt; verbruikt niets (de IPv6-tegenhanger
    /// van [`Stack::udp_readable`](crate::Stack::udp_readable)).
    pub fn udp6_readable(&mut self, h: Udp6Handle) -> Result<bool> {
        Ok(self.udp6_port(h)?.has_data())
    }
    /// Stuurt naar de vastgelegde peer.
    pub fn udp6_send(&mut self, h: Udp6Handle, data: &[u8], now: u64) -> Result<usize> {
        let (ip, port) = self.udp6_port(h)?.peer.ok_or(Error::NotConnected)?;
        self.udp6_write(h, Endpoint6 { ip, port }, data, now)
    }
    /// Stuurt één datagram; NDP-wachten en volle zendrijen geven WouldBlock.
    pub fn udp6_send_to(
        &mut self,
        h: Udp6Handle,
        to: Endpoint6,
        data: &[u8],
        now: u64,
    ) -> Result<usize> {
        if self.udp6_port(h)?.peer.is_some() {
            return Err(Error::WriteToConnected);
        }
        self.udp6_write(h, to, data, now)
    }
    fn udp6_write(&mut self, h: Udp6Handle, to: Endpoint6, data: &[u8], now: u64) -> Result<usize> {
        let u = self.udp6_port(h)?;
        let port = u.port;
        if u.wr_deadline.is_some_and(|d| now >= d) {
            return Err(Error::DeadlineExceeded);
        }
        if to.port == 0 {
            return Err(Error::InvalidPort);
        }
        if !w::is_unicast(to.ip) && !w::is_link_group(to.ip) {
            return Err(Error::InvalidIpv6);
        }
        if data.len() > 1232 {
            return Err(Error::DatagramTooLarge {
                len: data.len(),
                max: 1232,
            });
        }
        let v = self.v6.as_mut().ok_or(Error::Closed)?;
        v.expire(now);
        let src = v.source(to.ip).ok_or(Error::NoRoute6)?;
        let route = v.route(to.ip, now);
        self.notify();
        let mac = route?;
        if mac != self.cfg.mac && !self.udp_out_has_room() {
            return Err(Error::WouldBlock);
        }
        let mut scratch = core::mem::take(&mut self.scratch);
        let result = (|| {
            let len = 8 + data.len();
            let p = scratch.get_mut(54..54 + len).ok_or(Error::InvalidIpv6)?;
            p[..8].fill(0);
            p[..2].copy_from_slice(&port.to_be_bytes());
            p[2..4].copy_from_slice(&to.port.to_be_bytes());
            p[4..6].copy_from_slice(&(len as u16).to_be_bytes());
            p[8..].copy_from_slice(data);
            let sum = w::checksum(src, to.ip, 17, p);
            p[6..8].copy_from_slice(&if sum == 0 { 65535 } else { sum }.to_be_bytes());
            w::put(
                scratch.get_mut(14..).ok_or(Error::InvalidIpv6)?,
                src,
                to.ip,
                17,
                if w::is_link_group(to.ip) { 255 } else { 64 },
                len,
            )?;
            if let Sent::Wire(n) =
                self.send_eth(&mut scratch, mac, wire::ETHERTYPE_IPV6, 40 + len)?
                && !self.udp_out.push(&[&scratch[..n]])
            {
                return Err(Error::WouldBlock);
            }
            Ok(data.len())
        })();
        self.scratch = scratch;
        result
    }
    /// Laat de ontvangstrij en haar budget op elk pad vrij, met een wek voor wachtenden.
    pub fn udp6_close(&mut self, h: Udp6Handle) {
        if self.udp6_port(h).is_err() {
            return;
        }
        if let Some(v) = self.v6.as_mut()
            && let Some(mut u) = v.udp.close(h.idx, &mut self.pot)
        {
            u.read_waker.wake();
            u.write_waker.wake();
        }
        self.notify();
    }
    /// Zet de absolute leesdeadline.
    pub fn udp6_set_read_deadline(&mut self, h: Udp6Handle, d: Option<u64>) -> Result {
        let u = self.udp6_port(h)?;
        u.rd_deadline = d;
        u.read_waker.wake();
        Ok(())
    }
    /// Zet de absolute schrijfdeadline.
    pub fn udp6_set_write_deadline(&mut self, h: Udp6Handle, d: Option<u64>) -> Result {
        let u = self.udp6_port(h)?;
        u.wr_deadline = d;
        u.write_waker.wake();
        Ok(())
    }
    /// Registreert de lezer zonder verloren wek.
    pub fn udp6_register_read_waker(&mut self, h: Udp6Handle, w: &Waker) -> Result {
        self.udp6_port(h)?.read_waker.register(w);
        Ok(())
    }
    /// Registreert de schrijver voor NDP, leasewijzigingen en zendruimte.
    pub fn udp6_register_write_waker(&mut self, h: Udp6Handle, w: &Waker) -> Result {
        self.udp6_port(h)?.write_waker.register(w);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
