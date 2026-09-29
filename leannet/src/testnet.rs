//! Het testnet: twee stacks, één draad en een gesimuleerde klok.
//!
//! De Go-tests draaiden twee stacks met goroutines, `memDevice` en echte tijd.
//! Hier pompt de test zelf: [`Net::settle`] brengt frames heen en weer tot het
//! stil is, [`Net::run_for`] laat de klok lopen langs de timers van de stacks.
//! Zo worden dezelfde scenario's deterministisch en seconden-snel.

use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

use crate::wire::{self, TcpFlags, TcpHeader};
use crate::{Config, MS, SEC, Stack};

pub(crate) const IP_A: [u8; 4] = [10, 0, 0, 1];
pub(crate) const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub(crate) const IP_B: [u8; 4] = [10, 0, 0, 2];
pub(crate) const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];
/// De klok begint niet op nul, zoals een echte monotone klok na boot.
pub(crate) const T0: u64 = 3600 * SEC;

/// De configuratie van stack a, zoals `newStackPair`.
pub(crate) fn cfg_a(budget: usize) -> Config {
    Config {
        ip: IP_A,
        prefix: 24,
        mac: MAC_A,
        budget,
        adv_ws: 2,
        ..Config::default()
    }
}

/// De configuratie van stack b.
pub(crate) fn cfg_b(budget: usize) -> Config {
    Config {
        ip: IP_B,
        mac: MAC_B,
        ..cfg_a(budget)
    }
}

/// Een waker die telt hoe vaak hij gewekt werd.
#[derive(Default)]
pub(crate) struct Counter(AtomicUsize);

impl Counter {
    pub(crate) fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Een tellende waker en zijn teller.
pub(crate) fn counting_waker() -> (Waker, Arc<Counter>) {
    let c = Arc::new(Counter::default());
    (Waker::from(c.clone()), c)
}

/// Twee stacks aan één draad, of één stack met een vangnet.
pub(crate) struct Net {
    pub(crate) a: Stack,
    pub(crate) b: Option<Stack>,
    pub(crate) now: u64,
    /// ARP-vragen die a en b de deur uit deden.
    pub(crate) arp_queries_a: usize,
    pub(crate) arp_queries_b: usize,
    /// Alle ARP-frames van a.
    pub(crate) arp_frames_a: usize,
    /// Frames van a die b niet bereikten: er is geen b, of de draad is door.
    pub(crate) wire_a: Vec<Vec<u8>>,
    /// De draad is doorgeknipt; frames vallen weg.
    pub(crate) cut: bool,
    frame: Vec<u8>,
}

/// Of `f` een ARP-vraag is.
fn is_arp_request(f: &[u8]) -> bool {
    wire::parse_eth(f).is_ok_and(|e| {
        e.ether_type() == wire::ETHERTYPE_ARP
            && wire::parse_arp(e.payload()).is_ok_and(|a| a.op() == wire::ARP_REQUEST)
    })
}

/// Of `f` een ARP-frame is.
fn is_arp(f: &[u8]) -> bool {
    wire::parse_eth(f).is_ok_and(|e| e.ether_type() == wire::ETHERTYPE_ARP)
}

impl Net {
    /// Twee stacks zoals `newStackPair`.
    pub(crate) fn pair(budget_a: usize, budget_b: usize) -> Net {
        let a = Stack::new(cfg_a(budget_a), 12345).unwrap();
        let b = Stack::new(cfg_b(budget_b), 54321).unwrap();
        Net::with(a, Some(b))
    }

    /// Eén stack; alles wat hij stuurt belandt in `wire_a`.
    pub(crate) fn single(cfg: Config, seed: u32) -> Net {
        Net::with(Stack::new(cfg, seed).unwrap(), None)
    }

    /// Een net rond gegeven stacks.
    pub(crate) fn with(a: Stack, b: Option<Stack>) -> Net {
        Net {
            a,
            b,
            now: T0,
            arp_queries_a: 0,
            arp_queries_b: 0,
            arp_frames_a: 0,
            wire_a: Vec::new(),
            cut: false,
            frame: vec![0u8; 65535 + 18],
        }
    }

    /// Stack b; de test weet dat hij bestaat.
    pub(crate) fn b(&mut self) -> &mut Stack {
        self.b.as_mut().unwrap()
    }

    /// Pompt a leeg; `true` als er iets bewoog.
    fn pump_a(&mut self) -> bool {
        let mut moved = false;
        while let Some(n) = self.a.poll_transmit(self.now, &mut self.frame) {
            moved = true;
            let f = &self.frame[..n];
            if is_arp_request(f) {
                self.arp_queries_a += 1;
            }
            if is_arp(f) {
                self.arp_frames_a += 1;
            }
            match self.b.as_mut() {
                Some(b) if !self.cut => {
                    let _ = b.receive(f, self.now);
                }
                _ => self.wire_a.push(f.to_vec()),
            }
        }
        moved
    }

    /// Pompt b leeg; `true` als er iets bewoog.
    fn pump_b(&mut self) -> bool {
        let Some(b) = self.b.as_mut() else {
            return false;
        };
        let mut moved = false;
        while let Some(n) = b.poll_transmit(self.now, &mut self.frame) {
            moved = true;
            let f = &self.frame[..n];
            if is_arp_request(f) {
                self.arp_queries_b += 1;
            }
            if !self.cut {
                let _ = self.a.receive(f, self.now);
            }
        }
        moved
    }

    /// Brengt frames heen en weer tot beide stacks stil zijn.
    pub(crate) fn settle(&mut self) {
        for _ in 0..100_000 {
            let a = self.pump_a();
            let b = self.pump_b();
            if !a && !b {
                return;
            }
        }
        panic!("net did not settle");
    }

    /// De vroegste timer van beide stacks.
    fn next_timeout(&mut self) -> Option<u64> {
        let ta = self.a.next_timeout(self.now);
        let tb = self.b.as_mut().and_then(|b| b.next_timeout(self.now));
        match (ta, tb) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    /// Laat de klok `d` lopen, langs elke timer.
    pub(crate) fn run_for(&mut self, d: u64) {
        let target = self.now + d;
        loop {
            self.settle();
            if self.now >= target {
                return;
            }
            let next = self.next_timeout().unwrap_or(target);
            self.now = next.clamp(self.now + 1, target);
        }
    }

    /// Laat de klok lopen tot `cond` waar is of `max` verstreken is. De
    /// voorwaarde wordt minstens elke 5 ms gesimuleerde tijd bekeken, zoals een
    /// applicatietaak die snel reageert.
    pub(crate) fn run_until(&mut self, max: u64, mut cond: impl FnMut(&mut Net) -> bool) -> bool {
        let deadline = self.now + max;
        loop {
            self.settle();
            if cond(self) {
                return true;
            }
            if self.now >= deadline {
                return false;
            }
            let next = self.next_timeout().unwrap_or(u64::MAX);
            self.now = next.clamp(self.now + 1, self.now + 5 * MS).min(deadline);
        }
    }
}

/// Bouwt een Ethernet/IPv4/TCP-frame, zoals de Go-tests met de hand deden.
#[expect(clippy::too_many_arguments, reason = "een testframe met alle velden")]
pub(crate) fn tcp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    data: &[u8],
) -> Vec<u8> {
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4 + wire::SIZE_TCP + data.len()];
    wire::put_eth(&mut f, dst_mac, src_mac, wire::ETHERTYPE_IPV4).unwrap();
    let off = wire::SIZE_ETH + wire::SIZE_IPV4;
    f[off + wire::SIZE_TCP..].copy_from_slice(data);
    let h = TcpHeader {
        src_port: sport,
        dst_port: dport,
        seq,
        ack,
        flags,
        wnd: 1024,
        opts: &[],
    };
    let n = wire::put_tcp(&mut f[off..], &h, src, dst, data.len()).unwrap();
    wire::put_ipv4(&mut f[wire::SIZE_ETH..], wire::PROTO_TCP, src, dst, n).unwrap();
    f
}

/// Bouwt een Ethernet/IPv4/UDP-frame.
pub(crate) fn udp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4 + wire::SIZE_UDP + data.len()];
    wire::put_eth(&mut f, dst_mac, src_mac, wire::ETHERTYPE_IPV4).unwrap();
    let off = wire::SIZE_ETH + wire::SIZE_IPV4;
    f[off + wire::SIZE_UDP..].copy_from_slice(data);
    let n = wire::put_udp(&mut f[off..], sport, dport, src, dst, data.len()).unwrap();
    wire::put_ipv4(&mut f[wire::SIZE_ETH..], wire::PROTO_UDP, src, dst, n).unwrap();
    f
}

/// Een ontleed TCP-frame van de draad.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpSeen {
    pub(crate) dst_mac: [u8; 6],
    pub(crate) dst: [u8; 4],
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: TcpFlags,
}

/// Ontleedt een TCP-frame, of `None`.
pub(crate) fn seen_tcp(f: &[u8]) -> Option<TcpSeen> {
    let e = wire::parse_eth(f).ok()?;
    if e.ether_type() != wire::ETHERTYPE_IPV4 {
        return None;
    }
    let ip = wire::parse_ipv4(e.payload()).ok()?;
    if ip.proto() != wire::PROTO_TCP {
        return None;
    }
    let t = wire::parse_tcp(ip.payload()).ok()?;
    Some(TcpSeen {
        dst_mac: e.dst(),
        dst: ip.dst(),
        seq: t.seq(),
        ack: t.ack(),
        flags: t.flags(),
    })
}

/// Het doel-IP van een ARP-vraag, of `None`.
pub(crate) fn arp_request_target(f: &[u8]) -> Option<[u8; 4]> {
    let e = wire::parse_eth(f).ok()?;
    if e.ether_type() != wire::ETHERTYPE_ARP {
        return None;
    }
    let a = wire::parse_arp(e.payload()).ok()?;
    (a.op() == wire::ARP_REQUEST).then(|| a.target_ip())
}
