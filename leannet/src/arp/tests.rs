//! `arp_test.go` plus de ARP-tabeltests uit `stack_test.go`.

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::neighbor::{NEIGHBOR_ENTRY_TTL, NEIGHBOR_FAIL_TTL, NEIGHBOR_QUERY_TRIES};
use crate::{SEC, wire};

const OUR_IP: [u8; 4] = [192, 168, 99, 2];
const OUR_MAC: [u8; 6] = [0x02, 0x48, 0x4f, 0x50, 0x00, 0x02];
const PEER_IP: [u8; 4] = [192, 168, 99, 1];
const PEER_MAC: [u8; 6] = [0x02, 0x48, 0x4f, 0x50, 0x00, 0x01];
const EVIL_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x66];
const OTHER_IP: [u8; 4] = [192, 168, 99, 9];
const OTHER_MAC: [u8; 6] = [0x02, 0x48, 0x4f, 0x50, 0x00, 0x09];
const HOUR: u64 = 3600 * SEC;

fn table() -> ArpTable {
    ArpTable::new(OUR_IP, OUR_MAC).unwrap()
}

/// Een geserialiseerd ARP-pakket.
fn pkt(op: u16, sh: [u8; 6], si: [u8; 4], th: [u8; 6], ti: [u8; 4]) -> Vec<u8> {
    let mut buf = vec![0u8; wire::SIZE_ARP];
    wire::put_arp(&mut buf, op, sh, si, th, ti).unwrap();
    buf
}

fn recv(tab: &mut ArpTable, p: &[u8], now: u64) {
    tab.recv(&wire::parse_arp(p).unwrap(), now);
}

fn drain(tab: &mut ArpTable, now: u64) -> usize {
    let mut buf = [0u8; wire::SIZE_ARP];
    let mut count = 0;
    while tab.emit(&mut buf, now).is_some() {
        count += 1;
    }
    count
}

fn establish(tab: &mut ArpTable, ip: [u8; 4], mac: [u8; 6], now: u64) {
    assert!(
        tab.resolve(ip, now).is_none(),
        "resolve hit before any query"
    );
    assert!(
        tab.emit(&mut [0u8; wire::SIZE_ARP], now).is_some(),
        "no query emitted for pending resolve"
    );
    let (om, oi) = (tab.our_mac, tab.our_ip);
    recv(tab, &pkt(ARP_REPLY, mac, ip, om, oi), now);
    assert_eq!(tab.resolve(ip, now), Some(mac), "resolve after reply");
}

#[test]
fn arp_resolve_cycle() {
    let mut tab = table();
    assert!(
        tab.resolve(PEER_IP, 0).is_none(),
        "resolve hit on empty table"
    );
    let mut buf = [0u8; wire::SIZE_ARP];
    let (n, kind) = tab.emit(&mut buf, 0).expect("no query emitted");
    assert_eq!(kind, ArpOut::Request);
    let q = wire::parse_arp(&buf[..n]).unwrap();
    assert_eq!(q.op(), ARP_REQUEST);
    assert_eq!(
        (q.sender_hw(), q.sender_ip()),
        (OUR_MAC, OUR_IP),
        "query sender"
    );
    assert_eq!(q.target_ip(), PEER_IP, "query target");
    assert!(
        tab.emit(&mut buf, 0).is_none(),
        "retry due only after the interval"
    );
    recv(
        &mut tab,
        &pkt(ARP_REPLY, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP),
        1,
    );
    assert_eq!(tab.resolve(PEER_IP, 2), Some(PEER_MAC));
    assert_eq!(drain(&mut tab, 2), 0, "resolved entry still emits packets");
}

#[test]
fn arp_dedup() {
    let mut tab = table();
    tab.resolve(PEER_IP, 0);
    tab.resolve(PEER_IP, 0);
    assert_eq!(tab.nt.len(), 1);
    assert_eq!(drain(&mut tab, 0), 1, "queries for two resolves");
    tab.resolve(PEER_IP, 1);
    assert_eq!(drain(&mut tab, 1), 0, "extra queries after dedup");
}

#[test]
fn arp_foreign_reply_ignored() {
    let mut tab = table();
    recv(
        &mut tab,
        &pkt(ARP_REPLY, EVIL_MAC, PEER_IP, OTHER_MAC, OTHER_IP),
        0,
    );
    assert_eq!(tab.nt.len(), 0, "foreign reply created an entry");
    assert_eq!(tab.cnt.ignored, 1);
    recv(
        &mut tab,
        &pkt(ARP_REPLY, EVIL_MAC, OTHER_IP, OUR_MAC, OUR_IP),
        0,
    );
    assert_eq!(tab.nt.len(), 0, "unsolicited reply to us created an entry");
    establish(&mut tab, PEER_IP, PEER_MAC, 0);
    recv(
        &mut tab,
        &pkt(ARP_REPLY, EVIL_MAC, PEER_IP, OTHER_MAC, OTHER_IP),
        1,
    );
    assert_eq!(
        tab.resolve(PEER_IP, 2),
        Some(PEER_MAC),
        "established entry poisoned"
    );
}

#[test]
fn arp_gratuitous_refresh() {
    let mut tab = table();
    establish(&mut tab, PEER_IP, PEER_MAC, 0);
    let new_mac = [0x02, 0x48, 0x4f, 0x50, 0x00, 0x11];
    recv(
        &mut tab,
        &pkt(ARP_REPLY, new_mac, PEER_IP, new_mac, PEER_IP),
        60 * SEC,
    );
    assert_eq!(
        tab.resolve(PEER_IP, 60 * SEC),
        Some(new_mac),
        "gratuitous refresh"
    );
    assert_eq!(tab.cnt.mac_changed, 1);
    assert!(
        tab.resolve(PEER_IP, 130 * SEC).is_some(),
        "refresh did not extend the TTL"
    );
    recv(
        &mut tab,
        &pkt(ARP_REPLY, OTHER_MAC, OTHER_IP, OTHER_MAC, OTHER_IP),
        60 * SEC,
    );
    assert!(
        tab.nt.get(OTHER_IP).is_none(),
        "gratuitous reply created an entry for an unknown ip"
    );
}

#[test]
fn arp_expiry() {
    let mut tab = table();
    establish(&mut tab, PEER_IP, PEER_MAC, 0);
    assert!(
        tab.resolve(PEER_IP, NEIGHBOR_ENTRY_TTL - 1).is_some(),
        "entry expired before its TTL"
    );
    assert!(
        tab.resolve(PEER_IP, NEIGHBOR_ENTRY_TTL).is_none(),
        "entry survived its TTL"
    );
    assert_eq!(
        drain(&mut tab, NEIGHBOR_ENTRY_TTL),
        1,
        "queries after expiry-restart"
    );
}

#[test]
fn arp_retry_and_give_up() {
    let mut tab = table();
    tab.resolve(PEER_IP, 0);
    for i in 0..u64::from(NEIGHBOR_QUERY_TRIES) {
        let now = i * SEC;
        assert_eq!(drain(&mut tab, now), 1, "try {}", i + 1);
        assert_eq!(
            drain(&mut tab, now + SEC / 2),
            0,
            "try {}: retry before its interval",
            i + 1
        );
    }
    let give_up = u64::from(NEIGHBOR_QUERY_TRIES) * SEC;
    assert_eq!(
        drain(&mut tab, give_up),
        0,
        "query emitted after give-up point"
    );
    assert_eq!(tab.cnt.gave_up, 1);
    assert!(
        tab.no_answer(PEER_IP, give_up),
        "noAnswer = false after give-up"
    );
    assert!(
        tab.resolve(PEER_IP, give_up + 1).is_none(),
        "resolve hit on failed entry"
    );
    assert_eq!(
        drain(&mut tab, give_up + 1),
        0,
        "resolve on failed entry restarted early"
    );
    let fresh = give_up + NEIGHBOR_FAIL_TTL;
    assert!(
        !tab.no_answer(PEER_IP, fresh),
        "noAnswer sticks past the fail TTL"
    );
    assert!(
        tab.resolve(PEER_IP, fresh).is_none(),
        "resolve hit without any reply"
    );
    assert_eq!(drain(&mut tab, fresh), 1, "queries on fresh cycle");
    assert_eq!(tab.cnt.gave_up, 1, "gave_up after restart");
}

#[test]
fn arp_answers_request() {
    let mut tab = table();
    recv(
        &mut tab,
        &pkt(ARP_REQUEST, PEER_MAC, PEER_IP, [0; 6], OUR_IP),
        0,
    );
    let mut buf = [0u8; wire::SIZE_ARP];
    let (n, kind) = tab
        .emit(&mut buf, 0)
        .expect("no reply emitted for a request to our ip");
    assert_eq!(kind, ArpOut::Reply(PEER_MAC));
    let r = wire::parse_arp(&buf[..n]).unwrap();
    assert_eq!(r.op(), ARP_REPLY);
    assert_eq!(
        (r.sender_hw(), r.sender_ip()),
        (OUR_MAC, OUR_IP),
        "reply sender"
    );
    assert_eq!(
        (r.target_hw(), r.target_ip()),
        (PEER_MAC, PEER_IP),
        "reply target"
    );
    assert!(
        tab.emit(&mut buf, 0).is_none(),
        "reply queue not drained after one emit"
    );
    recv(
        &mut tab,
        &pkt(ARP_REQUEST, PEER_MAC, PEER_IP, [0; 6], OTHER_IP),
        0,
    );
    assert!(
        tab.emit(&mut buf, 0).is_none(),
        "replied to a request for someone else's ip"
    );
}

#[test]
fn arp_seed() {
    let mut tab = table();
    tab.seed(PEER_IP, PEER_MAC).unwrap();
    assert_eq!(tab.resolve(PEER_IP, 0), Some(PEER_MAC), "seeded resolve");
    assert!(
        tab.resolve(PEER_IP, 1000 * SEC).is_some(),
        "static seed expired"
    );
    assert_eq!(
        drain(&mut tab, 1000 * SEC),
        0,
        "seed caused packets on the wire"
    );
    recv(
        &mut tab,
        &pkt(ARP_REPLY, EVIL_MAC, PEER_IP, EVIL_MAC, PEER_IP),
        1000 * SEC,
    );
    assert_eq!(
        tab.resolve(PEER_IP, 1000 * SEC),
        Some(PEER_MAC),
        "gratuitous reply overwrote a seed"
    );
    tab.resolve(OTHER_IP, 0);
    tab.seed(OTHER_IP, OTHER_MAC).unwrap();
    assert_eq!(
        tab.resolve(OTHER_IP, 0),
        Some(OTHER_MAC),
        "seed over pending"
    );
}

#[test]
fn arp_learn_passive() {
    const T0: u64 = SEC;
    let our = [10, 0, 0, 1];
    let mut tbl = ArpTable::new(our, [2, 0, 0, 0, 0, 1]).unwrap();
    let (peer, mac) = ([10, 0, 0, 9], [9, 9, 9, 9, 9, 1]);
    tbl.learn(peer, mac, T0);
    assert_eq!(
        tbl.resolve(peer, T0),
        Some(mac),
        "passive learn did not resolve"
    );
    tbl.learn(peer, mac, T0 + NEIGHBOR_ENTRY_TTL - 1);
    assert!(
        tbl.resolve(peer, T0 + NEIGHBOR_ENTRY_TTL + 1).is_some(),
        "passive refresh did not extend the TTL"
    );
    let evil = [0xde, 0xad, 0, 0, 0, 1];
    tbl.learn(peer, evil, T0 + NEIGHBOR_ENTRY_TTL + 2);
    assert_ne!(
        tbl.resolve(peer, T0 + NEIGHBOR_ENTRY_TTL + 2),
        Some(evil),
        "passive learning overwrote a MAC"
    );
    tbl.learn(our, [1, 2, 3, 4, 5, 6], T0);
    assert!(
        tbl.nt.get(our).is_none(),
        "passive learning created an entry for our own IP"
    );
    let other = [10, 0, 0, 20];
    tbl.resolve(other, T0);
    tbl.learn(other, [7; 6], T0);
    assert_eq!(
        tbl.resolve(other, T0),
        Some([7; 6]),
        "data-plane answer did not satisfy a pending query"
    );
}

#[test]
fn arp_static_seed_survives_everything() {
    const T0: u64 = SEC;
    let mut tbl = ArpTable::new([10, 100, 0, 5], [2, 0, 0, 0, 0, 5]).unwrap();
    let (gw, mac) = ([10, 100, 0, 1], [2, 0, 0, 0, 0, 0]);
    tbl.seed(gw, mac).unwrap();
    assert_eq!(
        tbl.resolve(gw, T0 + 100 * NEIGHBOR_ENTRY_TTL),
        Some(mac),
        "static seed expired"
    );
    let evil = [0xba, 0xad, 0, 0, 0, 1];
    recv(&mut tbl, &pkt(ARP_REPLY, evil, gw, evil, gw), T0);
    assert_eq!(
        tbl.resolve(gw, T0),
        Some(mac),
        "gratuitous reply overwrote a static seed"
    );
    tbl.learn(gw, evil, T0);
    assert_eq!(
        tbl.resolve(gw, T0),
        Some(mac),
        "passive learning overwrote a static seed"
    );
    assert!(
        tbl.emit(&mut [0u8; 64], T0).is_none(),
        "seeded address still produced an ARP query"
    );
}

// ---- uit stack_test.go ----

#[test]
fn arp_leerplafond() {
    let mut tab = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    for i in 0..2 * ARP_CACHE_CAP {
        tab.learn([10, 0, (i >> 8) as u8, i as u8], [2, 0, 0, 0, 0, 9], 0);
    }
    assert!(
        tab.nt.len() <= ARP_CACHE_CAP,
        "de tabel draagt {} entries",
        tab.nt.len()
    );
    assert!(tab.cnt.learn_drop > 0, "er is geweigerd zonder te tellen");
}

#[test]
fn arp_resolve_verdringt_geleerd() {
    let mut tab = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    let mut i = 0usize;
    while tab.nt.len() < ARP_CACHE_CAP && i < 4 * ARP_CACHE_CAP {
        tab.learn([10, 0, (i >> 8) as u8, i as u8], [2, 0, 0, 0, 0, 9], 0);
        i += 1;
    }
    let want = [10, 0, 9, 99];
    assert!(
        tab.resolve(want, 0).is_none(),
        "een verse resolve kan niet meteen opgelost zijn"
    );
    assert!(
        tab.nt
            .get(want)
            .is_some_and(|e| e.state == NeighborState::Pending),
        "resolve op een volle tabel maakte geen pending entry"
    );
    assert!(
        tab.nt.len() <= ARP_CACHE_CAP,
        "de verdringing hield de cap niet"
    );
}

#[test]
fn arp_volle_tabel_is_luid() {
    let mut tbl = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    for i in 0..ARP_CACHE_CAP {
        tbl.resolve([10, 0, (i >> 8) as u8, i as u8], HOUR);
    }
    let slachtoffer = [10, 0, 200, 200];
    assert!(
        tbl.resolve(slachtoffer, HOUR).is_none(),
        "resolve op een volle tabel gaf een MAC"
    );
    assert!(
        tbl.no_answer(slachtoffer, HOUR),
        "volle tabel: de wachter slaapt voor altijd"
    );
    assert!(
        tbl.cnt.full_drop > 0,
        "de geweigerde resolve is niet geteld"
    );
    tbl.learn([10, 0, 0, 2], [2, 0, 0, 0, 0, 2], HOUR);
    let reply = pkt(
        ARP_REPLY,
        [2, 0, 0, 0, 0, 5],
        [10, 0, 0, 5],
        [2, 0, 0, 0, 0, 1],
        [10, 0, 0, 1],
    );
    recv(&mut tbl, &reply, HOUR);
    assert!(
        !tbl.no_answer(slachtoffer, HOUR),
        "met een verdringbare entry hoort noAnswer false te zijn"
    );
}

#[test]
fn capaciteitssweep_laat_pending_met_rust() {
    let mut tbl = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    for i in 0..ARP_CACHE_CAP {
        let mut e = NeighborEntry::pending(HOUR - 1);
        e.tries = NEIGHBOR_QUERY_TRIES;
        tbl.nt.insert([10, 0, (i >> 8) as u8, i as u8], e).unwrap();
    }
    tbl.resolve([10, 0, 200, 200], HOUR);
    tbl.no_answer([10, 0, 200, 201], HOUR);
    assert_eq!(tbl.cnt.gave_up, 0, "gave_up buiten de pomp om");
    assert!(
        tbl.nt
            .entries
            .iter()
            .all(|(_, e)| e.state == NeighborState::Pending),
        "een entry veranderde buiten de pomp om"
    );
    while tbl.emit(&mut [0u8; wire::SIZE_ARP], HOUR).is_some() {}
    assert_eq!(
        tbl.cnt.gave_up, ARP_CACHE_CAP,
        "emit gaf niet alle queries op"
    );
}

#[test]
fn resolve_verdringt_tot_er_ruimte_is() {
    let over = |evictable: usize| {
        let mut tbl = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
        for i in 0..ARP_CACHE_CAP + 1 - evictable {
            tbl.nt
                .insert(
                    [10, 1, (i >> 8) as u8, i as u8],
                    NeighborEntry::pending(HOUR),
                )
                .unwrap();
        }
        for i in 0..evictable {
            tbl.nt
                .insert([10, 2, 0, i as u8], NeighborEntry::resolved([0; 6], HOUR))
                .unwrap();
        }
        tbl
    };
    let doel = [10, 3, 0, 1];
    let mut tbl = over(2);
    tbl.resolve(doel, HOUR);
    assert!(
        tbl.nt
            .get(doel)
            .is_some_and(|e| e.state == NeighborState::Pending),
        "resolve startte geen query terwijl er ruimte was"
    );
    assert!(
        tbl.nt.len() <= ARP_CACHE_CAP,
        "tabel boven de cap na resolve"
    );

    let mut tbl = over(1);
    tbl.resolve(doel, HOUR);
    assert!(
        tbl.nt.get(doel).is_none(),
        "resolve startte een query op een tabel die vol hoort te zijn"
    );
    assert!(
        tbl.nt.full(HOUR),
        "full zei 'niet vol' terwijl resolve geen query kon starten"
    );
}
