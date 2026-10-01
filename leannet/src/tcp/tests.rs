//! De TCP-machine zonder draad, klok of taak: twee verbindingen en een
//! handmatige pomp. Elke test is een Go-test uit `tcp_test.go`,
//! `congestion_test.go`, `fast_retransmit_test.go` of `ephemeral_seed_test.go`
//! met dezelfde naam in snake_case en dezelfde bedoeling.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use super::*;
use crate::ring::Budget;

/// Een segment met zijn payload, zoals het over de testdraad gaat.
type Pkt = (Seg, Vec<u8>);

/// Een filter dat `true` geeft voor segmenten die de draad verliest.
type Drop = Option<Box<dyn FnMut(&Seg) -> bool>>;

/// Twee machines, twee potten, één klok.
struct Wire {
    a: TcpConn,
    b: TcpConn,
    pot_a: Budget,
    pot_b: Budget,
    now: u64,
    drop_ab: Drop,
    drop_ba: Drop,
}

/// Een segmentkop voor handgemaakte invoer.
fn s(seq: u32, ack: u32, flags: TcpFlags, wnd: u16) -> Seg {
    Seg {
        seq,
        ack,
        flags,
        wnd,
        ..Seg::default()
    }
}

const ACK: TcpFlags = TcpFlags::ACK;
const FIN: TcpFlags = TcpFlags::FIN;
const SYN: TcpFlags = TcpFlags::SYN;
const RST: TcpFlags = TcpFlags::RST;
const PSH: TcpFlags = TcpFlags::PSH;
const HOUR: u64 = 3600 * SEC;
const MIN: u64 = 60 * SEC;

fn new_pair(ring_a: usize, ring_b: usize) -> Wire {
    new_pair_iss(ring_a, ring_b, 1000, 5000, 0)
}

fn new_pair_iss(ring_a: usize, ring_b: usize, iss_a: u32, iss_b: u32, ws: u8) -> Wire {
    let mut a = TcpConn::with_rings(ring_a, ring_a).unwrap();
    let mut b = TcpConn::with_rings(ring_b, ring_b).unwrap();
    a.open_active(iss_a, 1460, ws);
    b.open_passive(iss_b, 1460, ws);
    Wire {
        a,
        b,
        pot_a: Budget::new(0),
        pot_b: Budget::new(0),
        now: HOUR,
        drop_ab: None,
        drop_ba: None,
    }
}

/// Emit tot de machine stil is.
fn drain_conn(c: &mut TcpConn, now: u64) -> Vec<Pkt> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 2048];
    for i in 0.. {
        assert!(i <= 64, "drain runaway: >64 segments from {}", c.state);
        let Some(seg) = c.emit(&mut buf, now) else {
            return out;
        };
        out.push((seg, buf[..seg.len].to_vec()));
    }
    out
}

/// Leest alles wat er ligt.
fn read_all(c: &mut TcpConn) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::new();
    loop {
        let n = c.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

impl Wire {
    fn advance(&mut self, d: u64) {
        self.now += d;
    }
    fn drain_a(&mut self) -> Vec<Pkt> {
        drain_conn(&mut self.a, self.now)
    }
    fn drain_b(&mut self) -> Vec<Pkt> {
        drain_conn(&mut self.b, self.now)
    }
    fn recv_a(&mut self, seg: &Seg, data: &[u8]) {
        self.a.recv(seg, data, self.now, &mut self.pot_a);
    }
    fn recv_b(&mut self, seg: &Seg, data: &[u8]) {
        self.b.recv(seg, data, self.now, &mut self.pot_b);
    }
    fn write_a(&mut self, p: &[u8]) -> Result<usize> {
        self.a.write(p, &mut self.pot_a)
    }
    fn write_b(&mut self, p: &[u8]) -> Result<usize> {
        self.b.write(p, &mut self.pot_b)
    }
    fn pump(&mut self) {
        for _ in 0..64 {
            let mut moved = false;
            for (seg, data) in self.drain_a() {
                moved = true;
                if !self.drop_ab.as_mut().is_some_and(|f| f(&seg)) {
                    self.recv_b(&seg, &data);
                }
            }
            for (seg, data) in self.drain_b() {
                moved = true;
                if !self.drop_ba.as_mut().is_some_and(|f| f(&seg)) {
                    self.recv_a(&seg, &data);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("pump did not settle: a={} b={}", self.a.state, self.b.state);
    }
    fn connect(&mut self) {
        self.pump();
        assert!(
            self.a.state == TcpState::Established && self.b.state == TcpState::Established,
            "handshake failed: a={} b={}",
            self.a.state,
            self.b.state
        );
    }
}

fn has(p: &Pkt, f: TcpFlags) -> bool {
    p.0.flags.has(f)
}

#[test]
fn tcp_handshake_and_data() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    assert_eq!(
        (w.a.peer_mss, w.b.peer_mss),
        (1460, 1460),
        "MSS not negotiated"
    );
    assert!(
        w.a.ws_on && w.b.ws_on,
        "window scaling not negotiated on mutual offer"
    );
    w.write_a(b"hello from a").unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.b), b"hello from a");
    w.write_b(b"hi back").unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.a), b"hi back");
}

#[test]
fn tcp_lost_bare_fin() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.a.close().unwrap();
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], FIN),
        "expected exactly one FIN, got {segs:?}"
    );

    w.advance(500 * MS);
    assert!(w.drain_a().is_empty(), "retransmit before RTO deadline");

    w.advance(600 * MS);
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], FIN),
        "lost bare FIN was not retransmitted: {segs:?}"
    );
    assert_eq!(w.a.state, TcpState::FinWait1);

    w.recv_b(&segs[0].0, &segs[0].1);
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::FinWait2, TcpState::CloseWait)
    );
    assert_eq!(
        w.b.read(&mut [0; 8]),
        Err(Error::TcpClosed),
        "b did not see EOF after peer FIN"
    );

    w.b.close().unwrap();
    w.pump();
    assert_eq!(w.b.state, TcpState::Closed);
    w.advance(2 * SEC);
    w.drain_a();
    assert_eq!(w.a.state, TcpState::Closed, "a not CLOSED after TIME-WAIT");
}

#[test]
fn tcp_rto_in_fin_wait1_keeps_fin() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.write_a(b"data!").unwrap();
    let drop = Rc::new(Cell::new(true));
    let d = drop.clone();
    w.drop_ab = Some(Box::new(move |_| d.get()));
    w.pump();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::FinWait1);

    drop.set(false);
    w.advance(3 * SEC);
    let segs = w.drain_a();
    let got_data = segs.iter().any(|p| !p.1.is_empty());
    let got_fin = segs.iter().any(|p| has(p, FIN));
    for (seg, data) in &segs {
        w.recv_b(seg, data);
    }
    assert!(
        got_data && got_fin,
        "RTO retransmission lost part of the sequence space: data={got_data} fin={got_fin} ({} segs)",
        segs.len()
    );
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::FinWait2, TcpState::CloseWait)
    );
    assert_eq!(read_all(&mut w.b), b"data!");
}

#[test]
fn tcp_partial_ack_holds_fin_wait1() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.write_a(b"data!").unwrap();
    w.drop_ab = Some(Box::new(|_| true));
    w.pump();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::FinWait1);
    let seg = s(w.b.nxt, w.a.fin_seq, ACK, 0xffff);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.state, TcpState::FinWait1, "partial ACK moved a");
    assert!(
        w.a.timer_on,
        "timer disarmed while the FIN is still unacknowledged"
    );
}

#[test]
fn tcp_last_ack_ignores_stale_ack() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.b.close().unwrap();
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::CloseWait, TcpState::FinWait2)
    );

    w.write_a(b"bye").unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.b), b"bye", "b in FIN-WAIT-2");
    w.a.close().unwrap();
    let segs = w.drain_a();
    assert_eq!(w.a.state, TcpState::LastAck);

    let seg = s(w.b.nxt, w.a.una, ACK, 0xffff);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.state, TcpState::LastAck, "stale ACK moved a");

    for (seg, data) in &segs {
        w.recv_b(seg, data);
    }
    w.pump();
    assert_eq!(w.a.state, TcpState::Closed);
}

#[test]
fn tcp_write_after_close() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.a.close().unwrap();
    assert_eq!(w.write_a(b"x"), Err(Error::TcpClosed));
    assert_eq!(w.a.close(), Err(Error::TcpClosing));
}

#[test]
fn tcp_fast_retransmit_in_fin_wait1() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.write_a(b"lost payload").unwrap();
    w.drop_ab = Some(Box::new(|_| true));
    w.pump();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::FinWait1);
    w.drop_ab = None;

    let wnd = w.a.snd_wnd as u16;
    for _ in 0..3 {
        let seg = s(w.b.nxt, w.a.una, ACK, wnd);
        w.recv_a(&seg, &[]);
    }
    let segs = w.drain_a();
    let got_data = segs.iter().any(|p| !p.1.is_empty() && p.0.seq == w.a.una);
    let got_fin = segs.iter().any(|p| has(p, FIN));
    assert!(
        got_data && got_fin,
        "fast retransmit dead in FIN-WAIT-1: data={got_data} fin={got_fin}"
    );
}

#[test]
fn tcp_flow_control_and_zero_window_probe() {
    let mut w = new_pair(1024, 16);
    w.connect();
    let payload: Vec<u8> = (0..64).map(|i| b'A' + (i % 26) as u8).collect();
    w.write_a(&payload).unwrap();
    w.pump();
    assert_eq!(
        seq_diff(w.a.nxt, w.a.una),
        0,
        "unacked data left after pump"
    );
    assert_eq!(
        w.b.rx.buffered(),
        16,
        "b should buffer its full window of 16"
    );

    let mut got = read_all(&mut w.b);
    for _ in 0..40 {
        if got.len() >= payload.len() {
            break;
        }
        w.advance(3 * SEC);
        w.pump();
        got.extend(read_all(&mut w.b));
    }
    assert_eq!(
        got,
        payload,
        "received {}/{} bytes",
        got.len(),
        payload.len()
    );
}

#[test]
fn tcp_simultaneous_close() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.a.close().unwrap();
    w.b.close().unwrap();
    let sa = w.drain_a();
    let sb = w.drain_b();
    for (seg, data) in &sa {
        w.recv_b(seg, data);
    }
    for (seg, data) in &sb {
        w.recv_a(seg, data);
    }
    w.pump();
    w.advance(2 * SEC);
    w.drain_a();
    w.drain_b();
    assert_eq!((w.a.state, w.b.state), (TcpState::Closed, TcpState::Closed));
}

#[test]
fn tcp_mss_segmentation() {
    let mut w = new_pair(8192, 8192);
    w.connect();
    let payload: Vec<u8> = (0..5000).map(|i| i as u8).collect();
    w.write_a(&payload).unwrap();
    let mut seg_count = 0;
    for _ in 0..8 {
        for (seg, data) in w.drain_a() {
            assert!(
                data.len() <= 1460,
                "segment of {} bytes exceeds MSS 1460",
                data.len()
            );
            if !data.is_empty() {
                seg_count += 1;
            }
            w.recv_b(&seg, &data);
        }
        for (seg, data) in w.drain_b() {
            w.recv_a(&seg, &data);
        }
    }
    assert_eq!(read_all(&mut w.b), payload);
    assert!(
        seg_count >= 4,
        "expected >=4 data segments, got {seg_count}"
    );
}

#[test]
fn tcp_lossy_bulk_transfer() {
    let mut w = new_pair(4096, 4096);
    w.connect();
    let mut n_a = 0;
    let mut n_b = 0;
    w.drop_ab = Some(Box::new(move |_| {
        n_a += 1;
        n_a % 7 == 0
    }));
    w.drop_ba = Some(Box::new(move |_| {
        n_b += 1;
        n_b % 11 == 0
    }));
    let payload: Vec<u8> = (0..20000).map(|i| (i * 13) as u8).collect();
    let mut got = Vec::new();
    let mut written = 0;
    for _ in 0..400 {
        if got.len() >= payload.len() {
            break;
        }
        if written < payload.len() {
            written += w.write_a(&payload[written..]).unwrap();
        }
        w.pump();
        got.extend(read_all(&mut w.b));
        w.advance(1500 * MS);
    }
    assert_eq!(
        got,
        payload,
        "lossy transfer corrupted: {}/{}",
        got.len(),
        payload.len()
    );

    w.a.close().unwrap();
    for _ in 0..40 {
        if w.a.state == TcpState::Closed {
            break;
        }
        w.pump();
        w.advance(2 * SEC);
        w.drain_a();
        w.drain_b();
    }
    assert_eq!(w.b.state, TcpState::CloseWait);
}

#[test]
fn tcp_rx_grows_under_pressure() {
    let mut w = new_pair(8192, 512);
    w.pot_b = Budget::new(8192);
    w.b.budgeted = true;
    w.b.max_buf = 4096;

    let payload: Vec<u8> = (0..6000).map(|i| (i * 31) as u8).collect();
    let mut got = Vec::new();
    let mut written = 0;
    for _ in 0..60 {
        if got.len() >= payload.len() {
            break;
        }
        if written < payload.len() {
            written += w.write_a(&payload[written..]).unwrap_or(0);
        }
        w.pump();
        got.extend(read_all(&mut w.b));
    }
    assert_eq!(
        got,
        payload,
        "transfer incomplete: {}/{}",
        got.len(),
        payload.len()
    );
    assert!(
        w.b.rx.size() > 512,
        "rx ring never grew under pressure: {}",
        w.b.rx.size()
    );
    assert!(
        w.b.rx.size() <= 4096,
        "rx ring exceeded maxBuf: {}",
        w.b.rx.size()
    );
    // De handgemaakte ring van 512 was niet uit de pot; alleen de groei telt.
    let want = w.b.rx.size() - 512;
    assert_eq!(w.pot_b.free(), 8192 - want, "budget accounting off");

    let mut w2 = new_pair(8192, 512);
    w2.pot_b = Budget::new(0);
    w2.b.budgeted = true;
    w2.b.max_buf = 4096;
    w2.connect();
    let mut got2 = Vec::new();
    let mut written2 = 0;
    for _ in 0..60 {
        if got2.len() >= 2000 {
            break;
        }
        if written2 < 2000 {
            written2 += w2.write_a(&payload[written2..2000]).unwrap_or(0);
        }
        w2.pump();
        got2.extend(read_all(&mut w2.b));
    }
    assert_eq!(got2, payload[..2000], "empty-pot transfer incomplete");
    assert_eq!(w2.b.rx.size(), 512, "rx ring grew without budget");
}

#[test]
fn tcp_rx_grows_on_full_segments() {
    // De ijzerconditie van 18-08-2026 (LicheeRV): een SNELLE lezer draint de
    // ring tussen de segmenten door, dus free == 0 komt op aankomst nooit voor,
    // en een MSS-gekwantiseerde zender vult een venster sowieso nooit exact.
    let mut w = new_pair(32 << 10, 4096);
    w.pot_b = Budget::new(64 << 10);
    w.b.budgeted = true;
    w.b.max_buf = 16 << 10;
    w.connect();

    let payload: Vec<u8> = (0..12 << 10).map(|i| (i * 31) as u8).collect();
    let mut got = Vec::new();
    let mut written = 0;
    for _ in 0..200 {
        if got.len() >= payload.len() {
            break;
        }
        if written < payload.len() {
            written += w.write_a(&payload[written..]).unwrap_or(0);
        }
        // Per segment bezorgen en meteen lezen: de snelle lezer.
        for (seg, data) in w.drain_a() {
            w.recv_b(&seg, &data);
            got.extend(read_all(&mut w.b));
        }
        for (seg, data) in w.drain_b() {
            w.recv_a(&seg, &data);
        }
    }
    assert_eq!(
        got,
        payload,
        "transfer incomplete: {}/{}",
        got.len(),
        payload.len()
    );
    assert!(
        w.b.rx.size() > 4096,
        "rx ring never grew for a window-limited sender with a fast reader: {}",
        w.b.rx.size()
    );
    assert!(
        w.b.rx.size() <= 16 << 10,
        "rx ring exceeded maxBuf: {}",
        w.b.rx.size()
    );

    // Chatverkeer: kleine segmenten, nooit vol; geen reden om te groeien.
    let mut w2 = new_pair(32 << 10, 4096);
    w2.pot_b = Budget::new(64 << 10);
    w2.b.budgeted = true;
    w2.b.max_buf = 16 << 10;
    w2.connect();
    for _ in 0..40 {
        w2.write_a(b"ping").unwrap();
        for (seg, data) in w2.drain_a() {
            w2.recv_b(&seg, &data);
            read_all(&mut w2.b);
        }
        for (seg, data) in w2.drain_b() {
            w2.recv_a(&seg, &data);
        }
    }
    assert_eq!(w2.b.rx.size(), 4096, "rx ring grew on small segments");
}

#[test]
fn tcp_window_update_for_blocked_sender() {
    let mut w = new_pair(32 << 10, 4096);
    w.connect();
    // De zender mag precies het geadverteerde venster kwijt; daarna wacht hij.
    let payload = vec![0u8; 8 << 10];
    w.write_a(&payload).unwrap();
    for (seg, data) in w.drain_a() {
        w.recv_b(&seg, &data);
        read_all(&mut w.b); // De snelle lezer: ring leeg vóór het volgende segment.
    }
    // Zonder nieuw inkomend verkeer moet b uit zichzelf een vensterupdate emitten.
    let segs = w.drain_b();
    assert!(
        !segs.is_empty(),
        "geen window-update voor een geblokkeerde zender"
    );
    let last = segs.last().unwrap();
    let wnd = usize::from(last.0.wnd) << w.b.rcv_ws;
    assert!(
        wnd >= w.b.peer_mss,
        "update adverteert geen bruikbaar venster: {wnd}"
    );
}

#[test]
fn tcp_rx_grows_on_a_jumbo_link_with_a_window_limited_sender() {
    // Het slot-LAN van HopOS (30-09-2026): MSS 65495, de ontvangstring op de
    // vloer van 16 KiB. De zender kan nooit een vol segment sturen zolang
    // ons venster kleiner is dan zijn MSS, en een snelle lezer houdt de ring
    // leeg; zonder de venster-trigger bleef de ring voorgoed 16 KiB.
    let mut a = TcpConn::with_rings(256 << 10, 256 << 10).unwrap();
    let mut b = TcpConn::with_rings(16 << 10, 16 << 10).unwrap();
    a.open_active(1000, 65495, 0);
    b.open_passive(5000, 65495, 0);
    let mut w = Wire {
        a,
        b,
        pot_a: Budget::new(0),
        pot_b: Budget::new(1 << 20),
        now: HOUR,
        drop_ab: None,
        drop_ba: None,
    };
    w.b.budgeted = true;
    w.b.max_buf = 256 << 10;
    w.connect();

    let payload: Vec<u8> = (0..512 << 10).map(|i| (i * 31) as u8).collect();
    let mut got = Vec::new();
    let mut written = 0;
    let mut buf = vec![0u8; 70 << 10];
    for _ in 0..400 {
        if got.len() >= payload.len() {
            break;
        }
        if written < payload.len() {
            written += w.write_a(&payload[written..]).unwrap_or(0);
        }
        // Jumbo-segmenten per stuk bezorgen en meteen lezen.
        let now = w.now;
        while let Some(seg) = w.a.emit(&mut buf, now) {
            let data = buf[..seg.len].to_vec();
            w.recv_b(&seg, &data);
            got.extend(read_all(&mut w.b));
        }
        while let Some(seg) = w.b.emit(&mut buf, now) {
            let data = buf[..seg.len].to_vec();
            w.recv_a(&seg, &data);
        }
    }
    assert_eq!(got.len(), payload.len(), "transfer incomplete");
    assert_eq!(got, payload);
    assert!(
        w.b.rx.size() >= 64 << 10,
        "rx ring stayed near the floor on a jumbo link: {}",
        w.b.rx.size()
    );
}

#[test]
fn tcp_tx_grows_when_peer_offers_window() {
    let mut w = new_pair(512, 16384);
    w.pot_a = Budget::new(16384);
    w.a.budgeted = true;
    w.a.max_buf = 8192;
    w.connect();
    let n = w.write_a(&[0u8; 4096]).unwrap();
    assert!(n > 512, "tx ring did not grow on demand: wrote {n}");
    assert!(
        w.a.tx.size() <= 8192,
        "tx ring exceeded maxBuf: {}",
        w.a.tx.size()
    );
}

#[test]
fn tcp_half_open_gives_up() {
    let mut w = new_pair(1024, 1024);
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], SYN),
        "expected one SYN, got {segs:?}"
    );
    w.recv_b(&segs[0].0, &segs[0].1);
    let mut synacks = 0;
    let mut rsts = 0;
    for _ in 0..40 {
        if w.b.state == TcpState::Closed {
            break;
        }
        for p in w.drain_b() {
            if has(&p, SYN) {
                synacks += 1;
            } else if has(&p, RST) {
                rsts += 1;
            }
        }
        w.advance(2 * SEC);
    }
    assert_eq!(
        w.b.state,
        TcpState::Closed,
        "half-open embryo never gave up after {synacks} SYN|ACKs"
    );
    assert_eq!(synacks, 1 + usize::from(TCP_MAX_RETRIES_HANDSHAKE));
    assert_eq!(rsts, 1, "expected exactly one parting RST");
}

#[test]
fn tcp_dead_peer_gives_up() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.write_a(b"into the void").unwrap();
    w.drop_ab = Some(Box::new(|_| true));
    w.drop_ba = Some(Box::new(|_| true));
    for _ in 0..60 {
        if w.a.state == TcpState::Closed {
            break;
        }
        w.pump();
        w.advance(90 * SEC);
    }
    assert_eq!(
        w.a.state,
        TcpState::Closed,
        "sender to a dead peer never gave up"
    );
}

#[test]
fn tcp_zero_window_peer_stays_alive() {
    let mut w = new_pair(1024, 16);
    w.connect();
    w.write_a(&[0u8; 64]).unwrap();
    w.pump();
    for _ in 0..3 * usize::from(TCP_MAX_RETRIES_DATA) {
        w.advance(90 * SEC);
        w.pump();
    }
    assert_eq!(
        w.a.state,
        TcpState::Established,
        "live zero-window peer was killed"
    );
}

#[test]
fn tcp_full_close_deadline_kan_niet_worden_vernieuwd() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    // Zet de peer in persist en laat data plus FIN achter het dichte venster wachten.
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 0);
    w.recv_a(&seg, &[]);
    w.write_a(b"blijft achter nul").unwrap();
    w.a.close().unwrap();
    w.a.abandon_read(w.now, &mut w.pot_a);
    let original = w.a.close_deadline;

    for _ in 0..4 {
        w.advance(4 * SEC);
        w.drain_a();
        assert_ne!(w.a.state, TcpState::Closed, "full close gaf te vroeg op");
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 0);
        w.recv_a(&seg, &[]);
        w.a.abandon_read(w.now, &mut w.pot_a); // Een dubbele close rekt de termijn niet.
        assert_eq!(w.a.close_deadline, original, "close-deadline verschoof");
    }

    w.now = original + 1;
    let segs = w.drain_a();
    assert!(
        w.a.state == TcpState::Closed && w.a.reset,
        "zero-window-peer hield full close voorbij de absolute termijn: state={} reset={}",
        w.a.state,
        w.a.reset
    );
    assert!(
        segs.iter().any(|p| has(p, RST)),
        "absolute full-close timeout gaf op zonder RST"
    );
}

#[test]
fn tcp_close_wait_ruimt_alleen_inactiviteit_op() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.b.close().unwrap();
    w.pump();
    assert!(
        w.a.state == TcpState::CloseWait && w.a.close_deadline != 0,
        "peer-FIN gaf state={} deadline={}",
        w.a.state,
        w.a.close_deadline
    );
    // Activiteit vernieuwt de idle-termijn; louter tijd en duplicate ACKs niet.
    let first = w.a.close_deadline;
    w.advance(MIN);
    w.a.touch_close_wait(w.now);
    assert!(
        w.a.close_deadline > first,
        "app-activiteit vernieuwde de CLOSE-WAIT-termijn niet"
    );
    let refreshed = w.a.close_deadline;
    let seg = s(w.a.rcv_nxt, w.a.una, ACK, w.a.snd_wnd as u16);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.close_deadline, refreshed,
        "duplicate ACK vernieuwde de CLOSE-WAIT-termijn"
    );

    w.now = refreshed + 1;
    let segs = w.drain_a();
    assert!(
        w.a.state == TcpState::Closed && w.a.reset,
        "vergeten CLOSE-WAIT werd niet gereapt"
    );
    assert!(
        segs.iter().any(|p| has(p, RST)),
        "CLOSE-WAIT-timeout gaf op zonder RST"
    );

    let mut idle = new_pair(8 << 10, 8 << 10);
    idle.connect();
    idle.advance(10 * TCP_CLOSE_WAIT_DUR);
    idle.drain_a();
    assert!(
        idle.a.state == TcpState::Established && idle.a.next_deadline().is_none(),
        "legitiem idle ESTABLISHED werd geraakt: state={} deadline={:?}",
        idle.a.state,
        idle.a.next_deadline()
    );
}

#[test]
fn tcp_full_close_vervangt_bijna_verlopen_close_wait_deadline() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.b.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::CloseWait);
    w.now = w.a.close_deadline - 5 * SEC;
    let old = w.a.close_deadline;
    w.a.close().unwrap();
    w.a.abandon_read(w.now, &mut w.pot_a);
    let want = w.now + TCP_FULL_CLOSE_DUR;
    assert!(
        w.a.close_deadline == want && w.a.close_deadline > old,
        "full Close deadline={}, want verse absolute deadline {want} (oude={old})",
        w.a.close_deadline
    );
    assert!(
        !w.a.lifecycle_expired(old + 1),
        "oude CLOSE-WAIT-deadline verkortte de full-Close-grace"
    );
    assert!(
        w.a.lifecycle_expired(want),
        "verse full-Close-deadline werd niet absoluut afgedwongen"
    );
}

#[test]
fn tcp_rst_kills_embryo() {
    let mut w = new_pair(1024, 1024);
    let segs = w.drain_a();
    w.recv_b(&segs[0].0, &segs[0].1);
    w.drain_b();
    assert_eq!(w.b.state, TcpState::SynRcvd);
    let seg = s(w.b.rcv_nxt, 0, RST, 0);
    w.recv_b(&seg, &[]);
    assert_eq!(
        w.b.state,
        TcpState::Closed,
        "RST in SYN-RCVD left the embryo alive"
    );
}

#[test]
fn tcp_sequence_wraparound() {
    let mut w = new_pair_iss(8192, 8192, 0xffff_ff00, 0xffff_fe80, 0);
    w.connect();
    let payload: Vec<u8> = (0..20000).map(|i| (i * 11) as u8).collect();
    let mut got = Vec::new();
    let mut written = 0;
    for _ in 0..60 {
        if got.len() >= payload.len() {
            break;
        }
        if written < payload.len() {
            written += w.write_a(&payload[written..]).unwrap();
        }
        w.pump();
        got.extend(read_all(&mut w.b));
    }
    assert_eq!(got, payload, "transfer across seq wrap corrupted");
    assert!(
        w.a.nxt < w.a.iss,
        "test did not actually cross the wrap; adjust iss"
    );
    w.a.close().unwrap();
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::FinWait2, TcpState::CloseWait)
    );
}

#[test]
fn tcp_blind_rst_challenge_ack() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    let seg = s(w.a.rcv_nxt + 100, 0, RST, 0);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.state,
        TcpState::Established,
        "in-window RST killed the connection"
    );
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], ACK) && segs[0].0.ack == w.a.rcv_nxt,
        "no challenge ACK on blind RST: {segs:?}"
    );
    let seg = s(w.a.rcv_nxt.wrapping_sub(5000), 0, RST, 0);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.state,
        TcpState::Established,
        "out-of-window RST killed the connection"
    );
    let seg = s(w.a.rcv_nxt, 0, RST, 0);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.state, TcpState::Closed, "exact RST ignored");
}

#[test]
fn tcp_syn_in_established_challenge() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    let before = w.a.rcv_nxt;
    let seg = Seg {
        seq: w.a.rcv_nxt,
        flags: SYN,
        mss: 100,
        ws_ok: true,
        ws: 7,
        ..Seg::default()
    };
    w.recv_a(&seg, &[]);
    assert!(
        w.a.state == TcpState::Established && w.a.rcv_nxt == before,
        "mid-connection SYN changed state"
    );
    assert!(
        w.a.peer_mss != 100 && w.a.snd_ws != 7,
        "mid-connection SYN options were honored"
    );
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], ACK),
        "no challenge ACK on mid-connection SYN"
    );
}

#[test]
fn tcp_duplicate_data_re_acked() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK | PSH, 0xffff);
    w.recv_a(&seg, b"once");
    w.drain_a();
    w.recv_a(&seg, b"once");
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], ACK) && segs[0].0.ack == w.a.rcv_nxt,
        "duplicate data not re-acked: {segs:?}"
    );
    assert_eq!(read_all(&mut w.a), b"once", "duplicate was buffered twice");
}

#[test]
fn tcp_out_of_order_dup_ack() {
    let mut w = new_pair(4096, 4096);
    w.connect();
    let seg = s(w.a.rcv_nxt + 1460, w.a.nxt, ACK | PSH, 0xffff);
    w.recv_a(&seg, b"future data");
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && segs[0].0.ack == w.a.rcv_nxt && segs[0].1.is_empty(),
        "no immediate dup-ACK on out-of-order data: {segs:?}"
    );
    assert_eq!(
        w.a.rx.buffered(),
        0,
        "out-of-order data was buffered in an in-order-only receiver"
    );
}

#[test]
fn tcp_ack_beyond_nxt_ignored() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    let una = w.a.una;
    let seg = s(w.b.nxt, w.a.nxt + 1000, ACK, 0xffff);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.una, una, "future ACK advanced una");
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], ACK),
        "future ACK not answered"
    );
}

#[test]
fn tcp_peer_window_shrink_clamped() {
    let mut w = new_pair(4096, 4096);
    w.connect();
    let seg = s(w.b.nxt, w.a.nxt, ACK, 4);
    w.recv_a(&seg, &[]);
    w.write_a(b"twelve bytes").unwrap();
    let mut sent: usize = w.drain_a().iter().map(|p| p.1.len()).sum();
    assert_eq!(sent, 4, "sent {sent} bytes into a 4-byte window");
    let seg = s(w.b.nxt, w.a.nxt, ACK, 0xffff);
    w.recv_a(&seg, &[]);
    sent += w.drain_a().iter().map(|p| p.1.len()).sum::<usize>();
    assert_eq!(
        sent,
        b"twelve bytes".len(),
        "did not resume after window reopened"
    );
}

#[test]
fn tcp_tiny_mss() {
    let mut w = new_pair(4096, 4096);
    let segs = w.drain_a();
    w.recv_b(&segs[0].0, &segs[0].1);
    let mut sa = w.drain_b();
    assert!(sa.len() == 1 && has(&sa[0], SYN), "expected SYN|ACK");
    sa[0].0.mss = 100;
    w.recv_a(&sa[0].0, &[]);
    w.pump();
    assert_eq!(w.a.state, TcpState::Established);
    w.write_a(&[0u8; 1000]).unwrap();
    for p in w.drain_a() {
        assert!(
            p.1.len() <= 100,
            "segment of {} bytes exceeds negotiated MSS 100",
            p.1.len()
        );
    }
}

#[test]
fn tcp_window_scaling_carries_large_window() {
    let mut w = new_pair_iss(512 << 10, 512 << 10, 1000, 5000, 4);
    w.connect();
    assert!(
        w.a.ws_on && w.b.ws_on && w.a.snd_ws == 4 && w.b.snd_ws == 4,
        "WS not negotiated: a on={} shift={}, b on={} shift={}",
        w.a.ws_on,
        w.a.snd_ws,
        w.b.ws_on,
        w.b.snd_ws
    );
    assert!(
        w.b.snd_wnd > 0xffff,
        "b sees a window of {}, want > 65535 through scaling",
        w.b.snd_wnd
    );
}

#[test]
fn tcp_time_wait_re_acks_fin() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.a.close().unwrap();
    w.pump();
    w.b.close().unwrap();
    let segs = w.drain_b();
    for (seg, data) in &segs {
        w.recv_a(seg, data);
    }
    w.drain_a();
    assert_eq!(w.a.state, TcpState::TimeWait);
    for (seg, data) in &segs {
        w.recv_a(seg, data);
    }
    let re = w.drain_a();
    assert!(
        re.len() == 1 && has(&re[0], ACK),
        "TIME-WAIT did not re-ACK a duplicate FIN: {re:?}"
    );
}

#[test]
fn tcp_close_in_syn_sent() {
    let mut w = new_pair(1024, 1024);
    w.drain_a();
    assert_eq!(w.a.state, TcpState::SynSent);
    w.a.close().unwrap();
    assert_eq!(
        w.a.state,
        TcpState::Closed,
        "close in SYN-SENT left the connection"
    );
    assert!(w.drain_a().is_empty(), "close in SYN-SENT emitted segments");
    assert_eq!(w.a.close(), Err(Error::TcpClosed));
}

#[test]
fn tcp_refused_dial_sees_rst() {
    let mut w = new_pair(1024, 1024);
    let segs = w.drain_a();
    let seg = s(0, segs[0].0.seq + 1, RST | ACK, 0);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.state, TcpState::Closed);
    assert!(
        w.a.refused,
        "refused flag not set: the dialer cannot tell 'no' from 'silence'"
    );

    let mut w2 = new_pair(1024, 1024);
    let s2 = w2.drain_a();
    let seg = s(0, s2[0].0.seq + 99, RST | ACK, 0);
    w2.recv_a(&seg, &[]);
    assert_eq!(w2.a.state, TcpState::SynSent, "bogus RST killed SYN-SENT");
}

#[test]
fn tcp_abort_sends_single_rst() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.a.abort();
    let segs = w.drain_a();
    assert!(
        segs.len() == 1 && has(&segs[0], RST),
        "abort emitted {segs:?}, want one RST"
    );
    assert!(w.drain_a().is_empty(), "aborted connection kept talking");
    let seg = s(w.b.rcv_nxt, w.b.nxt, RST | ACK, 0);
    w.recv_b(&seg, &[]);
    assert_eq!(w.b.state, TcpState::Closed);
}

#[test]
fn tcp_half_close_keeps_receiving() {
    let mut w = new_pair(4096, 4096);
    w.connect();
    w.write_a(b"GET /").unwrap();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::FinWait2, TcpState::CloseWait)
    );
    assert_eq!(read_all(&mut w.b), b"GET /");
    w.write_b(b"HTTP/1.1 200 OK").unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.a), b"HTTP/1.1 200 OK", "a after half-close");
    w.b.close().unwrap();
    w.pump();
    w.advance(2 * SEC);
    w.drain_a();
    assert_eq!((w.a.state, w.b.state), (TcpState::Closed, TcpState::Closed));
}

#[test]
fn tcp_tx_behoudt_groei_tot_close() {
    let floor_tx = crate::stack::TCP_FLOOR_TX;
    let mut w = new_pair(floor_tx, 32 << 10);
    w.pot_a = Budget::new(256 << 10);
    assert!(
        w.pot_a.reserve(2 * floor_tx),
        "pot te klein voor de handgemaakte ringen"
    );
    w.a.budgeted = true;
    w.a.max_buf = 32 << 10;
    w.connect();
    let base = w.pot_a.used;

    let payload: Vec<u8> = (0..16 << 10).map(|i| i as u8).collect();
    let n = w.write_a(&payload).unwrap();
    assert_eq!(n, payload.len(), "de ring hoort naar maxBuf te groeien");
    assert!(
        w.a.tx.size() > floor_tx,
        "de zendring is niet gegroeid; deze test meet dan niets"
    );
    w.pump();
    assert_eq!(
        w.a.tx.buffered(),
        0,
        "na de pump staat er nog onbevestigde data"
    );
    assert!(
        w.a.tx.size() > floor_tx,
        "zendring is na de laatste ACK teruggevallen naar {} bytes",
        w.a.tx.size()
    );
    assert!(
        w.pot_a.used > base,
        "pot draagt {} bytes, wil meer dan basis {base}",
        w.pot_a.used
    );
}

#[test]
fn tcp_out_of_window_ack_raakt_de_machine_niet() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let before = w.a.snd_wnd;
    let seg = s(w.a.rcv_nxt + w.a.rx.free() as u32 + 999, w.a.nxt, ACK, 1);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.snd_wnd, before,
        "out-of-window segment verzette het zendvenster"
    );
    assert!(
        w.a.need_ack,
        "geen verse ACK klaargezet voor een onacceptabel segment"
    );
}

#[test]
fn tcp_adv_edge_volgt_de_draad() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let c = &mut w.a;
    assert!(
        !(c.ws_on && c.rcv_ws != 0),
        "deze test wil een verbinding zonder effectieve schaling"
    );
    c.rx.grow(128 << 10).unwrap();
    c.adv_edge = 0;
    c.advertised_wnd();
    assert_eq!(
        seq_diff(c.adv_edge, c.rcv_nxt),
        0xffff,
        "advEdge belooft meer dan op de draad stond"
    );
}

#[test]
fn tcp_reset_is_geen_eof() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_b(b"half antwoord").unwrap();
    w.pump();
    let seg = s(w.a.rcv_nxt, w.a.nxt, RST, 0);
    w.recv_a(&seg, &[]);
    let r = w.a.read(&mut [0; 64]);
    assert_eq!(
        r,
        Err(Error::Reset),
        "read na RST hoort een reset-fout te zijn, geen net einde"
    );
    assert_eq!(w.write_a(b"x"), Err(Error::Reset));
}

#[test]
fn tcp_future_ack_dropt_hele_segment() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let before = w.a.rcv_nxt;
    let seg = s(w.a.rcv_nxt, w.a.nxt + 1000, ACK, 1024);
    w.recv_a(&seg, b"smokkelwaar");
    assert!(
        w.a.rcv_nxt == before && w.a.rx.buffered() == 0,
        "data van een future-ACK-segment is verwerkt"
    );
    assert!(w.a.need_ack, "geen correctie-ACK klaargezet");
}

#[test]
fn tcp_syn_rcvd_eist_echte_bevestiging() {
    let mut w = new_pair(8 << 10, 8 << 10);
    for (seg, data) in w.drain_a() {
        w.recv_b(&seg, &data);
    }
    w.drain_b();
    assert_eq!(w.b.state, TcpState::SynRcvd);
    w.b.retries = 3;
    let seg = s(w.b.rcv_nxt, w.b.iss, ACK, 1024);
    w.recv_b(&seg, &[]);
    assert_eq!(
        w.b.retries, 3,
        "een ongeldige ACK was het eeuwige levensteken"
    );
    assert!(
        w.b.rst.set && !w.b.rst.with_ack && w.b.rst.seq == w.b.iss,
        "geen <SEQ=SEG.ACK><CTL=RST> klaargezet voor de ongeldige ACK"
    );
    assert_eq!(w.b.state, TcpState::SynRcvd);
}

#[test]
fn tcp_data_voorbij_de_rand_wordt_getrimd() {
    let mut w = new_pair(1 << 10, 8 << 10);
    w.pot_a = Budget::new(256 << 10);
    w.pot_a.reserve(2 << 10);
    w.a.budgeted = true;
    w.a.max_buf = 64 << 10;
    w.connect();
    let promised = seq_diff(w.a.adv_edge, w.a.rcv_nxt);
    assert!(
        promised > 0 && promised <= 1 << 10,
        "test-aanname stuk: belofte is {promised} bytes"
    );
    let promised = promised as usize;
    let oversized: Vec<u8> = (0..2 * promised).map(|i| i as u8).collect();
    let before = w.a.rcv_nxt;
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 4096);
    w.recv_a(&seg, &oversized);
    assert_eq!(
        seq_diff(w.a.rcv_nxt, before) as usize,
        promised,
        "de rand is geen rand"
    );
    assert_eq!(w.a.rx.buffered(), promised);
}

#[test]
fn tcp_fin_op_de_rand_wordt_geknipt() {
    let mut w = new_pair(2 << 10, 8 << 10);
    w.connect();
    let promised = seq_diff(w.a.adv_edge, w.a.rcv_nxt);
    assert!(promised > 0, "test-aanname stuk: belofte is {promised}");
    let data = vec![0u8; promised as usize];
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK | FIN, 4096);
    w.recv_a(&seg, &data);
    assert!(
        !w.a.fin_rcvd,
        "de FIN lag één byte buiten het venster en is toch geaccepteerd"
    );
    assert_eq!(
        w.a.rx.buffered(),
        promised as usize,
        "de data zelf hoort er wél in"
    );

    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK | FIN, 4096);
    w.recv_a(&seg, &[]);
    assert!(
        !w.a.fin_rcvd,
        "kale FIN op een dicht venster is geaccepteerd"
    );

    read_all(&mut w.a);
    w.drain_a();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK | FIN, 4096);
    w.recv_a(&seg, &[]);
    assert!(
        w.a.fin_rcvd,
        "de herhaalde FIN binnen het verse venster is geweigerd"
    );
}

#[test]
fn tcp_syn_venster_is_een_belofte() {
    let mut w = new_pair(8 << 10, 1 << 10);
    for (seg, data) in w.drain_a() {
        w.recv_b(&seg, &data);
    }
    let syn_ack = w.drain_b();
    assert!(
        syn_ack.len() == 1 && has(&syn_ack[0], SYN),
        "verwachtte de SYN-ACK"
    );
    let promise = u32::from(syn_ack[0].0.wnd);
    for (seg, data) in &syn_ack {
        w.recv_a(seg, data);
    }
    for (seg, data) in w.drain_a() {
        w.recv_b(&seg, &data);
    }
    assert!(
        w.b.adv_set && seq_diff(w.b.adv_edge, w.b.rcv_nxt) == i64::from(promise),
        "de SYN-ACK-belofte is niet vastgelegd"
    );
    let seg = s(w.b.rcv_nxt, w.b.nxt, ACK, 4096);
    w.recv_b(&seg, &vec![0u8; promise as usize]);
    assert_eq!(
        read_all(&mut w.b).len(),
        promise as usize,
        "b las niet de volle belofte"
    );
    let voor = w.b.rcv_nxt;
    let seg = s(w.b.rcv_nxt, w.b.nxt, ACK, 4096);
    w.recv_b(&seg, b"smokkel");
    assert!(
        w.b.rcv_nxt == voor && read_all(&mut w.b).is_empty(),
        "data voorbij de SYN-beloofde rand werd geaccepteerd"
    );
}

#[test]
fn tcp_voortgangsloze_acks_pinnen_niet() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"data die nooit aangenomen wordt").unwrap();
    w.drain_a();
    for _ in 0..64 {
        if w.a.state == TcpState::Closed {
            break;
        }
        w.advance(MIN);
        w.drain_a();
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 8192);
        w.recv_a(&seg, &[]);
    }
    assert_eq!(
        w.a.state,
        TcpState::Closed,
        "64 voortgangsloze ACKs later leeft de verbinding nog"
    );
    assert!(
        w.a.reset,
        "het einde hoort een luide opgave te zijn (reset)"
    );
}

#[test]
fn tcp_zero_window_persist_blijft_leven() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 0);
    w.recv_a(&seg, &[]);
    w.write_a(b"wacht maar").unwrap();
    for _ in 0..20 {
        w.advance(MIN);
        w.drain_a();
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 0);
        w.recv_a(&seg, &[]);
    }
    assert_ne!(
        w.a.state,
        TcpState::Closed,
        "een levende zero-window-peer is doodverklaard"
    );
}

#[test]
fn tcp_max_buf_klemt_de_verbinding() {
    let mut w = new_pair(4 << 10, 32 << 10);
    w.pot_a = Budget::new(1 << 20);
    w.pot_a.reserve(2 * (4 << 10));
    w.a.budgeted = true;
    w.a.max_buf = 16 << 10;
    w.connect();
    let _ = w.write_a(&vec![0u8; 64 << 10]);
    let promised = seq_diff(w.a.adv_edge, w.a.rcv_nxt);
    if promised > 0 {
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 8192);
        w.recv_a(&seg, &vec![0u8; promised as usize]);
    }
    // Sinds 04-09-2026 klemt max_buf elke ring apart.
    assert!(
        w.a.rx.size() <= 16 << 10 && w.a.tx.size() <= 16 << 10,
        "ringen rx {} / tx {} bytes, maxBuf is {} per ring",
        w.a.rx.size(),
        w.a.tx.size(),
        16 << 10
    );
}

#[test]
fn tcp_syn_rst_opent_geen_embryo() {
    let mut w = new_pair(8 << 10, 8 << 10);
    let seg = s(42, 0, SYN | RST, 1024);
    w.recv_b(&seg, &[]);
    assert_eq!(
        w.b.state,
        TcpState::Closed,
        "b na een SYN|RST, wil CLOSED (genegeerd)"
    );
    assert!(
        w.drain_b().is_empty(),
        "b antwoordde op een SYN|RST, wil stilte"
    );
}

#[test]
fn tcp_acceptability_volgt_de_belofte() {
    let mut w = new_pair(1 << 10, 8 << 10);
    w.connect();
    let promised = seq_diff(w.a.adv_edge, w.a.rcv_nxt);
    assert!(promised > 0, "test-aanname stuk: geen belofte");
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 4096);
    w.recv_a(&seg, &vec![0u8; promised as usize]);
    read_all(&mut w.a);
    let before = w.a.snd_wnd;
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 1);
    w.recv_a(&seg, b"voorbij de belofte");
    assert_eq!(
        w.a.rx.buffered(),
        0,
        "data buiten de belofte is geabsorbeerd"
    );
    assert_eq!(
        w.a.snd_wnd, before,
        "segment buiten de belofte verzette het zendvenster"
    );
    assert!(w.a.need_ack, "geen correctie-ACK klaargezet");
}

#[test]
fn tcp_stale_zero_window_reset_geen_retries() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"data").unwrap();
    w.pump();
    w.a.retries = 5;
    w.a.wl1 = w.a.rcv_nxt + 1000;
    let seg = s(w.a.rcv_nxt, w.a.una, ACK, 0);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.retries, 5,
        "retries na een afgewezen zero-window-update"
    );
    assert_ne!(w.a.snd_wnd, 0, "de afgewezen update is tóch toegepast");
}

#[test]
fn tcp_herhaalde_fin_herstart_time_wait() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.a.close().unwrap();
    w.pump();
    w.b.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::TimeWait);
    w.advance(TCP_TIME_WAIT_DUR - 100 * MS);
    let dup_fin = s(w.a.rcv_nxt - 1, w.a.nxt, ACK | FIN, 1024);
    w.recv_a(&dup_fin, &[]);
    w.drain_a();
    w.advance(500 * MS);
    w.drain_a();
    assert_eq!(
        w.a.state,
        TcpState::TimeWait,
        "de herhaalde FIN herstartte TIME-WAIT niet"
    );
    w.advance(TCP_TIME_WAIT_DUR);
    w.drain_a();
    assert_eq!(w.a.state, TcpState::Closed);
}

#[test]
fn tcp_vreemde_fin_rekt_time_wait_niet() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.a.close().unwrap();
    w.pump();
    w.b.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::TimeWait);
    w.advance(TCP_TIME_WAIT_DUR - 100 * MS);
    let rogue = s(w.a.rcv_nxt - 100, w.a.nxt, ACK | FIN, 1024);
    w.recv_a(&rogue, &[]);
    w.drain_a();
    w.advance(500 * MS);
    w.drain_a();
    assert_eq!(
        w.a.state,
        TcpState::Closed,
        "een vreemde FIN rekte TIME-WAIT op"
    );
}

#[test]
fn tcp_verloren_probe_herstelt_bij_venster_opening() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 0);
    w.recv_a(&seg, &[]);
    w.write_a(b"hallo").unwrap();
    w.drain_a();
    let una = w.a.una;
    w.advance(MIN);
    let segs = w.drain_a();
    assert!(
        !segs.is_empty() && segs[0].1.len() == 1,
        "verwachtte één probe-byte, kreeg {segs:?}"
    );
    let seg = s(w.a.rcv_nxt, una, ACK, 1024);
    w.recv_a(&seg, &[]);
    let segs = w.drain_a();
    assert!(
        !segs.is_empty(),
        "geen hertransmissie na het openen van het venster"
    );
    assert_eq!(
        segs[0].0.seq, una,
        "de verloren probe-byte blijft anders een gat"
    );
}

#[test]
fn tcp_hertransmissie_bemeet_geen_rtt() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"hallo").unwrap();
    assert_eq!(w.drain_a().len(), 1, "verwachtte het datasegment");
    assert!(
        w.a.timing,
        "de eerste verzending hoort juist wél bemeten te worden"
    );
    w.advance(2 * SEC);
    let segs = w.drain_a();
    assert!(
        !segs.is_empty() && !segs[0].1.is_empty(),
        "geen hertransmissie"
    );
    assert!(
        !w.a.timing,
        "de hertransmissie startte een RTT-meting op oude ruimte"
    );
}

#[test]
fn tcp_persist_vervuilt_de_rto_niet() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 0);
    w.recv_a(&seg, &[]);
    w.write_a(b"wacht maar").unwrap();
    let rto_voor = w.a.rto;
    w.drain_a();
    for _ in 0..6 {
        w.advance(MIN);
        w.drain_a();
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 0);
        w.recv_a(&seg, &[]);
    }
    assert_eq!(w.a.rto, rto_voor, "zes probes lieten de RTO groeien");
    let seg = s(w.a.rcv_nxt, w.a.una, ACK, 1024);
    w.recv_a(&seg, &[]);
    assert_eq!(
        w.a.persist_backoff, 0,
        "persistBackoff na de venster-opening"
    );
}

#[test]
fn tcp_venster_shrink_is_geen_dup_ack() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"hallo").unwrap();
    w.drain_a();
    for _ in 0..3 {
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, 512);
        w.recv_a(&seg, &[]);
    }
    for p in w.drain_a() {
        assert!(
            p.1.is_empty(),
            "fast retransmit vuurde op een venster-shrink plus twee duplicaten"
        );
    }
    assert_eq!(w.a.dupacks, 2, "de shrink telt niet mee");
}

#[test]
fn tcp_handshake_neemt_geen_oude_rst_mee() {
    let mut w = new_pair(8 << 10, 8 << 10);
    let segs = w.drain_a();
    assert!(segs.len() == 1 && has(&segs[0], SYN), "verwachtte de SYN");
    let iss = w.a.iss;
    let seg = s(9999, iss + 5, ACK, 1024);
    w.recv_a(&seg, &[]);
    assert!(w.a.rst.set, "de ongeldige ACK zette geen pending RST");
    let seg = Seg {
        mss: 1460,
        ..s(5000, iss + 1, SYN | ACK, 1024)
    };
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.state, TcpState::Established);
    for p in w.drain_a() {
        assert!(
            !has(&p, RST),
            "SYN-SENT: het eerste segment van de geslaagde verbinding is een RST"
        );
    }

    let mut w2 = new_pair(8 << 10, 8 << 10);
    let syn = w2.drain_a().remove(0);
    w2.recv_b(&syn.0, &syn.1);
    let segs = w2.drain_b();
    assert!(
        segs.len() == 1 && has(&segs[0], SYN),
        "verwachtte de SYN-ACK"
    );
    let seg = s(w2.b.rcv_nxt, w2.b.iss, ACK, 1024);
    w2.recv_b(&seg, &[]);
    assert!(
        w2.b.rst.set,
        "de ongeldige ACK zette geen pending RST bij de passieve kant"
    );
    let seg = s(w2.b.rcv_nxt, w2.b.iss + 1, ACK, 1024);
    w2.recv_b(&seg, &[]);
    assert_eq!(w2.b.state, TcpState::Established);
    for p in w2.drain_b() {
        assert!(
            !has(&p, RST),
            "SYN-RCVD: het eerste segment van de geslaagde verbinding is een RST"
        );
    }
}

#[test]
fn tcp_niet_duplicaat_breekt_de_reeks() {
    let opzet = || {
        let mut w = new_pair(8 << 10, 8 << 10);
        w.connect();
        w.write_a(b"hallo").unwrap();
        w.drain_a();
        let wnd = w.a.snd_wnd as u16;
        (w, wnd)
    };
    let (mut w, wnd) = opzet();
    for win in [wnd, wnd, wnd / 2, wnd / 2] {
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, win);
        w.recv_a(&seg, &[]);
    }
    for p in w.drain_a() {
        assert!(
            p.1.is_empty(),
            "fast retransmit vuurde terwijl de shrink de reeks had moeten breken"
        );
    }
    assert_eq!(w.a.dupacks, 1, "reeks gebroken door de shrink");

    let (mut w, wnd) = opzet();
    for flags in [ACK, ACK, ACK | FIN] {
        let seg = s(w.a.rcv_nxt, w.a.una, flags, wnd);
        w.recv_a(&seg, &[]);
    }
    assert_eq!(w.a.dupacks, 0, "RFC 5681 sluit SYN/FIN uit");
}

#[test]
fn tcp_oude_ack_breekt_de_reeks() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"aaaa").unwrap();
    let oud = w.a.una;
    w.pump();
    assert_ne!(
        w.a.una, oud,
        "geen voortgang; het harnas bezorgde de eerste write niet"
    );
    w.write_a(b"bbbb").unwrap();
    w.drain_a();
    let wnd = w.a.snd_wnd as u16;
    let una = w.a.una;
    for ack in [una, una, oud, una] {
        let seg = s(w.a.rcv_nxt, ack, ACK, wnd);
        w.recv_a(&seg, &[]);
    }
    for p in w.drain_a() {
        assert!(
            p.1.is_empty(),
            "fast retransmit vuurde terwijl het oude ACK de reeks had moeten breken"
        );
    }
    assert_eq!(w.a.dupacks, 1, "reeks gebroken door het oude ACK");
}

#[test]
fn tcp_advertentie_overleeft_de_wrap() {
    let iss_b = !8192u32;
    let mut w = new_pair_iss(8 << 10, 8 << 10, 1000, iss_b, 0);
    w.connect();
    w.write_b(&[0u8; 100]).unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.a).len(), 100);
    assert_eq!(
        w.a.rcv_wnd(),
        8192 - 100,
        "de nul-rand telt kennelijk als unset"
    );
}

#[test]
fn tcp_kale_fin_respecteert_het_venster() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let seg = s(w.a.rcv_nxt, w.a.nxt, ACK, 0);
    w.recv_a(&seg, &[]);
    w.a.close().unwrap();
    for p in w.drain_a() {
        assert!(
            !has(&p, FIN),
            "de kale FIN ging door een dicht venster zonder probe"
        );
    }
    w.advance(MIN);
    let fin = w.drain_a().iter().any(|p| has(p, FIN));
    assert!(
        fin,
        "de FIN kwam ook via de persist-probe nooit: sluiten op een dicht venster is een deadlock"
    );
}

#[test]
fn tcp_groei_boekt_de_piek() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    let mut pot = Budget::new(2 * (8 << 10) + (12 << 10));
    pot.reserve(2 * (8 << 10));
    w.a.budgeted = true;
    w.a.max_buf = 64 << 10;
    assert!(
        !w.a.grow_rx(&mut pot),
        "growRing groeide terwijl de pot de piek (oud+nieuw) niet draagt"
    );
    pot.total = 2 * (8 << 10) + (16 << 10);
    assert!(
        w.a.grow_rx(&mut pot),
        "growRing weigerde terwijl de piek past"
    );
    assert_eq!(
        pot.used,
        (8 << 10) + (16 << 10),
        "tx + nieuwe rx; de oude rx is terug"
    );
}

#[test]
fn tcp_oude_prefix_wordt_getrimd() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.write_a(b"abc").unwrap();
    w.pump();
    assert_eq!(read_all(&mut w.b), b"abc");
    let seg = s(w.b.rcv_nxt - 2, w.b.nxt, ACK, 1024);
    w.recv_b(&seg, b"bcdef");
    assert_eq!(read_all(&mut w.b), b"def", "de oude prefix is niet getrimd");
}

#[test]
fn tcp_peer_mss_wordt_geklemd() {
    let mut c = TcpConn::default();
    c.take_syn_options(&Seg {
        mss: 9000,
        ..Seg::default()
    });
    assert_eq!(c.peer_mss, crate::MTU - 40);
}

#[test]
fn tcp_fin_wait2_houdt_geen_budget_vast() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.pot_a = Budget::new(1 << 20);
    w.pot_a.reserve(2 * (8 << 10));
    w.a.budgeted = true;
    w.connect();
    w.a.close().unwrap();
    w.a.abandon_read(w.now, &mut w.pot_a);
    w.pump();
    assert_eq!(w.a.state, TcpState::FinWait2);
    assert_eq!(
        w.pot_a.used, 0,
        "de ringen blijven de pot vullen in FIN-WAIT-2"
    );
}

#[test]
fn tcp_handshake_reset_de_rto() {
    let mut w = new_pair(8 << 10, 8 << 10);
    assert_eq!(w.drain_a().len(), 1, "verwachtte de SYN");
    w.advance(2 * SEC);
    w.drain_a();
    w.advance(4 * SEC);
    assert!(
        w.a.rto > TCP_RTO_INITIAL,
        "opzet: rto hoort opgeblazen te zijn"
    );
    w.pump();
    assert_eq!(w.a.state, TcpState::Established);
    assert!(
        w.a.rto == TCP_RTO_INITIAL && w.a.retries == 0 && w.a.backoff == 0,
        "na de handshake: rto={} retries={} backoff={}",
        w.a.rto,
        w.a.retries,
        w.a.backoff
    );
}

#[test]
fn tcp_cumulatieve_ack_na_go_back_n() {
    let mut w = new_pair(32 << 10, 32 << 10);
    w.connect();
    w.write_a(&[0u8; 4000]).unwrap();
    let segs = w.drain_a();
    assert!(segs.len() >= 3, "opzet: {} segmenten, wil >=3", segs.len());
    let hoog = w.a.nxt;
    let wnd = w.a.snd_wnd as u16;
    for _ in 0..3 {
        let seg = s(w.a.rcv_nxt, w.a.una, ACK, wnd);
        w.recv_a(&seg, &[]);
    }
    assert_ne!(
        w.a.nxt, hoog,
        "opzet: goBackN heeft de cursor niet teruggespoeld"
    );
    let seg = s(w.a.rcv_nxt, hoog, ACK, wnd);
    w.recv_a(&seg, &[]);
    assert_eq!(w.a.una, hoog, "de geldige cumulatieve ACK is geweigerd");
    assert_eq!(w.a.nxt, hoog, "nxt niet bijgetrokken");
}

#[test]
fn tcp_dubbele_syn_verliest_de_finale_ack_niet() {
    let mut w = new_pair(8 << 10, 8 << 10);
    let syn = w.drain_a();
    assert!(syn.len() == 1 && has(&syn[0], SYN), "verwachtte de SYN");
    w.recv_b(&syn[0].0, &syn[0].1);
    for (seg, data) in w.drain_b() {
        w.recv_a(&seg, &data);
    }
    let fin = w.drain_a();
    assert!(
        fin.len() == 1 && fin[0].0.ack == w.b.iss + 1,
        "verwachtte de finale ACK op iss+1"
    );
    w.recv_b(&syn[0].0, &syn[0].1);
    w.recv_b(&fin[0].0, &fin[0].1);
    assert_eq!(
        w.b.state,
        TcpState::Established,
        "de finale ACK is afgewezen"
    );
    for p in w.drain_b() {
        assert!(
            !has(&p, RST),
            "b resette zijn eigen handshake op de kruisende finale ACK"
        );
    }
}

#[test]
fn tcp_fin_wait2_timeout() {
    let mut w = new_pair(8 << 10, 8 << 10);
    w.connect();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(w.a.state, TcpState::FinWait2);
    w.advance(TCP_FIN_WAIT2_DUR + SEC);
    let segs = w.drain_a();
    assert_eq!(w.a.state, TcpState::Closed, "FIN-WAIT-2 heeft geen einde");
    assert!(
        segs.iter().any(|p| has(p, RST)),
        "geen RST bij het opgeven van FIN-WAIT-2"
    );
}

// ---- congestion_test.go ----

fn congestion_pair(iss: u32) -> Wire {
    let mut w = new_pair_iss(1 << 20, 1 << 20, iss, 5000, 4);
    w.a.congestion = true;
    w.b.congestion = true;
    w.connect();
    w
}

#[test]
fn tcp_congestion_initial_window_and_ack_growth() {
    let mut w = congestion_pair(1000);
    w.write_a(&vec![0u8; 64 << 10]).unwrap();
    let first = w.drain_a();
    assert!(
        first.len() == 10 && w.a.cwnd == 14600,
        "initial burst={} cwnd={}",
        first.len(),
        w.a.cwnd
    );
    for (seg, data) in &first {
        w.recv_b(seg, data);
        for (ack, d) in w.drain_b() {
            w.recv_a(&ack, &d);
        }
    }
    assert_eq!(w.a.cwnd, 29200, "slow start");
    w.a.ssthresh = w.a.cwnd;
    let before = w.a.cwnd;
    w.a.congestion_ack(before - 1);
    assert_eq!(w.a.cwnd, before, "avoidance grew before full window ACKed");
    w.a.congestion_ack(1);
    assert_eq!(
        w.a.cwnd,
        before + w.a.peer_mss,
        "avoidance did not grow one MSS"
    );
}

#[test]
fn tcp_congestion_replay_wrap_and_peer_window() {
    let mut w = congestion_pair(u32::MAX - 4000);
    w.write_a(&vec![0u8; 32 << 10]).unwrap();
    w.drain_a();
    let flight = seq_diff(w.a.max_sent, w.a.una) as usize;
    w.a.congestion_loss();
    w.a.go_back_n();
    let replay = w.drain_a();
    assert!(
        replay.len() == 1 && replay[0].1.len() == 1460 && w.a.ssthresh == flight / 2,
        "replay={} threshold={} flight={flight}",
        replay.len(),
        w.a.ssthresh
    );
    assert_eq!(
        w.a.congestion_available(),
        0,
        "rewound send cursor admitted extra replay"
    );
    w.a.go_back_n();
    w.a.snd_wnd = 700;
    let replay = w.drain_a();
    assert!(
        replay.len() == 1 && replay[0].1.len() == 700,
        "replay ignored smaller peer window"
    );
}

#[test]
fn tcp_congestion_rto_and_zero_window_probe() {
    let mut w = congestion_pair(1000);
    w.write_a(&vec![0u8; 32 << 10]).unwrap();
    w.drain_a();
    w.now = w.a.deadline;
    let replay = w.drain_a();
    assert!(
        w.a.cwnd == 1460 && replay.len() == 1,
        "RTO cwnd={} replay={}",
        w.a.cwnd,
        replay.len()
    );
    w.a.snd_wnd = 0;
    w.a.go_back_n();
    w.a.probe = true;
    let replay = w.drain_a();
    assert!(
        replay.len() == 1 && replay[0].1.len() == 1,
        "zero window probe={replay:?}"
    );
}

#[test]
fn tcp_trusted_memory_keeps_receive_window_fast_path() {
    let mut w = new_pair(65535, 65535);
    w.connect();
    w.write_a(&vec![0u8; 60 << 10]).unwrap();
    let got = w.drain_a().len();
    assert!(
        got > 10,
        "memory path unexpectedly congestion limited: {got}"
    );
}

#[test]
fn tcp_congestion_progress_through64_frame_queue() {
    let mut w = congestion_pair(1000);
    const TOTAL: usize = 8 << 20;
    let source: Vec<u8> = (0..TOTAL).map(|i| (i * 13 + i / 257) as u8).collect();
    let mut got = Vec::with_capacity(TOTAL);
    let mut written = 0;
    let mut drops = 0;
    let mut lost_first = false;
    let mut buf = vec![0u8; 2048];
    for _ in 0..20000 {
        if got.len() >= TOTAL {
            break;
        }
        if written < TOTAL {
            written += w.write_a(&source[written..]).unwrap_or(0);
        }
        let mut q: Vec<Pkt> = Vec::new();
        for count in 0.. {
            assert!(count <= 2048, "unbounded sender burst");
            let Some(seg) = w.a.emit(&mut buf, w.now) else {
                break;
            };
            let data = buf[..seg.len].to_vec();
            if !lost_first && !data.is_empty() {
                lost_first = true;
                drops += 1;
                continue;
            }
            if q.len() == 64 {
                drops += 1;
                continue;
            }
            q.push((seg, data));
        }
        let mut acks = Vec::new();
        for (seg, data) in &q {
            w.recv_b(seg, data);
            got.extend(read_all(&mut w.b));
            acks.extend(w.drain_b());
        }
        for (ack, d) in &acks {
            w.recv_a(ack, d);
        }
        w.advance(MS);
        if q.is_empty() && w.a.timer_on {
            w.now = w.now.max(w.a.deadline);
        }
    }
    assert!(
        got == source,
        "progress stopped at {}/{TOTAL}, sent={} fast={} rto={} drops={drops}",
        got.len(),
        w.a.cnt.bytes_out,
        w.a.cnt.fast_retrans,
        w.a.cnt.retrans
    );
    assert!(
        w.a.cnt.bytes_out <= 3 * TOTAL,
        "retransmission amplification: sent={}",
        w.a.cnt.bytes_out
    );
}

#[test]
fn tcp_congestion_idle_restart() {
    for scenario in ["idle", "active", "outstanding"] {
        let mut w = congestion_pair(1000);
        w.write_a(&[0u8; 1460]).unwrap();
        w.pump();
        assert_eq!(w.a.max_sent, w.a.una, "fixture flight was not acknowledged");
        w.a.cwnd = 40 * w.a.peer_mss;
        w.a.cwnd_acked = 100;
        w.write_a(&vec![0u8; 60 << 10]).unwrap();
        if scenario == "outstanding" {
            w.drain_a();
            w.a.go_back_n();
        }
        if scenario != "active" {
            w.advance(w.a.current_rto());
        }
        w.a.restart_congestion_after_idle(w.now);
        if scenario == "idle" {
            assert!(
                w.a.cwnd == w.a.initial_congestion_window() && w.a.cwnd_acked == 0,
                "idle restart cwnd={} credit={}",
                w.a.cwnd,
                w.a.cwnd_acked
            );
        } else {
            assert!(
                w.a.cwnd == 40 * w.a.peer_mss && w.a.cwnd_acked == 100,
                "{scenario} reset active recovery window"
            );
        }
    }
}

#[test]
fn tcp_congestion_fin_preserves_close() {
    let mut w = congestion_pair(1000);
    w.write_a(&vec![0u8; 32 << 10]).unwrap();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(
        (w.a.state, w.b.state),
        (TcpState::FinWait2, TcpState::CloseWait),
        "FIN stalled"
    );
    assert_eq!(read_all(&mut w.b).len(), 32 << 10, "FIN lost payload");
}

// ---- fast_retransmit_test.go ----

#[test]
fn tcp_queued_duplicate_acks_do_not_restart_recovery() {
    let mut w = new_pair(65535, 65535);
    w.connect();
    assert_eq!(w.write_a(&vec![0u8; 60 << 10]), Ok(60 << 10));
    let original = w.drain_a();
    let mut acks = Vec::new();
    // Verlies het eerste datasegment; de peer stuurt één duplicate ACK per later segment.
    for (seg, data) in &original[1..] {
        w.recv_b(seg, data);
        acks.extend(w.drain_b());
    }
    // ACKs die al onderweg zijn komen in batches aan voordat herstel terugkomt.
    while !acks.is_empty() {
        let batch = acks.len().min(4);
        for (ack, d) in acks.drain(..batch) {
            w.recv_a(&ack, &d);
        }
        w.drain_a();
    }
    assert_eq!(
        w.a.cnt.fast_retrans, 1,
        "one lost segment restarted the same recovery without ACK progress"
    );
}

#[test]
fn tcp_duplicate_ack_counter_does_not_wrap() {
    let mut w = new_pair(65535, 65535);
    w.connect();
    w.write_a(&[0u8; 4096]).unwrap();
    w.drain_a();
    let ack = s(w.a.rcv_nxt, w.a.una, ACK, w.a.snd_wnd as u16);
    for _ in 0..260 {
        w.recv_a(&ack, &[]);
        w.drain_a();
    }
    assert_eq!(w.a.cnt.fast_retrans, 1, "duplicate-ACK u8 wrap");
}

#[test]
fn tcp_fast_recovery_stays_latched_without_progress() {
    for event in ["old ACK", "window update", "rewound cursor"] {
        let mut w = new_pair(65535, 65535);
        w.connect();
        w.write_a(&[0u8; 8192]).unwrap();
        w.drain_a();
        let ack = s(w.a.rcv_nxt, w.a.una, ACK, w.a.snd_wnd as u16);
        for _ in 0..3 {
            w.recv_a(&ack, &[]);
        }
        let mut changed = ack;
        match event {
            "old ACK" => changed.ack -= 1,
            "window update" => changed.wnd -= 1,
            _ => {}
        }
        w.recv_a(&changed, &[]);
        w.drain_a();
        for _ in 0..6 {
            w.recv_a(&ack, &[]);
            w.drain_a();
        }
        assert!(
            w.a.cnt.fast_retrans == 1 && w.a.dupacks == 3,
            "{event}: recovery rearmed without progress: fast={} duplicates={}",
            w.a.cnt.fast_retrans,
            w.a.dupacks
        );
    }
}

#[test]
fn tcp_fast_recovery_rearms_on_progress_and_retains_rto() {
    let mut w = new_pair(65535, 65535);
    w.connect();
    w.write_a(&[0u8; 8192]).unwrap();
    w.drain_a();
    let mut ack = s(w.a.rcv_nxt, w.a.una, ACK, w.a.snd_wnd as u16);
    for _ in 0..3 {
        w.recv_a(&ack, &[]);
    }
    w.drain_a();
    ack.ack += 1460;
    w.recv_a(&ack, &[]);
    assert_eq!(w.a.dupacks, 0, "progress did not release recovery latch");
    for _ in 0..3 {
        w.recv_a(&ack, &[]);
    }
    w.drain_a();
    assert_eq!(
        w.a.cnt.fast_retrans, 2,
        "next missing segment did not recover"
    );
    assert!(w.a.timer_on, "unacknowledged retransmission lost RTO");
    w.now = w.a.deadline;
    let bytes: usize = w.drain_a().iter().map(|p| p.1.len()).sum();
    assert!(
        w.a.cnt.retrans == 1 && bytes == 8192 - 1460,
        "lost fast retransmission has no RTO fallback: rto={} bytes={bytes}",
        w.a.cnt.retrans
    );
}

// ---- ephemeral_seed_test.go (machinedeel) ----

#[test]
fn tcp_fresh_tuple_against_protected_time_wait() {
    let mut w = new_pair(1024, 1024);
    w.connect();
    w.b.close().unwrap();
    w.pump();
    w.a.close().unwrap();
    w.pump();
    assert_eq!(w.b.state, TcpState::TimeWait);
    // Een externe host die dit tupel vasthoudt over een kernelvervanging van de
    // node. Apple XNU negeert resets in TIME_WAIT (RFC 1337); zonder
    // timestamps heropent hij alleen voor een SYN voorbij de oude rcv_nxt.
    w.b.tw_deadline = w.now + MIN;
    w.b.close_deadline = w.b.tw_deadline;
    w.drop_ab = Some(Box::new(|s| s.flags.has(RST)));
    let mut fresh = TcpConn::with_rings(1024, 1024).unwrap();
    fresh.open_active(1000, 1460, 0);
    w.a = fresh;
    for _ in 0..100 {
        if w.a.state == TcpState::Closed {
            break;
        }
        w.pump();
        w.advance(100 * MS);
    }
    assert!(
        w.a.state == TcpState::SynSent && !w.a.refused && w.b.state == TcpState::TimeWait,
        "fresh={} refused={} peer={}",
        w.a.state,
        w.a.refused,
        w.b.state
    );
    // Een ander tupel bereikt een nieuw listener-embryo en komt tot stand.
    w.drop_ab = None;
    let mut b = TcpConn::with_rings(1024, 1024).unwrap();
    b.open_passive(7000, 1460, 0);
    w.b = b;
    let mut fresh = TcpConn::with_rings(1024, 1024).unwrap();
    fresh.open_active(1000, 1460, 0);
    w.a = fresh;
    w.connect();
}
