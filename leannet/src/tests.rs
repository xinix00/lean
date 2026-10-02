//! De stacktests: `stack_test.go`, `ephemeral_seed_test.go`, `jumbo_test.go`
//! en de stackkant van `congestion_test.go`, gedreven door het testnet in
//! plaats van goroutines, `memDevice` en echte tijd.

use alloc::vec;
use alloc::vec::Vec;

use crate::arp::{ARP_CACHE_CAP, ArpReply};
use crate::neighbor::{NeighborEntry, NeighborState};
use crate::stack::{
    ConnKey, EPHEMERAL_BASE, EPHEMERAL_END, LOOPBACK_MAX, TCP_BACKLOG, TCP_BACKLOG_WAIT_DUR,
    TCP_FLOOR_RING, TCP_FLOOR_RX, TCP_FLOOR_TX, is_broadcast_ip,
};
use crate::tcp::{TCP_FULL_CLOSE_DUR, TcpState};
use crate::testnet::*;
use crate::wire::{self, TcpFlags};
use crate::{Config, Endpoint, Error, ListenHandle, MS, MTU, Result, SEC, Stack, TcpHandle};

/// Kiest de stack waarop een helper werkt.
type Side = fn(&mut Net) -> &mut Stack;

fn sa(n: &mut Net) -> &mut Stack {
    &mut n.a
}

fn sb(n: &mut Net) -> &mut Stack {
    n.b()
}

/// Dialt vanaf a en wacht op de uitkomst, zoals `DialTCP` met een deadline.
fn dial(net: &mut Net, ip: [u8; 4], port: u16, within: u64) -> Result<TcpHandle> {
    let now = net.now;
    let h = net.a.tcp_connect(ip, port, Some(now + within), now)?;
    let mut out = Err(Error::WouldBlock);
    net.run_until(within + SEC, |n| {
        out = n.a.tcp_poll_connect(h, n.now);
        out != Err(Error::WouldBlock)
    });
    out.map(|()| h)
}

/// Neemt een verbinding aan op `side`.
fn accept(net: &mut Net, side: Side, l: ListenHandle) -> TcpHandle {
    let mut got = None;
    net.run_until(5 * SEC, |n| {
        let now = n.now;
        match side(n).tcp_accept(l, now) {
            Ok(h) => {
                got = Some(h);
                true
            }
            Err(Error::WouldBlock) => false,
            Err(e) => panic!("accept: {e}"),
        }
    });
    got.expect("server never accepted")
}

/// Een verbonden paar: client op a, server op b.
fn connected(net: &mut Net, port: u16) -> (TcpHandle, TcpHandle, ListenHandle) {
    let l = net.b().tcp_listen(port).unwrap();
    let c = dial(net, IP_B, port, 5 * SEC).unwrap();
    let s = accept(net, sb, l);
    (c, s, l)
}

/// Schrijft alles, pompend tot het erin zit.
fn write_all(net: &mut Net, side: Side, h: TcpHandle, data: &[u8], within: u64) {
    let mut off = 0;
    let ok = net.run_until(within, |n| {
        let now = n.now;
        match side(n).tcp_write(h, &data[off..], now) {
            Ok(k) => off += k,
            Err(Error::WouldBlock) => {}
            Err(e) => panic!("write after {off} bytes: {e}"),
        }
        off == data.len()
    });
    assert!(ok, "write stalled after {off} of {} bytes", data.len());
}

/// Leest precies `want` bytes.
fn read_exact(net: &mut Net, side: Side, h: TcpHandle, want: usize, within: u64) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = vec![0u8; 32 << 10];
    let ok = net.run_until(within, |n| {
        let now = n.now;
        loop {
            match side(n).tcp_read(h, &mut buf, now) {
                Ok(0) => panic!("EOF after {} of {want} bytes", got.len()),
                Ok(k) => got.extend_from_slice(&buf[..k]),
                Err(Error::WouldBlock) => break,
                Err(e) => panic!("read after {} of {want} bytes: {e}", got.len()),
            }
        }
        got.len() >= want
    });
    assert!(ok, "read stalled after {} of {want} bytes", got.len());
    got
}

/// Het aantal levende verbindingen in de demux.
fn live_conns(s: &Stack) -> usize {
    s.conns.iter().flatten().filter(|c| c.live).count()
}

/// Het aantal bezette verbindingsplekken.
fn slots(s: &Stack) -> usize {
    s.conns.iter().flatten().count()
}

/// Een stack zonder peer: `wire_a` vangt wat hij stuurt.
fn lone(ip: [u8; 4], mac: [u8; 6], seed: u32) -> Net {
    Net::single(
        Config {
            ip,
            mac,
            ..cfg_a(1 << 20)
        },
        seed,
    )
}

#[test]
fn stack_tcp_echo_end_to_end() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(80).unwrap();
    let c = dial(&mut net, IP_B, 80, 5 * SEC).unwrap();
    let msg: Vec<u8> = (0..30000).map(|i| (i * 7) as u8).collect();
    let mut server = None;
    let mut pending: Vec<u8> = Vec::new();
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    let ok = net.run_until(5 * SEC, |n| {
        let now = n.now;
        if server.is_none() {
            server = n.b().tcp_accept(l, now).ok();
        }
        if let Some(s) = server {
            // De echoserver: lezen en terugschrijven, met een eigen restbuffer.
            while let Ok(k) = n.b().tcp_read(s, &mut buf, now) {
                if k == 0 {
                    break;
                }
                pending.extend_from_slice(&buf[..k]);
            }
            if let Ok(k) = n.b().tcp_write(s, &pending, now) {
                pending.drain(..k);
            }
        }
        if sent < msg.len()
            && let Ok(k) = n.a.tcp_write(c, &msg[sent..], now)
        {
            sent += k;
        }
        while let Ok(k) = n.a.tcp_read(c, &mut buf, now) {
            if k == 0 {
                break;
            }
            got.extend_from_slice(&buf[..k]);
        }
        got.len() >= msg.len()
    });
    assert!(
        ok && got == msg,
        "echo corrupted the stream: {} of {} bytes",
        got.len(),
        msg.len()
    );
    let now = net.now;
    net.a.tcp_close(c, now).unwrap();
    net.b().tcp_close(server.unwrap(), now).unwrap();
    assert_eq!(
        net.arp_queries_b, 0,
        "server needed ARP queries; passive learning is broken"
    );
    assert_eq!(net.arp_queries_a, 1, "client ARP queries");
    let ok = net.run_until(4 * SEC, |n| {
        n.a.budget_free() == 1 << 20 && n.b().budget_free() == 1 << 20
    });
    assert!(
        ok,
        "budget leaked: a free {}, b free {}",
        net.a.budget_free(),
        net.b().budget_free()
    );
}

#[test]
fn stack_udp_roundtrip() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let srv = net.b().udp_bind(53).unwrap();
    let cl = net.a.udp_connect(IP_B, 53).unwrap();
    let now = net.now;
    // De eerste zending wacht op ARP.
    let mut sent = false;
    net.run_until(3 * SEC, |n| {
        sent = n.a.udp_send(cl, b"query", n.now).is_ok();
        sent
    });
    assert!(sent, "client send never got a route");
    let mut buf = [0u8; 512];
    let ok = net.run_until(3 * SEC, |n| {
        let now = n.now;
        if let Ok((k, from)) = n.b().udp_recv_from(srv, &mut buf, now) {
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&buf[..k]);
            n.b().udp_send_to(srv, from, &reply, now).unwrap();
        }
        n.a.udp_readable(cl).unwrap()
    });
    assert!(ok, "no reply");
    let k = net.a.udp_recv(cl, &mut buf, now).unwrap();
    assert_eq!(&buf[..k], b"re:query");
    assert!(
        net.a.udp_local(cl).unwrap().port >= EPHEMERAL_BASE,
        "client port not in the ephemeral range"
    );
}

#[test]
fn tcp_readable_meldt_data_en_fin_zonder_te_lezen() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, s, _) = connected(&mut net, 82);
    // Een verse verbinding: niets te lezen, en de vraag verbruikt niets.
    assert_eq!(net.a.tcp_readable(c), Ok(false));
    write_all(&mut net, sb, s, b"hallo", SEC);
    let ok = net.run_until(SEC, |n| n.a.tcp_readable(c) == Ok(true));
    assert!(ok, "readable werd nooit waar na een write van de peer");
    // Twee keer vragen is één keer vragen: de bytes staan er nog.
    assert_eq!(net.a.tcp_readable(c), Ok(true));
    assert_eq!(read_exact(&mut net, sa, c, 5, SEC), b"hallo");
    assert_eq!(net.a.tcp_readable(c), Ok(false));
    // De FIN van de peer maakt de verbinding leesbaar: de read zegt dan EOF.
    let now = net.now;
    net.b().tcp_close(s, now).unwrap();
    let ok = net.run_until(SEC, |n| n.a.tcp_readable(c) == Ok(true));
    assert!(ok, "readable werd nooit waar na de FIN van de peer");
    assert_eq!(net.a.tcp_read(c, &mut [0; 16], net.now), Ok(0));
    // Een vreemd handvat is een fout, geen `false`.
    net.a.tcp_close(c, net.now).unwrap();
    assert_eq!(net.a.tcp_readable(c), Err(Error::Closed));
}

#[test]
fn stack_read_deadline() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 81);
    let start = net.now;
    net.a
        .tcp_set_read_deadline(c, Some(start + 150 * MS))
        .unwrap();
    let (w, woke) = counting_waker();
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::WouldBlock)
    );
    net.a.tcp_register_read_waker(c, &w).unwrap();
    let mut res = Err(Error::WouldBlock);
    net.run_until(2 * SEC, |n| {
        if woke.count() == 0 {
            return false;
        }
        res = n.a.tcp_read(c, &mut [0; 16], n.now);
        res != Err(Error::WouldBlock)
    });
    assert_eq!(res, Err(Error::DeadlineExceeded));
    let elapsed = net.now - start;
    assert!(
        (100 * MS..=2 * SEC).contains(&elapsed),
        "deadline fired after {elapsed} ns"
    );
}

#[test]
fn stack_budget_refusal_sends_rst() {
    let mut net = Net::pair(1 << 20, 0);
    net.b().tcp_listen(82).unwrap();
    assert!(
        dial(&mut net, IP_B, 82, 2 * SEC).is_err(),
        "dial succeeded against a stack with zero budget"
    );
    assert!(net.b().stats().refused_no_budget > 0, "refusal was silent");
}

#[test]
fn stack_icmp_echo() {
    let mut net = lone(IP_B, MAC_B, 54321);
    let mut icmp = vec![8, 0, 0, 0, 0, 42, 0, 7, b'p', b'i', b'n', b'g'];
    let c = wire::checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut frame = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4 + icmp.len()];
    wire::put_eth(&mut frame, MAC_B, MAC_A, wire::ETHERTYPE_IPV4).unwrap();
    frame[wire::SIZE_ETH + wire::SIZE_IPV4..].copy_from_slice(&icmp);
    wire::put_ipv4(
        &mut frame[wire::SIZE_ETH..],
        wire::PROTO_ICMP,
        IP_A,
        IP_B,
        icmp.len(),
    )
    .unwrap();
    net.a.receive(&frame, net.now).unwrap();
    net.settle();
    let replied = net.wire_a.iter().any(|f| {
        let Ok(e) = wire::parse_eth(f) else {
            return false;
        };
        let Ok(ip) = wire::parse_ipv4(e.payload()) else {
            return false;
        };
        let p = ip.payload();
        ip.proto() == wire::PROTO_ICMP && p.first() == Some(&0) && p.get(8..) == Some(b"ping")
    });
    assert!(replied, "no echo reply");
}

#[test]
fn stack_ephemeral_skips_occupied() {
    let mut net = Net::single(cfg_a(1 << 20), 0);
    net.a.udp_bind(49153).unwrap();
    let u1 = net.a.udp_bind(0).unwrap();
    let u2 = net.a.udp_bind(0).unwrap();
    let p1 = net.a.udp_local(u1).unwrap().port;
    let p2 = net.a.udp_local(u2).unwrap().port;
    assert_eq!((p1, p2), (49152, 49154), "49153 must be skipped");
}

#[test]
fn stack_seed_neighbor_subnet_rule() {
    let mut net = Net::single(
        Config {
            gw: [10, 0, 0, 254],
            ..cfg_a(1 << 20)
        },
        1,
    );
    let now = net.now;
    net.a
        .seed_neighbor([10, 0, 0, 7], [1, 0, 0, 0, 0, 0], now)
        .expect("in-subnet seed refused");
    net.a
        .seed_neighbor([10, 0, 0, 254], [2, 0, 0, 0, 0, 0], now)
        .expect("gateway seed refused");
    assert!(
        net.a
            .seed_neighbor([192, 168, 1, 1], [3, 0, 0, 0, 0, 0], now)
            .is_err(),
        "out-of-subnet seed accepted silently (lneto #21)"
    );
}

/// De Go-test controleerde de vormen van `net.SocketFunc`; hier zijn dat de
/// handvattypen, en een mislukte dial geeft een fout, nooit een handvat.
#[test]
fn stack_socket_shapes() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l: ListenHandle = net.b().tcp_listen(90).unwrap();
    let c: TcpHandle = dial(&mut net, IP_B, 90, 3 * SEC).unwrap();
    let s = accept(&mut net, sb, l);
    let now = net.now;
    net.b().tcp_close(s, now).unwrap();
    net.a.tcp_close(c, now).unwrap();
    let _: crate::UdpHandle = net.a.udp_bind(5353).unwrap();
    assert!(
        dial(&mut net, [10, 0, 0, 99], 1, 300 * MS).is_err(),
        "failed dial returned a handle"
    );
}

#[test]
fn stack_idle_has_no_protocol_deadline() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    net.a.tcp_listen(80).unwrap();
    let now = net.now;
    assert_eq!(
        net.a.next_timeout(now),
        None,
        "idle stack with a listener has a pending deadline"
    );
}

#[test]
fn stack_garbage_never_panics() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    net.a.tcp_listen(80).unwrap();
    let now = net.now;
    let s = &mut net.a;
    let mut x: u64 = 0xdead_beef;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x as u8
    };
    let mut frame = [0u8; 200];
    for n in [0usize, 1, 13, 14, 15, 33, 60, 61, 200] {
        for _ in 0..50 {
            for b in frame[..n].iter_mut() {
                *b = rnd();
            }
            let _ = s.receive(&frame[..n], now);
        }
    }
    let src = [10, 0, 0, 9];
    let src_mac = [2, 0, 0, 0, 0, 9];
    // Een IPv4-header met kapotte checksum.
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4];
    wire::put_eth(&mut f, MAC_A, src_mac, wire::ETHERTYPE_IPV4).unwrap();
    wire::put_ipv4(&mut f[wire::SIZE_ETH..], wire::PROTO_TCP, src, IP_A, 0).unwrap();
    f[wire::SIZE_ETH + 10] ^= 0xff;
    let _ = s.receive(&f, now);
    // Een TCP-payload van acht bytes: te kort voor een header.
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4 + 8];
    wire::put_eth(&mut f, MAC_A, src_mac, wire::ETHERTYPE_IPV4).unwrap();
    wire::put_ipv4(&mut f[wire::SIZE_ETH..], wire::PROTO_TCP, src, IP_A, 8).unwrap();
    let _ = s.receive(&f, now);
    // Een SYN met kapotte TCP-checksum.
    let mut f = tcp_frame(MAC_A, src_mac, src, IP_A, 999, 80, 1, 0, TcpFlags::SYN, &[]);
    f[wire::SIZE_ETH + wire::SIZE_IPV4 + 16] ^= 0xff;
    let _ = s.receive(&f, now);
    // Een SYN met een optie van lengte nul.
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_IPV4 + wire::SIZE_TCP + 4];
    wire::put_eth(&mut f, MAC_A, src_mac, wire::ETHERTYPE_IPV4).unwrap();
    let h = wire::TcpHeader {
        src_port: 999,
        dst_port: 80,
        seq: 1,
        ack: 0,
        flags: TcpFlags::SYN,
        wnd: 100,
        opts: &[2, 0, 0, 0],
    };
    let off = wire::SIZE_ETH + wire::SIZE_IPV4;
    let n = wire::put_tcp(&mut f[off..], &h, src, IP_A, 0).unwrap();
    wire::put_ipv4(&mut f[wire::SIZE_ETH..], wire::PROTO_TCP, src, IP_A, n).unwrap();
    let _ = s.receive(&f, now);
    // Een ARP-pakket met een kapotte hardwaresoort.
    let mut f = vec![0u8; wire::SIZE_ETH + wire::SIZE_ARP];
    wire::put_eth(&mut f, MAC_A, src_mac, wire::ETHERTYPE_ARP).unwrap();
    wire::put_arp(
        &mut f[wire::SIZE_ETH..],
        wire::ARP_REQUEST,
        [9, 0, 0, 0, 0, 0],
        src,
        [0; 6],
        IP_A,
    )
    .unwrap();
    f[wire::SIZE_ETH] = 0xff;
    let _ = s.receive(&f, now);
    let st = s.stats();
    assert!(
        st.drop_bad_frame > 0 && st.drop_short_frame > 0,
        "garbage was not counted: bad={} short={}",
        st.drop_bad_frame,
        st.drop_short_frame
    );
    assert_eq!(slots(s), 0, "garbage created connections");
}

#[test]
fn stack_listener_backlog_overflow() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(88).unwrap();
    let dials = TCP_BACKLOG + 4;
    let mut reset = 0;
    let mut conns = Vec::new();
    for i in 0..dials {
        match dial(&mut net, IP_B, 88, 3 * SEC) {
            Ok(c) => conns.push(c),
            Err(Error::Reset) => reset += 1,
            Err(e) => panic!("dial {i}: {e}"),
        }
    }
    net.settle();
    assert_eq!(
        live_conns(net.b()),
        TCP_BACKLOG,
        "b holds more or fewer than the backlog"
    );
    for c in conns {
        let now = net.now;
        match net.a.tcp_read(c, &mut [0; 1], now) {
            Err(Error::WouldBlock) => {}
            _ => reset += 1,
        }
    }
    assert_eq!(
        reset,
        dials - TCP_BACKLOG,
        "overflow clients that saw the RST"
    );
    for i in 0..TCP_BACKLOG {
        let now = net.now;
        net.b()
            .tcp_accept(l, now)
            .unwrap_or_else(|e| panic!("accept {i}: {e}"));
    }
    net.b().tcp_listen_close(l);
}

#[test]
fn stack_budget_recovery() {
    let mut net = Net::pair(1 << 20, TCP_FLOOR_RING);
    let l = net.b().tcp_listen(89).unwrap();
    let c1 = dial(&mut net, IP_B, 89, 3 * SEC).unwrap();
    let s1 = accept(&mut net, sb, l);
    assert!(
        dial(&mut net, IP_B, 89, 2 * SEC).is_err(),
        "second dial succeeded against a full pot"
    );
    let now = net.now;
    net.b().tcp_close(s1, now).unwrap();
    net.a.tcp_close(c1, now).unwrap();
    let mut recovered = false;
    net.run_until(5 * SEC, |n| {
        let now = n.now;
        if let Ok(c3) = n.a.tcp_connect(IP_B, 89, Some(now + 2 * SEC), now) {
            n.settle();
            if n.a.tcp_poll_connect(c3, n.now).is_ok() {
                recovered = true;
                n.a.tcp_close(c3, n.now).unwrap();
                return true;
            }
            let _ = n.a.tcp_close(c3, n.now);
        }
        false
    });
    assert!(recovered, "budget never recovered after close");
}

#[test]
fn stack_ephemeral_wraps() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    net.a.next_eph = EPHEMERAL_END;
    let u1 = net.a.udp_bind(0).unwrap();
    let u2 = net.a.udp_bind(0).unwrap();
    let p = (
        net.a.udp_local(u1).unwrap().port,
        net.a.udp_local(u2).unwrap().port,
    );
    assert_eq!(p, (EPHEMERAL_END, EPHEMERAL_BASE));
}

#[test]
fn stack_routes_off_subnet_via_gateway() {
    let gw_mac = [0xaa, 0xbb, 0xcc, 0, 0, 1];
    let mut net = Net::single(
        Config {
            gw: [10, 0, 0, 254],
            ..cfg_a(1 << 20)
        },
        3,
    );
    let now = net.now;
    let c = net
        .a
        .tcp_connect([8, 8, 8, 8], 443, Some(now + 3 * SEC), now)
        .unwrap();
    net.settle();
    let targets: Vec<_> = net
        .wire_a
        .iter()
        .filter_map(|f| arp_request_target(f))
        .collect();
    assert!(
        !targets.contains(&[8, 8, 8, 8]),
        "stack ARP'd for an off-subnet address instead of the gateway"
    );
    assert!(
        targets.contains(&[10, 0, 0, 254]),
        "no ARP request for the gateway"
    );

    let mut reply = vec![0u8; 60];
    wire::put_eth(&mut reply, MAC_A, gw_mac, wire::ETHERTYPE_ARP).unwrap();
    wire::put_arp(
        &mut reply[wire::SIZE_ETH..],
        wire::ARP_REPLY,
        gw_mac,
        [10, 0, 0, 254],
        MAC_A,
        IP_A,
    )
    .unwrap();
    net.wire_a.clear();
    net.a.receive(&reply, net.now).unwrap();
    net.settle();
    let syn = net
        .wire_a
        .iter()
        .filter_map(|f| seen_tcp(f))
        .find(|t| t.dst == [8, 8, 8, 8] && t.flags.has(TcpFlags::SYN))
        .expect("no SYN towards the off-subnet peer after the gateway resolved");
    assert_eq!(
        syn.dst_mac, gw_mac,
        "off-subnet frame went elsewhere than the gateway MAC"
    );
    let mut out = Err(Error::WouldBlock);
    net.run_until(4 * SEC, |n| {
        out = n.a.tcp_poll_connect(c, n.now);
        out != Err(Error::WouldBlock)
    });
    assert!(out.is_err(), "dial to a silent peer succeeded");
}

#[test]
fn stack_static_gateway_mac_skips_arp() {
    let gw_mac = [2, 0, 0, 0, 0, 99];
    let mut net = Net::single(
        Config {
            ip: [10, 100, 0, 5],
            mac: [2, 0, 0, 0, 0, 5],
            gw: [10, 100, 0, 1],
            ..cfg_a(1 << 20)
        },
        4,
    );
    let now = net.now;
    net.a.seed_neighbor([10, 100, 0, 1], gw_mac, now).unwrap();
    net.a
        .tcp_connect([1, 1, 1, 1], 80, Some(now + SEC), now)
        .unwrap();
    net.settle();
    assert_eq!(
        net.arp_frames_a, 0,
        "static gateway MAC still triggered ARP"
    );
    let hit = net
        .wire_a
        .iter()
        .any(|f| wire::parse_eth(f).is_ok_and(|e| e.dst() == gw_mac));
    assert!(hit, "no frame towards the planned gateway MAC");
}

#[test]
fn stack_udp_accessors() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let now = net.now;
    let a = &mut net.a;
    let u = a.udp_bind(5555).unwrap();
    assert_eq!(
        a.udp_remote(u),
        Ok(None),
        "unconnected socket reports a remote address"
    );
    assert_eq!(a.udp_send(u, b"x", now), Err(Error::NotConnected));
    assert_eq!(a.udp_local(u).unwrap().port, 5555);
    a.udp_set_read_deadline(u, Some(now + 10 * MS)).unwrap();
    assert_eq!(
        a.udp_recv_from(u, &mut [0; 8], now + 10 * MS),
        Err(Error::DeadlineExceeded)
    );
    a.udp_set_write_deadline(u, None).unwrap();
    let port0 = Endpoint { ip: IP_B, port: 0 };
    assert_eq!(
        a.udp_send_to(u, port0, b"x", now),
        Err(Error::InvalidPort),
        "send to port 0 accepted"
    );
    a.udp_close(u);
    a.udp_close(u);
    assert_eq!(a.udp_recv_from(u, &mut [0; 8], now), Err(Error::Closed));
    let u2 = a.udp_bind(5555).expect("rebind after close");
    a.udp_close(u2);
}

#[test]
fn stack_listener_rejects_busy_port_and_reports_addr() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let now = net.now;
    let a = &mut net.a;
    let l = a.tcp_listen(1234).unwrap();
    assert_eq!(a.listen_port(l), Ok(1234));
    assert_eq!(a.tcp_listen(1234), Err(Error::TcpPortInUse { port: 1234 }));
    a.tcp_listen_close(l);
    let l2 = a.tcp_listen(1234).expect("relisten after close");
    assert_eq!(a.tcp_accept(l2, now), Err(Error::WouldBlock));
    let (w, woke) = counting_waker();
    a.listen_register_waker(l2, &w).unwrap();
    a.tcp_listen_close(l2);
    assert!(woke.count() > 0, "close did not release a blocked accept");
    assert_eq!(a.tcp_accept(l2, now), Err(Error::Closed));
}

#[test]
fn stack_fast_reader_keeps_full_window() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, s, _) = connected(&mut net, 91);
    let payload = vec![0u8; 200 << 10];
    let mut off = 0;
    let mut got = 0;
    let mut buf = vec![0u8; 32 << 10];
    let ok = net.run_until(5 * SEC, |n| {
        let now = n.now;
        if let Ok(k) = n.a.tcp_write(c, &payload[off..], now) {
            off += k;
        }
        while let Ok(k) = n.b().tcp_read(s, &mut buf, now) {
            if k == 0 {
                break;
            }
            got += k;
        }
        got == payload.len()
    });
    assert!(ok, "server read {got} of {} bytes", payload.len());
    let now = net.now;
    net.a.tcp_close(c, now).unwrap();
    net.settle();
    for sc in net.b().conns.iter().flatten().filter(|c| c.live) {
        assert!(
            sc.tcp.rx.size() >= 10 * 1460,
            "server receive window is {} bytes; a 10-segment initial burst does not fit",
            sc.tcp.rx.size()
        );
    }
}

#[test]
fn stack_self_dial() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.a.tcp_listen(7000).unwrap();
    let c = dial(&mut net, IP_A, 7000, 3 * SEC).expect("self-dial failed");
    let s = accept(&mut net, sa, l);
    assert_ne!(
        net.a.tcp_local(c),
        net.a.tcp_remote(c),
        "self-dial reused the same port on both ends"
    );
    let msg = b"talking to myself";
    write_all(&mut net, sa, c, msg, 3 * SEC);
    let echo = read_exact(&mut net, sa, s, msg.len(), 3 * SEC);
    write_all(&mut net, sa, s, &echo, 3 * SEC);
    assert_eq!(
        read_exact(&mut net, sa, c, msg.len(), 3 * SEC),
        msg,
        "echo over loopback"
    );
    assert_eq!(
        net.arp_queries_a, 0,
        "self-dial produced ARP queries on the wire"
    );
}

#[test]
fn stack_self_dial_refused() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let start = net.now;
    let err =
        dial(&mut net, IP_A, 7001, 3 * SEC).expect_err("dial to an unbound own port succeeded");
    assert!(
        !matches!(err, Error::Unreachable { .. }),
        "self-dial reported {err}"
    );
    assert!(
        net.now - start <= 2 * SEC,
        "refusal should be immediate, not an ARP timeout"
    );
}

#[test]
fn stack_self_dial_udp() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let srv = net.a.udp_bind(7002).unwrap();
    let cl = net.a.udp_connect(IP_A, 7002).unwrap();
    let now = net.now;
    net.a.udp_send(cl, b"ping", now).unwrap();
    net.settle();
    let mut buf = [0u8; 256];
    let (k, from) = net.a.udp_recv_from(srv, &mut buf, now).unwrap();
    let mut reply = b"echo:".to_vec();
    reply.extend_from_slice(&buf[..k]);
    net.a.udp_send_to(srv, from, &reply, now).unwrap();
    net.settle();
    let k = net.a.udp_recv(cl, &mut buf, now).unwrap();
    assert_eq!(&buf[..k], b"echo:ping", "udp loopback");
}

#[test]
fn stack_closed_port_refuses_fast() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    net.b().tcp_listen(6000).unwrap();
    let start = net.now;
    assert!(
        dial(&mut net, IP_B, 6001, 3 * SEC).is_err(),
        "dial to a closed port succeeded"
    );
    assert!(
        net.now - start <= SEC,
        "closed port was slow to refuse: the peer sent no RST"
    );
}

#[test]
fn stack_rst_storm_resistance() {
    let mut net = Net::single(cfg_a(1 << 20), 5);
    let now = net.now;
    net.a
        .seed_neighbor([10, 0, 0, 9], [2, 0, 0, 0, 0, 9], now)
        .unwrap();
    let f = tcp_frame(
        MAC_A,
        [2, 0, 0, 0, 0, 9],
        [10, 0, 0, 9],
        IP_A,
        1234,
        80,
        500,
        0,
        TcpFlags::RST,
        &[],
    );
    net.a.receive(&f, now).unwrap();
    net.run_for(500 * MS);
    let rst = net
        .wire_a
        .iter()
        .filter_map(|f| seen_tcp(f))
        .any(|t| t.flags.has(TcpFlags::RST));
    assert!(!rst, "answered a RST with a RST");
}

#[test]
fn stack_broadcast_gaat_naar_ffff() {
    for (naam, dst) in [
        ("limited", [255, 255, 255, 255]),
        ("subnet-directed", [10, 0, 0, 255]),
    ] {
        let mut net = Net::single(
            Config {
                gw: [10, 0, 0, 254],
                ..cfg_a(1 << 20)
            },
            7,
        );
        let u = net.a.udp_bind(68).unwrap();
        let now = net.now;
        net.a
            .udp_send_to(u, Endpoint { ip: dst, port: 67 }, b"REQUEST", now)
            .unwrap_or_else(|e| panic!("{naam}: broadcast weigerde: {e}"));
        net.settle();
        assert_eq!(
            net.arp_queries_a, 0,
            "{naam}: een broadcastadres bezit niemand"
        );
        let seen = net.wire_a.iter().any(|f| {
            let e = wire::parse_eth(f).unwrap();
            wire::parse_ipv4(e.payload())
                .is_ok_and(|ip| ip.dst() == dst && ip.proto() == wire::PROTO_UDP)
                && e.dst() == wire::BCAST_MAC
        });
        assert!(
            seen,
            "{naam}: geen broadcast-datagram naar ff:ff:ff:ff:ff:ff op de draad"
        );
    }
}

#[test]
fn is_broadcast_ip_cases() {
    let ip = [10, 0, 0, 1];
    for (dst, prefix, want) in [
        ([255, 255, 255, 255], 24, true),
        ([255, 255, 255, 255], 32, true),
        ([10, 0, 0, 255], 24, true),
        ([10, 0, 255, 255], 16, true),
        ([10, 0, 0, 255], 16, false),
        ([10, 0, 0, 2], 24, false),
        ([10, 0, 1, 255], 24, false),
        ([10, 0, 0, 1], 31, false),
        ([10, 0, 0, 1], 32, false),
        ([192, 168, 1, 255], 24, false),
    ] {
        assert_eq!(is_broadcast_ip(dst, ip, prefix), want, "{dst:?}/{prefix}");
    }
}

#[test]
fn stack_self_dial_meerdere_rondes() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.a.tcp_listen(7100).unwrap();
    let c = dial(&mut net, IP_A, 7100, 3 * SEC).unwrap();
    let s = accept(&mut net, sa, l);
    for i in 0..10 {
        let msg = alloc::format!("ronde-{i}").into_bytes();
        write_all(&mut net, sa, c, &msg, 3 * SEC);
        let got = read_exact(&mut net, sa, s, msg.len(), 3 * SEC);
        let mut re = b"re:".to_vec();
        re.extend_from_slice(&got);
        write_all(&mut net, sa, s, &re, 3 * SEC);
        assert_eq!(
            read_exact(&mut net, sa, c, re.len(), 3 * SEC),
            re,
            "ronde {i}"
        );
    }
}

#[test]
fn stack_peer_herstart_zelfde_vier_tupel() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(90).unwrap();
    let first = dial(&mut net, IP_B, 90, 5 * SEC).expect("eerste verbinding");
    accept(&mut net, sb, l);
    let port1 = net.a.tcp_local(first).unwrap().port;
    // De node gaat weg zonder RST: een gesloten stack pompt niets meer.
    net.a.close();
    net.run_for(50 * MS);
    // Botst bewust in het dynamische poortbereik maar verandert de ISS: de
    // regressie moet herstel van hetzelfde vier-tupel oefenen.
    net.a = Stack::new(cfg_a(1 << 20), 12345 + 16384).unwrap();
    let second =
        dial(&mut net, IP_B, 90, 10 * SEC).expect("herstarte peer kon niet opnieuw verbinden");
    assert_eq!(
        net.a.tcp_local(second).unwrap().port,
        port1,
        "het vier-tupel moet écht hetzelfde zijn"
    );
    let s2 = accept(&mut net, sb, l);
    write_all(&mut net, sa, second, b"hallo", 5 * SEC);
    assert_eq!(read_exact(&mut net, sb, s2, 5, 5 * SEC), b"hallo");
}

#[test]
fn stack_idle_verbinding_geeft_buffers_terug() {
    const BUDGET: usize = 512 << 10;
    let mut net = Net::pair(BUDGET, BUDGET);
    let (c, s, l) = connected(&mut net, 90);
    let payload: Vec<u8> = (0..300 << 10).map(|i| i as u8).collect();
    let mut off = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 32 << 10];
    let ok = net.run_until(15 * SEC, |n| {
        let now = n.now;
        if let Ok(k) = n.a.tcp_write(c, &payload[off..], now) {
            off += k;
        }
        while let Ok(k) = n.b().tcp_read(s, &mut buf, now) {
            if k == 0 {
                break;
            }
            got.extend_from_slice(&buf[..k]);
        }
        got.len() == payload.len()
    });
    assert!(ok && got == payload, "data kwam beschadigd of niet aan");
    // Een gegroeide verbinding hoort te sluiten; bij close komt alles terug.
    let now = net.now;
    net.a.tcp_close(c, now).unwrap();
    net.b().tcp_close(s, now).unwrap();
    let slack = TCP_FLOOR_RING;
    let ok = net.run_until(5 * SEC, |n| {
        n.a.budget_free() >= BUDGET - slack && n.b().budget_free() >= BUDGET - slack
    });
    assert!(
        ok,
        "pot niet teruggestort na close: zender {} van {BUDGET} vrij, ontvanger {}",
        net.a.budget_free(),
        net.b().budget_free()
    );
    // Een verse verbinding bewijst dat de pot na de teruggave bruikbaar is.
    let second = dial(&mut net, IP_B, 90, 5 * SEC).expect("verse verbinding na teruggave");
    let s2 = accept(&mut net, sb, l);
    write_all(&mut net, sa, second, b"terug", 5 * SEC);
    assert_eq!(read_exact(&mut net, sb, s2, 5, 5 * SEC), b"terug");
}

#[test]
fn stack_rst_op_losse_ack_is_kaal() {
    let mut net = lone(IP_B, MAC_B, 1);
    let now = net.now;
    net.a.seed_neighbor(IP_A, MAC_A, now).unwrap();
    let f = tcp_frame(
        MAC_B,
        MAC_A,
        IP_A,
        IP_B,
        5555,
        7,
        123,
        777,
        TcpFlags::ACK,
        &[],
    );
    net.a.receive(&f, now).unwrap();
    net.settle();
    let t = net
        .wire_a
        .iter()
        .find_map(|f| seen_tcp(f))
        .expect("geen RST gezien op de draad");
    assert!(t.flags.has(TcpFlags::RST), "antwoord draagt geen RST");
    assert!(
        !t.flags.has(TcpFlags::ACK),
        "RST op een losse ACK draagt de ACK-vlag"
    );
    assert_eq!(t.seq, 777, "RST-seq moet SEG.ACK zijn");
}

#[test]
fn stack_zonder_gateway_faalt_meteen() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    let now = net.now;
    let err = net
        .a
        .tcp_connect([192, 168, 1, 1], 80, Some(now + 10 * SEC), now)
        .unwrap_err();
    assert!(
        alloc::format!("{err}").contains("no gateway"),
        "fout zegt niet wat er mis is: {err}"
    );
    let u = net.a.udp_connect([192, 168, 1, 1], 53).unwrap();
    net.a
        .udp_set_write_deadline(u, Some(now + 10 * SEC))
        .unwrap();
    let err = net.a.udp_send(u, b"query", now).unwrap_err();
    assert!(
        alloc::format!("{err}").contains("no gateway"),
        "fout zegt niet wat er mis is: {err}"
    );
}

#[test]
fn sock_close_deblokkeer_read() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 90);
    let now = net.now;
    assert_eq!(net.a.tcp_read(c, &mut [0; 16], now), Err(Error::WouldBlock));
    let (w, woke) = counting_waker();
    net.a.tcp_register_read_waker(c, &w).unwrap();
    net.run_for(50 * MS);
    net.a.tcp_close(c, net.now).unwrap();
    assert!(
        woke.count() > 0,
        "close deblokkeerde de wachtende read niet"
    );
    assert_eq!(net.a.tcp_read(c, &mut [0; 16], net.now), Err(Error::Closed));
}

#[test]
fn sock_deadline_raakt_lopende_read() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 91);
    let (w, woke) = counting_waker();
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::WouldBlock)
    );
    net.a.tcp_register_read_waker(c, &w).unwrap();
    net.run_for(50 * MS);
    let before = woke.count();
    let dl = net.now + 100 * MS;
    net.a.tcp_set_read_deadline(c, Some(dl)).unwrap();
    net.a.tcp_register_read_waker(c, &w).unwrap();
    let ok = net.run_until(2 * SEC, |n| n.now >= dl && woke.count() > before + 1);
    assert!(
        ok,
        "de nieuw gezette deadline bereikte de lopende read niet"
    );
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::DeadlineExceeded)
    );
}

#[test]
fn stack_close_sluit_alles() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(90).unwrap();
    let u = net.b().udp_bind(5353).unwrap();
    let (wa, accept_woke) = counting_waker();
    let (wr, read_woke) = counting_waker();
    net.b().listen_register_waker(l, &wa).unwrap();
    net.b().udp_register_read_waker(u, &wr).unwrap();
    let _conn = dial(&mut net, IP_B, 90, 5 * SEC).unwrap();
    net.run_for(50 * MS);
    net.b().close();
    let now = net.now;
    assert!(
        accept_woke.count() > 0 && read_woke.count() > 0,
        "wachters bleven hangen na Stack::close"
    );
    assert_eq!(net.b().tcp_accept(l, now), Err(Error::Closed));
    assert_eq!(
        net.b().udp_recv_from(u, &mut [0; 64], now),
        Err(Error::Closed)
    );
    let b = net.b();
    assert!(
        b.pot.used == 0 && slots(b) == 0,
        "na close: pot {} bytes, {} verbindingen",
        b.pot.used,
        slots(b)
    );
}

#[test]
fn stack_close_laat_geen_dynamische_protocolopslag_hangen() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    let s = &mut net.a;
    // De begrensde hoogwaterstand die nog in de rij kan staan als close wint.
    s.arp.cnt.gave_up = 7;
    s.arp
        .nt
        .insert(
            [10, 0, 0, 9],
            NeighborEntry::resolved([2, 0, 0, 0, 0, 9], 0),
        )
        .unwrap();
    s.arp.queue_reply(ArpReply {
        hw: [0; 6],
        ip: [10, 0, 0, 9],
    });
    s.join_group([224, 0, 0, 251]).unwrap();
    s.queue_out([10, 0, 0, 9], wire::PROTO_ICMP, &[0u8; 1024]);
    assert!(s.loopback.push(&[&[0u8; MTU]]));
    s.close();
    assert!(
        s.conns.capacity() == 0
            && s.listeners.capacity() == 0
            && s.arp.nt.entries.capacity() == 0
            && s.groups.capacity() == 0
            && s.out.is_empty()
            && s.loopback.is_empty()
            && s.udp.ports.capacity() == 0,
        "gesloten stack behield dynamische protocolopslag"
    );
    assert_eq!(s.pot.used, 0, "gesloten stack behield bufferbudget");
    assert_eq!(s.stats().arp.gave_up, 7, "close verloor telemetrie");
    assert_eq!(
        s.seed_neighbor([10, 0, 0, 9], [2, 0, 0, 0, 0, 9], 0),
        Err(Error::StackClosed)
    );
    s.close(); // Idempotent.
}

#[test]
fn stack_listener_close_ruimt_embryos_op() {
    let mut net = lone(IP_B, MAC_B, 1);
    let l = net.a.tcp_listen(90).unwrap();
    let f = tcp_frame(
        MAC_B,
        MAC_A,
        IP_A,
        IP_B,
        49152,
        90,
        7000,
        0,
        TcpFlags::SYN,
        &[],
    );
    net.a.receive(&f, net.now).unwrap();
    assert_eq!(
        live_conns(&net.a),
        1,
        "verbindingen na de SYN, wil 1 embryo"
    );
    net.a.tcp_listen_close(l);
    assert!(
        slots(&net.a) == 0 && net.a.pot.used == 0,
        "na listener-close: de halve handshake bleef staan"
    );
}

#[test]
fn tcp_full_close_deadline_ruimt_end_to_end_op() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, srv, _) = connected(&mut net, 90);
    let before_budget = net.a.pot.used;
    // Een levende peer die nul adverteert zonder zijn buffer te vullen: de FIN
    // wacht dan in persist terwijl de peersocket in read wacht.
    net.a.conn_mut(c.idx).unwrap().tcp.snd_wnd = 0;
    let now = net.now;
    net.b()
        .tcp_set_read_deadline(srv, Some(now + 3 * SEC))
        .unwrap();
    let (w, woke) = counting_waker();
    assert_eq!(
        net.b().tcp_read(srv, &mut [0; 1], now),
        Err(Error::WouldBlock)
    );
    net.b().tcp_register_read_waker(srv, &w).unwrap();

    net.a.tcp_close(c, now).unwrap();
    let conn = net.a.conn(c.idx).unwrap();
    assert_eq!(
        conn.tcp.close_deadline,
        now + TCP_FULL_CLOSE_DUR,
        "full-close-deadline ligt niet exact 20 s na close"
    );
    assert!(
        conn.live && net.a.pot.used == TCP_FLOOR_TX && net.a.pot.used < before_budget,
        "voor expiry: retained={} budget={} (voor close {before_budget}), wil alleen de TX-vloer",
        conn.live,
        net.a.pot.used
    );
    net.run_for(20 * MS);
    assert_eq!(
        {
            let now = net.now;
            net.b().tcp_read(srv, &mut [0; 1], now)
        },
        Err(Error::WouldBlock),
        "peer-read eindigde vóór de deadline"
    );

    // Een gerichte timernaad: maak de al gezette deadline nu rijp.
    net.a.conn_mut(c.idx).unwrap().tcp.close_deadline = net.now - 1;
    net.settle();
    assert!(woke.count() > 0, "de RST wekte de peer-read niet");
    assert_eq!(
        {
            let now = net.now;
            net.b().tcp_read(srv, &mut [0; 1], now)
        },
        Err(Error::Reset)
    );
    assert!(
        slots(&net.a) == 0 && net.a.pot.used == 0 && net.a.out.is_empty(),
        "na expiry: slots={} budget={} queued={}",
        slots(&net.a),
        net.a.pot.used,
        net.a.out.len()
    );
    let b = net.b();
    assert!(
        live_conns(b) == 0 && b.pot.used == 0,
        "peer hield na de RST verbindingen of budget vast"
    );
}

#[test]
fn stack_dial_annuleerbaar() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    let now = net.now;
    let h = net
        .a
        .tcp_connect([10, 0, 0, 99], 80, Some(now + 10 * SEC), now)
        .unwrap();
    net.run_for(50 * MS);
    // Annuleren is sluiten: één opruimpad.
    net.a.tcp_close(h, net.now).unwrap();
    net.settle();
    assert_eq!(
        net.a.tcp_poll_connect(h, net.now),
        Err(Error::Closed),
        "geannuleerde dial gaf een verbinding"
    );
    assert!(
        net.a.pot.used == 0 && slots(&net.a) == 0,
        "na de cancel: pot {}, slots {}",
        net.a.pot.used,
        slots(&net.a)
    );
}

#[test]
fn sock_staart_lezen_dan_sluiten() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, srv, _) = connected(&mut net, 90);
    write_all(&mut net, sb, srv, b"staart", 2 * SEC);
    let now = net.now;
    net.b().tcp_close(srv, now).unwrap();
    net.settle();
    let mut buf = [0u8; 64];
    let n = net
        .a
        .tcp_read(c, &mut buf, net.now)
        .expect("CLOSE-WAIT hoort de staart te bewaren");
    assert_eq!(&buf[..n], b"staart");
    assert_eq!(
        net.a.tcp_read(c, &mut buf, net.now),
        Ok(0),
        "read na de staart hoort EOF te zijn"
    );
    net.a.tcp_close(c, net.now).unwrap();
    let ok = net.run_until(5 * SEC, |n| slots(&n.a) == 0 && n.a.pot.used == 0);
    assert!(
        ok,
        "na close: {} plekken, pot {}",
        slots(&net.a),
        net.a.pot.used
    );
}

#[test]
fn stack_reap_wekt_geblokkeerde_read() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 90);
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::WouldBlock)
    );
    let (w, woke) = counting_waker();
    net.a.tcp_register_read_waker(c, &w).unwrap();
    net.a.abort_and_reap(c.idx);
    assert!(woke.count() > 0, "reap wekte de geblokkeerde read niet");
    let r = net.a.tcp_read(c, &mut [0; 16], net.now);
    assert_eq!(
        r,
        Err(Error::Reset),
        "read na reap hoort de reset-fout te geven"
    );
}

#[test]
fn stack_route_dood_breekt_de_verbinding() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 90);
    net.run_for(100 * MS);
    net.cut = true;
    net.a.arp.nt.remove(IP_B);
    write_all(&mut net, sa, c, b"de leegte in", SEC);
    let start = net.now;
    net.a
        .tcp_set_read_deadline(c, Some(start + 15 * SEC))
        .unwrap();
    let mut res = Err(Error::WouldBlock);
    net.run_until(15 * SEC, |n| {
        res = n.a.tcp_read(c, &mut [0; 16], n.now);
        res != Err(Error::WouldBlock)
    });
    assert!(
        res.is_err() && res != Err(Error::DeadlineExceeded),
        "read gaf {res:?}: de verbinding hoort te breken als de route luid dood is"
    );
    assert!(
        net.now - start <= 12 * SEC,
        "dat is de deadline, niet de route-dood"
    );
}

#[test]
fn stack_accept_na_close_geeft_nooit_een_verbinding() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(90).unwrap();
    dial(&mut net, IP_B, 90, 5 * SEC).unwrap();
    net.b().close();
    for i in 0..32 {
        let now = net.now;
        assert_eq!(
            net.b().tcp_accept(l, now),
            Err(Error::Closed),
            "accept #{i} na Stack::close"
        );
    }
}

#[test]
fn stack_syn_rst_maakt_geen_verbinding() {
    let mut net = lone(IP_B, MAC_B, 1);
    net.a.tcp_listen(90).unwrap();
    let f = tcp_frame(
        MAC_B,
        MAC_A,
        IP_A,
        IP_B,
        49152,
        90,
        7000,
        0,
        TcpFlags::SYN | TcpFlags::RST,
        &[],
    );
    net.a.receive(&f, net.now).unwrap();
    assert!(
        slots(&net.a) == 0 && net.a.pot.used == 0,
        "SYN|RST maakte een verbinding"
    );
}

#[test]
fn stack_off_subnet_embryo_sterft() {
    let mut net = lone(IP_B, MAC_B, 1);
    net.a.tcp_listen(90).unwrap();
    let f = tcp_frame(
        MAC_B,
        [2, 0, 0, 0, 0, 9],
        [192, 168, 1, 9],
        IP_B,
        49152,
        90,
        7000,
        0,
        TcpFlags::SYN,
        &[],
    );
    net.a.receive(&f, net.now).unwrap();
    let ok = net.run_until(3 * SEC, |n| slots(&n.a) == 0 && n.a.pot.used == 0);
    assert!(ok, "embryo zonder route leeft nog: de zombieklasse");
}

#[test]
fn stack_dial_zegt_no_route_niet_timeout() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    let err = dial(&mut net, [10, 0, 0, 99], 80, 20 * SEC).unwrap_err();
    assert_eq!(
        err,
        Error::Unreachable {
            hop: [10, 0, 0, 99]
        },
        "de fout hoort naar de route te wijzen"
    );
}

#[test]
fn stack_volle_loopback_is_geen_succes() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    let s = &mut net.a;
    while s.loopback.len() < LOOPBACK_MAX {
        assert!(s.loopback.push(&[&[0u8]]));
    }
    let drops = s.stats.drop_reply_full;
    let mut frame = vec![0u8; 128];
    let r = s.send_eth(&mut frame, MAC_A, wire::ETHERTYPE_IPV4, 32);
    assert_eq!(
        r,
        Err(Error::LoopbackFull),
        "een volle loopback meldde succes"
    );
    assert_eq!(s.stats.drop_reply_full, drops + 1, "drop niet geteld");
}

#[test]
fn sock_deadline_verlengen_en_wissen() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 90);
    net.a
        .tcp_set_read_deadline(c, Some(net.now + 150 * MS))
        .unwrap();
    net.run_for(50 * MS);
    net.a.tcp_set_read_deadline(c, None).unwrap();
    net.run_for(400 * MS);
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::WouldBlock),
        "read gaf op een gewiste deadline"
    );
    net.a
        .tcp_set_read_deadline(c, Some(net.now + 50 * MS))
        .unwrap();
    net.run_for(50 * MS);
    assert_eq!(
        net.a.tcp_read(c, &mut [0; 16], net.now),
        Err(Error::DeadlineExceeded),
        "de vervroegde deadline bereikte de read niet"
    );
}

#[test]
fn stack_ctx_deadline_geeft_contextfout() {
    let mut net = Net::single(cfg_a(1 << 20), 1);
    for i in 0..8 {
        let err = dial(&mut net, [10, 0, 0, 99], 80, 60 * MS).unwrap_err();
        assert_eq!(err, Error::DeadlineExceeded, "poging {i}");
    }
}

#[test]
fn stack_rst_ack_telt_seg_len() {
    let mut net = lone(IP_B, MAC_B, 1);
    let now = net.now;
    net.a.seed_neighbor(IP_A, MAC_A, now).unwrap();
    for (flags, data, seq, want) in [
        (TcpFlags::NONE, &b"data"[..], 100u32, 104u32),
        (TcpFlags::SYN | TcpFlags::FIN, &b""[..], 200, 202),
    ] {
        net.wire_a.clear();
        let f = tcp_frame(MAC_B, MAC_A, IP_A, IP_B, 5555, 7, seq, 0, flags, data);
        net.a.receive(&f, net.now).unwrap();
        net.settle();
        let t = net
            .wire_a
            .iter()
            .filter_map(|f| seen_tcp(f))
            .find(|t| t.flags.has(TcpFlags::RST))
            .expect("geen RST gezien");
        assert_eq!(t.ack, want, "RST-ack");
    }
}

#[test]
fn arp_kapotte_checksum_leert_niet() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    net.a.tcp_listen(80).unwrap();
    let src = [10, 0, 0, 9];
    let mut f = tcp_frame(
        MAC_A,
        [2, 0, 0, 0, 0, 9],
        src,
        IP_A,
        999,
        80,
        1,
        0,
        TcpFlags::SYN,
        &[],
    );
    f[wire::SIZE_ETH + wire::SIZE_IPV4 + 16] ^= 0xff;
    net.a.receive(&f, net.now).unwrap();
    assert!(
        net.a.arp.nt.get(src).is_none(),
        "een frame met kapotte TCP-checksum veroverde een ARP-plek"
    );
    let f = tcp_frame(
        MAC_A,
        [2, 0, 0, 0, 0, 9],
        src,
        IP_A,
        999,
        80,
        1,
        0,
        TcpFlags::SYN,
        &[],
    );
    net.a.receive(&f, net.now).unwrap();
    assert!(
        net.a.arp.nt.get(src).is_some(),
        "een geldige SYN leerde de buur niet"
    );
}

#[test]
fn read_met_lege_buffer_keert_meteen_terug() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, _, _) = connected(&mut net, 91);
    assert_eq!(
        net.a.tcp_read(c, &mut [], net.now),
        Ok(0),
        "een lege read hoort meteen terug te keren"
    );
}

#[test]
fn refuse_rst_start_geen_arp_query() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let now = net.now;
    let mut i = 2u8;
    while net.a.arp.nt.len() < ARP_CACHE_CAP {
        net.a.arp.learn([10, 0, 0, i], [2, 0, 0, 0, 0, 9], now);
        i += 1;
    }
    let src = [10, 0, 0, 200];
    let f = tcp_frame(
        MAC_A,
        [2, 0, 0, 0, 0, 9],
        src,
        IP_A,
        999,
        81,
        1,
        0,
        TcpFlags::SYN,
        &[],
    );
    net.a.receive(&f, now).unwrap();
    net.run_for(50 * MS);
    let t = &net.a.arp.nt;
    let pending = t
        .entries
        .iter()
        .filter(|(_, e)| e.state == NeighborState::Pending)
        .count();
    assert!(
        t.get(src).is_none() && pending == 0 && t.len() <= ARP_CACHE_CAP,
        "de refuse-RST raakte de cache: pending={pending} n={}",
        t.len()
    );
}

#[test]
fn refuse_rst_naar_gateway_start_wel_een_query() {
    let gw = [10, 0, 0, 254];
    let mut net = Net::single(
        Config {
            gw,
            ..cfg_a(1 << 20)
        },
        7,
    );
    let f = tcp_frame(
        MAC_A,
        [2, 0, 0, 0, 0, 9],
        [192, 168, 1, 5],
        IP_A,
        999,
        81,
        1,
        0,
        TcpFlags::SYN,
        &[],
    );
    net.a.receive(&f, net.now).unwrap();
    net.run_for(50 * MS);
    assert!(
        net.a
            .arp
            .nt
            .get(gw)
            .is_some_and(|e| e.state == NeighborState::Pending),
        "de RST naar een off-subnet peer startte geen gateway-query"
    );
}

/// De Go-test weigerde ook poort -1 en 65536; in Rust kan alleen nul.
#[test]
fn socket_weigert_onzinnige_poort() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let now = net.now;
    assert_eq!(
        net.a.tcp_connect(IP_B, 0, None, now),
        Err(Error::InvalidPort)
    );
    assert_eq!(slots(&net.a), 0);
}

#[test]
fn connected_udp_filtert_bij_deliver() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let u = net.a.udp_connect(IP_B, 53).unwrap();
    let port = net.a.udp_local(u).unwrap().port;
    let spoofed = (0..1000)
        .filter(|_| {
            net.a
                .udp
                .deliver(port, [10, 0, 0, 66], 6666, &[0u8; 512])
                .is_some()
        })
        .count();
    let echt = net.a.udp.deliver(port, IP_B, 53, b"antwoord").is_some();
    assert_eq!(spoofed, 0, "gespoofde datagrammen kwamen de rij in");
    assert!(
        echt,
        "de echte peer werd verdrongen: het filter zit te laat"
    );
}

#[test]
fn accept_ziet_snelle_sluiter() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let l = net.a.tcp_listen(80).unwrap();
    let key = ConnKey {
        lport: 80,
        rip: IP_B,
        rport: 40000,
    };
    let i = net.a.new_conn(key).unwrap();
    let c = net.a.conn_mut(i).unwrap();
    c.listener = Some(l);
    c.tcp.state = TcpState::CloseWait;
    let now = net.now;
    net.a.maybe_accept(i, now);
    assert!(
        net.a.tcp_accept(l, now).is_ok(),
        "CLOSE-WAIT telt niet als aangekomen"
    );
}

#[test]
fn accept_slaat_gereapte_backlog_over() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let l = net.a.tcp_listen(80).unwrap();
    let live_key = ConnKey {
        lport: 80,
        rip: IP_B,
        rport: 40001,
    };
    let i = net.a.new_conn(live_key).unwrap();
    let c = net.a.conn_mut(i).unwrap();
    c.tcp.state = TcpState::Established;
    let live = TcpHandle {
        idx: i,
        generation: c.generation,
    };
    let stale = TcpHandle {
        idx: 99,
        generation: 1,
    };
    let lst = net.a.listener_mut(l).unwrap();
    assert!(lst.push(stale) && lst.push(live));
    assert_eq!(
        net.a.tcp_accept(l, net.now),
        Ok(live),
        "accept gaf een al gereapte backlogreferentie"
    );
}

#[test]
fn ongeaccepteerde_handshake_verloopt_en_maakt_backlog_vrij() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let now = net.now;
    net.a.seed_neighbor(IP_B, MAC_B, now).unwrap();
    let l = net.a.tcp_listen(80).unwrap();
    let key = ConnKey {
        lport: 80,
        rip: IP_B,
        rport: 50000,
    };
    let i = net.a.new_conn(key).unwrap();
    let c = net.a.conn_mut(i).unwrap();
    c.listener = Some(l);
    c.tcp.state = TcpState::Established;
    net.a.maybe_accept(i, now);
    let deadline = net.a.conn(i).unwrap().handoff_deadline;
    // Meer peersegmenten komen langs maybe_accept maar vernieuwen de
    // eigenaarloze overdracht nooit.
    net.a.maybe_accept(i, now + TCP_BACKLOG_WAIT_DUR / 2);
    let unchanged = net.a.conn(i).unwrap().handoff_deadline;
    let next = net.a.next_timeout(now);
    assert!(
        deadline != 0 && unchanged == deadline && next == Some(deadline),
        "handoffdeadline: first={deadline} na peeractiviteit={unchanged} next={next:?}"
    );
    // Maak de absolute deadline rijp; de pomp moet het tupel opruimen.
    net.a.conn_mut(i).unwrap().handoff_deadline = now - 1;
    net.settle();
    assert!(
        slots(&net.a) == 0 && net.a.pot.used == 0,
        "eigenaarloze backlogverbinding bleef staan"
    );
    // Reap haalde de verbinding weg; offer moet de verouderde backlogentry ook
    // weghalen vóór het plafond geldt.
    let lst = net.a.listener_mut(l).unwrap();
    while lst.len < TCP_BACKLOG {
        lst.push(TcpHandle {
            idx: 77,
            generation: 7,
        });
    }
    let j = net
        .a
        .new_conn(ConnKey {
            rport: 50001,
            ..key
        })
        .unwrap();
    let replacement = TcpHandle {
        idx: j,
        generation: net.a.conn(j).unwrap().generation,
    };
    net.a.offer(l, replacement);
    let lst = net.a.listener_mut(l).unwrap();
    assert_eq!(lst.len, 1, "offer behield verouderde backlogplekken");
    assert_eq!(
        lst.pop(),
        Some(replacement),
        "de gezonde handshake kwam niet in de opgeschoonde backlog"
    );
}

#[test]
fn jumbo_frame_wordt_geweigerd() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let voor = net.a.stats().drop_bad_frame;
    net.a.receive(&[0u8; 3000], net.now).unwrap();
    assert_eq!(
        net.a.stats().drop_bad_frame,
        voor + 1,
        "een jumboframe kwam langs de maatwacht"
    );
}

#[test]
fn read_weigert_na_verstreken_deadline() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, srv, _) = connected(&mut net, 92);
    write_all(&mut net, sb, srv, b"wachtend", SEC);
    net.run_for(200 * MS);
    net.a.tcp_set_read_deadline(c, Some(net.now - SEC)).unwrap();
    let r = net.a.tcp_read(c, &mut [0; 16], net.now);
    assert_eq!(
        r,
        Err(Error::DeadlineExceeded),
        "read leverde data ná een verstreken deadline"
    );
}

#[test]
fn udp_schrijver_wordt_gewekt_bij_arp_opgave() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let u = net.a.udp_connect([10, 0, 0, 99], 53).unwrap();
    let start = net.now;
    net.a
        .udp_set_write_deadline(u, Some(start + 30 * SEC))
        .unwrap();
    assert_eq!(net.a.udp_send(u, b"hallo", start), Err(Error::WouldBlock));
    let (w, woke) = counting_waker();
    let mut res = Err(Error::WouldBlock);
    net.run_until(30 * SEC, |n| {
        if woke.count() > 0 || n.now == start {
            res = n.a.udp_send(u, b"hallo", n.now);
            if res == Err(Error::WouldBlock) {
                n.a.udp_register_write_waker(u, &w).unwrap();
            }
        }
        res != Err(Error::WouldBlock)
    });
    assert_eq!(
        res,
        Err(Error::Unreachable {
            hop: [10, 0, 0, 99]
        })
    );
    assert!(
        net.now - start <= 8 * SEC,
        "de opgave-wek kwam te laat: de schrijver sliep tot zijn deadline"
    );
}

#[test]
fn socket_close_geeft_rx_direct_terug() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let l = net.b().tcp_listen(93).unwrap();
    let c = dial(&mut net, IP_B, 93, 5 * SEC).unwrap();
    let _srv = accept(&mut net, sb, l);
    net.a.tcp_close(c, net.now).unwrap();
    net.run_for(200 * MS);
    assert_eq!(
        net.a.pot.used, 0,
        "a's pot draagt nog bytes na de volle close"
    );
}

#[test]
fn connected_udp_weigert_write_to() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let u = net.a.udp_connect(IP_B, 53).unwrap();
    let to = Endpoint {
        ip: [10, 0, 0, 3],
        port: 53,
    };
    assert_eq!(
        net.a.udp_send_to(u, to, b"x", net.now),
        Err(Error::WriteToConnected)
    );
}

#[test]
fn seed_neighbor_kent_een_plafond() {
    let mut net = Net::single(cfg_a(1 << 20), 7);
    let now = net.now;
    let geweigerd = (2..2 + ARP_CACHE_CAP).any(|i| {
        net.a
            .seed_neighbor([10, 0, 0, i as u8], [2, 0, 0, 0, 0, 9], now)
            .is_err()
    });
    assert!(
        geweigerd,
        "de cap-hoeveelheid seeds werd zonder morren geaccepteerd"
    );
    assert!(
        ARP_CACHE_CAP > net.a.arp.nt.len(),
        "geen vrije cacheplekken over voor resolve"
    );
}

/// Wacht tot a een lopende ARP-query voor `ip` heeft.
fn wacht_op_pending(net: &mut Net, ip: [u8; 4]) {
    let ok = net.run_until(2 * SEC, |n| {
        n.a.arp
            .nt
            .get(ip)
            .is_some_and(|e| e.state == NeighborState::Pending)
    });
    assert!(ok, "de ARP-query kwam nooit op gang");
}

#[test]
fn seed_wekt_de_wachter() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let pc = net.a.udp_bind(9000).unwrap();
    let doel = [10, 0, 0, 99];
    let to = Endpoint { ip: doel, port: 7 };
    assert_eq!(
        net.a.udp_send_to(pc, to, b"ping", net.now),
        Err(Error::WouldBlock)
    );
    let (w, woke) = counting_waker();
    net.a.udp_register_write_waker(pc, &w).unwrap();
    wacht_op_pending(&mut net, doel);
    net.a
        .seed_neighbor(doel, [2, 0, 0, 0, 0, 99], net.now)
        .unwrap();
    assert!(
        woke.count() > 0,
        "de seed loste de route op maar wekte de wachter niet"
    );
    assert_eq!(net.a.udp_send_to(pc, to, b"ping", net.now), Ok(4));
}

#[test]
fn passief_leren_wekt_de_wachter() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let pc = net.a.udp_bind(9001).unwrap();
    let doel = [10, 0, 0, 99];
    let to = Endpoint { ip: doel, port: 7 };
    assert_eq!(
        net.a.udp_send_to(pc, to, b"ping", net.now),
        Err(Error::WouldBlock)
    );
    let (w, woke) = counting_waker();
    net.a.udp_register_write_waker(pc, &w).unwrap();
    wacht_op_pending(&mut net, doel);
    let f = udp_frame(MAC_A, [2, 0, 0, 0, 0, 99], doel, IP_A, 7, 4321, &[]);
    net.a.receive(&f, net.now).unwrap();
    assert!(
        woke.count() > 0,
        "het passieve leren loste de route op maar wekte de wachter niet"
    );
    assert_eq!(net.a.udp_send_to(pc, to, b"ping", net.now), Ok(4));
}

#[test]
fn seed_respecteert_totaalcap() {
    let mut net = Net::pair(0, 0);
    let now = net.now;
    for i in 0..65u8 {
        net.a
            .arp
            .nt
            .insert([10, 0, 0, 3 + i], NeighborEntry::pending(now))
            .unwrap();
    }
    let mut geplant = 0;
    let mut laatste = Ok(());
    for i in 0..64u8 {
        laatste = net
            .a
            .seed_neighbor([10, 0, 0, 100 + i], [2, 0, 0, 0, 0, i], now);
        if laatste.is_ok() {
            geplant += 1;
        }
    }
    assert!(
        geplant == 63 && laatste.is_err(),
        "{geplant} seeds geplant (wil 63), laatste {laatste:?}"
    );
    assert!(net.a.arp.nt.len() <= ARP_CACHE_CAP, "tabel boven de cap");
}

#[test]
fn gateway_seed_dekt_ook_de_gateway_zelf() {
    let a = Stack::new(
        Config {
            gw: IP_B,
            ..cfg_a(1 << 20)
        },
        12345,
    )
    .unwrap();
    let b = Stack::new(cfg_b(1 << 20), 54321).unwrap();
    let mut net = Net::with(a, Some(b));
    net.a.seed_neighbor(IP_B, MAC_B, net.now).unwrap();
    let l = net.b().tcp_listen(80).unwrap();
    let c = dial(&mut net, IP_B, 80, 5 * SEC).expect("dial naar de geseede gateway");
    let s = accept(&mut net, sb, l);
    let now = net.now;
    net.b().tcp_close(s, now).unwrap();
    net.a.tcp_close(c, net.now).unwrap();
    let pc = net.a.udp_bind(9002).unwrap();
    net.a
        .udp_send_to(pc, Endpoint { ip: IP_B, port: 7 }, b"hi", net.now)
        .expect("UDP naar de geseede gateway");
    net.settle();
    assert_eq!(
        net.arp_frames_a, 0,
        "ARP-frames de deur uit: de seed belooft er nul"
    );
}

#[test]
fn statische_gateway_negeert_volle_tabel() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let now = net.now;
    net.a.cfg.gw = IP_B;
    net.a.gw_mac = Some(MAC_B);
    for i in 0..ARP_CACHE_CAP {
        net.a
            .arp
            .nt
            .insert([10, 0, 1, i as u8], NeighborEntry::pending(now))
            .unwrap();
    }
    let err =
        dial(&mut net, [192, 168, 1, 1], 80, 400 * MS).expect_err("dial slaagde zonder server");
    assert!(
        !alloc::format!("{err}").contains("no route to host"),
        "de volle ARP-tabel blokkeerde een route zonder ARP-lot: {err}"
    );
    let pc = net.a.udp_bind(9003).unwrap();
    let to = Endpoint {
        ip: [192, 168, 1, 1],
        port: 7,
    };
    assert_eq!(
        net.a.udp_send_to(pc, to, b"hi", net.now),
        Ok(2),
        "off-subnet UDP via de statische gateway"
    );
}

#[test]
fn reseed_van_bestaande_static_mag_altijd() {
    let mut net = Net::pair(0, 0);
    let now = net.now;
    for i in 0..(ARP_CACHE_CAP / 2) as u8 {
        net.a
            .seed_neighbor([10, 0, 0, 10 + i], [2, 0, 0, 0, 0, i], now)
            .unwrap_or_else(|e| panic!("seed {i}: {e}"));
    }
    assert!(
        net.a
            .seed_neighbor([10, 0, 0, 200], [2, 0, 0, 0, 0, 200], now)
            .is_err(),
        "de 65e seed passeerde de cap"
    );
    net.a
        .seed_neighbor([10, 0, 0, 10], [2, 0, 0, 0, 0, 99], now)
        .expect("MAC-update van een bestaande static");
}

// ---- ephemeral_seed_test.go ----

#[test]
fn stack_fresh_seeds_change_ephemeral_start() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let pa = net.a.ephemeral_port(Stack::tcp_port_in_use).unwrap();
    let pb = net.b().ephemeral_port(Stack::tcp_port_in_use).unwrap();
    assert!(
        pa != pb && pa >= EPHEMERAL_BASE && pb >= EPHEMERAL_BASE,
        "ports {pa} {pb}"
    );
}

#[test]
fn stack_seeded_ephemeral_range_and_wrap() {
    for seed in [0u32, 1, 16383, 16384, u32::MAX] {
        let mut s = Stack::new(
            Config {
                prefix: 24,
                budget: 1 << 20,
                ..Config::default()
            },
            seed,
        )
        .unwrap();
        let mut pick = || s.ephemeral_port(|_, _| false).unwrap();
        let first = pick();
        assert_eq!(first, EPHEMERAL_BASE + (seed % 16384) as u16, "seed {seed}");
        let mut seen = vec![false; 65536];
        seen[usize::from(first)] = true;
        for _ in 1..16384 {
            let p = pick();
            assert!(
                p >= EPHEMERAL_BASE && !seen[usize::from(p)],
                "seed {seed}: port {p} repeat/outside"
            );
            seen[usize::from(p)] = true;
        }
        assert_eq!(pick(), first, "full cycle did not wrap");
    }
}

// ---- jumbo_test.go ----

/// Twee stacks met MTU 65535 op één prefix wisselen segmenten van bijna
/// 64 KiB uit: de MSS volgt de MTU per bestemming.
#[test]
fn jumbo_mss() {
    const JUMBO: usize = 65535;
    let jumbo = |cfg: Config| Config {
        budget: 8 << 20,
        max_buf_per_conn: 1 << 20,
        adv_ws: 4,
        mtu: JUMBO,
        ..cfg
    };
    let a = Stack::new(jumbo(cfg_a(0)), 1).unwrap();
    let b = Stack::new(jumbo(cfg_b(0)), 2).unwrap();
    let mut net = Net::with(a, Some(b));
    let (c, s, _) = connected(&mut net, 80);
    let msg: Vec<u8> = (0..1 << 20).map(|i| (i * 7) as u8).collect();
    let mut off = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 128 << 10];
    let ok = net.run_until(5 * SEC, |n| {
        let now = n.now;
        if let Ok(k) = n.a.tcp_write(c, &msg[off..], now) {
            off += k;
        }
        while let Ok(k) = n.b().tcp_read(s, &mut buf, now) {
            if k == 0 {
                break;
            }
            got.extend_from_slice(&buf[..k]);
        }
        got.len() == msg.len()
    });
    assert!(
        ok && got == msg,
        "ontvangen {} van {} bytes",
        got.len(),
        msg.len()
    );
    let st = net.a.stats();
    let avg = st.tcp_bytes_out / st.tcp_segs_out.max(1);
    assert!(
        avg >= 16 << 10,
        "gemiddeld segment {avg} B: jumbo-MSS niet onderhandeld"
    );
}

// ---- congestion_test.go (stackkant) ----

#[test]
fn stack_congestion_follows_trusted_route() {
    let mut s = Stack::new(
        Config {
            link_trusted: true,
            ..cfg_a(1 << 20)
        },
        1,
    )
    .unwrap();
    for ip in [[10, 0, 0, 2], [192, 168, 1, 144]] {
        let i = s
            .new_conn(ConnKey {
                lport: 8080,
                rip: ip,
                rport: 9000,
            })
            .unwrap();
        assert_ne!(
            s.conn(i).unwrap().tcp.congestion,
            s.trusted(ip),
            "wrong congestion policy for {ip:?}"
        );
    }
}

/// Een gewone begrensde RX-vloer: de verbinding start op de afgesproken maten.
#[test]
fn stack_conn_starts_at_floors() {
    let mut s = Stack::new(cfg_a(1 << 20), 1).unwrap();
    let i = s
        .new_conn(ConnKey {
            lport: 1,
            rip: IP_B,
            rport: 2,
        })
        .unwrap();
    let c = s.conn(i).unwrap();
    assert_eq!(
        (c.tcp.rx.size(), c.tcp.tx.size()),
        (TCP_FLOOR_RX, TCP_FLOOR_TX)
    );
    assert_eq!(s.pot.used, TCP_FLOOR_RING);
}

// ---- tcp_unacked en de flush (lean v3.1) ----

/// Brengt alle frames van a één voor één naar b en na elk frame b's
/// antwoorden terug, en geeft `tcp_unacked(h)` na elke ronde. Zo is elke
/// afzonderlijke ACK zichtbaar in plaats van alleen de eindstand.
fn step_unacked(net: &mut Net, h: TcpHandle) -> Vec<usize> {
    let now = net.now;
    let mut frame = vec![0u8; net.a.frame_len()];
    let mut out = Vec::new();
    while let Some(n) = net.a.poll_transmit(now, &mut frame) {
        out.push(frame[..n].to_vec());
    }
    let mut seen = Vec::new();
    for f in out {
        let _ = net.b().receive(&f, now);
        while let Some(n) = net.b().poll_transmit(now, &mut frame) {
            let _ = net.a.receive(&frame[..n], now);
        }
        seen.push(net.a.tcp_unacked(h).unwrap());
    }
    seen
}

/// Geschreven data telt tot de peer haar bevestigt, en daalt per ACK naar nul;
/// de write-waker gaat bij die ACKs af.
#[test]
fn unacked_daalt_met_acks_naar_nul() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, s, _) = connected(&mut net, 7001);
    assert_eq!(net.a.tcp_unacked(c), Ok(0), "verse verbinding");

    let data = vec![7u8; 3000]; // Drie segmenten bij een MSS van 1460.
    let now = net.now;
    assert_eq!(net.a.tcp_write(c, &data, now), Ok(3000));
    assert_eq!(net.a.tcp_unacked(c), Ok(3000), "onverzonden telt mee");

    let (w, woke) = counting_waker();
    net.a.tcp_register_write_waker(c, &w).unwrap();
    let seen = step_unacked(&mut net, c);
    assert!(woke.count() > 0, "write-waker ging niet af bij een ACK");
    assert!(
        seen.windows(2).all(|p| p[1] <= p[0]),
        "unacked steeg: {seen:?}"
    );
    assert!(
        seen.iter().any(|&u| u > 0 && u < 3000),
        "geen tussenstand per ACK: {seen:?}"
    );
    assert_eq!(seen.last(), Some(&0), "niet alles bevestigd: {seen:?}");
    assert_eq!(read_exact(&mut net, sb, s, 3000, SEC), data);
}

/// Na een close telt de FIN als één tot de peer hem bevestigt; een verloren
/// FIN houdt de teller op één. TIME-WAIT is nul, daarna is het handvat weg.
#[test]
fn unacked_fin_telt_tot_peer_ackt_en_time_wait_sluit_af() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, s, _) = connected(&mut net, 7002);
    let now = net.now;
    net.a.tcp_write(c, &[1u8; 100], now).unwrap();
    net.a.tcp_close(c, now).unwrap();
    // I/O is dicht, de bevraging niet: 100 bytes plus de FIN.
    assert_eq!(net.a.tcp_write(c, &[1], now), Err(Error::Closed));
    assert_eq!(net.a.tcp_unacked(c), Ok(101));

    // De draad is door: data en FIN gaan verloren, de teller blijft staan.
    net.cut = true;
    net.run_for(50 * MS);
    assert_eq!(
        net.a.tcp_unacked(c),
        Ok(101),
        "verloren data telde als bevestigd"
    );

    // De waker werkt na de close en gaat af als de hertransmissie bevestigd wordt.
    let (w, woke) = counting_waker();
    net.a.tcp_register_write_waker(c, &w).unwrap();
    net.cut = false;
    let acked = net.run_until(5 * SEC, |n| n.a.tcp_unacked(c) == Ok(0));
    assert!(acked, "FIN nooit bevestigd: {:?}", net.a.tcp_unacked(c));
    assert!(woke.count() > 0, "write-waker ging niet af na de close");
    assert_eq!(
        net.a.conns[c.idx].as_ref().unwrap().tcp.state,
        TcpState::FinWait2
    );

    // De server leest de staart en EOF en sluit; a gaat naar TIME-WAIT.
    let now = net.now;
    let mut buf = [0u8; 256];
    assert_eq!(net.b().tcp_read(s, &mut buf, now), Ok(100));
    assert_eq!(net.b().tcp_read(s, &mut buf, now), Ok(0), "geen EOF");
    net.b().tcp_close(s, now).unwrap();
    assert_eq!(net.b().tcp_unacked(s), Ok(1), "de FIN van b telt");
    // a adverteert na zijn close een nulvenster (zijn ontvangstring is terug),
    // dus b's FIN gaat mee op de eerste persist-probe, niet meteen.
    let tw = net.run_until(3 * SEC, |n| {
        n.a.conns[c.idx].as_ref().unwrap().tcp.state == TcpState::TimeWait
    });
    assert!(tw, "a kwam niet in TIME-WAIT");
    assert_eq!(
        net.a.tcp_unacked(c),
        Ok(0),
        "TIME-WAIT volgt op een bevestigde FIN"
    );
    // LAST-ACK ging bij de ACK meteen naar gesloten en is opgeruimd.
    assert_eq!(net.b().tcp_unacked(s), Err(Error::Closed));

    // Na TIME-WAIT is het handvat weg, ook als de plek hergebruikt wordt.
    let (w, woke) = counting_waker();
    net.a.tcp_register_write_waker(c, &w).unwrap();
    net.run_for(2 * SEC);
    assert!(woke.count() > 0, "het einde van TIME-WAIT wekte niet");
    assert_eq!(net.a.tcp_unacked(c), Err(Error::Closed));
    assert_eq!(net.a.tcp_register_write_waker(c, &w), Err(Error::Closed));
    let l2 = net.b().tcp_listen(7003).unwrap();
    let c2 = dial(&mut net, IP_B, 7003, 5 * SEC).unwrap();
    let _ = accept(&mut net, sb, l2);
    assert_eq!(c2.idx, c.idx, "de test wil hergebruik van de plek");
    assert_eq!(net.a.tcp_unacked(c), Err(Error::Closed));
    assert_eq!(net.a.tcp_unacked(c2), Ok(0));
}

/// Een peer die niet leest, sluit zijn venster: unacked blijft staan zolang
/// hij niet leest, persist-probes of niet, en valt naar nul als hij leest.
#[test]
fn unacked_blijft_hoog_bij_peer_die_niet_leest() {
    // Een kleine pot aan b houdt zijn ontvangstring op 20 KiB.
    let mut net = Net::pair(1 << 20, 80 << 10);
    let (c, s, _) = connected(&mut net, 7004);
    let data = vec![3u8; 256 << 10];
    let mut off = 0;
    net.run_until(3 * SEC, |n| {
        let now = n.now;
        if let Ok(k) = n.a.tcp_write(c, &data[off..], now) {
            off += k;
        }
        false
    });
    assert!(off < data.len(), "een niet-lezende peer nam alles aan");
    let held = |net: &mut Net| net.b().conns[s.idx].as_ref().unwrap().tcp.rx.buffered();
    let unacked = net.a.tcp_unacked(c).unwrap();
    assert!(unacked > 0, "niets onbevestigd tegen een vol venster");
    assert_eq!(
        unacked + held(&mut net),
        off,
        "unacked is niet wat b nog mist"
    );

    net.run_for(10 * SEC);
    assert_eq!(
        net.a.tcp_unacked(c),
        Ok(unacked),
        "probes veranderden de stand"
    );

    assert_eq!(read_exact(&mut net, sb, s, off, 10 * SEC).len(), off);
    let drained = net.run_until(5 * SEC, |n| n.a.tcp_unacked(c) == Ok(0));
    assert!(drained, "na lezen bleef {:?}", net.a.tcp_unacked(c));
}

/// Een reset terwijl de applicatie het handvat houdt is een fout, geen nul;
/// `Stack::close` stuurt niets en laat geen bevraagbaar handvat achter.
#[test]
fn unacked_reset_en_stack_close() {
    let mut net = Net::pair(1 << 20, 1 << 20);
    let (c, s, _) = connected(&mut net, 7005);
    let now = net.now;
    net.a.tcp_write(c, &[9u8; 500], now).unwrap();
    // b breekt de verbinding af; zijn pomp stuurt de RST.
    net.b().conns[s.idx].as_mut().unwrap().tcp.abort();
    net.settle();
    assert_eq!(net.a.tcp_unacked(c), Err(Error::Reset));

    let (c2, _, _) = connected(&mut net, 7006);
    let now = net.now;
    net.a.tcp_write(c2, &[9u8; 500], now).unwrap();
    net.a.close();
    let mut frame = vec![0u8; 2048];
    assert_eq!(
        net.a.poll_transmit(now, &mut frame),
        None,
        "close stuurde iets"
    );
    assert_eq!(net.a.tcp_unacked(c2), Err(Error::Closed));
}
