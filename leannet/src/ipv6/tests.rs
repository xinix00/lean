//! De Go-IPv6-regressies: draadgedrag, bronkeuze, leases en begrensde levensduur.
use super::*;
use crate::testnet::{MAC_A, MAC_B, cfg_a, cfg_b, counting_waker};
const NOW: u64 = 100 * SEC;
const GROUP: [u8; 16] = [255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251];
fn stack() -> Stack {
    Stack::new(cfg_a(1 << 20), 1).unwrap()
}
fn raw(
    src: [u8; 16],
    dst: [u8; 16],
    mac: [u8; 6],
    next: u8,
    hop: u8,
    mut body: Vec<u8>,
) -> Vec<u8> {
    let off = if next == 17 { 6 } else { 2 };
    body[off..off + 2].fill(0);
    let sum = w::checksum(src, dst, next, &body);
    body[off..off + 2].copy_from_slice(&sum.to_be_bytes());
    let mut f = vec![0; 54 + body.len()];
    wire::put_eth(
        &mut f,
        if dst[0] == 255 {
            w::multicast_mac(dst)
        } else {
            MAC_A
        },
        mac,
        wire::ETHERTYPE_IPV6,
    )
    .unwrap();
    w::put(&mut f[14..], src, dst, next, hop, body.len()).unwrap();
    f[54..].copy_from_slice(&body);
    f
}
fn pio(prefix: [u8; 16], flags: u8, valid: u32, preferred: u32) -> Vec<u8> {
    let mut o = vec![0; 32];
    o[0] = 3;
    o[1] = 4;
    o[2] = 64;
    o[3] = flags;
    o[4..8].copy_from_slice(&valid.to_be_bytes());
    o[8..12].copy_from_slice(&preferred.to_be_bytes());
    o[16..].copy_from_slice(&prefix);
    o
}
fn rio(prefix: [u8; 16], bits: u8, life: u32) -> Vec<u8> {
    let mut o = vec![0; 24];
    o[0] = 24;
    o[1] = 3;
    o[2] = bits;
    o[4..8].copy_from_slice(&life.to_be_bytes());
    o[8..].copy_from_slice(&prefix);
    o
}
fn prefix(n: u8) -> [u8; 16] {
    [253, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
fn ra(router: [u8; 16], mac: [u8; 6], life: u16, options: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b = vec![0; 16];
    b[0] = 134;
    b[6..8].copy_from_slice(&life.to_be_bytes());
    b.extend_from_slice(&[1, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
    for o in options {
        b.extend_from_slice(&o);
    }
    raw(router, w::ALL_NODES, mac, 58, 255, b)
}
fn pump(a: &mut Stack, b: &mut Stack, now: u64) {
    let mut f = [0; 1514];
    for _ in 0..40 {
        let mut progress = false;
        while let Some(n) = a.poll_transmit(now, &mut f) {
            b.receive(&f[..n], now).unwrap();
            progress = true;
        }
        while let Some(n) = b.poll_transmit(now, &mut f) {
            a.receive(&f[..n], now).unwrap();
            progress = true;
        }
        if !progress {
            return;
        }
    }
    panic!("network did not settle")
}
#[test]
fn disabled_lane_is_quiet_and_allocates_no_table() {
    let mut s = stack();
    let f = ra(
        w::link_local(MAC_B),
        MAC_B,
        60,
        vec![pio(prefix(1), 0xc0, 60, 30)],
    );
    s.receive(&f, NOW).unwrap();
    assert!(s.v6.is_none());
    assert_eq!(s.stats().drop_bad_frame, 0);
}
#[test]
fn ndp_two_stacks_udp_roundtrip_and_loopback() {
    let mut a = stack();
    let mut b = Stack::new(cfg_b(1 << 20), 2).unwrap();
    let ah = a.udp6_bind(1000, NOW).unwrap();
    let bh = b.udp6_bind(1000, NOW).unwrap();
    let to = Endpoint6 {
        ip: w::link_local(MAC_B),
        port: b.udp6_local(bh).unwrap().port,
    };
    assert_eq!(
        a.udp6_send_to(ah, to, b"request", NOW),
        Err(Error::WouldBlock)
    );
    pump(&mut a, &mut b, NOW);
    assert_eq!(a.udp6_send_to(ah, to, b"request", NOW), Ok(7));
    pump(&mut a, &mut b, NOW);
    let mut buf = [0; 30];
    let (n, from) = b.udp6_recv_from(bh, &mut buf, NOW).unwrap();
    assert_eq!(&buf[..n], b"request");
    b.udp6_send_to(bh, from, b"reply", NOW).unwrap();
    pump(&mut a, &mut b, NOW);
    assert_eq!(a.udp6_recv_from(ah, &mut buf, NOW).unwrap().0, 5);
    let own = Endpoint6 {
        ip: w::link_local(MAC_A),
        port: a.udp6_local(ah).unwrap().port,
    };
    a.udp6_send_to(ah, own, b"self", NOW).unwrap();
    pump(&mut a, &mut b, NOW);
    assert_eq!(a.udp6_recv_from(ah, &mut buf, NOW).unwrap().0, 4);
}
#[test]
fn multicast_requires_join_and_returns_local_copy() {
    let mut a = stack();
    let mut b = Stack::new(cfg_b(1 << 20), 2).unwrap();
    let ah = a.udp6_bind(5353, NOW).unwrap();
    let bh = b.udp6_bind(5353, NOW).unwrap();
    a.join_group6(GROUP, NOW).unwrap();
    a.udp6_send_to(
        ah,
        Endpoint6 {
            ip: GROUP,
            port: 5353,
        },
        b"query",
        NOW,
    )
    .unwrap();
    pump(&mut a, &mut b, NOW);
    let mut buf = [0; 20];
    assert_eq!(a.udp6_recv_from(ah, &mut buf, NOW).unwrap().0, 5);
    assert_eq!(b.udp6_recv_from(bh, &mut buf, NOW), Err(Error::WouldBlock));
    b.join_group6(GROUP, NOW).unwrap();
    a.udp6_send_to(
        ah,
        Endpoint6 {
            ip: GROUP,
            port: 5353,
        },
        b"query",
        NOW,
    )
    .unwrap();
    pump(&mut a, &mut b, NOW);
    assert_eq!(b.udp6_recv_from(bh, &mut buf, NOW).unwrap().0, 5);
}
#[test]
fn families_rebind_generation_budget_and_deadlines() {
    let mut s = stack();
    let free = s.budget_free();
    let v4 = s.udp_bind(5353).unwrap();
    let v6 = s.udp6_bind(5353, NOW).unwrap();
    let (wake, c) = counting_waker();
    s.udp6_register_read_waker(v6, &wake).unwrap();
    s.udp6_close(v6);
    assert!(c.count() > 0);
    let again = s.udp6_bind(5353, NOW).unwrap();
    assert_eq!(s.udp6_recv_from(v6, &mut [0; 1], NOW), Err(Error::Closed));
    s.udp6_set_read_deadline(again, Some(NOW)).unwrap();
    assert_eq!(
        s.udp6_recv_from(again, &mut [0; 1], NOW),
        Err(Error::DeadlineExceeded)
    );
    s.udp6_close(again);
    s.udp_close(v4);
    assert_eq!(s.budget_free(), free);
    s.close();
    assert_eq!(s.udp6_bind(0, NOW), Err(Error::StackClosed));
}
#[test]
fn fixed_mtu_and_invalid_addresses() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    let to = Endpoint6 { ip: GROUP, port: 1 };
    assert_eq!(
        s.udp6_send_to(h, to, &[0; 1233], NOW),
        Err(Error::DatagramTooLarge {
            len: 1233,
            max: 1232
        })
    );
    assert_eq!(s.udp6_send_to(h, to, &[0; 1232], NOW), Ok(1232));
    for ip in [
        [0; 16],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [255, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        assert_eq!(
            s.udp6_send_to(h, Endpoint6 { ip, port: 1 }, &[], NOW),
            Err(Error::InvalidIpv6)
        );
    }
}
#[test]
fn router_cache_is_not_a_routable_source() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    s.receive(&ra(w::link_local(MAC_B), MAC_B, 60, vec![]), NOW)
        .unwrap();
    assert_eq!(
        s.udp6_send_to(
            h,
            Endpoint6 {
                ip: prefix(7),
                port: 1
            },
            b"x",
            NOW
        ),
        Err(Error::NoRoute6)
    );
}
#[test]
fn slaac_thread_rio_and_router_withdrawal() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    let router = w::link_local(MAC_B);
    s.receive(
        &ra(
            router,
            MAC_B,
            0,
            vec![pio(prefix(1), 0xc0, 120, 100), rio(prefix(2), 64, 60)],
        ),
        NOW,
    )
    .unwrap();
    let to = Endpoint6 {
        ip: prefix(2),
        port: 5540,
    };
    s.udp6_send_to(h, to, b"matter", NOW).unwrap();
    let mut f = [0; 1514];
    let n = s.poll_transmit(NOW, &mut f).unwrap();
    let eth = wire::parse_eth(&f[..n]).unwrap();
    assert_eq!(eth.dst(), MAC_B);
    let p = w::parse(eth.payload()).unwrap();
    assert_eq!(p.src[..8], prefix(1)[..8]);
    assert_eq!(p.dst, to.ip);
    assert_eq!(w::checksum(p.src, p.dst, 17, p.payload), 0);
    assert!(s.v6.as_mut().unwrap().nt.peek(to.ip, NOW).is_none());
    s.receive(&ra(router, MAC_B, 0, vec![rio(prefix(2), 64, 0)]), NOW)
        .unwrap();
    assert_eq!(s.udp6_send_to(h, to, b"matter", NOW), Err(Error::NoRoute6));
}
#[test]
fn thread_route_without_sllao_learns_validated_ethernet_neighbor() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    s.receive(
        &ra(
            w::link_local(MAC_B),
            MAC_B,
            0,
            vec![pio(prefix(1), 0xc0, 1800, 1800)],
        ),
        NOW,
    )
    .unwrap();
    let mac = [2, 3, 4, 5, 6, 7];
    let router = w::link_local(mac);
    let mut body = vec![134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&rio(prefix(2), 64, 1800));
    // Start with a pending lookup, as on hardware before the next RA arrives.
    s.v6.as_mut().unwrap().nt.resolve(router, NOW);
    let wake = counting_waker();
    s.udp6_register_write_waker(h, &wake.0).unwrap();
    let mut malformed = body.clone();
    malformed.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 99]);
    s.receive(&raw(router, w::ALL_NODES, mac, 58, 255, malformed), NOW)
        .unwrap();
    assert!(s.v6.as_mut().unwrap().nt.peek(router, NOW).is_none());
    s.receive(&raw(router, w::ALL_NODES, mac, 58, 64, body.clone()), NOW)
        .unwrap();
    assert!(s.v6.as_mut().unwrap().nt.peek(router, NOW).is_none());
    s.receive(&raw(router, w::ALL_NODES, mac, 58, 255, body), NOW)
        .unwrap();
    assert!(wake.1.count() > 0);
    let peer = Endpoint6 {
        ip: prefix(2),
        port: 5540,
    };
    s.udp6_send_to(h, peer, b"matter", NOW).unwrap();
    let mut frame = [0; 1514];
    let n = s.poll_transmit(NOW, &mut frame).unwrap();
    let eth = wire::parse_eth(&frame[..n]).unwrap();
    assert_eq!(eth.dst(), mac);
    let packet = w::parse(eth.payload()).unwrap();
    assert_eq!(packet.dst, peer.ip);
    assert_eq!(packet.next, 17);
    assert_eq!(w::checksum(packet.src, packet.dst, 17, packet.payload), 0);
}
#[test]
fn malformed_ra_tail_is_atomic_and_hop_limit_is_checked() {
    let mut s = stack();
    s.enable_ipv6(NOW).unwrap();
    let router = w::link_local(MAC_B);
    let bad = ra(
        router,
        MAC_B,
        60,
        vec![pio(prefix(1), 0xc0, 60, 30), vec![24, 0, 0, 0, 0, 0, 0, 0]],
    );
    s.receive(&bad, NOW).unwrap();
    let v = s.v6.as_mut().unwrap();
    assert!(v.router.is_none() && v.global.is_none() && v.nt.peek(router, NOW).is_none());
    assert_eq!(v.stats.bad_ndp, 1);
    let mut f = ra(router, MAC_B, 60, vec![pio(prefix(1), 0xc0, 60, 30)]);
    f[21] = 64;
    s.receive(&f, NOW).unwrap();
    assert_eq!(s.ndp_stats().bad_ndp, 2);
    assert!(s.ipv6_addresses(NOW).unwrap().1.is_none());
}
#[test]
fn independent_pio_flags_and_preferred_address_selection() {
    let mut s = stack();
    s.enable_ipv6(NOW).unwrap();
    let router = w::link_local(MAC_B);
    s.receive(
        &ra(
            router,
            MAC_B,
            0,
            vec![pio(prefix(1), 0xc0, 20, 5), pio(prefix(2), 0xc0, 30, 30)],
        ),
        NOW,
    )
    .unwrap();
    assert_eq!(s.ipv6_addresses(NOW).unwrap().1.unwrap()[1], 1);
    assert_eq!(s.ipv6_addresses(NOW + 5 * SEC).unwrap().1.unwrap()[1], 2);
    s.receive(
        &ra(router, MAC_B, 0, vec![pio(prefix(1), 0x80, 0, 0)]),
        NOW + 6 * SEC,
    )
    .unwrap();
    let p =
        s.v6.as_ref()
            .unwrap()
            .prefixes
            .iter()
            .flatten()
            .find(|p| p.ip == prefix(1))
            .unwrap();
    assert_eq!(p.on_link, 0);
    assert!(p.valid > NOW);
    assert!(s.ipv6_addresses(NOW + 31 * SEC).unwrap().1.is_none());
    assert_eq!(s.next_timeout(NOW + 31 * SEC), Some(NOW + 31 * SEC));
}
#[test]
fn ndp_timeout_wakes_route_waiter_and_retries_after_negative_cache() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    let (wake, c) = counting_waker();
    s.udp6_register_write_waker(h, &wake).unwrap();
    let to = Endpoint6 {
        ip: w::link_local(MAC_B),
        port: 1,
    };
    assert_eq!(s.udp6_send_to(h, to, b"x", NOW), Err(Error::WouldBlock));
    let mut frame = [0; 1514];
    for second in 0..=5 {
        while s.poll_transmit(NOW + second * SEC, &mut frame).is_some() {}
    }
    assert!(c.count() > 0);
    assert_eq!(
        s.udp6_send_to(h, to, b"x", NOW + 5 * SEC),
        Err(Error::Unreachable6)
    );
    assert_eq!(
        s.udp6_send_to(h, to, b"x", NOW + 11 * SEC),
        Err(Error::WouldBlock)
    );
}
#[test]
fn zero_udp_checksum_and_truncated_frames_are_rejected() {
    let mut s = stack();
    let h = s.udp6_bind(99, NOW).unwrap();
    let src = w::link_local(MAC_B);
    let dst = w::link_local(MAC_A);
    let mut body = vec![0; 9];
    body[..2].copy_from_slice(&100_u16.to_be_bytes());
    body[2..4].copy_from_slice(&99_u16.to_be_bytes());
    body[4..6].copy_from_slice(&9_u16.to_be_bytes());
    body[8] = 1;
    let good = raw(src, dst, MAC_B, 17, 64, body);
    for n in 0..good.len() {
        s.receive(&good[..n], NOW).unwrap();
    }
    let mut bad = good.clone();
    bad[60..62].fill(0);
    s.receive(&bad, NOW).unwrap();
    assert_eq!(
        s.udp6_recv_from(h, &mut [0; 2], NOW),
        Err(Error::WouldBlock)
    );
    s.receive(&good, NOW).unwrap();
    assert_eq!(s.udp6_recv_from(h, &mut [0; 2], NOW).unwrap().0, 1);
}
#[test]
fn caps_and_bounded_ra_lifetime() {
    let mut s = stack();
    s.enable_ipv6(NOW).unwrap();
    let router = w::link_local(MAC_B);
    for i in 1..=7 {
        s.receive(
            &ra(
                router,
                MAC_B,
                u16::MAX,
                vec![pio(prefix(i), 0xc0, u32::MAX, u32::MAX)],
            ),
            NOW,
        )
        .unwrap();
    }
    assert_eq!(s.v6.as_ref().unwrap().prefixes.iter().flatten().count(), 4);
    assert_eq!(s.ndp_stats().prefix_drop, 3);
    assert!(s.ipv6_addresses(NOW + 7200 * SEC).unwrap().1.is_none());
    assert!(s.v6.as_ref().unwrap().router.is_none());
}
#[test]
fn unsolicited_na_cannot_create_neighbor_and_mac_mismatch_is_rejected() {
    let mut s = stack();
    s.enable_ipv6(NOW).unwrap();
    let peer = w::link_local(MAC_B);
    let mut b = vec![0; 32];
    b[0] = 136;
    b[4] = 0x20;
    b[8..24].copy_from_slice(&peer);
    b[24] = 2;
    b[25] = 1;
    b[26..].copy_from_slice(&MAC_B);
    let f = raw(peer, w::ALL_NODES, MAC_B, 58, 255, b.clone());
    s.receive(&f, NOW).unwrap();
    assert!(s.v6.as_mut().unwrap().nt.peek(peer, NOW).is_none());
    b[31] ^= 1;
    s.receive(&raw(peer, w::ALL_NODES, MAC_B, 58, 255, b), NOW)
        .unwrap();
    assert_eq!(s.ndp_stats().bad_ndp, 1);
}

#[test]
fn multicast_requires_exact_ethernet_mapping() {
    let mut s = stack();
    let h = s.udp6_bind(99, NOW).unwrap();
    s.join_group6(GROUP, NOW).unwrap();
    let body = vec![0, 100, 0, 99, 0, 9, 0, 0, 1];
    let good = raw(w::link_local(MAC_B), GROUP, MAC_B, 17, 255, body);
    let mut bad = good.clone();
    bad[..6].copy_from_slice(&MAC_A);
    s.receive(&bad, NOW).unwrap();
    assert_eq!(
        s.udp6_recv_from(h, &mut [0; 2], NOW),
        Err(Error::WouldBlock)
    );
    s.receive(&good, NOW).unwrap();
    assert_eq!(s.udp6_recv_from(h, &mut [0; 2], NOW).unwrap().0, 1);
}
#[test]
fn old_router_withdrawal_cannot_erase_replacement_and_expiry_wakes() {
    let mut s = stack();
    let h = s.udp6_bind(0, NOW).unwrap();
    let router = w::link_local(MAC_B);
    let other_mac = [2, 0, 0, 0, 0, 3];
    let other = w::link_local(other_mac);
    s.receive(
        &ra(
            router,
            MAC_B,
            0,
            vec![pio(prefix(1), 0xc0, 60, 60), rio(prefix(2), 64, 10)],
        ),
        NOW,
    )
    .unwrap();
    s.receive(&ra(other, other_mac, 0, vec![rio(prefix(2), 64, 20)]), NOW)
        .unwrap();
    s.receive(&ra(router, MAC_B, 0, vec![rio(prefix(2), 64, 0)]), NOW)
        .unwrap();
    assert_eq!(s.v6.as_ref().unwrap().next_hop(prefix(2)), Some(other));
    let (wake, count) = counting_waker();
    s.udp6_register_write_waker(h, &wake).unwrap();
    let mut f = [0; 1514];
    while s.poll_transmit(NOW + 20 * SEC, &mut f).is_some() {}
    assert!(count.count() > 0);
    assert_eq!(s.v6.as_ref().unwrap().next_hop(prefix(2)), None);
}
#[test]
fn expired_local_identity_suppresses_queued_echo_and_na() {
    let mut s = stack();
    s.enable_ipv6(NOW).unwrap();
    s.receive(
        &ra(
            w::link_local(MAC_B),
            MAC_B,
            60,
            vec![pio(prefix(1), 0xc0, 1, 1)],
        ),
        NOW,
    )
    .unwrap();
    let owned = s.ipv6_addresses(NOW).unwrap().1.unwrap();
    let peer = w::link_local(MAC_B);
    let echo = raw(peer, owned, MAC_B, 58, 64, vec![128, 0, 0, 0, 0, 1, 0, 1]);
    s.receive(&echo, NOW).unwrap();
    let mut ns = vec![0; 32];
    ns[0] = 135;
    ns[8..24].copy_from_slice(&owned);
    ns[24] = 1;
    ns[25] = 1;
    ns[26..].copy_from_slice(&MAC_B);
    s.receive(&raw(peer, w::solicited(owned), MAC_B, 58, 255, ns), NOW)
        .unwrap();
    assert_eq!(s.v6.as_ref().unwrap().replies.len(), 2);
    let mut f = [0; 1514];
    while let Some(n) = s.poll_transmit(NOW + SEC, &mut f) {
        let p = w::parse(&f[14..n]).unwrap();
        assert!(p.payload[0] != 129 && p.payload[0] != 136);
    }
    let before = s.ndp_stats();
    s.close();
    assert_eq!(s.ndp_stats(), before);
    assert!(s.v6.is_none());
}

#[test]
fn independent_go_codec_fixtures_deliver_udp_and_install_thread_route() {
    let mut s = stack();
    let h = s.udp6_bind(9999, NOW).unwrap();
    s.receive(include_bytes!("../../testdata/ipv6/udp.bin"), NOW)
        .unwrap();
    let mut buf = [0; 32];
    let (n, peer) = s.udp6_recv_from(h, &mut buf, NOW).unwrap();
    assert_eq!(&buf[..n], b"Go IPv6 fixture");
    assert_eq!(peer.port, 5540);
    s.receive(include_bytes!("../../testdata/ipv6/ra.bin"), NOW)
        .unwrap();
    assert_eq!(
        s.ipv6_addresses(NOW).unwrap().1.unwrap()[..8],
        prefix(1)[..8]
    );
    assert_eq!(
        s.udp6_send_to(
            h,
            Endpoint6 {
                ip: prefix(2),
                port: 5540
            },
            b"routed",
            NOW
        ),
        Ok(6)
    );
}
