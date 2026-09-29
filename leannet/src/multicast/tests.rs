//! `multicast_test.go`: link-local multicast.

use super::*;
use crate::testnet::{IP_A, MAC_A, Net, udp_frame};
use crate::{Config, Endpoint, SEC, wire};

const MDNS: [u8; 4] = [224, 0, 0, 251];

#[test]
fn multicast_mac_mapping() {
    // RFC 1112 §6.4: 01:00:5e plus de lage 23 bits; de hoogste bit van het
    // tweede octet verdwijnt.
    let cases = [
        ([224, 0, 0, 251], [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]),
        ([239, 129, 1, 1], [0x01, 0x00, 0x5e, 0x01, 0x01, 0x01]),
        ([224, 128, 255, 255], [0x01, 0x00, 0x5e, 0x00, 0xff, 0xff]),
    ];
    for (group, want) in cases {
        assert_eq!(multicast_mac(group), want, "{group:?}");
    }
    assert!(
        is_multicast_ip([224, 0, 0, 1]) && is_multicast_ip([239, 255, 255, 255]),
        "edges of 224/4"
    );
    assert!(
        !is_multicast_ip([223, 255, 255, 255]) && !is_multicast_ip([240, 0, 0, 1]),
        "neighbours of 224/4"
    );
}

#[test]
fn join_scope_and_cap() {
    let mut net = Net::pair(1 << 16, 1 << 16);
    let a = &mut net.a;
    assert_eq!(
        a.join_group([10, 0, 0, 1]),
        Err(Error::NotLinkLocalMulticast { ip: [10, 0, 0, 1] })
    );
    // 239.x is multicast maar geen link-local: routeerbare scope blijft buiten.
    assert!(
        a.join_group([239, 255, 255, 250]).is_err(),
        "routable multicast join accepted"
    );
    // Het basisadres 224.0.0.0 wordt nooit aan een groep toegewezen (RFC 1112 §4).
    assert!(
        a.join_group([224, 0, 0, 0]).is_err(),
        "base address join accepted"
    );
    a.join_group(MDNS).unwrap();
    a.join_group(MDNS).unwrap(); // Idempotent, geen nesting.
    assert!(
        a.joined(MDNS) && a.groups.len() == 1,
        "joined={} groups={}",
        a.joined(MDNS),
        a.groups.len()
    );
    for i in 1..MAX_GROUPS as u8 {
        a.join_group([224, 0, 0, i]).unwrap();
    }
    assert_eq!(
        a.join_group([224, 0, 0, 200]),
        Err(Error::GroupsFull { cap: MAX_GROUPS })
    );
    // Close geeft de set vrij en verdere joins weigeren netjes.
    a.close();
    assert_eq!(a.join_group(MDNS), Err(Error::StackClosed));
    assert!(
        a.groups.is_empty() && a.groups.capacity() == 0,
        "groups not released on close"
    );
}

/// TCP naar multicast weigert vóór er staat of draad aan te pas komt, en UDP
/// weigert multicast buiten het link-local blok.
#[test]
fn multicast_refusals() {
    let mut net = Net::pair(1 << 16, 1 << 16);
    let now = net.now;
    let a = &mut net.a;
    assert!(
        a.tcp_connect(MDNS, 80, Some(now + SEC), now).is_err(),
        "tcp_connect accepted multicast"
    );
    let u = a.udp_bind(5000).unwrap();
    let ssdp = Endpoint {
        ip: [239, 255, 255, 250],
        port: 1900,
    };
    assert_eq!(
        a.udp_send_to(u, ssdp, b"x", now),
        Err(Error::NotLinkLocalMulticast { ip: ssdp.ip })
    );
    let base = Endpoint {
        ip: [224, 0, 0, 0],
        port: 5353,
    };
    assert_eq!(
        a.udp_send_to(u, base, b"x", now),
        Err(Error::NotLinkLocalMulticast { ip: base.ip })
    );
}

/// Een pakket met een multicast-BRON is nooit geldig (RFC 1112 §7.2) en
/// verdwijnt stil, ook op het unicastpad.
#[test]
fn multicast_source_dropped() {
    let mut net = Net::pair(1 << 16, 1 << 16);
    let now = net.now;
    let b = net.b();
    b.join_group(MDNS).unwrap();
    let ub = b.udp_bind(5353).unwrap();
    let frame = udp_frame(
        multicast_mac(MDNS),
        [2, 0, 0, 0, 0, 9],
        [224, 0, 0, 9],
        MDNS,
        5353,
        5353,
        b"boom",
    );
    b.receive(&frame, now).unwrap();
    assert_eq!(
        b.udp_recv_from(ub, &mut [0; 64], now),
        Err(Error::WouldBlock),
        "delivered from a multicast source"
    );
    assert!(
        b.stats().drop_bad_frame > 0,
        "multicast source not counted as drop_bad_frame"
    );
}

/// Stuur naar een groep die de peer joinde: aflevering, de eigen loopbackkopie
/// van de zender, en stilte voor een groep die niemand joinde.
#[test]
fn multicast_end_to_end() {
    let mut net = Net::pair(1 << 16, 1 << 16);
    net.b().join_group(MDNS).unwrap();
    net.a.join_group(MDNS).unwrap(); // De zender joint ook: hij verwacht zijn eigen kopie.
    let ub = net.b().udp_bind(5353).unwrap();
    let ua = net.a.udp_bind(5353).unwrap();
    let dst = Endpoint {
        ip: MDNS,
        port: 5353,
    };
    let now = net.now;
    assert_eq!(net.a.udp_send_to(ua, dst, b"who has _matterc", now), Ok(16));
    net.settle();
    let mut buf = [0u8; 128];
    for (tag, s, u) in [
        ("peer", net.b.as_mut().unwrap(), ub),
        ("loopback", &mut net.a, ua),
    ] {
        let (n, from) = s
            .udp_recv_from(u, &mut buf, now)
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(&buf[..n], b"who has _matterc", "{tag}");
        assert_eq!(from.ip, IP_A, "{tag}: src");
    }
    // Een niet-gejoinde groep blijft stil.
    let other = Endpoint {
        ip: [224, 0, 0, 252],
        port: 5353,
    };
    net.a.udp_send_to(ua, other, b"anyone?", now).unwrap();
    net.settle();
    assert_eq!(
        net.b().udp_recv_from(ub, &mut buf, now),
        Err(Error::WouldBlock),
        "received for a group nobody joined"
    );
}

/// Het verzonden frame: RFC 1112-MAC, de groep als IP-bestemming, TTL 255 met
/// geldige checksum, en geen ARP.
#[test]
fn multicast_wire_format() {
    let cfg = Config {
        ip: IP_A,
        prefix: 24,
        mac: MAC_A,
        gw: [10, 0, 0, 254], // Een gateway die multicast nooit mag gebruiken.
        budget: 1 << 16,
        ..Config::default()
    };
    let mut net = Net::single(cfg, 1);
    let u = net.a.udp_bind(5353).unwrap();
    let now = net.now;
    net.a
        .udp_send_to(
            u,
            Endpoint {
                ip: MDNS,
                port: 5353,
            },
            b"x",
            now,
        )
        .unwrap();
    net.settle();
    assert_eq!(net.wire_a.len(), 1, "nothing transmitted");
    let f = &net.wire_a[0];
    let eth = wire::parse_eth(f).unwrap();
    assert_ne!(
        eth.ether_type(),
        wire::ETHERTYPE_ARP,
        "multicast send emitted an ARP query"
    );
    assert_eq!(eth.dst(), [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    let ip = wire::parse_ipv4(eth.payload()).unwrap();
    assert_eq!(ip.dst(), MDNS);
    assert_eq!(ip.ttl(), 255, "RFC 6762 §11");
    assert!(
        ip.checksum_ok(),
        "header checksum invalid after the TTL choice"
    );
    assert_eq!(net.arp_queries_a, 0);
}
