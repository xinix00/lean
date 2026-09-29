//! `frame_test.go`: draadformaten en checksums.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// Een referentie-checksum: alles aan elkaar, oneven aanvullen, optellen.
fn ref_checksum(blocks: &[&[u8]]) -> u16 {
    let mut all: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
    if !all.len().is_multiple_of(2) {
        all.push(0);
    }
    let mut sum: u64 = all
        .chunks(2)
        .map(|w| u64::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn checksum_golden() {
    let hdr = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    assert_eq!(checksum(&hdr), 0, "golden IPv4 header");
    let mut blank = hdr;
    blank[10] = 0;
    blank[11] = 0;
    assert_eq!(checksum(&blank), 0xb861, "golden IPv4 header: computed");
}

#[test]
fn checksum_odd_length() {
    let b = [0x01, 0x02, 0x03];
    assert_eq!(checksum(&b), ref_checksum(&[&b]));
}

#[test]
fn eth_roundtrip() {
    let mut buf = vec![0u8; SIZE_ETH + 4];
    put_eth(
        &mut buf,
        [0xff; 6],
        [2, 0x48, 0x4f, 0x50, 0, 1],
        ETHERTYPE_ARP,
    )
    .unwrap();
    let f = parse_eth(&buf).unwrap();
    assert_eq!(f.ether_type(), ETHERTYPE_ARP);
    assert_eq!(f.dst(), [0xff; 6]);
    assert_eq!(f.src(), [2, 0x48, 0x4f, 0x50, 0, 1]);
    assert!(
        parse_eth(&buf[..SIZE_ETH - 1]).is_err(),
        "short ethernet frame accepted"
    );
}

#[test]
fn arp_roundtrip() {
    let mut buf = [0u8; 64];
    let (sh, si) = ([1, 2, 3, 4, 5, 6], [10, 100, 0, 1]);
    let (th, ti) = ([0; 6], [10, 100, 0, 2]);
    let n = put_arp(&mut buf, ARP_REQUEST, sh, si, th, ti).unwrap();
    assert_eq!(n, SIZE_ARP);
    let f = parse_arp(&buf[..n]).unwrap();
    assert_eq!(f.op(), ARP_REQUEST);
    assert_eq!(
        (f.sender_hw(), f.sender_ip(), f.target_ip()),
        (sh, si, ti),
        "ARP fields corrupted"
    );
    let mut bad = buf[..n].to_vec();
    bad[0..2].copy_from_slice(&6u16.to_be_bytes());
    assert_eq!(
        parse_arp(&bad).err(),
        Some(Error::NotArp4),
        "non-ethernet ARP accepted"
    );
}

#[test]
fn ipv4_roundtrip() {
    let mut buf = [0u8; 128];
    let (src, dst) = ([192, 168, 99, 1], [192, 168, 99, 2]);
    let payload = b"hello ipv4";
    buf[SIZE_IPV4..SIZE_IPV4 + payload.len()].copy_from_slice(payload);
    let n = put_ipv4(&mut buf, PROTO_UDP, src, dst, payload.len()).unwrap();
    assert_eq!(n, SIZE_IPV4);

    let f = parse_ipv4(&buf[..60]).unwrap();
    assert!(f.checksum_ok(), "header checksum invalid");
    assert_eq!((f.proto(), f.src(), f.dst()), (PROTO_UDP, src, dst));
    assert_eq!(f.payload(), payload, "payload includes padding");

    buf[8] -= 1;
    assert!(
        !parse_ipv4(&buf[..60]).unwrap().checksum_ok(),
        "checksum still valid after corruption"
    );
    buf[8] += 1;

    let mut with_opts = buf[..60].to_vec();
    with_opts[0] = 4 << 4 | 6;
    assert_eq!(
        parse_ipv4(&with_opts).err(),
        Some(Error::Ipv4Options { ihl: 6 })
    );
    let mut frag = buf[..60].to_vec();
    frag[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    assert_eq!(parse_ipv4(&frag).err(), Some(Error::Fragmented));
    let mut frag2 = buf[..60].to_vec();
    frag2[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
    assert_eq!(
        parse_ipv4(&frag2).err(),
        Some(Error::Fragmented),
        "fragment offset"
    );
}

#[test]
fn udp_roundtrip() {
    let mut buf = [0u8; 128];
    let (src, dst) = ([10, 100, 0, 1], [10, 100, 0, 2]);
    let payload = b"dns query";
    buf[SIZE_UDP..SIZE_UDP + payload.len()].copy_from_slice(payload);
    let n = put_udp(&mut buf, 5353, 53, src, dst, payload.len()).unwrap();
    assert_eq!(n, SIZE_UDP + payload.len());
    let f = parse_udp(&buf[..n + 6]).unwrap();
    assert_eq!(
        (f.src_port(), f.dst_port(), f.payload()),
        (5353, 53, &payload[..])
    );
    assert!(f.checksum_ok(src, dst), "UDP checksum invalid");
    assert!(
        !f.checksum_ok(src, [10, 100, 0, 3]),
        "UDP checksum ignores the pseudo-header"
    );
    buf[6] = 0;
    buf[7] = 0;
    let f = parse_udp(&buf[..n + 6]).unwrap();
    assert!(f.checksum_ok(src, dst), "absent UDP checksum rejected");
}

#[test]
fn tcp_roundtrip() {
    let mut buf = [0u8; 256];
    let (src, dst) = ([192, 168, 99, 2], [140, 82, 121, 4]);
    let payload = b"GET / HTTP/1.1\r\n";
    let opts = [2, 4, 0x05, 0xb4];
    buf[SIZE_TCP + 4..SIZE_TCP + 4 + payload.len()].copy_from_slice(payload);
    let h = TcpHeader {
        src_port: 49152,
        dst_port: 443,
        seq: 1000,
        ack: 2000,
        flags: TcpFlags::ACK | TcpFlags::PSH,
        wnd: 0xfff0,
        opts: &opts,
    };
    let n = put_tcp(&mut buf, &h, src, dst, payload.len()).unwrap();
    let f = parse_tcp(&buf[..n]).unwrap();
    assert_eq!(
        (f.src_port(), f.dst_port()),
        (49152, 443),
        "ports corrupted"
    );
    assert_eq!((f.seq(), f.ack()), (1000, 2000), "seq/ack corrupted");
    assert!(f.flags().has(TcpFlags::ACK | TcpFlags::PSH) && !f.flags().has(TcpFlags::SYN));
    assert_eq!(f.window(), 0xfff0);
    assert_eq!(f.options(), &opts);
    assert_eq!(f.payload(), payload);
    assert!(f.checksum_ok(src, dst), "TCP checksum invalid");
    buf[n - 1] ^= 0xff;
    assert!(
        !parse_tcp(&buf[..n]).unwrap().checksum_ok(src, dst),
        "checksum valid after corruption"
    );
    buf[n - 1] ^= 0xff;

    let bad_opts = TcpHeader {
        opts: &[2, 4, 0],
        flags: TcpFlags::SYN,
        ..h
    };
    assert!(
        put_tcp(&mut buf, &bad_opts, src, dst, 0).is_err(),
        "unaligned options accepted"
    );
    let mut bad = buf[..n].to_vec();
    bad[12] = 3 << 4;
    assert_eq!(
        parse_tcp(&bad).err(),
        Some(Error::BadTcpOffset { offset: 12 })
    );
}

#[test]
fn pseudo_checksum_against_ref() {
    let (src, dst) = ([1, 2, 3, 4], [5, 6, 7, 8]);
    for n in [0usize, 1, 2, 3, 19, 20, 21, 1460] {
        let seg: Vec<u8> = (0..SIZE_TCP + n).map(|i| (i * 7 + n) as u8).collect();
        let mut ph = [0u8; 12];
        ph[0..4].copy_from_slice(&src);
        ph[4..8].copy_from_slice(&dst);
        ph[9] = PROTO_TCP;
        ph[10..12].copy_from_slice(&(seg.len() as u16).to_be_bytes());
        assert_eq!(
            pseudo_checksum(PROTO_TCP, src, dst, &seg),
            ref_checksum(&[&ph, &seg]),
            "len {n}"
        );
    }
}
