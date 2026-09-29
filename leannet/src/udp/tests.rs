//! `udp_test.go`: de poorttabel, de rij en de boekhouding.

use super::*;

const SRC: [u8; 4] = [10, 0, 0, 9];

/// In Go woog de descriptor 48 bytes; hier is het fysieke recordhoofd acht
/// bytes. De lading van 64 moet eerlijk blijven: nooit minder dan wat een
/// datagram fysiek in de ring kost, zodat de boekhouding de ring beschermt.
#[test]
fn udp_datagram_budget_charge_covers_descriptor() {
    assert_eq!(UDP_DGRAM_OVERHEAD, 64, "want an honest 64-byte charge");
    const { assert!(UDP_REC_HDR <= UDP_DGRAM_OVERHEAD) };
}

#[test]
fn udp_bind_close_rebind() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(4096);
    let u = tab.bind(5353, 1024, &mut pot, 1).unwrap();
    assert_eq!(
        tab.bind(5353, 1024, &mut pot, 2),
        Err(Error::UdpPortInUse { port: 5353 })
    );
    assert_eq!(
        alloc::format!("{}", Error::UdpPortInUse { port: 5353 }),
        "leannet: udp port 5353 in use"
    );
    tab.close(u, &mut pot);
    let u2 = tab
        .bind(5353, 1024, &mut pot, 3)
        .expect("rebind after close");
    tab.close(u2, &mut pot);
    assert_eq!(tab.bind(0, 1024, &mut pot, 4), Err(Error::InvalidPort));
    assert_eq!(tab.bind(53, 0, &mut pot, 5), Err(Error::UdpQueueCap));
}

#[test]
fn udp_deliver_recv_roundtrip() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(4096);
    let u = tab.bind(4242, 512, &mut pot, 1).unwrap();
    let payload = b"hello node";
    assert_eq!(
        tab.deliver(4242, SRC, 5678, payload),
        Some(u),
        "deliver to bound port failed"
    );
    let mut buf = [0u8; 64];
    let (n, src, sport) = tab.get_mut(u).unwrap().recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload);
    assert_eq!((src, sport), (SRC, 5678));
    assert!(
        tab.get_mut(u).unwrap().recv_from(&mut buf).is_none(),
        "recv on empty queue"
    );
    assert!(
        tab.deliver(9999, SRC, 1, payload).is_none(),
        "deliver to unbound port succeeded"
    );
    assert_eq!(tab.cnt_no_port, 1);
    tab.close(u, &mut pot);
}

#[test]
fn udp_queue_full_drop() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(4096);
    let u = tab
        .bind(7, UDP_DGRAM_OVERHEAD + 16 + 8, &mut pot, 1)
        .unwrap();
    let first = [0xaa; 16];
    let second = [0xbb; 16];
    assert!(
        tab.deliver(7, SRC, 1, &first).is_some(),
        "first deliver failed"
    );
    assert!(
        tab.deliver(7, SRC, 2, &second).is_none(),
        "second deliver fit in a full queue"
    );
    assert_eq!(tab.get_mut(u).unwrap().cnt_drop, 1);
    let mut buf = [0u8; 64];
    let (n, _, sport) = tab.get_mut(u).unwrap().recv_from(&mut buf).unwrap();
    assert!(
        sport == 1 && buf[..n] == first,
        "surviving datagram corrupted by the dropped one"
    );
    assert!(
        tab.deliver(7, SRC, 3, &second).is_some(),
        "queue accounting broken"
    );
    tab.close(u, &mut pot);
}

#[test]
fn udp_budget() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(100);
    let a = tab.bind(1, 64, &mut pot, 1).unwrap();
    assert_eq!(pot.free(), 36);
    assert_eq!(
        tab.bind(2, 64, &mut pot, 2),
        Err(Error::NoBudget { need: 64, free: 36 })
    );
    let b = tab.bind(2, 36, &mut pot, 3).unwrap();
    assert_eq!(pot.free(), 0);
    tab.close(a, &mut pot);
    tab.close(b, &mut pot);
    assert_eq!(pot.free(), 100);
    tab.close(a, &mut pot);
    assert_eq!(pot.free(), 100, "double close");
}

#[test]
fn udp_datagram_boundaries() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(4096);
    let u = tab.bind(53, 512, &mut pot, 1).unwrap();
    // De rij houdt een eigen kopie; de bron van de aanroeper mag daarna veranderen.
    let mut one = *b"aa";
    tab.deliver(53, SRC, 1, &one);
    tab.deliver(53, SRC, 2, b"bbbb");
    one[0] = b'X';
    assert_eq!(&one, b"Xa");
    let mut buf = [0u8; 64];
    let (n, _, sport) = tab.get_mut(u).unwrap().recv_from(&mut buf).unwrap();
    assert!(n == 2 && sport == 1 && &buf[..n] == b"aa", "first recv");
    let (n, _, sport) = tab.get_mut(u).unwrap().recv_from(&mut buf).unwrap();
    assert!(n == 4 && sport == 2 && &buf[..n] == b"bbbb", "second recv");
    tab.close(u, &mut pot);
}

#[test]
fn udp_truncation() {
    let mut tab = UdpTable::new();
    let mut pot = Budget::new(4096);
    let u = tab.bind(9, UDP_DGRAM_OVERHEAD + 16, &mut pot, 1).unwrap();
    assert!(tab.deliver(9, SRC, 1, b"0123456789").is_some());
    let mut small = [0u8; 4];
    let (n, _, _) = tab.get_mut(u).unwrap().recv_from(&mut small).unwrap();
    assert!(n == 4 && &small == b"0123", "truncated recv");
    assert!(
        tab.get_mut(u).unwrap().recv_from(&mut small).is_none(),
        "truncated remainder still readable"
    );
    assert!(
        tab.deliver(9, SRC, 2, &[1; 16]).is_some(),
        "queue accounting leaked after truncation"
    );
    tab.close(u, &mut pot);
}
