//! `neighbor_test.go`: één levensloop voor elke sleutelsoort.

use super::*;
use crate::arp::{ARP_CACHE_CAP, ArpTable};

fn neighbor_lifecycle<K: Copy + PartialEq + core::fmt::Debug>(keys: [K; 5]) {
    let mut tab = NeighborTable::<K>::new(3).unwrap();
    let mac = [2, 0, 0, 0, 0, 1];
    assert_eq!(tab.resolve(keys[0], 0), (None, false));
    assert_eq!(tab.len(), 1, "first resolve");
    assert_eq!(tab.resolve(keys[0], 0), (None, false));
    assert_eq!(tab.len(), 1, "deduplicated resolve");
    assert_eq!(tab.learn(keys[0], mac, 1), (true, false), "learn pending");
    assert_eq!(tab.peek(keys[0], 1), Some(mac), "peek learned");

    let mut now = 10;
    assert!(!tab.resolve(keys[1], now).1, "second query was refused");
    for attempt in 0..NEIGHBOR_QUERY_TRIES {
        assert_eq!(tab.poll(now), (Some(keys[1]), 0), "poll {attempt}");
        now += NEIGHBOR_RETRY_IVAL;
    }
    assert_eq!(tab.poll(now), (None, 1), "give-up poll");
    assert!(
        tab.no_answer(keys[1], now),
        "failed query was not negative-cached"
    );
    assert_eq!(
        tab.resolve(keys[1], now + NEIGHBOR_FAIL_TTL),
        (None, false),
        "expired failure did not restart"
    );
    let e = tab.get(keys[1]).unwrap();
    assert!(
        e.state == NeighborState::Pending && e.due == now + NEIGHBOR_FAIL_TTL,
        "expired failure restarted as {e:?}, want a fresh pending query"
    );

    // Een tabel boven zijn plafond vraagt meer dan één verdringing.
    let mut tab = NeighborTable::<K>::new(3).unwrap();
    tab.insert(keys[0], NeighborEntry::resolved([0; 6], 0))
        .unwrap();
    tab.insert(keys[1], NeighborEntry::resolved([0; 6], 0))
        .unwrap();
    tab.insert(keys[2], NeighborEntry::pending(0)).unwrap();
    tab.insert(keys[3], NeighborEntry::pending(0)).unwrap();
    assert!(
        tab.make_room(0) && tab.len() == 2,
        "multi-eviction left {} entries",
        tab.len()
    );
    tab.insert(keys[4], NeighborEntry::pending(0)).unwrap();
    assert!(
        tab.full(0) && tab.no_answer(keys[0], 0),
        "non-evictable capacity did not fail loudly"
    );
}

#[test]
fn neighbor_lifecycle_is_shared_by_address_family() {
    neighbor_lifecycle::<[u8; 4]>([
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        [3, 0, 0, 0],
        [4, 0, 0, 0],
        [5, 0, 0, 0],
    ]);
    let k6 = |b: u8| {
        let mut k = [0u8; 16];
        k[0] = b;
        k
    };
    neighbor_lifecycle::<[u8; 16]>([k6(1), k6(2), k6(3), k6(4), k6(5)]);
}

/// De Go-test deed dit voor ARP en NDP; zonder de IPv6-baan blijft de ARP-kant.
#[test]
fn neighbor_wrappers_keep_their_lifecycle_accounting() {
    let mut arp = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    assert_eq!(arp.nt.limit, ARP_CACHE_CAP, "neighbor limit");
    for i in 0..ARP_CACHE_CAP {
        arp.nt
            .insert([10, 1, (i >> 8) as u8, i as u8], NeighborEntry::pending(1))
            .unwrap();
    }
    let missing = [10, 2, 0, 1];
    assert!(arp.resolve(missing, 0).is_none());
    assert_eq!(arp.cnt.full_drop, 1, "full resolve");
    assert!(!arp.learn(missing, [2, 0, 0, 0, 0, 2], 0));
    assert_eq!(arp.cnt.learn_drop, 1, "full learn");

    let mut arp = ArpTable::new([10, 0, 0, 1], [2, 0, 0, 0, 0, 1]).unwrap();
    let mut e = NeighborEntry::pending(0);
    e.tries = NEIGHBOR_QUERY_TRIES;
    arp.nt.insert([10, 0, 0, 9], e).unwrap();
    arp.emit(&mut [0u8; 64], 0);
    assert_eq!(arp.cnt.gave_up, 1, "ARP give-up counter");
}
