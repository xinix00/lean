//! `ring_test.go`: de byteringen en de pot.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

#[test]
fn ring_exhaustive() {
    for size in 1..=8usize {
        for head_start in 0..size {
            for fill in 0..=size {
                let mut r = Ring::with_head(size, head_start);
                let seed: Vec<u8> = (0..fill).map(|i| 0x40 + i as u8).collect();
                assert_eq!(
                    r.write(&seed),
                    fill,
                    "size={size} head={head_start} fill={fill}"
                );
                let mut model = seed.clone();
                assert_eq!((r.buffered(), r.free()), (model.len(), size - model.len()));
                if r.free() == 0 {
                    assert_eq!(r.write(&[0xee]), 0, "write into full ring accepted bytes");
                }
                let h = model.len() / 2;
                let mut dst = vec![0u8; h];
                assert_eq!(r.read(&mut dst), h);
                assert_eq!(dst, model[..h], "half read");
                model.drain(..h);
                let extra: Vec<u8> = (0..size - model.len()).map(|i| 0x60 + i as u8).collect();
                r.write(&extra);
                model.extend_from_slice(&extra);
                let mut rest = vec![0u8; model.len()];
                assert_eq!(r.read(&mut rest), model.len());
                assert_eq!(rest, model, "size={size} head={head_start} fill={fill}");
                assert!(
                    r.buffered() == 0 && r.head() == 0,
                    "empty ring not normalized"
                );
            }
        }
    }
}

#[test]
fn ring_peek_offset() {
    let mut r = Ring::with_head(8, 6);
    r.write(b"abcdefg");
    let mut got = [0u8; 3];
    assert_eq!(r.peek(&mut got, 2), 3);
    assert_eq!(&got, b"cde");
    assert_eq!(r.peek(&mut got, 6), 1);
    assert_eq!(got[0], b'g');
    assert_eq!(r.peek(&mut got, 7), 0, "peek past end");
    let mut all = [0u8; 7];
    assert_eq!(r.read(&mut all), 7);
    assert_eq!(&all, b"abcdefg");
}

/// De Go-versie panickte hier; zonder panics in bibliotheekcode wordt de te
/// grote drop geweigerd en blijft de ring heel.
#[test]
fn ring_drop_panics_beyond_buffered() {
    let mut r = Ring::with_size(4).unwrap();
    r.write(b"ab");
    assert!(!r.drop_front(3), "drop beyond buffered was accepted");
    assert_eq!(r.buffered(), 2, "refused drop changed the ring");
    let mut got = [0u8; 2];
    assert_eq!(r.read(&mut got), 2);
    assert_eq!(&got, b"ab");
}

#[test]
fn ring_grow_preserves_order_across_wrap() {
    let mut r = Ring::with_head(4, 3);
    r.write(b"wxyz");
    r.grow(16).unwrap();
    assert_eq!((r.size(), r.head(), r.buffered()), (16, 0, 4));
    let mut got = [0u8; 4];
    r.read(&mut got);
    assert_eq!(&got, b"wxyz");
}

#[test]
fn tx_ring_send_ack_rewind() {
    let mut tx = TxRing::with_size(8).unwrap();
    tx.write_app(b"hallo");
    assert_eq!(tx.unsent(), 5);
    let mut p = [0u8; 3];
    assert_eq!(tx.next_send(&mut p), 3);
    assert_eq!(&p, b"hal");
    assert_eq!(tx.next_send(&mut p), 2);
    assert_eq!(&p[..2], b"lo");
    assert_eq!((tx.unsent(), tx.buffered()), (0, 5));
    assert!(tx.ack(2));
    assert_eq!((tx.buffered(), tx.unsent()), (3, 0));
    tx.rewind();
    assert_eq!(tx.unsent(), 3);
    assert_eq!(tx.next_send(&mut p), 3);
    assert_eq!(&p, b"llo", "retransmit read");
    tx.write_app(b"!!");
    assert_eq!(tx.unsent(), 2);
}

/// Een te grote teruggave (in Go een panic) wordt geweigerd en laat de pot heel.
#[test]
fn budget_reserve_release() {
    let mut b = Budget::new(100);
    assert!(
        b.reserve(60) && b.reserve(40),
        "reserve within budget refused"
    );
    assert!(!b.reserve(1), "reserve beyond budget granted");
    assert!(b.release(50));
    assert_eq!(b.free(), 50);
    assert!(b.reserve(50), "reserve after release refused");
    assert!(!b.release(101), "over-release was accepted");
    assert_eq!(b.used, 100, "refused over-release changed the pot");
}
