//! `icmp_test.go`: echo-antwoorden en weigeringen.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn icmp_test_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; SIZE_ICMP_ECHO + payload.len()];
    msg[0] = ICMP_ECHO_REQUEST;
    msg[4..6].copy_from_slice(&id.to_be_bytes());
    msg[6..8].copy_from_slice(&seq.to_be_bytes());
    msg[SIZE_ICMP_ECHO..].copy_from_slice(payload);
    let c = checksum(&msg);
    msg[2..4].copy_from_slice(&c.to_be_bytes());
    msg
}

#[test]
fn icmp_echo_golden_roundtrip() {
    let payload = b"leannet echo 0123456789";
    let req = icmp_test_request(0x1234, 7, payload);
    let mut reply = vec![0u8; req.len()];
    let n = icmp_echo(&req, &mut reply).unwrap();
    assert_eq!(n, req.len());
    assert_eq!(
        (reply[0], reply[1]),
        (ICMP_ECHO_REPLY, 0),
        "reply type/code"
    );
    assert_eq!(&reply[4..8], &[0x12, 0x34, 0, 7], "reply id/seq");
    assert_eq!(&reply[SIZE_ICMP_ECHO..n], payload);
    assert_eq!(checksum(&reply[..n]), 0, "reply checksum does not verify");
    let mut want = req.clone();
    want[0] = ICMP_ECHO_REPLY;
    want[2] = 0;
    want[3] = 0;
    let c = checksum(&want);
    want[2..4].copy_from_slice(&c.to_be_bytes());
    assert_eq!(reply[..n], want[..]);
}

#[test]
fn icmp_echo_rejects() {
    let mut reply = [0u8; 64];
    let mut bad = icmp_test_request(1, 1, b"ping");
    *bad.last_mut().unwrap() ^= 0xff;
    assert!(
        icmp_echo(&bad, &mut reply).is_none(),
        "broken checksum accepted"
    );

    let mut rep = icmp_test_request(1, 1, b"ping");
    rep[0] = ICMP_ECHO_REPLY;
    rep[2] = 0;
    rep[3] = 0;
    let c = checksum(&rep);
    rep[2..4].copy_from_slice(&c.to_be_bytes());
    assert!(
        icmp_echo(&rep, &mut reply).is_none(),
        "echo reply accepted as a request"
    );

    let mut code = icmp_test_request(1, 1, b"ping");
    code[1] = 3;
    code[2] = 0;
    code[3] = 0;
    let c = checksum(&code);
    code[2..4].copy_from_slice(&c.to_be_bytes());
    assert!(
        icmp_echo(&code, &mut reply).is_none(),
        "nonzero code accepted"
    );

    assert!(
        icmp_echo(&[ICMP_ECHO_REQUEST, 0, 0], &mut reply).is_none(),
        "short message accepted"
    );
    let good = icmp_test_request(1, 1, b"ping");
    assert!(
        icmp_echo(&good, &mut vec![0u8; good.len() - 1]).is_none(),
        "undersized reply buffer accepted"
    );
}
