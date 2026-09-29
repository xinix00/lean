//! Gereedschap voor de tests: een nagebootste DHCP-server op draadniveau.
//!
//! Bezit niets; bouwt antwoorden en leest verzonden frames.

use core::net::Ipv4Addr;

use crate::lease::Lease;
use crate::wire::checksum;

/// De opties van de lessor in de tests: /24, router, DNS en server
/// 192.168.1.1, lease 3600 s, T1 1800 s, T2 3150 s.
pub(crate) const LESSOR: &[u8] = &[
    1, 4, 255, 255, 255, 0, //
    3, 4, 192, 168, 1, 1, //
    6, 4, 192, 168, 1, 1, //
    54, 4, 192, 168, 1, 1, //
    51, 4, 0, 0, 0x0e, 0x10, //
    58, 4, 0, 0, 0x07, 0x08, //
    59, 4, 0, 0, 0x0c, 0x4e,
];

/// De lease die de tests als gebonden uitgangspunt nemen.
pub(crate) fn bound() -> Lease {
    let r = Ipv4Addr::new(192, 168, 1, 1);
    Lease {
        ip: Ipv4Addr::new(192, 168, 1, 33),
        mask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: r,
        dns: r,
        server: r,
        lease_secs: 3600,
        t1_secs: 1800,
        t2_secs: 3150,
    }
}

/// Big-endian `u32` uit vier bytes.
pub(crate) fn be32(d: &[u8]) -> u32 {
    u32::from_be_bytes(d[..4].try_into().unwrap())
}

/// Een BOOTP-antwoord op de BOOTP-payload `req`.
pub(crate) fn bootp_reply(req: &[u8], msg_type: u8, yiaddr: [u8; 4], extra: &[u8]) -> Vec<u8> {
    let mut bp = vec![0u8; 300];
    bp[..3].copy_from_slice(&[2, 1, 6]);
    bp[4..8].copy_from_slice(&req[4..8]);
    bp[28..34].copy_from_slice(&req[28..34]);
    bp[16..20].copy_from_slice(&yiaddr);
    bp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    let mut o = vec![53, 1, msg_type];
    o.extend_from_slice(extra);
    o.push(255);
    bp[240..240 + o.len()].copy_from_slice(&o);
    bp
}

/// Een compleet ethernet-frame met een antwoord op het frame `req`.
pub(crate) fn reply(req: &[u8], msg_type: u8, yiaddr: [u8; 4], extra: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 8 + 300];
    f[0..6].copy_from_slice(&req[42 + 28..42 + 34]);
    f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    let tot = (f.len() - 14) as u16;
    {
        let ip = &mut f[14..34];
        ip[0] = 0x45;
        ip[8] = 64;
        ip[9] = 17;
        ip[2..4].copy_from_slice(&tot.to_be_bytes());
        ip[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip[16..20].copy_from_slice(&yiaddr);
        let cs = checksum(ip);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());
    }
    f[35] = 67;
    f[37] = 68;
    f[38..40].copy_from_slice(&(tot - 20).to_be_bytes());
    let bp = bootp_reply(&req[42..], msg_type, yiaddr, extra);
    f[42..].copy_from_slice(&bp);
    f
}

/// Loopt de opties van een frame af en geeft `(code, data)` per optie.
fn options(frame: &[u8]) -> Vec<(u8, &[u8])> {
    let opts = &frame[42 + 240..];
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < opts.len() {
        match opts[i] {
            0 => i += 1,
            255 => break,
            code => {
                let ln = usize::from(opts[i + 1]);
                let Some(d) = opts.get(i + 2..i + 2 + ln) else {
                    break;
                };
                out.push((code, d));
                i += 2 + ln;
            }
        }
    }
    out
}

/// Het berichttype (optie 53) van een frame, of 0.
pub(crate) fn msg_type_of(frame: &[u8]) -> u8 {
    options(frame)
        .into_iter()
        .find(|(c, d)| *c == 53 && d.len() == 1)
        .map_or(0, |(_, d)| d[0])
}

/// Of het frame optie `code` met precies `want` draagt.
pub(crate) fn has_option(frame: &[u8], code: u8, want: &[u8]) -> bool {
    options(frame).iter().any(|(c, d)| *c == code && *d == want)
}

/// Of het frame optie `code` draagt.
pub(crate) fn has_option_code(frame: &[u8], code: u8) -> bool {
    options(frame).iter().any(|(c, _)| *c == code)
}
