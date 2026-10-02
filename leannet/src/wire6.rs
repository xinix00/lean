//! IPv6-draadformaat voor het begrensde UDP/ICMPv6-profiel uit Go's frame6.go.
use crate::{Error, Result};
/// De vaste IPv6-header.
pub const HEADER: usize = 40;
/// Het vaste plafond zonder fragmentatie of path-MTU discovery.
pub const MTU: usize = 1280;
/// ICMPv6-protocolnummer.
pub const ICMP: u8 = 58;
/// Alle nodes op de link.
pub const ALL_NODES: [u8; 16] = [255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// Alle routers op de link.
pub const ALL_ROUTERS: [u8; 16] = [255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// Een volledig gevalideerde header; transportchecksums volgen bij de ontvanger.
pub struct Packet<'a> {
    /// Bronadres.
    pub src: [u8; 16],
    /// Bestemming.
    pub dst: [u8; 16],
    /// Alleen UDP of ICMPv6; extensies en fragmenten zijn buiten dit profiel.
    pub next: u8,
    /// Resterende hops.
    pub hop: u8,
    /// Payload zonder Ethernet-padding.
    pub payload: &'a [u8],
}
/// Leest een pakket; geen jumbograms of extensieheaders.
pub fn parse(b: &[u8]) -> Result<Packet<'_>> {
    let h = b.get(..HEADER).ok_or(Error::InvalidIpv6)?;
    if h[0] >> 4 != 6 || !matches!(h[6], 17 | ICMP) {
        return Err(Error::InvalidIpv6);
    }
    let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
    let payload = b.get(HEADER..HEADER + len).ok_or(Error::InvalidIpv6)?;
    let mut src = [0; 16];
    src.copy_from_slice(&h[8..24]);
    let mut dst = [0; 16];
    dst.copy_from_slice(&h[24..40]);
    Ok(Packet {
        src,
        dst,
        next: h[6],
        hop: h[7],
        payload,
    })
}
/// Schrijft alleen de header; de payload staat er al achter.
pub fn put(b: &mut [u8], src: [u8; 16], dst: [u8; 16], next: u8, hop: u8, len: usize) -> Result {
    let len = u16::try_from(len).map_err(|_| Error::InvalidIpv6)?;
    let h = b.get_mut(..HEADER).ok_or(Error::InvalidIpv6)?;
    h.fill(0);
    h[0] = 0x60;
    h[4..6].copy_from_slice(&len.to_be_bytes());
    h[6] = next;
    h[7] = hop;
    h[8..24].copy_from_slice(&src);
    h[24..40].copy_from_slice(&dst);
    Ok(())
}
/// Internet-checksum inclusief IPv6-pseudoheader; nul betekent geldig.
pub fn checksum(src: [u8; 16], dst: [u8; 16], next: u8, p: &[u8]) -> u16 {
    let mut sum = u64::from(next) + p.len() as u64;
    for bytes in [&src[..], &dst[..], p] {
        for pair in bytes.chunks(2) {
            sum += u64::from(pair[0]) * 256 + u64::from(*pair.get(1).unwrap_or(&0));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
/// EUI-64-adres, gelijk aan de Go-stack en de HopOS-switch.
pub fn link_local(mac: [u8; 6]) -> [u8; 16] {
    [
        254,
        128,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 2,
        mac[1],
        mac[2],
        255,
        254,
        mac[3],
        mac[4],
        mac[5],
    ]
}
/// De solicited-nodegroep voor één unicastadres.
pub fn solicited(a: [u8; 16]) -> [u8; 16] {
    [
        255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, a[13], a[14], a[15],
    ]
}
/// Ethernetadres van een IPv6-multicastgroep.
pub fn multicast_mac(a: [u8; 16]) -> [u8; 6] {
    [51, 51, a[12], a[13], a[14], a[15]]
}
/// Link-local unicast.
pub fn is_link_local(a: [u8; 16]) -> bool {
    a[0] == 254 && a[1] & 192 == 128
}
/// Alleen ff02::/16 mag multicast versturen of joinen.
pub fn is_link_group(a: [u8; 16]) -> bool {
    a[0] == 255 && a[1] == 2
}
/// Bruikbare unicastbron, zonder unspecified, loopback of IPv4-mapping.
pub fn is_unicast(a: [u8; 16]) -> bool {
    a[0] != 255
        && a != [0; 16]
        && a != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        && !(a[..10] == [0; 10] && a[10..12] == [255, 255])
}
/// Maskeert hostbits; een prefix langer dan 128 is ongeldig.
pub fn canonical(mut a: [u8; 16], bits: u8) -> Result<[u8; 16]> {
    if bits > 128 {
        return Err(Error::InvalidIpv6);
    }
    for (i, b) in a.iter_mut().enumerate() {
        let keep = usize::from(bits).saturating_sub(i * 8).min(8);
        *b &= (255_u16 << (8 - keep)) as u8;
    }
    Ok(a)
}
/// Vergelijkt uitsluitend de prefixbits.
pub fn matches(a: [u8; 16], b: [u8; 16], bits: u8) -> bool {
    canonical(a, bits).ok() == canonical(b, bits).ok() && bits <= 128
}
pub(crate) fn mac_ok(a: [u8; 6]) -> bool {
    a != [0; 6] && a[0] & 1 == 0
}
pub(crate) fn be32(b: &[u8]) -> u32 {
    b.get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}
pub(crate) fn addr(b: &[u8]) -> [u8; 16] {
    let mut a = [0; 16];
    if let Some(b) = b.get(..16) {
        a.copy_from_slice(b);
    }
    a
}
/// Doorloopt alle NDP-opties; nul-lengtes en onvolledige staarten worden geweigerd.
pub(crate) fn options(mut b: &[u8], mut f: impl FnMut(u8, &[u8]) -> bool) -> bool {
    while !b.is_empty() {
        let Some(&units) = b.get(1) else { return false };
        let n = usize::from(units) * 8;
        if n == 0 || n > b.len() || !f(b[0], &b[..n]) {
            return false;
        }
        b = &b[n..];
    }
    true
}
