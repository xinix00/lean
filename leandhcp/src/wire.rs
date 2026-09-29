//! Het draadformaat: DHCP-berichten bouwen in een vaste buffer en antwoorden
//! lezen uit een geleende slice.
//!
//! Deze module bezit geen staat en alloceert niet. Bouwen gaat in een array van
//! vaste grootte die de aanroeper (de client of de keeper) bezit; lezen
//! vertrouwt geen enkel byte en gaat uitsluitend via `get`.

use core::net::Ipv4Addr;

use crate::lease::Lease;

/// De UDP-poort van de DHCP-server.
pub const SERVER_PORT: u16 = 67;

/// De UDP-poort van de DHCP-client; de keeper ontvangt hierop.
pub const CLIENT_PORT: u16 = 68;

/// DHCPDISCOVER (optie 53).
pub(crate) const MSG_DISCOVER: u8 = 1;
/// DHCPOFFER (optie 53).
pub(crate) const MSG_OFFER: u8 = 2;
/// DHCPREQUEST (optie 53).
pub(crate) const MSG_REQUEST: u8 = 3;
/// DHCPACK (optie 53).
pub(crate) const MSG_ACK: u8 = 5;
/// DHCPNAK (optie 53).
pub(crate) const MSG_NAK: u8 = 6;

/// Lengte van de ethernet-kop.
const ETH_LEN: usize = 14;
/// Lengte van een IPv4-kop zonder opties; wij zenden nooit opties.
const IP_LEN: usize = 20;
/// Lengte van de UDP-kop.
const UDP_LEN: usize = 8;
/// Wat wij zenden aan BOOTP: 236 vaste bytes, de magic en 60 bytes opties.
/// Dat is de klassieke BOOTP-minimumlengte van 300, die oude relays eisen.
pub(crate) const BOOTP_LEN: usize = 300;
/// Offset van de DHCP-magic in de BOOTP-payload.
const MAGIC_AT: usize = 236;
/// Offset van de opties in de BOOTP-payload.
const OPTIONS_AT: usize = 240;
/// De DHCP-magic cookie (RFC 2131 §3).
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// Offset van de BOOTP-payload in een ethernet-frame zonder IP-opties.
const BOOTP_AT: usize = ETH_LEN + IP_LEN + UDP_LEN;

/// Lengte van elk frame dat de [`Client`](crate::Client) zendt: ethernet, IPv4,
/// UDP en 300 bytes BOOTP.
pub const FRAME_LEN: usize = BOOTP_AT + BOOTP_LEN;

/// Parameter-request (optie 55): mask, router, DNS, lease, T1 en T2.
const PARAMS: [u8; 6] = [1, 3, 6, 51, 58, 59];

/// Wat een REQUEST in de DORA-ronde bevestigt: optie 50 en optie 54.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Confirm {
    /// Het aangeboden adres (optie 50).
    pub(crate) ip: Ipv4Addr,
    /// De server die het aanbood (optie 54).
    pub(crate) server: Ipv4Addr,
}

/// Bouwt een BOOTP/DHCP-payload in `bp`.
///
/// `ciaddr` is het lease-adres bij RENEW (RFC 2131 §4.3.2) en anders nul.
/// `broadcast` vraagt tijdens de DORA-ronde om een broadcast-antwoord: zonder
/// adres kan een unicast-antwoord op het RX-filter stuklopen.
pub(crate) fn write_bootp(
    bp: &mut [u8; BOOTP_LEN],
    mac: &[u8; 6],
    xid: u32,
    msg_type: u8,
    ciaddr: Ipv4Addr,
    broadcast: bool,
    confirm: Option<Confirm>,
) {
    bp.fill(0);
    bp[0] = 1; // BOOTREQUEST.
    bp[1] = 1; // Ethernet.
    bp[2] = 6; // Lengte van het hardware-adres.
    bp[4..8].copy_from_slice(&xid.to_be_bytes());
    if broadcast {
        bp[10] = 0x80;
    }
    bp[12..16].copy_from_slice(&ciaddr.octets());
    bp[28..34].copy_from_slice(mac);
    bp[MAGIC_AT..OPTIONS_AT].copy_from_slice(&MAGIC);

    let o = OPTIONS_AT;
    bp[o..o + 3].copy_from_slice(&[53, 1, msg_type]);
    bp[o + 3..o + 5].copy_from_slice(&[55, 6]);
    bp[o + 5..o + 11].copy_from_slice(&PARAMS);
    let mut end = o + 11;
    if let Some(c) = confirm {
        bp[end..end + 2].copy_from_slice(&[50, 4]);
        bp[end + 2..end + 6].copy_from_slice(&c.ip.octets());
        bp[end + 6..end + 8].copy_from_slice(&[54, 4]);
        bp[end + 8..end + 12].copy_from_slice(&c.server.octets());
        end += 12;
    }
    bp[end] = 255;
}

/// Bouwt een broadcast-DHCP-frame in `f`: IPv4 0.0.0.0 naar 255.255.255.255,
/// UDP 68 naar 67 met de toegestane checksum nul, en BOOTP met de
/// broadcast-vlag.
pub(crate) fn write_frame(
    f: &mut [u8; FRAME_LEN],
    mac: &[u8; 6],
    xid: u32,
    msg_type: u8,
    confirm: Option<Confirm>,
) {
    f.fill(0);
    f[0..6].fill(0xff);
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);

    // De lengtes zijn constanten die ruim binnen een u16 vallen (342 bytes).
    const IP_TOTAL: u16 = (FRAME_LEN - ETH_LEN) as u16;
    const UDP_TOTAL: u16 = IP_TOTAL - IP_LEN as u16;

    let ip = &mut f[ETH_LEN..ETH_LEN + IP_LEN];
    ip[0] = 0x45; // Versie 4, IHL 5.
    ip[2..4].copy_from_slice(&IP_TOTAL.to_be_bytes());
    ip[8] = 64; // TTL.
    ip[9] = 17; // UDP.
    ip[16..20].fill(255);
    let cs = checksum(ip);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());

    let udp = &mut f[ETH_LEN + IP_LEN..BOOTP_AT];
    udp[0..2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&SERVER_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&UDP_TOTAL.to_be_bytes());

    let mut bp = [0u8; BOOTP_LEN];
    write_bootp(
        &mut bp,
        mac,
        xid,
        msg_type,
        Ipv4Addr::UNSPECIFIED,
        true,
        confirm,
    );
    f[BOOTP_AT..].copy_from_slice(&bp);
}

/// Het standaard 16-bits one's-complement van een IP-kop.
///
/// Een oneven laatste byte telt als hoge helft, zoals RFC 1071 zegt; een kop
/// is altijd even lang, maar zo kan deze functie op geen enkele invoer vallen.
pub(crate) fn checksum(h: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for pair in h.chunks(2) {
        let hi = pair.first().copied().unwrap_or(0);
        let lo = pair.get(1).copied().unwrap_or(0);
        s += u32::from(u16::from_be_bytes([hi, lo]));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    // Na het vouwen past `s` in 16 bits.
    !(s as u16)
}

/// Leest een DHCP-antwoord uit een ethernet-frame, voor dit `xid` en MAC.
///
/// Geeft het berichttype (optie 53) en de lease terug, of `None` voor alles
/// wat geen antwoord op ons verzoek is.
pub(crate) fn parse_frame(f: &[u8], mac: &[u8; 6], xid: u32) -> Option<(u8, Lease)> {
    if f.len() < BOOTP_AT + OPTIONS_AT || f.get(12..14)? != [0x08, 0x00] || *f.get(23)? != 17 {
        return None;
    }
    let ihl = usize::from(*f.get(ETH_LEN)? & 0xf) * 4;
    let udp = f.get(ETH_LEN + ihl..)?;
    if udp.len() < UDP_LEN + OPTIONS_AT || udp.get(2..4)? != CLIENT_PORT.to_be_bytes() {
        return None;
    }
    parse_bootp(udp.get(UDP_LEN..)?, mac, xid)
}

/// Leest een BOOTP/DHCP-antwoord uit een UDP-payload; gedeeld door de
/// bring-up over rauwe frames en de keeper over een socket.
pub(crate) fn parse_bootp(bp: &[u8], mac: &[u8; 6], xid: u32) -> Option<(u8, Lease)> {
    if bp.len() < OPTIONS_AT || *bp.first()? != 2 {
        return None; // Geen BOOTREPLY.
    }
    if be32(bp.get(4..8)?)? != xid || bp.get(28..34)? != mac {
        return None;
    }
    let mut lease = Lease {
        ip: addr(bp.get(16..20)?)?, // yiaddr
        ..Lease::default()
    };
    let msg_type = read_options(bp.get(OPTIONS_AT..)?, &mut lease)?;
    Some((msg_type, lease))
}

/// Loopt de opties af (`[code len data...]`, 0 is opvulling, 255 het eind) en
/// vult `lease`. Geeft het berichttype, of `None` als optie 53 ontbreekt of
/// ongeldig is. Geldt optie 53 meer dan eens, dan telt de laatste, zoals in
/// de Go-versie.
fn read_options(opts: &[u8], lease: &mut Lease) -> Option<u8> {
    let mut msg_type = None;
    let mut i = 0;
    while i + 1 < opts.len() {
        let code = opts[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        let len = usize::from(opts[i + 1]);
        let Some(d) = opts.get(i + 2..i + 2 + len) else {
            break;
        };
        match code {
            53 => msg_type = if len == 1 { Some(d[0]) } else { None },
            1 => set_addr(&mut lease.mask, d),
            3 => set_addr(&mut lease.gateway, d),
            6 => set_addr(&mut lease.dns, d),
            54 => set_addr(&mut lease.server, d),
            51 => set_u32(&mut lease.lease_secs, d),
            58 => set_u32(&mut lease.t1_secs, d),
            59 => set_u32(&mut lease.t2_secs, d),
            _ => {}
        }
        i += 2 + len;
    }
    msg_type
}

/// Leest de eerste vier bytes als big-endian `u32`.
fn be32(d: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(..4)?.try_into().ok()?))
}

/// Leest de eerste vier bytes als adres.
fn addr(d: &[u8]) -> Option<Ipv4Addr> {
    be32(d).map(Ipv4Addr::from)
}

/// Zet een adres uit een optie van minstens vier bytes (de eerste router, de
/// eerste resolver); een kortere optie laat het veld staan.
fn set_addr(field: &mut Ipv4Addr, d: &[u8]) {
    if let Some(a) = addr(d) {
        *field = a;
    }
}

/// Zet een tijd in seconden uit een optie van minstens vier bytes.
fn set_u32(field: &mut u32, d: &[u8]) {
    if let Some(v) = be32(d) {
        *field = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{LESSOR, reply};

    #[test]
    fn parse_rommel_panickt_nooit() {
        let mac = [2, 0, 0, 0, 0, 1];
        let mut req = [0u8; FRAME_LEN];
        write_frame(&mut req, &mac, 7, MSG_REQUEST, None);
        let base = reply(&req, MSG_ACK, [1, 2, 3, 4], LESSOR);
        assert!(
            parse_frame(&base, &mac, 7).is_some(),
            "het basisframe zelf hoort te parsen"
        );

        for n in 0..=base.len() {
            let _ = parse_frame(&base[..n], &mac, 7);
            if n >= 42 {
                let _ = parse_bootp(&base[42..n], &mac, 7);
            }
        }

        for i in 0..base.len() {
            let mut f = base.clone();
            f[i] ^= 0xff;
            let _ = parse_frame(&f, &mac, 7);
        }

        for ln in [0u8, 1, 200, 255] {
            let mut f = base.clone();
            let mut i = 42 + 240;
            while i + 1 < f.len() {
                f[i] = 58;
                f[i + 1] = ln;
                i += 2;
            }
            let _ = parse_frame(&f, &mac, 7);
        }

        for n in 0..400usize {
            let f: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            let _ = parse_frame(&f, &mac, 7);
        }
    }

    #[test]
    fn checksum_van_eigen_kop_is_nul() {
        let mut f = [0u8; FRAME_LEN];
        write_frame(&mut f, &[2, 0, 0, 0, 0, 1], 1, MSG_DISCOVER, None);
        assert_eq!(checksum(&f[14..34]), 0);
        assert_eq!(checksum(&[0xff]), 0x00ff);
    }
}
