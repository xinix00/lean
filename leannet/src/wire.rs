//! Allocatievrije views over Ethernet, ARP, IPv4, UDP en TCP, plus de
//! Internet-checksum.
//!
//! Deze module bezit alleen draadformaten: offsets uit RFC 826, 791, 768 en
//! 9293. Elke `parse_*` weigert een ongeldige of niet-ondersteunde vorm met
//! een eigen fout, zodat telemetrie ziet wát er binnenkwam; elke `put_*`
//! schrijft in een buffer van de aanroeper en geeft de lengte terug. Geen
//! toestand, geen tijd, geen allocatie.

use crate::{Error, Result};

/// EtherType van IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType van ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType van IPv6 (alleen herkend om hem stil te laten liggen).
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// IP-protocolnummer van ICMP.
pub const PROTO_ICMP: u8 = 1;
/// IP-protocolnummer van TCP.
pub const PROTO_TCP: u8 = 6;
/// IP-protocolnummer van UDP.
pub const PROTO_UDP: u8 = 17;

/// ARP-opcode voor een vraag.
pub const ARP_REQUEST: u16 = 1;
/// ARP-opcode voor een antwoord.
pub const ARP_REPLY: u16 = 2;

/// Het Ethernet-broadcastadres.
pub const BCAST_MAC: [u8; 6] = [0xff; 6];
/// RFC 919's limited broadcast; directed broadcast hangt van de configuratie af.
pub const BCAST_IP: [u8; 4] = [255; 4];

/// Grootte van een Ethernet-header (dst, src, EtherType).
pub const SIZE_ETH: usize = 14;
/// Grootte van een Ethernet/IPv4-ARP-payload.
pub const SIZE_ARP: usize = 28;
/// Grootte van een IPv4-header zonder opties.
pub const SIZE_IPV4: usize = 20;
/// Grootte van een UDP-header.
pub const SIZE_UDP: usize = 8;
/// Grootte van een TCP-header zonder opties.
pub const SIZE_TCP: usize = 20;
/// Kleinste Ethernet-frame zonder FCS; kortere frames worden met nullen
/// aangevuld zodat oude bufferinhoud niet lekt.
pub const MIN_FRAME: usize = 60;

/// Leest een big-endian `u16` op `off`; buiten de slice is het nul.
///
/// Elke view hieronder heeft zijn lengte al bewezen voordat hij velden leest;
/// de nul-terugval bestaat alleen zodat er geen panic-pad is.
fn be16(b: &[u8], off: usize) -> u16 {
    match b.get(off..off + 2) {
        Some(&[x, y]) => u16::from_be_bytes([x, y]),
        _ => 0,
    }
}

/// Leest een big-endian `u32` op `off`; buiten de slice is het nul.
fn be32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off + 4) {
        Some(&[a, c, d, e]) => u32::from_be_bytes([a, c, d, e]),
        _ => 0,
    }
}

/// Schrijft een big-endian `u16` op `off`; buiten de slice gebeurt er niets.
fn put16(b: &mut [u8], off: usize, v: u16) {
    if let Some(dst) = b.get_mut(off..off + 2) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
}

/// Schrijft een big-endian `u32` op `off`; buiten de slice gebeurt er niets.
fn put32(b: &mut [u8], off: usize, v: u32) {
    if let Some(dst) = b.get_mut(off..off + 4) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
}

/// Kopieert `N` bytes vanaf `off` naar een array; buiten de slice nullen.
fn arr<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if let Some(src) = b.get(off..off + N) {
        out.copy_from_slice(src);
    }
    out
}

/// Kopieert `src` naar `b[off..]` voor zover het past.
fn put_bytes(b: &mut [u8], off: usize, src: &[u8]) {
    if let Some(dst) = b.get_mut(off..off + src.len()) {
        dst.copy_from_slice(src);
    }
}

/// Faalt met [`Error::ShortFrame`] als `b` korter is dan `need`.
fn need(b: &[u8], need: usize) -> Result {
    if b.len() < need {
        return Err(Error::ShortFrame { len: b.len(), need });
    }
    Ok(())
}

// ---- Ethernet (DIX) ----

/// Een view over een Ethernet-frame: dst(6), src(6), EtherType(2), payload.
#[derive(Clone, Copy, Debug)]
pub struct Eth<'a>(&'a [u8]);

/// Valideert de minimale lengte en geeft een view.
pub fn parse_eth(b: &[u8]) -> Result<Eth<'_>> {
    need(b, SIZE_ETH)?;
    Ok(Eth(b))
}

impl<'a> Eth<'a> {
    /// Het doel-MAC-adres.
    pub fn dst(&self) -> [u8; 6] {
        arr(self.0, 0)
    }
    /// Het bron-MAC-adres.
    pub fn src(&self) -> [u8; 6] {
        arr(self.0, 6)
    }
    /// Het EtherType-veld.
    pub fn ether_type(&self) -> u16 {
        be16(self.0, 12)
    }
    /// Alles na de header.
    pub fn payload(&self) -> &'a [u8] {
        self.0.get(SIZE_ETH..).unwrap_or(&[])
    }
}

/// Schrijft een Ethernet-header in `b`; faalt als `b` te kort is.
pub fn put_eth(b: &mut [u8], dst: [u8; 6], src: [u8; 6], ether_type: u16) -> Result {
    need(b, SIZE_ETH)?;
    put_bytes(b, 0, &dst);
    put_bytes(b, 6, &src);
    put16(b, 12, ether_type);
    Ok(())
}

// ---- ARP (alleen Ethernet/IPv4, RFC 826) ----

/// Een view over de 28-byte Ethernet/IPv4-ARP-payload.
#[derive(Clone, Copy, Debug)]
pub struct Arp<'a>(&'a [u8]);

/// Valideert lengte en de Ethernet/IPv4-ARP-indeling.
pub fn parse_arp(b: &[u8]) -> Result<Arp<'_>> {
    need(b, SIZE_ARP)?;
    if be16(b, 0) != 1
        || be16(b, 2) != ETHERTYPE_IPV4
        || b.get(4) != Some(&6)
        || b.get(5) != Some(&4)
    {
        return Err(Error::NotArp4);
    }
    Ok(Arp(b))
}

impl Arp<'_> {
    /// De opcode ([`ARP_REQUEST`] of [`ARP_REPLY`]).
    pub fn op(&self) -> u16 {
        be16(self.0, 6)
    }
    /// Het hardware-adres van de afzender.
    pub fn sender_hw(&self) -> [u8; 6] {
        arr(self.0, 8)
    }
    /// Het IPv4-adres van de afzender.
    pub fn sender_ip(&self) -> [u8; 4] {
        arr(self.0, 14)
    }
    /// Het hardware-adres van het doel.
    pub fn target_hw(&self) -> [u8; 6] {
        arr(self.0, 18)
    }
    /// Het IPv4-adres van het doel.
    pub fn target_ip(&self) -> [u8; 4] {
        arr(self.0, 24)
    }
}

/// Schrijft een volledig ARP-pakket en geeft zijn lengte.
pub fn put_arp(
    b: &mut [u8],
    op: u16,
    sender_hw: [u8; 6],
    sender_ip: [u8; 4],
    target_hw: [u8; 6],
    target_ip: [u8; 4],
) -> Result<usize> {
    need(b, SIZE_ARP)?;
    put16(b, 0, 1);
    put16(b, 2, ETHERTYPE_IPV4);
    put_bytes(b, 4, &[6, 4]);
    put16(b, 6, op);
    put_bytes(b, 8, &sender_hw);
    put_bytes(b, 14, &sender_ip);
    put_bytes(b, 18, &target_hw);
    put_bytes(b, 24, &target_ip);
    Ok(SIZE_ARP)
}

// ---- IPv4 (RFC 791) ----

/// Een view over een IPv4-header zonder opties (IHL=5).
#[derive(Clone, Copy, Debug)]
pub struct Ipv4<'a>(&'a [u8]);

/// Valideert versie, IHL, totale lengte en fragmentatie.
///
/// Opties en fragmenten krijgen elk een eigen fout: ze horen niet op onze
/// paden (DF, MTU 1500), en stil accepteren zou ze voor de meetlat verbergen.
pub fn parse_ipv4(b: &[u8]) -> Result<Ipv4<'_>> {
    need(b, SIZE_IPV4)?;
    let vihl = b.first().copied().unwrap_or(0);
    if vihl >> 4 != 4 {
        return Err(Error::NotIpv4);
    }
    if vihl & 0x0f != 5 {
        return Err(Error::Ipv4Options { ihl: vihl & 0x0f });
    }
    let total = usize::from(be16(b, 2));
    if total > b.len() || total < SIZE_IPV4 {
        return Err(Error::ShortFrame {
            len: b.len(),
            need: total.max(SIZE_IPV4),
        });
    }
    // Een offset ongelijk aan nul of de More-Fragments-vlag: een fragment.
    if be16(b, 6) & 0x3fff != 0 {
        return Err(Error::Fragmented);
    }
    Ok(Ipv4(b))
}

impl<'a> Ipv4<'a> {
    /// De totale lengte uit de header.
    pub fn total_len(&self) -> usize {
        usize::from(be16(self.0, 2))
    }
    /// De TTL.
    pub fn ttl(&self) -> u8 {
        self.0.get(8).copied().unwrap_or(0)
    }
    /// Het protocolnummer.
    pub fn proto(&self) -> u8 {
        self.0.get(9).copied().unwrap_or(0)
    }
    /// Het bronadres.
    pub fn src(&self) -> [u8; 4] {
        arr(self.0, 12)
    }
    /// Het doeladres.
    pub fn dst(&self) -> [u8; 4] {
        arr(self.0, 16)
    }
    /// De payload binnen `total_len`, zonder Ethernet-opvulling.
    pub fn payload(&self) -> &'a [u8] {
        self.0.get(SIZE_IPV4..self.total_len()).unwrap_or(&[])
    }
    /// Controleert de header-checksum.
    pub fn checksum_ok(&self) -> bool {
        checksum(self.0.get(..SIZE_IPV4).unwrap_or(&[])) == 0
    }
}

/// Schrijft een IHL=5-header met DF en checksum; de payload staat al op
/// `b[SIZE_IPV4..]`.
///
/// De TTL volgt de scope van de bestemming: link-local multicast krijgt 255
/// (RFC 6762 §11), wat veilig is omdat routers dat blok nooit doorsturen
/// (RFC 5771); al het andere krijgt de gerouteerde standaard 64.
pub fn put_ipv4(
    b: &mut [u8],
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    payload_len: usize,
) -> Result<usize> {
    need(b, SIZE_IPV4)?;
    let total = u16::try_from(SIZE_IPV4 + payload_len).map_err(|_| Error::DatagramTooLarge {
        len: payload_len,
        max: usize::from(u16::MAX) - SIZE_IPV4,
    })?;
    let ttl = if crate::multicast::is_link_local_multicast(dst) {
        255
    } else {
        64
    };
    put_bytes(b, 0, &[4 << 4 | 5, 0]);
    put16(b, 2, total);
    put16(b, 4, 0); // Zonder fragmentatie is de identificatie ongebruikt.
    put16(b, 6, 0x4000); // DF.
    put_bytes(b, 8, &[ttl, proto]);
    put16(b, 10, 0);
    put_bytes(b, 12, &src);
    put_bytes(b, 16, &dst);
    let sum = checksum(b.get(..SIZE_IPV4).unwrap_or(&[]));
    put16(b, 10, sum);
    Ok(SIZE_IPV4)
}

// ---- UDP (RFC 768) ----

/// Een view over een UDP-header en payload.
#[derive(Clone, Copy, Debug)]
pub struct Udp<'a>(&'a [u8]);

/// Valideert de header en het lengteveld.
pub fn parse_udp(b: &[u8]) -> Result<Udp<'_>> {
    need(b, SIZE_UDP)?;
    let len = usize::from(be16(b, 4));
    if len > b.len() || len < SIZE_UDP {
        return Err(Error::ShortFrame {
            len: b.len(),
            need: len.max(SIZE_UDP),
        });
    }
    Ok(Udp(b))
}

impl<'a> Udp<'a> {
    /// De bronpoort.
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    /// De doelpoort.
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Het lengteveld (header plus payload).
    pub fn len(&self) -> usize {
        usize::from(be16(self.0, 4))
    }
    /// Waar als het lengteveld alleen de header telt.
    pub fn is_empty(&self) -> bool {
        self.len() <= SIZE_UDP
    }
    /// Het checksumveld.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 6)
    }
    /// De payload binnen het lengteveld.
    pub fn payload(&self) -> &'a [u8] {
        self.0.get(SIZE_UDP..self.len()).unwrap_or(&[])
    }
    /// Controleert de pseudo-header-checksum; RFC 768 staat nul toe als "afwezig".
    pub fn checksum_ok(&self, src: [u8; 4], dst: [u8; 4]) -> bool {
        if self.checksum() == 0 {
            return true;
        }
        pseudo_checksum(PROTO_UDP, src, dst, self.0.get(..self.len()).unwrap_or(&[])) == 0
    }
}

/// Schrijft header en checksum voor een payload die al op `b[SIZE_UDP..]` staat.
pub fn put_udp(
    b: &mut [u8],
    src_port: u16,
    dst_port: u16,
    src: [u8; 4],
    dst: [u8; 4],
    payload_len: usize,
) -> Result<usize> {
    put_udp_sum(b, src_port, dst_port, src, dst, payload_len, true)
}

/// Is [`put_udp`] met een optionele checksum: een link die geheugen is (een
/// ring tussen twee stacks op één machine) kent geen bitfouten, en beide
/// kanten spreken via [`crate::Config::link_trusted`] af het veld leeg te laten.
pub(crate) fn put_udp_sum(
    b: &mut [u8],
    src_port: u16,
    dst_port: u16,
    src: [u8; 4],
    dst: [u8; 4],
    payload_len: usize,
    sum: bool,
) -> Result<usize> {
    let total = SIZE_UDP + payload_len;
    need(b, total)?;
    let wire = u16::try_from(total).map_err(|_| Error::DatagramTooLarge {
        len: payload_len,
        max: usize::from(u16::MAX) - SIZE_UDP,
    })?;
    put16(b, 0, src_port);
    put16(b, 2, dst_port);
    put16(b, 4, wire);
    put16(b, 6, 0);
    if !sum {
        return Ok(total); // Nul betekent: geen checksum; UDP staat dat toe.
    }
    let mut csum = pseudo_checksum(PROTO_UDP, src, dst, b.get(..total).unwrap_or(&[]));
    if csum == 0 {
        csum = 0xffff; // RFC 768 reserveert nul voor een afwezige checksum.
    }
    put16(b, 6, csum);
    Ok(total)
}

// ---- TCP (RFC 9293); de toestandsmachine staat in tcp.rs ----

/// TCP-vlaggen als bitmasker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    /// Geen vlaggen.
    pub const NONE: TcpFlags = TcpFlags(0);
    /// FIN: de zender is klaar.
    pub const FIN: TcpFlags = TcpFlags(1 << 0);
    /// SYN: synchroniseer volgnummers.
    pub const SYN: TcpFlags = TcpFlags(1 << 1);
    /// RST: reset de verbinding.
    pub const RST: TcpFlags = TcpFlags(1 << 2);
    /// PSH: lever direct af.
    pub const PSH: TcpFlags = TcpFlags(1 << 3);
    /// ACK: het ack-veld is geldig.
    pub const ACK: TcpFlags = TcpFlags(1 << 4);

    /// Waar als elke vlag in `mask` staat.
    pub fn has(self, mask: TcpFlags) -> bool {
        self.0 & mask.0 == mask.0
    }
}

impl core::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: TcpFlags) {
        self.0 |= rhs.0;
    }
}

/// Een view over een TCP-header en payload.
#[derive(Clone, Copy, Debug)]
pub struct Tcp<'a>(&'a [u8]);

/// Valideert de header en de data-offset.
pub fn parse_tcp(b: &[u8]) -> Result<Tcp<'_>> {
    need(b, SIZE_TCP)?;
    let f = Tcp(b);
    let off = f.header_len();
    if off < SIZE_TCP || off > b.len() {
        return Err(Error::BadTcpOffset { offset: off });
    }
    Ok(f)
}

impl<'a> Tcp<'a> {
    /// De bronpoort.
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    /// De doelpoort.
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Het volgnummer.
    pub fn seq(&self) -> u32 {
        be32(self.0, 4)
    }
    /// Het bevestigingsnummer.
    pub fn ack(&self) -> u32 {
        be32(self.0, 8)
    }
    /// De vlaggen (negen bits).
    pub fn flags(&self) -> TcpFlags {
        TcpFlags(be16(self.0, 12) & 0x01ff)
    }
    /// Het vensterveld zoals op de draad.
    pub fn window(&self) -> u16 {
        be16(self.0, 14)
    }
    /// Het checksumveld.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 16)
    }
    /// De headerlengte uit de data-offset.
    pub fn header_len(&self) -> usize {
        usize::from(self.0.get(12).copied().unwrap_or(0) >> 4) * 4
    }
    /// De ruwe optiebytes tussen vaste header en payload.
    pub fn options(&self) -> &'a [u8] {
        self.0.get(SIZE_TCP..self.header_len()).unwrap_or(&[])
    }
    /// De databytes; de aanroeper begrenst het frame tot de IPv4-payload.
    pub fn payload(&self) -> &'a [u8] {
        self.0.get(self.header_len()..).unwrap_or(&[])
    }
    /// Controleert de pseudo-header-checksum.
    pub fn checksum_ok(&self, src: [u8; 4], dst: [u8; 4]) -> bool {
        pseudo_checksum(PROTO_TCP, src, dst, self.0) == 0
    }
}

/// Een uitgaande TCP-header in machinevorm, zonder payload.
#[derive(Clone, Copy, Debug)]
pub struct TcpHeader<'o> {
    /// Bronpoort.
    pub src_port: u16,
    /// Doelpoort.
    pub dst_port: u16,
    /// Volgnummer.
    pub seq: u32,
    /// Bevestigingsnummer.
    pub ack: u32,
    /// Vlaggen.
    pub flags: TcpFlags,
    /// Vensterveld zoals op de draad.
    pub wnd: u16,
    /// Opties, een veelvoud van vier bytes (de aanroeper levert NOP/EOL-vulling).
    pub opts: &'o [u8],
}

/// Schrijft header, opties en checksum voor een payload die al op
/// `b[SIZE_TCP + opts.len()..]` staat.
pub fn put_tcp(
    b: &mut [u8],
    h: &TcpHeader<'_>,
    src: [u8; 4],
    dst: [u8; 4],
    payload_len: usize,
) -> Result<usize> {
    put_tcp_sum(b, h, src, dst, payload_len, true)
}

/// Is [`put_tcp`] met een optionele checksum; zie [`put_udp_sum`] voor het waarom.
pub(crate) fn put_tcp_sum(
    b: &mut [u8],
    h: &TcpHeader<'_>,
    src: [u8; 4],
    dst: [u8; 4],
    payload_len: usize,
    sum: bool,
) -> Result<usize> {
    if !h.opts.len().is_multiple_of(4) || h.opts.len() > 40 {
        return Err(Error::BadTcpOffset {
            offset: SIZE_TCP + h.opts.len(),
        });
    }
    let hdr = SIZE_TCP + h.opts.len();
    let total = hdr + payload_len;
    need(b, total)?;
    put16(b, 0, h.src_port);
    put16(b, 2, h.dst_port);
    put32(b, 4, h.seq);
    put32(b, 8, h.ack);
    // `hdr` is hoogstens 60, dus hdr/4 past in vier bits.
    let off = u16::try_from(hdr / 4).unwrap_or(0);
    put16(b, 12, off << 12 | h.flags.0);
    put16(b, 14, h.wnd);
    put16(b, 16, 0);
    put16(b, 18, 0); // De urgent pointer is ongebruikt.
    put_bytes(b, SIZE_TCP, h.opts);
    if sum {
        let csum = pseudo_checksum(PROTO_TCP, src, dst, b.get(..total).unwrap_or(&[]));
        put16(b, 16, csum);
    }
    Ok(total)
}

// ---- Internet-checksum (RFC 1071) ----

/// Vouwt en complementeert de one's-complement-som van `b`; geldige data geeft nul.
pub fn checksum(b: &[u8]) -> u16 {
    fold_checksum(sum_bytes(0, b))
}

/// Is de checksum inclusief de IPv4-pseudo-header (bron, doel, protocol, lengte).
pub fn pseudo_checksum(proto: u8, src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(&src);
    ph[4..8].copy_from_slice(&dst);
    ph[9] = proto;
    // Een segment is hoogstens 64 KiB; de truncatie is die van het draadveld.
    let len = u16::try_from(segment.len()).unwrap_or(u16::MAX);
    ph[10..12].copy_from_slice(&len.to_be_bytes());
    fold_checksum(sum_bytes(sum_bytes(0, &ph), segment))
}

/// Telt big-endian 16-bitwoorden op; een oneven staart is de hoge byte van het
/// laatste woord (RFC 1071).
///
/// De som loopt in een `u64`: 2^48 woorden van 0xffff passen erin, en een
/// segment is hoogstens 32 Ki woorden, dus hij loopt nooit over.
fn sum_bytes(mut sum: u64, b: &[u8]) -> u64 {
    let mut words = b.chunks_exact(2);
    for w in &mut words {
        if let &[hi, lo] = w {
            sum += u64::from(u16::from_be_bytes([hi, lo]));
        }
    }
    if let &[last] = words.remainder() {
        sum += u64::from(last) << 8;
    }
    sum
}

/// Vouwt de carries terug tot 16 bits en complementeert.
fn fold_checksum(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // Na het vouwen past de som in 16 bits.
    !u16::try_from(sum).unwrap_or(0)
}

#[cfg(test)]
mod tests;
