//! Link-local IPv4-multicast voor de stack met één adres.
//!
//! Join een groep om hem te ontvangen; zenden gebruikt de directe RFC
//! 1112-MAC-mapping (geen ARP, geen gateway). Alleen UDP, en alleen
//! 224.0.0.0/24: het link-local blok dat routers nooit doorsturen (RFC 5771),
//! wat ook de reden is dat TTL 255 daar veilig is (RFC 6762 §11). Breder
//! multicast (239.0.0.0/8 en verwanten) wordt geweigerd: met een TTL boven 1
//! kan een multicastrouter het voorbij het LAN dragen, en niemand hier heeft
//! het nodig.
//!
//! Een join geldt voor de levensduur van de stack: de enige consument (mDNS)
//! verlaat nooit, dus er is geen Leave, geen nesting en geen refcount om fout
//! te doen. Groepen zijn begrensd en worden bij `close` vrijgegeven. Er is
//! geen IGMP: thuisswitches fluiten link-local multicast rond. Het device
//! eronder moet multicastframes al doorlaten; een NIC-filter is niet de zorg
//! van deze stack.

use crate::{Error, Result, Stack};

/// Begrenst de groepenset. mDNS heeft er één nodig; het plafond bestaat alleen
/// zodat een aanroepersfout de stacktoestand niet onbegrensd laat groeien.
pub(crate) const MAX_GROUPS: usize = 4;

/// Of `ip` in 224.0.0.0/4 ligt (RFC 1112 §4): nooit een geldige unicastpeer,
/// bron of TCP-bestemming.
pub(crate) fn is_multicast_ip(ip: [u8; 4]) -> bool {
    ip[0] & 0xf0 == 0xe0
}

/// Of `ip` een bruikbare groep in 224.0.0.0/24 is (RFC 5771): het enige
/// multicast dat deze stack joint of verstuurt. Het basisadres 224.0.0.0 wordt
/// nooit aan een groep toegewezen (RFC 1112 §4) en valt erbuiten.
pub(crate) fn is_link_local_multicast(ip: [u8; 4]) -> bool {
    ip[0] == 224 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
}

/// Koppelt een groep aan zijn Ethernet-adres: 01:00:5e plus de lage 23 bits
/// van de groep (RFC 1112 §6.4).
pub(crate) fn multicast_mac(group: [u8; 4]) -> [u8; 6] {
    [0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]]
}

/// Of `dst` een IPv4-multicast-Ethernetadres is.
pub(crate) fn is_multicast_mac(dst: [u8; 6]) -> bool {
    dst[0] == 0x01 && dst[1] == 0x00 && dst[2] == 0x5e
}

impl Stack {
    /// Abonneert de stack op een link-local multicastgroep, voor zijn hele
    /// levensduur. Een groep opnieuw joinen doet niets.
    pub fn join_group(&mut self, group: [u8; 4]) -> Result {
        if !is_link_local_multicast(group) {
            return Err(Error::NotLinkLocalMulticast { ip: group });
        }
        if self.closed {
            return Err(Error::StackClosed);
        }
        if self.joined(group) {
            return Ok(());
        }
        if self.groups.len() >= MAX_GROUPS {
            return Err(Error::GroupsFull { cap: MAX_GROUPS });
        }
        crate::try_push(&mut self.groups, group)
    }

    /// Of de stack lid is van `group`.
    pub(crate) fn joined(&self, group: [u8; 4]) -> bool {
        self.groups.contains(&group)
    }
}

#[cfg(test)]
mod tests;
