//! De Ethernet/IPv4-ARP-machine (RFC 826).
//!
//! Geen klok, geen taak: de aanroeper geeft monotone nanoseconden aan
//! `resolve`, `recv` en `emit`. De stack pompt pakketten en vraagt `resolve`
//! opnieuw tot hij een MAC krijgt of `no_answer` een expliciete opgave meldt.
//! Pollen in plaats van callbacks vermijdt levenslooptoestand: een eerdere
//! implementatie vuurde verouderde callbacks keer op keer af op latere
//! gratuitous replies.
//!
//! Deze module bezit de ARP-tabel, de antwoordwachtrij en de ARP-tellers;
//! routering en het subnet kent hij niet.

use crate::neighbor::{NeighborEntry, NeighborState, NeighborTable};
use crate::wire::{self, ARP_REPLY, ARP_REQUEST};
use crate::{ArpStats, Result};

/// Begrenst wachtende antwoorden, zodat een vraagvloed geen geheugen kweekt.
pub(crate) const ARP_REPLY_QUEUE_CAP: usize = 8;

/// Begrenst passief leren, zodat gespoofde bronadressen de tabel niet tot een
/// geheugen-DoS laten groeien. Echte nodes kennen veel minder dan 128 peers.
pub(crate) const ARP_CACHE_CAP: usize = 128;

/// Een wachtend antwoord op een vraag naar ons adres.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ArpReply {
    pub(crate) hw: [u8; 6],
    pub(crate) ip: [u8; 4],
}

/// Wat `emit` schreef: een antwoord (unicast) of een vraag (broadcast).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArpOut {
    /// Een antwoord naar dit MAC-adres.
    Reply([u8; 6]),
    /// Een vraag, naar broadcast.
    Request,
}

/// Koppelt IPv4-adressen aan MACs en drijft de vragen.
#[derive(Debug)]
pub(crate) struct ArpTable {
    pub(crate) nt: NeighborTable<[u8; 4]>,
    pub(crate) our_ip: [u8; 4],
    pub(crate) our_mac: [u8; 6],
    /// Een vaste ring van wachtende antwoorden.
    replies: [ArpReply; ARP_REPLY_QUEUE_CAP],
    replies_len: usize,
    /// Tellers voor telemetrie; de machine zelf logt niet.
    pub(crate) cnt: ArpStats,
}

impl ArpTable {
    /// Maakt een tabel voor één identiteit.
    pub(crate) fn new(our_ip: [u8; 4], our_mac: [u8; 6]) -> Result<ArpTable> {
        Ok(ArpTable {
            nt: NeighborTable::new(ARP_CACHE_CAP)?,
            our_ip,
            our_mac,
            replies: [ArpReply::default(); ARP_REPLY_QUEUE_CAP],
            replies_len: 0,
            cnt: ArpStats::default(),
        })
    }

    /// Zet een antwoord in de wachtrij (voor tests die een volle rij nabootsen).
    pub(crate) fn queue_reply(&mut self, r: ArpReply) -> bool {
        match self.replies.get_mut(self.replies_len) {
            Some(slot) => {
                *slot = r;
                self.replies_len += 1;
                true
            }
            None => false,
        }
    }

    /// Laat alle wachtende antwoorden vallen.
    pub(crate) fn clear_replies(&mut self) {
        self.replies_len = 0;
    }

    /// Geeft een bekende MAC of start één ontdubbelde query. Mislukte queries
    /// blijven even negatief gecachet; wachters falen via `no_answer`.
    pub(crate) fn resolve(&mut self, ip: [u8; 4], now: u64) -> Option<[u8; 6]> {
        let (mac, refused) = self.nt.resolve(ip, now);
        if refused {
            self.cnt.full_drop += 1;
        }
        mac
    }

    /// Geeft een bekende MAC zonder query.
    pub(crate) fn peek(&mut self, ip: [u8; 4], now: u64) -> Option<[u8; 6]> {
        self.nt.peek(ip, now)
    }

    /// Of `ip` een negatieve-cachetreffer is of geen plek kan krijgen.
    pub(crate) fn no_answer(&mut self, ip: [u8; 4], now: u64) -> bool {
        self.nt.no_answer(ip, now)
    }

    /// Installeert een statische, nooit verlopende entry en vervangt wat er
    /// was. `true` zegt de stack wachters te wekken wier query en timer
    /// verdwenen. De stack weigert seeds buiten het subnet; deze tabel kent
    /// het subnet niet.
    pub(crate) fn seed(&mut self, ip: [u8; 4], mac: [u8; 6]) -> Result<bool> {
        let was_pending = matches!(self.nt.get(ip), Some(e) if e.state == NeighborState::Pending);
        let mut e = NeighborEntry::resolved(mac, 0);
        e.is_static = true;
        self.nt.insert(ip, e)?;
        Ok(was_pending)
    }

    /// Legt unicast-IPv4-bronnen aan ons passief vast. Maakt of ververst een
    /// entry maar verandert nooit een bestaande MAC; dat vergt ARP `recv`,
    /// zodat gespoofde dataframes een gatewayentry niet kunnen omleiden.
    ///
    /// `true` vraagt de stack een wachter te wekken, ook als latere
    /// pakketverwerking vroeg terugkeert.
    pub(crate) fn learn(&mut self, ip: [u8; 4], mac: [u8; 6], now: u64) -> bool {
        if ip == self.our_ip {
            return false;
        }
        let (woke, dropped) = self.nt.learn(ip, mac, now);
        if dropped {
            self.cnt.learn_drop += 1;
        }
        woke
    }

    /// Verwerkt een gevalideerde ARP-payload. Alleen een antwoord aan ons op
    /// een lopende query mag oplossing scheppen. Vragen, gratuitous
    /// aankondigingen en verkeer van derden kunnen alleen een bestaande
    /// opgeloste entry verversen. `true` betekent dat een query opgelost is.
    pub(crate) fn recv(&mut self, f: &wire::Arp<'_>, now: u64) -> bool {
        let sender = f.sender_ip();
        let target = f.target_ip();
        let sender_hw = f.sender_hw();
        match f.op() {
            ARP_REQUEST => {
                // Antwoord als de peer naar ons adres vraagt.
                if target == self.our_ip
                    && sender != self.our_ip
                    && !self.queue_reply(ArpReply {
                        hw: sender_hw,
                        ip: sender,
                    })
                {
                    self.cnt.reply_drop += 1;
                }
                // De afzender van een vraag mag alleen verversen; een lopende
                // query lost hij niet op.
                self.refresh(sender, sender_hw, now);
                false
            }
            ARP_REPLY => {
                if target == self.our_ip {
                    // Een antwoord aan ons lost een query op of ververst.
                    if self.nt.resolve_pending(sender, sender_hw, now) {
                        return true;
                    }
                    self.refresh(sender, sender_hw, now);
                } else if target == sender {
                    // Gratuitous: ververst maar schept nooit.
                    self.refresh(sender, sender_hw, now);
                } else {
                    // Antwoorden voor andermans uitwisseling negeren; ze
                    // accepteren maakt broadcast-ARP-vergiftiging mogelijk.
                    self.cnt.ignored += 1;
                }
                false
            }
            _ => false,
        }
    }

    /// Ververst een bestaande niet-statische entry; schept er nooit een.
    fn refresh(&mut self, ip: [u8; 4], mac: [u8; 6], now: u64) {
        let (_, changed) = self.nt.refresh(ip, mac, now);
        if changed {
            self.cnt.mac_changed += 1;
        }
    }

    /// Schrijft één wachtend antwoord of rijpe vraag in `buf`. De aanroeper
    /// herhaalt tot `None` en verpakt antwoorden in unicast- en vragen in
    /// broadcast-Ethernet.
    pub(crate) fn emit(&mut self, buf: &mut [u8], now: u64) -> Option<(usize, ArpOut)> {
        if self.replies_len > 0 {
            let r = self.replies[0];
            self.replies.copy_within(1..self.replies_len, 0);
            self.replies_len -= 1;
            let n = self.put(buf, ARP_REPLY, r.hw, r.ip).ok()?;
            return Some((n, ArpOut::Reply(r.hw)));
        }
        let (ip, gave_up) = self.nt.poll(now);
        self.cnt.gave_up += gave_up;
        let ip = ip?;
        let n = self.put(buf, ARP_REQUEST, [0; 6], ip).ok()?;
        Some((n, ArpOut::Request))
    }

    /// Schrijft een pakket waarvan de afzender altijd deze host is.
    fn put(
        &self,
        buf: &mut [u8],
        op: u16,
        target_hw: [u8; 6],
        target_ip: [u8; 4],
    ) -> Result<usize> {
        wire::put_arp(buf, op, self.our_mac, self.our_ip, target_hw, target_ip)
    }
}

#[cfg(test)]
mod tests;
