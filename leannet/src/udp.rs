//! De UDP-poorttabel: binden, afleveren, ophalen, sluiten.
//!
//! `bind` reserveert een begrensde wachtrij uit het budget, `deliver` zet een
//! datagram in de rij en `recv_from` haalt hem eruit; blokkeren en deadlines
//! zijn van de socketlaag ([`crate::Stack`]). Deze kleine expliciete rij is de
//! enige reservering vooraf in leannet, en sluiten geeft hem volledig terug.
//!
//! De rij is een bytering van records (bron, poort, lengte, payload), dus een
//! datagram kost geen eigen allocatie en grenzen blijven bewaard. Uitgaande
//! datagrammen hebben geen toestand hier; de stack bouwt ze direct.

use alloc::vec::Vec;

use crate::ring::{Budget, Ring};
use crate::waker::WakerSlot;
use crate::{Error, Result};

/// Wat één datagram van de rij kost. De Go-versie rekende de 48-byte
/// descriptor plus allocatorafronding van zijn privékopie; die lading houden we
/// aan, zodat dezelfde capaciteit even veel datagrammen draagt. Ons fysieke
/// recordhoofd ([`UDP_REC_HDR`]) is kleiner, dus wat de boekhouding toelaat
/// past altijd in de ring.
pub(crate) const UDP_DGRAM_OVERHEAD: usize = 64;

/// Het fysieke recordhoofd in de ring: bron (4), bronpoort (2), lengte (2).
#[cfg(test)]
pub(crate) const UDP_REC_HDR: usize = 8;

/// Eén gebonden poort en zijn ontvangstrij.
#[derive(Debug)]
pub(crate) struct UdpPort<const N: usize = 4> {
    /// Generatie van het handvat dat naar deze plek wijst.
    pub(crate) generation: u32,
    /// Het poortnummer.
    pub(crate) port: u16,
    /// Rijcapaciteit, gereserveerd uit het budget.
    cap: usize,
    /// Bezette bytes volgens de boekhouding, inclusief overhead.
    used: usize,
    /// De records.
    q: Ring,
    /// Het filter van een verbonden socket: alleen deze peer komt binnen.
    pub(crate) peer: Option<([u8; N], u16)>,
    /// Datagrammen die vielen omdat de rij vol was of het filter weigerde.
    pub(crate) cnt_drop: usize,
    /// Leesdeadline in monotone nanoseconden.
    pub(crate) rd_deadline: Option<u64>,
    /// Schrijfdeadline in monotone nanoseconden.
    pub(crate) wr_deadline: Option<u64>,
    /// Wie wacht op een datagram.
    pub(crate) read_waker: WakerSlot,
    /// Wie wacht op een route voor een datagram.
    pub(crate) write_waker: WakerSlot,
}

impl<const N: usize> UdpPort<N> {
    /// Haalt het oudste datagram op zonder te blokkeren. Is `p` te klein, dan
    /// valt de rest weg (UDP-semantiek) maar blijft de recordgrens.
    pub(crate) fn recv_from(&mut self, p: &mut [u8]) -> Option<(usize, [u8; N], u16)> {
        let mut src = [0; N];
        let mut hdr = [0; 4];
        if self.q.peek(&mut src, 0) != N || self.q.peek(&mut hdr, N) != 4 {
            return None;
        }
        let [p0, p1, l0, l1] = hdr;
        let sport = u16::from_be_bytes([p0, p1]);
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        let take = len.min(p.len());
        let n = self.q.peek(p.get_mut(..take).unwrap_or(&mut []), N + 4);
        self.q.drop_front(N + 4 + len);
        self.used = self.used.saturating_sub(UDP_DGRAM_OVERHEAD + len);
        Some((n, src, sport))
    }

    /// Of er een datagram klaarligt.
    pub(crate) fn has_data(&self) -> bool {
        self.q.buffered() > 0
    }
}

/// Wijst poorten toe en verdeelt binnenkomende datagrammen.
#[derive(Debug, Default)]
pub(crate) struct UdpTable<const N: usize = 4> {
    pub(crate) ports: Vec<Option<UdpPort<N>>>,
    /// Voor telemetrie en een toekomstig ICMP port-unreachable.
    pub(crate) cnt_no_port: usize,
}

impl<const N: usize> UdpTable<N> {
    /// Een lege tabel.
    pub(crate) fn new() -> UdpTable<N> {
        UdpTable::default()
    }

    /// Reserveert `queue_cap` bytes voor een poort ongelijk aan nul en geeft
    /// de plek. De stack kiest efemere poorten; nul is hier geen wildcard.
    pub(crate) fn bind(
        &mut self,
        port: u16,
        queue_cap: usize,
        pot: &mut Budget,
        generation: u32,
    ) -> Result<usize> {
        if port == 0 {
            return Err(Error::InvalidPort);
        }
        if queue_cap == 0 {
            return Err(Error::UdpQueueCap);
        }
        if self.bound(port) {
            return Err(Error::UdpPortInUse { port });
        }
        if !pot.reserve(queue_cap) {
            return Err(Error::NoBudget {
                need: queue_cap,
                free: pot.free(),
            });
        }
        let q = match Ring::with_size(queue_cap) {
            Ok(q) => q,
            Err(e) => {
                pot.release(queue_cap);
                return Err(e);
            }
        };
        let u = UdpPort {
            generation,
            port,
            cap: queue_cap,
            used: 0,
            q,
            peer: None,
            cnt_drop: 0,
            rd_deadline: None,
            wr_deadline: None,
            read_waker: WakerSlot::default(),
            write_waker: WakerSlot::default(),
        };
        if let Some(i) = self.ports.iter().position(Option::is_none) {
            if let Some(slot) = self.ports.get_mut(i) {
                *slot = Some(u);
            }
            return Ok(i);
        }
        if let Err(e) = crate::try_push(&mut self.ports, Some(u)) {
            pot.release(queue_cap);
            return Err(e);
        }
        Ok(self.ports.len() - 1)
    }

    /// Of de efemere-poortkiezer deze poort moet overslaan.
    pub(crate) fn bound(&self, port: u16) -> bool {
        self.find(port).is_some()
    }

    /// De plek van een gebonden poort.
    pub(crate) fn find(&self, port: u16) -> Option<usize> {
        self.ports
            .iter()
            .position(|u| matches!(u, Some(u) if u.port == port))
    }

    /// De poort op plek `i`.
    pub(crate) fn get_mut(&mut self, i: usize) -> Option<&mut UdpPort<N>> {
        self.ports.get_mut(i).and_then(Option::as_mut)
    }

    /// Zet een binnenkomend IPv4-datagram in de rij en geeft de plek. `None`
    /// betekent: geen gebonden poort, gefilterd, of een volle rij.
    pub(crate) fn deliver(
        &mut self,
        dst_port: u16,
        src: [u8; N],
        src_port: u16,
        payload: &[u8],
    ) -> Option<usize> {
        let Some(i) = self.find(dst_port) else {
            self.cnt_no_port += 1;
            return None;
        };
        let u = self.get_mut(i)?;
        if u.peer.is_some_and(|p| p != (src, src_port)) {
            // Filter verbonden sockets vóór de rij, zodat gespoofde afzenders
            // de rij niet kunnen vullen en de echte peer verdringen.
            u.cnt_drop += 1;
            return None;
        }
        let cost = UDP_DGRAM_OVERHEAD + payload.len();
        let Ok(len) = u16::try_from(payload.len()) else {
            u.cnt_drop += 1;
            return None;
        };
        if u.used + cost > u.cap || u.q.free() < N + 4 + payload.len() {
            u.cnt_drop += 1;
            return None;
        }
        u.used += cost;
        let [p0, p1] = src_port.to_be_bytes();
        let [l0, l1] = len.to_be_bytes();
        u.q.write(&src);
        u.q.write(&[p0, p1, l0, l1]);
        u.q.write(payload);
        Some(i)
    }

    /// Geeft de poort op plek `i` vrij met zijn volledige reservering. Idempotent.
    pub(crate) fn close(&mut self, i: usize, pot: &mut Budget) -> Option<UdpPort<N>> {
        let u = self.ports.get_mut(i)?.take()?;
        pot.release(u.cap);
        Some(u)
    }
}

#[cfg(test)]
mod tests;
