//! De byteringen achter elke verbinding en de ene geheugenpot.
//!
//! - [`Ring`]: het netwerk schrijft bytes in volgorde achteraan, de applicatie
//!   leest vooraan. Vrije ruimte is het ontvangstvenster.
//! - [`TxRing`]: de applicatie schrijft achteraan en een cursor houdt bij wat
//!   verstuurd is. Een ACK geeft de kop vrij; een RTO spoelt de cursor terug
//!   voor go-back-N. Hertransmissie is zo een herlezing van dezelfde ring.
//! - [`Budget`]: telt capaciteit; de bytes zelf alloceert de eigenaar.
//!
//! Groei is expliciet en faalbaar, zodat de verbinding hem tegen het budget
//! kan boeken. Deze module bezit geen verbindingstoestand.

use alloc::vec::Vec;

use crate::{Error, Result};

/// Alloceert een genulde buffer van `n` bytes, of weigert netjes.
pub(crate) fn alloc_zeroed(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| Error::OutOfMemory { bytes: n })?;
    // Na de reservering alloceert resize niet meer.
    v.resize(n, 0);
    Ok(v)
}

/// Een FIFO over een vaste bytebuffer.
///
/// `head` is de leespositie en `n` het aantal gebufferde bytes; `n` apart
/// bijhouden onderscheidt vol van leeg zonder een slot te verliezen.
///
/// # Invariants
///
/// `n <= buf.len()` en `head < buf.len()` (of beide nul bij een lege buffer).
#[derive(Debug, Default)]
pub(crate) struct Ring {
    buf: Vec<u8>,
    head: usize,
    n: usize,
}

impl Ring {
    /// Maakt een ring van `size` bytes.
    pub(crate) fn with_size(size: usize) -> Result<Ring> {
        // INVARIANT: een lege ring met head 0.
        Ok(Ring {
            buf: alloc_zeroed(size)?,
            head: 0,
            n: 0,
        })
    }

    /// De capaciteit in bytes.
    pub(crate) fn size(&self) -> usize {
        self.buf.len()
    }

    /// Het aantal gebufferde bytes.
    pub(crate) fn buffered(&self) -> usize {
        self.n
    }

    /// De vrije ruimte in bytes.
    pub(crate) fn free(&self) -> usize {
        self.buf.len() - self.n
    }

    /// Kopieert zoveel mogelijk van `p` achteraan en geeft het aantal.
    pub(crate) fn write(&mut self, mut p: &[u8]) -> usize {
        let size = self.buf.len();
        let mut total = 0;
        while !p.is_empty() && self.n < size {
            let w = (self.head + self.n) % size;
            // Aaneengesloten stuk tot de fysieke rand of tot de kop.
            let chunk = (size - w).min(size - self.n).min(p.len());
            let (src, rest) = p.split_at(chunk);
            if let Some(dst) = self.buf.get_mut(w..w + chunk) {
                dst.copy_from_slice(src);
            }
            self.n += chunk;
            total += chunk;
            p = rest;
        }
        total
    }

    /// Kopieert beschikbare bytes vanaf `off` na de kop zonder te consumeren.
    pub(crate) fn peek(&self, p: &mut [u8], off: usize) -> usize {
        if off >= self.n {
            return 0;
        }
        let size = self.buf.len();
        let avail = self.n - off;
        let want = p.len().min(avail);
        let mut pos = (self.head + off) % size;
        let mut done = 0;
        while done < want {
            let chunk = (size - pos).min(want - done);
            if let (Some(dst), Some(src)) = (
                p.get_mut(done..done + chunk),
                self.buf.get(pos..pos + chunk),
            ) {
                dst.copy_from_slice(src);
            }
            done += chunk;
            pos = (pos + chunk) % size;
        }
        want
    }

    /// Consumeert `k` bytes. Meer dan gebufferd wordt geweigerd (`false`) en
    /// laat de ring ongemoeid: het zou een volgnummerfout zijn, geen invoer.
    pub(crate) fn drop_front(&mut self, k: usize) -> bool {
        if k > self.n {
            return false;
        }
        if k == 0 {
            return true;
        }
        self.head = (self.head + k) % self.buf.len();
        self.n -= k;
        if self.n == 0 {
            // Een lege ring normaliseren maakt groei en tests voorspelbaar.
            self.head = 0;
        }
        true
    }

    /// Kopieert vanaf de kop en consumeert de bytes.
    pub(crate) fn read(&mut self, p: &mut [u8]) -> usize {
        let got = self.peek(p, 0);
        self.drop_front(got);
        got
    }

    /// Verhuist de inhoud naar het begin van een even grote of grotere buffer.
    ///
    /// Faalt zonder iets te veranderen als de allocator weigert of de nieuwe
    /// maat de inhoud niet draagt.
    pub(crate) fn grow(&mut self, new_size: usize) -> Result {
        if new_size < self.n {
            return Err(Error::NoBudget {
                need: self.n,
                free: new_size,
            });
        }
        let mut nb = alloc_zeroed(new_size)?;
        let n = self.n;
        let got = self.peek(nb.get_mut(..n).unwrap_or(&mut []), 0);
        // INVARIANT: de inhoud staat nu vanaf nul; head wordt nul.
        self.buf = nb;
        self.head = 0;
        self.n = got;
        Ok(())
    }

    /// Test-toegang tot de kop, voor de normalisatie-eis.
    #[cfg(test)]
    pub(crate) fn head(&self) -> usize {
        self.head
    }

    /// Maakt een ring met een gegeven kop, zoals de Go-tests dat deden.
    #[cfg(test)]
    pub(crate) fn with_head(size: usize, head: usize) -> Ring {
        let mut r = Ring::with_size(size).unwrap();
        r.head = head;
        r
    }
}

/// Een zendring die bytes vasthoudt tot ze bevestigd zijn.
///
/// `sent` telt gebufferde bytes die minstens één keer verstuurd zijn; de kop
/// van de ring is `snd.UNA`.
#[derive(Debug, Default)]
pub(crate) struct TxRing {
    pub(crate) ring: Ring,
    sent: usize,
}

impl TxRing {
    /// Maakt een zendring van `size` bytes.
    pub(crate) fn with_size(size: usize) -> Result<TxRing> {
        Ok(TxRing {
            ring: Ring::with_size(size)?,
            sent: 0,
        })
    }

    /// Buffert zoveel applicatiebytes als passen.
    pub(crate) fn write_app(&mut self, p: &[u8]) -> usize {
        self.ring.write(p)
    }

    /// De capaciteit.
    pub(crate) fn size(&self) -> usize {
        self.ring.size()
    }

    /// Onbevestigde plus onverzonden bytes.
    pub(crate) fn buffered(&self) -> usize {
        self.ring.buffered()
    }

    /// Bytes die nog verstuurd moeten worden, ook na een terugspoeling.
    pub(crate) fn unsent(&self) -> usize {
        self.ring.buffered() - self.sent
    }

    /// Kopieert onverzonden bytes en schuift de cursor op; een ACK geeft ze later vrij.
    pub(crate) fn next_send(&mut self, p: &mut [u8]) -> usize {
        let got = self.ring.peek(p, self.sent);
        self.sent += got;
        got
    }

    /// Geeft `k` bevestigde bytes vrij en past de cursor aan. De verbinding
    /// weigert ACKs voorbij verstuurde data voordat ze dit aanroept; een
    /// te grote `k` wordt daarom geweigerd in plaats van geloofd.
    pub(crate) fn ack(&mut self, k: usize) -> bool {
        if k > self.sent || !self.ring.drop_front(k) {
            return false;
        }
        self.sent -= k;
        true
    }

    /// Markeert elke onbevestigde byte voor go-back-N-hertransmissie.
    pub(crate) fn rewind(&mut self) {
        self.sent = 0;
    }

    /// Laat een cumulatieve ACK een lopende hertransmissie na een terugspoeling
    /// inhalen, zonder voorbij de gebufferde data te gaan.
    pub(crate) fn force_sent(&mut self, k: usize) {
        let k = k.min(self.ring.buffered());
        if self.sent < k {
            self.sent = k;
        }
    }

    /// Verhuist naar een grotere buffer; de cursor blijft staan.
    pub(crate) fn grow(&mut self, new_size: usize) -> Result {
        self.ring.grow(new_size)
    }
}

/// De ene geheugencontrole: capaciteit voor alle TCP-ringen en UDP-wachtrijen
/// samen.
///
/// Verbindingen reserveren terwijl ze groeien en geven terug bij sluiten, zodat
/// geheugen gebruik volgt en geen configuratie. De vorige stack reserveerde
/// 2 MiB per listener en 256 KiB per dial; op een 64 MiB-node gaf dat
/// reproduceerbaar een OOM na 151 seconden downloadlast (DESIGN.md).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Budget {
    pub(crate) total: usize,
    pub(crate) used: usize,
}

impl Budget {
    /// Maakt een pot van `total` bytes.
    pub(crate) fn new(total: usize) -> Budget {
        Budget { total, used: 0 }
    }

    /// Claimt `n` bytes als ze er zijn. Een aanroeper mag kleiner proberen of
    /// falen, maar wacht nooit stil op geheugen.
    pub(crate) fn reserve(&mut self, n: usize) -> bool {
        match self.used.checked_add(n) {
            Some(u) if u <= self.total => {
                self.used = u;
                true
            }
            _ => false,
        }
    }

    /// Geeft `n` bytes terug. Meer teruggeven dan gereserveerd zou de
    /// budgetbelofte ongeldig maken; dat wordt geweigerd (`false`) en laat de
    /// pot ongemoeid.
    pub(crate) fn release(&mut self, n: usize) -> bool {
        match self.used.checked_sub(n) {
            Some(u) => {
                self.used = u;
                true
            }
            None => false,
        }
    }

    /// Momentopname van de vrije ruimte; `reserve` is gezaghebbend.
    pub(crate) fn free(&self) -> usize {
        self.total.saturating_sub(self.used)
    }
}

#[cfg(test)]
mod tests;
