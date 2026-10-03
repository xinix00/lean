//! De buurlevensloop die ARP deelt (en NDP zou delen): verloop, capaciteit,
//! leren, vragen en opgeven, één keer geïmplementeerd.
//!
//! Draadformaten, antwoorden, routerstaat en publieke tellers blijven bij het
//! protocol ([`crate::arp`]); deze tabel bezit alleen de levensloop per sleutel.
//! Tijd is monotone nanoseconden van de aanroeper.
//!
//! De tabel is een platte `Vec` met vooraf gereserveerde capaciteit: 128
//! buren lineair doorzoeken kost minder dan een map, en na de reservering
//! alloceert geen enkel pad meer.

use alloc::vec::Vec;

use crate::{Error, Result, SEC};

/// Hoe lang een opgelost antwoord geldt.
pub(crate) const NEIGHBOR_ENTRY_TTL: u64 = 120 * SEC;
/// Wachttijd tussen twee vragen.
pub(crate) const NEIGHBOR_RETRY_IVAL: u64 = SEC;
/// Vragen voordat een query opgeeft.
pub(crate) const NEIGHBOR_QUERY_TRIES: u8 = 5;
/// Hoe lang een opgegeven query negatief gecachet blijft.
pub(crate) const NEIGHBOR_FAIL_TTL: u64 = 5 * SEC;

/// De drie toestanden van een buur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NeighborState {
    /// Query loopt; MAC onbekend.
    Pending,
    /// MAC bekend tot `born + NEIGHBOR_ENTRY_TTL`.
    Resolved,
    /// Negatieve cache tot `born + NEIGHBOR_FAIL_TTL`.
    Failed,
}

/// Eén buur.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NeighborEntry {
    pub(crate) mac: [u8; 6],
    pub(crate) state: NeighborState,
    /// Geseede entries verlopen en verversen nooit.
    pub(crate) is_static: bool,
    /// Tijd van oplossing, verversing of opgave.
    pub(crate) born: u64,
    /// Vragen verstuurd terwijl pending; opgelost: 1 = een twijfelvraag
    /// die nog uit moet ([`NeighborTable::probe`]).
    pub(crate) tries: u8,
    /// Volgende vraagtijd terwijl pending; opgelost: de vroegste volgende
    /// twijfel.
    pub(crate) due: u64,
}

impl NeighborEntry {
    /// Een verse lopende query.
    pub(crate) fn pending(due: u64) -> NeighborEntry {
        NeighborEntry {
            mac: [0; 6],
            state: NeighborState::Pending,
            is_static: false,
            born: 0,
            tries: 0,
            due,
        }
    }

    /// Een opgelost antwoord.
    pub(crate) fn resolved(mac: [u8; 6], born: u64) -> NeighborEntry {
        NeighborEntry {
            mac,
            state: NeighborState::Resolved,
            is_static: false,
            born,
            tries: 0,
            due: 0,
        }
    }
}

/// De levensloop per sleutel, begrensd op `limit` entries (plus statische
/// configuratie, die de protocolkant apart begrenst).
#[derive(Debug)]
pub(crate) struct NeighborTable<K> {
    pub(crate) entries: Vec<(K, NeighborEntry)>,
    pub(crate) limit: usize,
}

impl<K: Copy + PartialEq> NeighborTable<K> {
    /// Maakt een tabel en reserveert haar capaciteit in één keer.
    pub(crate) fn new(limit: usize) -> Result<NeighborTable<K>> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limit)
            .map_err(|_| Error::OutOfMemory {
                bytes: limit * core::mem::size_of::<(K, NeighborEntry)>(),
            })?;
        Ok(NeighborTable { entries, limit })
    }

    /// Het aantal entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// De index van `key`.
    fn find(&self, key: K) -> Option<usize> {
        self.entries.iter().position(|(k, _)| *k == key)
    }

    /// Een kopie van de entry voor `key`.
    pub(crate) fn get(&self, key: K) -> Option<NeighborEntry> {
        self.find(key)
            .and_then(|i| self.entries.get(i))
            .map(|(_, e)| *e)
    }

    /// Een veranderbare verwijzing naar de entry voor `key`.
    fn get_mut(&mut self, key: K) -> Option<&mut NeighborEntry> {
        self.entries
            .iter_mut()
            .find(|(k, _)| *k == key)
            .map(|(_, e)| e)
    }

    /// Verwijdert `key`.
    pub(crate) fn remove(&mut self, key: K) {
        if let Some(i) = self.find(key) {
            self.entries.swap_remove(i);
        }
    }

    /// Zet `key` op `e`, vervangend of toevoegend. Toevoegen voorbij de
    /// gereserveerde capaciteit is faalbaar, nooit een abort.
    pub(crate) fn insert(&mut self, key: K, e: NeighborEntry) -> Result {
        if let Some(slot) = self.get_mut(key) {
            *slot = e;
            return Ok(());
        }
        crate::try_push(&mut self.entries, (key, e))
    }

    /// Of een entry nog leeft; verlopen opgeloste en mislukte entries tellen
    /// niet. Een pending query verloopt alleen via [`NeighborTable::poll`],
    /// in de pomp, waar het protocol wachters kan wekken.
    fn is_live(e: &NeighborEntry, now: u64) -> bool {
        match e.state {
            NeighborState::Pending => true,
            NeighborState::Resolved => {
                e.is_static || now.saturating_sub(e.born) < NEIGHBOR_ENTRY_TTL
            }
            NeighborState::Failed => now.saturating_sub(e.born) < NEIGHBOR_FAIL_TTL,
        }
    }

    /// Verwijdert `key` als hij verlopen is; geeft de levende entry terug.
    fn tick(&mut self, key: K, now: u64) -> Option<NeighborEntry> {
        let e = self.get(key)?;
        if Self::is_live(&e, now) {
            return Some(e);
        }
        self.remove(key);
        None
    }

    /// Geeft een bekende MAC, of start één ontdubbelde query. `refused` betekent
    /// dat pending/statisch werk de tabel vulde en er geen query bij kon.
    pub(crate) fn resolve(&mut self, key: K, now: u64) -> (Option<[u8; 6]>, bool) {
        if let Some(e) = self.tick(key, now) {
            if e.state == NeighborState::Resolved {
                return (Some(e.mac), false);
            }
            return (None, false);
        }
        if !self.make_room(now) {
            return (None, true);
        }
        if self.insert(key, NeighborEntry::pending(now)).is_err() {
            return (None, true);
        }
        (None, false)
    }

    /// Laat verlopen entries vallen en verdringt tot een nieuwe past. Het is
    /// een lus omdat statische configuratie de tabel boven zijn nominale
    /// grens kan houden.
    pub(crate) fn make_room(&mut self, now: u64) -> bool {
        if self.entries.len() < self.limit {
            return true;
        }
        self.sweep_expired(now);
        while self.entries.len() >= self.limit {
            if !self.evict_resolved() {
                return false;
            }
        }
        true
    }

    /// Verwijdert alle verlopen entries.
    pub(crate) fn sweep_expired(&mut self, now: u64) {
        self.entries.retain(|(_, e)| Self::is_live(e, now));
    }

    /// Verwijdert één niet-statisch antwoord. Lopend werk en statische
    /// configuratie worden nooit verdrongen; een echte peer is later opnieuw
    /// te leren.
    fn evict_resolved(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .position(|(_, e)| e.state == NeighborState::Resolved && !e.is_static);
        match victim {
            Some(i) => {
                self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Geeft een bekende MAC zonder een query te starten.
    pub(crate) fn peek(&mut self, key: K, now: u64) -> Option<[u8; 6]> {
        match self.tick(key, now) {
            Some(e) if e.state == NeighborState::Resolved => Some(e.mac),
            _ => None,
        }
    }

    /// Meldt een negatieve-cachetreffer, of een tabel die de ontbrekende query
    /// niet kan toelaten. Het is het exacte weigerspiegelbeeld van `make_room`.
    pub(crate) fn no_answer(&mut self, key: K, now: u64) -> bool {
        if self.find(key).is_none() {
            return self.full(now);
        }
        matches!(self.tick(key, now), Some(e) if e.state == NeighborState::Failed)
    }

    /// Of de tabel geen nieuwe query meer kan toelaten.
    pub(crate) fn full(&mut self, now: u64) -> bool {
        if self.entries.len() < self.limit {
            return false;
        }
        self.sweep_expired(now);
        let evictable = self
            .entries
            .iter()
            .filter(|(_, e)| e.state == NeighborState::Resolved && !e.is_static)
            .count();
        self.entries.len() - evictable >= self.limit
    }

    /// Legt gevalideerd passief verkeer vast. Verdringt nooit en verandert de
    /// MAC van een opgeloste entry nooit. Geeft `(woke, dropped)`: een pending
    /// query werd opgelost, of de capaciteit weigerde.
    pub(crate) fn learn(&mut self, key: K, mac: [u8; 6], now: u64) -> (bool, bool) {
        let Some(e) = self.tick(key, now) else {
            if self.entries.len() >= self.limit {
                self.sweep_expired(now);
                if self.entries.len() >= self.limit {
                    return (false, true);
                }
            }
            let dropped = self.insert(key, NeighborEntry::resolved(mac, now)).is_err();
            return (false, dropped);
        };
        let Some(slot) = self.get_mut(key) else {
            return (false, false);
        };
        match e.state {
            NeighborState::Pending => {
                *slot = NeighborEntry::resolved(mac, now);
                (true, false)
            }
            NeighborState::Resolved if !e.is_static && e.mac == mac => {
                slot.born = now;
                (false, false)
            }
            _ => (false, false),
        }
    }

    /// Past een gevraagd draadantwoord alleen toe op een lopende query.
    pub(crate) fn resolve_pending(&mut self, key: K, mac: [u8; 6], now: u64) -> bool {
        match self.tick(key, now) {
            Some(e) if e.state == NeighborState::Pending => {
                if let Some(slot) = self.get_mut(key) {
                    *slot = NeighborEntry::resolved(mac, now);
                }
                true
            }
            _ => false,
        }
    }

    /// Ververst één levende, niet-statische opgeloste entry. De twee
    /// uitkomsten onderscheiden een genegeerde aankondiging van een echte
    /// verversing, en tellen MAC-wissels zonder protocoltellers hier.
    pub(crate) fn refresh(&mut self, key: K, mac: [u8; 6], now: u64) -> (bool, bool) {
        match self.tick(key, now) {
            Some(e) if e.state == NeighborState::Resolved && !e.is_static => {
                let changed = e.mac != mac;
                if let Some(slot) = self.get_mut(key) {
                    slot.mac = mac;
                    slot.born = now;
                }
                (true, changed)
            }
            _ => (false, false),
        }
    }

    /// Twijfel aan een opgeloste entry (Linux: `NUD_PROBE`): één vraag,
    /// hoogstens één per [`NEIGHBOR_RETRY_IVAL`], en de MAC blijft gelden
    /// tot het antwoord hem ververst of de entry verloopt. `tries` op een
    /// opgeloste entry is de vraag die [`NeighborTable::poll`] nog stuurt.
    pub(crate) fn probe(&mut self, key: K, now: u64) {
        if let Some(e) = self.get_mut(key)
            && e.state == NeighborState::Resolved
            && !e.is_static
            && now >= e.due
        {
            e.tries = 1;
            e.due = now + NEIGHBOR_RETRY_IVAL;
        }
    }

    /// Voert rijp pending werk uit. Kan meerdere entries opgeven voordat hij
    /// één query teruggeeft voor de protocolspecifieke zender.
    pub(crate) fn poll(&mut self, now: u64) -> (Option<K>, usize) {
        self.sweep_expired(now);
        let mut gave_up = 0;
        for (k, e) in &mut self.entries {
            if e.state == NeighborState::Resolved && e.tries > 0 {
                e.tries = 0;
                return (Some(*k), gave_up);
            }
            if e.state != NeighborState::Pending || now < e.due {
                continue;
            }
            if e.tries >= NEIGHBOR_QUERY_TRIES {
                e.state = NeighborState::Failed;
                e.born = now;
                gave_up += 1;
                continue;
            }
            e.tries += 1;
            e.due = now + NEIGHBOR_RETRY_IVAL;
            return (Some(*k), gave_up);
        }
        (None, gave_up)
    }

    /// De vroegste deadline van lopend werk en negatieve cache.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter_map(|(_, e)| match e.state {
                NeighborState::Pending => Some(e.due),
                NeighborState::Failed => Some(e.born + NEIGHBOR_FAIL_TTL),
                NeighborState::Resolved => None,
            })
            .min()
    }
}

#[cfg(test)]
mod tests;
