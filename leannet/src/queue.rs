//! Een begrensde rij van records met lengteprefix over één bytering.
//!
//! De stack gebruikt er drie: verbindingsloze antwoorden (ICMP-echo, RSTs),
//! uitgaande UDP-frames en loopback-frames. De Go-versie alloceerde per
//! antwoord en per loopbackframe een eigen slice; hier groeit één ring met
//! gebruik tot zijn plafond en wordt daarna hergebruikt, zodat het hete pad
//! niet alloceert. Deze module weet niet wat er in een record staat.

use crate::ring::Ring;

/// Bytes voor het lengteprefix van een record.
const PREFIX: usize = 2;

/// Een begrensde FIFO van records.
#[derive(Debug, Default)]
pub(crate) struct RecordQueue {
    ring: Ring,
    records: usize,
    max_records: usize,
    max_bytes: usize,
}

impl RecordQueue {
    /// Een lege rij met plafonds; er wordt pas bij gebruik gealloceerd.
    pub(crate) fn new(max_records: usize, max_bytes: usize) -> RecordQueue {
        RecordQueue {
            ring: Ring::default(),
            records: 0,
            max_records,
            max_bytes,
        }
    }

    /// Het aantal records.
    pub(crate) fn len(&self) -> usize {
        self.records
    }

    /// Of de rij leeg is.
    pub(crate) fn is_empty(&self) -> bool {
        self.records == 0
    }

    /// Of een record van `len` bytes er nu bij kan (eventueel na groei).
    pub(crate) fn can_fit(&self, len: usize) -> bool {
        self.records < self.max_records && self.ring.buffered() + PREFIX + len <= self.max_bytes
    }

    /// Voegt een record toe dat bestaat uit de aaneengesloten `parts`.
    /// `false` bij een vol plafond of een geweigerde allocatie.
    pub(crate) fn push(&mut self, parts: &[&[u8]]) -> bool {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let Ok(wire) = u16::try_from(len) else {
            return false;
        };
        if !self.can_fit(len) {
            return false;
        }
        let need = PREFIX + len;
        if self.ring.free() < need {
            let grown = (self.ring.size() * 2)
                .max(self.ring.buffered() + need)
                .max(1024)
                .min(self.max_bytes);
            if grown < self.ring.buffered() + need || self.ring.grow(grown).is_err() {
                return false;
            }
        }
        self.ring.write(&wire.to_be_bytes());
        for p in parts {
            self.ring.write(p);
        }
        self.records += 1;
        true
    }

    /// Haalt het oudste record op in `out` en geeft zijn lengte. Een te kleine
    /// `out` krijgt het begin; de rest vervalt, de recordgrens blijft.
    pub(crate) fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut pfx = [0u8; PREFIX];
        if self.records == 0 || self.ring.peek(&mut pfx, 0) != PREFIX {
            return None;
        }
        let len = usize::from(u16::from_be_bytes(pfx));
        let take = len.min(out.len());
        let n = self
            .ring
            .peek(out.get_mut(..take).unwrap_or(&mut []), PREFIX);
        self.ring.drop_front(PREFIX + len);
        self.records -= 1;
        Some(n)
    }

    /// Laat alles vallen en geeft de opslag terug aan de allocator.
    pub(crate) fn release(&mut self) {
        self.ring = Ring::default();
        self.records = 0;
    }
}
