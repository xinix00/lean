//! Eén waker-slot per wachtende kant van een handvat.
//!
//! De stack heeft één eigenaar en wordt alleen via `&mut` aangeraakt, dus een
//! slot is een gewone `Option<Waker>`: geen atomics, geen slot. Wie wakkert,
//! neemt de waker eruit; wie wacht, registreert opnieuw bij de volgende poll.
//! Dat is het gewone futures-contract en het maakt een verloren wek
//! onmogelijk zolang de wachter eerst registreert en dan opnieuw kijkt.

use core::task::Waker;

/// Houdt hoogstens één waker vast.
#[derive(Debug, Default)]
pub(crate) struct WakerSlot(Option<Waker>);

impl WakerSlot {
    /// Registreert `w`; een waker die dezelfde taak wekt wordt niet gekloond.
    pub(crate) fn register(&mut self, w: &Waker) {
        match &self.0 {
            Some(old) if old.will_wake(w) => {}
            _ => self.0 = Some(w.clone()),
        }
    }

    /// Wekt en leegt het slot.
    pub(crate) fn wake(&mut self) {
        if let Some(w) = self.0.take() {
            w.wake();
        }
    }

    /// Of er een wachter is.
    pub(crate) fn is_set(&self) -> bool {
        self.0.is_some()
    }
}
