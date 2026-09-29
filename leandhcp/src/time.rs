//! De klok van de aanroeper: een monotoon tijdstip, geen wandklok.
//!
//! Deze module bezit alleen het type. Waar de tijd vandaan komt (de teller van
//! de architectuur, een timer-wiel) is van de aanroeper.

use core::ops::Add;
use core::time::Duration;

/// Een tijdstip op een monotone klok met een willekeurige oorsprong.
///
/// Monotoon is contract. De Go-versie telde zijn eigen slaapjes op omdat de
/// wandklok van Tamago bij de SNTP-stap tijdens de boot van epoch naar nu
/// sprong; één lange `Sleep` gaf daardoor een renew vlak na de boot (gemeten
/// 11-07-2026). Een monotone teller springt niet, dus rekenen we hier gewoon
/// met tijdstippen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
    /// De oorsprong van de klok.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Het tijdstip `ms` milliseconden na de oorsprong.
    pub const fn from_millis(ms: u64) -> Self {
        Self(Duration::from_millis(ms))
    }

    /// Het tijdstip `d` na de oorsprong.
    pub const fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    /// De tijd sinds de oorsprong.
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// De tijd van `earlier` tot `self`, of nul als `earlier` later ligt.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    /// Telt op en blijft aan het eind van de klok staan in plaats van te
    /// panieken: een deadline van "nooit" is dan gewoon het verste tijdstip.
    fn add(self, rhs: Duration) -> Self {
        Self(self.0.saturating_add(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instant_verzadigt() {
        let end = Instant::from_duration(Duration::MAX);
        assert_eq!(end + Duration::from_secs(1), end);
        let a = Instant::from_millis(5);
        assert_eq!(a.saturating_duration_since(end), Duration::ZERO);
        assert_eq!(end.saturating_duration_since(Instant::ZERO), Duration::MAX);
    }
}
