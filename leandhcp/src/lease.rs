//! De lease: wat een ACK ons geeft, en wanneer dat verlengd moet worden.
//!
//! Deze module bezit alleen waarden; geen toestand, geen klok.

use core::fmt;
use core::net::Ipv4Addr;
use core::time::Duration;

/// Het resultaat van een geslaagde handshake: een adres en wat erbij hoort.
///
/// Een `Lease` komt uit een DHCPACK. De Go-versie had een vlag `Acquired` om
/// een echte lease van de nulwaarde te scheiden; hier is dat het type zelf:
/// wie statisch configureert, maakt geen [`Keeper`](crate::Keeper). Een lease
/// zonder looptijd (de nulwaarde) valt voor de keeper onder "onbekend" en
/// wordt dus niet onderhouden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Ons adres (yiaddr).
    pub ip: Ipv4Addr,
    /// Het subnetmasker (optie 1).
    pub mask: Ipv4Addr,
    /// De eerste router (optie 3).
    pub gateway: Ipv4Addr,
    /// De eerste resolver (optie 6); 0.0.0.0 betekent: geen.
    pub dns: Ipv4Addr,
    /// De server die de lease gaf (optie 54).
    pub server: Ipv4Addr,
    /// Looptijd in seconden (optie 51); `0xFFFF_FFFF` is oneindig.
    pub lease_secs: u32,
    /// Renew-tijd T1 in seconden (optie 58); zie [`Lease::timers`].
    pub t1_secs: u32,
    /// Rebind-tijd T2 in seconden (optie 59); zie [`Lease::timers`].
    pub t2_secs: u32,
}

impl Default for Lease {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            mask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            server: Ipv4Addr::UNSPECIFIED,
            lease_secs: 0,
            t1_secs: 0,
            t2_secs: 0,
        }
    }
}

/// De drie momenten van een lease, gerekend vanaf de ontvangst van de ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    /// Vanaf hier renewen we unicast bij de lessor.
    pub t1: Duration,
    /// Vanaf hier rebinden we per broadcast bij elke server.
    pub t2: Duration,
    /// Vanaf hier is het adres niet meer van ons.
    pub expiry: Duration,
}

/// Een adres met prefixlengte, zoals `192.168.1.33/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// Het adres.
    pub ip: Ipv4Addr,
    /// Het aantal enen in het masker.
    pub prefix: u32,
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

impl Lease {
    /// Het adres met de prefixlengte uit het masker, voor de netstack.
    pub fn cidr(&self) -> Cidr {
        Cidr {
            ip: self.ip,
            prefix: u32::from(self.mask).count_ones(),
        }
    }

    /// T1, T2 en het verlopen, gerekend vanaf de ontvangst van de ACK.
    ///
    /// `None` betekent een oneindige of onbekende lease: niets te plannen.
    /// Een ongeldige volgorde valt terug op de RFC 2131-verhoudingen 0,5 en
    /// 0,875. Echte routers hebben T1 = T2 = looptijd gestuurd, en dat wist de
    /// rebind-fase uit; daarom geldt steeds 0 < T1 < T2 < looptijd.
    pub fn timers(&self) -> Option<Timers> {
        if self.lease_secs == 0 || self.lease_secs == u32::MAX {
            return None;
        }
        let expiry = secs(self.lease_secs);
        let mut t1 = secs(self.t1_secs);
        let mut t2 = secs(self.t2_secs);
        if t1.is_zero() || t1 >= expiry {
            t1 = expiry / 2;
        }
        if t2 <= t1 || t2 >= expiry {
            t2 = expiry / 8 * 7;
        }
        if t1 >= t2 {
            // T1 boven 0,875 van de looptijd is de ongeldige waarde.
            t1 = expiry / 2;
        }
        Some(Timers { t1, t2, expiry })
    }

    /// Legt een karige verleng-ACK over deze lease.
    ///
    /// Velden die de server weglaat, blijven staan. Zonder dat zou een zwijgzame
    /// server de looptijd stil op nul zetten, en dan stopt het onderhoud.
    pub(crate) fn merge(self, fresh: Self) -> Self {
        let keep = |new: Ipv4Addr, old: Ipv4Addr| if new.is_unspecified() { old } else { new };
        let (lease_secs, t1_secs, t2_secs) = if fresh.lease_secs == 0 {
            (self.lease_secs, self.t1_secs, self.t2_secs)
        } else {
            (fresh.lease_secs, fresh.t1_secs, fresh.t2_secs)
        };
        Self {
            ip: keep(fresh.ip, self.ip),
            mask: keep(fresh.mask, self.mask),
            gateway: keep(fresh.gateway, self.gateway),
            dns: keep(fresh.dns, self.dns),
            server: keep(fresh.server, self.server),
            lease_secs,
            t1_secs,
            t2_secs,
        }
    }
}

/// Seconden als `Duration`.
fn secs(v: u32) -> Duration {
    Duration::from_secs(u64::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::bound;

    #[test]
    fn lease_tekstvormen() {
        let l = Lease {
            ip: Ipv4Addr::new(10, 0, 0, 7),
            mask: Ipv4Addr::new(255, 255, 240, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            ..Lease::default()
        };
        assert_eq!(l.cidr().to_string(), "10.0.0.7/20");
        assert_eq!(l.ip.to_string(), "10.0.0.7");
        assert_eq!(Lease::default().dns.to_string(), "0.0.0.0");
    }

    #[test]
    fn timers() {
        let min = |m: u64| Duration::from_secs(m * 60);
        let s = Duration::from_secs;
        let lease = |l, t1, t2| Lease {
            lease_secs: l,
            t1_secs: t1,
            t2_secs: t2,
            ..Lease::default()
        };
        let standaard = Some(Timers {
            t1: min(30),
            t2: min(52) + s(30),
            expiry: min(60),
        });
        let cases = [
            ("server stuurt alles", lease(3600, 1800, 3150), standaard),
            (
                "alleen lease-tijd: RFC-verhoudingen",
                lease(800, 0, 0),
                Some(Timers {
                    t1: s(400),
                    t2: s(700),
                    expiry: s(800),
                }),
            ),
            (
                "T1 = T2 = lease (bestaat in het veld)",
                lease(3600, 3600, 3600),
                standaard,
            ),
            ("T1 boven 0.875 lease", lease(3600, 3400, 0), standaard),
            ("T2 onder T1", lease(3600, 1800, 600), standaard),
            ("oneindig", lease(u32::MAX, 0, 0), None),
            ("onbekend", Lease::default(), None),
        ];
        for (naam, l, want) in cases {
            let got = l.timers();
            assert_eq!(got, want, "{naam}");
            if let Some(t) = got {
                assert!(
                    Duration::ZERO < t.t1 && t.t1 < t.t2 && t.t2 < t.expiry,
                    "{naam}: de orde 0 < T1 < T2 < lease is geschonden: {t:?}"
                );
            }
        }
    }

    #[test]
    fn merge_draagt_door() {
        let oud = bound();
        let kaal = Lease {
            ip: oud.ip,
            ..Lease::default()
        };
        assert_eq!(
            oud.merge(kaal),
            oud,
            "alles hoort uit de oude lease te komen"
        );

        let nieuw = Lease {
            ip: oud.ip,
            lease_secs: 7200,
            t1_secs: 3600,
            t2_secs: 6300,
            dns: Ipv4Addr::new(9, 9, 9, 9),
            ..Lease::default()
        };
        let got = oud.merge(nieuw);
        assert_eq!(
            (got.lease_secs, got.t1_secs, got.t2_secs),
            (7200, 3600, 6300),
            "verse timers werden niet overgenomen"
        );
        assert_eq!(got.dns, Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!((got.mask, got.gateway), (oud.mask, oud.gateway));
    }
}
