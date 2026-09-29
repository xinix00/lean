//! DHCPv4 (RFC 2131) op rauwe ethernet-frames: een lease voordat er een netstack is.
//!
//! De crate bezit twee toestandsmachines en het draadformaat; hij bezit geen
//! NIC, geen socket en geen klok. De aanroeper levert de tijd en de frames
//! (sans-I/O), zodat de hele logica op de host testbaar is zonder device en
//! zonder echt te wachten.
//!
//! De grens met de netstack verdeelt de crate in tweeën:
//!
//! - [`Client`] haalt een lease op met rauwe ethernet-frames tijdens de
//!   bring-up: DISCOVER, OFFER, REQUEST, ACK. Er is dan nog geen stack, dus
//!   bouwt de client zelf de ethernet-, IPv4- en UDP-koppen.
//! - [`Keeper`] houdt die lease daarna in leven volgens RFC 2131 §4.4.5
//!   (bound, renewing, rebinding). Zodra de stack de RX-ringen bezit, mogen
//!   die maar één eigenaar hebben; daarom spreekt de keeper UDP-payloads op
//!   poort 68 en zendt de stack ze.
//!
//! DISCOVER en OFFER zijn bewezen op een Pi 5 (probe6 run 5, 10-07-2026): een
//! OFFER van een FRITZ!Box kwam door de eigen keten PCIe, RP1, GEM.
//!
//! # Examples
//!
//! De vorm van de lus bij de aanroeper; hier zonder server, dus hij eindigt
//! na de time-out met een fout.
//!
//! ```
//! use core::time::Duration;
//! use leandhcp::{Action, Client, Instant};
//!
//! let mut now = Instant::from_millis(0);
//! let mut client = Client::new([2, 0, 0, 0, 0, 1], now, Duration::from_millis(500));
//! let err = loop {
//!     match client.poll(now) {
//!         Ok(Action::Transmit(frame)) => assert_eq!(frame.len(), 342), // nic.transmit(frame)
//!         Ok(Action::Wait(until)) => now = until, // Voer frames toe met client.receive.
//!         Ok(Action::Bound(lease)) => panic!("lease uit het niets: {}", lease.cidr()),
//!         Err(err) => break err,
//!     }
//! };
//! assert!(err.to_string().contains("no server answered"));
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
#![forbid(unsafe_code)]

mod client;
mod keeper;
mod lease;
mod time;
mod wire;

#[cfg(test)]
mod testutil;

pub use client::{Action, Client};
pub use keeper::{Event, KeepAction, Keeper, State};
pub use lease::{Cidr, Lease, Timers};
pub use time::Instant;
pub use wire::{CLIENT_PORT, FRAME_LEN, SERVER_PORT};

use core::fmt;
use core::net::Ipv4Addr;
use core::time::Duration;

/// Het resultaat van een handeling in deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Waarom er geen (of niet langer een) lease is.
///
/// Elke variant draagt de getallen en adressen mee die in de logregel horen.
/// De varianten van de [`Keeper`] eindigen op een marker (`HOPOS_DHCP_*`)
/// waar de soak-scripts op greppen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Binnen de time-out antwoordde geen server met een lease.
    NoLease {
        /// De totale time-out die de aanroeper gaf.
        timeout: Duration,
        /// Hoeveel ontvangstfouten de NIC meldde. Niet nul betekent: een kapotte
        /// NIC, geen afwezige server.
        rx_errors: u32,
    },
    /// De aanroeper meldde dat zenden faalde; verder pollen heeft dan geen zin.
    Transmit,
    /// De server antwoordde DHCPNAK: het adres is niet meer van ons.
    Refused {
        /// De fase waarin de weigering kwam.
        state: State,
        /// Het adres dat we kwijt zijn.
        ip: Ipv4Addr,
    },
    /// De lease verliep zonder dat een server hem verlengde.
    Expired {
        /// Het adres dat we kwijt zijn.
        ip: Ipv4Addr,
    },
    /// Een server gaf bij het verlengen een ander adres; een draaiende node kan
    /// niet van adres wisselen.
    Moved {
        /// Het adres dat de node gebruikt.
        from: Ipv4Addr,
        /// Het adres dat de server nu aanbiedt.
        to: Ipv4Addr,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoLease {
                timeout,
                rx_errors: 0,
            } => write!(
                f,
                "dhcp: no lease within {} ms (no server answered)",
                timeout.as_millis()
            ),
            Self::NoLease { timeout, rx_errors } => write!(
                f,
                "dhcp: no lease within {} ms; {rx_errors} NIC receive errors",
                timeout.as_millis()
            ),
            Self::Transmit => f.write_str("dhcp: TX failed"),
            Self::Refused { state, ip } => write!(
                f,
                "dhcp {state}: server refused the lease (DHCPNAK); {ip} is no longer ours, \
                 a reboot acquires a new address HOPOS_DHCP_NAK"
            ),
            Self::Expired { ip } => write!(
                f,
                "dhcp: lease on {ip} EXPIRED and could not be rebound; \
                 the address is no longer ours HOPOS_DHCP_EXPIRED"
            ),
            Self::Moved { from, to } => write!(
                f,
                "dhcp: server offered {to} instead of {from}; a running node cannot change \
                 address, a reboot picks up the new one HOPOS_DHCP_MOVED"
            ),
        }
    }
}

impl core::error::Error for Error {}
