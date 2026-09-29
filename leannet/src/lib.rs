//! TCP/IP voor bare metal: Ethernet, IPv4 ARP/ICMP/UDP/TCP, link-local
//! multicast, en één begrensd bufferbudget.
//!
//! leannet doet precies wat HopOS nodig heeft: een node bereikbaar maken
//! (agent-, leader- en consolelisteners), artefacten downloaden (uitgaand TCP
//! onder TLS), namen en tijd ophalen (UDP voor DNS en SNTP) en link-local
//! multicast voor mDNS. Al het andere is bewust afwezig, niet onaf; de grenzen
//! staan in `KAM.md` (de leannet-sectie) en het waarom in `OLD/leannet/DESIGN.md`.
//!
//! # Eén eigenaar, geen I/O
//!
//! [`Stack`] bezit alle verbindingen, de ARP-tabel, de pot, de wachtrijen en de
//! timers, en wordt door precies één taak gedreven. Hij doet zelf geen I/O en
//! kent geen klok: de eigenaar geeft frames en de tijd, en haalt frames op.
//!
//! ```
//! use leannet::{Config, Stack};
//!
//! let cfg = Config {
//!     ip: [10, 0, 0, 1],
//!     prefix: 24,
//!     mac: [2, 0, 0, 0, 0, 1],
//!     budget: 1 << 20,
//!     ..Config::default()
//! };
//! let mut stack = Stack::new(cfg, 0x1234_5678)?;
//! let mut frame = vec![0u8; stack.frame_len()];
//! let now = 1_000_000_000; // Monotone nanoseconden van de aanroeper.
//!
//! // De pomp: ontvangen frames erin, klare frames eruit, dan slapen.
//! // stack.receive(&rx_frame, now)?;
//! while let Some(n) = stack.poll_transmit(now, &mut frame) {
//!     let _wire = &frame[..n]; // Naar het device.
//! }
//! let _sleep_until = stack.next_timeout(now);
//! # Ok::<(), leannet::Error>(())
//! ```
//!
//! De eigenaar-taak draait die lus: [`Stack::receive`] voor elk binnenkomend
//! frame, [`Stack::poll_transmit`] tot `None`, en dan slapen tot
//! [`Stack::next_timeout`], een nieuw frame, of een wek van de waker die hij
//! met [`Stack::register_driver_waker`] registreerde (een write of close kan
//! uitgaand werk maken).
//!
//! # Tijd
//!
//! Alle tijd is monotone nanoseconden (`u64`) die de aanroeper levert, nooit
//! wandtijd: SNTP die de klok verzet mag geen hertransmissie meteen of nooit
//! laten vuren. Deadlines van sockets zijn absolute tijdstippen in dezelfde klok.
//!
//! # Sockets
//!
//! Sockets zijn handvatten: [`TcpHandle`], [`ListenHandle`], [`UdpHandle`].
//! Elke call is synchroon en blokkeert nooit; "nog niet" is
//! [`Error::WouldBlock`]. Wie wil wachten registreert een waker op het
//! handvat (`tcp_register_read_waker`, `tcp_register_write_waker`,
//! `listen_register_waker`, `udp_register_*`) en probeert opnieuw als hij
//! gewekt wordt; een kleine wrapper elders maakt daar een `Future` van. Dat
//! is de dichtste vorm bij de Go-semantiek (`net.Conn` met deadlines,
//! `Listener.Accept`, `PacketConn`) zonder een executor aan de stack te binden.
//!
//! ```
//! # use leannet::{Config, Stack, Error};
//! # let mut stack = Stack::new(Config { ip: [10,0,0,1], prefix: 24, budget: 1 << 20, ..Config::default() }, 1)?;
//! # let now = 0;
//! let l = stack.tcp_listen(80)?;
//! match stack.tcp_accept(l, now) {
//!     Ok(conn) => {
//!         let mut buf = [0u8; 512];
//!         match stack.tcp_read(conn, &mut buf, now) {
//!             Ok(0) => { /* EOF */ }
//!             Ok(n) => { stack.tcp_write(conn, &buf[..n], now)?; }
//!             Err(Error::WouldBlock) => { /* registreer een waker */ }
//!             Err(e) => return Err(e),
//!         }
//!         stack.tcp_close(conn, now)?;
//!     }
//!     Err(Error::WouldBlock) => { /* nog geen verbinding */ }
//!     Err(e) => return Err(e),
//! }
//! # Ok::<(), leannet::Error>(())
//! ```
//!
//! # Geheugen
//!
//! [`Config::budget`] is één gedeelde pot voor alle TCP-ringen en
//! UDP-wachtrijen; [`Config::max_buf_per_conn`] klemt één verbinding (nul is
//! `budget / 4`). Verbindingen beginnen met 16 KiB ontvangst en 4 KiB zenden
//! en groeien onder gemeten druk. Past een reservering niet, dan faalt de stack
//! luid (een fout of een RST), nooit met een stille wacht of een abort.
//! Allocatie is overal faalbaar; na opbouw en groei alloceert het hete pad niet.
//!
//! De vorige stack alloceerde naar configuratie in plaats van gebruik: 2 MiB
//! per listener vooraf en 256 KiB per dial. Op een 64 MiB HopOS-doel gaf dat
//! reproduceerbaar een OOM na 151 seconden downloadlast.
//!
//! # Niet in deze crate
//!
//! De opt-in IPv6-baan uit de Go-versie (UDP/ICMPv6/NDP/SLAAC) is niet geport;
//! een IPv6-frame is hier stille LAN-ruis. De TamaGo-`net.SocketFunc`-naad
//! bestaat niet in Rust; de handvat-API hierboven vervangt hem.

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

extern crate alloc;

mod arp;
mod error;
mod icmp;
mod multicast;
mod neighbor;
mod queue;
mod ring;
mod socket;
mod stack;
mod tcp;
mod udp;
mod waker;
pub mod wire;

#[cfg(test)]
mod testnet;
#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use socket::{Endpoint, UDP_MAX_PAYLOAD};
pub use stack::{
    Config, ETHERNET_HEADER_SIZE, ETHERNET_MAXIMUM_SIZE, ListenHandle, MTU, Stack, Stats,
    TcpHandle, UdpHandle,
};
pub use tcp::TcpState;

/// Eén milliseconde in nanoseconden.
pub const MS: u64 = 1_000_000;
/// Eén seconde in nanoseconden.
pub const SEC: u64 = 1_000_000_000;

/// De tellers van de ARP-machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArpStats {
    /// Queries opgegeven na vijf pogingen.
    pub gave_up: usize,
    /// Antwoorden die niet aan ons en niet gratuitous waren.
    pub ignored: usize,
    /// Verversingen die de MAC van een bestaande entry veranderden.
    pub mac_changed: usize,
    /// Antwoorden die vielen omdat hun rij vol was.
    pub reply_drop: usize,
    /// Passieve leerpogingen geweigerd op het plafond van 128.
    pub learn_drop: usize,
    /// Resoluties geblokkeerd door een tabel vol pending/statische entries.
    pub full_drop: usize,
}

/// Voegt `x` toe aan `v` met faalbare allocatie: een geweigerde allocatie is
/// een [`Error::OutOfMemory`], nooit een abort.
pub(crate) fn try_push<T>(v: &mut alloc::vec::Vec<T>, x: T) -> Result {
    v.try_reserve(1).map_err(|_| Error::OutOfMemory {
        bytes: core::mem::size_of::<T>(),
    })?;
    v.push(x);
    Ok(())
}
