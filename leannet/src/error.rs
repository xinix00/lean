//! De foutsoort van leannet: één kleine `enum` die in `Display` de getallen
//! meegeeft (adres, poort, maat).
//!
//! Deze module bezit alleen de vorm van een fout. Wanneer een fout ontstaat,
//! staat bij de laag die hem geeft; tellers voor stille drops staan in
//! [`crate::Stats`], want een stack die per frame praat is een kapotte stack
//! (DESIGN.md: één print per frame doodde op 11-08 een LicheeRV binnen 250 s).

use core::fmt;

/// Alles wat leannet kan weigeren of melden.
///
/// De teksten volgen de Go-versie woord voor woord waar die er een had, zodat
/// logregels en operatorkennis de taalwissel overleven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Een ongeldig of niet-ondersteund IPv6-pakket/adres.
    #[cfg(feature = "ipv6")]
    InvalidIpv6,
    /// Geen bruikbare bron of route naar de IPv6-bestemming.
    #[cfg(feature = "ipv6")]
    NoRoute6,
    /// De IPv6-buur gaf geen antwoord binnen vijf pogingen.
    #[cfg(feature = "ipv6")]
    Unreachable6,

    /// Een frame of header is korter dan zijn vaste deel of zijn lengteveld.
    ShortFrame {
        /// Aanwezige bytes.
        len: usize,
        /// Minimaal benodigde bytes.
        need: usize,
    },
    /// Versie of IHL zegt dat dit geen IPv4-header is.
    NotIpv4,
    /// IPv4-opties zijn buiten het profiel (KAM: MURDER).
    Ipv4Options {
        /// De IHL uit de header, in 32-bitwoorden.
        ihl: u8,
    },
    /// Gefragmenteerd IPv4 is buiten het profiel (KAM: MURDER).
    Fragmented,
    /// Geen Ethernet/IPv4-ARP-pakket.
    NotArp4,
    /// De TCP data-offset valt buiten het segment.
    BadTcpOffset {
        /// De offset in bytes.
        offset: usize,
    },
    /// Nog niet klaar: registreer een waker en probeer het opnieuw.
    WouldBlock,
    /// De deadline van een dial is verstreken ([`crate::Stack::tcp_poll_connect`]).
    DeadlineExceeded,
    /// Het handvat is gesloten of bestaat niet meer.
    Closed,
    /// De stack is gesloten.
    StackClosed,
    /// De peer stuurde een reset; dat is nooit een net einde (EOF).
    Reset,
    /// De verbinding is gesloten of half-gesloten voor schrijven.
    TcpClosed,
    /// De verbinding sluit al.
    TcpClosing,
    /// De peer weigerde de verbinding met een RST.
    Refused {
        /// Adres van de peer.
        ip: [u8; 4],
        /// Poort van de peer.
        port: u16,
    },
    /// De handshake kreeg na alle pogingen geen antwoord.
    ConnectTimeout {
        /// Adres van de peer.
        ip: [u8; 4],
        /// Poort van de peer.
        port: u16,
    },
    /// ARP gaf op voor de next hop.
    Unreachable {
        /// De next hop waarvoor ARP opgaf.
        hop: [u8; 4],
    },
    /// Buiten het subnet en geen gateway geconfigureerd.
    NoRoute {
        /// De bestemming.
        ip: [u8; 4],
    },
    /// Het bufferbudget kan deze reservering niet dragen.
    NoBudget {
        /// Gevraagde bytes.
        need: usize,
        /// Vrije bytes in de pot.
        free: usize,
    },
    /// Alle efemere poorten zijn bezet.
    PortsInUse,
    /// Deze TCP-poort heeft al een listener of verbinding.
    TcpPortInUse {
        /// De poort.
        port: u16,
    },
    /// Deze UDP-poort is al gebonden.
    UdpPortInUse {
        /// De poort.
        port: u16,
    },
    /// Poort nul is geen geldige bestemming of binding.
    InvalidPort,
    /// Een UDP-wachtrij moet een positieve capaciteit hebben.
    UdpQueueCap,
    /// TCP naar een multicastadres bestaat niet.
    MulticastTcp {
        /// De bestemming.
        ip: [u8; 4],
    },
    /// Alleen link-local multicast (224.0.0.0/24) is toegestaan.
    NotLinkLocalMulticast {
        /// Het geweigerde adres.
        ip: [u8; 4],
    },
    /// Het plafond voor multicastgroepen is bereikt.
    GroupsFull {
        /// Het plafond.
        cap: usize,
    },
    /// Een UDP-datagram past niet in één frame.
    DatagramTooLarge {
        /// Lengte van het datagram.
        len: usize,
        /// Maximum.
        max: usize,
    },
    /// Een seed buiten het subnet zou nooit geraadpleegd worden.
    SeedOffSubnet {
        /// Het geweigerde adres.
        ip: [u8; 4],
    },
    /// Te veel statische buren.
    SeedCap {
        /// Het plafond.
        cap: usize,
    },
    /// De buurtabel zit vol met lopende queries.
    NeighborTableFull {
        /// Het adres dat geen plek kreeg.
        ip: [u8; 4],
    },
    /// Een prefixlengte buiten 0..=32.
    InvalidPrefix {
        /// De geweigerde lengte.
        prefix: u8,
    },
    /// De loopback-wachtrij is vol; het frame ligt nergens.
    LoopbackFull,
    /// De uitgaande wachtrij is vol.
    QueueFull,
    /// De allocator weigerde; het budget is dan niet aangetast.
    OutOfMemory {
        /// Gevraagde bytes.
        bytes: usize,
    },
}

/// Het resultaat van elke faalbare leannet-operatie.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Schrijft een IPv4-adres als vier decimale octetten.
struct Ip([u8; 4]);

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv6")]
            Self::InvalidIpv6 => write!(f, "invalid or unsupported IPv6 packet/address"),
            #[cfg(feature = "ipv6")]
            Self::NoRoute6 => write!(f, "no IPv6 route or source address"),
            #[cfg(feature = "ipv6")]
            Self::Unreachable6 => write!(f, "IPv6 neighbor did not answer"),
            Error::ShortFrame { len, need } => {
                write!(f, "leannet: frame too short ({len} < {need} bytes)")
            }
            Error::NotIpv4 => f.write_str("leannet: not an IPv4 header (version/IHL)"),
            Error::Ipv4Options { ihl } => {
                write!(f, "leannet: IPv4 options unsupported (IHL {ihl})")
            }
            Error::Fragmented => f.write_str("leannet: fragmented IPv4 unsupported"),
            Error::NotArp4 => f.write_str("leannet: not an ethernet/IPv4 ARP packet"),
            Error::BadTcpOffset { offset } => {
                write!(f, "leannet: TCP data offset out of range ({offset} bytes)")
            }
            Error::WouldBlock => f.write_str("leannet: operation would block"),
            Error::DeadlineExceeded => f.write_str("leannet: i/o deadline exceeded"),
            Error::Closed => f.write_str("leannet: use of closed network connection"),
            Error::StackClosed => f.write_str("leannet: stack closed"),
            Error::Reset => f.write_str("leannet: connection reset by peer"),
            Error::TcpClosed => f.write_str("leannet: connection closed"),
            Error::TcpClosing => f.write_str("leannet: connection already closing"),
            Error::Refused { ip, port } => {
                write!(f, "leannet: connection refused ({}:{port})", Ip(ip))
            }
            Error::ConnectTimeout { ip, port } => write!(
                f,
                "leannet: connect timed out, no response ({}:{port})",
                Ip(ip)
            ),
            Error::Unreachable { hop } => {
                write!(f, "leannet: no route to host (arp gave up for {})", Ip(hop))
            }
            Error::NoRoute { ip } => write!(
                f,
                "leannet: no route to host ({} off-subnet and no gateway configured)",
                Ip(ip)
            ),
            Error::NoBudget { need, free } => write!(
                f,
                "leannet: connection refused, buffer budget exhausted (need {need}, free {free})"
            ),
            Error::PortsInUse => f.write_str("leannet: no free ephemeral port"),
            Error::TcpPortInUse { port } => write!(f, "leannet: tcp port {port} in use"),
            Error::UdpPortInUse { port } => write!(f, "leannet: udp port {port} in use"),
            Error::InvalidPort => f.write_str("leannet: port must be nonzero"),
            Error::UdpQueueCap => f.write_str("leannet: udp queue capacity must be positive"),
            Error::MulticastTcp { ip } => {
                write!(f, "leannet: tcp to a multicast address ({})", Ip(ip))
            }
            Error::NotLinkLocalMulticast { ip } => write!(
                f,
                "leannet: only link-local multicast (224.0.0.0/24), not {}",
                Ip(ip)
            ),
            Error::GroupsFull { cap } => {
                write!(f, "leannet: multicast group cap reached ({cap})")
            }
            Error::DatagramTooLarge { len, max } => {
                write!(f, "leannet: udp datagram exceeds mtu ({len} > {max} bytes)")
            }
            Error::SeedOffSubnet { ip } => write!(
                f,
                "leannet: seed {} outside subnet would never be consulted",
                Ip(ip)
            ),
            Error::SeedCap { cap } => {
                write!(f, "leannet: too many static neighbor seeds (cap is {cap})")
            }
            Error::NeighborTableFull { ip } => write!(
                f,
                "leannet: neighbor table is full of pending queries; cannot seed {}",
                Ip(ip)
            ),
            Error::InvalidPrefix { prefix } => {
                write!(f, "leannet: prefix /{prefix} must be in 0..=32")
            }
            Error::LoopbackFull => f.write_str("leannet: loopback queue full"),
            Error::QueueFull => f.write_str("leannet: transmit queue full"),
            Error::OutOfMemory { bytes } => {
                write!(f, "leannet: allocation of {bytes} bytes refused")
            }
        }
    }
}

impl core::error::Error for Error {}
