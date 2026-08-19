// Package leannet is a small IP stack for bare-metal Go (TamaGo). Its always-on
// lane provides Ethernet, IPv4 ARP and routing, ICMP echo, UDP, TCP, and joined
// link-local multicast. An IPv6 lane is created only when the caller opens an
// AF_INET6 UDP socket, calls [Stack.ListenUDP6] or [Stack.DialUDP6], or calls
// [Stack.JoinGroup6]; a stack that never uses IPv6 has no IPv6 neighbor, route,
// address, or timer state.
//
// The IPv6 lane is deliberately UDP-only. It provides unicast ICMPv6 echo and
// the bounded NDP control needed for RS/RA and NS/NA, an EUI-64 link-local address,
// the first SLAAC address from an autonomous /64, capped PIO/RIO route state,
// and explicitly joined ff02::/16 multicast. IPv4 and IPv6 UDP ports are
// separate. IPv6 sockets are v6-only and wildcard-bound, report "[::]:port" as
// their local bind, and select the link-local or SLAAC wire source from the
// destination. A write that needs an RA before one has arrived fails with an
// explicit no-route error so the caller can retry. Unspecified, loopback,
// multicast-source, and IPv4-mapped application traffic is rejected; a valid
// unspecified-source neighbor solicitation for passive DAD is the sole
// unspecified-source exception.
//
// IPv6 output is capped at its 1280-byte minimum MTU, leaving at most 1232 bytes
// for a UDP payload. TCPv6, DHCPv6, IPv4-mapped dual-family sockets, extension
// headers, fragmentation, PMTUD, MLD, wider multicast, full NUD, active DAD,
// ICMPv6 redirect/error state, multiple or temporary addresses, and automatic
// renumbering are outside the profile and fail rather than being half-supported.
//
// The socket layer supplies net.Conn, net.Listener, and net.PacketConn to
// net.SocketFunc for the supported combinations. The package uses only the
// standard library.
//
// The previous stack allocated by configuration rather than use: 2 MiB per
// listener up front and 256 KiB per outgoing dial. On a 64 MiB HopOS target this
// reproducibly caused an OOM after 151 seconds of download load. It also failed
// to retransmit a lost FIN, allowing eight wedged closes to permanently fill an
// eight-slot listener.
//
// leannet instead uses Config.Budget as one shared pool. MaxBufPerConn caps one
// TCP connection's share. Connections start with 16 KiB receive and 4 KiB
// transmit buffers and grow under measured pressure, capped by Budget/4 by
// default and by available capacity. UDP receive queues reserve from the same
// pool. If a required reservation does not fit, the stack fails loudly.
//
// Retransmission operates on sequence space, so SYN and FIN participate. All
// timer contracts use a monotonic clock. V1 drops out-of-order data and sends an
// immediate duplicate ACK so the peer can fast-retransmit.
//
// The rationale is in the [design document]. The frozen cross-package scope and
// release gates are in the [KAM].
//
// [design document]: https://github.com/xinix00/lean/blob/main/leannet/DESIGN.md
// [KAM]: https://github.com/xinix00/lean/blob/main/KAM.md
package leannet
