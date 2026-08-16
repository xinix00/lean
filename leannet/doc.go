// Package leannet is a small TCP/IP stack for bare-metal Go (TamaGo): Ethernet,
// ARP, IPv4, ICMP echo, UDP, TCP, and link-local IPv4 multicast (mDNS), plus
// a socket layer that supplies
// net.Conn, net.Listener, and net.PacketConn to net.SocketFunc. It uses only the
// standard library.
//
// The previous stack allocated by configuration rather than use: 2 MiB per
// listener up front and 256 KiB per outgoing dial. On a 64 MiB HopOS target this
// reproducibly caused an OOM after 151 seconds of download load. It also failed
// to retransmit a lost FIN, allowing eight wedged closes to permanently fill an
// eight-slot listener.
//
// leannet instead uses one total pool, Config.Budget. MaxBufPerConn only caps one
// connection's share. Connections start with 16 KiB receive and 4 KiB transmit
// buffers and grow under measured pressure, capped by Budget/4 by default and
// by available capacity. If even the floor does not fit, the stack fails loudly.
//
// Retransmission operates on sequence space, so SYN and FIN participate. All
// timer contracts use a monotonic clock. V1 drops out-of-order data and sends an
// immediate duplicate ACK so the peer can fast-retransmit.
//
// The rationale is in the [design document]. The frozen cross-package scope and
// release gate are in the [KAM].
//
// [design document]: https://github.com/xinix00/lean/blob/main/leannet/DESIGN.md
// [KAM]: https://github.com/xinix00/lean/blob/main/KAM.md
package leannet
