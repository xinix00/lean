# leannet — why it exists and why it is this small

This document answers the question someone will ask next year: *why is there no
SACK, reassembly, TCPv6, or full dual stack, and may I add it?* The answer is
almost always “only with a measurement,” for the reasons below.

## The idea in one paragraph

leannet is a TCP/IP stack for bare-metal Go that does exactly what HopOS needs:
make a node reachable (agent, leader, and console listeners), download artifacts
(outbound TCP over TLS), retrieve names and time (UDP for DNS and SNTP), and
carry Matter discovery and UDP traffic over IPv6. IPv6 is an opt-in lane, not a
second general-purpose stack. Everything else is deliberately absent, not
merely unfinished. Buffer memory comes from one operator-configured pool and
scales with *use*, not configuration.

## Why not an existing stack

We ran two, then left both for reasons visible in code:

**gVisor** (until 2026-08-09) worked, but added about 90,000 linked lines,
2.7 MB to every app image, 340,000 allocations per 64 MiB on the RX path, and a
goroutine handoff per segment. That matters on a 64 MB node.

**lneto + go-net** (2026-08-09 through 12) was much smaller and fast (RX rose
from 26 to 61 MB/s on the bench), but we consumed about 13,000 lines through
**two forks** with custom tags, and the hard part was incomplete. A review on
August 11 found 29 issues (`~/Git/lneto/BEVINDINGEN.md`): a lost bare FIN was
never retransmitted, leaking a pool slot; an RTO in FIN-WAIT-1 removed FIN from
accounting; LAST-ACK aborted on every ACK; and retransmission used wall time
while NTP adjusted the stack's clock. Four findings were in our own PR branches:
we already shared the complexity without merge rights.

The deciding factor was not merely broken code, but the **repair path**. A fix
reached our nodes only through PR diplomacy or fork maintenance (`replace`
affects only the main module, so apps silently built against unpatched upstream).
For the subset we actually use, owning the implementation costs less.

## What is deliberately absent

Each row is a decision, not a gap. Adding one requires a measurement proving it
is needed.

| Absent | Why | When to add it |
|---|---|---|
| **Congestion control (cwnd, slow start)** | Senders such as GitHub and Bunny limit our downloads; our uploads are heartbeats and API responses. We have no path that fills a congested link. | When a node sends large uploads over a congested WAN. The send loop already caps on `sndWnd`; cwnd would be a second cap. |
| **Out-of-order reassembly (SACK, reorder buffer)** | An out-of-order segment is dropped with an immediate duplicate ACK, and the peer recovers through fast retransmit. This is RFC-compliant and removes the half of the state machine where lneto's bugs lived. | When hardware measurements show that reordering, rather than loss, costs throughput. Reordering is rare on our LANs and single-gateway paths. |
| **General-purpose IPv6** | The measured path needs UDP, link-scoped discovery, and a ULA behind a Thread border router—not a second TCP stack or every IPv6 control plane. The implemented lane therefore stops at ICMPv6/NDP, one SLAAC identity, and bounded PIO/RIO routing. | Extend only for a measured consumer. TCPv6, DHCPv6, IPv4-mapped dual-family sockets, extension headers, fragmentation, PMTUD, MLD, wider multicast, full NUD, active DAD, ICMPv6 redirect/error state, privacy addresses, multiple SLAAC identities, and automatic renumbering are separate features, not implied follow-ups. |
| **IPv4 fragmentation and options** | Both fail with their own error and counter. Our paths use DF and MTU 1500; options do not occur. Silent acceptance would hide them from metrics. | Only when a measured path sends them. Reassembly brings its full attack surface. |
| **TCP timestamps / PAWS** | Needed only to prevent sequence wrap within one RTT (sustained >1 Gbit/s) or for finer RTT measurement. Karn's algorithm is enough for our RTO. | At multi-gigabit throughput per connection. |
| **Nagle** | Disabled. Embedded traffic is small and latency-sensitive; coalescing would add unrequested delay. | Never by default; perhaps as a socket option. |
| **SYN cookies** | Five handshake RTOs, per-connection floors, and the global budget make floods bounded without cookie machinery: an embryo costs a few KiB and dies in about six seconds. | When a public node demonstrably receives SYN floods. |
| **Urgent pointer or PSH API semantics** | Nothing uses them; data carries `PSH`, which is otherwise ignored. | Never. |
| **Inbound IP broadcast** | Outbound limited and subnet broadcast has used `ff:ff:ff:ff:ff:ff` without ARP since August 12 because DHCP rebinding needs it. Inbound remains closed: the UDP checksum covers the destination IP, so accepting broadcast requires carrying the actual `dst` through the entire demux. The only current consumer, a rebind ACK, returns unicast to `ciaddr` because we leave the broadcast flag clear. | Partially arrived August 15: link-local multicast (multicast.go) carries `dst` through `recvIPv4`/`ChecksumOK` for joined groups — exactly the mDNS case. Inbound IP *broadcast* remains closed until a consumer exists. |
| **A logging framework in the stack** | The stack counts (`CntDropBadFrame`, `CntRefusedNoBudget`, ARP counters) instead of logging. The HopOS console busy-waits per byte; one print per frame killed a LicheeRV within 250 seconds on August 11. A speaking data path is a broken data path. | Never in the data path. Reading counters is always fine. |
| **A second global buffer control** | Splitting inbound/outbound or kernel/app uses the wrong axis: bulk and control exist in both directions. The relevant axis is per socket, which only the socket knows. | Never. See the budget model below. |

## What is included, and why

**One shared pool, with an optional per-connection cap.** `Config.Budget` is the
hard shared reservation pool for TCP rings and UDP receive queues;
`Config.MaxBufPerConn` limits how much one TCP connection may grow (zero means
`Budget/4`). A listener does not reserve a connection's rings in advance. An
accepted or dialed TCP connection starts at a floor and doubles under *measured
pressure*: RX when the peer fills it, TX when a `Write` fills it while the peer
offers more window than the ring. Growth remains bounded by both controls and
available pool space. UDP binds reserve a bounded receive queue from that same
pool.

Socket close returns unread RX and UDP reservations immediately. TCP TX remains
reserved until FIN is acknowledged or the connection is reaped, because those
bytes can still be retransmitted. Refusing a reservation is preferable to
quietly exceeding the configured budget.

**IPv6 is a lazy, narrow lane.** The first IPv6 UDP socket or `JoinGroup6`
creates its address, NDP, route, multicast, and UDP state and starts bounded
router solicitation. Until then an IPv4-only stack has no IPv6 timers or tables.
The lane carries UDP plus only the ICMPv6 needed for unicast echo, RS/RA, and
NS/NA. IPv4 and IPv6 have separate UDP port spaces; IPv6 sockets are v6-only
and wildcard-bound. Their local bind is `[::]:port`, while source selection
happens per datagram: link-local for link-local or `ff02::/16`, and SLAAC for
routed traffic.

The address model is intentionally finite: one EUI-64 link-local address and
the first SLAAC address from an autonomous `/64`. Router advertisements can
install capped on-link PIO prefixes, capped RIO routes, and one default router;
the longest matching RIO wins and a newer advertisement for the same prefix
replaces its next hop. Explicit PIO/RIO withdrawals remove routing state, but a
PIO withdrawal does not silently replace the selected SLAAC identity.
Wall-clock lifetimes, route preference, and automatic renumbering do not run in
the stack; that identity lasts until restart. Before a usable RA, an off-link
write returns no-route immediately and may be retried on the same socket.

Application multicast is explicit and link-scoped. `JoinGroup6` accepts only
`ff02::/16`, keeps a capped membership for the stack lifetime, and does not
pretend that opening UDP port 5353 joined mDNS. All-nodes and the solicited-node
groups for the owned addresses are implicit. Ingress admits only the stack's
unicast MAC or the exact `33:33` mapping of one of those implicit or joined
groups. Unspecified, loopback, multicast-source, and IPv4-mapped application
traffic is rejected; a valid unspecified-source NS for passive DAD is the one
exception. IPv6 output is capped at the 1280-byte minimum MTU, so a UDP payload
is at most 1232 bytes; extension headers, fragmentation, and PMTUD cannot blur
that boundary.

Supported NS, NA, and RA are deliberately stricter than RFC 4861: every
SLLA/TLLA must exactly match the Ethernet source MAC. A mismatch is rejected
before state mutation. This fail-closed home/Matter-link rule intentionally
excludes proxy-ND and VRRP-style virtual-router MAC indirection.

The asymmetric floors—16 KiB RX and 4 KiB TX—are the only values not derived
from pressure. The peer controls RX rate and starts with an initial congestion
window of ten segments (RFC 6928). Advertising less prevents that burst, while
a fast reader keeps the ring from filling and therefore from growing. Our
window would remain the bottleneck. TX has no such problem because the
application supplies pressure. gVisor uses the same RX floor for this reason;
we need the floor, not its RTT estimator. This was found while reviewing the
benchmark before the first hardware test.

The mechanism is intentionally coarser than gVisor's estimator, which sizes RX
by bytes consumed per RTT. It takes `log2(cap/floor)` RTTs to warm up—
unmeasurable on LAN, about 300 ms on a 25 ms path—but its signal is **reality**
(ring full, window offered), not a prediction that can drift. “Simply good” is
enough here; gVisor is 300 times larger.

The measured problem: the previous stack reserved 2 MB per listener plus
256 KiB per outbound dial through one `TCPBufferSize` setting. Under download
load, a 64 MB HOP window reproducibly ran out of memory within 151 seconds.

**Retransmission operates on sequence space, not “data.”** SYN and FIN consume
sequence numbers and follow the normal go-back-N path. An RTO rewinds `nxt` to
`una`; the send loop regenerates whatever follows—data, data+FIN, or bare FIN.
No separate flag queue can become empty while its segment vanished on the wire.
Three severe lneto findings lived in this class, so this is a design choice, not
a patch: `tcp.go`'s `txRing` makes retransmission a reread of the same ring.

**All time is monotonic and injected.** The TCP, ARP, and NDP state machines
take `now int64` and own no wall clock. The stack uses `time.Since(start)`, never
`time.Now().UnixNano()`, which jumps when SNTP adjusts time and could fire a
retry immediately or never. Injection also makes failure paths deterministic
in tests without protocol sleeps.

**The stack neither logs nor decides policy.** Refusal is loud—an error or RST
plus a counter—for exhausted budget, full backlog, or abandoned ARP/NDP. Silent
retention is the worst state: on August 11, eight abandoned browser connections
left a listener permanently deaf and killed the console.

**The pump sleeps until the earliest deadline.** There is no fixed tick. An
idle stack has no wake time and consumes no CPU, a hard requirement for nodes
that put their core to sleep (`metal/cpu/idle`). A regression test protects it.

**One mutex protects all state-machine data.** This is not claimed to be the
fastest choice. It avoids “which lock owns this cache entry?” bugs such as
lneto's `CacheRemove` race beside an unused locked wrapper. If it ever contends,
a second buffer is the escape hatch, not a finer lock.

## Code structure

The files follow ownership boundaries rather than promising one file per layer:

1. `frame.go` and `frame6.go` provide allocation-free in-place wire-format
   views and checksums. Every `Parse*` rejects malformed or unsupported input.
2. `budget.go` and `ring.go` own reservations and TCP rings. `txRing` anchors
   the send ring in sequence space (head = `snd.UNA`, cursor = bytes sent).
3. `tcp.go`, `udp.go`, and `icmp.go` contain the bounded transport machines;
   `neighbor.go` owns the one lifecycle shared by the wire-specific `arp.go`
   and `ndp.go`; `multicast.go` and `ipv6.go` contain the corresponding
   family-specific membership, address, and route policy.
4. `stack.go` owns the mutex, ingress demux, loopback, and the single transmit
   pump that drives TCP, ARP, NDP, and connectionless replies.
5. `socket.go` is the boundary to Go's `net` package (`net.SocketFunc` on
   TamaGo) and keeps the IPv4 and IPv6 UDP families separate.

This separation enables direct tests of FIN behavior, sequence wrap, and
RFC 5961 on the state machine without a wire, clock, or goroutine.

## Evidence

- The release gate runs regular tests, the race detector, and vet. All 29 lneto
  review findings are accounted for by a regression or an explanation of why
  their failure mode cannot exist here.
- gVisor classics: sequence wraparound (bulk plus close across 2³²), blind-RST
  challenge ACK, mid-connection SYN, window shrink, duplicate data, and tiny
  MSS.
- A garbage-input test feeds every layer bad checksums, truncated headers, and
  a zero-length option: everything is counted and dropped, with no panic or
  connection.
- In-memory IPv6 regressions exercise lazy enablement through link-local UDP,
  joined multicast and loopback, RA-to-SLAAC/RIO source selection, fail-fast
  writes before RA, NDP validation, and the TamaGo socket boundary. The
  [KAM](../KAM.md) names the wider source and hardware evidence required before
  release.
- In QEMU it carries the full HopOS chain: agent + leader, SNTP, DNS, TLS to
  GitHub, and the slot demo. The separate hardware gate in the KAM is required
  before external IPv6 routing or multicast is called released.

## Rule for additions

This package belongs in `lean` because it meets the repository's three rules:
it solves a measured problem documented with number and date, fails loudly,
and stands alone on the standard library. Hold every extension to those rules
and this one:

> Add a feature when a measurement shows that its absence has a cost—not
> because another stack has it.
