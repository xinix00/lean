# leannet — why it exists and why it is this small

This document answers the question someone will ask next year: *why is there no
SACK, reassembly, or IPv6, and may I add it?* The answer is almost always “only
with a measurement,” for the reasons below.

## The idea in one paragraph

leannet is a TCP/IP stack for bare-metal Go that does exactly what HopOS needs:
make a node reachable (agent, leader, and console listeners), download artifacts
(outbound TCP over TLS), and retrieve names and time (UDP for DNS and SNTP).
Everything else is deliberately absent, not merely unfinished. Memory comes
from one operator-configured pool and scales with *use*, not configuration.

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
| **IPv6 / NDP** | No HopOS environment requires it; internal networks are IPv4 (`10.100.0.0/24`) and the LAN side uses DHCPv4. lneto's NDP duplicated its ARP race for no use. | When a deployment requires it. This is a new demux branch plus a neighbor table, not a rewrite. |
| **IPv4 fragmentation and options** | Both fail with their own error and counter. Our paths use DF and MTU 1500; options do not occur. Silent acceptance would hide them from metrics. | Only when a measured path sends them. Reassembly brings its full attack surface. |
| **TCP timestamps / PAWS** | Needed only to prevent sequence wrap within one RTT (sustained >1 Gbit/s) or for finer RTT measurement. Karn's algorithm is enough for our RTO. | At multi-gigabit throughput per connection. |
| **Nagle** | Disabled. Embedded traffic is small and latency-sensitive; coalescing would add unrequested delay. | Never by default; perhaps as a socket option. |
| **SYN cookies** | Five handshake RTOs, per-connection floors, and the global budget make floods bounded without cookie machinery: an embryo costs a few KiB and dies in about six seconds. | When a public node demonstrably receives SYN floods. |
| **Urgent pointer or PSH API semantics** | Nothing uses them; data carries `PSH`, which is otherwise ignored. | Never. |
| **Inbound IP broadcast** | Outbound limited and subnet broadcast has used `ff:ff:ff:ff:ff:ff` without ARP since August 12 because DHCP rebinding needs it. Inbound remains closed: the UDP checksum covers the destination IP, so accepting broadcast requires carrying the actual `dst` through the entire demux. The only current consumer, a rebind ACK, returns unicast to `ciaddr` because we leave the broadcast flag clear. | When a protocol requires a response not addressed to our IP, such as mDNS or NetBIOS. Carry `dst` through `recvIPv4` and `ChecksumOK`, then wake only bound ports. |
| **A logging framework in the stack** | The stack counts (`CntDropBadFrame`, `CntRefusedNoBudget`, ARP counters) instead of logging. The HopOS console busy-waits per byte; one print per frame killed a LicheeRV within 250 seconds on August 11. A speaking data path is a broken data path. | Never in the data path. Reading counters is always fine. |
| **A second global buffer control** | Splitting inbound/outbound or kernel/app uses the wrong axis: bulk and control exist in both directions. The relevant axis is per socket, which only the socket knows. | Never. See the budget model below. |

## What is included, and why

**One control: `Config.Budget`.** Give the stack 2 MB on a small board or 40 MB
on a server and let it divide the pool. Nothing is preallocated: listeners and
dials initially cost nothing extra. Each connection starts at a floor and
doubles under *measured pressure*: RX when the peer fills it, TX when a `Write`
fills it while the peer offers more window than the ring. Growth is capped at
`Budget/4` per connection and by available pool space; close returns everything.

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

**All time is monotonic and injected.** The `tcp` and `arp` state machines take
`now int64` and own no clock. The stack uses `time.Since(start)`, never
`time.Now().UnixNano()`, which jumps when SNTP adjusts time and could fire an
RTO immediately or never. Injection also makes every failure deterministic in
tests without sleeps.

**The stack neither logs nor decides policy.** Refusal is loud—RST plus a
counter—for exhausted budget, full backlog, or abandoned ARP. Silent retention
is the worst state: on August 11, eight abandoned browser connections left a
listener permanently deaf and killed the console.

**The pump sleeps until the earliest deadline.** There is no fixed tick. An
idle stack has no wake time and consumes no CPU, a hard requirement for nodes
that put their core to sleep (`metal/cpu/idle`). A regression test protects it.

**One mutex protects all state-machine data.** This is not claimed to be the
fastest choice. It avoids “which lock owns this cache entry?” bugs such as
lneto's `CacheRemove` race beside an unused locked wrapper. If it ever contends,
a second buffer is the escape hatch, not a finer lock.

## Code structure

Five layers, bottom to top, each in one file:

1. `frame.go` — in-place wire-format views. No allocations; every `Parse*`
   rejects malformed input loudly.
2. `budget.go` + `ring.go` — the pool and rings. `txRing` anchors the send ring
   in sequence space (head = `snd.UNA`, cursor = bytes sent).
3. `tcp.go`, `arp.go`, `udp.go`, `icmp.go` — pure state machines: no goroutines,
   clocks, or I/O. They consume and produce segments.
4. `stack.go` — the only layer with locks and a goroutine: demux, routing, the
   TX pump, and port tables.
5. `socket.go` — the boundary to Go's `net` package (`net.SocketFunc` on tamago).

This separation enables direct tests of FIN behavior, sequence wrap, and
RFC 5961 on the state machine without a wire, clock, or goroutine.

## Evidence

- About 80 tests, 91% statement coverage, and a clean `-race` run. All 29 lneto
  review findings are accounted for by tests or an explanation of why their
  failure mode cannot exist here; hop-os `TODO.md` has the coverage table.
- gVisor classics: sequence wraparound (bulk plus close across 2³²), blind-RST
  challenge ACK, mid-connection SYN, window shrink, duplicate data, and tiny
  MSS.
- A garbage-input test feeds every layer bad checksums, truncated headers, and
  a zero-length option: everything is counted and dropped, with no panic or
  connection.
- In QEMU it carries the full HopOS chain: agent + leader, SNTP, DNS, TLS to
  GitHub, and all 20 slot-demo markers.

## Rule for additions

This package belongs in `lean` because it meets the repository's three rules:
it solves a measured problem documented with number and date, fails loudly,
and stands alone on the standard library. Hold every extension to those rules
and this one:

> Add a feature when a measurement shows that its absence has a cost—not
> because another stack has it.
