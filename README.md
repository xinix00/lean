# lean

Small Go packages that do what they say and link nothing you did not ask for.

They exist because the usual choice is top-heavy. `net/http` links crypto/tls
whether or not you ever open an https URL. An RTSP library drags a whole media
stack along when you wanted to forward one H.264 stream. That goes unnoticed in
a gigabyte container, but not in a binary running on a hub in a meter cupboard
— and least of all in the time you lose to someone else's assumptions.

Every package here stands on its own: its own files, its own tests, no
dependencies on each other, standard library only. Import one and you pay for
that one.

| | |
|---|---|
| [`leanhttp`](leanhttp/) | HTTP/1.1 without TLS — small client and server, chunked reading and writing |
| [`leandhcp`](leandhcp/) | DHCPv4 (RFC 2131) on raw ethernet frames — a lease before any netstack exists |

## The rule

A package belongs here when all three hold:

1. **It solves a measured problem.** Not "this could be lighter" but "this is
   2.9 MB lighter, here is the number and how it was measured". The package doc
   carries that evidence, so a reader in five years can check whether it still
   holds.
2. **It fails loudly.** What it cannot do, it refuses with a clear message. A
   package that avoids linking TLS and then quietly tries an https URL is worse
   than `net/http`, not lighter.
3. **It stands alone.** Standard library only. A lean package that needs
   another lean package is no longer a building block; it is a framework in
   the making.

What does not belong here: anything that only becomes useful once you take
three more along with it.

## Where these came from

`leanhttp` comes from HopOS (`metal/app/applib/apphttp`), written there because
an app image should not carry 2.9 MB of TLS for traffic that is plain http. The
measurements in the package doc are from that work and have not been redone;
they carry their date, so it is clear what was tested and when.

`leandhcp` comes from HopOS too (`metal/net/dhcp`), written there because a
freshly booted node needs a lease before it has a network stack to get one
with. It speaks raw ethernet frames through a two-method NIC contract, so any
driver fits. The DISCOVER/OFFER half was proven on hardware (Pi 5, 2026-07-10:
an OFFER from a FRITZ!Box through our own PCIe→RP1→GEM chain).

The package documentation is in Dutch, as it was written.
