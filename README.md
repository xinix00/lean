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
| [`leannet`](leannet/) | TCP/IP for bare-metal Go — ethernet, ARP, IPv4, ICMP echo, UDP, TCP, and `net.Conn`/`Listener`/`PacketConn` on top. One memory knob, buffers that grow with use instead of with configuration |
| [`leancookie`](leancookie/) | A cookie jar (RFC 6265) on `net/url` and strings — domain, path, expiry and Secure, without dragging `net/http/cookiejar` (and with it 3.2 MB of `net/http`) into the image. Host-only by default, because a public-suffix list is not something a bare-metal image should carry |
| [`leanhttps`](leanhttps/) | **A composition:** `leanhttp` over `leantls`, and nothing else. Sets SNI per connection so it follows a redirect to another host. **2.01 MB** lighter than `net/http` + `crypto/tls` with a real chain, 3.12 MB with a pinned peer |
| [`leans3`](leans3/) | S3: SigV4 signing plus the object operations, including the streaming and the conditional (If-Match/ETag) ones. It exists because one stack already carried **two** hand-written SigV4 implementations, and the second one skipped URI escaping — so a key with a space in it signed a different string than the server read. Reads the listing itself instead of with `encoding/xml`: **84 KB** less in a kernel, and a truncated response is still an error |
| [`leanelf`](leanelf/) | ELF64 for a loader: the PT_LOAD segments, the bytes at a load address, and a handful of symbols by name — **162 KB** lighter than `debug/elf` in the HopOS kernel. That package can also read DWARF, so importing it links `debug/dwarf`, `compress/zlib` and `internal/zstd` to decompress debug sections a loader never looks at |
| [`leanrand`](leanrand/) | Random for a node: bytes, an id, a bounded number, jitter on a wait. One source (`crypto/rand`), no error return for an error that cannot happen, no `% n` bias, and no UUID — `github.com/google/uuid` cost a bare-metal kernel 3.8 KB *and* `database/sql/driver` (it implements `sql.Scanner`) for two calls of `uuid.New().String()` |
| [`leantls`](leantls/) | TLS 1.3 for a network you own — one version, one suite, and a peer you recognise by pinned Ed25519 key instead of by certificate chain — **1.57 MB** lighter than `crypto/tls`. With a real chain (`leantls/x509verify`) it is what finally makes `leanhttp` usable for https: that stack is **1.73 MB** lighter than `net/http` with `crypto/tls`. Refuses to connect without a trust model |

## The rule

A package belongs here when all three hold:

1. **It solves a measured problem.** Not "this could be lighter" but "this is
   2.9 MB lighter, here is the number and how it was measured". The package doc
   carries that evidence, so a reader in five years can check whether it still
   holds.
2. **It fails loudly.** What it cannot do, it refuses with a clear message. A
   package that avoids linking TLS and then quietly tries an https URL is worse
   than `net/http`, not lighter.
3. **It stands alone.** Standard library only. A building block that needs
   another building block is no longer a building block; it is a framework in
   the making.

What does not belong here: anything that only becomes useful once you take
three more along with it.

## The one exception: compositions

Some things are two blocks by nature. `https` is exactly `http` over `tls` —
there is no third thing to invent, and a package that "does https" without
importing a TLS implementation would have to carry its own copy of one. So there
is a second, narrower kind of package here: a **composition**, which may import
the blocks it joins and nothing else.

The point is not convenience, it is that the joint is where the mistakes live.
Sending SNI for the wrong host after a redirect, picking port 443 but verifying
nothing, forgetting to close the connection on a 3xx: every user of two blocks
writes that same glue, and every one of them can write it subtly wrong. A
composition writes it once, out in the open, with tests on it.

**lean + lean = leaner**, and that is meant literally: a composition makes the
*use* thinner without making the blocks thicker. Whoever imports `leanhttp`
still links no TLS. That is the property that keeps this from sliding into a
framework, and it is the first thing to check when adding one.

Four rules keep a composition honest:

1. **It only joins.** It adds no protocol, no format, no behaviour that is not
   already in its parts. If it has features of its own, it is a block — hold it
   to the three rules above instead.
2. **It stays smaller than its smallest part.** Glue that outgrows the thing it
   glues is not glue any more. This is a number you can check.
3. **One level deep.** A composition imports blocks, never other compositions.
   Otherwise the import graph becomes a tree, and a tree is a framework.
4. **The blocks stay usable alone.** If joining two blocks required changing one
   of them into something only the composition can use, the seam is wrong.
   (A block may grow a *general* seam for this — `leanhttp` takes any dialer,
   which is useful for a proxy or a test long before TLS enters the picture.)

`leans3` is the one package here that is neither: it has a protocol of its own
(SigV4 and the S3 object API), so it is a block, but it cannot be standard
library only — an S3 client needs an HTTP client, and reaching for `net/http`
would defeat the purpose. It imports `leanhttps`, which rule 3 forbids a
composition from doing, and the reason it is right here is the same reason
compositions exist: the alternative is to rewrite the joint `leanhttps` already
tests. The cost is stated in its package doc — someone who talks plain http to a
MinIO on a LAN still links the PKI chain, because the scheme choice is reachable
from every call and the linker cannot drop it.

`leantls` was written here rather than lifted from HopOS, because HopOS never had
it: that core still links `crypto/tls` for one https download. It exists because
the same measurement kept coming back — TLS/PKI is the second-largest block in a
bare-metal Go image after the network stack — and because almost all of that
weight buys one thing we do not need between our own machines: validating a
certificate from an arbitrary certificate authority. What it does need, a peer
you already know the key of, costs 0.82 MB instead of 2.40 MB.

Handling real certificate chains brings back crypto/x509 and the arithmetic it
needs, and on its own that is only 0.63 MB lighter than crypto/tls. The first
version of this note concluded from that number that the chain mode was not worth
having, which was the wrong baseline: nobody fetches a file with crypto/tls
alone, they use `net/http`. Measured as the stack it actually replaces, it is
1.73 MB — and `leanhttp` contributes 1.10 MB of that, which was unreachable for
https before, because it refuses an https URL without a dialer and the only
dialer available was crypto/tls. Two packages that each looked marginal are worth
almost 2 MB together. That is an argument for measuring the whole path rather
than the piece you happen to be working on.

The scope is the safety argument, not a limitation to work around. Version
downgrade, renegotiation, compression, CBC padding and RSA PKCS#1v1.5 are the
recurring holes in TLS implementations, and none of them exist in TLS 1.3 with a
single suite. Chain validation, the richest source of homegrown TLS bugs, is not
carefully implemented here — it is absent. What is left is a key schedule, a
record layer and a transcript, and all three are checked against known answers:
the schedule against the worked handshake in RFC 8448, the rest against
`crypto/tls` itself as the peer.

## Where these came from

`leanhttp` comes from HopOS (`metal/app/applib/apphttp`), written there because
an app image should not carry 2.9 MB of TLS for traffic that is plain http. The
measurements in the package doc are from that work and have not been redone;
they carry their date, so it is clear what was tested and when.

`leandhcp` comes from HopOS too (`metal/net/dhcp`), written there because a
freshly booted node needs a lease before it has a network stack to get one
with. It speaks raw ethernet frames through a two-method NIC contract, so any
driver fits. The DISCOVER/OFFER half was proven on hardware (Pi 5, 2026-07-10:
an OFFER from a FRITZ!Box through our own PCIe→RP1→GEM chain). Keeping the lease
alive is a second half that runs over the stack instead of the NIC, because
after bring-up the receive loop has exactly one owner.

The package documentation is in Dutch, as it was written.
