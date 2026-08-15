# TODO — lean

Outstanding work by package. [README.md](README.md) defines the rule for new
packages; new features in existing packages follow the same rule: a measurement
must show that their absence has a cost.

## leannet — complete, but not tested on hardware

Built on 2026-08-11/12 to replace lneto+go-net in HopOS. See
[leannet/DESIGN.md](leannet/DESIGN.md) for the design, trade-offs, and deliberate
omissions.

Status: the full test suite, including `-race`, passes; the stack compiles with
the tamago toolchain for riscv64 and arm64. HopOS runs entirely on it in QEMU
(agent + leader, SNTP, DNS, a TLS download from GitHub, 20/20 slot-demo markers,
200 clean connection churn cycles, and 8 held connections plus a fresh one 200
times).

**Flaky test fixed on 2026-08-12.** `TestStackBudgetRecovery` failed once during
a full `-race` run (an assertion, not a data race). The server closed immediately
after Accept, so whether the slot was still occupied depended on TIME-WAIT
(~1 s) expiring before the second dial. The race detector made that timing more
likely. The server now holds the connection until the test releases it. Six
isolated `-race` runs and two full `-race` runs passed.

**Built after v0.2.0 (2026-08-12) — two gaps found by hardware:**

- [x] **Self-traffic (loopback).** A world could not reach itself. Dialing its
      own IP sent an ARP request for itself, but a switch floods to every port
      except the source, so five attempts ended in `no route to host`. On
      hardware, cloudflared used the slot IP as its own origin after a rolling
      update, hiding the cause five layers away. `routeLocked` now returns the
      local MAC for the local IP, `sendEthLocked` queues those frames for
      loopback, and the pump passes them through the normal ingress demux
      (`ingressLocked`). Covered for TCP and UDP by three regression tests.
- [x] **RST for a closed port** (RFC 9293 §3.10.7.1). Previously every dial to
      an unused port waited for its deadline instead of returning
      `connection refused`. An RST never elicits another RST; the storm case is
      tested.

**Built after v0.3.0 (2026-08-12):**

- [x] **Outbound broadcast.** Limited broadcast (`255.255.255.255`) used to go
      to the gateway as unicast, while subnet-directed broadcast entered ARP
      for an address no host owns. Both now use `ff:ff:ff:ff:ff:ff` without
      ARP. DHCP rebinding needs this path. Inbound broadcast remains disabled;
      DESIGN.md explains why.

**First, and the only material open question:**

- [ ] **Verify on hardware.** Test a LicheeRV Nano (RISC-V, 100 Mbit dwmac) and
      Radxa Zero 3E. The previous stack set the bar at RX ≥ 8.84 MB/s without
      drops and survival past 250 seconds. QEMU cannot answer this: slirp
      terminates TCP on the host, giving the guest microsecond RTTs and hiding
      real window and DMA-chain behavior.
- [ ] **Run a netmeter A/B** using the bench that judged the previous two stack
      changes (`hop-os/metal/cmd/netmeter`). Compare RX/TX ceilings,
      allocations per phase, and GC pressure with lneto.
- [ ] **Survive the OOM reproducer:** a 64 MB HOP window plus SSE load on
      `/v1/events`. Buffer preallocation killed the previous stack within 151 s;
      the budget model should remain stable. Then measure whether HopOS
      `cpu/memlimit` can move from its GOGC-25 workaround toward Go's ~10%
      guidance.

**Then, in order:**

- [ ] Profile throughput by layer on hardware: checksum, copies, and demux. The
      bench already has counters; leannet may add more if they stay off the data
      path.
- [ ] Measure warm-up on a real WAN path. Doubling whenever full costs
      `log2(cap/floor)` RTTs. If this measurably delays full throughput, refine
      it with gVisor's RTT estimator; both growth decisions already pass through
      `growRing`.
- [ ] Make the current 1 s `TIME-WAIT` constant configurable when an environment
      requires it. A four-minute 2MSL does not fit an embedded node, but 1 s is
      still an unmeasured choice.
- [x] `Stats()` returns a struct copy while holding the stack lock, avoiding
      racy reads of exported counters.

**Deliberately absent** (see DESIGN.md): congestion control, out-of-order
reassembly/SACK, IPv6/NDP, IPv4 fragmentation, TCP timestamps/PAWS, Nagle,
SYN cookies, stack logging, and a second global buffer pool.

## leanhttp — extended on 2026-08-12 for browser basics

The question was whether the browser basics belong here, so the next caller
does not have to import net/http and pay 3.2 MB. They do, and adding them exposed
a real bug.

- [x] **`Call.DialContext`** — one general, cancellable dialer seam for proxies,
      Unix sockets, test doubles, and TLS. This keeps TLS out of the package;
      callers such as leanhttps compose the two.
- [x] **Keep-alive client** — one pool per host. A connection returns to the
      pool only after its body is read to EOF; otherwise the next request would
      parse the previous response tail as its status line. Tests cover ten
      requests over one connection and partial bodies without desynchronizing.
- [x] **Transparent gzip** — callers control `Accept-Encoding` (default:
      `identity`), and `Response.Encoding` reports the result. `compress/gzip`
      stays outside; callers can wrap `Body` themselves.
- [x] **Unfolded `Response.SetCookie` — bug fix.** Repeated headers normally
      fold into a comma-separated list (RFC 9110 §5.3), but Set-Cookie is the
      exception because cookie values and Expires dates can contain commas. It
      is now preserved one value per field line.
- [x] **`GetCall`** — Get plus the remaining `Call` controls: headers, deadline,
      and `DialContext`, matching what `Do` already provided.
- [x] **Bodyless 204/304 client handling.** An S3 DELETE and a hoplockserver
      DELETE exposed clients waiting on a keep-alive connection for a body that
      cannot arrive. `leanhttp` handles both centrally; 304 retains an optional
      informational Content-Length.

## leans3 (new on 2026-08-12)

Moved from hoplock/s3 because one stack contained two custom SigV4
implementations: complete `hoplock/s3/sigv4.go` and GET-only,
non-URI-escaping `hop/internal/runner/download_s3.go`. The signer already ran
against AWS, R2, MinIO, and Hetzner/Ceph RGW; this is its first standalone home.

- [ ] **Remove hop's second signer.** `internal/runner/download_s3.go` can use
      `leans3` or only its signer. That removes the weaker copy: keys containing
      spaces or `+` sign incorrectly, it lacks session tokens, and it only
      supports virtual-hosted addressing. Identified, not implemented.
- [ ] **Repeat the measurement in a tamago image.** The same signed HTTPS GET
      shrank from 5.68 to 3.95 MB on darwin/arm64 with `-ldflags=-w`. The
      expected hardware saving is the same 1.73 MB measured for x509verify on
      riscv64, but linking a board-specific image is required to prove it.
- [ ] **Exercise this form against real hardware and a provider.** hoplock/s3
      and HopOS build on it and host tests pass, but neither has been done since
      the move.
- [x] **Removed `encoding/xml`** (2026-08-12). LIST responses need only three
      fields, while that decoder added 39,256 bytes of symbols and 85,681 image
      bytes to an arm64 kernel. `listparse.go` makes one pass, matches local
      element name and position (`Contents/Key`, not `CommonPrefixes/Key`), and
      supports the five named entities plus numeric entities. Tests compare it
      with `encoding/xml`, including every truncation point in a real MinIO
      response so an incomplete page can never look complete.

**Deliberately absent:** streaming signatures
(`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), multipart upload, presigned URLs,
SigV4a, IMDS/IAM credentials, HEAD, and CopyObject. `Client.URLFor` is the seam
for callers that need another operation without reimplementing addressing.

## leanelf (new on 2026-08-12)

Built because `hop-os/metal/abi/place` was the kernel's only `debug/elf`
importer, pulling in `debug/dwarf`, `internal/zstd`, and `compress/zlib` for
compressed debug sections a loader never reads. The package docs record a
166,397-byte image reduction with identical placement.

- [x] Cross-checked against `debug/elf`: tests build ELF64 files and require
      identical segment, symbol, and machine results for valid inputs.
- [x] `Lookup` replaces a complete symbol dump. `place` seeks five names in an
      app image containing tens of thousands, so no unrequested name string is
      allocated.
- [ ] **Test on hardware.** The QEMU gate places images with it (passing
      `abi/place` host tests and booting the kernel), but no real board has yet.

**Deliberately absent:** 32-bit, big-endian, sections by name, relocations,
DWARF, and a complete symbol dump. These fail loudly. Add one only with a
measurement showing that its absence costs something.

## leanrand (new on 2026-08-12)

Replaces `github.com/google/uuid` in hop. Two calls to `uuid.New().String()`,
one truncated to eight characters, cost 3.8 KB of symbols and pulled
`database/sql/driver` into the kernel because UUID implements `sql.Scanner`.

- [x] `N` uses rejection sampling instead of `%`, avoiding bias even for bounds
      just above 2⁶³; the full range is tested.
- [x] `Read` has no error result. `crypto/rand.Read` can no longer fail per its
      own documentation, so every `if err != nil` is an untested branch. This
      package panics because a node without entropy cannot continue safely.
- [x] `Jitter` avoids hop's exact 1, 2, 4, 8 second restart schedule, which made
      a hundred nodes retry together.

**Deliberately absent:** a custom generator, seeding, a reproducible production
stream (tests should provide their own), and UUID formatting—36 characters for
16 bytes whose structure we never inspect.

## leancookie (new on 2026-08-12)

No open items. **Deliberately absent:** a public suffix list (hundreds of KB and
updated monthly, so host-only is the default with an `AllowDomain` hook),
SameSite (browser navigation policy, not jar policy), and the `__Host-` and
`__Secure-` prefixes.

## leanhttps (new on 2026-08-12, the first composition)

No open items. Measured at 3.75 MB versus 5.77 MB for
net/http+crypto/tls+CA bundle, and 2.65 MB with a pinned peer.

**Deliberately absent:** a server. This composition is client-only; serving
HTTPS requires leantls's server half and is outside the current KAM.

## leandhcp — both items completed on 2026-08-12, now tested

The package previously had no tests. It now has 30 tests, 95% coverage, and a
clean `-race` run. The complete DORA handshake and lease lifecycle run against
a fake NIC and socket in microseconds rather than hours.

- [x] **Separate `StateRenewing` and `StateRebinding`.** `KeepAlive` previously
      tried six unicast renewals 30 seconds apart, unrelated to the lease. When
      the lessor disappears, those cannot succeed even if another server on the
      segment would extend the lease. The client now requests and reads option
      59 (T2); `Lease.timers` returns T1, T2, and expiry with RFC ratios
      0.5/0.875 when the server sends invalid values. Attempts halve the
      remaining time with a 60 s floor (§4.4.5), stop exactly at the phase
      boundary, and switch to broadcast at T2. Expiry fails loudly with
      `HOPOS_DHCP_EXPIRED`.
- [x] **Final-tick gap (lneto finding #16).** `await` checked the clock before
      reading, discarding a response already in the ring when the window closed.
      In the worst case, the server had assigned the IP to this MAC while the
      node reported `no server answered` and booted offline. The clock is now
      checked only while the bounded ring is empty. REQUEST also gets a minimum
      window because it binds state whereas DISCOVER does not. Two tests fail
      reliably against the old code.
- [x] Also fixed: DHCPNAK was ignored; it now returns `errRefused` and stops with
      `HOPOS_DHCP_NAK`. A sparse ACK could reset `LeaseSecs` to zero and silently
      disable maintenance; `merge` now preserves timers too.
- [ ] A rebind answered by another server may assign another address, which the
      fixed-IP stack cannot apply. It now reports `HOPOS_DHCP_MOVED` and stops,
      leaving recovery to reboot. Live stack reconfiguration belongs in hopnet,
      not leandhcp.
- [ ] We do not receive servers that broadcast rebind replies because leannet
      ignores inbound IP broadcasts (see leannet/DESIGN.md). RFC-compliant
      servers need not do this while the broadcast flag is clear. Fix only when
      a real router requires it.

## Repository-wide

- [ ] **KAM compliance: do not normalize Mux patterns.** Request paths with
      duplicate slashes are rejected, but registration still silently folds
      `/a//b` into `/a/b`. Make non-canonical patterns fail fast and add a
      registration test; wiring also needs one spelling per path.
- [ ] **KAM compliance: reject client `CONNECT` loudly.** The server already
      rejects CONNECT, but the client serializer accepts any valid method token
      without exposing a tunnel API. Add an explicit rejection and regression
      test before the next tag; silently sending origin-form CONNECT is not a
      supported middle ground.
- [ ] **KAM release gate: surfserve `/stream`.** An endpoint that claims
      `Request.Done` must first require its exact method and reject or drain a
      non-empty request body. `serveStream` currently claims `Done`
      unconditionally, allowing a body-bearing request to reach leanhttp's
      fail-fast check. Test `GET /stream` with a non-empty Content-Length (4xx,
      server remains usable) and a bodyless non-GET (405). See
      [KAM.md](KAM.md#consumer-obligations).
- [ ] **KAM release gate: make versions standalone.** Tag lean first, then
      update and verify hoplock, hoplockserver, Hop, surfserve, and metal in
      dependency order. Every local-path `replace`, relative or absolute, is
      development wiring only. Use the pinned Go 1.26.4 toolchain; consumer CI
      must not remain on Go 1.24.

- [x] This repository is tagged through v0.6.0.
- [ ] **Next tag:** only after the two KAM release gates above. Then update and
      test consumers standalone in dependency order; temporary workspace and
      `replace` wiring is not evidence.
