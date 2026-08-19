# KAM — the frozen HTTP/IP profile

This document fixes the scope of `leanhttp`, `leanhttps`, `leans3`, and
`leannet`. It is not a list of everything HTTP and the underlying IP transports
can do. It defines what this repository **promises to do correctly**,
deliberately narrows, and loudly rejects.

KAM has three outcomes:

- **KEEP** — required by a measured consumer. This behavior is contractual; a
  defect blocks release.
- **ADAPT** — the need is real, but the boundary may be smaller than the general
  standard if it remains explicit and safe.
- **MURDER** — no measured consumer. Remove the feature and its state space;
  reject dependent input loudly where possible.

Lean means less surface area, not less correctness. Framing, deadlines,
ownership, security, and resource release remain complete inside the supported
profile. Behavior outside it is neither an implicit compatibility promise nor
a TODO. It returns only after a measurement shows that its absence has a cost.

This file is normative for scope. `README.md` and package docs summarize it,
`leannet/DESIGN.md` explains the transport choices, and `TODO.md` records the
backlog, evidence, and history. `TODO.md` cannot silently extend the KAM; a
contradiction between these documents is a documentation bug.

## Deployment profile

The stack supports this concrete chain:

- a plain HTTP/1.1 server for local APIs, files, redirects, browser streams, and
  raw protocol takeover;
- an HTTP client for API calls and artifact downloads, optionally through
  `leanhttps`, with sequential keep-alive per connection;
- a SigV4 S3 client for the object operations Hop and HopOS actually use;
- an IPv4/TCP/UDP stack plus an opt-in IPv6 lane with UDP as its only
  application transport for bare-metal nodes, with one bounded buffer pool.

“Multiple things over one channel” means **sequential requests and responses
over a keep-alive connection**. Speculative HTTP pipelining and multiplexing are
not contractual.

## Decision matrix

| Area | KEEP | ADAPT | MURDER |
|---|---|---|---|
| HTTP server | HTTP/1.1, sequential keep-alive, fixed and streamed responses, `HEAD`, `204`/`205`/`304`, `Done`, `Hijack` | origin-form only, known-length request bodies, WebSocket through raw takeover | HTTP/1.0/2, CONNECT, request chunking/trailers, server-side Expect state machine, general 1xx state machine |
| Mux | method+path, exact/subtree, `{segment}`, `{rest...}`, `GET`→`HEAD`, `404`/`405`+`Allow` | canonical paths or rejection; immutable after start | host routing, `{$}`, escaped/dot routing, slash normalization, net/http compatibility work |
| HTTP client | outbound HTTP/1.1, inbound 1.0/1.1, GET/HEAD redirects, response framing, deadlines, keep-alive pool | fixed-length streaming upload with a strict Expect decision; compression pass-through | request chunking, automatic decompression, CONNECT/upgrade, general retry state machine |
| TLS/S3 | explicit trust model, SNI per connection, SigV4 and used object operations | TLS as a dialer composition; signed S3 calls never follow redirects | TLS server, silent skip-verify, multipart, streaming SigV4, SigV4a, presigned URLs, IMDS/IAM |
| leannet | Ethernet; IPv4 ARP/ICMP/UDP/TCP and link-local multicast; opt-in IPv6 UDP, ICMPv6/NDP, link-scoped multicast, one SLAAC identity, and PIO/RIO routing; deadlines, close, bounded memory | one IPv4 identity; one derived link-local plus one SLAAC IPv6 identity; bounded simplified NDP and route state; fixed 1280-byte IPv6 packet ceiling | TCPv6, DHCPv6, extension headers, fragmentation, PMTUD, MLD/IGMP, wider multicast, dual-family sockets, full NUD and renumbering, congestion control, timestamps, Nagle, SYN cookies, data-path logging |

The table is a summary; the boundaries below are normative.

## leanhttp server and Mux

### KEEP

The server MUST:

- pass only a syntactically unambiguous HTTP/1.1 request to a handler;
- limit each header line to 8 KiB and all request headers to 64 KiB;
- require exactly one non-empty `Host` and accept only origin-form targets;
- process requests sequentially per connection while both sides permit
  keep-alive;
- accept a request body only with exactly one valid `Content-Length`, up to
  1 MiB; a short body returns `io.ErrUnexpectedEOF`, never success;
- drain an unread request body within bounds before reuse and, while the
  transport remains healthy, before a clean close;
- keep response framing unambiguous: known `Content-Length` or writer-owned
  chunked framing, never both;
- buffer a response of unknown length up to 64 KiB, then switch automatically
  to chunked framing;
- send no body bytes for `HEAD`, `204`, `205`, or `304`, and frame `205`
  explicitly with `Content-Length: 0`;
- support handler statuses `200`–`599`; redirects and error statuses remain the
  web server's decision;
- survive temporary accept errors with bounded backoff and apply the documented
  deadlines to request parsing, request-body reads, and response writes.

`Flush` is the streaming-response seam. Without a known length, the writer
chooses chunked framing. `Hijack` is the protocol-takeover seam: the hijacker
writes the `101` handshake and then owns bytes, framing, and lifecycle.
Leanhttp implements neither the WebSocket handshake nor WebSocket frames.

`Request.Done` is the disconnect seam for a long-lived HTTP stream. Calling it
transfers ownership of the read side. If the request body is incomplete, the
server first attempts a bounded drain; one watcher then consumes remaining
input until disconnect. This keeps a valid client-controlled body from causing
an ownership panic. Three strict rules apply:

1. a handler that needs body content reads it before `Done`;
2. after `Done`, the handler never reads `Request.Body`, and it claims `Done`
   before the first response header reaches the wire;
3. `Done` and `Hijack` are mutually exclusive.

Only the last two boundaries MAY panic fail-fast: the handler controls them
entirely. `Serve` deliberately does not recover handler panics, so programmer
errors can terminate the process. Consumers may wrap handlers in an explicit
recovery policy, but that does not make ownership optional.

The server assumes every `net.Conn` from the listener implements deadlines.
Deadline-setter errors are not converted into separate HTTP responses. The
`Done` watcher intentionally reads without a deadline until disconnect; after
`Hijack`, the new owner manages all deadlines.

The Mux supports only:

- an exact path, optionally prefixed by a method;
- a trailing-slash subtree pattern;
- `{name}` for one segment and `{name...}` for the remainder;
- a `GET` route serving `HEAD`, unless an explicit `HEAD` route wins;
- the most specific route under a strict subset relation;
- `404` when no path matches and `405` plus `Allow` when only the method differs.

The route table is immutable after serving starts. Registration errors panic
before serving; per-request synchronization for dynamic registration is outside
this profile.

Route patterns must also be canonical. Registration of a pattern containing
duplicate slashes, dot segments, or similar ambiguity panics before serving;
the Mux never normalizes a pattern into another route meaning.

### ADAPT

Path interpretation has exactly one form. A request path starts with `/`, has no
empty inner segments, and contains neither `.` nor `..`. Percent escapes that
decode into a separator or dot segment are ambiguous and rejected. The parser
returns `400`; a non-canonical `Request.Path` built manually or by middleware
does not match in the Mux and returns `404`.

Registration and dispatch deliberately perform no normalization or automatic
slash redirect. One input never receives one meaning from middleware and a
different meaning from the router.

### MURDER

The server explicitly rejects:

- HTTP/1.0 and other versions (`505`);
- `CONNECT` (`501`);
- absolute-, authority-, and asterisk-form request targets (`400`);
- request `Transfer-Encoding`, including chunked (`501`);
- duplicate framing or `Transfer-Encoding` with `Content-Length` (`400`);
- a non-empty `Expect` (`417`);
- request bodies larger than 1 MiB (`413`).

`WriteHeader` does not accept 1xx. `101` is available only through `Hijack`.
`205` remains its own final status, is always bodyless, and receives
`Content-Length: 0`; the writer never silently changes it into another status.

The Mux has no host routing, `{$}`, escaped routing, path cleaning, automatic
slash redirects, or complete `net/http.ServeMux` algebra.

## leanhttp client

### KEEP

The client MUST:

- write HTTP/1.1 requests and understand HTTP/1.0 and HTTP/1.1 responses;
- limit each response/status line to 8 KiB and all interim plus final headers
  together to 64 KiB;
- return every final status from `Do`, while `Get` requires exactly `200` and a
  known `Content-Length`;
- bound bodies using `Content-Length`, chunked framing, or EOF, treating `HEAD`,
  `204`, `205`, and `304` as proven bodyless;
- report a truncated fixed-length body as an error;
- enforce `Timeout` as one absolute deadline across dial, redirects, headers,
  and body; `HeaderTimeout` applies only to response headers and decisions;
- return only a proven fully read response to the pool;
- bound idle connections both per host and globally, and close them by time;
- retry one fresh connection after a stale keep-alive failure, only for
  replay-safe `GET`/`HEAD` before a usable response;
- automatically follow only `301`, `302`, `303`, `307`, and `308`, only for
  bodyless `GET`/`HEAD`, and for at most ten hops;
- strip all caller headers on a cross-origin redirect and reject HTTPS→HTTP
  downgrade.

Package-level calls do not pool: every redirect hop gets a separate connection
with `Connection: close`. `Client` is the explicit keep-alive form.

### ADAPT

A small body is `[]byte`. A large upload uses `BodyReader` with exact `BodyLen`;
request chunking does not exist. Such a stream is not replayable and therefore
sends `Expect: 100-continue` first.

Within one absolute decision deadline, the server MUST send a complete `100` or
a final response header. Silence, a partial decision, or only other interim
responses until the deadline is an error and closes the connection. There is no
“send after one second anyway” fallback. After `100`, the upload clears the
header deadline and applies a configured `HeaderTimeout` anew to the final
response. If both `HeaderTimeout` and `Timeout` are zero, that final response—
like a regular call—deliberately has no deadline.

Compression is pass-through. The default is `identity`; a caller that sets
`Accept-Encoding` reads `Response.Encoding` and performs decompression itself.

### MURDER and accepted boundary

The client has no request chunking, automatic decompression, protocol upgrade,
or general retry for mutating requests. A `101` is an error. `CONNECT` is
rejected before dial and serialization; the client exposes no tunnel seam.
Caller headers may not duplicate package-owned `Host`, framing, `Connection`,
or `Expect`. `Accept-Encoding` is the explicit pass-through exception.

Chunked responses accept only bare hexadecimal sizes. Even syntactically valid
chunk extensions fail closed because no measured consumer justifies a complete,
quote-aware extension parser. Trailers are bounded and validated for grammar
and forbidden fields, but their values are not exposed.

The keep-alive pool deliberately has no permanent read loop per idle connection.
Its contract therefore assumes a protocol-correct origin that does not inject
unsolicited response bytes while idle. Already buffered bytes are detected and
the connection is closed; defending against bytes arriving just after that
check requires a permanent reader owner and lies outside scope. The stale retry
protects against a closed idle connection, not a syntactically valid forged
response.

## leanhttps and leans3

### leanhttps

`leanhttps` only composes `leanhttp` and `leantls`:

- an explicit trust model—pinned peer key or certificate verification—is
  mandatory;
- SNI comes from the current dial address for each connection, so an allowed
  redirect to another host verifies the right name;
- caller configuration is never mutated;
- TLS keep-alive uses `leanhttp.Client` with `leanhttps.DialerContext(...)`.

A nil config and certificate validation against a bare IP address fail loudly.
`ServerName` is package-owned and must be empty in caller configuration:
`Client` rejects a preset value, while standalone `DialerContext` safely
overwrites it in a configuration copy with the current dial host. `leanhttps`
has no server side and adds no HTTP or TLS protocol.

### leans3

`leans3` provides SigV4 with static credentials and an optional session token,
virtual-hosted and path-style addressing, plus the object operations in use:
`Get`, `GetTo`, `Put`, `PutFrom`, conditional PUT/DELETE, ETag, and paginated
`ListObjectsV2`.

These invariants apply:

- every PUT has a known length and payload hash;
- `UnsignedPayload` is allowed only for an HTTPS endpoint; replacing the
  default transport with `Client.DialContext` transfers responsibility for
  authenticated encryption and peer validation to the caller;
- a signed request never follows redirects because origin, target, and headers
  are part of the signature;
- expected 404/409/412 bodies and other error bodies are read within bounds, so
  an ordinary miss or CAS race does not unnecessarily destroy the TLS pool;
- large objects use `GetTo`/`PutFrom` and need not be buffered in full.

There is no streaming SigV4, multipart, SigV4a, presigned URLs, IMDS/IAM
credentials, HEAD/CopyObject, versioning, object lock, tagging, or S3-level
retry. GET/LIST may use leanhttp's single generic stale-keep-alive retry before
a response; mutating S3 operations are never repeated. Add an operation only
when a real consumer needs it.

An S3 context is checked before the call, and its deadline becomes the total
HTTP deadline. Bare cancellation without a deadline does not interrupt a call
already in progress; supporting that requires first measuring and designing a
general cancellable `leanhttp.Call` seam.

Each LIST page is limited to 4 MiB. `List(max <= 0)` deliberately collects all
keys from all pages into one slice and may grow with the object count; callers
on small nodes should pass a positive `max`.

## leannet

### KEEP

`leannet` provides Ethernet; IPv4 ARP, ICMP echo, UDP, TCP, and link-local
multicast for one IPv4 identity; plus an opt-in IPv6 UDP/ICMPv6 lane. It
implements `net.Conn`, `net.Listener`, `net.PacketConn`, and the Tamago socket
seam only for the combinations named below.

IPv4 multicast MUST:

- accept joins for 224.0.0.0/24 only (RFC 5771 link-local — the block routers
  never forward), idempotent, capped (`maxGroups`), for the stack's lifetime
  (no Leave: the only consumer never leaves), released on `Close`;
- deliver a joined group's UDP datagrams and ignore other multicast silently
  — normal LAN noise, not a drop statistic;
- map groups per RFC 1112 §6.4 (01:00:5e plus the low 23 bits), never ARP and
  never route via the gateway — the scope is this link;
- send with TTL 255 (safe precisely because the block is unroutable; RFC 6762
  §11) and loop a joined sender's own datagrams back to its local listeners,
  while still transmitting them to the wire;
- refuse what multicast can never be: TCP dials to 224.0.0.0/4, UDP sends to
  multicast outside the link-local block (routable scope, RFC 2365), and any
  packet whose SOURCE is multicast (silently, RFC 1112 §7.2);
- carry UDP only: no ICMP echo replies to multicast (RFC 1122 §3.2.2.6).
  IGMP is omitted: home switches flood link-local multicast, and a snooping
  switch that requires membership reports is out of scope. The device below
  must already pass multicast frames; NIC filters are not this stack's
  concern.

The IPv6 lane exists for one concrete path: Matter discovery and UDP traffic
to a device ULA behind a Thread border router. It remains absent until the
first IPv6 UDP socket or `JoinGroup6`; a v4-only stack pays no IPv6 state or
timers.

The IPv6 lane MUST:

- provide UDP through `AF_INET6`, `ListenUDP6`, and `DialUDP6`; sockets are
  wildcard-bound and v6-only, so a non-wildcard local address and an
  IPv4-mapped address fail loudly, while TCPv6 remains unsupported;
- own one EUI-64 link-local address and at most the first SLAAC address from an
  autonomous `/64`; use a link-local source only for link-local unicast and
  `ff02::/16`, and require the SLAAC source for every routed packet;
- implement only the ICMPv6 control needed by this path: bounded RS/RA and
  NS/NA plus unicast echo; validate every invariant of those supported forms
  before rejected input can mutate state;
- retain bounded on-link PIO prefixes and bounded RIO routes, prefer the
  longest RIO match, replace the next hop for a repeated prefix, remove an
  explicitly withdrawn PIO or RIO, and use one advertised default router only
  as a last resort;
- accept explicit joins only for `ff02::/16`, with capped, stack-lifetime
  membership and local-loop behavior; all-nodes and the stack's
  solicited-node groups are implicit;
- require a nonzero UDP checksum and emit no IPv6 packet larger than the
  IPv6-minimum MTU of 1280 bytes; without fragmentation or PMTUD, an emitted
  UDPv6 payload is therefore at most 1232 bytes;
- reject unspecified, loopback, multicast-source, and IPv4-mapped application
  traffic at the applicable public or ingress boundary; the one unspecified
  source exception is a valid passive-DAD NS, and the stack's own link-local or
  SLAAC address is the only supported local loopback destination;
- fail immediately when no usable source or route exists, fail after bounded
  NDP resolution when a neighbor is unreachable, and wake blocked operations
  on resolution, failure, deadline, or close;
- accept only unicast frames addressed to this interface's MAC and multicast
  frames addressed to the exact `33:33` mapping of an implicit or joined IPv6
  group.

The transport core MUST:

- keep all TCP rings and UDP queue reservations within `Config.Budget`;
- start each TCP connection with 16 KiB RX and 4 KiB TX, grow under measured
  pressure, shrink unused excess while idle, and return remaining budget on
  close or reap;
- account SYN, data, and FIN in one sequence space and retransmit after loss;
- validate cumulative ACKs against bytes actually sent, including during a
  retransmission rewind;
- return reset as an error, not EOF;
- drive blocked I/O through wakeups and deadlines and unblock it on `Close`;
- use monotonic time exclusively for protocol timers;
- perform ARP and NDP abandonment in the pump, fail loudly, and wake all
  waiters;
- turn exhausted budgets, full backlogs, and unreachable routes into explicit
  errors or RSTs, never silent permanent waits.

Socket `Close` returns unread RX budget immediately. TX budget returns when FIN
is acknowledged or the connection is reaped. The deliberately short close
bounds—20 seconds in FIN-WAIT-2 and 1 second in TIME-WAIT—are resource policy
for these nodes, not general Internet defaults.

### ADAPT

Out-of-order TCP data is dropped with an immediate duplicate ACK; the peer
recovers through retransmission. This is the chosen small loss state machine,
not half a SACK implementation.

IPv6 is not a general dual-stack implementation. NDP uses the same bounded,
ARP-like resolution and aging model instead of the complete Neighbor
Unreachability Detection state machine. The first autonomous `/64` remains
selected for the stack lifetime; SLAAC renumbering requires a restart. PIO and
RIO wall-clock expiry and route-preference machinery are absent, but an
explicit zero-lifetime PIO or RIO withdrawal takes effect and a newer RIO for
the same prefix replaces its next hop. A write before the first usable RA
receives an explicit no-route error rather than implicitly waiting for
configuration. Withdrawing a PIO removes its on-link classification but does
not silently replace the selected SLAAC identity.

The socket seam is equally narrow: IPv4 and IPv6 have separate UDP port spaces
and no dual-family socket. IPv6 binds are wildcard-only, report `[::]:port` as
their local bind, and choose a wire source per destination; pretending to honor
a specific local address is forbidden.

### MURDER

Absent: congestion control, out-of-order reassembly/SACK, TCPv6, DHCPv6,
IPv4-mapped dual-family sockets, active DAD, privacy or temporary addresses,
multiple SLAAC identities, full NUD and automatic renumbering, MLD/IGMP,
multicast outside link scope, ICMPv6 redirects and error/PMTUD state, IPv4 and
IPv6 fragmentation, IPv4 options, IPv6 extension headers and jumbograms, TCP
timestamps/PAWS, Nagle, SYN cookies, urgent-data API, inbound IP broadcast,
and data-path logging. [`leannet/DESIGN.md`](leannet/DESIGN.md) explains why
and when a feature may return.

## Consumer obligations

The core stays small only if consumers do not rebuild each seam halfway:

- a streaming handler reads needed request-body content before `Done`.
  Otherwise `Done` transfers the unread body to the bounded server drain. The
  handler never touches `Request.Body` afterward. The hard boundary is before
  response headers reach the wire, so the simple rule is to claim it before
  `WriteHeader`, `Write`, or `Flush`;
- a hijacker uses neither `Done` nor the regular `ResponseWriter`;
- a caller that wants connection reuse reads a response to its proven end and
  always closes it;
- a signed protocol does not follow generic redirects, but validates and signs
  each hop itself; `leans3` therefore chooses `NoFollow`;
- a custom `DialContext` honors context cancellation/deadlines and returns a
  connection with working deadlines;
- a custom S3 dialer for HTTPS preserves authenticated encryption and peer
  validation, especially with `UnsignedPayload`;
- IPv6 slot traffic is native layer-2/routed traffic, not IPv4 NAT. `leannet`
  is not a firewall: the switch or application owns exposure policy for every
  bound UDPv6 port;
- a consumer explicitly joins every application multicast group; opening an
  IPv6 UDP socket does not by itself join `ff02::fb` or another application
  group;
- the `Device` below an IPv6-enabled stack passes the stack's unicast MAC and
  relevant `33:33` multicast frames. A consumer that depends on promiscuous or
  all-multicast NIC mode proves that mode on each supported driver;
- an off-link caller treats no-route before the first usable RA as an explicit,
  retryable result rather than an implicit configuration wait;
- consumers build standalone against a published Lean version. A local
  workspace or filesystem `replace` is development tooling, not release proof.

## Release gate

A profile change may land only when all relevant gates pass.

### Repository

```sh
git diff --check
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Prefer regressions at the layer that owns the invariant: parsing, framing, and
lifecycle in `leanhttp`; the pure TCP/ARP/NDP state machines in `leannet`;
composition errors in `leanhttps` or `leans3`.

An IPv6 profile change additionally proves lazy enablement, v4/v6 port
isolation, the mandatory UDP checksum, the 1280/1232-byte transmit boundary,
exact Ethernet destination filtering, malformed NDP with zero state mutation,
NDP give-up/deadline/close wakeups, and RA source selection plus
PIO/RIO/default-route precedence, replacement, and explicit withdrawal.

### Consumer source gate

Before tagging, connect the measured chain to candidate source in one local
workspace. Local `replace` directives are allowed because this is source
integration, not release proof. The gate includes:

- regular tests, race tests, and `go vet` for Hop, hoplock, and hoplockserver;
- a Tamago compile check of Hop's alternative HTTP files:
  `go test -run '^$' -tags tamago ./pkg/hophttp`;
- regular tests, race tests, and `go vet` for HopOS `metal/net/hopswitch`
  against the candidate Lean when IPv6 routing or multicast changes; these
  prove that direct synthetic slot-MAC delivery accepts IPv6 only and cannot
  bypass the IPv4 NAT/publication boundary;
- a TamaGo test compile of `metal/app/applib/appnet` against the candidate Lean,
  including its native `ff02::fb` join regression. The package imports the
  TamaGo runtime and therefore cannot honestly count as a host-executed test;
  family dispatch and `JoinGroup6` behavior execute in Lean's host suite;
- regular tests, race tests, and `go vet` for surfserve against local Lean;
- exactly two surfserve regressions: `GET /stream` with a non-empty
  `Content-Length` returns 4xx and leaves the server usable; a bodyless non-GET
  on `/stream` returns `405`.

In the existing sibling workspace, the first three lines are:

```sh
go test -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go test -race -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go vet ./hop/... ../hoplock/... ./hoplockserver/...
go -C hop test -run '^$' -tags tamago ./pkg/hophttp
```

Surfserve is absent from the regular development workspace. Connect the
candidate in a temporary, uncommitted `go.work` containing only the Lean and
hop-os-surf worktrees, then use that `GOWORK` for host tests of
`./stack/surfserve`. The official surfserve build script sets `GOWORK=off`, so
it proves a candidate tag only after publication.

```sh
LEAN_CANDIDATE=/path/to/lean
SURF_CANDIDATE=/path/to/hop-os-surf
KAM_WORKDIR="$(mktemp -d)"
go -C "$KAM_WORKDIR" work init "$LEAN_CANDIDATE" "$SURF_CANDIDATE"
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" test -count=1 ./stack/surfserve
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" test -race -count=1 ./stack/surfserve
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" vet ./stack/surfserve
```

The temporary directory stays outside every repository and is removed after
the gate.

`go test ./...` is not a valid hop-os-surf host gate because the metal commands
are Tamago-only. Test only the relevant host packages in this pre-tag gate.

### Consumer release gate

After tagging and updating dependencies, run Hop, hoplock, and hoplockserver
again outside the local workspace:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go list -m all
```

For surfserve, replace `./...` with its host gate on `./stack/surfserve` plus
the official `tools/test.sh`. That script covers the Tamago builds, while the
remaining metal commands cannot use the host toolchain. Hop still requires the
explicit `-tags tamago` compile of `./pkg/hophttp`.

```sh
GOWORK=off go test -count=1 ./stack/surfserve
GOWORK=off go test -race -count=1 ./stack/surfserve
GOWORK=off go vet ./stack/surfserve
GOWORK=off ./tools/test.sh
```

Provide the pinned Tamago toolchain to `tools/test.sh` through its existing
`TAMAGO` configuration.

Every module list MUST show the new tags and MUST NOT contain a `replace` to a
local filesystem path, whether relative or absolute. Run this gate from a clean
checkout of the commits being published; `GOWORK=off` does not disable a
`replace` in `go.mod`.

The gate uses one explicitly pinned toolchain: Go 1.26.4 for this KAM. Consumer
CI MUST NOT rely on an older `setup-go` version or count an incidental automatic
toolchain download as proof. Upgrade the toolchain together with this rule and
the CI configuration.

Before tagging, no publishable `go.mod` contains local-path `replace`
directives. Publish Lean first, then update consumers in dependency order and
rebuild them standalone. TCP throughput, netmeter, and 64 MiB OOM validation
for `leannet` remains deployment evidence in [`TODO.md`](TODO.md); passing host
tests cannot replace it. IPv6 has the separate consumer hardware gate below.

The IPv6 hardware gate first proves slot-to-slot link-local UDP6 echo. Before
SLAAC/RIO and IPv6 application multicast count as released consumer paths, it
also proves one real Thread-border-router exchange—RA to SLAAC to RIO to UDP
`:5540` and back—and an explicit `ff02::fb` join. Every advertised NIC either
passes relevant `33:33` multicast and synthetic slot-MAC unicast or is excluded
from the IPv6 hardware scope. Until that evidence exists, DWMAC1000/LicheeRV is
the only candidate external-IPv6 carrier; DWMAC4, GENET, GEM, and IGB remain
explicitly outside that scope rather than inheriting support from a shared
interface. The app or switch test also proves that a bound UDPv6 port has the
intended exposure policy; IPv4 NAT tests are not evidence for native IPv6.

## Change rule

An extension to this KAM includes all of:

1. the measurement or concrete consumer that needs the missing feature;
2. the smallest explicit contract change;
3. a regression test at the owning layer and, for a seam, a consumer test;
4. the updated KEEP/ADAPT/MURDER decision in this document;
5. proof that hard-rejected input still fails loudly and within bounds.

Without all five, the feature stays outside scope. This is not incomplete
standards compliance; it is the safety boundary that keeps the supported subset
fully reviewable.
