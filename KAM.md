# KAM — the frozen HTTP/IP profile

This document fixes the scope of `leanhttp`, `leanh2`, `leanhttps`, `leans3`,
and `leannet`. It is not a list of everything HTTP and the underlying IP
transports can do. It defines what this repository **promises to do correctly**,
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
  application transport for bare-metal nodes, with one bounded buffer pool;
- an HTTP/2 server role on a connection the caller supplies and has already
  chosen, for one measured consumer: a Cloudflare Tunnel, where the far side
  dials nothing and speaks HTTP/2 client over our outbound connection.

For `leanhttp`, “multiple things over one channel” means **sequential requests
and responses over a keep-alive connection**; speculative HTTP pipelining is not
contractual, and that package multiplexes nothing. Concurrent streams exist in
exactly one place, `leanh2`, because one measured consumer's peer opens them —
not as a general capability of this stack. A caller that has a choice uses
`leanhttp`.

## Decision matrix

| Area | KEEP | ADAPT | MURDER |
|---|---|---|---|
| HTTP server | HTTP/1.1, sequential keep-alive, fixed and streamed responses, `HEAD`, `204`/`205`/`304`, `Done`, `Hijack` | origin-form only, known-length request bodies, WebSocket through raw takeover | HTTP/1.0, HTTP/2 in this package (it lives in `leanh2`), CONNECT, request chunking/trailers, server-side Expect state machine, general 1xx state machine |
| leanh2 | HTTP/2 server role on a caller-supplied connection: the client preface then SETTINGS first; 32 streams; 16 KiB frames; 64 KiB compressed and decoded headers; 64 KiB receive window per stream; atomic two-level flow control; statuses 200–599 | request bodies with exact Content-Length integrity; exact static HPACK matches use their index, otherwise response fields are literals without indexing; syntactically valid PRIORITY accepted and ignored; `GOAWAY` with the highest accepted stream | client role, listener/dialer, TLS/ALPN, `h2c` upgrade, protocol sniffing, push, CONNECT, trailing header sections, 1xx, priority state or scheduling, dynamic response compression |
| Mux | method+path, exact/subtree, `{segment}`, `{rest...}`, `GET`→`HEAD`, `404`/`405`+`Allow` | canonical paths or rejection; immutable after start | host routing, `{$}`, escaped/dot routing, slash normalization, net/http compatibility work |
| HTTP client | outbound HTTP/1.1, inbound 1.0/1.1, GET/HEAD redirects, response framing, deadlines, keep-alive pool | fixed-length streaming upload with a strict Expect decision; compression pass-through | request chunking, automatic decompression, CONNECT/upgrade, general retry state machine |
| TLS/S3 | explicit trust model, SNI per connection, SigV4 and used object operations | TLS as a dialer composition; signed S3 calls never follow redirects | TLS server, silent skip-verify, multipart, streaming SigV4, SigV4a, presigned URLs, IMDS/IAM |
| leannet | Ethernet; IPv4 ARP/ICMP/UDP/TCP and link-local multicast; opt-in IPv6 UDP, ICMPv6/NDP, link-scoped multicast, one active SLAAC identity, and expiring PIO/RIO routing; deadlines, close, bounded memory | one IPv4 identity; one derived link-local plus one active SLAAC IPv6 identity; bounded simplified NDP and route state; fixed 1280-byte IPv6 packet ceiling | TCPv6, DHCPv6, extension headers, fragmentation, PMTUD, MLD/IGMP, wider multicast, dual-family sockets, full NUD and multi-address renumbering, congestion control, timestamps, Nagle, SYN cookies, data-path logging |

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
- bind dial, request I/O, and response-body reads to `Call.Context`; cancellation
  closes that call's active connection and prevents it from entering the pool;
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
response. If `HeaderTimeout` and `Timeout` are both zero and the context has no
deadline, that final response—like a regular call—deliberately has no deadline.

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

TLS shutdown is best effort: `Close` attempts `close_notify`, but bounds that
write to 250 milliseconds and always closes the transport. Before shutdown, any
TLS record write error is terminal for that connection; later writes return the
stored error and never attempt to continue a partially written record stream.

### leans3

`leans3` provides SigV4 with static credentials and an optional session token,
virtual-hosted and path-style addressing, plus the object operations in use:
`Get`, `GetTo`, `Put`, `PutFrom`, conditional PUT/DELETE, ETag, and paginated
`ListObjectsV2`.

These invariants apply:

- every PUT has a known length and payload hash;
- `UnsignedPayload` is allowed only for an HTTPS endpoint; replacing the
  default transport with `Client.Dial` transfers responsibility for
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

An S3 context covers dialing, request I/O, and response-body reads. Bare
cancellation closes that operation's active connection; the callback is stopped
before a completed connection can return to the HTTP pool. As with net/http, an
arbitrary upload source blocked inside its own `Read`, or a download sink blocked
inside its own `Write`, must provide its own cancellation seam.

S3 additionally applies a 30-second socket-progress timeout by default. Long
`GetTo` and `PutFrom` transfers may run for any total duration while reads or
writes keep making progress; a socket operation blocked for thirty seconds
without progress fails the operation and closes its connection.
`Client.IdleTimeout` selects another positive duration; zero selects the
default. S3 applies this policy around its dialed connections rather than
adding per-call progress policy to `leanhttp`.

Buffered `Get` has a fixed 4 MiB allocation cap and returns
`ErrObjectTooLarge` above it; larger objects use `GetTo`.
Each LIST page is limited to 4 MiB, 1,000 keys, 1,024 bytes per key, and 16 KiB
per continuation token. `List` requires a positive result cap and rejects an
empty-progress page or an unchanged continuation token.

### Change rule, filled in: cancellable calls

1. **Consumer.** S3 operations already accept contexts, and Hop's TamaGo HTTP
   client needs the same cancellation behavior as its host implementation.
2. **Smallest contract.** `leanhttp.Call.Context` bounds only that call and
   closes its active connection on cancellation; S3 owns its separate fixed
   connection-progress policy.
3. **Tests.** Dial, header, body, cancellation-versus-pool-handoff, and S3
   operation cancellation are covered at their owning layers; Hop's TamaGo
   client is compile-gated against the seam.
4. **Decision.** Call cancellation is KEEP. Interrupting an arbitrary caller
   `Reader` or `Writer` remains the caller's responsibility.
5. **Hard rejection.** Cancellation that wins before pool handoff never returns
   the connection; after handoff its callback is unregistered. A nil context
   retains the ordinary background lifetime.

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
- own one EUI-64 link-local address and at most one active SLAAC address from
  capped autonomous `/64` PIO state; use a link-local source only for
  link-local unicast and `ff02::/16`, and require the SLAAC source for every
  routed packet;
- implement only the ICMPv6 control needed by this path: bounded RS/RA and
  NS/NA plus unicast echo; validate every invariant of those supported forms
  before rejected input can mutate state;
- require every SLLA/TLLA in a supported NS, NA, or RA to equal the Ethernet
  source MAC; reject a mismatch before it can mutate state;
- retain bounded PIO identities and bounded RIO routes, honor default-router,
  PIO valid/preferred, and RIO lifetimes with monotonic pump deadlines, but cap
  every positive advertised value (including `0xffffffff`) to a renewable
  two-hour local lease; prefer the longest live RIO match, replace the next hop
  for a repeated prefix, remove expired or explicitly withdrawn state, wake
  route/NDP waiters on that transition, and use one live advertised default
  router only as a last resort; count a new PIO/RIO identity refused by its cap;
- keep the selected SLAAC identity stable while preferred, replace it with a
  retained preferred candidate after deprecation, and remove or replace it at
  valid expiry or autonomous withdrawal without ever owning two SLAAC
  identities; restart bounded router solicitation after the last live
  RA-derived router, PIO, or RIO disappears;
- preserve an echo request's exact owned destination as its queued reply source,
  and drop a queued echo reply or NA if that local address is no longer owned
  when the pump reaches wire emission;
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

Socket `Close` returns unread RX budget immediately and starts one absolute
20-second cleanup bound that ACKs and zero-window updates cannot renew. TX
budget returns when FIN is acknowledged or the connection is reaped. A peer
half-close may remain useful for tail reads and response writes, but an idle
CLOSE-WAIT is reaped after two minutes unless real application I/O or cumulative
ACK progress renews it. TIME-WAIT remains deliberately short at one second.
These are resource policy for these nodes, not general Internet defaults.

A completed inbound handshake is not caller-owned until `Accept` returns it.
That backlog handoff therefore has one absolute 30-second deadline which peer
traffic cannot renew. Reaped channel entries are physically pruned before the
backlog cap is applied, so stale references cannot make an otherwise empty
listener permanently refuse healthy handshakes.

An open ESTABLISHED socket has no arbitrary idle reaper: silence alone does not
prove either endpoint dead, so its handle remains caller-owned until `Close`, a
reset, or bounded retransmission failure. Applications that impose an idle
session policy must express it with socket deadlines and `Close`.

A live `Stack` owns one sleeping pump until the caller invokes `Stack.Close`;
that explicit close is the lifecycle boundary. It snapshots ARP/NDP counters,
releases TCP/UDP budget, and drops dynamic protocol maps, queues, loopback
caches, the transmit buffer, IPv6 state, and the Device reference. Keeping a
closed `Stack` for telemetry therefore does not keep its former high-water
storage alive.

### ADAPT

Out-of-order TCP data is dropped with an immediate duplicate ACK; the peer
recovers through retransmission. This is the chosen small loss state machine,
not half a SACK implementation.

IPv6 is not a general dual-stack implementation. NDP uses the same bounded,
ARP-like resolution and aging model instead of the complete Neighbor
Unreachability Detection state machine. RA lifetimes are relative values
converted to monotonic deadlines and clipped to a renewable two-hour ownership
lease. Thus even the wire's infinite value requires a live router to refresh;
expiry and explicit zero-lifetime withdrawal free PIO/RIO/default-router state
and wake its waiters. PIO L and A state are independent, so an L-only withdrawal
removes on-link classification without inventing an autonomous withdrawal. One
selected SLAAC address remains stable while preferred and can move to another
retained preferred prefix after deprecation, withdrawal, or valid expiry;
overlap with multiple owned identities remains outside the profile. A write
before the first usable RA receives an explicit no-route error rather than
implicitly waiting for configuration.

NDP is deliberately stricter than RFC 4861: the SLLA/TLLA and Ethernet source
MAC must identify the same sender. This fail-closed home-link rule excludes
proxy-ND and VRRP-style virtual-router MAC indirection.

The socket seam is equally narrow: IPv4 and IPv6 have separate UDP port spaces
and no dual-family socket. IPv6 binds are wildcard-only, report `[::]:port` as
their local bind, and choose a wire source per destination; pretending to honor
a specific local address is forbidden.

### MURDER

Absent: congestion control, out-of-order reassembly/SACK, TCPv6, DHCPv6,
IPv4-mapped dual-family sockets, active DAD, privacy or temporary addresses,
multiple simultaneous SLAAC identities, full NUD and multi-address renumbering,
MLD/IGMP, multicast outside link scope, proxy-ND and VRRP-style MAC indirection,
ICMPv6 redirects and error/PMTUD state, IPv4 and IPv6 fragmentation, IPv4 options,
IPv6 extension headers and jumbograms, TCP timestamps/PAWS, Nagle, SYN
cookies, urgent-data API, inbound IP broadcast, and data-path logging.
[`leannet/DESIGN.md`](leannet/DESIGN.md) explains why and when a feature may
return.

## leanh2

`leanh2` is the one place in this repository where concurrent streams exist. It
serves the HTTP/2 **server** role on a connection the caller supplies and has
already chosen: no listener, no dialer, no client role, and no negotiation
about which protocol version this is.

The measured consumer is a Cloudflare Tunnel (`HopOS/apps/cloudflared-lean`).
That consumer's shape is the whole reason for the profile below: the tunnel
dials out, and the edge then behaves as the HTTP/2 client on that outbound
connection — it sends the preface, it opens every stream, and it never expects a
request from this side.

### KEEP

The connection MUST:

- invoke `Serve` exactly once for a `Conn`;
- read the client preface before anything else and refuse a connection that
  does not begin with it;
- require the peer's first frame after that preface to be a non-acknowledgement
  `SETTINGS` frame on stream zero;
- refuse public `GOAWAY` output until `Serve` has read the preface and sent its
  initial SETTINGS, so no shutdown race can precede the server SETTINGS frame;
- announce `HEADER_TABLE_SIZE=0`, `ENABLE_PUSH=0`,
  `MAX_CONCURRENT_STREAMS=32`, `INITIAL_WINDOW_SIZE=65536`,
  `MAX_FRAME_SIZE=16384`, and `MAX_HEADER_LIST_SIZE=65536`; honour the peer's
  `INITIAL_WINDOW_SIZE` and `MAX_FRAME_SIZE`, including the shift a changed
  initial window applies to live streams. Output remains at the 16384-byte RFC
  floor even when the peer permits larger frames;
- raise the default connection receive window once by exactly 1048576 bytes;
  this bounds total unread body data across streams while allowing several
  65536-byte stream windows to make progress;
- answer every non-acknowledgement `PING` with its payload, because a peer may
  withhold all work until it sees the acknowledgement;
- accept a header block as one indivisible unit: after `HEADERS` without
  `END_HEADERS`, only `CONTINUATION` on that same stream is accepted and
  anything else ends the connection;
- write a header block as one indivisible unit: `HEADERS` and its
  `CONTINUATION` frames leave the connection with no other frame between them,
  whatever other streams are writing;
- accept only client-initiated stream identifiers that are odd and strictly
  increasing, and refuse an even, reused, or lower identifier;
- admit at most 32 concurrent streams, at most 65536 accumulated compressed
  header bytes in one block, at most 65536 decoded header-list bytes, and at
  most 65536 unread request-body bytes per stream;
- claim the same final byte count atomically from the outbound stream and
  connection windows granted by the peer: concurrent response writers may
  neither spend the same connection credit twice nor lose the difference
  between the two levels;
- debit every received `DATA` payload, including its pad-length byte and
  padding, from both receive windows before accepting it; refuse either window
  being exceeded and refuse every update that would overflow a window;
- return receive credit only for bytes the handler consumed or the server
  deliberately discarded; resetting or completing a stream with buffered,
  unread body bytes returns their connection credit exactly once;
- keep request delivery off the connection frame loop, so one slow handler
  cannot stall `PING`, `SETTINGS`, or another stream;
- pass only a request with exactly one non-empty valid-token `:method`, exactly
  one non-empty `:scheme`, exactly one non-empty `:path`, at most one
  `:authority`, no other pseudo-header, and no pseudo-header after a regular
  field; `CONNECT` and extended CONNECT are rejected before the handler;
- require every regular field name to be a non-empty lowercase HTTP token and
  every value to be a valid HTTP field value; reject connection-specific
  fields and a trailing header section, and join split `cookie` fields with
  `"; "` before exposing the generic request;
- accept at most one `content-length`, in strict unsigned decimal form, and
  require it to equal exactly the number of unpadded `DATA` octets received
  when the request ends; a short or overlong body is an error, never a request
  the handler may mistake for complete;
- accept only final response statuses 200–599, reject 1xx before writing, and
  reject a body write for `HEAD`, `204`, `205`, or `304` before emitting bytes;
- validate response field names and values before writing and reject pseudo-
  headers supplied by the handler, connection-specific fields, trailers, and
  `content-length`; DATA plus `END_STREAM` is the sole response-length state;
- give each stream its own goroutine and contain a handler panic to that
  stream, with `RST_STREAM` to the peer and the connection intact;
- send `GOAWAY` with the highest stream identifier it accepted and may still
  finish, and accept no new stream afterwards, so the peer never retries work
  that can still have side effects here;
- release every stream's state and reader on close, with the reason. The caller
  chooses the connection and owns its deadline policy; once `Serve` starts,
  `Conn` closes the transport before that sole invocation returns so a blocked
  writer, body reader, or flow-control waiter is released before it completes.

### ADAPT

- A request body is delivered, bounded by the window this side advertises
  rather than by any figure the peer names. The consumer needs it: the tunnel's
  control stream is bidirectional and its configuration push carries JSON.
- An exact response field in HPACK's static table uses that index; every other
  response field goes out as a literal without indexing. The encoder therefore
  keeps no dynamic table, and the announced table size of zero keeps the peer
  from building one either. The decoder does maintain the peer's table, because
  the peer may use it before that setting arrives.
- `SETTINGS_HEADER_TABLE_SIZE` is announced as zero and a peer size update is
  accepted only at the start of a header block. Once the peer acknowledges the
  setting, zero is enforced for every following block. A static-only block is
  accepted without demanding the otherwise ceremonial leading update-to-zero;
  any growth or dynamic reference is still refused.
- A handler that closes a request body stops receiving stream credit; later
  bytes can consume only the already announced remainder until response finish
  resets the remote half. DATA already in flight after our reset is discarded
  only for a bounded set of 32 recent reset streams and only within each one's
  remaining window; DATA after a normal close remains an error.
- A syntactically valid five-byte `PRIORITY` frame on a nonzero stream, and the
  syntactically valid priority field of `HEADERS`, are accepted and ignored.
  They allocate no state and influence no scheduling.

### MURDER

No measured consumer, removed with its state space, and refused loudly where
input can reach it: the client role; a listener or dialer; TLS, ALPN, and `h2c`
upgrade; protocol sniffing between HTTP/1.1 and HTTP/2 on one connection;
`PUSH_PROMISE` and server push; `CONNECT` and extended CONNECT; request or
response trailing header sections; 1xx responses; priority state and priority
scheduling; and dynamic compression of response headers. The valid PRIORITY
wire forms named under ADAPT are compatibility input, not a priority feature.

Protocol sniffing deserves its own sentence, because it was written and removed:
four bytes cannot prove an HTTP/2 preface follows — `PRI` is a valid HTTP
extension method — and the seam it advertised did not exist, since `leanhttp`
exposes no per-connection serve entry. A caller that must carry both versions
chooses per listener, not per connection.

### Change rule, filled in

1. **Measurement and consumer.** `HopOS/apps/cloudflared-lean` needs an HTTP/2
   server role: the Cloudflare edge speaks HTTP/2 client over the tunnel's
   outbound connection and offers no HTTP/1.1 transport (`--protocol` accepts
   only `auto`, `quic`, and `http2`). Two equivalent one-connection servers,
   `-ldflags="-s -w"`, CGO off, 2026-08-19: `x/net/http2` with `net/http`
   5.10 MB against 2.22 MB, so 2.88 MB and 56%. The cause is structural:
   `http2.Server.ServeConn` takes an `http.Handler`, so that package cannot be
   used without `net/http`, which links `crypto/tls` and `crypto/x509` whether
   or not the connection is encrypted.
2. **Smallest explicit contract change.** A separate package, not a mode of
   `leanhttp`: importing one links nothing of the other, and `leanhttp` keeps
   murdering HTTP/2. The server role only, on a caller-supplied connection.
3. **Tests.** At the owning layer: the settings exchange and its
   acknowledgement and SETTINGS as the first peer frame; the exact announced
   caps; `PING`; indivisible header blocks in both directions; the 32-stream
   cap and identifier discipline; simultaneous response writers competing for
   one connection window; stream- and connection-level receive overruns;
   consumed and discarded body credit; strict pseudo-header, field, CONNECT,
   trailer, Content-Length, response-status, and bodyless-response rules; a
   contained handler panic; a wrong preface; and `GOAWAY` once with its highest
   accepted stream. HPACK decoding against RFC 7541 Appendix C and against a
   recorded header block from the edge, including enforcement of the zero table
   size after SETTINGS acknowledgement. For the seam, the consumer test is the
   tunnel against the real edge: registration, a public request with the
   `Host` preserved, and 5 MiB byte-identical.
4. **Decision.** The matrix row and the boundaries above.
5. **Hard rejection.** Every peer protocol violation in KEEP ends the
   connection with a named error and bounded work. A handler-side response
   violation returns an error before malformed bytes are written; finish keeps
   the stream well framed and resets it only when cancellation is required.
   The recorded edge block proves the decoder handles the peer that actually
   calls.

## Consumer obligations

The core stays small only if consumers do not rebuild each seam halfway:

- a streaming handler reads needed request-body content before `Done`.
  Otherwise `Done` transfers the unread body to the bounded server drain. The
  handler never touches `Request.Body` afterward. The hard boundary is before
  response headers reach the wire, so the simple rule is to claim it before
  `WriteHeader`, `Write`, or `Flush`;
- a hijacker uses neither `Done` nor the regular `ResponseWriter`;
- a `leanh2` caller chooses HTTP/2 before constructing `Conn` and supplies its
  liveness/deadline policy. The transport permits one concurrent read and write,
  and closing it wakes both. The caller may close or deadline it to initiate a
  stop; a graceful stop sends `GOAWAY` after startup and then closes that
  transport. `Conn` also guarantees the transport is closed before its sole
  `Serve` invocation returns, so a blocked reader or writer cannot survive it;
- a `leanh2` handler also bounds its own external work and returns after its
  Body or Response reports cancellation. Closing the connection wakes package-
  owned waits; it cannot interrupt an arbitrary channel receive or third-party
  call inside handler code, and that handler keeps one of the 32 slots until it
  returns;
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
lifecycle in `leanhttp`; framing, stream state, HPACK, and both flow-control
levels in `leanh2`; the pure TCP/ARP/NDP state machines in `leannet`;
composition errors in `leanhttps` or `leans3`.

An IPv6 profile change additionally proves lazy enablement, v4/v6 port
isolation, the mandatory UDP checksum, the 1280/1232-byte transmit boundary,
exact Ethernet destination filtering, malformed NDP with zero state mutation,
NDP give-up/deadline/close wakeups, and RA source selection plus monotonic
two-hour-capped PIO/RIO/default-route expiry and refresh, bounded-slot release,
replacement, explicit withdrawal, single-address renumbering, pump-driven
solicitation/waiter wakeups, and stale queued NA/echo suppression.

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
  on `/stream` returns `405`;
- regular tests, race tests, `go vet`, and a host build for
  `HopOS/apps/cloudflared-lean` against candidate Lean; its two TamaGo images
  must also compile with the pinned toolchain before release.

In the existing sibling workspace, the first three lines are:

```sh
go test -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go test -race -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go vet ./hop/... ../hoplock/... ./hoplockserver/...
go -C hop test -run '^$' -tags tamago ./pkg/hophttp
```

`cloudflared-lean` is its own module inside HopOS. Connect exactly that module
and candidate Lean in a temporary workspace; testing the surrounding HopOS
module does not exercise this seam.

```sh
LEAN_CANDIDATE=/path/to/lean
CLOUDFLARED_LEAN_CANDIDATE=/path/to/hop-os/apps/cloudflared-lean
H2_KAM_WORKDIR="$(mktemp -d)"
go -C "$H2_KAM_WORKDIR" work init "$LEAN_CANDIDATE" "$CLOUDFLARED_LEAN_CANDIDATE"
GOWORK="$H2_KAM_WORKDIR/go.work" go -C "$CLOUDFLARED_LEAN_CANDIDATE" test -count=1 ./...
GOWORK="$H2_KAM_WORKDIR/go.work" go -C "$CLOUDFLARED_LEAN_CANDIDATE" test -race -count=1 ./...
GOWORK="$H2_KAM_WORKDIR/go.work" go -C "$CLOUDFLARED_LEAN_CANDIDATE" vet ./...
GOWORK="$H2_KAM_WORKDIR/go.work" go -C "$CLOUDFLARED_LEAN_CANDIDATE" build -o "$H2_KAM_WORKDIR/cloudflared-lean-host" ./cmd/cloudflared-lean
```

The module lookup in that workspace MUST resolve `github.com/xinix00/lean` to
`LEAN_CANDIDATE`; an older tag or an unrelated filesystem `replace` is not
candidate evidence. The host tests are not a TamaGo build. Run the consumer's
official `tools/build.sh` with the pinned `TAMAGO` compiler after its Lean
dependency points at the candidate tag; it builds both arm64 and riscv64.
Until that script creates its ignored `out` directory before its host build,
the gate MUST precreate `out` as the standalone command block below does.

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

### leanh2 real-edge gate

Wire-unit tests cannot substitute for the peer that selected this profile.
Before tagging any change to leanh2 framing, HPACK, stream lifecycle, flow
control, or its consumer seam, use the host binary built from the candidate
workspace above against `region1.v2.argotunnel.com` or
`region2.v2.argotunnel.com` with a dedicated test tunnel.

The origin fixture records the received `Host` and serves one deterministic
file of exactly 5 MiB. Then run the candidate host binary with the test token
and that fixture as its fallback origin:

```sh
TUNNEL_TOKEN=the-dedicated-test-token \
TUNNEL_URL=http://127.0.0.1:the-origin-port \
"$H2_KAM_WORKDIR/cloudflared-lean-host"
```

The gate passes only when all of these are observed on the same candidate:

1. every configured tunnel connection logs successful registration and stays
   registered through the transfers;
2. a request through the public hostname reaches the fixture with that exact
   public `Host`, not the edge address or fallback origin address;
3. downloading the 5 MiB fixture through the public hostname is byte-for-byte
   identical to the local fixture;
4. a configuration push is read to its exact end and acknowledged, proving the
   bidirectional request-body path; and
5. shutdown sends `GOAWAY`, closes the supplied connection, and leaves no stuck
   process or stream.

Record the edge region, date, candidate commits, file digest, and outcomes.
The token is never written to this repository. A recorded HPACK block proves
decoder compatibility but does not replace this gate.

### Consumer release gate

After tagging and updating dependencies, run Hop, hoplock, and hoplockserver
again outside the local workspace:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go list -m all
```

For `HopOS/apps/cloudflared-lean`, after updating it to the released Lean tag,
run its standalone gate with no workspace and no Lean filesystem replacement:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go list -m all
mkdir -p out
GOWORK=off ./tools/build.sh
```

Run those commands from the `cloudflared-lean` module. Its module list MUST
name the released Lean version. Repeat the real-edge gate with the standalone
host binary produced by `tools/build.sh`; a source-workspace success does not
prove the published dependency chain.

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
