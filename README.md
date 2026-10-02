# lean

Small Rust crates that do what they say and link nothing you did not ask for.

This is lean v3, in Rust. [KAM.md](KAM.md) fixes what each crate promises,
narrows and refuses.

Every crate stands on its own: `core` and `alloc`, its own tests, no
dependencies on each other and none from outside. Import one and you pay for
that one. The exception is a composition (`leanhttps`), which may import the
crates it joins and nothing else.

| | |
|---|---|
| `leanrand` | Random for a node: bytes, an id, a bounded number, jitter on a wait. |
| `leanelf` | ELF64 for a loader: PT_LOAD segments, bytes at a load address, symbols by name. |
| `leandhcp` | DHCPv4 on raw ethernet frames: a lease before any netstack exists. |
| `leannet` | TCP/IP for bare metal: Ethernet, IPv4 ARP/ICMP/UDP/TCP; opt-in IPv6 UDP/NDP/SLAAC and Thread routes, one bounded buffer budget. |
| `leancookie` | A cookie jar (RFC 6265), host-only by default. |
| `leanhttp` | HTTP/1.1 without TLS: client and server, sequential keep-alive, chunked responses and request bodies. |
| `leantls` | TLS 1.3 for a network you own: one version, one suite, a pinned Ed25519 peer or a real chain. |
| `leanhttps` | A composition: `leanhttp` over `leantls`, and nothing else. |
| `leans3` | S3: SigV4 signing plus the object operations that are actually used. |
| `leanh2` | HTTP/2 server role on a connection the caller already chose. |

How the code is written, for every crate here: the haas.software Rust
handbook (`rustdoc/README.md` next to this repository).
