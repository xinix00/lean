package leannet

// ipv6.go adds an opt-in IPv6 lane to the one-address stack, sized for what
// needs it: Matter and mDNS on the local link. UDP and ICMPv6 only — no TCP
// over v6, no extension headers, no DHCPv6, no global prefixes beyond one
// SLAAC address. The lane does not exist until the first v6 socket or group
// join creates it: a stack that never touches v6 drops 0x86dd frames at the
// demux and pays nothing else. That is the whole opt-in mechanism — use is
// the switch (DESIGN.md's "when a deployment requires it" arrived: Matter
// devices live on IPv6 ULAs behind a Thread border router, measured 18-08).
//
// Addressing is self-contained the way Matter expects it on a home LAN:
// a link-local address from the MAC (EUI-64), one SLAAC address when a router
// advertises an autonomous /64, on-link prefixes from PIOs, specific routes
// from RIOs (RFC 4191 — how a Thread border router publishes its mesh), and
// a default router as the last resort. No router means link-local only,
// which still carries mDNS and on-link Matter.

import (
	"errors"
	"net"
	"time"
)

var (
	errNoRoute6      = errors.New("leannet: no IPv6 route (no router advertised)")
	errUnreachable6  = errors.New("leannet: IPv6 neighbor did not answer")
	errNotLinkMcast6 = errors.New("leannet: only link-scoped multicast (ff02::/16)")
	errV6Disabled    = errors.New("leannet: IPv6 lane is not enabled")
)

// v6State is the whole IPv6 lane; nil on stacks that never use v6.
type v6State struct {
	ll        [16]byte // link-local, from the MAC; always present
	global    [16]byte // one SLAAC address, from the first autonomous /64
	hasGlobal bool

	ndp *ndpTable
	udp *udpTable

	// Joined link-scoped groups (mDNS's ff02::fb). Solicited-node groups for
	// our own addresses are computed, not stored.
	groups map[[16]byte]struct{}

	router    [16]byte // default router (link-local), from the last RA
	hasRouter bool

	prefixes []v6prefix // on-link prefixes from PIOs, capped
	routes   []v6route  // specific routes from RIOs, capped
}

// out6 mirrors outPkt for connectionless v6 replies (echo).
type outPkt6 struct {
	dst  [16]byte
	next byte
	pkt  []byte
}

// enableV6Locked creates the lane on first use. Idempotent.
func (s *Stack) enableV6Locked() *v6State {
	if s.v6 != nil {
		return s.v6
	}
	now := s.now()
	s.v6 = &v6State{
		ll:     llAddrFromMAC(s.cfg.MAC),
		ndp:    newNDPTable(s.cfg.MAC, now),
		udp:    newUDPTable(),
		groups: make(map[[16]byte]struct{}),
	}
	s.notify() // arm the router-solicitation timer in the pump
	return s.v6
}

// JoinGroup6 subscribes to a link-scoped multicast group for the stack's
// lifetime, enabling the v6 lane if needed. Mirrors JoinGroup: no Leave, a
// small cap, cleared on Close.
func (s *Stack) JoinGroup6(group [16]byte) error {
	if !isLinkScopedMulticast6(group) {
		return errNotLinkMcast6
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStackClosed
	}
	v6 := s.enableV6Locked()
	if _, ok := v6.groups[group]; ok {
		return nil
	}
	if len(v6.groups) >= maxGroups {
		return errGroupsFull
	}
	v6.groups[group] = struct{}{}
	return nil
}

// ourAddr6 reports whether a is one of this stack's unicast addresses.
func (v *v6State) ourAddr6(a [16]byte) bool {
	return a == v.ll || (v.hasGlobal && a == v.global)
}

// acceptDst6 reports whether a frame for dst is for us: our unicast, all-nodes,
// our solicited-node groups, or an explicitly joined group.
func (v *v6State) acceptDst6(dst [16]byte) bool {
	if v.ourAddr6(dst) || dst == allNodes6 {
		return true
	}
	if dst == solicitedNode(v.ll) || (v.hasGlobal && dst == solicitedNode(v.global)) {
		return true
	}
	_, ok := v.groups[dst]
	return ok
}

// recvIPv6 demultiplexes one validated IPv6 frame; ingressLocked checked the
// destination filter. srcMAC feeds passive neighbor learning.
func (s *Stack) recvIPv6(ip IPv6Frame, srcMAC [6]byte, now int64) {
	v6 := s.v6
	src := ip.Src()
	if isMulticast6(src) {
		s.stats.DropBadFrame++
		return
	}
	switch ip.NextHeader() {
	case ProtoICMPv6:
		f, err := ParseICMPv6(ip.Payload(), src, ip.Dst())
		if err != nil {
			s.stats.DropBadFrame++
			return
		}
		switch f.Type() {
		case icmp6NeighborSolicit, icmp6NeighborAdvert, icmp6RouterAdvert:
			// RFC 4861 §3: NDP with a decremented hop limit crossed a router.
			if ip.HopLimit() != hopLimitNDP {
				v6.ndp.cnt.BadNDP++
				return
			}
		}
		switch f.Type() {
		case icmp6NeighborSolicit:
			v6.ndp.recvNS(f, src, v6.ourAddr6, now)
			s.notify() // a queued advertisement may be ready
		case icmp6NeighborAdvert:
			if v6.ndp.recvNA(f, now) {
				s.notify() // a route waiter can proceed
			}
		case icmp6RouterAdvert:
			if r, ok := v6.ndp.recvRA(f, src, s.cfg.MAC, now); ok {
				s.applyRALocked(r)
				s.notify()
			}
		case icmp6EchoRequest:
			// Mirror the IPv4 echo: the free field diagnostic. Unicast only —
			// answering multicast pings is how a link gets storms.
			if !v6.ourAddr6(ip.Dst()) || len(s.out6) >= outQueueCap {
				if len(s.out6) >= outQueueCap {
					s.stats.DropReplyFull++
				}
				return
			}
			v6.ndp.learn(src, srcMAC, now)
			reply := append([]byte(nil), f...)
			reply[0] = icmp6EchoReply
			reply[2], reply[3] = 0, 0
			csum := pseudoChecksum6(ProtoICMPv6, ip.Dst(), src, reply)
			reply[2], reply[3] = byte(csum>>8), byte(csum)
			s.out6 = append(s.out6, outPkt6{dst: src, next: ProtoICMPv6, pkt: reply})
			s.notify()
		}
	case ProtoUDP:
		f, err := ParseUDP(ip.Payload())
		if err != nil || !f.ChecksumOK6(src, ip.Dst()) {
			s.stats.DropBadFrame++
			return
		}
		// Learn only from unicast addressed to us, after checksum validation,
		// mirroring the IPv4 discipline.
		if v6.ourAddr6(ip.Dst()) && v6.ndp.learn(src, srcMAC, now) {
			s.notify()
		}
		if !v6.udp.deliver6(f.DstPort(), src, f.SrcPort(), f.Payload()) {
			s.stats.DropNoPort++
			return
		}
		s.notify()
	}
}

// applyRALocked folds one advertisement into the address and route state.
func (s *Stack) applyRALocked(r raResult) {
	v6 := s.v6
	if r.hasLifetime {
		v6.router = r.router
		v6.hasRouter = true
	} else if v6.hasRouter && v6.router == r.router {
		v6.hasRouter = false // the router resigned (lifetime zero)
	}
	if r.hasSLAAC && !v6.hasGlobal {
		// One address is enough for a Matter controller; the first autonomous
		// prefix wins and later renumbering waits for a stack restart.
		v6.global = r.slaac
		v6.hasGlobal = true
	}
	for _, p := range r.onLink {
		if len(v6.prefixes) >= ndpPrefixCap {
			break
		}
		known := false
		for _, have := range v6.prefixes {
			if have == p {
				known = true
				break
			}
		}
		if !known {
			v6.prefixes = append(v6.prefixes, p)
		}
	}
	for _, rt := range r.routes {
		if len(v6.routes) >= ndpRouteCap {
			break
		}
		known := false
		for _, have := range v6.routes {
			if have == rt {
				known = true
				break
			}
		}
		if !known {
			v6.routes = append(v6.routes, rt)
		}
	}
}

// nextHop6Locked mirrors nextHopLocked: which address's NDP state governs dst.
func (s *Stack) nextHop6Locked(dst [16]byte) (hop [16]byte, ok bool) {
	v6 := s.v6
	if isLinkLocal6(dst) {
		return dst, true
	}
	for _, p := range v6.prefixes {
		if prefixMatch6(dst, p.prefix, p.bits) {
			return dst, true
		}
	}
	// Longest matching RIO route wins over the default router.
	best := -1
	for _, rt := range v6.routes {
		if prefixMatch6(dst, rt.prefix, rt.bits) && rt.bits > best {
			best = rt.bits
			hop = rt.router
		}
	}
	if best >= 0 {
		return hop, true
	}
	if v6.hasRouter {
		return v6.router, true
	}
	return hop, false
}

// route6Locked resolves dst to a next-hop MAC; query=false only peeks.
func (s *Stack) route6Locked(dst [16]byte, now int64, query bool) ([6]byte, bool) {
	v6 := s.v6
	if v6.ourAddr6(dst) {
		return s.cfg.MAC, true // loopback via sendEthLocked's own-MAC path
	}
	if isLinkScopedMulticast6(dst) {
		return multicastMAC6(dst), true
	}
	hop, ok := s.nextHop6Locked(dst)
	if !ok {
		return [6]byte{}, false
	}
	if !query {
		return v6.ndp.peek(hop, now)
	}
	return v6.ndp.resolve(hop, now)
}

// sendIPv6Locked wraps payload in IPv6+Ethernet from txBuf and transmits.
func (s *Stack) sendIPv6Locked(dstMAC [6]byte, src, dst [16]byte, next, hopLimit byte, payload []byte) error {
	off := EthernetHeaderSize
	copy(s.txBuf[off+sizeIPv6:], payload)
	PutIPv6(s.txBuf[off:], next, hopLimit, src, dst, len(payload))
	return s.sendEthLocked(dstMAC, EtherTypeIPv6, sizeIPv6+len(payload))
}

// srcAddr6For picks our source address for dst: link-local destinations and
// link-scoped multicast take the link-local source (required for NDP, right
// for mDNS); everything routed takes the SLAAC address, without which an
// off-link peer could not answer.
func (v *v6State) srcAddr6For(dst [16]byte) ([16]byte, bool) {
	if isLinkLocal6(dst) || isLinkScopedMulticast6(dst) {
		return v.ll, true
	}
	if v.hasGlobal {
		return v.global, true
	}
	return v.ll, false
}

// drain6Locked is drainLocked's v6 half: best-effort replies and NDP emission.
func (s *Stack) drain6Locked(now int64) {
	v6 := s.v6
	if v6 == nil {
		return
	}
	for _, o := range s.out6 {
		if mac, ok := s.route6Locked(o.dst, now, false); ok {
			src, _ := v6.srcAddr6For(o.dst)
			hop := byte(hopLimitDefault)
			if o.next == ProtoICMPv6 {
				hop = hopLimitNDP // echo replies mirror ping's expectations
			}
			s.sendIPv6Locked(mac, src, o.dst, o.next, hop, o.pkt)
		}
	}
	s.out6 = s.out6[:0]

	gaveUpBefore := v6.ndp.cnt.GaveUp
	var body [64]byte
	for {
		e, ok := v6.ndp.emit(body[:], v6.ll, now)
		if !ok {
			break
		}
		// NDP source selection (RFC 4861): advertisements travel from the
		// advertised address itself; solicitations from link-local.
		src := v6.ll
		if e.icmpType == icmp6NeighborAdvert && len(e.body) >= 20 {
			src = [16]byte(e.body[4:20])
		}
		off := EthernetHeaderSize + sizeIPv6
		n, err := putNDP(s.txBuf[off:], e.icmpType, e.body, src, e.dstIP)
		if err != nil {
			break // txBuf is MTU-sized; only a sizing bug reaches this
		}
		PutIPv6(s.txBuf[EthernetHeaderSize:], ProtoICMPv6, hopLimitNDP, src, e.dstIP, n)
		s.sendEthLocked(e.dstMAC, EtherTypeIPv6, sizeIPv6+n)
	}
	if v6.ndp.cnt.GaveUp != gaveUpBefore {
		s.notify()
	}
}

// ---- v6 UDP sockets; the shapes mirror socket.go's v4 half ----

// ListenUDP6 binds a UDP port on the v6 lane, enabling it if needed.
func (s *Stack) ListenUDP6(port uint16) (*udpSock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStackClosed
	}
	v6 := s.enableV6Locked()
	if port == 0 {
		p, err := s.ephemeralPort(v6.udp.bound)
		if err != nil {
			return nil, err
		}
		port = p
	}
	u, err := v6.udp.bind(port, udpQueueCap, &s.pot)
	if err != nil {
		return nil, err
	}
	return &udpSock{s: s, port: u, lport: port, v6: true}, nil
}

// DialUDP6 binds an ephemeral v6 port connected to one peer.
func (s *Stack) DialUDP6(raddr [16]byte, rport uint16) (*udpSock, error) {
	u, err := s.ListenUDP6(0)
	if err != nil {
		return nil, err
	}
	u.connected, u.raddr, u.rport = true, raddr, rport
	u.s.mu.Lock()
	u.port.connected, u.port.peer, u.port.peerPort = true, raddr, rport
	u.s.mu.Unlock()
	return u, nil
}

// writeUDP6 sends one datagram, waiting by deadline for unresolved neighbors.
func (u *udpSock) writeUDP6(p []byte, dst [16]byte, dport uint16) (int, error) {
	if err := u.s.closedFirst(func() bool { return u.port.closed }); err != nil {
		return 0, err
	}
	if isMulticast6(dst) && !isLinkScopedMulticast6(dst) {
		return 0, errNotLinkMcast6
	}
	if len(p) > MTU-sizeIPv6-sizeUDP {
		return 0, errors.New("leannet: udp datagram exceeds mtu")
	}
	s := u.s
	var sent int
	err := s.await(nil, func() time.Time { return u.wrDeadline },
		func() (bool, error) {
			if u.port.closed {
				return false, net.ErrClosed
			}
			v6 := s.v6
			if v6 == nil {
				return false, errV6Disabled
			}
			src, routable := v6.srcAddr6For(dst)
			now := s.now()
			if mac, ok := s.route6Locked(dst, now, true); ok {
				off := EthernetHeaderSize + sizeIPv6
				copy(s.txBuf[off+sizeUDP:], p)
				n, err := PutUDP6(s.txBuf[off:], u.lport, dport, src, dst, len(p))
				if err != nil {
					return false, err
				}
				hop := byte(hopLimitDefault)
				if isLinkScopedMulticast6(dst) {
					hop = hopLimitNDP // mDNS uses 255 on the link (RFC 6762 §11)
				}
				PutIPv6(s.txBuf[EthernetHeaderSize:], ProtoUDP, hop, src, dst, n)
				if err := s.sendEthLocked(mac, EtherTypeIPv6, sizeIPv6+n); err != nil {
					return false, err
				}
				sent = len(p)
				return true, nil
			}
			hop, ok := s.nextHop6Locked(dst)
			if !ok {
				return false, errNoRoute6 // no router: an answer, not a wait
			}
			if !routable && !isLinkLocal6(dst) {
				// Off-link with only a link-local source cannot be answered;
				// fail now instead of after five silent solicitations.
				return false, errNoRoute6
			}
			if v6.ndp.noAnswer(hop, now) {
				return false, errUnreachable6
			}
			s.notify() // pump the neighbor solicitation
			return false, nil
		})
	return sent, err
}
