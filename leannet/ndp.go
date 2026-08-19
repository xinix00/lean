package leannet

// ndp.go implements the neighbor half of NDP (RFC 4861) the way arp.go
// implements ARP: no goroutines or clock, callers pass monotonic nanoseconds,
// the stack lock covers every operation, and the pump polls resolve until it
// gets a MAC or noAnswer reports failure. The lifecycle constants are ARP's;
// the RFC's full reachability state machine (REACHABLE/STALE/PROBE) is
// deliberately absent — the ARP model has served the IPv4 half on the same
// links, and a wrong entry ages out on the same TTL.
//
// The router side (RS/RA with prefix and route options) lives here too: it is
// a few fields, and the emitter that sends solicitations is shared. SLAAC
// address formation and route lookup stay in ipv6.go with the stack state.
//
// Duplicate address detection is deliberately absent: our addresses derive
// from the interface MAC (EUI-64), so a duplicate address means a duplicate
// MAC — a fault DAD cannot repair either.

import "encoding/binary"

// Caps mirror arp.go where a v6 twin exists.
const (
	ndpReplyQueueCap = 8
	ndpCacheCap      = 128
	ndpRSTries       = 3                    // solicitations before waiting for an unsolicited RA
	ndpRSIval        = int64(4_000_000_000) // RFC 4861 §6.3.7: 4s between RS
	ndpPrefixCap     = 4                    // on-link prefixes retained from PIOs
	ndpRouteCap      = 8                    // specific routes retained from RIOs
)

// NDPStats mirrors ARPStats for the v6 neighbor machine.
type NDPStats struct {
	GaveUp     int // queries that exhausted their tries
	LearnDrop  int // passive learns refused by the cap
	FullDrop   int // resolutions refused because the table was full
	ReplyDrop  int // NA replies dropped by the queue cap
	MACChanged int // resolved entries whose MAC changed
	Ignored    int // advertisements that matched no query of ours
	BadNDP     int // NDP packets that failed validation (hop limit, options)
}

// ndpReply is a queued neighbor advertisement.
type ndpReply struct {
	hw        [6]byte  // link-layer destination
	dst       [16]byte // IPv6 destination (the solicitor)
	target    [16]byte // our address being advertised
	solicited bool
}

// ndpTable maps IPv6 addresses to MACs and drives solicitations. Entries reuse
// arpEntry: the lifecycle (pending/resolved/failed, TTLs, tries) is identical.
type ndpTable struct {
	ourMAC [6]byte

	entries map[[16]byte]*arpEntry
	replies []ndpReply

	// Router solicitation state: emit sends up to ndpRSTries while no RA has
	// arrived; the first valid RA stops it.
	rsTries int
	rsDue   int64
	rsDone  bool

	cnt NDPStats
}

func newNDPTable(ourMAC [6]byte, now int64) *ndpTable {
	return &ndpTable{ourMAC: ourMAC, entries: make(map[[16]byte]*arpEntry), rsDue: now}
}

// tick, resolve, peek, noAnswer, learn, and refresh mirror arp.go exactly; the
// shared arpEntry keeps the two machines honest about staying identical.

func (t *ndpTable) tick(ip [16]byte, e *arpEntry, now int64) bool {
	switch e.state {
	case arpPending:
	case arpResolved:
		if !e.static && now-e.born >= arpEntryTTL {
			delete(t.entries, ip)
			return false
		}
	case arpFailed:
		if now-e.born >= arpFailTTL {
			delete(t.entries, ip)
			return false
		}
	}
	return true
}

func (t *ndpTable) resolve(ip [16]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) {
		if e.state == arpResolved {
			return e.mac, true
		}
		return mac, false
	}
	if !t.makeRoom(now) {
		t.cnt.FullDrop++
		return mac, false
	}
	t.entries[ip] = &arpEntry{state: arpPending, due: now}
	return mac, false
}

func (t *ndpTable) makeRoom(now int64) bool {
	if len(t.entries) < ndpCacheCap {
		return true
	}
	t.sweepExpired(now)
	for len(t.entries) >= ndpCacheCap {
		if !t.evictResolved() {
			return false
		}
	}
	return true
}

func (t *ndpTable) sweepExpired(now int64) {
	for ip, e := range t.entries {
		t.tick(ip, e, now)
	}
}

func (t *ndpTable) evictResolved() bool {
	for ip, e := range t.entries {
		if e.state == arpResolved && !e.static {
			delete(t.entries, ip)
			return true
		}
	}
	return false
}

func (t *ndpTable) peek(ip [16]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) && e.state == arpResolved {
		return e.mac, true
	}
	return mac, false
}

func (t *ndpTable) noAnswer(ip [16]byte, now int64) bool {
	e, exists := t.entries[ip]
	if !exists {
		return t.fullLocked(now)
	}
	return t.tick(ip, e, now) && e.state == arpFailed
}

func (t *ndpTable) fullLocked(now int64) bool {
	if len(t.entries) < ndpCacheCap {
		return false
	}
	t.sweepExpired(now)
	evictable := 0
	for _, e := range t.entries {
		if e.state == arpResolved && !e.static {
			evictable++
		}
	}
	return len(t.entries)-evictable >= ndpCacheCap
}

func (t *ndpTable) learn(ip [16]byte, mac [6]byte, now int64) (wokePending bool) {
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) {
		if len(t.entries) >= ndpCacheCap {
			t.sweepExpired(now)
			if len(t.entries) >= ndpCacheCap {
				t.cnt.LearnDrop++
				return false
			}
		}
		t.entries[ip] = &arpEntry{mac: mac, state: arpResolved, born: now}
		return false
	}
	switch {
	case e.state == arpPending:
		e.state = arpResolved
		e.mac = mac
		e.born = now
		return true
	case e.state == arpResolved && !e.static && e.mac == mac:
		e.born = now
	}
	return false
}

func (t *ndpTable) refresh(ip [16]byte, mac [6]byte, now int64) {
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) || e.state != arpResolved || e.static {
		return
	}
	if e.mac != mac {
		t.cnt.MACChanged++
		e.mac = mac
	}
	e.born = now
}

// ---- receive side; the stack validated hop limit 255 and the checksum ----

// recvNS handles a neighbor solicitation for one of our addresses. Every
// supported invariant is checked before either the neighbor table or reply
// queue changes (RFC 4861 §§7.1.1, 7.2.4).
func (t *ndpTable) recvNS(f ICMPv6Frame, src, dst [16]byte, srcHW [6]byte, ours func([16]byte) bool, now int64) {
	body := f.Body()
	if f.Code() != 0 || len(body) < 20 {
		t.cnt.BadNDP++
		return
	}
	target := [16]byte(body[4:20])
	var srcMAC [6]byte
	hasSrc := false
	valid := ndpOptions(body[20:], func(typ byte, opt []byte) bool {
		if typ == ndpOptSourceLLA {
			if hasSrc || len(opt) != 8 {
				return false
			}
			copy(srcMAC[:], opt[2:8])
			hasSrc = true
		}
		return true
	})
	dad := isZero6(src)
	if !valid || isZero6(target) || isMulticast6(target) || isLoopback6(target) || isIPv4Mapped6(target) ||
		!validUnicastMAC(srcHW) || (dad && (hasSrc || dst != solicitedNode(target))) ||
		(!dad && (!validIngressSource6(src) || (dst != target && dst != solicitedNode(target)))) ||
		(hasSrc && (!validUnicastMAC(srcMAC) || srcMAC != srcHW)) ||
		(!dad && isMulticast6(dst) && !hasSrc) {
		t.cnt.BadNDP++
		return
	}
	if !ours(target) {
		return
	}
	if dad {
		// Someone else's DAD probe for an address we own: a duplicate MAC
		// (see the header note). Advertise to all-nodes so they back off.
		if len(t.replies) >= ndpReplyQueueCap {
			t.cnt.ReplyDrop++
			return
		}
		t.replies = append(t.replies, ndpReply{hw: multicastMAC6(allNodes6), dst: allNodes6, target: target})
		return
	}
	if hasSrc && !ours(src) {
		t.learn(src, srcMAC, now)
	}
	if len(t.replies) >= ndpReplyQueueCap {
		t.cnt.ReplyDrop++
		return
	}
	// The Ethernet source is already validated against SLLA when present, and
	// also lets us answer a valid unicast NS whose option was omitted.
	t.replies = append(t.replies, ndpReply{hw: srcHW, dst: src, target: target, solicited: true})
}

// recvNA resolves a pending query or refreshes an entry (RFC 4861 §7.2.5).
// Only the target address may gain state; unsolicited advertisements refresh
// but never create, mirroring ARP's poisoning rule.
func (t *ndpTable) recvNA(f ICMPv6Frame, src, dst [16]byte, srcHW [6]byte, now int64) (wokePending bool) {
	body := f.Body()
	if f.Code() != 0 || len(body) < 20 {
		t.cnt.BadNDP++
		return false
	}
	target := [16]byte(body[4:20])
	var mac [6]byte
	hasMAC := false
	valid := ndpOptions(body[20:], func(typ byte, opt []byte) bool {
		if typ == ndpOptTargetLLA {
			if hasMAC || len(opt) != 8 {
				return false
			}
			copy(mac[:], opt[2:8])
			hasMAC = true
		}
		return true
	})
	solicited := body[0]&0x40 != 0
	if !valid || !validIngressSource6(src) || !validIngressSource6(target) ||
		!validUnicastMAC(srcHW) || (solicited && isMulticast6(dst)) ||
		(hasMAC && (!validUnicastMAC(mac) || mac != srcHW)) {
		t.cnt.BadNDP++
		return false
	}
	if !hasMAC {
		return false // an advertisement without a link-layer address teaches nothing here
	}
	if e, exists := t.entries[target]; exists && t.tick(target, e, now) && e.state == arpPending {
		e.state = arpResolved
		e.mac = mac
		e.born = now
		return true
	}
	t.refresh(target, mac, now)
	t.cnt.Ignored++
	return false
}

// ---- emit side; the stack wraps these in IPv6+Ethernet ----

// ndpEmit is one packet the table wants transmitted.
type ndpEmit struct {
	icmpType byte
	dstIP    [16]byte
	dstMAC   [6]byte
	body     []byte
}

// emit yields one queued advertisement, due solicitation, or router
// solicitation. The caller loops until false. buf backs the body.
func (t *ndpTable) emit(buf []byte, ourLL [16]byte, now int64) (e ndpEmit, ok bool) {
	if len(t.replies) > 0 {
		r := t.replies[0]
		copy(t.replies, t.replies[1:])
		t.replies = t.replies[:len(t.replies)-1]
		// NA body: flags(4) target(16) + target LLA option.
		body := buf[:28]
		for i := range body {
			body[i] = 0
		}
		if r.solicited {
			body[0] = 0x60 // solicited + override
		} else {
			body[0] = 0x20 // override
		}
		copy(body[4:20], r.target[:])
		body[20], body[21] = ndpOptTargetLLA, 1
		copy(body[22:28], t.ourMAC[:])
		return ndpEmit{icmpType: icmp6NeighborAdvert, dstIP: r.dst, dstMAC: r.hw, body: body}, true
	}
	for ip, entry := range t.entries {
		if !t.tick(ip, entry, now) || entry.state != arpPending || now < entry.due {
			continue
		}
		if entry.tries >= arpQueryTries {
			entry.state = arpFailed
			entry.born = now
			t.cnt.GaveUp++
			continue
		}
		entry.tries++
		entry.due = now + arpRetryIval
		// NS body: reserved(4) target(16) + source LLA option, to the
		// target's solicited-node group (RFC 4861 §7.2.2).
		body := buf[:28]
		for i := range body {
			body[i] = 0
		}
		copy(body[4:20], ip[:])
		body[20], body[21] = ndpOptSourceLLA, 1
		copy(body[22:28], t.ourMAC[:])
		group := solicitedNode(ip)
		return ndpEmit{icmpType: icmp6NeighborSolicit, dstIP: group, dstMAC: multicastMAC6(group), body: body}, true
	}
	if !t.rsDone && t.rsTries < ndpRSTries && now >= t.rsDue {
		t.rsTries++
		t.rsDue = now + ndpRSIval
		// RS body: reserved(4) + source LLA option (RFC 4861 §4.1).
		body := buf[:12]
		for i := range body {
			body[i] = 0
		}
		body[4], body[5] = ndpOptSourceLLA, 1
		copy(body[6:12], t.ourMAC[:])
		_ = ourLL
		return ndpEmit{icmpType: icmp6RouterSolicit, dstIP: allRouters6, dstMAC: multicastMAC6(allRouters6), body: body}, true
	}
	return ndpEmit{}, false
}

// nextDeadline mirrors arp entries plus the router-solicitation timer.
func (t *ndpTable) nextDeadline(add func(int64)) {
	for _, e := range t.entries {
		switch e.state {
		case arpPending:
			add(e.due)
		case arpFailed:
			add(e.born + arpFailTTL)
		}
	}
	if !t.rsDone && t.rsTries < ndpRSTries {
		add(t.rsDue)
	}
}

// ---- router advertisements (RFC 4861 §6, RFC 4191 routes) ----

// v6prefix is one on-link prefix learned from a PIO.
type v6prefix struct {
	prefix [16]byte
	bits   int
}

// v6route is one specific route from a RIO: traffic for prefix goes via router.
type v6route struct {
	prefix [16]byte
	bits   int
	router [16]byte // link-local address of the advertising router
}

// RA actions retain explicit zero-lifetime withdrawals until ipv6.go commits
// the fully validated advertisement. They are not stored in the route tables.
type raPrefix struct {
	prefix   v6prefix
	withdraw bool
}

type raRoute struct {
	route    v6route
	withdraw bool
}

// raResult is what one router advertisement taught the stack; ipv6.go applies
// it to the address and route state under the same lock.
type raResult struct {
	router      [16]byte // the RA's source (link-local)
	hasLifetime bool     // router lifetime > 0: usable as default router
	slaac       [16]byte // address formed from the first autonomous prefix
	hasSLAAC    bool
	prefixes    []raPrefix
	routes      []raRoute
	hasMAC      bool
	mac         [6]byte
}

// recvRA parses an advertisement without changing any table. The caller
// commits r only after this function has validated the complete option list,
// so a malformed suffix cannot leave a learned MAC or partial route behind.
// Wall-clock lifetimes are deliberately absent, but explicit zero values are
// retained as withdrawal actions.
func (t *ndpTable) recvRA(f ICMPv6Frame, src, dst [16]byte, srcHW, ourMAC [6]byte) (r raResult, ok bool) {
	if f.Code() != 0 || !isLinkLocal6(src) || !validUnicastMAC(srcHW) ||
		(isMulticast6(dst) && dst != allNodes6) {
		t.cnt.BadNDP++
		return r, false // RFC 4861 §6.1.2: routers advertise from link-local
	}
	body := f.Body()
	if len(body) < 12 {
		t.cnt.BadNDP++
		return r, false
	}
	r.router = src
	r.hasLifetime = binary.BigEndian.Uint16(body[2:4]) > 0
	valid := ndpOptions(body[12:], func(typ byte, opt []byte) bool {
		switch typ {
		case ndpOptSourceLLA:
			if r.hasMAC || len(opt) != 8 {
				return false
			}
			copy(r.mac[:], opt[2:8])
			r.hasMAC = true
			if !validUnicastMAC(r.mac) || r.mac != srcHW {
				return false
			}
		case ndpOptPrefixInfo:
			if len(opt) != 32 {
				return false
			}
			bits := int(opt[2])
			flags := opt[3]
			validLife := binary.BigEndian.Uint32(opt[4:8])
			preferredLife := binary.BigEndian.Uint32(opt[8:12])
			if bits > 128 || preferredLife > validLife {
				return false
			}
			prefix := canonicalPrefix6([16]byte(opt[16:32]), bits)
			// RFC 4861 excludes link-local prefixes from PIO processing; a
			// multicast prefix can never describe on-link unicast or SLAAC.
			if isLinkLocal6(prefix) || isMulticast6(prefix) {
				return false
			}
			key := v6prefix{prefix: prefix, bits: bits}
			for _, have := range r.prefixes {
				if have.prefix == key {
					return false
				}
			}
			if flags&0x80 != 0 { // L: on-link
				r.prefixes = append(r.prefixes, raPrefix{prefix: key, withdraw: validLife == 0})
			}
			// A: autonomous — form one SLAAC address from the first /64.
			if flags&0x40 != 0 && bits == 64 && validLife > 0 && !r.hasSLAAC {
				addr := prefix
				iid := llAddrFromMAC(ourMAC)
				copy(addr[8:], iid[8:])
				r.slaac = addr
				r.hasSLAAC = true
			}
		case ndpOptRouteInfo:
			if len(opt) != 8 && len(opt) != 16 && len(opt) != 24 {
				return false
			}
			bits := int(opt[2])
			// RFC 4191 allows a longer Prefix field than strictly needed;
			// reject only a length too short to carry the declared bits.
			if bits > 128 || (len(opt) == 8 && bits != 0) ||
				(len(opt) == 16 && bits > 64) || opt[3]&0x18 == 0x10 {
				return false
			}
			lifetime := binary.BigEndian.Uint32(opt[4:8])
			var prefix [16]byte
			copy(prefix[:], opt[8:])
			prefix = canonicalPrefix6(prefix, bits)
			if bits > 0 && (isLinkLocal6(prefix) || isMulticast6(prefix)) {
				return false
			}
			key := v6prefix{prefix: prefix, bits: bits}
			for _, have := range r.routes {
				if have.route.prefix == key.prefix && have.route.bits == key.bits {
					return false
				}
			}
			r.routes = append(r.routes, raRoute{
				route:    v6route{prefix: prefix, bits: bits, router: src},
				withdraw: lifetime == 0,
			})
		}
		return true
	})
	if !valid {
		t.cnt.BadNDP++
		return raResult{}, false
	}
	return r, true
}
