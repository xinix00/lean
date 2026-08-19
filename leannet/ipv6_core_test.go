package leannet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func newIPv6CoreStack(t *testing.T) (*Stack, *memDevice) {
	t.Helper()
	collector := &memDevice{}
	dev := &memDevice{peer: collector}
	collector.peer = dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24,
		MAC: [6]byte{2, 0, 0, 0, 0, 1}, Budget: 1 << 20, AdvWS: 2,
	}, 123)
	t.Cleanup(func() { s.Close() })
	return s, collector
}

func testUDP6EthernetFrame(t *testing.T, dstHW, srcHW [6]byte, src, dst [16]byte, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	f := make([]byte, sizeEth+sizeIPv6+sizeUDP+len(payload))
	eth := EthFrame(f)
	eth.SetDst(dstHW)
	eth.SetSrc(srcHW)
	eth.SetEtherType(EtherTypeIPv6)
	copy(f[sizeEth+sizeIPv6+sizeUDP:], payload)
	n, err := PutUDP6(f[sizeEth+sizeIPv6:], sport, dport, src, dst, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv6(f[sizeEth:], ProtoUDP, hopLimitDefault, src, dst, n); err != nil {
		t.Fatal(err)
	}
	return f
}

func testNDP6EthernetFrame(t *testing.T, dstHW, srcHW [6]byte, src, dst [16]byte, typ, code byte, body []byte) []byte {
	t.Helper()
	f := make([]byte, sizeEth+sizeIPv6+4+len(body))
	eth := EthFrame(f)
	eth.SetDst(dstHW)
	eth.SetSrc(srcHW)
	eth.SetEtherType(EtherTypeIPv6)
	n, err := putNDP(f[sizeEth+sizeIPv6:], typ, body, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		icmp := f[sizeEth+sizeIPv6 : sizeEth+sizeIPv6+n]
		icmp[1], icmp[2], icmp[3] = code, 0, 0
		csum := pseudoChecksum6(ProtoICMPv6, src, dst, icmp)
		binary.BigEndian.PutUint16(icmp[2:4], csum)
	}
	if _, err := PutIPv6(f[sizeEth:], ProtoICMPv6, hopLimitNDP, src, dst, n); err != nil {
		t.Fatal(err)
	}
	return f
}

func testICMP6(typ, code byte, body []byte) ICMPv6Frame {
	f := make(ICMPv6Frame, 4+len(body))
	f[0], f[1] = typ, code
	copy(f[4:], body)
	return f
}

func testRA6Frame(t *testing.T, router [16]byte, routerHW [6]byte, lifetime uint16, options ...[]byte) []byte {
	t.Helper()
	n := 12
	for _, opt := range options {
		n += len(opt)
	}
	body := make([]byte, n)
	binary.BigEndian.PutUint16(body[2:4], lifetime)
	off := 12
	for _, opt := range options {
		copy(body[off:], opt)
		off += len(opt)
	}
	return testNDP6EthernetFrame(t, multicastMAC6(allNodes6), routerHW, router, allNodes6, icmp6RouterAdvert, 0, body)
}

func testSLLA6(mac [6]byte) []byte {
	opt := make([]byte, 8)
	opt[0], opt[1] = ndpOptSourceLLA, 1
	copy(opt[2:], mac[:])
	return opt
}

func testPIO6(prefix [16]byte, bits byte, flags byte, valid, preferred uint32) []byte {
	opt := make([]byte, 32)
	opt[0], opt[1], opt[2], opt[3] = ndpOptPrefixInfo, 4, bits, flags
	binary.BigEndian.PutUint32(opt[4:8], valid)
	binary.BigEndian.PutUint32(opt[8:12], preferred)
	copy(opt[16:], prefix[:])
	return opt
}

func testRIO6(prefix [16]byte, bits byte, lifetime uint32) []byte {
	// The full form is valid for every nonzero prefix and lets tests vary
	// ignored host bits to pin canonical identity.
	opt := make([]byte, 24)
	opt[0], opt[1], opt[2] = ndpOptRouteInfo, 3, bits
	binary.BigEndian.PutUint32(opt[4:8], lifetime)
	copy(opt[8:], prefix[:])
	return opt
}

func TestUDP6CachedRouterStillRequiresRoutableSource(t *testing.T) {
	s, collector := newIPv6CoreStack(t)
	u, err := s.ListenUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	router := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	routerHW := [6]byte{2, 0, 0, 0, 0, 2}
	s.mu.Lock()
	s.v6.router, s.v6.hasRouter = router, true
	s.v6.ndp.learn(router, routerHW, s.now()) // force the former cache-hit path
	s.mu.Unlock()

	dst := [16]byte{0xfd, 0x1a, 0x81, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IP(dst[:]), Port: 5540}); !errors.Is(err, errNoRoute6) {
		t.Fatalf("cached routed write without SLAAC = %v, want errNoRoute6", err)
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	for _, raw := range collector.q {
		eth, _ := ParseEth(raw)
		if eth.EtherType() == EtherTypeIPv6 {
			ip, err := ParseIPv6(eth.Payload())
			if err == nil && ip.NextHeader() == ProtoUDP {
				t.Fatal("write emitted UDP with a link-local source after a router-cache hit")
			}
		}
	}
}

func TestUDP6Fixed1280TransmitCeiling(t *testing.T) {
	s, collector := newIPv6CoreStack(t)
	u, err := s.ListenUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	peer := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	s.mu.Lock()
	s.v6.ndp.learn(peer, peerHW, s.now())
	s.mu.Unlock()

	payload := bytes.Repeat([]byte{0xa5}, maxUDP6Payload)
	if n, err := u.WriteTo(payload, &net.UDPAddr{IP: net.IP(peer[:]), Port: 5540}); err != nil || n != len(payload) {
		t.Fatalf("1232-byte write = (%d, %v)", n, err)
	}
	if _, err := u.WriteTo(append(payload, 0), &net.UDPAddr{IP: net.IP(peer[:]), Port: 5540}); err == nil {
		t.Fatal("1233-byte UDP6 payload was accepted")
	}

	found := false
	collector.mu.Lock()
	for _, raw := range collector.q {
		eth, _ := ParseEth(raw)
		if eth.EtherType() != EtherTypeIPv6 {
			continue
		}
		ip, err := ParseIPv6(eth.Payload())
		if err == nil && ip.NextHeader() == ProtoUDP {
			found = true
			if got := sizeIPv6 + int(ip.PayloadLen()); got != ipv6MinimumMTU {
				t.Errorf("IPv6 packet size = %d, want %d", got, ipv6MinimumMTU)
			}
		}
	}
	collector.mu.Unlock()
	if !found {
		t.Fatal("boundary UDP6 frame was not transmitted")
	}

	s.mu.Lock()
	err = s.sendIPv6Locked(peerHW, s.v6.ll, peer, ProtoICMPv6, hopLimitDefault, make([]byte, ipv6MinimumMTU-sizeIPv6+1))
	s.mu.Unlock()
	if err == nil {
		t.Fatal("generic IPv6 sender accepted a packet above 1280 bytes")
	}
}

func TestIPv6IngressRequiresExactEthernetDestination(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	u, err := s.ListenUDP6(7777)
	if err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(time.Second))
	ourHW := [6]byte{2, 0, 0, 0, 0, 1}
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	ourLL := llAddrFromMAC(ourHW)
	peerLL := llAddrFromMAC(peerHW)

	wrongHW := [6]byte{2, 0, 0, 0, 0, 9}
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, wrongHW, peerHW, peerLL, ourLL, 9000, 7777, []byte("wrong"))); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, ourHW, peerHW, peerLL, ourLL, 9000, 7777, []byte("right"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := u.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "right" {
		t.Fatalf("unicast delivery = %q, %v", buf[:n], err)
	}

	group := [16]byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
	if err := s.JoinGroup6(group); err != nil {
		t.Fatal(err)
	}
	m, err := s.ListenUDP6(5353)
	if err != nil {
		t.Fatal(err)
	}
	m.SetReadDeadline(time.Now().Add(time.Second))
	wrongMcast := multicastMAC6(group)
	wrongMcast[5]++
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, wrongMcast, peerHW, peerLL, group, 5353, 5353, []byte("wrong"))); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, multicastMAC6(group), peerHW, peerLL, group, 5353, 5353, []byte("right"))); err != nil {
		t.Fatal(err)
	}
	n, _, err = m.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "right" {
		t.Fatalf("multicast delivery = %q, %v", buf[:n], err)
	}
}

func TestIPv6EchoDropCountersAreDisjoint(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	if _, err := s.ListenUDP6(0); err != nil {
		t.Fatal(err)
	}
	ourHW := s.cfg.MAC
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	ourLL := llAddrFromMAC(ourHW)
	peerLL := llAddrFromMAC(peerHW)
	recvFull := func(raw []byte) (bad, full int) {
		eth, err := ParseEth(raw)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ParseIPv6(eth.Payload())
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.out6 = make([]outPkt6, outQueueCap)
		beforeBad, beforeFull := s.stats.DropBadFrame, s.stats.DropReplyFull
		s.recvIPv6(ip, peerHW, s.now())
		return s.stats.DropBadFrame - beforeBad, s.stats.DropReplyFull - beforeFull
	}

	bad := testNDP6EthernetFrame(t, ourHW, peerHW, peerLL, ourLL, icmp6EchoRequest, 1, make([]byte, 4))
	if badDrops, fullDrops := recvFull(bad); badDrops != 1 || fullDrops != 0 {
		t.Fatalf("bad echo counters: bad=%d reply-full=%d", badDrops, fullDrops)
	}

	valid := testNDP6EthernetFrame(t, ourHW, peerHW, peerLL, ourLL, icmp6EchoRequest, 0, make([]byte, 4))
	if badDrops, fullDrops := recvFull(valid); badDrops != 0 || fullDrops != 1 {
		t.Fatalf("full echo counters: bad=%d reply-full=%d", badDrops, fullDrops)
	}
}

func TestRAPreservesAtomicityAndCanonicalRouteActions(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	if _, err := s.ListenUDP6(0); err != nil {
		t.Fatal(err)
	}
	r1 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11}
	m1 := [6]byte{2, 0, 0, 0, 0, 0x11}
	prefix := [16]byte{0xfd, 0, 0, 0xaa, 0, 0, 0, 0, 1, 2, 3}
	route := [16]byte{0xfd, 0x1a, 0x81, 0x20, 0, 0, 0, 0, 1, 2, 3}

	// A valid first option followed by a zero-length option rejects the whole
	// RA: not even the SLLA may leak into the neighbor cache.
	malformed := []byte{99, 0}
	if err := s.RecvInboundPacket(testRA6Frame(t, r1, m1, 1800, testSLLA6(m1), malformed)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, learned := s.v6.ndp.entries[r1]
	mutated := learned || s.v6.hasRouter || s.v6.hasGlobal || len(s.v6.prefixes) != 0 || len(s.v6.routes) != 0 || s.v6.ndp.rsDone
	s.mu.Unlock()
	if mutated {
		t.Fatal("malformed RA partially mutated IPv6 state")
	}

	if err := s.RecvInboundPacket(testRA6Frame(t, r1, m1, 1800,
		testSLLA6(m1), testPIO6(prefix, 64, 0xc0, 3600, 1800), testRIO6(route, 64, 3600))); err != nil {
		t.Fatal(err)
	}
	r2 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22}
	m2 := [6]byte{2, 0, 0, 0, 0, 0x22}
	routeWithOtherHostBits := route
	routeWithOtherHostBits[15] = 0xee
	if err := s.RecvInboundPacket(testRA6Frame(t, r2, m2, 0, testRIO6(routeWithOtherHostBits, 64, 7200))); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if len(s.v6.prefixes) != 1 || len(s.v6.routes) != 1 || s.v6.routes[0].router != r2 {
		t.Fatalf("replacement state: prefixes=%#v routes=%#v", s.v6.prefixes, s.v6.routes)
	}
	if s.v6.prefixes[0].prefix != canonicalPrefix6(prefix, 64) || s.v6.routes[0].prefix != canonicalPrefix6(route, 64) {
		t.Fatal("RA prefixes were not canonicalized")
	}
	s.mu.Unlock()

	// A stale withdrawal from r1 cannot erase r2's replacement.
	if err := s.RecvInboundPacket(testRA6Frame(t, r1, m1, 0, testRIO6(route, 64, 0))); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	kept := len(s.v6.routes) == 1 && s.v6.routes[0].router == r2
	s.mu.Unlock()
	if !kept {
		t.Fatal("old router withdrawal erased replacement route")
	}

	if err := s.RecvInboundPacket(testRA6Frame(t, r2, m2, 0, testRIO6(route, 64, 0))); err != nil {
		t.Fatal(err)
	}
	prefixWithOtherHostBits := prefix
	prefixWithOtherHostBits[15] = 0xdd
	if err := s.RecvInboundPacket(testRA6Frame(t, r1, m1, 0, testPIO6(prefixWithOtherHostBits, 64, 0x80, 0, 0))); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	routes, prefixes, stillGlobal := len(s.v6.routes), len(s.v6.prefixes), s.v6.hasGlobal
	s.mu.Unlock()
	if routes != 0 || prefixes != 0 || !stillGlobal {
		t.Fatalf("withdrawal state: routes=%d prefixes=%d global=%v", routes, prefixes, stillGlobal)
	}
}

func TestNDPFormValidationBeforeMutation(t *testing.T) {
	ourHW := [6]byte{2, 0, 0, 0, 0, 1}
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	ourLL := llAddrFromMAC(ourHW)
	peerLL := llAddrFromMAC(peerHW)
	otherOurs := ourLL
	otherOurs[15]++
	targetGroup := solicitedNode(ourLL)
	tab := newNDPTable(ourHW, 1)
	ours := func(a [16]byte) bool { return a == ourLL || a == otherOurs }

	ns := make([]byte, 28)
	copy(ns[4:20], ourLL[:])
	ns[20], ns[21] = ndpOptSourceLLA, 1
	copy(ns[22:], peerHW[:])
	// DAD's unspecified source forbids a source-LLA option.
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 0, ns), [16]byte{}, targetGroup, peerHW, ours, 1)
	// A nonzero code is invalid even when every other field is valid.
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 1, ns), peerLL, targetGroup, peerHW, ours, 1)
	// A non-DAD solicitation still belongs only at its target or that target's
	// solicited-node group, never all-nodes or another address we own.
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 0, ns), peerLL, allNodes6, peerHW, ours, 1)
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 0, ns), peerLL, otherOurs, peerHW, ours, 1)
	if len(tab.replies) != 0 {
		t.Fatal("invalid NS queued an advertisement")
	}
	if _, learned := tab.entries[peerLL]; learned {
		t.Fatal("wrong-destination NS learned a neighbor")
	}

	// A valid passive-DAD NS is the sole accepted unspecified source form.
	validDAD := make([]byte, 20)
	copy(validDAD[4:20], ourLL[:])
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 0, validDAD), [16]byte{}, targetGroup, [6]byte{}, ours, 1)
	if len(tab.replies) != 0 {
		t.Fatal("DAD from an invalid Ethernet source queued an advertisement")
	}
	tab.recvNS(testICMP6(icmp6NeighborSolicit, 0, validDAD), [16]byte{}, targetGroup, peerHW, ours, 1)
	if len(tab.replies) != 1 {
		t.Fatalf("valid DAD queued %d replies, want 1", len(tab.replies))
	}

	// A solicited NA may not use a multicast IPv6 destination.
	tab.replies = nil
	tab.resolve(peerLL, 1)
	na := make([]byte, 28)
	na[0] = 0x60 // solicited + override
	copy(na[4:20], peerLL[:])
	na[20], na[21] = ndpOptTargetLLA, 1
	copy(na[22:], peerHW[:])
	tab.recvNA(testICMP6(icmp6NeighborAdvert, 0, na), peerLL, allNodes6, peerHW, 1)
	_, resolved := tab.peek(peerLL, 1)
	if resolved {
		t.Fatal("solicited multicast NA resolved a neighbor")
	}
	tab.recvNA(testICMP6(icmp6NeighborAdvert, 0, na), peerLL, ourLL, peerHW, 1)
	_, resolved = tab.peek(peerLL, 1)
	if !resolved {
		t.Fatal("valid unicast NA did not resolve the pending neighbor")
	}
}

func TestNDPRefreshIsNotIgnored(t *testing.T) {
	ourHW := [6]byte{2, 0, 0, 0, 0, 1}
	ourLL := llAddrFromMAC(ourHW)
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	peerLL := llAddrFromMAC(peerHW)
	tab := newNDPTable(ourHW, 0)
	tab.entries[peerLL] = &neighborEntry{mac: peerHW, state: neighborResolved}

	advert := func(target [16]byte, mac [6]byte) ICMPv6Frame {
		body := make([]byte, 28)
		body[0] = 0x20 // unsolicited override
		copy(body[4:20], target[:])
		body[20], body[21] = ndpOptTargetLLA, 1
		copy(body[22:], mac[:])
		return testICMP6(icmp6NeighborAdvert, 0, body)
	}
	newHW := [6]byte{2, 0, 0, 0, 0, 3}
	tab.recvNA(advert(peerLL, newHW), peerLL, ourLL, newHW, 1)
	if tab.cnt.Ignored != 0 || tab.cnt.MACChanged != 1 {
		t.Fatalf("refresh counters: ignored=%d changed=%d", tab.cnt.Ignored, tab.cnt.MACChanged)
	}
	if got, ok := tab.peek(peerLL, 1); !ok || got != newHW {
		t.Fatalf("refreshed neighbor = (%v, %v), want (%v, true)", got, ok, newHW)
	}

	unknownHW := [6]byte{2, 0, 0, 0, 0, 4}
	unknown := llAddrFromMAC(unknownHW)
	tab.recvNA(advert(unknown, unknownHW), unknown, allNodes6, unknownHW, 2)
	if tab.cnt.Ignored != 1 {
		t.Fatalf("unknown advertisement ignored=%d, want 1", tab.cnt.Ignored)
	}
}

func TestIPv6IngressSourcePolicyAndOnLinkLearning(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	u, err := s.ListenUDP6(7777)
	if err != nil {
		t.Fatal(err)
	}
	u.SetReadDeadline(time.Now().Add(time.Second))
	ourHW := [6]byte{2, 0, 0, 0, 0, 1}
	routerHW := [6]byte{2, 0, 0, 0, 0, 2}
	ourLL := llAddrFromMAC(ourHW)

	invalid := [][16]byte{
		{},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2},
		{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	for _, src := range invalid {
		if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, ourHW, routerHW, src, ourLL, 9000, 7777, []byte("bad"))); err != nil {
			t.Fatal(err)
		}
	}

	routed := [16]byte{0xfd, 0x1a, 0x81, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, ourHW, routerHW, routed, ourLL, 9000, 7777, []byte("routed"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := u.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "routed" {
		t.Fatalf("first accepted datagram = %q, %v", buf[:n], err)
	}
	s.mu.Lock()
	_, learnedRouted := s.v6.ndp.entries[routed]
	s.mu.Unlock()
	if learnedRouted {
		t.Fatal("passive learning cached a routed remote as a direct neighbor")
	}

	peerLL := llAddrFromMAC(routerHW)
	if err := s.RecvInboundPacket(testUDP6EthernetFrame(t, ourHW, routerHW, peerLL, ourLL, 9000, 7777, []byte("on-link"))); err != nil {
		t.Fatal(err)
	}
	n, _, err = u.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "on-link" {
		t.Fatalf("on-link datagram = %q, %v", buf[:n], err)
	}
	s.mu.Lock()
	_, learnedOnLink := s.v6.ndp.entries[peerLL]
	s.mu.Unlock()
	if !learnedOnLink {
		t.Fatal("validated on-link source was not passively learned")
	}
}
