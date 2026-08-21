package leannet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type capturedICMP6 struct {
	typ      byte
	src, dst [16]byte
}

func takeICMP6(t *testing.T, collector *memDevice) []capturedICMP6 {
	t.Helper()
	collector.mu.Lock()
	raw := collector.q
	collector.q = nil
	collector.mu.Unlock()
	var got []capturedICMP6
	for _, frame := range raw {
		eth, err := ParseEth(frame)
		if err != nil || eth.EtherType() != EtherTypeIPv6 {
			continue
		}
		ip, err := ParseIPv6(eth.Payload())
		if err != nil || ip.NextHeader() != ProtoICMPv6 {
			continue
		}
		icmp, err := ParseICMPv6(ip.Payload(), ip.Src(), ip.Dst())
		if err == nil {
			got = append(got, capturedICMP6{typ: icmp.Type(), src: ip.Src(), dst: ip.Dst()})
		}
	}
	return got
}

func newDormantIPv6Stack(now int64) (*Stack, *memDevice) {
	collector := &memDevice{}
	dev := &memDevice{peer: collector}
	collector.peer = dev
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	v6 := &v6State{
		ll:     llAddrFromMAC(mac),
		ndp:    newNDPTable(mac, now),
		udp:    newUDPTable(),
		groups: make(map[[16]byte]struct{}),
	}
	return &Stack{
		cfg: Config{MAC: mac}, dev: dev, v6: v6,
		wake: make(chan struct{}), closed: true,
		txBuf: make([]byte, MTU+EthernetMaximumSize),
	}, collector
}

func installTestSLAAC(v6 *v6State, prefix [16]byte, now, until int64) [16]byte {
	v6.prefixes = []v6prefix{{
		prefix: canonicalPrefix6(prefix, 64), bits: 64,
		autonomous: true, validUntil: until, preferredUntil: until,
	}}
	v6.selectGlobal(now)
	v6.syncRouterSolicitation(now)
	return v6.global
}

func waitPendingNDP6(t *testing.T, s *Stack, peer [16]byte) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		e := s.v6.ndp.entries[peer]
		s.mu.Unlock()
		if e != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("IPv6 write did not start NDP resolution")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUDP6NDPWaiterLifecycle(t *testing.T) {
	peer := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	remote := &net.UDPAddr{IP: net.IP(peer[:]), Port: 5540}

	t.Run("give-up wakes with unreachable", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()

		result := make(chan error, 1)
		go func() {
			_, err := u.WriteTo([]byte("x"), remote)
			result <- err
		}()
		waitPendingNDP6(t, s, peer)
		s.mu.Lock()
		e := s.v6.ndp.entries[peer]
		if e == nil {
			s.mu.Unlock()
			t.Fatal("pending NDP entry disappeared")
		}
		e.tries = neighborQueryTries
		e.due = s.now()
		s.drain6Locked(s.now())
		s.mu.Unlock()

		select {
		case err := <-result:
			if !errors.Is(err, errUnreachable6) {
				t.Fatalf("write after NDP give-up = %v, want %v", err, errUnreachable6)
			}
		case <-time.After(time.Second):
			t.Fatal("NDP give-up did not wake the blocked writer")
		}
	})

	t.Run("write deadline", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		if err := u.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := u.WriteTo([]byte("x"), remote); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unresolved write = %v, want deadline exceeded", err)
		}
	})

	t.Run("close wakes", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := u.WriteTo([]byte("x"), remote)
			result <- err
		}()
		waitPendingNDP6(t, s, peer)
		if err := u.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after Close = %v, want %v", err, net.ErrClosed)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not wake the blocked IPv6 writer")
		}
	})
}

func TestRAPumpExpiryRestartsRouterSolicitation(t *testing.T) {
	s, collector := newIPv6CoreStack(t)
	if _, err := s.ListenUDP6(0); err != nil {
		t.Fatal(err)
	}
	router := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	routerHW := [6]byte{2, 0, 0, 0, 0, 2}
	if err := s.RecvInboundPacket(testRA6Frame(t, router, routerHW, 60)); err != nil {
		t.Fatal(err)
	}
	takeICMP6(t, collector) // discard the lane's initial solicitation

	// Shorten the already parsed lease so the real pump, rather than a direct
	// expireRA call, owns the deadline transition exercised here.
	s.mu.Lock()
	s.v6.routerUntil = s.now() + int64(40*time.Millisecond)
	s.notify()
	s.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range takeICMP6(t, collector) {
			if f.typ == icmp6RouterSolicit {
				s.mu.Lock()
				hasRouter, rsDone := s.v6.hasRouter, s.v6.ndp.rsDone
				s.mu.Unlock()
				if hasRouter || rsDone {
					t.Fatalf("RS emitted while expired state remained: router=%v done=%v", hasRouter, rsDone)
				}
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("RA deadline did not expire through the pump and restart solicitation")
}

func TestRAPumpExpiryWakesPendingUDP6Route(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	u, err := s.ListenUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if err := u.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	router := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	routerHW := [6]byte{2, 0, 0, 0, 0, 2}
	prefix := [16]byte{0xfd, 0, 0, 0xaa}
	route := [16]byte{0xfd, 0x1a, 0x81, 0x20}
	// No SLLA: the first write must block resolving the RIO next hop.
	if err := s.RecvInboundPacket(testRA6Frame(t, router, routerHW, 0,
		testPIO6(prefix, 64, 0x40, 60, 60), testRIO6(route, 64, 60))); err != nil {
		t.Fatal(err)
	}
	dst := route
	dst[15] = 9
	result := make(chan error, 1)
	go func() {
		_, err := u.WriteTo([]byte("wake"), &net.UDPAddr{IP: net.IP(dst[:]), Port: 5540})
		result <- err
	}()
	waitPendingNDP6(t, s, router)

	s.mu.Lock()
	s.v6.routes[0].until = s.now() + int64(25*time.Millisecond)
	s.notify()
	s.mu.Unlock()
	select {
	case err := <-result:
		if !errors.Is(err, errNoRoute6) {
			t.Fatalf("write after RIO expiry = %v, want %v", err, errNoRoute6)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pump expiry changed the route but did not wake its UDP6 waiter")
	}
}

func TestQueuedNADroppedAfterSLAACExpiry(t *testing.T) {
	const now = int64(time.Second)
	s, collector := newDormantIPv6Stack(now)
	global := installTestSLAAC(s.v6, [16]byte{0xfd, 0, 0, 0xaa}, now, now+int64(time.Second))
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	peerLL := llAddrFromMAC(peerHW)
	body := make([]byte, 28)
	copy(body[4:20], global[:])
	body[20], body[21] = ndpOptSourceLLA, 1
	copy(body[22:], peerHW[:])
	s.v6.ndp.recvNS(testICMP6(icmp6NeighborSolicit, 0, body), peerLL,
		solicitedNode(global), peerHW, s.v6.ourAddr6, now)
	if len(s.v6.ndp.replies) != 1 {
		t.Fatal("valid NS did not queue its NA")
	}

	s.drain6Locked(now + int64(time.Second))
	for _, f := range takeICMP6(t, collector) {
		if f.typ == icmp6NeighborAdvert {
			t.Fatal("queued NA advertised a SLAAC target after ownership expired")
		}
	}
	if len(s.v6.ndp.replies) != 0 {
		t.Fatal("stale queued NA was not discarded")
	}
}

func TestQueuedEchoPreservesAndRequiresOriginalLocalAddress(t *testing.T) {
	const now = int64(time.Second)
	s, collector := newDormantIPv6Stack(now)
	global := installTestSLAAC(s.v6, [16]byte{0xfd, 0, 0, 0xbb}, now, now+int64(time.Second))
	peerHW := [6]byte{2, 0, 0, 0, 0, 2}
	peerLL := llAddrFromMAC(peerHW)
	queue := func(at int64) {
		raw := testNDP6EthernetFrame(t, s.cfg.MAC, peerHW, peerLL, global,
			icmp6EchoRequest, 0, make([]byte, 4))
		eth, err := ParseEth(raw)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ParseIPv6(eth.Payload())
		if err != nil {
			t.Fatal(err)
		}
		s.recvIPv6(ip, peerHW, at)
	}

	queue(now)
	s.drain6Locked(now)
	found := false
	for _, f := range takeICMP6(t, collector) {
		if f.typ == icmp6EchoReply {
			found = true
			if f.src != global || f.dst != peerLL {
				t.Fatalf("echo reply tuple = %x -> %x, want %x -> %x", f.src, f.dst, global, peerLL)
			}
		}
	}
	if !found {
		t.Fatal("queued echo reply was not transmitted")
	}
	if cap(s.out6) > 0 && s.out6[:cap(s.out6)][0].pkt != nil {
		t.Fatal("drained IPv6 reply payload remained rooted in the reusable queue")
	}

	queue(now)
	s.drain6Locked(now + int64(time.Second))
	for _, f := range takeICMP6(t, collector) {
		if f.typ == icmp6EchoReply {
			t.Fatal("queued echo used an address after SLAAC ownership expired")
		}
	}
}

func TestRouterSolicitationStopsAfterBoundedCycle(t *testing.T) {
	table := newNDPTable([6]byte{2, 0, 0, 0, 0, 1}, 0)
	buf := make([]byte, 64)
	now := int64(0)
	for i := 0; i < ndpRSTries; i++ {
		e, ok := table.emitOwned(buf, now, nil)
		if !ok || e.icmpType != icmp6RouterSolicit {
			t.Fatalf("solicitation %d = %#v/%v", i+1, e, ok)
		}
		now += ndpRSIval
	}
	if e, ok := table.emitOwned(buf, now+int64(24*time.Hour), nil); ok {
		t.Fatalf("emitted after bounded RS cycle: %#v", e)
	}
	offered := false
	table.nextDeadline(func(int64) { offered = true })
	if offered {
		t.Fatal("bounded RS cycle left a deadline that roots the pump")
	}
}

func TestDrainClearsIPv4ConnectionlessPayloadReference(t *testing.T) {
	s, _ := newIPv6CoreStack(t)
	s.mu.Lock()
	s.out = append(s.out, outPkt{
		dst: [4]byte{203, 0, 113, 1}, proto: ProtoICMP,
		pkt: make([]byte, 64),
	})
	s.drainLocked()
	if len(s.out) != 0 || cap(s.out) == 0 || s.out[:cap(s.out)][0].pkt != nil {
		s.mu.Unlock()
		t.Fatal("drained IPv4 reply payload remained rooted in the reusable queue")
	}
	s.mu.Unlock()
}
