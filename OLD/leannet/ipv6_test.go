package leannet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// TestLinkLocalFromMAC pins the EUI-64 arithmetic to a known vector.
func TestLinkLocalFromMAC(t *testing.T) {
	got := llAddrFromMAC([6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	want := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01}
	if got != want {
		t.Fatalf("llAddrFromMAC = %x, want %x", got, want)
	}
	group := solicitedNode(want)
	if group != ([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 1}) {
		t.Fatalf("solicitedNode = %x", group)
	}
	if multicastMAC6(group) != ([6]byte{0x33, 0x33, 0xff, 0x00, 0x00, 0x01}) {
		t.Fatalf("multicastMAC6 = %x", multicastMAC6(group))
	}
}

// TestUDP6BetweenLinkLocalNeighbors proves the whole on-link path: the v6 lane
// enables on first use, NDP resolves the neighbor through solicited-node
// multicast, and UDP flows both ways with correct sources.
func TestUDP6BetweenLinkLocalNeighbors(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)

	lb, err := b.ListenUDP6(7777)
	if err != nil {
		t.Fatal(err)
	}
	bLL := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 2})
	da, err := a.DialUDP6(bLL, 7777)
	if err != nil {
		t.Fatal(err)
	}
	da.SetDeadline(time.Now().Add(5 * time.Second))
	lb.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := da.Write([]byte("ping6")); err != nil {
		t.Fatalf("v6 write: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := lb.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("ping6")) {
		t.Fatalf("v6 read = %q, %v", buf[:n], err)
	}
	ua := from.(*net.UDPAddr)
	aLL := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 1})
	if !ua.IP.Equal(net.IP(aLL[:])) {
		t.Fatalf("source = %v, want %v", ua.IP, net.IP(aLL[:]))
	}
	if _, err := lb.WriteTo([]byte("pong6"), from); err != nil {
		t.Fatalf("v6 reply: %v", err)
	}
	n, _, err = da.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("pong6")) {
		t.Fatalf("v6 reply read = %q, %v", buf[:n], err)
	}
}

// TestMDNS6GroupLoopbackAndDelivery mirrors the IPv4 multicast contract: a
// joined sender hears its own datagram and the peer receives it on the wire.
func TestMDNS6GroupLoopbackAndDelivery(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	mdns := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
	if err := a.JoinGroup6(mdns); err != nil {
		t.Fatal(err)
	}
	if err := b.JoinGroup6(mdns); err != nil {
		t.Fatal(err)
	}
	sa, err := a.ListenUDP6(5353)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.ListenUDP6(5353)
	if err != nil {
		t.Fatal(err)
	}
	sa.SetDeadline(time.Now().Add(5 * time.Second))
	sb.SetDeadline(time.Now().Add(5 * time.Second))

	to := &net.UDPAddr{IP: net.IP(mdns[:]), Port: 5353}
	if _, err := sa.WriteTo([]byte("query"), to); err != nil {
		t.Fatalf("multicast write: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := sb.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("query")) {
		t.Fatalf("peer multicast read = %q, %v", buf[:n], err)
	}
	n, _, err = sa.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("query")) {
		t.Fatalf("loopback multicast read = %q, %v", buf[:n], err)
	}
}

// putTestRA builds a router advertisement ethernet frame: SLLA + one
// autonomous on-link /64 + one RIO route, from a link-local router.
func putTestRA(routerLL [16]byte, routerMAC, dstMAC [6]byte, prefix, routePrefix [16]byte, lifetime uint16) []byte {
	body := make([]byte, 12+8+32+24)
	binary.BigEndian.PutUint16(body[2:4], lifetime)
	opt := body[12:]
	opt[0], opt[1] = ndpOptSourceLLA, 1
	copy(opt[2:8], routerMAC[:])
	pio := opt[8:]
	pio[0], pio[1] = ndpOptPrefixInfo, 4
	pio[2] = 64
	pio[3] = 0xc0 // on-link + autonomous
	binary.BigEndian.PutUint32(pio[4:8], 2592000)
	binary.BigEndian.PutUint32(pio[8:12], 604800)
	copy(pio[16:32], prefix[:])
	rio := pio[32:]
	rio[0], rio[1] = ndpOptRouteInfo, 3
	rio[2] = 64
	binary.BigEndian.PutUint32(rio[4:8], 3600)
	copy(rio[8:24], routePrefix[:])

	frame := make([]byte, sizeEth+sizeIPv6+4+len(body))
	eth := EthFrame(frame)
	eth.SetDst(dstMAC)
	eth.SetSrc(routerMAC)
	eth.SetEtherType(EtherTypeIPv6)
	n, _ := putNDP(frame[sizeEth+sizeIPv6:], icmp6RouterAdvert, body, routerLL, allNodes6)
	PutIPv6(frame[sizeEth:], ProtoICMPv6, hopLimitNDP, routerLL, allNodes6, n)
	return frame
}

// TestRouterAdvertisementFormsAddressAndRoute proves SLAAC and RFC 4191
// routing: after one RA, the stack owns a global address and reaches a ULA
// behind the router without any further resolution.
func TestRouterAdvertisementFormsAddressAndRoute(t *testing.T) {
	collector := &memDevice{}
	dev := &memDevice{peer: collector}
	collector.peer = dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20, AdvWS: 2,
	}, 99)
	defer s.Close()

	sock, err := s.ListenUDP6(0) // enables the lane
	if err != nil {
		t.Fatal(err)
	}
	sock.SetDeadline(time.Now().Add(5 * time.Second))

	routerLL := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	routerMAC := [6]byte{2, 0, 0, 0, 0, 0xee}
	prefix := [16]byte{0xfd, 0x00, 0x00, 0xaa}      // fd00:aa::/64, autonomous+on-link
	routePrefix := [16]byte{0xfd, 0x1a, 0x81, 0x20} // fd1a:8120::/64 via the router
	ra := putTestRA(routerLL, routerMAC, [6]byte{0x33, 0x33, 0, 0, 0, 1}, prefix, routePrefix, 1800)
	if err := s.RecvInboundPacket(ra); err != nil {
		t.Fatal(err)
	}

	// The SLAAC address is prefix + our EUI-64 interface id.
	wantAddr := prefix
	iid := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 1})
	copy(wantAddr[8:], iid[8:])
	s.mu.Lock()
	gotGlobal, has := s.v6.global, s.v6.hasGlobal
	s.mu.Unlock()
	if !has || gotGlobal != wantAddr {
		t.Fatalf("SLAAC address = %x (has=%v), want %x", gotGlobal, has, wantAddr)
	}

	// A ULA inside the advertised route goes straight to the router's MAC,
	// sourced from the SLAAC address.
	dst := routePrefix
	dst[15] = 0x05
	if _, err := sock.WriteTo([]byte("case-sigma1"), &net.UDPAddr{IP: net.IP(dst[:]), Port: 5540}); err != nil {
		t.Fatalf("routed v6 write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		collector.mu.Lock()
		var found []byte
		for _, f := range collector.q {
			eth, err := ParseEth(f)
			if err != nil || eth.EtherType() != EtherTypeIPv6 {
				continue
			}
			ip, err := ParseIPv6(eth.Payload())
			if err != nil || ip.NextHeader() != ProtoUDP {
				continue
			}
			if [6]byte(eth.Dst()) != routerMAC {
				t.Errorf("routed frame went to %x, want router %x", eth.Dst(), routerMAC)
			}
			if ip.Src() != wantAddr {
				t.Errorf("routed frame sourced from %x, want SLAAC %x", ip.Src(), wantAddr)
			}
			if ip.Dst() != dst {
				t.Errorf("routed frame to %x, want %x", ip.Dst(), dst)
			}
			found = f
		}
		collector.mu.Unlock()
		if found != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("routed v6 datagram never left the stack")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestV6WithoutRouterFailsFast proves the explicit-refusal contract: an
// off-link destination without any router is an immediate error, not a stall.
func TestV6WithoutRouterFailsFast(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	sock, err := a.ListenUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	ula := [16]byte{0xfd, 0x1a, 0x81, 0x20, 0, 0, 0, 1}
	_, err = sock.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IP(ula[:]), Port: 5540})
	if !errors.Is(err, errNoRoute6) {
		t.Fatalf("off-link without router = %v, want errNoRoute6", err)
	}
}

// TestNDPHopLimitEnforced drops NDP that crossed a router (RFC 4861 §3).
func TestNDPHopLimitEnforced(t *testing.T) {
	collector := &memDevice{}
	dev := &memDevice{peer: collector}
	collector.peer = dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20, AdvWS: 2,
	}, 7)
	defer s.Close()
	if _, err := s.ListenUDP6(0); err != nil {
		t.Fatal(err)
	}

	ourLL := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 1})
	srcLL := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99}
	body := make([]byte, 28)
	copy(body[4:20], ourLL[:])
	body[20], body[21] = ndpOptSourceLLA, 1
	copy(body[22:28], []byte{2, 0, 0, 0, 0, 0x99})

	frame := make([]byte, sizeEth+sizeIPv6+4+len(body))
	eth := EthFrame(frame)
	eth.SetDst([6]byte{2, 0, 0, 0, 0, 1})
	eth.SetSrc([6]byte{2, 0, 0, 0, 0, 0x99})
	eth.SetEtherType(EtherTypeIPv6)
	n, _ := putNDP(frame[sizeEth+sizeIPv6:], icmp6NeighborSolicit, body, srcLL, ourLL)
	PutIPv6(frame[sizeEth:], ProtoICMPv6, 64, srcLL, ourLL, n) // hop limit 64: crossed a router
	if err := s.RecvInboundPacket(frame); err != nil {
		t.Fatal(err)
	}
	if s.Stats().NDP.BadNDP == 0 {
		t.Fatal("NS with hop limit 64 was not counted as bad NDP")
	}
}

// TestSocketBoundaryUDP6 covers the SocketFunc seam: udp6 works, tcp6 refuses
// with ErrUnsupported so the net package reports it honestly.
func TestSocketBoundaryUDP6(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	_ = b
	c, err := a.Socket(nil, "udp6", afINET6, sockDGRAM, &net.UDPAddr{Port: 5540}, nil)
	if err != nil {
		t.Fatalf("udp6 listen through boundary: %v", err)
	}
	if u, ok := c.(*udpSock); !ok || !u.v6 || u.lport != 5540 {
		t.Fatalf("boundary returned %#v", c)
	}
	bLL := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 2})
	d, err := a.Socket(nil, "udp", afINET6, sockDGRAM, nil, &net.UDPAddr{IP: net.IP(bLL[:]), Port: 5540})
	if err != nil {
		t.Fatalf("udp dial v6 through boundary: %v", err)
	}
	if u, ok := d.(*udpSock); !ok || !u.v6 || !u.connected {
		t.Fatalf("boundary dial returned %#v", d)
	}
	if _, err := a.Socket(nil, "tcp6", afINET6, sockSTREAM, nil, &net.TCPAddr{IP: net.IP(bLL[:]), Port: 80}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("tcp6 = %v, want ErrUnsupported", err)
	}
}
