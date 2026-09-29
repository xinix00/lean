package leannet

import (
	"net"
	"testing"
	"time"
)

var mdnsGroup = [4]byte{224, 0, 0, 251}

func TestMulticastMACMapping(t *testing.T) {
	// RFC 1112 §6.4: 01:00:5e plus the low 23 bits — the top bit of the
	// second octet must vanish.
	cases := []struct {
		group [4]byte
		want  [6]byte
	}{
		{[4]byte{224, 0, 0, 251}, [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}},
		{[4]byte{239, 129, 1, 1}, [6]byte{0x01, 0x00, 0x5e, 0x01, 0x01, 0x01}},
		{[4]byte{224, 128, 255, 255}, [6]byte{0x01, 0x00, 0x5e, 0x00, 0xff, 0xff}},
	}
	for _, c := range cases {
		if got := multicastMAC(c.group); got != c.want {
			t.Errorf("multicastMAC(%v) = %x, want %x", c.group, got, c.want)
		}
	}
	if !isMulticastIP([4]byte{224, 0, 0, 1}) || !isMulticastIP([4]byte{239, 255, 255, 255}) {
		t.Error("edges of 224.0.0.0/4 not recognized")
	}
	if isMulticastIP([4]byte{223, 255, 255, 255}) || isMulticastIP([4]byte{240, 0, 0, 1}) {
		t.Error("neighbours of 224.0.0.0/4 wrongly recognized")
	}
}

func TestJoinScopeAndCap(t *testing.T) {
	a, _ := newStackPair(t, 1<<16, 1<<16)
	if err := a.JoinGroup([4]byte{10, 0, 0, 1}); err != errNotLinkLocalMulticast {
		t.Fatalf("unicast join error = %v, want %v", err, errNotLinkLocalMulticast)
	}
	// 239.x is multicast but not link-local: routable scope stays out.
	if err := a.JoinGroup([4]byte{239, 255, 255, 250}); err != errNotLinkLocalMulticast {
		t.Fatalf("routable multicast join error = %v, want %v", err, errNotLinkLocalMulticast)
	}
	// Het basisadres 224.0.0.0 wordt nooit aan een groep toegewezen
	// (RFC 1112 §4): rand van het blok, expliciet dicht.
	if err := a.JoinGroup([4]byte{224, 0, 0, 0}); err != errNotLinkLocalMulticast {
		t.Fatalf("base address join error = %v, want %v", err, errNotLinkLocalMulticast)
	}
	if err := a.JoinGroup(mdnsGroup); err != nil {
		t.Fatal(err)
	}
	if err := a.JoinGroup(mdnsGroup); err != nil { // idempotent, geen nesting
		t.Fatal(err)
	}
	a.mu.Lock()
	joined, n := a.joinedLocked(mdnsGroup), len(a.groups)
	a.mu.Unlock()
	if !joined || n != 1 {
		t.Fatalf("joined=%v groups=%d, want true/1", joined, n)
	}
	// De cap begrenst het aantal groepen (bounded memory).
	for i := byte(1); i < maxGroups; i++ {
		if err := a.JoinGroup([4]byte{224, 0, 0, i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.JoinGroup([4]byte{224, 0, 0, 200}); err != errGroupsFull {
		t.Fatalf("cap error = %v, want %v", err, errGroupsFull)
	}
	// Close geeft de set vrij en verdere joins weigeren netjes.
	a.Close()
	if err := a.JoinGroup(mdnsGroup); err != errStackClosed {
		t.Fatalf("join after close = %v, want %v", err, errStackClosed)
	}
	a.mu.Lock()
	freed := a.groups == nil
	a.mu.Unlock()
	if !freed {
		t.Fatal("groups not released on Close")
	}
}

// TestMulticastRefusals: TCP naar multicast weigert vóór er staat of draad
// aan te pas komt, en UDP weigert multicast buiten het link-local blok.
func TestMulticastRefusals(t *testing.T) {
	a, _ := newStackPair(t, 1<<16, 1<<16)
	if _, err := a.DialTCP([4]byte{224, 0, 0, 251}, 80, time.Now().Add(time.Second)); err == nil {
		t.Fatal("DialTCP accepted a multicast destination")
	}
	u, err := a.ListenUDP(5000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != errNotLinkLocalMulticast {
		t.Fatalf("routable multicast WriteTo = %v, want %v", err, errNotLinkLocalMulticast)
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(224, 0, 0, 0), Port: 5353}); err != errNotLinkLocalMulticast {
		t.Fatalf("base address WriteTo = %v, want %v", err, errNotLinkLocalMulticast)
	}
}

// TestMulticastSourceDropped: een pakket met een multicast-BRON is nooit
// geldig (RFC 1112 §7.2) en verdwijnt stil, ook op het unicast-pad.
func TestMulticastSourceDropped(t *testing.T) {
	a, b := newStackPair(t, 1<<16, 1<<16)
	_ = a
	if err := b.JoinGroup(mdnsGroup); err != nil {
		t.Fatal(err)
	}
	ub, err := b.ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	// Handgebouwd frame: geldige UDP naar de groep, maar bron = multicast.
	frame := make([]byte, EthernetHeaderSize+sizeIPv4+sizeUDP+4)
	eth, _ := ParseEth(frame)
	eth.SetDst(multicastMAC(mdnsGroup))
	eth.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	eth.SetEtherType(EtherTypeIPv4)
	src := [4]byte{224, 0, 0, 9}
	copy(frame[EthernetHeaderSize+sizeIPv4+sizeUDP:], "boom")
	PutUDP(frame[EthernetHeaderSize+sizeIPv4:], 5353, 5353, src, mdnsGroup, 4)
	PutIPv4(frame[EthernetHeaderSize:], ProtoUDP, src, mdnsGroup, sizeUDP+4)
	if err := b.RecvInboundPacket(frame); err != nil {
		t.Fatal(err)
	}
	ub.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _, err := ub.ReadFrom(buf); err == nil {
		t.Fatalf("delivered %q from a multicast source", buf[:n])
	}
	if got := b.Stats().DropBadFrame; got == 0 {
		t.Fatal("multicast source not counted as DropBadFrame")
	}
}

// TestMulticastEndToEnd sends from one stack to a group the peer joined and
// checks delivery, the sender's own loopback copy, and that leaving stops it.
func TestMulticastEndToEnd(t *testing.T) {
	a, b := newStackPair(t, 1<<16, 1<<16)

	if err := b.JoinGroup(mdnsGroup); err != nil {
		t.Fatal(err)
	}
	if err := a.JoinGroup(mdnsGroup); err != nil { // sender joins too: expects its own copy
		t.Fatal(err)
	}

	ub, err := b.ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	ua, err := a.ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	if _, err := ua.WriteTo([]byte("who has _matterc"), dst); err != nil {
		t.Fatal(err)
	}

	read := func(u *udpSock, tag string) {
		t.Helper()
		u.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 128)
		n, src, err := u.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		if string(buf[:n]) != "who has _matterc" {
			t.Fatalf("%s: payload %q", tag, buf[:n])
		}
		if sa, ok := src.(*net.UDPAddr); !ok || !sa.IP.Equal(net.IPv4(10, 0, 0, 1)) {
			t.Fatalf("%s: src = %v, want 10.0.0.1", tag, src)
		}
	}
	read(ub, "peer")     // over the wire
	read(ua, "loopback") // the sender's own copy

	// Een niet-gejoinde groep blijft stil: dezelfde probe naar 224.0.0.252
	// (wel geldig link-local, niemand lid) wordt genegeerd.
	if _, err := ua.WriteTo([]byte("anyone?"), &net.UDPAddr{IP: net.IPv4(224, 0, 0, 252), Port: 5353}); err != nil {
		t.Fatal(err)
	}
	ub.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 128)
	if n, _, err := ub.ReadFrom(buf); err == nil {
		t.Fatalf("received %q for a group nobody joined", buf[:n])
	}
}

// TestMulticastWireFormat inspects the transmitted frame: RFC 1112 MAC, the
// group as IP destination, TTL 255 with a valid header checksum, and no ARP.
func TestMulticastWireFormat(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	a := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW:     [4]byte{10, 0, 0, 254}, // a gateway that multicast must never use
		Budget: 1 << 16,
	}, 1)
	t.Cleanup(func() { a.Close() })

	u, err := a.ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		t.Fatal(err)
	}

	// The pump owns transmission; poll the peer device bounded by a deadline.
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, MTU+EthernetMaximumSize)
	var frame []byte
	for time.Now().Before(deadline) {
		if n, _ := db.Receive(buf); n > 0 {
			frame = buf[:n]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if frame == nil {
		t.Fatal("nothing transmitted")
	}
	eth, err := ParseEth(frame)
	if err != nil {
		t.Fatal(err)
	}
	if eth.EtherType() == EtherTypeARP {
		t.Fatal("multicast send emitted an ARP query")
	}
	if got := [6]byte(eth.Dst()); got != [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb} {
		t.Fatalf("dst MAC = %x", got)
	}
	ip, err := ParseIPv4(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if ip.Dst() != mdnsGroup {
		t.Fatalf("dst IP = %v", ip.Dst())
	}
	if ip[8] != 255 {
		t.Fatalf("TTL = %d, want 255 (RFC 6762 §11)", ip[8])
	}
	if !ip.ChecksumOK() {
		t.Fatal("header checksum invalid after the TTL patch")
	}
	da.mu.Lock()
	got := da.arpQueries
	da.mu.Unlock()
	if got != 0 {
		t.Fatalf("ARP queries = %d, want 0", got)
	}
}
