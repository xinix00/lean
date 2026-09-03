package leannet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memDevice struct {
	mu   sync.Mutex
	q    [][]byte
	peer *memDevice

	arpQueries int
}

func (d *memDevice) Transmit(buf []byte) error {
	if f, err := ParseEth(buf); err == nil && f.EtherType() == EtherTypeARP {
		if a, err := ParseARP(f.Payload()); err == nil && a.Op() == ARPRequest {
			d.mu.Lock()
			d.arpQueries++
			d.mu.Unlock()
		}
	}
	cp := append([]byte(nil), buf...)
	d.peer.mu.Lock()
	d.peer.q = append(d.peer.q, cp)
	d.peer.mu.Unlock()
	return nil
}

func (d *memDevice) Receive(buf []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.q) == 0 {
		return 0, nil
	}
	f := d.q[0]
	d.q = d.q[1:]
	return copy(buf, f), nil
}

func newStackPair(t *testing.T, budgetA, budgetB int) (a, b *Stack) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	a = NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: budgetA, AdvWS: 2,
	}, 12345)
	b = NewStack(db, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: budgetB, AdvWS: 2,
	}, 54321)
	stop := make(chan struct{})
	rx := func(s *Stack, d *memDevice) {
		buf := make([]byte, MTU+EthernetMaximumSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _ := d.Receive(buf)
			if n == 0 {
				time.Sleep(100 * time.Microsecond)
				continue
			}
			s.RecvInboundPacket(buf[:n])
		}
	}
	go rx(a, da)
	go rx(b, db)
	t.Cleanup(func() {
		close(stop)
		a.Close()
		b.Close()
	})
	return a, b
}

func TestStackTCPEchoEndToEnd(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)

	l, err := b.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	srvDone := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		if _, err := io.Copy(c, c); err != nil {
			srvDone <- err
			return
		}
		srvDone <- c.Close()
	}()

	c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 80, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 30000)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	go func() {
		c.Write(msg)

	}()
	got := make([]byte, 0, len(msg))
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < len(msg) {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo corrupted the stream")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("server: %v", err)
	}

	da := a.dev.(*memDevice)
	db := b.dev.(*memDevice)
	if db.arpQueries != 0 {
		t.Errorf("server needed %d ARP queries; passive learning is broken", db.arpQueries)
	}
	if da.arpQueries != 1 {
		t.Errorf("client sent %d ARP queries, want 1", da.arpQueries)
	}

	deadline := time.Now().Add(4 * time.Second)
	for {
		a.mu.Lock()
		freeA := a.pot.free()
		a.mu.Unlock()
		b.mu.Lock()
		freeB := b.pot.free()
		b.mu.Unlock()
		if freeA == 1<<20 && freeB == 1<<20 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("budget leaked: a free %d, b free %d, want %d", freeA, freeB, 1<<20)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStackUDPRoundtrip(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)

	srv, err := b.ListenUDP(53)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		n, addr, err := srv.ReadFrom(buf)
		if err != nil {
			return
		}
		srv.WriteTo(append([]byte("re:"), buf[:n]...), addr)
	}()

	cl, err := a.DialUDP([4]byte{10, 0, 0, 2}, 53)
	if err != nil {
		t.Fatal(err)
	}
	cl.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cl.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := cl.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "re:query" {
		t.Fatalf("got %q", buf[:n])
	}
	if la, ok := cl.LocalAddr().(*net.UDPAddr); !ok || la.Port < ephemeralBase {
		t.Fatalf("client port %v not in the ephemeral range", cl.LocalAddr())
	}
}

func TestStackReadDeadline(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(81)
	if err != nil {
		t.Fatal(err)
	}
	go l.Accept()

	c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 81, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	start := time.Now()
	_, err = c.Read(make([]byte, 16))
	elapsed := time.Since(start)
	if err != os.ErrDeadlineExceeded {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	var nerr net.Error
	if !errorsAs(err, &nerr) || !nerr.Timeout() {
		t.Fatal("deadline error is not a net.Error timeout")
	}
	if elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("deadline fired after %v", elapsed)
	}
}

func errorsAs(err error, target *net.Error) bool {
	if e, ok := err.(net.Error); ok {
		*target = e
		return true
	}
	return false
}

func TestStackBudgetRefusalSendsRST(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 0)

	if _, err := b.Listen(82); err != nil {
		t.Fatal(err)
	}
	_, err := a.DialTCP([4]byte{10, 0, 0, 2}, 82, time.Now().Add(2*time.Second))
	if err == nil {
		t.Fatal("dial succeeded against a stack with zero budget")
	}
	b.mu.Lock()
	refused := b.stats.RefusedNoBudget
	b.mu.Unlock()
	if refused == 0 {
		t.Fatal("refusal was silent: CntRefusedNoBudget == 0")
	}
}

func TestStackICMPEcho(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	b := NewStack(db, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 54321)
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, MTU+EthernetMaximumSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _ := db.Receive(buf)
			if n == 0 {
				time.Sleep(100 * time.Microsecond)
				continue
			}
			b.RecvInboundPacket(buf[:n])
		}
	}()
	t.Cleanup(func() { close(stop); b.Close() })
	frame := make([]byte, 128)
	eth, _ := ParseEth(frame)
	eth.SetDst([6]byte{2, 0, 0, 0, 0, 2})
	eth.SetSrc([6]byte{2, 0, 0, 0, 0, 1})
	eth.SetEtherType(EtherTypeIPv4)
	icmp := []byte{icmpEchoRequest, 0, 0, 0, 0, 42, 0, 7, 'p', 'i', 'n', 'g'}
	csum := checksum(icmp)
	icmp[2], icmp[3] = byte(csum>>8), byte(csum)
	copy(frame[EthernetHeaderSize+sizeIPv4:], icmp)
	PutIPv4(frame[EthernetHeaderSize:], ProtoICMP, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, len(icmp))
	da.Transmit(frame[:EthernetHeaderSize+sizeIPv4+len(icmp)])

	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 256)
	for time.Now().Before(deadline) {
		n, _ := da.Receive(buf)
		if n == 0 {
			time.Sleep(200 * time.Microsecond)
			continue
		}
		f, err := ParseEth(buf[:n])
		if err != nil || f.EtherType() != EtherTypeIPv4 {
			continue
		}
		ip, err := ParseIPv4(f.Payload())
		if err != nil || ip.Proto() != ProtoICMP {
			continue
		}
		reply := ip.Payload()
		if reply[0] == icmpEchoReply && bytes.Equal(reply[8:], []byte("ping")) {
			return
		}
	}
	t.Fatal("no echo reply within 2s")
}

func TestStackEphemeralSkipsOccupied(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)

	if _, err := s.ListenUDP(49153); err != nil {
		t.Fatal(err)
	}
	u1, err := s.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	p1 := u1.LocalAddr().(*net.UDPAddr).Port
	p2 := u2.LocalAddr().(*net.UDPAddr).Port
	if p1 != 49152 || p2 != 49154 {
		t.Fatalf("ephemeral picks = %d, %d; want 49152 and 49154 (49153 skipped)", p1, p2)
	}
}

func TestStackSeedNeighborSubnetRule(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: [4]byte{10, 0, 0, 254}, Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)

	if err := s.SeedNeighbor([4]byte{10, 0, 0, 7}, [6]byte{1}); err != nil {
		t.Fatalf("in-subnet seed refused: %v", err)
	}
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 254}, [6]byte{2}); err != nil {
		t.Fatalf("gateway seed refused: %v", err)
	}
	if err := s.SeedNeighbor([4]byte{192, 168, 1, 1}, [6]byte{3}); err == nil {
		t.Fatal("out-of-subnet seed accepted silently (lneto #21)")
	}
}

func TestStackSocketShapes(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)

	ctx := context.Background()

	lsAny, err := b.Socket(ctx, "tcp", afINET, sockSTREAM, &net.TCPAddr{Port: 90}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, ok := lsAny.(net.Listener)
	if !ok {
		t.Fatalf("listen returned %T, want net.Listener", lsAny)
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()

	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cAny, err := a.Socket(dctx, "tcp", afINET, sockSTREAM, nil,
		&net.TCPAddr{IP: net.IP{10, 0, 0, 2}, Port: 90})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cAny.(net.Conn); !ok {
		t.Fatalf("dial returned %T, want net.Conn", cAny)
	}
	cAny.(net.Conn).Close()

	pcAny, err := a.Socket(ctx, "udp", afINET, sockDGRAM, &net.UDPAddr{Port: 5353}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pcAny.(net.PacketConn); !ok {
		t.Fatalf("udp listen returned %T, want net.PacketConn", pcAny)
	}

	if v, err := a.Socket(ctx, "tcp", afINET6, sockSTREAM, nil, &net.TCPAddr{IP: net.IPv6loopback, Port: 1}); err == nil || v != nil {
		t.Fatalf("ipv6 returned (%v, %v), want (nil, error)", v, err)
	}

	fctx, fcancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer fcancel()
	v, err := a.Socket(fctx, "tcp", afINET, sockSTREAM, nil,
		&net.TCPAddr{IP: net.IP{10, 0, 0, 99}, Port: 1})
	if err == nil || v != nil {
		t.Fatalf("failed dial returned (%v, %v), want (nil, error)", v, err)
	}
}

func TestStackIdleHasNoProtocolDeadline(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)

	if _, err := s.Listen(80); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	d := s.nextDeadlineLocked()
	s.mu.Unlock()
	if d != 0 {
		t.Fatalf("idle stack with a listener has a pending deadline (%d); the pump would tick for nothing", d)
	}
}

func TestStackGarbageNeverPanics(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	if _, err := s.Listen(80); err != nil {
		t.Fatal(err)
	}

	x := uint64(0xdeadbeef)
	rnd := func() byte {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return byte(x)
	}
	frame := make([]byte, 200)
	fill := func(n int) []byte {
		for i := 0; i < n; i++ {
			frame[i] = rnd()
		}
		return frame[:n]
	}

	for _, n := range []int{0, 1, 13, 14, 15, 33, 60, 61, 200} {
		for i := 0; i < 50; i++ {
			s.RecvInboundPacket(fill(n))
		}
	}

	mkEth := func(payloadLen int) EthFrame {
		f, _ := ParseEth(frame[:EthernetHeaderSize+payloadLen])
		f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
		f.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
		f.SetEtherType(EtherTypeIPv4)
		return f
	}

	mkEth(sizeIPv4)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	frame[EthernetHeaderSize+10] ^= 0xff
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4])

	mkEth(sizeIPv4 + 8)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 8)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+8])

	mkEth(sizeIPv4 + sizeTCP)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100, nil,
		[4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	frame[EthernetHeaderSize+sizeIPv4+16] ^= 0xff
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+sizeTCP])

	mkEth(sizeIPv4 + sizeTCP + 4)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100,
		[]byte{2, 0, 0, 0}, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, sizeTCP+4)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+sizeTCP+4])

	f := mkEth(sizeARP)
	f.SetEtherType(EtherTypeARP)
	PutARP(frame[EthernetHeaderSize:], ARPRequest, [6]byte{9}, [4]byte{10, 0, 0, 9}, [6]byte{}, [4]byte{10, 0, 0, 1})
	frame[EthernetHeaderSize] = 0xff
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeARP])

	s.mu.Lock()
	bad, short, conns := s.stats.DropBadFrame, s.stats.DropShortFrame, len(s.conns)
	s.mu.Unlock()
	if bad == 0 || short == 0 {
		t.Fatalf("garbage was not counted: bad=%d short=%d", bad, short)
	}
	if conns != 0 {
		t.Fatalf("garbage created %d connections", conns)
	}
}

func TestStackListenerBacklogOverflow(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(88)
	if err != nil {
		t.Fatal(err)
	}
	const dials = tcpBacklog + 4
	conns := make([]net.Conn, 0, dials)
	for i := 0; i < dials; i++ {
		c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 88, time.Now().Add(3*time.Second))
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		b.mu.Lock()
		n := len(b.conns)
		b.mu.Unlock()
		if n == tcpBacklog {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("b holds %d conns, want exactly the backlog of %d", n, tcpBacklog)
		}
		time.Sleep(20 * time.Millisecond)
	}

	dead := 0
	for _, c := range conns {

		c.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && err != os.ErrDeadlineExceeded {
			dead++
		}
	}
	if dead != dials-tcpBacklog {
		t.Fatalf("%d overflow clients saw the RST, want exactly %d", dead, dials-tcpBacklog)
	}

	for i := 0; i < tcpBacklog; i++ {
		if _, err := l.Accept(); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}
	l.Close()
}

func TestStackBudgetRecovery(t *testing.T) {
	a, b := newStackPair(t, 1<<20, tcpFloorRing)
	l, err := b.Listen(89)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 4)
	release := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
			<-release
			c.Close()
		}
	}()
	c1, err := a.DialTCP([4]byte{10, 0, 0, 2}, 89, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("server never accepted the first connection")
	}

	if _, err := a.DialTCP([4]byte{10, 0, 0, 2}, 89, time.Now().Add(2*time.Second)); err == nil {
		t.Fatal("second dial succeeded against a full pot")
	}
	close(release)
	c1.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		c3, err := a.DialTCP([4]byte{10, 0, 0, 2}, 89, time.Now().Add(2*time.Second))
		if err == nil {
			c3.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("budget never recovered after close: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestStackEphemeralWraps(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)
	s.mu.Lock()
	s.nextEph = ephemeralEnd
	s.mu.Unlock()
	u1, err := s.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	p1 := u1.LocalAddr().(*net.UDPAddr).Port
	p2 := u2.LocalAddr().(*net.UDPAddr).Port
	if p1 != ephemeralEnd || p2 != ephemeralBase {
		t.Fatalf("wrap picks = %d, %d; want %d then %d", p1, p2, ephemeralEnd, ephemeralBase)
	}
}

func drainWire(d *memDevice) [][]byte {
	var out [][]byte
	buf := make([]byte, MTU+EthernetMaximumSize)
	for {
		n, _ := d.Receive(buf)
		if n == 0 {
			return out
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
}

func TestStackRoutesOffSubnetViaGateway(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	gwMAC := [6]byte{0xaa, 0xbb, 0xcc, 0, 0, 1}
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: [4]byte{10, 0, 0, 254}, Budget: 1 << 20,
	}, 3)
	t.Cleanup(s.Close)

	done := make(chan error, 1)
	go func() {
		_, err := s.DialTCP([4]byte{8, 8, 8, 8}, 443, time.Now().Add(3*time.Second))
		done <- err
	}()

	var asked bool
	deadline := time.Now().Add(2 * time.Second)
	for !asked && time.Now().Before(deadline) {
		for _, fr := range drainWire(db) {
			f, err := ParseEth(fr)
			if err != nil || f.EtherType() != EtherTypeARP {
				continue
			}
			a, err := ParseARP(f.Payload())
			if err != nil || a.Op() != ARPRequest {
				continue
			}
			target := [4]byte(a.TargetProto())
			if target == [4]byte{8, 8, 8, 8} {
				t.Fatal("stack ARP'd for an off-subnet address instead of the gateway")
			}
			if target == [4]byte{10, 0, 0, 254} {
				asked = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !asked {
		t.Fatal("no ARP request for the gateway")
	}

	reply := make([]byte, 60)
	ef, _ := ParseEth(reply)
	ef.SetDst(s.cfg.MAC)
	ef.SetSrc(gwMAC)
	ef.SetEtherType(EtherTypeARP)
	PutARP(reply[EthernetHeaderSize:], ARPReply, gwMAC, [4]byte{10, 0, 0, 254},
		s.cfg.MAC, [4]byte{10, 0, 0, 1})
	s.RecvInboundPacket(reply)

	var sawSYN bool
	deadline = time.Now().Add(2 * time.Second)
	for !sawSYN && time.Now().Before(deadline) {
		for _, fr := range drainWire(db) {
			f, err := ParseEth(fr)
			if err != nil || f.EtherType() != EtherTypeIPv4 {
				continue
			}
			ip, err := ParseIPv4(f.Payload())
			if err != nil || ip.Dst() != [4]byte{8, 8, 8, 8} {
				continue
			}
			if [6]byte(f.Dst()) != gwMAC {
				t.Fatalf("off-subnet frame went to %x, want the gateway MAC %x", f.Dst(), gwMAC)
			}
			tcpf, err := ParseTCP(ip.Payload())
			if err == nil && tcpf.Flags().Has(FlagSYN) {
				sawSYN = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawSYN {
		t.Fatal("no SYN towards the off-subnet peer after the gateway resolved")
	}

	if err := <-done; err == nil {
		t.Fatal("dial to a silent peer succeeded")
	}
}

func TestStackStaticGatewayMACSkipsARP(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	gwMAC := [6]byte{2, 0, 0, 0, 0, 99}
	s := NewStack(da, Config{
		IP: [4]byte{10, 100, 0, 5}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 5},
		GW: [4]byte{10, 100, 0, 1}, Budget: 1 << 20,
	}, 4)
	t.Cleanup(s.Close)
	if err := s.SeedNeighbor([4]byte{10, 100, 0, 1}, gwMAC); err != nil {
		t.Fatal(err)
	}
	go s.DialTCP([4]byte{1, 1, 1, 1}, 80, time.Now().Add(1*time.Second))

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		for _, fr := range drainWire(db) {
			f, err := ParseEth(fr)
			if err != nil {
				continue
			}
			if f.EtherType() == EtherTypeARP {
				t.Fatal("static gateway MAC still triggered ARP")
			}
			if [6]byte(f.Dst()) == gwMAC {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no frame towards the planned gateway MAC")
}

func TestStackUDPAccessors(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.ListenUDP(5555)
	if err != nil {
		t.Fatal(err)
	}
	if u.RemoteAddr() != nil {
		t.Error("unconnected socket reports a remote address")
	}
	if _, err := u.Write([]byte("x")); err == nil {
		t.Error("Write on an unconnected socket succeeded")
	}
	if la := u.LocalAddr().(*net.UDPAddr); la.Port != 5555 {
		t.Errorf("LocalAddr = %v", la)
	}
	if err := u.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.ReadFrom(make([]byte, 8)); err != os.ErrDeadlineExceeded {
		t.Errorf("ReadFrom err = %v, want deadline exceeded", err)
	}

	if err := u.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := u.WriteTo([]byte("x"), &net.TCPAddr{IP: net.IP{10, 0, 0, 2}, Port: 1}); err == nil {
		t.Error("WriteTo accepted a TCP address")
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IP{10, 0, 0, 2}, Port: -1}); err == nil {
		t.Error("WriteTo accepted a negative port")
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IP{10, 0, 0, 2}, Port: 65536}); err == nil {
		t.Error("WriteTo accepted port 65536")
	}
	u.Close()
	u.Close()
	if _, _, err := u.ReadFrom(make([]byte, 8)); err != net.ErrClosed {
		t.Errorf("ReadFrom after close = %v, want net.ErrClosed", err)
	}

	u2, err := a.ListenUDP(5555)
	if err != nil {
		t.Fatalf("rebind after close: %v", err)
	}
	u2.Close()
}

func TestStackListenerRejectsBusyPortAndReportsAddr(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	l, err := a.Listen(1234)
	if err != nil {
		t.Fatal(err)
	}
	if ta := l.Addr().(*net.TCPAddr); ta.Port != 1234 {
		t.Errorf("Addr = %v", ta)
	}
	if _, err := a.Listen(1234); err == nil {
		t.Error("second listen on a busy port succeeded")
	}
	l.Close()
	l2, err := a.Listen(1234)
	if err != nil {
		t.Fatalf("relisten after close: %v", err)
	}

	released := make(chan error, 1)
	go func() {
		_, err := l2.Accept()
		released <- err
	}()
	time.Sleep(20 * time.Millisecond)
	l2.Close()
	select {
	case err := <-released:
		if err != net.ErrClosed {
			t.Errorf("blocked Accept released with %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release a blocked Accept")
	}
	if _, err := l2.Accept(); err != net.ErrClosed {
		t.Errorf("Accept after close = %v, want net.ErrClosed", err)
	}
}

func TestStackFastReaderKeepsFullWindow(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(91)
	if err != nil {
		t.Fatal(err)
	}
	srvDone := make(chan int, 1)
	gemeten := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			srvDone <- -1
			return
		}

		n, _ := io.Copy(io.Discard, c)
		srvDone <- int(n)
		<-gemeten
		c.Close()
	}()

	c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 91, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 200<<10)
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := <-srvDone; got != len(payload) {
		t.Fatalf("server read %d of %d bytes", got, len(payload))
	}

	b.mu.Lock()
	for _, sc := range b.conns {
		if w := sc.tcp.rx.size(); w < 10*1460 {
			t.Fatalf("server receive window is %d bytes; a 10-segment initial burst (%d) does not fit, so bulk RX degrades to stop-and-wait",
				w, 10*1460)
		}
	}
	b.mu.Unlock()
	close(gemeten)
}

func TestStackSelfDial(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	self := [4]byte{10, 0, 0, 1}

	l, err := a.Listen(7000)
	if err != nil {
		t.Fatal(err)
	}
	srv := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			srv <- err
			return
		}
		_, err = io.Copy(c, c)
		c.Close()
		srv <- err
	}()

	c, err := a.DialTCP(self, 7000, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("self-dial failed: %v", err)
	}
	if la, ra := c.LocalAddr().String(), c.RemoteAddr().String(); la == ra {
		t.Fatalf("self-dial reused the same port on both ends: %s", la)
	}
	msg := []byte("talking to myself")
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo over loopback = %q", got)
	}
	c.Close()
	if err := <-srv; err != nil {
		t.Fatalf("server side: %v", err)
	}

	da := a.dev.(*memDevice)
	da.mu.Lock()
	queries := da.arpQueries
	da.mu.Unlock()
	if queries != 0 {
		t.Errorf("self-dial produced %d ARP queries on the wire; nobody answers 'who has myself'", queries)
	}
}

func TestStackSelfDialRefused(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	start := time.Now()
	_, err := a.DialTCP([4]byte{10, 0, 0, 1}, 7001, time.Now().Add(3*time.Second))
	if err == nil {
		t.Fatal("dial to an unbound own port succeeded")
	}
	if err == errUnreachable {
		t.Fatalf("self-dial reported %v; that points the operator at ARP and the switch", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("refusal took %v — should be immediate, not an ARP timeout", elapsed)
	}
}

func TestStackSelfDialUDP(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	srv, err := a.ListenUDP(7002)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 256)
		n, addr, err := srv.ReadFrom(buf)
		if err == nil {
			srv.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	cl, err := a.DialUDP([4]byte{10, 0, 0, 1}, 7002)
	if err != nil {
		t.Fatal(err)
	}
	cl.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cl.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := cl.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("udp loopback = %q", buf[:n])
	}
}

func TestStackClosedPortRefusesFast(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	if _, err := b.Listen(6000); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := a.DialTCP([4]byte{10, 0, 0, 2}, 6001, time.Now().Add(3*time.Second))
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("closed port took %v to refuse — the peer sent no RST", elapsed)
	}
}

func TestStackRSTStormResistance(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 5)
	t.Cleanup(s.Close)
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 9}, [6]byte{2, 0, 0, 0, 0, 9}); err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 60)
	eth, _ := ParseEth(frame)
	eth.SetDst(s.cfg.MAC)
	eth.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	eth.SetEtherType(EtherTypeIPv4)
	n, _ := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 1234, 80, 500, 0, FlagRST, 0, nil,
		[4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, n)
	drainWire(db)
	s.RecvInboundPacket(frame)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		for _, fr := range drainWire(db) {
			f, err := ParseEth(fr)
			if err != nil || f.EtherType() != EtherTypeIPv4 {
				continue
			}
			ip, err := ParseIPv4(f.Payload())
			if err != nil || ip.Proto() != ProtoTCP {
				continue
			}
			if tf, err := ParseTCP(ip.Payload()); err == nil && tf.Flags().Has(FlagRST) {
				t.Fatal("answered a RST with a RST — that is a storm between two strangers")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStackBroadcastGaatNaarFFFF(t *testing.T) {
	for _, tc := range []struct {
		naam string
		dst  [4]byte
	}{
		{"limited", [4]byte{255, 255, 255, 255}},
		{"subnet-directed", [4]byte{10, 0, 0, 255}},
	} {
		t.Run(tc.naam, func(t *testing.T) {
			da, db := &memDevice{}, &memDevice{}
			da.peer, db.peer = db, da
			s := NewStack(da, Config{
				IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
				GW: [4]byte{10, 0, 0, 254}, Budget: 1 << 20,
			}, 7)
			t.Cleanup(s.Close)

			u, err := s.ListenUDP(68)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := u.WriteTo([]byte("REQUEST"), &net.UDPAddr{IP: net.IP(tc.dst[:]), Port: 67}); err != nil {
				t.Fatalf("broadcast weigerde: %v", err)
			}

			var seen bool
			deadline := time.Now().Add(2 * time.Second)
			for !seen && time.Now().Before(deadline) {
				for _, fr := range drainWire(db) {
					f, err := ParseEth(fr)
					if err != nil {
						continue
					}
					if f.EtherType() == EtherTypeARP {
						a, err := ParseARP(f.Payload())
						if err == nil && a.Op() == ARPRequest {
							t.Fatalf("stack ARP'de voor %v — een broadcastadres bezit niemand", a.TargetProto())
						}
						continue
					}
					if f.EtherType() != EtherTypeIPv4 {
						continue
					}
					ip, err := ParseIPv4(f.Payload())
					if err != nil || ip.Proto() != ProtoUDP || ip.Dst() != tc.dst {
						continue
					}
					if [6]byte(f.Dst()) != bcastMAC {
						t.Fatalf("broadcast ging naar %x, want ff:ff:ff:ff:ff:ff", f.Dst())
					}
					seen = true
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !seen {
				t.Fatal("geen broadcast-datagram op de draad")
			}
		})
	}
}

func TestIsBroadcastIP(t *testing.T) {
	ip := [4]byte{10, 0, 0, 1}
	for _, tc := range []struct {
		dst    [4]byte
		prefix int
		want   bool
	}{
		{[4]byte{255, 255, 255, 255}, 24, true},
		{[4]byte{255, 255, 255, 255}, 32, true},
		{[4]byte{10, 0, 0, 255}, 24, true},
		{[4]byte{10, 0, 255, 255}, 16, true},
		{[4]byte{10, 0, 0, 255}, 16, false},
		{[4]byte{10, 0, 0, 2}, 24, false},
		{[4]byte{10, 0, 1, 255}, 24, false},
		{[4]byte{10, 0, 0, 1}, 31, false},
		{[4]byte{10, 0, 0, 1}, 32, false},
		{[4]byte{192, 168, 1, 255}, 24, false},
	} {
		if got := isBroadcastIP(tc.dst, ip, tc.prefix); got != tc.want {
			t.Errorf("isBroadcastIP(%v, /%d) = %v, want %v", tc.dst, tc.prefix, got, tc.want)
		}
	}
}

func TestStackSelfDialMeerdereRondes(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	self := [4]byte{10, 0, 0, 1}

	l, err := a.Listen(7100)
	if err != nil {
		t.Fatal(err)
	}
	srv := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			srv <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, werr := c.Write(append([]byte("re:"), buf[:n]...)); werr != nil {
					srv <- werr
					return
				}
			}
			if err != nil {
				srv <- nil
				return
			}
		}
	}()

	c, err := a.DialTCP(self, 7100, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("self-dial: %v", err)
	}
	defer c.Close()

	for i := range 10 {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		msg := fmt.Appendf(nil, "ronde-%d", i)
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("ronde %d: write: %v", i, err)
		}
		want := append([]byte("re:"), msg...)
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("ronde %d: lezen na %d geslaagde rondes: %v", i, i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ronde %d: %q, want %q", i, got, want)
		}
	}
}

func TestStackPeerHerstartZelfdeVierTupel(t *testing.T) {
	const budget = 1 << 20
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	cfgA := Config{IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1}, Budget: budget, AdvWS: 2}
	cfgB := Config{IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2}, Budget: budget, AdvWS: 2}
	a := NewStack(da, cfgA, 12345)
	b := NewStack(db, cfgB, 54321)

	stop := make(chan struct{})
	pump := func(s *Stack, d *memDevice) {
		buf := make([]byte, MTU+EthernetMaximumSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if n, _ := d.Receive(buf); n > 0 {
				s.RecvInboundPacket(buf[:n])
				continue
			}
			time.Sleep(100 * time.Microsecond)
		}
	}
	go pump(a, da)
	go pump(b, db)
	defer close(stop)
	defer b.Close()

	server, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := server.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	first, err := a.DialTCP(cfgB.IP, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("eerste verbinding: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server accepteerde de eerste verbinding niet")
	}
	port1 := first.LocalAddr().(*net.TCPAddr).Port

	a.Close()
	<-time.After(50 * time.Millisecond)

	da2 := &memDevice{}
	da2.peer, db.peer = db, da2
	a2 := NewStack(da2, cfgA, 999)
	defer a2.Close()
	go pump(a2, da2)

	second, err := a2.DialTCP(cfgB.IP, 90, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("herstarte peer kon niet opnieuw verbinden: %v", err)
	}
	defer second.Close()
	if port2 := second.LocalAddr().(*net.TCPAddr).Port; port2 != port1 {
		t.Fatalf("bronpoort %d, wil %d — deze test bewijst alleen iets als het "+
			"vier-tupel écht hetzelfde is", port2, port1)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server accepteerde de tweede verbinding niet")
	}
	if _, err := second.Write([]byte("hallo")); err != nil {
		t.Fatalf("schrijven over de nieuwe verbinding: %v", err)
	}
}

func TestStackIdleVerbindingGeeftBuffersTerug(t *testing.T) {
	const budget = 512 << 10
	a, b := newStackPair(t, budget, budget)

	listener, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			server <- c
		}
	}()

	client, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	srv := <-server
	defer srv.Close()

	payload := make([]byte, 300<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		done <- err
	}()
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 32<<10)
	srv.SetReadDeadline(time.Now().Add(15 * time.Second))
	for len(got) < len(payload) {
		n, err := srv.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("lezen na %d van %d bytes: %v", len(got), len(payload), err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("schrijven: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("data kwam beschadigd aan")
	}

	// Sinds de RX-groei op volle segmenten (tcp.go) draagt een gegroeide
	// ontvanger een venster-BELOFTE die de pot pint zolang de verbinding
	// idle openstaat — de belofte mag niet naar links (RFC 9293).
	// "Snel heeft altijd een eind": de verbinding die groeide
	// hoort te SLUITEN (de leanhttp-pool sluit gegroeide verbindingen,
	// client.go put; trage stromen groeien nooit en poolen gewoon). De
	// invariant is dus: bij close komt álles per direct terug in de pot.
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
	const slack = tcpFloorRing
	deadline := time.Now().Add(5 * time.Second)
	for {
		freeA, freeB := a.pot.free(), b.pot.free()
		if freeA >= budget-slack && freeB >= budget-slack {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pot niet teruggestort ná close: zender %d van %d vrij, ontvanger %d van %d "+
				"— een gesloten verbinding houdt zijn gegroeide buffers vast",
				freeA, budget, freeB, budget)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Een nieuwe verbinding over dezelfde stack bewijst dat de pot na de
	// teruggave gewoon bruikbaar is (de oude na-krimp-echo kan niet meer:
	// de gegroeide verbinding is per het model hierboven gesloten).
	go func() {
		c, err := listener.Accept()
		if err == nil {
			server <- c
		}
	}()
	second, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("verse verbinding na teruggave: %v", err)
	}
	defer second.Close()
	srv2 := <-server
	defer srv2.Close()
	if _, err := second.Write([]byte("terug")); err != nil {
		t.Fatalf("schrijven na teruggave: %v", err)
	}
	echo := make([]byte, 5)
	srv2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(srv2, echo); err != nil {
		t.Fatalf("lezen na teruggave: %v", err)
	}
	if string(echo) != "terug" {
		t.Fatalf("na teruggave kwam %q terug", echo)
	}
}

func TestStackRSTOpLosseAckIsKaal(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	if err := s.SeedNeighbor([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 256)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	tcpLen, err := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 5555, 7, 123, 777, FlagACK, 512, nil, src, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, dst, tcpLen); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+tcpLen]); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 256)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := capture.Receive(buf)
		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		eth, err := ParseEth(buf[:n])
		if err != nil || eth.EtherType() != EtherTypeIPv4 {
			continue
		}
		ip, err := ParseIPv4(eth.Payload())
		if err != nil || ip.Proto() != ProtoTCP {
			continue
		}
		f, err := ParseTCP(ip.Payload())
		if err != nil {
			continue
		}
		if !f.Flags().Has(FlagRST) {
			t.Fatalf("antwoord draagt geen RST: vlaggen %v", f.Flags())
		}
		if f.Flags().Has(FlagACK) {
			t.Fatal("RST op een losse ACK draagt de ACK-vlag — een strikte SYN-SENT-peer gooit hem dan weg")
		}
		if got := f.Seq(); got != 777 {
			t.Fatalf("RST-seq = %d, wil SEG.ACK (777)", got)
		}
		return
	}
	t.Fatal("geen RST gezien op de draad")
}

func TestStackZonderGatewayFaaltMeteen(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	start := time.Now()
	_, err := s.DialTCP([4]byte{192, 168, 1, 1}, 80, time.Now().Add(10*time.Second))
	if err == nil {
		t.Fatal("dial buiten het subnet zonder gateway hoort te falen")
	}
	if !strings.Contains(err.Error(), "no gateway") {
		t.Fatalf("fout zegt niet wat er mis is: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("dial deed er %v over — dit hoort een onmiddellijk antwoord te zijn, geen deadline-wacht", d)
	}

	u, err := s.DialUDP([4]byte{192, 168, 1, 1}, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetWriteDeadline(time.Now().Add(10 * time.Second))
	start = time.Now()
	if _, err := u.Write([]byte("query")); err == nil {
		t.Fatal("udp-write buiten het subnet zonder gateway hoort te falen")
	} else if !strings.Contains(err.Error(), "no gateway") {
		t.Fatalf("fout zegt niet wat er mis is: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("udp-write deed er %v over — hoort onmiddellijk te zijn", d)
	}
}

func TestSockCloseDeblokkeerRead(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	select {
	case err := <-got:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read na Close gaf %v, wil net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close deblokkeerde de wachtende Read niet")
	}
}

func TestSockDeadlineRaaktLopendeRead(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(91)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 91, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	select {
	case err := <-got:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read gaf %v, wil een timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("de nieuw gezette deadline bereikte de lopende Read niet")
	}
}

func TestStackCloseSluitAlles(t *testing.T) {
	const budget = 1 << 20
	a, b := newStackPair(t, budget, budget)

	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	acceptErr := make(chan error, 1)
	go func() {
		for {
			_, err := l.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
		}
	}()
	u, err := b.ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := u.ReadFrom(buf)
		readErr <- err
	}()

	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	b.Close()

	for name, ch := range map[string]chan error{"Accept": acceptErr, "ReadFrom": readErr} {
		select {
		case err := <-ch:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s na Stack.Close gaf %v, wil net.ErrClosed", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s bleef hangen na Stack.Close", name)
		}
	}
	b.mu.Lock()
	used, conns := b.pot.used, len(b.conns)
	b.mu.Unlock()
	if used != 0 || conns != 0 {
		t.Fatalf("na Close: pot draagt nog %d bytes, %d verbindingen — niet alles is teruggegeven", used, conns)
	}
}

func TestStackCloseLaatGeenDynamischeProtocolopslagHangen(t *testing.T) {
	dev, peer := &memDevice{}, &memDevice{}
	dev.peer, peer.peer = peer, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)

	// Model the bounded high-water state that can still be queued when Close
	// wins before the pump's final drain.
	s.mu.Lock()
	s.arp.cnt.GaveUp = 7
	s.arp.entries[[4]byte{10, 0, 0, 9}] = &neighborEntry{
		state: neighborResolved, mac: [6]byte{2, 0, 0, 0, 0, 9},
	}
	s.arp.replies = append(s.arp.replies, arpReply{ip: [4]byte{10, 0, 0, 9}})
	s.groups = map[[4]byte]struct{}{{224, 0, 0, 251}: {}}
	s.out = append(s.out, outPkt{pkt: make([]byte, 1024)})
	s.loopback = append(s.loopback, make([]byte, MTU))
	s.lbFree = append(s.lbFree, make([]byte, MTU))

	v6 := &v6State{
		ll:       llAddrFromMAC(s.cfg.MAC),
		ndp:      newNDPTable(s.cfg.MAC, s.now()),
		udp:      newUDPTable(),
		groups:   map[[16]byte]struct{}{allNodes6: {}},
		prefixes: []v6prefix{{prefix: [16]byte{0xfd}, bits: 64, onLink: true}},
		routes:   []v6route{{prefix: [16]byte{0xfd}, bits: 64}},
	}
	v6.ndp.cnt.GaveUp = 11
	v6.ndp.entries[[16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1}] = &neighborEntry{
		state: neighborResolved, mac: [6]byte{2, 0, 0, 0, 0, 10},
	}
	v6.ndp.replies = append(v6.ndp.replies, ndpReply{target: v6.ll})
	s.v6 = v6
	s.out6 = append(s.out6, outPkt6{pkt: make([]byte, 1024)})
	s.mu.Unlock()

	s.Close()

	s.mu.Lock()
	retained := s.dev != nil || s.arp != nil || s.v6 != nil || s.udp != nil ||
		s.conns != nil || s.listeners != nil || s.groups != nil || s.out != nil ||
		s.out6 != nil || s.loopback != nil || s.lbFree != nil || s.txBuf != nil
	used := s.pot.used
	s.mu.Unlock()
	if retained {
		t.Fatal("gesloten Stack behield dynamische protocolopslag")
	}
	if used != 0 {
		t.Fatalf("gesloten Stack behield %d bytes bufferbudget", used)
	}
	stats := s.Stats()
	if stats.ARP.GaveUp != 7 || stats.NDP.GaveUp != 11 {
		t.Fatalf("Close verloor telemetry: ARP=%+v NDP=%+v", stats.ARP, stats.NDP)
	}
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 9}, [6]byte{2, 0, 0, 0, 0, 9}); !errors.Is(err, errStackClosed) {
		t.Fatalf("SeedNeighbor na Close gaf %v, wil errStackClosed", err)
	}
	s.Close() // teardown remains idempotent after dropping its internal tables
}

func TestStackListenerCloseRuimtEmbryosOp(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()
	l, err := s.Listen(90)
	if err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 256)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	n, err := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 49152, 90, 7000, 0, FlagSYN, 1024, nil, src, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, dst, n); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+n]); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	embryos := len(s.conns)
	s.mu.Unlock()
	if embryos != 1 {
		t.Fatalf("%d verbindingen na de SYN, wil 1 embryo", embryos)
	}

	l.Close()
	s.mu.Lock()
	left, used := len(s.conns), s.pot.used
	s.mu.Unlock()
	if left != 0 || used != 0 {
		t.Fatalf("na listener.Close: %d embryo's over, pot draagt %d — de halve handshake bleef staan", left, used)
	}
}

func TestTCPFinWait2Timeout(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()

	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if w.a.state != tcpFinWait2 {
		t.Fatalf("a is %s, wil FIN-WAIT-2", w.a.state)
	}

	w.advance(time.Duration(tcpFinWait2Dur) + time.Second)
	segs := w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a is na de timeout nog %s — FIN-WAIT-2 heeft geen einde", w.a.state)
	}
	rst := false
	for _, seg := range segs {
		if seg.flags.Has(FlagRST) {
			rst = true
		}
	}
	if !rst {
		t.Fatal("geen RST bij het opgeven van FIN-WAIT-2 — de peer hoort te weten dat wij weg zijn")
	}
}

func TestTCPFullCloseDeadlineRuimtEndToEndOp(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := l.Accept()
		if acceptErr == nil {
			accepted <- c
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	srv := <-accepted
	defer srv.Close()

	client := conn.(*tcpSock)
	a.mu.Lock()
	key := client.c.key
	beforeBudget := a.pot.used
	// Model a live peer advertising zero without filling its receive buffer.
	// FIN must then wait in persist, while the peer socket can block in Read.
	client.c.tcp.sndWnd = 0
	a.mu.Unlock()

	if err := srv.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	readStarted := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		close(readStarted)
		_, readErrValue := srv.Read(make([]byte, 1))
		readErr <- readErrValue
	}()
	<-readStarted

	beforeClose := a.now()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	afterClose := a.now()

	a.mu.Lock()
	closeDeadline := client.c.tcp.closeDeadline
	_, retained := a.conns[key]
	retainedBudget := a.pot.used
	a.mu.Unlock()
	if closeDeadline < beforeClose+tcpFullCloseDur || closeDeadline > afterClose+tcpFullCloseDur {
		t.Fatalf("full Close deadline %d ligt niet exact %v na Close [%d,%d]",
			closeDeadline, time.Duration(tcpFullCloseDur), beforeClose, afterClose)
	}
	if !retained || retainedBudget != tcpFloorTx || retainedBudget >= beforeBudget {
		t.Fatalf("voor expiry: retained=%v budget=%d (voor Close %d), wil alleen TX-vloer %d",
			retained, retainedBudget, beforeBudget, tcpFloorTx)
	}
	select {
	case err := <-readErr:
		t.Fatalf("peer-Read eindigde vóór de full-Close deadline: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	// Gerichte timerseam: de pure-machine test controleert de volledige 20s en
	// niet-verlengbaarheid; hier maken we alleen de reeds ingestelde deadline due.
	// notify must wake the sleeping pump and drive the whole stack path.
	a.mu.Lock()
	client.c.tcp.closeDeadline = a.now() - 1
	a.notify()
	a.mu.Unlock()

	select {
	case err := <-readErr:
		if !errors.Is(err, errTCPReset) {
			t.Fatalf("geblokkeerde peer-Read na cleanup gaf %v, wil TCP reset", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RST na de full-Close deadline wekte de peer-Read niet")
	}

	wallDeadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		_, retained = a.conns[key]
		retainedBudget = a.pot.used
		queued := len(a.out)
		a.mu.Unlock()
		if !retained && retainedBudget == 0 && queued == 0 {
			break
		}
		if time.Now().After(wallDeadline) {
			t.Fatalf("na expiry: retained=%v budget=%d queued=%d",
				retained, retainedBudget, queued)
		}
		time.Sleep(time.Millisecond)
	}

	b.mu.Lock()
	peerConns, peerBudget := len(b.conns), b.pot.used
	b.mu.Unlock()
	if peerConns != 0 || peerBudget != 0 {
		t.Fatalf("peer hield na RST %d verbinding(en) en %d budget vast", peerConns, peerBudget)
	}
}

func TestStackDialAnnuleerbaar(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	got := make(chan error, 1)
	go func() {

		_, err := s.Socket(ctx, "tcp", afINET, sockSTREAM, nil,
			&net.TCPAddr{IP: net.IP{10, 0, 0, 99}, Port: 80})
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("geannuleerde dial gaf een verbinding")
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("dial keerde pas na %v terug — de cancel deed niets", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial negeerde de cancel volledig")
	}

	s.mu.Lock()
	used, conns := s.pot.used, len(s.conns)
	s.mu.Unlock()
	if used != 0 || conns != 0 {
		t.Fatalf("na de cancel: pot %d, conns %d — de geannuleerde dial liet iets achter", used, conns)
	}
}

func TestSockStaartLezenDanSluiten(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srvc := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			srvc <- c
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	srv := <-srvc

	if _, err := srv.Write([]byte("staart")); err != nil {
		t.Fatal(err)
	}
	srv.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "staart" {
		t.Fatalf("staart-read gaf %q, %v — CLOSE-WAIT hoort de staart te bewaren", buf[:n], err)
	}
	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("read na de staart gaf %v, wil io.EOF", err)
	}

	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		conns, used := len(a.conns), a.pot.used
		a.mu.Unlock()
		if conns == 0 && used == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("na Close: %d verbindingen, pot %d — reap kwam niet of gaf niet alles terug", conns, used)
		}
		time.Sleep(20 * time.Millisecond)
	}

	sock := conn.(*tcpSock)
	if sock.c.tcp.rx.size() != 0 || sock.c.tcp.tx.size() != 0 {
		t.Fatalf("gereapte verbinding draagt nog buffers (rx %d, tx %d)",
			sock.c.tcp.rx.size(), sock.c.tcp.tx.size())
	}
}

func TestStackReapWektGeblokkeerdeRead(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)

	sock := conn.(*tcpSock)
	a.mu.Lock()
	sock.c.tcp.abort()
	a.reap(sock.c.key, sock.c)
	a.mu.Unlock()

	select {
	case err := <-got:
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read gaf %v, wil de reset-fout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reap wekte de geblokkeerde Read niet")
	}
}

func TestStackRouteDoodBreektDeVerbinding(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(30 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	time.Sleep(100 * time.Millisecond)

	a.mu.Lock()
	a.dev.(*memDevice).peer = &memDevice{}
	delete(a.arp.entries, [4]byte{10, 0, 0, 2})
	a.mu.Unlock()
	b.mu.Lock()
	b.dev.(*memDevice).peer = &memDevice{}
	b.mu.Unlock()

	if _, err := conn.Write([]byte("de leegte in")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 16)
	start := time.Now()
	_, err = conn.Read(buf)
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read gaf %v — de verbinding hoort te breken als de route luid dood is", err)
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Fatalf("het duurde %v — dat is de deadline, niet de route-dood", d)
	}
}

func TestStackAcceptNaCloseGeeftNooitEenVerbinding(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	b.Close()
	for i := 0; i < 32; i++ {
		c, err := l.Accept()
		if err == nil {
			t.Fatalf("Accept #%d gaf een verbinding ná Stack.Close (%v)", i, c.RemoteAddr())
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept gaf %v, wil net.ErrClosed", err)
		}
	}
}

func TestStackSynRstMaaktGeenVerbinding(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()
	l, err := s.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	frame := make([]byte, 256)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	n, err := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 49152, 90, 7000, 0,
		FlagSYN|FlagRST, 1024, nil, src, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, dst, n); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+n]); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	conns, used := len(s.conns), s.pot.used
	s.mu.Unlock()
	if conns != 0 || used != 0 {
		t.Fatalf("SYN|RST maakte %d verbinding(en), pot %d — hoort genegeerd te worden", conns, used)
	}
}

func TestStackOffSubnetEmbryoSterft(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()
	l, err := s.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	frame := make([]byte, 256)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 9})
	frame[12], frame[13] = 0x08, 0x00
	src, dst := [4]byte{192, 168, 1, 9}, [4]byte{10, 0, 0, 2}
	n, err := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 49152, 90, 7000, 0,
		FlagSYN, 1024, nil, src, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, dst, n); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+n]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		conns, used := len(s.conns), s.pot.used
		s.mu.Unlock()
		if conns == 0 && used == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("embryo zonder route leeft nog: %d verbinding(en), pot %d — de zombie-klasse", conns, used)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStackDialZegtNoRouteNietTimeout(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	_, err := s.DialTCP([4]byte{10, 0, 0, 99}, 80, time.Now().Add(20*time.Second))
	if err == nil {
		t.Fatal("dial naar een dode buur slaagde")
	}
	if err != errUnreachable {
		t.Fatalf("dial gaf %q, wil %q — de fout hoort naar de route te wijzen", err, errUnreachable)
	}
}

func TestStackVolleLoopbackIsGeenSucces(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	s.mu.Lock()
	for len(s.loopback) < loopbackMax {
		s.loopback = append(s.loopback, []byte{0})
	}
	drops := s.stats.DropReplyFull
	err := s.sendEthLocked(s.cfg.MAC, EtherTypeIPv4, 32)
	gotDrops := s.stats.DropReplyFull
	s.mu.Unlock()

	if err == nil {
		t.Fatal("sendEthLocked op een volle loopback meldde succes — het pakket ligt nergens")
	}
	if gotDrops != drops+1 {
		t.Fatalf("drop niet geteld: %d → %d", drops, gotDrops)
	}
}

func TestSockDeadlineVerlengenEnWissen(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(10 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond)
	conn.SetReadDeadline(time.Time{})

	select {
	case err := <-got:
		t.Fatalf("Read keerde terug (%v) op een deadline die gewist was", err)
	case <-time.After(400 * time.Millisecond):
	}

	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	select {
	case err := <-got:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read gaf %v, wil een timeout op de nieuwe deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("de vervroegde deadline bereikte de Read niet")
	}
}

func TestStackCtxDeadlineGeeftContextfout(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		_, err := s.Socket(ctx, "tcp", afINET, sockSTREAM, nil,
			&net.TCPAddr{IP: net.IP{10, 0, 0, 99}, Port: 80})
		cancel()
		if err == nil {
			t.Fatal("dial naar een dode buur slaagde")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("poging %d: fout is %v, wil context.DeadlineExceeded", i, err)
		}
	}
}

func TestStackRSTAckTeltSegLen(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}

	send := func(flags TCPFlags, data []byte, seq uint32) {
		frame := make([]byte, 256)
		copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2})
		copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
		frame[12], frame[13] = 0x08, 0x00
		src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
		off := EthernetHeaderSize + sizeIPv4
		copy(frame[off+sizeTCP:], data)
		n, err := PutTCP(frame[off:], 5555, 7, seq, 0, flags, 512, nil, src, dst, len(data))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, dst, n); err != nil {
			t.Fatal(err)
		}
		if err := s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+n]); err != nil {
			t.Fatal(err)
		}
	}
	expectAck := func(want uint32) {
		t.Helper()
		buf := make([]byte, 256)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			n, _ := capture.Receive(buf)
			if n == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			eth, err := ParseEth(buf[:n])
			if err != nil || eth.EtherType() != EtherTypeIPv4 {
				continue
			}
			ip, err := ParseIPv4(eth.Payload())
			if err != nil || ip.Proto() != ProtoTCP {
				continue
			}
			f, err := ParseTCP(ip.Payload())
			if err != nil || !f.Flags().Has(FlagRST) {
				continue
			}
			if got := f.Ack(); got != want {
				t.Fatalf("RST-ack = %d, wil %d", got, want)
			}
			return
		}
		t.Fatal("geen RST gezien")
	}

	send(0, []byte("data"), 100)
	expectAck(104)
	send(FlagSYN|FlagFIN, nil, 200)
	expectAck(202)
}

func TestARPLeerplafond(t *testing.T) {
	tab := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	for i := 0; i < 2*arpCacheCap; i++ {
		tab.learn([4]byte{10, 0, byte(i >> 8), byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}, 0)
	}
	if len(tab.entries) > arpCacheCap {
		t.Fatalf("de tabel draagt %d entries, de cap is %d", len(tab.entries), arpCacheCap)
	}
	if tab.cnt.LearnDrop == 0 {
		t.Fatal("er is geweigerd zonder te tellen")
	}
}

func TestARPResolveVerdringtGeleerd(t *testing.T) {
	tab := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	for i := 0; len(tab.entries) < arpCacheCap && i < 4*arpCacheCap; i++ {
		tab.learn([4]byte{10, 0, byte(i >> 8), byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}, 0)
	}
	want := [4]byte{10, 0, 9, 99}
	if _, ok := tab.resolve(want, 0); ok {
		t.Fatal("een verse resolve kan niet meteen opgelost zijn")
	}
	if e, exists := tab.entries[want]; !exists || e.state != neighborPending {
		t.Fatal("resolve op een volle tabel maakte geen pending entry — de verdringing werkt niet")
	}
	if len(tab.entries) > arpCacheCap {
		t.Fatalf("de verdringing hield de cap niet: %d entries", len(tab.entries))
	}
}

func TestARPKapotteChecksumLeertNiet(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	if _, err := s.Listen(80); err != nil {
		t.Fatal(err)
	}

	src := [4]byte{10, 0, 0, 9}
	frame := make([]byte, EthernetHeaderSize+sizeIPv4+sizeTCP)
	f, _ := ParseEth(frame)
	f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
	f.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	f.SetEtherType(EtherTypeIPv4)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100, nil,
		src, [4]byte{10, 0, 0, 1}, 0)
	frame[EthernetHeaderSize+sizeIPv4+16] ^= 0xff
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame)

	s.mu.Lock()
	_, learned := s.arp.entries[src]
	s.mu.Unlock()
	if learned {
		t.Fatal("een frame met kapotte TCP-checksum veroverde een ARP-cache-plek")
	}

	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100, nil,
		src, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame)
	s.mu.Lock()
	_, learned = s.arp.entries[src]
	s.mu.Unlock()
	if !learned {
		t.Fatal("een geldige SYN leerde de buur niet — het passieve leren is te ver verhuisd")
	}
}

func TestReadMetLegeBufferKeertMeteenTerug(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(91)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			defer c.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 91, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make(chan error, 1)
	go func() {
		n, err := conn.Read(nil)
		if err == nil && n != 0 {
			err = fmt.Errorf("lege read gaf n=%d", n)
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read(nil) blokkeert — een lege read hoort meteen terug te keren")
	}
}

func TestRefuseRSTStartGeenARPQuery(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)

	s.mu.Lock()
	now := s.now()
	for i := 2; len(s.arp.entries) < arpCacheCap; i++ {
		s.arp.learn([4]byte{10, 0, 0, byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}, now)
	}
	s.mu.Unlock()

	src := [4]byte{10, 0, 0, 200}
	frame := make([]byte, EthernetHeaderSize+sizeIPv4+sizeTCP)
	f, _ := ParseEth(frame)
	f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
	f.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	f.SetEtherType(EtherTypeIPv4)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 81, 1, 0, FlagSYN, 100, nil,
		src, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame)
	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	_, exists := s.arp.entries[src]
	n, pending := len(s.arp.entries), 0
	for _, e := range s.arp.entries {
		if e.state == neighborPending {
			pending++
		}
	}
	s.mu.Unlock()
	if exists || pending > 0 || n > arpCacheCap {
		t.Fatalf("de refuse-RST raakte de cache: entry=%v pending=%d n=%d (cap %d)", exists, pending, n, arpCacheCap)
	}
}

func TestRefuseRSTNaarGatewayStartWelEenQuery(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	gw := [4]byte{10, 0, 0, 254}
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: gw, Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)

	src := [4]byte{192, 168, 1, 5}
	frame := make([]byte, EthernetHeaderSize+sizeIPv4+sizeTCP)
	f, _ := ParseEth(frame)
	f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
	f.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	f.SetEtherType(EtherTypeIPv4)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 81, 1, 0, FlagSYN, 100, nil,
		src, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame)
	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	e, exists := s.arp.entries[gw]
	s.mu.Unlock()
	if !exists || e.state != neighborPending {
		t.Fatal("de RST naar een off-subnet peer startte geen gateway-query — de weigering verdampt op een verse node")
	}
}

func TestSocketWeigertOngeldigRemoteAdres(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	v, err := s.Socket(context.Background(), "tcp", afINET, sockSTREAM, nil,
		&net.TCPAddr{IP: net.IPv6loopback, Port: 5})
	if err == nil || v != nil {
		t.Fatalf("kreeg (%v, %v) — een ongeldig remote-adres hoort (nil, error) te geven", v, err)
	}
}

func TestConnectedUDPFiltertBijDeliver(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	u, err := s.DialUDP([4]byte{10, 0, 0, 2}, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	s.mu.Lock()
	spoofed := 0
	for i := 0; i < 1000; i++ {
		if s.udp.deliver(u.port.port, [4]byte{10, 0, 0, 66}, 6666, make([]byte, 512)) {
			spoofed++
		}
	}
	echt := s.udp.deliver(u.port.port, [4]byte{10, 0, 0, 2}, 53, []byte("antwoord"))
	s.mu.Unlock()
	if spoofed != 0 {
		t.Fatalf("%d gespoofde datagrammen kwamen de wachtrij in", spoofed)
	}
	if !echt {
		t.Fatal("de echte peer werd verdrongen — het filter zit te laat")
	}
}

func TestAcceptZietSnelleSluiter(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	l, err := s.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	s.mu.Lock()
	key := connKey{lport: 80, rip: [4]byte{10, 0, 0, 2}, rport: 40000}
	c, err := s.newConnLocked(key)
	if err == nil {
		c.listener = l.(*tcpListener)
		c.tcp.state = tcpCloseWait
		s.maybeAccept(c, s.now())
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept zag de snelle sluiter nooit — CLOSE-WAIT telt niet als aangekomen")
	}
}

func TestAcceptSlaatGereapteBacklogOver(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	lAny, err := s.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	l := lAny.(*tcpListener)

	stale := &sconn{key: connKey{lport: 80, rip: [4]byte{10, 0, 0, 9}, rport: 40000}}
	liveKey := connKey{lport: 80, rip: [4]byte{10, 0, 0, 2}, rport: 40001}
	s.mu.Lock()
	live, err := s.newConnLocked(liveKey)
	if err == nil {
		live.tcp.state = tcpEstablished
	}
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	l.backlog <- stale
	l.backlog <- live

	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.(*tcpSock).c; got != live {
		t.Fatal("Accept gaf een al gereapte backlog-referentie terug")
	}
}

func TestOngeaccepteerdeHandshakeVerlooptEnMaaktBacklogVrij(t *testing.T) {
	dev, peer := &memDevice{}, &memDevice{}
	dev.peer, peer.peer = peer, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 2}); err != nil {
		t.Fatal(err)
	}
	lAny, err := s.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	l := lAny.(*tcpListener)

	key := connKey{lport: 80, rip: [4]byte{10, 0, 0, 2}, rport: 50000}
	s.mu.Lock()
	c, err := s.newConnLocked(key)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	c.listener = l
	c.tcp.state = tcpEstablished
	now := s.now()
	s.maybeAccept(c, now)
	deadline := c.handoffDeadline
	// More peer segments revisit maybeAccept but may never renew the ownerless
	// handoff window.
	s.maybeAccept(c, now+tcpBacklogWaitDur/2)
	unchanged := c.handoffDeadline
	next := s.nextDeadlineLocked()
	s.notify()
	s.mu.Unlock()
	if deadline == 0 || unchanged != deadline || next != deadline {
		t.Fatalf("handoffdeadline: first=%d na peeractiviteit=%d next=%d", deadline, unchanged, next)
	}

	// Make the already-installed absolute deadline due without waiting 30 wall
	// seconds. The real pump must reap the tuple and return its floor budget.
	s.mu.Lock()
	c.handoffDeadline = s.now() - 1
	s.notify()
	s.mu.Unlock()
	wallDeadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		_, retained := s.conns[key]
		used := s.pot.used
		s.mu.Unlock()
		if !retained && used == 0 {
			break
		}
		if time.Now().After(wallDeadline) {
			t.Fatalf("ownerloze backlogverbinding bleef staan: retained=%v used=%d",
				retained, used)
		}
		time.Sleep(time.Millisecond)
	}

	// Reap removed the map entry; offer must also evict its stale channel
	// reference before applying tcpBacklog, otherwise a full stale queue can
	// reject healthy handshakes forever.
	for len(l.backlog) < tcpBacklog {
		l.backlog <- &sconn{}
	}
	replacement := &sconn{}
	s.mu.Lock()
	l.offer(replacement)
	s.mu.Unlock()
	if len(l.backlog) != 1 {
		t.Fatalf("offer behield stale backlogslots: len=%d, wil 1", len(l.backlog))
	}
	if got := <-l.backlog; got != replacement {
		t.Fatal("gezonde vervangende handshake kwam niet in de opgeschoonde backlog")
	}
}

func TestJumboFrameWordtGeweigerd(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	voor := s.Stats().DropBadFrame
	s.RecvInboundPacket(make([]byte, 3000))
	if s.Stats().DropBadFrame != voor+1 {
		t.Fatal("een jumbo frame kwam langs de maatwacht")
	}
}

func TestReadWeigertNaVerstrekenDeadline(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(92)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Write([]byte("wachtend"))
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 92, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(200 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("Read leverde %d bytes ná een verstreken deadline", n)
	}
}

func TestUDPSchrijverWordtGewektBijARPOpgave(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.DialUDP([4]byte{10, 0, 0, 99}, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetWriteDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	_, err = u.Write([]byte("hallo"))
	if err == nil || !errors.Is(err, errUnreachable) {
		t.Fatalf("Write gaf %v, wil errUnreachable", err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("de opgave-wek kwam pas na %v — de writer sliep tot zijn deadline", d)
	}
}

func TestSocketWeigertOnzinnigePoort(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	for _, port := range []int{0, -1, 65536} {
		v, err := s.Socket(context.Background(), "tcp", afINET, sockSTREAM, nil,
			&net.TCPAddr{IP: net.IP{10, 0, 0, 2}, Port: port})
		if err == nil || v != nil {
			t.Fatalf("poort %d: kreeg (%v, %v), wil (nil, error)", port, v, err)
		}
	}
}

func TestSocketCloseGeeftRxDirectTerug(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(93)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	klaar := make(chan struct{})
	go func() {
		if c, err := l.Accept(); err == nil {
			<-klaar
			c.Close()
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 93, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	a.mu.Lock()
	used := a.pot.used
	a.mu.Unlock()
	if used != 0 {
		t.Fatalf("a's pot draagt nog %d bytes na de volle close — abandonRead is niet bedraad", used)
	}
	close(klaar)
}

func TestConnectedUDPWeigertWriteTo(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.DialUDP([4]byte{10, 0, 0, 2}, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IP{10, 0, 0, 3}, Port: 53}); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("WriteTo op een connected socket gaf %v, wil net.ErrWriteToConnected", err)
	}
}

func TestSeedNeighborKentEenPlafond(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	var geweigerd bool
	for i := 2; i < 2+arpCacheCap; i++ {
		if err := s.SeedNeighbor([4]byte{10, 0, 0, byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}); err != nil {
			geweigerd = true
			break
		}
	}
	if !geweigerd {
		t.Fatal("de cap-hoeveelheid seeds werd zonder morren geaccepteerd")
	}
	s.mu.Lock()
	vrij := arpCacheCap - len(s.arp.entries)
	s.mu.Unlock()
	if vrij <= 0 {
		t.Fatalf("geen vrije cache-plekken over (%d) — resolve kan nergens meer heen", vrij)
	}
}

func TestSocketWeigertOngeldigLokaalAdres(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)
	for name, laddr := range map[string]net.Addr{
		"ipv6":          &net.TCPAddr{IP: net.IPv6loopback, Port: 80},
		"vreemde poort": &net.TCPAddr{IP: net.IP{10, 0, 0, 1}, Port: -1},
		"andermans ip":  &net.TCPAddr{IP: net.IP{10, 0, 0, 9}, Port: 80},
	} {
		v, err := s.Socket(context.Background(), "tcp", afINET, sockSTREAM, laddr, nil)
		if err == nil || v != nil {
			t.Fatalf("%s: kreeg (%v, %v), wil (nil, error)", name, v, err)
		}
	}
}

func TestARPVolleTabelIsLuid(t *testing.T) {
	tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	now := int64(time.Hour)

	for i := 0; i < arpCacheCap; i++ {
		tbl.resolve([4]byte{10, 0, byte(i >> 8), byte(i)}, now)
	}
	slachtoffer := [4]byte{10, 0, 200, 200}
	if _, ok := tbl.resolve(slachtoffer, now); ok {
		t.Fatal("resolve op een volle tabel gaf een MAC")
	}
	if !tbl.noAnswer(slachtoffer, now) {
		t.Fatal("volle tabel: noAnswer bleef false — de wachter slaapt voor altijd")
	}
	if tbl.cnt.FullDrop == 0 {
		t.Fatal("de geweigerde resolve is niet geteld (FullDrop)")
	}

	tbl.learn([4]byte{10, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 2}, now)
	tbl.recv(mustARPReply(t, [4]byte{10, 0, 0, 5}, [6]byte{2, 0, 0, 0, 0, 5}, [4]byte{10, 0, 0, 1}), now)
	if tbl.noAnswer(slachtoffer, now) {
		t.Fatal("met een verdringbare (opgeloste) entry hoort noAnswer weer false te zijn")
	}
}

func mustARPReply(t *testing.T, senderIP [4]byte, senderHW [6]byte, target [4]byte) ARPFrame {
	t.Helper()
	buf := make([]byte, sizeARP)
	if _, err := PutARP(buf, ARPReply, senderHW, senderIP, [6]byte{2, 0, 0, 0, 0, 1}, target); err != nil {
		t.Fatal(err)
	}
	f, err := ParseARP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSocketWeigertBronpoortBijDial(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	_, err := a.Socket(context.Background(), "tcp4", afINET, sockSTREAM,
		&net.TCPAddr{IP: net.IP(a.cfg.IP[:]), Port: 1234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 80})
	if err == nil || !strings.Contains(err.Error(), "local port") {
		t.Fatalf("dial met bronpoort gaf %v, wil een luide weigering", err)
	}
}

func TestCapaciteitssweepLaatPendingMetRust(t *testing.T) {
	tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	now := int64(time.Hour)

	for i := 0; i < arpCacheCap; i++ {
		ip := [4]byte{10, 0, byte(i >> 8), byte(i)}
		tbl.entries[ip] = &neighborEntry{state: neighborPending, tries: neighborQueryTries, due: now - 1}
	}

	tbl.resolve([4]byte{10, 0, 200, 200}, now)
	tbl.noAnswer([4]byte{10, 0, 200, 201}, now)
	if tbl.cnt.GaveUp != 0 {
		t.Fatalf("GaveUp = %d buiten de pomp om — die transitie is van emit", tbl.cnt.GaveUp)
	}
	for ip, e := range tbl.entries {
		if e.state != neighborPending {
			t.Fatalf("%v is %v geworden buiten de pomp om", ip, e.state)
		}
	}

	buf := make([]byte, sizeARP)
	for {
		if _, ok := tbl.emit(buf, now); !ok {
			break
		}
	}
	if tbl.cnt.GaveUp != arpCacheCap {
		t.Fatalf("emit gaf %d queries op, wil %d", tbl.cnt.GaveUp, arpCacheCap)
	}
}

func wachtOpPending(t *testing.T, s *Stack, ip [4]byte) {
	t.Helper()
	for begin := time.Now(); time.Since(begin) < 2*time.Second; {
		s.mu.Lock()
		e, ok := s.arp.entries[ip]
		pending := ok && e.state == neighborPending
		s.mu.Unlock()
		if pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("de ARP-query kwam nooit op gang")
}

func TestSeedWektDeWachter(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	pc, err := a.ListenUDP(9000)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	doel := [4]byte{10, 0, 0, 99}
	klaar := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("ping"), &net.UDPAddr{IP: net.IP(doel[:]), Port: 7})
		klaar <- err
	}()
	wachtOpPending(t, a, doel)
	if err := a.SeedNeighbor(doel, [6]byte{2, 0, 0, 0, 0, 99}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-klaar:
		if err != nil {
			t.Fatalf("WriteTo na de seed gaf %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("de seed loste de route op maar wekte de wachter niet")
	}
}

func TestPassiefLerenWektDeWachter(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	pc, err := a.ListenUDP(9001)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	doel := [4]byte{10, 0, 0, 99}
	klaar := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("ping"), &net.UDPAddr{IP: net.IP(doel[:]), Port: 7})
		klaar <- err
	}()
	wachtOpPending(t, a, doel)

	frame := make([]byte, EthernetHeaderSize+sizeIPv4+sizeUDP)
	f, _ := ParseEth(frame)
	f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
	f.SetSrc([6]byte{2, 0, 0, 0, 0, 99})
	f.SetEtherType(EtherTypeIPv4)
	if _, err := PutUDP(frame[EthernetHeaderSize+sizeIPv4:], 7, 4321, doel, [4]byte{10, 0, 0, 1}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := PutIPv4(frame[EthernetHeaderSize:], ProtoUDP, doel, [4]byte{10, 0, 0, 1}, sizeUDP); err != nil {
		t.Fatal(err)
	}
	if err := a.RecvInboundPacket(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-klaar:
		if err != nil {
			t.Fatalf("WriteTo na het passieve leren gaf %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("het passieve leren loste de route op maar wekte de wachter niet")
	}
}

func TestSeedRespecteertTotaalcap(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	a.mu.Lock()
	for i := 0; i < 65; i++ {
		a.arp.entries[[4]byte{10, 0, 0, byte(3 + i)}] = &neighborEntry{state: neighborPending, due: a.now()}
	}
	a.mu.Unlock()
	geplant := 0
	var laatste error
	for i := 0; i < 64; i++ {
		laatste = a.SeedNeighbor([4]byte{10, 0, 0, byte(100 + i)}, [6]byte{2, 0, 0, 0, 0, byte(i)})
		if laatste == nil {
			geplant++
		}
	}
	if geplant != 63 || laatste == nil {
		t.Fatalf("%d seeds geplant (wil 63) en de laatste gaf %v (wil een vol-fout)", geplant, laatste)
	}
	a.mu.Lock()
	n := len(a.arp.entries)
	a.mu.Unlock()
	if n > arpCacheCap {
		t.Fatalf("tabel draagt %d entries, cap is %d", n, arpCacheCap)
	}
}

func TestResolveVerdringtTotErRuimteIs(t *testing.T) {
	now := int64(time.Hour)
	over := func(evictable int) *arpTable {
		tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
		for i := 0; i < arpCacheCap+1-evictable; i++ {
			tbl.entries[[4]byte{10, 1, byte(i >> 8), byte(i)}] = &neighborEntry{state: neighborPending, due: now}
		}
		for i := 0; i < evictable; i++ {
			tbl.entries[[4]byte{10, 2, 0, byte(i)}] = &neighborEntry{state: neighborResolved, born: now}
		}
		return tbl
	}

	tbl := over(2)
	doel := [4]byte{10, 3, 0, 1}
	tbl.resolve(doel, now)
	if e, ok := tbl.entries[doel]; !ok || e.state != neighborPending {
		t.Fatal("resolve startte geen query terwijl er (na twee verdringingen) ruimte was")
	}
	if len(tbl.entries) > arpCacheCap {
		t.Fatalf("tabel draagt %d entries na resolve, cap is %d", len(tbl.entries), arpCacheCap)
	}

	tbl = over(1)
	tbl.resolve(doel, now)
	if _, ok := tbl.entries[doel]; ok {
		t.Fatal("resolve startte een query op een tabel die vol hoort te zijn")
	}
	if !tbl.fullLocked(now) {
		t.Fatal("fullLocked zei 'niet vol' terwijl resolve geen query kon starten — de wachter slaapt eeuwig")
	}
}

type arpFrameTeller struct {
	*memDevice
	n atomic.Int32
}

func (d *arpFrameTeller) Transmit(p []byte) error {
	if f, err := ParseEth(p); err == nil && f.EtherType() == EtherTypeARP {
		d.n.Add(1)
	}
	return d.memDevice.Transmit(p)
}

func TestGatewaySeedDektOokDeGatewayZelf(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	teller := &arpFrameTeller{memDevice: da}
	a := NewStack(teller, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: [4]byte{10, 0, 0, 2}, Budget: 1 << 20, AdvWS: 2,
	}, 12345)
	b := NewStack(db, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20, AdvWS: 2,
	}, 54321)
	stop := make(chan struct{})
	rx := func(s *Stack, d *memDevice) {
		buf := make([]byte, MTU+EthernetMaximumSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _ := d.Receive(buf)
			if n == 0 {
				time.Sleep(100 * time.Microsecond)
				continue
			}
			s.RecvInboundPacket(buf[:n])
		}
	}
	go rx(a, da)
	go rx(b, db)
	t.Cleanup(func() { close(stop); a.Close(); b.Close() })

	if err := a.SeedNeighbor([4]byte{10, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 2}); err != nil {
		t.Fatal(err)
	}

	l, err := b.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 80, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("dial naar de geseede gateway: %v", err)
	}
	c.Close()

	pc, err := a.ListenUDP(9002)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hi"), &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 7}); err != nil {
		t.Fatalf("UDP naar de geseede gateway: %v", err)
	}
	if n := teller.n.Load(); n != 0 {
		t.Fatalf("%d ARP-frames de deur uit — de seed belooft er nul", n)
	}
}

func TestStatischeGatewayNegeertVolleTabel(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	a.mu.Lock()
	a.cfg.GW = [4]byte{10, 0, 0, 2}
	a.gwMAC, a.hasGwMAC = [6]byte{2, 0, 0, 0, 0, 2}, true
	for i := 0; i < arpCacheCap; i++ {
		a.arp.entries[[4]byte{10, 0, 1, byte(i)}] = &neighborEntry{state: neighborPending, due: a.now()}
	}
	a.mu.Unlock()

	_, err := a.DialTCP([4]byte{192, 168, 1, 1}, 80, time.Now().Add(400*time.Millisecond))
	if err == nil {
		t.Fatal("dial slaagde — er is daar helemaal geen server")
	}
	if strings.Contains(err.Error(), "no route to host") {
		t.Fatalf("dial gaf %v: de volle ARP-tabel blokkeerde een route zonder ARP-lot", err)
	}

	pc, err := a.ListenUDP(9003)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hi"), &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 7}); err != nil {
		t.Fatalf("off-subnet UDP via de statische gateway gaf %v", err)
	}
}

func TestReseedVanBestaandeStaticMagAltijd(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	for i := 0; i < arpCacheCap/2; i++ {
		if err := a.SeedNeighbor([4]byte{10, 0, 0, byte(10 + i)}, [6]byte{2, 0, 0, 0, 0, byte(i)}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := a.SeedNeighbor([4]byte{10, 0, 0, 200}, [6]byte{2, 0, 0, 0, 0, 200}); err == nil {
		t.Fatal("de 65e statische seed passeerde de cap")
	}
	if err := a.SeedNeighbor([4]byte{10, 0, 0, 10}, [6]byte{2, 0, 0, 0, 0, 99}); err != nil {
		t.Fatalf("MAC-update van een bestaande static gaf %v", err)
	}
}
