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
	"sync/atomic"
	"sync"
	"testing"
	"time"
)

// memDevice is een in-memory NIC: Transmit legt frames in de wachtrij van de
// peer, Receive popt de eigen wachtrij ((0,nil) = niets, zoals het contract
// wil). Telt ARP-queries per kant voor de PassivePeers-regressie.
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

// newStackPair bouwt twee stacks op één draad, elk met een RX-lus zoals
// hopnet die drijft. cleanup stopt alles.
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

// TestStackTCPEchoEndToEnd: het hele huis — dial via ARP, handshake, echo,
// EOF-propagatie, en na afloop is élke byte terug in de pot. Plus de
// PassivePeers-regressie: de server leert zijn beller passief en heeft nul
// eigen ARP-queries nodig.
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
		if _, err := io.Copy(c, c); err != nil { // echo tot EOF van de peer
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
		// Half-close bestaat niet op deze rand; Close na de write en de echo
		// leest gewoon door tot de FIN via de server terugkomt.
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

	// PassivePeers-regressie: b (de server) hoort zijn beller uit de
	// SYN-frames geleerd te hebben — nul eigen queries; a heeft er precies
	// één nodig gehad om b te vinden.
	da := a.dev.(*memDevice)
	db := b.dev.(*memDevice)
	if db.arpQueries != 0 {
		t.Errorf("server needed %d ARP queries; passive learning is broken", db.arpQueries)
	}
	if da.arpQueries != 1 {
		t.Errorf("client sent %d ARP queries, want 1", da.arpQueries)
	}

	// Budget-hygiëne: als alle verbindingen door TIME-WAIT heen zijn is de
	// pot weer vol. (De actieve sluiter houdt zijn floor ~1s vast.)
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

// TestStackUDPRoundtrip: DNS-vormig verkeer — dial, vraag, antwoord via
// ReadFrom/WriteTo, met adressen die kloppen.
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

// TestStackReadDeadline: een stille peer laat Read exact op de deadline los,
// met een echte timeout-fout — deadline-gedreven, nooit iteration-capped.
func TestStackReadDeadline(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(81)
	if err != nil {
		t.Fatal(err)
	}
	go l.Accept() // accepteren en zwijgen

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

// errorsAs zonder errors te schaduwen in de testnaamruimte.
func errorsAs(err error, target *net.Error) bool {
	if e, ok := err.(net.Error); ok {
		*target = e
		return true
	}
	return false
}

// TestStackBudgetRefusalSendsRST: is de pot te leeg voor zelfs een floor, dan
// krijgt de beller een luide RST (refused) in plaats van stilte.
func TestStackBudgetRefusalSendsRST(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 0) // b heeft NIETS te vergeven

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

// TestStackICMPEcho: een ping wordt beantwoord — de diagnose-route van de
// node-watchdog. De test speelt de pinger zélf (geen tweede stack: twee
// lezers op één wachtrij was exact de meetbank-valkuil van 11-08).
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
			return // dáár is hij
		}
	}
	t.Fatal("no echo reply within 2s")
}

// TestStackEphemeralSkipsOccupied — lneto's #14: een botsing met een levende
// poort betekent overslaan en herkiezen, nooit een harde dial-fout.
func TestStackEphemeralSkipsOccupied(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)

	// Bezet 49153 expliciet; de teller staat op 49152.
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

// TestStackSeedNeighborSubnetRule — lneto's #21: een seed buiten het subnet
// zou nooit geraadpleegd worden en wordt dus luid geweigerd; de gateway en
// binnen-subnet-seeds werken.
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

// TestStackSocketShapes — lneto's #4: het Socket-contract levert échte
// net-typen en fouten als fouten, nooit een fout vermomd als verbinding.
func TestStackSocketShapes(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)

	ctx := context.Background()
	// Listener-vorm.
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
	// Conn-vorm.
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
	// PacketConn-vorm.
	pcAny, err := a.Socket(ctx, "udp", afINET, sockDGRAM, &net.UDPAddr{Port: 5353}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pcAny.(net.PacketConn); !ok {
		t.Fatalf("udp listen returned %T, want net.PacketConn", pcAny)
	}
	// IPv6: nette weigering, geen paniek en geen vermomde waarde.
	if v, err := a.Socket(ctx, "tcp", afINET6, sockSTREAM, nil, &net.TCPAddr{IP: net.IPv6loopback, Port: 1}); err == nil || v != nil {
		t.Fatalf("ipv6 returned (%v, %v), want (nil, error)", v, err)
	}
	// Een dial die faalt levert (nil, err) — de #4-kern.
	fctx, fcancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer fcancel()
	v, err := a.Socket(fctx, "tcp", afINET, sockSTREAM, nil,
		&net.TCPAddr{IP: net.IP{10, 0, 0, 99}, Port: 1}) // bestaat niet
	if err == nil || v != nil {
		t.Fatalf("failed dial returned (%v, %v), want (nil, error)", v, err)
	}
}

// TestStackIdleCostsNothing — lneto's #17: een idle listener spinde daar een
// volledige pool-scan per lege poll. Hier blokkeert Accept op een kanaal en
// slaapt de pomp zonder deadline: een stack zonder werk heeft geen enkele
// wektijd staan en verbruikt dus geen CPU.
func TestStackIdleCostsNothing(t *testing.T) {
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

// TestStackGarbageNeverPanics: de onvertrouwde rand. Rommel in élke laag —
// afgekapt, corrupt, kapotte optielijsten, verkeerde checksums — wordt geteld
// en gedropt, nooit gepanict. hopnet draait hier een recover omheen, maar
// daar hoort niets aan te komen.
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

	// Pseudo-willekeurig met vaste seed: reproduceerbaar, geen wandklok.
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
	// Puur ruis in alle maten, inclusief te kort voor ethernet.
	for _, n := range []int{0, 1, 13, 14, 15, 33, 60, 61, 200} {
		for i := 0; i < 50; i++ {
			s.RecvInboundPacket(fill(n))
		}
	}
	// Gericht kapot: aan ons geadresseerd zodat de diepere lagen meedoen.
	mkEth := func(payloadLen int) EthFrame {
		f, _ := ParseEth(frame[:EthernetHeaderSize+payloadLen])
		f.SetDst([6]byte{2, 0, 0, 0, 0, 1})
		f.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
		f.SetEtherType(EtherTypeIPv4)
		return f
	}
	// 1: IPv4-header met kapotte checksum.
	mkEth(sizeIPv4)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	frame[EthernetHeaderSize+10] ^= 0xff
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4])
	// 2: geldige IPv4, afgekapte TCP.
	mkEth(sizeIPv4 + 8)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 8)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+8])
	// 3: geldige IPv4 + TCP-SYN met corrupte TCP-checksum.
	mkEth(sizeIPv4 + sizeTCP)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100, nil,
		[4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	frame[EthernetHeaderSize+sizeIPv4+16] ^= 0xff
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+sizeTCP])
	// 4: SYN met een kapotte optielijst (kind 2, lengte 0 → oneindige-lus-aas).
	mkEth(sizeIPv4 + sizeTCP + 4)
	PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 999, 80, 1, 0, FlagSYN, 100,
		[]byte{2, 0, 0, 0}, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, sizeTCP+4)
	s.RecvInboundPacket(frame[:EthernetHeaderSize+sizeIPv4+sizeTCP+4])
	// 5: ARP die geen ethernet/IPv4-ARP is.
	f := mkEth(sizeARP)
	f.SetEtherType(EtherTypeARP)
	PutARP(frame[EthernetHeaderSize:], ARPRequest, [6]byte{9}, [4]byte{10, 0, 0, 9}, [6]byte{}, [4]byte{10, 0, 0, 1})
	frame[EthernetHeaderSize] = 0xff // htype kapot
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

// TestStackListenerBacklogOverflow: meer voltooide handshakes dan de backlog
// draagt → de overloop wordt luid geweigerd (abort+RST), en Accept levert
// precies de backlog. Geen stil vastgehouden restje (de conport-les).
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
	// Zonder accepter: de overloop is geaborteerd en gereapt, en b houdt
	// precies de backlog vast — geen byte meer. (De late handshake-ACKs
	// druppelen asynchroon binnen, dus even laten settelen.)
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
	// De overloop-clients zijn ge-RST: hun Read faalt (geen eeuwige stilte).
	dead := 0
	for _, c := range conns {
		// Kort: de ge-RST'e verbindingen falen meteen, de levende kosten elk
		// hun volle deadline (8 × dit getal is de looptijd van deze test).
		c.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && err != os.ErrDeadlineExceeded {
			dead++
		}
	}
	if dead != dials-tcpBacklog {
		t.Fatalf("%d overflow clients saw the RST, want exactly %d", dead, dials-tcpBacklog)
	}
	// En wat er wél wacht is netjes op te halen: precies tcpBacklog stuks.
	for i := 0; i < tcpBacklog; i++ {
		if _, err := l.Accept(); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}
	l.Close()
}

// TestStackBudgetRecovery: een pot van precies één verbinding weigert de
// tweede en accepteert weer zodra de eerste zijn geheugen teruggaf — de
// kringloop die het OOM-probleem verving.
//
// De server houdt zijn verbinding vast tot de test hem vrijgeeft. Dat is geen
// omslachtigheid maar de fix van een flaky variant: sloot hij meteen na
// Accept, dan hing "is het slot nog bezet?" aan de vraag of TIME-WAIT (~1s) al
// verstreken was voordat de tweede dial startte — en onder de race-detector is
// alles langzamer, dus viel de test daar soms door.
func TestStackBudgetRecovery(t *testing.T) {
	a, b := newStackPair(t, 1<<20, tcpFloorRing) // b: exact één verbinding
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
			<-release // vasthouden tot de test het slot wil terug
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
	// De pot is nu aantoonbaar vol: de tweede dial krijgt een luide RST.
	if _, err := a.DialTCP([4]byte{10, 0, 0, 2}, 89, time.Now().Add(2*time.Second)); err == nil {
		t.Fatal("second dial succeeded against a full pot")
	}
	close(release)
	c1.Close()
	// b's kant loopt door TIME-WAIT (~1s) en dan is de floor terug.
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

// TestStackEphemeralWraps: de teller loopt over de rand van het bereik en
// begint gewoon opnieuw bij de basis.
func TestStackEphemeralWraps(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	t.Cleanup(s.Close)
	s.mu.Lock()
	s.nextEph = ephemeralEnd // 65535
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

// drainWire haalt alle frames uit een device-wachtrij (de "buitenwereld").
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

// TestStackRoutesOffSubnetViaGateway: verkeer naar buiten het subnet gaat naar
// het MAC van de GATEWAY, niet naar een (onmogelijke) ARP voor het
// bestemmings-IP. Dat is het internet-pad — downloads, TLS, SNTP — en het
// verdient een expliciete test los van het ijzer.
func TestStackRoutesOffSubnetViaGateway(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	gwMAC := [6]byte{0xaa, 0xbb, 0xcc, 0, 0, 1}
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: [4]byte{10, 0, 0, 254}, Budget: 1 << 20,
	}, 3)
	t.Cleanup(s.Close)

	// Dial naar een publiek adres; de stack heeft de gateway-MAC nog niet.
	done := make(chan error, 1)
	go func() {
		_, err := s.DialTCP([4]byte{8, 8, 8, 8}, 443, time.Now().Add(3*time.Second))
		done <- err
	}()

	// Op de draad hoort nu een ARP-request voor de GATEWAY te staan.
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

	// De "router" antwoordt; daarna moet de SYN naar het gateway-MAC gaan,
	// met het publieke IP als bestemming.
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
	// 8.8.8.8 antwoordt niet: de dial hoort luid op te geven, niet te hangen.
	if err := <-done; err == nil {
		t.Fatal("dial to a silent peer succeeded")
	}
}

// TestStackStaticGatewayMACSkipsARP: met een geplande gateway-MAC (appnet's
// deterministische net) gaat er nul ARP over de draad — het scheelt een
// rondje op élke eerste dial naar buiten.
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
				return // de SYN ging direct naar het geplande MAC
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no frame towards the planned gateway MAC")
}

// TestStackUDPAccessors: de kleine net-contract-oppervlakken die het
// standaard-net-pakket wél gebruikt (deadlines, adressen, dubbel sluiten).
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
	// WriteTo met een verkeerd adrestype of onzinnige poort weigert luid —
	// zónder verlopen deadline in de buurt: de oude test was daarop
	// vals-groen (review 13-08, dertigste ronde).
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
	u.Close() // idempotent
	if _, _, err := u.ReadFrom(make([]byte, 8)); err != net.ErrClosed {
		t.Errorf("ReadFrom after close = %v, want net.ErrClosed", err)
	}
	// De poort is vrij: opnieuw binden moet lukken.
	u2, err := a.ListenUDP(5555)
	if err != nil {
		t.Fatalf("rebind after close: %v", err)
	}
	u2.Close()
}

// TestStackListenerRejectsBusyPortAndReportsAddr: de listener-rand.
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
	// Een wachtende Accept moet door Close losgelaten worden (anders lekt een
	// goroutine bij elke listener-teardown), en daarna blijft hij ErrClosed
	// geven.
	released := make(chan error, 1)
	go func() {
		_, err := l2.Accept()
		released <- err
	}()
	time.Sleep(20 * time.Millisecond) // Accept zit nu te wachten
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

// TestStackFastReaderKeepsFullWindow: de reden dat de rx-vloer 16KiB is en
// niet 2KiB. Een lezer die sneller leest dan het net levert laat de ring nooit
// vollopen, dus groeit hij nooit — het venster dat wij adverteren is dan
// permanent de vloer. Die vloer moet daarom op zichzelf al een
// initial-cwnd-burst (10 segmenten) kunnen absorberen, anders wordt élke bulk
// binnenkomst stop-and-wait en meten we onze eigen rem.
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
		// Zo snel lezen als het maar kan: dit is de "snelle lezer".
		n, _ := io.Copy(io.Discard, c)
		srvDone <- int(n)
		<-gemeten // de volle close geeft de ring terug (abandonRead): eerst meten
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

	// De kern van de test: het venster dat de server adverteerde moet een
	// volle initial-cwnd-burst kunnen dragen, ook al is zijn ring nooit
	// gegroeid (snelle lezer). 10 × 1460 is de burst die een zender opent.
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

// TestStackSelfDial: een wereld moet bij zichzelf kunnen. Zonder de
// loopback-naad vroeg een dial naar het eigen IP op de draad "who has
// <mijzelf>" — een vraag die geen switch beantwoordt (broadcast gaat naar
// iedereen BEHALVE de bron), dus kwam er na vijf pogingen "no route to host".
// GEMETEN 12-08 op ijzer: na een rolling update stond cloudflared op het
// slot-IP dat zijn eigen config als origin noemde, en die fout wees vijf lagen
// weg van de oorzaak. Zelfde klasse als de watchdog-canary die zijn eigen
// agent-poort niet kon bereiken.
func TestStackSelfDial(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	self := [4]byte{10, 0, 0, 1} // a's eigen adres

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
		_, err = io.Copy(c, c) // echo tot de peer sluit
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

	// En geen enkel zelf-frame mag de draad op zijn gegaan.
	da := a.dev.(*memDevice)
	da.mu.Lock()
	queries := da.arpQueries
	da.mu.Unlock()
	if queries != 0 {
		t.Errorf("self-dial produced %d ARP queries on the wire; nobody answers 'who has myself'", queries)
	}
}

// TestStackSelfDialRefused: is er niets dat luistert op de eigen poort, dan
// hoort dat "refused" te zijn — niet vijf seconden stilte en dan een
// route-fout die de operator naar de switch stuurt. Dat was letterlijk de
// verkeerde diagnose-richting op 12-08.
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

// TestStackSelfDialUDP: zelfde naad voor datagrammen (de SNTP/DNS-vorm).
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

// TestStackClosedPortRefusesFast: het algemene geval van de refused-fix — een
// dial naar een dichte poort op een ANDERE node hoort ook meteen "nee" te
// krijgen (RFC 9293 §3.10.7.1), niet de deadline uit te zitten.
func TestStackClosedPortRefusesFast(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	if _, err := b.Listen(6000); err != nil { // een ándere poort dan we dialen
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

// TestStackRSTStormResistance: een RST naar een onbekende verbinding mag
// nooit een RST uitlokken (dat is een storm tussen twee nodes die elkaar
// beide niet kennen).
func TestStackRSTStormResistance(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 5)
	t.Cleanup(s.Close)
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 9}, [6]byte{2, 0, 0, 0, 0, 9}); err != nil {
		t.Fatal(err) // seed onder het stack-slot: de pomp leest de tabel al
	}

	// Een kale RST voor een verbinding die hier niet bestaat.
	frame := make([]byte, 60)
	eth, _ := ParseEth(frame)
	eth.SetDst(s.cfg.MAC)
	eth.SetSrc([6]byte{2, 0, 0, 0, 0, 9})
	eth.SetEtherType(EtherTypeIPv4)
	n, _ := PutTCP(frame[EthernetHeaderSize+sizeIPv4:], 1234, 80, 500, 0, FlagRST, 0, nil,
		[4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, 0)
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 1}, n)
	drainWire(db) // wire leegmaken
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

// TestStackBroadcastGaatNaarFFFF: een datagram aan 255.255.255.255 of aan het
// subnet-broadcastadres gaat naar ff:ff:ff:ff:ff:ff en lokt GEEN ARP uit. Dit
// is het pad van een DHCP-rebind (RFC 2131 §4.4.5): als de lessor weg is, is
// broadcast de enige manier om de lease te houden. Vóór deze regel ging een
// limited broadcast als unicast naar de gateway en ARP'de een subnet-broadcast
// zich vijf keer dood.
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

// TestIsBroadcastIP dekt de randen die de routelaag zelf niet laat zien: een
// /31 en /32 hebben GEEN broadcastadres (RFC 3021), en een adres met alle
// hostbits aan in een ánder subnet is gewoon een unicast-adres elders.
func TestIsBroadcastIP(t *testing.T) {
	ip := [4]byte{10, 0, 0, 1}
	for _, tc := range []struct {
		dst    [4]byte
		prefix int
		want   bool
	}{
		{[4]byte{255, 255, 255, 255}, 24, true},
		{[4]byte{255, 255, 255, 255}, 32, true}, // limited kan altijd
		{[4]byte{10, 0, 0, 255}, 24, true},
		{[4]byte{10, 0, 255, 255}, 16, true},
		{[4]byte{10, 0, 0, 255}, 16, false}, // hostbits niet allemaal aan
		{[4]byte{10, 0, 0, 2}, 24, false},
		{[4]byte{10, 0, 1, 255}, 24, false}, // broadcast van een ánder subnet
		{[4]byte{10, 0, 0, 1}, 31, false},   // /31: geen broadcast (RFC 3021)
		{[4]byte{10, 0, 0, 1}, 32, false},   // /32: idem
		{[4]byte{192, 168, 1, 255}, 24, false},
	} {
		if got := isBroadcastIP(tc.dst, ip, tc.prefix); got != tc.want {
			t.Errorf("isBroadcastIP(%v, /%d) = %v, want %v", tc.dst, tc.prefix, got, tc.want)
		}
	}
}

// TestStackSelfDialMeerdereRondes: MEERDERE vraag-antwoord-rondes over ÉÉN
// loopback-verbinding, want dat is wat keep-alive doet en het bestaande
// self-dial-geval deed maar één ronde.
//
// GEMETEN 12-08 op ijzer (LicheeRV op 192.168.99.2): hop's agent proxyt naar de
// leader op dezelfde node, dus over loopback, met een verbinding uit de
// keep-alive-pool. Uitkomst: 200, 502, 200, 502 — perfect om en om. De eerste
// ronde van een verse verbinding lukte, de tweede over dezelfde verbinding niet.
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

	// Tien rondes: elke ronde ontstaat er tijdens de verwerking van het
	// binnenkomende frame een uitgaand frame (het antwoord plus zijn ACK), en
	// dat is precies de situatie waarin een gedeelde wachtrij-array zichzelf
	// overschrijft.
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

// TestStackPeerHerstartZelfdeVierTupel bouwt de situatie op het ijzer na: een
// peer verdwijnt terwijl zijn verbinding openstaat, komt terug als VERSE stack
// (zelfde IP, zelfde MAC) en belt dezelfde server op dezelfde poort — dus met
// exact hetzelfde vier-tupel, want elke verse stack begint zijn efemere reeks op
// 49152.
//
// Dat is op HopOS de RÉGEL en niet de uitzondering: HOP herstart een app op
// hetzelfde slot, dus met hetzelfde IP, en de eerste dial van die app pakt weer
// 49152. De server weet niets van dat verdwijnen (er is geen keepalive) en
// challenge-ACKt elke nieuwe SYN op dat tupel (RFC 5961 §4.2). Zonder de reset
// uit SYN-SENT (RFC 9293 §3.10.7.3) eindigt dat nergens: de nieuwe verbinding
// komt er nooit, met "i/o timeout" als enige spoor.
//
// GEMETEN 12-08 op een LicheeRV: Stulp's attach-poort was voor een herstarte app
// onbereikbaar terwijl poort 80 van diezelfde Stulp meteen antwoordde.
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

	// De peer verdwijnt zoals een kooi verdwijnt: geen FIN, geen RST, niets. Zijn
	// stack stopt gewoon. De server houdt zijn verbinding dus voor levend.
	a.Close()
	<-time.After(50 * time.Millisecond)

	// Hij komt terug als verse stack op hetzelfde adres, met dezelfde MAC.
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

// TestStackIdleVerbindingGeeftBuffersTerug — een verbinding die één keer druk was
// mag zijn gegroeide buffers niet houden. Een gepoolde HTTP-verbinding sluit niet,
// en MaxBufPerConn is Budget/4: vier zulke verbindingen en de pot is leeg, waarna
// leannet élke nieuwe verbinding weigert.
//
// GEMETEN 12-08 op een LicheeRV: HOP haalde app-images op (5MB per stuk), liet
// gepoolde verbindingen achter en gaf daarna op élke dial "buffer budget
// exhausted". De watchdog vraagt voor zijn levensteken juist een VERSE verbinding
// naar de agent-poort, dus resette de node zichzelf — twee keer op één avond.
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

	// Genoeg door de verbinding duwen dat beide kanten groeien.
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

	// Beide kanten zijn nu bij: de zender heeft alles bevestigd gekregen, de
	// ontvanger heeft alles opgehaald. Wat er nog vast staat, staat vast voor
	// niets. De marge is één floor-verbinding: de ringen mogen op hun vloer
	// staan, niet op hun piek.
	const slack = tcpFloorRing
	deadline := time.Now().Add(5 * time.Second)
	for {
		freeA, freeB := a.pot.free(), b.pot.free()
		if freeA >= budget-tcpFloorRing-slack && freeB >= budget-tcpFloorRing-slack {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pot niet teruggestort: zender %d van %d vrij, ontvanger %d van %d "+
				"— een verbinding die klaar is houdt zijn gegroeide buffers vast",
				freeA, budget, freeB, budget)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// En hij moet daarna nog gewoon werken: krimpen mag geen verbinding slopen.
	if _, err := srv.Write([]byte("terug")); err != nil {
		t.Fatalf("schrijven na krimp: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	echo := make([]byte, 5)
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatalf("lezen na krimp: %v", err)
	}
	if string(echo) != "terug" {
		t.Fatalf("na krimp kwam %q terug", echo)
	}
}

// TestStackRSTOpLosseAckIsKaal — een ACK-segment voor een verbinding die niet
// bestaat krijgt <SEQ=SEG.ACK><CTL=RST>, zónder ACK-vlag (RFC 9293 §3.10.7.1):
// er is geen sequence-ruimte van de peer om te bevestigen, en een RST|ACK met
// ack=0 wordt door een strikte SYN-SENT-peer juist wéggegooid — die eist
// ack == iss+1 (review 13-08).
func TestStackRSTOpLosseAckIsKaal(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()
	// De afzender als statische buur, zodat de RST direct te routeren is.
	if err := s.SeedNeighbor([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}

	// Frame van 10.0.0.1:5555 → 10.0.0.2:7 (geen listener, geen verbinding),
	// ACK gezet met ack=777.
	frame := make([]byte, 256)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 2}) // dst = de stack
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

	// De pomp verstuurt de RST; vang hem op de draad.
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
			continue // ARP of rommel: overslaan
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

// TestStackZonderGatewayFaaltMeteen — een bestemming buiten het subnet zonder
// gateway (statisch noch geconfigureerd) is een antwoord, geen wachttijd:
// routeLocked start dan nooit een ARP-query, dus arp.noAnswer zou nooit waar
// worden en een dial zat zijn volle deadline uit op een fout die bij de eerste
// blik vaststond (review 13-08). Zelfde regel voor UDP.
func TestStackZonderGatewayFaaltMeteen(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20, // GW bewust leeg
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

// TestSockCloseDeblokkeerRead — het net.Conn-contract: Close moet een
// geblokkeerde Read wakker maken én laten falen. Vóór deze fix werd de Read wel
// gewekt (notify) maar ging hij opnieuw wachten zolang de peer geen FIN stuurde
// (review 13-08).
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
			time.Sleep(5 * time.Second) // stuurt nooit iets, sluit niet
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf) // blokkeert: er komt nooit data
		got <- err
	}()
	time.Sleep(50 * time.Millisecond) // de Read staat nu echt te wachten
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

// TestSockDeadlineRaaktLopendeRead — een deadline die ná de Read gezet wordt
// moet die Read alsnog afbreken; vóór de fix pakte alleen een vólgende call de
// nieuwe deadline (review 13-08).
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
		_, err := conn.Read(buf) // blokkeert zonder deadline
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

// TestStackCloseSluitAlles — Stack.Close is de hele publieke stack: een
// geblokkeerde Accept en ReadFrom keren terug, verbindingen worden gereapt en
// het budget komt integraal terug. Vóór de fix bleef Accept eeuwig hangen en
// hielden conns en UDP-wachtrijen hun budget vast (review 13-08).
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
	// Eén levende verbinding, zodat er echt iets te reapen valt.
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(50 * time.Millisecond) // Accept- en ReadFrom-goroutines staan nu te wachten

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

// TestStackListenerCloseRuimtEmbryosOp — een listener die dichtgaat laat geen
// halve handshakes achter: het embryo (SYN binnen, SYN|ACK uit, geen slot-ACK)
// wijst naar een deur die niet meer bestaat en zat vóór de fix zijn hele
// backoff uit mét floor-budget (review 13-08).
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

	// Een kale SYN, met de hand: er komt nooit een voltooiende ACK.
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

// TestTCPFinWait2Timeout — een peer die onze FIN bevestigt maar zelf nooit
// sluit, hield de verbinding (en haar floor-budget) vóór de fix onbeperkt vast:
// FIN-WAIT-2 had geen deadline (review 13-08).
func TestTCPFinWait2Timeout(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()

	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	w.pump() // FIN eruit, ACK terug — b sluit bewust niet
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

// TestStackDialAnnuleerbaar — een dial via net.DialContext hoort op de
// cancel terug te keren, niet pas op zijn deadline. Vóór de fix keek de
// wachtlus alleen naar de deadline (review 13-08).
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
		// Een buur die nooit antwoordt: de ARP-machine gaat er ~5s over doen.
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
	// De halve verbinding is opgeruimd, budget terug.
	s.mu.Lock()
	used, conns := s.pot.used, len(s.conns)
	s.mu.Unlock()
	if used != 0 || conns != 0 {
		t.Fatalf("na de cancel: pot %d, conns %d — de geannuleerde dial liet iets achter", used, conns)
	}
}

// TestSockStaartLezenDanSluiten — de leesbare staart van een half-gesloten
// peer leeft in CLOSE-WAIT (vóór reap) en blijft leesbaar; ná de eigen Close
// wordt de verbinding gereapt en is het budget én de echte buffer weg, ook al
// houdt de aanroeper de socket nog vast (review 13-08, L9).
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
	srv.Close() // FIN; a leest pas hierna — CLOSE-WAIT bewaart de staart

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "staart" {
		t.Fatalf("staart-read gaf %q, %v — CLOSE-WAIT hoort de staart te bewaren", buf[:n], err)
	}
	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("read na de staart gaf %v, wil io.EOF", err)
	}

	conn.Close() // volle sluiting: LAST-ACK → closed → reap
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
	// De aanroeper houdt de socket nog vast, maar de échte bytes zijn los:
	// géén tweede budget aan dood geheugen.
	sock := conn.(*tcpSock)
	if sock.c.tcp.rx.size() != 0 || sock.c.tcp.tx.size() != 0 {
		t.Fatalf("gereapte verbinding draagt nog buffers (rx %d, tx %d)",
			sock.c.tcp.rx.size(), sock.c.tcp.tx.size())
	}
}

// TestStackReapWektGeblokkeerdeRead — een verbinding die via een TIMER sterft
// (opgave, FIN-WAIT-2-verval) wordt door de pomp gereapt; zonder notify in
// reap bleef een Read zonder deadline wachten tot toevallig ander verkeer
// langskwam (review 13-08, tweede ronde). De abort+reap hieronder is exact wat
// het timer-pad doet.
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

// TestStackRouteDoodBreektDeVerbinding — als ARP mid-verbinding luid opgeeft,
// bevroor de verbinding vóór de fix voorgoed: emitWire werd overgeslagen, dus
// de retransmissietimer telde nooit door (review 13-08, tweede ronde). Duur:
// ~5s (de vijf ARP-pogingen).
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

	// Eerst de handshake volledig laten settelen: blijft a's laatste ACK in
	// de blackhole hangen, dan hertransmit b zijn SYN|ACK en LEERT a's
	// ARP-tabel het adres passief opnieuw (b→a-verkeer) — dan test dit de
	// TCP-opgave-ladder i.p.v. de route-dood.
	time.Sleep(100 * time.Millisecond)
	// De peer verdwijnt van het net: ARP-entry weg en béide richtingen dood.
	a.mu.Lock()
	a.dev.(*memDevice).peer = &memDevice{}
	delete(a.arp.entries, [4]byte{10, 0, 0, 2})
	a.mu.Unlock()
	b.mu.Lock()
	b.dev.(*memDevice).peer = &memDevice{}
	b.mu.Unlock()

	if _, err := conn.Write([]byte("de leegte in")); err != nil {
		t.Fatal(err) // de write zelf slaagt: hij vult de ring
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

// TestStackAcceptNaCloseGeeftNooitEenVerbinding — de backlog-referenties
// bleven bij Stack.Close in het kanaal staan, en Accept select't over backlog
// én done: een Accept ná Close kon dus willekeurig een al gereapte (dode)
// verbinding teruggeven (review 13-08, tweede ronde).
func TestStackAcceptNaCloseGeeftNooitEenVerbinding(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(90)
	if err != nil {
		t.Fatal(err)
	}
	// Eén voltooide handshake die niemand accepteert: die staat in de backlog.
	if _, err := a.DialTCP([4]byte{10, 0, 0, 2}, 90, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	b.Close()
	for i := 0; i < 32; i++ { // het select-muntje mag nooit verkeerd vallen
		c, err := l.Accept()
		if err == nil {
			t.Fatalf("Accept #%d gaf een verbinding ná Stack.Close (%v)", i, c.RemoteAddr())
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept gaf %v, wil net.ErrClosed", err)
		}
	}
}

// TestStackSynRstMaaktGeenVerbinding — de stack-poort op het SYN-pad kende
// geen RST-toets; samen met de machine-guard (Has-maskerfout) maakte een
// SYN|RST zo een embryo mét floor-budget (review 13-08, vijfde ronde).
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

// TestStackOffSubnetEmbryoSterft — een inbound SYN van een peer buiten het
// subnet zónder gateway maakte een embryo waarvan de timer nooit gewapend werd
// (emit draait niet zonder route): een 20KiB-zombie per SYN, tot de pot leeg
// was. Het route-dood-vangnet dekt nu ook hop == 0.0.0.0 (review 13-08,
// vijfde ronde).
func TestStackOffSubnetEmbryoSterft(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2},
		Budget: 1 << 20, // GW bewust leeg
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
	src, dst := [4]byte{192, 168, 1, 9}, [4]byte{10, 0, 0, 2} // buiten het subnet
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

// TestStackDialZegtNoRouteNietTimeout — de pomp kan de ARP-opgave als eerste
// zien en de verbinding aborten; de dial-waiter las dan "connect timed out"
// waar "no route to host" hoort — het soort verkeerd-wijzende fout dat op
// 12-08 vijf lagen zoeken kostte (review 13-08, vijfde ronde).
func TestStackDialZegtNoRouteNietTimeout(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	// In-subnet buur die nooit op ARP antwoordt; ruime deadline zodat de
	// ARP-opgave (±5s) ruim vóór de deadline valt.
	_, err := s.DialTCP([4]byte{10, 0, 0, 99}, 80, time.Now().Add(20*time.Second))
	if err == nil {
		t.Fatal("dial naar een dode buur slaagde")
	}
	if err != errUnreachable {
		t.Fatalf("dial gaf %q, wil %q — de fout hoort naar de route te wijzen", err, errUnreachable)
	}
}

// TestStackVolleLoopbackIsGeenSucces — een schrijver naar het eigen adres op
// een volle loopback-wachtrij meldde stil succes, en UDP heeft geen
// retransmissie die dat later goedmaakt (review 13-08, vijfde ronde).
// Rechtstreeks op sendEthLocked, onder het slot: de pomp draint de wachtrij
// zodra hij mag, dus een socket-level-vorm racet met zijn eigen opstelling
// (gemeten als flake onder -race).
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
	err := s.sendEthLocked(s.cfg.MAC, EtherTypeIPv4, 32) // naar onszelf: loopback
	gotDrops := s.stats.DropReplyFull
	s.mu.Unlock()

	if err == nil {
		t.Fatal("sendEthLocked op een volle loopback meldde succes — het pakket ligt nergens")
	}
	if gotDrops != drops+1 {
		t.Fatalf("drop niet geteld: %d → %d", drops, gotDrops)
	}
}

// TestSockDeadlineVerlengenEnWissen — het net.Conn-contract in de andere
// richting: een verlengde of gewiste deadline moet lopende I/O óók bereiken.
// Set*Deadline wekt bewust niet bij verruimen (de notify-storm), dus await
// herkeurt de actuele deadline op het moment dat de oude timer afloopt — vóór
// die herkeuring liep een Read af op een deadline die allang gewist was
// (review 13-08, zevende ronde).
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
	conn.SetReadDeadline(time.Time{}) // gewist: de Read hoort dóór te wachten

	select {
	case err := <-got:
		t.Fatalf("Read keerde terug (%v) op een deadline die gewist was", err)
	case <-time.After(400 * time.Millisecond): // ruim voorbij de oude 150ms
	}

	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // vervroegd: wekt wél
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

// TestStackCtxDeadlineGeeftContextfout — rond een context-deadline raceten de
// eigen timer en ctx.Done(), en wie won bepaalde of de aanroeper
// os.ErrDeadlineExceeded of context.Canceled zag; context.DeadlineExceeded is
// het verwachte, stabiele antwoord (review 13-08, negende ronde).
func TestStackCtxDeadlineGeeftContextfout(t *testing.T) {
	dev, capture := &memDevice{}, &memDevice{}
	dev.peer, capture.peer = capture, dev
	s := NewStack(dev, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 1)
	defer s.Close()

	for i := 0; i < 8; i++ { // de race is per definitie een muntworp: vaak gooien
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

// TestStackRSTAckTeltSegLen — de ACK op een geweigerd niet-ACK-segment is
// SEG.SEQ + SEG.LEN, en SEG.LEN telt alleen SYN/FIN als extra plek: de vaste
// +1 was bij kale data één te hoog en bij SYN|FIN één te laag (review 13-08,
// negende ronde).
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

	send(0, []byte("data"), 100) // kale data, geen vlaggen: SEG.LEN = 4
	expectAck(104)
	send(FlagSYN|FlagFIN, nil, 200) // SYN|FIN: SEG.LEN = 2
	expectAck(202)
}

// TestARPLeerplafond — passief leren is gratis voor de afzender: zonder cap
// vulde een stroom frames met gespoofde bron-IP's de tabel onbegrensd, en op
// een node van 64MB is een onbegrensde map een DoS (review 13-08, dertiende
// ronde).
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

// TestARPResolveVerdringtGeleerd — een actieve resolve (iemand wíl dit adres)
// gaat vóór een passief bewaard antwoord: vol=vol geldt voor leren, niet voor
// wie het adres echt nodig heeft (review 13-08, dertiende ronde).
func TestARPResolveVerdringtGeleerd(t *testing.T) {
	tab := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	for i := 0; len(tab.entries) < arpCacheCap && i < 4*arpCacheCap; i++ {
		tab.learn([4]byte{10, 0, byte(i >> 8), byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}, 0)
	}
	want := [4]byte{10, 0, 9, 99}
	if _, ok := tab.resolve(want, 0); ok {
		t.Fatal("een verse resolve kan niet meteen opgelost zijn")
	}
	if e, exists := tab.entries[want]; !exists || e.state != arpPending {
		t.Fatal("resolve op een volle tabel maakte geen pending entry — de verdringing werkt niet")
	}
	if len(tab.entries) > arpCacheCap {
		t.Fatalf("de verdringing hield de cap niet: %d entries", len(tab.entries))
	}
}

// TestARPKapotteChecksumLeertNiet — het passieve leren zit ná de
// transportvalidatie: een geldige IP-header met een kapotte TCP-checksum is
// met één gok te vervalsen en verdient geen cache-plek (review 13-08,
// dertiende ronde).
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
	frame[EthernetHeaderSize+sizeIPv4+16] ^= 0xff // TCP-checksum kapot
	PutIPv4(frame[EthernetHeaderSize:], ProtoTCP, src, [4]byte{10, 0, 0, 1}, sizeTCP)
	s.RecvInboundPacket(frame)

	s.mu.Lock()
	_, learned := s.arp.entries[src]
	s.mu.Unlock()
	if learned {
		t.Fatal("een frame met kapotte TCP-checksum veroverde een ARP-cache-plek")
	}

	// En exact dezelfde SYN mét kloppende checksum leert wél.
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

// TestReadMetLegeBufferKeertMeteenTerug — net.Conn-contract: een lege read is
// meteen klaar. Hij kwam in await terecht (tcp.read geeft (0, nil)) en
// wachtte op verkeer dat er nooit hoeft te komen (review 13-08, dertiende
// ronde).
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
			time.Sleep(2 * time.Second) // stuurt niets
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

// TestRefuseRSTStartGeenARPQuery — het best-effort-uitvoerpad (RST op een
// gesloten poort, echo-reply) raadpleegt de ARP-cache alleen nog (peek): een
// actieve query starten liet élke gespoofde SYN een echte cache-plek
// verdringen, tot de hele tabel uit pending spoof-queries bestond en een
// legitieme resolve moest wachten op retries/verval (review 13-08, vijftiende
// ronde).
func TestRefuseRSTStartGeenARPQuery(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)

	// De tabel vol met passief geleerde buren (allemaal vers, niets verlopen).
	// Alles BINNEN het /24: buiten het subnet beslist de gateway-route al en
	// komt er nooit een resolve (dat maskeerde de eerste versie van deze test).
	s.mu.Lock()
	now := s.now()
	for i := 2; len(s.arp.entries) < arpCacheCap; i++ {
		s.arp.learn([4]byte{10, 0, 0, byte(i)}, [6]byte{2, 0, 0, 0, 0, 9}, now)
	}
	s.mu.Unlock()

	// Een geldige SYN naar een gesloten poort, van een verse (gespoofde) bron.
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
	time.Sleep(50 * time.Millisecond) // de pomp bezorgt de RST best-effort

	s.mu.Lock()
	_, exists := s.arp.entries[src]
	n, pending := len(s.arp.entries), 0
	for _, e := range s.arp.entries {
		if e.state == arpPending {
			pending++
		}
	}
	s.mu.Unlock()
	if exists || pending > 0 || n > arpCacheCap {
		t.Fatalf("de refuse-RST raakte de cache: entry=%v pending=%d n=%d (cap %d)", exists, pending, n, arpCacheCap)
	}
}

// TestRefuseRSTNaarGatewayStartWelEenQuery — de peek-regel geldt niet voor de
// gateway: dat IP komt uit de config, niet uit het pakket, dus een spoofer
// kan er nooit méér dan die ene entry mee laten bestaan — en zonder query
// verdampte een refuse-RST naar een off-subnet peer stil op een verse node
// die nog nooit uitbelde (review 13-08, zestiende ronde).
func TestRefuseRSTNaarGatewayStartWelEenQuery(t *testing.T) {
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	gw := [4]byte{10, 0, 0, 254}
	s := NewStack(da, Config{
		IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1},
		GW: gw, Budget: 1 << 20,
	}, 7)
	t.Cleanup(s.Close)

	// Een geldige SYN van een off-subnet bron (via de router binnengekomen)
	// naar een gesloten poort: de RST terug moet via de gateway.
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
	if !exists || e.state != arpPending {
		t.Fatal("de RST naar een off-subnet peer startte geen gateway-query — de weigering verdampt op een verse node")
	}
}

// TestSocketWeigertOngeldigRemoteAdres — een niet-nil maar onbruikbaar
// remote-adres (IPv6 op een v4-stack) werd stil een LISTENER; een dial die
// faalt hoort (nil, err) te geven (review 13-08, vijfentwintigste ronde).
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

// TestConnectedUDPFiltertBijDeliver — vreemde afzenders vielen pas in
// ReadFrom af en konden intussen de hele wachtrij vullen, de echte peer
// verdringend (review 13-08, vijfentwintigste ronde).
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

	// Een spoofer probeert de wachtrij te vullen; daarna komt de echte peer.
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

// TestAcceptZietSnelleSluiter — de derde handshake-ACK kan data én FIN
// dragen: de verbinding schiet dan in één recv door ESTABLISHED naar
// CLOSE-WAIT, en de handoff op exact ESTABLISHED liet Accept eeuwig wachten
// mét hangend floorbudget (review 13-08, zevenentwintigste ronde).
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

	// Een embryo dat al voorbij ESTABLISHED is als de handoff hem ziet.
	c := &sconn{listener: l.(*tcpListener)}
	c.tcp.state = tcpCloseWait
	s.mu.Lock()
	s.maybeAccept(c)
	s.mu.Unlock()

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

// TestJumboFrameWordtGeweigerd — een frame boven MTU+ethernet kan verderop
// een reply bouwen die groter is dan txBuf en de pomp laten panicken; de
// maatwacht zit aan de deur (review 13-08, zevenentwintigste ronde).
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

// TestReadWeigertNaVerstrekenDeadline — een verstreken deadline hoort ÉLKE
// operatie meteen te weigeren, ook met data in de wachtrij: de toets zat ná
// het gereed-I/O-pad, dus gequeue'de data werd na de deadline nog geleverd
// (review 13-08, achtentwintigste ronde).
func TestReadWeigertNaVerstrekenDeadline(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	l, err := b.Listen(92)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Write([]byte("wachtend")) // data staat klaar in a's ring
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 92, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(200 * time.Millisecond) // de data is bezorgd
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("Read leverde %d bytes ná een verstreken deadline", n)
	}
}

// TestUDPSchrijverWordtGewektBijARPOpgave — de pending→failed-overgang
// gebeurde in de drain zonder notify: een UDP-writer die op noAnswer pollt
// hoorde pas bij zijn eigen deadline dat de route dood was (review 13-08,
// achtentwintigste ronde).
func TestUDPSchrijverWordtGewektBijARPOpgave(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.DialUDP([4]byte{10, 0, 0, 99}, 53) // niemand thuis: ARP geeft na ~5s op
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetWriteDeadline(time.Now().Add(30 * time.Second)) // ruim: de wek moet éérder komen
	start := time.Now()
	_, err = u.Write([]byte("hallo"))
	if err == nil || !errors.Is(err, errUnreachable) {
		t.Fatalf("Write gaf %v, wil errUnreachable", err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("de opgave-wek kwam pas na %v — de writer sliep tot zijn deadline", d)
	}
}

// TestSocketWeigertOnzinnigePoort — poort 0, negatief of 65536 op een non-nil
// remote werd via de uint16-conversie een stille listener (review 13-08,
// achtentwintigste ronde).
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

// TestSocketCloseGeeftRxDirectTerug — de volle close van de socket-laag hoort
// abandonRead aan te roepen: zonder die bedrading hield een gepoolde/idle-
// geëvicte verbinding minstens 16KiB RX-budget vast tot de peer sloot of
// FIN-WAIT-2 na 20s verliep (review 13-08, negenentwintigste ronde — de
// machinefix bestond, de wiring was in een toggle-herstel gesneuveld).
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
			<-klaar // b sluit NIET: a moet zijn budget zelf terugkrijgen
			c.Close()
		}
	}()
	conn, err := a.DialTCP([4]byte{10, 0, 0, 2}, 93, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond) // FIN + ACK wisselen; b blijft open
	a.mu.Lock()
	used := a.pot.used
	a.mu.Unlock()
	if used != 0 {
		t.Fatalf("a's pot draagt nog %d bytes na de volle close — abandonRead is niet bedraad", used)
	}
	close(klaar)
}

// TestConnectedUDPWeigertWriteTo — na DialUDP(peerA) is WriteTo naar peerB
// een zwart gat (replies van B worden bij deliver al weggegooid): het
// net.UDPConn-contract weigert hem, wij nu ook (review 13-08, dertigste
// ronde).
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

// TestSeedNeighborKentEenPlafond — statische seeds omzeilen tick, sweep én
// verdringing: onbegrensd zaaien kon de tabel vullen waarna resolve geen
// pending entry meer kwijt kon en een UDP-write zonder deadline permanent
// sliep (review 13-08, dertigste ronde).
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

// TestSocketWeigertOngeldigLokaalAdres — een IPv6- of vreemd-type laddr werd
// stil een wildcard-listener, en een vreemde poort klapte om via uint16
// (review 13-08, dertigste ronde).
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

// TestARPVolleTabelIsLuid — een resolver wiens query niet eens kán starten
// (tabel vol met pending/statisch, niets verdringbaars) hoort dat als "geen
// antwoord" te zien: er komt immers nooit een arpFailed-entry waar noAnswer op
// zou slaan, dus sliep de wachter tot zijn deadline — of zonder deadline voor
// altijd (review 13-08, eenendertigste ronde).
func TestARPVolleTabelIsLuid(t *testing.T) {
	tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	now := int64(time.Hour)
	// De tabel volpompen met pending queries (allemaal onverdringbaar).
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
	// Zodra er iets verdringbaars staat is het geen vol-fout meer: een entry
	// lost op (wordt verdringbaar) en de nieuwe resolve hoort weer te lopen.
	tbl.learn([4]byte{10, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 2}, now) // ververst niets: vol
	tbl.recv(mustARPReply(t, [4]byte{10, 0, 0, 5}, [6]byte{2, 0, 0, 0, 0, 5}, [4]byte{10, 0, 0, 1}), now)
	if tbl.noAnswer(slachtoffer, now) {
		t.Fatal("met een verdringbare (opgeloste) entry hoort noAnswer weer false te zijn")
	}
}

// mustARPReply bouwt een geldige aan-ons-gerichte reply voor de test hierboven.
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

// TestSocketWeigertBronpoortBijDial — een gevraagde bronpoort op een dial werd
// stil genegeerd (de stack kiest altijd efemeer): dat hoort een luide fout te
// zijn (review 13-08, eenendertigste ronde).
func TestSocketWeigertBronpoortBijDial(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	_, err := a.Socket(context.Background(), "tcp4", afINET, sockSTREAM,
		&net.TCPAddr{IP: net.IP(a.cfg.IP[:]), Port: 1234},
		&net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 80})
	if err == nil || !strings.Contains(err.Error(), "local port") {
		t.Fatalf("dial met bronpoort gaf %v, wil een luide weigering", err)
	}
}

// TestCapaciteitssweepLaatPendingMetRust — pending → failed doet UITSLUITEND
// de pomp (emit): de capaciteitssweep in resolve (en noAnswer's toets) kon een
// uitgeputte query buiten de pomp om naar failed tikken, en dan viel de
// transitie buiten de GaveUp-tellerbaseline van drainLocked — de notify die
// bestaande wachters moest wekken kwam er nooit (review 13-08,
// tweeëndertigste ronde).
func TestCapaciteitssweepLaatPendingMetRust(t *testing.T) {
	tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
	now := int64(time.Hour)
	// Volle tabel met uitgeputte pending queries (laatste tussenpoos voorbij).
	for i := 0; i < arpCacheCap; i++ {
		ip := [4]byte{10, 0, byte(i >> 8), byte(i)}
		tbl.entries[ip] = &arpEntry{state: arpPending, tries: arpQueryTries, due: now - 1}
	}
	// De capaciteitspaden (resolve op een nieuw IP → sweep, en noAnswer's
	// vol-toets) mogen die staat niet aanraken.
	tbl.resolve([4]byte{10, 0, 200, 200}, now)
	tbl.noAnswer([4]byte{10, 0, 200, 201}, now)
	if tbl.cnt.GaveUp != 0 {
		t.Fatalf("GaveUp = %d buiten de pomp om — die transitie is van emit", tbl.cnt.GaveUp)
	}
	for ip, e := range tbl.entries {
		if e.state != arpPending {
			t.Fatalf("%v is %v geworden buiten de pomp om", ip, e.state)
		}
	}
	// De pomp zelf geeft ze luid op — mét teller, dus mét notify.
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

// ---- vierendertigste ronde ----

// wachtOpPending pollt tot de ARP-entry voor ip pending is — het moment
// waarop de wachter van de test écht op de query slaapt.
func wachtOpPending(t *testing.T, s *Stack, ip [4]byte) {
	t.Helper()
	for begin := time.Now(); time.Since(begin) < 2*time.Second; {
		s.mu.Lock()
		e, ok := s.arp.entries[ip]
		pending := ok && e.state == arpPending
		s.mu.Unlock()
		if pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("de ARP-query kwam nooit op gang")
}

// TestSeedWektDeWachter — SeedNeighbor kan een lopende query vervangen door
// een statische entry; daarmee verdwijnt de query-timer uit nextDeadline, en
// zonder notify sliep een deadline-loze UDP-writer op die route voorgoed
// (review 13-08, vierendertigste ronde).
func TestSeedWektDeWachter(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	pc, err := a.ListenUDP(9000)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	doel := [4]byte{10, 0, 0, 99} // niemand antwoordt op deze ARP
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

// TestPassiefLerenWektDeWachter — passief leren kan een lopende query
// oplossen terwijl het pakket zelf daarna op een early-return-pad sterft
// (hier: UDP naar een poort zonder listener). Zonder notify uit het leren
// zelf wekte niets de wachter meer (review 13-08, vierendertigste ronde).
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

	// Een geldig UDP-frame VAN het doel, naar een poort zonder listener: het
	// no-port-pad dropt het (early return) — alleen het passieve leren blijft
	// over, en dat moet de wachter wekken.
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

// TestSeedRespecteertTotaalcap — de statics-cap (arpCacheCap/2) begrensde
// alleen de seeds zelf: met 65 dynamische entries erbij groeide de tabel naar
// 129, waarna resolve's ene verdringing nooit onder de cap kwam en fullLocked
// tóch "niet vol" zei — geen query, geen fout, geen timer (review 13-08,
// vierendertigste ronde).
func TestSeedRespecteertTotaalcap(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	a.mu.Lock()
	for i := 0; i < 65; i++ { // 65 onverdringbare pending queries
		a.arp.entries[[4]byte{10, 0, 0, byte(3 + i)}] = &arpEntry{state: arpPending, due: a.now()}
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

// TestResolveVerdringtTotErRuimteIs — stond de tabel ooit boven de cap, dan
// moet resolve verdringen TOT er ruimte is (en fullLocked precies dan "vol"
// zeggen wanneer dat niet kan) — één verdringing liet 129 entries op 128
// staan: geen query én geen fout (review 13-08, vierendertigste ronde).
func TestResolveVerdringtTotErRuimteIs(t *testing.T) {
	now := int64(time.Hour)
	over := func(evictable int) *arpTable {
		tbl := newARPTable([4]byte{10, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 1})
		for i := 0; i < arpCacheCap+1-evictable; i++ {
			tbl.entries[[4]byte{10, 1, byte(i >> 8), byte(i)}] = &arpEntry{state: arpPending, due: now}
		}
		for i := 0; i < evictable; i++ {
			tbl.entries[[4]byte{10, 2, 0, byte(i)}] = &arpEntry{state: arpResolved, born: now}
		}
		return tbl // len = arpCacheCap+1: de historische boven-cap-toestand
	}

	// Twee verdringbare: resolve moet ze BEIDE ruimen en de query starten.
	tbl := over(2)
	doel := [4]byte{10, 3, 0, 1}
	tbl.resolve(doel, now)
	if e, ok := tbl.entries[doel]; !ok || e.state != arpPending {
		t.Fatal("resolve startte geen query terwijl er (na twee verdringingen) ruimte was")
	}
	if len(tbl.entries) > arpCacheCap {
		t.Fatalf("tabel draagt %d entries na resolve, cap is %d", len(tbl.entries), arpCacheCap)
	}

	// Eén verdringbare op 129: dat is en blijft vol — en fullLocked moet dat
	// ook ZEGGEN, anders wacht de teleurgestelde resolver eeuwig.
	tbl = over(1)
	tbl.resolve(doel, now)
	if _, ok := tbl.entries[doel]; ok {
		t.Fatal("resolve startte een query op een tabel die vol hoort te zijn")
	}
	if !tbl.fullLocked(now) {
		t.Fatal("fullLocked zei 'niet vol' terwijl resolve geen query kon starten — de wachter slaapt eeuwig")
	}
}

// ---- zesendertigste ronde ----

// arpFrameTeller telt uitgaande ARP-frames — het meetinstrument voor de
// nul-ARP-belofte van een geseede gateway.
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

// TestGatewaySeedDektOokDeGatewayZelf — de gateway is same-subnet, dus
// verkeer NAAR hem viel buiten de gwMAC-route en startte alsnog ARP, terwijl
// appnet.Up belooft dat dials naar de host nul ARP kosten (hopswitch maskeerde
// dat door de query te beantwoorden). Nu: dst == cfg.GW && hasGwMAC routeert
// rechtstreeks — TCP én UDP, nul ARP-frames (review 13-08, zesendertigste
// ronde).
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
	// TCP naar de gateway zelf.
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
	// En UDP.
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

// TestStatischeGatewayNegeertVolleTabel — off-subnet verkeer met een geseede
// gateway-MAC heeft géén ARP-lot, maar nextHopLocked gaf de eindbestemming als
// vulwaarde terug en de wachter vroeg daar tóch noAnswer op: op een tabel vol
// onverdringbaar werk werd elke remote bestemming zo meteen "unreachable"
// terwijl het pakket gewoon via de bekende MAC kan vertrekken (review 13-08,
// zesendertigste ronde).
func TestStatischeGatewayNegeertVolleTabel(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	a.mu.Lock()
	a.cfg.GW = [4]byte{10, 0, 0, 2}
	a.gwMAC, a.hasGwMAC = [6]byte{2, 0, 0, 0, 0, 2}, true
	for i := 0; i < arpCacheCap; i++ { // vol met onverdringbaar werk
		a.arp.entries[[4]byte{10, 0, 1, byte(i)}] = &arpEntry{state: arpPending, due: a.now()}
	}
	a.mu.Unlock()
	// De DIAL-cond is de plek die het gat had: die toetst noAnswer VÓÓR de
	// uitkomst van de handshake, dus vóór de SYN ook maar vertrokken was.
	// Niemand antwoordt op 192.168.1.1, dus de dial hoort op zijn DEADLINE te
	// stranden (de SYN vertrok via de bekende gateway-MAC) — niet op de
	// onmiddellijke "unreachable" die de volle tabel hem aanpraatte.
	_, err := a.DialTCP([4]byte{192, 168, 1, 1}, 80, time.Now().Add(400*time.Millisecond))
	if err == nil {
		t.Fatal("dial slaagde — er is daar helemaal geen server")
	}
	if strings.Contains(err.Error(), "no route to host") {
		t.Fatalf("dial gaf %v: de volle ARP-tabel blokkeerde een route zonder ARP-lot", err)
	}
	// En UDP blijft gewoon vertrekken (de route slaagt direct op gwMAC).
	pc, err := a.ListenUDP(9003)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hi"), &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 7}); err != nil {
		t.Fatalf("off-subnet UDP via de statische gateway gaf %v", err)
	}
}

// TestReseedVanBestaandeStaticMagAltijd — de static-cap werd getoetst vóór de
// bestaat-hij-al-vraag: een MAC-update van een bestaande static (nul extra
// entries) faalde dus zodra de cap vol stond (review 13-08, zesendertigste
// ronde).
func TestReseedVanBestaandeStaticMagAltijd(t *testing.T) {
	a, _ := newStackPair(t, 0, 0)
	for i := 0; i < arpCacheCap/2; i++ {
		if err := a.SeedNeighbor([4]byte{10, 0, 0, byte(10 + i)}, [6]byte{2, 0, 0, 0, 0, byte(i)}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	// De cap staat vol; een verse static moet falen, een UPDATE niet.
	if err := a.SeedNeighbor([4]byte{10, 0, 0, 200}, [6]byte{2, 0, 0, 0, 0, 200}); err == nil {
		t.Fatal("de 65e statische seed passeerde de cap")
	}
	if err := a.SeedNeighbor([4]byte{10, 0, 0, 10}, [6]byte{2, 0, 0, 0, 0, 99}); err != nil {
		t.Fatalf("MAC-update van een bestaande static gaf %v", err)
	}
}
