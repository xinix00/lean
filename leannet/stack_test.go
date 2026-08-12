package leannet

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
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
	refused := b.CntRefusedNoBudget
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
	bad, short, conns := s.CntDropBadFrame, s.CntDropShortFrame, len(s.conns)
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
	if err := u.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	// WriteTo met een niet-IPv4-adres weigert luid.
	if _, err := u.WriteTo([]byte("x"), &net.TCPAddr{Port: 1}); err == nil {
		t.Error("WriteTo accepted a TCP address")
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
	go func() {
		c, err := l.Accept()
		if err != nil {
			srvDone <- -1
			return
		}
		// Zo snel lezen als het maar kan: dit is de "snelle lezer".
		n, _ := io.Copy(io.Discard, c)
		srvDone <- int(n)
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
	defer b.mu.Unlock()
	for _, sc := range b.conns {
		if w := sc.tcp.rx.size(); w < 10*1460 {
			t.Fatalf("server receive window is %d bytes; a 10-segment initial burst (%d) does not fit, so bulk RX degrades to stop-and-wait",
				w, 10*1460)
		}
	}
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
	s.arp.seed([4]byte{10, 0, 0, 9}, [6]byte{2, 0, 0, 0, 0, 9})

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
