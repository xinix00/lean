package leannet

import (
	"bytes"
	"testing"
	"time"
)

// De testbank: twee machines op een draad met injecteerbaar verlies en een
// geïnjecteerde monotone klok. Geen sleep, geen wandklok — elk scenario is
// deterministisch. De nummers in de testnamen verwijzen naar BEVINDINGEN.md
// van de lneto-review (11-08): dit zijn de faalscenario's die daar bewezen
// zijn en hier vanaf dag één regressietests zijn.

type tcpWire struct {
	t        *testing.T
	a, b     *tcpConn
	now      int64
	dropAtoB func(seg tcpSeg) bool
	dropBtoA func(seg tcpSeg) bool
}

func newTCPPair(t *testing.T, ringA, ringB int) *tcpWire {
	return newTCPPairISS(t, ringA, ringB, 1000, 5000, 0)
}

// newTCPPairISS kiest de startsequencenummers en de WS-shift zelf — voor de
// wrap-tests (iss vlak onder 2³²) en de schaal-tests.
func newTCPPairISS(t *testing.T, ringA, ringB int, issA, issB uint32, ws uint8) *tcpWire {
	w := &tcpWire{t: t, a: &tcpConn{}, b: &tcpConn{}, now: int64(time.Hour)}
	w.a.rx = ring{buf: make([]byte, ringA)}
	w.a.tx = txRing{ring: ring{buf: make([]byte, ringA)}}
	w.b.rx = ring{buf: make([]byte, ringB)}
	w.b.tx = txRing{ring: ring{buf: make([]byte, ringB)}}
	w.a.openActive(issA, 1460, ws)
	w.b.openPassive(issB, 1460, ws)
	return w
}

func (w *tcpWire) advance(d time.Duration) { w.now += int64(d) }

// drain haalt alle klaarstaande segmenten uit c (met gekopieerde payload).
func (w *tcpWire) drain(c *tcpConn) []tcpSeg {
	var out []tcpSeg
	buf := make([]byte, 2048)
	for i := 0; ; i++ {
		if i > 64 {
			w.t.Fatalf("drain runaway: >64 segments from %s", c.state)
		}
		seg, ok := c.emit(buf, w.now)
		if !ok {
			return out
		}
		seg.data = append([]byte(nil), seg.data...)
		out = append(out, seg)
	}
}

// pump wisselt segmenten uit tot beide kanten stil zijn (of maxRounds op is).
func (w *tcpWire) pump() {
	for round := 0; round < 64; round++ {
		moved := false
		for _, seg := range w.drain(w.a) {
			moved = true
			if w.dropAtoB == nil || !w.dropAtoB(seg) {
				w.b.recv(seg, w.now)
			}
		}
		for _, seg := range w.drain(w.b) {
			moved = true
			if w.dropBtoA == nil || !w.dropBtoA(seg) {
				w.a.recv(seg, w.now)
			}
		}
		if !moved {
			return
		}
	}
	w.t.Fatalf("pump did not settle: a=%s b=%s", w.a.state, w.b.state)
}

func (w *tcpWire) connect() {
	w.pump()
	if w.a.state != tcpEstablished || w.b.state != tcpEstablished {
		w.t.Fatalf("handshake failed: a=%s b=%s", w.a.state, w.b.state)
	}
}

// readAll leest wat er nu in de ontvangring staat.
func readAll(c *tcpConn) []byte {
	buf := make([]byte, 4096)
	var out []byte
	for {
		n, _ := c.read(buf)
		if n == 0 {
			return out
		}
		out = append(out, buf[:n]...)
	}
}

func TestTCPHandshakeAndData(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	if w.a.peerMSS != 1460 || w.b.peerMSS != 1460 {
		t.Errorf("MSS not negotiated: a=%d b=%d", w.a.peerMSS, w.b.peerMSS)
	}
	if !w.a.wsOn || !w.b.wsOn {
		t.Error("window scaling not negotiated on mutual offer")
	}
	w.a.write([]byte("hello from a"))
	w.pump()
	if got := readAll(w.b); string(got) != "hello from a" {
		t.Fatalf("b received %q", got)
	}
	w.b.write([]byte("hi back"))
	w.pump()
	if got := readAll(w.a); string(got) != "hi back" {
		t.Fatalf("a received %q", got)
	}
}

// TestTCPLostBareFIN — BEVINDINGEN #1: een verloren kale FIN moet door de
// retransmissietimer opnieuw verzonden worden. In lneto bestond daar geen
// enkel pad voor en bleef de verbinding voorgoed in FIN-WAIT-1 hangen.
func TestTCPLostBareFIN(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagFIN) {
		t.Fatalf("expected exactly one FIN, got %+v", segs)
	}
	// De FIN verdwijnt op de lijn. Vóór de deadline gebeurt er niets...
	w.advance(500 * time.Millisecond)
	if segs := w.drain(w.a); len(segs) != 0 {
		t.Fatalf("retransmit before RTO deadline: %+v", segs)
	}
	// ...en erna komt hij terug.
	w.advance(600 * time.Millisecond)
	segs = w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagFIN) {
		t.Fatalf("lost bare FIN was not retransmitted: %+v", segs)
	}
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}
	// Nu netjes afleveren: b hoort EOF te zien en a komt via FIN-WAIT-2 los.
	w.b.recv(segs[0], w.now)
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("after delivery: a=%s b=%s", w.a.state, w.b.state)
	}
	if _, err := w.b.read(make([]byte, 8)); err != errTCPClosed {
		t.Fatal("b did not see EOF after peer FIN")
	}
	// b sluit ook; de hele keten moet dichtlopen.
	w.b.close()
	w.pump()
	if w.b.state != tcpClosed {
		t.Fatalf("b = %s, want CLOSED", w.b.state)
	}
	w.advance(2 * time.Second) // TIME-WAIT verloopt
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a = %s, want CLOSED after TIME-WAIT", w.a.state)
	}
}

// TestTCPRTOInFinWait1KeepsFIN — BEVINDINGEN #2: na een RTO in FIN-WAIT-1
// moet de retransmissie de FIN meenemen, en een ACK die alleen de data dekt
// mag géén overgang naar FIN-WAIT-2 zijn.
func TestTCPRTOInFinWait1KeepsFIN(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.write([]byte("data!"))
	drop := true
	w.dropAtoB = func(seg tcpSeg) bool { return drop }
	w.pump() // data + FIN verdwijnen op de lijn
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}

	// De RTO: de her-zending moet data én FIN dragen.
	drop = false
	w.advance(3 * time.Second)
	segs := w.drain(w.a)
	var gotData, gotFin bool
	for _, s := range segs {
		if len(s.data) > 0 {
			gotData = true
		}
		if s.flags.Has(FlagFIN) {
			gotFin = true
		}
		w.b.recv(s, w.now)
	}
	if !gotData || !gotFin {
		t.Fatalf("RTO retransmission lost part of the sequence space: data=%v fin=%v (%d segs)", gotData, gotFin, len(segs))
	}
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("after recovery: a=%s b=%s", w.a.state, w.b.state)
	}
	if got := readAll(w.b); string(got) != "data!" {
		t.Fatalf("b received %q", got)
	}
}

// TestTCPPartialAckHoldsFinWait1 — de tweede helft van BEVINDINGEN #2: een
// ACK die alleen de data dekt (tot finSeq, niet erover) is geen FIN-ACK en
// mag dus géén overgang naar FIN-WAIT-2 zijn. lneto ging hier wel over en
// gooide de FIN stilzwijgend weg. Merk op: zo'n ACK bevestigt de data échte
// TCP-gewijs, dus de ring geeft die bytes terecht vrij — de toets is puur de
// staat.
func TestTCPPartialAckHoldsFinWait1(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.write([]byte("data!"))
	w.dropAtoB = func(seg tcpSeg) bool { return true }
	w.pump()
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}
	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.finSeq, flags: FlagACK, wnd: 0xffff}, w.now)
	if w.a.state != tcpFinWait1 {
		t.Fatalf("partial ACK moved a to %s, want FIN-WAIT-1", w.a.state)
	}
	// En de FIN blijft bewaakt: de timer staat nog gewapend.
	if !w.a.timerOn {
		t.Fatal("timer disarmed while the FIN is still unacknowledged")
	}
}

// TestTCPLastAckIgnoresStaleACK — BEVINDINGEN #3: LAST-ACK sluit alleen op de
// exacte bevestiging van de FIN; een verouderde of partiële ACK is ruis.
// lneto deed daar Abort() op élke ACK.
func TestTCPLastAckIgnoresStaleACK(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	// b sluit eerst; a beantwoordt niets automatisch (half-close).
	w.b.close()
	w.pump()
	if w.a.state != tcpCloseWait || w.b.state != tcpFinWait2 {
		t.Fatalf("half-close: a=%s b=%s", w.a.state, w.b.state)
	}
	// a mag in CLOSE-WAIT nog schrijven, en sluit dan.
	if _, err := w.a.write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := readAll(w.b); string(got) != "bye" {
		t.Fatalf("b received %q in FIN-WAIT-2", got)
	}
	w.a.close()
	segs := w.drain(w.a) // FIN staat klaar maar leveren we nog niet af
	if w.a.state != tcpLastAck {
		t.Fatalf("a = %s, want LAST-ACK", w.a.state)
	}
	// Verouderde ACK (ack == una): a moet blijven staan.
	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.una, flags: FlagACK, wnd: 0xffff}, w.now)
	if w.a.state != tcpLastAck {
		t.Fatalf("stale ACK moved a to %s, want LAST-ACK", w.a.state)
	}
	// De echte bevestiging sluit hem wél.
	for _, s := range segs {
		w.b.recv(s, w.now)
	}
	w.pump()
	if w.a.state != tcpClosed {
		t.Fatalf("a = %s, want CLOSED", w.a.state)
	}
}

// TestTCPWriteAfterClose — BEVINDINGEN #13: na close() bestaat er geen pad
// meer waarlangs data boven de eigen FIN kan ontstaan.
func TestTCPWriteAfterClose(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.close()
	if _, err := w.a.write([]byte("x")); err != errTCPClosed {
		t.Fatalf("write after close: err = %v, want errTCPClosed", err)
	}
	if err := w.a.close(); err != errTCPClosing {
		t.Fatalf("double close: err = %v, want errTCPClosing", err)
	}
}

// TestTCPFastRetransmitInFinWait1 — BEVINDINGEN #15: drie dup-ACKs lokken ook
// in een sluitstaat een go-back-N uit, zonder op de RTO te wachten.
func TestTCPFastRetransmitInFinWait1(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.write([]byte("lost payload"))
	w.dropAtoB = func(seg tcpSeg) bool { return true }
	w.pump()
	w.a.close()
	w.pump() // ook de FIN verdwijnt
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}
	w.dropAtoB = nil

	// Drie dup-ACKs van de peer — de klok staat stil, dus dit kan alleen via
	// fast retransmit tot een her-zending leiden.
	for i := 0; i < 3; i++ {
		w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.una, flags: FlagACK, wnd: 0xffff}, w.now)
	}
	segs := w.drain(w.a)
	var gotData, gotFin bool
	for _, s := range segs {
		if len(s.data) > 0 && s.seq == w.a.una {
			gotData = true
		}
		if s.flags.Has(FlagFIN) {
			gotFin = true
		}
	}
	if !gotData || !gotFin {
		t.Fatalf("fast retransmit dead in FIN-WAIT-1: data=%v fin=%v", gotData, gotFin)
	}
}

// TestTCPFlowControlAndZeroWindowProbe: de zender respecteert het venster van
// een kleine ontvanger, en een dichtgelopen venster komt via de probe weer
// los — ook als de venster-update op de lijn zou zoekraken.
func TestTCPFlowControlAndZeroWindowProbe(t *testing.T) {
	w := newTCPPair(t, 1024, 16)
	w.connect()

	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte('A' + i%26)
	}
	w.a.write(payload)
	w.pump()
	if inFlight := seqDiff(w.a.nxt, w.a.una); inFlight != 0 {
		t.Fatalf("unacked data left after pump: %d", inFlight)
	}
	if got := w.b.rx.buffered(); got != 16 {
		t.Fatalf("b buffered %d, want its full window of 16", got)
	}

	// b leest telkens leeg; a moet via probes en verse vensters alles kwijt.
	var got []byte
	got = append(got, readAll(w.b)...)
	for round := 0; round < 40 && len(got) < len(payload); round++ {
		w.advance(3 * time.Second)
		w.pump()
		got = append(got, readAll(w.b)...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received %d/%d bytes: %q", len(got), len(payload), got)
	}
}

// TestTCPSimultaneousClose: beide kanten sluiten tegelijk (CLOSING-pad).
func TestTCPSimultaneousClose(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.close()
	w.b.close()
	// Beide FINs kruisen elkaar.
	sa, sb := w.drain(w.a), w.drain(w.b)
	for _, s := range sa {
		w.b.recv(s, w.now)
	}
	for _, s := range sb {
		w.a.recv(s, w.now)
	}
	w.pump()
	w.advance(2 * time.Second)
	w.drain(w.a)
	w.drain(w.b)
	if w.a.state != tcpClosed || w.b.state != tcpClosed {
		t.Fatalf("simultaneous close: a=%s b=%s", w.a.state, w.b.state)
	}
}

// TestTCPMSSSegmentation: één grote write wordt in ≤MSS-stukken geknipt.
func TestTCPMSSSegmentation(t *testing.T) {
	w := newTCPPair(t, 8192, 8192)
	w.connect()
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i)
	}
	w.a.write(payload)
	var segCount int
	for round := 0; round < 8; round++ {
		segs := w.drain(w.a)
		for _, s := range segs {
			if len(s.data) > 1460 {
				t.Fatalf("segment of %d bytes exceeds MSS 1460", len(s.data))
			}
			if len(s.data) > 0 {
				segCount++
			}
			w.b.recv(s, w.now)
		}
		for _, s := range w.drain(w.b) {
			w.a.recv(s, w.now)
		}
	}
	if got := readAll(w.b); !bytes.Equal(got, payload) {
		t.Fatalf("b received %d/%d bytes", len(got), len(payload))
	}
	if segCount < 4 {
		t.Fatalf("expected ≥4 data segments, got %d", segCount)
	}
}

// TestTCPLossyBulkTransfer: bulk over een lijn die elk zevende segment eet,
// beide richtingen. De integriteits-eis: alles komt exact één keer en in
// volgorde aan — het scenario waarin lneto op ijzer stil corrumpeerde.
func TestTCPLossyBulkTransfer(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	w.connect()

	var nA, nB int
	w.dropAtoB = func(seg tcpSeg) bool { nA++; return nA%7 == 0 }
	w.dropBtoA = func(seg tcpSeg) bool { nB++; return nB%11 == 0 }

	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i * 13)
	}
	var got []byte
	written := 0
	for round := 0; round < 400 && len(got) < len(payload); round++ {
		if written < len(payload) {
			n, _ := w.a.write(payload[written:])
			written += n
		}
		w.pump()
		got = append(got, readAll(w.b)...)
		w.advance(1500 * time.Millisecond) // laat RTO's vuren voor de gedropte staarten
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("lossy transfer corrupted: %d/%d bytes", len(got), len(payload))
	}
	// En netjes sluiten over dezelfde slechte lijn.
	w.a.close()
	for round := 0; round < 40 && w.a.state != tcpClosed; round++ {
		w.pump()
		w.advance(2 * time.Second)
		w.drain(w.a)
		w.drain(w.b)
	}
	if w.b.state != tcpCloseWait {
		t.Fatalf("b = %s, want CLOSE-WAIT", w.b.state)
	}
}

// TestTCPRxGrowsUnderPressure: het budgetmodel op de ontvangkant — een
// verbinding die aan de rand van zijn venster loopt verdubbelt zijn ring uit
// de pot; een lege pot laat hem klein (maar werkend).
func TestTCPRxGrowsUnderPressure(t *testing.T) {
	w := newTCPPair(t, 8192, 512)
	pot := &budget{total: 8192}
	w.b.pot, w.b.maxBuf = pot, 4096

	payload := make([]byte, 6000)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	var got []byte
	written := 0
	for round := 0; round < 60 && len(got) < len(payload); round++ {
		if written < len(payload) {
			n, _ := w.a.write(payload[written:])
			written += n
		}
		w.pump()
		got = append(got, readAll(w.b)...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("transfer incomplete: %d/%d", len(got), len(payload))
	}
	if w.b.rx.size() <= 512 {
		t.Fatalf("rx ring never grew under pressure: %d", w.b.rx.size())
	}
	if w.b.rx.size() > 4096 {
		t.Fatalf("rx ring exceeded maxBuf: %d", w.b.rx.size())
	}
	if want := w.b.rx.size() - 512; pot.free() != 8192-want {
		t.Fatalf("budget accounting off: free=%d, want %d", pot.free(), 8192-want)
	}

	// Zelfde druk, lege pot: klein blijven en tóch alles ontvangen.
	w2 := newTCPPair(t, 8192, 512)
	w2.b.pot, w2.b.maxBuf = &budget{total: 0}, 4096
	w2.connect()
	var got2 []byte
	written2 := 0
	for round := 0; round < 60 && len(got2) < 2000; round++ {
		if written2 < 2000 {
			n, _ := w2.a.write(payload[written2:2000])
			written2 += n
		}
		w2.pump()
		got2 = append(got2, readAll(w2.b)...)
	}
	if !bytes.Equal(got2, payload[:2000]) {
		t.Fatalf("empty-pot transfer incomplete: %d/2000", len(got2))
	}
	if w2.b.rx.size() != 512 {
		t.Fatalf("rx ring grew without budget: %d", w2.b.rx.size())
	}
}

// TestTCPTxGrowsWhenPeerOffersWindow: de zendkant groeit alleen als de peer
// méér venster biedt dan de ring groot is — vraag stuurt, niet configuratie.
func TestTCPTxGrowsWhenPeerOffersWindow(t *testing.T) {
	w := newTCPPair(t, 512, 16384)
	pot := &budget{total: 16384}
	w.a.pot, w.a.maxBuf = pot, 8192
	w.connect()

	n, err := w.a.write(make([]byte, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if n <= 512 {
		t.Fatalf("tx ring did not grow on demand: wrote %d", n)
	}
	if w.a.tx.size() > 8192 {
		t.Fatalf("tx ring exceeded maxBuf: %d", w.a.tx.size())
	}
}

// TestTCPHalfOpenGivesUp — de lneto-#6-klasse: een embryo waarvan de peer na
// de SYN zwijgt, geeft na zijn backoff-ladder luid op (RST + Closed) in
// plaats van eeuwig zijn floor-geheugen vast te houden. Er is geen aparte
// reaper: de opgeef-grens zit in de machine zelf, dus hij werkt óók onder
// load (lneto's CheckTimeouts draaide alleen als de listener idle was).
func TestTCPHalfOpenGivesUp(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	// Alleen b meedoen: één SYN erin, daarna stilte.
	segs := w.drain(w.a) // a's SYN
	if len(segs) != 1 || !segs[0].flags.Has(FlagSYN) {
		t.Fatalf("expected one SYN, got %+v", segs)
	}
	w.b.recv(segs[0], w.now)
	var synacks, rsts int
	for round := 0; round < 40 && w.b.state != tcpClosed; round++ {
		for _, s := range w.drain(w.b) {
			switch {
			case s.flags.Has(FlagSYN):
				synacks++
			case s.flags.Has(FlagRST):
				rsts++
			}
			// Niets afleveren: de peer zwijgt.
		}
		w.advance(2 * time.Second)
	}
	if w.b.state != tcpClosed {
		t.Fatalf("half-open embryo never gave up: %s after %d SYN|ACKs", w.b.state, synacks)
	}
	if synacks != 1+tcpMaxRetriesHandshake {
		t.Errorf("SYN|ACK sent %d times, want %d (1 + %d retries)", synacks, 1+tcpMaxRetriesHandshake, tcpMaxRetriesHandshake)
	}
	if rsts != 1 {
		t.Errorf("expected exactly one parting RST, got %d", rsts)
	}
}

// TestTCPDeadPeerGivesUp: een gevestigde peer die verdwijnt met data in
// flight wordt na de data-ladder opgegeven — stilte doodt, uiteindelijk.
func TestTCPDeadPeerGivesUp(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.write([]byte("into the void"))
	w.dropAtoB = func(seg tcpSeg) bool { return true }
	w.dropBtoA = func(seg tcpSeg) bool { return true }
	for round := 0; round < 60 && w.a.state != tcpClosed; round++ {
		w.pump()
		w.advance(90 * time.Second) // ruim voorbij élke rtoMax-stap
	}
	if w.a.state != tcpClosed {
		t.Fatalf("sender to a dead peer never gave up: %s", w.a.state)
	}
}

// TestTCPZeroWindowPeerStaysAlive: het spiegelbeeld — een peer met een dicht
// venster die wél ACKt is een levende peer en wordt nooit opgegeven, hoe lang
// het ook duurt.
func TestTCPZeroWindowPeerStaysAlive(t *testing.T) {
	w := newTCPPair(t, 1024, 16)
	w.connect()
	w.a.write(make([]byte, 64))
	w.pump() // vult b's venster van 16; b leest níét
	for i := 0; i < 3*int(tcpMaxRetriesData); i++ {
		w.advance(90 * time.Second)
		w.pump() // probe eruit, dup-ACK terug: levensteken, teller reset
	}
	if w.a.state != tcpEstablished {
		t.Fatalf("live zero-window peer was killed: %s", w.a.state)
	}
}

// TestTCPRSTKillsEmbryo — de #18-klasse bestaat hier niet: een RST in
// SYN-RCVD sloopt het embryo compleet; een volgende handshake krijgt op
// stack-niveau een verse machine, dus stale window-scale-staat kán niet.
func TestTCPRSTKillsEmbryo(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	segs := w.drain(w.a)
	w.b.recv(segs[0], w.now) // SYN → SYN-RCVD
	w.drain(w.b)             // SYN|ACK eruit
	if w.b.state != tcpSynRcvd {
		t.Fatalf("b = %s, want SYN-RCVD", w.b.state)
	}
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, flags: FlagRST}, w.now)
	if w.b.state != tcpClosed {
		t.Fatalf("RST in SYN-RCVD left %s", w.b.state)
	}
}

// TestTCPSequenceWraparound — dé klassieker uit de gVisor-suite: alle
// sequence-rekenkunde is modulo 2³², dus een verbinding waarvan de nummers
// tijdens de transfer over de nul rollen moet zich identiek gedragen —
// inclusief de close mét finSeq voorbij de wrap.
func TestTCPSequenceWraparound(t *testing.T) {
	// iss zó dat de wrap midden in de bulk valt, aan beide kanten.
	w := newTCPPairISS(t, 8192, 8192, 0xffffff00, 0xfffffe80, 0)
	w.connect()

	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i * 11)
	}
	var got []byte
	written := 0
	for round := 0; round < 60 && len(got) < len(payload); round++ {
		if written < len(payload) {
			n, _ := w.a.write(payload[written:])
			written += n
		}
		w.pump()
		got = append(got, readAll(w.b)...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("transfer across seq wrap corrupted: %d/%d bytes", len(got), len(payload))
	}
	// Rúwe uint32-vergelijking: na de wrap is nxt numeriek kleiner dan iss.
	// (Modulair vergelijken zou hier per definitie "geen wrap" zeggen — dat
	// is precies waarom modulaire rekenkunde werkt.)
	if w.a.nxt >= w.a.iss {
		t.Fatal("test did not actually cross the wrap; adjust iss")
	}
	// En netjes sluiten, met de FIN aan de overkant van de nul.
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("close across wrap: a=%s b=%s", w.a.state, w.b.state)
	}
}

// TestTCPBlindRSTChallengeACK — RFC 5961 §3.2: een RST die in het venster
// valt maar niet exact op rcv.NXT staat is verdacht (blind reset) en krijgt
// een challenge-ACK; alleen de exacte RST sloopt de verbinding.
func TestTCPBlindRSTChallengeACK(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	// In het venster, niet exact: challenge, geen dood.
	w.a.recv(tcpSeg{seq: w.a.rcvNxt + 100, flags: FlagRST}, w.now)
	if w.a.state != tcpEstablished {
		t.Fatalf("in-window RST killed the connection: %s", w.a.state)
	}
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) || segs[0].ack != w.a.rcvNxt {
		t.Fatalf("no challenge ACK on blind RST: %+v", segs)
	}
	// Volledig buiten het venster: stil negeren.
	w.a.recv(tcpSeg{seq: w.a.rcvNxt - 5000, flags: FlagRST}, w.now)
	if w.a.state != tcpEstablished {
		t.Fatalf("out-of-window RST killed the connection: %s", w.a.state)
	}
	// Exact: dood.
	w.a.recv(tcpSeg{seq: w.a.rcvNxt, flags: FlagRST}, w.now)
	if w.a.state != tcpClosed {
		t.Fatalf("exact RST ignored: %s", w.a.state)
	}
}

// TestTCPSYNInEstablishedChallenge — RFC 5961 §4.2: een SYN op een
// gesynchroniseerde verbinding is nooit legitiem; challenge-ACK en verder
// niets (geen staat, geen rcvNxt-beweging).
func TestTCPSYNInEstablishedChallenge(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	before := w.a.rcvNxt
	w.a.recv(tcpSeg{seq: w.a.rcvNxt, flags: FlagSYN, mss: 100, wsOK: true, ws: 7}, w.now)
	if w.a.state != tcpEstablished || w.a.rcvNxt != before {
		t.Fatalf("mid-connection SYN changed state: %s rcvNxt %d→%d", w.a.state, before, w.a.rcvNxt)
	}
	if w.a.peerMSS == 100 || w.a.sndWS == 7 {
		t.Fatal("mid-connection SYN options were honored")
	}
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) {
		t.Fatalf("no challenge ACK on mid-connection SYN: %+v", segs)
	}
}

// TestTCPDuplicateDataReAcked: een retransmissie van al ontvangen data (onze
// ACK raakte zoek) krijgt een verse ACK en wordt níét dubbel gebufferd.
func TestTCPDuplicateDataReAcked(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	seg := tcpSeg{seq: w.a.rcvNxt, ack: w.a.nxt, flags: FlagACK | FlagPSH,
		wnd: 0xffff, data: []byte("once")}
	w.a.recv(seg, w.now)
	w.drain(w.a) // de eerste ACK
	w.a.recv(seg, w.now)
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) || segs[0].ack != w.a.rcvNxt {
		t.Fatalf("duplicate data not re-acked: %+v", segs)
	}
	if got := readAll(w.a); string(got) != "once" {
		t.Fatalf("duplicate was buffered twice: %q", got)
	}
}

// TestTCPOutOfOrderDupAck: het v1-contract — een out-of-order segment wordt
// gedropt mét een onmiddellijke dup-ACK (ack = rcvNxt), zodat de peer via
// fast retransmit herstelt zonder dat wij reassembleren.
func TestTCPOutOfOrderDupAck(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	w.connect()
	w.a.recv(tcpSeg{seq: w.a.rcvNxt + 1460, ack: w.a.nxt, flags: FlagACK | FlagPSH,
		wnd: 0xffff, data: []byte("future data")}, w.now)
	segs := w.drain(w.a)
	if len(segs) != 1 || segs[0].ack != w.a.rcvNxt || len(segs[0].data) != 0 {
		t.Fatalf("no immediate dup-ACK on out-of-order data: %+v", segs)
	}
	if w.a.rx.buffered() != 0 {
		t.Fatal("out-of-order data was buffered in a v1 in-order-only receiver")
	}
}

// TestTCPAckBeyondNxtIgnored: een ACK voor data die we nooit stuurden mag de
// boekhouding niet raken; we herbevestigen onze werkelijkheid met een ACK.
func TestTCPAckBeyondNxtIgnored(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	una := w.a.una
	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.nxt + 1000, flags: FlagACK, wnd: 0xffff}, w.now)
	if w.a.una != una {
		t.Fatalf("future ACK advanced una: %d → %d", una, w.a.una)
	}
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) {
		t.Fatalf("future ACK not answered: %+v", segs)
	}
}

// TestTCPPeerWindowShrinkClamped: een peer die zijn venster onder wat al in
// flight is trekt (reneging — mág niet, gebeurt tóch) mag ons niet laten
// panikeren of over het venster heen laten zenden; herstel zodra het weer
// opent.
func TestTCPPeerWindowShrinkClamped(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	w.connect()

	// Venster kunstmatig klein: b adverteert 4 bytes.
	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.nxt, flags: FlagACK, wnd: 4}, w.now)
	w.a.write([]byte("twelve bytes"))
	segs := w.drain(w.a)
	var sent int
	for _, s := range segs {
		sent += len(s.data)
	}
	if sent != 4 {
		t.Fatalf("sent %d bytes into a 4-byte window", sent)
	}
	// Venster weer open (zelfde seq, hogere ack-loze update mag niet — dus
	// een verse ACK van b): de rest volgt.
	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.nxt, flags: FlagACK, wnd: 0xffff}, w.now)
	segs = w.drain(w.a)
	for _, s := range segs {
		sent += len(s.data)
	}
	if sent != len("twelve bytes") {
		t.Fatalf("did not resume after window reopened: %d bytes", sent)
	}
}

// TestTCPTinyMSS: een peer met een kleine MSS krijgt segmenten die er ook
// echt in passen.
func TestTCPTinyMSS(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	// Onderschep b's SYN|ACK en verklein de MSS-optie naar 100.
	w.dropBtoA = nil
	segs := w.drain(w.a)
	w.b.recv(segs[0], w.now)
	sa := w.drain(w.b)
	if len(sa) != 1 || !sa[0].flags.Has(FlagSYN) {
		t.Fatalf("expected SYN|ACK, got %+v", sa)
	}
	sa[0].mss = 100
	w.a.recv(sa[0], w.now)
	w.pump()
	if w.a.state != tcpEstablished {
		t.Fatalf("a = %s", w.a.state)
	}
	w.a.write(make([]byte, 1000))
	for _, s := range w.drain(w.a) {
		if len(s.data) > 100 {
			t.Fatalf("segment of %d bytes exceeds negotiated MSS 100", len(s.data))
		}
	}
}

// TestTCPWindowScalingCarriesLargeWindow: met wederzijdse WS-aanbieding
// draagt de venster-boekhouding echte waarden boven 64KiB — de reden dat WS
// vanaf dag één in v1 zit (het 40MB-server-venster).
func TestTCPWindowScalingCarriesLargeWindow(t *testing.T) {
	w := newTCPPairISS(t, 512<<10, 512<<10, 1000, 5000, 4)
	w.connect()
	if !w.a.wsOn || !w.b.wsOn || w.a.sndWS != 4 || w.b.sndWS != 4 {
		t.Fatalf("WS not negotiated: a on=%v shift=%d, b on=%v shift=%d",
			w.a.wsOn, w.a.sndWS, w.b.wsOn, w.b.sndWS)
	}
	// b ontving a's handshake-ACK als geschaald segment: zijn beeld van a's
	// venster moet ver boven het ongeschaalde plafond liggen.
	if w.b.sndWnd <= 0xffff {
		t.Fatalf("b sees a window of %d, want > 65535 through scaling", w.b.sndWnd)
	}
}

// TestTCPTimeWaitReAcksFIN: een dupliceerde FIN (onze laatste ACK raakte
// zoek) wordt in TIME-WAIT opnieuw beantwoord, anders blijft de peer in
// LAST-ACK hangen.
func TestTCPTimeWaitReAcksFIN(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.close()
	w.pump()
	w.b.close()
	segs := w.drain(w.b) // b's FIN
	for _, s := range segs {
		w.a.recv(s, w.now)
	}
	w.drain(w.a) // a's afsluitende ACK (die "verliezen" we: niet afleveren)
	if w.a.state != tcpTimeWait {
		t.Fatalf("a = %s, want TIME-WAIT", w.a.state)
	}
	// b herzendt zijn FIN; a moet opnieuw ACKen.
	for _, s := range segs {
		w.a.recv(s, w.now)
	}
	re := w.drain(w.a)
	if len(re) != 1 || !re[0].flags.Has(FlagACK) {
		t.Fatalf("TIME-WAIT did not re-ACK a duplicate FIN: %+v", re)
	}
}

// TestTCPCloseInSynSent: sluiten vóór er iets gesynchroniseerd is kost geen
// FIN — er is geen peer die er iets mee kan.
func TestTCPCloseInSynSent(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.drain(w.a) // SYN eruit, niemand antwoordt
	if w.a.state != tcpSynSent {
		t.Fatalf("a = %s, want SYN-SENT", w.a.state)
	}
	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	if w.a.state != tcpClosed {
		t.Fatalf("close in SYN-SENT left %s", w.a.state)
	}
	if segs := w.drain(w.a); len(segs) != 0 {
		t.Fatalf("close in SYN-SENT emitted %+v", segs)
	}
	if err := w.a.close(); err != errTCPClosed {
		t.Fatalf("second close = %v, want errTCPClosed", err)
	}
}

// TestTCPRefusedDialSeesRST: een SYN naar een dichte poort krijgt RST|ACK; de
// dialer weet dan dat het "nee" is en niet "stilte" (de socket-laag maakt er
// connection-refused van).
func TestTCPRefusedDialSeesRST(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	segs := w.drain(w.a)
	w.a.recv(tcpSeg{seq: 0, ack: segs[0].seq + 1, flags: FlagRST | FlagACK}, w.now)
	if w.a.state != tcpClosed {
		t.Fatalf("a = %s, want CLOSED", w.a.state)
	}
	if !w.a.refused {
		t.Fatal("refused flag not set: the dialer cannot tell 'no' from 'silence'")
	}
	// Een RST met een ACK die onze SYN niet dekt is ruis en doodt niets.
	w2 := newTCPPair(t, 1024, 1024)
	s2 := w2.drain(w2.a)
	w2.a.recv(tcpSeg{seq: 0, ack: s2[0].seq + 99, flags: FlagRST | FlagACK}, w2.now)
	if w2.a.state != tcpSynSent {
		t.Fatalf("bogus RST killed SYN-SENT: %s", w2.a.state)
	}
}

// TestTCPAbortSendsSingleRST: abort levert precies één RST en daarna stilte —
// geen storm, geen tweede leven.
func TestTCPAbortSendsSingleRST(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.abort()
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagRST) {
		t.Fatalf("abort emitted %+v, want one RST", segs)
	}
	if segs := w.drain(w.a); len(segs) != 0 {
		t.Fatalf("aborted connection kept talking: %+v", segs)
	}
	// En de peer die de RST krijgt gaat mee dood.
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, ack: w.b.nxt, flags: FlagRST | FlagACK}, w.now)
	if w.b.state != tcpClosed {
		t.Fatalf("b = %s after RST, want CLOSED", w.b.state)
	}
}

// TestTCPHalfCloseKeepsReceiving: na ónze FIN mag de peer blijven sturen en
// moeten wij die bytes gewoon afleveren (RFC 9293 §3.5 half-close). Dat is
// het pad van een HTTP-client die zijn request afsluit en dan het antwoord
// leest.
func TestTCPHalfCloseKeepsReceiving(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	w.connect()
	w.a.write([]byte("GET /"))
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("half-close: a=%s b=%s", w.a.state, w.b.state)
	}
	if got := readAll(w.b); string(got) != "GET /" {
		t.Fatalf("b received %q", got)
	}
	// b antwoordt ná onze FIN.
	if _, err := w.b.write([]byte("HTTP/1.1 200 OK")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := readAll(w.a); string(got) != "HTTP/1.1 200 OK" {
		t.Fatalf("a received %q after half-close", got)
	}
	// En dan sluit b ook: alles netjes dicht.
	w.b.close()
	w.pump()
	w.advance(2 * time.Second)
	w.drain(w.a)
	if w.a.state != tcpClosed || w.b.state != tcpClosed {
		t.Fatalf("final: a=%s b=%s", w.a.state, w.b.state)
	}
}
