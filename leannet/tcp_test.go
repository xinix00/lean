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
	// fast retransmit tot een her-zending leiden. Mét het ongewijzigde venster:
	// een duplicate ACK vereist dat ook (RFC 5681 §2) — de oude 0xffff maakte
	// van de eerste ACK een venster-update, geen duplicaat (review 13-08,
	// negentiende ronde).
	wnd := uint16(w.a.sndWnd)
	for i := 0; i < 3; i++ {
		w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.una, flags: FlagACK, wnd: wnd}, w.now)
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

// TestTCPTxKrimptOpDeLaatsteAck — de ACK die de zendring leegmaakt moet hem ook
// naar de vloer terugbrengen, want op een gepoolde verbinding is dat het LAATSTE
// segment: er komt geen venster-update meer achteraan die het alsnog zou doen.
// De eerste versie van de shrink-aanroep stond vóór de una-update en vuurde dus
// alleen op ná-verkeer — de stack-test haalde dat (live pompen sturen updates),
// het gemeten scenario niet (review 13-08). Deze test levert de cumulatieve ACK
// als allerlaatste segment, deterministisch.
func TestTCPTxKrimptOpDeLaatsteAck(t *testing.T) {
	w := newTCPPair(t, tcpFloorTx, 32<<10)
	pot := &budget{total: 256 << 10}
	if !pot.reserve(2 * tcpFloorTx) {
		t.Fatal("pot te klein voor de handgemaakte ringen")
	}
	// maxBuf klemt sinds de vierde reviewronde rx+tx SAMEN; 32K laat de
	// zendring naar 16K groeien naast de 4K-ontvangring.
	w.a.pot, w.a.maxBuf = pot, 32<<10
	w.connect()
	base := pot.used

	payload := make([]byte, 16<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := w.a.write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("write: %d van %d bytes (%v) — de ring hoort naar maxBuf te groeien", n, len(payload), err)
	}
	if w.a.tx.size() <= tcpFloorTx {
		t.Fatal("de zendring is niet gegroeid; deze test meet dan niets")
	}
	w.pump() // alle data + ACKs, tot beide kanten stil zijn

	if got := w.a.tx.buffered(); got != 0 {
		t.Fatalf("na de pump staat er nog %d bytes onbevestigd", got)
	}
	if got := w.a.tx.size(); got != tcpFloorTx {
		t.Fatalf("zendring is %d bytes na de laatste ACK, wil de vloer %d — "+
			"de gegroeide ring blijft staan tot iets ánders nog een ACK stuurt", got, tcpFloorTx)
	}
	if pot.used != base {
		t.Fatalf("pot draagt %d bytes, wil %d — de groei is niet teruggestort", pot.used, base)
	}
}

// TestTCPOutOfWindowAckRaaktDeMachineNiet — RFC 9293 §3.10.7.4, stap één: een
// segment buiten het receive-venster mag níets aan de machine veranderen (geen
// venster-update, geen retry-reset), alleen een verse ACK uitlokken. Zonder die
// toets verzette een verdwaald segment met een ver-toekomstige SEQ het
// zendvenster — wl1 was ouder, dus de update-regel liet hem door (review 13-08).
func TestTCPOutOfWindowAckRaaktDeMachineNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	before := c.sndWnd

	seg := tcpSeg{
		seq:   c.rcvNxt + uint32(c.rx.free()) + 999, // ver buiten het venster
		ack:   c.nxt,                                // op zich een geldige ack
		flags: FlagACK,
		wnd:   1, // zou het zendvenster naar 1 slaan als hij doorkwam
	}
	c.recv(seg, w.now)

	if c.sndWnd != before {
		t.Fatalf("out-of-window segment verzette het zendvenster: %d → %d", before, c.sndWnd)
	}
	if !c.needAck {
		t.Fatal("geen verse ACK klaargezet voor een onacceptabel segment")
	}
}

// TestTCPAdvEdgeVolgtDeDraad — de toezegging die shrinkRx moet respecteren is
// wat er op de DRAAD stond, ná schaling en de 16-bit-clamp. free() nemen pinde
// bij een grote ring zonder window scaling het dubbele vast van wat ooit beloofd
// was (review 13-08).
func TestTCPAdvEdgeVolgtDeDraad(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10) // ws-shift 0
	w.connect()
	c := w.a
	if c.wsOn && c.rcvWS != 0 {
		t.Fatal("deze test wil een verbinding zonder effectieve schaling")
	}
	c.rx.grow(make([]byte, 128<<10)) // groot en leeg: free() = 128K
	c.advEdge = 0
	c.advertisedWnd()
	if d := seqDiff(c.advEdge, c.rcvNxt); d != 0xffff {
		t.Fatalf("advEdge belooft %d bytes, op de draad stond %d", d, 0xffff)
	}
}

// TestTCPResetIsGeenEOF — een RST is een fout, geen einde van de stroom. Vóór
// de fix werd élke gesloten machine io.EOF op de socket-rand, en dan eindigt
// een half HTTP-antwoord als "compleet maar kort bestand" (review 13-08).
func TestTCPResetIsGeenEOF(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()

	// De peer stuurt data en breekt dan het gesprek met een exacte RST.
	if _, err := w.b.write([]byte("half antwoord")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	w.a.recv(tcpSeg{seq: w.a.rcvNxt, ack: w.a.nxt, flags: FlagRST}, w.now)

	buf := make([]byte, 64)
	_, err := w.a.read(buf)
	if err == nil || err == errTCPClosed {
		t.Fatalf("read na RST gaf %v — dit hoort een reset-fout te zijn, geen (netjes) einde", err)
	}
	if _, werr := w.a.write([]byte("x")); werr != errTCPReset {
		t.Fatalf("write na RST gaf %v, wil errTCPReset", werr)
	}
}

// TestTCPFutureAckDroptHeleSegment — RFC 9293 §3.10.7.4: een ACK voor iets dat
// we nooit stuurden betekent ACK-terug-en-droppen, voor het HELE segment. Vóór
// de fix kreeg de peer wel de correctie-ACK, maar belandde de meegestuurde data
// gewoon in de ring (review 13-08).
func TestTCPFutureAckDroptHeleSegment(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	before := c.rcvNxt

	c.recv(tcpSeg{
		seq:   c.rcvNxt,
		ack:   c.nxt + 1000, // bevestigt iets dat nooit verstuurd is
		flags: FlagACK,
		wnd:   1024,
		data:  []byte("smokkelwaar"),
	}, w.now)

	if c.rcvNxt != before || c.rx.buffered() != 0 {
		t.Fatalf("data van een future-ACK-segment is verwerkt (rcvNxt %d→%d, buffered %d)",
			before, c.rcvNxt, c.rx.buffered())
	}
	if !c.needAck {
		t.Fatal("geen correctie-ACK klaargezet")
	}
}

// TestTCPSynRcvdEistEchteBevestiging — in SYN-RCVD is alleen SND.UNA < ACK ≤
// SND.NXT een bevestiging; ACK == ISS is dat niet en mag dus ook geen
// levensteken zijn. Vóór de fix resette zo'n ACK de opgeef-teller en kon een
// peer een embryo (en zijn floor-budget) eeuwig vastpinnen (review 13-08).
func TestTCPSynRcvdEistEchteBevestiging(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	// Alleen de handshake-helft: SYN van a bij b bezorgen, b's SYN|ACK laten
	// staan — b zit nu in SYN-RCVD.
	for _, seg := range w.drain(w.a) {
		w.b.recv(seg, w.now)
	}
	w.drain(w.b) // SYN|ACK eruit (bewust niet bezorgd)
	if w.b.state != tcpSynRcvd {
		t.Fatalf("b is %s, wil SYN-RCVD", w.b.state)
	}

	w.b.retries = 3 // alsof er al een paar retransmissies liepen
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, ack: w.b.iss, flags: FlagACK, wnd: 1024}, w.now)

	if w.b.retries != 3 {
		t.Fatalf("retries %d na een ongeldige ACK, wil 3 — dit was het eeuwige levensteken", w.b.retries)
	}
	if !w.b.rst.set || w.b.rst.withAck || w.b.rst.seq != w.b.iss {
		t.Fatal("geen <SEQ=SEG.ACK><CTL=RST> klaargezet voor de ongeldige ACK")
	}
	if w.b.state != tcpSynRcvd {
		t.Fatalf("b is %s geworden, wil SYN-RCVD blijven", w.b.state)
	}
}

// TestTCPDataVoorbijDeRandWordtGetrimd — een segment dat op rcv.NXT begint maar
// voorbij het geadverteerde venster doorloopt wordt tot de rand geknipt. Vóór
// de fix groeide de ring op commando van de peer (groei-op-vol) en werd de
// hele payload geabsorbeerd, dwars door de belofte heen (review 13-08).
func TestTCPDataVoorbijDeRandWordtGetrimd(t *testing.T) {
	w := newTCPPair(t, 1<<10, 8<<10)
	pot := &budget{total: 256 << 10}
	pot.reserve(2 << 10) // de handgemaakte ringen van a
	w.a.pot, w.a.maxBuf = pot, 64<<10
	w.connect()
	c := w.a

	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 || promised > 1<<10 {
		t.Fatalf("test-aanname stuk: belofte is %d bytes", promised)
	}

	// Twee keer de belofte, in één segment.
	oversized := make([]byte, 2*promised)
	for i := range oversized {
		oversized[i] = byte(i)
	}
	before := c.rcvNxt
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 4096, data: oversized}, w.now)

	if got := seqDiff(c.rcvNxt, before); got != promised {
		t.Fatalf("machine nam %d bytes aan, de belofte was %d — de rand is geen rand", got, promised)
	}
	if c.rx.buffered() != promised {
		t.Fatalf("ring draagt %d bytes, wil %d", c.rx.buffered(), promised)
	}
}

// TestTCPFinOpDeRandWordtGeknipt — payload die het venster PRECIES vult laat
// de FIN één sequence-byte buiten de belofte liggen: die hoort eruit. En een
// kale FIN op een dicht venster idem. Beide komen in de retransmissie terug
// zodra het venster ruimte biedt (review 13-08, tweede ronde).
func TestTCPFinOpDeRandWordtGeknipt(t *testing.T) {
	w := newTCPPair(t, 2<<10, 8<<10)
	w.connect()
	c := w.a
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 {
		t.Fatalf("test-aanname stuk: belofte is %d", promised)
	}

	// Data die de belofte exact vult, mét FIN: data erin, FIN eruit.
	data := make([]byte, promised)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096, data: data}, w.now)
	if c.finRcvd {
		t.Fatal("de FIN lag één byte buiten het venster en is toch geaccepteerd")
	}
	if got := c.rx.buffered(); got != promised {
		t.Fatalf("data zelf hoort er wél in: %d van %d", got, promised)
	}

	// Kale FIN op het (nu dichte) venster: ook geknipt.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096}, w.now)
	if c.finRcvd {
		t.Fatal("kale FIN op een dicht venster is geaccepteerd")
	}

	// App leest, venster adverteert opnieuw, de herhaalde FIN mag erin.
	// drain, niet pump: de data hierboven is búiten b om geïnjecteerd, dus b
	// zou a's ACKs als future-ACKs zien en de pomp settelt nooit.
	readAll(c)
	w.drain(c) // de venster-update eruit (advertisedWnd zet advEdge op)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096}, w.now)
	if !c.finRcvd {
		t.Fatal("de herhaalde FIN binnen het verse venster is geweigerd")
	}
}

// TestTCPSynVensterIsEenBelofte — de SYN(-ACK)-advertentie is een gedane
// belofte en wordt sinds review 13-08 (vierentwintigste ronde) als advEdge
// vastgelegd. Vóór die fix viel rcvWnd tot de eerste gewone ACK terug op de
// fysieke ring: na een snelle application-read accepteerde de machine data
// voorbij de rand die de SYN-ACK beloofde. (Dit verving de oude
// "geen groei vóór de eerste advertentie"-test: die toestand bestaat niet
// meer — de handshake ís de eerste advertentie.)
func TestTCPSynVensterIsEenBelofte(t *testing.T) {
	w := newTCPPair(t, 8<<10, 1<<10) // b: kleine ring, klein venster

	// Handshake handmatig, zodat b's eerste gewone ACK nog niet vertrokken is.
	for _, seg := range w.drain(w.a) { // SYN
		w.b.recv(seg, w.now)
	}
	synACK := w.drain(w.b) // SYN|ACK: dít is de belofte
	if len(synACK) != 1 || !synACK[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN-ACK, kreeg %v", synACK)
	}
	promise := uint32(synACK[0].wnd)
	for _, seg := range synACK {
		w.a.recv(seg, w.now)
	}
	for _, seg := range w.drain(w.a) { // de vestigende ACK
		w.b.recv(seg, w.now)
	}
	if !w.b.advSet || seqDiff(w.b.advEdge, w.b.rcvNxt) != int(promise) {
		t.Fatalf("de SYN-ACK-belofte is niet vastgelegd: advSet=%v rand=%d wil %d",
			w.b.advSet, seqDiff(w.b.advEdge, w.b.rcvNxt), promise)
	}

	// De peer vult de belofte exact, de app leest alles weg — en dan komt er
	// méér, voorbij de beloofde rand, vóórdat een nieuwe advertentie de deur
	// uit is. Dat hoort geweigerd te worden, hoe leeg de ring ook is.
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, ack: w.b.nxt, flags: FlagACK, wnd: 4096,
		data: make([]byte, promise)}, w.now)
	if got := len(readAll(w.b)); got != int(promise) {
		t.Fatalf("b las %d bytes, wil de volle belofte (%d)", got, promise)
	}
	voorNxt := w.b.rcvNxt
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, ack: w.b.nxt, flags: FlagACK, wnd: 4096,
		data: []byte("smokkel")}, w.now)
	if w.b.rcvNxt != voorNxt || len(readAll(w.b)) != 0 {
		t.Fatal("data voorbij de SYN-beloofde rand werd geaccepteerd — de belofte telt niet")
	}
}

// TestTCPVoortgangslozeAcksPinnenNiet — een peer die elke retransmissie keurig
// beantwoordt (zelfde ack, open venster) zonder ooit een byte aan te nemen,
// hield de verbinding en haar buffers vóór de fix onbeperkt vast: élke geldige
// ACK gold als levensteken. Nu reset alleen voortgang (of een dicht venster:
// persist) de opgeef-teller (review 13-08, vierde ronde).
func TestTCPVoortgangslozeAcksPinnenNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("data die nooit aangenomen wordt")); err != nil {
		t.Fatal(err)
	}
	w.drain(c) // de data de deur uit; timer gewapend

	// De vastpin-peer: op elke RTO een keurige ACK zónder voortgang, venster
	// wagenwijd open.
	for i := 0; i < 64 && c.state != tcpClosed; i++ {
		w.advance(time.Minute) // ruim voorbij elke RTO
		w.drain(c)             // retransmissie eruit (telt retries op)
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 8192}, w.now)
	}
	if c.state != tcpClosed {
		t.Fatal("64 voortgangsloze ACKs later leeft de verbinding nog — de pin werkt")
	}
	if !c.reset {
		t.Fatal("het einde hoort een luide opgave te zijn (reset), geen stille dood")
	}
}

// TestTCPZeroWindowPersistBlijftLeven — de keerzijde: een peer met een DICHT
// venster is gewoon levend (RFC 9293 §3.8.6.1) en zijn probe-antwoorden zijn
// per definitie voortgangsloos. Die verbinding mag níet sterven.
func TestTCPZeroWindowPersistBlijftLeven(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Peer sluit zijn venster.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("wacht maar")); err != nil {
		t.Fatal(err)
	}
	// Twintig probe-rondes: elke probe krijgt een ACK met venster 0 terug.
	for i := 0; i < 20; i++ {
		w.advance(time.Minute)
		w.drain(c) // de zero-window-probe eruit
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	}
	if c.state == tcpClosed {
		t.Fatal("een levende zero-window-peer is doodverklaard — persist hoort eeuwig te mogen leven")
	}
}

// TestTCPMaxBufKlemtDeVerbinding — maxBuf is de grens van rx+tx SAMEN:
// "Budget/4 per verbinding" was met een per-ring-toets stiekem het dubbele
// (review 13-08, vierde ronde).
func TestTCPMaxBufKlemtDeVerbinding(t *testing.T) {
	w := newTCPPair(t, 4<<10, 32<<10)
	pot := &budget{total: 1 << 20}
	pot.reserve(2 * (4 << 10))
	w.a.pot, w.a.maxBuf = pot, 16<<10
	w.connect()
	c := w.a

	// Beide kanten onder druk: schrijven tot de zendring niet meer groeit, en
	// binnenkomende data die de ontvangring vult.
	big := make([]byte, 64<<10)
	c.write(big)
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised > 0 {
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 8192,
			data: make([]byte, promised)}, w.now)
	}

	if total := c.rx.size() + c.tx.size(); total > 16<<10 {
		t.Fatalf("verbinding draagt %d bytes aan ringen, maxBuf is %d — de grens is per ring i.p.v. per verbinding", total, 16<<10)
	}
}

// TestTCPSynRstOpentGeenEmbryo — Has(ACK|RST) eist beide bits, dus de oude
// guard weerde alleen die combinatie: een kale SYN|RST opende een embryo
// (20KiB floor) en kreeg een SYN|ACK terug — naar een host die net RST zei.
// RFC 9293 §3.10.7.2: een RST in LISTEN wordt genegeerd (review 13-08,
// vijfde ronde).
func TestTCPSynRstOpentGeenEmbryo(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.b.recv(tcpSeg{seq: 42, flags: FlagSYN | FlagRST, wnd: 1024}, w.now)
	if w.b.state != tcpClosed {
		t.Fatalf("b is %s na een SYN|RST, wil CLOSED (genegeerd)", w.b.state)
	}
	if segs := w.drain(w.b); len(segs) != 0 {
		t.Fatalf("b antwoordde met %d segment(en) op een SYN|RST, wil stilte", len(segs))
	}
}

// TestTCPAcceptabilityVolgtDeBelofte — tussen een app-read en de venster-update
// die hem meldt is rx.free() groter dan wat de peer weet; de machine
// accepteerde dan segmenten (mét hun ACK-bijwerking) die buiten de belofte
// vallen (review 13-08, vijfde ronde).
func TestTCPAcceptabilityVolgtDeBelofte(t *testing.T) {
	w := newTCPPair(t, 1<<10, 8<<10)
	w.connect()
	c := w.a
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 {
		t.Fatal("test-aanname stuk: geen belofte")
	}
	// De ring is fysiek ruimer dan de belofte? Niet per se — dus maak hem zo:
	// vul tot de belofte, laat de app alles lezen (free groeit), maar houd de
	// venster-update tegen (geen drain).
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 4096,
		data: make([]byte, promised)}, w.now)
	readAll(c) // free() is nu de hele ring; de belofte is verbruikt (advEdge == rcvNxt)

	before := c.sndWnd
	seg := tcpSeg{
		seq:   c.rcvNxt, // netjes op rcvNxt, maar de belofte is OP
		ack:   c.nxt,
		flags: FlagACK,
		wnd:   1, // zou het zendvenster verzetten als hij doorkwam
		data:  []byte("voorbij de belofte"),
	}
	c.recv(seg, w.now)
	if c.rx.buffered() != 0 {
		t.Fatalf("data buiten de belofte is geabsorbeerd (%d bytes)", c.rx.buffered())
	}
	if c.sndWnd != before {
		t.Fatalf("segment buiten de belofte verzette het zendvenster: %d → %d", before, c.sndWnd)
	}
	if !c.needAck {
		t.Fatal("geen correctie-ACK klaargezet")
	}
}

// TestTCPStaleZeroWindowResetGeenRetries — een herhaalde OUDE zero-window-ACK
// (afgewezen door de WL1/WL2-poort) mag de opgeef-teller niet resetten: anders
// pint hij de verbinding terwijl het effectieve venster gewoon openstaat
// (review 13-08, vijfde ronde).
func TestTCPStaleZeroWindowResetGeenRetries(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Echte voortgang eerst, zodat wl1/wl2 vooruit staan.
	if _, err := c.write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	c.retries = 5

	// Het segment moet ACCEPTABEL zijn (seq == rcvNxt — anders sterft hij al
	// bij segAcceptable en raakt de test de WL1/WL2-poort nooit; zo was de
	// eerste versie van deze test óók vóór de fix groen, review 13-08,
	// zevende ronde) maar zijn venster-update moet AFGEWEZEN worden: wl1
	// kunstmatig nieuwer, alsof er al een latere update verwerkt is.
	c.wl1 = c.rcvNxt + 1000
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	if c.retries != 5 {
		t.Fatalf("retries %d na een afgewezen zero-window-update, wil 5", c.retries)
	}
	if c.sndWnd == 0 {
		t.Fatal("de afgewezen update is tóch toegepast")
	}
}

// TestTCPHerhaaldeFinHerstartTimeWait — RFC 9293 §3.10.7.4: een geherhaalde
// FIN in TIME-WAIT (onze ACK raakte zoek) start de 2MSL-termijn opnieuw.
// Zonder herstart kon de staat vlak ná de verse ACK verlopen — en als dié ACK
// óók zoekraakt, is er niemand meer om te antwoorden (review 13-08, tiende
// ronde).
func TestTCPHerhaaldeFinHerstartTimeWait(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	// Nette sluiting van beide kanten: a → TIME-WAIT.
	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if err := w.b.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if w.a.state != tcpTimeWait {
		t.Fatalf("a is %s, wil TIME-WAIT", w.a.state)
	}

	// Vlak vóór het verval komt de FIN van b opnieuw (alsof onze ACK zoek was).
	w.advance(time.Duration(tcpTimeWaitDur) - 100*time.Millisecond)
	dupFin := tcpSeg{seq: w.a.rcvNxt - 1, ack: w.a.nxt, flags: FlagACK | FlagFIN, wnd: 1024}
	w.a.recv(dupFin, w.now)
	w.drain(w.a) // de verse ACK eruit

	// Ruim voorbij de OORSPRONKELIJKE deadline, maar binnen de herstarte.
	w.advance(500 * time.Millisecond)
	w.drain(w.a)
	if w.a.state != tcpTimeWait {
		t.Fatal("TIME-WAIT verliep op de oorspronkelijke termijn — de herhaalde FIN herstartte hem niet")
	}
	// En na de volle herstarte termijn loopt hij gewoon af.
	w.advance(time.Duration(tcpTimeWaitDur))
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a is %s na de herstarte termijn, wil CLOSED", w.a.state)
	}
}

// TestTCPVreemdeFinRektTimeWaitNiet — de herstart van TIME-WAIT is er voor de
// échte duplicate FIN (positie exact rcvNxt-1); elke out-of-window FIN laten
// tellen liet verkeer met het juiste vier-tupel het TIME-WAIT-slot en zijn
// buffers onbeperkt vasthouden (review 13-08, twaalfde ronde).
func TestTCPVreemdeFinRektTimeWaitNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if err := w.b.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if w.a.state != tcpTimeWait {
		t.Fatalf("a is %s, wil TIME-WAIT", w.a.state)
	}

	// Vlak vóór het verval: een FIN op de VERKEERDE plek (niet rcvNxt-1).
	w.advance(time.Duration(tcpTimeWaitDur) - 100*time.Millisecond)
	rogue := tcpSeg{seq: w.a.rcvNxt - 100, ack: w.a.nxt, flags: FlagACK | FlagFIN, wnd: 1024}
	w.a.recv(rogue, w.now)
	w.drain(w.a) // de verse ACK mag eruit, maar de klok hoort stil te staan

	// Voorbij de oorspronkelijke termijn hoort de staat gewoon te verlopen.
	w.advance(500 * time.Millisecond)
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a is %s — een vreemde FIN rekte TIME-WAIT op", w.a.state)
	}
}

// TestTCPVerlorenProbeHersteltBijVensterOpening — de zero-window-probe duwt
// nxt één byte voorbij het venster; gaat hij verloren en opent de peer daarna
// het venster met ack==una, dan begon de eerstvolgende verzending ná de
// ontbrekende byte: out-of-order bij de ontvanger, en een kleine write levert
// nooit drie dup-ACKs — herstel wachtte dus op de tijdens de persist
// opgebouwde RTO, tot een minuut (review 13-08, zeventiende ronde). Het
// venster-openen hoort een go-back-N te doen: opnieuw vanaf una.
func TestTCPVerlorenProbeHersteltBijVensterOpening(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Peer sluit zijn venster; een kleine write staat klaar.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	w.drain(c) // wapent de persist-timer: er past nu niets in het venster
	una := c.una
	// De probe gaat de deur uit en gaat VERLOREN (niet bezorgen).
	w.advance(time.Minute)
	if segs := w.drain(c); len(segs) == 0 || len(segs[0].data) != 1 {
		t.Fatalf("verwachtte één probe-byte, kreeg %v", segs)
	}
	// Het venster gaat open, zonder voortgang: ack == una.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: una, flags: FlagACK, wnd: 1024}, w.now)
	segs := w.drain(c)
	if len(segs) == 0 {
		t.Fatal("geen hertransmissie na het openen van het venster")
	}
	if segs[0].seq != una {
		t.Fatalf("hertransmissie begint op %d, wil una (%d) — de verloren probe-byte blijft anders een gat", segs[0].seq, una)
	}
}

// TestTCPHertransmissieBemeetGeenRTT — Karn volledig: goBackN zette timing
// uit, maar postTx startte op de hertransmissie meteen een verse meting op
// oude sequence-ruimte; de ambigue ACK daarvan vouwde in updateRTT en zette
// backoff=0 (review 13-08, negentiende ronde). Een sample hoort alleen te
// starten op ruimte die nog nooit verzonden is.
func TestTCPHertransmissieBemeetGeenRTT(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	if segs := w.drain(c); len(segs) != 1 {
		t.Fatalf("verwachtte het datasegment, kreeg %d", len(segs))
	} // ... en het gaat verloren
	if !c.timing {
		t.Fatal("de eerste verzending hoort juist wél bemeten te worden")
	}
	w.advance(2 * time.Second) // ruim voorbij de RTO
	segs := w.drain(c)         // de hertransmissie (via goBackN in het timerpad)
	if len(segs) == 0 || len(segs[0].data) == 0 {
		t.Fatalf("geen hertransmissie, kreeg %v", segs)
	}
	if c.timing {
		t.Fatal("de hertransmissie startte een RTT-sample op oude ruimte — Karn zegt: niet bemeten")
	}
}

// TestTCPPersistVervuiltDeRTONiet — elke zero-window-probe verdubbelde c.rto
// mee in het algemene timerpad, en die vervuiling bleef ná de venster-opening
// staan: verlies van de directe hertransmissie kostte dan opnieuw bijna een
// minuut. Persist heeft nu zijn eigen ladder (review 13-08, negentiende
// ronde).
func TestTCPPersistVervuiltDeRTONiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("wacht maar")); err != nil {
		t.Fatal(err)
	}
	rtoVoor := c.rto
	w.drain(c) // wapent de persist-timer
	for i := 0; i < 6; i++ {
		w.advance(time.Minute)
		w.drain(c) // de probe
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	}
	if c.rto != rtoVoor {
		t.Fatalf("zes probes lieten de RTO groeien van %v naar %v — persist hoort de estimator niet te raken", rtoVoor, c.rto)
	}
	// En na de venster-opening is de persist-episode echt voorbij.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 1024}, w.now)
	if c.persistBackoff != 0 {
		t.Fatalf("persistBackoff is %d na de venster-opening, wil 0", c.persistBackoff)
	}
}

// TestTCPVensterShrinkIsGeenDupAck — een duplicate ACK vereist ook een
// ongewijzigd advertised window (RFC 5681 §2): een shrink gleed anders de
// teller in, en één shrink plus twee echte duplicaten activeerde al fast
// retransmit (review 13-08, negentiende ronde).
func TestTCPVensterShrinkIsGeenDupAck(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	w.drain(c) // het segment is onderweg (en "zoek"): una != nxt
	// Eén shrink en twee échte duplicaten: geen fast retransmit.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 512}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 512}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 512}, w.now)
	for _, s := range w.drain(c) {
		if len(s.data) > 0 {
			t.Fatal("fast retransmit vuurde op een venster-shrink plus twee duplicaten")
		}
	}
	if c.dupacks != 2 {
		t.Fatalf("dupacks = %d, wil 2 (de shrink telt niet mee)", c.dupacks)
	}
}

// TestTCPHandshakeNeemtGeenOudeRSTMee — een ongeldige ACK zet een pending
// RST, maar ingress en de TX-pomp zijn asynchroon: komt daarna de géldige
// bevestiging binnen vóór emit draait, dan was het eerste segment van de
// geslaagde verbinding een RST naar de echte peer (review 13-08, twintigste
// ronde). enterEstablished hoort de weigering te wissen — in beide rollen.
func TestTCPHandshakeNeemtGeenOudeRSTMee(t *testing.T) {
	// Actieve kant (SYN-SENT).
	w := newTCPPair(t, 8<<10, 8<<10)
	a := w.a
	if segs := w.drain(a); len(segs) != 1 || !segs[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN, kreeg %v", segs)
	}
	a.recv(tcpSeg{seq: 9999, ack: a.iss + 5, flags: FlagACK, wnd: 1024}, w.now) // ongeldig: RST klaargezet
	if !a.rst.set {
		t.Fatal("de ongeldige ACK zette geen pending RST — het scenario bestaat niet meer?")
	}
	a.recv(tcpSeg{seq: 5000, ack: a.iss + 1, flags: FlagSYN | FlagACK, wnd: 1024, mss: 1460}, w.now)
	if a.state != tcpEstablished {
		t.Fatalf("a is %s, wil ESTABLISHED", a.state)
	}
	for _, s := range w.drain(a) {
		if s.flags.Has(FlagRST) {
			t.Fatal("SYN-SENT: het eerste segment van de geslaagde verbinding is een RST")
		}
	}

	// Passieve kant (SYN-RCVD).
	w2 := newTCPPair(t, 8<<10, 8<<10)
	b := w2.b
	syn := w2.drain(w2.a)[0]
	b.recv(syn, w2.now)
	if segs := w2.drain(b); len(segs) != 1 || !segs[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN-ACK, kreeg %v", segs)
	} // ... en die raakt zoek; b staat in SYN-RCVD met nxt = iss+1
	b.recv(tcpSeg{seq: b.rcvNxt, ack: b.iss, flags: FlagACK, wnd: 1024}, w2.now) // ongeldig
	if !b.rst.set {
		t.Fatal("de ongeldige ACK zette geen pending RST bij de passieve kant")
	}
	b.recv(tcpSeg{seq: b.rcvNxt, ack: b.iss + 1, flags: FlagACK, wnd: 1024}, w2.now) // geldig
	if b.state != tcpEstablished {
		t.Fatalf("b is %s, wil ESTABLISHED", b.state)
	}
	for _, s := range w2.drain(b) {
		if s.flags.Has(FlagRST) {
			t.Fatal("SYN-RCVD: het eerste segment van de geslaagde verbinding is een RST")
		}
	}
}

// TestTCPNietDuplicaatBreektDeReeks — de dup-teller hoort te resetten op elk
// tussenliggend niet-duplicaat: "twee duplicaten, shrink, duplicaat"
// activeerde anders alsnog fast retransmit, en een FIN met hetzelfde ack
// telde ook mee terwijl RFC 5681 SYN/FIN uitsluit (review 13-08, twintigste
// ronde).
func TestTCPNietDuplicaatBreektDeReeks(t *testing.T) {
	opzet := func() (*tcpWire, *tcpConn, uint16) {
		w := newTCPPair(t, 8<<10, 8<<10)
		w.connect()
		c := w.a
		if _, err := c.write([]byte("hallo")); err != nil {
			t.Fatal(err)
		}
		w.drain(c) // het segment is "zoek": una != nxt
		return w, c, uint16(c.sndWnd)
	}

	// Twee duplicaten, een shrink, en nóg een duplicaat: reeks gebroken.
	w, c, wnd := opzet()
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd / 2}, w.now) // shrink: geen duplicaat
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd / 2}, w.now)
	for _, s := range w.drain(c) {
		if len(s.data) > 0 {
			t.Fatal("fast retransmit vuurde terwijl de shrink de reeks had moeten breken")
		}
	}
	if c.dupacks != 1 {
		t.Fatalf("dupacks = %d, wil 1 (reeks gebroken door de shrink)", c.dupacks)
	}

	// En een FIN met hetzelfde ack is geen duplicaat.
	w, c, wnd = opzet()
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK | FlagFIN, wnd: wnd}, w.now)
	if c.dupacks != 0 {
		t.Fatalf("dupacks = %d na een FIN, wil 0 (RFC 5681 sluit SYN/FIN uit)", c.dupacks)
	}
}

// TestTCPOudeACKBreektDeReeks — een ACK onder una is per RFC 5681 §2 geen
// duplicaat (verkeerd ack-nummer) en hoort dus, net als elk ander
// niet-duplicaat, de dup-reeks te breken: "twee duplicaten, oud ACK,
// duplicaat" activeerde anders alsnog fast retransmit (review 13-08,
// eenentwintigste ronde).
func TestTCPOudeACKBreektDeReeks(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Eerst échte voortgang, zodat er een "oud" ack-nummer bestaat.
	if _, err := c.write([]byte("aaaa")); err != nil {
		t.Fatal(err)
	}
	oud := c.una
	w.pump() // bezorgd en bevestigd: una is opgeschoven
	if c.una == oud {
		t.Fatal("geen voortgang; het harnas bezorgde de eerste write niet")
	}
	// Dan een verzending die zoekraakt.
	if _, err := c.write([]byte("bbbb")); err != nil {
		t.Fatal(err)
	}
	w.drain(c)
	wnd := uint16(c.sndWnd)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: oud, flags: FlagACK, wnd: wnd}, w.now) // oud: geen duplicaat
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	for _, s := range w.drain(c) {
		if len(s.data) > 0 {
			t.Fatal("fast retransmit vuurde terwijl het oude ACK de reeks had moeten breken")
		}
	}
	if c.dupacks != 1 {
		t.Fatalf("dupacks = %d, wil 1 (reeks gebroken door het oude ACK)", c.dupacks)
	}
}

// TestTCPAdvertentieOverleeftDeWrap — advEdge gebruikte 0 als "nog niets
// geadverteerd", maar door sequence-wrap ís 0 een geldige rechterrand: met
// een peer-ISS vlak onder de wrap bleef de belofte eruitzien als unset, viel
// rcvWnd terug op de fysieke ring en werd nét vrijgekomen, nooit
// geadverteerde ruimte geaccepteerd (review 13-08, tweeëntwintigste ronde).
func TestTCPAdvertentieOverleeftDeWrap(t *testing.T) {
	// issB zó dat a's rechterrand (rcvNxt + venster) precies op 0 uitkomt:
	// rcvNxt = issB+1, venster = 8192 (lege ring, ws=0).
	issB := ^uint32(8192) // = 2³²−8193
	w := newTCPPairISS(t, 8<<10, 8<<10, 1000, issB, 0)
	w.connect()
	a := w.a

	if _, err := w.b.write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := len(readAll(a)); got != 100 {
		t.Fatalf("a las %d bytes, wil 100", got)
	}
	// De ring is weer leeg, maar de BELOFTE staat nog op de oude rand: tussen
	// de read en de eerstvolgende venster-update mag rcvWnd alleen de belofte
	// exposeren — niet de verse ringruimte.
	if promise := a.rcvWnd(); promise != 8192-100 {
		t.Fatalf("rcvWnd = %d, wil de belofte (%d) — de nul-rand telt kennelijk als unset en exposeert de verse ring", promise, 8192-100)
	}
}

// TestTCPKaleFinRespecteertHetVenster — de FIN neemt een sequence-plek in en
// valt onder dezelfde vensterdiscipline als data: bij een dicht zendvenster
// ging hij onvoorwaardelijk de deur uit, één plek buiten het peer-venster,
// zonder dat de persist-timer de probe had toegestaan (review 13-08,
// vierentwintigste ronde).
func TestTCPKaleFinRespecteertHetVenster(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Peer sluit zijn venster; daarna willen wij sluiten.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.drain(c) {
		if s.flags.Has(FlagFIN) {
			t.Fatal("de kale FIN ging door een dicht venster zonder probe")
		}
	}
	// Via de persist-timer mag hij wél — als de probe.
	w.advance(time.Minute)
	fin := false
	for _, s := range w.drain(c) {
		if s.flags.Has(FlagFIN) {
			fin = true
		}
	}
	if !fin {
		t.Fatal("de FIN kwam ook via de persist-probe nooit — sluiten op een dicht venster is een deadlock")
	}
}

// TestTCPGroeiBoektDePiek — tijdens een ringwissel leven de oude en nieuwe
// ring even naast elkaar: alleen de delta reserveren liet 16→32MiB transient
// 48MiB gebruiken terwijl de boekhouding 32MiB zei — op een 64MB-board alsnog
// een OOM (review 13-08, vierentwintigste ronde). growRing reserveert nu de
// hele nieuwe maat en geeft de oude pas ná de wissel terug.
func TestTCPGroeiBoektDePiek(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	// Pot met ruimte voor de delta (8K) maar niet voor de piek (oud 8K naast
	// nieuw 16K vraagt 16K vrije ruimte).
	pot := &budget{total: 2*(8<<10) + 12<<10}
	pot.reserve(2 * (8 << 10)) // de bestaande ringen
	c.pot, c.maxBuf = pot, 64<<10
	if c.growRing(&c.rx) {
		t.Fatal("growRing groeide terwijl de pot de piek (oud+nieuw) niet draagt")
	}
	// Met piek-ruimte lukt het wél, en netto is alleen de delta geboekt.
	pot.total = 2*(8<<10) + (16 << 10)
	if !c.growRing(&c.rx) {
		t.Fatal("growRing weigerde terwijl de piek past")
	}
	if pot.used != 8<<10+16<<10 {
		t.Fatalf("pot.used = %d na de groei, wil %d (tx + nieuwe rx; de oude rx is terug)", pot.used, 8<<10+16<<10)
	}
}

// TestTCPOudePrefixWordtGetrimd — een retransmissie kan vóór rcvNxt beginnen
// maar nieuwe bytes dragen; het exact-op-rcvNxt-vereiste dropte dan het hele
// segment, nieuwe bytes incluis (review 13-08, vijfentwintigste ronde).
func TestTCPOudePrefixWordtGetrimd(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	// a stuurt "abc"; b ontvangt en de app leest het.
	if _, err := w.a.write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := string(readAll(w.b)); got != "abc" {
		t.Fatalf("opzet: b las %q", got)
	}
	// Een gemergde retransmissie: oude prefix ("bc") plus nieuwe suffix ("def").
	seg := tcpSeg{seq: w.b.rcvNxt - 2, ack: w.b.nxt, flags: FlagACK, wnd: 1024,
		data: []byte("bcdef")}
	w.b.recv(seg, w.now)
	if got := string(readAll(w.b)); got != "def" {
		t.Fatalf("b las %q, wil de nieuwe suffix %q — de oude prefix is niet getrimd", got, "def")
	}
}

// TestTCPKrimpLuktOpVollePot — reserveer-dan-wissel faalde bij een randvolle
// pot per definitie, waardoor lege gegroeide verbindingen de pot permanent
// bleven vullen: krimp geeft nu eerst terug en reserveert dan (review 13-08,
// zevenentwintigste ronde).
func TestTCPKrimpLuktOpVollePot(t *testing.T) {
	c := &tcpConn{}
	c.rx = ring{buf: make([]byte, 32<<10)}
	c.pot = &budget{total: 32 << 10, used: 32 << 10} // randvol
	c.maxBuf = 64 << 10
	c.advSet = true // keep = advEdge-rcvNxt = 0: niets toegezegd
	c.shrinkRx()
	if got := c.rx.size(); got != tcpFloorRx {
		t.Fatalf("ring is %d na krimp op een volle pot, wil de vloer (%d)", got, tcpFloorRx)
	}
	if c.pot.used != tcpFloorRx {
		t.Fatalf("pot.used = %d, wil %d — de krimp gaf de oude ring niet terug", c.pot.used, tcpFloorRx)
	}
}

// TestTCPPeerMSSWordtGeklemd — een peer-MSS boven MTU-40 zou frames boven de
// draadmaat laten bouwen; de optie is een bovengrens, dus klemmen mag altijd
// (review 13-08, zevenentwintigste ronde).
func TestTCPPeerMSSWordtGeklemd(t *testing.T) {
	c := &tcpConn{}
	c.takeSynOptions(tcpSeg{mss: 9000})
	if c.peerMSS != MTU-40 {
		t.Fatalf("peerMSS = %d, wil de klem op %d", c.peerMSS, MTU-40)
	}
}

// TestTCPFinWait2HoudtGeenBudgetVast — een pool-geëvicte verbinding (volle
// close) hield zijn 20KiB de hele FIN-WAIT-2-termijn (20s) vast; de volle
// close geeft de ontvangring meteen terug (abandonRead) en de zendring zodra
// de FIN bevestigd is (review 13-08, achtentwintigste ronde).
func TestTCPFinWait2HoudtGeenBudgetVast(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	pot := &budget{total: 1 << 20}
	pot.reserve(2 * (8 << 10))
	w.a.pot = pot
	w.connect()
	if err := w.a.close(); err != nil { // half-close: FIN eruit
		t.Fatal(err)
	}
	w.a.abandonRead() // de volle close van de socket-laag
	w.pump()          // b bevestigt de FIN; b sluit zelf niet
	if w.a.state != tcpFinWait2 {
		t.Fatalf("a is %s, wil FIN-WAIT-2", w.a.state)
	}
	if pot.used != 0 {
		t.Fatalf("pot.used = %d in FIN-WAIT-2, wil 0 — de ringen blijven de pot vullen", pot.used)
	}
}

// TestTCPHandshakeResetDeRTO — een moeizame handshake (SYN-verlies) blies de
// RTO op, en het eerste dataverlies daarna wachtte de volle opgestapelde
// backoff (review 13-08, achtentwintigste ronde).
func TestTCPHandshakeResetDeRTO(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	// De eerste twee SYN's raken zoek: backoff en rto lopen op.
	if segs := w.drain(w.a); len(segs) != 1 {
		t.Fatal("verwachtte de SYN")
	}
	w.advance(2 * time.Second)
	w.drain(w.a) // retransmissie, ook zoek
	w.advance(4 * time.Second)
	if w.a.rto <= tcpRTOInitial {
		t.Fatalf("opzet: rto is %v, hoort opgeblazen te zijn", w.a.rto)
	}
	w.pump() // en nu slaagt de handshake
	if w.a.state != tcpEstablished {
		t.Fatalf("a is %s, wil ESTABLISHED", w.a.state)
	}
	if w.a.rto != tcpRTOInitial || w.a.retries != 0 || w.a.backoff != 0 {
		t.Fatalf("na de handshake: rto=%v retries=%d backoff=%d — de opgeblazen ladder bleef staan",
			w.a.rto, w.a.retries, w.a.backoff)
	}
}

// TestTCPCumulatieveACKNaGoBackN — goBackN spoelt nxt (de zendcursor) terug;
// een geldige cumulatieve ACK die de hertransmissie vóór was werd dan als
// "future" geweigerd — bij een gekrompen venster zelfs blijvend. nxt is nu
// weer een cursor en maxSent de high-watermark (review 13-08,
// negenentwintigste ronde).
func TestTCPCumulatieveACKNaGoBackN(t *testing.T) {
	w := newTCPPair(t, 32<<10, 32<<10)
	w.connect()
	c := w.a
	if _, err := c.write(make([]byte, 4000)); err != nil { // 3 segmenten à ~1460
		t.Fatal(err)
	}
	segs := w.drain(c) // ... en alle drie zoek
	if len(segs) < 3 {
		t.Fatalf("opzet: %d segmenten, wil ≥3", len(segs))
	}
	hoog := c.nxt
	wnd := uint16(c.sndWnd)
	for i := 0; i < 3; i++ { // drie duplicaten → fast retransmit spoelt nxt terug
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	}
	if c.nxt == hoog {
		t.Fatal("opzet: goBackN heeft de cursor niet teruggespoeld")
	}
	// De cumulatieve ACK voor álles arriveert vóór de pomp opnieuw zond.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: hoog, flags: FlagACK, wnd: wnd}, w.now)
	if c.una != hoog {
		t.Fatalf("una = %d, wil %d — de geldige cumulatieve ACK is geweigerd", c.una, hoog)
	}
	if c.nxt != hoog {
		t.Fatalf("nxt = %d, wil bijgetrokken tot %d", c.nxt, hoog)
	}
}

// TestTCPDubbeleSYNVerliestDeFinaleACKNiet — een dubbele SYN (onze SYN-ACK
// leek zoek) spoelt nxt terug naar iss voor de hertransmissie. Kruiste de
// FINALE ACK van de peer die dubbele SYN op de draad, dan wees de
// SYN-RCVD-poort (ack ≤ nxt, met nxt=iss) hem af als toekomst-ACK en resette
// hij de eigen handshake met een RST (review 13-08, eenendertigste ronde). De
// maat hoort maxSent te zijn: die rewindt nooit.
func TestTCPDubbeleSYNVerliestDeFinaleACKNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)

	syn := w.drain(w.a) // de SYN van de actieve kant
	if len(syn) != 1 || !syn[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN, kreeg %v", syn)
	}
	w.b.recv(syn[0], w.now)
	for _, seg := range w.drain(w.b) { // SYN-ACK naar a
		w.a.recv(seg, w.now)
	}
	final := w.drain(w.a) // de finale ACK — nog even vasthouden
	if len(final) != 1 || final[0].ack != w.b.iss+1 {
		t.Fatalf("verwachtte de finale ACK op iss+1, kreeg %v", final)
	}

	// Het netwerk-duplicaat van de oorspronkelijke SYN arriveert eerst: b
	// spoelt nxt terug voor een verse SYN-ACK.
	w.b.recv(syn[0], w.now)
	// En dán pas de finale ACK, vóór die hertransmissie de deur uit is.
	w.b.recv(final[0], w.now)

	if w.b.state != tcpEstablished {
		t.Fatalf("b staat in %v, wil ESTABLISHED — de finale ACK is afgewezen", w.b.state)
	}
	for _, seg := range w.drain(w.b) {
		if seg.flags.Has(FlagRST) {
			t.Fatal("b resette zijn eigen handshake op de kruisende finale ACK")
		}
	}
}
