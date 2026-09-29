package leannet

import (
	"bytes"
	"testing"
	"time"
)

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

	w.advance(500 * time.Millisecond)
	if segs := w.drain(w.a); len(segs) != 0 {
		t.Fatalf("retransmit before RTO deadline: %+v", segs)
	}

	w.advance(600 * time.Millisecond)
	segs = w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagFIN) {
		t.Fatalf("lost bare FIN was not retransmitted: %+v", segs)
	}
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}

	w.b.recv(segs[0], w.now)
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("after delivery: a=%s b=%s", w.a.state, w.b.state)
	}
	if _, err := w.b.read(make([]byte, 8)); err != errTCPClosed {
		t.Fatal("b did not see EOF after peer FIN")
	}

	w.b.close()
	w.pump()
	if w.b.state != tcpClosed {
		t.Fatalf("b = %s, want CLOSED", w.b.state)
	}
	w.advance(2 * time.Second)
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a = %s, want CLOSED after TIME-WAIT", w.a.state)
	}
}

func TestTCPRTOInFinWait1KeepsFIN(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.write([]byte("data!"))
	drop := true
	w.dropAtoB = func(seg tcpSeg) bool { return drop }
	w.pump()
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}

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

	if !w.a.timerOn {
		t.Fatal("timer disarmed while the FIN is still unacknowledged")
	}
}

func TestTCPLastAckIgnoresStaleACK(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.b.close()
	w.pump()
	if w.a.state != tcpCloseWait || w.b.state != tcpFinWait2 {
		t.Fatalf("half-close: a=%s b=%s", w.a.state, w.b.state)
	}

	if _, err := w.a.write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := readAll(w.b); string(got) != "bye" {
		t.Fatalf("b received %q in FIN-WAIT-2", got)
	}
	w.a.close()
	segs := w.drain(w.a)
	if w.a.state != tcpLastAck {
		t.Fatalf("a = %s, want LAST-ACK", w.a.state)
	}

	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.una, flags: FlagACK, wnd: 0xffff}, w.now)
	if w.a.state != tcpLastAck {
		t.Fatalf("stale ACK moved a to %s, want LAST-ACK", w.a.state)
	}

	for _, s := range segs {
		w.b.recv(s, w.now)
	}
	w.pump()
	if w.a.state != tcpClosed {
		t.Fatalf("a = %s, want CLOSED", w.a.state)
	}
}

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

func TestTCPFastRetransmitInFinWait1(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.write([]byte("lost payload"))
	w.dropAtoB = func(seg tcpSeg) bool { return true }
	w.pump()
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait1 {
		t.Fatalf("a = %s, want FIN-WAIT-1", w.a.state)
	}
	w.dropAtoB = nil

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

func TestTCPSimultaneousClose(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.close()
	w.b.close()

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
		w.advance(1500 * time.Millisecond)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("lossy transfer corrupted: %d/%d bytes", len(got), len(payload))
	}

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

// TestTCPRxGrowsOnFullSegments is de ijzer-conditie van 18-08 (LicheeRV): een
// SNELLE lezer draint de ring tussen de segmenten door, dus vrij==0 komt op
// aankomstmoment nooit voor — en een MSS-gekwantiseerde zender vult een
// 16KiB-venster sowieso nooit exact (11×1460 = 16060). Een vol-alleen-trigger
// hield elke bulk-transfer daardoor voorgoed op de vloer: image-streams op
// ~170KB/s terwijl de budget-pot leeg stond te wachten. Het groei-signaal is
// het VOLLE segment (len == advMSS): dat zegt "de zender is venster-beperkt".
// Chat-verkeer stuurt nooit volle segmenten en blijft op de vloer.
func TestTCPRxGrowsOnFullSegments(t *testing.T) {
	w := newTCPPair(t, 32<<10, 4096)
	pot := &budget{total: 64 << 10}
	w.b.pot, w.b.maxBuf = pot, 16<<10
	w.connect()

	payload := make([]byte, 12<<10)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	var got []byte
	written := 0
	for round := 0; round < 200 && len(got) < len(payload); round++ {
		if written < len(payload) {
			n, _ := w.a.write(payload[written:])
			written += n
		}
		// Per segment bezorgen en meteen lezen: de snelle lezer. De ring van b
		// is zo nooit vol op aankomstmoment — precies de conditie waarin een
		// vol-alleen-trigger nooit vuurt.
		for _, seg := range w.drain(w.a) {
			w.b.recv(seg, w.now)
			got = append(got, readAll(w.b)...)
		}
		for _, seg := range w.drain(w.b) {
			w.a.recv(seg, w.now)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("transfer incomplete: %d/%d", len(got), len(payload))
	}
	if w.b.rx.size() <= 4096 {
		t.Fatalf("rx ring never grew for a window-limited sender with a fast reader: %d", w.b.rx.size())
	}
	if w.b.rx.size() > 16<<10 {
		t.Fatalf("rx ring exceeded maxBuf: %d", w.b.rx.size())
	}

	// Chat-verkeer: kleine segmenten, nooit vol — geen reden om te groeien.
	w2 := newTCPPair(t, 32<<10, 4096)
	w2.b.pot, w2.b.maxBuf = &budget{total: 64 << 10}, 16<<10
	w2.connect()
	for round := 0; round < 40; round++ {
		w2.a.write([]byte("ping"))
		for _, seg := range w2.drain(w2.a) {
			w2.b.recv(seg, w2.now)
			readAll(w2.b)
		}
		for _, seg := range w2.drain(w2.b) {
			w2.a.recv(seg, w2.now)
		}
	}
	if w2.b.rx.size() != 4096 {
		t.Fatalf("rx ring grew on small segments: %d", w2.b.rx.size())
	}
}

// TestTCPWindowUpdateForBlockedSender: een snelle lezer houdt de ring leeg,
// dus de klassieke bijna-vol-conditie vuurt nooit — maar de ZENDER heeft zijn
// geadverteerde belofte opgemaakt en wacht. De read hoort dan een window-
// update te queuen die de emit-lus ook zónder inkomend verkeer verstuurt;
// anders loopt elke bulk-transfer op de persist-probe-klok van de peer
// (gemeten 18-08 op de LicheeRV: mediaan 165ms per venster-ronde, 100% van de
// transfertijd was wachten).
func TestTCPWindowUpdateForBlockedSender(t *testing.T) {
	w := newTCPPair(t, 32<<10, 4096)
	w.connect()

	// De zender mag precies het geadverteerde venster (~4096) kwijt; daarna
	// blokkeert hij op zijn opgemaakte belofte.
	payload := make([]byte, 8<<10)
	w.a.write(payload)
	for _, seg := range w.drain(w.a) {
		w.b.recv(seg, w.now)
		readAll(w.b) // de snelle lezer: ring leeg vóór het volgende segment
	}

	// Zonder nieuw inkomend verkeer moet b nu uit zichzelf een window-update
	// emitten die de zender weer ruimte geeft.
	segs := w.drain(w.b)
	if len(segs) == 0 {
		t.Fatal("geen window-update voor een geblokkeerde zender — de transfer zou op de persist-probe van de peer lopen")
	}
	last := segs[len(segs)-1]
	if int(last.wnd)<<w.b.rcvWS < int(w.b.peerMSS) {
		t.Fatalf("update adverteert geen bruikbaar venster: %d", int(last.wnd)<<w.b.rcvWS)
	}
}

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

func TestTCPHalfOpenGivesUp(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)

	segs := w.drain(w.a)
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

func TestTCPDeadPeerGivesUp(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.write([]byte("into the void"))
	w.dropAtoB = func(seg tcpSeg) bool { return true }
	w.dropBtoA = func(seg tcpSeg) bool { return true }
	for round := 0; round < 60 && w.a.state != tcpClosed; round++ {
		w.pump()
		w.advance(90 * time.Second)
	}
	if w.a.state != tcpClosed {
		t.Fatalf("sender to a dead peer never gave up: %s", w.a.state)
	}
}

func TestTCPZeroWindowPeerStaysAlive(t *testing.T) {
	w := newTCPPair(t, 1024, 16)
	w.connect()
	w.a.write(make([]byte, 64))
	w.pump()
	for i := 0; i < 3*int(tcpMaxRetriesData); i++ {
		w.advance(90 * time.Second)
		w.pump()
	}
	if w.a.state != tcpEstablished {
		t.Fatalf("live zero-window peer was killed: %s", w.a.state)
	}
}

func TestTCPFullCloseDeadlineKanNietWordenVernieuwd(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	// Zet de peer in persist en laat data plus FIN achter het dichte venster
	// wachten. Geldige updates blijven aantonen dat de peer leeft.
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("blijft achter nul")); err != nil {
		t.Fatal(err)
	}
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
	c.abandonRead(w.now)
	original := c.closeDeadline

	for i := 0; i < 4; i++ {
		w.advance(4 * time.Second)
		w.drain(c)
		if c.state == tcpClosed {
			t.Fatalf("full close gaf al na %v op", time.Duration(w.now-(original-tcpFullCloseDur)))
		}
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
		c.abandonRead(w.now) // een dubbele net.Conn.Close mag de termijn niet rekken
		if c.closeDeadline != original {
			t.Fatalf("close-deadline verschoof van %d naar %d", original, c.closeDeadline)
		}
	}

	w.advance(time.Duration(original-w.now) + time.Nanosecond)
	segs := w.drain(c)
	if c.state != tcpClosed || !c.reset {
		t.Fatalf("zero-window-peer hield full close voorbij de absolute termijn: state=%s reset=%v", c.state, c.reset)
	}
	rst := false
	for _, seg := range segs {
		rst = rst || seg.flags.Has(FlagRST)
	}
	if !rst {
		t.Fatal("absolute full-close timeout gaf op zonder RST")
	}
}

func TestTCPCloseWaitRuimtAlleenInactiviteitOp(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	if err := w.b.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	c := w.a
	if c.state != tcpCloseWait || c.closeDeadline == 0 {
		t.Fatalf("peer-FIN gaf state=%s deadline=%d, wil begrensde CLOSE-WAIT", c.state, c.closeDeadline)
	}

	// Een echte app-read/write zou dezelfde touch doen. Activiteit vernieuwt de
	// idle-termijn; louter tijd en duplicate ACKs doen dat niet.
	first := c.closeDeadline
	w.advance(time.Minute)
	c.touchCloseWait(w.now)
	if c.closeDeadline <= first {
		t.Fatal("app-activiteit vernieuwde de CLOSE-WAIT idle-termijn niet")
	}
	refreshed := c.closeDeadline
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: uint16(c.sndWnd)}, w.now)
	if c.closeDeadline != refreshed {
		t.Fatal("duplicate ACK vernieuwde de CLOSE-WAIT idle-termijn")
	}

	w.advance(time.Duration(refreshed-w.now) + time.Nanosecond)
	segs := w.drain(c)
	if c.state != tcpClosed || !c.reset {
		t.Fatalf("vergeten CLOSE-WAIT werd niet gereapt: state=%s reset=%v", c.state, c.reset)
	}
	rst := false
	for _, seg := range segs {
		rst = rst || seg.flags.Has(FlagRST)
	}
	if !rst {
		t.Fatal("CLOSE-WAIT timeout gaf op zonder RST")
	}

	idle := newTCPPair(t, 8<<10, 8<<10)
	idle.connect()
	idle.advance(10 * time.Duration(tcpCloseWaitDur))
	idle.drain(idle.a)
	if idle.a.state != tcpEstablished || idle.a.nextDeadline() != 0 {
		t.Fatalf("legitiem idle ESTABLISHED werd geraakt: state=%s deadline=%d", idle.a.state, idle.a.nextDeadline())
	}
}

func TestTCPFullCloseVervangtBijnaVerlopenCloseWaitDeadline(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	if err := w.b.close(); err != nil {
		t.Fatal(err)
	}
	w.pump()
	c := w.a
	if c.state != tcpCloseWait {
		t.Fatalf("peer-FIN gaf state=%s, wil CLOSE-WAIT", c.state)
	}

	w.advance(time.Duration(c.closeDeadline-w.now) - 5*time.Second)
	old := c.closeDeadline
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
	c.abandonRead(w.now)
	want := w.now + tcpFullCloseDur
	if c.closeDeadline != want || c.closeDeadline <= old {
		t.Fatalf("full Close deadline=%d, want verse absolute deadline %d (oude=%d)",
			c.closeDeadline, want, old)
	}
	if c.lifecycleExpired(old + 1) {
		t.Fatal("oude CLOSE-WAIT deadline verkortte de full-Close grace")
	}
	if !c.lifecycleExpired(want) {
		t.Fatal("verse full-Close deadline werd niet absoluut afgedwongen")
	}
}

func TestTCPRSTKillsEmbryo(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	segs := w.drain(w.a)
	w.b.recv(segs[0], w.now)
	w.drain(w.b)
	if w.b.state != tcpSynRcvd {
		t.Fatalf("b = %s, want SYN-RCVD", w.b.state)
	}
	w.b.recv(tcpSeg{seq: w.b.rcvNxt, flags: FlagRST}, w.now)
	if w.b.state != tcpClosed {
		t.Fatalf("RST in SYN-RCVD left %s", w.b.state)
	}
}

func TestTCPSequenceWraparound(t *testing.T) {

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

	if w.a.nxt >= w.a.iss {
		t.Fatal("test did not actually cross the wrap; adjust iss")
	}

	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("close across wrap: a=%s b=%s", w.a.state, w.b.state)
	}
}

func TestTCPBlindRSTChallengeACK(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()

	w.a.recv(tcpSeg{seq: w.a.rcvNxt + 100, flags: FlagRST}, w.now)
	if w.a.state != tcpEstablished {
		t.Fatalf("in-window RST killed the connection: %s", w.a.state)
	}
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) || segs[0].ack != w.a.rcvNxt {
		t.Fatalf("no challenge ACK on blind RST: %+v", segs)
	}

	w.a.recv(tcpSeg{seq: w.a.rcvNxt - 5000, flags: FlagRST}, w.now)
	if w.a.state != tcpEstablished {
		t.Fatalf("out-of-window RST killed the connection: %s", w.a.state)
	}

	w.a.recv(tcpSeg{seq: w.a.rcvNxt, flags: FlagRST}, w.now)
	if w.a.state != tcpClosed {
		t.Fatalf("exact RST ignored: %s", w.a.state)
	}
}

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

func TestTCPDuplicateDataReAcked(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	seg := tcpSeg{seq: w.a.rcvNxt, ack: w.a.nxt, flags: FlagACK | FlagPSH,
		wnd: 0xffff, data: []byte("once")}
	w.a.recv(seg, w.now)
	w.drain(w.a)
	w.a.recv(seg, w.now)
	segs := w.drain(w.a)
	if len(segs) != 1 || !segs[0].flags.Has(FlagACK) || segs[0].ack != w.a.rcvNxt {
		t.Fatalf("duplicate data not re-acked: %+v", segs)
	}
	if got := readAll(w.a); string(got) != "once" {
		t.Fatalf("duplicate was buffered twice: %q", got)
	}
}

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

func TestTCPPeerWindowShrinkClamped(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)
	w.connect()

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

	w.a.recv(tcpSeg{seq: w.b.nxt, ack: w.a.nxt, flags: FlagACK, wnd: 0xffff}, w.now)
	segs = w.drain(w.a)
	for _, s := range segs {
		sent += len(s.data)
	}
	if sent != len("twelve bytes") {
		t.Fatalf("did not resume after window reopened: %d bytes", sent)
	}
}

func TestTCPTinyMSS(t *testing.T) {
	w := newTCPPair(t, 4096, 4096)

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

func TestTCPWindowScalingCarriesLargeWindow(t *testing.T) {
	w := newTCPPairISS(t, 512<<10, 512<<10, 1000, 5000, 4)
	w.connect()
	if !w.a.wsOn || !w.b.wsOn || w.a.sndWS != 4 || w.b.sndWS != 4 {
		t.Fatalf("WS not negotiated: a on=%v shift=%d, b on=%v shift=%d",
			w.a.wsOn, w.a.sndWS, w.b.wsOn, w.b.sndWS)
	}

	if w.b.sndWnd <= 0xffff {
		t.Fatalf("b sees a window of %d, want > 65535 through scaling", w.b.sndWnd)
	}
}

func TestTCPTimeWaitReAcksFIN(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.a.close()
	w.pump()
	w.b.close()
	segs := w.drain(w.b)
	for _, s := range segs {
		w.a.recv(s, w.now)
	}
	w.drain(w.a)
	if w.a.state != tcpTimeWait {
		t.Fatalf("a = %s, want TIME-WAIT", w.a.state)
	}

	for _, s := range segs {
		w.a.recv(s, w.now)
	}
	re := w.drain(w.a)
	if len(re) != 1 || !re[0].flags.Has(FlagACK) {
		t.Fatalf("TIME-WAIT did not re-ACK a duplicate FIN: %+v", re)
	}
}

func TestTCPCloseInSynSent(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.drain(w.a)
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

	w2 := newTCPPair(t, 1024, 1024)
	s2 := w2.drain(w2.a)
	w2.a.recv(tcpSeg{seq: 0, ack: s2[0].seq + 99, flags: FlagRST | FlagACK}, w2.now)
	if w2.a.state != tcpSynSent {
		t.Fatalf("bogus RST killed SYN-SENT: %s", w2.a.state)
	}
}

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

	w.b.recv(tcpSeg{seq: w.b.rcvNxt, ack: w.b.nxt, flags: FlagRST | FlagACK}, w.now)
	if w.b.state != tcpClosed {
		t.Fatalf("b = %s after RST, want CLOSED", w.b.state)
	}
}

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

	if _, err := w.b.write([]byte("HTTP/1.1 200 OK")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := readAll(w.a); string(got) != "HTTP/1.1 200 OK" {
		t.Fatalf("a received %q after half-close", got)
	}

	w.b.close()
	w.pump()
	w.advance(2 * time.Second)
	w.drain(w.a)
	if w.a.state != tcpClosed || w.b.state != tcpClosed {
		t.Fatalf("final: a=%s b=%s", w.a.state, w.b.state)
	}
}

func TestTCPTxBehoudtGroeiTotClose(t *testing.T) {
	w := newTCPPair(t, tcpFloorTx, 32<<10)
	pot := &budget{total: 256 << 10}
	if !pot.reserve(2 * tcpFloorTx) {
		t.Fatal("pot te klein voor de handgemaakte ringen")
	}

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
	w.pump()

	if got := w.a.tx.buffered(); got != 0 {
		t.Fatalf("na de pump staat er nog %d bytes onbevestigd", got)
	}
	if got := w.a.tx.size(); got <= tcpFloorTx {
		t.Fatalf("zendring is na de laatste ACK teruggevallen naar %d bytes — "+
			"één bulkstroom zou daardoor steeds opnieuw alloceren", got)
	}
	if pot.used <= base {
		t.Fatalf("pot draagt %d bytes, wil meer dan basis %d zolang de verbinding leeft", pot.used, base)
	}
}

func TestTCPOutOfWindowAckRaaktDeMachineNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	before := c.sndWnd

	seg := tcpSeg{
		seq:   c.rcvNxt + uint32(c.rx.free()) + 999,
		ack:   c.nxt,
		flags: FlagACK,
		wnd:   1,
	}
	c.recv(seg, w.now)

	if c.sndWnd != before {
		t.Fatalf("out-of-window segment verzette het zendvenster: %d → %d", before, c.sndWnd)
	}
	if !c.needAck {
		t.Fatal("geen verse ACK klaargezet voor een onacceptabel segment")
	}
}

func TestTCPAdvEdgeVolgtDeDraad(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if c.wsOn && c.rcvWS != 0 {
		t.Fatal("deze test wil een verbinding zonder effectieve schaling")
	}
	c.rx.grow(make([]byte, 128<<10))
	c.advEdge = 0
	c.advertisedWnd()
	if d := seqDiff(c.advEdge, c.rcvNxt); d != 0xffff {
		t.Fatalf("advEdge belooft %d bytes, op de draad stond %d", d, 0xffff)
	}
}

func TestTCPResetIsGeenEOF(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()

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

func TestTCPFutureAckDroptHeleSegment(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	before := c.rcvNxt

	c.recv(tcpSeg{
		seq:   c.rcvNxt,
		ack:   c.nxt + 1000,
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

func TestTCPSynRcvdEistEchteBevestiging(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)

	for _, seg := range w.drain(w.a) {
		w.b.recv(seg, w.now)
	}
	w.drain(w.b)
	if w.b.state != tcpSynRcvd {
		t.Fatalf("b is %s, wil SYN-RCVD", w.b.state)
	}

	w.b.retries = 3
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

func TestTCPDataVoorbijDeRandWordtGetrimd(t *testing.T) {
	w := newTCPPair(t, 1<<10, 8<<10)
	pot := &budget{total: 256 << 10}
	pot.reserve(2 << 10)
	w.a.pot, w.a.maxBuf = pot, 64<<10
	w.connect()
	c := w.a

	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 || promised > 1<<10 {
		t.Fatalf("test-aanname stuk: belofte is %d bytes", promised)
	}

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

func TestTCPFinOpDeRandWordtGeknipt(t *testing.T) {
	w := newTCPPair(t, 2<<10, 8<<10)
	w.connect()
	c := w.a
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 {
		t.Fatalf("test-aanname stuk: belofte is %d", promised)
	}

	data := make([]byte, promised)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096, data: data}, w.now)
	if c.finRcvd {
		t.Fatal("de FIN lag één byte buiten het venster en is toch geaccepteerd")
	}
	if got := c.rx.buffered(); got != promised {
		t.Fatalf("data zelf hoort er wél in: %d van %d", got, promised)
	}

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096}, w.now)
	if c.finRcvd {
		t.Fatal("kale FIN op een dicht venster is geaccepteerd")
	}

	readAll(c)
	w.drain(c)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK | FlagFIN, wnd: 4096}, w.now)
	if !c.finRcvd {
		t.Fatal("de herhaalde FIN binnen het verse venster is geweigerd")
	}
}

func TestTCPSynVensterIsEenBelofte(t *testing.T) {
	w := newTCPPair(t, 8<<10, 1<<10)

	for _, seg := range w.drain(w.a) {
		w.b.recv(seg, w.now)
	}
	synACK := w.drain(w.b)
	if len(synACK) != 1 || !synACK[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN-ACK, kreeg %v", synACK)
	}
	promise := uint32(synACK[0].wnd)
	for _, seg := range synACK {
		w.a.recv(seg, w.now)
	}
	for _, seg := range w.drain(w.a) {
		w.b.recv(seg, w.now)
	}
	if !w.b.advSet || seqDiff(w.b.advEdge, w.b.rcvNxt) != int(promise) {
		t.Fatalf("de SYN-ACK-belofte is niet vastgelegd: advSet=%v rand=%d wil %d",
			w.b.advSet, seqDiff(w.b.advEdge, w.b.rcvNxt), promise)
	}

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

func TestTCPVoortgangslozeAcksPinnenNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("data die nooit aangenomen wordt")); err != nil {
		t.Fatal(err)
	}
	w.drain(c)

	for i := 0; i < 64 && c.state != tcpClosed; i++ {
		w.advance(time.Minute)
		w.drain(c)
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 8192}, w.now)
	}
	if c.state != tcpClosed {
		t.Fatal("64 voortgangsloze ACKs later leeft de verbinding nog — de pin werkt")
	}
	if !c.reset {
		t.Fatal("het einde hoort een luide opgave te zijn (reset), geen stille dood")
	}
}

func TestTCPZeroWindowPersistBlijftLeven(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("wacht maar")); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		w.advance(time.Minute)
		w.drain(c)
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	}
	if c.state == tcpClosed {
		t.Fatal("een levende zero-window-peer is doodverklaard — persist hoort eeuwig te mogen leven")
	}
}

func TestTCPMaxBufKlemtDeVerbinding(t *testing.T) {
	w := newTCPPair(t, 4<<10, 32<<10)
	pot := &budget{total: 1 << 20}
	pot.reserve(2 * (4 << 10))
	w.a.pot, w.a.maxBuf = pot, 16<<10
	w.connect()
	c := w.a

	big := make([]byte, 64<<10)
	c.write(big)
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised > 0 {
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 8192,
			data: make([]byte, promised)}, w.now)
	}

	// Sinds 04-09 klemt maxBuf élke ring apart: gecombineerd nam de tx-ring
	// van een verbinding die om beurten grote chunks schrijft en leest de
	// hele ruimte, en bleef de rx-ring op zijn vloer — de peer mocht dan
	// 4 KiB per rondje sturen (HopOS system-verbinding, 256 rondjes per MiB).
	if c.rx.size() > 16<<10 || c.tx.size() > 16<<10 {
		t.Fatalf("ringen rx %d / tx %d bytes, maxBuf is %d per ring", c.rx.size(), c.tx.size(), 16<<10)
	}
}

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

func TestTCPAcceptabilityVolgtDeBelofte(t *testing.T) {
	w := newTCPPair(t, 1<<10, 8<<10)
	w.connect()
	c := w.a
	promised := seqDiff(c.advEdge, c.rcvNxt)
	if promised <= 0 {
		t.Fatal("test-aanname stuk: geen belofte")
	}

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 4096,
		data: make([]byte, promised)}, w.now)
	readAll(c)

	before := c.sndWnd
	seg := tcpSeg{
		seq:   c.rcvNxt,
		ack:   c.nxt,
		flags: FlagACK,
		wnd:   1,
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

func TestTCPStaleZeroWindowResetGeenRetries(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	if _, err := c.write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	c.retries = 5

	c.wl1 = c.rcvNxt + 1000
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	if c.retries != 5 {
		t.Fatalf("retries %d na een afgewezen zero-window-update, wil 5", c.retries)
	}
	if c.sndWnd == 0 {
		t.Fatal("de afgewezen update is tóch toegepast")
	}
}

func TestTCPHerhaaldeFinHerstartTimeWait(t *testing.T) {
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

	w.advance(time.Duration(tcpTimeWaitDur) - 100*time.Millisecond)
	dupFin := tcpSeg{seq: w.a.rcvNxt - 1, ack: w.a.nxt, flags: FlagACK | FlagFIN, wnd: 1024}
	w.a.recv(dupFin, w.now)
	w.drain(w.a)

	w.advance(500 * time.Millisecond)
	w.drain(w.a)
	if w.a.state != tcpTimeWait {
		t.Fatal("TIME-WAIT verliep op de oorspronkelijke termijn — de herhaalde FIN herstartte hem niet")
	}

	w.advance(time.Duration(tcpTimeWaitDur))
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a is %s na de herstarte termijn, wil CLOSED", w.a.state)
	}
}

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

	w.advance(time.Duration(tcpTimeWaitDur) - 100*time.Millisecond)
	rogue := tcpSeg{seq: w.a.rcvNxt - 100, ack: w.a.nxt, flags: FlagACK | FlagFIN, wnd: 1024}
	w.a.recv(rogue, w.now)
	w.drain(w.a)

	w.advance(500 * time.Millisecond)
	w.drain(w.a)
	if w.a.state != tcpClosed {
		t.Fatalf("a is %s — een vreemde FIN rekte TIME-WAIT op", w.a.state)
	}
}

func TestTCPVerlorenProbeHersteltBijVensterOpening(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	w.drain(c)
	una := c.una

	w.advance(time.Minute)
	if segs := w.drain(c); len(segs) == 0 || len(segs[0].data) != 1 {
		t.Fatalf("verwachtte één probe-byte, kreeg %v", segs)
	}

	c.recv(tcpSeg{seq: c.rcvNxt, ack: una, flags: FlagACK, wnd: 1024}, w.now)
	segs := w.drain(c)
	if len(segs) == 0 {
		t.Fatal("geen hertransmissie na het openen van het venster")
	}
	if segs[0].seq != una {
		t.Fatalf("hertransmissie begint op %d, wil una (%d) — de verloren probe-byte blijft anders een gat", segs[0].seq, una)
	}
}

func TestTCPHertransmissieBemeetGeenRTT(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	if segs := w.drain(c); len(segs) != 1 {
		t.Fatalf("verwachtte het datasegment, kreeg %d", len(segs))
	}
	if !c.timing {
		t.Fatal("de eerste verzending hoort juist wél bemeten te worden")
	}
	w.advance(2 * time.Second)
	segs := w.drain(c)
	if len(segs) == 0 || len(segs[0].data) == 0 {
		t.Fatalf("geen hertransmissie, kreeg %v", segs)
	}
	if c.timing {
		t.Fatal("de hertransmissie startte een RTT-sample op oude ruimte — Karn zegt: niet bemeten")
	}
}

func TestTCPPersistVervuiltDeRTONiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if _, err := c.write([]byte("wacht maar")); err != nil {
		t.Fatal(err)
	}
	rtoVoor := c.rto
	w.drain(c)
	for i := 0; i < 6; i++ {
		w.advance(time.Minute)
		w.drain(c)
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 0}, w.now)
	}
	if c.rto != rtoVoor {
		t.Fatalf("zes probes lieten de RTO groeien van %v naar %v — persist hoort de estimator niet te raken", rtoVoor, c.rto)
	}

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: 1024}, w.now)
	if c.persistBackoff != 0 {
		t.Fatalf("persistBackoff is %d na de venster-opening, wil 0", c.persistBackoff)
	}
}

func TestTCPVensterShrinkIsGeenDupAck(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a
	if _, err := c.write([]byte("hallo")); err != nil {
		t.Fatal(err)
	}
	w.drain(c)

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

func TestTCPHandshakeNeemtGeenOudeRSTMee(t *testing.T) {

	w := newTCPPair(t, 8<<10, 8<<10)
	a := w.a
	if segs := w.drain(a); len(segs) != 1 || !segs[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN, kreeg %v", segs)
	}
	a.recv(tcpSeg{seq: 9999, ack: a.iss + 5, flags: FlagACK, wnd: 1024}, w.now)
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

	w2 := newTCPPair(t, 8<<10, 8<<10)
	b := w2.b
	syn := w2.drain(w2.a)[0]
	b.recv(syn, w2.now)
	if segs := w2.drain(b); len(segs) != 1 || !segs[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN-ACK, kreeg %v", segs)
	}
	b.recv(tcpSeg{seq: b.rcvNxt, ack: b.iss, flags: FlagACK, wnd: 1024}, w2.now)
	if !b.rst.set {
		t.Fatal("de ongeldige ACK zette geen pending RST bij de passieve kant")
	}
	b.recv(tcpSeg{seq: b.rcvNxt, ack: b.iss + 1, flags: FlagACK, wnd: 1024}, w2.now)
	if b.state != tcpEstablished {
		t.Fatalf("b is %s, wil ESTABLISHED", b.state)
	}
	for _, s := range w2.drain(b) {
		if s.flags.Has(FlagRST) {
			t.Fatal("SYN-RCVD: het eerste segment van de geslaagde verbinding is een RST")
		}
	}
}

func TestTCPNietDuplicaatBreektDeReeks(t *testing.T) {
	opzet := func() (*tcpWire, *tcpConn, uint16) {
		w := newTCPPair(t, 8<<10, 8<<10)
		w.connect()
		c := w.a
		if _, err := c.write([]byte("hallo")); err != nil {
			t.Fatal(err)
		}
		w.drain(c)
		return w, c, uint16(c.sndWnd)
	}

	w, c, wnd := opzet()
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd / 2}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd / 2}, w.now)
	for _, s := range w.drain(c) {
		if len(s.data) > 0 {
			t.Fatal("fast retransmit vuurde terwijl de shrink de reeks had moeten breken")
		}
	}
	if c.dupacks != 1 {
		t.Fatalf("dupacks = %d, wil 1 (reeks gebroken door de shrink)", c.dupacks)
	}

	w, c, wnd = opzet()
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK | FlagFIN, wnd: wnd}, w.now)
	if c.dupacks != 0 {
		t.Fatalf("dupacks = %d na een FIN, wil 0 (RFC 5681 sluit SYN/FIN uit)", c.dupacks)
	}
}

func TestTCPOudeACKBreektDeReeks(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	if _, err := c.write([]byte("aaaa")); err != nil {
		t.Fatal(err)
	}
	oud := c.una
	w.pump()
	if c.una == oud {
		t.Fatal("geen voortgang; het harnas bezorgde de eerste write niet")
	}

	if _, err := c.write([]byte("bbbb")); err != nil {
		t.Fatal(err)
	}
	w.drain(c)
	wnd := uint16(c.sndWnd)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	c.recv(tcpSeg{seq: c.rcvNxt, ack: oud, flags: FlagACK, wnd: wnd}, w.now)
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

func TestTCPAdvertentieOverleeftDeWrap(t *testing.T) {

	issB := ^uint32(8192)
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

	if promise := a.rcvWnd(); promise != 8192-100 {
		t.Fatalf("rcvWnd = %d, wil de belofte (%d) — de nul-rand telt kennelijk als unset en exposeert de verse ring", promise, 8192-100)
	}
}

func TestTCPKaleFinRespecteertHetVenster(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	c.recv(tcpSeg{seq: c.rcvNxt, ack: c.nxt, flags: FlagACK, wnd: 0}, w.now)
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.drain(c) {
		if s.flags.Has(FlagFIN) {
			t.Fatal("de kale FIN ging door een dicht venster zonder probe")
		}
	}

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

func TestTCPGroeiBoektDePiek(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()
	c := w.a

	pot := &budget{total: 2*(8<<10) + 12<<10}
	pot.reserve(2 * (8 << 10))
	c.pot, c.maxBuf = pot, 64<<10
	if c.growRing(&c.rx) {
		t.Fatal("growRing groeide terwijl de pot de piek (oud+nieuw) niet draagt")
	}

	pot.total = 2*(8<<10) + (16 << 10)
	if !c.growRing(&c.rx) {
		t.Fatal("growRing weigerde terwijl de piek past")
	}
	if pot.used != 8<<10+16<<10 {
		t.Fatalf("pot.used = %d na de groei, wil %d (tx + nieuwe rx; de oude rx is terug)", pot.used, 8<<10+16<<10)
	}
}

func TestTCPOudePrefixWordtGetrimd(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	w.connect()

	if _, err := w.a.write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	w.pump()
	if got := string(readAll(w.b)); got != "abc" {
		t.Fatalf("opzet: b las %q", got)
	}

	seg := tcpSeg{seq: w.b.rcvNxt - 2, ack: w.b.nxt, flags: FlagACK, wnd: 1024,
		data: []byte("bcdef")}
	w.b.recv(seg, w.now)
	if got := string(readAll(w.b)); got != "def" {
		t.Fatalf("b las %q, wil de nieuwe suffix %q — de oude prefix is niet getrimd", got, "def")
	}
}

func TestTCPPeerMSSWordtGeklemd(t *testing.T) {
	c := &tcpConn{}
	c.takeSynOptions(tcpSeg{mss: 9000})
	if c.peerMSS != MTU-40 {
		t.Fatalf("peerMSS = %d, wil de klem op %d", c.peerMSS, MTU-40)
	}
}

func TestTCPFinWait2HoudtGeenBudgetVast(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)
	pot := &budget{total: 1 << 20}
	pot.reserve(2 * (8 << 10))
	w.a.pot = pot
	w.connect()
	if err := w.a.close(); err != nil {
		t.Fatal(err)
	}
	w.a.abandonRead(w.now)
	w.pump()
	if w.a.state != tcpFinWait2 {
		t.Fatalf("a is %s, wil FIN-WAIT-2", w.a.state)
	}
	if pot.used != 0 {
		t.Fatalf("pot.used = %d in FIN-WAIT-2, wil 0 — de ringen blijven de pot vullen", pot.used)
	}
}

func TestTCPHandshakeResetDeRTO(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)

	if segs := w.drain(w.a); len(segs) != 1 {
		t.Fatal("verwachtte de SYN")
	}
	w.advance(2 * time.Second)
	w.drain(w.a)
	w.advance(4 * time.Second)
	if w.a.rto <= tcpRTOInitial {
		t.Fatalf("opzet: rto is %v, hoort opgeblazen te zijn", w.a.rto)
	}
	w.pump()
	if w.a.state != tcpEstablished {
		t.Fatalf("a is %s, wil ESTABLISHED", w.a.state)
	}
	if w.a.rto != tcpRTOInitial || w.a.retries != 0 || w.a.backoff != 0 {
		t.Fatalf("na de handshake: rto=%v retries=%d backoff=%d — de opgeblazen ladder bleef staan",
			w.a.rto, w.a.retries, w.a.backoff)
	}
}

func TestTCPCumulatieveACKNaGoBackN(t *testing.T) {
	w := newTCPPair(t, 32<<10, 32<<10)
	w.connect()
	c := w.a
	if _, err := c.write(make([]byte, 4000)); err != nil {
		t.Fatal(err)
	}
	segs := w.drain(c)
	if len(segs) < 3 {
		t.Fatalf("opzet: %d segmenten, wil ≥3", len(segs))
	}
	hoog := c.nxt
	wnd := uint16(c.sndWnd)
	for i := 0; i < 3; i++ {
		c.recv(tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: wnd}, w.now)
	}
	if c.nxt == hoog {
		t.Fatal("opzet: goBackN heeft de cursor niet teruggespoeld")
	}

	c.recv(tcpSeg{seq: c.rcvNxt, ack: hoog, flags: FlagACK, wnd: wnd}, w.now)
	if c.una != hoog {
		t.Fatalf("una = %d, wil %d — de geldige cumulatieve ACK is geweigerd", c.una, hoog)
	}
	if c.nxt != hoog {
		t.Fatalf("nxt = %d, wil bijgetrokken tot %d", c.nxt, hoog)
	}
}

func TestTCPDubbeleSYNVerliestDeFinaleACKNiet(t *testing.T) {
	w := newTCPPair(t, 8<<10, 8<<10)

	syn := w.drain(w.a)
	if len(syn) != 1 || !syn[0].flags.Has(FlagSYN) {
		t.Fatalf("verwachtte de SYN, kreeg %v", syn)
	}
	w.b.recv(syn[0], w.now)
	for _, seg := range w.drain(w.b) {
		w.a.recv(seg, w.now)
	}
	final := w.drain(w.a)
	if len(final) != 1 || final[0].ack != w.b.iss+1 {
		t.Fatalf("verwachtte de finale ACK op iss+1, kreeg %v", final)
	}

	w.b.recv(syn[0], w.now)

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
