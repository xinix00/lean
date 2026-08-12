package leannet

// udp_test.go — de poorttabel: bind/close/herbind, roundtrip mét afzender,
// vol=drop+teller, budget-boekhouding, en de heilige datagram-grenzen.

import (
	"bytes"
	"testing"
)

var udpTestSrc = [4]byte{10, 0, 0, 9}

// TestUDPBindCloseRebind: dubbel binden weigert luid, close maakt de poort
// weer vrij.
func TestUDPBindCloseRebind(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 4096}

	u, err := tab.bind(5353, 1024, pot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tab.bind(5353, 1024, pot); err != errUDPPortInUse {
		t.Fatalf("double bind error = %v, want %v", err, errUDPPortInUse)
	}
	if got := errUDPPortInUse.Error(); got != "leannet: udp port in use" {
		t.Fatalf("error string = %q", got)
	}

	u.close()
	u2, err := tab.bind(5353, 1024, pot)
	if err != nil {
		t.Fatalf("rebind after close: %v", err)
	}
	u2.close()

	// Onbruikbare parameters weigeren luid.
	if _, err := tab.bind(0, 1024, pot); err != errUDPPortZero {
		t.Fatalf("bind port 0 error = %v, want %v", err, errUDPPortZero)
	}
	if _, err := tab.bind(53, 0, pot); err != errUDPQueueCap {
		t.Fatalf("bind cap 0 error = %v, want %v", err, errUDPQueueCap)
	}
}

// TestUDPDeliverRecvRoundtrip: deliver → recvFrom mét afzender; lege wachtrij
// en ongebonden poort geven false (plus teller).
func TestUDPDeliverRecvRoundtrip(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 4096}
	u, err := tab.bind(4242, 512, pot)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello node")
	if !tab.deliver(4242, udpTestSrc, 5678, payload) {
		t.Fatal("deliver to bound port failed")
	}

	buf := make([]byte, 64)
	n, src, srcPort, ok := u.recvFrom(buf)
	if !ok || n != len(payload) || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("recvFrom = %q, %v; want %q, true", buf[:n], ok, payload)
	}
	if src != udpTestSrc || srcPort != 5678 {
		t.Fatalf("recvFrom src = %v:%d, want %v:5678", src, srcPort, udpTestSrc)
	}

	// Leeg: non-blocking false, het wachten is de zorg van de socket-laag.
	if _, _, _, ok := u.recvFrom(buf); ok {
		t.Fatal("recvFrom on empty queue returned ok")
	}

	// Ongebonden poort: weg + teller.
	if tab.deliver(9999, udpTestSrc, 1, payload) {
		t.Fatal("deliver to unbound port succeeded")
	}
	if tab.cntNoPort != 1 {
		t.Fatalf("cntNoPort = %d, want 1", tab.cntNoPort)
	}
	u.close()
}

// TestUDPQueueFullDrop: een volle wachtrij dropt het datagram (UDP mag dat)
// mét teller; wat er al lag blijft intact en recv maakt weer ruimte.
func TestUDPQueueFullDrop(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 4096}
	// Cap 40: één datagram van 16 bytes kost 8+16=24, twee passen niet.
	u, err := tab.bind(7, 40, pot)
	if err != nil {
		t.Fatal(err)
	}

	first := bytes.Repeat([]byte{0xaa}, 16)
	second := bytes.Repeat([]byte{0xbb}, 16)
	if !tab.deliver(7, udpTestSrc, 1, first) {
		t.Fatal("first deliver failed")
	}
	if tab.deliver(7, udpTestSrc, 2, second) {
		t.Fatal("second deliver fit in a full queue")
	}
	if u.cntDrop != 1 {
		t.Fatalf("cntDrop = %d, want 1", u.cntDrop)
	}

	buf := make([]byte, 64)
	n, _, srcPort, ok := u.recvFrom(buf)
	if !ok || srcPort != 1 || !bytes.Equal(buf[:n], first) {
		t.Fatal("surviving datagram corrupted by the dropped one")
	}
	// De pop gaf de bytes terug aan de wachtrij: er past weer één.
	if !tab.deliver(7, udpTestSrc, 3, second) {
		t.Fatal("deliver after recv failed; queue accounting broken")
	}
	u.close()
}

// TestUDPBudget: bind reserveert queueCap uit de pot (de enige vooraf-claim),
// een pot die het niet draagt weigert luid, en close stort integraal terug —
// precies één keer, ook bij dubbel sluiten.
func TestUDPBudget(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 100}

	a, err := tab.bind(1, 64, pot)
	if err != nil {
		t.Fatal(err)
	}
	if got := pot.free(); got != 36 {
		t.Fatalf("pot.free() = %d after bind, want 36", got)
	}
	if _, err := tab.bind(2, 64, pot); err != errUDPBudget {
		t.Fatalf("over-budget bind error = %v, want %v", err, errUDPBudget)
	}
	b, err := tab.bind(2, 36, pot)
	if err != nil {
		t.Fatal(err)
	}
	if got := pot.free(); got != 0 {
		t.Fatalf("pot.free() = %d, want 0", got)
	}

	a.close()
	b.close()
	if got := pot.free(); got != 100 {
		t.Fatalf("pot.free() = %d after close, want 100", got)
	}
	// Idempotent: dubbel sluiten stort niet dubbel terug (en panict niet).
	a.close()
	if got := pot.free(); got != 100 {
		t.Fatalf("pot.free() = %d after double close, want 100", got)
	}
}

// TestUDPDatagramBoundaries: twee delivers zijn twee recvs — grenzen blijven,
// niets plakt samen, en de payload is een eigen kopie.
func TestUDPDatagramBoundaries(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 4096}
	u, err := tab.bind(53, 512, pot)
	if err != nil {
		t.Fatal(err)
	}

	one := []byte("aa")
	two := []byte("bbbb")
	tab.deliver(53, udpTestSrc, 1, one)
	tab.deliver(53, udpTestSrc, 2, two)
	one[0] = 'X' // de wachtrij moet een eigen kopie dragen

	buf := make([]byte, 64)
	n, _, srcPort, ok := u.recvFrom(buf)
	if !ok || n != 2 || srcPort != 1 || !bytes.Equal(buf[:n], []byte("aa")) {
		t.Fatalf("first recv = %q (n=%d, port=%d), want \"aa\"", buf[:n], n, srcPort)
	}
	n, _, srcPort, ok = u.recvFrom(buf)
	if !ok || n != 4 || srcPort != 2 || !bytes.Equal(buf[:n], two) {
		t.Fatalf("second recv = %q (n=%d, port=%d), want \"bbbb\"", buf[:n], n, srcPort)
	}
	u.close()
}

// TestUDPTruncation: past een datagram niet in de leesbuffer, dan is de rest
// weg maar blijft de grens staan — en de wachtrij-boekhouding klopt.
func TestUDPTruncation(t *testing.T) {
	tab := newUDPTable()
	pot := &budget{total: 4096}
	u, err := tab.bind(9, 32, pot)
	if err != nil {
		t.Fatal(err)
	}

	if !tab.deliver(9, udpTestSrc, 1, []byte("0123456789")) {
		t.Fatal("deliver failed")
	}
	small := make([]byte, 4)
	n, _, _, ok := u.recvFrom(small)
	if !ok || n != 4 || !bytes.Equal(small, []byte("0123")) {
		t.Fatalf("truncated recv = %q (n=%d), want \"0123\"", small[:n], n)
	}
	// De rest van het datagram is weg, geen tweede lees-beurt.
	if _, _, _, ok := u.recvFrom(small); ok {
		t.Fatal("truncated remainder still readable")
	}
	// En de vólledige kosten zijn vrijgegeven: een cap-vullend datagram past.
	if !tab.deliver(9, udpTestSrc, 2, bytes.Repeat([]byte{1}, 32-udpDGramOverhead)) {
		t.Fatal("queue accounting leaked after truncation")
	}
	u.close()
}
