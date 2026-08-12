package leannet

// udp.go — de UDP-poorttabel: bind reserveert een wachtrij (in bytes, uit de
// budget-pot), deliver legt binnengekomen datagrammen erin, recvFrom haalt ze
// er non-blocking uit — het blocken en de deadlines doet de socket-laag
// later. De reservering bij bind is de enige vooraf-claim in heel leannet, en
// hij is klein en expliciet: de aanroeper kiest hem per poort en close stort
// hem integraal terug.
//
// Datagram-grenzen zijn heilig: elk datagram is een eigen record met een
// eigen payload-kopie (KISS wint hier van zero-alloc). Twee delivers zijn
// twee recvs, nooit één samengeplakte stroom.
//
// Verzenden is geen machine-werk: een uitgaand datagram heeft geen staat, dus
// de stack-laag bouwt hem direct met PutUDP (frame.go) en stuurt hem weg.
//
// De tabel is niet zelf-vergrendeld: de stack-laag houdt één lock over
// bind/deliver/recvFrom/close (zelfde regime als de rest van het package).

import "errors"

var (
	errUDPPortInUse = errors.New("leannet: udp port in use")
	errUDPPortZero  = errors.New("leannet: udp port must be nonzero")
	errUDPQueueCap  = errors.New("leannet: udp queue capacity must be positive")
	errUDPBudget    = errors.New("leannet: udp bind exceeds budget")
)

// udpDGramOverhead is wat één datagram naast zijn payload tegen de
// wachtrijcapaciteit telt: de draad-header (8 bytes). Zo kan een vloed lege
// datagrammen de wachtrij niet gratis laten vollopen.
const udpDGramOverhead = sizeUDP

// udpDatagram is één ontvangen datagram, afzender en grenzen inbegrepen.
type udpDatagram struct {
	src     [4]byte
	srcPort uint16
	payload []byte // eigen kopie: het RX-frame is allang hergebruikt
}

// udpTable wijst poorten toe en demuxt binnenkomende datagrammen.
type udpTable struct {
	ports map[uint16]*udpPort

	// cntNoPort telt datagrammen voor een ongebonden poort — voer voor een
	// latere ICMP port-unreachable en voor telemetrie.
	cntNoPort int
}

func newUDPTable() *udpTable { return &udpTable{ports: make(map[uint16]*udpPort)} }

// bind claimt een poort met een wachtrij van queueCap BYTES, gereserveerd uit
// pot. Bezette poort, onbruikbare capaciteit of een pot die het niet draagt:
// luid weigeren. Het kiezen van een vrije (ephemerale) poort is de zorg van
// de stack-laag; poort 0 is hier geen jokerteken.
func (t *udpTable) bind(port uint16, queueCap int, pot *budget) (*udpPort, error) {
	if port == 0 {
		return nil, errUDPPortZero
	}
	if queueCap <= 0 {
		return nil, errUDPQueueCap
	}
	if _, taken := t.ports[port]; taken {
		return nil, errUDPPortInUse
	}
	if !pot.reserve(queueCap) {
		return nil, errUDPBudget
	}
	u := &udpPort{table: t, pot: pot, port: port, cap: queueCap}
	t.ports[port] = u
	return u, nil
}

// bound rapporteert of een poort in gebruik is (voor de efemere kiezer).
func (t *udpTable) bound(port uint16) bool {
	_, taken := t.ports[port]
	return taken
}

// deliver legt een binnengekomen datagram in de wachtrij van dstPort.
// false = weg: poort niet gebonden, of wachtrij vol. UDP mág droppen — maar
// het telt, zodat de stack-laag het kan zien.
func (t *udpTable) deliver(dstPort uint16, src [4]byte, srcPort uint16, payload []byte) bool {
	u, bound := t.ports[dstPort]
	if !bound {
		t.cntNoPort++
		return false
	}
	cost := udpDGramOverhead + len(payload)
	if u.used+cost > u.cap {
		u.cntDrop++
		return false
	}
	u.used += cost
	u.q = append(u.q, udpDatagram{
		src:     src,
		srcPort: srcPort,
		payload: append([]byte(nil), payload...),
	})
	return true
}

// udpPort is één gebonden poort met zijn wachtrij.
type udpPort struct {
	table *udpTable
	pot   *budget
	port  uint16
	cap   int // wachtrijcapaciteit in bytes, gereserveerd uit de pot
	used  int // bezette bytes (overhead + payloads)
	q     []udpDatagram

	cntDrop int // datagrammen gedropt omdat de wachtrij vol was
	closed  bool
}

// recvFrom popt het oudste datagram, non-blocking: ok=false is "niets", het
// wachten doet de socket-laag. Past het datagram niet in p, dan is n de
// afgekapte lengte en is de rest weg — UDP-semantiek: de grens blijft
// bestaan, de bytes niet.
func (u *udpPort) recvFrom(p []byte) (n int, src [4]byte, srcPort uint16, ok bool) {
	if len(u.q) == 0 {
		return 0, src, 0, false
	}
	d := u.q[0]
	u.q[0] = udpDatagram{} // payload-referentie wissen voor de GC
	u.q = u.q[1:]
	if len(u.q) == 0 {
		u.q = nil // drager loslaten: een lege wachtrij kost niets
	}
	u.used -= udpDGramOverhead + len(d.payload)
	n = copy(p, d.payload)
	return n, d.src, d.srcPort, true
}

// close geeft de poort vrij en stort de volledige wachtrijcapaciteit terug in
// de pot. Idempotent: dubbel sluiten is geen fout en stort niet dubbel terug.
func (u *udpPort) close() {
	if u.closed {
		return
	}
	u.closed = true
	delete(u.table.ports, u.port)
	u.q = nil
	u.used = 0
	u.pot.release(u.cap)
}
