package leannet

// udp.go implements the UDP port table. bind reserves a byte-sized queue from
// the budget, deliver enqueues datagrams, and recvFrom polls it; the socket
// layer handles blocking and deadlines. This small explicit queue is leannet's
// only up-front reservation and close returns it in full.
//
// Datagram boundaries are preserved with a private payload copy per record.
//
// Outgoing datagrams have no state and are built directly with PutUDP. The
// table is not internally locked; the stack lock covers all operations.

import "errors"

var (
	errUDPPortInUse = errors.New("leannet: udp port in use")
	errUDPPortZero  = errors.New("leannet: udp port must be nonzero")
	errUDPQueueCap  = errors.New("leannet: udp queue capacity must be positive")
	errUDPBudget    = errors.New("leannet: udp bind exceeds budget")
)

// udpDGramOverhead approximates the actual 64-bit heap cost of the descriptor
// and allocation rounding. Wire overhead would undercount memory use.
const udpDGramOverhead = 48

// udpDatagram stores one received datagram and its sender.
type udpDatagram struct {
	src     [4]byte
	srcPort uint16
	payload []byte // private copy; the RX frame is reused
}

// udpTable assigns ports and demultiplexes incoming datagrams.
type udpTable struct {
	ports map[uint16]*udpPort

	// cntNoPort supports telemetry and a future ICMP port-unreachable reply.
	cntNoPort int
}

func newUDPTable() *udpTable { return &udpTable{ports: make(map[uint16]*udpPort)} }

// bind reserves queueCap bytes for a nonzero port. The stack layer chooses
// ephemeral ports; port zero is not a wildcard here.
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

// bound reports whether the ephemeral-port chooser may use a port.
func (t *udpTable) bound(port uint16) bool {
	_, taken := t.ports[port]
	return taken
}

// deliver queues an incoming datagram. False means no bound port or a full queue.
func (t *udpTable) deliver(dstPort uint16, src [4]byte, srcPort uint16, payload []byte) bool {
	u, bound := t.ports[dstPort]
	if !bound {
		t.cntNoPort++
		return false
	}
	if u.connected && (src != u.peer || srcPort != u.peerPort) {
		// Filter connected sockets before enqueueing so spoofed senders cannot
		// fill the queue and displace the real peer.
		u.cntDrop++
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

// udpPort is one bound port and its receive queue.
type udpPort struct {
	table *udpTable
	pot   *budget
	port  uint16
	cap   int // queue capacity reserved from the budget

	// DialUDP configures this connected filter while holding the stack lock.
	connected bool
	peer      [4]byte
	peerPort  uint16
	used      int // occupied bytes, including overhead
	q         []udpDatagram

	cntDrop int // datagrams dropped because the queue was full
	closed  bool
}

// recvFrom pops the oldest datagram without blocking. If p is too small, UDP
// semantics discard the remainder while preserving the record boundary.
func (u *udpPort) recvFrom(p []byte) (n int, src [4]byte, srcPort uint16, ok bool) {
	if len(u.q) == 0 {
		return 0, src, 0, false
	}
	d := u.q[0]
	u.q[0] = udpDatagram{} // clear the payload reference for GC
	u.q = u.q[1:]
	if len(u.q) == 0 {
		u.q = nil // release the empty queue's backing storage
	}
	u.used -= udpDGramOverhead + len(d.payload)
	n = copy(p, d.payload)
	return n, d.src, d.srcPort, true
}

// close releases the port and returns its entire queue reservation. It is idempotent.
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
