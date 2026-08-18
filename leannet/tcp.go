package leannet

// tcp.go implements one pure TCP machine per tcpConn (RFCs 9293 and 6298).
// recv and emit receive monotonic nanoseconds, making loss and timing scenarios
// deterministic in tests without internal goroutines or clocks.
//
// Retransmission operates on sequence space, not only data. SYN and FIN
// therefore participate in go-back-N: an RTO rewinds nxt to una and emit
// regenerates data and control flags together.
//
// V1 accepts only in-order input and duplicate-ACKs out-of-order segments for
// peer fast retransmit. It supports window scaling but not SACK or timestamps.

import (
	"errors"
	"time"
)

// ---- sequence arithmetic modulo 2^32 ----

func seqLT(a, b uint32) bool  { return int32(a-b) < 0 }
func seqLEQ(a, b uint32) bool { return int32(a-b) <= 0 }

// seqDiff returns a-b as an int, assuming a small distance.
func seqDiff(a, b uint32) int { return int(int32(a - b)) }

// ---- states ----

type tcpState uint8

const (
	tcpClosed tcpState = iota
	tcpSynSent
	tcpSynRcvd
	tcpEstablished
	tcpFinWait1
	tcpFinWait2
	tcpCloseWait
	tcpLastAck
	tcpClosing
	tcpTimeWait
)

var tcpStateNames = [...]string{"CLOSED", "SYN-SENT", "SYN-RCVD", "ESTABLISHED",
	"FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "TIME-WAIT"}

func (s tcpState) String() string { return tcpStateNames[s] }

// ---- RTO-parameters (RFC 6298) ----

const (
	tcpRTOInitial = time.Second
	// RFC 6298 §2.4 recommends 1 second; embedded LANs use a lower floor.
	tcpRTOMin     = 200 * time.Millisecond
	tcpRTOMax     = 60 * time.Second
	tcpBackoffMax = 12 // cap doubling; a stuck peer keeps probing at rtoMax

	tcpTimeWaitDur = int64(time.Second) // embedded targets cannot afford a four-minute 2MSL

	// Bound FIN-WAIT-2 after full socket Close so a peer that never closes cannot
	// retain the connection's floor budget indefinitely.
	tcpFinWait2Dur = int64(20 * time.Second)
	tcpDefaultMSS  = 536

	// Retry limits count RTOs without a valid ACK. Any valid ACK resets them, so
	// a live zero-window peer survives while silent half-open floods do not.
	tcpMaxRetriesHandshake = 5  // roughly 6 seconds without a SYN response
	tcpMaxRetriesData      = 12 // minutes for a vanished established peer
)

var (
	errTCPClosed  = errors.New("leannet: connection closed")
	errTCPClosing = errors.New("leannet: connection already closing")

	// Reset is an error, never EOF: it does not promise a complete byte stream.
	errTCPReset = errors.New("leannet: connection reset by peer")
)

// tcpSeg is machine-level form; the stack converts it to and from wire bytes.
type tcpSeg struct {
	seq, ack uint32
	flags    TCPFlags
	wnd      uint16 // wire value before scaling
	data     []byte

	// Meaningful only on SYN segments.
	mss  uint16
	wsOK bool  // window-scale option present
	ws   uint8 // offered shift
}

// tcpConn is one connection. The socket layer provides all synchronization.
type tcpConn struct {
	state  tcpState
	listen bool // passive side: SYN on tcpClosed opens into SYN-RCVD

	// Send side. dataBase anchors the tx head in sequence space, making
	// retransmission a reread. close fixes finSeq and rejects later writes.
	iss      uint32
	una      uint32 // highest sequence acknowledged by the peer
	nxt      uint32 // next sequence to transmit
	dataBase uint32
	closing  bool
	finSeq   uint32
	sndWnd   uint32 // peer window in octets after scaling
	wl1, wl2 uint32 // segment of last window update (RFC 9293 §3.10.7.4)
	peerMSS  int
	sndWS    uint8 // shift for incoming peer window advertisements

	// Receive side.
	irs     uint32
	rcvNxt  uint32
	finRcvd bool
	rcvWS   uint8 // shift for our window advertisements
	wsOn    bool  // both sides offered window scaling

	// Values advertised on our SYN.
	advMSS uint16
	advWS  uint8

	rx ring
	tx txRing

	// Rings start at their floors and double under receive or write pressure,
	// bounded by maxBuf and pot. nil pot disables growth.
	//
	// Empty rings shrink to their floors after the last read or ACK. Otherwise a
	// few idle pooled HTTP connections could retain the entire budget.
	pot    *budget
	maxBuf int

	// Control.
	needAck bool // data, FIN, duplicate, or challenge requires an ACK

	// appClosed marks full socket close. Incoming promised data is counted and
	// discarded so ACK/FIN can progress after the receive ring is released.
	appClosed bool

	// rst holds at most one reset and its exact form. Abort uses RST|ACK; an ACK
	// that does not acknowledge our SYN uses bare <SEQ=SEG.ACK>. emit sends it
	// first, and reap preserves it if the connection dies before pumping.
	rst pendingRST

	// advEdge is the furthest advertised receive edge. advSet cannot use zero as
	// a sentinel because sequence wrap makes zero valid. It also prevents
	// shrinking below a window already promised (RFC 9293 §3.8.6.2.1).
	advEdge uint32
	advSet  bool

	// synWnd records the active SYN's promise until the peer ISS defines rcvNxt.
	synWnd uint16

	// RTO and Karn sampling. maxSent prevents RTT timing retransmitted space.
	srtt, rttvar, rto time.Duration
	haveRTT           bool
	timerOn           bool
	deadline          int64
	backoff           uint8
	timing            bool
	timedSeq          uint32
	timedAt           int64
	maxSent           uint32

	// Zero-window probes use separate backoff so they do not poison RTT/RTO.
	persistBackoff uint8

	// Simple fast retransmit (RFC 5681 §3.2).
	dupacks uint8

	// RTO firings since the last valid ACK.
	retries uint8
	// refused distinguishes SYN reset from retry exhaustion.
	refused bool
	// reset preserves unclean termination so I/O reports error rather than EOF.
	reset bool

	// The timer arms one one-byte zero-window probe.
	probe bool

	twDeadline int64
}

// openActive starts an outgoing connection; the next emit sends SYN. Owner-provided
// rings and budget linkage survive the reset.
func (c *tcpConn) openActive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpSynSent, iss: iss, una: iss, nxt: iss, maxSent: iss,
		dataBase: iss + 1, advMSS: advMSS, advWS: advWS,
		rto: tcpRTOInitial, peerMSS: tcpDefaultMSS,
		rx: c.rx, tx: c.tx, pot: c.pot, maxBuf: c.maxBuf}
}

// openPassive creates a listener embryo that an incoming SYN opens into SYN-RCVD.
func (c *tcpConn) openPassive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpClosed, listen: true, iss: iss, maxSent: iss,
		advMSS: advMSS, advWS: advWS,
		rto: tcpRTOInitial, peerMSS: tcpDefaultMSS,
		rx: c.rx, tx: c.tx, pot: c.pot, maxBuf: c.maxBuf}
}

// close fixes FIN's sequence number after the final data byte and rejects later writes.
func (c *tcpConn) close() error {
	switch {
	case c.closing:
		return errTCPClosing
	case c.state == tcpClosed, c.state == tcpTimeWait:
		return errTCPClosed
	case c.state == tcpSynSent:
		// Nothing synchronized yet; discard the attempt.
		c.state = tcpClosed
		return nil
	}
	c.closing = true
	c.finSeq = c.dataBase + uint32(c.tx.buffered())
	return nil
}

// abandonRead marks full socket close, unlike machine close's write half-close.
// It releases unread receive storage while appClosed still advances and ACKs
// incoming data so the peer can deliver FIN.
func (c *tcpConn) abandonRead() {
	c.appClosed = true
	if c.pot != nil {
		c.pot.release(c.rx.size())
		c.rx = ring{}
	}
}

// pendingRST stores the queued reset described by tcpConn.rst.
type pendingRST struct {
	seq, ack uint32
	withAck  bool
	set      bool
}

// abort terminates the connection and queues one reset.
func (c *tcpConn) abort() {
	if c.state != tcpClosed && c.state != tcpSynSent {
		c.rst = pendingRST{seq: c.nxt, ack: c.rcvNxt, withAck: true, set: true}
		c.reset = true // abort is not clean EOF; I/O must fail
	}
	c.state = tcpClosed
	c.timerOn = false
}

// write buffers application data. A full ring while the peer offers more window
// signals local transmit growth.
func (c *tcpConn) write(p []byte) (int, error) {
	if c.reset {
		return 0, errTCPReset
	}
	if c.closing || (c.state != tcpEstablished && c.state != tcpCloseWait) {
		return 0, errTCPClosed
	}
	n := c.tx.writeApp(p)
	for n < len(p) && int(c.sndWnd) > c.tx.size() && c.growRing(&c.tx.ring) {
		n += c.tx.writeApp(p[n:])
	}
	return n, nil
}

// shrinkRing returns an empty grown ring to its floor. Without this, four idle
// pooled HTTP connections at the default per-connection cap can exhaust Budget
// and prevent even the watchdog from dialing.
//
// keep preserves an already-advertised receive window, which cannot shrink left
// (RFC 9293 §3.8.6.2.1). Transmit rings have no external promise.
func (c *tcpConn) shrinkRing(r *ring, floor, keep int) {
	if c.pot == nil || r.buffered() != 0 {
		return
	}
	target := floor
	if keep > target {
		target = keep
	}
	if target >= r.size() {
		return
	}
	// Release the empty old buffer before reserving the smaller one. Reserving
	// first would necessarily fail when the budget is full and prevent shrink.
	old := r.size()
	r.grow(nil)
	c.pot.release(old)
	if !c.pot.reserve(target) {
		// Only an accounting bug can fail after releasing a larger reservation.
		panic("leannet: shrink reservation failed after releasing a larger ring")
	}
	r.grow(make([]byte, target))
}

// shrinkRx and shrinkTx run after the final read and final acknowledgment.
func (c *tcpConn) shrinkRx() {
	// Before the first post-SYN advertisement the ring remains at its floor and
	// a zero edge carries no shrink information.
	if !c.advSet {
		return
	}
	keep := 0
	if d := seqDiff(c.advEdge, c.rcvNxt); d > 0 {
		keep = d
	}
	c.shrinkRing(&c.rx, tcpFloorRx, keep)
}

func (c *tcpConn) shrinkTx() {
	// No sent guard is needed: shrink requires empty and sent never exceeds buffered.
	c.shrinkRing(&c.tx.ring, tcpFloorTx, 0)
}

// growRing doubles r within maxBuf and the budget.
func (c *tcpConn) growRing(r *ring) bool {
	if c.pot == nil {
		return false
	}
	// maxBuf caps receive and transmit combined, not each ring independently.
	headroom := c.maxBuf - (c.rx.size() + c.tx.size())
	if headroom <= 0 {
		return false
	}
	newSize := r.size() * 2
	if newSize-r.size() > headroom {
		newSize = r.size() + headroom
	}
	if newSize <= r.size() {
		return false
	}
	return c.swapRing(r, newSize) // failure to afford the peak simply keeps it small
}

// swapRing accounts for peak memory by reserving the entire new buffer before
// replacing and releasing the old one. False leaves the old ring unchanged.
func (c *tcpConn) swapRing(r *ring, newSize int) bool {
	if !c.pot.reserve(newSize) {
		return false
	}
	old := r.size()
	r.grow(make([]byte, newSize))
	c.pot.release(old)
	return true
}

// read returns received bytes; zero with errTCPClosed means EOF after peer FIN.
//
// Reopening a nearly closed window queues an update once at least one MSS is
// free, avoiding a seconds-long wait for the peer's zero-window probe.
func (c *tcpConn) read(p []byte) (int, error) {
	if c.reset {
		// A reset invalidates buffered tail data; return an error rather than
		// presenting a falsely complete stream.
		return 0, errTCPReset
	}
	wasFree := c.rx.free()
	n := c.rx.read(p)
	if n == 0 && (c.finRcvd || c.state == tcpClosed) {
		return 0, errTCPClosed
	}
	// Threshold is min(MSS, half the ring), with a floor of one.
	thresh := c.peerMSS
	if h := c.rx.size() / 2; h < thresh {
		thresh = h
	}
	if thresh < 1 {
		thresh = 1
	}
	if wasFree < thresh && c.rx.free() >= thresh {
		c.needAck = true
	}
	// Het venster van de PEER is wat wij hem het laatst beloofden
	// (advEdge − rcvNxt), niet onze lokale vrije ruimte. Een snelle lezer
	// houdt de ring leeg — wasFree blijft dan hoog en de conditie hierboven
	// vuurt nooit — terwijl de zender zijn belofte allang heeft opgemaakt en
	// geblokkeerd wacht. Zonder deze check kwam de window-update dan pas mee
	// op de persist-probe van de peer: gemeten 18-08 (LicheeRV, zender-
	// zijdig): 194 stalls die sámen 43,047 van de 43,049s besloegen, mediaan
	// 165ms per venster-ronde — élke stream liep op de probe-klok van de Mac.
	if c.advSet {
		if out := seqDiff(c.advEdge, c.rcvNxt); out >= 0 && out < thresh &&
			c.rx.free()-out >= thresh {
			c.needAck = true
		}
	}
	// The application caught up; release surplus empty capacity.
	c.shrinkRx()
	return n, nil
}

// promiseEdge records an advertised window without moving its right edge left
// (RFC 9293 §3.8.6.2.1). All SYN and regular advertisements share this path.
func (c *tcpConn) promiseEdge(wnd uint32) {
	if edge := c.rcvNxt + wnd; !c.advSet || seqLT(c.advEdge, edge) {
		c.advEdge, c.advSet = edge, true
	}
}

// advertisedWnd returns the scaled free receive space. It never promises
// unallocated capacity.
func (c *tcpConn) advertisedWnd() uint16 {
	w := c.rx.free()
	if c.wsOn {
		w >>= c.rcvWS
	}
	if w > 0xffff {
		w = 0xffff
	}
	// Preserve the actual clamped wire promise, not all free capacity. Without
	// scaling a 128 KiB ring promises only 65,535 bytes and may shrink to that.
	promised := uint32(w)
	if c.wsOn {
		promised <<= c.rcvWS
	}
	c.promiseEdge(promised)
	return uint16(w)
}

// ---- receive ----

// recv processes a checksummed, demultiplexed segment through the RFC machine.
func (c *tcpConn) recv(seg tcpSeg, now int64) {
	if c.state == tcpClosed {
		// Test ACK and RST separately: Has(ACK|RST) requires both and would let
		// SYN|RST allocate an embryo. LISTEN ignores RST (RFC 9293 §3.10.7.2).
		if c.listen && seg.flags.Has(FlagSYN) &&
			!seg.flags.Has(FlagACK) && !seg.flags.Has(FlagRST) {
			c.acceptSyn(seg)
		}
		return
	}
	if c.state == tcpSynSent {
		c.recvSynSent(seg, now)
		return
	}

	// RST requires an exact sequence match; an in-window mismatch gets a
	// challenge ACK to resist blind reset (RFC 5961 §3.2).
	if seg.flags.Has(FlagRST) {
		if seg.seq == c.rcvNxt {
			c.state = tcpClosed
			c.timerOn = false
			c.reset = true // peer reset is not EOF
		} else if c.inRcvWindow(seg.seq) {
			c.needAck = true
		}
		return
	}
	// SYN on a synchronized connection receives challenge ACK (RFC 5961 §4.2).
	if seg.flags.Has(FlagSYN) {
		if c.state == tcpSynRcvd && seg.seq == c.irs {
			// Duplicate SYN implies our SYN|ACK was lost; retransmit it.
			c.nxt = c.iss
			return
		}
		c.needAck = true
		return
	}
	if !seg.flags.Has(FlagACK) {
		return // every post-SYN segment carries ACK (RFC 9293 §3.10.7.4)
	}
	// RFC 9293 acceptability precedes ACK processing, window updates, and retry
	// resets. Out-of-window input only triggers a fresh ACK, covering probes and
	// retransmitted FINs without letting stray input mutate send state.
	if !c.segAcceptable(seg) {
		// An exact duplicate FIN in TIME-WAIT restarts 2MSL so another lost ACK
		// can still be recovered. Other out-of-window FINs must not extend state.
		if c.state == tcpTimeWait && seg.flags.Has(FlagFIN) &&
			seg.seq+uint32(len(seg.data)) == c.rcvNxt-1 {
			c.twDeadline = now + tcpTimeWaitDur
		}
		c.needAck = true
		return
	}

	if !c.processAck(seg, now) {
		// Invalid ACK rejects the whole segment, including data and FIN.
		return
	}

	// Process data/FIN only in receiving states; otherwise ACK duplicates so the
	// peer does not retransmit forever.
	switch c.state {
	case tcpEstablished, tcpFinWait1, tcpFinWait2:
		c.processData(seg, now)
	default:
		if len(seg.data) > 0 || seg.flags.Has(FlagFIN) {
			c.needAck = true
		}
	}
}

// acceptSyn moves a listener embryo from SYN to SYN-RCVD.
func (c *tcpConn) acceptSyn(seg tcpSeg) {
	c.state = tcpSynRcvd
	c.listen = false
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.una = c.iss
	c.nxt = c.iss
	c.dataBase = c.iss + 1
	c.takeSynOptions(seg)
	// SYN windows are never scaled (RFC 7323 §2.2).
	c.sndWnd = uint32(seg.wnd)
	c.wl1, c.wl2 = seg.seq, 0
}

func (c *tcpConn) recvSynSent(seg tcpSeg, now int64) {
	if seg.flags.Has(FlagRST) {
		if seg.flags.Has(FlagACK) && seg.ack == c.iss+1 {
			c.state = tcpClosed // connection refused
			c.refused = true
			c.timerOn = false
		}
		return
	}
	// A non-RST ACK that does not acknowledge our SYN gets
	// <SEQ=SEG.ACK><CTL=RST> while SYN-SENT continues (RFC 9293 §3.10.7.3). This
	// clears a stale connection at the peer so the next SYN can reach its listener.
	if seg.flags.Has(FlagACK) && seg.ack != c.iss+1 {
		c.rst = pendingRST{seq: seg.ack, set: true}
		return
	}
	if !seg.flags.Has(FlagSYN) || !seg.flags.Has(FlagACK) {
		return // V1 does not support simultaneous open
	}
	c.enterEstablished()
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.una = seg.ack
	c.needAck = true
	// Anchor our SYN's receive-window promise now that rcvNxt is known.
	c.promiseEdge(uint32(c.synWnd))
	c.takeSynOptions(seg)
	// SYN windows are unscaled; this is the initial value.
	c.sndWnd = uint32(seg.wnd)
	c.wl1, c.wl2 = seg.seq, seg.ack
}

// enterEstablished shares handshake-completion accounting for active and passive opens.
func (c *tcpConn) enterEstablished() {
	c.state = tcpEstablished
	c.timerOn = false
	c.timing = false
	c.backoff = 0
	// Reset handshake backoff so the first data loss does not inherit up to a
	// minute from earlier SYN loss. A later RTT sample recalibrates it.
	c.rto = tcpRTOInitial
	c.retries = 0
	// Discard a queued invalid-ACK reset once a later valid ACK establishes the
	// asynchronous handshake.
	c.rst = pendingRST{}
}

// takeSynOptions applies peer MSS and enables scaling only when both sides
// offered it (RFC 7323 §2.2).
func (c *tcpConn) takeSynOptions(seg tcpSeg) {
	if seg.mss != 0 {
		c.peerMSS = int(seg.mss)
		if c.peerMSS > MTU-40 {
			// Peer MSS is an upper bound; clamp it to our MTU.
			c.peerMSS = MTU - 40
		}
	}
	if seg.wsOK {
		c.wsOn = true
		c.sndWS = seg.ws
		c.rcvWS = c.advWS
		if c.sndWS > 14 {
			c.sndWS = 14 // RFC 7323 §2.3 caps the shift at 14
		}
	}
}

// rcvWnd is the promised window used for acceptability and RST validation, not
// newly freed physical space that has not yet been advertised.
func (c *tcpConn) rcvWnd() uint32 {
	if c.advSet {
		if d := seqDiff(c.advEdge, c.rcvNxt); d > 0 {
			return uint32(d)
		}
		return 0
	}
	return uint32(c.rx.free())
}

// inRcvWindow reports whether seq lies within the receive window.
func (c *tcpConn) inRcvWindow(seq uint32) bool {
	return seqLEQ(c.rcvNxt, seq) && seqLT(seq, c.rcvNxt+c.rcvWnd())
}

// segAcceptable implements RFC 9293 §3.10.7.4's four cases against the promised
// receive window. SEG.LEN includes FIN; SYN was handled earlier.
func (c *tcpConn) segAcceptable(seg tcpSeg) bool {
	segLen := uint32(len(seg.data))
	if seg.flags.Has(FlagFIN) {
		segLen++
	}
	wnd := c.rcvWnd()
	switch {
	case segLen == 0 && wnd == 0:
		return seg.seq == c.rcvNxt
	case segLen == 0:
		return c.inRcvWindow(seg.seq)
	case wnd == 0:
		return false // data while full gets a zero-window ACK
	default:
		// Use the same window predicate for both ends of the segment.
		return c.inRcvWindow(seg.seq) || c.inRcvWindow(seg.seq+segLen-1)
	}
}

// processAck advances sequence/ring state, updates windows and RTT, counts
// duplicates, and drives close transitions. Only ack==finSeq+1 acknowledges FIN.
func (c *tcpConn) processAck(seg tcpSeg, now int64) (accept bool) {
	ack := seg.ack
	// SYN-RCVD accepts only SND.UNA < ACK ≤ SND.NXT (RFC 9293 §3.10.7.4).
	// Invalid ACKs get <SEQ=SEG.ACK><RST> and cannot keep an embryo alive.
	//
	// Compare against maxSent because duplicate SYN may rewind nxt while a valid
	// final ACK for the earlier SYN-ACK is already in flight.
	if c.state == tcpSynRcvd && !(seqLT(c.una, ack) && seqLEQ(ack, c.maxSent)) {
		c.rst = pendingRST{seq: ack, set: true}
		return false
	}
	switch {
	case seqLT(c.maxSent, ack):
		// ACK beyond anything ever sent: advertise our state and drop the segment.
		// maxSent, unlike the retransmit cursor nxt, never rewinds.
		c.needAck = true
		return false
	case seqLT(ack, c.una):
		// An old ACK is not a duplicate under RFC 5681 §2 and breaks the run.
		c.dupacks = 0
		return true // ignore old ACK but still permit segment data
	}

	if c.state == tcpSynRcvd {
		// The guard above makes this the sole valid SYN-RCVD ACK. The shared
		// scaled window update below handles wl1/wl2.
		c.enterEstablished()
	}

	// Apply window updates only from segments no older than the last update.
	wnd := uint32(seg.wnd)
	if c.wsOn {
		wnd <<= c.sndWS
	}
	// Duplicate ACK requires an unchanged advertised window (RFC 5681 §2).
	sameWnd := wnd == c.sndWnd
	if seqLT(c.wl1, seg.seq) || (c.wl1 == seg.seq && seqLEQ(c.wl2, ack)) {
		wasClosed := c.sndWnd == 0
		c.sndWnd = wnd
		c.wl1, c.wl2 = seg.seq, ack
		// A valid zero-window update proves the peer is alive in persist mode and
		// resets retry count. Old zero-window advertisements do not.
		if c.sndWnd == 0 {
			c.retries = 0
		}
		// When a zero window opens without ACK progress, rewind to una because the
		// probe may have been lost. Resending one byte is safe if it arrived.
		if wasClosed && wnd > 0 {
			// End persist backoff; postTx will arm a clean normal RTO.
			c.persistBackoff = 0
			c.timerOn = false
			if ack == c.una && c.una != c.nxt {
				c.goBackN()
			}
		}
	}

	if ack == c.una {
		// RFC 5681 duplicate ACK: no data or FIN, same ACK and window, with data
		// in flight. Three trigger one go-back-N in any sending close state.
		if len(seg.data) == 0 && !seg.flags.Has(FlagFIN) && sameWnd && c.una != c.nxt {
			c.dupacks++
			if c.dupacks == 3 {
				c.goBackN()
			}
		} else {
			c.dupacks = 0
		}
		return true
	}

	// ack > una is real progress.
	dataAcked := seqDiff(ack, c.dataBase)
	if dataAcked > 0 {
		if dataAcked > c.tx.buffered() {
			dataAcked = c.tx.buffered() // SYN/FIN sequence space is not ring data
		}
		// A cumulative ACK may overtake retransmission after goBackN. Restore the
		// sent cursor before removing acknowledged bytes.
		c.tx.forceSent(dataAcked)
		c.tx.ack(dataAcked)
		c.dataBase += uint32(dataAcked)
	}
	c.una = ack
	if seqLT(c.nxt, ack) {
		// Catch the rewound send cursor up to a cumulative ACK.
		c.nxt = ack
	}
	c.dupacks = 0
	c.retries = 0 // real progress proves liveness
	c.persistBackoff = 0

	// Shrink after updating accounting because this final ACK may empty an idle
	// pooled connection. An in-flight FIN uses sequence, not ring, space.
	c.shrinkTx()

	// Karn permits RTT measurement only for non-retransmitted space.
	if c.timing && seqLEQ(c.timedSeq, ack) {
		c.updateRTT(time.Duration(now - c.timedAt))
		c.timing = false
		c.backoff = 0
	}

	// RFC 6298: stop the timer when fully acknowledged, otherwise restart it.
	if c.una == c.nxt {
		c.timerOn = false
	} else {
		c.timerOn = true
		c.deadline = now + int64(c.currentRTO())
	}

	// Close transitions that require exact FIN acknowledgment.
	if c.closing && ack == c.finSeq+1 {
		switch c.state {
		case tcpFinWait1:
			c.state = tcpFinWait2
			c.twDeadline = now + tcpFinWait2Dur // see tcpFinWait2Dur
		case tcpClosing:
			c.state = tcpTimeWait
			c.twDeadline = now + tcpTimeWaitDur
		case tcpLastAck:
			c.state = tcpClosed
			c.timerOn = false
		}
		// FIN acknowledgment means all transmit data is acknowledged, so release
		// the ring instead of holding it through FIN-WAIT-2 or TIME-WAIT.
		if c.pot != nil && c.tx.buffered() == 0 {
			c.pot.release(c.tx.size())
			c.tx = txRing{}
		}
	}
	return true
}

// processData handles in-order payload and FIN. It drops gaps with an immediate
// duplicate ACK so peers recover quickly without local reassembly.
func (c *tcpConn) processData(seg tcpSeg, now int64) {
	dataLen := len(seg.data)
	segEnd := seg.seq + uint32(dataLen)
	hasFin := seg.flags.Has(FlagFIN)

	// Trim an already-received prefix while retaining a new retransmitted suffix
	// (RFC 9293 §3.10.7.4).
	if d := seqDiff(c.rcvNxt, seg.seq); d > 0 && dataLen > 0 {
		if d >= dataLen {
			seg.data, dataLen = nil, 0 // all data seen; FIN may still count
		} else {
			seg.data = seg.data[d:]
			dataLen -= d
		}
		seg.seq = c.rcvNxt
		segEnd = seg.seq + uint32(dataLen)
	}

	// Trim at the advertised edge. A peer must not force ring growth by sending
	// beyond our promise; it will retransmit the tail within a later window.
	if c.advSet {
		allowed := seqDiff(c.advEdge, seg.seq)
		// FIN occupies one sequence position after data and needs remaining window.
		if hasFin && allowed <= dataLen {
			hasFin = false
			c.needAck = true // peer retransmits FIN after our window opens
		}
		if allowed < dataLen {
			// segAcceptable guarantees a positive overlap for data here.
			dataLen = allowed
			seg.data = seg.data[:allowed]
			segEnd = seg.seq + uint32(dataLen)
		}
	}

	if dataLen > 0 {
		if seg.seq != c.rcvNxt {
			c.needAck = true // duplicate ACK reports the gap
			return
		}
		if c.appClosed {
			// After full app close, advance and discard promised data so ACK and
			// FIN can still complete.
			c.rcvNxt += uint32(dataLen)
			c.needAck = true
			if hasFin {
				segEnd = c.rcvNxt
			}
			goto fin
		}
		n := c.rx.write(seg.data)
		c.rcvNxt += uint32(n)
		c.needAck = true
		// Receive growth, anchored to the first regular advertised edge. Two
		// signals, either one grows the ring:
		//   - the promised window filled (free == 0): the pressure case — a
		//     slow reader against a fast sender;
		//   - a FULL segment arrived (len == advMSS): the sender is window-
		//     limited while the reader keeps up. A fast reader drains between
		//     poll batches, so the ring never fills and a full-only trigger
		//     kept every bulk transfer at the 16KiB floor forever — measured
		//     18-08 on the LicheeRV: image streams at ~170KB/s (one floor
		//     window per ~90ms) while the budget pot sat idle. Chatty
		//     connections never send full segments and stay at the floor;
		//     shrinkRx returns grown rings there after the final read.
		if c.advSet && (c.rx.free() == 0 || len(seg.data) >= int(c.advMSS)) {
			if c.growRing(&c.rx) && n < dataLen {
				m := c.rx.write(seg.data[n:])
				c.rcvNxt += uint32(m)
				n += m
			}
		}
		if n < dataLen {
			// The peer retransmits the tail and any following FIN.
			return
		}
	}
fin:
	if hasFin {
		if segEnd != c.rcvNxt {
			c.needAck = true // out-of-order FIN uses the duplicate-ACK path
			return
		}
		c.rcvNxt++
		c.finRcvd = true
		c.needAck = true
		switch c.state {
		case tcpEstablished:
			c.state = tcpCloseWait
		case tcpFinWait1:
			// Our FIN remains unacknowledged: simultaneous close.
			c.state = tcpClosing
		case tcpFinWait2:
			c.state = tcpTimeWait
			c.twDeadline = now + tcpTimeWaitDur
		}
	}
}

// ---- transmit ----

// emit produces one segment with payload in buf. Call repeatedly until false;
// one connection may have a burst or data plus FIN ready.
func (c *tcpConn) emit(buf []byte, now int64) (seg tcpSeg, ok bool) {
	if seg, ok := c.takeRST(); ok {
		// A queued abort or invalid-ACK reset precedes all other output.
		return seg, true
	}
	switch c.state {
	case tcpClosed:
		return tcpSeg{}, false
	case tcpFinWait2:
		if now >= c.twDeadline {
			// Peer acknowledged our FIN but never closed; abort explicitly.
			return c.abortWithRST()
		}
	case tcpTimeWait:
		if now >= c.twDeadline {
			c.state = tcpClosed
			return tcpSeg{}, false
		}
		if c.needAck {
			c.needAck = false
			return c.bareAck(), true
		}
		return tcpSeg{}, false
	}

	// Pending work behind a zero window keeps a persist timer armed because the
	// peer's window-opening ACK may be lost.
	if !c.timerOn && c.sndWnd == 0 && (c.tx.unsent() > 0 || c.finPending()) {
		c.armTimer(now)
	}

	// RFC 6298 retransmission covers all in-flight sequence space, including SYN
	// and FIN.
	if c.timerOn && now >= c.deadline {
		c.retries++
		limit := uint8(tcpMaxRetriesData)
		if c.state == tcpSynSent || c.state == tcpSynRcvd {
			limit = tcpMaxRetriesHandshake
		}
		if c.retries > limit {
			// Peer stayed silent through the entire backoff ladder.
			return c.abortWithRST()
		}
		if c.sndWnd == 0 && seqDiff(c.nxt, c.una) <= 1 &&
			(c.tx.buffered() > 0 || c.finPending()) {
			// Persist probes use separate backoff (RFC 9293 §3.8.6.1) so a long
			// zero-window episode does not inflate the normal RTO.
			if c.persistBackoff < tcpBackoffMax {
				c.persistBackoff++
			}
			c.deadline = now + int64(min(c.currentRTO()*(1<<c.persistBackoff), tcpRTOMax))
			if c.una != c.nxt {
				c.goBackN() // resend the previous probe byte
			}
			c.probe = true // permit one byte beyond the zero window
		} else {
			if c.backoff < tcpBackoffMax {
				c.backoff++
				c.rto = min(c.currentRTO()*2, tcpRTOMax)
			}
			c.deadline = now + int64(c.currentRTO())
			if c.una != c.nxt {
				c.goBackN()
			}
		}
	}

	// nxt at iss means SYN or SYN|ACK, including retransmission, is due.
	if (c.state == tcpSynSent || c.state == tcpSynRcvd) && c.nxt == c.iss {
		c.nxt = c.iss + 1
		if seqLT(c.maxSent, c.nxt) {
			c.maxSent = c.nxt // SYN consumes sequence space
		}
		c.armTimer(now)
		// SYN windows are unscaled; SYN|ACK offers WS only when the peer did.
		seg = tcpSeg{seq: c.iss, flags: FlagSYN, wnd: c.rawWnd(),
			mss: c.advMSS, wsOK: true, ws: c.advWS}
		if c.state == tcpSynRcvd {
			seg.flags |= FlagACK
			seg.ack = c.rcvNxt
			seg.wsOK = c.wsOn
			// Record the unscaled SYN|ACK promise before a fast peer sends data.
			c.promiseEdge(uint32(seg.wnd))
		} else {
			c.synWnd = seg.wnd // active open anchors this after SYN|ACK
		}
		return seg, true
	}
	if c.state == tcpSynSent || c.state == tcpSynRcvd {
		return tcpSeg{}, false // SYN in flight; wait for response or timer
	}

	// Data path uses send-window headroom; an armed probe may exceed zero by one byte.
	inFlight := seqDiff(c.nxt, c.una)
	avail := int(c.sndWnd) - inFlight
	if avail < 0 {
		avail = 0
	}
	if c.probe && avail == 0 {
		avail = 1
	}
	n := c.tx.unsent()
	if n > avail {
		n = avail
	}
	if n > c.peerMSS {
		n = c.peerMSS
	}
	if n > len(buf) {
		n = len(buf)
	}
	if n > 0 {
		c.probe = false
		got := c.tx.nextSend(buf[:n])
		seg = tcpSeg{seq: c.nxt, ack: c.rcvNxt, flags: FlagACK | FlagPSH,
			wnd: c.advertisedWnd(), data: buf[:got]}
		c.nxt += uint32(got)
		c.postTx(seg.seq+uint32(got), now)
		// Piggyback FIN on final data when the window permits.
		if c.finPending() && c.nxt == c.finSeq && inFlight+got < int(c.sndWnd) {
			seg.flags |= FlagFIN
			c.sendFinBookkeeping(now)
		}
		c.needAck = false
		return seg, true
	}

	// Bare FIN consumes sequence space and obeys the send window. An armed probe
	// may use that one position and is consumed by the FIN.
	if c.finPending() && c.nxt == c.finSeq && (inFlight < int(c.sndWnd) || c.probe) {
		c.probe = false
		seg = tcpSeg{seq: c.nxt, ack: c.rcvNxt, flags: FlagFIN | FlagACK,
			wnd: c.advertisedWnd()}
		c.sendFinBookkeeping(now)
		c.needAck = false
		return seg, true
	}

	if c.needAck {
		c.needAck = false
		return c.bareAck(), true
	}
	return tcpSeg{}, false
}

// abortWithRST terminates and returns its reset in the same emit sequence.
func (c *tcpConn) abortWithRST() (tcpSeg, bool) {
	c.abort()
	return c.takeRST()
}

// takeRST is the single encoder and consumer of a queued reset.
func (c *tcpConn) takeRST() (tcpSeg, bool) {
	if !c.rst.set {
		return tcpSeg{}, false
	}
	r := c.rst
	c.rst = pendingRST{}
	seg := tcpSeg{seq: r.seq, flags: FlagRST}
	if r.withAck {
		seg.flags |= FlagACK
		seg.ack = r.ack
	}
	return seg, true
}

// finPending includes FIN made pending again by go-back-N rewind.
func (c *tcpConn) finPending() bool {
	return c.closing && seqLEQ(c.nxt, c.finSeq) && stateSendsFin(c.state)
}

func stateSendsFin(s tcpState) bool {
	switch s {
	case tcpEstablished, tcpCloseWait, tcpFinWait1, tcpClosing, tcpLastAck:
		return true
	}
	return false
}

// sendFinBookkeeping advances nxt over FIN and transitions state.
func (c *tcpConn) sendFinBookkeeping(now int64) {
	c.nxt = c.finSeq + 1
	if seqLT(c.maxSent, c.nxt) {
		c.maxSent = c.nxt // FIN consumes sequence space for future-ACK validation
	}
	c.armTimer(now)
	switch c.state {
	case tcpEstablished:
		c.state = tcpFinWait1
	case tcpCloseWait:
		c.state = tcpLastAck
	}
}

func (c *tcpConn) bareAck() tcpSeg {
	// Bare ACK carries SND.NXT (RFC 9293 §3.9), represented by never-rewound
	// maxSent rather than the temporary retransmit cursor nxt.
	return tcpSeg{seq: c.maxSent, ack: c.rcvNxt, flags: FlagACK, wnd: c.advertisedWnd()}
}

// rawWnd returns the unscaled SYN window.
func (c *tcpConn) rawWnd() uint16 {
	if w := c.rx.free(); w < 0xffff {
		return uint16(w)
	}
	return 0xffff
}

// goBackN rewinds the ring cursor and nxt to una so emit regenerates all
// unacknowledged data, SYN, and FIN.
func (c *tcpConn) goBackN() {
	c.tx.rewind()
	// The ring head is dataBase; una may precede it while SYN is in flight.
	if syn := seqDiff(c.dataBase, c.una); syn > 0 {
		c.nxt = c.iss // retransmit handshake
	} else {
		c.nxt = c.una
		// Acknowledged bytes already left the ring, so its head is una.
	}
	c.timing = false // Karn excludes retransmissions from RTT timing
}

// postTx records newly sent sequence space and arms RTT timing (RFC 6298 §5.1).
func (c *tcpConn) postTx(segEnd uint32, now int64) {
	// Karn starts samples only beyond maxSent. ACKs of retransmitted space are
	// ambiguous and must not collapse RTO or reset backoff.
	if !c.timing && seqLT(c.maxSent, segEnd) {
		c.timing = true
		c.timedSeq = segEnd
		c.timedAt = now
	}
	if seqLT(c.maxSent, segEnd) {
		c.maxSent = segEnd
	}
	c.armTimer(now)
}

func (c *tcpConn) armTimer(now int64) {
	if !c.timerOn {
		c.timerOn = true
		c.deadline = now + int64(c.currentRTO())
	}
}

// nextDeadline centralizes retransmission, FIN-WAIT-2, and TIME-WAIT scheduling.
// Retransmission wins if timers ever overlap.
func (c *tcpConn) nextDeadline() int64 {
	switch {
	case c.timerOn:
		return c.deadline
	case c.state == tcpTimeWait, c.state == tcpFinWait2:
		return c.twDeadline
	}
	return 0
}

func (c *tcpConn) currentRTO() time.Duration {
	rto := c.rto
	if rto < tcpRTOMin {
		rto = tcpRTOMin
	} else if rto > tcpRTOMax {
		rto = tcpRTOMax
	}
	return rto
}

// updateRTT folds a sample into SRTT, RTTVAR, and RTO (RFC 6298 §2.2/§2.3).
func (c *tcpConn) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if !c.haveRTT {
		c.srtt = sample
		c.rttvar = sample / 2
		c.haveRTT = true
	} else {
		diff := c.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		c.rttvar += (diff - c.rttvar) / 4
		c.srtt += (sample - c.srtt) / 8
	}
	c.rto = c.srtt + 4*c.rttvar
}
