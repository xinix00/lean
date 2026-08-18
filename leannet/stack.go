package leannet

// stack.go connects the pure protocol machines to a device: ingress
// demultiplexing, transmit pumping, ARP routing, and port tables. Only this
// layer knows about goroutines and locks.
//
// One mutex protects all machine state. One pump goroutine transmits frames and
// observes RTO, ARP, and TIME-WAIT timers. It sleeps until the earliest deadline
// or a notification, so an idle stack consumes no CPU. Blocking socket calls
// wait on the same notifications with their own deadlines.
//
// The transmit pump belongs here because HopOS has no separate transmit loop.

import (
	"errors"
	"sync"
	"time"
)

// Device is the NIC contract shared by HopOS drivers. Receive returns (0, nil)
// when empty; the owner of the receive loop passes frames to RecvInboundPacket.
type Device interface {
	Receive(buf []byte) (int, error)
	Transmit(buf []byte) error
}

// Wire constants exposed for buffer sizing.
const (
	MTU                 = 1500
	EthernetHeaderSize  = 14
	EthernetMaximumSize = 18 // header plus FCS margin
)

// Ephemeral ports are sequential within RFC 6335's dynamic range. Keep this
// range disjoint from hopswitch.MasqEnd.
const (
	ephemeralBase = 49152
	ephemeralEnd  = 65535
)

// loopbackMax covers a handshake plus a window of segments; overflow drops.
const loopbackMax = 64

// Bound connectionless replies so closed-port SYNs or echo floods cannot grow memory.
const outQueueCap = 32

// Initial TCP ring sizes are asymmetric because peers and applications create
// different pressure.
//
// Receive starts at 16 KiB so a peer can send RFC 6928's ten-segment initial
// congestion window without our advertised window forcing stop-and-wait. A
// fast reader might otherwise prevent growth from ever triggering.
//
// Transmit starts at 4 KiB and grows when application writes create pressure.
const (
	tcpFloorRx   = 16 << 10
	tcpFloorTx   = 4 << 10
	tcpFloorRing = tcpFloorRx + tcpFloorTx // minimum reservation per connection
)

var (
	errNoBudget     = errors.New("leannet: connection refused, buffer budget exhausted")
	errPortsInUse   = errors.New("leannet: no free ephemeral port")
	errUnreachable  = errors.New("leannet: no route to host (arp gave up)")
	errNoRoute      = errors.New("leannet: no route to host (destination off-subnet and no gateway configured)")
	errStackClosed  = errors.New("leannet: stack closed")
	errLoopbackFull = errors.New("leannet: loopback queue full")
)

// Config defines stack identity and its total connection-buffer budget.
type Config struct {
	IP     [4]byte
	Prefix int // subnet prefix length used for routing and seed validation
	MAC    [6]byte
	GW     [4]byte // zero means no route outside the subnet

	Budget int // bytes for all connection buffers combined

	// MaxBufPerConn caps one connection's growth; 0 means Budget/4.
	MaxBufPerConn int

	// AdvWS is the advertised window-scale shift. Zero is valid (RFC 7323).
	AdvWS uint8
}

type connKey struct {
	lport uint16
	rip   [4]byte
	rport uint16
}

// Stack connects the protocol machines under one mutex.
type Stack struct {
	mu  sync.Mutex
	cfg Config
	dev Device
	arp *arpTable
	pot budget

	conns     map[connKey]*sconn
	listeners map[uint16]*tcpListener
	udp       *udpTable

	// Connectionless replies are serialized when queued and routed best-effort.
	out []outPkt

	// Loopback frames target our own MAC; lbFree recycles their buffers.
	loopback [][]byte
	lbFree   [][]byte

	// Joined link-local multicast groups (multicast.go): a bounded set,
	// lazily allocated — most stacks never join anything.
	groups map[[4]byte]struct{}

	// The opt-in IPv6 lane (ipv6.go): nil until the first v6 socket or group
	// join, so a v4-only stack pays one nil check at the demux.
	v6   *v6State
	out6 []outPkt6

	gwMAC    [6]byte // statically planned gateway
	hasGwMAC bool

	// Closing wake broadcasts a state change. Waiters capture it under the lock.
	wake   chan struct{}
	closed bool

	t0 time.Time // monotonic clock origin

	nextEph uint16
	issSeed uint32

	txBuf []byte

	// Counters are protected by s.mu and exposed through snapshotting Stats().
	stats Stats
}

// Stats is a snapshot for external logging and telemetry.
type Stats struct {
	RefusedNoBudget int // connections refused because the budget was exhausted
	DropShortFrame  int
	DropNoPort      int
	DropBadFrame    int
	DropReplyFull   int // connectionless replies or loopback frames dropped on overflow

	// ARP contains a complete copy of the ARP machine counters.
	ARP ARPStats

	// NDP mirrors ARP for the v6 lane; all-zero when the lane never existed.
	NDP NDPStats
}

// ARPStats contains ARP machine counters.
type ARPStats struct {
	GaveUp     int // queries abandoned after arpQueryTries attempts
	Ignored    int // replies neither addressed to us nor gratuitous
	MACChanged int // refreshes that changed an existing entry's MAC
	ReplyDrop  int // replies dropped because their queue was full
	LearnDrop  int // passive learns rejected at arpCacheCap
	FullDrop   int // resolves blocked by pending/static entries filling the table
}

// Stats returns a race-free copy of all counters.
func (s *Stack) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.ARP = s.arp.cnt
	if s.v6 != nil {
		st.NDP = s.v6.ndp.cnt
	}
	return st
}

// NewStack creates a stack and starts its pump. issSeed should come from a real
// entropy source supplied by the caller.
func NewStack(dev Device, cfg Config, issSeed uint32) *Stack {
	// Invalid prefixes are programmer errors. RFC 7323 caps window scaling at 14;
	// larger values could shift every advertised window to zero.
	if cfg.Prefix < 0 || cfg.Prefix > 32 {
		panic("leannet: Config.Prefix must be in 0..32")
	}
	if cfg.AdvWS > 14 {
		cfg.AdvWS = 14 // RFC 7323 §2.3
	}
	if cfg.MaxBufPerConn == 0 {
		cfg.MaxBufPerConn = cfg.Budget / 4
	}
	if cfg.MaxBufPerConn < tcpFloorRing {
		cfg.MaxBufPerConn = tcpFloorRing
	}
	s := &Stack{
		cfg:       cfg,
		dev:       dev,
		arp:       newARPTable(cfg.IP, cfg.MAC),
		pot:       budget{total: cfg.Budget},
		conns:     make(map[connKey]*sconn),
		listeners: make(map[uint16]*tcpListener),
		udp:       newUDPTable(),
		wake:      make(chan struct{}),
		t0:        time.Now(),
		nextEph:   ephemeralBase,
		issSeed:   issSeed,
		txBuf:     make([]byte, MTU+EthernetMaximumSize),
	}
	go s.pump()
	return s
}

// now is the stack's monotonic clock and is unaffected by wall-clock changes.
func (s *Stack) now() int64 { return int64(time.Since(s.t0)) }

// notify wakes the pump and all socket waiters. s.mu must be held.
func (s *Stack) notify() {
	close(s.wake)
	s.wake = make(chan struct{})
}

// Close stops the pump, aborts and reaps connections, closes listeners, and
// releases UDP ports. Blocked operations return net.ErrClosed.
func (s *Stack) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.groups = nil
	for key, c := range s.conns {
		c.tcp.abort()
		s.reap(key, c)
	}
	// Use listener teardown to close done and clear backlog references; otherwise
	// Accept after Close could return an already-reaped connection.
	for _, l := range s.listeners {
		l.closeLocked()
	}
	for _, u := range s.udp.ports {
		// Deletion during map iteration is defined and close is idempotent.
		u.close()
	}
	if s.v6 != nil {
		for _, u := range s.v6.udp.ports {
			u.close()
		}
		s.v6.groups = nil
	}
	s.notify()
}

// SeedNeighbor installs a static neighbor. Non-gateway seeds outside the local
// subnet are rejected because routing would never consult them.
func (s *Stack) SeedNeighbor(ip [4]byte, mac [6]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == s.cfg.GW {
		s.gwMAC, s.hasGwMAC = mac, true
		// A static gateway makes any pending query obsolete; wake its waiters
		// because that query's timer no longer exists.
		delete(s.arp.entries, ip)
		s.notify()
		return nil
	}
	if !sameSubnet(ip, s.cfg.IP, s.cfg.Prefix) {
		return errors.New("leannet: seed outside subnet would never be consulted")
	}
	// Static entries bypass expiry and eviction, so cap them at half the table.
	// Updating an existing static entry does not consume another slot.
	e, exists := s.arp.entries[ip]
	if !exists || !e.static {
		statics := 0
		for _, o := range s.arp.entries {
			if o.static {
				statics++
			}
		}
		if statics >= arpCacheCap/2 {
			return errors.New("leannet: too many static neighbor seeds (cap is arpCacheCap/2)")
		}
	}
	// Seeds also obey the total cap; an existing IP does not grow the table.
	if !exists && !s.arp.makeRoom(s.now()) {
		return errors.New("leannet: neighbor table is full of pending queries; cannot seed")
	}
	if s.arp.seed(ip, mac) {
		// Wake waiters when the seed replaced their query and its timer.
		s.notify()
	}
	return nil
}

func sameSubnet(a, b [4]byte, prefix int) bool {
	au := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	bu := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	mask := ^uint32(0) << (32 - uint32(prefix))
	return au&mask == bu&mask
}

// isBroadcastIP recognizes limited and local directed broadcasts. RFC 3021
// defines no broadcast address for /31 and /32.
func isBroadcastIP(dst, ip [4]byte, prefix int) bool {
	if dst == bcastIP {
		return true
	}
	if prefix >= 31 {
		return false
	}
	du := uint32(dst[0])<<24 | uint32(dst[1])<<16 | uint32(dst[2])<<8 | uint32(dst[3])
	ou := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	mask := ^uint32(0) << (32 - uint32(prefix))
	return du&mask == ou&mask && du&^mask == ^mask
}

// ---- ingress ----

// RecvInboundPacket processes one untrusted Ethernet frame. It counts and drops
// short, misaddressed, or corrupt input without panicking.
func (s *Stack) RecvInboundPacket(frame []byte) error {
	eth, err := ParseEth(frame)
	if err != nil {
		s.mu.Lock()
		s.stats.DropShortFrame++
		s.mu.Unlock()
		return nil
	}
	if len(frame) > MTU+EthernetMaximumSize {
		// Reject jumbo frames before a generated reply can overflow txBuf.
		s.mu.Lock()
		s.stats.DropBadFrame++
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStackClosed
	}
	s.ingressLocked(eth, s.now())
	return nil
}

// ingressLocked is separated so the pump can feed loopback through the same demux.
func (s *Stack) ingressLocked(eth EthFrame, now int64) {
	toUs := [6]byte(eth.Dst()) == s.cfg.MAC
	switch eth.EtherType() {
	case EtherTypeARP:
		f, err := ParseARP(eth.Payload())
		if err != nil {
			s.stats.DropBadFrame++
			return
		}
		s.arp.recv(f, now)
		s.notify() // resolution or a reply may now be ready
	case EtherTypeIPv4:
		if !toUs {
			// Joined multicast is the one exception to "addressed to us".
			// UDP only: RFC 1122 §3.2.2.6 discourages echo replies to
			// multicast and TCP has no meaning there. Everything else is
			// normal LAN noise and leaves silently — counting it would
			// drown the drop counters that matter.
			if !isMulticastMAC([6]byte(eth.Dst())) {
				return
			}
			ip, err := ParseIPv4(eth.Payload())
			if err != nil || !ip.ChecksumOK() || !s.joinedLocked(ip.Dst()) || ip.Proto() != ProtoUDP {
				return
			}
			s.recvIPv4(ip, [6]byte(eth.Src()), now)
			return
		}
		ip, err := ParseIPv4(eth.Payload())
		if err != nil || !ip.ChecksumOK() || ip.Dst() != s.cfg.IP {
			s.stats.DropBadFrame++
			return
		}
		// Passive learning happens after transport checksum validation so a
		// forged IP header alone cannot claim a cache entry.
		s.recvIPv4(ip, [6]byte(eth.Src()), now)
	case EtherTypeIPv6:
		// The lane is opt-in: without it, v6 frames are ordinary LAN noise
		// and leave silently, uncounted, like unjoined multicast above.
		if s.v6 == nil {
			return
		}
		ip, err := ParseIPv6(eth.Payload())
		if err != nil {
			return // extension headers and truncations are noise, not faults
		}
		if !s.v6.acceptDst6(ip.Dst()) {
			return
		}
		s.recvIPv6(ip, [6]byte(eth.Src()), now)
	}
}

func (s *Stack) recvIPv4(ip IPv4Frame, srcMAC [6]byte, now int64) {
	src := ip.Src()
	// A multicast source address is never valid (RFC 1112 §7.2): discard
	// silently before any transport work or replies.
	if isMulticastIP(src) {
		s.stats.DropBadFrame++
		return
	}
	// Learn only from unicast addressed to us after transport checksum
	// validation. The checksum is not authentication; arp.learn's cap remains
	// the security boundary.
	learn := func() {
		if sameSubnet(src, s.cfg.IP, s.cfg.Prefix) && s.arp.learn(src, srcMAC, now) {
			// Wake route waiters now because later packet processing may return
			// early and resolving the query removed its timer.
			s.notify()
		}
	}
	switch ip.Proto() {
	case ProtoTCP:
		f, err := ParseTCP(ip.Payload())
		if err != nil || !f.ChecksumOK(src, s.cfg.IP) {
			s.stats.DropBadFrame++
			return
		}
		learn()
		s.recvTCP(f, src, now)
	case ProtoUDP:
		f, err := ParseUDP(ip.Payload())
		// The pseudo-header carries the frame's own destination: our unicast
		// address (guaranteed by ingress) or a joined multicast group.
		if err != nil || !f.ChecksumOK(src, ip.Dst()) {
			s.stats.DropBadFrame++
			return
		}
		learn()
		// Connected UDP shares the port table; deliver applies its peer filter.
		if !s.udp.deliver(f.DstPort(), src, f.SrcPort(), f.Payload()) {
			s.stats.DropNoPort++
			return
		}
		s.notify()
	case ProtoICMP:
		// Build an echo reply for the pump to transmit.
		if len(s.out) >= outQueueCap {
			s.stats.DropReplyFull++
			return
		}
		reply := make([]byte, len(ip.Payload()))
		if n, ok := icmpEcho(ip.Payload(), reply); ok {
			learn() // icmpEcho validated the ICMP checksum
			s.queueOutLocked(src, ProtoICMP, reply[:n])
			s.notify()
		}
	}
}

// outPkt is a serialized connectionless payload and destination.
type outPkt struct {
	dst   [4]byte
	proto byte
	pkt   []byte
}

func (s *Stack) recvTCP(f TCPFrame, src [4]byte, now int64) {
	seg, ok := parseTCPSeg(f)
	if !ok {
		s.stats.DropBadFrame++
		return
	}
	key := connKey{lport: f.DstPort(), rip: src, rport: f.SrcPort()}
	if c, exists := s.conns[key]; exists {
		c.tcp.recv(seg, now)
		s.maybeAccept(c)
		s.reap(key, c)
		s.notify()
		return
	}
	// Without a connection, a SYN to a listener opens an embryo. Everything but
	// RST receives an RFC 9293 §3.10.7.1 reset so closed-port dials fail promptly.
	l, listening := s.listeners[f.DstPort()]
	// Reject SYN|RST before allocating an embryo that the machine would ignore,
	// leaving a 20 KiB connection without a timer or reaper.
	if !listening || !seg.flags.Has(FlagSYN) || seg.flags.Has(FlagACK) ||
		seg.flags.Has(FlagRST) {
		if !seg.flags.Has(FlagRST) {
			// RFC reset sequence rules depend on whether the segment carried ACK.
			if seg.flags.Has(FlagACK) {
				// <SEQ=SEG.ACK><CTL=RST> has no ACK flag; strict SYN-SENT peers
				// discard RST|ACK with ack=0.
				s.queueRSTLocked(src, f.DstPort(), f.SrcPort(), seg.ack, 0, false)
			} else {
				// ACK covers SEG.LEN; SYN and FIN each consume one sequence number.
				segLen := uint32(len(seg.data))
				if seg.flags.Has(FlagSYN) {
					segLen++
				}
				if seg.flags.Has(FlagFIN) {
					segLen++
				}
				s.queueRSTLocked(src, f.DstPort(), f.SrcPort(), 0, seg.seq+segLen, true)
			}
			s.notify()
		}
		return
	}
	c, err := s.newConnLocked(key)
	if err != nil {
		// Refuse immediately with RST when the buffer budget is exhausted.
		s.stats.RefusedNoBudget++
		s.queueRSTLocked(src, f.DstPort(), f.SrcPort(), 0, seg.seq+1, true)
		s.notify()
		return
	}
	c.tcp.openPassive(s.nextISS(), uint16(MTU-40), s.cfg.AdvWS)
	c.tcp.recv(seg, now)
	// emit sends any pending reset first; reap preserves it if the connection dies.
	c.listener = l
	s.notify()
}

// maybeAccept offers a newly established embryo to its listener. The handshake
// completes on receive and need not produce an outgoing segment.
func (s *Stack) maybeAccept(c *sconn) {
	// Include CLOSE-WAIT because the final handshake ACK may also carry data and
	// FIN, passing through ESTABLISHED within one receive.
	if c.listener != nil && !c.accepted &&
		(c.tcp.state == tcpEstablished || c.tcp.state == tcpCloseWait) {
		c.accepted = true
		c.listener.offer(c)
	}
}

// reap removes a closed connection and returns its buffers. s.mu must be held.
//
// Move any pending RST to the connectionless queue first, or abort-and-reap can
// delete it before the pump sees it.
func (s *Stack) reap(key connKey, c *sconn) {
	if c.tcp.state != tcpClosed || c.reaped {
		return
	}
	if r := c.tcp.rst; r.set {
		// Use the capped queue like every other reset; notification follows below.
		c.tcp.rst = pendingRST{}
		s.queueRSTLocked(key.rip, key.lport, key.rport, r.seq, r.ack, r.withAck)
	}
	c.reaped = true
	delete(s.conns, key)
	s.pot.release(c.tcp.rx.size() + c.tcp.tx.size())
	// Wake blocked operations when a timer, rather than ingress, killed the connection.
	s.notify()
	// Detach budget accounting so later reads cannot release the same capacity twice.
	c.tcp.pot = nil
	// Drop actual backing arrays when returning their logical budget. Reap only
	// follows full close or reset; readable half-closed data remains in CLOSE-WAIT.
	c.tcp.tx = txRing{}
	c.tcp.rx = ring{}
}

// newConnLocked reserves and creates a connection at the floor sizes.
func (s *Stack) newConnLocked(key connKey) (*sconn, error) {
	if !s.pot.reserve(tcpFloorRing) {
		return nil, errNoBudget
	}
	c := &sconn{stack: s, key: key}
	c.tcp.rx = ring{buf: make([]byte, tcpFloorRx)}
	c.tcp.tx = txRing{ring: ring{buf: make([]byte, tcpFloorTx)}}
	c.tcp.pot = &s.pot
	c.tcp.maxBuf = s.cfg.MaxBufPerConn
	s.conns[key] = c
	return c, nil
}

// nextISS advances per connection to keep rapid port reuse from matching old segments.
func (s *Stack) nextISS() uint32 {
	s.issSeed += 64007 // prime increment traverses the full space
	return s.issSeed
}

// ephemeralPort chooses the next free dynamic port. inUse supplies the caller's
// namespace because TCP and UDP ports are independent.
func (s *Stack) ephemeralPort(inUse func(uint16) bool) (uint16, error) {
	for i := 0; i <= ephemeralEnd-ephemeralBase; i++ {
		p := s.nextEph
		if s.nextEph == ephemeralEnd {
			s.nextEph = ephemeralBase
		} else {
			s.nextEph++
		}
		if inUse(p) {
			continue
		}
		return p, nil
	}
	return 0, errPortsInUse
}

// tcpPortInUse includes listeners and connections, including TIME-WAIT.
func (s *Stack) tcpPortInUse(p uint16) bool {
	if _, ok := s.listeners[p]; ok {
		return true
	}
	for k := range s.conns {
		if k.lport == p {
			return true
		}
	}
	return false
}

// ---- egress pump ----

// pump sleeps until the earliest deadline or notification, then drains all
// ready output.
func (s *Stack) pump() {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		again := s.drainLocked()
		deadline := s.nextDeadlineLocked()
		ch := s.wake
		s.mu.Unlock()

		if again {
			continue // loopback input may have produced an immediate response
		}
		if deadline == 0 {
			<-ch
			continue
		}
		// nextDeadlineLocked already delays an expired deadline; negative timers fire now.
		t := time.NewTimer(time.Duration(deadline - s.now()))
		select {
		case <-ch:
		case <-t.C:
		}
		t.Stop()
	}
}

// drainLocked writes every ready frame. Device.Transmit is a short ring write,
// so it runs under the lock; double-buffer if that assumption changes.
func (s *Stack) drainLocked() (again bool) {
	now := s.now()

	for _, o := range s.out {
		// Route best-effort without starting ARP. Legitimate request sources were
		// just learned; querying spoofed sources would evict real cache entries.
		if mac, ok := s.routeLocked(o.dst, now, false); ok {
			s.sendIPv4Locked(mac, o.dst, o.proto, o.pkt)
		}
	}
	s.out = s.out[:0]

	// Wake route waiters when an ARP query gives up in this drain cycle.
	gaveUpVoor := s.arp.cnt.GaveUp
	for {
		n, ok := s.arp.emit(s.txBuf[EthernetHeaderSize:], now)
		if !ok {
			break
		}
		f, _ := ParseARP(s.txBuf[EthernetHeaderSize : EthernetHeaderSize+n])
		dst := bcastMAC
		if f.Op() == ARPReply {
			dst = [6]byte(f.TargetHW())
		}
		s.sendEthLocked(dst, EtherTypeARP, n)
	}
	if s.arp.cnt.GaveUp != gaveUpVoor {
		s.notify()
	}

	// The v6 lane's replies and NDP emission; a nil lane returns immediately.
	s.drain6Locked(now)

	// Drain each TCP connection when its route is available. emit is lazy, so a
	// missing MAC consumes no sequence state while ARP resolution runs.
	for key, c := range s.conns {
		mac, ok := s.routeLocked(key.rip, now, true)
		if !ok {
			// Abort once ARP gave up or routing has no gateway. Otherwise emit never
			// arms retransmission and the connection retains its budget forever.
			if hop, viaARP := s.nextHopLocked(key.rip); viaARP && (hop == ([4]byte{}) || s.arp.noAnswer(hop, now)) {
				// Static-gateway routes never reach this failure path.
				c.tcp.abort() // make reads and writes fail explicitly
				s.reap(key, c)
			}
			continue
		}
		for {
			seg, ok := c.emitWire(s.txBuf, now)
			if !ok {
				break
			}
			s.sendTCPLocked(mac, key, seg)
		}
		s.reap(key, c)
	}

	// Feed loopback through ingress. It may produce an immediate response, so ask
	// for another drain cycle instead of relying on a notification raised before
	// the pump captures its next wake channel.
	if len(s.loopback) == 0 {
		return false
	}
	lb := s.loopback
	s.loopback = s.loopback[:0]
	for _, fr := range lb {
		if eth, err := ParseEth(fr); err == nil {
			s.ingressLocked(eth, now)
		}
		s.lbFree = append(s.lbFree, fr)
	}
	return true
}

// nextDeadlineLocked returns the earliest machine deadline, or zero for none.
func (s *Stack) nextDeadlineLocked() int64 {
	var d int64
	now := s.now()
	add := func(t int64) {
		if t == 0 {
			return
		}
		// Recheck expired deadlines at the minimum RTO. A missing route may leave
		// one pending, and a 10 ms retry caused 100 idle wakeups per second.
		if t <= now {
			t = now + int64(tcpRTOMin)
		}
		if d == 0 || t < d {
			d = t
		}
	}
	for _, c := range s.conns {
		add(c.tcp.nextDeadline())
	}
	for _, e := range s.arp.entries {
		switch e.state {
		case arpPending:
			add(e.due)
		case arpFailed:
			add(e.born + arpFailTTL)
		case arpResolved:
			// No wakeup: every lookup expires lazily and capacity paths sweep.
			// Memory is already capped, so periodic cleanup would only cost idle CPU.
		}
	}
	if s.v6 != nil {
		s.v6.ndp.nextDeadline(add)
	}
	return d
}

// nextHopLocked returns the address whose ARP state governs dst. viaARP=false
// marks a static gateway route that no ARP failure may block. Dial, UDP, and the
// pump share this decision.
func (s *Stack) nextHopLocked(dst [4]byte) (hop [4]byte, viaARP bool) {
	if isLinkLocalMulticast(dst) {
		return dst, false // link-local: never the gateway, never ARP
	}
	if s.hasGwMAC && (dst == s.cfg.GW || !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix)) {
		return dst, false // static plan has no ARP outcome
	}
	if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) {
		return s.cfg.GW, true // zero means no configured route
	}
	return dst, true
}

// routeLocked resolves the next-hop MAC directly or through the gateway.
// query=false only peeks, for best-effort output from drainLocked.
func (s *Stack) routeLocked(dst [4]byte, now int64, query bool) ([6]byte, bool) {
	// Route our own address directly to loopback. ARPing for ourselves cannot
	// succeed because a switch does not reflect the broadcast to its source.
	if dst == s.cfg.IP {
		return s.cfg.MAC, true
	}
	// Link-local multicast maps straight to its Ethernet address (RFC 1112
	// §6.4): no resolution, and never the gateway — the scope is this link.
	// Wider multicast never reaches here: writeUDP refuses it, dialTCP too.
	if isLinkLocalMulticast(dst) {
		return multicastMAC(dst), true
	}
	// Route limited and directed broadcasts to the Ethernet broadcast MAC. This
	// is required for DHCP rebind (RFC 2131 §4.4.5); replies arrive unicast.
	if isBroadcastIP(dst, s.cfg.IP, s.cfg.Prefix) {
		return bcastMAC, true
	}
	// A seeded gateway also covers traffic addressed to the gateway itself.
	if s.hasGwMAC && dst == s.cfg.GW {
		return s.gwMAC, true
	}
	if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) {
		if s.hasGwMAC {
			return s.gwMAC, true
		}
		dst = s.cfg.GW
		if dst == ([4]byte{}) {
			return [6]byte{}, false
		}
		// Even best-effort output may resolve the configured gateway: it can create
		// only this one trusted entry and enables off-subnet refusal resets.
		query = true
	}
	if !query {
		return s.arp.peek(dst, now)
	}
	return s.arp.resolve(dst, now)
}

// ---- wire writers; s.mu must be held ----

// queueOutLocked queues a bounded connectionless packet and counts overflow.
func (s *Stack) queueOutLocked(dst [4]byte, proto byte, pkt []byte) {
	if len(s.out) >= outQueueCap {
		s.stats.DropReplyFull++
		return
	}
	s.out = append(s.out, outPkt{dst: dst, proto: proto, pkt: pkt})
}

// queueRSTLocked serializes and queues a reset. withAck selects RST|ACK versus
// RFC 9293 §3.10.7.1's bare <SEQ=SEG.ACK><RST>.
func (s *Stack) queueRSTLocked(dst [4]byte, sport, dport uint16, seq, ack uint32, withAck bool) {
	flags := FlagRST
	if withAck {
		flags |= FlagACK
	}
	buf := make([]byte, sizeTCP)
	n, err := PutTCP(buf, sport, dport, seq, ack, flags, 0, nil, s.cfg.IP, dst, 0)
	if err != nil {
		return // only an internal sizing error can reach this
	}
	// queueOutLocked enforces the cap and counts overflow.
	s.queueOutLocked(dst, ProtoTCP, buf[:n])
}

func (s *Stack) sendEthLocked(dst [6]byte, etherType uint16, payloadLen int) error {
	eth, _ := ParseEth(s.txBuf)
	eth.SetDst(dst)
	eth.SetSrc(s.cfg.MAC)
	eth.SetEtherType(etherType)
	n := EthernetHeaderSize + payloadLen
	if n < 60 {
		// Zero-pad to the minimum Ethernet frame length to avoid leaking old data.
		for i := EthernetHeaderSize + payloadLen; i < 60; i++ {
			s.txBuf[i] = 0
		}
		n = 60
	}
	// A joined group hears its own sends (IP_MULTICAST_LOOP semantics
	// elsewhere): copy to loopback AND still transmit to the wire. mDNS
	// responders depend on hearing their own queries. Overflow only loses
	// the local copy.
	if isMulticastMAC(dst) && etherType == EtherTypeIPv4 {
		if ip, err := ParseIPv4(s.txBuf[EthernetHeaderSize:n]); err == nil && s.joinedLocked(ip.Dst()) {
			if len(s.loopback) < loopbackMax {
				s.loopback = append(s.loopback, append(s.lbBuf(), s.txBuf[:n]...))
				s.notify()
			} else {
				s.stats.DropReplyFull++
			}
		}
	}
	// The same IP_MULTICAST_LOOP semantics for the v6 lane's joined groups.
	if isMulticastMAC6(dst) && etherType == EtherTypeIPv6 && s.v6 != nil {
		if ip, err := ParseIPv6(s.txBuf[EthernetHeaderSize:n]); err == nil {
			if _, joined := s.v6.groups[ip.Dst()]; joined {
				if len(s.loopback) < loopbackMax {
					s.loopback = append(s.loopback, append(s.lbBuf(), s.txBuf[:n]...))
					s.notify()
				} else {
					s.stats.DropReplyFull++
				}
			}
		}
	}
	// Frames to our own MAC enter local ingress rather than the wire, providing
	// loopback semantics on this stack's only address.
	//
	// Copy because txBuf is reused immediately. Overflow drops and TCP retransmits.
	if dst == s.cfg.MAC {
		if len(s.loopback) >= loopbackMax {
			// Report overflow: TCP can recover by retransmission, but UDP cannot.
			s.stats.DropReplyFull++
			return errLoopbackFull
		}
		s.loopback = append(s.loopback, append(s.lbBuf(), s.txBuf[:n]...))
		// Wake the pump because UDP may enqueue loopback directly from Write.
		s.notify()
		return nil
	}
	// Return transmit errors; TCP retransmits, while UDP must report failure.
	return s.dev.Transmit(s.txBuf[:n])
}

// lbBuf reuses loopback buffers returned by drainLocked.
func (s *Stack) lbBuf() []byte {
	if n := len(s.lbFree); n > 0 {
		b := s.lbFree[n-1]
		s.lbFree = s.lbFree[:n-1]
		return b[:0]
	}
	return make([]byte, 0, MTU+EthernetMaximumSize)
}

func (s *Stack) sendIPv4Locked(dstMAC [6]byte, dstIP [4]byte, proto byte, payload []byte) {
	off := EthernetHeaderSize
	copy(s.txBuf[off+sizeIPv4:], payload)
	n, _ := PutIPv4(s.txBuf[off:], proto, s.cfg.IP, dstIP, len(payload))
	s.sendEthLocked(dstMAC, EtherTypeIPv4, n+len(payload))
}

func (s *Stack) sendTCPLocked(dstMAC [6]byte, key connKey, w wireSeg) {
	off := EthernetHeaderSize + sizeIPv4
	n, err := PutTCP(s.txBuf[off:], key.lport, key.rport, w.seg.seq, w.seg.ack,
		w.seg.flags, w.seg.wnd, w.opts, s.cfg.IP, key.rip, w.payloadLen)
	if err != nil {
		s.stats.DropBadFrame++ // count the internal sizing error explicitly
		return
	}
	PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoTCP, s.cfg.IP, key.rip, n)
	s.sendEthLocked(dstMAC, EtherTypeIPv4, sizeIPv4+n)
}

// ---- TCP segment ⇄ wire ----

// wireSeg is an emitted segment plus wire-format details.
type wireSeg struct {
	seg        tcpSeg
	opts       []byte
	payloadLen int
}

// sconn combines a TCP machine with stack identity.
type sconn struct {
	stack    *Stack
	key      connKey
	tcp      tcpConn
	listener *tcpListener // set on embryos and cleared by accept
	accepted bool
	reaped   bool

	optsBuf [8]byte
}

// emitWire writes payload directly into its transmit-frame position and adds SYN options.
func (c *sconn) emitWire(txBuf []byte, now int64) (wireSeg, bool) {
	payloadAt := EthernetHeaderSize + sizeIPv4 + sizeTCP
	seg, ok := c.tcp.emit(txBuf[payloadAt:], now)
	if !ok {
		return wireSeg{}, false
	}
	w := wireSeg{seg: seg, payloadLen: len(seg.data)}
	if seg.flags.Has(FlagSYN) {
		// MSS plus NOP and window scale occupy one aligned eight-byte block. SYN
		// carries no payload here, so options overlap nothing.
		b := c.optsBuf[:0]
		b = append(b, 2, 4, byte(seg.mss>>8), byte(seg.mss))
		if seg.wsOK {
			b = append(b, 1, 3, 3, seg.ws)
		}
		w.opts = b
	}
	return w, true
}

// parseTCPSeg converts a validated frame and its MSS/WS options to machine form.
func parseTCPSeg(f TCPFrame) (tcpSeg, bool) {
	seg := tcpSeg{
		seq:   f.Seq(),
		ack:   f.Ack(),
		flags: f.Flags(),
		wnd:   f.Window(),
		data:  f.Payload(),
	}
	if seg.flags.Has(FlagSYN) {
		opts := f.Options()
		for len(opts) > 0 {
			switch opts[0] {
			case 0: // EOL
				return seg, true
			case 1: // NOP
				opts = opts[1:]
				continue
			}
			if len(opts) < 2 || int(opts[1]) < 2 || int(opts[1]) > len(opts) {
				return seg, false // reject malformed options
			}
			switch opts[0] {
			case 2: // MSS
				if opts[1] == 4 {
					seg.mss = uint16(opts[2])<<8 | uint16(opts[3])
				}
			case 3: // window scale
				if opts[1] == 3 {
					seg.wsOK, seg.ws = true, opts[2]
				}
			}
			opts = opts[opts[1]:]
		}
	}
	return seg, true
}
