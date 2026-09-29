package leannet

// socket.go adapts the stack to net.Conn, net.Listener, net.PacketConn, and
// TamaGo's net.SocketFunc. Errors never masquerade as values, deadlines govern
// all blocking, ReadFrom returns *net.UDPAddr, and accepted connections expose
// usable addresses.
//
// Blocking checks a condition under s.mu, captures wake, unlocks, then selects
// on notification and deadline. It never polls or sleeps.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

// Socket family and type values match TamaGo's syscall package, the one
// consumer of this boundary. TamaGo numbers them with iota (UNSPEC, UNIX,
// INET, INET6), so AF_INET happens to match Linux's 2 while AF_INET6 is 3 —
// NOT Linux's 10; that mismatch cost a QEMU boot to find (18-08).
const (
	afINET     = 2
	afINET6    = 3
	sockSTREAM = 1
	sockDGRAM  = 2
)

const (
	// Bound dials without a context deadline against silent hosts.
	dialTimeoutDefault = 30 * time.Second

	// Per-socket UDP queue bytes, sufficient for DNS, SNTP, and QUIC transport.
	udpQueueCap = 32 << 10

	// Completed handshakes awaiting Accept. Overflow gets RST rather than
	// retaining an invisible connection slot.
	tcpBacklog = 8

	// A completed handshake has no application owner until Accept returns it.
	// Bound that handoff independently of peer traffic so an abandoned listener
	// cannot retain the backlog's tuples and floor buffers forever.
	tcpBacklogWaitDur = int64(30 * time.Second)
)

var errInvalidUDP6Remote = errors.New("leannet: invalid IPv6 UDP remote address")

// waitCtx waits for notification, deadline, or context cancellation. ctx may be
// nil; that hot path avoids unnecessary select machinery when no deadline exists.
//
// Context deadlines must consistently report context.DeadlineExceeded even if
// the local timer wins the race with ctx.Done.
func waitCtx(ctx context.Context, ch <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		if ctx == nil {
			<-ch
			return nil
		}
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d := time.Until(deadline)
	if d <= 0 {
		return deadlineErr(ctx, deadline)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	if ctx == nil {
		select {
		case <-ch:
			return nil
		case <-t.C:
			return os.ErrDeadlineExceeded
		}
	}
	select {
	case <-ch:
		return nil
	case <-t.C:
		return deadlineErr(ctx, deadline)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// deadlineErr maps a local timer matching the context deadline to
// context.DeadlineExceeded, independent of timer race order.
func deadlineErr(ctx context.Context, deadline time.Time) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if dl, ok := ctx.Deadline(); ok && !deadline.Before(dl) {
			return context.DeadlineExceeded
		}
	}
	return os.ErrDeadlineExceeded
}

// await evaluates cond under s.mu until completion or error. It rereads dl each
// cycle so Set*Deadline affects blocked I/O. closedFirst preserves net.Conn's
// rule that an already-closed socket takes precedence over an expired deadline.
func (s *Stack) closedFirst(closed func() bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed() {
		return net.ErrClosed
	}
	return nil
}

func (s *Stack) await(ctx context.Context, dl func() time.Time, cond func() (bool, error)) error {
	s.mu.Lock()
	for {
		// An expired deadline rejects even ready I/O; otherwise a late Read would
		// still consume queued data.
		if d := dl(); !d.IsZero() && !time.Now().Before(d) {
			s.mu.Unlock()
			return deadlineErr(ctx, d)
		}
		finished, err := cond()
		if finished || err != nil {
			s.mu.Unlock()
			return err
		}
		ch := s.wake
		deadline := dl()
		s.mu.Unlock()
		werr := waitCtx(ctx, ch, deadline)
		s.mu.Lock()
		if werr != nil {
			// Recheck the current deadline: extending or clearing it deliberately
			// does not broadcast, so the timer may represent obsolete state.
			if errors.Is(werr, os.ErrDeadlineExceeded) {
				if cur := dl(); cur.IsZero() || time.Now().Before(cur) {
					continue
				}
			}
			s.mu.Unlock()
			return werr
		}
	}
}

func tcpAddr(ip [4]byte, port uint16) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(ip[:]).To16(), Port: int(port)}
}
func udpAddr(ip [4]byte, port uint16) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(ip[:]).To16(), Port: int(port)}
}

// addrPort extracts an IPv4 address and port from net.Addr.
func addrPort(a net.Addr) (ip [4]byte, port uint16, ok bool) {
	// Handle typed nils explicitly while accepting an empty address as wildcard.
	var ap netip.AddrPort
	switch v := a.(type) {
	case *net.TCPAddr:
		if v == nil {
			return ip, 0, false
		}
		ap = v.AddrPort()
	case *net.UDPAddr:
		if v == nil {
			return ip, 0, false
		}
		ap = v.AddrPort()
	default:
		return ip, 0, false
	}
	if a4 := ap.Addr().Unmap(); a4.Is4() {
		ip = a4.As4()
	} else if a4.IsValid() {
		return ip, 0, false // native IPv6 is unsupported
	}
	return ip, ap.Port(), true
}

// portInRange validates the original int before conversion to uint16 can wrap it.
func portInRange(a net.Addr) bool {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.Port >= 0 && v.Port <= 65535
	case *net.UDPAddr:
		return v.Port >= 0 && v.Port <= 65535
	}
	return false
}

// Socket also rejects unusable remote ports so an invalid dial cannot become a listener.

// ---- TCP listener ----

// tcpListener implements net.Listener.
type tcpListener struct {
	s       *Stack
	port    uint16
	backlog chan *sconn
	done    chan struct{}
	closed  bool
}

// Listen opens a TCP listener; port zero selects an ephemeral port. Only
// connections consume buffer budget.
func (s *Stack) Listen(port uint16) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStackClosed
	}
	if port == 0 {
		p, err := s.ephemeralPort(s.tcpPortInUse)
		if err != nil {
			return nil, err
		}
		port = p
	} else if s.tcpPortInUse(port) {
		return nil, errors.New("leannet: tcp port in use")
	}
	l := &tcpListener{s: s, port: port,
		backlog: make(chan *sconn, tcpBacklog), done: make(chan struct{})}
	s.listeners[port] = l
	return l, nil
}

// offer sends a completed handshake to Accept. Backlog overflow aborts it.
// s.mu must be held.
func (l *tcpListener) offer(c *sconn) {
	// Reject handshakes finishing after Close so they cannot retain budget in an
	// unread backlog.
	if l.closed {
		c.tcp.abort()
		l.s.reap(c.key, c)
		return
	}
	l.pruneStaleLocked()
	select {
	case l.backlog <- c:
	default:
		c.tcp.abort()
		l.s.reap(c.key, c)
	}
}

// pruneStaleLocked physically removes stale channel entries before applying
// the backlog cap. Reap removes the connection from Stack.conns immediately,
// but a channel reference otherwise occupies its slot until an Accept happens.
// l.s.mu must be held; Accept may concurrently consume but no other sender can
// run while this method rotates the bounded queue.
func (l *tcpListener) pruneStaleLocked() {
	var keep [tcpBacklog]*sconn
	nkeep := 0
	n := len(l.backlog)
drain:
	for range n {
		select {
		case c := <-l.backlog:
			if l.s.conns[c.key] == c {
				keep[nkeep] = c
				nkeep++
			}
		default:
			break drain
		}
	}
	for _, c := range keep[:nkeep] {
		l.backlog <- c
	}
}

func (l *tcpListener) Accept() (net.Conn, error) {
	for {
		select {
		case c := <-l.backlog:
			// A peer may reset, or a CLOSE-WAIT lifecycle timer may reap the
			// connection while it is queued. Never hand that stale backlog
			// reference to the application.
			l.s.mu.Lock()
			live := l.s.conns[c.key] == c
			if live {
				c.handoffDeadline = 0
				c.listener = nil
				c.tcp.touchCloseWait(l.s.now())
				// Recalculate the protocol timer after removing the handoff bound.
				l.s.notify()
			}
			l.s.mu.Unlock()
			if !live {
				continue
			}
			return &tcpSock{s: l.s, c: c}, nil
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
}

func (l *tcpListener) Close() error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	l.closeLocked()
	return nil
}

// closeLocked is the shared idempotent listener teardown. s.mu must be held.
func (l *tcpListener) closeLocked() {
	if l.closed {
		return
	}
	l.closed = true
	delete(l.s.listeners, l.port)
	close(l.done)
	// Drain backlog references so Accept cannot select an already-dead connection.
	for {
		select {
		case c := <-l.backlog:
			c.tcp.abort()
			l.s.reap(c.key, c)
		default:
			// Abort in-progress embryos immediately rather than retaining their
			// budget through handshake backoff against a closed listener.
			for key, c := range l.s.conns {
				if c.listener == l && c.handoffDeadline == 0 {
					c.tcp.abort()
					l.s.reap(key, c)
				}
			}
			l.s.notify()
			return
		}
	}
}

func (l *tcpListener) Addr() net.Addr { return tcpAddr(l.s.cfg.IP, l.port) }

// ---- TCP conn ----

// tcpSock implements net.Conn over a stack connection.
type tcpSock struct {
	s *Stack
	c *sconn

	rdDeadline time.Time
	wrDeadline time.Time

	// closed makes all socket I/O return net.ErrClosed while TCP completes its FIN.
	closed bool
}

// DialTCP actively opens a connection and waits for success, RST, ARP failure,
// or deadline.
func (s *Stack) DialTCP(raddr [4]byte, rport uint16, deadline time.Time) (net.Conn, error) {
	return s.dialTCP(nil, raddr, rport, deadline)
}

// dialTCP adds an optional cancellable context for SocketFunc and net.DialContext.
func (s *Stack) dialTCP(ctx context.Context, raddr [4]byte, rport uint16, deadline time.Time) (net.Conn, error) {
	if deadline.IsZero() {
		deadline = time.Now().Add(dialTimeoutDefault)
	}
	// TCP to a multicast address is meaningless: ingress drops multicast TCP
	// by contract, so a SYN would only burn wire and ~20 KiB of connection
	// state until the handshake times out. Refuse before any of that exists.
	if isMulticastIP(raddr) {
		return nil, errors.New("leannet: tcp to a multicast address")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errStackClosed
	}
	// Fail immediately when an off-subnet destination has no gateway; no ARP
	// query could ever make progress.
	hop, hopViaARP := s.nextHopLocked(raddr)
	if hopViaARP && hop == ([4]byte{}) {
		s.mu.Unlock()
		return nil, errNoRoute
	}
	lport, err := s.ephemeralPort(s.tcpPortInUse)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	key := connKey{lport: lport, rip: raddr, rport: rport}
	c, err := s.newConnLocked(key)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	c.tcp.openActive(s.nextISS(), uint16(s.linkMTU(raddr)-40), s.cfg.AdvWS)
	// hop determines which ARP outcome governs this dial.
	s.notify() // pump the SYN, resolving ARP first if needed

	s.mu.Unlock()

	err = s.await(ctx, func() time.Time { return deadline },
		func() (bool, error) {
			switch {
			case s.closed:
				return false, errStackClosed
			case c.tcp.state == tcpEstablished || c.tcp.state == tcpCloseWait:
				// A peer may send data and FIN before this waiter wakes, moving
				// through ESTABLISHED into a still-usable CLOSE-WAIT.
				c.tcp.touchCloseWait(s.now())
				return true, nil
			case hopViaARP && s.arp.noAnswer(hop, s.now()):
				// Only ARP-governed routes can fail here. Check before tcpClosed
				// because the pump may already have aborted the connection for the
				// same route failure; report no route rather than timeout.
				return false, errUnreachable
			case c.tcp.state == tcpClosed:
				if c.tcp.refused {
					return false, errors.New("leannet: connection refused")
				}
				// No RST or response: handshake retries exhausted.
				return false, errors.New("leannet: connect timed out, no response")
			}
			return false, nil
		})
	if err != nil {
		// One idempotent cleanup path covers state errors, deadlines, and cancellation.
		s.mu.Lock()
		c.tcp.abort()
		s.reap(key, c)
		s.mu.Unlock()
		return nil, err
	}
	return &tcpSock{s: s, c: c}, nil
}

func (t *tcpSock) Read(p []byte) (int, error) {
	if err := t.s.closedFirst(func() bool { return t.closed }); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		// net.Conn requires a zero-length read to return immediately.
		return 0, nil
	}
	var total int
	err := t.s.await(nil, func() time.Time { return t.rdDeadline },
		func() (bool, error) {
			if t.closed {
				return false, net.ErrClosed
			}
			n, err := t.c.tcp.read(p)
			if n > 0 {
				total = n
				t.c.tcp.touchCloseWait(t.s.now())
				t.s.notify() // reading may have opened the receive window
				return true, nil
			}
			if err == errTCPClosed {
				// FIN is EOF; reset remains an error.
				return false, io.EOF
			}
			return false, err // nil means wait for data
		})
	return total, err
}

func (t *tcpSock) Write(p []byte) (int, error) {
	if err := t.s.closedFirst(func() bool { return t.closed }); err != nil {
		return 0, err
	}
	var total int
	err := t.s.await(nil, func() time.Time { return t.wrDeadline },
		func() (bool, error) {
			for {
				if t.closed {
					return false, net.ErrClosed
				}
				n, err := t.c.tcp.write(p[total:])
				total += n
				if n > 0 {
					t.c.tcp.touchCloseWait(t.s.now())
				}
				if err != nil {
					return false, err
				}
				if total == len(p) {
					t.s.notify() // let the pump transmit
					return true, nil
				}
				if n == 0 {
					// Full ring that could not grow: wait for ACK space.
					return false, nil
				}
				t.s.notify() // partial write; pump it before retrying
			}
		})
	return total, err
}

func (t *tcpSock) Close() error {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	t.closed = true              // blocked I/O observes this on wake
	_ = t.c.tcp.close()          // duplicate socket close is not an error
	t.c.tcp.abandonRead(s.now()) // full close releases RX and arms absolute cleanup
	s.notify()                   // send FIN and wake waiters
	return nil
}

func (t *tcpSock) LocalAddr() net.Addr  { return tcpAddr(t.s.cfg.IP, t.c.key.lport) }
func (t *tcpSock) RemoteAddr() net.Addr { return tcpAddr(t.c.key.rip, t.c.key.rport) }

// Grown reports whether this connection's rings outgrew their floors. That is
// the connection classifying itself: only bulk transfers grow (a full segment
// is the growth signal, tcp.go); chatty long-lived streams (SSE, attach
// sessions) stay at the floor forever. A grown receive ring carries an
// advertised-window promise that pins budget for as long as the connection
// idles open (the promise cannot shrink left, RFC 9293). So "fast
// always has an end": a pool should CLOSE a grown connection instead of
// keeping it idle — the promise dies with the close and the budget returns at
// once. leanhttp does that on both sides of a request.
func (t *tcpSock) Grown() bool {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	return t.c.tcp.rx.size() > tcpFloorRx || t.c.tcp.tx.size() > tcpFloorTx
}

// Wake deadline waiters only when a new deadline is earlier or replaces zero.
// Extending one is observed when the old timer fires, avoiding broadcast storms.
func deadlineNeedsWake(old, new time.Time) bool {
	return !new.IsZero() && (old.IsZero() || new.Before(old))
}

// storeDeadline updates one or two fields under s.mu and applies the shared wake rule.
func (s *Stack) storeDeadline(tm time.Time, a, b *time.Time) error {
	s.mu.Lock()
	wake := deadlineNeedsWake(*a, tm)
	*a = tm
	if b != nil {
		wake = wake || deadlineNeedsWake(*b, tm)
		*b = tm
	}
	if wake {
		s.notify()
	}
	s.mu.Unlock()
	return nil
}

func (t *tcpSock) SetDeadline(tm time.Time) error {
	return t.s.storeDeadline(tm, &t.rdDeadline, &t.wrDeadline)
}
func (t *tcpSock) SetReadDeadline(tm time.Time) error {
	return t.s.storeDeadline(tm, &t.rdDeadline, nil)
}
func (t *tcpSock) SetWriteDeadline(tm time.Time) error {
	return t.s.storeDeadline(tm, &t.wrDeadline, nil)
}

// ---- UDP ----

// udpSock implements net.PacketConn and, when connected, net.Conn.
type udpSock struct {
	s     *Stack
	port  *udpPort
	lport uint16
	v6    bool // bound on the v6 lane (ipv6.go); families never mix on one socket

	// raddr is family-wide like udpDatagram.src: IPv4 in the first four bytes.
	connected bool
	raddr     [16]byte
	rport     uint16

	rdDeadline time.Time
	wrDeadline time.Time
}

// ListenUDP binds a UDP port, selecting an ephemeral one for zero.
func (s *Stack) ListenUDP(port uint16) (*udpSock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStackClosed
	}
	if port == 0 {
		p, err := s.ephemeralPort(s.udp.bound)
		if err != nil {
			return nil, err
		}
		port = p
	}
	u, err := s.udp.bind(port, udpQueueCap, &s.pot)
	if err != nil {
		return nil, err
	}
	return &udpSock{s: s, port: u, lport: port}, nil
}

// DialUDP binds an ephemeral port to one peer for Read and Write.
func (s *Stack) DialUDP(raddr [4]byte, rport uint16) (*udpSock, error) {
	u, err := s.ListenUDP(0)
	if err != nil {
		return nil, err
	}
	var wide [16]byte
	copy(wide[:4], raddr[:])
	u.connected, u.raddr, u.rport = true, wide, rport
	u.s.mu.Lock()
	u.port.connected, u.port.peer, u.port.peerPort = true, wide, rport
	u.s.mu.Unlock()
	return u, nil
}

func (u *udpSock) ReadFrom(p []byte) (int, net.Addr, error) {
	if err := u.s.closedFirst(func() bool { return u.port.closed }); err != nil {
		return 0, nil, err
	}
	var (
		total int
		from  net.Addr
	)
	err := u.s.await(nil, func() time.Time { return u.rdDeadline },
		func() (bool, error) {
			for {
				if u.port.closed {
					// Both socket and stack close release the queue; no datagram can follow.
					return false, net.ErrClosed
				}
				n, src, is6, sport, ok := u.port.recvFrom(p)
				if !ok {
					return false, nil // wait for a datagram
				}
				if u.connected && (src != u.raddr || sport != u.rport) {
					continue // connected sockets ignore other senders
				}
				if is6 {
					total, from = n, &net.UDPAddr{IP: append(net.IP(nil), src[:]...), Port: int(sport)}
				} else {
					total, from = n, udpAddr([4]byte(src[:4]), sport)
				}
				return true, nil
			}
		})
	return total, from, err
}

func (u *udpSock) WriteTo(p []byte, addr net.Addr) (int, error) {
	if u.connected {
		// A connected UDP socket may only write to its peer.
		return 0, net.ErrWriteToConnected
	}
	ua, isUDP := addr.(*net.UDPAddr)
	if !isUDP || ua == nil || ua.Port <= 0 || ua.Port > 65535 {
		// Require *net.UDPAddr explicitly; generic extraction also accepts TCP addresses.
		return 0, errors.New("leannet: WriteTo needs a *net.UDPAddr with a valid port")
	}
	if u.v6 {
		// The families never mix on one socket: a v6 socket writes v6 only,
		// exactly like a kernel socket bound with IPV6_V6ONLY.
		if ua.IP.To4() != nil || len(ua.IP.To16()) != net.IPv6len {
			return 0, errors.New("leannet: WriteTo on a v6 socket needs an IPv6 *net.UDPAddr")
		}
		dst := [16]byte(ua.IP.To16())
		return u.writeUDP6(p, dst, uint16(ua.Port))
	}
	dst, dport, ok := addrPort(addr)
	if !ok {
		return 0, errors.New("leannet: WriteTo needs an IPv4 *net.UDPAddr")
	}
	return u.writeUDP(p, dst, dport)
}

// writeUDP sends one datagram, waiting by deadline for unresolved ARP routes.
func (u *udpSock) writeUDP(p []byte, dst [4]byte, dport uint16) (int, error) {
	if err := u.s.closedFirst(func() bool { return u.port.closed }); err != nil {
		return 0, err
	}
	// Only the link-local block is sendable multicast: wider groups could be
	// forwarded beyond the LAN by a multicast router (RFC 2365), and nothing
	// here needs them. Explicit refusal beats an ARP timeout.
	if isMulticastIP(dst) && !isLinkLocalMulticast(dst) {
		return 0, errNotLinkLocalMulticast
	}
	if len(p) > MTU-sizeIPv4-sizeUDP {
		return 0, errors.New("leannet: udp datagram exceeds mtu")
	}
	s := u.s
	var sent int
	err := s.await(nil, func() time.Time { return u.wrDeadline },
		func() (bool, error) {
			if u.port.closed {
				return false, net.ErrClosed
			}
			now := s.now()
			if mac, ok := s.routeLocked(dst, now, true); ok {
				off := EthernetHeaderSize + sizeIPv4
				copy(s.txBuf[off+sizeUDP:], p)
				n, err := putUDP(s.txBuf[off:], u.lport, dport, s.cfg.IP, dst, len(p), !s.trusted(dst))
				if err != nil {
					return false, err
				}
				PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoUDP, s.cfg.IP, dst, n)
				if err := s.sendEthLocked(mac, EtherTypeIPv4, sizeIPv4+n); err != nil {
					// UDP cannot recover a rejected transmit through retransmission.
					return false, err
				}
				sent = len(p)
				return true, nil
			}
			hop, viaARP := s.nextHopLocked(dst)
			if viaARP && hop == ([4]byte{}) {
				// No gateway is an immediate answer, not a reason to wait.
				return false, errNoRoute
			}
			if viaARP && s.arp.noAnswer(hop, now) {
				return false, errUnreachable
			}
			s.notify() // pump the ARP query
			return false, nil
		})
	return sent, err
}

// Read and Write implement the connected net.Conn side.
func (u *udpSock) Read(p []byte) (int, error) {
	n, _, err := u.ReadFrom(p)
	return n, err
}
func (u *udpSock) Write(p []byte) (int, error) {
	if !u.connected {
		return 0, errors.New("leannet: Write on unconnected udp socket")
	}
	if u.v6 {
		return u.writeUDP6(p, u.raddr, u.rport)
	}
	return u.writeUDP(p, [4]byte(u.raddr[:4]), u.rport)
}

func (u *udpSock) Close() error {
	s := u.s
	s.mu.Lock()
	defer s.mu.Unlock()
	u.port.close() // idempotent; port.closed is authoritative
	s.notify()
	return nil
}

func (u *udpSock) LocalAddr() net.Addr {
	if u.v6 {
		// The socket is wildcard-bound. Source selection happens for each
		// destination in writeUDP6; reporting one owned address here would
		// falsely promise that the caller selected it as the bind identity.
		return &net.UDPAddr{IP: append(net.IP(nil), net.IPv6zero...), Port: int(u.lport)}
	}
	return udpAddr(u.s.cfg.IP, u.lport)
}
func (u *udpSock) RemoteAddr() net.Addr {
	if !u.connected {
		return nil
	}
	if u.v6 {
		return &net.UDPAddr{IP: append(net.IP(nil), u.raddr[:]...), Port: int(u.rport)}
	}
	return udpAddr([4]byte(u.raddr[:4]), u.rport)
}

// UDP uses the same deadline wake rule as TCP; see storeDeadline.
func (u *udpSock) SetDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.rdDeadline, &u.wrDeadline)
}
func (u *udpSock) SetReadDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.rdDeadline, nil)
}
func (u *udpSock) SetWriteDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.wrDeadline, nil)
}

// ---- SocketFunc boundary ----

// Socket implements TamaGo's net.SocketFunc contract: a local address without
// a remote creates a listener; otherwise it returns Conn or PacketConn. Failed
// dials return (nil, err), never a substitute value.
func (s *Stack) Socket(ctx context.Context, network string, family, sotype int, laddr, raddr net.Addr) (interface{}, error) {
	if family == afINET6 {
		// The v6 lane (ipv6.go) is UDP-only and opt-in by use: the app that
		// opens a udp6 socket (Matter) is the switch. TCP over v6 stays
		// unsupported — nothing on a HopOS node needs it.
		return s.socket6(ctx, network, sotype, laddr, raddr)
	}
	if family != afINET {
		return nil, errors.New("leannet: unsupported address family")
	}
	lip, lport, hasL := addrPort(laddr)
	if laddr != nil && (!hasL || !portInRange(laddr)) {
		// Reject unusable non-nil local addresses instead of silently using wildcard.
		return nil, errors.New("leannet: unsupported local address")
	}
	if lip != ([4]byte{}) && lip != s.cfg.IP {
		// This stack owns one address and must not ignore a different binding.
		return nil, errors.New("leannet: local address is not this stack's address")
	}
	rip, rport, hasR := addrPort(raddr)
	if raddr != nil && (!hasR || rport == 0 || !portInRange(raddr)) {
		// An invalid remote must fail the dial, not silently create a listener.
		return nil, errors.New("leannet: unsupported remote address")
	}
	isDial := hasR
	if isDial && lport != 0 {
		// The stack always chooses an ephemeral dial source port; reject a fixed
		// request rather than silently ignoring it.
		return nil, errors.New("leannet: dialing from a fixed local port is not supported")
	}

	switch network {
	case "tcp", "tcp4":
		if sotype != sockSTREAM {
			return nil, errors.New("leannet: tcp requires SOCK_STREAM")
		}
		if isDial {
			var deadline time.Time
			if d, ok := ctx.Deadline(); ok {
				deadline = d
			}
			return s.dialTCP(ctx, rip, rport, deadline)
		}
		return s.Listen(lport)
	case "udp", "udp4":
		if sotype != sockDGRAM {
			return nil, errors.New("leannet: udp requires SOCK_DGRAM")
		}
		if isDial {
			return s.DialUDP(rip, rport)
		}
		return s.ListenUDP(lport)
	}
	return nil, errors.New("leannet: unsupported network " + network)
}

// socket6 is the AF_INET6 half of the SocketFunc boundary: UDP only.
func (s *Stack) socket6(ctx context.Context, network string, sotype int, laddr, raddr net.Addr) (interface{}, error) {
	_ = ctx
	switch network {
	case "udp", "udp6":
	case "tcp", "tcp6":
		return nil, errors.ErrUnsupported
	default:
		return nil, errors.New("leannet: unsupported network " + network)
	}
	if sotype != sockDGRAM {
		return nil, errors.New("leannet: udp requires SOCK_DGRAM")
	}
	lip, lport, okL := addrPort6(laddr)
	if laddr != nil && !okL {
		return nil, errors.New("leannet: unsupported local address")
	}
	if !isZero6(lip) {
		// The v6 lane deliberately exposes wildcard binds only. It chooses its
		// link-local or SLAAC source per destination when writing.
		return nil, errors.New("leannet: IPv6 local address must be wildcard")
	}
	rip, rport, okR := addrPort6(raddr)
	if raddr != nil && (!okR || rport == 0) {
		return nil, errors.New("leannet: unsupported remote address")
	}
	if raddr != nil {
		if lport != 0 {
			return nil, errors.New("leannet: dialing from a fixed local port is not supported")
		}
		u, err := s.DialUDP6(rip, rport)
		if err != nil {
			return nil, err // avoid a typed nil inside the interface result
		}
		return u, nil
	}
	return s.ListenUDP6(lport)
}

// addrPort6 extracts a v6 address and port; a v4 or v4-mapped address is not ok.
func addrPort6(a net.Addr) (ip [16]byte, port uint16, ok bool) {
	var nip net.IP
	var p int
	switch t := a.(type) {
	case *net.UDPAddr:
		if t == nil {
			return ip, 0, false
		}
		nip, p = t.IP, t.Port
	case *net.TCPAddr:
		if t == nil {
			return ip, 0, false
		}
		nip, p = t.IP, t.Port
	default:
		return ip, 0, false
	}
	if p < 0 || p > 65535 {
		return ip, 0, false
	}
	if len(nip) == 0 {
		return ip, uint16(p), true // wildcard (::)
	}
	if nip.To4() != nil {
		return ip, 0, false
	}
	b := nip.To16()
	if b == nil {
		return ip, 0, false
	}
	return [16]byte(b), uint16(p), true
}
