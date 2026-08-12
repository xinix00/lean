package leannet

// socket.go — de rand naar Go's net-pakket: net.Conn, net.Listener en
// net.PacketConn over de stack, toewijsbaar aan tamago's net.SocketFunc.
// De contract-eisen (naad-rapport): fouten zijn fouten en nooit een waarde
// (BEVINDINGEN #4), deadlines zijn echt en overal (deadline-gedreven, nooit
// iteration-capped), ReadFrom levert *net.UDPAddr, en Accept levert een
// net.Conn met werkende adressen.
//
// Blokkeer-patroon: conditie toetsen onder s.mu, zo niet dan het wake-kanaal
// pakken, loslaten, en selecten op wake/deadline. Geen polling, geen slaap.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// Socket-familie/type-constanten (gelijk aan syscall op alle targets).
const (
	afINET     = 2
	afINET6    = 10
	sockSTREAM = 1
	sockDGRAM  = 2
)

const (
	// dialTimeoutDefault begrenst een dial zonder context-deadline: een SYN
	// naar een zwijgende host mag niet eeuwig blijven backoffen.
	dialTimeoutDefault = 30 * time.Second

	// udpQueueCap is de wachtrij per UDP-socket (bytes, uit de pot): ruim voor
	// DNS/SNTP, genoeg voor een QUIC-transport.
	udpQueueCap = 32 << 10

	// tcpBacklog is hoeveel voltooide handshakes een listener maximaal laat
	// wachten op Accept. Vol = luide RST, geen stil vastgehouden slot — de
	// les van de console-dood van 11-08.
	tcpBacklog = 8
)

// waitTimeout wacht op verandering (ch dicht) of deadline. Nul-deadline =
// eeuwig geduld. Geeft os.ErrDeadlineExceeded terug (een echte net.Error met
// Timeout() == true).
func waitTimeout(ch <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		<-ch
		return nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		return os.ErrDeadlineExceeded
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return nil
	case <-t.C:
		return os.ErrDeadlineExceeded
	}
}

func tcpAddr(ip [4]byte, port uint16) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(ip[:]).To16(), Port: int(port)}
}
func udpAddr(ip [4]byte, port uint16) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(ip[:]).To16(), Port: int(port)}
}

// addrPort haalt (ip, poort) uit een net.Addr. ok=false voor nil of niet-IPv4.
func addrPort(a net.Addr) (ip [4]byte, port uint16, ok bool) {
	var nip net.IP
	var p int
	switch v := a.(type) {
	case *net.TCPAddr:
		if v == nil {
			return ip, 0, false
		}
		nip, p = v.IP, v.Port
	case *net.UDPAddr:
		if v == nil {
			return ip, 0, false
		}
		nip, p = v.IP, v.Port
	default:
		return ip, 0, false
	}
	if v4 := nip.To4(); v4 != nil {
		copy(ip[:], v4)
	} else if len(nip) != 0 {
		return ip, 0, false // echt IPv6-adres: niet de onze
	}
	return ip, uint16(p), true
}

// ---- TCP listener ----

// tcpListener implementeert net.Listener.
type tcpListener struct {
	s       *Stack
	port    uint16
	backlog chan *sconn
	done    chan struct{}
	closed  bool
}

// Listen opent een TCP-listener; port 0 kiest een efemere poort. Een listener
// kost niets uit de pot — pas een verbinding kost (floor, dan groei).
func (s *Stack) Listen(port uint16) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStackClosed
	}
	if port == 0 {
		p, err := s.ephemeralPort()
		if err != nil {
			return nil, err
		}
		port = p
	} else if s.portInUse(port) {
		return nil, errors.New("leannet: tcp port in use")
	}
	l := &tcpListener{s: s, port: port,
		backlog: make(chan *sconn, tcpBacklog), done: make(chan struct{})}
	s.listeners[port] = l
	return l, nil
}

// offer geeft een voltooide handshake aan Accept. Backlog vol = luid weigeren
// (RST + teller): een trage accepter mag geen stille slot-verzameling kweken.
// Aangeroepen onder s.mu.
func (l *tcpListener) offer(c *sconn) {
	select {
	case l.backlog <- c:
	default:
		c.tcp.abort()
		l.s.reap(c.key, c)
	}
}

func (l *tcpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.backlog:
		return &tcpSock{s: l.s, c: c}, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *tcpListener) Close() error {
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	delete(l.s.listeners, l.port)
	close(l.done)
	// Wachtende, nog niet geaccepteerde verbindingen netjes weg.
	for {
		select {
		case c := <-l.backlog:
			c.tcp.abort()
			l.s.reap(c.key, c)
		default:
			l.s.notify()
			return nil
		}
	}
}

func (l *tcpListener) Addr() net.Addr { return tcpAddr(l.s.cfg.IP, l.port) }

// ---- TCP conn ----

// tcpSock implementeert net.Conn over een stack-verbinding.
type tcpSock struct {
	s *Stack
	c *sconn

	rdDeadline time.Time
	wrDeadline time.Time
}

// DialTCP opent actief een verbinding en wacht deadline-gedreven op de
// uitkomst: verbonden, geweigerd (RST), onbereikbaar (ARP gaf luid op) of
// deadline.
func (s *Stack) DialTCP(raddr [4]byte, rport uint16, deadline time.Time) (net.Conn, error) {
	if deadline.IsZero() {
		deadline = time.Now().Add(dialTimeoutDefault)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errStackClosed
	}
	lport, err := s.ephemeralPort()
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
	c.tcp.openActive(s.nextISS(), uint16(MTU-40), s.cfg.AdvWS)
	// De volgende hop bepaalt wiens ARP-lot deze dial deelt.
	hop := raddr
	if !sameSubnet(raddr, s.cfg.IP, s.cfg.Prefix) && !s.hasGwMAC {
		hop = s.cfg.GW
	}
	s.notify() // pomp: SYN eruit (en zo nodig eerst de ARP-query)

	for {
		switch {
		case c.tcp.state == tcpEstablished:
			s.mu.Unlock()
			return &tcpSock{s: s, c: c}, nil
		case c.tcp.state == tcpClosed:
			refused := c.tcp.refused
			s.reap(key, c)
			s.mu.Unlock()
			if refused {
				return nil, errors.New("leannet: connection refused")
			}
			// Geen RST maar ook geen antwoord: de handshake gaf op na zijn
			// backoff-ladder (~6s).
			return nil, errors.New("leannet: connect timed out, no response")
		case s.arp.noAnswer(hop, s.now()):
			c.tcp.abort()
			s.reap(key, c)
			s.mu.Unlock()
			return nil, errUnreachable
		}
		ch := s.wake
		s.mu.Unlock()
		if err := waitTimeout(ch, deadline); err != nil {
			s.mu.Lock()
			c.tcp.abort()
			s.reap(key, c)
			s.mu.Unlock()
			return nil, err
		}
		s.mu.Lock()
	}
}

func (t *tcpSock) Read(p []byte) (int, error) {
	s := t.s
	s.mu.Lock()
	for {
		n, err := t.c.tcp.read(p)
		if n > 0 {
			// Het venster kan geopend zijn: de pomp mag de update versturen.
			s.notify()
			s.mu.Unlock()
			return n, nil
		}
		if err != nil {
			s.mu.Unlock()
			if err == errTCPClosed {
				return 0, io.EOF
			}
			return 0, err
		}
		ch, dl := s.wake, t.rdDeadline
		s.mu.Unlock()
		if werr := waitTimeout(ch, dl); werr != nil {
			return 0, werr
		}
		s.mu.Lock()
	}
}

func (t *tcpSock) Write(p []byte) (int, error) {
	s := t.s
	total := 0
	s.mu.Lock()
	for total < len(p) {
		n, err := t.c.tcp.write(p[total:])
		total += n
		if err != nil {
			s.mu.Unlock()
			if total > 0 {
				return total, err
			}
			return 0, err
		}
		if n > 0 {
			s.notify() // de pomp mag gaan zenden
			continue
		}
		// Ring vol en niet verder gegroeid: wachten tot ACKs ruimte maken.
		ch, dl := s.wake, t.wrDeadline
		s.mu.Unlock()
		if werr := waitTimeout(ch, dl); werr != nil {
			return total, werr
		}
		s.mu.Lock()
	}
	s.mu.Unlock()
	return total, nil
}

func (t *tcpSock) Close() error {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = t.c.tcp.close() // dubbel sluiten is geen fout op de socket-rand
	s.notify()          // de FIN mag eruit
	return nil
}

func (t *tcpSock) LocalAddr() net.Addr  { return tcpAddr(t.s.cfg.IP, t.c.key.lport) }
func (t *tcpSock) RemoteAddr() net.Addr { return tcpAddr(t.c.key.rip, t.c.key.rport) }

func (t *tcpSock) SetDeadline(tm time.Time) error {
	t.s.mu.Lock()
	t.rdDeadline, t.wrDeadline = tm, tm
	t.s.mu.Unlock()
	return nil
}
func (t *tcpSock) SetReadDeadline(tm time.Time) error {
	t.s.mu.Lock()
	t.rdDeadline = tm
	t.s.mu.Unlock()
	return nil
}
func (t *tcpSock) SetWriteDeadline(tm time.Time) error {
	t.s.mu.Lock()
	t.wrDeadline = tm
	t.s.mu.Unlock()
	return nil
}

// ---- UDP ----

// udpSock implementeert net.PacketConn, en als hij connected is ook net.Conn.
type udpSock struct {
	s     *Stack
	port  *udpPort
	lport uint16

	connected bool
	raddr     [4]byte
	rport     uint16

	rdDeadline time.Time
	wrDeadline time.Time
	closed     bool
}

// ListenUDP bindt een UDP-poort (0 = efemeer) met een wachtrij uit de pot.
func (s *Stack) ListenUDP(port uint16) (*udpSock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errStackClosed
	}
	if port == 0 {
		p, err := s.ephemeralPort()
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

// DialUDP is ListenUDP op een efemere poort plus een vast doel: Write/Read
// in plaats van WriteTo/ReadFrom, en vreemde afzenders worden gefilterd.
func (s *Stack) DialUDP(raddr [4]byte, rport uint16) (*udpSock, error) {
	u, err := s.ListenUDP(0)
	if err != nil {
		return nil, err
	}
	u.connected, u.raddr, u.rport = true, raddr, rport
	return u, nil
}

func (u *udpSock) ReadFrom(p []byte) (int, net.Addr, error) {
	s := u.s
	s.mu.Lock()
	for {
		if u.closed {
			s.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		n, src, sport, ok := u.port.recvFrom(p)
		if ok {
			if u.connected && (src != u.raddr || sport != u.rport) {
				continue // niet onze peer: stil verder (connected-semantiek)
			}
			s.mu.Unlock()
			return n, udpAddr(src, sport), nil
		}
		ch, dl := s.wake, u.rdDeadline
		s.mu.Unlock()
		if werr := waitTimeout(ch, dl); werr != nil {
			return 0, nil, werr
		}
		s.mu.Lock()
	}
}

func (u *udpSock) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst, dport, ok := addrPort(addr)
	if !ok {
		return 0, errors.New("leannet: WriteTo needs an IPv4 *net.UDPAddr")
	}
	return u.writeUDP(p, dst, dport)
}

// writeUDP bouwt en verstuurt één datagram; op een onopgeloste route wacht
// hij deadline-gedreven op ARP (het eerste DNS-pakket van een verse node).
func (u *udpSock) writeUDP(p []byte, dst [4]byte, dport uint16) (int, error) {
	if len(p) > MTU-sizeIPv4-sizeUDP {
		return 0, errors.New("leannet: udp datagram exceeds mtu")
	}
	s := u.s
	s.mu.Lock()
	for {
		if u.closed {
			s.mu.Unlock()
			return 0, net.ErrClosed
		}
		now := s.now()
		if mac, ok := s.routeLocked(dst, now); ok {
			off := EthernetHeaderSize + sizeIPv4
			copy(s.txBuf[off+sizeUDP:], p)
			n, err := PutUDP(s.txBuf[off:], u.lport, dport, s.cfg.IP, dst, len(p))
			if err != nil {
				s.mu.Unlock()
				return 0, err
			}
			PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoUDP, s.cfg.IP, dst, n)
			s.sendEthLocked(mac, EtherTypeIPv4, sizeIPv4+n)
			s.mu.Unlock()
			return len(p), nil
		}
		hop := dst
		if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) {
			hop = s.cfg.GW
		}
		if s.arp.noAnswer(hop, now) {
			s.mu.Unlock()
			return 0, errUnreachable
		}
		s.notify() // pomp: ARP-query eruit
		ch, dl := s.wake, u.wrDeadline
		s.mu.Unlock()
		if werr := waitTimeout(ch, dl); werr != nil {
			return 0, werr
		}
		s.mu.Lock()
	}
}

// Read/Write: de connected helft (net.Conn).
func (u *udpSock) Read(p []byte) (int, error) {
	n, _, err := u.ReadFrom(p)
	return n, err
}
func (u *udpSock) Write(p []byte) (int, error) {
	if !u.connected {
		return 0, errors.New("leannet: Write on unconnected udp socket")
	}
	return u.writeUDP(p, u.raddr, u.rport)
}

func (u *udpSock) Close() error {
	s := u.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if !u.closed {
		u.closed = true
		u.port.close()
		s.notify()
	}
	return nil
}

func (u *udpSock) LocalAddr() net.Addr { return udpAddr(u.s.cfg.IP, u.lport) }
func (u *udpSock) RemoteAddr() net.Addr {
	if !u.connected {
		return nil
	}
	return udpAddr(u.raddr, u.rport)
}

func (u *udpSock) SetDeadline(t time.Time) error {
	u.s.mu.Lock()
	u.rdDeadline, u.wrDeadline = t, t
	u.s.mu.Unlock()
	return nil
}
func (u *udpSock) SetReadDeadline(t time.Time) error {
	u.s.mu.Lock()
	u.rdDeadline = t
	u.s.mu.Unlock()
	return nil
}
func (u *udpSock) SetWriteDeadline(t time.Time) error {
	u.s.mu.Lock()
	u.wrDeadline = t
	u.s.mu.Unlock()
	return nil
}

// ---- de SocketFunc-rand ----

// Socket is toewijsbaar aan tamago's net.SocketFunc. De vorm-eisen staan in
// net_tamago.go: Listener bij laddr-zonder-raddr, anders Conn/PacketConn.
// Fouten komen terug als fouten — een dial die faalt levert (nil, err), nooit
// een waarde die geen verbinding is (BEVINDINGEN #4).
func (s *Stack) Socket(ctx context.Context, network string, family, sotype int, laddr, raddr net.Addr) (interface{}, error) {
	if family == afINET6 {
		return nil, errors.ErrUnsupported
	}
	if family != afINET {
		return nil, errors.New("leannet: unsupported address family")
	}
	lip, lport, _ := addrPort(laddr)
	_ = lip // we luisteren altijd op ons ene adres
	rip, rport, hasR := addrPort(raddr)
	isDial := hasR && rport != 0

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
			return s.DialTCP(rip, rport, deadline)
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
