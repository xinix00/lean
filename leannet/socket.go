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
	"net/netip"
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

// waitCtx wacht op een wek (ch), een deadline, of een annuleerbare context —
// een dial die via net.DialContext loopt hoort op ctx.Done() terug te keren,
// niet pas op zijn deadline (review 13-08). ctx mag nil zijn (contextloze
// paden) — en dat pad is de hete lus van élke geblokkeerde Read/Write, dus het
// slaat de select-machinerie over waar een kale ontvangst volstaat.
//
// De fout komt uit ctx.Err() zodra de context erbij betrokken is: rond een
// context-DEADLINE racen de eigen timer en ctx.Done(), en wie won bepaalde of
// de aanroeper os.ErrDeadlineExceeded of context.Canceled zag — terwijl
// context.DeadlineExceeded het verwachte antwoord is (review 13-08, negende
// ronde). Daarom wint ctx.Err() ook als de éigen timer als eerste vuurde.
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

// deadlineErr kiest de fout bij een verstreken termijn. Draagt de context een
// deadline die niet ná de onze ligt, dan ís onze verstreken timer de zijne —
// context.DeadlineExceeded dus, ook als zijn eigen klok een haar achterloopt
// (de twee timers vuren nooit exact gelijk; wie won bepaalde anders de fout —
// review 13-08, negende ronde).
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

// await draait cond onder s.mu tot hij klaar is (finished, of een fout).
// dl wordt per ronde ónder de lock herlezen — dat is het Set*Deadline-contract:
// een nieuwe deadline geldt ook voor I/O die al staat te wachten. ctx mag nil
// zijn (contextloze paden). Dit is hét blokkeer-patroon van dit bestand; het stond vijf keer
// uitgeschreven, en dan zijn er vijf plekken waar de wake/deadline-dans fout
// kan (review 13-08, zesde ronde).
// closedFirst laat een al-gesloten socket vóór de deadline-toets falen: het
// net.Conn-contract geeft "use of closed connection" voorrang op een
// verstreken termijn, en de deadline-eerst-regel in await zou hem anders
// maskeren (review 13-08, achtentwintigste ronde).
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
		// De deadline wint van gereed I/O: een net.Conn met een verstreken
		// termijn hoort ÉLKE operatie meteen te weigeren, ook als er al data
		// klaarstaat — anders consumeerde een Read na de deadline vrolijk de
		// wachtrij leeg (review 13-08, achtentwintigste ronde).
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
			// Een verstreken timer is pas een deadline-fout als de ÁCTUELE
			// deadline ook verstreken is: Set*Deadline wekt bewust niet bij
			// verruimen of wissen (de notify-storm), dus een verlengde of
			// gewiste termijn wordt hiér herkeurd — anders liep een Read af op
			// een deadline die allang niet meer bestond (review 13-08,
			// zevende ronde).
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

// addrPort haalt (ip, poort) uit een net.Addr. ok=false voor nil of niet-IPv4.
func addrPort(a net.Addr) (ip [4]byte, port uint16, ok bool) {
	// *net.TCPAddr en *net.UDPAddr dragen beide AddrPort(): één uitpak-pad
	// (review 13-08, achttiende ronde). De nil-wachten blijven expliciet —
	// een getypte nil als laddr is een geldige net.Addr, en een lege
	// &TCPAddr{} (bind op alles) hoort juist wél te slagen.
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
		return ip, 0, false // echt IPv6-adres: niet de onze
	}
	return ip, ap.Port(), true
}

// portInRange toetst de RUWE poort van een adres: *net.TCPAddr/*net.UDPAddr
// dragen hem als int, en -1 of 65536 vermomde zich via de uint16-conversie
// als geldige poort — waarna de dial stil een listener werd (review 13-08,
// achtentwintigste ronde).
func portInRange(a net.Addr) bool {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.Port >= 0 && v.Port <= 65535
	case *net.UDPAddr:
		return v.Port >= 0 && v.Port <= 65535
	}
	return false
}

// (netip.AddrPort draagt de poort al als uint16, dus een negatieve of te
// grote poort uit een *net.TCPAddr is dáár al verminkt — de wacht daarop zit
// hieronder in Socket: een remote zónder bruikbare poort is een fout, geen
// listener.)

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

// offer geeft een voltooide handshake aan Accept. Backlog vol = luid weigeren
// (RST + teller): een trage accepter mag geen stille slot-verzameling kweken.
// Aangeroepen onder s.mu.
func (l *tcpListener) offer(c *sconn) {
	// Een dichte listener neemt niets meer aan: een handshake die net ná Close
	// voltooit zou anders in een backlog belanden die niemand ooit nog leest —
	// een gevestigde verbinding plus floor-budget, voorgoed (review 13-08).
	if l.closed {
		c.tcp.abort()
		l.s.reap(c.key, c)
		return
	}
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
	l.closeLocked()
	return nil
}

// closeLocked is de ene definitie van "een listener gaat dicht"; Stack.Close
// gebruikt hem ook (die had er een eigen, half afwijkende kopie van — review
// 13-08, vijfde ronde). Aanroepen onder s.mu; idempotent, en abort/reap zijn
// no-ops op verbindingen die al gereapt zijn.
func (l *tcpListener) closeLocked() {
	if l.closed {
		return
	}
	l.closed = true
	delete(l.s.listeners, l.port)
	close(l.done)
	// Wachtende, nog niet geaccepteerde verbindingen netjes weg — óók hun
	// referenties in het kanaal, want Accept select't over backlog én done en
	// kon anders willekeurig een dode verbinding teruggeven.
	for {
		select {
		case c := <-l.backlog:
			c.tcp.abort()
			l.s.reap(c.key, c)
		default:
			// En de embryo's die nog midden in hun handshake zitten: die wijzen
			// naar déze listener en zouden hun handshake-backoff (~6s) uitzitten
			// op een deur die al dicht is — of erger, hem voltooien en dan in
			// offer stranden. Nu meteen weg, mét hun budget (review 13-08).
			for key, c := range l.s.conns {
				if c.listener == l && !c.accepted {
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

// tcpSock implementeert net.Conn over een stack-verbinding.
type tcpSock struct {
	s *Stack
	c *sconn

	rdDeadline time.Time
	wrDeadline time.Time

	// closed: de gebruiker heeft Close geroepen. Vanaf dan faalt élke I/O op
	// deze socket met net.ErrClosed — óók een Read die al stond te wachten
	// (het net.Conn-contract: "Close unblocks blocked I/O", review 13-08).
	// De TCP-machine sluit intussen netjes af (FIN); dit is de socket-rand.
	closed bool
}

// DialTCP opent actief een verbinding en wacht deadline-gedreven op de
// uitkomst: verbonden, geweigerd (RST), onbereikbaar (ARP gaf luid op) of
// deadline.
func (s *Stack) DialTCP(raddr [4]byte, rport uint16, deadline time.Time) (net.Conn, error) {
	return s.dialTCP(nil, raddr, rport, deadline)
}

// dialTCP is DialTCP met een annuleerbare context (nil = geen); de
// SocketFunc-rand geeft zijn context door zodat net.DialContext echt
// annuleerbaar is — en de fout op een context-deadline stabiel
// context.DeadlineExceeded (zie deadlineErr).
func (s *Stack) dialTCP(ctx context.Context, raddr [4]byte, rport uint16, deadline time.Time) (net.Conn, error) {
	if deadline.IsZero() {
		deadline = time.Now().Add(dialTimeoutDefault)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errStackClosed
	}
	// Route-loze bestemming: meteen zeggen, niet de deadline uitzitten. Zonder
	// gateway (statisch noch geconfigureerd) start routeLocked nooit een query,
	// dus zou arp.noAnswer hieronder nooit waar worden en wachtte een dial naar
	// buiten het subnet zijn volle 30s uit op een fout die bij de eerste blik
	// vaststond (review 13-08).
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
	c.tcp.openActive(s.nextISS(), uint16(MTU-40), s.cfg.AdvWS)
	// hop (hierboven) bepaalt wiens ARP-lot deze dial deelt.
	s.notify() // pomp: SYN eruit (en zo nodig eerst de ARP-query)

	s.mu.Unlock()

	err = s.await(ctx, func() time.Time { return deadline },
		func() (bool, error) {
			switch {
			case s.closed:
				return false, errStackClosed
			case c.tcp.state == tcpEstablished || c.tcp.state == tcpCloseWait:
				// CLOSE-WAIT telt ook: een peer die accepteert, data stuurt
				// en meteen sluit kan vóór deze waiter wakker werd al door
				// ESTABLISHED heen zijn — de verbinding is dan gewoon
				// bruikbaar (lezen tot EOF, schrijven mag nog)
				// (review 13-08, zevenentwintigste ronde).
				return true, nil
			case hopViaARP && s.arp.noAnswer(hop, s.now()):
				// Alleen als de route een ARP-lot HEEFT: met een statische
				// gateway-MAC is hop een vulwaarde zonder eigen query, en de
				// vol-tabel-toets in noAnswer verklaarde die bestemming
				// anders meteen onbereikbaar terwijl de SYN gewoon via de
				// bekende MAC vertrekt (review 13-08, zesendertigste ronde).
				// VÓÓR de closed-toets: het route-dood-vangnet in de pomp kan
				// deze verbinding al geabort hebben (zelfde noAnswer, andere
				// goroutine), en dan las de closed-tak "connect timed out"
				// waar "no route" hoort — het soort verkeerd-wijzende fout dat
				// op 12-08 vijf lagen zoeken kostte. De arpFailed-status leeft
				// nog arpFailTTL, dus hij is hier nog te lezen (review 13-08,
				// vijfde ronde).
				return false, errUnreachable
			case c.tcp.state == tcpClosed:
				if c.tcp.refused {
					return false, errors.New("leannet: connection refused")
				}
				// Geen RST maar ook geen antwoord: de handshake gaf op na
				// zijn backoff-ladder (~6s).
				return false, errors.New("leannet: connect timed out, no response")
			}
			return false, nil
		})
	if err != nil {
		// Hét opruimpad, voor élke fout: uit de switch én uit het wachten
		// (deadline/cancel). De takken hierboven ruimen bewust níets zelf op —
		// dat deden ze eerst wel, en dan stond exact dezelfde abort+reap hier
		// nóg eens (review 13-08, achtste ronde). Idempotent voor het geval de
		// pomp of Stack.Close ons voor was.
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
		// net.Conn-contract: een lege read is meteen klaar. Zonder deze regel
		// kwam hij in await terecht (tcp.read geeft (0, nil)) en wachtte een
		// levende verbinding op verkeer dat er niet hoeft te komen
		// (review 13-08, dertiende ronde).
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
				t.s.notify() // het venster kan geopend zijn: de pomp mag de update versturen
				return true, nil
			}
			if err == errTCPClosed {
				// Een échte FIN: de stroom is compleet. errTCPReset valt hier
				// bewust búiten — een reset is een fout, geen einde.
				return false, io.EOF
			}
			return false, err // err == nil: wachten op data
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
				if err != nil {
					return false, err
				}
				if total == len(p) {
					t.s.notify() // de pomp mag gaan zenden
					return true, nil
				}
				if n == 0 {
					// Ring vol en niet verder gegroeid: wachten op ACK-ruimte.
					return false, nil
				}
				t.s.notify() // deel geplaatst; meteen nog een poging
			}
		})
	return total, err
}

func (t *tcpSock) Close() error {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	t.closed = true       // wachtende Reads/Writes zien dit bij hun wek-ronde
	_ = t.c.tcp.close()   // dubbel sluiten is geen fout op de socket-rand
	t.c.tcp.abandonRead() // VOLLE close: de ontvangkant mag zijn ring kwijt (zie tcp.abandonRead)
	s.notify()            // de FIN mag eruit én de waiters worden wakker
	return nil
}

func (t *tcpSock) LocalAddr() net.Addr  { return tcpAddr(t.s.cfg.IP, t.c.key.lport) }
func (t *tcpSock) RemoteAddr() net.Addr { return tcpAddr(t.c.key.rip, t.c.key.rport) }

// De Set*Deadline's wekken de waiters — maar alleen als een waiter de nieuwe
// deadline kan MISSEN: vervroegd, of van eeuwig (nul) naar eindig. Een láter
// gezette deadline haalt de wachtlus vanzelf (hij wordt wakker op de oude,
// herleest, en wacht door). Het contract blijft heel, en de notify-storm van
// een verzoek dat 4+ deadlines vooruitschuift verdwijnt: élke notify wekt
// ALLE waiters op een GOMAXPROCS=1-target (review 13-08, derde ronde).
func deadlineNeedsWake(old, new time.Time) bool {
	return !new.IsZero() && (old.IsZero() || new.Before(old))
}

// storeDeadline zet één of twee deadline-velden onder s.mu, met de wek-regel
// van deadlineNeedsWake — één definitie voor de zes Set*Deadline's van TCP en
// UDP. b mag nil zijn.
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
}

// ListenUDP bindt een UDP-poort (0 = efemeer) met een wachtrij uit de pot.
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

// DialUDP is ListenUDP op een efemere poort plus een vast doel: Write/Read
// in plaats van WriteTo/ReadFrom, en vreemde afzenders worden gefilterd.
func (s *Stack) DialUDP(raddr [4]byte, rport uint16) (*udpSock, error) {
	u, err := s.ListenUDP(0)
	if err != nil {
		return nil, err
	}
	u.connected, u.raddr, u.rport = true, raddr, rport
	u.s.mu.Lock()
	u.port.connected, u.port.peer, u.port.peerPort = true, raddr, rport
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
					// Dekt de eigen Close én Stack.Close: de wachtrij is terug
					// en er komt nooit meer een datagram — eeuwig wachten is
					// dan het contract breken.
					return false, net.ErrClosed
				}
				n, src, sport, ok := u.port.recvFrom(p)
				if !ok {
					return false, nil // wachten op een datagram
				}
				if u.connected && (src != u.raddr || sport != u.rport) {
					continue // niet onze peer: stil verder (connected-semantiek)
				}
				total, from = n, udpAddr(src, sport)
				return true, nil
			}
		})
	return total, from, err
}

func (u *udpSock) WriteTo(p []byte, addr net.Addr) (int, error) {
	if u.connected {
		// net.UDPConn-contract: een connected socket schrijft alleen naar
		// zijn peer — en replies van een ánder adres worden toch al bij
		// deliver weggegooid, dus dit was hoe dan ook een zwart gat
		// (review 13-08, dertigste ronde).
		return 0, net.ErrWriteToConnected
	}
	ua, isUDP := addr.(*net.UDPAddr)
	if !isUDP || ua == nil || ua.Port <= 0 || ua.Port > 65535 {
		// Strikt een *net.UDPAddr mét bruikbare poort: de generieke addrPort
		// accepteerde zelfs een *net.TCPAddr, en de test daarop was
		// vals-groen op een verlopen write-deadline (review 13-08, dertigste
		// ronde).
		return 0, errors.New("leannet: WriteTo needs an IPv4 *net.UDPAddr with a valid port")
	}
	dst, dport, ok := addrPort(addr)
	if !ok {
		return 0, errors.New("leannet: WriteTo needs an IPv4 *net.UDPAddr")
	}
	return u.writeUDP(p, dst, dport)
}

// writeUDP bouwt en verstuurt één datagram; op een onopgeloste route wacht
// hij deadline-gedreven op ARP (het eerste DNS-pakket van een verse node).
func (u *udpSock) writeUDP(p []byte, dst [4]byte, dport uint16) (int, error) {
	if err := u.s.closedFirst(func() bool { return u.port.closed }); err != nil {
		return 0, err
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
				n, err := PutUDP(s.txBuf[off:], u.lport, dport, s.cfg.IP, dst, len(p))
				if err != nil {
					return false, err
				}
				PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoUDP, s.cfg.IP, dst, n)
				if err := s.sendEthLocked(mac, EtherTypeIPv4, sizeIPv4+n); err != nil {
					// De NIC weigerde het pakket: dat is een fout, geen succes
					// — UDP heeft geen retransmissie die dit later goedmaakt.
					return false, err
				}
				sent = len(p)
				return true, nil
			}
			hop, viaARP := s.nextHopLocked(dst)
			if viaARP && hop == ([4]byte{}) {
				// Zelfde regel als DialTCP: geen gateway is een antwoord,
				// geen wachttijd.
				return false, errNoRoute
			}
			if viaARP && s.arp.noAnswer(hop, now) {
				return false, errUnreachable
			}
			s.notify() // pomp: ARP-query eruit
			return false, nil
		})
	return sent, err
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
	u.port.close() // idempotent; port.closed is de ene waarheid
	s.notify()
	return nil
}

func (u *udpSock) LocalAddr() net.Addr { return udpAddr(u.s.cfg.IP, u.lport) }
func (u *udpSock) RemoteAddr() net.Addr {
	if !u.connected {
		return nil
	}
	return udpAddr(u.raddr, u.rport)
}

// Zelfde wek-regel als bij TCP: één definitie, zie storeDeadline.
func (u *udpSock) SetDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.rdDeadline, &u.wrDeadline)
}
func (u *udpSock) SetReadDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.rdDeadline, nil)
}
func (u *udpSock) SetWriteDeadline(t time.Time) error {
	return u.s.storeDeadline(t, &u.wrDeadline, nil)
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
	lip, lport, hasL := addrPort(laddr)
	if laddr != nil && (!hasL || !portInRange(laddr)) {
		// Zelfde regel als voor het remote-adres: een niet-nil maar
		// onbruikbaar lokaal adres (IPv6, vreemd type, poort buiten bereik)
		// werd stil een wildcard-listener (review 13-08, dertigste ronde).
		return nil, errors.New("leannet: unsupported local address")
	}
	if lip != ([4]byte{}) && lip != s.cfg.IP {
		// We dragen één adres; binden op iets anders is een bedradingsfout,
		// geen wens die stil genegeerd hoort te worden.
		return nil, errors.New("leannet: local address is not this stack's address")
	}
	rip, rport, hasR := addrPort(raddr)
	if raddr != nil && (!hasR || rport == 0 || !portInRange(raddr)) {
		// Een niet-nil maar onbruikbaar remote-adres (IPv6, vreemd type) werd
		// stil een LISTENER — een dial die faalt hoort (nil, err) te geven,
		// nooit iets anders dan gevraagd (review 13-08, vijfentwintigste
		// ronde; zelfde geest als BEVINDINGEN #4).
		return nil, errors.New("leannet: unsupported remote address")
	}
	isDial := hasR
	if isDial && lport != 0 {
		// Een gevraagde bronpoort op een dial werd stil genegeerd (de stack
		// kiest altijd een efemere poort): wie hem zet — een firewall-afspraak,
		// een protocol met vaste bronpoort — hoort te horen dat dat hier niet
		// bestaat (review 13-08, eenendertigste ronde).
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
