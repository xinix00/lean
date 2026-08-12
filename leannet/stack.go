package leannet

// stack.go — de laag die de pure machines (tcp.go, arp.go, udp.go, icmp.go)
// aan een echt device knoopt: ingress-demux, de TX-pomp, routing via ARP en
// de poorttabellen. Dit is de enige laag met goroutine- en lock-kennis; alle
// machines eronder blijven puur.
//
// Threading-model: één stack-mutex over alle machine-staat, één pomp-goroutine
// die uitgaande frames schrijft en timers bewaakt (RTO's, ARP-retries,
// TIME-WAIT). De pomp slaapt exact tot de vroegste deadline of tot een notify;
// er is geen vaste tick, dus een idle stack kost geen CPU — de les van HOP's
// poll-tijd-jacht. Blokkerende socket-calls (socket.go) wachten op dezelfde
// notify met hun eigen deadline: deadline-gedreven, nooit iteration-capped.
//
// De TX-pomp is een stack-plicht: hop-os heeft geen eigen TX-lus (go-net's
// lifetimeGoroutine deed dit stilletjes; zie het naad-rapport in het
// ontwerpdossier).

import (
	"errors"
	"sync"
	"time"
)

// Device is het NIC-contract: exact de twee methodes die élke HopOS-driver al
// spreekt (dwmac, gem, genet, igb, virtionet, locdev, hopswitch.Uplink — en
// leandhcp.NIC heeft dezelfde vorm). Receive geeft (0, nil) als er niets is;
// de stack pollt niet zelf — de eigenaar van de RX-lus (hopnet) voert frames
// via Stack.RecvInboundPacket.
type Device interface {
	Receive(buf []byte) (int, error)
	Transmit(buf []byte) error
}

// Draadconstanten die de buitenwereld nodig heeft voor buffermaten.
const (
	MTU                 = 1500
	EthernetHeaderSize  = 14
	EthernetMaximumSize = 18 // header + FCS-marge; zelfde waarde als go-net
)

// Efemere poorten: sequentieel vanaf 49152 (RFC 6335 dynamic range). Dit
// bereik is per constructie disjunct van hopswitch.MasqEnd — verplaats het
// niet zonder die invariant mee te nemen.
const (
	ephemeralBase = 49152
	ephemeralEnd  = 65535
)

// Buffer-floors per TCP-verbinding: waar de ringen beginnen vóór budgetgroei.
// Ze zijn asymmetrisch, en dat is het enige getal in leannet dat niet uit
// "groeien op druk" volgt maar uit hoe de tegenpartij begint.
//
// ONTVANGEN (16KiB): een zender start met een initial congestion window van 10
// segmenten (RFC 6928) en stuurt die als burst. Adverteren wij minder, dan kan
// hij niet aan die burst beginnen: één segment, wachten op onze ACK, weer één —
// stop-and-wait, waarbij ÓNS venster de rem is in plaats van de link. Dat is
// geen opwarmen dat een verdubbeling later goedmaakt: bij een snelle lezer
// loopt de ring nooit vol, dus komt die verdubbeling er nooit. 10 × 1460 × 2
// afgerond op 16KiB is dus de laagste maat waarop de ontvangkant eerlijk is.
// (Dit is hetzelfde getal dat gVisor als receive-vloer neemt, om dezelfde
// reden — de RTT-schatter erboven hebben we niet nodig, deze vloer wel.)
//
// ZENDEN (4KiB): hier bepaalt de applicatie het tempo, en de ring groeit op de
// druk die zij zelf zet (een Write die niet past terwijl de peer méér venster
// biedt). Klein beginnen kost daar dus niets.
const (
	tcpFloorRx   = 16 << 10
	tcpFloorTx   = 4 << 10
	tcpFloorRing = tcpFloorRx + tcpFloorTx // wat één verbinding minimaal claimt
)

var (
	errNoBudget    = errors.New("leannet: connection refused, buffer budget exhausted")
	errPortsInUse  = errors.New("leannet: no free ephemeral port")
	errUnreachable = errors.New("leannet: no route to host (arp gave up)")
	errStackClosed = errors.New("leannet: stack closed")
)

// Config is de stack-configuratie. Budget is dé knop (doc.go): alle
// verbindingsbuffers samen blijven eronder. De rest is identiteit.
type Config struct {
	IP     [4]byte
	Prefix int // subnet-prefixlengte, voor de routebeslissing en seed-checks
	MAC    [6]byte
	GW     [4]byte // gateway; nul = geen route buiten het subnet

	Budget int // bytes voor álle verbindingsbuffers samen

	// MaxBufPerConn klemt de groei van één verbinding. 0 = Budget/4
	// (ontwerpdossier: één download mag hard, maar niet alles).
	MaxBufPerConn int

	// AdvWS is de window-scale-shift die we aanbieden. 0 is een geldige
	// aanbieding (RFC 7323); de shift begrenst het maximale venster dat
	// MaxBufPerConn ooit kan adverteren.
	AdvWS uint8
}

type connKey struct {
	lport uint16
	rip   [4]byte
	rport uint16
}

// Stack knoopt alles aan elkaar. Eén mutex over alle staat (zie boven).
type Stack struct {
	mu  sync.Mutex
	cfg Config
	dev Device
	arp *arpTable
	pot budget

	conns     map[connKey]*sconn
	listeners map[uint16]*tcpListener
	udp       *udpTable

	// Verbindingsloze uitgaande wachtrijen; de pomp werkt ze af.
	rstOut  []rstPending
	icmpOut []icmpPending

	gwMAC    [6]byte // statisch geplande gateway (SeedNeighbor-equivalent)
	hasGwMAC bool

	// wake is het broadcast-kanaal: dicht = er is iets veranderd. Waiters
	// pakken hem onder de lock en selecten erop naast hun eigen deadline.
	wake   chan struct{}
	closed bool

	t0 time.Time // basis van de monotone klok (nooit de wandklok — BEVINDINGEN #9)

	nextEph uint16
	issSeed uint32

	txBuf []byte

	// Tellers: de stack logt niet zelf; hopnet hangt hier logregels aan.
	CntRefusedNoBudget int
	CntDropShortFrame  int
	CntDropNoPort      int
	CntDropBadFrame    int
}

// NewStack bouwt de stack en start de pomp. issSeed hoort uit een echte
// entropiebron te komen (de aanroeper heeft die; wij eisen hem in plaats van
// stiekem een zwakke te kiezen).
func NewStack(dev Device, cfg Config, issSeed uint32) *Stack {
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

// now is de monotone klok van de hele stack: time.Since overleeft elke
// NTP-stap, in tegenstelling tot UnixNano (BEVINDINGEN #9/#10).
func (s *Stack) now() int64 { return int64(time.Since(s.t0)) }

// notify maakt alle waiters (pomp én sockets) wakker. Aanroepen onder s.mu.
func (s *Stack) notify() {
	close(s.wake)
	s.wake = make(chan struct{})
}

// Close stopt de pomp en kapt alle verbindingen hard af.
func (s *Stack) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, c := range s.conns {
		c.tcp.abort()
	}
	s.notify()
}

// SeedNeighbor plant een statische buur: het deterministische gateway-plan
// van appnet (layout.SlotMAC, nul ARP). Buiten het subnet is een seed
// zinloos — de routelaag stuurt zulk verkeer naar de gateway en raadpleegt
// de tabel nooit — dus weigeren we hem luid (BEVINDINGEN #21).
func (s *Stack) SeedNeighbor(ip [4]byte, mac [6]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == s.cfg.GW {
		s.gwMAC, s.hasGwMAC = mac, true
		return nil
	}
	if !sameSubnet(ip, s.cfg.IP, s.cfg.Prefix) {
		return errors.New("leannet: seed outside subnet would never be consulted")
	}
	s.arp.seed(ip, mac)
	return nil
}

func sameSubnet(a, b [4]byte, prefix int) bool {
	au := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	bu := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	mask := ^uint32(0) << (32 - uint32(prefix))
	return au&mask == bu&mask
}

// ---- ingress ----

// RecvInboundPacket verwerkt één rauw ethernet-frame. Veilig voor rommel: te
// kort, verkeerd geadresseerd of corrupt wordt geteld en gedropt, nooit
// gepanict — dit is de onvertrouwde rand (hopnet draait hem onder recover,
// maar daar hoort niets aan te komen).
func (s *Stack) RecvInboundPacket(frame []byte) error {
	eth, err := ParseEth(frame)
	if err != nil {
		s.mu.Lock()
		s.CntDropShortFrame++
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStackClosed
	}
	now := s.now()

	toUs := [6]byte(eth.Dst()) == s.cfg.MAC
	switch eth.EtherType() {
	case EtherTypeARP:
		f, err := ParseARP(eth.Payload())
		if err != nil {
			s.CntDropBadFrame++
			return nil
		}
		s.arp.recv(f, now)
		s.notify() // een resolve kan nu klaar zijn; ook de pomp wil kijken (reply)
	case EtherTypeIPv4:
		if !toUs {
			return nil // niet voor ons (broadcast-IP doen we niet aan)
		}
		ip, err := ParseIPv4(eth.Payload())
		if err != nil || !ip.ChecksumOK() || ip.Dst() != s.cfg.IP {
			s.CntDropBadFrame++
			return nil
		}
		// Passief buurleren, alleen van unicast aan óns (zie arp.learn).
		if sameSubnet(ip.Src(), s.cfg.IP, s.cfg.Prefix) {
			s.arp.learn(ip.Src(), [6]byte(eth.Src()), now)
		}
		s.recvIPv4(ip, now)
	}
	return nil
}

func (s *Stack) recvIPv4(ip IPv4Frame, now int64) {
	src := ip.Src()
	switch ip.Proto() {
	case ProtoTCP:
		f, err := ParseTCP(ip.Payload())
		if err != nil || !f.ChecksumOK(src, s.cfg.IP) {
			s.CntDropBadFrame++
			return
		}
		s.recvTCP(f, src, now)
	case ProtoUDP:
		f, err := ParseUDP(ip.Payload())
		if err != nil || !f.ChecksumOK(src, s.cfg.IP) {
			s.CntDropBadFrame++
			return
		}
		// Connected UDP deelt gewoon de poorttabel; het filteren op afzender
		// doet de socket-laag (de efemere poort is per dial uniek, dus vreemd
		// verkeer erheen is uitzondering, geen pad).
		if !s.udp.deliver(f.DstPort(), src, f.SrcPort(), f.Payload()) {
			s.CntDropNoPort++
			return
		}
		s.notify()
	case ProtoICMP:
		// Echo-reply bouwen en klaarleggen; de pomp verstuurt hem.
		reply := make([]byte, len(ip.Payload()))
		if n, ok := icmpEcho(ip.Payload(), reply); ok {
			s.icmpOut = append(s.icmpOut, icmpPending{dst: src, pkt: reply[:n]})
			s.notify()
		}
	}
}

// icmpPending is één klaarstaande echo-reply.
type icmpPending struct {
	dst [4]byte
	pkt []byte
}

func (s *Stack) recvTCP(f TCPFrame, src [4]byte, now int64) {
	seg, ok := parseTCPSeg(f)
	if !ok {
		s.CntDropBadFrame++
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
	// Geen verbinding: een SYN voor een listener opent een embryo.
	l, listening := s.listeners[f.DstPort()]
	if !listening || !seg.flags.Has(FlagSYN) || seg.flags.Has(FlagACK) {
		return // geen RST-generatie in v1; de peer time-out
	}
	c, err := s.newConnLocked(key)
	if err != nil {
		// De pot is leeg: luid weigeren met een RST in plaats van stil
		// verhongeren (lean-regel 2). De peer krijgt meteen "nee".
		s.CntRefusedNoBudget++
		s.rstOut = append(s.rstOut, rstPending{
			dst: src, sport: f.DstPort(), dport: f.SrcPort(),
			seq: 0, ack: seg.seq + 1,
		})
		s.notify()
		return
	}
	c.tcp.openPassive(s.nextISS(), uint16(MTU-40), s.cfg.AdvWS)
	c.tcp.recv(seg, now)
	c.listener = l
	s.notify()
}

// maybeAccept geeft een embryo dat zojuist Established werd aan zijn
// listener. Hier en niet in het emit-pad: de handshake voltooit op een RECV
// (de ACK van de peer), en daar hoeft geen enkel uitgaand segment op te
// volgen.
func (s *Stack) maybeAccept(c *sconn) {
	if c.listener != nil && !c.accepted && c.tcp.state == tcpEstablished {
		c.accepted = true
		c.listener.offer(c)
	}
}

// rstPending is een verbindingsloze weigering (refused/no budget).
type rstPending struct {
	dst          [4]byte
	sport, dport uint16
	seq, ack     uint32
}

// reap ruimt een gesloten verbinding op: sleutel weg, buffers terug de pot in.
// Aanroepen onder s.mu na elke recv/emit die de staat kan hebben gesloten.
//
// Staat er nog een RST klaar, dan verhuist die eerst naar de verbindingsloze
// wachtrij. Zonder die stap gaat een abort-dan-reap-in-één-adem stil verloren
// (de pomp loopt over s.conns, en die sleutel is dan al weg) — gemeten met de
// backlog-overflow-test: de geweigerde beller bleef in ESTABLISHED wachten op
// een antwoord dat nooit kwam. Weigeren moet luid, altijd.
func (s *Stack) reap(key connKey, c *sconn) {
	if c.tcp.state != tcpClosed || c.reaped {
		return
	}
	if c.tcp.rstOut {
		c.tcp.rstOut = false
		s.rstOut = append(s.rstOut, rstPending{
			dst: key.rip, sport: key.lport, dport: key.rport,
			seq: c.tcp.nxt, ack: c.tcp.rcvNxt,
		})
		s.notify()
	}
	c.reaped = true
	delete(s.conns, key)
	s.pot.release(c.tcp.rx.size() + c.tcp.tx.size())
}

// newConnLocked maakt een verbinding op de floor-maat, uit de pot.
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

// nextISS geeft een startsequencenummer. Geen kryptografische eis in v1 —
// wel per verbinding vooruit, zodat snelle poort-hergebruik geen oude
// segmenten matcht.
func (s *Stack) nextISS() uint32 {
	s.issSeed += 64007 // priem; loopt de hele ruimte af
	return s.issSeed
}

// ephemeralPort kiest sequentieel een vrije poort ≥ 49152 en slaat bezette
// over; bij een botsing kiest de váller opnieuw in plaats van hard te falen
// (BEVINDINGEN #14).
func (s *Stack) ephemeralPort() (uint16, error) {
	for i := 0; i <= ephemeralEnd-ephemeralBase; i++ {
		p := s.nextEph
		if s.nextEph == ephemeralEnd {
			s.nextEph = ephemeralBase
		} else {
			s.nextEph++
		}
		if s.portInUse(p) {
			continue
		}
		return p, nil
	}
	return 0, errPortsInUse
}

func (s *Stack) portInUse(p uint16) bool {
	if _, ok := s.listeners[p]; ok {
		return true
	}
	for k := range s.conns {
		if k.lport == p {
			return true
		}
	}
	return s.udp.bound(p)
}

// ---- egress: de pomp ----

// pump is de TX-motor: hij slaapt tot de vroegste deadline of een notify,
// en schrijft dan alles wat de machines klaar hebben. Register-volgorde per
// ronde: RST-weigeringen, ICMP, ARP, dan de TCP-verbindingen.
func (s *Stack) pump() {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.drainLocked()
		deadline := s.nextDeadlineLocked()
		ch := s.wake
		s.mu.Unlock()

		if deadline == 0 {
			<-ch
			continue
		}
		wait := time.Duration(deadline - s.now())
		if wait <= 0 {
			// Deadline al verstreken: meteen nog een ronde, maar geef de
			// scheduler lucht (GOMAXPROCS=1 op tamago).
			wait = 50 * time.Microsecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ch:
		case <-t.C:
		}
		t.Stop()
	}
}

// drainLocked schrijft alle klaarstaande frames. De transmit gebeurt onder de
// lock (Device.Transmit is bij alle HopOS-drivers een korte ring-schrijf);
// als dat ooit knelt is een dubbele buffer de uitweg, niet een fijner slot.
func (s *Stack) drainLocked() {
	now := s.now()

	for _, r := range s.rstOut {
		s.sendRSTLocked(r)
	}
	s.rstOut = s.rstOut[:0]

	for _, p := range s.icmpOut {
		if mac, ok := s.routeLocked(p.dst, now); ok {
			s.sendIPv4Locked(mac, p.dst, ProtoICMP, p.pkt)
		}
	}
	s.icmpOut = s.icmpOut[:0]

	// ARP zelf: replies en query-(re)tries.
	for {
		n, ok := s.arp.emit(s.txBuf[EthernetHeaderSize:], now)
		if !ok {
			break
		}
		f, _ := ParseARP(s.txBuf[EthernetHeaderSize : EthernetHeaderSize+n])
		dst := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if f.Op() == ARPReply {
			dst = [6]byte(f.TargetHW())
		}
		s.sendEthLocked(dst, EtherTypeARP, n)
	}

	// TCP: elke verbinding mag zijn klaarstaande segmenten kwijt — mits de
	// route er is. Zonder MAC slaan we de verbinding óver (emit is lui, er
	// wordt geen sequence-staat verspild) en heeft arp.resolve de query al
	// gestart; de reply komt via notify terug.
	for key, c := range s.conns {
		mac, ok := s.routeLocked(key.rip, now)
		if !ok {
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
}

// nextDeadlineLocked geeft de vroegste wektijd van alle machines, of 0 als
// niets een timer heeft lopen (dan slaapt de pomp tot een notify).
func (s *Stack) nextDeadlineLocked() int64 {
	var d int64
	now := s.now()
	add := func(t int64) {
		if t == 0 {
			return
		}
		// Een deadline in het verleden hoort al door drainLocked afgehandeld
		// te zijn; blijft hij staan (verbinding zonder route wordt in drain
		// overgeslagen), dan is 10ms het hertry-tempo — geen microseconde-spin.
		if t <= now {
			t = now + int64(10*time.Millisecond)
		}
		if d == 0 || t < d {
			d = t
		}
	}
	for _, c := range s.conns {
		if c.tcp.timerOn {
			add(c.tcp.deadline)
		}
		if c.tcp.state == tcpTimeWait {
			add(c.tcp.twDeadline)
		}
	}
	for _, e := range s.arp.entries {
		switch e.state {
		case arpPending:
			add(e.due)
		case arpFailed:
			add(e.born + arpFailTTL)
		}
	}
	return d
}

// routeLocked beslist het volgende-hop-MAC: binnen het subnet direct via ARP,
// daarbuiten de gateway (statisch plan of ARP).
func (s *Stack) routeLocked(dst [4]byte, now int64) ([6]byte, bool) {
	if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) {
		if s.hasGwMAC {
			return s.gwMAC, true
		}
		dst = s.cfg.GW
		if dst == ([4]byte{}) {
			return [6]byte{}, false
		}
	}
	return s.arp.resolve(dst, now)
}

// ---- wire-schrijvers (allemaal onder s.mu) ----

func (s *Stack) sendEthLocked(dst [6]byte, etherType uint16, payloadLen int) {
	eth, _ := ParseEth(s.txBuf)
	eth.SetDst(dst)
	eth.SetSrc(s.cfg.MAC)
	eth.SetEtherType(etherType)
	n := EthernetHeaderSize + payloadLen
	if n < 60 {
		// Minimale ethernet-framelengte; padding nul zodat er geen oud
		// bufferafval het net op gaat.
		for i := EthernetHeaderSize + payloadLen; i < 60; i++ {
			s.txBuf[i] = 0
		}
		n = 60
	}
	_ = s.dev.Transmit(s.txBuf[:n])
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
		s.CntDropBadFrame++ // kan alleen bij een interne maatfout; tel hem luid
		return
	}
	PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoTCP, s.cfg.IP, key.rip, n)
	s.sendEthLocked(dstMAC, EtherTypeIPv4, sizeIPv4+n)
}

// sendRSTLocked stuurt een verbindingsloze RST (refused). Route best-effort:
// zonder MAC vervalt hij — de peer merkt het aan zijn timeout.
func (s *Stack) sendRSTLocked(r rstPending) {
	mac, ok := s.routeLocked(r.dst, s.now())
	if !ok {
		return
	}
	off := EthernetHeaderSize + sizeIPv4
	n, _ := PutTCP(s.txBuf[off:], r.sport, r.dport, r.seq, r.ack,
		FlagRST|FlagACK, 0, nil, s.cfg.IP, r.dst, 0)
	PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoTCP, s.cfg.IP, r.dst, n)
	s.sendEthLocked(mac, EtherTypeIPv4, sizeIPv4+n)
}

// ---- TCP-segment ⇄ draad ----

// wireSeg is een emit-resultaat plus zijn draaddetails.
type wireSeg struct {
	seg        tcpSeg
	opts       []byte
	payloadLen int
}

// sconn is een verbinding zoals de stack hem kent: machine + identiteit.
type sconn struct {
	stack    *Stack
	key      connKey
	tcp      tcpConn
	listener *tcpListener // gezet op embryo's; accept haalt hem hier weg
	accepted bool
	reaped   bool

	optsBuf [8]byte
}

// emitWire laat de machine één segment produceren, direct in het tx-frame op
// de plek waar de payload hoort (nul kopieën), en bouwt de SYN-opties erbij.
func (c *sconn) emitWire(txBuf []byte, now int64) (wireSeg, bool) {
	payloadAt := EthernetHeaderSize + sizeIPv4 + sizeTCP
	seg, ok := c.tcp.emit(txBuf[payloadAt:], now)
	if !ok {
		return wireSeg{}, false
	}
	w := wireSeg{seg: seg, payloadLen: len(seg.data)}
	if seg.flags.Has(FlagSYN) {
		// MSS (kind 2) + NOP + WS (kind 3): samen 8 bytes, netjes uitgelijnd.
		// Een SYN draagt bij ons nooit payload, dus de optie-bytes overlappen
		// niets.
		b := c.optsBuf[:0]
		b = append(b, 2, 4, byte(seg.mss>>8), byte(seg.mss))
		if seg.wsOK {
			b = append(b, 1, 3, 3, seg.ws)
		}
		w.opts = b
	}
	return w, true
}

// parseTCPSeg vertaalt een gevalideerd TCP-frame naar het machine-segment,
// inclusief de SYN-opties (MSS, WS).
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
				return seg, false // kapotte optielijst: frame weigeren
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
