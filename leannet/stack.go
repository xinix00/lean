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

// loopbackMax begrenst de zelf-verkeer-wachtrij. Ruim voor een handshake plus
// een venster aan segmenten; vol = droppen zoals elke ring dropt.
const loopbackMax = 64

// De verbindingsloze reply-wachtrijen zijn begrensd, net als arp's
// reply-queue en om dezelfde reden: een flood van SYNs naar dichte poorten of
// echo-requests mag hier geen geheugen laten groeien. Vol = droppen mét
// teller; de peer merkt het aan zijn timeout en herhaalt (review 13-08).
const outQueueCap = 32

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
	errNoBudget     = errors.New("leannet: connection refused, buffer budget exhausted")
	errPortsInUse   = errors.New("leannet: no free ephemeral port")
	errUnreachable  = errors.New("leannet: no route to host (arp gave up)")
	errNoRoute      = errors.New("leannet: no route to host (destination off-subnet and no gateway configured)")
	errStackClosed  = errors.New("leannet: stack closed")
	errLoopbackFull = errors.New("leannet: loopback queue full")
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

	// Verbindingsloze uitgaande pakketten (RST's, echo-replies), al tot bytes
	// gebouwd op het queue-moment; de pomp bezorgt ze route-best-effort. Eén
	// wachtrij, één cap, één drop-teller — het waren er twee met dezelfde
	// levensloop (review 13-08, zesde ronde).
	out []outPkt

	// Loopback: frames aan ons eigen MAC (zie sendEthLocked). lbFree recyclet
	// de buffers.
	loopback [][]byte
	lbFree   [][]byte

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

	// Tellers, onder s.mu; de buitenwereld leest ze via Stats() — publieke
	// velden die intern onder een privé-mutex muteren waren een datarace voor
	// élke live-lezer (review 13-08, vierde ronde).
	stats Stats
}

// Stats is een momentopname van de stack-tellers: de stack logt niet zelf,
// hopnet hangt hier logregels/telemetrie aan.
type Stats struct {
	RefusedNoBudget int // verbindingen geweigerd omdat de pot leeg was
	DropShortFrame  int
	DropNoPort      int
	DropBadFrame    int
	DropReplyFull   int // verbindingsloze replies (RST/echo) én loopback-frames gedropt op een volle wachtrij

	// ARP zijn de tellers van de ARP-machine, als heel blok gekopieerd.
	ARP ARPStats
}

// ARPStats — de tellers van de ARP-machine.
type ARPStats struct {
	GaveUp     int // queries die na arpQueryTries pogingen opgaven
	Ignored    int // replies die niet aan ons gericht en niet gratuitous waren
	MACChanged int // refresh die een ánder MAC op een bestaande entry zette
	ReplyDrop  int // reply-antwoorden gedropt omdat de wachtrij vol was
	LearnDrop  int // passieve leerpogingen geweigerd op een volle tabel (arpCacheCap)
}

// Stats geeft de tellers als kopie, onder het stack-slot: race-vrij te lezen.
func (s *Stack) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.ARP = s.arp.cnt
	return st
}

// NewStack bouwt de stack en start de pomp. issSeed hoort uit een echte
// entropiebron te komen (de aanroeper heeft die; wij eisen hem in plaats van
// stiekem een zwakke te kiezen).
func NewStack(dev Device, cfg Config, issSeed uint32) *Stack {
	// Config-hygiëne, luid waar het een bug is en stil waar de RFC een klem
	// voorschrijft (review 13-08, vierde ronde). Een Prefix buiten 0..32 maakt
	// élke subnet-beslissing onzin — dat is een programmeerfout, geen input.
	// Een AdvWS boven 14 zou ná de handshake elk eigen venster naar nul
	// schuiven (advertisedWnd >>= shift): de peer-kant klemde al, de eigen
	// config nog niet.
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

// now is de monotone klok van de hele stack: time.Since overleeft elke
// NTP-stap, in tegenstelling tot UnixNano (BEVINDINGEN #9/#10).
func (s *Stack) now() int64 { return int64(time.Since(s.t0)) }

// notify maakt alle waiters (pomp én sockets) wakker. Aanroepen onder s.mu.
func (s *Stack) notify() {
	close(s.wake)
	s.wake = make(chan struct{})
}

// Close sluit de héle publieke stack: de pomp stopt, elke verbinding wordt
// afgekapt en gereapt (budget terug), elke listener gaat dicht (een
// geblokkeerde Accept keert terug met net.ErrClosed) en elke UDP-poort wordt
// vrijgegeven (een geblokkeerde ReadFrom idem). Vóór deze vorm bleef een
// wachtende Accept eeuwig hangen en hielden conns en UDP-wachtrijen hun
// budget vast (review 13-08).
func (s *Stack) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for key, c := range s.conns {
		c.tcp.abort()
		s.reap(key, c)
	}
	// Dezelfde teardown als tcpListener.Close (één definitie): de sconns zijn
	// hierboven al afgekapt en gereapt, dus de abort/reap-helft ervan is hier
	// een no-op — wat telt is done sluiten en de backlog-referenties legen,
	// anders kon een Accept ná Close willekeurig een gereapte (dode)
	// verbinding teruggeven (review 13-08).
	for _, l := range s.listeners {
		l.closeLocked()
	}
	for _, u := range s.udp.ports {
		// close verwijdert de poort uit de tabel en stort de wachtrij terug;
		// verzamelen hoeft niet — delete-tijdens-range is in Go gedefinieerd
		// en close is idempotent.
		u.close()
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

// isBroadcastIP rapporteert of dst een broadcast-adres is: 255.255.255.255
// (limited) of het adres met alle hostbits aan in ons eigen subnet (directed).
// Bij /31 en /32 bestaat er geen broadcastadres (RFC 3021).
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

// RecvInboundPacket verwerkt één rauw ethernet-frame. Veilig voor rommel: te
// kort, verkeerd geadresseerd of corrupt wordt geteld en gedropt, nooit
// gepanict — dit is de onvertrouwde rand (hopnet draait hem onder recover,
// maar daar hoort niets aan te komen).
func (s *Stack) RecvInboundPacket(frame []byte) error {
	eth, err := ParseEth(frame)
	if err != nil {
		s.mu.Lock()
		s.stats.DropShortFrame++
		s.mu.Unlock()
		return nil
	}
	if len(frame) > MTU+EthernetMaximumSize {
		// Een jumbo frame (driver zonder maatwacht, of een test) kan verderop
		// een reply bouwen die groter is dan txBuf — en dan panickt de pomp
		// op zijn eigen slice (review 13-08, zevenentwintigste ronde). Aan de
		// deur meten, één keer.
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

// ingressLocked is de demux zelf, los van het slot zodat de pomp
// loopback-frames langs hetzelfde pad kan voeren (zie sendEthLocked).
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
		s.notify() // een resolve kan nu klaar zijn; ook de pomp wil kijken (reply)
	case EtherTypeIPv4:
		if !toUs {
			return // niet voor ons (broadcast-IP doen we niet aan)
		}
		ip, err := ParseIPv4(eth.Payload())
		if err != nil || !ip.ChecksumOK() || ip.Dst() != s.cfg.IP {
			s.stats.DropBadFrame++
			return
		}
		// Het passieve buurleren zit in recvIPv4, ná de transport-checksum:
		// een IP-header alleen is met één gok te vervalsen, en vóór deze
		// verhuizing maakte élk frame met een gespoofd bron-IP een verse
		// cache-entry aan (review 13-08, dertiende ronde).
		s.recvIPv4(ip, [6]byte(eth.Src()), now)
	}
}

func (s *Stack) recvIPv4(ip IPv4Frame, srcMAC [6]byte, now int64) {
	src := ip.Src()
	// Passief buurleren, alleen van unicast aan óns én pas nadat de
	// transport-checksum klopte (zie ingressLocked): wie leert vóór de
	// validatie geeft elke spoofer een gratis cache-plek. De checksum is geen
	// authenticatie — de échte grens is de cap in arp.learn — maar hij haalt
	// de triviaalste vervalsing eruit.
	learn := func() {
		if sameSubnet(src, s.cfg.IP, s.cfg.Prefix) {
			s.arp.learn(src, srcMAC, now)
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
		if err != nil || !f.ChecksumOK(src, s.cfg.IP) {
			s.stats.DropBadFrame++
			return
		}
		learn()
		// Connected UDP deelt gewoon de poorttabel; het filteren op afzender
		// doet de socket-laag (de efemere poort is per dial uniek, dus vreemd
		// verkeer erheen is uitzondering, geen pad).
		if !s.udp.deliver(f.DstPort(), src, f.SrcPort(), f.Payload()) {
			s.stats.DropNoPort++
			return
		}
		s.notify()
	case ProtoICMP:
		// Echo-reply bouwen en klaarleggen; de pomp verstuurt hem.
		if len(s.out) >= outQueueCap {
			s.stats.DropReplyFull++
			return
		}
		reply := make([]byte, len(ip.Payload()))
		if n, ok := icmpEcho(ip.Payload(), reply); ok {
			learn() // icmpEcho heeft de ICMP-checksum dan gevalideerd
			s.queueOutLocked(src, ProtoICMP, reply[:n])
			s.notify()
		}
	}
}

// outPkt is één verbindingsloos uitgaand pakket: de payload boven IPv4, al
// gebouwd, plus waar hij heen moet.
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
	// Geen verbinding: een SYN voor een listener opent een embryo. Al het
	// andere krijgt een RST (RFC 9293 §3.10.7.1) — behalve een RST zelf, want
	// daarop antwoorden is een storm.
	//
	// Dat "behalve" was er eerst niet en daarmee ontbrak élke weigering: een
	// dial naar een dichte poort wachtte zijn volle deadline uit in plaats van
	// meteen "connection refused" te krijgen. Voor een health-check of een
	// origin die net verhuisd is, is het verschil tussen 3 seconden stilte en
	// een onmiddellijk antwoord het verschil tussen zoeken en weten (12-08:
	// een verkeerd origin-adres leek een netwerkprobleem).
	l, listening := s.listeners[f.DstPort()]
	// De RST-toets hoort hier óók (RFC 9293 §3.10.7.2): een SYN|RST valt zo in
	// het refuse-pad, en dat dropt RST-dragende segmenten al stil — zelfde
	// regel als de machine-guard. Zonder deze poort maakte newConnLocked
	// hieronder een embryo dat de machine daarna weigerde: 20KiB in s.conns
	// zonder timer en zonder reaper (review 13-08, vijfde ronde).
	if !listening || !seg.flags.Has(FlagSYN) || seg.flags.Has(FlagACK) ||
		seg.flags.Has(FlagRST) {
		if !seg.flags.Has(FlagRST) {
			// SEQ/ACK per RFC: een segment mét ACK spiegelt dat nummer als
			// SEQ, anders is SEQ 0 en bevestigen we de sequence-ruimte die de
			// peer beweert te hebben gebruikt.
			if seg.flags.Has(FlagACK) {
				// <SEQ=SEG.ACK><CTL=RST>, zónder ACK-vlag (RFC 9293 §3.10.7.1):
				// er is geen sequence-ruimte van de peer om te bevestigen, en
				// een RST|ACK met ack=0 wordt door een strikte SYN-SENT-peer
				// juist wéggegooid (die eist ack == iss+1) — review 13-08.
				s.queueRSTLocked(src, f.DstPort(), f.SrcPort(), seg.ack, 0, false)
			} else {
				// ACK = SEG.SEQ + SEG.LEN, en SEG.LEN telt SYN en FIN als één
				// sequence-plek — de vaste +1 die hier stond klopte alleen
				// voor een kale SYN: bij data-zonder-vlaggen was de ACK één te
				// hoog, bij SYN|FIN één te laag (review 13-08, negende ronde).
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
		// De pot is leeg: luid weigeren met een RST in plaats van stil
		// verhongeren (lean-regel 2). De peer krijgt meteen "nee".
		s.stats.RefusedNoBudget++
		s.queueRSTLocked(src, f.DstPort(), f.SrcPort(), 0, seg.seq+1, true)
		s.notify()
		return
	}
	c.tcp.openPassive(s.nextISS(), uint16(MTU-40), s.cfg.AdvWS)
	c.tcp.recv(seg, now)
	// De reset op een onacceptabele ACK (tcpConn.rst) hoeft hier — en op
	// het pad hierboven — niet geleegd te worden: emit stuurt hem zelf als
	// eerstvolgende segment, en reap vangt de verbinding die eerder sterft.
	// De vlag-en-leegprotocol tussen de lagen (dat élke recv-aanroeper moest
	// kennen) is daarmee weg (review 13-08, vijfde ronde).
	c.listener = l
	s.notify()
}

// maybeAccept geeft een embryo dat zojuist Established werd aan zijn
// listener. Hier en niet in het emit-pad: de handshake voltooit op een RECV
// (de ACK van de peer), en daar hoeft geen enkel uitgaand segment op te
// volgen.
func (s *Stack) maybeAccept(c *sconn) {
	// Ook CLOSE-WAIT: de derde handshake-ACK kan data én FIN dragen, en dan
	// is de verbinding in één recv door ESTABLISHED heen geschoten. Alleen op
	// exact ESTABLISHED toetsen liet Accept dan eeuwig wachten en het
	// floor-budget hangen (review 13-08, zevenentwintigste ronde). De data en
	// de EOF staan gewoon klaar voor de lezer.
	if c.listener != nil && !c.accepted &&
		(c.tcp.state == tcpEstablished || c.tcp.state == tcpCloseWait) {
		c.accepted = true
		c.listener.offer(c)
	}
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
	if r := c.tcp.rst; r.set {
		// Normaal stuurt emit hem zelf, maar een verbinding die sterft vóór
		// de pomp langskwam nam zijn afscheids-RST anders mee het graf in.
		// Door de queue-cap, net als élke andere RST: een kale append
		// omzeilde de begrenzing die queueRST juist bewaakte (review 13-08,
		// vierde ronde). Geen eigen notify: hieronder staat de
		// onvoorwaardelijke.
		c.tcp.rst = pendingRST{}
		s.queueRSTLocked(key.rip, key.lport, key.rport, r.seq, r.ack, r.withAck)
	}
	c.reaped = true
	delete(s.conns, key)
	s.pot.release(c.tcp.rx.size() + c.tcp.tx.size())
	// Iedereen wakker maken: een verbinding die via een TIMER stierf (opgave
	// na retries, FIN-WAIT-2-verval) komt hier via de pomp binnen, en zonder
	// notify bleef een geblokkeerde Read wachten tot er toevallig ander
	// verkeer langskwam (review 13-08). Voor de recv-paden is dit een dubbele
	// wek — en dat kost een kanaal-swap, geen ronde.
	s.notify()
	// De pot-boekhouding van deze verbinding is hiermee AFGESLOTEN: de teller
	// eraf halen maakt élke latere grow/shrink een no-op. Zonder dit kon een
	// read-na-reap die de ring leegde via shrinkRx een twééde release doen —
	// een boekhoud-panic in de maak (gevonden bij review 13-08, L9).
	c.tcp.pot = nil
	// Buffer-hygiëne: het budget is logisch terug, maar een socket die de
	// aanroeper nog vasthoudt hield de échte bytes vast terwijl nieuwe
	// verbindingen datzelfde budget opnieuw mochten alloceren — 2× het budget
	// aan werkelijk geheugen (review 13-08). Beide ringen mogen weg: reap komt
	// alleen na een volledige sluiting of een reset, en in beide gevallen komt
	// er geen read meer bij de ring (de socket-laag geeft ErrClosed na de eigen
	// Close, en een reset-fout vóór hij de ring aanraakt). De leesbare staart
	// van een half-gesloten peer leeft in CLOSE-WAIT, en dáár is nog niet
	// gereapt.
	c.tcp.tx = txRing{}
	c.tcp.rx = ring{}
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
// (BEVINDINGEN #14). inUse is de namespace van de vrager: TCP en UDP zijn
// onafhankelijke poortruimtes (TCP:80 en UDP:80 bestaan naast elkaar) — de
// oude gedeelde toets was asymmetrisch: TCP-na-UDP faalde, UDP-na-TCP niet
// (review 13-08). De cursor blijft gedeeld; dat kost hoogstens een extra stap.
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

// tcpPortInUse is de TCP-namespace: listeners plus lokale poorten van
// verbindingen (TIME-WAIT inbegrepen — zolang die staat leeft, is snel
// hergebruik van het vier-tupel het risico dat hij afdekt).
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
		again := s.drainLocked()
		deadline := s.nextDeadlineLocked()
		ch := s.wake
		s.mu.Unlock()

		if again {
			continue // zelf-verkeer verwerkt: er staat mogelijk antwoord klaar
		}
		if deadline == 0 {
			<-ch
			continue
		}
		// Geen ondergrens nodig: nextDeadlineLocked klemt een verstreken
		// deadline al op now+10ms, en een negatieve timer vuurt gewoon meteen.
		t := time.NewTimer(time.Duration(deadline - s.now()))
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
func (s *Stack) drainLocked() (again bool) {
	now := s.now()

	for _, o := range s.out {
		// Route best-effort én zonder ARP-molen (query=false): zonder bekend
		// MAC vervalt het pakket — de peer merkt het aan zijn timeout en
		// herhaalt. In het legitieme geval is het MAC er altijd (de geldige
		// SYN/echo die dit antwoord uitlokte is net passief geleerd); een
		// actieve query hier gaf een spoofer per refuse-RST een verdringing
		// in de cache (review 13-08, vijftiende ronde).
		if mac, ok := s.routeLocked(o.dst, now, false); ok {
			s.sendIPv4Locked(mac, o.dst, o.proto, o.pkt)
		}
	}
	s.out = s.out[:0]

	// ARP zelf: replies en query-(re)tries. Een query die in deze ronde luid
	// opgeeft moet zijn wachters wekken: een UDP-writer (of dial) die op
	// noAnswer poll't kreeg anders pas bij zijn eigen deadline te horen dat
	// de route dood is (review 13-08, achtentwintigste ronde).
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

	// TCP: elke verbinding mag zijn klaarstaande segmenten kwijt — mits de
	// route er is. Zonder MAC slaan we de verbinding óver (emit is lui, er
	// wordt geen sequence-staat verspild) en heeft arp.resolve de query al
	// gestart; de reply komt via notify terug.
	for key, c := range s.conns {
		mac, ok := s.routeLocked(key.rip, now, true)
		if !ok {
			// Route weg én ARP heeft luid opgegeven: dan is overslaan geen
			// geduld maar een bevriezing — emit draait nooit, dus de
			// retransmissietimer telt nooit door en de verbinding hangt
			// voorgoed (review 13-08). Zelfde hop-keuze als de dial. En hop
			// nul (peer buiten het subnet, geen gateway) is dezelfde dood
			// zonder ARP-lot: een inbound SYN van zo'n peer maakte anders een
			// embryo waarvan de timer nooit gewapend werd — een 20KiB-zombie
			// per SYN, tot de pot leeg was (review 13-08, vijfde ronde).
			if hop := s.nextHopLocked(key.rip); hop == ([4]byte{}) || s.arp.noAnswer(hop, now) {
				c.tcp.abort() // reset: read/write falen luid
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

	// Zelf-verkeer: door de eigen ingress, niet de draad op. Wat hier
	// binnenkomt kan een antwoord opleveren (een SYN wil een SYN-ACK), dus
	// vraagt de pomp om nog een ronde in plaats van te gaan slapen — anders
	// zou de notify die recvIPv4 zet net te laat komen (de pomp leest zijn
	// wake-kanaal ná deze functie).
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
		// overgeslagen), dan is dít het herkeur-tempo. De RTO-vloer volstaat:
		// in die fase valt er niets te versturen, en 10ms betekende 100
		// wakeups/s zolang de route zoek was (review 13-08, derde ronde).
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
			// Bewust GEEN wektijd. Correctheid is lui gedekt (élk consult
			// tikt, en arp.emit tikt de hele tabel per drain-ronde) en het
			// geheugen is al begrensd (arpCacheCap; de vol-paden vegen
			// verlopen entries precies wanneer de ruimte ertoe doet). Een
			// wektijd hier kocht alleen eerder opruimen van al-begrensd
			// geheugen — tegen de prijs dat een stille stack met een paar
			// geleerde buren periodiek wakker werd, en "een idle stack kost
			// geen CPU" is de les van HOP's poll-tijd-jacht (review 13-08,
			// veertiende ronde).
		}
	}
	return d
}

// nextHopLocked geeft het IP waarvan het ARP-lot dit doel draagt: binnen het
// subnet het doel zelf, daarbuiten de gateway (nul = geen route geconfigureerd;
// met een statische gateway-MAC is er geen ARP-lot en telt het doel als
// onschadelijke vulling). Eén beslissing voor dial, UDP-write én de route-dood
// in de pomp — drie inline kopieën waren al aan het uiteenlopen
// (review 13-08, derde ronde).
func (s *Stack) nextHopLocked(dst [4]byte) [4]byte {
	if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) && !s.hasGwMAC {
		return s.cfg.GW
	}
	return dst
}

// routeLocked beslist het volgende-hop-MAC: binnen het subnet direct via ARP,
// daarbuiten de gateway (statisch plan of ARP). query=false raadpleegt alleen
// de cache (arp.peek) en start nooit een query — voor het best-effort-pad,
// zie drainLocked.
func (s *Stack) routeLocked(dst [4]byte, now int64, query bool) ([6]byte, bool) {
	// Ons eigen adres: nooit ARP'en, nooit de draad op. Zonder deze regel
	// vraagt een wereld die zijn eigen IP dialt op de draad "who has <mijzelf>"
	// — een vraag die niemand hoort te beantwoorden (een switch floodt naar
	// iedereen BEHALVE de bron), dus gaf dat na vijf pogingen "no route to
	// host". GEMETEN 12-08 op ijzer: cloudflared stond na een rolling update op
	// het slot-IP dat zijn eigen config als origin noemde, en de fout wees vijf
	// lagen weg van de oorzaak. Zie sendEthLocked voor de loopback-naad.
	if dst == s.cfg.IP {
		return s.cfg.MAC, true
	}
	// Broadcast gaat naar ff:ff:ff:ff:ff:ff en wordt nooit geARP't. Zonder deze
	// regel deed de routelaag er iets stils-fouts mee: 255.255.255.255 valt
	// buiten élk subnet, dus ging het als UNICAST naar de gateway (die het
	// terecht negeert), en een subnet-gericht adres (x.x.x.255) ging de
	// ARP-molen in naar een adres dat niemand bezit — vijf pogingen, dan "no
	// route to host". De gebruiker vandaag is een DHCP-rebind (RFC 2131
	// §4.4.5): als de lessor verdwijnt is broadcast de enige manier om de lease
	// te houden, en dan is een fout hier het verschil tussen doorleven en het
	// IP verliezen. Ingress blijft broadcast-IP's negeren (zie ingressLocked):
	// het antwoord op een rebind komt unicast op ciaddr terug.
	if isBroadcastIP(dst, s.cfg.IP, s.cfg.Prefix) {
		return bcastMAC, true
	}
	if !sameSubnet(dst, s.cfg.IP, s.cfg.Prefix) {
		if s.hasGwMAC {
			return s.gwMAC, true
		}
		dst = s.cfg.GW
		if dst == ([4]byte{}) {
			return [6]byte{}, false
		}
		// De gateway mag óók op het best-effort-pad een echte query starten:
		// zijn IP komt uit de config, niet uit het pakket, dus een spoofer
		// kan er nooit méér dan deze ene entry mee laten bestaan. Zonder deze
		// uitzondering verdampte een refuse-RST naar een off-subnet peer stil
		// op een verse node die nog nooit uitbelde (review 13-08, zestiende
		// ronde).
		query = true
	}
	if !query {
		return s.arp.peek(dst, now)
	}
	return s.arp.resolve(dst, now)
}

// ---- wire-schrijvers (allemaal onder s.mu) ----

// queueOutLocked legt een gebouwd verbindingsloos pakket klaar, begrensd:
// vol = droppen mét teller (de peer herhaalt en krijgt hem dan alsnog).
func (s *Stack) queueOutLocked(dst [4]byte, proto byte, pkt []byte) {
	if len(s.out) >= outQueueCap {
		s.stats.DropReplyFull++
		return
	}
	s.out = append(s.out, outPkt{dst: dst, proto: proto, pkt: pkt})
}

// queueRSTLocked bouwt een verbindingsloze RST en legt hem klaar. De bytes
// ontstaan op het quéue-moment: alles wat PutTCP nodig heeft is hier al
// bekend, en dan hoeft er geen tweede pending-vorm (rstPending + noAck) naast
// de wachtrij te bestaan (review 13-08, zesde ronde). withAck kiest tussen
// <SEQ,ACK><RST|ACK> (op een SYN of vanuit een verbinding) en de kale
// <SEQ=SEG.ACK><RST> van RFC 9293 §3.10.7.1.
func (s *Stack) queueRSTLocked(dst [4]byte, sport, dport uint16, seq, ack uint32, withAck bool) {
	flags := FlagRST
	if withAck {
		flags |= FlagACK
	}
	buf := make([]byte, sizeTCP)
	n, err := PutTCP(buf, sport, dport, seq, ack, flags, 0, nil, s.cfg.IP, dst, 0)
	if err != nil {
		return // kan alleen bij een interne maatfout
	}
	// queueOutLocked draagt de cap en de teller; bij vol zijn de 20 gebouwde
	// bytes het enige verlies (review 13-08, achtste ronde).
	s.queueOutLocked(dst, ProtoTCP, buf[:n])
}

func (s *Stack) sendEthLocked(dst [6]byte, etherType uint16, payloadLen int) error {
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
	// Loopback: een frame aan onszelf gaat niet de draad op maar de eigen
	// ingress in. Dat is wat "127.0.0.1" elders doet, hier op het enige adres
	// dat we hebben — een agent die zijn eigen poort belt en een app die per
	// ongeluk zijn eigen slot-IP als origin heeft, komen beide netjes uit
	// (verbinding of connection refused, niet "no route to host").
	//
	// De kopie is nodig omdat txBuf de volgende regel al hergebruikt wordt.
	// Bewust geen bulk-pad: dit draagt agent↔leader-verkeer, geen downloads.
	// Loopt de wachtrij vol (een lokale peer die niet leest), dan dropt dit
	// zoals elke volle ring dropt — TCP herzendt.
	if dst == s.cfg.MAC {
		if len(s.loopback) >= loopbackMax {
			// Vol is een FOUT voor de aanroeper: TCP negeert hem (de
			// retransmissie herstelt), maar een UDP-Write die "gelukt" meldt
			// terwijl het datagram nergens ligt is een leugen zonder tweede
			// kans (review 13-08, vijfde ronde).
			s.stats.DropReplyFull++
			return errLoopbackFull
		}
		s.loopback = append(s.loopback, append(s.lbBuf(), s.txBuf[:n]...))
		// Wakker maken, want niet elke zender is de pomp: een UDP-Write
		// schrijft rechtstreeks vanuit de socket-call, en zonder notify
		// bleef zijn datagram in de wachtrij tot er iets ánders gebeurde
		// (i/o timeout op een loopback-vraag, gemeten in de eerste versie
		// van deze naad).
		s.notify()
		return nil
	}
	// De fout gaat terug naar de aanroeper. TCP negeert hem (de retransmissie
	// ís het herstel), maar UDP heeft geen tweede kans: een Write die "gelukt"
	// meldt terwijl de NIC het pakket weigerde, is een leugen (review 13-08).
	return s.dev.Transmit(s.txBuf[:n])
}

// lbBuf geeft een lege buffer voor de loopback-wachtrij: hergebruikt wat
// drainLocked teruggaf, zodat een levendige lokale gesprekspartner niet elke
// ronde nieuwe frames alloceert.
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
		s.stats.DropBadFrame++ // kan alleen bij een interne maatfout; tel hem luid
		return
	}
	PutIPv4(s.txBuf[EthernetHeaderSize:], ProtoTCP, s.cfg.IP, key.rip, n)
	s.sendEthLocked(dstMAC, EtherTypeIPv4, sizeIPv4+n)
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
