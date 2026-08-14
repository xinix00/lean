package leannet

// tcp.go — de TCP-machine (RFC 9293 + RFC 6298), één verbinding per tcpConn.
// De machine is puur: geen goroutines, geen klok — recv/emit krijgen een
// monotone nanoseconde-tijd aangereikt en al het gedrag volgt daaruit. Dat
// maakt élk faalscenario deterministisch testbaar (tcp_test.go injecteert
// verlies en tijd).
//
// De kernkeuze, en het verschil met waar lneto brak (BEVINDINGEN #1/#2):
// retransmissie werkt op SEQUENCE-RUIMTE, niet op "data". SYN en FIN nemen
// een sequencenummer in en rollen dus vanzelf mee in het go-back-N-pad: een
// RTO spoelt nxt terug naar una, en emit regenereert vanaf daar wat er ook
// stond — data, de FIN erachteraan, of een kale FIN. Er bestaat geen aparte
// vlaggen-wachtrij die leeg kan raken terwijl het segment op de lijn
// verdwenen is.
//
// v1-keuzes (ontwerpdossier): in-order-only ontvangst — een out-of-order
// segment wordt gedropt mét een directe dup-ACK zodat de peer fast-retransmit
// kan doen; geen SACK, geen timestamps; window scaling wél (nodig voor
// vensters boven 64KiB).

import (
	"errors"
	"time"
)

// ---- sequence-rekenkunde (modulo 2^32) ----

func seqLT(a, b uint32) bool  { return int32(a-b) < 0 }
func seqLEQ(a, b uint32) bool { return int32(a-b) <= 0 }

// seqDiff geeft a-b als gewone int (klein verondersteld).
func seqDiff(a, b uint32) int { return int(int32(a - b)) }

// ---- staten ----

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
	// §2.4 adviseert 1s minimum; op de LAN/embedded-links waar leannet draait
	// is dat strafwerk — zelfde afweging als Linux: een lagere vloer.
	tcpRTOMin     = 200 * time.Millisecond
	tcpRTOMax     = 60 * time.Second
	tcpBackoffMax = 12 // begrenst de verdubbeling; een vastzittende peer blijft op rtoMax proben

	tcpTimeWaitDur = int64(time.Second) // kort en straks configureerbaar; 2MSL=4min past een embedded node niet

	// tcpFinWait2Dur begrenst FIN-WAIT-2: onze FIN is bevestigd maar de peer
	// sluit zelf nooit. Elke FIN-WAIT-2 is bij ons post-Close (close() is de
	// enige weg ernaartoe en tcpSock.Close is een vólle close), dus er is geen
	// half-open lezer om te ontzien — zonder deadline houdt zo'n peer de
	// verbinding en haar floor-budget onbeperkt vast (review 13-08). Linux'
	// tcp_fin_timeout doet hetzelfde (default 60s; wij korter, zelfde reden
	// als TIME-WAIT).
	tcpFinWait2Dur = int64(20 * time.Second)
	tcpDefaultMSS  = 536

	// Opgeef-grenzen: zoveel RTO-vuringen zonder één geldige ACK van de peer,
	// dan is hij dood en gaat de verbinding eraan (abort + RST). Élke geldige
	// ACK reset de teller, dus een levende peer met een dicht venster blijft
	// gewoon leven — alleen stilte doodt. Zonder deze grens houdt een
	// SYN-flood-embryo zijn floor-geheugen eeuwig vast (lneto's #6, de
	// half-open-flood die een listener blijvend doof maakte).
	tcpMaxRetriesHandshake = 5  // ~6s: SYN of SYN|ACK zonder antwoord
	tcpMaxRetriesData      = 12 // ~minuten: gevestigde peer die verdween
)

var (
	errTCPClosed  = errors.New("leannet: connection closed")
	errTCPClosing = errors.New("leannet: connection already closing")

	// errTCPReset is de niet-nette dood: een RST van de peer, of opgegeven na
	// de hele backoff-ladder. De socket-laag geeft hem dóór als fout — nooit
	// als io.EOF, want "de stroom is compleet" is precies wat een reset níet
	// zegt. Een HTTP-body die hierop eindigt is een half bestand (review 13-08).
	errTCPReset = errors.New("leannet: connection reset by peer")
)

// tcpSeg is een segment op machine-niveau: de stack-laag vertaalt van/naar
// draadbytes (frame.go); de tests spreken de machine rechtstreeks aan.
type tcpSeg struct {
	seq, ack uint32
	flags    TCPFlags
	wnd      uint16 // draadwaarde (vóór schaling)
	data     []byte

	// Alleen betekenisvol op SYN-segmenten.
	mss  uint16
	wsOK bool  // window-scale-optie aanwezig
	ws   uint8 // aangeboden shift
}

// tcpConn is één verbinding. Niet zelf-vergrendeld: de socket-laag houdt per
// verbinding één lock over recv/emit/app-calls (één regime, zie ring.go).
type tcpConn struct {
	state  tcpState
	listen bool // passieve kant: een SYN op tcpClosed opent naar SYN-RCVD

	// Zendkant. dataBase is het sequencenummer van de kop van tx — daarmee is
	// de ring in sequence-ruimte verankerd en is elke retransmissie een
	// her-lezing (ring.go). finSeq ligt vast vanaf close(): er komt geen
	// Write meer bij, dus data boven de eigen FIN kan niet bestaan
	// (BEVINDINGEN #13, by construction).
	iss      uint32
	una      uint32 // hoogste door de peer bevestigde seq
	nxt      uint32 // volgende te versturen seq
	dataBase uint32
	closing  bool
	finSeq   uint32
	sndWnd   uint32 // peer-venster in octetten (ná schaling)
	wl1, wl2 uint32 // segment dat het venster het laatst bijwerkte (RFC 9293 §3.10.7.4)
	peerMSS  int
	sndWS    uint8 // shift op binnenkomende venster-advertenties van de peer

	// Ontvangkant.
	irs     uint32
	rcvNxt  uint32
	finRcvd bool
	rcvWS   uint8 // shift op ónze venster-advertenties
	wsOn    bool  // beide kanten boden WS aan

	// Wat wij op onze SYN adverteren.
	advMSS uint16
	advWS  uint8

	rx ring
	tx txRing

	// Het budgetmodel (doc.go): rings starten op hun floor en verdubbelen op
	// gemeten druk — een volle rx bij aankomst, een volle tx bij write — tot
	// maxBuf of tot de pot nee zegt. pot == nil (tests, of een wereld zonder
	// budget) betekent: nooit groeien.
	//
	// Krimpen bestaat sinds 12-08 wél (shrinkRing): een LEGE ring gaat terug naar
	// zijn vloer zodra de app de laatste byte ophaalde of de peer de laatste byte
	// bevestigde. Zonder dat houdt een verbinding die één keer druk was zijn
	// buffers tot hij sluit, en een gepoolde HTTP-verbinding sluit niet — vier van
	// die verbindingen en de pot van een node is leeg. Close geeft daarnaast nog
	// altijd alles in één keer terug (de stack-laag stort de ringmaten terug).
	pot    *budget
	maxBuf int

	// Besturing.
	needAck bool // er is iets te bevestigen (data, FIN, dup, challenge)

	// appClosed: de eigenaar deed een VOLLE close (socket-laag; zie
	// abandonRead — het machine-close is een half-close en laat lezen door).
	// Binnenkomende data binnen de belofte wordt geteld en weggegooid
	// (rcvNxt schuift, de peer krijgt zijn ACK, de FIN kan landen), en de
	// ontvangring is al terug in de pot: een pool-geëvicte verbinding hield
	// zijn ringen anders de volle FIN-WAIT-2-termijn vast (review 13-08,
	// achtentwintigste ronde).
	appClosed bool

	// rst: er staat hoogstens één afscheids-RST klaar, mét zijn vorm. De
	// abort-variant draagt <SEQ=NXT><ACK=RCV.NXT> (withAck); de weigering op
	// een ACK die onze SYN niet bevestigt (SYN-SENT/SYN-RCVD, RFC 9293
	// §3.10.7.3/.4) is kaal: <SEQ=SEG.ACK>, er is geen sequence-ruimte van de
	// peer om te bevestigen — en de verbinding zelf blijft dan staan
	// (SYN-SENT herhaalt gewoon zijn SYN). Snapshotten bij het zetten is
	// veilig: na een abort bewegen nxt/rcvNxt niet meer. emit stuurt hem als
	// eerstvolgende segment; sterft de verbinding vóór de pomp langskwam, dan
	// verhuist reap hem naar de verbindingsloze wachtrij — de weigering gaat
	// áltijd de deur uit. (Twee vlaggensets met elk hun emit-blok en
	// reap-drain, samengevouwen in review 13-08, achttiende ronde.)
	rst pendingRST

	// advEdge is de verste rechterrand die we ooit adverteerden (rcvNxt +
	// venster); advSet zegt óf we ooit adverteerden. Een aparte bool en geen
	// nul-sentinel: door sequence-wrap is 0 een geldige rechterrand (peer's
	// ISS + venster kan precies op 0 uitkomen), en dan bleef de belofte
	// eruitzien als "nog niets toegezegd" — rcvWnd viel terug op de fysieke
	// ring en accepteerde data buiten het geadverteerde venster
	// (review 13-08, tweeëntwintigste ronde).
	// Alleen om te weten hoe klein de ontvangstring mág worden: het venster mag
	// nooit naar links krimpen (RFC 9293 §3.8.6.2.1), dus wat we toegezegd hebben
	// moet beschikbaar blijven.
	advEdge uint32
	advSet  bool

	// synWnd is het venster dat onze SYN adverteerde (actieve open): een
	// belofte als elke andere, maar bij het versturen is rcvNxt nog onbekend —
	// recvSynSent legt de rand vast zodra de peer-ISS binnen is (review 13-08,
	// vierentwintigste ronde).
	synWnd uint16

	// RTO (RFC 6298) + Karn-sampling. maxSent is de verste ooit verzonden
	// sequence-rand: een RTT-sample start alléén op ruimte daarvoorbij —
	// nooit op een hertransmissie (zie postTx).
	srtt, rttvar, rto time.Duration
	haveRTT           bool
	timerOn           bool
	deadline          int64
	backoff           uint8
	timing            bool
	timedSeq          uint32
	timedAt           int64
	maxSent           uint32

	// persistBackoff is de eigen backoff-ladder van de zero-window-persist:
	// probes mogen de RTT/RTO-estimator niet muteren (zie emit), anders
	// draagt de verbinding ná de venster-opening nog minutenlange RTO's.
	persistBackoff uint8

	// Fast retransmit (RFC 5681 §3.2, de simpele vorm).
	dupacks uint8

	// Opgeef-boekhouding: RTO-vuringen sinds de laatste geldige ACK.
	retries uint8
	// refused onderscheidt "peer zei nee" (RST op onze SYN) van "peer zweeg"
	// (opgegeven na retries) — de socket-laag maakt er twee fouten van.
	refused bool
	// reset onthoudt een niet-nette dood ná de handshake: een RST van de peer
	// of een abort (opgave, harde kill). read/write melden dan een fout in
	// plaats van EOF — de oorzaak mag niet wegvallen in de staat "closed".
	reset bool

	// Zero-window-probe: gezet door de timer, verbruikt door één 1-byte-probe.
	probe bool

	twDeadline int64
}

// openActive start een uitgaande verbinding: de eerstvolgende emit stuurt de
// SYN. Rings en budget-koppeling overleven de reset — die zijn van de eigenaar.
func (c *tcpConn) openActive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpSynSent, iss: iss, una: iss, nxt: iss, maxSent: iss,
		dataBase: iss + 1, advMSS: advMSS, advWS: advWS,
		rto: tcpRTOInitial, peerMSS: tcpDefaultMSS,
		rx: c.rx, tx: c.tx, pot: c.pot, maxBuf: c.maxBuf}
}

// openPassive maakt de verbinding een luister-embryo: een binnenkomende SYN
// opent hem naar SYN-RCVD. De listener-laag kloont hier één per handshake van.
func (c *tcpConn) openPassive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpClosed, listen: true, iss: iss, maxSent: iss,
		advMSS: advMSS, advWS: advWS,
		rto: tcpRTOInitial, peerMSS: tcpDefaultMSS,
		rx: c.rx, tx: c.tx, pot: c.pot, maxBuf: c.maxBuf}
}

// close vraagt de nette sluiting aan: de FIN krijgt zíjn sequencenummer nu en
// gaat mee in het gewone zendpad (na de laatste databyte). Write faalt vanaf
// hier met errTCPClosed.
func (c *tcpConn) close() error {
	switch {
	case c.closing:
		return errTCPClosing
	case c.state == tcpClosed, c.state == tcpTimeWait:
		return errTCPClosed
	case c.state == tcpSynSent:
		// Nog niets gesynchroniseerd: gewoon weg.
		c.state = tcpClosed
		return nil
	}
	c.closing = true
	c.finSeq = c.dataBase + uint32(c.tx.buffered())
	return nil
}

// abandonRead: de eigenaar verklaart dat er nooit meer gelezen wordt. Dit is
// BEWUST een aparte stap naast close(): het machine-close is een half-close
// (shutdown-write, lezen blijft mogelijk — zie TestTCPHalfCloseKeepsReceiving),
// terwijl een net.Conn.Close op de socket-laag een vólle close is. Alleen die
// laatste mag de ontvangkant opgeven: ongelezen bytes gaan met de ring mee
// terug de pot in, en binnenkomende data wordt vanaf nu geteld-en-weggegooid
// (zie appClosed) zodat de peer zijn ACK's en zijn FIN kwijt kan
// (review 13-08, achtentwintigste ronde).
func (c *tcpConn) abandonRead() {
	c.appClosed = true
	if c.pot != nil {
		c.pot.release(c.rx.size())
		c.rx = ring{}
	}
}

// pendingRST is de klaarstaande afscheids-RST (zie tcpConn.rst).
type pendingRST struct {
	seq, ack uint32
	withAck  bool
	set      bool
}

// abort kapt de verbinding hard af: één RST eruit, daarna is alles dood.
func (c *tcpConn) abort() {
	if c.state != tcpClosed && c.state != tcpSynSent {
		c.rst = pendingRST{seq: c.nxt, ack: c.rcvNxt, withAck: true, set: true}
		c.reset = true // een abort is geen net einde; read/write horen te falen
	}
	c.state = tcpClosed
	c.timerOn = false
}

// write neemt applicatiebytes op in de zendring (zoveel als past). Een volle
// ring terwijl de peer méér venster biedt is het groeisignaal voor de
// zendkant: er ís vraag, wij zijn de rem.
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

// shrinkRing geeft ruimte van een LEGE ring terug aan de pot. Zonder dit houdt
// een verbinding die één keer druk was zijn gegroeide buffers tot hij sluit — en
// een gepoolde HTTP-verbinding sluit niet. Vier zulke verbindingen en de pot van
// een node is leeg (MaxBufPerConn is Budget/4), en dan wordt élke nieuwe
// verbinding geweigerd.
//
// GEMETEN 12-08 op een LicheeRV: HOP haalde app-images op, liet gepoolde
// verbindingen achter en meldde daarna "buffer budget exhausted" op elke dial —
// waarna de watchdog de node reset, want zijn levensteken vraagt juist een verse
// verbinding.
//
// keep is wat gereserveerd moet blijven: voor de ontvangstring is dat het venster
// dat we al toegezegd hebben (advEdge - rcvNxt), want dat mag niet naar links
// krimpen (RFC 9293 §3.8.6.2.1). Voor de zendring is dat nul — die is puur van
// ons. Gevolg van die regel: een verbinding die stil openstaat mét een wijd
// venster houdt zijn ring; krimpen kan pas als de peer dat venster verbruikt
// heeft. Dat is precies het einde van een download, en dus precies het geval dat
// de pot leegvrat.
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
	// Anders dan bij groei: EERST de oude buffer loslaten (de ring is leeg,
	// dus grow(nil) mag), dan pas de kleinere reserveren — die reservering
	// kan niet falen, want target ≤ wat we net teruggaven. De omgekeerde
	// volgorde (reserveer-dan-wissel) faalde bij een randvolle pot per
	// definitie, waardoor lege gegroeide verbindingen de pot permanent bleven
	// vullen: een resource-cirkel (review 13-08, zevenentwintigste ronde).
	// De echte piek is hier max(oud, nieuw) — de oude buffer is al los vóór
	// de nieuwe bestaat.
	old := r.size()
	r.grow(nil)
	c.pot.release(old)
	if !c.pot.reserve(target) {
		// Kan alleen bij een boekhoudfout elders; luid, zoals elke
		// boekhoudfout in dit package.
		panic("leannet: shrink reservation failed after releasing a larger ring")
	}
	r.grow(make([]byte, target))
}

// shrinkRx en shrinkTx zijn de twee plekken waar dat mag: net nadat de app de
// laatste byte ophaalde, en net nadat de peer de laatste byte bevestigde.
func (c *tcpConn) shrinkRx() {
	// Vóór de eerste post-SYN-advertentie is er niets te krimpen: de ring
	// staat op zijn floor (processData groeit niet zolang advEdge nul is) en
	// seqDiff tegen een nul-rand zegt niets. Expliciet toetsen, geen betoog
	// (review 13-08, derde ronde).
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
	// Geen sent-guard nodig: shrinkRing weigert elke niet-lege ring, en per
	// constructie is sent ≤ buffered (nextSend peekt gebufferd, ack verlaagt
	// beide) — sent zonder buffered bestaat niet.
	c.shrinkRing(&c.tx.ring, tcpFloorTx, 0)
}

// growRing verdubbelt r binnen maxBuf en de pot; false = niet gegroeid.
func (c *tcpConn) growRing(r *ring) bool {
	if c.pot == nil {
		return false
	}
	// maxBuf klemt de VERBINDING (rx én tx samen): met een per-ring-toets was
	// "Budget/4 per verbinding" stiekem het dubbele voor full-duplexverkeer,
	// en droegen twee drukke verbindingen de hele pot (review 13-08, vierde
	// ronde).
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
	return c.swapRing(r, newSize) // pot draagt de piek niet: klein blijven is geen fout
}

// swapRing is de piek-eerlijke ringwissel: reserveer de héle nieuwe maat,
// wissel, en geef de oude pas daarna terug — tijdens de wissel leven beide
// ringen en de boekhouding dekt die dubbel-levende piek (de delta-vorm zei
// 32MiB terwijl er transient 48MiB leefde: op een 64MB-board een OOM —
// review 13-08, vierentwintigste ronde; groei en krimp deelden de wissel
// sindsdien als twee kopieën, zesentwintigste ronde). De release vertrouwt
// voor de échte vrijgave op de GC. false = de pot draagt de piek niet, en de
// aanroeper houdt wat hij had.
func (c *tcpConn) swapRing(r *ring, newSize int) bool {
	if !c.pot.reserve(newSize) {
		return false
	}
	old := r.size()
	r.grow(make([]byte, newSize))
	c.pot.release(old)
	return true
}

// read levert ontvangen bytes; 0 bytes met errTCPClosed betekent EOF ná de
// FIN van de peer (de socket-laag vertaalt dat naar io.EOF).
//
// Opent de lezer een (vrijwel) dicht venster, dan staat er een venster-update
// klaar (RFC 9293 SWS-vermijding aan de ontvangkant: pas melden als er
// minstens een MSS vrij is). Zonder die update hangt de doorvoer aan de
// zero-window-probe van de peer, en die is seconden traag.
func (c *tcpConn) read(p []byte) (int, error) {
	if c.reset {
		// Een gebroken verbinding levert een fout, geen (rest)data en geen
		// EOF: wat er nog in de ring stond is niet te vertrouwen als "einde
		// van de stroom" — dat is het klassieke halve-bestand-gat.
		return 0, errTCPReset
	}
	wasFree := c.rx.free()
	n := c.rx.read(p)
	if n == 0 && (c.finRcvd || c.state == tcpClosed) {
		return 0, errTCPClosed
	}
	// Drempel = min(MSS, halve ring), met vloer 1: een ring kleiner dan een
	// MSS moet zijn updates ook kwijt kunnen.
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
	// De app is bij: ruimte die niemand meer nodig heeft terug de pot in.
	c.shrinkRx()
	return n, nil
}

// promiseEdge legt een zojuist geadverteerd venster vast als belofte: de rand
// schuift alleen naar voren (een venster mag nooit naar links krimpen,
// RFC 9293 §3.8.6.2.1). Dit is de ENE plek die advEdge/advSet zet — de
// advertentie zelf, de SYN-ACK en het SYN-anker in recvSynSent deelden deze
// regels eerst als drie letterlijke kopieën, en dit is een van de subtielste
// invarianten van de machine: de 22e (wrap-sentinel) en 24e (SYN-belofte)
// ronde gingen er allebei over (review 13-08, zesentwintigste ronde).
func (c *tcpConn) promiseEdge(wnd uint32) {
	if edge := c.rcvNxt + wnd; !c.advSet || seqLT(c.advEdge, edge) {
		c.advEdge, c.advSet = edge, true
	}
}

// advertisedWnd geeft de draadwaarde van ons receive-venster: de vrije
// ringruimte, geschaald. We adverteren alleen wat er al gealloceerd is —
// nooit reneg-en (ontwerpdossier).
func (c *tcpConn) advertisedWnd() uint16 {
	w := c.rx.free()
	if c.wsOn {
		w >>= c.rcvWS
	}
	if w > 0xffff {
		w = 0xffff
	}
	// De rand die we toezeggen onthouden: shrinkRing mag daar nooit binnen
	// komen. Dit is de énige plek waar een venster de deur uit gaat, dus ook de
	// enige plek waar die rand kan opschuiven. En het is de DRAADwaarde die
	// telt — ná schaling en de 16-bit-clamp, teruggerekend. free() nemen leek
	// hetzelfde maar pinde méér vast dan ooit beloofd was: zonder window
	// scaling belooft een ring van 128K maar 65535 bytes, en dan moet een
	// lege ring ook tot daar terug kunnen krimpen (review 13-08).
	promised := uint32(w)
	if c.wsOn {
		promised <<= c.rcvWS
	}
	c.promiseEdge(promised)
	return uint16(w)
}

// ---- ontvangst ----

// recv verwerkt één binnengekomen segment. De stack-laag heeft checksum en
// demux al gedaan; hier leeft alleen de RFC-machine.
func (c *tcpConn) recv(seg tcpSeg, now int64) {
	if c.state == tcpClosed {
		// LET OP het masker: Has(ACK|RST) eist ACK én RST tegelijk, dus de
		// oude vorm !Has(FlagACK|FlagRST) weerde alleen die combinatie en liet
		// een kale SYN|RST een embryo openen — 20KiB floor-budget plus een
		// SYN|ACK naar een host die net RST zei. Een RST in LISTEN hoort
		// genegeerd te worden (RFC 9293 §3.10.7.2; review 13-08, vijfde ronde).
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

	// RST: exacte SEQ-match vereist; in-window maar niet exact → challenge-ACK
	// (RFC 5961 §3.2 — voorkomt blind reset).
	if seg.flags.Has(FlagRST) {
		if seg.seq == c.rcvNxt {
			c.state = tcpClosed
			c.timerOn = false
			c.reset = true // géén EOF: de peer heeft het gesprek gebroken
		} else if c.inRcvWindow(seg.seq) {
			c.needAck = true
		}
		return
	}
	// SYN op een gesynchroniseerde verbinding → challenge-ACK, drop (RFC 5961 §4.2).
	if seg.flags.Has(FlagSYN) {
		if c.state == tcpSynRcvd && seg.seq == c.irs {
			// Dubbele SYN van de peer: onze SYN|ACK is kennelijk zoek — opnieuw.
			c.nxt = c.iss
			return
		}
		c.needAck = true
		return
	}
	if !seg.flags.Has(FlagACK) {
		return // elk segment na de SYN draagt een ACK (RFC 9293 §3.10.7.4)
	}
	// Acceptability-toets (RFC 9293 §3.10.7.4, stap één): valt het segment
	// buiten ons receive-venster, dan raakt het de machine niet — geen
	// ACK-verwerking, geen venster-update, geen retry-reset. Wel een verse ACK
	// terug, zodat de peer onze werkelijkheid hoort (dat dekt meteen de
	// zero-window-probe en de herhaalde FIN wiens ACK zoekraakte). Zonder deze
	// toets kon een verdwaald out-of-window segment het zendvenster verzetten
	// en de opgeef-teller resetten (review 13-08). RST en SYN zijn hierboven
	// al afgehandeld, RFC 5961-stijl.
	if !c.segAcceptable(seg) {
		// Een geherhaalde FIN in TIME-WAIT (onze ACK raakte zoek) komt hiér
		// binnen — één sequence-plek vóór rcvNxt, dus onacceptabel — en hoort
		// de 2MSL-termijn opnieuw te starten (RFC 9293 §3.10.7.4, TIME-WAIT):
		// anders kon de staat vrijwel direct ná de verse ACK verlopen, en als
		// dié ACK ook zoekraakt is er niemand meer om te antwoorden
		// (review 13-08, tiende ronde). Maar ALLEEN de echte duplicate telt:
		// zijn FIN moet exact op rcvNxt-1 staan. Elke out-of-window FIN laten
		// tellen liet verkeer met het juiste vier-tupel het TIME-WAIT-slot en
		// zijn buffers onbeperkt vasthouden (review 13-08, twaalfde ronde).
		if c.state == tcpTimeWait && seg.flags.Has(FlagFIN) &&
			seg.seq+uint32(len(seg.data)) == c.rcvNxt-1 {
			c.twDeadline = now + tcpTimeWaitDur
		}
		c.needAck = true
		return
	}

	if !c.processAck(seg, now) {
		// Het segment is afgekeurd (future-ACK, of een ongeldige ACK in
		// SYN-RCVD): heel het segment valt, inclusief data en FIN — RFC 9293
		// §3.10.7.4 zegt ACK-en-droppen, niet ACK-en-toch-verwerken. Vóór deze
		// poort kon een segment met een onmogelijke ACK zijn data alsnog in de
		// ring leggen (review 13-08).
		return
	}

	// Data en FIN alleen in staten waar de peer nog mag leveren. In de andere
	// staten is een segment mét data of FIN per definitie een duplicaat
	// (bijvoorbeeld een FIN-retransmissie omdat onze ACK zoekraakte) en
	// verdient hij een verse ACK — anders blijft de peer eeuwig herhalen.
	switch c.state {
	case tcpEstablished, tcpFinWait1, tcpFinWait2:
		c.processData(seg, now)
	default:
		if len(seg.data) > 0 || seg.flags.Has(FlagFIN) {
			c.needAck = true
		}
	}
}

// acceptSyn opent het luister-embryo: SYN → SYN-RCVD.
func (c *tcpConn) acceptSyn(seg tcpSeg) {
	c.state = tcpSynRcvd
	c.listen = false
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.una = c.iss
	c.nxt = c.iss
	c.dataBase = c.iss + 1
	c.takeSynOptions(seg)
	// Het venster op een SYN is nooit geschaald (RFC 7323 §2.2).
	c.sndWnd = uint32(seg.wnd)
	c.wl1, c.wl2 = seg.seq, 0
}

func (c *tcpConn) recvSynSent(seg tcpSeg, now int64) {
	if seg.flags.Has(FlagRST) {
		if seg.flags.Has(FlagACK) && seg.ack == c.iss+1 {
			c.state = tcpClosed // verbinding geweigerd
			c.refused = true
			c.timerOn = false
		}
		return
	}
	// Een ACK die onze SYN niet bevestigt, zonder RST erbij: antwoord met
	// <SEQ=SEG.ACK><CTL=RST> en blijf in SYN-SENT (RFC 9293 §3.10.7.3, "check the
	// ACK bit"). Die ene RST is wat een oude verbinding aan de andere kant opruimt.
	//
	// Zonder hem kan een peer die opnieuw begint NOOIT meer verbinden vanaf
	// dezelfde poort. De andere kant houdt zijn verbinding voor levend (er is geen
	// keepalive die hem vertelt dat de bewoner weg is) en challenge-ACKt élke
	// nieuwe SYN op dat vier-tupel (RFC 5961 §4.2, hierboven in recv) — een
	// gesprek dat nergens eindigt. Onze RST is het bewijs dat die verbinding niet
	// bestaat: hij landt exact op zijn rcvNxt (dáárom SEQ=SEG.ACK), dus hij
	// passeert diens RST-validatie, en onze volgende SYN-herhaling komt bij de
	// listener uit.
	//
	// GEMETEN 12-08 op een LicheeRV: een app die HOP opnieuw plaatste belde met
	// hetzelfde vier-tupel als zijn voorganger — elk vers leannet begint zijn
	// efemere reeks op 49152 en het slot-IP is per slot vast — en kreeg eindeloos
	// "i/o timeout", terwijl een ándere poort van diezelfde server meteen
	// antwoordde. Dat verschil per poort is het handschrift van deze bug.
	if seg.flags.Has(FlagACK) && seg.ack != c.iss+1 {
		c.rst = pendingRST{seq: seg.ack, set: true}
		return
	}
	if !seg.flags.Has(FlagSYN) || !seg.flags.Has(FlagACK) {
		return // simultane open doen we niet (v1); alles anders is ruis
	}
	c.enterEstablished()
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.una = seg.ack
	c.needAck = true
	// De belofte uit onze SYN krijgt nu zijn anker (zie synWnd).
	c.promiseEdge(uint32(c.synWnd))
	c.takeSynOptions(seg)
	// SYN-segmenten zijn nooit geschaald; dit is de startwaarde van het venster.
	c.sndWnd = uint32(seg.wnd)
	c.wl1, c.wl2 = seg.seq, seg.ack
}

// enterEstablished is de gedeelde boekhouding van beide handshake-voltooiingen
// (SYN-SENT en SYN-RCVD): de SYN is bevestigd, dus er is niets meer in flight
// (review 13-08, achttiende ronde).
func (c *tcpConn) enterEstablished() {
	c.state = tcpEstablished
	c.timerOn = false
	c.timing = false
	c.backoff = 0
	// Ook de opgeblazen RTO en de opgeef-teller van een moeizame handshake
	// gaan terug naar af: zonder deze reset kostte het éérste dataverlies na
	// een SYN-verlies de volle opgestapelde backoff — tot een minuut wachten
	// op een verbinding die net bewees te leven (review 13-08,
	// achtentwintigste ronde). De eerste echte RTT-meting ijkt hem daarna.
	c.rto = tcpRTOInitial
	c.retries = 0
	// Een weigering uit de handshake (RST op een ongeldige ACK) die de pomp
	// nog niet verstuurde is nu achterhaald — én gevaarlijk: ingress en de
	// TX-pomp zijn asynchroon, dus de ongeldige en de geldige bevestiging
	// kunnen beide binnen zijn vóór emit draait, en het eerste segment van de
	// geslaagde verbinding was dan een RST naar de échte peer (review 13-08,
	// twintigste ronde).
	c.rst = pendingRST{}
}

// takeSynOptions verwerkt MSS en WS van de SYN(-ACK) van de peer. WS staat
// alleen aan als béíde kanten hem boden (RFC 7323 §2.2) — de optie en de
// schaalstaat leven en sterven samen met de verbinding (BEVINDINGEN #18/#19).
func (c *tcpConn) takeSynOptions(seg tcpSeg) {
	if seg.mss != 0 {
		c.peerMSS = int(seg.mss)
		if c.peerMSS > MTU-40 {
			// Een peer-MSS boven onze MTU zou frames boven de draadmaat laten
			// bouwen; de optie is een BOVENgrens van de peer, dus klemmen mag
			// altijd (review 13-08, zevenentwintigste ronde).
			c.peerMSS = MTU - 40
		}
	}
	if seg.wsOK {
		c.wsOn = true
		c.sndWS = seg.ws
		c.rcvWS = c.advWS
		if c.sndWS > 14 {
			c.sndWS = 14 // RFC 7323 §2.3: shift boven 14 wordt afgekapt
		}
	}
}

// rcvWnd is het venster waar acceptability en RST-validatie tegen toetsen:
// wat we de peer BELOOFD hebben (advEdge), niet de fysieke vrije ring. Tussen
// een app-read en de venster-update die hem meldt is free() groter dan de
// belofte, en dan accepteerde de machine segmenten (en hun ACK-bijwerking!)
// die de peer nooit had mogen sturen (review 13-08, vijfde ronde). Vóór de
// eerste advertentie (advEdge 0) is de ring de enige maat die er is.
func (c *tcpConn) rcvWnd() uint32 {
	if c.advSet {
		if d := seqDiff(c.advEdge, c.rcvNxt); d > 0 {
			return uint32(d)
		}
		return 0
	}
	return uint32(c.rx.free())
}

// inRcvWindow rapporteert of seq binnen ons receive-venster valt.
func (c *tcpConn) inRcvWindow(seq uint32) bool {
	return seqLEQ(c.rcvNxt, seq) && seqLT(seq, c.rcvNxt+c.rcvWnd())
}

// segAcceptable is de vier-gevallen-tabel van RFC 9293 §3.10.7.4: mag dit
// segment de machine in? Het venster is rcvWnd() — wat we de peer BELOOFD
// hebben (advEdge), niet de fysieke ring; zie rcvWnd voor waarom dat verschil
// telt. SEG.LEN telt de FIN mee; de SYN niet, want die komt hier nooit
// (challenge-ACK in recv).
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
		return false // data terwijl we vol zitten: ACK met venster 0 (de probe-echo)
	default:
		// Beide toetsen door dezelfde vensterdefinitie: als die ooit verhuist,
		// splitst deze niet stilletjes (review 13-08, derde ronde).
		return c.inRcvWindow(seg.seq) || c.inRcvWindow(seg.seq+segLen-1)
	}
}

// processAck is de bevestigings-boekhouding: una/dataBase/ring opschuiven,
// venster bijwerken, RTT meten, dup-ACKs tellen en de sluitstaat-transities
// die van een ACK afhangen — met de exacte toets ack == finSeq+1
// (BEVINDINGEN #2/#3: een partiële of verouderde ACK is nooit een FIN-ACK).
func (c *tcpConn) processAck(seg tcpSeg, now int64) (accept bool) {
	ack := seg.ack
	// SYN-RCVD kent maar één geldige bevestiging: SND.UNA < ACK ≤ SND.NXT
	// (RFC 9293 §3.10.7.4, SYN-RECEIVED). Al het andere — óók ACK == ISS —
	// krijgt een reset <SEQ=SEG.ACK> en raakt de machine niet: vóór deze regel
	// gold zo'n ACK als "levensteken" en hield hij via de retry-reset een
	// embryo eeuwig vast (review 13-08).
	//
	// De maat is maxSent, niet nxt: een dubbele SYN spoelt nxt terug naar iss
	// (de SYN-ACK moet opnieuw), en als de finale ACK van de peer die
	// hertransmissie vóór was — hij kruiste de dubbele SYN op de draad — dan
	// wees ack ≤ nxt hem af en RESETTE deze regel de eigen handshake
	// (review 13-08, eenendertigste ronde). maxSent rewindt nooit.
	if c.state == tcpSynRcvd && !(seqLT(c.una, ack) && seqLEQ(ack, c.maxSent)) {
		c.rst = pendingRST{seq: ack, set: true}
		return false
	}
	switch {
	case seqLT(c.maxSent, ack):
		// ACK voor ruimte die we NOOIT verzonden: bevestig onze werkelijkheid,
		// en drop het hele segment (de aanroeper ziet accept=false). De maat
		// is maxSent, niet nxt: goBackN spoelt nxt (de retransmit-cursor)
		// terug, en een geldige cumulatieve ACK die de pomp vóór was werd dan
		// als "future" geweigerd — bij een gekrompen venster zelfs blijvend,
		// want tot dat punt zenden kon niet meer (review 13-08,
		// negenentwintigste ronde).
		c.needAck = true
		return false
	case seqLT(ack, c.una):
		// Géén duplicaat (verkeerd ack-nummer, RFC 5681 §2): breekt dus ook
		// de dup-reeks — "twee duplicaten, oud ACK, duplicaat" telde anders
		// gewoon door naar fast retransmit (review 13-08, eenentwintigste
		// ronde).
		c.dupacks = 0
		return true // oude ACK: negeren, maar de data van het segment mag nog
	}

	if c.state == tcpSynRcvd {
		// De poort bovenaan garandeert dat déze ACK de enige geldige is
		// (UNA < ACK ≤ NXT, en dat bereik is in SYN-RCVD precies {ISS+1}).
		// Venster en wl1/wl2 zet de algemene update hieronder — mét schaling;
		// acceptSyn liet wl1 op irs staan, dus die update vuurt op dit segment
		// gegarandeerd. De ongeschaalde voordringer die hier stond was dubbel
		// en heel even fout (review 13-08).
		c.enterEstablished()
	}

	// Venster-update (RFC 9293 §3.10.7.4): alleen van segmenten die niet
	// ouder zijn dan de laatste update.
	wnd := uint32(seg.wnd)
	if c.wsOn {
		wnd <<= c.sndWS
	}
	// Vóór de update vastleggen: een duplicate ACK vereist óók een ongewijzigd
	// advertised window (RFC 5681 §2) — een shrink gleed anders de teller in
	// en telde mee richting fast retransmit (review 13-08, negentiende ronde).
	sameWnd := wnd == c.sndWnd
	if seqLT(c.wl1, seg.seq) || (c.wl1 == seg.seq && seqLEQ(c.wl2, ack)) {
		wasClosed := c.sndWnd == 0
		c.sndWnd = wnd
		c.wl1, c.wl2 = seg.seq, ack
		// De opgeef-teller reset alleen op een ACK die iets ZEGT: échte
		// voortgang (verderop, bij ack > una), of een GEACCEPTEERDE update
		// naar een dicht venster — persist-modus, RFC 9293 §3.8.6.1: een
		// levende peer die niet kán ontvangen mag eeuwig leven. Binnen de
		// WL1/WL2-poort, want de ruwe seg.wnd meetellen liet herhaalde OUDE
		// zero-window-ACKs de teller pinnen terwijl het effectieve venster
		// gewoon openstond (review 13-08, vijfde ronde).
		if c.sndWnd == 0 {
			c.retries = 0
		}
		// Gaat een dicht venster open terwijl er op ack==una nog iets in
		// flight staat, dan is dat de zero-window-probe — en die kan verloren
		// zijn. Zonder rewind begon de eerstvolgende verzending ná de
		// ontbrekende probe-byte: out-of-order bij de ontvanger, en een
		// kleine write levert nooit drie dup-ACKs, dus wachtte herstel op de
		// tijdens de persist opgebouwde RTO — tot een minuut (review 13-08,
		// zeventiende ronde). Opnieuw vanaf una is altijd veilig: kwam de
		// probe wél aan, dan is het ene dubbele byte gewoon her-ACKt.
		if wasClosed && wnd > 0 {
			// De persist-episode is voorbij: eigen backoff weg, en de (ver
			// uitgestelde) persist-deadline ook — de eerstvolgende verzending
			// wapent via postTx een verse, onvervuilde RTO (review 13-08,
			// negentiende ronde).
			c.persistBackoff = 0
			c.timerOn = false
			if ack == c.una && c.una != c.nxt {
				c.goBackN()
			}
		}
	}

	if ack == c.una {
		// Duplicate ACK (RFC 5681 §2): geen data, geen SYN/FIN, zelfde ack,
		// ongewijzigd venster, én iets in flight. Drie op rij → één go-back-N
		// zonder op de RTO te wachten; bewust niet op staat gegokt: ook in
		// FIN-WAIT-1/CLOSING/LAST-ACK telt dit door (BEVINDINGEN #15). Alles
		// wat één criterium mist is géén duplicaat en BREEKT de reeks: "twee
		// duplicaten, shrink, duplicaat" telde anders gewoon door naar fast
		// retransmit, en een FIN met hetzelfde ack telde ook mee
		// (review 13-08, twintigste ronde). SYN komt hier nooit (challenge
		// hierboven).
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

	// ack > una: echte voortgang.
	dataAcked := seqDiff(ack, c.dataBase)
	if dataAcked > 0 {
		if dataAcked > c.tx.buffered() {
			dataAcked = c.tx.buffered() // SYN/FIN-randen: die tellen niet als ringdata
		}
		// De ACK kan de hertransmissie vóór zijn geweest (goBackN spoelde de
		// sent-cursor terug): wat bevestigd wordt wás verzonden — eerst
		// terugboeken, dan pas poppen (zie txRing.forceSent).
		c.tx.forceSent(dataAcked)
		c.tx.ack(dataAcked)
		c.dataBase += uint32(dataAcked)
	}
	c.una = ack
	if seqLT(c.nxt, ack) {
		// De ACK ligt vóórbij de (door goBackN teruggespoelde) zendcursor:
		// alles tot ack is bevestigd, dus daar hoeft niets meer heen — cursor
		// bijtrekken (review 13-08, negenentwintigste ronde).
		c.nxt = ack
	}
	c.dupacks = 0
	c.retries = 0 // échte voortgang: hét levensteken
	c.persistBackoff = 0

	// Nú pas krimpen, met de bijgewerkte boekhouding: dít segment kan de ACK
	// zijn die de ring leegmaakt, en op een gepoolde verbinding is het ook het
	// LAATSTE segment — er komt geen venster-update meer achteraan die het
	// alsnog zou doen. (De eerste versie van deze aanroep stond vóór
	// `c.una = ack` en vuurde dus alleen op ná-verkeer; de test haalde het
	// daardoor wél en het gemeten scenario niet — review 13-08.) Een FIN die
	// nog in flight is houdt niets tegen: die neemt sequence-ruimte in, geen
	// ringruimte, en een go-back-N regenereert hem zonder buffer.
	c.shrinkTx()

	// RTT-meting (Karn: alleen als het bemeten segment niet hergezonden is).
	if c.timing && seqLEQ(c.timedSeq, ack) {
		c.updateRTT(time.Duration(now - c.timedAt))
		c.timing = false
		c.backoff = 0
	}

	// Timer (RFC 6298 §5.2/§5.3): alles bevestigd → uit; anders herstarten.
	if c.una == c.nxt {
		c.timerOn = false
	} else {
		c.timerOn = true
		c.deadline = now + int64(c.currentRTO())
	}

	// De sluit-transities die een bevestigde FIN eisen.
	if c.closing && ack == c.finSeq+1 {
		switch c.state {
		case tcpFinWait1:
			c.state = tcpFinWait2
			c.twDeadline = now + tcpFinWait2Dur // zie tcpFinWait2Dur
		case tcpClosing:
			c.state = tcpTimeWait
			c.twDeadline = now + tcpTimeWaitDur
		case tcpLastAck:
			c.state = tcpClosed
			c.timerOn = false
		}
		// De FIN is bevestigd, dus álles is bevestigd: ook de zendring kan
		// terug de pot in — FIN-WAIT-2 mag 20s duren en TIME-WAIT 1s, en al
		// die tijd 20KiB vasthouden was precies het pool-evictie-lek
		// (review 13-08, achtentwintigste ronde). reap ziet daarna maat nul.
		if c.pot != nil && c.tx.buffered() == 0 {
			c.pot.release(c.tx.size())
			c.tx = txRing{}
		}
	}
	return true
}

// processData verwerkt payload en peer-FIN, in-order-only: alles wat niet
// exact op rcv.NXT aansluit wordt gedropt met een directe dup-ACK, zodat de
// peer zonder onze reassembly toch snel herstelt.
func (c *tcpConn) processData(seg tcpSeg, now int64) {
	dataLen := len(seg.data)
	segEnd := seg.seq + uint32(dataLen)
	hasFin := seg.flags.Has(FlagFIN)

	// Oude-prefix-trim (RFC 9293 §3.10.7.4): een retransmissie kan vóór
	// rcvNxt beginnen maar nieuwe bytes dragen (oude prefix + nieuwe suffix).
	// segAcceptable laat hem terecht door — hij overlapt het venster — maar
	// het exact-op-rcvNxt-vereiste verderop dropte dan het héle segment,
	// nieuwe bytes incluis (review 13-08, vijfentwintigste ronde).
	if d := seqDiff(c.rcvNxt, seg.seq); d > 0 && dataLen > 0 {
		if d >= dataLen {
			seg.data, dataLen = nil, 0 // alles al gezien; hooguit de FIN telt nog
		} else {
			seg.data = seg.data[d:]
			dataLen -= d
		}
		seg.seq = c.rcvNxt
		segEnd = seg.seq + uint32(dataLen)
	}

	// Trim op de geadverteerde rand (RFC 9293 §3.10.7.4: verwerk alleen wat in
	// het venster valt). Zonder deze knip absorbeerde processData een segment
	// dat op rcv.NXT begint maar vóórbij onze belofte doorloopt in zijn geheel
	// — de groei-op-vol deed de ring dan groeien op commando van de peer, tot
	// maxBuf, dwars door het venster heen (review 13-08). De staart (en een
	// FIN die erachter ligt) komt in de retransmissie terug, dán binnen het
	// venster dat de eerstvolgende ACK adverteert. Vóór de eerste advertentie
	// (advSet uit) laat dit de oude cap-op-free staan: die belofte was
	// hoogstens de floor-ring, en daar knipt rx.write vanzelf.
	if c.advSet {
		allowed := seqDiff(c.advEdge, seg.seq)
		// De FIN neemt één sequence-plek NÁ de data in: hij valt alleen binnen
		// het venster als er na de data nog ruimte is (allowed > dataLen). Dit
		// dekt ook de kale FIN (dataLen 0, allowed ≤ 0) en het randgeval waar
		// de payload het venster PRECIES vult — daar bleef de FIN eerst staan
		// terwijl hij één byte buiten de belofte lag (review 13-08).
		if hasFin && allowed <= dataLen {
			hasFin = false
			c.needAck = true // de peer herhaalt de FIN zodra ons venster ruimte biedt
		}
		if allowed < dataLen {
			// allowed is hier altijd ≥ 1: segAcceptable toetst tegen dezelfde
			// belofte (rcvWnd), dus een data-dragend segment komt de machine
			// alleen in als het met [rcvNxt, advEdge) overlapt — de
			// allowed<=0-tak die hier stond was sindsdien onbereikbaar
			// (review 13-08, achtste ronde).
			dataLen = allowed
			seg.data = seg.data[:allowed]
			segEnd = seg.seq + uint32(dataLen)
		}
	}

	if dataLen > 0 {
		if seg.seq != c.rcvNxt {
			c.needAck = true // dup-ACK: vertelt de peer wat we wél hebben
			return
		}
		if c.appClosed {
			// Niemand leest ooit nog: binnen de belofte tellen en weggooien,
			// zodat de peer zijn ACK krijgt en zijn FIN kan landen (zie
			// appClosed bij de velden).
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
		if c.rx.free() == 0 && c.advSet {
			// De peer vult ons venster tot de rand: het groeisignaal voor de
			// ontvangkant. Groeien kan mid-ontvangst — het venster wordt er
			// alleen maar groter van, reneg-en kan zo niet ontstaan. Maar pas
			// NÁ de eerste advertentie: vóór advEdge is de belofte de SYN-raw
			// (≤ de floor), en zonder deze rem kon data op de derde
			// handshake-ACK de ring voorbij dat SYN-venster laten groeien
			// (review 13-08).
			if c.growRing(&c.rx) && n < dataLen {
				m := c.rx.write(seg.data[n:])
				c.rcvNxt += uint32(m)
				n += m
			}
		}
		if n < dataLen {
			// Venster vol: de staart (en een eventuele FIN erachter) komt in
			// de retransmissie van de peer terug.
			return
		}
	}
fin:
	if hasFin {
		if segEnd != c.rcvNxt {
			c.needAck = true // out-of-order FIN: zelfde dup-ACK-pad
			return
		}
		c.rcvNxt++
		c.finRcvd = true
		c.needAck = true
		switch c.state {
		case tcpEstablished:
			c.state = tcpCloseWait
		case tcpFinWait1:
			// Onze FIN is nog niet bevestigd (anders waren we al FIN-WAIT-2):
			// simultane sluiting.
			c.state = tcpClosing
		case tcpFinWait2:
			c.state = tcpTimeWait
			c.twDeadline = now + tcpTimeWaitDur
		}
	}
}

// ---- verzending ----

// emit produceert het volgende uitgaande segment, met payload geschreven in
// buf. ok=false betekent: niets te doen. De aanroeper blijft emit'en tot
// ok=false — één verbinding kan meerdere segmenten klaar hebben staan (een
// burst na een venster-opening, data + FIN, ...).
func (c *tcpConn) emit(buf []byte, now int64) (seg tcpSeg, ok bool) {
	if seg, ok := c.takeRST(); ok {
		// De klaarstaande afscheids-RST (abort of onacceptabele ACK) gaat
		// vóór alles: gewoon het eerstvolgende segment, geen vlag-en-leeg-
		// protocol dat elke recv-aanroeper moest kennen (review 13-08,
		// vijfde ronde; samengevouwen in de achttiende).
		return seg, true
	}
	switch c.state {
	case tcpClosed:
		return tcpSeg{}, false
	case tcpFinWait2:
		if now >= c.twDeadline {
			// De peer bevestigde onze FIN maar sluit zelf nooit: opgeven, luid.
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

	// Een dicht peer-venster met wachtend werk houdt de timer gewapend: de
	// venster-opening komt als onbetrouwbare kale ACK en kan zoekraken, dus
	// zonder probe is dit een deadlock.
	if !c.timerOn && c.sndWnd == 0 && (c.tx.unsent() > 0 || c.finPending()) {
		c.armTimer(now)
	}

	// De retransmissietimer (RFC 6298 §5.4-§5.6). Omdat SYN en FIN gewoon
	// sequence-ruimte innemen is 'iets in flight' hier per definitie ook 'de
	// timer bewaakt het' — een verloren kale FIN heeft dus een deadline
	// (BEVINDINGEN #1).
	if c.timerOn && now >= c.deadline {
		c.retries++
		limit := uint8(tcpMaxRetriesData)
		if c.state == tcpSynSent || c.state == tcpSynRcvd {
			limit = tcpMaxRetriesHandshake
		}
		if c.retries > limit {
			// De peer zwijgt al de hele backoff-ladder: opgeven, luid.
			return c.abortWithRST()
		}
		if c.sndWnd == 0 && seqDiff(c.nxt, c.una) <= 1 &&
			(c.tx.buffered() > 0 || c.finPending()) {
			// Persist (RFC 9293 §3.8.6.1): hooguit de probe-byte in flight en
			// het venster dicht. Eigen backoff-ladder — élke probe verdubbelde
			// eerst c.rto mee, en die vervuiling bleef ná de venster-opening
			// staan: verlies van de directe hertransmissie kostte dan opnieuw
			// bijna een minuut (review 13-08, negentiende ronde). De
			// RTT/RTO-estimator blijft hier dus ongemoeid.
			if c.persistBackoff < tcpBackoffMax {
				c.persistBackoff++
			}
			c.deadline = now + int64(min(c.currentRTO()*(1<<c.persistBackoff), tcpRTOMax))
			if c.una != c.nxt {
				c.goBackN() // de vorige probe-byte gaat opnieuw mee
			}
			c.probe = true // zero-window-probe: één byte voorbij het venster
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

	// Handshake-segmenten: zolang nxt nog op iss staat is de SYN(‑ACK) (of
	// zijn retransmissie na go-back-N) aan de beurt.
	if (c.state == tcpSynSent || c.state == tcpSynRcvd) && c.nxt == c.iss {
		c.nxt = c.iss + 1
		if seqLT(c.maxSent, c.nxt) {
			c.maxSent = c.nxt // de SYN neemt sequence-ruimte in: zijn ACK is geen future
		}
		c.armTimer(now)
		// Het venster op een SYN is nooit geschaald; en op een SYN|ACK mag de
		// WS-optie alleen mee als de peer hem zelf bood (RFC 7323 §2.2).
		seg = tcpSeg{seq: c.iss, flags: FlagSYN, wnd: c.rawWnd(),
			mss: c.advMSS, wsOK: true, ws: c.advWS}
		if c.state == tcpSynRcvd {
			seg.flags |= FlagACK
			seg.ack = c.rcvNxt
			seg.wsOK = c.wsOn
			// De SYN-ACK-advertentie is een gedane belofte: vastleggen, anders
			// viel rcvWnd tot de eerste gewone ACK terug op de fysieke ring en
			// accepteerde een snelle peer data voorbij de beloofde rand
			// (review 13-08, vierentwintigste ronde). SYN-vensters zijn nooit
			// geschaald.
			c.promiseEdge(uint32(seg.wnd))
		} else {
			c.synWnd = seg.wnd // actieve open: rcvNxt volgt pas met de SYN-ACK
		}
		return seg, true
	}
	if c.state == tcpSynSent || c.state == tcpSynRcvd {
		return tcpSeg{}, false // SYN in flight; wachten op antwoord of timer
	}

	// Datapad. Venster-hoofdruimte in octetten; een gewapende probe mag er
	// één byte doorheen persen om een stil geopend venster te ontdekken.
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
		// FIN meeliften als dit de laatste data was en het venster het toelaat.
		if c.finPending() && c.nxt == c.finSeq && inFlight+got < int(c.sndWnd) {
			seg.flags |= FlagFIN
			c.sendFinBookkeeping(now)
		}
		c.needAck = false
		return seg, true
	}

	// Kale FIN (geen data meer, wel sluiten) — ook dit is gewoon een stap in
	// sequence-ruimte, met timer, en dus ónder de vensterdiscipline: bij een
	// vol of dicht zendvenster wacht hij op ruimte of op de persist-probe —
	// onvoorwaardelijk versturen zette hem één sequence-plek buiten het
	// peer-venster (review 13-08, vierentwintigste ronde). Stond de probe
	// gewapend, dan ís de FIN de probe: verbruik de vlag, anders blijft hij
	// staan en perst hij later ongevraagd een databyte door een dicht venster.
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

// abortWithRST kapt af en levert de afscheids-RST in dezelfde emit-reeks —
// er is geen aparte reaper die hem anders zou dragen (TestTCPHalfOpenGivesUp
// pint dat), dus de abort en zijn RST horen bij elkaar.
func (c *tcpConn) abortWithRST() (tcpSeg, bool) {
	c.abort()
	return c.takeRST()
}

// takeRST verbruikt de klaarstaande afscheids-RST en bouwt zijn segment — de
// ENE plek die de vorm kent. emit en abortWithRST hadden er elk een, waarvan
// de tweede het ACK-deel hardcodeerde; dat dat klopte (abort zet altijd
// withAck) wist alleen wie beide plekken naast elkaar legde (review 13-08,
// zesentwintigste ronde).
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

// finPending rapporteert of onze FIN nog verzonden moet worden — óók na een
// go-back-N die nxt onder finSeq terugzette (dan gaat hij gewoon opnieuw mee).
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

// sendFinBookkeeping schuift nxt over de FIN en doet de staatstransitie.
func (c *tcpConn) sendFinBookkeeping(now int64) {
	c.nxt = c.finSeq + 1
	if seqLT(c.maxSent, c.nxt) {
		c.maxSent = c.nxt // ook de FIN neemt sequence-ruimte in (zie de future-poort)
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
	// seq is maxSent, niet nxt: een kale ACK draagt SND.NXT (RFC 9293 §3.9),
	// en dat is de verste ooit verzonden rand — nxt is onze retransmit-cursor
	// en staat na een go-back-N tijdelijk terug (review 13-08, eenendertigste
	// ronde; semantiek, geen aangetoond falen).
	return tcpSeg{seq: c.maxSent, ack: c.rcvNxt, flags: FlagACK, wnd: c.advertisedWnd()}
}

// rawWnd is het ongeschaalde venster voor SYN-segmenten.
func (c *tcpConn) rawWnd() uint16 {
	if w := c.rx.free(); w < 0xffff {
		return uint16(w)
	}
	return 0xffff
}

// goBackN spoelt de zendkant terug naar una: ring-cursor én nxt. Alles wat
// onbevestigd is — data, FIN, een SYN in de handshake — wordt vanzelf
// geregenereerd door emit.
func (c *tcpConn) goBackN() {
	c.tx.rewind()
	// De ringkop staat op dataBase; una kan daarvóór liggen (SYN in flight).
	if syn := seqDiff(c.dataBase, c.una); syn > 0 {
		c.nxt = c.iss // handshake opnieuw
	} else {
		c.nxt = c.una
		// Cursor vooruitzetten tot una: bevestigde bytes zijn de ring al uit,
		// dus una-dataBase is 0 — de rewind naar de kop ís de juiste positie.
	}
	c.timing = false // Karn: hergezonden segmenten niet bemeten
}

// postTx administreert nieuw verzonden sequence-ruimte: RTT-sample starten en
// de timer wapenen (RFC 6298 §5.1).
func (c *tcpConn) postTx(segEnd uint32, now int64) {
	// Karn volledig: een sample start alléén op sequence-ruimte die nog nooit
	// eerder verzonden is. goBackN zette timing=false, maar de hertransmissie
	// zelf startte hier meteen een verse meting op óude ruimte — en de ACK
	// daarvan is ambigu (bevestigt hij het origineel of de hertransmissie?),
	// dus vouwde een gok in updateRTT en zette backoff=0: een ambigu ACK kon
	// de RTO zo naar 200ms laten instorten (review 13-08, negentiende ronde).
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

// nextDeadline geeft de vroegste wektijd van deze verbinding, of 0 als er geen
// timer loopt — de ene plek die weet welke staten een tijdslot dragen, zodat de
// pomp dat niet hoeft te spiegelen (dat spiegelen kostte de FIN-WAIT-2-fix twee
// edits, review 13-08, vijfde ronde). De retransmissietimer en de tw-deadline
// sluiten elkaar in de praktijk uit (in FIN-WAIT-2/TIME-WAIT is alles
// bevestigd, dus timerOn is uit); de timer wint als ze ooit samenvallen.
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

// updateRTT vouwt een meting in SRTT/RTTVAR/RTO (RFC 6298 §2.2/§2.3).
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
