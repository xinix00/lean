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
	// budget) betekent: nooit groeien. Krimpen bestaat niet; close geeft
	// alles in één keer terug (de stack-laag stort de ringmaten terug).
	pot    *budget
	maxBuf int

	// Besturing.
	needAck bool // er is iets te bevestigen (data, FIN, dup, challenge)
	rstOut  bool

	// RTO (RFC 6298) + Karn-sampling.
	srtt, rttvar, rto time.Duration
	haveRTT           bool
	timerOn           bool
	deadline          int64
	backoff           uint8
	timing            bool
	timedSeq          uint32
	timedAt           int64

	// Fast retransmit (RFC 5681 §3.2, de simpele vorm).
	dupacks uint8

	// Opgeef-boekhouding: RTO-vuringen sinds de laatste geldige ACK.
	retries uint8
	// refused onderscheidt "peer zei nee" (RST op onze SYN) van "peer zweeg"
	// (opgegeven na retries) — de socket-laag maakt er twee fouten van.
	refused bool

	// Zero-window-probe: gezet door de timer, verbruikt door één 1-byte-probe.
	probe bool

	twDeadline int64
}

// openActive start een uitgaande verbinding: de eerstvolgende emit stuurt de
// SYN. Rings en budget-koppeling overleven de reset — die zijn van de eigenaar.
func (c *tcpConn) openActive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpSynSent, iss: iss, una: iss, nxt: iss,
		dataBase: iss + 1, advMSS: advMSS, advWS: advWS,
		rto: tcpRTOInitial, peerMSS: tcpDefaultMSS,
		rx: c.rx, tx: c.tx, pot: c.pot, maxBuf: c.maxBuf}
}

// openPassive maakt de verbinding een luister-embryo: een binnenkomende SYN
// opent hem naar SYN-RCVD. De listener-laag kloont hier één per handshake van.
func (c *tcpConn) openPassive(iss uint32, advMSS uint16, advWS uint8) {
	*c = tcpConn{state: tcpClosed, listen: true, iss: iss,
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

// abort kapt de verbinding hard af: één RST eruit, daarna is alles dood.
func (c *tcpConn) abort() {
	if c.state != tcpClosed && c.state != tcpSynSent {
		c.rstOut = true
	}
	c.state = tcpClosed
	c.timerOn = false
}

// write neemt applicatiebytes op in de zendring (zoveel als past). Een volle
// ring terwijl de peer méér venster biedt is het groeisignaal voor de
// zendkant: er ís vraag, wij zijn de rem.
func (c *tcpConn) write(p []byte) (int, error) {
	if c.closing || (c.state != tcpEstablished && c.state != tcpCloseWait) {
		return 0, errTCPClosed
	}
	n := c.tx.writeApp(p)
	for n < len(p) && int(c.sndWnd) > c.tx.size() && c.growRing(&c.tx.ring) {
		n += c.tx.writeApp(p[n:])
	}
	return n, nil
}

// growRing verdubbelt r binnen maxBuf en de pot; false = niet gegroeid.
func (c *tcpConn) growRing(r *ring) bool {
	if c.pot == nil || r.size() >= c.maxBuf {
		return false
	}
	newSize := r.size() * 2
	if newSize > c.maxBuf {
		newSize = c.maxBuf
	}
	delta := newSize - r.size()
	if delta <= 0 || !c.pot.reserve(delta) {
		return false // pot leeg: klein blijven is geen fout, alleen langzamer
	}
	r.grow(make([]byte, newSize))
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
	return n, nil
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
	return uint16(w)
}

// ---- ontvangst ----

// recv verwerkt één binnengekomen segment. De stack-laag heeft checksum en
// demux al gedaan; hier leeft alleen de RFC-machine.
func (c *tcpConn) recv(seg tcpSeg, now int64) {
	if c.state == tcpClosed {
		if c.listen && seg.flags.Has(FlagSYN) && !seg.flags.Has(FlagACK|FlagRST) {
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

	c.processAck(seg, now)

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
	if !seg.flags.Has(FlagSYN) || !seg.flags.Has(FlagACK) || seg.ack != c.iss+1 {
		return // simultane open doen we niet (v1); alles anders is ruis
	}
	c.state = tcpEstablished
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.una = seg.ack
	c.needAck = true
	c.takeSynOptions(seg)
	// SYN-segmenten zijn nooit geschaald; dit is de startwaarde van het venster.
	c.sndWnd = uint32(seg.wnd)
	c.wl1, c.wl2 = seg.seq, seg.ack
	c.timerOn = false // de SYN is bevestigd; er is niets meer in flight
	c.timing = false
	c.backoff = 0
}

// takeSynOptions verwerkt MSS en WS van de SYN(-ACK) van de peer. WS staat
// alleen aan als béíde kanten hem boden (RFC 7323 §2.2) — de optie en de
// schaalstaat leven en sterven samen met de verbinding (BEVINDINGEN #18/#19).
func (c *tcpConn) takeSynOptions(seg tcpSeg) {
	if seg.mss != 0 {
		c.peerMSS = int(seg.mss)
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

// inRcvWindow rapporteert of seq binnen ons receive-venster valt.
func (c *tcpConn) inRcvWindow(seq uint32) bool {
	return seqLEQ(c.rcvNxt, seq) && seqLT(seq, c.rcvNxt+uint32(c.rx.free()))
}

// processAck is de bevestigings-boekhouding: una/dataBase/ring opschuiven,
// venster bijwerken, RTT meten, dup-ACKs tellen en de sluitstaat-transities
// die van een ACK afhangen — met de exacte toets ack == finSeq+1
// (BEVINDINGEN #2/#3: een partiële of verouderde ACK is nooit een FIN-ACK).
func (c *tcpConn) processAck(seg tcpSeg, now int64) {
	ack := seg.ack
	switch {
	case seqLT(c.nxt, ack):
		// ACK voor iets dat we nog niet stuurden: bevestig onze werkelijkheid.
		c.needAck = true
		return
	case seqLT(ack, c.una):
		return // oud, negeren
	}

	// Een geldige ACK — óók zonder voortgang — is een levensteken: de
	// opgeef-teller mag terug naar nul (zero-window-peers leven van dup-ACKs).
	c.retries = 0

	if c.state == tcpSynRcvd && ack == c.iss+1 {
		c.state = tcpEstablished
		c.sndWnd = uint32(seg.wnd) // eerste echte venster; ACK op onze SYN|ACK is al post-SYN maar ongescaled bijwerken hieronder overschrijft zo nodig
		c.wl1, c.wl2 = seg.seq, seg.ack
		c.timerOn = false
		c.timing = false
		c.backoff = 0
	}

	// Venster-update (RFC 9293 §3.10.7.4): alleen van segmenten die niet
	// ouder zijn dan de laatste update.
	wnd := uint32(seg.wnd)
	if c.wsOn {
		wnd <<= c.sndWS
	}
	if seqLT(c.wl1, seg.seq) || (c.wl1 == seg.seq && seqLEQ(c.wl2, ack)) {
		grew := wnd > c.sndWnd
		c.sndWnd = wnd
		c.wl1, c.wl2 = seg.seq, ack
		if grew {
			c.dupacks = 0 // een venster-update is geen duplicaat-signaal
		}
	}

	if ack == c.una {
		// Mogelijk een dup-ACK (RFC 5681): zelfde ack, geen data, met iets in
		// flight. Drie op rij → één go-back-N zonder op de RTO te wachten.
		// Bewust niet op staat gegokt: ook in FIN-WAIT-1/CLOSING/LAST-ACK
		// telt dit gewoon door (BEVINDINGEN #15).
		if len(seg.data) == 0 && c.una != c.nxt {
			c.dupacks++
			if c.dupacks == 3 {
				c.goBackN()
			}
		}
		return
	}

	// ack > una: echte voortgang.
	acked := seqDiff(ack, c.una)
	_ = acked
	dataAcked := seqDiff(ack, c.dataBase)
	if dataAcked > 0 {
		if dataAcked > c.tx.buffered() {
			dataAcked = c.tx.buffered() // SYN/FIN-randen: die tellen niet als ringdata
		}
		c.tx.ack(dataAcked)
		c.dataBase += uint32(dataAcked)
	}
	c.una = ack
	c.dupacks = 0

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
		case tcpClosing:
			c.state = tcpTimeWait
			c.twDeadline = now + tcpTimeWaitDur
		case tcpLastAck:
			c.state = tcpClosed
			c.timerOn = false
		}
	}
}

// processData verwerkt payload en peer-FIN, in-order-only: alles wat niet
// exact op rcv.NXT aansluit wordt gedropt met een directe dup-ACK, zodat de
// peer zonder onze reassembly toch snel herstelt.
func (c *tcpConn) processData(seg tcpSeg, now int64) {
	dataLen := len(seg.data)
	segEnd := seg.seq + uint32(dataLen)
	hasFin := seg.flags.Has(FlagFIN)

	if dataLen > 0 {
		if seg.seq != c.rcvNxt {
			c.needAck = true // dup-ACK: vertelt de peer wat we wél hebben
			return
		}
		n := c.rx.write(seg.data)
		c.rcvNxt += uint32(n)
		c.needAck = true
		if c.rx.free() == 0 {
			// De peer vult ons venster tot de rand: het groeisignaal voor de
			// ontvangkant. Groeien kan mid-ontvangst — het venster wordt er
			// alleen maar groter van, reneg-en kan zo niet ontstaan.
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
	if c.rstOut {
		c.rstOut = false
		return tcpSeg{seq: c.nxt, ack: c.rcvNxt, flags: FlagRST | FlagACK}, true
	}
	switch c.state {
	case tcpClosed:
		return tcpSeg{}, false
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
			// De peer zwijgt al de hele backoff-ladder: opgeven, luid. De
			// abort zet de RST klaar; die gaat nu meteen mee naar buiten.
			c.abort()
			if c.rstOut {
				c.rstOut = false
				return tcpSeg{seq: c.nxt, ack: c.rcvNxt, flags: FlagRST | FlagACK}, true
			}
			return tcpSeg{}, false
		}
		if c.backoff < tcpBackoffMax {
			c.backoff++
			c.rto = min(c.currentRTO()*2, tcpRTOMax)
		}
		c.deadline = now + int64(c.currentRTO())
		if c.una != c.nxt {
			c.goBackN()
		} else if c.sndWnd == 0 && (c.tx.unsent() > 0 || c.finPending()) {
			c.probe = true // zero-window-probe: één byte voorbij het venster
		}
	}

	// Handshake-segmenten: zolang nxt nog op iss staat is de SYN(‑ACK) (of
	// zijn retransmissie na go-back-N) aan de beurt.
	if (c.state == tcpSynSent || c.state == tcpSynRcvd) && c.nxt == c.iss {
		c.nxt = c.iss + 1
		c.armTimer(now)
		// Het venster op een SYN is nooit geschaald; en op een SYN|ACK mag de
		// WS-optie alleen mee als de peer hem zelf bood (RFC 7323 §2.2).
		seg = tcpSeg{seq: c.iss, flags: FlagSYN, wnd: c.rawWnd(),
			mss: c.advMSS, wsOK: true, ws: c.advWS}
		if c.state == tcpSynRcvd {
			seg.flags |= FlagACK
			seg.ack = c.rcvNxt
			seg.wsOK = c.wsOn
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
	// sequence-ruimte, met timer.
	if c.finPending() && c.nxt == c.finSeq {
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
	c.armTimer(now)
	switch c.state {
	case tcpEstablished:
		c.state = tcpFinWait1
	case tcpCloseWait:
		c.state = tcpLastAck
	}
}

func (c *tcpConn) bareAck() tcpSeg {
	return tcpSeg{seq: c.nxt, ack: c.rcvNxt, flags: FlagACK, wnd: c.advertisedWnd()}
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
	if !c.timing {
		c.timing = true
		c.timedSeq = segEnd
		c.timedAt = now
	}
	c.armTimer(now)
}

func (c *tcpConn) armTimer(now int64) {
	if !c.timerOn {
		c.timerOn = true
		c.deadline = now + int64(c.currentRTO())
	}
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
