package leannet

// arp.go — de ARP-machine (RFC 826, alleen ethernet/IPv4). Puur zoals de rest
// van het package: geen goroutines, geen klok — resolve/recv/emit krijgen een
// monotone nanoseconde-tijd aangereikt. De stack-laag pompt: binnenkomende
// ARP-payloads gaan naar recv, uitgaande pakketten komen uit emit (loop tot
// ok=false), en een verzender pollt resolve tot hij een MAC heeft of via
// noAnswer ziet dat de query luid is opgegeven.
//
// Geen callbacks, bewust. lneto's resolve-callback-vlag had een levenscyclus
// die nergens eindigde (BEVINDINGEN #20: elke latere gratuitous reply
// hervuurde de callback voor een adres dat niemand opnieuw vroeg). In het
// poll-model bestaat die levenscyclus niet: er wordt geen vlag gezet, dus er
// valt geen vlag te wissen — de vraagsteller haalt het antwoord zelf op.
//
// De tabel is niet zelf-vergrendeld: de stack-laag houdt één lock over
// resolve/recv/emit/seed — één mutex-regime, cache-mutaties altijd onder
// hetzelfde slot als ingress (BEVINDINGEN #11, zelfde afspraak als ring.go).

import "time"

// Tijd- en poging-constanten. Alle tijden zijn monotone nanoseconden.
const (
	arpEntryTTL   = int64(120 * time.Second) // levensduur van een opgelost antwoord
	arpRetryIval  = int64(time.Second)       // vaste tussenpoos tussen queries
	arpQueryTries = 5                        // zoveel queries, dan luid opgeven

	// Een opgegeven query blijft even als "geen antwoord" staan: de wachtende
	// verzender ziet de status (noAnswer) en een dode host wordt niet
	// eindeloos bestookt. Daarna mag een verse resolve opnieuw beginnen.
	arpFailTTL = int64(5 * time.Second)

	// Meer dan zoveel wachtende reply-antwoorden droppen we (met teller):
	// een request-flood mag de tabel geen geheugen laten groeien.
	arpReplyQueueCap = 8

	// arpCacheCap begrenst de hele tabel. Passief leren is gratis voor de
	// afzender: een stroom frames met gespoofde bron-IP's (de transport-
	// checksum is geen authenticatie) maakte anders per frame een entry — op
	// een node van 64MB is een onbegrensde map een DoS (review 13-08,
	// dertiende ronde). Een HOP-node praat met een handvol peers; 128 is daar
	// ruim boven en kost hooguit ~15KB.
	arpCacheCap = 128
)

// arpState — de drie levensfasen van een entry.
type arpState uint8

const (
	arpPending  arpState = iota // query loopt, MAC nog onbekend
	arpResolved                 // MAC bekend, verloopt op born+arpEntryTTL
	arpFailed                   // luid opgegeven; negatieve cache tot born+arpFailTTL
)

// arpEntry is de staat van één IP in de tabel.
type arpEntry struct {
	mac    [6]byte
	state  arpState
	static bool  // seed: verloopt nooit en wordt niet ververst
	born   int64 // aanmaak/refresh (arpResolved) of moment van opgeven (arpFailed)
	tries  int   // verzonden queries (arpPending)
	due    int64 // volgende query-moment (arpPending)
}

// arpReply is een klaarstaand antwoord op een request voor ons IP.
type arpReply struct {
	hw [6]byte
	ip [4]byte
}

// arpTable koppelt IPv4-adressen aan MAC's en drijft de query-cyclus.
type arpTable struct {
	ourIP  [4]byte
	ourMAC [6]byte

	// Eén entry per IP, altijd: de map-sleutel ís de dedup. lneto's
	// acquireNext maakte per racende resolver een verse entry aan en lekte
	// de rest tot de cache vol zat (BEVINDINGEN #12); hier kán die toestand
	// niet bestaan.
	entries map[[4]byte]*arpEntry

	// Wachtende replies op requests voor ons IP; emit werkt ze af.
	replies []arpReply

	// Tellers voor de stack-laag (telemetrie/logregels; de machine zelf
	// logt niet). Eén blok: Stats() kopieert hem in z'n geheel, dus een
	// nieuwe teller reist vanzelf mee (review 13-08, achttiende ronde).
	cnt ARPStats
}

func newARPTable(ourIP [4]byte, ourMAC [6]byte) *arpTable {
	return &arpTable{ourIP: ourIP, ourMAC: ourMAC, entries: make(map[[4]byte]*arpEntry)}
}

// tick werkt de tijdsafhankelijke staat van één entry bij: een pending query
// die na de laatste poging zijn tussenpoos zonder antwoord uitzat geeft luid
// op, en verlopen entries (opgelost óf opgegeven) verdwijnen. false = de
// entry bestaat niet meer.
func (t *arpTable) tick(ip [4]byte, e *arpEntry, now int64) bool {
	switch e.state {
	case arpPending:
		if e.tries >= arpQueryTries && now >= e.due {
			e.state = arpFailed
			e.born = now
			t.cnt.GaveUp++
		}
	case arpResolved:
		if !e.static && now-e.born >= arpEntryTTL {
			delete(t.entries, ip)
			return false
		}
	case arpFailed:
		if now-e.born >= arpFailTTL {
			delete(t.entries, ip)
			return false
		}
	}
	return true
}

// resolve geeft het MAC voor ip (ok=true) of zet een query in gang (ok=false);
// emit verstuurt hem. Loopt er al een query voor ip, dan dedupt de aanroep
// daarop: er komt géén tweede entry en géén extra pakket op de draad
// (BEVINDINGEN #12). Na luid opgeven blijft resolve ok=false geven zónder een
// nieuwe query te starten (negatieve cache); de wachtende verzender leest die
// status via noAnswer en hoort dan te falen in plaats van eeuwig te pollen.
func (t *arpTable) resolve(ip [4]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) {
		if e.state == arpResolved {
			return e.mac, true
		}
		return mac, false // pending of failed: geen nieuwe query
	}
	// Vol? Eerst verlopen entries ruimen, dan een passief geleerde cache-plek
	// verdringen: een actieve resolve (iemand wíl dit adres) gaat vóór een
	// bewaard antwoord dat niemand vroeg. Ook dit pad is van buiten te
	// triggeren (elke refuse-RST resolvet zijn bestemming), dus ook hier
	// geldt de cap (review 13-08, dertiende ronde).
	if len(t.entries) >= arpCacheCap {
		t.sweepExpired(now)
		if len(t.entries) >= arpCacheCap {
			t.evictResolved()
		}
	}
	if len(t.entries) >= arpCacheCap {
		return mac, false // alles pending/statisch: niet aanmaken, de poller komt terug
	}
	t.entries[ip] = &arpEntry{state: arpPending, due: now}
	return mac, false
}

// sweepExpired tikt élke entry, zodat verlopen exemplaren verdwijnen — voor
// de cap-paden: eerst ruimte maken, dan pas verdringen of weigeren.
func (t *arpTable) sweepExpired(now int64) {
	for ip, e := range t.entries {
		t.tick(ip, e, now)
	}
}

// evictResolved verdringt een willekeurige opgeloste, niet-statische entry —
// alleen die soort: pending draagt een lopende query van een échte vrager en
// statisch is configuratie. Bewust niet de óudste zoeken: map-willekeur raakt
// met een handvol echte buren op 128 plekken vrijwel zeker een spoof-entry,
// en een echte peer die zijn plek verliest leert zichzelf bij zijn volgende
// pakket gewoon terug (review 13-08, achttiende ronde).
func (t *arpTable) evictResolved() {
	for ip, e := range t.entries {
		if e.state == arpResolved && !e.static {
			delete(t.entries, ip)
			return
		}
	}
}

// peek geeft het MAC voor ip als dat al bekend is, zonder ooit een query te
// starten. Voor best-effort-uitvoer (RST op een refuse, echo-reply): wie ons
// net geldig aansprak is zojuist passief geleerd, dus in het legitieme geval
// is het antwoord er altijd — en voor een gespoofde bron een actieve query
// starten liet élke refuse-RST een echte cache-plek verdringen, tot de hele
// tabel uit pending spoof-queries bestond (review 13-08, vijftiende ronde).
func (t *arpTable) peek(ip [4]byte, now int64) (mac [6]byte, ok bool) {
	if e, exists := t.entries[ip]; exists && t.tick(ip, e, now) && e.state == arpResolved {
		return e.mac, true
	}
	return mac, false
}

// noAnswer rapporteert of de query voor ip luid is opgegeven: arpQueryTries
// pogingen zonder reply. Na arpFailTTL verdwijnt die status en mag resolve
// opnieuw beginnen.
func (t *arpTable) noAnswer(ip [4]byte, now int64) bool {
	e, exists := t.entries[ip]
	return exists && t.tick(ip, e, now) && e.state == arpFailed
}

// seed zet een statische entry: lost meteen op en verloopt nooit. Eén entry
// per IP blijft gelden — een bestaande entry (pending, opgelost of opgegeven)
// wordt vervangen; een wachtende resolver ziet bij de volgende poll de hit.
//
// LET OP (BEVINDINGEN #21): de subnet-check is de zorg van de stack-laag.
// Deze tabel kent geen subnet en accepteert élk IP. Wie hier een seed buiten
// het eigen subnet in zet terwijl de routelaag zulke adressen nooit via ARP
// oplost, krijgt lneto's halve werking terug: de seed lijkt te bestaan maar
// wordt nooit geraadpleegd. De stack-laag hoort buiten-subnet-seeds te
// weigeren, luid.
func (t *arpTable) seed(ip [4]byte, mac [6]byte) {
	t.entries[ip] = &arpEntry{mac: mac, state: arpResolved, static: true}
}

// learn is het passieve pad: de stack-laag meldt (src-IP, src-MAC) van
// unicast-IPv4-frames die aan óns gericht waren. Zonder dit kent een listener
// zijn same-subnet-bellers alleen via een extra ARP-rondje (go-net loste dat
// met PassivePeers op). Strikter dan lneto's learnPassive: passief leren mag
// een entry AANMAKEN en zijn TTL verversen, maar nooit het MAC van een
// bestaande entry wijzigen — een MAC-wissel vergt een echte ARP-uitwisseling
// (recv). Zo kan een gespoofd data-frame nooit een gevestigde (gateway-)entry
// omleiden.
func (t *arpTable) learn(ip [4]byte, mac [6]byte, now int64) {
	if ip == t.ourIP {
		return
	}
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) {
		// Passief leren verdringt níets: vol is vol (na een sweep), en de
		// weigering telt. Een échte peer verliest daar alleen de gratis
		// cache-plek — zijn verkeer werkt gewoon, via de ARP-molen
		// (review 13-08, dertiende ronde).
		if len(t.entries) >= arpCacheCap {
			t.sweepExpired(now)
			if len(t.entries) >= arpCacheCap {
				t.cnt.LearnDrop++
				return
			}
		}
		t.entries[ip] = &arpEntry{mac: mac, state: arpResolved, born: now}
		return
	}
	switch {
	case e.state == arpPending:
		// Het antwoord kwam als dataverkeer vóór (of in plaats van) de reply.
		e.state = arpResolved
		e.mac = mac
		e.born = now
	case e.state == arpResolved && !e.static && e.mac == mac:
		e.born = now // zelfde MAC: alleen de TTL verversen
	}
}

// recv verwerkt één binnengekomen ARP-payload (al gevalideerd door ParseARP).
// De harde regel (BEVINDINGEN #8): nieuwe entries ontstaan UITSLUITEND uit
// een aan ons gerichte reply op een eigen, nog-pending query. Al het andere —
// requests, gratuitous announcements, andermans verkeer — ververst hoogstens
// een bestáánde opgeloste entry. Een broadcast-reply kan hier dus nooit een
// cache-plek veroveren; lneto accepteerde die onvoorwaardelijk en dat is
// klassieke ARP-poisoning op de gateway-entry.
func (t *arpTable) recv(f ARPFrame, now int64) {
	sender := [4]byte(f.SenderProto())
	target := [4]byte(f.TargetProto())
	var senderHW [6]byte
	copy(senderHW[:], f.SenderHW())

	switch f.Op() {
	case ARPRequest:
		// Vraagt de peer óns adres? Reply klaarzetten; emit verstuurt hem.
		if target == t.ourIP && sender != t.ourIP {
			if len(t.replies) >= arpReplyQueueCap {
				t.cnt.ReplyDrop++
			} else {
				t.replies = append(t.replies, arpReply{hw: senderHW, ip: sender})
			}
		}
		// Sender-info uit een request (ook een gratuitous request) ververst
		// hoogstens een bestaande entry; een pending query lost er bewust
		// niet mee op — dat doet alleen een aan ons gerichte reply.
		t.refresh(sender, senderHW, now)
	case ARPReply:
		switch {
		case target == t.ourIP:
			// Aan ons gericht: lost onze pending query op, of ververst een
			// bestaande entry. Zonder pending query en zonder entry doet
			// zelfs een aan ons gerichte reply niets (#8).
			if e, exists := t.entries[sender]; exists && t.tick(sender, e, now) && e.state == arpPending {
				e.state = arpResolved
				e.mac = senderHW
				e.born = now
				return
			}
			t.refresh(sender, senderHW, now)
		case target == sender:
			// Gratuitous: een host kondigt zijn eigen adres aan. Alleen
			// verversen, nooit aanmaken (#8); een MAC-wissel telt mee zodat
			// de stack-laag er een logregel aan kan hangen.
			t.refresh(sender, senderHW, now)
		default:
			// Niet aan ons gericht en niet gratuitous: negeren. Dit is de
			// poisoning-vorm — een (broadcast-)reply voor andermans gesprek.
			t.cnt.Ignored++
		}
	}
}

// refresh zet een nieuw MAC en een verse TTL op een bestaande, opgeloste
// entry. Onbekende IP's maken hier bewust niets aan (#8) en statische seeds
// blijven staan.
func (t *arpTable) refresh(ip [4]byte, mac [6]byte, now int64) {
	e, exists := t.entries[ip]
	if !exists || !t.tick(ip, e, now) || e.state != arpResolved || e.static {
		return
	}
	if e.mac != mac {
		t.cnt.MACChanged++
		e.mac = mac
	}
	e.born = now
}

// emit schrijft één uitgaand ARP-pakket in buf: eerst wachtende replies, dan
// pending queries die aan een (re)try toe zijn. De aanroeper loopt tot
// ok=false en wikkelt elk pakket zelf in ethernet: op=ARPReply gaat unicast
// naar het TargetHW-veld, op=ARPRequest gaat broadcast. buf moet minstens
// sizeARP bytes dragen; korter is een aanroeperfout en panict, zoals elke
// boekhoudfout in dit package.
func (t *arpTable) emit(buf []byte, now int64) (n int, ok bool) {
	if len(t.replies) > 0 {
		r := t.replies[0]
		copy(t.replies, t.replies[1:])
		t.replies = t.replies[:len(t.replies)-1]
		return t.putARP(buf, ARPReply, r.hw, r.ip)
	}
	for ip, e := range t.entries {
		if !t.tick(ip, e, now) || e.state != arpPending || now < e.due {
			continue
		}
		e.tries++
		e.due = now + arpRetryIval
		return t.putARP(buf, ARPRequest, [6]byte{}, ip)
	}
	return 0, false
}

// putARP is de gedeelde schrijver: de sender is altijd wijzelf.
func (t *arpTable) putARP(buf []byte, op uint16, targetHW [6]byte, targetIP [4]byte) (int, bool) {
	n, err := PutARP(buf, op, t.ourMAC, t.ourIP, targetHW, targetIP)
	if err != nil {
		panic("leannet: arp emit buffer too small")
	}
	return n, true
}
