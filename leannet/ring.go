package leannet

// ring.go — de byte-rings onder elke verbinding. Twee smaken op één drager:
//
//   - rxRing: netwerk schrijft in-order bytes op de staart, de applicatie
//     leest van de kop. De vrije ruimte ís het receive-venster.
//   - txRing: de applicatie schrijft op de staart; een zend-cursor markeert
//     tot waar al verzonden is. ACKs geven de kop vrij, een RTO spoelt de
//     cursor terug naar de kop (go-back-N) — retransmissie is daarmee een
//     her-lezing, geen aparte administratie.
//
// De rings zijn niet zelf-vergrendeld: de verbinding houdt zijn eigen lock
// vast (één regime, geen dubbel locken per byte). Groeien gebeurt expliciet
// via grow(), zodat de budget-boekhouding (budget.go) erbuiten blijft: de
// ring weet niets van de pot, de verbinding verbindt die twee.

// ring is de gedeelde drager: een FIFO over een vaste []byte.
// head = leespositie, n = aantal gebufferde bytes; de schrijfpositie is
// (head+n) mod len(buf). Die vorm maakt vol-vs-leeg ondubbelzinnig zonder
// een verloren slot.
type ring struct {
	buf  []byte
	head int
	n    int
}

func (r *ring) size() int     { return len(r.buf) }
func (r *ring) buffered() int { return r.n }
func (r *ring) free() int     { return len(r.buf) - r.n }

// write kopieert zoveel mogelijk van p op de staart en geeft het aantal terug.
func (r *ring) write(p []byte) int {
	total := 0
	for len(p) > 0 && r.n < len(r.buf) {
		w := (r.head + r.n) % len(r.buf)
		// Aaneengesloten stuk tot de fysieke rand of tot de kop.
		chunk := len(r.buf) - w
		if free := len(r.buf) - r.n; chunk > free {
			chunk = free
		}
		if chunk > len(p) {
			chunk = len(p)
		}
		copy(r.buf[w:w+chunk], p[:chunk])
		r.n += chunk
		total += chunk
		p = p[chunk:]
	}
	return total
}

// peek kopieert maximaal len(p) bytes vanaf offset off achter de kop, zonder
// te consumeren. off+len(p) mag voorbij de inhoud wijzen; gekopieerd wordt
// wat er is.
func (r *ring) peek(p []byte, off int) int {
	if off >= r.n {
		return 0
	}
	total := 0
	avail := r.n - off
	if len(p) > avail {
		p = p[:avail]
	}
	pos := (r.head + off) % len(r.buf)
	for len(p) > 0 {
		chunk := len(r.buf) - pos
		if chunk > len(p) {
			chunk = len(p)
		}
		copy(p[:chunk], r.buf[pos:pos+chunk])
		total += chunk
		p = p[chunk:]
		pos = (pos + chunk) % len(r.buf)
	}
	return total
}

// drop consumeert k bytes van de kop. k > buffered panict: dat is een
// sequence-boekhoudfout die stil doorgaan zou verhullen.
func (r *ring) drop(k int) {
	if k < 0 || k > r.n {
		panic("leannet: ring drop exceeds buffered")
	}
	r.head = (r.head + k) % len(r.buf)
	r.n -= k
	if r.n == 0 {
		r.head = 0 // genormaliseerd: maakt groeien en testen voorspelbaar
	}
}

// read is drop mét de bytes: kopieer van de kop en consumeer.
func (r *ring) read(p []byte) int {
	got := r.peek(p, 0)
	r.drop(got)
	return got
}

// grow vervangt de drager door newBuf (groter of gelijk) en legt de inhoud
// plat vooraan. De aanroeper heeft newBuf al bij het budget verantwoord.
func (r *ring) grow(newBuf []byte) {
	if len(newBuf) < r.n {
		panic("leannet: ring grow smaller than contents")
	}
	r.peek(newBuf[:r.n], 0)
	r.buf = newBuf
	r.head = 0
}

// ---- txRing: verzendbuffer met zend-cursor ----

// txRing draagt app-bytes tussen Write en het door de peer bevestigde punt.
// sent telt hoeveel van de gebufferde bytes minstens één keer verzonden zijn;
// de kop van de ring ís snd.UNA in bytes.
type txRing struct {
	ring
	sent int
}

// writeApp neemt app-bytes op (zoveel als past) en geeft het aantal terug.
func (t *txRing) writeApp(p []byte) int { return t.write(p) }

// unsent geeft hoeveel gebufferde bytes nog niet (of opnieuw, na rewind)
// verzonden moeten worden.
func (t *txRing) unsent() int { return t.n - t.sent }

// nextSend kopieert maximaal len(p) nog-niet-verzonden bytes en schuift de
// zend-cursor op. De bytes blijven gebufferd tot ack() ze vrijgeeft.
func (t *txRing) nextSend(p []byte) int {
	got := t.peek(p, t.sent)
	t.sent += got
	return got
}

// ack geeft k bevestigde bytes vrij van de kop. De zend-cursor schuift mee
// terug; een ACK die verder reikt dan wat verzonden is, is bij de verbinding
// al afgekeurd vóór hij hier komt.
func (t *txRing) ack(k int) {
	t.drop(k)
	t.sent -= k
	if t.sent < 0 {
		panic("leannet: tx ack beyond sent")
	}
}

// rewind spoelt de zend-cursor terug naar de kop: alles wat onbevestigd is
// geldt weer als te verzenden (go-back-N na een RTO).
func (t *txRing) rewind() { t.sent = 0 }
