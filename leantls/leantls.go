// Package leantls is een TLS 1.3-client voor een netwerk dat je zelf bezit: één
// versie, één cipher suite, één sleuteluitwisseling, en een tegenpartij die je
// herkent aan een VASTGEZETTE Ed25519-sleutel in plaats van aan een
// certificaatketen. Stdlib-only.
//
// Het gemeten probleem (2026-08-12, tamago/riscv64, dezelfde main met alleen de
// TLS-kant verschillend, `-w -T 0x84010000`):
//
//	board + fmt (de vloer) ................... 1,69 MB
//	+ dit pakket, gepinde sleutel ............ 2,51 MB   (+0,82)
//	+ dit pakket, keten via leantls/x509verify  3,73 MB   (+2,04)
//	+ crypto/tls met CA-rootbundel ........... 4,09 MB   (+2,40)
//
// LEES DIE TABEL GOED, want er staan twee heel verschillende getallen in:
//
//   - Met een GEPINDE SLEUTEL is dit pakket 1,57 MB lichter dan crypto/tls, en
//     dat is na de netstack het grootste enkele blok dat een bare-metal
//     Go-programma kan laten staan. Dáár is dit pakket voor.
//   - Met een ECHTE CERTIFICAATKETEN (leantls/x509verify) is het 0,63 MB lichter
//     dan crypto/tls. Op zichzelf weinig — maar het ontsluit iets groters, en
//     dat is de reden dat die modus bestaat. Zie hieronder.
//
// # Waarom de ketenmodus tóch de moeite is
//
// Een programma dat een bestand over https ophaalt gebruikt geen crypto/tls
// LOS; het gebruikt net/http, en dat is de echte basislijn. Gemeten met dezelfde
// download:
//
//	net/http + crypto/tls ................. 5,53 MB
//	leanhttp + crypto/tls ................. 4,43 MB   (-1,10)
//	leanhttp + leantls + x509verify ....... 3,80 MB   (-1,73)
//
// Die 1,10 MB van leanhttp was vóór dit pakket NIET te verzilveren voor https:
// leanhttp weigert een https-URL zonder een eigen Dial, en de enige Dial die
// bestond was crypto/tls — waarmee de PKI en het halve net/http-gewicht weer
// binnenkwamen. leantls is de Dial die dat opent. In een kern die vandaag
// net/http plus crypto/tls draagt, is de hele stapel dus 1,73 MB lichter.
//
// De winst zit dus niet in TLS maar in de PKI die je NIET nodig hebt zodra je de
// tegenpartij al kent: crypto/x509, encoding/asn1, math/big, RSA, de NIST-curves
// met hun voorberekende tabel (86 KB) en de CA-rootbundel (123 KB). Wat dit
// pakket in de gepinde modus gebruikt is crypto/ecdh (X25519), crypto/aes +
// crypto/cipher (AES-128-GCM), crypto/sha256, crypto/hmac, crypto/hkdf,
// crypto/ed25519 en crypto/rand. Verder niets — geen enkel symbool van
// crypto/tls, crypto/x509 of encoding/asn1 in het image.
//
// # Wat "een gepinde sleutel" is
//
// Gewone https werkt zo: je weet niet wie de server is, dus je vertrouwt een
// KETEN. Het certificaat zegt "ik ben github.com" en een CA die jij vertrouwt
// staat daarvoor in. Om dat na te rekenen heb je alles nodig wat hierboven
// 1,05 MB kost — 119 roots, padopbouw, geldigheidsdata, naamvergelijking — en
// je vertrouwt daarmee 119 organisaties om nooit een verkeerd certificaat uit
// te geven.
//
// Een pin draait dat om: je KENT de sleutel van de tegenpartij al, omdat je hem
// er zelf hebt neergezet. De leader maakt één keer een Ed25519-sleutelpaar; zijn
// PUBLIEKE helft (32 bytes) gaat mee in de config of het image van de node. Bij
// de handshake doet dit pakket dan twee dingen: het vergelijkt de sleutel in het
// certificaat met die 32 bytes, en het toetst dat de tegenpartij met de
// bijbehorende geheime helft over het transcript heeft ondertekend.
//
// Daarmee vervalt de hele vraag "wie staat hiervoor in?". Je vraagt niet meer
// "is dit echt github.com?" maar "is dit de sleutel die ik zelf in mijn config
// heb gezet?" — en dat is geen zwakkere controle maar een strengere: er is geen
// CA die zich kan vergissen, geen naam die kan matchen op iets anders, geen
// datum die kan verlopen. Wat je ervoor inlevert is distributie: die 32 bytes
// moeten bij de node komen, en als de sleutel wisselt moet dat opnieuw. Voor een
// vloot die je zelf bezit is dat een configuratieregel. Voor github.com kan het
// niet, want dáár ken je de sleutel niet vooraf en roteert hij per kwartaal.
//
// # Wat het niet doet, en waarom dat luid faalt
//
// De ruil is scherp en hij staat hier zodat niemand hem per ongeluk maakt:
//
//   - In de gepinde modus: GEEN certificaatketen, geen CA's, geen
//     naamvergelijking, geen geldigheidsdata. Wie de tegenpartij is, staat in
//     [Config.PeerKey]. Wil je een keten, dan zet je [Config.VerifyPeer] en doe
//     je dat zelf — dit pakket importeert crypto/x509 niet, zodat wie met een pin
//     werkt er niets voor betaalt. En zie de tabel hierboven vóór je dat doet.
//   - Zonder vertrouwensmodel weigert [Client] te verbinden. Niet "vertrouw
//     alles", niet een waarschuwing: een weigering die zegt wat de twee keuzes
//     zijn.
//   - Alleen TLS 1.3. Een server die 1.2 kiest krijgt geen stille terugval maar
//     een fout: terugvallen is precies waar de aanvallen op TLS zitten.
//   - Eén suite (TLS_AES_128_GCM_SHA256), één groep (X25519), één signatuur
//     (Ed25519). Alles anders is een fout met het gekozen nummer erin.
//   - Geen session resumption, geen PSK, geen 0-RTT, geen clientcertificaten,
//     geen HelloRetryRequest, geen renegotiation (die bestaat niet in 1.3).
//
// Dat lijstje is niet alleen een beperking, het is de veiligheidsredenering.
// Wat rolling-your-own-TLS historisch sloopt is bijna altijd version downgrade,
// renegotiation, compressie, CBC-padding, RSA-PKCS#1v1.5, of een fout in
// ketenvalidatie. Geen daarvan is hier voorzichtig aangepakt: ze bestaan niet.
// Wat overblijft is de key schedule, de recordlaag en het transcript — en die
// drie zijn deterministisch en met bekende antwoorden te toetsen. De schedule
// staat in schedule_test.go tegen de uitgewerkte handshake van RFC 8448; de rest
// staat in leantls_test.go tegen crypto/tls zelf als tegenpartij.
//
// # Gebruik
//
//	// Waar dit pakket voor is: een tegenpartij die je al kent.
//	conn, err := leantls.Dial("tcp", "leader:7443", &leantls.Config{
//	    PeerKey: leaderKey, // 32 bytes, uit je eigen configuratie
//	})
//
//	// En als het toch een echte keten moet zijn (lees eerst de tabel hierboven):
//	conn, err := leantls.Dial("tcp", "github.com:443", &leantls.Config{
//	    ServerName:          "github.com",
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	})
//
// Het resultaat is een gewone net.Conn, dus leanhttp of wat dan ook gaat er
// bovenop. Dit pakket kent geen HTTP en geen netstack — het staat op net.Conn en
// verder niets, zoals elk pakket hier.
package leantls

import (
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Config beschrijft wie we verwachten aan de andere kant. Kies ÉÉN van de twee
// vertrouwensmodellen: PeerKey (een gepinde sleutel) of VerifyPeer (je eigen
// controle, bijvoorbeeld een echte certificaatketen). Beide leeg is een
// weigering, en beide gezet ook — dan is niet duidelijk wat er telt.
type Config struct {
	// PeerKey is de Ed25519-publieke sleutel die de server MOET hebben: geen
	// keten, maar één vergelijking. Dit is de goedkope modus — er komt geen enkel
	// stukje PKI aan te pas.
	PeerKey ed25519.PublicKey

	// VerifyPeer is de andere modus: jíj bepaalt of deze tegenpartij te
	// vertrouwen is. Hij krijgt de certificaatketen zoals de server hem stuurde
	// (DER, leaf eerst) plus de naam waarvoor hij hoort te gelden, en geeft terug
	// hoe de handtekening van die server over het transcript getoetst moet worden.
	//
	// Waarom een HAAK en geen ingebouwde ketenvalidatie: wie een echte keten wil
	// valideren, wil crypto/x509 — dat is de implementatie die de wereld al een
	// decennium aanvalt, en zelf X.509 schrijven levert gemeten ~0,2 MB op tegen
	// precies de code waar de CVE's in die categorie zitten. Maar crypto/x509
	// kost ~0,75 MB, en dat mag niet gelden voor wie met een gepinde sleutel
	// werkt. Met deze haak importeert leantls het niet: wie hem gebruikt, linkt
	// het zelf.
	//
	// Voor de gewone https-vorm staat er een kant-en-klare in het subpakket
	// leantls/x509verify.
	VerifyPeer func(certs [][]byte, serverName string) (SignatureVerifier, error)

	// ServerName is de SNI die we sturen, en in de VerifyPeer-modus tevens de
	// naam waarvoor het certificaat moet gelden. In de PeerKey-modus is hij
	// optioneel: daar doet de pin het vertrouwen, niet de naam.
	ServerName string

	// SignatureAlgorithms zijn de TLS-codes die we in ClientHello aanbieden voor
	// de handtekening van de server (RFC 8446 §4.2.3). Leeg betekent alleen
	// Ed25519 — precies wat de PeerKey-modus kan toetsen. Een VerifyPeer die
	// meer kan, hoort hier te zeggen wát; x509verify.SignatureAlgorithms is de
	// bijbehorende lijst.
	//
	// Een server kiest ALTIJD uit deze lijst, dus een algoritme aanbieden dat je
	// niet kunt toetsen levert een handshake die pas bij de handtekening faalt.
	SignatureAlgorithms []uint16
}

// SignatureVerifier toetst de CertificateVerify van de server: sigAlg is de code
// die de server koos, signed is precies wat er ondertekend hoort te zijn, en sig
// de handtekening. Nil terug = goed.
//
// Een ALIAS en geen eigen type, en dat is functioneel: een eigen type zou pas
// toewijsbaar zijn vanuit code die leantls importeert, en dan moet een
// hulppakket als leantls/x509verify dit pakket importeren om er een verifier aan
// te kunnen geven. Met een alias is de functievorm identiek en blijft dat
// hulppakket een bouwsteen die op zichzelf staat — precies de regel waar deze
// hele verzameling op rust.
type SignatureVerifier = func(sigAlg uint16, signed, sig []byte) error

// Conn is een TLS 1.3-verbinding en implementeert net.Conn.
type Conn struct {
	conn net.Conn
	cfg  Config

	// Eén slot per richting. Dit is GEEN netheid: net.Conn staat toe dat
	// meerdere goroutines hem tegelijk gebruiken, en twee gelijktijdige Writes
	// zouden twee records met hetzelfde recordnummer kunnen opleveren. Dat is in
	// AES-GCM een hergebruikte nonce, en een hergebruikte nonce is niet een bug
	// met een verkeerd resultaat maar het einde van zowel de vertrouwelijkheid
	// als de integriteit van die sleutel. Read heeft zijn eigen slot om dezelfde
	// reden aan de leeskant, plus omdat hij post-handshake berichten verwerkt
	// (en daarvoor de zendkant nodig heeft, vandaar wmu binnen rmu).
	rmu sync.Mutex
	wmu sync.Mutex

	// Recordlaag per richting. seq begint bij nul na élke sleutelwissel.
	wKeys trafficKeys
	wAEAD cipher.AEAD
	wSeq  uint64
	rKeys trafficKeys
	rAEAD cipher.AEAD
	rSeq  uint64

	transcript []byte // alle handshake-berichten; leeg na de handshake
	hsBuf      []byte // handshake-bytes die nog geen heel bericht vormen
	plain      []byte // uitgelezen applicatiedata die nog niet opgehaald is
	readErr    error  // sticky: een recordlaag die faalde faalt voorgoed
}

var _ net.Conn = (*Conn)(nil)

// dialTimeout begrenst het opzetten van de verbinding én de handshake, elk
// apart: een peer die de TCP-handdruk wél beantwoordt maar daarna zwijgt
// (firewall-blackhole, kapotte middlebox) gijzelde anders de goroutine en de
// socket voorgoed — en elke laag erboven (leanhttp's dialBounded) kan een
// dialer alleen begrenzen als die zélf eindig is (review 13-08, dertiende
// ronde). Zelfde waarde als leanhttp's dialTimeout.
const dialTimeout = 10 * time.Second

// Dial opent een TCP-verbinding en doet de handshake, beide met een termijn
// (zie dialTimeout). Wie andere termijnen wil, dialt zelf en geeft de
// verbinding aan [Client]; wie kan annuleren wil, neemt [DialContext].
func Dial(network, addr string, cfg *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, cfg)
}

// DialContext is Dial mét annulering: ctx kapt de TCP-dial af, en zijn
// deadline klemt (indien eerder) ook de handshake-termijn — zo leeft er geen
// dial voort nadat de aanroeper al opgaf (review 13-08, vijftiende ronde).
func DialContext(ctx context.Context, network, addr string, cfg *Config) (*Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(dialTimeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	c.SetDeadline(dl)
	tc, err := Client(c, cfg)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return tc, nil
}

// Client doet de handshake over een bestaande verbinding. Bij een fout is de
// onderliggende verbinding onbruikbaar en aan de aanroeper om te sluiten.
//
// De handshake gebeurt hier en niet bij de eerste Read of Write: een fout in het
// vertrouwen (verkeerde sleutel, geen 1.3) hoort te vallen waar je hem
// verwacht, niet drie lagen verderop bij een lees.
func Client(conn net.Conn, cfg *Config) (*Conn, error) {
	if cfg == nil {
		return nil, errors.New("leantls: a Config is required")
	}
	pinned := len(cfg.PeerKey) > 0
	switch {
	case pinned && cfg.VerifyPeer != nil:
		return nil, errors.New("leantls: set either Config.PeerKey or Config.VerifyPeer, not both — " +
			"with both it is not clear which one decides whether the peer is trusted")
	case pinned && len(cfg.PeerKey) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("leantls: Config.PeerKey is %d bytes, an Ed25519 public key is %d",
			len(cfg.PeerKey), ed25519.PublicKeySize)
	case !pinned && cfg.VerifyPeer == nil:
		// Lean-regel 2 op de plek waar het het meest telt: geen stille
		// "vertrouw alles", maar een weigering die zegt wat de twee keuzes zijn.
		return nil, errors.New("leantls: no trust model — set Config.PeerKey for a pinned peer, " +
			"or Config.VerifyPeer to check a certificate chain yourself (see leantls/x509verify)")
	case !pinned && cfg.ServerName == "":
		return nil, errors.New("leantls: Config.ServerName is required with VerifyPeer — " +
			"a chain that is not checked against a name proves nothing about who you reached")
	}
	c := &Conn{conn: conn, cfg: *cfg}
	if err := c.handshake(); err != nil {
		return nil, err
	}
	return c, nil
}

// hash is de Transcript-Hash over alles wat er tot nu toe gewisseld is.
//
// Het transcript wordt als BYTES bijgehouden en niet als lopende hash, omdat de
// schedule er op vijf momenten een momentopname van nodig heeft (§4.4.1) en een
// hash die je vijf keer moet klonen meer fout kan gaan dan een buffer van een
// paar kilobyte. Na de handshake gaat hij op nil.
func (c *Conn) hash() []byte {
	sum := sha256.Sum256(c.transcript)
	return sum[:]
}

func (c *Conn) setRead(k trafficKeys) {
	c.rKeys, c.rAEAD, c.rSeq = k, aeadFor(k), 0
}

func (c *Conn) setWrite(k trafficKeys) {
	c.wKeys, c.wAEAD, c.wSeq = k, aeadFor(k), 0
}

// writeCCS stuurt het lege change_cipher_spec-record. Altijd plaintext, ook als
// de sleutels al staan — daarom niet via writeRecord.
func (c *Conn) writeCCS() error {
	_, err := c.conn.Write([]byte{recCCS, 3, 3, 0, 1, 1})
	return err
}

// readHandshakeMsg geeft het volgende handshake-bericht (type + body) en voegt
// het aan het transcript toe. Berichten en records staan los van elkaar: één
// record kan meerdere berichten dragen en één bericht kan over records
// verdeeld zijn, dus dit buffert over recordgrenzen heen.
func (c *Conn) readHandshakeMsg() (byte, []byte, error) {
	for {
		if len(c.hsBuf) >= 4 {
			n := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
			if len(c.hsBuf) >= 4+n {
				msg := c.hsBuf[:4+n]
				c.hsBuf = c.hsBuf[4+n:]
				c.transcript = append(c.transcript, msg...)
				return msg[0], msg[4:], nil
			}
		}
		typ, payload, err := c.readRecord()
		if err != nil {
			return 0, nil, err
		}
		switch typ {
		case recCCS:
			// Middlebox-compatibiliteit, zonder betekenis in 1.3 (§5). Niet in
			// het transcript, want het is geen handshake-bericht.
		case recAlert:
			return 0, nil, alertError(payload)
		case recHandshake:
			if len(c.hsBuf)+len(payload) > maxHandshake {
				return 0, nil, fmt.Errorf("leantls: handshake message larger than %d bytes", maxHandshake)
			}
			c.hsBuf = append(c.hsBuf, payload...)
		default:
			return 0, nil, fmt.Errorf("leantls: unexpected record type %d during handshake", typ)
		}
	}
}

// maxHandshake begrenst wat één handshake-bericht mag zijn. Een certificaatketen
// is het grootste dat hier langskomt en die is in de praktijk enkele KB; dit is
// de grens waarboven een tegenpartij ons geheugen laat claimen in plaats van een
// handshake te doen.
const maxHandshake = 1 << 16

// Read levert applicatiedata. Post-handshake berichten van de tegenpartij
// (NewSessionTicket, KeyUpdate) worden hier afgehandeld en zijn voor de
// aanroeper onzichtbaar — dat is de enige plek waar ze langs kunnen komen.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.plain) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		typ, payload, err := c.readRecord()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		switch typ {
		case recAppData:
			c.plain = payload
		case recAlert:
			c.readErr = alertError(payload)
			return 0, c.readErr
		case recCCS:
			// negeren, ook na de handshake
		case recHandshake:
			if err := c.postHandshake(payload); err != nil {
				c.readErr = err
				return 0, err
			}
		default:
			c.readErr = fmt.Errorf("leantls: unexpected record type %d", typ)
			return 0, c.readErr
		}
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

// postHandshake verwerkt wat een server ná de handshake nog mag sturen.
func (c *Conn) postHandshake(payload []byte) error {
	r := reader{buf: payload}
	for !r.empty() {
		typ, err := r.u8()
		if err != nil {
			return err
		}
		body, err := r.vec24()
		if err != nil {
			return err
		}
		switch typ {
		case hsNewSessionTicket:
			// We doen geen resumption, dus dit is informatie die we niet
			// gebruiken. Overslaan en niet als fout melden: een server die
			// tickets stuurt doet niets verkeerd.
		case hsKeyUpdate:
			// §4.6.3. De tegenpartij vernieuwt zijn zendsleutel, dus wij
			// vernieuwen onze leessleutel. Vraagt hij er ook om (1), dan doen we
			// hetzelfde met onze zendkant en melden dat — anders zou hij op een
			// antwoord wachten dat nooit komt.
			req, err := body.u8()
			if err != nil {
				return err
			}
			c.setRead(c.rKeys.next())
			if req == 1 {
				// Expliciet slot en geen defer: er kunnen meer KeyUpdates in
				// één record zitten, en een defer in deze lus zou bij de tweede
				// op zijn eigen slot gaan staan.
				c.wmu.Lock()
				err := c.writeRecord(recHandshake, keyUpdateMsg())
				if err == nil {
					c.setWrite(c.wKeys.next())
				}
				c.wmu.Unlock()
				if err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("leantls: unexpected post-handshake message type %d", typ)
		}
	}
	return nil
}

// Write verstuurt applicatiedata, gefragmenteerd op de recordgrens van de RFC.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxPlain)
		if err := c.writeRecord(recAppData, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// Close stuurt close_notify en sluit de verbinding. De alert is niet optioneel
// als je wilt dat de andere kant het verschil ziet tussen "klaar" en
// "weggevallen" — dat onderscheid is precies wat een afgekapte download
// onzichtbaar zou maken.
func (c *Conn) Close() error {
	if c.wAEAD != nil {
		c.wmu.Lock()
		// Een fout hier mag het sluiten niet tegenhouden: de verbinding kan al
		// weg zijn, en dan is close_notify sturen zinloos maar niet erg.
		_ = c.writeRecord(recAlert, []byte{2, alertCloseNotify})
		c.wmu.Unlock()
	}
	return c.conn.Close()
}

// keyUpdateMsg is het antwoord op een KeyUpdate die om een wederdienst vraagt:
// wij vernieuwen ook, en vragen op onze beurt niets (anders blijven twee
// implementaties elkaar eindeloos om sleutelwissels vragen).
func keyUpdateMsg() []byte {
	var b builder
	b.u8(hsKeyUpdate)
	b.u24len(func() { b.u8(0) }) // update_not_requested
	return b.buf
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// PeerKey geeft de sleutel waarmee deze verbinding tot stand kwam — dezelfde als
// in de Config, maar bewezen: hij zat in het certificaat én hij zette de
// handtekening over het transcript.
func (c *Conn) PeerKey() ed25519.PublicKey { return c.cfg.PeerKey }
