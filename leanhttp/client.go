package leanhttp

// client.go — keep-alive aan de clientkant: een pool van verbindingen per
// host, zodat een reeks verzoeken niet elke keer een TCP-handshake (en over
// TLS: een sleuteluitwisseling) betaalt.
//
// Waarom dit hier hoort en niet bij de aanroeper: zonder keep-alive grijpt de
// volgende gebruiker die dertig resources van één host haalt naar net/http, en
// dan betaalt zijn image ~3,2 MB — meer dan alles wat dit hele pakket ooit
// uitspaart. De pool is puur logica (net en sync waren er al), dus wie hem
// niet gebruikt betaalt er ook niets voor: de linker gooit een ongebruikt
// Client-type gewoon weg.
//
// De veiligheidsregel staat in body.Close en is er maar één: een verbinding
// gaat alleen terug in de pool als de body TOT HET EINDE gelezen is. Een
// verbinding met ongelezen bytes erin hergebruiken laat het volgende verzoek
// de staart van dit antwoord als statusregel lezen. Twijfel = sluiten.

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"
)

// Standaardmaten van de pool. Twee verbindingen per host is wat een pagina met
// parallelle resources nodig heeft zonder een server te bestormen; 30 seconden
// idle is ruim onder wat servers zelf dichtgooien (nginx: 75s, Go: 3 minuten).
const (
	defaultMaxIdlePerHost = 2
	defaultIdleTimeout    = 30 * time.Second

	// defaultMaxIdleTotal begrenst de héle pool: alleen een per-host-cap liet
	// een burst naar unieke (of case-gevarieerde) hosts op leannet de hele
	// bufferpot claimen voor de duur van de idle-termijn (review 13-08,
	// dertigste ronde).
	defaultMaxIdleTotal = 8
)

// Client doet verzoeken mét keep-alive. Hij is veilig voor gelijktijdig
// gebruik; de zero value werkt (dial via net.DialTimeout, twee idle
// verbindingen per host, 30s idle-timeout).
//
// De package-level [Do] en [Get] blijven de kale vorm: één verzoek per
// verbinding, Connection: close. Wie geen pool wil, verandert niets.
type Client struct {
	// DialContext maakt een nieuwe verbinding; nil = de stdlib-dialer op
	// tcp4. Zelfde contract als [Call.DialContext] — een TLS-dialer past er
	// dus ook op, en dan poolt dit type versleutelde verbindingen.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// MaxIdlePerHost is hoeveel ongebruikte verbindingen per host blijven
	// staan; 0 = 2. Meer kost geheugen en socket-slots op de server, minder
	// kost handshakes.
	MaxIdlePerHost int

	// MaxIdleTotal is het plafond over álle hosts samen; 0 = 8. Zie de
	// const: zonder totaalcap claimde een burst naar unieke hosts de hele
	// leannet-pot.
	MaxIdleTotal int

	// IdleTimeout is hoe lang een ongebruikte verbinding blijft staan; 0 = 30s.
	// Wie langer wacht dan de server, krijgt een verbinding die al dicht is —
	// daarom staat dit ruim onder de gangbare server-waarden.
	IdleTimeout time.Duration

	mu   sync.Mutex
	idle map[string][]idleConn

	// sweepTimer loopt zolang er idle verbindingen staan (zie put): de
	// sweep-bij-dial dekt alleen een vólgend verzoek, en na het laatste
	// verzoek kwam die nooit — precies de gepoolde verbinding die op leannet
	// minstens 20KiB pot vasthield tot de watchdog de node resette
	// (review 13-08, vierentwintigste ronde).
	sweepTimer *time.Timer
}

type idleConn struct {
	c    net.Conn
	br   *bufio.Reader // de gebufferde lezer hoort bij de verbinding, niet bij het verzoek
	when time.Time
}

// Do voert één verzoek uit over een verbinding uit de pool (of een nieuwe) en
// laat hem daarna staan voor het volgende verzoek. Verder identiek aan [Do]:
// een foutstatus is geen fout.
func (cl *Client) Do(call Call) (*Response, error) {
	if call.DialContext != nil {
		// Een eigen transport per call mengt niet met de pool: de verbinding
		// erin stoppen zou een volgende Get een verbinding van een ánder
		// transport geven (review 13-08, tweede ronde). Dit is dan gewoon een
		// kale Do met Connection: close.
		return Do(call)
	}
	// Het transport gaat als PARAMETER mee, niet als Call-veld: do() vraagt
	// zelf via.Dial voor de schemewacht en via.dial voor de pool — er valt
	// niets meer verkeerd te zetten (review 13-08, zesde ronde: drie eerdere
	// rondes braken alle drie op "de pool-dialer vermomd als Call.DialContext").
	return doVia(call, cl)
}

// Get is [Get] over de pool: 200 mét Content-Length vereist.
func (cl *Client) Get(url string) (*Response, error) {
	resp, err := doVia(Call{URL: url}, cl)
	if err != nil {
		return nil, err
	}
	return checkGet(resp)
}

// CloseIdle sluit alle ongebruikte verbindingen. Aan te roepen als je klaar
// bent of als het netwerk onder je is weggevallen — een lopend verzoek raakt
// hij niet.
func (cl *Client) CloseIdle() {
	cl.mu.Lock()
	idle := cl.idle
	cl.idle = nil
	cl.mu.Unlock()
	for _, list := range idle {
		for _, ic := range list {
			ic.c.Close()
		}
	}
}

// dial pakt eerst een verbinding uit de pool; is er geen, dan een verse — in
// de ene interne dialervorm (zie normalizeDial in leanhttp.go): de ctx draagt
// de totaaltermijn van de call, dus ook de fallback-dial hieronder leeft
// erbinnen (review 13-08, elfde/twaalfde ronde; achttiende: genormaliseerd).
//
// De sweep staat hiér, vóór het verzoek — niet alleen in put, ná het verzoek.
// Dat is geen smaak maar de volgorde van het gemeten faalscenario: als de
// netstack-pot op is door verlopen gepoolde verbindingen, dan FAALT de dial,
// dus komt er geen put, dus zou een sweep-in-put nooit draaien — de toestand
// die hem moet opruimen is precies de toestand die hem onbereikbaar maakt
// (review 13-08). Eerst ruimen, dan vragen.
func (cl *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// Sweep en pop in één kritieke sectie: na de sweep is élke overgebleven
	// verbinding per definitie vers, dus de pop hoeft geen eigen
	// versheids-toets meer (review 13-08, tweede ronde).
	cl.mu.Lock()
	stale := cl.sweepLocked()
	cl.mu.Unlock()
	for _, ic := range stale {
		// Buiten het slot, en let wel: Close start een nette sluiting (FIN) —
		// de buffers komen pas vrij als die rond is. Op een levend LAN is dat
		// éen RTT; een dial die er te vroeg bij is, slaagt bij zijn herhaling.
		ic.c.Close()
	}
	for {
		cl.mu.Lock()
		c, br := cl.popLocked(addr)
		cl.mu.Unlock()
		if c == nil {
			break
		}
		// Alleen de Buffered()-toets: een verbinding met al-voorgelezen bytes
		// draagt een ongevraagd "antwoord" en gaat dicht. GEEN read-probe
		// meer: de 1ms-probe van de zevenentwintigste ronde vergiftigde élke
		// gezonde TLS-verbinding (leantls maakt record-leesfouten bewust
		// permanent, en een half gelezen recordheader is onherstelbaar),
		// negeerde EOF's, en was TOCTOU. Een application-level Read ís geen
		// liveness-probe; dat zou een blijvende reader-eigenaar per verbinding
		// vergen (net/http's readLoop), en dat gewicht is deze pool niet waard
		// (review 13-08, negenentwintigste ronde). Restrisico — bytes die ná
		// deze toets arriveren — accepteren we alleen binnen het contract van
		// een protocolcorrecte origin. De stale-herkansing vangt een GESLOTEN
		// idle verbinding voor GET/HEAD op; zij kan een syntactisch geldig
		// ongevraagd antwoord niet van een echt antwoord onderscheiden. Zie
		// KAM.md.
		if br.Buffered() == 0 {
			return &pooledConn{Conn: c, br: br}, nil
		}
		c.Close()
	}
	return normalizeDial(cl.DialContext)(ctx, network, addr)
}

// popLocked pakt de warmste verbinding voor addr. De versheid is al geborgd:
// de enige aanroeper (dial) sweept in dezelfde kritieke sectie. Aanroepen met
// cl.mu vast.
func (cl *Client) popLocked(addr string) (net.Conn, *bufio.Reader) {
	list := cl.idle[addr]
	if len(list) == 0 {
		return nil, nil
	}
	ic := list[len(list)-1] // laatst teruggegeven = warmst
	if len(list) == 1 {
		delete(cl.idle, addr)
	} else {
		cl.idle[addr] = list[:len(list)-1]
	}
	return ic.c, ic.br
}

// put geeft een verbinding terug; false = de pool wil hem niet (vol), en dan
// sluit de aanroeper hem. Alleen body.Close roept dit aan, en alleen als de
// body helemaal gelezen is.
func (cl *Client) put(addr string, c net.Conn, br *bufio.Reader) bool {
	// Uitpakken: c is bij hergebruik de pooledConn die dial er zelf omheen
	// wikkelde, en dial wikkelt er straks een verse laag omheen. Zonder deze
	// stap groeit de nesting per ronde — een poller van 1 req/s draagt na een
	// dag ~86k lagen en elke Read loopt de hele keten af (review 13-08,
	// derde ronde).
	if pc, ok := c.(*pooledConn); ok {
		c = pc.Conn
	}
	max := cl.MaxIdlePerHost
	if max == 0 {
		max = defaultMaxIdlePerHost
	}
	maxTotal := cl.MaxIdleTotal
	if maxTotal == 0 {
		maxTotal = defaultMaxIdleTotal
	}
	// De deadline van het vorige verzoek mag niet op een verbinding blijven
	// staan die straks een ander verzoek draagt — en een transport dat de wis
	// WEIGERT is per definitie niet herbruikbaar: poolen zou een kapotte
	// verbinding aan het volgende verzoek geven (review 13-08,
	// vijfentwintigste ronde).
	if c.SetDeadline(time.Time{}) != nil {
		return false
	}
	// Geen sweep hier: dial sweept vóór élk verzoek en dat is ook het enige
	// moment dat telt (zonder verkeer is er niets dat een sweep triggert, mét
	// verkeer loopt hij toch). Twee sweeps per verzoek was dubbel werk
	// (review 13-08, derde ronde).
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(cl.idle[addr]) >= max {
		return false
	}
	total := 0
	for _, list := range cl.idle {
		total += len(list)
	}
	if total >= maxTotal {
		return false
	}
	if cl.idle == nil {
		cl.idle = make(map[string][]idleConn)
	}
	cl.idle[addr] = append(cl.idle[addr], idleConn{c: c, br: br, when: time.Now()})
	cl.scheduleSweepLocked()
	return true
}

// scheduleSweepLocked zorgt dat er precies één timer loopt zolang de pool
// niet leeg is. De marge (timeout/4) voorkomt dat de timer nét vóór de
// vervaltijd van de oudste verbinding vuurt; een verbinding staat er zo
// hooguit ~2× de idle-timeout. Aanroepen met cl.mu vast.
func (cl *Client) scheduleSweepLocked() {
	if cl.sweepTimer != nil {
		return
	}
	timeout := cl.IdleTimeout
	if timeout == 0 {
		timeout = defaultIdleTimeout
	}
	cl.sweepTimer = time.AfterFunc(timeout+timeout/4, cl.timedSweep)
}

// timedSweep is de timer-gedreven opruiming: verlopen verbindingen dicht, en
// zolang er nog verse staan komt er een nieuwe timer.
func (cl *Client) timedSweep() {
	cl.mu.Lock()
	cl.sweepTimer = nil
	stale := cl.sweepLocked()
	if len(cl.idle) > 0 {
		cl.scheduleSweepLocked()
	}
	cl.mu.Unlock()
	for _, ic := range stale {
		ic.c.Close()
	}
}

// sweepLocked haalt de verlopen verbindingen van ÁLLE hosts uit de pool en
// geeft ze terug om te sluiten. Aanroepen met cl.mu vast.
//
// Waarom over alle hosts en niet alleen de host die je nodig hebt: de
// idle-timeout werd alleen afgedwongen in get(addr), dus een verbinding naar een
// host die je nooit meer belt bleef staan tot het einde der tijden. Op een
// gewone machine is dat een socket die niemand mist. Op een node is het een stuk
// van de netstack-pot: leannet houdt de buffers van een open verbinding
// gereserveerd, en die groeien mee met wat er door ging — een afgeronde download
// van 5MB laat dus een dikke verbinding achter.
//
// GEMETEN 12-08 op een LicheeRV: HOP haalde app-images op bij een artifact-server,
// liet er twee gepoold achter, en had daarna zo weinig pot over dat élke nieuwe
// verbinding "buffer budget exhausted" kreeg. De watchdog eist voor zijn
// levensteken juist een VERSE verbinding naar de agent-poort — dus resette de
// node zichzelf, twee keer op één avond.
func (cl *Client) sweepLocked() []idleConn {
	timeout := cl.IdleTimeout
	if timeout == 0 {
		timeout = defaultIdleTimeout
	}
	now := time.Now() // één klokread voor de hele sweep, niet één per verbinding
	var stale []idleConn
	for addr, list := range cl.idle {
		keep := list[:0]
		for _, ic := range list {
			if now.Sub(ic.when) < timeout {
				keep = append(keep, ic)
				continue
			}
			stale = append(stale, ic)
		}
		if len(keep) == 0 {
			delete(cl.idle, addr)
			continue
		}
		cl.idle[addr] = keep
	}
	return stale
}

// pooledConn is een verbinding uit de pool plus de bufio.Reader die er al op
// stond. Do gebruikt die lezer in plaats van een nieuwe te maken — anders
// zouden bytes die al in de oude buffer stonden verloren gaan.
type pooledConn struct {
	net.Conn
	br *bufio.Reader
}

// idleCount en idleFor zijn er voor de tests in dit package: de pool is
// opzettelijk niet naar buiten zichtbaar, maar wat hij vasthoudt is precies wat
// getest moet worden.
func (cl *Client) idleCount() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	n := 0
	for _, list := range cl.idle {
		n += len(list)
	}
	return n
}

func (cl *Client) idleFor(addr string) int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return len(cl.idle[addr])
}
