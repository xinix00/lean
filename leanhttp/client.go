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
	"net"
	"sync"
	"time"

	"bufio"
)

// Standaardmaten van de pool. Twee verbindingen per host is wat een pagina met
// parallelle resources nodig heeft zonder een server te bestormen; 30 seconden
// idle is ruim onder wat servers zelf dichtgooien (nginx: 75s, Go: 3 minuten).
const (
	defaultMaxIdlePerHost = 2
	defaultIdleTimeout    = 30 * time.Second
)

// Client doet verzoeken mét keep-alive. Hij is veilig voor gelijktijdig
// gebruik; de zero value werkt (dial via net.DialTimeout, twee idle
// verbindingen per host, 30s idle-timeout).
//
// De package-level [Do] en [Get] blijven de kale vorm: één verzoek per
// verbinding, Connection: close. Wie geen pool wil, verandert niets.
type Client struct {
	// Dial maakt een nieuwe verbinding; nil = net.DialTimeout op tcp4. Zelfde
	// contract als [Call.Dial] — een TLS-dialer past er dus ook op, en dan
	// poolt dit type versleutelde verbindingen.
	Dial func(network, addr string) (net.Conn, error)

	// MaxIdlePerHost is hoeveel ongebruikte verbindingen per host blijven
	// staan; 0 = 2. Meer kost geheugen en socket-slots op de server, minder
	// kost handshakes.
	MaxIdlePerHost int

	// IdleTimeout is hoe lang een ongebruikte verbinding blijft staan; 0 = 30s.
	// Wie langer wacht dan de server, krijgt een verbinding die al dicht is —
	// daarom staat dit ruim onder de gangbare server-waarden.
	IdleTimeout time.Duration

	mu   sync.Mutex
	idle map[string][]idleConn
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
	call.keepAlive = true
	call.pool = cl
	if call.Dial == nil {
		call.Dial = cl.dial
	}
	return Do(call)
}

// Get is [Get] over de pool: 200 mét Content-Length vereist.
func (cl *Client) Get(url string) (*Response, error) {
	call := Call{URL: url, keepAlive: true, pool: cl}
	call.Dial = cl.dial
	if cl.Dial != nil {
		call.Dial = cl.Dial
	}
	return GetCall(call)
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

// dial pakt eerst een verbinding uit de pool; is er geen, dan een verse.
func (cl *Client) dial(network, addr string) (net.Conn, error) {
	if c, br := cl.get(addr); c != nil {
		return &pooledConn{Conn: c, br: br}, nil
	}
	if cl.Dial != nil {
		return cl.Dial(network, addr)
	}
	return net.DialTimeout(network, addr, dialTimeout)
}

// get haalt een bruikbare verbinding voor addr uit de pool. Verlopen
// verbindingen gaan onderweg dicht — een idle socket die de server al
// opgeruimd heeft, is geen verbinding maar een fout op het volgende verzoek.
func (cl *Client) get(addr string) (net.Conn, *bufio.Reader) {
	timeout := cl.IdleTimeout
	if timeout == 0 {
		timeout = defaultIdleTimeout
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	list := cl.idle[addr]
	for len(list) > 0 {
		ic := list[len(list)-1] // laatst teruggegeven = warmst
		list = list[:len(list)-1]
		if time.Since(ic.when) < timeout {
			cl.idle[addr] = list
			return ic.c, ic.br
		}
		ic.c.Close()
	}
	delete(cl.idle, addr)
	return nil, nil
}

// put geeft een verbinding terug; false = de pool wil hem niet (vol), en dan
// sluit de aanroeper hem. Alleen body.Close roept dit aan, en alleen als de
// body helemaal gelezen is.
func (cl *Client) put(addr string, c net.Conn, br *bufio.Reader) bool {
	if addr == "" {
		return false
	}
	max := cl.MaxIdlePerHost
	if max == 0 {
		max = defaultMaxIdlePerHost
	}
	// De deadline van het vorige verzoek mag niet op een verbinding blijven
	// staan die straks een ander verzoek draagt.
	c.SetDeadline(time.Time{})
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(cl.idle[addr]) >= max {
		return false
	}
	if cl.idle == nil {
		cl.idle = make(map[string][]idleConn)
	}
	cl.idle[addr] = append(cl.idle[addr], idleConn{c: c, br: br, when: time.Now()})
	return true
}

// pooledConn is een verbinding uit de pool plus de bufio.Reader die er al op
// stond. Do gebruikt die lezer in plaats van een nieuwe te maken — anders
// zouden bytes die al in de oude buffer stonden verloren gaan.
type pooledConn struct {
	net.Conn
	br *bufio.Reader
}
