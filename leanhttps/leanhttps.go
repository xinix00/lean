// Package leanhttps is https voor bare-metal Go: het knoopt [leanhttp] aan
// [leantls] en verder niets. Het is een SAMENSTELLING (zie de README): het
// voegt geen protocol en geen gedrag toe, het doet één knoop goed die anders
// elke gebruiker zelf legt.
//
// Waarom die knoop een pakket verdient — het zijn precies de drie dingen die
// je erin fout kunt doen:
//
//  1. SNI per HOST, niet per verzoek. Een release-URL van GitHub redirect naar
//     een CDN op een ándere hostnaam; wie zijn TLS-config één keer opbouwt met
//     een vaste ServerName, valideert na die redirect tegen de verkeerde naam.
//     Hier komt de naam uit het dial-adres, dus hij volgt de redirect mee.
//  2. Poort 443 zonder vertrouwensmodel. leantls weigert dat zelf luid, maar
//     alleen als je zijn Config doorgeeft in plaats van er zelf een te maken
//     met een lege VerifyPeer — dit pakket geeft hem door.
//  3. De verbinding sluiten op een 3xx. Dat doet leanhttp al, maar alleen als
//     de dialer per verzoek geroepen wordt (en dat is hier zo).
//
// Wat het NIET doet: TLS aan wie het niet vraagt. Importeer je [leanhttp]
// rechtstreeks, dan linkt je binary geen byte TLS — dit pakket is de enige
// plek waar de twee elkaar zien. Dat is de eigenschap die een samenstelling
// van een framework onderscheidt, en er staat een test op.
//
// Gemeten (2026-08-12, tamago/riscv64, zelfde main met alleen de HTTP/TLS-kant
// verschillend, `-w -T 0x84010000`):
//
//	board + fmt (de vloer) .................... 2,09 MB
//	net/http + crypto/tls + CA-bundel ......... 5,77 MB   (wat je vervangt)
//	dit pakket, keten via leantls/x509verify .. 3,75 MB   (−2,01)
//	dit pakket, gepinde sleutel ............... 2,65 MB   (−3,12)
//
// Alle vier met dezelfde main en dezelfde board-vloer, alleen de HTTP/TLS-kant
// verschilt; de twee middelste doen functioneel hetzelfde (https ophalen met
// echte certificaatvalidatie).
//
// De sprong zit vooral in net/http: dat pakket linkt crypto/tls
// onvoorwaardelijk, dus zolang het in je binary staat kost TLS je niets extra
// én levert het weglaten ervan niets op. Vervang eerst de HTTP-kant; daarna is
// de TLS-keuze pas een keuze.
//
// # Gebruik
//
// Een tegenpartij die je al kent (goedkoop: geen PKI in het image):
//
//	c := leanhttps.Client{TLS: &leantls.Config{PeerKey: leaderKey}}
//	resp, err := c.Get("https://leader.internal/v1/jobs")
//
// Een echte certificaatketen (github.com en andere publieke servers):
//
//	c := leanhttps.Client{TLS: &leantls.Config{
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	}}
//	resp, err := c.Get("https://github.com/org/repo/releases/download/tag/app.elf")
//
// Laat ServerName leeg: dit pakket vult hem per verbinding met de host die hij
// dialt. Zet je hem zelf, dan geldt hij voor élke host in de redirect-keten en
// dat is bijna nooit wat je bedoelt — daarom weigert Client dat luid.
package leanhttps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xinix00/lean/leanhttp"
	"github.com/xinix00/lean/leantls"
)

// Client doet https-verzoeken. TLS is verplicht: zonder vertrouwensmodel is er
// niets te knopen, en een default verzinnen zou precies de stille fout zijn die
// leantls weigert te maken.
type Client struct {
	// TLS is het vertrouwensmodel: PeerKey (gepind) of VerifyPeer (keten).
	// ServerName hoort leeg te blijven — zie de pakketdoc.
	TLS *leantls.Config

	// Timeout dekt één verzoek inclusief het lezen van de body; 0 = geen
	// termijn (een blijvende stream hoort niet af te lopen).
	Timeout time.Duration
}

var errNoConfig = errors.New("leanhttps: Client.TLS is nil — set PeerKey (a pinned peer) or VerifyPeer (a chain); there is no default")

// Get haalt één URL op en geeft de response; een niet-200 is een fout, net als
// bij [leanhttp.Get]. Voor alles anders dan GET: [Client.Do].
func (c Client) Get(url string) (*leanhttp.Response, error) {
	call, err := c.call(leanhttp.Call{URL: url})
	if err != nil {
		return nil, err
	}
	return leanhttp.GetCall(call)
}

// Do voert één verzoek uit; een foutstatus is geen fout (de aanroeper leest hem
// zelf), net als bij [leanhttp.Do].
func (c Client) Do(call leanhttp.Call) (*leanhttp.Response, error) {
	call, err := c.call(call)
	if err != nil {
		return nil, err
	}
	return leanhttp.Do(call)
}

// DialerContext geeft de TLS-dialer los, om in een [leanhttp.Client] te
// hangen: dan poolt die versleutelde verbindingen (keep-alive over TLS).
//
//	pool := &leanhttp.Client{DialContext: leanhttps.DialerContext(tlsCfg)}
//
// De config wordt niet gemuteerd en ServerName komt per verbinding uit het
// dial-adres, net als bij [Client]. (De contextloze Dialer-vorm is gesloopt
// in review 13-08, dertigste ronde: één dialer-gedaante.)
func DialerContext(cfg *leantls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return Client{TLS: cfg}.dial
}

// call hangt de TLS-dialer aan een leanhttp.Call. Dit is het hele pakket.
func (c Client) call(call leanhttp.Call) (leanhttp.Call, error) {
	if c.TLS == nil {
		return call, errNoConfig
	}
	if c.TLS.ServerName != "" {
		return call, fmt.Errorf("leanhttps: leave Config.ServerName empty (%q) — "+
			"this package sets it per connection, so it follows a redirect to another host",
			c.TLS.ServerName)
	}
	if call.Timeout == 0 {
		call.Timeout = c.Timeout
	}
	// DialContext, niet Dial: dan draagt de totaaltermijn van de call als
	// context-deadline door tot in de TCP-dial en de handshake — een dial die
	// leanhttp allang opgaf leeft dan ook zelf niet meer door (review 13-08,
	// vijftiende ronde).
	call.DialContext = c.dial
	return call, nil
}

// dial verbindt versleuteld. De SNI-naam komt uit addr — dus uit de host die
// leanhttp op DIT moment wil bereiken, niet uit de oorspronkelijke URL.
func (c Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.TLS == nil {
		// DialerContext(nil) levert deze dialer zónder de wacht in call():
		// een fout bij het dialen is laat maar leesbaar, een nil-deref op
		// c.TLS.PeerKey hieronder was een panic vijf lagen van de oorzaak
		// (review 13-08, eenendertigste ronde).
		return nil, errNoConfig
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// Een IP-adres is geen naam om tegen te valideren; met een gepinde sleutel
	// hoeft dat ook niet (de sleutel ís de identiteit), met een keten wél — en
	// dan hoort dat luid te falen in plaats van tegen een lege naam te matchen.
	if c.TLS.PeerKey == nil && net.ParseIP(host) != nil {
		return nil, fmt.Errorf("leanhttps: %s is an IP address, so there is no name to verify a "+
			"chain against — use a hostname, or pin the peer's key", host)
	}
	cfg := *c.TLS // kopie: de dialer mag de config van de aanroeper niet muteren
	cfg.ServerName = strings.TrimSuffix(host, ".")
	return leantls.DialContext(ctx, network, addr, &cfg)
}
