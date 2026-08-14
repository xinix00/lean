// Package leanhttp is HTTP/1.1 zonder TLS: een kleine client (Get, Do) én een
// kleine server (Serve) voor programma's die alleen plain http praten — een
// buur op het LAN, een lokale API, of zélf een pagina of stream serveren.
//
// Het bestaat omdat net/http onvoorwaardelijk crypto/tls meelinkt, ook als je
// nooit een https-URL opent. Gemeten in HopOS-app-images (26-07, op app/hello):
//
//	applib alleen ............... 1,71 MB
//	+ appnet (gVisor) ........... 4,70 MB
//	+ net/http .................. 7,99 MB   <- meer dan de netstack zelf
//	+ dit pakket i.p.v. net/http  5,06 MB
//
// Van wat net/http toevoegt is ~54% TLS/PKI (crypto/tls + x/crypto + x509 +
// math/big + asn1), geen HTTP. Op drie echte apps scheelde het ~2,9 MB per
// stuk, met nul crypto/tls-symbolen in de symboltabel:
//
//	display  8,68 MB -> 5,88 MB   (serveert een pagina plus een web-KVM)
//	launcher 8,42 MB -> 5,48 MB   (POST/DELETE naar een lokale API)
//	taskman  8,45 MB -> 5,54 MB   (idem plus een SSE-logstaart)
//
// Wie wél https praat hoort net/http te gebruiken. Dit pakket is voor code die
// zelf weet dat zijn verkeer plain http is.
//
// Wat dit NIET doet, en waarom dat mag:
//
//   - geen https. Een https-URL faalt LUID met een duidelijke melding -- nooit
//     stil, want dit pakket bestaat juist om geen TLS te linken.
//   - de package-level Do/Get doen één verzoek per verbinding (Connection:
//     close). Wie een reeks verzoeken naar dezelfde host doet, gebruikt
//     [Client]: die poolt verbindingen (keep-alive) en geeft ze alleen terug
//     als de body helemaal gelezen is. De serverkant hergebruikt altijd (zie
//     serve.go): een pagina die frames pollt hoort niet elke keer een
//     TCP-handdruk te betalen.
//   - geen HTTP/2. Geen compressie in het pakket: de default is
//     Accept-Encoding: identity, maar wie hem zelf zet krijgt hem doorgegeven
//     en leest in Response.Encoding wat er terugkwam (zo blijft compress/gzip
//     buiten dit pakket). Geen cookies: die wonen in leancookie, dat niets van
//     HTTP weet en dus ook niets meelinkt.
//
// Chunked transfer kan dit pakket wél lezen (Do) en schrijven (Flush) -- dat is
// niet optioneel zodra je een SSE-staart of een frame-stream wilt, en het is
// veertig regels. Alleen [Get] weigert hem: die belooft zijn aanroeper een
// vooraf bekende lengte en een antwoord zonder Content-Length kan dat niet
// waarmaken.
//
// Redirects worden gevolgd (bounded, alleen voor verzoeken zonder body).
//
// De headerparser leest netwerkdata van een tegenpartij die wij niet schreven,
// dus hij is dubbel begrensd: per regel (readLine, via de bufio-buffer) én
// cumulatief (maxHeaderBytes). Aan de clientkant staat de body erna vrij -- die
// lengte kondigt Content-Length aan en de aanroeper toetst hem; aan de
// serverkant is ook de body begrensd (maxBodyBytes).
//
// Gaat via net.Dial en net.Listen, verder niets.
package leanhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// dialTimeout begrenst het opzetten van de verbinding: een onbereikbare
	// host mag geen job-start gijzelen. De download zelf staat bewust vrij
	// (Call.Timeout is er voor wie wél een totaaltermijn wil).
	dialTimeout = 10 * time.Second

	// maxRedirects volgt hetzelfde plafond als net/http's default.
	maxRedirects = 10

	// expectTimeout is hoe lang een gestroomde upload op het oordeel van de
	// server wacht (100 of een vroege finale status) als er geen strakkere
	// termijn geldt (HeaderTimeout/Timeout). Stilte is daarna een FOUT en de
	// verbinding gaat dicht — er is geen stuur-toch-pad (zie de Expect-dans).
	expectTimeout = 10 * time.Second

	// bufSize is tevens de maximale lengte van één headerregel: readLine leest
	// via ReadSlice, dus een regel die niet in de buffer past is een fout i.p.v.
	// ongebonden geheugengroei. Ruim voor elke echte header.
	bufSize = 8 << 10

	// maxHeaderBytes is de cumulatieve grens: veel kleine regels passen elk
	// binnen bufSize maar mogen samen niet ongebonden groeien.
	maxHeaderBytes = 64 << 10
)

// Statuscodes die dit pakket zelf noemt — genoeg om aanroepers leesbaar te
// houden zonder net/http's volledige lijst over te schrijven.
const (
	StatusOK                    = 200
	StatusCreated               = 201
	StatusNoContent             = 204
	StatusFound                 = 302
	StatusBadRequest            = 400
	StatusNotFound              = 404
	StatusMethodNotAllowed      = 405
	StatusRequestEntityTooLarge = 413
	StatusExpectationFailed     = 417
	StatusInternalServerError   = 500
	StatusNotImplemented        = 501
)

// Header is één verzameling headers. HTTP-headernamen zijn
// hoofdletter-ongevoelig, dus Get/Set zijn dat ook; de opgeslagen schrijfwijze
// is die van de zender (client) of van de draad (server).
type Header map[string]string

// Get geeft de waarde van key ("" als hij ontbreekt), ongeacht schrijfwijze.
func (h Header) Get(key string) string {
	if v, ok := h[key]; ok { // snelle weg: exact zoals opgeslagen
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// Set zet key op value en ruimt een afwijkend gespelde dubbel op.
func (h Header) Set(key, value string) {
	h.Del(key)
	h[key] = value
}

// Del verwijdert key, hoe hij ook gespeld is.
func (h Header) Del(key string) {
	for k := range h {
		if strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
}

// add voegt toe: een herhaalde header wordt één komma-lijst (RFC 9110 §5.3),
// zodat een tweede regel de eerste niet stil overschrijft.
func (h Header) add(key, value string) {
	if cur := h.Get(key); cur != "" {
		value = cur + ", " + value
	}
	h.Set(key, value)
}

// Call is één uitgaand verzoek voor [Do]. Host, Content-Length, Connection en
// Accept-Encoding zet Do zelf — die staan niet ter discussie.
type Call struct {
	Method  string        // "" = GET
	URL     string        // http://, of https:// mét Dial (zie daar)
	Header  Header        // extra verzoekheaders (mag nil zijn)
	Body    []byte        // nil = geen body
	Timeout time.Duration // totaaltermijn incl. body-lezen; 0 = geen (blijvende streams)

	// HeaderTimeout begrenst ALLEEN het wachten op de antwoordkop, niet de body.
	//
	// Die twee zijn verschillende vragen, en een download laat dat zien: een
	// artifact van 30MB wil géén totaaltermijn (die kapt het bestand af) maar ook
	// niet oneindig wachten op een server die de verbinding aanneemt en dan
	// zwijgt. Eén deadline kan dat niet, dus zijn het twee velden. 0 = geen
	// aparte grens.
	HeaderTimeout time.Duration

	// BodyReader stuurt de body als STROOM in plaats van als []byte, en dan is
	// BodyLen verplicht (dit pakket chunkt niet: een Content-Length is de hele
	// afspraak met de server). Body en BodyReader sluiten elkaar uit.
	//
	// Waarom dit bestaat: een object-store-upload is de ene body die niet in het
	// geheugen hoort. Een app-image door []byte duwen betekent hem twee keer in
	// het geheugen hebben op een node die 64MB heeft — precies de OOM die HopOS
	// op 11-08 al eens doodde. Een stroom kost één buffer, ongeacht de maat.
	//
	// Een gestroomde body kan niet opnieuw verstuurd worden, dus [Do] volgt geen
	// redirect: de 3xx komt bij de aanroeper terecht, net als bij Body.
	//
	// Een stroom vraagt eerst het oordeel van de server (Expect:
	// 100-continue): een vroege 401/413 spaart de hele upload uit. De server
	// MOET dat oordeel geven (een 100 of een finale status); stilte is na
	// expectTimeout een fout en de verbinding gaat dicht — het oude
	// na-één-seconde-tóch-sturen-pad vergiftigde op TLS de reader blijvend
	// (review 13-08, eenendertigste ronde).
	BodyReader io.Reader
	BodyLen    int64

	// DialContext maakt de verbinding; nil = de stdlib-dialer op tcp4, en dan
	// blijft dit pakket wat het is: plain http zonder één byte TLS.
	//
	// De naad is er voor álles wat een andere verbinding wil zijn dan een
	// kale TCP-dial: een proxy, een testdubbel, en vooral een versleutelde
	// verbinding (leanhttps.DialerContext past hier). addr is "host:poort"
	// mét de hostnaam erin (voor SNI); bij een redirect naar een andere host
	// wordt de dialer opnieuw geroepen met die nieuwe host. De context draagt
	// de totaaltermijn (Timeout, over alle redirects heen): een dialer hoort
	// op ctx.Done() op te geven.
	//
	// (De kale Dial-gedaante zonder context is gesloopt in review 13-08,
	// dertigste ronde: er waren nog twee gebruikers — hophttp en leans3,
	// allebei van ons — en één gedaante scheelt de dialBounded-adapter, het
	// eindigheids-contract en een klasse uiteenloop-bugs.)
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NoFollow geeft de 3xx aan de aanroeper in plaats van hem te volgen.
	//
	// Wie een cookie-jar heeft MOET dit zetten. Redirects volgen is namelijk
	// niet één ronde maar een keten, en op elke stap kan een Set-Cookie staan
	// die de vólgende stap nodig heeft — dat is precies hoe een consent- of
	// login-muur werkt. [Do] kent geen jar en kan die stap dus niet zetten;
	// wie er wel een heeft, loopt de keten zelf af en past per stap zijn
	// cookies toe.
	NoFollow bool
}

// Response is één antwoord. Body is de ongelezen responsebody; sluit hem (dat
// sluit de verbinding). Length is de aangekondigde Content-Length, of -1 als
// het antwoord chunked is of tot EOF loopt.
type Response struct {
	StatusCode int
	Status     string // code met reden, bv. "404 Not Found" (zoals net/http)
	Header     Header
	Body       io.ReadCloser
	Length     int64

	// URL is de URL waar dit antwoord vandaan kwam: ná de redirects, dus niet
	// per se de URL die je vroeg. Wie iets relatiefs oplost tegen de aangevraagde
	// URL in plaats van tegen deze, mist elke link op een pagina die verhuisd is
	// — en dat is de helft van het web (http→https, /pad→/pad/).
	URL string

	// Encoding is de Content-Encoding van het antwoord ("" = geen). Dit pakket
	// pakt niets uit; wie Accept-Encoding zet, leest hier wat hij terugkreeg en
	// wikkelt Body zelf (bijvoorbeeld in gzip.NewReader).
	Encoding string

	// SetCookie zijn de Set-Cookie-regels, één per element en ONGEVOUWEN.
	// Ze staan apart omdat ze de uitzondering van de HTTP-specificatie zijn:
	// herhaalde headers mogen als komma-lijst samengevoegd worden (RFC 9110
	// §5.3) — behalve deze, want een cookie-waarde en een Expires-datum
	// bevatten zelf komma's ("Expires=Mon, 02 Jan 2026 ..."). Gevouwen is die
	// lijst niet betrouwbaar terug te splitsen, en dan lees je één cookie waar
	// er twee stonden. Header bevat ze dus NIET; leancookie eet dit veld.
	SetCookie []string

	chunked bool // voor Get: het onderscheid tussen "chunked" en "geen lengte"
}

// Get doet één HTTP/1.1 GET en geeft de body als stream plus zijn lengte.
// Volgt redirects (tot maxRedirects) en eist een 200 mét Content-Length: wie
// Get gebruikt wil een bestand van bekende omvang, geen half antwoord. Voor al
// het andere is er [Do].
func Get(raw string) (*Response, error) { return GetCall(Call{URL: raw}) }

// GetCall is Get met de rest van de Call erbij — headers, een termijn, of een
// eigen [Call.DialContext]. Zelfde eisen: een 200 mét Content-Length. Dit is wat Get
// is voor Do: dezelfde ronde, maar met de controles die een bestand-ophaler
// wil.
func GetCall(c Call) (*Response, error) {
	resp, err := Do(c)
	if err != nil {
		return nil, err
	}
	return checkGet(resp)
}

// checkGet zijn de Get-eisen op een al-ontvangen antwoord: een 200 mét
// Content-Length. Gedeeld door GetCall en Client.Get.
func checkGet(resp *Response) (*Response, error) {
	switch {
	case resp.StatusCode != StatusOK:
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: HTTP %s", resp.Status)
	case resp.chunked:
		// Een image zónder lengte kon de apploader nooit stagen (hij weigerde
		// ContentLength <= 0): luid falen i.p.v. half werk.
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: chunked/encoded transfer is not supported here — serve the artifact with a Content-Length")
	case resp.Length < 0:
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: no Content-Length in response")
	}
	return resp, nil
}

// Do voert één verzoek uit en geeft het antwoord — óók een 404 of een 500: een
// foutstatus is geen transportfout, de aanroeper leest hem zelf (en zijn body,
// die vaak zegt wat er mis is). Redirects worden gevolgd zolang het verzoek
// geen body heeft; met body (of BodyReader) krijgt de aanroeper de 3xx zelf te
// zien, want een POST opnieuw afvuren op een ander pad is niet aan dit pakket —
// en een stroom is niet eens opnieuw te versturen.
func Do(c Call) (*Response, error) { return doVia(c, nil) }

// doVia is Do mét zijn transport: via is de Client wiens pool en dialer deze
// call draagt, of nil voor de kale éénmalige vorm. Een parameter en geen
// Call-veld, want dat veld moest élk constructiepad correct zetten — drie
// reviewrondes op precies die naad (pool-bypass in Get, plaintext-443 op een
// redirect, per-call-DialContext-menging) kwamen alle drie neer op "de pool-dialer
// vermomd als Call.DialContext" (review 13-08, zesde ronde).
func doVia(c Call, via *Client) (*Response, error) {
	// Eén absolute termijn voor de HELE call, redirects inbegrepen: de klok
	// startte eerst pas ná de dial en elke redirect kreeg een verse Timeout —
	// een call met Timeout: 1s kon zo lang dialen en per hop opnieuw een
	// seconde krijgen (review 13-08, tiende ronde).
	var total time.Time
	if c.Timeout > 0 {
		total = time.Now().Add(c.Timeout)
	}
	loc := c.URL
	for range maxRedirects + 1 {
		resp, err := do(c, via, loc, total)
		if err != nil && errors.Is(err, errStalePooled) && c.BodyReader == nil &&
			(c.Method == "" || c.Method == "GET" || c.Method == "HEAD") &&
			!errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
			// Eén veilige herkansing (zie errStalePooled) — en alléén voor
			// GET/HEAD: "geen BodyReader" was te ruim, een bodyloze POST of
			// DELETE is niet replay-safe. Timeouts tellen niet als stale (de
			// herkansing zou toch meteen verlopen). En de herkansing OMZEILT
			// de pool: met twee stale verbindingen erin (de standaardcap)
			// verloor één herkansing anders alsnog — een eigen DialContext op
			// de call dwingt een verse verbinding af, en het antwoord poolt
			// daarna gewoon weer (review 13-08, achtentwintigste ronde).
			fresh := c
			fresh.DialContext = normalizeDial(via.DialContext)
			resp, err = do(fresh, via, loc, total)
		}
		if err != nil {
			return nil, err
		}
		// Automatisch volgen alleen voor de vijf échte redirect-statussen
		// (301/302/303/307/308, RFC 9110 §15.4) en alleen voor GET/HEAD.
		// "Geen body" was een proxy voor "veilig te herhalen", maar een
		// bodyloze POST of DELETE is dat niet (die werd stil op de nieuwe URL
		// heruitgevoerd), een 303 hoort een POST juist naar een retrieval om
		// te zetten, en een 304 is een cache-validatieantwoord — geen
		// doorverwijzing, ook niet mét Location (review 13-08,
		// tweeëntwintigste ronde). Elke andere methode of status krijgt de
		// 3xx gewoon terug, zoals bij NoFollow: de aanroeper beslist.
		next := ""
		if !c.NoFollow && c.Body == nil && c.BodyReader == nil &&
			(c.Method == "" || c.Method == "GET" || c.Method == "HEAD") {
			switch resp.StatusCode {
			case 301, 302, 303, 307, 308:
				next = resp.Header.Get("Location")
			}
		}
		if next == "" {
			return resp, nil
		}
		// Redirect: de body van het 3xx-antwoord interesseert ons niet, maar de
		// verbinding moet dicht vóór we de volgende opzetten (Connection: close
		// belooft de server hetzelfde, maar wij houden onze fd's in eigen hand).
		resp.Body.Close()
		base, err := url.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("leanhttp: bad URL %q: %w", loc, err)
		}
		ref, err := url.Parse(next)
		if err != nil {
			return nil, fmt.Errorf("leanhttp: bad Location %q: %w", next, err)
		}
		dest := base.ResolveReference(ref)
		// Een https→http-degradatie volgen we NOOIT: wat de aanroeper
		// versleuteld begon hoort niet op een wenk van de server het
		// plaintext-net op — ook niet "zonder headers", want de URL zelf (het
		// pad, de query, een signed token daarin) is dan al de lekkage. Wie
		// dit écht wil, zet NoFollow en volgt zelf (review 13-08,
		// eenendertigste ronde).
		if strings.EqualFold(base.Scheme, "https") && !strings.EqualFold(dest.Scheme, "https") {
			return nil, fmt.Errorf("leanhttp: refusing redirect from %s to %s: https must not degrade to plain http", loc, dest)
		}
		// Callerheaders reizen alleen mee binnen dezelfde ORIGIN (schema én
		// host én poort) — en cross-origin gaan ze er ÁLLEMAAL af, niet alleen
		// een lijstje "gevoelige": welke header een geheim draagt weet alleen
		// de aanroeper (X-Api-Key, een HMAC-header, een sessie-token in een
		// eigen naam), en een blocklist die dat moet raden is precies de fout
		// die pas opvalt als het geheim al bij de CDN ligt (review 13-08,
		// eenendertigste ronde; de blocklist was de tweede/vijfentwintigste).
		if originOf(dest) != originOf(base) {
			c.Header = nil
		}
		loc = dest.String() // een relatieve Location mag
	}
	return nil, fmt.Errorf("leanhttp: too many redirects (>%d) starting at %s", maxRedirects, c.URL)
}

// Intern bestaat er maar ÉÉN dialervorm: die van DialContext. De totaaltermijn
// reist als context-deadline. (De kale Dial-gedaante en zijn
// dialBounded-adapter zijn in de dertigste ronde gesloopt; de normalisatie
// die overblijft is alleen nog "geen dialer = de stdlib-dialer".)

// normalizeDial vouwt de ene publieke dialer-gedaante naar de interne vorm:
// DialContext zoals hij is, en niets = de stdlib-dialer (net.Dialer
// combineert zijn Timeout zelf met de ctx-deadline; wie het eerst om is
// wint). Call- en Client-dialers gaan hier allebei doorheen en zijn dus per
// constructie identiek genormaliseerd — "de twee dialer-ingangen liepen
// uiteen" was letterlijk de bugklasse die drie rondes kostte (review 13-08,
// zesentwintigste ronde).
func normalizeDial(dc func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if dc != nil {
		return dc
	}
	return (&net.Dialer{Timeout: dialTimeout}).DialContext
}

// errStalePooled markeert een verzoek dat op een HERGEBRUIKTE verbinding
// faalde vóór de eerste antwoordbyte: vrijwel altijd een server die zijn idle
// keep-alive net sloot. doVia herkanst dan één keer — veilig, want er is
// niets geconsumeerd en het hele verzoek gaat opnieuw (review 13-08,
// vijfentwintigste ronde).
var errStalePooled = errors.New("leanhttp: pooled connection went stale")

// originOf normaliseert schema+host+poort tot één origin: http zonder poort
// ís poort 80, https 443 — http://host en http://host:80 zijn dezelfde origin
// en gevoelige headers hoorden daartussen gewoon mee te reizen (review 13-08,
// vijfentwintigste ronde).
func originOf(u *url.URL) string {
	host := u.Host
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			host += ":80"
		case "https":
			host += ":443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(host)
}

// do doet één ronde: verbinden, verzoek schrijven, antwoordkop lezen. via is
// het transport (zie doVia); nil = kale call.
func do(c Call, via *Client, raw string, total time.Time) (_ *Response, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: bad URL %q: %w", raw, err)
	}
	// Luid, niet stil: zonder Dial linkt dit pakket geen TLS, dus is een
	// https-URL een configuratiefout die je op de console hoort te zien — mét
	// de twee uitwegen erin, want een fout die niet zegt wat te doen kost een
	// zoektocht.
	//
	// plainDial: de pool-dialer van een Client zonder eigen (TLS-)Dial spreekt
	// per definitie geen TLS. Afgeleid uit de pool zelf — als apart veld moest
	// élk Call-constructiepad hem correct zetten. En de toets staat hiér, per
	// ronde, omdat een 301 van http naar https het verzoek anders alsnog
	// plaintext naar poort 443 droeg, inclusief Authorization (review 13-08,
	// derde ronde: dat heropende precies het gat dat de schemewacht op de
	// eerste URL dichtte).
	// TLS kan uit twee hoeken komen: een expliciete Call.DialContext, of de
	// eigen DialContext van de Client die deze call draagt.
	hasTLS := c.DialContext != nil || (via != nil && via.DialContext != nil)
	port := "80"
	switch {
	case u.Scheme == "http":
	case u.Scheme == "https" && hasTLS:
		port = "443"
	case u.Scheme == "https":
		return nil, fmt.Errorf("leanhttp: https:// needs a Call.DialContext that returns an "+
			"encrypted connection (this package links no TLS) — use leanhttps, or set DialContext yourself: %s", raw)
	default:
		return nil, fmt.Errorf("leanhttp: only http:// and https:// are supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("leanhttp: URL %q has no host", raw)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(addr, port)
	}

	req, err := requestBytes(c, u, via != nil)
	if err != nil {
		return nil, err
	}

	// Normaliseren naar de ene interne dialervorm (zie normalizeDial): de
	// totaaltermijn reist als context-deadline, dus élk pad — ook de pool en
	// de kale stdlib-dial — leeft erbinnen (review 13-08, elfde/twaalfde
	// ronde: beide gaten waren precies een pad dat total niet kende).
	ctx := context.Background()
	if !total.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, total)
		defer cancel()
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if c.DialContext == nil && via != nil {
		dial = via.dial // pool eerst; de staart normaliseert de Client-dialers
	} else {
		dial = normalizeDial(c.DialContext)
	}
	conn, err := dial(ctx, "tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: dial %s: %w", addr, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("leanhttp: DialContext returned no connection and no error for %s", addr)
	}
	// Elk faalpad hierna sluit de verbinding; het succespad geeft hem als Body
	// aan de aanroeper mee.
	handedOff := false
	defer func() {
		if !handedOff {
			conn.Close()
		}
	}()
	// De termijn dekt álles tot en met het lezen van de body — dat is wat een
	// aanroeper met een timeout bedoelt. Geen timeout = een blijvende stream
	// (een SSE-staart hoort niet af te lopen).
	// total is het ENE moment waarop de hele call om is (nulwaarde = nooit) en
	// komt van doVia: één absolute deadline over álle redirects heen. De kop
	// mag daarbinnen zijn eigen, kortere grens hebben; na de kop gaat de
	// deadline terug naar total, zodat de body de RESTERENDE tijd krijgt en
	// niet een verse termijn.
	if !total.IsZero() {
		// Een transport dat de termijn weigert is onbruikbaar: doorgaan
		// zónder termijn is precies de hang die de aanroeper wilde uitsluiten
		// (review 13-08, achtentwintigste ronde).
		if err := conn.SetDeadline(total); err != nil {
			return nil, fmt.Errorf("leanhttp: set deadline: %w", err)
		}
	}
	// De gebufferde lezer komt VÓÓR de body-send tot leven: de Expect-dans
	// hieronder wil op het antwoord kunnen wachten voordat er één body-byte
	// vertrokken is.
	var br *bufio.Reader
	if pc, ok := conn.(*pooledConn); ok {
		br = pc.br // de pool bewaart de reader bij de verbinding, altijd
	} else {
		br = bufio.NewReaderSize(conn, bufSize)
	}

	// pooled: dit verzoek rijdt op een hergebruikte verbinding. Faalt die vóór
	// de eerste antwoordbyte, dan is dat vrijwel altijd een server die zijn
	// idle keep-alive net sloot — doVia mag dan één keer veilig opnieuw (er is
	// niets van het antwoord geconsumeerd en het hele verzoek gaat opnieuw).
	_, pooled := conn.(*pooledConn)
	stale := func(err error) error {
		if pooled {
			return fmt.Errorf("%w: %w", errStalePooled, err)
		}
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, stale(fmt.Errorf("leanhttp: write request: %w", err))
	}
	// Precies BodyLen bytes: dat is wat de Content-Length de server belooft.
	// Een reader die minder levert laat de server op de rest wachten en de
	// verbinding hangen — dus dat is een fout, niet een korte upload.
	sendStream := func() error {
		n, err := io.CopyN(conn, c.BodyReader, c.BodyLen)
		switch {
		case err != nil:
			return fmt.Errorf("leanhttp: stream body after %d of %d bytes: %w", n, c.BodyLen, err)
		case n != c.BodyLen:
			return fmt.Errorf("leanhttp: BodyReader gave %d bytes, Content-Length promised %d", n, c.BodyLen)
		}
		return nil
	}
	bodySent := c.BodyReader == nil
	if c.BodyReader != nil {
		// De Expect-dans (RFC 9110 §10.1.1): requestBytes stuurde
		// "Expect: 100-continue" mee, dus de server oordeelt éérst; de
		// statusloop hieronder leest dat oordeel — een 100 laat de stroom
		// vertrekken, een vroege 401/413 spaart hem volledig uit. STILTE IS
		// EEN FOUT (eenendertigste ronde), en de termijn daarop is ÉÉN
		// absolute deadline die blijft staan tot het complete oordeel —
		// statusregel én kopblok — binnen is. De Peek(1) die hier stond
		// bewaakte alleen de éérste byte: daarna kreeg de server er een verse
		// kop-termijn bovenop (één byte op 90ms + de rest op 160ms slaagde
		// met HeaderTimeout: 100ms), en zonder verdere termijnen mocht hij na
		// die ene byte zelfs eeuwig zwijgen (review 13-08, tweeëndertigste
		// ronde).
		wacht := time.Now().Add(expectTimeout)
		if c.HeaderTimeout > 0 {
			if h := time.Now().Add(c.HeaderTimeout); h.Before(wacht) {
				wacht = h // het oordeel is een kop: de kop-termijn geldt ook hier
			}
		}
		if !total.IsZero() && total.Before(wacht) {
			wacht = total
		}
		if err := conn.SetDeadline(wacht); err != nil {
			return nil, fmt.Errorf("leanhttp: set deadline: %w", err)
		}
	} else {
		if len(c.Body) > 0 {
			if _, err := conn.Write(c.Body); err != nil {
				return nil, fmt.Errorf("leanhttp: write body: %w", err)
			}
		}
	}
	// De kop-termijn gaat pas NU in: het contract zegt "alleen het wachten op
	// de antwoordkop", en vóór deze verplaatsing stond hij al tijdens de upload
	// aan — een trage S3-upload sneuvelde dan op de header-timeout terwijl er
	// niets mis was (review 13-08, negende ronde). Binnen total blijven. Als
	// closure: de 100-tak in de statusloop moet hem voor de duur van de upload
	// uit- en daarna opnieuw áánzetten (eenendertigste ronde).
	armHeader := func() error {
		if c.HeaderTimeout <= 0 {
			return nil
		}
		if head := time.Now().Add(c.HeaderTimeout); total.IsZero() || head.Before(total) {
			if err := conn.SetDeadline(head); err != nil {
				return fmt.Errorf("leanhttp: set header deadline: %w", err)
			}
		}
		return nil
	}
	if c.BodyReader == nil {
		// De stroom-variant heeft zijn oordeel-deadline al staan en die MOET
		// blijven staan: hem hier verversen gaf de server per fase een nieuw
		// budget (tweeëndertigste ronde). Ná de upload zet de 100-tak hem
		// alsnog via ditzelfde closure.
		if err := armHeader(); err != nil {
			return nil, err
		}
	}

	// Een verbinding uit de pool draagt zijn eigen bufio.Reader mee: daar kunnen
	// bytes in staan die al van de socket gelezen zijn (de server stuurde kop en
	// body in één pakket). De Reader is hierboven al aan de verbinding
	// gebonden (vóór de Expect-dans).
	budget := maxHeaderBytes

	// Interim-antwoorden (1xx) zijn geen eindantwoord: een 100 Continue of een
	// 103 Early Hints heeft een eigen kopblok en daarná komt het echte antwoord
	// op dezelfde verbinding. Ze als eindantwoord teruggeven desynchroniseert
	// een keep-alive-verbinding onmiddellijk (review 13-08). Het budget is
	// cumulatief over de interims — de totale kop blijft begrensd. 101 is een
	// protocolwissel en die spreken we niet.
	var code int
	var proto, status string
	firstRead := true
	for {
		line, err := readLine(br, &budget)
		if err != nil {
			if firstRead {
				if c.BodyReader != nil && !bodySent {
					// Geen (complete) statusregel binnen de oordeel-termijn:
					// deze server spreekt (waarschijnlijk) geen Expect. Dat is
					// een expliciete mismatch — benoemen scheelt de zoektocht
					// die een kale "read status line: timeout" zou starten.
					return nil, fmt.Errorf("leanhttp: no verdict on Expect: 100-continue (want 100 or a final status): %w", err)
				}
				// Nog geen antwoordbyte gezien: op een gepoolde verbinding is
				// dit het stale-keep-alive-geval en mag doVia herkansen. Ná
				// een gelezen interim niet meer — er is dan al geconsumeerd.
				return nil, stale(fmt.Errorf("leanhttp: read status line: %w", err))
			}
			return nil, fmt.Errorf("leanhttp: read status line: %w", err)
		}
		firstRead = false
		if code, proto, err = statusCode(line); err != nil {
			return nil, err
		}
		if code < 100 || code > 199 {
			_, status, _ = strings.Cut(line, " ") // "HTTP/1.1 404 Not Found" → "404 Not Found"
			break
		}
		if code == 101 {
			return nil, fmt.Errorf("leanhttp: server switched protocols (101); this package speaks HTTP/1.1 only")
		}
		// De (meestal lege) kop van het interim-antwoord wegslikken.
		if err := readHeaderBlock(br, &budget, nil); err != nil {
			return nil, fmt.Errorf("leanhttp: read interim headers: %w", err)
		}
		if code == 100 && !bodySent {
			// Het oordeel is er: de stroom mag vertrekken (Expect-dans). De
			// kop-termijn dekt per contract alléén het wachten op een kop, dus
			// hij gaat UIT voor de upload en daarna opnieuw aan — hij stond
			// hier al gewapend en een upload die langer duurde dan de
			// HeaderTimeout sneuvelde zonder dat er iets mis was
			// (review 13-08, eenendertigste ronde).
			if err := conn.SetDeadline(total); err != nil {
				return nil, fmt.Errorf("leanhttp: clear header deadline: %w", err)
			}
			if err := sendStream(); err != nil {
				return nil, err
			}
			bodySent = true
			if err := armHeader(); err != nil {
				return nil, err
			}
		}
	}

	hdr := Header{}
	var setCookie []string
	var length int64 = -1
	var chunked bool
	headerErr := readHeaderBlock(br, &budget, func(k, v string) error {
		switch {
		case strings.EqualFold(k, "Content-Length"):
			// Een tweede, andere lengte is een smokkel-signaal, geen
			// laatste-wint-geval: falen.
			if length >= 0 {
				return fmt.Errorf("leanhttp: duplicate Content-Length")
			}
			// parseDecimal, geen ParseInt: alleen kale cijfers ("+5" is bij een
			// andere parser in de keten een 5, bij weer een andere een fout).
			n, ok := parseDecimal(v)
			if !ok {
				return fmt.Errorf("leanhttp: bad Content-Length %q", v)
			}
			length = n
		case strings.EqualFold(k, "Transfer-Encoding"):
			// Alleen exact "chunked": élke andere codering als chunked lezen
			// legt het lichaamseinde op de verkeerde plek (review 13-08). En
			// maar één keer: elke regel werd los goedgekeurd waarna alleen de
			// boolean won — twee parsers kunnen op zo'n dubbelzinnig antwoord
			// een ander einde zien, en deze verbinding kon daarna de pool in
			// (review 13-08, zeventiende ronde).
			if chunked {
				return fmt.Errorf("leanhttp: duplicate Transfer-Encoding in response")
			}
			if !strings.EqualFold(v, "chunked") {
				return fmt.Errorf("leanhttp: unsupported Transfer-Encoding %q in response", v)
			}
			chunked = true
		case strings.EqualFold(k, "Set-Cookie"):
			// Niet vouwen, niet in Header: zie Response.SetCookie.
			setCookie = append(setCookie, v)
			return nil
		}
		hdr.add(k, v)
		return nil
	})
	if headerErr != nil {
		return nil, fmt.Errorf("leanhttp: read headers: %w", headerErr)
	}
	// Beide framings tegelijk is aan de serverkant al een 400 (RFC 9112 §6.1)
	// en hier net zo hard een fout: "chunked wint" liet de verbinding met een
	// dubbelzinnig geframed antwoord gewoon de pool in, terwijl twee parsers
	// op zo'n antwoord een ander einde kunnen zien (review 13-08, zeventiende
	// ronde). Een fout sluit de verbinding — dat is precies de bedoeling.
	if chunked && length >= 0 {
		return nil, fmt.Errorf("leanhttp: both Transfer-Encoding and Content-Length in response")
	}

	// Een antwoord op HEAD draagt de kop van het GET-antwoord maar géén body
	// (RFC 9112 §6.3): een Content-Length betekent daar niet dat er bytes
	// komen. Zonder deze regel las de client body-bytes die niet bestaan —
	// het volgende antwoord op de verbinding — als de body van de HEAD
	// (review 13-08). Length blijft de geadverteerde waarde (informatief).
	isHEAD := c.Method == "HEAD" // exact: methode-tokens zijn hoofdlettergevoelig (RFC 9110 §9.1)
	var rd io.Reader
	switch {
	case isHEAD:
		rd, chunked = emptyBody{}, false
	case !bodyAllowed(code):
		// 204 en 304 hebben per definitie geen body (RFC 9112 §6.3), ook niet
		// als de server een lengte of Transfer-Encoding meestuurde. Zonder deze
		// regel valt zo'n antwoord in het "tot EOF"-geval hieronder, en op een
		// keep-alive-verbinding komt dat EOF pas als de server zijn idle-timeout
		// haalt. GEMETEN 12-08 door leans3: een S3-DELETE en een
		// hoplockserver-DELETE antwoorden béide met 204, dus élke delete bleef
		// staan tot de tegenpartij hem verveeld dichtgooide (in de test: een
		// `go test` die zijn eigen timeout haalde). De serverkant kende deze
		// regel al; de clientkant niet.
		rd, chunked = emptyBody{}, false
		if code == StatusNoContent || code == 205 {
			length = 0 // een 204/205 draagt per definitie niets (RFC 9110)
		}
		// Een 304 mag een informatieve Content-Length dragen (RFC 9110 §8.6):
		// Length blijft dan de geadverteerde waarde, zoals bij HEAD
		// (review 13-08, vijfentwintigste ronde). Body blijft leeg.
	case chunked:
		rd, length = &chunkReader{br: br}, -1
	case length >= 0:
		// Geen io.LimitReader: die geeft een kale io.EOF, óók als de verbinding
		// halverwege stierf — en dan eindigt een half antwoord als "compleet
		// maar kort bestand". lengthReader kent het verschil (review 13-08).
		rd = &lengthReader{r: br, n: length}
	default:
		rd = br // geen lengte, geen chunks: de body loopt tot EOF
	}

	// De kop is binnen: terug naar de totaal-deadline. Is die er niet (total is
	// de nulwaarde), dan wist dit de deadline en mag de body zo lang duren als
	// hij duurt — een artifact van 30MB hoort niet af te lopen. Ook voor de
	// stroom-variant zónder HeaderTimeout: daar staat de oordeel-deadline
	// (expectTimeout) nog en die hoort niet over de responsebody te regeren.
	if c.HeaderTimeout > 0 || c.BodyReader != nil {
		if err := conn.SetDeadline(total); err != nil {
			return nil, fmt.Errorf("leanhttp: restore deadline: %w", err)
		}
	}

	// Hergebruik mag alleen als we het einde van de body kunnen vinden EN de
	// server de verbinding openhoudt. Zonder lengte en zonder chunks loopt de
	// body tot EOF, en dan IS de verbinding het einde — die kan nooit terug.
	//
	// En het protocol beslist mee, want HTTP/1.0 heeft de omgekeerde default:
	// dáár sluit de server tenzij hij expliciet keep-alive zegt (RFC 9112 §9.3).
	// GEMETEN 12-08: Python's http.server spreekt 1.0 en stuurt een nette
	// Content-Length zonder Connection-header, dus zag dit er precies uit als een
	// herbruikbare verbinding. Gevolg op ijzer: élke tweede artifact-download van
	// zo'n server viel om met "read status line: EOF", en op de server bleven
	// verbindingen staan die niemand meer las.
	connHdr := hdr.Get("Connection")
	keepAliveOK := proto != "HTTP/1.0" || connectionHas(connHdr, "keep-alive")
	bodyless := isHEAD || !bodyAllowed(code)
	reuse := via != nil && keepAliveOK && (bodyless || chunked || length >= 0) &&
		!connectionHas(connHdr, "close") && bodySent

	handedOff = true
	b := body{r: rd, c: conn, deadline: total}
	// Een bewezen-lege body is meteen "gelezen": HEAD/204/304 en een
	// niet-chunked lengte 0 dragen per definitie nul bytes, dus een caller die
	// alleen netjes Close doet (de DELETE→204-route) hoort de verbinding te
	// poolen in plaats van te sluiten (review 13-08, drieëntwintigste ronde).
	// Chunked blijft pas bewezen ná de nul-chunk.
	if bodyless || (!chunked && length == 0) {
		b.done = true
	}
	if reuse {
		b.pool, b.key, b.br = via, addr, br
	}
	return &Response{
		StatusCode: code,
		Status:     status,
		Header:     hdr,
		Body:       &b,
		Length:     length,
		URL:        raw,
		Encoding:   hdr.Get("Content-Encoding"),
		SetCookie:  setCookie,
		chunked:    chunked,
	}, nil
}

// requestBytes bouwt de verzoekkop. Header-waarden mogen geen CR/LF bevatten:
// dat zou een tweede verzoek in het eerste smokkelen.
func requestBytes(c Call, u *url.URL, keepAlive bool) ([]byte, error) {
	method := c.Method
	if method == "" {
		method = "GET"
	} else if !validToken(method) {
		// Een methode met een spatie of CRLF erin is een tweede verzoek in
		// vermomming (request-line-injectie) — zelfde wacht als de
		// headernamen (review 13-08, vijfde ronde).
		return nil, fmt.Errorf("leanhttp: invalid method %q", c.Method)
	}
	if method == "CONNECT" {
		// CONNECT vraagt een tunnel, en dit pakket heeft geen tunnel-API: na
		// een 2xx zou de verbinding rauw moeten worden overgedragen, en dat
		// contract bestaat hier niet. Hem tóch serialiseren stuurde een
		// tunnelopdracht de deur uit waarvan het antwoord vervolgens als
		// gewone response gelezen werd (review 13-08, vierendertigste ronde;
		// de serverkant weigert hem sinds de tweeëndertigste).
		return nil, errors.New("leanhttp: CONNECT is not supported (this client is never a tunnel)")
	}
	var b bytes.Buffer
	// Accept-Encoding: identity is de DEFAULT, niet een wet — wij pakken niets
	// uit, dus vragen we niets. Wie wél gecomprimeerd wil (een browser: 2-5×
	// minder bytes over de lijn) zet de header zelf en pakt Response.Body zelf
	// uit; Response.Encoding zegt wat er terugkwam. Zo blijft compress/gzip
	// buiten dit pakket en betaalt niemand ervoor die het niet vraagt.
	enc := "identity"
	if v := c.Header.Get("Accept-Encoding"); v != "" {
		enc = v
	}
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	// Host zonder poort-default, net als net/http.
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: %s\r\nConnection: %s\r\n",
		method, u.RequestURI(), u.Host, enc, conn)
	switch {
	case c.Body != nil && c.BodyReader != nil:
		return nil, errors.New("leanhttp: set Body or BodyReader, not both")
	case c.BodyReader != nil:
		if c.BodyLen < 0 {
			return nil, errors.New("leanhttp: BodyReader needs a BodyLen (this package does not chunk uploads)")
		}
		// Een stroom kan niet opnieuw, dus vraagt hij eerst het oordeel van
		// de server (RFC 9110 §10.1.1): een vroege 401/413 spaart de hele
		// upload uit — zie de Expect-dans in do (review 13-08,
		// negenentwintigste ronde).
		fmt.Fprintf(&b, "Content-Length: %d\r\nExpect: 100-continue\r\n", c.BodyLen)
	case c.Body != nil:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(c.Body))
	}
	for k, v := range c.Header {
		switch {
		case !validToken(k):
			// Zelfde tokenwacht als overal: ook een tab of andere control-byte
			// in de naam is een injectie, niet een header (review 13-08,
			// zevende ronde).
			return nil, fmt.Errorf("leanhttp: illegal header name %q", k)
		case !validFieldValue(v):
			// Zelfde grammatica als inkomend (validFieldValue): ook een NUL of
			// VT is een injectievector, niet alleen CR/LF.
			return nil, fmt.Errorf("leanhttp: illegal value for header %q", k)
		// De framing- en verbindingsheaders zijn van ons; stil laten
		// overschrijven zou het verzoek onbegrijpelijk maken. Expect hoort er
		// sinds de tweeëndertigste ronde bij: BodyReader schrijft hem zelf, en
		// een caller-Expect ernaast gaf twee (mogelijk strijdige) regels.
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Content-Length"),
			strings.EqualFold(k, "Connection"), strings.EqualFold(k, "Transfer-Encoding"),
			strings.EqualFold(k, "Expect"):
			return nil, fmt.Errorf("leanhttp: header %q is set by the package, not by the caller", k)
		case strings.EqualFold(k, "Accept-Encoding"):
			continue // al in de statusregel geschreven; niet dubbel
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// readHeaderBlock leest regels tot de lege regel en geeft elke header als
// (naam, getrimde waarde) aan each. Dit is de ENE plek waar client én server
// een kopblok ontleden — twee eigen lussen waren al aan het uiteenlopen, en
// headers horen aan beide kanten voor altijd hetzelfde te parsen
// (review 13-08, zesde ronde). each mag nil zijn (kop wegslikken, zoals bij
// een 1xx-interim).
func readHeaderBlock(br *bufio.Reader, budget *int, each func(k, v string) error) error {
	for {
		line, err := readLine(br, budget)
		if err != nil {
			return err
		}
		if line == "" {
			return nil // lege regel: einde kop
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("leanhttp: malformed header %q", line)
		}
		// De naam moet een strak token zijn, zónder witruimte vóór de dubbele
		// punt (RFC 9112 §5.1). Tolerantie is een smokkelgat: "Content-Length
		// : 5" werd een onbekende header en de vijf bodybytes het begin van
		// het VOLGENDE bericht (review 13-08). Hier, zodat client en server
		// dit gegarandeerd hetzelfde doen.
		if !validToken(k) {
			return fmt.Errorf("leanhttp: invalid header name %q", k)
		}
		if each == nil {
			continue
		}
		if err := each(k, trimOWS(v)); err != nil {
			return err
		}
	}
}

// readLine leest één CRLF-regel en trekt hem van het budget af. Strikt: de
// regel MOET op precies \r\n eindigen (kale LF geweigerd, losse CR's blijven
// staan en vallen op de CTL-wacht hieronder), en control-bytes in de regel
// zijn een fout. Een parser die zulke vormen stil normaliseert leest een
// bericht anders af dan de proxy ervóór, en dat verschil ís het smokkelgat —
// na alle eerdere hardening was dit de overgebleven parserdifferentiaal
// (review 13-08, dertiende ronde). ReadSlice begrenst de regel op de
// buffergrootte (ErrBufferFull = te lang) i.p.v. ongebonden te groeien.
func readLine(br *bufio.Reader, budget *int) (string, error) {
	raw, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", fmt.Errorf("header line exceeds %d bytes", bufSize)
	}
	if err != nil {
		return "", err
	}
	if *budget -= len(raw); *budget < 0 {
		return "", fmt.Errorf("headers exceed %d bytes", maxHeaderBytes)
	}
	if len(raw) < 2 || raw[len(raw)-2] != '\r' {
		return "", fmt.Errorf("leanhttp: line not terminated by CRLF")
	}
	// raw wijst in de bufio-buffer en is na de volgende read ongeldig — de
	// string-conversie hieronder kopieert, dus dat is hier afgehandeld.
	line := string(raw[:len(raw)-2])
	if !validFieldValue(line) {
		return "", fmt.Errorf("leanhttp: control byte in line %q", line)
	}
	return line, nil
}

// validFieldValue toetst tegen de veldwaarde-grammatica van RFC 9110 §5.5:
// HTAB, zichtbare ASCII en obs-text (≥0x80) mogen, elke andere control-byte
// niet. Dit is bewust ÉÉN functie voor de reader (readLine) én beide writers
// (requestBytes, writeHead): inkomend werden NUL/VT/FF/DEL al geweigerd
// terwijl uitgaand alleen CR/LF sneuvelde — dan zet je een header op de draad
// die je zelf zou weigeren (review 13-08, vijftiende ronde).
func validFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// trimOWS trimt uitsluitend HTTP-witruimte (SP en HTAB, RFC 9110 §5.6.3).
// strings.TrimSpace nam ook \r, \v, \f en Unicode-spaties mee — ruimer dan de
// grammatica, en élke tolerantie hier is een kans op een parserdifferentiaal
// (review 13-08, dertiende ronde).
func trimOWS(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// parseDecimal parseert uitsluitend ASCII-cijfers. strconv.ParseInt accepteert
// ook "+5", en een Content-Length die wij anders lezen dan de proxy vóór ons
// is precies het framing-verschil waar request smuggling op drijft
// (review 13-08, dertiende ronde). De lengtegrens houdt het product binnen
// int64 zonder overloop-acrobatiek.
func parseDecimal(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

// parseHex is parseDecimal voor chunk-groottes: uitsluitend hex-cijfers.
func parseHex(s string) (int64, bool) {
	if s == "" || len(s) > 15 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		var d int64
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | d
	}
	return n, true
}

// connectionHas toetst of de Connection-header een token draagt: de waarde is
// een kommalijst ("upgrade, close"), en een substring- of hele-string-toets
// mist dan de close die erin staat — waarna een verbinding gepoold wordt die
// de server sluit (review 13-08, tweede ronde).
func connectionHas(header, token string) bool {
	// strings.Cut in plaats van Split: dit loopt per verzoek/antwoord en hoeft
	// er geen slice voor te alloceren.
	for header != "" {
		var part string
		part, header, _ = strings.Cut(header, ",")
		if strings.EqualFold(trimOWS(part), token) {
			return true
		}
	}
	return false
}

// statusCode pelt code én protocol uit "HTTP/1.1 200 OK". Het protocol telt:
// zie de hergebruik-regel in do.
func statusCode(line string) (int, string, error) {
	proto, rest, found := strings.Cut(line, " ")
	// De prefix-toets is functioneel gedekt door de exacte versietoets eronder;
	// hij bestaat om de melding — "geen HTTP" is een andere diagnose dan "een
	// HTTP-versie die we niet spreken" (zelfde afweging als checkGet's
	// chunked-tak).
	if !found || !strings.HasPrefix(proto, "HTTP/") {
		return 0, "", fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	if proto != "HTTP/1.0" && proto != "HTTP/1.1" {
		// Alleen de twee versies die we spréken: al het andere accepteren
		// betekent gokken over framing en persistentie — een "HTTP/9.9" kon
		// zo de keep-alive-pool in (review 13-08, negende ronde).
		return 0, "", fmt.Errorf("leanhttp: unsupported protocol in status line %q", line)
	}
	// parseDecimal + exact drie cijfers (RFC 9112 §4): Atoi accepteerde ook
	// "+200", en de statuscode stuurt bodyAllowed, de 1xx-lus én de
	// hergebruik-beslissing — het parserdifferentiaal-argument van de
	// Content-Length geldt hier onverkort (review 13-08, veertiende ronde).
	num, _, _ := strings.Cut(rest, " ")
	code, ok := parseDecimal(num)
	if !ok || len(num) != 3 || code < 100 || code > 599 {
		return 0, "", fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	return int(code), proto, nil
}

// body koppelt de (eventueel ge-de-chunkte) lezer aan de verbinding, zodat
// Close beide afsluit: de bufio kan al body-bytes vooruit gelezen hebben, dus
// de body moet dóór die reader gelezen worden en niet rechtstreeks van de conn.
// Close is tevens het afbreek-signaal van een blijvende stream: een lezer die
// in Read hangt komt eruit zodra de fd dicht is.
// body is de responsebody plus de verbinding eronder. Sluit hij, dan gaat de
// verbinding dicht — tenzij er een pool is EN de body helemaal gelezen is.
//
// Die laatste voorwaarde is de hele veiligheid van keep-alive: een verbinding
// met ongelezen bytes erin teruggeven betekent dat het volgende verzoek de
// staart van dit antwoord als zijn statusregel leest. Dan lees je de body van
// pagina A als de headers van pagina B, en dat is precies het soort fout dat
// jaren onopgemerkt blijft. Twijfel = sluiten.
type body struct {
	r    io.Reader
	c    net.Conn
	br   *bufio.Reader
	pool *Client
	key  string

	// deadline is de totaaltermijn van de call: de conn-deadline dekt alleen
	// SOCKET-reads, en bytes die de bufio al vooruitgelezen had kwamen daar
	// nooit langs — een verlopen Call.Timeout las dan vrolijk door
	// (review 13-08, vijfentwintigste ronde).
	deadline time.Time

	// mu bewaakt done/shut: het contract staat een Close toe die een
	// geblokkeerde Read afbreekt, en dat waren twee goroutines op dezelfde
	// velden (review 13-08, vijfentwintigste ronde).
	mu   sync.Mutex
	done bool // de body is tot het einde gelezen
	shut bool // Close is al geweest
}

func (b *body) Read(p []byte) (int, error) {
	if !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := b.r.Read(p)
	if err == io.EOF {
		// Alleen een BEWEZEN einde telt voor de pool: exact Content-Length
		// bytes, of de nul-chunk met afgesloten trailers. Een framing-lezer
		// die het einde niet kan bewijzen geeft io.ErrUnexpectedEOF (RFC 9112
		// §8: incomplete message) en komt hier dus niet. De tot-EOF-body komt
		// hier wél, maar die verbinding was al onherbruikbaar (pool staat uit).
		b.mu.Lock()
		b.done = true
		b.mu.Unlock()
	}
	return n, err
}

// lengthReader is de Content-Length-lezer: precies n bytes, en een verbinding
// die eerder sterft is io.ErrUnexpectedEOF — nooit een kale EOF, want dat is
// het verschil tussen "bestand compleet" en "half bestand als succes"
// (review 13-08).
type lengthReader struct {
	r io.Reader
	n int64

	// connEOF: de onderliggende verbinding gaf een EOF, ook al was de body op
	// dat moment compleet (data + EOF in één Read — een TLS-close_notify kan
	// dat). De body is dan geldig, maar de verbinding is DOOD: wie hem poolt,
	// geeft het volgende verzoek een "read status line: EOF" zonder tweede
	// kans (review 13-08, derde ronde).
	connEOF bool
}

func (l *lengthReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if err == io.EOF {
		l.connEOF = true
		if l.n > 0 {
			return n, io.ErrUnexpectedEOF
		}
		err = nil // de body is compleet; de vólgende Read geeft de nette EOF
	}
	// Bij l.n == 0 is het einde nu bewezen; de volgende Read geeft de nette EOF.
	return n, err
}

func (b *body) Close() error {
	b.mu.Lock()
	if b.shut {
		b.mu.Unlock()
		return nil
	}
	b.shut = true
	done := b.done
	b.mu.Unlock()
	if !done {
		// Niet compleet: nooit poolen, en — belangrijker — geen énkele blik
		// op de reader: een geblokkeerde Read kan er nog middenin zitten
		// (het contract staat Close-als-afbreker toe), en connEOF/Buffered
		// lezen naast een lopende Read is een datarace (review 13-08,
		// achtentwintigste ronde). De mutex hierboven geeft happens-before
		// met de Read die done wél zette: daarná is de reader stil.
		return b.c.Close()
	}
	// Een complete body over een verbinding die intussen zelf een EOF gaf
	// (lengthReader.connEOF) is klaar om te LEZEN maar dood om te HERGEBRUIKEN.
	dead := false
	if lr, ok := b.r.(*lengthReader); ok {
		dead = lr.connEOF
	}
	// En nooit poolen met ongelezen bytes in de reader: na een bewezen-lege
	// body kán daar alleen een ongevraagd, vooruitgestuurd "antwoord" staan —
	// call 2 zou zijn verzoek schrijven en dát lezen (review 13-08,
	// vierentwintigste ronde).
	clean := b.br == nil || b.br.Buffered() == 0
	if b.pool != nil && !dead && clean && b.pool.put(b.key, b.c, b.br) {
		return nil // de verbinding leeft door in de pool
	}
	return b.c.Close()
}

// chunkReader ontleedt chunked transfer-encoding: per chunk een hex-lengte,
// die bytes, CRLF; lengte 0 sluit af (gevolgd door optionele trailers). Nodig
// zodra je een antwoord leest dat een Go-server streamt — die kent zijn lengte
// niet vooraf en chunkt dus altijd (SSE, logstaarten).
type chunkReader struct {
	br   *bufio.Reader
	n    int64 // resterende bytes in de huidige chunk
	done bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.n == 0 {
		if err := c.next(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.br.Read(p)
	c.n -= int64(n)
	if err == io.EOF {
		// Élke EOF hier is een incompleet bericht (RFC 9112 §8): ook als hij
		// precies op de chunkgrens valt is de afsluitende CRLF — laat staan de
		// nul-chunk — nooit gezien (review 13-08, derde ronde).
		err = io.ErrUnexpectedEOF
	}
	if c.n == 0 && err == nil {
		// Einde chunk: de afsluitende CRLF hoort niet bij de data.
		crlf, err := c.line()
		if err == io.EOF {
			// Sterft de verbinding exact vóór die CRLF ("5\r\nhallo" en
			// dicht), dan gaf dit een kale EOF door: de body gold als compleet
			// en de dóde verbinding ging de pool in (review 13-08, derde
			// ronde).
			return n, io.ErrUnexpectedEOF
		}
		if err != nil {
			return n, err
		}
		if crlf != "" {
			return n, fmt.Errorf("leanhttp: chunk not terminated by CRLF")
		}
	}
	return n, err
}

// line leest één regel van de chunk-framing. Bewust géén cumulatief budget
// zoals bij de headers: een blijvende stream (SSE-staart) heeft ónbeperkt veel
// chunks, en elke kop is meteen weer weg. De per-regel-grens van readLine
// (bufSize) is hier de bescherming die telt.
func (c *chunkReader) line() (string, error) {
	budget := bufSize
	return readLine(c.br, &budget)
}

// forbiddenTrailers zijn de velden die per RFC 9110 §6.5.1 nooit in een
// trailer thuishoren: framing, routing, verbindingsbeheer, authenticatie,
// caching/conditionals en content-verwerking. Wij negeren trailer-inhoud
// sowieso, maar een parser verderop in de keten misschien niet — fail-closed
// (review 13-08, twintigste ronde: de eerste lijst dekte alleen framing).
var forbiddenTrailers = map[string]bool{
	"transfer-encoding": true, "content-length": true, "host": true,
	"connection": true, "upgrade": true, "te": true, "trailer": true,
	"content-type": true, "content-encoding": true, "content-range": true,
	"cache-control": true, "expect": true, "max-forwards": true,
	"pragma": true, "range": true, "if-match": true, "if-none-match": true,
	"if-modified-since": true, "if-unmodified-since": true, "if-range": true,
	"authorization": true, "www-authenticate": true, "cookie": true,
	"set-cookie": true, "proxy-authenticate": true, "proxy-authorization": true,
	"age": true, "location": true, "retry-after": true, "vary": true,
}

// next leest de eerstvolgende chunk-kop; done wordt gezet op de nul-chunk.
func (c *chunkReader) next() error {
	line, err := c.line()
	if err == io.EOF {
		// Geen nul-chunk gezien: de body is niet compleet, hoe netjes de
		// verbinding ook sloot (review 13-08).
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	// "1a3;ext=foo" — de extensie is voor ons betekenisloos. parseHex, geen
	// ParseInt(…, 16, …): die accepteert ook "+1a3" — en géén OWS-trim: een
	// chunk-size is exact 1*HEXDIG (RFC 9112 §7.1), en juist bij framing is
	// elke tolerantie een parserdifferentiaal (review 13-08, zeventiende
	// ronde).
	size, ext, hasExt := strings.Cut(line, ";")
	n, ok := parseHex(size)
	if !ok {
		return fmt.Errorf("leanhttp: malformed chunk size %q", line)
	}
	if hasExt {
		// BEWUSTE AFWIJKING van RFC 9112 §7.1.1: een ontvanger hoort
		// onbekende maar sýntactisch geldige chunk-extensies te negeren, en
		// dit weigert ze categorisch — óók een geldige "5;foo=bar". De
		// afweging: "geldig" toetsen vergt een quote-bewuste ABNF-parser
		// (x="a;b" is geldig, x=a b niet, BWS vóór ";" wel) voor iets dat
		// geen van onze tegenpartijen ooit stuurt, en half valideren was
		// aantoonbaar zelf een parserdifferentiaal (ronde 19→20).
		// Fail-closed op framing weegt hier zwaarder dan de MUST-ignore;
		// duikt er ooit een peer op die ze stuurt, dan hoort hier die parser
		// (review 13-08, eenentwintigste ronde).
		_ = ext
		return fmt.Errorf("leanhttp: chunk extensions are not supported: %q", line)
	}
	if n == 0 {
		// Trailers wegslikken tot de lege regel — die is er altijd; hier telt
		// het cumulatieve budget wél, want dit blok is eindig en eenmalig.
		// Fouten tellen: een verbinding die sterft vóór de lege regel heeft
		// het einde niet bewezen, en done blijft dan uit zodat de pool deze
		// verbinding nooit krijgt (review 13-08).
		budget := maxHeaderBytes
		for {
			t, err := readLine(c.br, &budget)
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			if err != nil {
				return err
			}
			if t == "" {
				c.done = true
				return nil
			}
			// Trailerregels volgen de header-grammatica, en framing/routing
			// hoort er niet in (RFC 9110 §6.5.1): een "trailer" die
			// Content-Length of Transfer-Encoding zegt is een smokkelpoging,
			// geen metadata (review 13-08, negentiende ronde). De inhoud
			// blijft verder genegeerd.
			k, _, found := strings.Cut(t, ":")
			if !found || !validToken(k) {
				return fmt.Errorf("leanhttp: malformed trailer line %q", t)
			}
			if forbiddenTrailers[strings.ToLower(k)] {
				return fmt.Errorf("leanhttp: forbidden trailer field %q", k)
			}
		}
	}
	c.n = n
	return nil
}
