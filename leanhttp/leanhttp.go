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
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// dialTimeout begrenst het opzetten van de verbinding: een onbereikbare
	// host mag geen job-start gijzelen. De download zelf staat bewust vrij
	// (Call.Timeout is er voor wie wél een totaaltermijn wil).
	dialTimeout = 10 * time.Second

	// maxRedirects volgt hetzelfde plafond als net/http's default.
	maxRedirects = 10

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
	StatusInternalServerError   = 500
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
	for k := range h {
		if k != key && strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
	h[key] = value
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
	BodyReader io.Reader
	BodyLen    int64

	// Dial maakt de verbinding. nil = net.DialTimeout op tcp4, en dan blijft
	// dit pakket wat het is: plain http zonder één byte TLS.
	//
	// De naad is er voor álles wat een andere verbinding wil zijn dan een kale
	// TCP-dial: een proxy, een unix-socket, een testdubbel dat nooit het net
	// op gaat — en een versleutelde verbinding. In dat laatste geval hoort de
	// aanroeper hier een TLS-dialer neer te zetten; dit pakket weet daar niets
	// van en linkt er niets voor (leanhttps doet die knoop voor je).
	//
	// addr is "host:poort" met de hostnaam er nog in (niet opgelost naar een
	// IP), zodat een TLS-dialer zijn SNI kan zetten. Bij een redirect naar een
	// andere host wordt Dial opnieuw geroepen met die nieuwe host — wie SNI uit
	// addr haalt, volgt dus automatisch mee.
	Dial func(network, addr string) (net.Conn, error)

	// NoFollow geeft de 3xx aan de aanroeper in plaats van hem te volgen.
	//
	// Wie een cookie-jar heeft MOET dit zetten. Redirects volgen is namelijk
	// niet één ronde maar een keten, en op elke stap kan een Set-Cookie staan
	// die de vólgende stap nodig heeft — dat is precies hoe een consent- of
	// login-muur werkt. [Do] kent geen jar en kan die stap dus niet zetten;
	// wie er wel een heeft, loopt de keten zelf af en past per stap zijn
	// cookies toe.
	NoFollow bool

	// keepAlive wordt door [Client] gezet: dan vraagt het verzoek om een
	// verbinding die blijft staan, en geeft de body hem terug aan de pool.
	// Niet exported — een losse Do heeft geen pool om iets aan terug te geven.
	keepAlive bool
	pool      *Client
	addrKey   string
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
// eigen [Call.Dial]. Zelfde eisen: een 200 mét Content-Length. Dit is wat Get
// is voor Do: dezelfde ronde, maar met de controles die een bestand-ophaler
// wil.
func GetCall(c Call) (*Response, error) {
	resp, err := Do(c)
	if err != nil {
		return nil, err
	}
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
func Do(c Call) (*Response, error) {
	loc := c.URL
	for range maxRedirects + 1 {
		resp, err := do(c, loc)
		if err != nil {
			return nil, err
		}
		next := ""
		if c.Body == nil && c.BodyReader == nil && !c.NoFollow && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			next = resp.Header.Get("Location")
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
		loc = base.ResolveReference(ref).String() // een relatieve Location mag
	}
	return nil, fmt.Errorf("leanhttp: too many redirects (>%d) starting at %s", maxRedirects, c.URL)
}

// do doet één ronde: verbinden, verzoek schrijven, antwoordkop lezen.
func do(c Call, raw string) (_ *Response, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: bad URL %q: %w", raw, err)
	}
	// Luid, niet stil: zonder Dial linkt dit pakket geen TLS, dus is een
	// https-URL een configuratiefout die je op de console hoort te zien — mét
	// de twee uitwegen erin, want een fout die niet zegt wat te doen kost een
	// zoektocht.
	port := "80"
	switch {
	case u.Scheme == "http":
	case u.Scheme == "https" && c.Dial != nil:
		port = "443"
	case u.Scheme == "https":
		return nil, fmt.Errorf("leanhttp: https:// needs a Call.Dial that returns an "+
			"encrypted connection (this package links no TLS) — use leanhttps, or set Dial yourself: %s", raw)
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

	req, err := requestBytes(c, u)
	if err != nil {
		return nil, err
	}

	dial := c.Dial
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, dialTimeout)
		}
	}
	conn, err := dial("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: dial %s: %w", addr, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("leanhttp: Call.Dial returned no connection and no error for %s", addr)
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
	// total is het ENE moment waarop de hele call om is (nulwaarde = nooit). De
	// kop mag daarbinnen zijn eigen, kortere grens hebben; na de kop gaat de
	// deadline terug naar total, zodat de body de RESTERENDE tijd krijgt en niet
	// een verse termijn.
	var total time.Time
	if c.Timeout > 0 {
		total = time.Now().Add(c.Timeout)
		conn.SetDeadline(total)
	}
	if c.HeaderTimeout > 0 {
		if head := time.Now().Add(c.HeaderTimeout); total.IsZero() || head.Before(total) {
			conn.SetDeadline(head)
		}
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("leanhttp: write request: %w", err)
	}
	if c.BodyReader != nil {
		// Precies BodyLen bytes: dat is wat de Content-Length de server belooft.
		// Een reader die minder levert laat de server op de rest wachten en de
		// verbinding hangen — dus dat is hier een fout, niet een korte upload.
		n, err := io.CopyN(conn, c.BodyReader, c.BodyLen)
		switch {
		case err != nil:
			return nil, fmt.Errorf("leanhttp: stream body after %d of %d bytes: %w", n, c.BodyLen, err)
		case n != c.BodyLen:
			return nil, fmt.Errorf("leanhttp: BodyReader gave %d bytes, Content-Length promised %d", n, c.BodyLen)
		}
	}
	if len(c.Body) > 0 {
		if _, err := conn.Write(c.Body); err != nil {
			return nil, fmt.Errorf("leanhttp: write body: %w", err)
		}
	}

	// Een verbinding uit de pool draagt zijn eigen bufio.Reader mee: daar kunnen
	// bytes in staan die al van de socket gelezen zijn (de server stuurde kop en
	// body in één pakket). Een nieuwe Reader maken zou die bytes weggooien en
	// het volgende antwoord half laten beginnen.
	var br *bufio.Reader
	if pc, ok := conn.(*pooledConn); ok && pc.br != nil {
		br = pc.br
	} else {
		br = bufio.NewReaderSize(conn, bufSize)
	}
	c.addrKey = addr
	budget := maxHeaderBytes

	line, err := readLine(br, &budget)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: read status line: %w", err)
	}
	code, err := statusCode(line)
	if err != nil {
		return nil, err
	}
	_, status, _ := strings.Cut(line, " ") // "HTTP/1.1 404 Not Found" → "404 Not Found"

	hdr := Header{}
	var setCookie []string
	var length int64 = -1
	var chunked bool
	for {
		line, err := readLine(br, &budget)
		if err != nil {
			return nil, fmt.Errorf("leanhttp: read headers: %w", err)
		}
		if line == "" {
			break // lege regel: einde headers
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("leanhttp: malformed header %q", line)
		}
		v = strings.TrimSpace(v)
		switch {
		case strings.EqualFold(k, "Content-Length"):
			// Een tweede, andere lengte is een smokkel-signaal, geen
			// laatste-wint-geval: falen.
			if length >= 0 {
				return nil, fmt.Errorf("leanhttp: duplicate Content-Length")
			}
			if length, err = strconv.ParseInt(v, 10, 64); err != nil || length < 0 {
				return nil, fmt.Errorf("leanhttp: bad Content-Length %q", v)
			}
		case strings.EqualFold(k, "Transfer-Encoding"):
			chunked = !strings.EqualFold(v, "identity")
		case strings.EqualFold(k, "Set-Cookie"):
			// Niet vouwen, niet in Header: zie Response.SetCookie.
			setCookie = append(setCookie, v)
			continue
		}
		hdr.add(k, v)
	}

	// Chunked wint van Content-Length (RFC 9112 §6.1) — en een antwoord met
	// beide is smokkel-verdacht, dus de lengte gaat overboord.
	var rd io.Reader
	switch {
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
		rd, length, chunked = emptyBody{}, 0, false
	case chunked:
		rd, length = &chunkReader{br: br}, -1
	case length >= 0:
		rd = io.LimitReader(br, length)
	default:
		rd = br // geen lengte, geen chunks: de body loopt tot EOF
	}

	// De kop is binnen: terug naar de totaal-deadline. Is die er niet (total is
	// de nulwaarde), dan wist dit de deadline en mag de body zo lang duren als
	// hij duurt — een artifact van 30MB hoort niet af te lopen.
	if c.HeaderTimeout > 0 {
		conn.SetDeadline(total)
	}

	// Hergebruik mag alleen als we het einde van de body kunnen vinden EN de
	// server de verbinding openhoudt. Zonder lengte en zonder chunks loopt de
	// body tot EOF, en dan IS de verbinding het einde — die kan nooit terug.
	reuse := c.keepAlive && (chunked || length >= 0) &&
		!strings.EqualFold(hdr.Get("Connection"), "close")

	handedOff = true
	b := body{r: rd, c: conn}
	if reuse {
		b.pool, b.key, b.br = c.pool, c.addrKey, br
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
func requestBytes(c Call, u *url.URL) ([]byte, error) {
	method := c.Method
	if method == "" {
		method = "GET"
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
	if c.keepAlive {
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
		fmt.Fprintf(&b, "Content-Length: %d\r\n", c.BodyLen)
	case c.Body != nil:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(c.Body))
	}
	for k, v := range c.Header {
		switch {
		case strings.ContainsAny(k, "\r\n: ") || k == "":
			return nil, fmt.Errorf("leanhttp: illegal header name %q", k)
		case strings.ContainsAny(v, "\r\n"):
			return nil, fmt.Errorf("leanhttp: illegal value for header %q", k)
		// De vier hierboven zijn van ons; stil laten overschrijven zou het
		// verzoek onbegrijpelijk maken.
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Content-Length"),
			strings.EqualFold(k, "Connection"), strings.EqualFold(k, "Transfer-Encoding"):
			return nil, fmt.Errorf("leanhttp: header %q is set by the package, not by the caller", k)
		case strings.EqualFold(k, "Accept-Encoding"):
			continue // al in de statusregel geschreven; niet dubbel
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// readLine leest één CRLF-regel en trekt hem van het budget af. ReadSlice
// begrenst de regel op de buffergrootte (ErrBufferFull = te lang) i.p.v.
// ongebonden te groeien zoals ReadString zou doen.
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
	// raw wijst in de bufio-buffer en is na de volgende read ongeldig — de
	// string-conversie hieronder kopieert, dus dat is hier afgehandeld.
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// statusCode pelt de code uit "HTTP/1.1 200 OK".
func statusCode(line string) (int, error) {
	proto, rest, found := strings.Cut(line, " ")
	if !found || !strings.HasPrefix(proto, "HTTP/") {
		return 0, fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	num, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(num)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	return code, nil
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
	done bool // de body is tot het einde gelezen
	shut bool // Close is al geweest
}

func (b *body) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF {
		b.done = true
	}
	return n, err
}

func (b *body) Close() error {
	if b.shut {
		return nil
	}
	b.shut = true
	if b.pool != nil && b.done && b.pool.put(b.key, b.c, b.br) {
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
	if c.n == 0 && err == nil {
		// Einde chunk: de afsluitende CRLF hoort niet bij de data.
		crlf, err := c.line()
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

// next leest de eerstvolgende chunk-kop; done wordt gezet op de nul-chunk.
func (c *chunkReader) next() error {
	line, err := c.line()
	if err != nil {
		return err
	}
	// "1a3; ext=foo" — de extensie is voor ons betekenisloos.
	size, _, _ := strings.Cut(line, ";")
	n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("leanhttp: malformed chunk size %q", line)
	}
	if n == 0 {
		c.done = true
		// Trailers wegslikken tot de lege regel — die is er altijd; hier telt
		// het cumulatieve budget wél, want dit blok is eindig en eenmalig.
		budget := maxHeaderBytes
		for {
			t, err := readLine(c.br, &budget)
			if err != nil || t == "" {
				return nil
			}
		}
	}
	c.n = n
	return nil
}
