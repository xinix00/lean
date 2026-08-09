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
//   - geen keep-alive aan de clientkant, geen connection pool: één verzoek per
//     verbinding (Connection: close). De serverkant hergebruikt wél (zie
//     serve.go): een pagina die frames pollt hoort niet elke keer een
//     TCP-handdruk te betalen.
//   - geen HTTP/2, geen compressie (Accept-Encoding: identity), geen cookies.
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
	URL     string        // moet http:// zijn
	Header  Header        // extra verzoekheaders (mag nil zijn)
	Body    []byte        // nil = geen body
	Timeout time.Duration // totaaltermijn incl. body-lezen; 0 = geen (blijvende streams)
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

	chunked bool // voor Get: het onderscheid tussen "chunked" en "geen lengte"
}

// Get doet één HTTP/1.1 GET en geeft de body als stream plus zijn lengte.
// Volgt redirects (tot maxRedirects) en eist een 200 mét Content-Length: wie
// Get gebruikt wil een bestand van bekende omvang, geen half antwoord. Voor al
// het andere is er [Do].
func Get(raw string) (*Response, error) {
	resp, err := Do(Call{URL: raw})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode != StatusOK:
		resp.Body.Close()
		return nil, fmt.Errorf("apphttp: HTTP %s", resp.Status)
	case resp.chunked:
		// Een image zónder lengte kon de apploader nooit stagen (hij weigerde
		// ContentLength <= 0): luid falen i.p.v. half werk.
		resp.Body.Close()
		return nil, fmt.Errorf("apphttp: chunked/encoded transfer is not supported here — serve the artifact with a Content-Length")
	case resp.Length < 0:
		resp.Body.Close()
		return nil, fmt.Errorf("apphttp: no Content-Length in response")
	}
	return resp, nil
}

// Do voert één verzoek uit en geeft het antwoord — óók een 404 of een 500: een
// foutstatus is geen transportfout, de aanroeper leest hem zelf (en zijn body,
// die vaak zegt wat er mis is). Redirects worden gevolgd zolang het verzoek
// geen body heeft; met body krijgt de aanroeper de 3xx zelf te zien, want een
// POST opnieuw afvuren op een ander pad is niet aan dit pakket.
func Do(c Call) (*Response, error) {
	loc := c.URL
	for range maxRedirects + 1 {
		resp, err := do(c, loc)
		if err != nil {
			return nil, err
		}
		next := ""
		if c.Body == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
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
			return nil, fmt.Errorf("apphttp: bad URL %q: %w", loc, err)
		}
		ref, err := url.Parse(next)
		if err != nil {
			return nil, fmt.Errorf("apphttp: bad Location %q: %w", next, err)
		}
		loc = base.ResolveReference(ref).String() // een relatieve Location mag
	}
	return nil, fmt.Errorf("apphttp: too many redirects (>%d) starting at %s", maxRedirects, c.URL)
}

// do doet één ronde: verbinden, verzoek schrijven, antwoordkop lezen.
func do(c Call, raw string) (_ *Response, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("apphttp: bad URL %q: %w", raw, err)
	}
	// Luid, niet stil: dit pakket bestaat juist om TLS niet te linken, dus een
	// https-URL is een configuratiefout die je op de console hoort te zien.
	if u.Scheme != "http" {
		return nil, fmt.Errorf("apphttp: only http:// is supported, got %q — "+
			"this app links no TLS (use a plain-http URL on the LAN, or build the app with net/http)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("apphttp: URL %q has no host", raw)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(addr, "80")
	}

	req, err := requestBytes(c, u)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp4", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("apphttp: dial %s: %w", addr, err)
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
	if c.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(c.Timeout))
	}

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("apphttp: write request: %w", err)
	}
	if len(c.Body) > 0 {
		if _, err := conn.Write(c.Body); err != nil {
			return nil, fmt.Errorf("apphttp: write body: %w", err)
		}
	}

	br := bufio.NewReaderSize(conn, bufSize)
	budget := maxHeaderBytes

	line, err := readLine(br, &budget)
	if err != nil {
		return nil, fmt.Errorf("apphttp: read status line: %w", err)
	}
	code, err := statusCode(line)
	if err != nil {
		return nil, err
	}
	_, status, _ := strings.Cut(line, " ") // "HTTP/1.1 404 Not Found" → "404 Not Found"

	hdr := Header{}
	var length int64 = -1
	var chunked bool
	for {
		line, err := readLine(br, &budget)
		if err != nil {
			return nil, fmt.Errorf("apphttp: read headers: %w", err)
		}
		if line == "" {
			break // lege regel: einde headers
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("apphttp: malformed header %q", line)
		}
		v = strings.TrimSpace(v)
		switch {
		case strings.EqualFold(k, "Content-Length"):
			// Een tweede, andere lengte is een smokkel-signaal, geen
			// laatste-wint-geval: falen.
			if length >= 0 {
				return nil, fmt.Errorf("apphttp: duplicate Content-Length")
			}
			if length, err = strconv.ParseInt(v, 10, 64); err != nil || length < 0 {
				return nil, fmt.Errorf("apphttp: bad Content-Length %q", v)
			}
		case strings.EqualFold(k, "Transfer-Encoding"):
			chunked = !strings.EqualFold(v, "identity")
		}
		hdr.add(k, v)
	}

	// Chunked wint van Content-Length (RFC 9112 §6.1) — en een antwoord met
	// beide is smokkel-verdacht, dus de lengte gaat overboord.
	var rd io.Reader
	switch {
	case chunked:
		rd, length = &chunkReader{br: br}, -1
	case length >= 0:
		rd = io.LimitReader(br, length)
	default:
		rd = br // geen lengte, geen chunks: de body loopt tot EOF
	}

	handedOff = true
	return &Response{
		StatusCode: code,
		Status:     status,
		Header:     hdr,
		Body:       body{rd, conn},
		Length:     length,
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
	// Accept-Encoding: identity — wij pakken niets uit, dus vraag het ook niet.
	// Host zonder poort-default, net als net/http.
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
		method, u.RequestURI(), u.Host)
	if c.Body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(c.Body))
	}
	for k, v := range c.Header {
		switch {
		case strings.ContainsAny(k, "\r\n: ") || k == "":
			return nil, fmt.Errorf("apphttp: illegal header name %q", k)
		case strings.ContainsAny(v, "\r\n"):
			return nil, fmt.Errorf("apphttp: illegal value for header %q", k)
		// De vier hierboven zijn van ons; stil laten overschrijven zou het
		// verzoek onbegrijpelijk maken.
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Content-Length"),
			strings.EqualFold(k, "Connection"), strings.EqualFold(k, "Transfer-Encoding"):
			return nil, fmt.Errorf("apphttp: header %q is set by the package, not by the caller", k)
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
		return 0, fmt.Errorf("apphttp: malformed status line %q", line)
	}
	num, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(num)
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("apphttp: malformed status line %q", line)
	}
	return code, nil
}

// body koppelt de (eventueel ge-de-chunkte) lezer aan de verbinding, zodat
// Close beide afsluit: de bufio kan al body-bytes vooruit gelezen hebben, dus
// de body moet dóór die reader gelezen worden en niet rechtstreeks van de conn.
// Close is tevens het afbreek-signaal van een blijvende stream: een lezer die
// in Read hangt komt eruit zodra de fd dicht is.
type body struct {
	r io.Reader
	c net.Conn
}

func (b body) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b body) Close() error               { return b.c.Close() }

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
			return n, fmt.Errorf("apphttp: chunk not terminated by CRLF")
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
		return fmt.Errorf("apphttp: malformed chunk size %q", line)
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
