package leanhttp

// De serverkant. Een client-only pakket helpt de apps niet die zélf serveren:
// de SURF-display serveert /screen.png, de frame-stream en de web-KVM op :80 —
// precies de app die het meeste baat heeft bij een image zonder TLS.
//
// Het model is bewust klein: één handler (routeer zelf op r.Path — een mux is
// een switch, en die kun je beter zien), antwoorden met Content-Length tenzij
// de handler Flush aanroept (dan chunked), en Hijack voor wie de verbinding
// overneemt (de WebSocket van de KVM-pagina). Geen HTTP/2, geen TLS, geen
// pipelining.
//
// Wat er wél in zit omdat het anders niet werkt:
//
//   - keep-alive voor antwoorden met bekende lengte: een pagina die frames
//     pollt hoort niet per frame een TCP-handdruk te betalen.
//   - Flush: zonder tussentijds duwen is een frame-stream of een SSE-staart
//     onmogelijk.
//   - Hijack: de WebSocket-handshake is HTTP, de rest niet.
//   - Request.Done: een handler die eindeloos pusht moet kunnen merken dat de
//     kijker weg is, anders blijft er per dode kijker een goroutine draaien.
//
// Een panic in een handler wordt NIET opgevangen. Dat is geen omissie: op
// HopOS is een panic dodelijk by design (KILL on PANIC) — een display die half
// werkt is erger dan een die herstart.

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
	"sync"
	"time"
)

const (
	// maxBodyBytes begrenst het verzoek-lichaam. Dit pakket serveert API's en
	// kleine formulieren, geen uploads; wie meer nodig heeft leest r.Body van
	// een handler die zijn eigen grens kent.
	maxBodyBytes = 1 << 20

	// requestTimeout: hoe lang een verse verbinding over zijn verzoekkop mag
	// doen. Een half verzoek dat blijft hangen kost anders een goroutine.
	requestTimeout = 15 * time.Second

	// idleTimeout: hoe lang een hergebruikte verbinding stil mag blijven
	// voordat we hem opruimen.
	idleTimeout = 60 * time.Second

	// writeTimeout geldt per schrijfronde, niet per antwoord: een stream mag
	// uren openstaan, maar één plas bytes die er in een halve minuut niet uit
	// komt betekent een client die niet meer leest.
	writeTimeout = 30 * time.Second

	// drainTimeout: hoe lang we een afgewezen verzoek nog laten uitpraten
	// zodat het antwoord (413, 400) aankomt in plaats van een RST.
	drainTimeout = 2 * time.Second
)

// Handler behandelt één verzoek. Routeren doe je zelf op r.Path.
type Handler func(w ResponseWriter, r *Request)

// ResponseWriter is de schrijfkant van één antwoord. Anders dan bij net/http
// zijn Flush en Hijack geen optionele interfaces om naar te casten: een server
// zonder TLS en zonder HTTP/2 kan ze altijd, dus staan ze gewoon in het
// contract.
type ResponseWriter interface {
	// Header zijn de headers van het antwoord; wijzig ze vóór de eerste Write.
	Header() Header

	// WriteHeader legt de statuscode vast (default 200). Alleen de eerste
	// aanroep telt.
	WriteHeader(status int)

	// Write schrijft body-bytes. Zolang er geen Content-Length in de headers
	// staat en er niet geflusht is, wordt het antwoord gebufferd — dan telt de
	// server de lengte zelf.
	Write(p []byte) (int, error)

	// Flush duwt wat er staat naar de client. De eerste Flush zonder
	// Content-Length maakt het antwoord chunked; daarna is het antwoord een
	// stream en bepaalt de handler wanneer hij ophoudt.
	Flush() error

	// Hijack geeft de rauwe verbinding aan de aanroeper (WebSocket-upgrade).
	// Daarna schrijft de server zelf niets meer; sluiten is aan de aanroeper.
	// Mag niet nadat het antwoord al begonnen is.
	Hijack() (net.Conn, *bufio.ReadWriter, error)
}

// Request is één binnengekomen verzoek.
type Request struct {
	Method     string // "GET", "POST", …
	Path       string // het pad, %-decodeerd, altijd beginnend met "/"
	RawQuery   string // alles achter de "?" (zie Query)
	Proto      string // "HTTP/1.1"
	Header     Header
	Body       io.Reader // nooit nil; begrensd op maxBodyBytes
	RemoteAddr string

	// ContentLength is de aangekondigde bodylengte, of -1 als er geen
	// Content-Length was (chunked of geen body). Zelfde betekenis als bij
	// net/http, zodat een handler die hem leest niets hoeft te weten van welke
	// server eronder staat.
	ContentLength int64

	c         *conn
	vals      map[string]string // door de Mux gevuld uit {wildcards}
	query     url.Values
	queryOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{}
	keepAlive bool
}

// PathValue geeft wat een {wildcard} in het gematchte patroon opving, of "" als
// het patroon die naam niet had. Zie mux.go.
func (r *Request) PathValue(name string) string { return r.vals[name] }

// Query ontleedt de querystring (één keer, daarna gecachet).
func (r *Request) Query() url.Values {
	r.queryOnce.Do(func() {
		r.query, _ = url.ParseQuery(r.RawQuery) // kromme query = lege waarden
	})
	return r.query
}

// Done sluit zodra de client de verbinding verbreekt — voor handlers die
// eindeloos pushen (frame-stream, SSE) en anders per verdwenen kijker een
// goroutine op een dode socket laten wachten.
//
// Wie Done aanroept verklaart zichzelf tot streamer: vanaf dat moment leest een
// wachthond de verbinding leeg (zo mérken we het einde) en wordt hij na dit
// antwoord niet hergebruikt. Roep hem dus niet aan vóórdat je r.Body gelezen
// hebt — de wachthond zou die bytes opeten.
func (r *Request) Done() <-chan struct{} {
	r.doneOnce.Do(func() {
		r.done = make(chan struct{})
		r.c.watched = true
		go func() {
			defer close(r.done)
			// Wat er nog binnenkomt is oninteressant; we wachten op het einde,
			// en dat is precies wat een read met een fout ons vertelt (FIN,
			// RST, of onze eigen Close als de handler klaar is).
			io.Copy(io.Discard, r.c.br)
		}()
	})
	return r.done
}

// Serve draait de accept-lus tot de listener sluit; elke verbinding krijgt zijn
// eigen goroutine.
func Serve(l net.Listener, h Handler) error {
	// De accept-lus mag nooit vrij kunnen rondtollen. Een listener die een
	// tijdelijke fout of — zoals gemeten 27-07 op de app-netstack — een lege
	// accept (nil, nil) teruggeeft, maakte hiervan een spin die de hele core
	// opat: de app stond op 100% CPU en antwoordde nooit, zonder één logregel.
	// net/http heeft datzelfde vangnet (oplopende pauze bij een tijdelijke
	// fout); leanhttp had het niet, en dat verschil was precies het verschil
	// tussen een werkende en een dode display.
	//
	// Tijdelijk = even wachten en opnieuw. Een lege accept zónder fout is geen
	// toestand waar we onszelf uit kunnen redden: dan stoppen we mét reden, zodat
	// de app het logt en de node hem herstart (fail loudly — een display die
	// stilletjes niets doet is erger dan een die opnieuw begint).
	const maxDelay = 100 * time.Millisecond
	var delay time.Duration
	for {
		nc, err := l.Accept()
		switch {
		case err != nil:
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				return err
			}
			if delay == 0 {
				delay = time.Millisecond
			} else if delay *= 2; delay > maxDelay {
				delay = maxDelay
			}
			time.Sleep(delay)
			continue
		case nc == nil:
			return errors.New("leanhttp: listener returned no connection and no error")
		}
		delay = 0
		go serveConn(nc, h)
	}
}

// ListenAndServe luistert op addr (":80") en serveert daar.
func ListenAndServe(addr string, h Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer l.Close()
	return Serve(l, h)
}

// conn is één verbinding in behandeling.
type conn struct {
	nc       net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	hijacked bool // de handler nam de verbinding over
	watched  bool // Done(): er leest een wachthond mee, dus niet hergebruiken
}

func serveConn(nc net.Conn, h Handler) {
	c := &conn{nc: nc, br: bufio.NewReaderSize(nc, bufSize), bw: bufio.NewWriterSize(nc, bufSize)}
	defer func() {
		if !c.hijacked {
			nc.Close()
		}
	}()

	for first := true; ; first = false {
		limit := idleTimeout
		if first {
			limit = requestTimeout
		}
		nc.SetReadDeadline(time.Now().Add(limit))

		r, err := readRequest(c)
		if err != nil {
			// EOF/deadline: de client is gewoon weg. Al het andere is een
			// kapot verzoek en verdient een antwoord vóór we ophangen.
			var perr parseError
			if errors.As(err, &perr) {
				writeBare(nc, perr.status, perr.Error())
				// De client is vaak nog aan het schrijven (een te grote body
				// bijvoorbeeld). Meteen sluiten geeft hem een RST i.p.v. ons
				// antwoord, dus lezen we begrensd mee tot hij uitgesproken is.
				nc.SetReadDeadline(time.Now().Add(drainTimeout))
				io.CopyN(io.Discard, c.br, maxBodyBytes)
			}
			return
		}
		// Vanaf hier bepaalt de handler het tempo: geen leestermijn meer (een
		// stream mag uren duren), de schrijftermijn blijft het vangnet.
		nc.SetReadDeadline(time.Time{})

		w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: r.keepAlive}
		h(w, r)
		if c.hijacked {
			return
		}
		if err := w.finish(); err != nil || !w.keepAlive || c.watched {
			return
		}
		// Het restant van de body wegslikken, anders begint het volgende
		// verzoek middenin de vorige. Lukt dat niet, dan is hergebruik onveilig.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
	}
}

// parseError is een kapot verzoek: de status die de client verdient, plus het
// waarom.
type parseError struct {
	status int
	msg    string
}

func (e parseError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return parseError{StatusBadRequest, fmt.Sprintf(format, args...)}
}

// readRequest leest verzoekregel, headers en de body-omhulling van één verzoek.
func readRequest(c *conn) (*Request, error) {
	budget := maxHeaderBytes
	line, err := readLine(c.br, &budget)
	if err != nil {
		return nil, err // EOF of deadline: geen verzoek meer, geen antwoord nodig
	}
	if line == "" { // een losse CRLF vóór het verzoek mag (RFC 9112 §2.2)
		if line, err = readLine(c.br, &budget); err != nil {
			return nil, err
		}
	}

	method, rest, ok := strings.Cut(line, " ")
	if !ok {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	// Onderscheid: "HTTP/2" is een versie die we niet doen (505), al het andere
	// op die plek is geen verzoekregel (400).
	if !strings.HasPrefix(proto, "HTTP/") {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	if !strings.HasPrefix(proto, "HTTP/1.") {
		return nil, parseError{505, fmt.Sprintf("leanhttp: unsupported protocol %q", proto)}
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, badRequest("leanhttp: bad request target %q", target)
	}

	hdr := Header{}
	for {
		l, err := readLine(c.br, &budget)
		if err != nil {
			// Hier is een afgebroken verbinding wél een kapot verzoek: de
			// client was al begonnen.
			return nil, badRequest("leanhttp: read headers: %v", err)
		}
		if l == "" {
			break
		}
		k, v, found := strings.Cut(l, ":")
		if !found {
			return nil, badRequest("leanhttp: malformed header %q", l)
		}
		hdr.add(k, strings.TrimSpace(v))
	}

	r := &Request{
		ContentLength: -1, // geen Content-Length gezien; hieronder gezet als hij er is
		Method:        method,
		Path:          u.Path,
		RawQuery:      u.RawQuery,
		Proto:         proto,
		Header:        hdr,
		Body:          emptyBody{},
		RemoteAddr:    c.nc.RemoteAddr().String(),
		c:             c,
	}
	// HTTP/1.1 houdt de verbinding open tenzij iemand "close" zegt; 1.0 is
	// andersom.
	want := strings.ToLower(hdr.Get("Connection"))
	r.keepAlive = proto == "HTTP/1.1" && !strings.Contains(want, "close") ||
		proto == "HTTP/1.0" && strings.Contains(want, "keep-alive")

	switch te := hdr.Get("Transfer-Encoding"); {
	case te != "" && !strings.EqualFold(te, "identity"):
		// Chunked kunnen we lezen, maar dan weten we niet of we het einde
		// precies raken: deze verbinding is na dit verzoek op.
		r.Body = io.LimitReader(&chunkReader{br: c.br}, maxBodyBytes)
		r.keepAlive = false
	case hdr.Get("Content-Length") != "":
		n, err := strconv.ParseInt(hdr.Get("Content-Length"), 10, 64)
		if err != nil || n < 0 {
			return nil, badRequest("leanhttp: bad Content-Length %q", hdr.Get("Content-Length"))
		}
		if n > maxBodyBytes {
			return nil, parseError{StatusRequestEntityTooLarge,
				fmt.Sprintf("leanhttp: body of %d bytes exceeds the %d-byte limit", n, maxBodyBytes)}
		}
		r.ContentLength = n
		r.Body = io.LimitReader(c.br, n)
	}
	return r, nil
}

// emptyBody is de body van een bericht dat er geen heeft: leesbaar, meteen op.
// Aan de serverkant een verzoek zonder body, aan de clientkant een 204/304.
type emptyBody struct{}

func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }

// respWriter is de ResponseWriter van één verzoek.
type respWriter struct {
	c         *conn
	hdr       Header
	status    int
	statusSet bool
	buf       bytes.Buffer // gebufferd tot finish: zo kennen we de lengte
	started   bool         // de kop is de deur uit
	chunked   bool
	written   int64 // body-bytes de deur uit (voor de lengte-controle)
	keepAlive bool
	err       error
}

var errHijacked = errors.New("leanhttp: connection was hijacked")

func (w *respWriter) Header() Header { return w.hdr }

func (w *respWriter) WriteHeader(status int) {
	if w.statusSet || w.started {
		return // de eerste keer telt; een tweede WriteHeader is een bug, geen tweede kop
	}
	w.status, w.statusSet = status, true
}

func (w *respWriter) Write(p []byte) (int, error) {
	switch {
	case w.c.hijacked:
		return 0, errHijacked
	case w.err != nil:
		return 0, w.err
	case !w.started:
		// Zonder aangekondigde lengte bufferen we: bij finish weten we hoeveel
		// het geworden is en gaat er een Content-Length op. Een handler die de
		// lengte zélf zet (een gecachete PNG bijvoorbeeld) schrijft rechtstreeks
		// door — dan hoeft die megabyte niet nog eens in een buffer.
		if w.hdr.Get("Content-Length") == "" {
			return w.buf.Write(p)
		}
		w.writeHead()
	}
	return w.writeBody(p)
}

func (w *respWriter) Flush() error {
	switch {
	case w.c.hijacked:
		return errHijacked
	case w.err != nil:
		return w.err
	case !w.started:
		// Tussentijds duwen zonder aangekondigde lengte: de lengte komt er dus
		// nooit — chunked. Wat al gebufferd stond gaat als eerste chunk mee.
		if w.hdr.Get("Content-Length") == "" {
			w.chunked = true
		}
		pending := w.buf.Bytes()
		w.writeHead()
		if len(pending) > 0 {
			w.writeBody(pending)
		}
		w.buf.Reset()
	}
	return w.flush()
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.started {
		return nil, nil, errors.New("leanhttp: Hijack after the response already started")
	}
	if w.c.hijacked {
		return nil, nil, errHijacked
	}
	w.c.hijacked = true
	w.c.nc.SetDeadline(time.Time{}) // vanaf nu bepaalt de overnemer de termijnen
	return w.c.nc, bufio.NewReadWriter(w.c.br, w.c.bw), nil
}

// writeHead schrijft statusregel + headers in de buffer.
func (w *respWriter) writeHead() {
	w.started = true
	if w.chunked {
		w.hdr.Set("Transfer-Encoding", "chunked")
	}
	// De wachthond van Done() leest mee op deze verbinding, dus hij is na dit
	// antwoord op — en dan mag de kop géén keep-alive beloven. Deed hij dat
	// wel, dan legt een client met een pool hem netjes weg en loopt het
	// VOLGENDE verzoek op een dode verbinding: GEMETEN 12-08 op ijzer als
	// 200/502/200/502 door hop's agent-proxy, want die bouwde per verzoek een
	// context uit Done().
	if w.keepAlive && !w.c.watched {
		w.hdr.Set("Connection", "keep-alive")
	} else {
		w.hdr.Set("Connection", "close")
	}
	fmt.Fprintf(w.c.bw, "HTTP/1.1 %d %s\r\n", w.status, statusText(w.status))
	for k, v := range w.hdr {
		// Een CRLF in naam of waarde zou een tweede antwoord in dit antwoord
		// smokkelen: overslaan, niet doorgeven.
		if strings.ContainsAny(k, "\r\n: ") || k == "" || strings.ContainsAny(v, "\r\n") {
			continue
		}
		fmt.Fprintf(w.c.bw, "%s: %s\r\n", k, v)
	}
	w.c.bw.WriteString("\r\n")
}

// writeBody schrijft body-bytes in de gekozen framing.
func (w *respWriter) writeBody(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, w.err
	}
	if w.chunked {
		fmt.Fprintf(w.c.bw, "%x\r\n", len(p))
	}
	n, err := w.c.bw.Write(p)
	w.written += int64(n)
	if err == nil && w.chunked {
		_, err = w.c.bw.WriteString("\r\n")
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// flush duwt de bufio naar de socket, met een schrijftermijn als vangnet: een
// client die niet meer leest mag geen goroutine gijzelen.
func (w *respWriter) flush() error {
	w.c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := w.c.bw.Flush()
	w.c.nc.SetWriteDeadline(time.Time{})
	if err != nil && w.err == nil {
		w.err = err
	}
	return err
}

// finish rondt het antwoord af: het normale (gebufferde) geval krijgt hier zijn
// Content-Length, een chunked antwoord zijn nul-chunk.
func (w *respWriter) finish() error {
	if w.c.hijacked {
		return nil
	}
	switch {
	case !w.started:
		body := w.buf.Bytes()
		if !bodyAllowed(w.status) {
			body = nil // 204/304: een lengte of body hoort er niet
		} else {
			w.hdr.Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.writeHead()
		w.writeBody(body)
	case w.chunked:
		w.c.bw.WriteString("0\r\n\r\n")
	default:
		// Het rechtstreekse pad: de handler beloofde een lengte. Klopt die
		// niet met wat hij schreef, dan staat de volgende lezer op deze
		// verbinding op de verkeerde byte — hergebruik is dan uitgesloten.
		if n, err := strconv.ParseInt(w.hdr.Get("Content-Length"), 10, 64); err != nil || n != w.written {
			w.keepAlive = false
		}
	}
	if err := w.flush(); err != nil {
		return err
	}
	return w.err
}

// bodyAllowed: 1xx, 204 en 304 hebben per definitie geen body.
func bodyAllowed(status int) bool {
	return status >= 200 && status != StatusNoContent && status != 304
}

// writeBare antwoordt op een verzoek dat we niet eens konden lezen. Kort, en
// daarna gaat de verbinding dicht.
func writeBare(nc net.Conn, status int, msg string) {
	nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	fmt.Fprintf(nc, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s\n", status, statusText(status), len(msg)+1, msg)
}

// Error antwoordt met een statuscode en een platte-tekst-uitleg.
func Error(w ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

// Redirect stuurt de client door (302 tenzij anders gevraagd).
func Redirect(w ResponseWriter, location string, status int) {
	w.Header().Set("Location", location)
	w.WriteHeader(status)
	io.WriteString(w, "redirecting to "+location+"\n")
}

// statusText geeft de reden-tekst bij een code. Alleen wat dit pakket en zijn
// afnemers echt versturen; de rest is "Status" — een client leest de code, niet
// het proza.
func statusText(status int) string {
	switch status {
	case StatusOK:
		return "OK"
	case StatusCreated:
		return "Created"
	case StatusNoContent:
		return "No Content"
	case 304:
		return "Not Modified"
	case StatusFound:
		return "Found"
	case StatusBadRequest:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case StatusNotFound:
		return "Not Found"
	case StatusMethodNotAllowed:
		return "Method Not Allowed"
	case 411:
		return "Length Required"
	case StatusRequestEntityTooLarge:
		return "Request Entity Too Large"
	case StatusInternalServerError:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 505:
		return "HTTP Version Not Supported"
	}
	return "Status"
}
