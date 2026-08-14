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

	// autoChunkBytes is de drempel waarboven een antwoord zonder aangekondigde
	// Content-Length overschakelt op chunked in plaats van dóór te bufferen.
	// Zonder drempel buffert een vergeten lengte onbegrensd — op een node van
	// 64MB is één zo'n handler een OOM (review 13-08). 64K houdt de gewone
	// API-antwoorden op het één-kop-één-lengte-pad.
	autoChunkBytes = 64 << 10

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

	// bodyTimeout begrenst het lezen van de verzoekbody dóór de handler: een
	// client die een Content-Length belooft en dan stilvalt hield anders een
	// goroutine (en zijn fd) onbeperkt vast in io.ReadAll — de drain ná de
	// handler had wel een termijn, maar werd dan nooit bereikt (review 13-08,
	// tiende ronde). De body is begrensd op maxBodyBytes (1MiB), dus dit is op
	// élke link die deze server dient ruim.
	bodyTimeout = 5 * time.Second
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
	Method string // "GET", "POST", …
	// Path is het pad: %-gedecodeerd en geschoond (geen "..", geen dubbele
	// slashes). Ambigue escapes — een segment dat naar "/", "." of ".."
	// decodeert — zijn bij het parsen al geweigerd (400), dus deze ene vorm
	// is voor middleware, Mux en handler dezelfde, en een rewrite door
	// middleware telt gewoon (review 13-08, zevenentwintigste ronde).
	Path       string
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

	c *conn

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
// hebt — de wachthond zou die bytes opeten. En roep hem VÓÓR je eerste Flush
// aan: de kop moet "Connection: close" kunnen zeggen (zie writeHead), en die
// is na de eerste Flush al de deur uit.
//
// Done en Hijack sluiten elkaar uit: de leeskant heeft precies één eigenaar —
// HTTP zelf, de wachthond van Done, óf de overnemer van Hijack. Done ná een
// Hijack panickt: de wachthond zou de bytes van de overnemer (WebSocket-frames)
// opeten, en dat is een bedradingsfout, geen storing (review 13-08,
// eenendertigste ronde).
//
// De Hijack- en kop-regel zijn sinds de tweeëndertigste ronde AFGEDWONGEN,
// fail-fast bij de éérste aanroep: die twee condities zijn puur
// handler-gestuurd, dus een overtreding is een bedradingsfout van óns. Een
// ongelezen body is dat NIET: "GET /stream" mét "Content-Length: 1" is
// volkomen geldig HTTP van de klant, en de fail-fast-panic die hier één ronde
// stond maakte dat een remote kill — op HopOS is een panic een node-herstart,
// herhaalbaar per verzoek (review 13-08, zesendertigste ronde). Dus: een
// niet-gedrainde body wordt hier begrensd wéggedraineerd (zelfde
// drainTimeout-recept als serveConn) vóór de wachthond start; wat er dan nog
// zou druppelen eet de wachthond toch. Het contract "lees éérst je body"
// blijft gelden voor handlers die de body daadwerkelijk willen.
// Latere aanroepen (een streamer die per lusronde r.Done()/Context() vraagt)
// zijn vrij: het eigenaarschap is dan al geclaimd.
func (r *Request) Done() <-chan struct{} {
	if r.done == nil {
		switch {
		case r.c.hijacked:
			panic("leanhttp: Request.Done after Hijack — the connection's read side belongs to the hijacker")
		case r.c.headSent:
			panic("leanhttp: Request.Done after the response started — claim done before your first Flush")
		}
		if !bodyDrained(r.Body) {
			r.c.nc.SetReadDeadline(time.Now().Add(drainTimeout))
			io.Copy(io.Discard, r.Body)
		}
	}
	r.doneOnce.Do(func() {
		r.done = make(chan struct{})
		r.c.watched = true
		// De leestermijn wissen, net als Hijack: op een body-dragend verzoek
		// staat de bodyTimeout van serveConn nog aan, en de wachthond hieronder
		// leest op diezelfde verbinding — zijn read liep dan na ~5s op die
		// termijn stuk, en een read-fout betekent voor hem "de kijker is weg".
		// Een POST-streamer die eerst netjes zijn body las en dán Done aanriep
		// zag zijn stream zo spontaan verlaten (review 13-08, elfde ronde).
		r.c.nc.SetReadDeadline(time.Time{})
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
			// Ook Temporary(): een EMFILE (fd's op) is geen reden om de hele
			// server te laten sterven — even wachten en opnieuw, net als
			// net/http (review 13-08, vijfentwintigste ronde). De methode is
			// deprecated, maar het onderscheid dat hij maakt is precies wat
			// hier nodig is.
			if !errors.As(err, &ne) || (!ne.Timeout() && !ne.Temporary()) {
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
	headSent bool // de responsekop is de deur uit (writeHead) — Done is dan te laat
}

// timedWriter is de ENE plek die de socket schrijft, en elke write draagt
// zijn eigen schrijftermijn — letterlijk "per schrijfronde, niet per
// antwoord". De bufio erboven beslist wanneer er geschreven wordt (flush,
// overloop, grote passthrough); dit type hoeft alleen te weten dát het de
// socket raakt. De hele arm/clear-choreografie die eerst rond élke mogelijk-
// spillende operatie stond (armWrite/armIfSpills/clearWrite, marges, en de
// vergeten-wis-valkuil) verdween hiermee (review 13-08, achttiende ronde).
type timedWriter struct{ nc net.Conn }

func (t *timedWriter) Write(p []byte) (int, error) {
	t.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	n, err := t.nc.Write(p)
	t.nc.SetWriteDeadline(time.Time{})
	return n, err
}

func serveConn(nc net.Conn, h Handler) {
	c := &conn{nc: nc, br: bufio.NewReaderSize(nc, bufSize), bw: bufio.NewWriterSize(&timedWriter{nc: nc}, bufSize)}
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
				// Alleen als er een aangekondigde body onderweg is (413,
				// TE+CL, kapotte lengte) lezen we begrensd mee tot de client
				// uitgesproken is: meteen sluiten gaf hem een RST i.p.v. ons
				// antwoord. Bij een kale syntaxfout is het verzoek al binnen
				// en was de onvoorwaardelijke drain een cadeautje: elke
				// malformed request pinde goroutine, socket en leannet-budget
				// twee volle seconden (review 13-08, vijftiende ronde).
				if perr.drain {
					nc.SetReadDeadline(time.Now().Add(drainTimeout))
					io.CopyN(io.Discard, c.br, maxBodyBytes)
				}
			}
			return
		}
		// Vanaf hier bepaalt de handler het tempo — behálve voor het lezen van
		// een verzoekbody: die is begrensd (bodyTimeout, zie boven). Valt er
		// niets te lezen, dan géén leestermijn: een handler leest dan toch
		// niets, en een SSE-stroom mag uren duren (de schrijftermijn blijft het
		// vangnet). bodyDrained en niet een typetoets op emptyBody: een
		// Content-Length: 0 draagt een lengthReader{n: 0} en is nét zo goed
		// bodyloos (review 13-08, elfde ronde).
		if bodyDrained(r.Body) {
			nc.SetReadDeadline(time.Time{})
		} else {
			nc.SetReadDeadline(time.Now().Add(bodyTimeout))
		}

		// (De 100-Continue-machine die hier stond is gesloopt: élke Expect is
		// bij het parsen al een 417 — eenendertigste ronde.)
		// Exact "HEAD", geen EqualFold: methode-tokens zijn hoofdlettergevoelig
		// (RFC 9110 §9.1) — "head" is een ándere, custom methode, en die de
		// body onderdrukken terwijl de kop een lengte belooft liet de client
		// op bytes wachten die nooit komen (review 13-08, drieëntwintigste
		// ronde).
		c.headSent = false // per verzoek: de vorige ronde op deze keep-alive telt niet
		w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: r.keepAlive,
			head: r.Method == "HEAD", declared: -1}
		h(w, r)
		if c.hijacked {
			return
		}
		if err := w.finish(); err != nil || !w.keepAlive || c.watched {
			// Ook vóór een NETTE sluiting hoort het ongelezen restant van een
			// geldige body begrensd weggeslikt: een Close met ontvangen-maar-
			// ongelezen bytes wordt op TCP een RST, en een RST gooit óók de
			// zendwachtrij weg — het antwoord dat hierboven net verstuurd is
			// kon zo bij de client stukbreken vóór hij het las (review 13-08,
			// eenendertigste ronde). Niet na een schrijffout (verbinding is al
			// kapot) en niet als de Done-wachthond de lezer bezit.
			if err == nil && !c.watched && !bodyDrained(r.Body) {
				nc.SetReadDeadline(time.Now().Add(drainTimeout))
				io.Copy(io.Discard, r.Body)
			}
			return
		}
		// Het restant van de body wegslikken, anders begint het volgende
		// verzoek middenin de vorige. Mét termijn: een client die een lengte
		// belooft en dan stilvalt hield anders deze goroutine onbeperkt vast
		// (review 13-08). Lukt het niet, dan is hergebruik onveilig. Is de body
		// al op (geen body, of helemaal gelezen — het gewone geval), dan slaan
		// we ook de deadline-wissels over: op leannet is elke SetReadDeadline
		// een stack-brede wek (review 13-08, vijfde ronde).
		if !bodyDrained(r.Body) {
			nc.SetReadDeadline(time.Now().Add(drainTimeout))
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			nc.SetReadDeadline(time.Time{})
		}
	}
}

// bodyDrained rapporteert of er aan een verzoekbody niets (meer) te lezen valt:
// er was er geen, hij was leeg (Content-Length: 0), of hij is al tot het einde
// gelezen. Dit zijn ook de enige twee bodyvormen die bestaan: chunked uploads
// zijn gesloopt (eenendertigste ronde).
func bodyDrained(r io.Reader) bool {
	switch b := r.(type) {
	case emptyBody:
		return true
	case *lengthReader:
		return b.n <= 0
	}
	return false
}

// parseError is een kapot verzoek: de status die de client verdient, plus het
// waarom. drain: de headers kondigen een body aan die (mogelijk) nog
// binnenkomt — dan eerst begrensd leeglezen zodat het antwoord aankomt in
// plaats van een RST. Voor een pure syntaxfout staat hij uit: daar is het
// verzoek al binnen en was de drain alleen een vasthoudlus (review 13-08,
// vijftiende ronde).
type parseError struct {
	status int
	msg    string
	drain  bool
}

func (e parseError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return parseError{status: StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

// readRequest leest verzoekregel, headers en de body-omhulling van één verzoek.
func readRequest(c *conn) (*Request, error) {
	// EOF of deadline op de verzoekregel: de client is gewoon weg, geen
	// antwoord nodig. Maar een regel die er wél is en niet deugt — kale LF,
	// control-bytes, te lang (zie readLine) — is een verzóek, en dat verdient
	// een 400 in plaats van een stille close (review 13-08, dertiende ronde:
	// readLine werd strikt en daarmee kreeg dit pad echte syntaxfouten).
	classify := func(err error) error {
		if errors.Is(err, io.EOF) {
			return err
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return err
		}
		return badRequest("%v", err)
	}
	budget := maxHeaderBytes
	line, err := readLine(c.br, &budget)
	if err != nil {
		return nil, classify(err)
	}
	if line == "" { // een losse CRLF vóór het verzoek mag (RFC 9112 §2.2)
		if line, err = readLine(c.br, &budget); err != nil {
			return nil, classify(err)
		}
	}

	method, rest, ok := strings.Cut(line, " ")
	if !ok {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	if !validToken(method) {
		// Zelfde tokenwacht als uitgaand: een "methode" met rare bytes is
		// achter een proxy een bekende bron van afwijkende routering
		// (review 13-08, tiende ronde).
		return nil, badRequest("leanhttp: invalid method %q", method)
	}
	if method == "CONNECT" {
		// CONNECT is een tunnelopdracht, geen verzoek — en deze server is
		// nooit een tunnel. De origin-form-toets hieronder ving alleen de
		// authority-form; "CONNECT / HTTP/1.1" bereikte de handler als was
		// het een gewone methode (review 13-08, tweeëndertigste ronde).
		return nil, parseError{StatusNotImplemented, "leanhttp: CONNECT is not supported", false}
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
	if proto != "HTTP/1.1" {
		// Exact, geen prefix (HasPrefix("HTTP/1.") accepteerde HTTP/1.9). En
		// alléén 1.1: niets in of rond HopOS spreekt nog HTTP/1.0 tégen ons —
		// de 1.0-tak (omgekeerde keep-alive-default, geen chunked, eigen
		// statusregel, Host optioneel) was puur reviewvlak (review 13-08,
		// negenentwintigste ronde, "minder code = minder fouten"). De CLIENT
		// blijft 1.0-antwoorden wél verstaan: Python's http.server spreekt
		// het, gemeten 12-08.
		return nil, parseError{status: 505, msg: fmt.Sprintf("leanhttp: unsupported protocol %q", proto)}
	}
	if target == "" || target[0] != '/' {
		// Uitsluitend de origin-form ("/pad?query", RFC 9112 §3.2.1). De
		// asterisk-form (OPTIONS *) gaf als pad "/*" een verzonnen route
		// (review 13-08, achtentwintigste ronde); de absolute-form droeg een
		// tweede authority naast Host en daarmee een blijvende
		// consistentie-plicht; de authority-form is CONNECT en dat is een
		// tunnel die deze server nooit zal zijn. Eén toets weigert alle drie
		// (review 13-08, eenendertigste ronde: weigeren wat je niet draagt).
		return nil, badRequest("leanhttp: only origin-form request targets are supported, got %q", target)
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, badRequest("leanhttp: bad request target %q", target)
	}
	// Ambigue escapes weigeren we aan de deur (zie cleanEscapes in mux.go):
	// een segment dat naar "/", "." of ".." decodeert is ná decoderen niet
	// meer van echte padstructuur te onderscheiden (review 13-08,
	// zevenentwintigste ronde).
	if !cleanEscapes(u.EscapedPath()) {
		return nil, badRequest("leanhttp: ambiguous percent-escape in path %q", u.EscapedPath())
	}
	// En het gedecodeerde pad moet CANONIEK zijn: geen lege segmenten
	// ("//admin"), geen dot-segmenten. Normaliseren (cleanPath) was een tweede
	// interpretatiemoment — "//admin" werd stil "/admin", en dat is precies de
	// klasse differentialen die de deur-weigering hierboven dichtgooide. Eén
	// predicaat, gedeeld met de Mux: hier een 400, daar een 404
	// (review 13-08, tweeëndertigste ronde; cleanPath is gesloopt).
	if !canonicalPath(u.Path) {
		return nil, badRequest("leanhttp: non-canonical request path %q", u.Path)
	}

	hdr := Header{}
	hosts, cls, tes := 0, 0, 0
	if err := readHeaderBlock(c.br, &budget, func(k, v string) error {
		// De tokenwacht op de naam zit in readHeaderBlock zelf (één parser
		// voor beide kanten); hier alleen tellen en opslaan. De framing-
		// headers tellen per FYSIEKE regel: hdr.add vouwt waarden en liet een
		// lege eerste zelfs verdwijnen — "Content-Length:" plus
		// "Content-Length: 5" werd zo één geldige lengte, een klassiek
		// smuggling-differentiaal (review 13-08, vierentwintigste ronde).
		switch {
		case strings.EqualFold(k, "Host"):
			hosts++
		case strings.EqualFold(k, "Content-Length"):
			cls++
		case strings.EqualFold(k, "Transfer-Encoding"):
			tes++
		}
		hdr.add(k, v)
		return nil
	}); err != nil {
		// Alles hier — kapotte header, ongeldige naam, afgebroken verbinding —
		// is een kapot verzoek van een client die al begonnen was: 400.
		return nil, badRequest("leanhttp: read headers: %v", err)
	}

	// HTTP/1.1 eist precies één niet-lege Host (RFC 9112 §3.2): geen, leeg of
	// meerdere is achter een proxy een routerings-smokkelgat (review 13-08,
	// tiende ronde). Meerdere regels zijn door hdr.add al tot een kommalijst
	// gevouwen — vandaar de teller.
	// Geen TrimSpace: readHeaderBlock levert waarden al getrimd af.
	// Precies één niet-lege Host (RFC 9112 §3.2) — en verder NIETS: de
	// half-algemene vorm-parser (hostnaam-grammatica, [v6], poortcijfers) uit
	// de dertigste ronde is er in de eenendertigste weer uit. Deze server
	// routeert en autoriseert nergens op Host, dus elke vormtolerantie of
	// -strengheid was dode zorg; de dag dat Host wél iets bepaalt hoort hier
	// een expliciete allowlist, geen grammatica. De regel die overblijft is de
	// smuggling-wacht: geen, leeg of meerdere is achter een proxy een
	// routerings-differentiaal. Waarden zijn al CTL-vrij (readLine).
	if hosts != 1 || hdr.Get("Host") == "" {
		return nil, badRequest("leanhttp: HTTP/1.1 requires exactly one non-empty Host header (got %d)", hosts)
	}

	r := &Request{
		ContentLength: -1, // geen Content-Length gezien; hieronder gezet als hij er is
		Method:        method,
		Path:          u.Path, // canoniek bewezen (canonicalPath hierboven)
		RawQuery:      u.RawQuery,
		Proto:         proto,
		Header:        hdr,
		Body:          emptyBody{},
		RemoteAddr:    c.nc.RemoteAddr().String(),
		c:             c,
	}
	// HTTP/1.1 houdt de verbinding open tenzij iemand "close" zegt.
	// Connection is een tokenlijst; de client-kant toetst al zo (connectionHas)
	// en een substring-toets is te ruim (review 13-08, vierde ronde).
	r.keepAlive = !connectionHas(hdr.Get("Connection"), "close")

	// Iedere Expect is een 417 en de verbinding gaat dicht (RFC 9110 §10.1.1
	// staat dat toe: een server MAG elke verwachting afwijzen). De hele
	// 100-Continue-machine aan de serverkant — het interim-antwoord, de
	// wachttijd-afstemming met de bodyTimeout — bestond voor precies nul
	// interne bellers: onze eigen client stuurt Expect alleen bij een
	// BodyReader, en niets in de keten streamt een upload naar déze server
	// (review 13-08, eenendertigste ronde: minder machine = minder reviewvlak).
	// drain=false: een client met Expect wacht juist met zijn body.
	if hdr.Get("Expect") != "" {
		return nil, parseError{StatusExpectationFailed,
			fmt.Sprintf("leanhttp: Expect %q is not supported", hdr.Get("Expect")), false}
	}

	switch {
	case cls > 1 || tes > 1:
		// Herhaalde framingheaders (ook met lege waarden) zijn per regel
		// geteld en per definitie verdacht: weigeren (RFC 9112 §6).
		return nil, parseError{StatusBadRequest,
			"leanhttp: repeated framing header", true}
	case tes == 1 && cls == 1:
		// Beide framings tegelijk is hét smokkelsignaal (RFC 9112 §6.1): twee
		// parsers in de keten kiezen dan elk hun eigen lichaamseinde. Weigeren,
		// en de verbinding is niet meer te vertrouwen.
		return nil, parseError{StatusBadRequest,
			"leanhttp: both Transfer-Encoding and Content-Length", true}
	case tes == 1:
		// Verzoeklichamen dragen een Content-Length, punt: chunked uploads —
		// mét hun trailers, extensies en limiet-op-de-lezer — zijn gesloopt
		// (review 13-08, eenendertigste ronde). Geen van onze afnemers
		// verstuurde er ooit één (de eigen client chunkt bewust niet), en de
		// chunk-parser aan deze kant was puur reviewvlak. De CLIENT blijft
		// chunked ANTWOORDEN wél lezen — dat is niet optioneel voor SSE.
		return nil, parseError{StatusNotImplemented,
			"leanhttp: Transfer-Encoding is not supported for requests; send a Content-Length", true}
	case cls == 1:
		// parseDecimal, geen ParseInt: "+5" moet hier een 400 zijn, geen 5 —
		// een lengte die wij anders lezen dan de proxy vóór ons is precies het
		// framing-verschil waar smuggling op drijft (review 13-08, dertiende
		// ronde).
		n, ok := parseDecimal(hdr.Get("Content-Length"))
		if !ok {
			// drain: er ís een Content-Length, dus de client stuurt
			// (waarschijnlijk) een body achter dit kopblok aan.
			return nil, parseError{StatusBadRequest,
				fmt.Sprintf("leanhttp: bad Content-Length %q", hdr.Get("Content-Length")), true}
		}
		if n > maxBodyBytes {
			return nil, parseError{StatusRequestEntityTooLarge,
				fmt.Sprintf("leanhttp: body of %d bytes exceeds the %d-byte limit", n, maxBodyBytes), true}
		}
		r.ContentLength = n
		// Zelfde exacte-lengte-semantiek als de clientkant (lengthReader): een
		// client die na 5 van de 10 beloofde bytes sluit is een AFGEBROKEN
		// verzoek (io.ErrUnexpectedEOF), geen kortere body — de handler
		// verwerkte anders een half verzoek als compleet (review 13-08).
		r.Body = &lengthReader{r: c.br, n: n}
	}
	return r, nil
}

// emptyBody is de body van een bericht dat er geen heeft: leesbaar, meteen op.
// Aan de serverkant een verzoek zonder body, aan de clientkant een 204/304.
type emptyBody struct{}

func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }

// validToken toetst een headernaam aan het token-alfabet van RFC 9110 §5.6.2.
// Witruimte valt daar per constructie buiten — dus ook de spatie-vóór-de-
// dubbele-punt die een smokkelaar gebruikt om een framing-header te verstoppen.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

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
	declared  int64 // beloofde Content-Length op het rechtstreekse pad; -1 = geen
	keepAlive bool
	head      bool // antwoord op HEAD: kop als bij GET, maar géén body-bytes
	err       error
}

// errWroteTooMuch: de handler schreef voorbij zijn eigen Content-Length. De
// surplus-bytes gaan NIET de deur uit — op een keep-alive-verbinding zouden ze
// het begin van het volgende antwoord zijn (review 13-08, vijfde ronde).
var errWroteTooMuch = errors.New("leanhttp: handler wrote past its declared Content-Length")

var errHijacked = errors.New("leanhttp: connection was hijacked")

func (w *respWriter) Header() Header { return w.hdr }

// suppressBody: dit antwoord draagt per definitie geen body-bytes — HEAD, of
// een status zonder body (204/304). De kop (inclusief Content-Length) blijft
// wat hij is; de bytes worden geslikt (RFC 9110 §9.3.2 en 9112 §6.3). Vóór de
// fix werden ze gewoon geschreven en stond de volgende lezer op de verkeerde
// byte (review 13-08).
func (w *respWriter) suppressBody() bool { return w.head || !bodyAllowed(w.status) }

func (w *respWriter) WriteHeader(status int) {
	if status < 200 || status > 599 {
		// Alleen finale statussen (200–599): 0, negatief, viercijferig én élke
		// 1xx is een bedradingsfout in de handler. Interim-antwoorden verstuurt
		// deze server per contract niet — de WebSocket-101 loopt uitsluitend
		// via Hijack, waar de overnemer zijn eigen statusregel schrijft
		// (review 13-08, dertigste + eenendertigste ronde; het stille
		// 1xx-negeren van de vijfentwintigste is daarmee ook weg).
		panic("leanhttp: WriteHeader with a non-final status")
	}
	// (205 is gewoon een finale status: hij wordt als zichzelf gedragen en is
	// per definitie bodyloos — zie bodyAllowed. De remap naar 204 die hier één
	// ronde stond veranderde de status stil, en de panic van de ronde ervóór
	// was via hop's status-kopiërende proxy van buiten voedbaar. KAM: "de
	// writer verandert haar niet stil in een andere status" — review 13-08,
	// zevendertigste ronde.)
	if w.statusSet || w.started || w.buf.Len() > 0 {
		// De eerste keer telt — en een Write telt óók als commit: Write("ok")
		// gevolgd door WriteHeader(500) leverde anders een 500 met de "ok"
		// als foutbody (review 13-08, achtentwintigste ronde).
		return
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
			if w.buf.Len()+len(p) <= autoChunkBytes {
				return w.buf.Write(p)
			}
			// Drempel voorbij: de lengte komt er toch nooit meer, en
			// dóórbufferen is de OOM van een vergeten Content-Length.
			if err := w.startChunked(); err != nil {
				return 0, err
			}
			return w.writeBody(p)
		}
		w.writeHead()
	}
	return w.writeBody(p)
}

// startChunked schakelt over op chunked; gedeeld door Write (drempel) en
// Flush (expliciet).
func (w *respWriter) startChunked() error {
	w.chunked = true
	return w.flushHead()
}

// flushHead schrijft de kop plus wat gebufferd stond, en laat de buffer écht
// los (een Reset houdt de backing array vast voor de rest van een streamende
// response — review 13-08, derde ronde).
func (w *respWriter) flushHead() error {
	pending := w.buf.Bytes()
	w.writeHead()
	if len(pending) > 0 {
		if _, err := w.writeBody(pending); err != nil {
			return err
		}
	}
	w.buf = bytes.Buffer{}
	return nil
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
			if err := w.startChunked(); err != nil {
				return err
			}
			break
		}
		// De handler beloofde wél een lengte: kop plus buffer eruit, framing
		// blijft de lengte.
		if err := w.flushHead(); err != nil {
			return err
		}
	}
	return w.flush()
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.started || w.buf.Len() > 0 || w.statusSet {
		// Ook gebúfferde writes en een gezette status tellen als begonnen: de
		// aanroep rapporteerde succes, en een geslaagde Hijack liet dat werk
		// stil verdwijnen (review 13-08, vijfentwintigste en achtentwintigste
		// ronde).
		return nil, nil, errors.New("leanhttp: Hijack after the response already started")
	}
	if w.c.watched {
		// De leeskant heeft al een eigenaar: de wachthond van Request.Done
		// leest deze verbinding leeg. Hem tóch overdragen liet twee lezers om
		// dezelfde bytes racen — de wachthond at dan WebSocket-frames op
		// (review 13-08, eenendertigste ronde). Done, Hijack of gewoon HTTP:
		// kies er één.
		return nil, nil, errors.New("leanhttp: Hijack after Request.Done — the read side already has an owner")
	}
	if w.c.hijacked {
		return nil, nil, errHijacked
	}
	w.c.hijacked = true
	// De leestermijn wissen: op een body-dragend verzoek staat de bodyTimeout
	// nog aan (serveConn), en de overnemer bepaalt vanaf hier zijn eigen
	// termijnen.
	w.c.nc.SetDeadline(time.Time{})
	// Een VERSE writer rechtstreeks op de socket: c.bw schrijft door de
	// timedWriter en zou de overnemer de 30s-per-write laten erven, terwijl
	// het contract zegt dat de overnemer zijn eigen termijnen bepaalt. Er
	// staat niets in c.bw (Hijack kan alleen vóór de eerste write).
	return w.c.nc, bufio.NewReadWriter(w.c.br, bufio.NewWriterSize(w.c.nc, bufSize)), nil
}

// writeHead schrijft statusregel + headers in de buffer.
func (w *respWriter) writeHead() {
	w.started = true
	w.c.headSent = true // vanaf hier is Done() te laat: de kop staat op de draad
	// Casevarianten eerst deterministisch oplossen, vóór élke validatie:
	// directe mapwrites konden "Content-Length: 2" én "content-length: 5"
	// dragen, waarna Get willekeurig de één valideerde en de schrijf-lus de
	// ander uitgaf (review 13-08, zevenentwintigste ronde). Gelijke waarden
	// vouwen samen; conflicterende gaan er allemaal uit en de verbinding
	// sluit — framing op EOF is dan de enige eerlijke vorm.
	byFold := make(map[string][]string, len(w.hdr))
	for k := range w.hdr {
		lk := strings.ToLower(k)
		byFold[lk] = append(byFold[lk], k)
	}
	for _, keys := range byFold {
		if len(keys) < 2 {
			continue
		}
		conflict := false
		for _, k := range keys[1:] {
			if w.hdr[k] != w.hdr[keys[0]] {
				conflict = true
			}
			delete(w.hdr, k)
		}
		if conflict {
			delete(w.hdr, keys[0])
			w.keepAlive = false
		}
	}
	// De framing is van de WRITER, nooit van de handler: een handler die zelf
	// Transfer-Encoding zette terwijl de writer op het lengte-pad zat, stuurde
	// TE én Content-Length met een ongechunkte body — ongeldig én
	// smokkel-verdacht bij de ontvanger (review 13-08, tweede ronde).
	w.hdr.Del("Transfer-Encoding")
	// Een handler die zelf "Connection: close" zegt, meent dat: de writer
	// overschreef hem met keep-alive (review 13-08, vijfentwintigste ronde).
	if connectionHas(w.hdr.Get("Connection"), "close") {
		w.keepAlive = false
	}
	if w.suppressBody() {
		w.chunked = false // een bodyloos antwoord framet niets, ook geen nul-chunk
		if w.status == StatusNoContent {
			// Een 204 draagt nooit een lengte (RFC 9110 §8.6, MUST NOT); een
			// 304 mág hem juist informatief dragen — die bleef eerst ook niet
			// staan (review 13-08, vijfentwintigste ronde). HEAD houdt hem
			// sowieso: daar is de lengte de informatie.
			w.hdr.Del("Content-Length")
		}
		if w.status == 205 && !w.head {
			// 205 staat niet in het framingloos-bodyloze rijtje van RFC 9112
			// §6.3: zonder expliciete nul las een standaardclient tot EOF.
			w.hdr.Set("Content-Length", "0")
		}
	}
	if w.chunked {
		w.hdr.Set("Transfer-Encoding", "chunked")
		// Chunked framet zichzelf: élke Content-Length gaat eruit — ook een
		// LEGE ("Content-Length:"), want die ontweek de validatie hieronder
		// (Get geeft "") en stond dan naast de Transfer-Encoding op de draad:
		// TE+CL tegelijk is precies het dubbelzinnige antwoord dat we inkomend
		// als smokkelsignaal weigeren (review 13-08, eenendertigste ronde).
		w.hdr.Del("Content-Length")
	}
	// Zelfde strikte parser als inkomend, en voor ÉLKE kop die een
	// Content-Length draagt — ook een HEAD-antwoord (suppressBody) houdt hem
	// als informatie en glipte er eerst langs (review 13-08, negentiende
	// ronde): "abc" of "+5" is zichtbare ASCII en passeerde validFieldValue,
	// mét een keep-alive-belofte erbij, terwijl we zo'n lengte inkomend als
	// 400 weigeren (zeventiende ronde). Ongeldig = kop eraf en de verbinding
	// dicht: het antwoord framet dan op EOF.
	if cl := w.hdr.Get("Content-Length"); cl != "" {
		n, ok := parseDecimal(cl)
		switch {
		case !ok:
			w.hdr.Del("Content-Length")
			w.keepAlive = false
		case !w.chunked && !w.suppressBody():
			w.declared = n // vanaf nu is élke write hieraan gebonden
		}
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
		// Dezelfde token- en waardewacht als inkomend (validToken,
		// validFieldValue): een naam of waarde met control-bytes zou een
		// tweede antwoord in dit antwoord smokkelen — overslaan, niet
		// doorgeven. En één regel per naam, hoe de map ook bespeeld is:
		// directe mapwrites konden twee case-varianten van Content-Length
		// dragen waarvan er maar één gevalideerd was (review 13-08,
		// vijfentwintigste ronde).
		if !validToken(k) || !validFieldValue(v) {
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
	if w.suppressBody() {
		// De handler mag schrijven (dezelfde code bedient GET en HEAD); de
		// bytes verlaten alleen nooit de node. len(p) terugmelden is het
		// net/http-contract: de handler hoort geen fout te zien.
		return len(p), nil
	}
	if w.declared >= 0 {
		// De belofte is de grens, PER write: de surplus-bytes tegenhouden ná
		// verzending kan niet meer — finish zag de overschrijding pas toen ze
		// al op de draad stonden, klaar om als het volgende antwoord gelezen
		// te worden. Short-write plus fout, en de verbinding is op.
		if allowed := w.declared - w.written; int64(len(p)) > allowed {
			p = p[:allowed]
			n := 0
			if len(p) > 0 {
				n, _ = w.writeBodyRaw(p)
			}
			// De fout gaat naar de HANDLER, niet naar w.err: dat veld is de
			// transportstatus en finish geeft hem terug — dan sloot de
			// verbinding alsnog, terwijl er na het afkappen een exact
			// kloppende response op de draad staat en de kop keep-alive al
			// beloofd had (review 13-08, zevende ronde). Elke vólgende write
			// komt hier opnieuw (allowed is dan 0) en faalt opnieuw luid.
			return n, errWroteTooMuch
		}
	}
	return w.writeBodyRaw(p)
}

// writeBodyRaw schrijft in de gekozen framing, zonder de lengte-wacht.
func (w *respWriter) writeBodyRaw(p []byte) (int, error) {
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

// flush duwt de bufio naar de socket; de schrijftermijn zit per write in de
// timedWriter eronder — een client die niet meer leest mag geen goroutine
// gijzelen.
func (w *respWriter) flush() error {
	err := w.c.bw.Flush()
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
		// writeBody slikt de bytes van een 204/304 zelf al in (suppressBody);
		// hier beslist alleen de kop: wel of geen Content-Length.
		if bodyAllowed(w.status) && !(w.head && w.hdr.Get("Content-Length") != "") {
			// Ook voor HEAD: de Content-Length hoort te zeggen wat GET zou
			// geven (RFC 9110 §9.3.2) — de buffer ís dat antwoord. MAAR een
			// handler die op HEAD zélf een (correcte) lengte zette zonder de
			// bytes te schrijven, zag die met nul overschreven worden
			// (review 13-08, vijfentwintigste ronde). writeBody slikt de
			// bytes daarna in.
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
		// De maat is w.declared — wat er op de DRAAD staat — en nooit de
		// header-map: die is mutabel, en een handler die de lengte ná zijn
		// eerste write "bijwerkte" praatte de controle anders om terwijl de
		// kop al verstuurd was (review 13-08, zevende ronde). Een onderdrukte
		// body (HEAD/204/304) is juist een bewezen einde: die slaan we over.
		if !w.suppressBody() && (w.declared < 0 || w.declared != w.written) {
			w.keepAlive = false
		}
	}
	if err := w.flush(); err != nil {
		return err
	}
	return w.err
}

// bodyAllowed: 1xx, 204, 205 en 304 hebben per definitie geen body (RFC 9110;
// voor 205 §15.3.6: "does not generate content"). LET OP voor 205 aan de
// schrijfkant: RFC 9112 §6.3 noemt hem NIET in het rijtje dat een ontvanger
// zonder framing als bodyloos leest — dus krijgt hij een expliciete
// Content-Length: 0 mee (zie writeHead), anders las een standaardclient tot
// EOF (review 13-08, zevendertigste ronde).
func bodyAllowed(status int) bool {
	return status >= 200 && status != StatusNoContent && status != 205 && status != 304
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
	case 205:
		return "Reset Content"
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
	case StatusExpectationFailed:
		return "Expectation Failed"
	case StatusInternalServerError:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 505:
		return "HTTP Version Not Supported"
	}
	return "Status"
}
