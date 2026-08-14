package leanhttp

// mux.go — routeren op methode, pad en patroon. BEWUST KLEIN: dit is níet
// net/http's ServeMux (die belofte stond hier ooit, en elke reviewronde vond
// de volgende afwijking van Go's formele spec — we waren de router van
// net/http aan het herimplementeren, één bevinding per keer). Dit is de basis
// die onze eigen routetabellen nodig hebben (geteld over hop, hopy en metal:
// ~110 registraties), en verder niets:
//
//	"/health"                       exact dit pad (zonder sluitende slash)
//	"GET /v1/agents"                idem, alleen deze methode (GET bedient ook HEAD)
//	"/logs/"                        de wortel (mét slash) en alles eronder (subtree)
//	"/v1/agents/{id}/logs/"         {id} vangt één segment, leesbaar via PathValue
//	"GET /app-ui/{app}/{path...}"   {path...} vangt de rest, inclusief slashes
//
// Wat er bewust NIET is (weggegooid, review 13-08, zevenentwintigste ronde):
//
//   - géén {$}: een vast pad (zonder slash) en een subtree (mét) dekken samen
//     elke echte routetabel — nul {$}-registraties geteld. {$} registreren
//     panickt met het alternatief in de melding.
//   - géén escaped routing: een %-escape die naar "/", "." of ".." decodeert
//     wordt bij het PARSEN al geweigerd (400, zie cleanEscapes) — weigeren in
//     plaats van afhandelen, dezelfde stance als bij de chunk-extensies.
//     Daardoor is r.Path gewoon het gedecodeerde, geschoonde pad, zien
//     middleware en Mux per constructie hetzelfde, en kán een wildcardwaarde
//     nooit een padscheiding of dot-segment dragen.
//   - géén score en géén sortering: de winnaar is de meest specifieke match
//     (strikte subsetrelatie), per verzoek bepaald. Een telsom liet / en
//     /{x}/{rest...} allebei op 0 uitkomen, waarna registratievolgorde
//     besliste.
//
// Registratiefouten — kruisende patronen, dubbele wildcardnamen, segmenten na
// {rest...}, %-escapes of {$} in een patroon — panicken bij HandleFunc: een
// route die stil nooit vuurt is de slechtste manier om erachter te komen.
//
// De Mux is IMMUTABLE ná de start: registreer alles vóór Serve — HandleFunc
// naast lopende verzoeken is een datarace, en synchronisatie op élk verzoek
// is de prijs niet waard voor een tabel die nooit hoort te muteren
// (review 13-08, achtentwintigste ronde).

import (
	"net/url"
	"strings"
)

// Mux routeert verzoeken naar handlers. Gebruik NewServeMux.
type Mux struct {
	routes []route
}

// route is één geregistreerd patroon, voorgekauwd zodat matchen niets meer
// hoeft te ontleden.
type route struct {
	method  string   // "" = elke methode
	lits    []string // per segment de letterlijke tekst, of "" bij een wildcard
	names   []string // per segment de wildcardnaam, of "" bij een letterlijk
	rest    string   // naam van een {rest...}-wildcard, of ""
	subtree bool     // patroon eindigde op "/": de wortel (mét slash) en alles eronder
	h       Handler
}

// NewServeMux geeft een lege Mux.
func NewServeMux() *Mux { return &Mux{} }

// HandleFunc registreert h voor pattern (zie het docblok voor de vormen).
func (m *Mux) HandleFunc(pattern string, h Handler) {
	method, p := "", pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		method, p = pattern[:i], strings.TrimSpace(pattern[i+1:])
	}
	// Vroeg falen, volledig (review 13-08, dertigste ronde): een kromme
	// methode ("GE(T"), een nil-handler of een patroon dat nooit kan vuren
	// is een bedradingsfout die je bij de start wilt zien, niet bij dispatch.
	if h == nil {
		panic("leanhttp: pattern " + pattern + " registered with a nil handler")
	}
	if method != "" && !validToken(method) {
		panic("leanhttp: pattern " + pattern + " has a malformed method token")
	}
	if !canonicalPath(p) {
		// Hetzelfde predicaat als requestdispatch (parser 400, ServeHTTP 404):
		// de Trim/Split hieronder — met zijn overslaan van lege segmenten —
		// vouwde "/a//b", "//a" en "/a//" anders STIL naar een andere route,
		// die vervolgens nooit kon vuren of (erger) een andere dekking had
		// dan geschreven stond (review 13-08, vierendertigste ronde).
		panic("leanhttp: pattern " + pattern + " is not canonical (leading slash, no empty or dot segments)")
	}
	rt := route{method: method, h: h, subtree: strings.HasSuffix(p, "/")}
	seen := map[string]bool{} // wildcardnamen binnen dit patroon
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		// Een rest-wildcard slokt alles op: segmenten erná zouden stil nooit
		// gematcht worden.
		if rt.rest != "" {
			panic("leanhttp: pattern " + pattern + " has segments after {" + rt.rest + "...}")
		}
		switch {
		case seg == "":
			continue // het wortelpatroon "/" heeft geen segmenten
		case seg == "{$}":
			panic("leanhttp: pattern " + pattern + " uses {$}, which this mux does not carry — " +
				"use a fixed path (no trailing slash) or a subtree (trailing slash)")
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "...}"):
			name := seg[1 : len(seg)-4]
			if name == "" || seen[name] {
				panic("leanhttp: pattern " + pattern + " has an empty or duplicate wildcard name")
			}
			seen[name] = true
			rt.rest = name
			rt.subtree = true // de rest mag leeg zijn en mag slashes hebben
		case len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}':
			name := seg[1 : len(seg)-1]
			if seen[name] {
				panic("leanhttp: pattern " + pattern + " has a duplicate wildcard name {" + name + "}")
			}
			seen[name] = true
			rt.lits = append(rt.lits, "")
			rt.names = append(rt.names, name)
		case strings.HasPrefix(seg, "{") || strings.HasSuffix(seg, "}"):
			// "{}", "{...}" of een half accolade-segment: stil als letterlijk
			// segment interpreteren is een valstrik, geen tolerantie.
			panic("leanhttp: pattern " + pattern + " has a malformed wildcard segment " + seg)
		default:
			// (Dot-segmenten zijn hierboven al door canonicalPath geweigerd.)
			if strings.ContainsRune(seg, '%') {
				// Verzoekpaden zijn bij het parsen al gedecodeerd; een escaped
				// literal zou dus nooit matchen. Patronen zijn broncode:
				// schrijf het teken zelf.
				panic("leanhttp: pattern " + pattern + " has a %-escape in a literal segment")
			}
			rt.lits = append(rt.lits, seg)
			rt.names = append(rt.names, "")
		}
	}

	// Conflictdetectie op dekking: twee patronen die eenzelfde verzoek kunnen
	// matchen zijn alleen verenigbaar als de één een STRIKTE subset van de
	// ander is — dan beslist specificiteit. Gelijk (dubbele registratie) of
	// kruisend (GET /a/{x} vs GET /{x}/b op /a/b) is een conflict: daar zou
	// registratievolgorde de winnaar kiezen, en dat is geen antwoord.
	for i := range m.routes {
		if rt.conflictsWith(&m.routes[i]) {
			panic("leanhttp: pattern " + pattern + " conflicts with " +
				strings.TrimSpace(m.routes[i].method+" "+m.routes[i].pattern()))
		}
	}
	m.routes = append(m.routes, rt) // geen sortering: ServeHTTP kiest de specifiekste
}

// conflictsWith: overlap zonder strikte subsetrelatie (of met gelijke
// dekking) is een conflict.
func (r *route) conflictsWith(o *route) bool {
	if !methodsOverlap(r.method, o.method) || !r.pathOverlaps(o) {
		return false
	}
	rSub := methodSubset(r.method, o.method) && r.pathSubset(o)
	oSub := methodSubset(o.method, r.method) && o.pathSubset(r)
	// Precies één subsetrichting = specificiteit beslist; gelijk of geen van
	// beide = conflict.
	return rSub == oSub
}

// De methodevelden zijn SETS, geen strings: "" dekt élke methode, en een
// GET-route bedient ook HEAD (de terugval in ServeHTTP) — dus
// HEAD ⊂ GET ⊂ "".

// methodsOverlap: snijden de twee methode-sets?
func methodsOverlap(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return (a == "GET" && b == "HEAD") || (a == "HEAD" && b == "GET")
}

// methodSubset: dekt b alles wat a dekt?
func methodSubset(a, b string) bool {
	return b == "" || a == b || (a == "HEAD" && b == "GET")
}

// Het slash-model, gedeeld door pathOverlaps, pathSubset en match: een vast
// patroon matcht exact zijn diepte zónder sluitende slash; een subtree matcht
// zijn wortel mét slash plus alles eronder. /admin en /admin/ zijn dus
// verschillende paden — en daarmee disjunct registreerbaar.

// pathOverlaps: bestaat er een pad dat beide patronen matcht?
func (r *route) pathOverlaps(o *route) bool {
	n := min(len(r.lits), len(o.lits))
	for i := 0; i < n; i++ {
		if r.lits[i] != "" && o.lits[i] != "" && r.lits[i] != o.lits[i] {
			return false // twee verschillende literals op dezelfde plek: disjunct
		}
	}
	switch {
	case r.subtree && o.subtree:
		return true
	case r.subtree:
		return len(o.lits) > len(r.lits) // o's vaste pad moet strikt ónder r's wortel liggen
	case o.subtree:
		return len(r.lits) > len(o.lits)
	default:
		return len(r.lits) == len(o.lits)
	}
}

// pathSubset: matcht o élk pad dat r matcht?
func (r *route) pathSubset(o *route) bool {
	for i, lit := range o.lits {
		if lit == "" {
			continue // wildcard bij o: dekt alles op deze plek
		}
		if i >= len(r.lits) || r.lits[i] != lit {
			return false // r staat hier iets anders (of alles) toe
		}
	}
	if o.subtree {
		if r.subtree {
			return len(r.lits) >= len(o.lits)
		}
		return len(r.lits) > len(o.lits) // vaste paden dragen geen slash: alleen strikt eronder
	}
	return !r.subtree && len(r.lits) == len(o.lits)
}

// moreSpecific: is r een strikte subset van o? Dit ís de precedentieregel.
func (r *route) moreSpecific(o *route) bool {
	rSub := methodSubset(r.method, o.method) && r.pathSubset(o)
	oSub := methodSubset(o.method, r.method) && o.pathSubset(r)
	return rSub && !oSub
}

// pattern bouwt de padvorm van een route terug, voor de conflict-foutmelding.
func (r route) pattern() string {
	var b strings.Builder
	for i, lit := range r.lits {
		b.WriteByte('/')
		if lit == "" {
			b.WriteString("{" + r.names[i] + "}")
			continue
		}
		b.WriteString(lit)
	}
	switch {
	case r.rest != "":
		b.WriteString("/{" + r.rest + "...}")
	case r.subtree:
		b.WriteByte('/')
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

// Handler geeft de mux als Handler, zodat hij in middleware past.
func (m *Mux) Handler() Handler { return m.ServeHTTP }

// ServeHTTP routeert één verzoek: van alle matchende routes wint de meest
// specifieke (strikte subset), ongeacht registratievolgorde. De matchende
// routes vormen dankzij de conflictwacht altijd een keten, dus paarsgewijs
// vergelijken volstaat.
func (m *Mux) ServeHTTP(w ResponseWriter, r *Request) {
	// GEEN normalisatie: de parser is de ene plek die het pad valideert
	// (readRequest weigert niet-canoniek met een 400), en dit is hetzelfde
	// predicaat als daar. Zonder deze wacht liet splitPath — dat slashes
	// trimt — een handgebouwde "api/devices" of "//api/devices" alsnog
	// matchen: normalisatie via de achterdeur (review 13-08, tweeëndertigste
	// ronde). Een middleware-rewrite hoort canoniek aan te leveren;
	// niet-canoniek bestaat hier gewoon niet: 404.
	if !canonicalPath(r.Path) {
		Error(w, "not found", StatusNotFound)
		return
	}
	segs := splitPath(r.Path)
	trailing := strings.HasSuffix(r.Path, "/")

	// HEAD valt terug op GET: de handler draait als bij GET en de server
	// slikt de body-bytes zelf in (suppressBody). De terugval doet als
	// kandidaat gewoon mee in de specificiteitsstrijd: een expliciete
	// HEAD-route is een striktere subset en wint vanzelf, een methode-loze
	// route verliest vanzelf (GET ⊂ "").
	var pick, fb *route
	var pickVals, fbVals map[string]string
	var allowed map[string]bool
	var allowList []string
	pathMatched := false
	for i := range m.routes {
		rt := &m.routes[i]
		vals, ok := rt.match(segs, trailing)
		if !ok {
			continue
		}
		if rt.method != "" && rt.method != r.Method {
			if rt.method == "GET" && r.Method == "HEAD" {
				if fb == nil || rt.moreSpecific(fb) {
					fb, fbVals = rt, vals
				}
				continue
			}
			pathMatched = true // het pad bestaat, deze methode niet
			if allowed == nil {
				allowed = map[string]bool{}
			}
			if !allowed[rt.method] {
				allowed[rt.method] = true
				allowList = append(allowList, rt.method)
			}
			if rt.method == "GET" && !allowed["HEAD"] {
				// Een GET-route bedient per contract ook HEAD: de Allow hoort
				// dat te zeggen (review 13-08, dertigste ronde).
				allowed["HEAD"] = true
				allowList = append(allowList, "HEAD")
			}
			continue
		}
		if pick == nil || rt.moreSpecific(pick) {
			pick, pickVals = rt, vals
		}
	}
	if fb != nil && (pick == nil || fb.moreSpecific(pick)) {
		pick, pickVals = fb, fbVals
	}
	if pick != nil {
		r.vals = pickVals
		pick.h(w, r)
		return
	}
	if pathMatched {
		// Het pad bestaat, deze methode niet. Een 404 zou de aanroeper naar
		// zijn URL laten kijken in plaats van naar zijn werkwoord — en de
		// Allow-header vertelt hem welke werkwoorden er wél zijn (RFC 9110
		// §15.5.6 eist hem bij een 405; review 13-08, achtentwintigste ronde).
		w.Header().Set("Allow", strings.Join(allowList, ", "))
		Error(w, "method not allowed", StatusMethodNotAllowed)
		return
	}
	Error(w, "not found", StatusNotFound)
}

// match toetst één route en geeft de wildcardwaarden terug.
func (r *route) match(segs []string, trailing bool) (map[string]string, bool) {
	if r.subtree {
		// Dieper mag altijd; de wortel bestaat alleen mét sluitende slash.
		if len(segs) < len(r.lits) || (len(segs) == len(r.lits) && !trailing) {
			return nil, false
		}
	} else if len(segs) != len(r.lits) || trailing {
		// Een vast patroon is exact dít pad, zonder slash.
		return nil, false
	}
	var vals map[string]string
	for i, lit := range r.lits {
		if lit == "" { // wildcard: één segment, inhoud vrij
			if vals == nil {
				vals = make(map[string]string, len(r.lits)+1)
			}
			vals[r.names[i]] = segs[i]
			continue
		}
		if segs[i] != lit {
			return nil, false
		}
	}
	if r.rest != "" {
		if vals == nil {
			vals = make(map[string]string, 1)
		}
		v := strings.Join(segs[len(r.lits):], "/")
		if trailing && v != "" {
			v += "/" // de sluitende slash is deel van de rest: /files/a/ vangt "a/"
		}
		vals[r.rest] = v
	}
	return vals, true
}

// cleanEscapes keurt een ESCAPED pad vóór het gedecodeerd wordt: een segment
// met een %-escape moet naar iets onschuldigs decoderen. Een %2F is ná
// decoderen niet meer van een padscheiding te onderscheiden, en een segment
// dat naar "." of ".." decodeert omzeilt cleanPath (die ziet de escaped vorm
// niet). Weigeren in plaats van afhandelen — daarmee bestaat de hele klasse
// "mux en middleware interpreteren het pad verschillend" niet meer
// (review 13-08, zevenentwintigste ronde).
func cleanEscapes(escaped string) bool {
	for _, seg := range strings.Split(escaped, "/") {
		if seg == "." || seg == ".." {
			// Ook de RUWE dot-segmenten worden geweigerd: cleanPath vouwde
			// /admin/. en /admin/x/.. tot /admin, waarmee de wortel van een
			// beveiligde /admin/-subtree bij de publieke exacte route
			// belandde — en middleware zag consistent dezelfde, verkeerde
			// grens. Weigeren spaart bovendien het hele
			// remove-dot-segments-algoritme uit (review 13-08,
			// negenentwintigste ronde).
			return false
		}
		if !strings.ContainsRune(seg, '%') {
			continue
		}
		dec, err := url.PathUnescape(seg)
		if err != nil || strings.ContainsRune(dec, '/') || dec == "." || dec == ".." {
			return false
		}
	}
	return true
}

// splitPath knipt een pad in segmenten. "/" en "" geven er geen, zodat het
// wortelpatroon ze beide matcht.
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// canonicalPath: één spelling per pad — begint met '/', geen lege segmenten
// (dus geen "//"), geen "."/".."-segmenten; alleen de staart mag leeg zijn (de
// sluitende slash, die betekenis draagt: subtree-wortel). Dit is het ENE
// predicaat dat parser (400) en Mux (404) delen; zijn voorganger cleanPath
// NORMALISEERDE in plaats van te toetsen, en elke normalisatie is een tweede
// interpretatiemoment van hetzelfde pad (review 13-08, tweeëndertigste ronde).
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	segs := strings.Split(p[1:], "/")
	for i, seg := range segs {
		if seg == "." || seg == ".." {
			return false
		}
		if seg == "" && i != len(segs)-1 {
			return false
		}
	}
	return true
}
