package leanhttp

// mux.go — routeren op methode, pad en patroon.
//
// De serverkant had dit niet: een handler was één functie en wie meerdere wegen
// wilde, schreef een switch op r.Path. Dat werkt tot het niet meer werkt, en het
// punt waarop dat gebeurt is voorspelbaar: zodra twee patronen hetzelfde pad
// kunnen matchen moet er iets beslissen wie voorgaat, en een switch beslist dat
// op leesvolgorde. GEMETEN als storing in HopOS: een log-staart die door de
// generieke proxy werd beantwoord in plaats van door de streamende, waardoor
// élke SSE-stroom stil bufferde tot het einde dat nooit kwam.
//
// De patroonvorm is die van net/http's ServeMux sinds Go 1.22, want dat is wat
// bestaande handlers al schrijven:
//
//	"/health"                      exact dit pad
//	"GET /v1/agents"               exact, en alleen deze methode
//	"/logs/"                       dit pad en alles eronder (subtree)
//	"/v1/agents/{id}/logs/"        {id} is één segment, leesbaar via PathValue
//	"GET /app-ui/{app}/{path...}"  {path...} is de hele rest, ook met slashes
//	"GET /app-ui/{app}/{$}"        {$} eist dat het pad hier ÉINDIGT
//
// Wat er niet is: reguliere expressies, hosts in het patroon, en de
// pad-opschoning met een 301 die net/http erbij doet. Dat laatste is een keuze:
// een redirect op een pad met ".." erin verplaatst het probleem naar de client.
// Deze mux normaliseert (zie cleanPath) en matcht daarna, zodat een handler
// nooit een ".." te zien krijgt.

import (
	"path"
	"sort"
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
	subtree bool     // patroon eindigde op "/": ook alles eronder
	exact   bool     // patroon eindigde op "{$}": het pad moet hier ophouden
	h       Handler
	score   int
}

// NewServeMux geeft een lege Mux.
func NewServeMux() *Mux { return &Mux{} }

// HandleFunc registreert h voor pattern. Een patroon zonder leidende "/" of een
// dubbele registratie is een bedradingsfout die vanaf de eerste run bestaat, dus
// die paniekt — een route die stil nooit vuurt is de slechtste manier om daar
// achter te komen.
func (m *Mux) HandleFunc(pattern string, h Handler) {
	method, p := "", pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		method, p = pattern[:i], strings.TrimSpace(pattern[i+1:])
	}
	if !strings.HasPrefix(p, "/") {
		panic("leanhttp: pattern " + pattern + " must start with /")
	}
	for _, r := range m.routes {
		if r.method == method && r.pattern() == p {
			panic("leanhttp: duplicate pattern " + pattern)
		}
	}

	rt := route{method: method, h: h, subtree: strings.HasSuffix(p, "/")}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		switch {
		case seg == "":
			continue // het wortelpatroon "/" heeft geen segmenten
		case seg == "{$}":
			// Anker: geen segment om te matchen, maar het pad mag hier niet
			// verder. In een subtree-patroon is dat het verschil tussen "deze
			// map" en "alles eronder".
			rt.exact, rt.subtree = true, false
			rt.score += 2
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "...}"):
			rt.rest = seg[1 : len(seg)-4]
			rt.subtree = true // de rest mag leeg zijn en mag slashes hebben
		case len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}':
			rt.lits = append(rt.lits, "")
			rt.names = append(rt.names, seg[1:len(seg)-1])
			rt.score += 1 // een wildcard matcht, maar het zwakst
		default:
			rt.lits = append(rt.lits, seg)
			rt.names = append(rt.names, "")
			rt.score += 4 // een letterlijk segment gaat vóór een wildcard
		}
	}
	if !rt.subtree {
		rt.score += 2 // een exact patroon gaat vóór een subtree die net zo diep reikt
	}
	if rt.rest != "" {
		rt.score -= 1 // een rest-wildcard is de ruimste vorm die er is
	}
	if method != "" {
		rt.score++ // wie zijn methode noemt, gaat vóór wie elke methode neemt
	}

	m.routes = append(m.routes, rt)
	// Meest specifieke eerst, zodat de eerste match de juiste is. Bij het
	// registreren gesorteerd (dat gebeurt één keer) in plaats van per verzoek.
	sort.SliceStable(m.routes, func(i, j int) bool { return m.routes[i].score > m.routes[j].score })
}

// pattern bouwt de padvorm van een route terug, voor de dubbel-controle en voor
// foutmeldingen.
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
	case r.exact:
		b.WriteString("/{$}")
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

// ServeHTTP routeert één verzoek. De naam is die van net/http's ServeMux, zodat
// code die tussen de twee moet kunnen wisselen dezelfde regel houdt.
func (m *Mux) ServeHTTP(w ResponseWriter, r *Request) {
	segs := splitPath(cleanPath(r.Path))
	pathMatched := false
	for i := range m.routes {
		rt := &m.routes[i]
		vals, ok := rt.match(segs)
		if !ok {
			continue
		}
		if rt.method != "" && rt.method != r.Method {
			pathMatched = true // het pad bestaat, deze methode niet
			continue
		}
		r.vals = vals
		rt.h(w, r)
		return
	}
	if pathMatched {
		// Het pad bestaat, deze methode niet. Een 404 zou de aanroeper naar zijn
		// URL laten kijken in plaats van naar zijn werkwoord.
		Error(w, "method not allowed", StatusMethodNotAllowed)
		return
	}
	Error(w, "not found", StatusNotFound)
}

// match toetst één route en geeft de wildcardwaarden terug.
func (r *route) match(segs []string) (map[string]string, bool) {
	switch {
	case r.subtree && len(segs) < len(r.lits):
		return nil, false
	case !r.subtree && len(segs) != len(r.lits):
		return nil, false
	}
	var vals map[string]string
	for i, lit := range r.lits {
		if lit == "" { // wildcard: één niet-leeg segment, inhoud vrij
			if segs[i] == "" {
				return nil, false
			}
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
		vals[r.rest] = strings.Join(segs[len(r.lits):], "/")
	}
	return vals, true
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

// cleanPath normaliseert zoals net/http's ServeMux dat doet: een leidende slash,
// geen "." of ".."-stappen, geen dubbele slashes. Zonder dit zou "/app-ui/x/../.."
// bij een subtree-handler komen die het nooit had mogen zien — en met een
// redirect (wat net/http doet) verplaats je die vraag naar de client.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	// path.Clean haalt een sluitende slash weg, en die slash betekent hier iets:
	// hij bepaalt of een pad een subtree-patroon matcht.
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	return cleaned
}
