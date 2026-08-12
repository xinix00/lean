// Package leancookie is een cookie-jar (RFC 6265) op stdlib alleen: het slaat
// Set-Cookie op, kiest bij een verzoek de cookies die erbij horen, en houdt
// zich aan domein, pad, verval en Secure. Het weet niets van HTTP — je geeft
// het de headerregels en een URL, en het geeft je de Cookie-header terug.
//
// Het gemeten probleem: `net/http/cookiejar` sleept net/http mee, en net/http
// linkt onvoorwaardelijk crypto/tls. Wie op bare metal een jar wil, betaalt dus
// ~3,2 MB voor iets wat over een paar honderd regels gaat (gemeten 2026-08-12,
// tamago/riscv64: net/http + crypto/tls + CA-bundel = 3,68 MB boven een
// board-vloer van 2,09 MB). Dit pakket is die paar honderd regels.
//
// # Wat het niet doet, en waarom dat eerlijk is
//
// Er is GEEN public-suffix-lijst. Die is honderden KB's en verandert
// maandelijks — precies wat niet in een bare-metal image hoort. Zonder die
// lijst kan dit pakket niet weten dat "co.uk" een suffix is en "example.com"
// niet, en dus zou een server op "a.co.uk" een cookie voor heel ".co.uk"
// kunnen zetten die naar iedereen daarbinnen meegaat.
//
// En "a.co.uk mag co.uk niet zetten" is niet te onderscheiden van
// "sub.example.com mag example.com wel zetten": het is dezelfde vorm, één
// label eraf. Zonder de lijst is er geen regel die het ene toestaat en het
// andere weigert — dat is geen implementatiedetail, dat is de reden dat die
// lijst bestaat.
//
// Dus is de default: cookies gelden ALLEEN voor de host die ze zette. Een
// Domain-attribuut wordt geweigerd en geteld ([Jar.Rejected]). Wie
// subdomein-cookies nodig heeft, brengt zijn eigen kennis mee via
// [Jar.AllowDomain] — een lijstje eigen domeinen is drie regels, en wie een
// echte suffix-lijst toch al heeft, hangt die daar aan. Het pakket doet de
// helft die veilig te doen is, en laat de rest aan wie het kan weten.
//
// Verder niet: geen SameSite-handhaving (dat is browser-navigatiebeleid, niet
// jar-beleid), geen __Host-/__Secure-voorvoegsels, geen cookie-limiet per
// domein anders dan een totaalmaximum.
//
// # Gebruik
//
//	jar := leancookie.New(0)
//	// na een antwoord:
//	jar.SetFrom(u, resp.Header.Values("Set-Cookie"))
//	// bij het volgende verzoek:
//	if h := jar.Header(u); h != "" {
//	    call.Header = leanhttp.Header{"Cookie": h}
//	}
package leancookie

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultMax is het aantal cookies dat een jar bewaart. Een browsersessie op
// een node komt daar niet aan; een server die er duizenden stuurt hoort niet
// het geheugen van de node te bepalen.
const defaultMax = 256

// Jar bewaart cookies. Veilig voor gelijktijdig gebruik.
type Jar struct {
	mu   sync.Mutex
	max  int
	list []cookie

	// Rejected telt cookies die geweigerd zijn (kromme regel, geweigerd Domain,
	// verlopen bij aankomst, jar vol). Nul betekent niet "geen cookies" maar
	// "niets afgekeurd" — een teller die stil op nul blijft is de reden dat
	// niemand merkt dat zijn login niet werkt.
	Rejected int

	// AllowDomain beslist of een Domain-attribuut mag. nil = nee, en dan zijn
	// alle cookies host-only (de veilige default; zie de pakketdoc). De
	// aanroeper krijgt de host die de cookie stuurde en het gevraagde domein,
	// beide lowercase en zonder punt ervoor.
	//
	// Wie dit zet, neemt de suffix-vraag over. De simpelste veilige vorm is een
	// lijst van domeinen die je zelf bezit:
	//
	//	jar.AllowDomain = func(host, domain string) bool {
	//	    return domain == "example.com" || domain == "gethop.org"
	//	}
	AllowDomain func(host, domain string) bool
}

type cookie struct {
	name, value string
	host        string // de host waarvoor hij geldt (zonder punt)
	path        string
	expires     time.Time // nulwaarde = sessie-cookie
	subdomains  bool      // gezet via Domain: geldt ook voor subdomeinen
	secure      bool
}

// New maakt een jar; max 0 = 256 cookies.
func New(max int) *Jar {
	if max <= 0 {
		max = defaultMax
	}
	return &Jar{max: max}
}

// SetFrom neemt de Set-Cookie-regels van één antwoord op. Onbruikbare regels
// worden geteld, niet gemeld: één server die rommel stuurt hoort een verzoek
// niet te laten falen.
func (j *Jar) SetFrom(u *url.URL, lines []string) {
	if u == nil {
		return
	}
	now := time.Now()
	for _, line := range lines {
		c, ok := j.parse(line, u, now)
		if !ok {
			j.mu.Lock()
			j.Rejected++
			j.mu.Unlock()
			continue
		}
		j.store(c, now)
	}
}

// Header geeft de Cookie-header voor u, of "" als er niets bij hoort. De
// volgorde is langste pad eerst (RFC 6265 §5.4).
func (j *Jar) Header(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(hostOf(u))
	path := pathOf(u)
	https := u.Scheme == "https"
	now := time.Now()

	j.mu.Lock()
	defer j.mu.Unlock()
	var hits []cookie
	kept := j.list[:0]
	for _, c := range j.list {
		if !c.expires.IsZero() && !c.expires.After(now) {
			continue // verlopen: onderweg opruimen
		}
		kept = append(kept, c)
		switch {
		case c.secure && !https:
		case !hostMatch(host, c):
		case !pathMatch(path, c.path):
		default:
			hits = append(hits, c)
		}
	}
	j.list = kept
	if len(hits) == 0 {
		return ""
	}
	// Langste pad eerst; bij gelijk pad de invoegvolgorde (die is al zo).
	for i := 1; i < len(hits); i++ {
		for k := i; k > 0 && len(hits[k].path) > len(hits[k-1].path); k-- {
			hits[k], hits[k-1] = hits[k-1], hits[k]
		}
	}
	var b strings.Builder
	for i, c := range hits {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.name)
		b.WriteByte('=')
		b.WriteString(c.value)
	}
	return b.String()
}

// Len geeft het aantal bewaarde cookies (diagnose).
func (j *Jar) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.list)
}

// store voegt toe of vervangt. Vervangen gaat op (naam, host, pad) — dat is de
// identiteit die de RFC gebruikt, en het is waarom een tweede login-cookie de
// eerste niet naast zich laat staan.
func (j *Jar) store(c cookie, now time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.list {
		if j.list[i].name == c.name && j.list[i].host == c.host && j.list[i].path == c.path {
			if c.value == "" && !c.expires.IsZero() && !c.expires.After(now) {
				j.list = append(j.list[:i], j.list[i+1:]...) // verlopen = verwijderen
				return
			}
			j.list[i] = c
			return
		}
	}
	// Een cookie die al verlopen aankomt is een verwijdering van iets dat we
	// niet hebben: niets te doen.
	if !c.expires.IsZero() && !c.expires.After(now) {
		j.Rejected++
		return
	}
	if len(j.list) >= j.max {
		j.Rejected++
		return
	}
	j.list = append(j.list, c)
}

// parse ontleedt één Set-Cookie-regel tegen de URL waar hij van kwam.
func (j *Jar) parse(line string, u *url.URL, now time.Time) (cookie, bool) {
	first, rest, _ := strings.Cut(line, ";")
	name, value, found := strings.Cut(first, "=")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !found || name == "" || strings.ContainsAny(name, " \t\r\n;") {
		return cookie{}, false
	}
	// Aanhalingstekens rond de waarde horen bij de waarde niet.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	if strings.ContainsAny(value, "\r\n;") {
		return cookie{}, false
	}

	host := strings.ToLower(hostOf(u))
	c := cookie{name: name, value: value, host: host, path: defaultPath(u)}
	var maxAge *int

	for rest != "" {
		var attr string
		attr, rest, _ = strings.Cut(rest, ";")
		k, v, _ := strings.Cut(attr, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "path":
			if strings.HasPrefix(v, "/") {
				c.path = v
			}
		case "domain":
			d := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "."))
			if !j.domainOK(host, d) {
				return cookie{}, false // host-only tenzij AllowDomain zegt van wel
			}
			c.host, c.subdomains = d, true
		case "expires":
			if t, ok := parseTime(v); ok && maxAge == nil {
				c.expires = t
			}
		case "max-age":
			// Max-Age wint van Expires (RFC 6265 §5.3 stap 3).
			if n, err := strconv.Atoi(v); err == nil {
				maxAge = &n
				if n <= 0 {
					c.expires = now.Add(-time.Second)
				} else {
					c.expires = now.Add(time.Duration(n) * time.Second)
				}
			}
		case "secure":
			c.secure = true
		}
	}
	return c, true
}

// domainOK beslist over een Domain-attribuut. Twee dingen gelden altijd, ook
// met een AllowDomain-hook: het domein moet een suffix van de host zijn op een
// labelgrens (anders zet een server cookies voor iemand anders), en de host
// zelf mag altijd. De rest is de vraag die alleen de aanroeper kan beantwoorden.
func (j *Jar) domainOK(host, domain string) bool {
	switch {
	case domain == "":
		return false
	case domain == host:
		return true // Domain=eigen host is host-only, dus altijd goed
	case !strings.HasSuffix(host, "."+domain):
		return false // geen suffix op een labelgrens: nooit
	case j.AllowDomain == nil:
		return false // de veilige default (zie de pakketdoc)
	default:
		return j.AllowDomain(host, domain)
	}
}

func hostMatch(host string, c cookie) bool {
	if host == c.host {
		return true
	}
	return c.subdomains && strings.HasSuffix(host, "."+c.host)
}

// pathMatch is RFC 6265 §5.1.4: gelijk, of een prefix die op / eindigt (of
// waar het volgende teken een / is).
func pathMatch(path, cookiePath string) bool {
	switch {
	case path == cookiePath:
		return true
	case !strings.HasPrefix(path, cookiePath):
		return false
	case strings.HasSuffix(cookiePath, "/"):
		return true
	default:
		return len(path) > len(cookiePath) && path[len(cookiePath)] == '/'
	}
}

func hostOf(u *url.URL) string { return u.Hostname() }

func pathOf(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

// defaultPath is de directory van het verzoek-pad (RFC 6265 §5.1.4).
func defaultPath(u *url.URL) string {
	p := u.Path
	if !strings.HasPrefix(p, "/") {
		return "/"
	}
	i := strings.LastIndexByte(p, '/')
	if i == 0 {
		return "/"
	}
	return p[:i]
}

// parseTime leest de drie datumvormen die servers echt sturen (RFC 1123, de
// oude RFC 850-vorm en de asctime-vorm van RFC 2616 §3.3.1).
func parseTime(v string) (time.Time, bool) {
	for _, layout := range []string{
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Mon, 02-Jan-2006 15:04:05 MST",
		"Monday, 02-Jan-06 15:04:05 MST",
		"Mon Jan _2 15:04:05 2006",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
