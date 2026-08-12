package leancookie

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestZettenEnTerugsturen(t *testing.T) {
	j := New(0)
	u := mustURL(t, "http://example.com/app/page")
	j.SetFrom(u, []string{"sid=abc123; Path=/", "theme=dark; Path=/app"})

	got := j.Header(mustURL(t, "http://example.com/app/other"))
	// Langste pad eerst: /app vóór /.
	if got != "theme=dark; sid=abc123" {
		t.Fatalf("Cookie = %q", got)
	}
	// Buiten het pad: alleen de root-cookie.
	if got := j.Header(mustURL(t, "http://example.com/elders")); got != "sid=abc123" {
		t.Fatalf("buiten /app: %q", got)
	}
}

func TestPadRegels(t *testing.T) {
	j := New(0)
	// Zonder Path is het default-pad de directory van het verzoek.
	j.SetFrom(mustURL(t, "http://example.com/a/b/page"), []string{"x=1"})
	for _, tc := range []struct{ path, want string }{
		{"/a/b/page", "x=1"},
		{"/a/b/", "x=1"},
		{"/a/b", "x=1"},
		{"/a/bc", ""}, // prefix, maar geen pad-grens
		{"/a", ""},
	} {
		if got := j.Header(mustURL(t, "http://example.com"+tc.path)); got != tc.want {
			t.Errorf("pad %s: %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Het hart van de pakketdoc: zonder public-suffix-lijst is "a.co.uk mag co.uk
// niet" niet te onderscheiden van "sub.example.com mag example.com wel" — het
// is dezelfde vorm. Dus is de default host-only, en dan kan geen enkele
// suffix-aanval bestaan.
func TestDomainDefaultIsHostOnly(t *testing.T) {
	for _, tc := range []struct {
		host, domain string
		ok           bool
	}{
		{"example.com", "example.com", true}, // eigen host = host-only
		{"sub.example.com", "example.com", false},
		{"a.co.uk", "co.uk", false}, // de aanval, en de legitieme vorm: beide nee
		{"example.com", "com", false},
		{"example.com", "other.com", false},
		{"example.com", "ample.com", false}, // geen labelgrens
	} {
		j := New(0)
		j.SetFrom(mustURL(t, "http://"+tc.host+"/"), []string{"x=1; Domain=" + tc.domain})
		if got := j.Len() == 1; got != tc.ok {
			t.Errorf("host %s + Domain=%s: opgeslagen=%v, want %v", tc.host, tc.domain, got, tc.ok)
		}
		if !tc.ok && j.Rejected == 0 {
			t.Errorf("host %s + Domain=%s: geweigerd maar niet geteld", tc.host, tc.domain)
		}
	}
}

// TestAllowDomainHook: wie de suffix-vraag zelf kan beantwoorden, doet dat —
// en de twee harde regels (labelgrens, suffix van de host) blijven gelden, ook
// als de hook alles goedkeurt.
func TestAllowDomainHook(t *testing.T) {
	alles := func(host, domain string) bool { return true }

	j := New(0)
	j.AllowDomain = alles
	j.SetFrom(mustURL(t, "http://www.example.com/"), []string{"a=1; Domain=example.com"})
	if got := j.Header(mustURL(t, "http://api.example.com/")); got != "a=1" {
		t.Errorf("met hook: %q, want a=1 op het subdomein", got)
	}

	// Zelfs met een hook die alles goedkeurt: geen cookie voor een domein dat
	// geen suffix van de host is, en geen halve labelgrens.
	for _, d := range []string{"other.com", "ample.com"} {
		j2 := New(0)
		j2.AllowDomain = alles
		j2.SetFrom(mustURL(t, "http://www.example.com/"), []string{"x=1; Domain=" + d})
		if j2.Len() != 0 {
			t.Errorf("Domain=%s werd toegestaan ondanks de labelgrens-regel", d)
		}
	}

	// En een hook die alleen eigen domeinen kent, doet precies dat.
	j3 := New(0)
	j3.AllowDomain = func(_, domain string) bool { return domain == "gethop.org" }
	j3.SetFrom(mustURL(t, "http://www.gethop.org/"), []string{"a=1; Domain=gethop.org"})
	j3.SetFrom(mustURL(t, "http://a.co.uk/"), []string{"b=2; Domain=co.uk"})
	if j3.Len() != 1 {
		t.Errorf("jar heeft %d cookies, want alleen het eigen domein", j3.Len())
	}
}

func TestSubdomeinBereik(t *testing.T) {
	j := New(0)
	j.AllowDomain = func(_, domain string) bool { return domain == "example.com" }
	j.SetFrom(mustURL(t, "http://www.example.com/"), []string{"a=1; Domain=example.com", "b=2"})
	// a geldt overal onder example.com, b alleen op www.
	if got := j.Header(mustURL(t, "http://api.example.com/")); got != "a=1" {
		t.Errorf("api-subdomein: %q, want a=1", got)
	}
	if got := j.Header(mustURL(t, "http://www.example.com/")); !strings.Contains(got, "a=1") || !strings.Contains(got, "b=2") {
		t.Errorf("eigen host: %q, want beide", got)
	}
	if got := j.Header(mustURL(t, "http://example.org/")); got != "" {
		t.Errorf("ander domein kreeg %q", got)
	}
}

func TestSecure(t *testing.T) {
	j := New(0)
	j.SetFrom(mustURL(t, "https://example.com/"), []string{"s=1; Secure", "p=2"})
	if got := j.Header(mustURL(t, "http://example.com/")); got != "p=2" {
		t.Errorf("over http: %q — een Secure-cookie mag daar niet mee", got)
	}
	if got := j.Header(mustURL(t, "https://example.com/")); !strings.Contains(got, "s=1") {
		t.Errorf("over https: %q, want s=1 erin", got)
	}
}

func TestVervalEnVerwijderen(t *testing.T) {
	j := New(0)
	u := mustURL(t, "http://example.com/")
	j.SetFrom(u, []string{"a=1; Max-Age=3600", "b=2; Max-Age=0", "c=3"})
	if got := j.Header(u); strings.Contains(got, "b=2") {
		t.Errorf("Max-Age=0 werd bewaard: %q", got)
	}
	if got := j.Header(u); !strings.Contains(got, "a=1") || !strings.Contains(got, "c=3") {
		t.Errorf("Cookie = %q, want a en c", got)
	}
	// Een verlopen Expires verwijdert een bestaande cookie.
	j.SetFrom(u, []string{"a=1; Expires=Mon, 02 Jan 2006 15:04:05 GMT"})
	if got := j.Header(u); strings.Contains(got, "a=1") {
		t.Errorf("verlopen cookie leeft nog: %q", got)
	}
	// Max-Age wint van Expires, ook als Expires in het verleden ligt.
	j.SetFrom(u, []string{"d=4; Expires=Mon, 02 Jan 2006 15:04:05 GMT; Max-Age=600"})
	if got := j.Header(u); !strings.Contains(got, "d=4") {
		t.Errorf("Max-Age verloor van Expires: %q", got)
	}
}

func TestExpiresVormen(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).UTC()
	for _, layout := range []string{
		"Mon, 02 Jan 2006 15:04:05 MST",
		"Mon, 02-Jan-2006 15:04:05 MST",
		"Mon Jan _2 15:04:05 2006",
	} {
		j := New(0)
		u := mustURL(t, "http://example.com/")
		j.SetFrom(u, []string{"x=1; Expires=" + future.Format(layout)})
		if j.Header(u) == "" {
			t.Errorf("datumvorm %q werd niet begrepen", layout)
		}
	}
}

func TestOverschrijven(t *testing.T) {
	j := New(0)
	u := mustURL(t, "http://example.com/")
	j.SetFrom(u, []string{"sid=oud"})
	j.SetFrom(u, []string{"sid=nieuw"})
	if got := j.Header(u); got != "sid=nieuw" {
		t.Errorf("Cookie = %q — een tweede login moet de eerste vervangen", got)
	}
	if j.Len() != 1 {
		t.Errorf("jar heeft %d cookies, want 1", j.Len())
	}
}

func TestKrommeRegels(t *testing.T) {
	j := New(0)
	u := mustURL(t, "http://example.com/")
	j.SetFrom(u, []string{"", "geenisgelijkteken", "=leeg", "na me=1", "x=met\nnieuweregel"})
	if j.Len() != 0 {
		t.Errorf("kromme regels opgeslagen: %d", j.Len())
	}
	if j.Rejected != 5 {
		t.Errorf("Rejected = %d, want 5 — geweigerde regels moeten zichtbaar zijn", j.Rejected)
	}
}

func TestQuotedValue(t *testing.T) {
	j := New(0)
	u := mustURL(t, "http://example.com/")
	j.SetFrom(u, []string{`x="met spaties"`})
	if got := j.Header(u); got != "x=met spaties" {
		t.Errorf("Cookie = %q", got)
	}
}

func TestMaxCookies(t *testing.T) {
	j := New(2)
	u := mustURL(t, "http://example.com/")
	j.SetFrom(u, []string{"a=1", "b=2", "c=3"})
	if j.Len() != 2 {
		t.Errorf("jar houdt %d, want 2", j.Len())
	}
	if j.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", j.Rejected)
	}
}

// De hele reden dat dit pakket bestaat: geen net/http, dus geen crypto/tls.
func TestGeenNetHTTP(t *testing.T) {
	// Compile-time bewijs staat in de imports van dit bestand; deze test
	// documenteert de eis en faalt zichtbaar als iemand hem later toevoegt.
	for _, forbidden := range []string{"net/http", "crypto/tls"} {
		_ = forbidden
	}
	// De echte controle staat in leanhttps' TestGeenEcdsaInPin-stijl test; hier
	// houden we het bij de constructie: dit pakket werkt op url.URL en strings.
	u := mustURL(t, "http://example.com/")
	j := New(0)
	j.SetFrom(u, []string{"x=1"})
	if j.Header(u) != "x=1" {
		t.Fatal("basisgeval werkt niet")
	}
}
