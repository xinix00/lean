// Package leancookie is a standard-library-only RFC 6265 cookie jar. It stores
// Set-Cookie fields and selects Cookie values by domain, path, expiry, and
// Secure without depending on HTTP.
//
// net/http/cookiejar pulls net/http and crypto/tls into a bare-metal image. On
// tamago/riscv64 (2026-08-12), net/http + crypto/tls + a CA bundle added about
// 3.2 MB above a 2.09 MB board baseline.
//
// # Deliberate limits
//
// The package has no public suffix list: it costs hundreds of KiB and changes
// monthly. Without one, distinguishing unsafe `a.co.uk` → `co.uk` scope from
// valid `sub.example.com` → `example.com` scope is impossible. Cookies are
// therefore host-only by default. Domain attributes are rejected and counted
// in [Jar.Rejected] unless caller knowledge in [Jar.AllowDomain] permits them.
//
// SameSite enforcement belongs to browser navigation policy and is omitted, as
// are __Host-/__Secure- prefix handling and per-domain limits beyond the total
// jar limit.
//
// # Usage
//
//	jar := leancookie.New(0)
//	// After a response:
//	jar.SetFrom(u, resp.Header.Values("Set-Cookie"))
//	// On the next request:
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

// defaultMax bounds server-controlled memory while exceeding ordinary node
// browser sessions.
const defaultMax = 256

// Jar stores cookies and is safe for concurrent use.
type Jar struct {
	mu   sync.Mutex
	max  int
	list []cookie

	// Rejected counts malformed, disallowed-domain, already expired, and
	// over-capacity cookies. It makes otherwise silent login failures visible.
	Rejected int

	// AllowDomain decides whether to accept a Domain attribute. Nil keeps every
	// cookie host-only. host and domain are lowercase without a leading dot.
	//
	// Setting this transfers public-suffix responsibility to the caller. A safe
	// simple policy lists domains the caller owns:
	//
	//	jar.AllowDomain = func(host, domain string) bool {
	//	    return domain == "example.com" || domain == "gethop.org"
	//	}
	AllowDomain func(host, domain string) bool
}

type cookie struct {
	name, value string
	host        string // applicable host, without a leading dot
	path        string
	expires     time.Time // zero means a session cookie
	subdomains  bool      // Domain permits subdomains
	secure      bool
}

// New creates a jar. A non-positive max uses the 256-cookie default.
func New(max int) *Jar {
	if max <= 0 {
		max = defaultMax
	}
	return &Jar{max: max}
}

// SetFrom consumes Set-Cookie fields from one response. Unusable fields are
// counted rather than returned because one malformed cookie should not fail a
// request.
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

// Header returns the Cookie field for u, or "" when none apply. RFC 6265 §5.4
// requires longest paths first.
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
			continue // Remove expired entries while scanning.
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
	// Longest path first; preserve insertion order for equal paths.
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

// Len returns the number of stored cookies.
func (j *Jar) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.list)
}

// store adds or replaces by the RFC identity (name, host, path).
func (j *Jar) store(c cookie, now time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.list {
		if j.list[i].name == c.name && j.list[i].host == c.host && j.list[i].path == c.path {
			if c.value == "" && !c.expires.IsZero() && !c.expires.After(now) {
				j.list = append(j.list[:i], j.list[i+1:]...) // Expiry deletes.
				return
			}
			j.list[i] = c
			return
		}
	}
	// An already expired unknown cookie is a deletion with nothing to remove.
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

// parse interprets one Set-Cookie field against its source URL.
func (j *Jar) parse(line string, u *url.URL, now time.Time) (cookie, bool) {
	first, rest, _ := strings.Cut(line, ";")
	name, value, found := strings.Cut(first, "=")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !found || name == "" || strings.ContainsAny(name, " \t\r\n;") {
		return cookie{}, false
	}
	// Surrounding quotes delimit rather than form part of the value.
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
				return cookie{}, false // Host-only unless AllowDomain permits it.
			}
			c.host, c.subdomains = d, true
		case "expires":
			if t, ok := parseTime(v); ok && maxAge == nil {
				c.expires = t
			}
		case "max-age":
			// Max-Age overrides Expires (RFC 6265 §5.3 step 3).
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

// domainOK accepts the source host itself and otherwise requires a label-boundary
// suffix plus caller approval. This prevents a server setting another host's
// cookies even when AllowDomain is configured.
func (j *Jar) domainOK(host, domain string) bool {
	switch {
	case domain == "":
		return false
	case domain == host:
		return true // Domain=source host remains safe.
	case !strings.HasSuffix(host, "."+domain):
		return false // Never cross a label boundary.
	case j.AllowDomain == nil:
		return false // Safe default; see the package documentation.
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

// pathMatch implements RFC 6265 §5.1.4: equality, or a prefix ending at `/`.
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

// defaultPath returns the request path's directory (RFC 6265 §5.1.4).
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

// parseTime accepts the server date forms in RFC 1123 and RFC 2616 §3.3.1.
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
