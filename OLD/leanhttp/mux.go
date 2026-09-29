package leanhttp

// mux.go routes by method and path. It deliberately implements only the forms
// used by this project's route tables, not net/http's full ServeMux contract:
//
//	"/health"                       exact path, without a trailing slash
//	"GET /v1/agents"                exact path and method; GET also serves HEAD
//	"/logs/"                        slash-terminated root and its subtree
//	"/v1/agents/{id}/logs/"         {id} captures one PathValue segment
//	"GET /app-ui/{app}/{path...}"   {path...} captures the remaining path
//
// Deliberate omissions:
//
//   - No {$}; fixed paths and trailing-slash subtrees cover the actual tables.
//   - No escaped routing; parsing rejects escapes that decode to "/", ".", or
//     "..", so middleware and Mux see the same decoded canonical path.
//   - No scores or sorting; the strict-subset relation selects the most
//     specific match independently of registration order.
//
// HandleFunc panics for conflicts and malformed patterns so dead routes fail at
// startup rather than silently at dispatch.
//
// Mux is immutable after serving starts. Register every route before Serve;
// concurrent HandleFunc calls are a data race.

import (
	"net/url"
	"strings"
)

// Mux routes requests to handlers. Create one with NewServeMux.
type Mux struct {
	routes []route
}

// route is a pre-parsed registered pattern.
type route struct {
	method  string   // "" matches every method
	lits    []string // literal per segment, or "" for a wildcard
	names   []string // wildcard name per segment, or "" for a literal
	rest    string   // {rest...} wildcard name, or ""
	subtree bool     // pattern ended in "/": its slash root and descendants
	h       Handler
}

// NewServeMux returns an empty Mux.
func NewServeMux() *Mux { return &Mux{} }

// HandleFunc registers h for pattern; the package comment lists the forms.
func (m *Mux) HandleFunc(pattern string, h Handler) {
	method, p := "", pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		method, p = pattern[:i], strings.TrimSpace(pattern[i+1:])
	}
	// Invalid methods, nil handlers, and impossible patterns are startup wiring
	// errors and must fail before dispatch.
	if h == nil {
		panic("leanhttp: pattern " + pattern + " registered with a nil handler")
	}
	if method != "" && !validToken(method) {
		panic("leanhttp: pattern " + pattern + " has a malformed method token")
	}
	if !canonicalPath(p) {
		// Use dispatch's predicate. Otherwise Trim/Split would silently fold paths
		// such as "/a//b" into a route with different coverage.
		panic("leanhttp: pattern " + pattern + " is not canonical (leading slash, no empty or dot segments)")
	}
	rt := route{method: method, h: h, subtree: strings.HasSuffix(p, "/")}
	seen := map[string]bool{} // wildcard names within this pattern
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		// A rest wildcard consumes everything, so later segments cannot match.
		if rt.rest != "" {
			panic("leanhttp: pattern " + pattern + " has segments after {" + rt.rest + "...}")
		}
		switch {
		case seg == "":
			continue // the root pattern "/" has no segments
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
			rt.subtree = true // rest may be empty and contain slashes
		case len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}':
			name := seg[1 : len(seg)-1]
			if seen[name] {
				panic("leanhttp: pattern " + pattern + " has a duplicate wildcard name {" + name + "}")
			}
			seen[name] = true
			rt.lits = append(rt.lits, "")
			rt.names = append(rt.names, name)
		case strings.HasPrefix(seg, "{") || strings.HasSuffix(seg, "}"):
			// Treating malformed wildcard syntax as a literal hides wiring errors.
			panic("leanhttp: pattern " + pattern + " has a malformed wildcard segment " + seg)
		default:
			// canonicalPath already rejected dot segments.
			if strings.ContainsRune(seg, '%') {
				// Request paths are decoded while parsing, so escaped literals could
				// never match. Patterns are source code; write the character itself.
				panic("leanhttp: pattern " + pattern + " has a %-escape in a literal segment")
			}
			rt.lits = append(rt.lits, seg)
			rt.names = append(rt.names, "")
		}
	}

	// Overlapping patterns are compatible only when one is a strict subset of
	// the other. Equal or crossing coverage would make registration order decide.
	for i := range m.routes {
		if rt.conflictsWith(&m.routes[i]) {
			panic("leanhttp: pattern " + pattern + " conflicts with " +
				strings.TrimSpace(m.routes[i].method+" "+m.routes[i].pattern()))
		}
	}
	m.routes = append(m.routes, rt) // ServeHTTP selects the most specific route
}

// conflictsWith reports overlap without exactly one strict subset relation.
func (r *route) conflictsWith(o *route) bool {
	if !methodsOverlap(r.method, o.method) || !r.pathOverlaps(o) {
		return false
	}
	rSub := methodSubset(r.method, o.method) && r.pathSubset(o)
	oSub := methodSubset(o.method, r.method) && o.pathSubset(r)
	// Exactly one subset direction lets specificity decide.
	return rSub == oSub
}

// Method fields represent sets: "" covers all methods and GET also serves
// HEAD, so HEAD ⊂ GET ⊂ "".

// methodsOverlap reports whether two method sets intersect.
func methodsOverlap(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return (a == "GET" && b == "HEAD") || (a == "HEAD" && b == "GET")
}

// methodSubset reports whether b covers every method covered by a.
func methodSubset(a, b string) bool {
	return b == "" || a == b || (a == "HEAD" && b == "GET")
}

// Fixed patterns match exactly without a trailing slash. Subtrees match their
// slash-terminated root and descendants, so /admin and /admin/ are disjoint.

// pathOverlaps reports whether any path matches both patterns.
func (r *route) pathOverlaps(o *route) bool {
	n := min(len(r.lits), len(o.lits))
	for i := 0; i < n; i++ {
		if r.lits[i] != "" && o.lits[i] != "" && r.lits[i] != o.lits[i] {
			return false // different literals at one position are disjoint
		}
	}
	switch {
	case r.subtree && o.subtree:
		return true
	case r.subtree:
		return len(o.lits) > len(r.lits) // o's fixed path must be below r's root
	case o.subtree:
		return len(r.lits) > len(o.lits)
	default:
		return len(r.lits) == len(o.lits)
	}
}

// pathSubset reports whether o matches every path matched by r.
func (r *route) pathSubset(o *route) bool {
	for i, lit := range o.lits {
		if lit == "" {
			continue // o's wildcard covers everything here
		}
		if i >= len(r.lits) || r.lits[i] != lit {
			return false // r permits something else, or everything
		}
	}
	if o.subtree {
		if r.subtree {
			return len(r.lits) >= len(o.lits)
		}
		return len(r.lits) > len(o.lits) // fixed paths lack a slash: strictly below only
	}
	return !r.subtree && len(r.lits) == len(o.lits)
}

// moreSpecific reports whether r is a strict subset of o.
func (r *route) moreSpecific(o *route) bool {
	rSub := methodSubset(r.method, o.method) && r.pathSubset(o)
	oSub := methodSubset(o.method, r.method) && o.pathSubset(r)
	return rSub && !oSub
}

// pattern reconstructs a route path for conflict errors.
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

// Handler exposes the mux as a Handler for middleware composition.
func (m *Mux) Handler() Handler { return m.ServeHTTP }

// ServeHTTP dispatches to the most specific matching route, independent of
// registration order. Conflict detection guarantees the matches form a chain.
func (m *Mux) ServeHTTP(w ResponseWriter, r *Request) {
	// Do not normalize here. The parser is the one validation point, and this
	// same predicate prevents hand-built or middleware-rewritten non-canonical
	// paths from matching through splitPath's trimming behavior.
	if !canonicalPath(r.Path) {
		Error(w, "not found", StatusNotFound)
		return
	}
	segs := splitPath(r.Path)
	trailing := strings.HasSuffix(r.Path, "/")

	// HEAD falls back to GET while the server suppresses body bytes. Normal
	// specificity still makes an explicit HEAD route win and a methodless route
	// lose to GET.
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
			pathMatched = true // the path exists, but not for this method
			if allowed == nil {
				allowed = map[string]bool{}
			}
			if !allowed[rt.method] {
				allowed[rt.method] = true
				allowList = append(allowList, rt.method)
			}
			if rt.method == "GET" && !allowed["HEAD"] {
				// GET serves HEAD by contract, so Allow must advertise it.
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
		// A known path with the wrong method is 405, with the required Allow
		// header identifying valid methods (RFC 9110 §15.5.6).
		w.Header().Set("Allow", strings.Join(allowList, ", "))
		Error(w, "method not allowed", StatusMethodNotAllowed)
		return
	}
	Error(w, "not found", StatusNotFound)
}

// match checks one route and returns its wildcard values.
func (r *route) match(segs []string, trailing bool) (map[string]string, bool) {
	if r.subtree {
		// Descendants always match; the root itself requires a trailing slash.
		if len(segs) < len(r.lits) || (len(segs) == len(r.lits) && !trailing) {
			return nil, false
		}
	} else if len(segs) != len(r.lits) || trailing {
		// A fixed pattern matches exactly, without a trailing slash.
		return nil, false
	}
	var vals map[string]string
	for i, lit := range r.lits {
		if lit == "" { // wildcard: one unrestricted segment
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
			v += "/" // the trailing slash belongs to rest: /files/a/ captures "a/"
		}
		vals[r.rest] = v
	}
	return vals, true
}

// cleanEscapes validates an escaped path before decoding. Escapes may not
// introduce separators or dot segments, preventing Mux and middleware from
// interpreting the same path differently.
func cleanEscapes(escaped string) bool {
	for _, seg := range strings.Split(escaped, "/") {
		if seg == "." || seg == ".." {
			// Reject raw dot segments too. Normalizing /admin/. or /admin/x/..
			// to /admin can cross the boundary between a protected subtree and
			// a public exact route.
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

// splitPath splits a path into segments; "/" and "" produce none.
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// canonicalPath accepts one spelling per path: leading slash, no empty or dot
// segments, and only an optional empty final segment for a subtree root. The
// parser and Mux share this predicate to avoid a second interpretation step.
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
