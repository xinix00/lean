package leanhttp

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"
)

// muxWriter is een ResponseWriter die alleen onthoudt wat er gebeurde.
type muxWriter struct {
	hdr    Header
	status int
	body   bytes.Buffer
}

func (m *muxWriter) Header() Header { return m.hdr }
func (m *muxWriter) WriteHeader(s int) {
	if m.status == 0 {
		m.status = s
	}
}
func (m *muxWriter) Write(p []byte) (int, error) { m.WriteHeader(StatusOK); return m.body.Write(p) }
func (m *muxWriter) Flush() error                { return nil }
func (m *muxWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("muxWriter cannot be hijacked")
}

// TestMuxPatronen: de patroonvormen die bestaande handlers al schrijven, en de
// precedentie ertussen. Een fout hier is onzichtbaar tot een specifieke route
// door een generieke wordt beantwoord — de storing waar deze mux voor bestaat.
func TestMuxPatronen(t *testing.T) {
	var got string
	vals := map[string]string{}
	m := NewServeMux()
	for _, p := range []string{
		"/health",
		"/logs/",
		"GET /api/devices",
		"POST /api/devices",
		"DELETE /api/devices/",
		"GET /api/devices/{id}",
		"GET /api/devices/{id}/history",
		"GET /app-ui/{app}/settings/{path...}",
		"GET /app-ui/{app}/pair/{driver}/{path...}",
	} {
		naam := p
		m.HandleFunc(p, func(w ResponseWriter, r *Request) {
			got = naam
			for _, k := range []string{"id", "app", "driver", "path"} {
				if v := r.PathValue(k); v != "" {
					vals[k] = v
				}
			}
			w.WriteHeader(StatusOK)
		})
	}

	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/health", "/health"},
		{"GET", "/logs/abc/def", "/logs/"},
		{"GET", "/api/devices", "GET /api/devices"},
		{"POST", "/api/devices", "POST /api/devices"},
		{"GET", "/api/devices/lamp-1", "GET /api/devices/{id}"},
		{"GET", "/api/devices/lamp-1/history", "GET /api/devices/{id}/history"},
		{"DELETE", "/api/devices/lamp-1", "DELETE /api/devices/"},

		// {path...} pakt de rest — ook de lege rest op de wortel-mét-slash
		// ({$} is gesloopt in de zevenentwintigste ronde: subtree dekt dit).
		{"GET", "/app-ui/com.x/settings/", "GET /app-ui/{app}/settings/{path...}"},
		{"GET", "/app-ui/com.x/settings/style.css", "GET /app-ui/{app}/settings/{path...}"},
		{"GET", "/app-ui/com.x/settings/a/b/c.png", "GET /app-ui/{app}/settings/{path...}"},
		{"GET", "/app-ui/com.x/pair/switch/index.html", "GET /app-ui/{app}/pair/{driver}/{path...}"},
	} {
		got = ""
		m.ServeHTTP(&muxWriter{hdr: Header{}}, &Request{Method: tc.method, Path: tc.path, Header: Header{}})
		if got != tc.want {
			t.Errorf("%s %s -> %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}

	// De wildcards die onderweg opgevangen zijn.
	for k, want := range map[string]string{
		"app": "com.x", "driver": "switch", "path": "index.html", "id": "lamp-1",
	} {
		if vals[k] != want {
			t.Errorf("PathValue(%q) = %q, want %q", k, vals[k], want)
		}
	}
}

// TestMuxMatchtAlleenCanoniek: de mux normaliseert NIET (meer) — de parser is
// de ene plek die het pad schoont en valideert, en een tweede interpretatie in
// de mux was zelf een differentiaal-risico (review 13-08, eenendertigste
// ronde). Een met de hand gebouwde Request met een niet-canoniek pad matcht
// dus gewoon niets; over de draad bestaat die vorm niet (parser schoont
// dubbele slashes en weigert dot-segmenten met een 400).
func TestMuxMatchtAlleenCanoniek(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /api/devices", func(w ResponseWriter, r *Request) { w.WriteHeader(StatusOK) })
	// Sinds de tweeëndertigste ronde deelt de mux het canonicalPath-predicaat
	// met de parser: ook een ontbrekende leidende slash — die splitPath'
	// getrim anders liet matchen — is gewoon een 404.
	for _, pad := range []string{"/api//devices", "/api/devices/", "api/devices", "//api/devices"} {
		w := &muxWriter{hdr: Header{}}
		m.ServeHTTP(w, &Request{Method: "GET", Path: pad, Header: Header{}})
		if w.status != StatusNotFound {
			t.Errorf("%s -> %d, wil 404: de mux hoort niet-canonieke paden niet te herschrijven", pad, w.status)
		}
	}
}

// TestMuxRestKanLeegZijn: {path...} matcht ook nul segmenten, want dat is wat
// een map-index is.
func TestMuxRestKanLeegZijn(t *testing.T) {
	var rest string
	geraakt := false
	m := NewServeMux()
	m.HandleFunc("GET /files/{path...}", func(w ResponseWriter, r *Request) {
		geraakt, rest = true, r.PathValue("path")
		w.WriteHeader(StatusOK)
	})
	m.ServeHTTP(&muxWriter{hdr: Header{}}, &Request{Method: "GET", Path: "/files/", Header: Header{}})
	if !geraakt {
		t.Fatal("/files/ raakte de rest-wildcard niet")
	}
	if rest != "" {
		t.Errorf("path = %q, want leeg", rest)
	}
}

// TestMuxStatus: geen route is 404, een route die alleen onder een andere
// methode bestaat is 405, en een eigen NotFound wint van de kale 404.
func TestMuxStatus(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /x", func(w ResponseWriter, r *Request) { w.WriteHeader(StatusOK) })

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/x", StatusOK},
		{"POST", "/x", StatusMethodNotAllowed},
		{"GET", "/y", StatusNotFound},
	} {
		w := &muxWriter{hdr: Header{}}
		m.ServeHTTP(w, &Request{Method: tc.method, Path: tc.path, Header: Header{}})
		if w.status != tc.want {
			t.Errorf("%s %s -> %d, want %d", tc.method, tc.path, w.status, tc.want)
		}
	}

}

// TestMuxWeigertFouteWiring: een patroon zonder leidende slash en een dubbele
// registratie zijn bedradingsfouten die vanaf de eerste run bestaan.
func TestMuxWeigertFouteWiring(t *testing.T) {
	for _, fn := range []func(*Mux){
		func(m *Mux) { m.HandleFunc("health", nil) },
		func(m *Mux) { m.HandleFunc("/x", nil); m.HandleFunc("/x", nil) },
		func(m *Mux) { m.HandleFunc("GET /x", nil); m.HandleFunc("GET /x", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("geen panic op foute wiring")
				}
			}()
			fn(NewServeMux())
		}()
	}
	// Dezelfde weg onder een andere methode is juist normaal — mét echte
	// handlers, want een nil-handler panickt sinds de dertigste ronde zelf.
	h := func(w ResponseWriter, r *Request) {}
	m := NewServeMux()
	m.HandleFunc("GET /x", h)
	m.HandleFunc("POST /x", h)
}

// TestMuxOverDeDraad: de mux als Handler in Serve, zodat de padnormalisatie en
// de wildcards ook over een echte verbinding kloppen.
func TestMuxOverDeDraad(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /api/devices/{id}", func(w ResponseWriter, r *Request) {
		w.Write([]byte("device " + r.PathValue("id")))
	})
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Serve(l, m.Handler())

	resp, err := Get("http://" + l.Addr().String() + "/api/devices/lamp-9")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 32)
	n, _ := resp.Body.Read(body)
	if string(body[:n]) != "device lamp-9" {
		t.Errorf("body = %q", body[:n])
	}
}
