package leanhttp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingListener telt hoeveel TCP-verbindingen er echt geopend worden — dat
// is de enige manier om keep-alive te meten die niet naar de implementatie
// kijkt maar naar het gedrag.
type countingListener struct {
	net.Listener
	n atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func servedBy(t *testing.T, h http.Handler) (addr string, conns *countingListener) {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: raw}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = cl
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), cl
}

// TestKeepAliveHergebruikt: tien verzoeken over één verbinding. Zonder pool
// zouden dat tien TCP-handshakes zijn (en over TLS tien sleuteluitwisselingen).
func TestKeepAliveHergebruikt(t *testing.T) {
	addr, conns := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hallo")
	}))
	cl := &Client{}
	defer cl.CloseIdle()

	for i := range 10 {
		resp, err := cl.Get("http://" + addr + "/x")
		if err != nil {
			t.Fatalf("verzoek %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hallo" {
			t.Fatalf("verzoek %d: body = %q", i, body)
		}
	}
	if got := conns.n.Load(); got != 1 {
		t.Errorf("%d verbindingen voor 10 verzoeken, want 1", got)
	}
}

// TestKeepAliveNietBijHalveBody is de veiligheidsregel: een body die niet tot
// het einde gelezen is mag NOOIT terug in de pool. Zou dat gebeuren, dan leest
// het volgende verzoek de staart van dit antwoord als zijn statusregel.
func TestKeepAliveNietBijHalveBody(t *testing.T) {
	addr, conns := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 4096))
	}))
	cl := &Client{}
	defer cl.CloseIdle()

	for range 3 {
		resp, err := cl.Do(Call{URL: "http://" + addr + "/x"})
		if err != nil {
			t.Fatal(err)
		}
		io.CopyN(io.Discard, resp.Body, 10) // bewust maar 10 van 4096 bytes
		resp.Body.Close()
	}
	if got := conns.n.Load(); got != 3 {
		t.Errorf("%d verbindingen, want 3 — een half gelezen body werd hergebruikt", got)
	}
	// En het volgende volledige verzoek moet nog kloppen (geen desync).
	resp, err := cl.Do(Call{URL: "http://" + addr + "/x"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != 4096 {
		t.Errorf("na halve bodies: %d bytes, want 4096 — protocol-desync", len(body))
	}
}

// TestKeepAliveServerSluit: zegt de server "Connection: close", dan houden we
// hem niet vast (en het volgende verzoek moet gewoon werken).
func TestKeepAliveServerSluit(t *testing.T) {
	addr, conns := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "eenmalig")
	}))
	cl := &Client{}
	defer cl.CloseIdle()
	for i := range 3 {
		resp, err := cl.Get("http://" + addr + "/x")
		if err != nil {
			t.Fatalf("verzoek %d: %v", i, err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if got := conns.n.Load(); got != 3 {
		t.Errorf("%d verbindingen, want 3 — een server die close zegt werd toch hergebruikt", got)
	}
}

// TestKeepAliveIdleTimeout: een verbinding die te lang stilstaat wordt niet
// hergebruikt (de server heeft hem dan vaak al opgeruimd).
func TestKeepAliveIdleTimeout(t *testing.T) {
	addr, conns := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cl := &Client{IdleTimeout: 20 * time.Millisecond}
	defer cl.CloseIdle()
	for range 2 {
		resp, _ := cl.Get("http://" + addr + "/x")
		io.ReadAll(resp.Body)
		resp.Body.Close()
		time.Sleep(40 * time.Millisecond) // langer dan de idle-timeout
	}
	if got := conns.n.Load(); got != 2 {
		t.Errorf("%d verbindingen, want 2 — een verlopen verbinding werd hergebruikt", got)
	}
}

// TestKeepAliveMaxIdle: de pool houdt niet meer vast dan is toegestaan.
func TestKeepAliveMaxIdle(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cl := &Client{MaxIdlePerHost: 1}
	defer cl.CloseIdle()

	// Twee tegelijk open, dan beide teruggeven: één past, één moet dicht.
	r1, err := cl.Get("http://" + addr + "/a")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := cl.Get("http://" + addr + "/b")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(r1.Body)
	io.ReadAll(r2.Body)
	r1.Body.Close()
	r2.Body.Close()
	cl.mu.Lock()
	n := len(cl.idle[addr])
	cl.mu.Unlock()
	if n != 1 {
		t.Errorf("pool houdt %d verbindingen, want 1", n)
	}
}

// TestGzipDoorlaat: het pakket pakt niets uit, maar laat het wél toe — de
// aanroeper zet de header en leest Response.Encoding. Zo blijft compress/gzip
// buiten dit pakket.
func TestGzipDoorlaat(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("server zag Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", "3")
		w.Write([]byte("abc")) // doet alsof; de test gaat over de doorgifte
	}))
	resp, err := Do(Call{URL: "http://" + addr + "/x", Header: Header{"Accept-Encoding": "gzip"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Encoding != "gzip" {
		t.Errorf("Response.Encoding = %q, want gzip", resp.Encoding)
	}
}

// TestDefaultBlijftIdentity: wie niets zegt, vraagt niets — anders zou een
// bestaande gebruiker plots gecomprimeerde bytes krijgen die hij niet uitpakt.
func TestDefaultBlijftIdentity(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q, want identity", got)
		}
		fmt.Fprint(w, "ok")
	}))
	resp, err := Do(Call{URL: "http://" + addr + "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// TestSetCookieNietGevouwen: twee Set-Cookie-regels moeten twee blijven. Dit is
// de uitzondering van de HTTP-spec — een cookie-waarde en een Expires-datum
// bevatten zelf komma's, dus gevouwen is de lijst niet meer te splitsen. Vouwen
// betekent hier: één cookie lezen waar er twee stonden (login weg, en niemand
// merkt het).
func TestSetCookieNietGevouwen(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid=abc; Path=/; Expires=Mon, 02 Jan 2027 15:04:05 GMT")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		fmt.Fprint(w, "ok")
	}))
	resp, err := Do(Call{URL: "http://" + addr + "/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if len(resp.SetCookie) != 2 {
		t.Fatalf("SetCookie = %q, want twee losse regels", resp.SetCookie)
	}
	if !strings.Contains(resp.SetCookie[0], "Expires=Mon, 02 Jan 2027") {
		t.Errorf("eerste cookie kwijt of afgekapt: %q", resp.SetCookie[0])
	}
	if resp.SetCookie[1] != "theme=dark; Path=/" {
		t.Errorf("tweede cookie = %q", resp.SetCookie[1])
	}
	// En ze staan NIET in Header, want daar zouden ze gevouwen zijn.
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie staat óók in Header (%q) — daar kan hij alleen gevouwen staan", got)
	}
}

// TestPoolNegeertHTTP10 is de derde bug uit dezelfde familie, en de duurste om
// te vinden: HTTP/1.0 heeft de OMGEKEERDE default. Daar sluit de server tenzij
// hij expliciet keep-alive zegt (RFC 9112 §9.3), terwijl 1.1 openhoudt tenzij hij
// close zegt.
//
// GEMETEN 12-08 op een echte node: Python's http.server — waar half de wereld
// zijn artifacts mee serveert — spreekt 1.0 en stuurt een nette Content-Length
// zonder Connection-header. Dat zag er hier uit als een herbruikbare verbinding,
// dus ging hij de pool in, en élke tweede download viel om met
// "read status line: EOF". Op de server bleven verbindingen staan die niemand
// meer las.
func TestPoolNegeertHTTP10(t *testing.T) {
	for _, tc := range []struct {
		naam       string
		statusLijn string
		extra      string
		wantConns  int
	}{
		{"1.0 zonder Connection", "HTTP/1.0 200 OK", "", 3},
		{"1.0 mét keep-alive", "HTTP/1.0 200 OK", "Connection: keep-alive\r\n", 1},
		{"1.1 zonder Connection", "HTTP/1.1 200 OK", "", 1},
	} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var conns int
		var mu sync.Mutex
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns++
				mu.Unlock()
				go func(c net.Conn) {
					defer c.Close()
					br := bufio.NewReader(c)
					for {
						// Kop wegnemen tot de lege regel.
						for {
							line, err := br.ReadString('\n')
							if err != nil {
								return
							}
							if strings.TrimSpace(line) == "" {
								break
							}
						}
						fmt.Fprintf(c, "%s\r\nContent-Length: 2\r\n%s\r\nok", tc.statusLijn, tc.extra)
						// Een 1.0-server zonder keep-alive doet hierna wat 1.0
						// voorschrijft: dicht.
						if tc.wantConns > 1 {
							return
						}
					}
				}(c)
			}
		}()

		var pool Client
		for i := range 3 {
			resp, err := pool.Do(Call{URL: "http://" + l.Addr().String() + "/x"})
			if err != nil {
				t.Fatalf("%s: verzoek %d: %v", tc.naam, i+1, err)
			}
			body, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr != nil || string(body) != "ok" {
				t.Fatalf("%s: verzoek %d gaf %q (%v)", tc.naam, i+1, body, rerr)
			}
		}
		pool.CloseIdle()
		l.Close()

		mu.Lock()
		got := conns
		mu.Unlock()
		if got != tc.wantConns {
			t.Errorf("%s: %d verbindingen voor 3 verzoeken, want %d", tc.naam, got, tc.wantConns)
		}
	}
}

// TestPoolRuimtElkeHostOp — een verlopen verbinding naar host A moet ook
// verdwijnen als het volgende verzoek naar host B gaat. Eerst gebeurde dat alleen
// in get(addr): wie host A nooit meer belde, hield die verbinding voor altijd.
//
// Op een gewone machine is dat een slapende socket die niemand mist. Op een node
// is het een stuk van de netstack-pot — leannet houdt de buffers van een open
// verbinding gereserveerd en die groeien mee met wat er door ging, dus een
// afgeronde download van 5MB laat een dikke verbinding achter. GEMETEN 12-08 op
// een LicheeRV: na een reeks app-images was er zo weinig pot over dat élke nieuwe
// verbinding "buffer budget exhausted" kreeg, en omdat de watchdog voor zijn
// levensteken juist een VERSE verbinding eist, resette de node zichzelf.
func TestPoolRuimtElkeHostOp(t *testing.T) {
	hello := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	hostA, _ := servedBy(t, hello)
	hostB, _ := servedBy(t, hello)

	cl := &Client{IdleTimeout: 20 * time.Millisecond}
	defer cl.CloseIdle()

	resp, err := cl.Get("http://" + hostA + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if n := cl.idleCount(); n != 1 {
		t.Fatalf("pool draagt %d verbindingen na host A, wil 1", n)
	}

	time.Sleep(40 * time.Millisecond) // langer dan de idle-timeout

	resp, err = cl.Get("http://" + hostB + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Alleen host B mag er nog staan; die van A is verlopen en hoort gesloten.
	if n := cl.idleCount(); n != 1 {
		t.Fatalf("pool draagt %d verbindingen, wil 1 (alleen host B) — een verlopen "+
			"verbinding naar een host die je niet meer belt blijft dus staan", n)
	}
	if cl.idleFor(hostA) != 0 {
		t.Fatal("de verlopen verbinding naar host A staat nog in de pool")
	}
}

// TestPoolRuimtOpVoorDeDial — de sweep moet vóór het verzoek gebeuren, niet
// alleen erná (in put). De volgorde van het gemeten faalscenario: de pot van de
// netstack is op dóór verlopen gepoolde verbindingen → de dial faalt → er komt
// geen put → een sweep-in-put draait nooit. De toestand die de sweep moet
// opruimen maakt hem dan onbereikbaar (review 13-08). Hier nagebootst met een
// verzoek dat faalt: ook dán moet de verlopen verbinding weg zijn.
func TestPoolRuimtOpVoorDeDial(t *testing.T) {
	hostA, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cl := &Client{IdleTimeout: 20 * time.Millisecond}
	defer cl.CloseIdle()

	resp, err := cl.Get("http://" + hostA + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if cl.idleCount() != 1 {
		t.Fatal("verbinding naar host A kwam niet in de pool")
	}
	time.Sleep(40 * time.Millisecond) // laat hem verlopen

	// Een adres dat gegarandeerd weigert: een net gesloten listener.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close()
	if _, err := cl.Get("http://" + dead + "/"); err == nil {
		t.Fatal("verwachtte een dial-fout naar een dichte poort")
	}

	if n := cl.idleCount(); n != 0 {
		t.Fatalf("pool draagt nog %d verbindingen na een GEFAALD verzoek — "+
			"de sweep zit dus achter het verzoek, en het faalscenario komt daar nooit", n)
	}
}
