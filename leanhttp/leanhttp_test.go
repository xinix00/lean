// Host-tests voor de handgerolde HTTP-parser. Dit pad leest netwerkdata van een
// server die wij niet schreven, dus het is precies het soort code dat tests
// verdient: elk faalpad moet luid falen i.p.v. een half antwoord door te geven.
package leanhttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// lees haalt de hele body op en sluit hem.
func lees(t *testing.T, r *Response) []byte {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("body lezen: %v", err)
	}
	return b
}

func TestGewoneGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("methode %q, wil GET", r.Method)
		}
		if r.Host == "" {
			t.Error("geen Host-header meegestuurd")
		}
		w.Write([]byte("hallo"))
	}))
	defer srv.Close()

	resp, err := Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Length != 5 {
		t.Fatalf("Length %d, wil 5", resp.Length)
	}
	if got := lees(t, resp); string(got) != "hallo" {
		t.Fatalf("body %q, wil %q", got, "hallo")
	}
}

// De regressie die ik bijna shipte: de header-begrenzing mag de BODY niet
// afknijpen. Een image is megabytes groot, dus een payload ruim boven bufSize
// (8KB) én boven maxHeaderBytes (64KB) moet compleet doorkomen.
func TestGroteBodyWordtNietAfgekapt(t *testing.T) {
	want := bytes.Repeat([]byte("0123456789abcdef"), 20_000) // 320KB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expliciet, anders schakelt Go's server op deze omvang naar chunked —
		// en dat weigert deze client bewust (zie TestChunkedWeigert).
		w.Header().Set("Content-Length", fmt.Sprint(len(want)))
		w.Write(want)
	}))
	defer srv.Close()

	resp, err := Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Length != int64(len(want)) {
		t.Fatalf("Length %d, wil %d", resp.Length, len(want))
	}
	if got := lees(t, resp); !bytes.Equal(got, want) {
		t.Fatalf("body %d bytes, wil %d — afgekapt", len(got), len(want))
	}
}

func TestRedirectWordtGevolgd(t *testing.T) {
	var doel *httptest.Server
	doel = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/een":
			http.Redirect(w, r, doel.URL+"/twee", http.StatusFound) // absoluut
		case "/twee":
			http.Redirect(w, r, "/drie", http.StatusMovedPermanently) // relatief
		case "/drie":
			w.Write([]byte("aangekomen"))
		default:
			t.Errorf("onverwacht pad %q", r.URL.Path)
		}
	}))
	defer doel.Close()

	resp, err := Get(doel.URL + "/een")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := lees(t, resp); string(got) != "aangekomen" {
		t.Fatalf("body %q, wil %q", got, "aangekomen")
	}
}

func TestRedirectLusStopt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/rond", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := Get(srv.URL); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("err = %v, wil een too-many-redirects-fout", err)
	}
}

// De kern van het pakket: https ZONDER dialer moet luid weigeren, want er is
// geen TLS gelinkt. Stil doorgaan zou een onbegrijpelijke verbindingsfout
// geven — en een fout die niet zegt wat te doen kost een zoektocht, dus de
// melding noemt beide uitwegen.
func TestHTTPSWeigertLuid(t *testing.T) {
	_, err := Get("https://example.com/app.elf")
	if err == nil {
		t.Fatal("https werd geaccepteerd")
	}
	for _, want := range []string{"TLS", "Dial", "leanhttps"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v — de melding moet %q noemen", err, want)
		}
	}
}

// De dialer-naad is ALGEMEEN, niet TLS-specifiek: hier stuurt hij een
// https-URL naar een gewone testserver. Daarmee is bewezen dat het mechanisme
// werkt zonder dat deze test (of dit pakket) TLS aanraakt — precies waarom de
// naad zo mag bestaan.
func TestDialHookStuurtOm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "artifacts.example" {
			t.Errorf("Host-header = %q, want de URL-host (niet het dial-adres)", r.Host)
		}
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	var dialedTo string
	resp, err := Do(Call{
		URL: "https://artifacts.example/app.elf",
		Dial: func(network, addr string) (net.Conn, error) {
			dialedTo = addr // moet de hostnaam + 443 zijn, niet een IP
			return net.Dial(network, strings.TrimPrefix(srv.URL, "http://"))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if dialedTo != "artifacts.example:443" {
		t.Errorf("Dial kreeg %q, want artifacts.example:443 (hostnaam voor SNI, https-poort)", dialedTo)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Errorf("body = %q", body)
	}
}

// Een dialer die niets teruggeeft (en ook geen fout) mag geen nil-pointer
// verderop worden.
func TestDialHookNilConn(t *testing.T) {
	_, err := Do(Call{
		URL:  "https://x.example/y",
		Dial: func(string, string) (net.Conn, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("nil-verbinding zonder fout werd geaccepteerd")
	}
}

func TestChunkedWeigert(t *testing.T) {
	// Handmatig antwoorden: httptest's ResponseWriter zet zelf Content-Length
	// op kleine bodies, dus chunked moet op de draad geforceerd worden.
	srv := rauweServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n0\r\n\r\n")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "chunked") {
		t.Fatalf("err = %v, wil een chunked-fout", err)
	}
}

func TestZonderContentLengthWeigert(t *testing.T) {
	srv := rauweServer(t, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nhallo")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "no Content-Length") {
		t.Fatalf("err = %v, wil een ontbrekende-lengte-fout", err)
	}
}

// Twee verschillende lengtes is een smokkel-signaal, geen laatste-wint-geval.
func TestDubbeleContentLengthWeigert(t *testing.T) {
	srv := rauweServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhallo")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "duplicate Content-Length") {
		t.Fatalf("err = %v, wil een dubbele-lengte-fout", err)
	}
}

func TestFoutstatusGeeftFout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "weg", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := Get(srv.URL); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, wil een 404-fout", err)
	}
}

func TestKromgeStatusregelWeigert(t *testing.T) {
	srv := rauweServer(t, "ik ben geen http\r\n\r\n")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "malformed status line") {
		t.Fatalf("err = %v, wil een malformed-status-fout", err)
	}
}

// Eén absurd lange headerregel mag geen ongebonden buffergroei geven.
func TestTeLangeHeaderregelWeigert(t *testing.T) {
	srv := rauweServer(t, "HTTP/1.1 200 OK\r\nX-Groot: "+strings.Repeat("A", bufSize+1)+"\r\nContent-Length: 1\r\n\r\nx")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "header line exceeds") {
		t.Fatalf("err = %v, wil een te-lange-regel-fout", err)
	}
}

// Veel kleine regels passen elk in de buffer maar mogen samen niet ongebonden
// groeien — de cumulatieve grens (maxHeaderBytes).
func TestTeVeelHeaderbytesWeigert(t *testing.T) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	for i := 0; b.Len() < maxHeaderBytes+1024; i++ {
		fmt.Fprintf(&b, "X-Vul-%d: %s\r\n", i, strings.Repeat("v", 200))
	}
	b.WriteString("Content-Length: 1\r\n\r\nx")
	if _, err := Get(rauweServer(t, b.String())); err == nil || !strings.Contains(err.Error(), "headers exceed") {
		t.Fatalf("err = %v, wil een headers-te-groot-fout", err)
	}
}

func TestGeenHostWeigert(t *testing.T) {
	if _, err := Get("http:///app.elf"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("err = %v, wil een geen-host-fout", err)
	}
}

// Do is de algemene weg: methode, headers, body — en een foutstatus is géén
// transportfout, want de aanroeper wil de body ervan lezen.
func TestDoPOST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(body) != `{"n":1}` {
			t.Errorf("kreeg %s met body %q", r.Method, body)
		}
		if got := r.Header.Get("X-Hop-Auth"); got != "abc" {
			t.Errorf("X-Hop-Auth = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if r.ContentLength != 7 {
			t.Errorf("Content-Length = %d, wil 7", r.ContentLength)
		}
		http.Error(w, "job locked", http.StatusConflict)
	}))
	defer srv.Close()

	resp, err := Do(Call{
		Method: "POST", URL: srv.URL + "/v1/jobs",
		Header: Header{"Content-Type": "application/json", "X-Hop-Auth": "abc"},
		Body:   []byte(`{"n":1}`),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != 409 {
		t.Fatalf("StatusCode %d, wil 409 — een foutstatus is geen transportfout", resp.StatusCode)
	}
	if got := lees(t, resp); !strings.Contains(string(got), "job locked") {
		t.Fatalf("de body van de fout hoort leesbaar te zijn: %q", got)
	}
}

// De reden dat chunked erin zit: een Go-server die streamt kent zijn lengte
// niet en chunkt dus altijd. Zonder dit is elke SSE-staart onleesbaar.
func TestDoLeestChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		for i := range 3 {
			fmt.Fprintf(w, "data: regel %d\n", i)
			f.Flush()
		}
	}))
	defer srv.Close()

	resp, err := Do(Call{URL: srv.URL})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Length != -1 {
		t.Fatalf("Length %d, wil -1 (chunked kent geen lengte vooraf)", resp.Length)
	}
	want := "data: regel 0\ndata: regel 1\ndata: regel 2\n"
	if got := lees(t, resp); string(got) != want {
		t.Fatalf("body %q, wil %q", got, want)
	}
}

// Een blijvende stream leest regel voor regel door en breekt af op Close —
// niet op een timeout, want een logstaart hoort open te blijven.
func TestDoStreamStoptOpClose(t *testing.T) {
	los := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		io.WriteString(w, "eerste\n")
		f.Flush()
		<-r.Context().Done()
		close(los)
	}))
	defer srv.Close()

	resp, err := Do(Call{URL: srv.URL}) // Timeout 0: geen totaaltermijn
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "eerste\n" {
		t.Fatalf("regel %q (%v)", line, err)
	}
	resp.Body.Close()
	select {
	case <-los:
	case <-time.After(5 * time.Second):
		t.Fatal("de server merkte niet dat de client ophing")
	}
}

func TestDoTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // antwoordt nooit
	}))
	defer srv.Close()

	start := time.Now()
	if _, err := Do(Call{URL: srv.URL, Timeout: 300 * time.Millisecond}); err == nil {
		t.Fatal("een server die niet antwoordt hoort op de termijn te stuiten")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("de termijn hield het pas na %v tegen", d)
	}
}

// Headers die het pakket zelf zet mag een aanroeper niet stil overschrijven, en
// een CRLF in een waarde zou een tweede verzoek smokkelen.
func TestDoWeigertGesmokkeldeHeaders(t *testing.T) {
	for naam, h := range map[string]Header{
		"eigen Host":     {"Host": "elders"},
		"eigen lengte":   {"Content-Length": "0"},
		"CRLF in waarde": {"X-Iets": "a\r\nX-Gesmokkeld: b"},
	} {
		if _, err := Do(Call{URL: "http://127.0.0.1:1/", Header: h}); err == nil {
			t.Errorf("%s: werd geaccepteerd", naam)
		}
	}
}

// rauweServer antwoordt op elke verbinding met exact deze bytes en geeft zijn
// URL — nodig waar net/http's server het antwoord te netjes zou maken.
func rauweServer(t *testing.T, antwoord string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// Het verzoek eerst wegslikken tot de lege regel, zodat de
				// client zijn write kwijt kan.
				buf := make([]byte, 4096)
				c.Read(buf)
				io.WriteString(c, antwoord)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}
