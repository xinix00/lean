// Host-tests voor de serverkant. De tegenpartij is hier net/http's client:
// die is streng en kent het protocol beter dan wij, dus wat hij accepteert is
// echt HTTP — precies de toets die een handgerolde server nodig heeft.
package leanhttp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// serveer start een server op een vrije poort en geeft zijn basis-URL.
func serveer(t *testing.T, h Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go Serve(ln, h)
	return "http://" + ln.Addr().String()
}

// haal doet een GET met net/http (de strenge tegenpartij) en geeft status+body.
func haal(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body lezen: %v", err)
	}
	return resp, string(b)
}

func TestServeGewoonAntwoord(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		if r.Method != "GET" || r.Path != "/hallo" {
			t.Errorf("verzoek = %s %s, wil GET /hallo", r.Method, r.Path)
		}
		if r.Header.Get("host") == "" { // hoofdletter-ongevoelig, net als de draad
			t.Error("geen Host-header ontvangen")
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "dag")
	})

	resp, body := haal(t, base+"/hallo")
	if resp.StatusCode != 200 || body != "dag" {
		t.Fatalf("%s / %q, wil 200 / \"dag\"", resp.Status, body)
	}
	// De server telt de lengte zelf: dat is de belofte van het gebufferde pad.
	if resp.ContentLength != 3 {
		t.Fatalf("ContentLength %d, wil 3", resp.ContentLength)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type %q", got)
	}
}

// Een handler die zelf een lengte aankondigt schrijft rechtstreeks door — geen
// tweede kopie van een megabyte-PNG in een buffer.
func TestServeEigenContentLength(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 300_000)
	base := serveer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(want)))
		w.Write(want)
	})

	resp, body := haal(t, base+"/groot")
	if resp.ContentLength != int64(len(want)) || len(body) != len(want) {
		t.Fatalf("lengte %d/%d, wil %d", resp.ContentLength, len(body), len(want))
	}
}

func TestServeStatusEnZonderBody(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) { w.WriteHeader(StatusNoContent) })

	resp, body := haal(t, base+"/niets")
	if resp.StatusCode != 204 || body != "" {
		t.Fatalf("%s / %q, wil 204 / leeg", resp.Status, body)
	}
	// Een 204 met Content-Length is protocol-fout; net/http meldt hem als -1.
	if v := resp.Header.Get("Content-Length"); v != "" {
		t.Fatalf("204 hoort geen Content-Length te hebben, kreeg %q", v)
	}
}

// De reden dat de display dit pakket kan gebruiken: tussentijds duwen. Zonder
// aangekondigde lengte wordt het chunked, en de client ziet elk frame meteen.
func TestServeFlushStreamt(t *testing.T) {
	los := make(chan struct{})
	base := serveer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		for i := range 3 {
			fmt.Fprintf(w, "frame %d\n", i)
			if err := w.Flush(); err != nil {
				t.Errorf("Flush: %v", err)
				return
			}
		}
		<-los // de verbinding blijft open: de client moet er tóch al bij kunnen
	})
	defer close(los)

	resp, err := http.Get(base + "/stream")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 {
		t.Fatalf("ContentLength %d, wil -1 (chunked)", resp.ContentLength)
	}
	br := bufio.NewReader(resp.Body)
	for i := range 3 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("frame %d lezen: %v", i, err)
		}
		if want := fmt.Sprintf("frame %d\n", i); line != want {
			t.Fatalf("frame %d = %q, wil %q", i, line, want)
		}
	}
}

// Een handler die eindeloos pusht moet mérken dat de kijker weg is, anders
// blijft er per verdwenen kijker een goroutine op een dode socket wachten.
func TestServeDoneBijWegvallendeClient(t *testing.T) {
	gemerkt := make(chan struct{})
	base := serveer(t, func(w ResponseWriter, r *Request) {
		// Vóór de eerste Flush: Done claimt de leeskant én de kop moet
		// "Connection: close" kunnen zeggen (fail-fast sinds de
		// tweeëndertigste ronde).
		done := r.Done()
		w.Write([]byte("hoi\n"))
		w.Flush()
		<-done
		close(gemerkt)
	})

	resp, err := http.Get(base + "/stream")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.CopyN(io.Discard, resp.Body, 4)
	resp.Body.Close() // kijker weg

	select {
	case <-gemerkt:
	case <-time.After(5 * time.Second):
		t.Fatal("Done sloot niet toen de client verdween")
	}
}

func TestServePOSTMetBody(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		if r.Method != "POST" {
			Error(w, "POST only", StatusMethodNotAllowed)
			return
		}
		var m map[string]int
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			Error(w, err.Error(), StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%d", m["n"])
	})

	resp, err := http.Post(base+"/tel", "application/json", strings.NewReader(`{"n":42}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "42" {
		t.Fatalf("body %q, wil \"42\"", b)
	}

	// En de andere kant op: een GET op hetzelfde pad is een nette 405.
	if r, _ := haal(t, base+"/tel"); r.StatusCode != 405 {
		t.Fatalf("GET → %s, wil 405", r.Status)
	}
}

// Chunked verzoeken (fetch met een stream-body) moeten leesbaar zijn, niet
// stilzwijgend leeg.
func TestServeChunkedVerzoekBodyIsEen501(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	})

	// Een body zonder bekende lengte: net/http chunkt hem dan — en chunked
	// uploads zijn gesloopt (eenendertigste ronde): verzoeklichamen dragen
	// een Content-Length, punt. De 501 hoort netjes aan te komen.
	req, _ := http.NewRequest("POST", base+"/echo", io.NopCloser(strings.NewReader("hallo chunked")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("status %d, wil 501 voor een gechunkt verzoek", resp.StatusCode)
	}

	// Mét lengte (net/http stuurt hem zodra de maat bekend is): gewoon werk.
	resp2, err := http.Post(base+"/echo", "text/plain", strings.NewReader("hallo lengte"))
	if err != nil {
		t.Fatalf("POST met lengte: %v", err)
	}
	defer resp2.Body.Close()
	if b, _ := io.ReadAll(resp2.Body); string(b) != "hallo lengte" {
		t.Fatalf("echo %q", b)
	}
}

// Keep-alive is geen luxe: de KVM-pagina pollt frames, en een TCP-handdruk per
// frame is zonde. Twee verzoeken over dezelfde verbinding moeten allebei kloppen.
func TestServeKeepAlive(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) { io.WriteString(w, r.Path) })

	c, err := net.Dial("tcp4", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	host := strings.TrimPrefix(base, "http://")
	for _, pad := range []string{"/een", "/twee"} {
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", pad, host)
	}
	br := bufio.NewReader(c)
	for _, pad := range []string{"/een", "/twee"} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("antwoord op %s: %v", pad, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != pad {
			t.Fatalf("antwoord %q, wil %q — verbinding werd niet hergebruikt", b, pad)
		}
	}
}

// Een handler die een lengte belooft en zich niet aan zijn woord houdt, mag de
// volgende lezer op die verbinding niet op de verkeerde byte zetten.
func TestServeVerkeerdeContentLengthSluitDeVerbinding(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "10") // maar er komen er drie
		w.Write([]byte("abc"))
	})

	c, err := net.Dial("tcp4", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	// De server hoort op te hangen; anders wacht een hergebruiker eeuwig op de
	// zeven ontbrekende bytes.
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("verbinding bleef open: %v", err)
	}
}

// Hijack: de WebSocket-handshake is HTTP, alles daarna niet.
func TestServeHijack(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			Error(w, "geen upgrade", StatusBadRequest)
			return
		}
		conn, brw, err := w.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
		brw.Flush()
		line, _ := brw.ReadString('\n') // en nu praten we ons eigen protocol
		brw.WriteString("echo: " + line)
		brw.Flush()
	})

	c, err := net.Dial("tcp4", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /input HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(c)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "101") {
		t.Fatalf("statusregel %q, wil 101", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	fmt.Fprintf(c, "ping\n")
	if got, _ := br.ReadString('\n'); got != "echo: ping\n" {
		t.Fatalf("na de upgrade kwam %q terug", got)
	}
}

func TestServeQuery(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, r.Query().Get("z")+"|"+r.Path)
	})
	if _, body := haal(t, base+"/stream?z=1&a=2"); body != "1|/stream" {
		t.Fatalf("body %q", body)
	}
}

func TestServeRedirect(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		if r.Path == "/" {
			Redirect(w, "/kvm", StatusFound)
			return
		}
		io.WriteString(w, "de pagina")
	})
	if _, body := haal(t, base+"/"); body != "de pagina" { // net/http volgt hem
		t.Fatalf("body %q — redirect niet gevolgd", body)
	}
}

// Een kapot verzoek krijgt een nette 400 en daarna gaat de verbinding dicht —
// niet een half antwoord of een hangende socket.
func TestServeKapotVerzoek(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) { t.Error("handler had niet mogen draaien") })

	c, err := net.Dial("tcp4", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprint(c, "ik ben geen http\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("geen antwoord: %v", err)
	}
	if !strings.Contains(line, "400") {
		t.Fatalf("statusregel %q, wil 400", line)
	}
}

// Een body groter dan de grens wordt geweigerd vóór hij gelezen is: dit is de
// kant waar onbekende netwerkdata binnenkomt.
func TestServeTeGroteBodyWeigert(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) { t.Error("handler had niet mogen draaien") })

	resp, err := http.Post(base+"/upload", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte("x"), maxBodyBytes+1)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusRequestEntityTooLarge {
		t.Fatalf("%s, wil 413", resp.Status)
	}
}

// Eén absurd lange headerregel mag ook aan de serverkant geen ongebonden
// buffergroei geven.
func TestServeTeLangeHeaderregelWeigert(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) { t.Error("handler had niet mogen draaien") })

	c, err := net.Dial("tcp4", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Groot: %s\r\n\r\n", strings.Repeat("A", bufSize+1))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("geen antwoord: %v", err)
	}
	if !strings.Contains(line, "400") {
		t.Fatalf("statusregel %q, wil 400", line)
	}
}

// Een header-waarde met een CRLF erin zou een tweede antwoord in het eerste
// smokkelen: die hoort er niet uit te komen.
func TestServeGeenResponseSplitting(t *testing.T) {
	base := serveer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Echo", "goed\r\nX-Gesmokkeld: fout")
		io.WriteString(w, "ok")
	})
	resp, _ := haal(t, base+"/")
	if got := resp.Header.Get("X-Gesmokkeld"); got != "" {
		t.Fatalf("gesmokkelde header kwam door: %q", got)
	}
}

// fakeListener levert eerst een tijdelijke fout, dan (nil, nil) — de twee
// manieren waarop een accept-lus kan gaan rondtollen.
type fakeListener struct {
	calls   int
	nilOnly bool
}

type tempErr struct{}

func (tempErr) Error() string   { return "tijdelijk" }
func (tempErr) Timeout() bool   { return true }
func (tempErr) Temporary() bool { return true }

func (l *fakeListener) Accept() (net.Conn, error) {
	l.calls++
	if !l.nilOnly && l.calls < 3 {
		return nil, tempErr{}
	}
	return nil, nil // lege accept: geen verbinding, geen fout
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return nil }

// TestServeNeverSpins pint het vangnet in de accept-lus: een listener die
// (nil, nil) teruggeeft moet de lus mét reden beëindigen, niet eindeloos
// doortollen. Zonder dit stond de SURF-display op 100% CPU zonder ooit te
// antwoorden of iets te loggen (gemeten 27-07 in QEMU).
func TestServeNeverSpins(t *testing.T) {
	l := &fakeListener{}
	done := make(chan error, 1)
	go func() { done <- Serve(l, func(ResponseWriter, *Request) {}) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve gaf nil terug; wil een fout die de app kan loggen")
		}
		if l.calls < 3 {
			t.Fatalf("Accept %d× aangeroepen; de tijdelijke fouten hadden herprobeerd moeten worden", l.calls)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve keerde niet terug — de accept-lus tolt rond (de bug van 27-07)")
	}
}

// TestServeDoneZegtGeenKeepAlive: een handler die Done() vraagt zet een
// wachthond op de verbinding, dus die is na dit antwoord op. De KOP moet dat dan
// ook zeggen.
//
// GEMETEN 12-08 op ijzer: hij zei het niet. De kop belooft keep-alive (die
// beslissing valt vóór de handler), een client met een pool legt de verbinding
// netjes weg, en het volgende verzoek loopt op een dode socket — 200/502/200/502
// door hop's agent-proxy, die per verzoek een context uit Done() bouwde.
func TestServeDoneZegtGeenKeepAlive(t *testing.T) {
	for _, tc := range []struct {
		naam  string
		vraag bool
		want  string
	}{
		{"zonder Done()", false, "keep-alive"},
		{"met Done()", true, "close"},
	} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go Serve(l, func(w ResponseWriter, r *Request) {
			if tc.vraag {
				_ = r.Done()
			}
			w.Write([]byte("ok"))
		})

		// Via een Client, want alleen die vraagt om keep-alive.
		var pool Client
		resp, err := pool.Do(Call{URL: "http://" + l.Addr().String() + "/"})
		if err != nil {
			l.Close()
			t.Fatalf("%s: %v", tc.naam, err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := resp.Header.Get("Connection"); got != tc.want {
			t.Errorf("%s: Connection = %q, want %q", tc.naam, got, tc.want)
		}

		// En de tweede ronde moet lukken: precies dit deed hij niet op ijzer.
		// Zonder wachthond komt hij uit de pool, mét wachthond vers — beide
		// horen een antwoord te geven in plaats van EOF.
		resp2, err := pool.Do(Call{URL: "http://" + l.Addr().String() + "/"})
		if err != nil {
			l.Close()
			t.Fatalf("%s: tweede ronde: %v", tc.naam, err)
		}
		body, rerr := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if rerr != nil || string(body) != "ok" {
			t.Errorf("%s: tweede ronde gaf %q (%v)", tc.naam, body, rerr)
		}
		pool.CloseIdle()
		l.Close()
	}
}
