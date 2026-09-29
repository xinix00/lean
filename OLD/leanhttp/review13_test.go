package leanhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func rawServer(t *testing.T, response string) string {
	t.Helper()
	return strings.TrimPrefix(rauweServer(t, response), "http://")
}

func TestBodyKorterDanContentLengthIsGeenEOF(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf!")
	resp, err := Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("korte body gaf %v, wil io.ErrUnexpectedEOF", err)
	}
}

func TestChunkedZonderNulchunkIsGeenEOF(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo\r\n")
	resp, err := Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if string(body) != "hallo" || err != io.ErrUnexpectedEOF {
		t.Fatalf("chunked zonder nul-chunk gaf (%q, %v), wil (hallo, io.ErrUnexpectedEOF)", body, err)
	}
}

func TestInterimAntwoordenWordenOvergeslagen(t *testing.T) {
	addr := rawServer(t,
		"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"+
			"HTTP/1.1 100 Continue\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\necht")
	resp, err := Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, wil 200 (het eindantwoord ná de interims)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "echt" {
		t.Fatalf("body %q, wil %q", body, "echt")
	}
}

func TestHEADLeestGeenBody(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
	resp, err := Do(Call{URL: "http://" + addr + "/", Method: "HEAD", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if len(body) != 0 || err != nil {
		t.Fatalf("HEAD-body gaf (%d bytes, %v), wil (0, nil)", len(body), err)
	}
	if resp.Length != 1234 {
		t.Fatalf("Length %d, wil de geadverteerde 1234 (informatief)", resp.Length)
	}
}

func leanServer(t *testing.T, h Handler) string {
	t.Helper()
	return strings.TrimPrefix(serveer(t, h), "http://")
}

func rawRoundTrip(t *testing.T, addr, request string) string {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(c)
	return string(out)
}

func TestServerWeigertSpatieVoorDubbelePunt(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr,
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nAAAAA")
	if !strings.Contains(got, "400") {
		t.Fatalf("antwoord was %q, wil een 400", got)
	}
}

func TestServerWeigertTEPlusContentLength(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr,
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")
	if !strings.Contains(got, "400") {
		t.Fatalf("antwoord was %q, wil een 400", got)
	}
}

func TestServerWeigertVreemdeTE(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr,
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
	if !strings.Contains(got, "501") {
		t.Fatalf("antwoord was %q, wil een 501", got)
	}
}

func TestServerUploadBovenLimietIsFout(t *testing.T) {
	raakte := false
	addr := leanServer(t, func(w ResponseWriter, r *Request) { raakte = true })
	got := rawRoundTrip(t, addr, fmt.Sprintf(
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", maxBodyBytes+1))
	if !strings.Contains(got, "413") {
		t.Fatalf("antwoord %q, wil een 413", got)
	}
	if raakte {
		t.Fatal("de handler draaide voor een verzoek dat de deur had moeten weigeren")
	}
}

func TestDotSegmentenWordenGeweigerd(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("/admin", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "publiek") })
	m.HandleFunc("/admin/", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "beveiligd") })
	addr := leanServer(t, m.ServeHTTP)
	for _, pad := range []string{"/admin/.", "/admin/x/..", "/../admin", "/veilig/a/../b"} {
		if got := rawRoundTrip(t, addr, "GET "+pad+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", pad, got)
		}
	}
}

func TestClientGetGebruiktDePoolMetEigenDial(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	dials := 0
	cl := &Client{DialContext: func(_ context.Context, network, a string) (net.Conn, error) {
		dials++
		return net.DialTimeout(network, a, time.Second)
	}}
	defer cl.CloseIdle()
	for i := 0; i < 3; i++ {
		resp, err := cl.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if dials != 1 {
		t.Fatalf("%d verse verbindingen voor 3 Gets — de pool wordt omzeild", dials)
	}
}

func TestClientWeigertHTTPSZonderTLSDialer(t *testing.T) {
	cl := &Client{}
	if _, err := cl.Get("https://example.invalid/"); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("https op een kale Client gaf %v, wil een TLS-configuratiefout", err)
	}
	if _, err := cl.Do(Call{URL: "https://example.invalid/"}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("Do https op een kale Client gaf %v, wil een TLS-configuratiefout", err)
	}
}

func TestRedirectStriptAuthorizationCrossOrigin(t *testing.T) {
	var gotAuth, gotKey string
	target := leanServer(t, func(w ResponseWriter, r *Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		io.WriteString(w, "einde")
	})

	host, port, _ := net.SplitHostPort(target)
	_ = host
	hopAddr := leanServer(t, func(w ResponseWriter, r *Request) {
		Redirect(w, "http://localhost:"+port+"/", 302)
	})
	resp, err := Do(Call{URL: "http://" + hopAddr + "/",
		Header: Header{"Authorization": "Bearer geheim", "X-Api-Key": "ook-geheim"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	if gotAuth != "" || gotKey != "" {
		t.Fatalf("headers (%q, %q) kwamen mee naar de andere origin", gotAuth, gotKey)
	}
}

func TestServerUploadVanExactDeLimietIsGeldig(t *testing.T) {
	got := make(chan struct {
		n   int64
		err error
	}, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		n, err := io.Copy(io.Discard, r.Body)
		got <- struct {
			n   int64
			err error
		}{n, err}
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", maxBodyBytes)
	chunk := strings.Repeat("A", 64<<10)
	for sent := 0; sent < maxBodyBytes; sent += len(chunk) {
		c.Write([]byte(chunk))
	}
	select {
	case r := <-got:
		if r.err != nil || r.n != maxBodyBytes {
			t.Fatalf("handler las (%d, %v), wil (%d, nil) — exact de limiet is geldig", r.n, r.err, maxBodyBytes)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler kwam niet door de body")
	}
}

func TestServerZietAfgebrokenContentLength(t *testing.T) {
	got := make(chan error, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		_, err := io.Copy(io.Discard, r.Body)
		got <- err
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhalf!")
	c.Close()
	select {
	case err := <-got:
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("handler las %v, wil io.ErrUnexpectedEOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler bleef hangen op de afgebroken body")
	}
}

func TestServerWeigertTEIdentity(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr,
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\nsmokkel")
	if !strings.Contains(got, "501") {
		t.Fatalf("antwoord was %q, wil een 501", got)
	}
}

func TestWriterIsEigenaarVanDeFraming(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		if r.Path == "/te" {
			w.Header().Set("Transfer-Encoding", "chunked")
			io.WriteString(w, "body")
			return
		}
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(StatusNoContent)
	})
	got := rawRoundTrip(t, addr, "GET /te HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	head, _, _ := strings.Cut(got, "\r\n\r\n")
	if strings.Contains(strings.ToLower(head), "transfer-encoding") &&
		strings.Contains(strings.ToLower(head), "content-length") {
		t.Fatalf("antwoord draagt TE én Content-Length:\n%s", head)
	}
	got = rawRoundTrip(t, addr, "GET /204 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	head, body, _ := strings.Cut(got, "\r\n\r\n")
	if strings.Contains(strings.ToLower(head), "content-length") || body != "" {
		t.Fatalf("204 draagt een lengte of body:\n%s%q", head, body)
	}
}

func TestRedirectStriptOokBijAnderePoort(t *testing.T) {
	var gotAuth string
	target := leanServer(t, func(w ResponseWriter, r *Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	hop := leanServer(t, func(w ResponseWriter, r *Request) {
		Redirect(w, "http://"+target+"/", 302)
	})
	resp, err := Do(Call{URL: "http://" + hop + "/", Header: Header{"Authorization": "Bearer geheim"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	if gotAuth != "" {
		t.Fatalf("Authorization %q reisde mee naar een andere poort", gotAuth)
	}
}

func TestEigenDialBlijftBuitenDePool(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	cl := &Client{}
	defer cl.CloseIdle()
	resp, err := cl.Do(Call{URL: "http://" + addr + "/", DialContext: func(_ context.Context, network, a string) (net.Conn, error) {
		return net.DialTimeout(network, a, time.Second)
	}})
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("pool draagt %d verbinding(en) van een per-call transport", n)
	}
}

func TestConnectionAlsTokenlijst(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: upgrade, close\r\n\r\nok")
	cl := &Client{}
	defer cl.CloseIdle()
	resp, err := cl.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("een verbinding met 'Connection: upgrade, close' is gepoold (%d)", n)
	}
}

func TestClientWeigertVreemdeTEInRespons(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nrommel")
	if _, err := Do(Call{URL: "http://" + addr + "/"}); err == nil || !strings.Contains(err.Error(), "Transfer-Encoding") {
		t.Fatalf("respons met TE: gzip gaf %v, wil een framing-fout", err)
	}
}

func TestRedirectNaarHTTPSGaatNooitPlaintext(t *testing.T) {
	leaked := make(chan string, 1)

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		leaked <- string(buf[:n])
	}()

	hop := leanServer(t, func(w ResponseWriter, r *Request) {
		Redirect(w, "https://"+l.Addr().String()+"/", 301)
	})
	cl := &Client{}
	defer cl.CloseIdle()
	_, err = cl.Do(Call{URL: "http://" + hop + "/", Header: Header{"Authorization": "Bearer geheim"}})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("redirect naar https gaf %v, wil een TLS-configuratiefout", err)
	}
	select {
	case req := <-leaked:
		t.Fatalf("plaintext op de https-poort:\n%s", req)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestChunkAfgekaptVoorDeCRLF(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo")
	cl := &Client{}
	defer cl.CloseIdle()
	resp, err := cl.Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hallo" || err != io.ErrUnexpectedEOF {
		t.Fatalf("afgekapte chunk gaf (%q, %v), wil (hallo, io.ErrUnexpectedEOF)", body, err)
	}
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("de dode verbinding is gepoold (%d)", n)
	}
}

func TestPooledConnNestNiet(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	cl := &Client{}
	defer cl.CloseIdle()
	for i := 0; i < 5; i++ {
		resp, err := cl.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for _, list := range cl.idle {
		for _, ic := range list {
			if _, nested := ic.c.(*pooledConn); nested {
				t.Fatal("de pool draagt een pooledConn-wrapper — de nesting groeit per hergebruik")
			}
		}
	}
}

func TestDataPlusEOFPooltDeDodeVerbindingNiet(t *testing.T) {
	lr := &lengthReader{r: dataPlusEOF{data: []byte("hallo")}, n: 5}
	b := &body{r: lr}
	buf := make([]byte, 16)
	n, err := b.Read(buf)
	if n != 5 || err != nil {
		t.Fatalf("eerste read gaf (%d, %v), wil (5, nil)", n, err)
	}
	if _, err := b.Read(buf); err != io.EOF {
		t.Fatalf("tweede read gaf %v, wil io.EOF (de body ís compleet)", err)
	}
	if !b.done {
		t.Fatal("body niet als compleet gemarkeerd")
	}
	if !lr.connEOF {
		t.Fatal("de dood van de verbinding is niet geregistreerd — hij zou gepoold worden")
	}
}

type dataPlusEOF struct{ data []byte }

func (d dataPlusEOF) Read(p []byte) (int, error) {
	n := copy(p, d.data)
	return n, io.EOF
}

func TestMuxDollarPanicktMetAlternatief(t *testing.T) {
	defer func() {
		p := recover()
		if p == nil || !strings.Contains(p.(string), "{$}") {
			t.Fatalf("geen (of onduidelijke) panic op {$}: %v", p)
		}
	}()
	NewServeMux().HandleFunc("GET /logs/{$}", func(w ResponseWriter, r *Request) {})
}

func TestHandlerKanContentLengthNietOverschrijden(t *testing.T) {
	sawErr := make(chan error, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		_, err1 := io.WriteString(w, "12345")
		_, err2 := io.WriteString(w, "SMOKKEL")
		if err1 != nil {
			sawErr <- err1
			return
		}
		sawErr <- err2
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, body, _ := strings.Cut(got, "\r\n\r\n")
	if body != "12345" {
		t.Fatalf("draad draagt %q, wil exact de beloofde 5 bytes", body)
	}
	select {
	case err := <-sawErr:
		if err == nil {
			t.Fatal("de handler zag geen fout bij het overschrijden van zijn eigen lengte")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler kwam niet terug")
	}
}

func TestCallMethodInjectieGeweigerd(t *testing.T) {
	_, err := Do(Call{URL: "http://127.0.0.1:1/", Method: "GET / HTTP/1.1\r\nX-Evil: 1\r\n\r\nGET"})
	if err == nil || !strings.Contains(err.Error(), "invalid method") {
		t.Fatalf("geïnjecteerde methode gaf %v, wil een method-validatiefout (vóór de dial)", err)
	}
}

func TestContentLengthMutatieOmzeiltDeControleNiet(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "10")
		io.WriteString(w, "12345")
		w.Header().Set("Content-Length", "5")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
	all, _ := io.ReadAll(c)
	if n := strings.Count(string(all), "HTTP/1.1 200"); n != 1 {
		t.Fatalf("%d antwoorden op een verbinding met een gebroken lengtebelofte, wil 1 (dan dicht)", n)
	}
}

func TestOverrunLaatDeVerbindingLeven(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		io.WriteString(w, "12345")
		io.WriteString(w, "SMOKKEL")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	all, _ := io.ReadAll(c)
	if n := strings.Count(string(all), "HTTP/1.1 200"); n != 2 {
		t.Fatalf("%d antwoorden, wil 2 — de afgekapte (maar draad-correcte) response hoort de verbinding niet te kosten", n)
	}
	if strings.Contains(string(all), "SMOKKEL") {
		t.Fatal("de surplus-bytes staan tóch op de draad")
	}
}

func TestUitgaandeHeadernaamStrikt(t *testing.T) {
	_, err := Do(Call{URL: "http://127.0.0.1:1/", Header: Header{"X-Bad\theader": "v"}})
	if err == nil || !strings.Contains(err.Error(), "illegal header name") {
		t.Fatalf("tab in headernaam gaf %v, wil een naam-validatiefout", err)
	}
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 2\r\n\r\nok")
	if _, err := Do(Call{URL: "http://" + addr + "/"}); err == nil || !strings.Contains(err.Error(), "invalid header name") {
		t.Fatalf("respons met ongeldige headernaam gaf %v, wil een parse-fout", err)
	}
}

func TestHeaderTimeoutLooptNietTijdensDeUpload(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(15 * time.Second))

		io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n")
		time.Sleep(400 * time.Millisecond)
		io.Copy(io.Discard, io.LimitReader(c, 1<<30))

	}()

	body := bytes.Repeat([]byte("A"), 4<<20)
	_, err = Do(Call{
		URL:           "http://" + l.Addr().String() + "/",
		Method:        "PUT",
		BodyReader:    bytes.NewReader(body),
		BodyLen:       int64(len(body)),
		HeaderTimeout: 150 * time.Millisecond,
		Timeout:       10 * time.Second,
	})

	if err == nil {
		t.Fatal("verwachtte een fout (de server antwoordt nooit)")
	}
	if strings.Contains(err.Error(), "stream body") {
		t.Fatalf("de upload sneuvelde op de header-termijn: %v", err)
	}
}

func TestVreemdeProtocolversieWordtGeweigerd(t *testing.T) {
	addr := rawServer(t, "HTTP/9.9 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := Do(Call{URL: "http://" + addr + "/"}); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("HTTP/9.9 gaf %v, wil een protocol-weigering", err)
	}
	srv := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, srv, "GET / HTTP/1.9\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "505") {
		t.Fatalf("HTTP/1.9 aan de serverkant gaf %q, wil een 505", got)
	}
}

func TestMuxWeigertAmbigueRoutes(t *testing.T) {
	expectPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: geen panic op een ambigu patroon", name)
			}
		}()
		fn()
	}
	h := func(w ResponseWriter, r *Request) {}

	m := NewServeMux()
	m.HandleFunc("GET /users/{id}", h)
	expectPanic("zelfde vorm", func() { m.HandleFunc("GET /users/{name}", h) })

	m2 := NewServeMux()
	m2.HandleFunc("GET /a/{x}", h)
	expectPanic("kruisend met gelijke score", func() { m2.HandleFunc("GET /{y}/b", h) })

	m3 := NewServeMux()
	m3.HandleFunc("GET /a/{x}", h)
	m3.HandleFunc("GET /a/b", h)
}

func TestTimeoutDektDeHeleRedirectKeten(t *testing.T) {
	slow := leanServer(t, func(w ResponseWriter, r *Request) {
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	hop := leanServer(t, func(w ResponseWriter, r *Request) {
		time.Sleep(400 * time.Millisecond)
		Redirect(w, "http://"+slow+"/", 302)
	})
	start := time.Now()
	_, err := Do(Call{URL: "http://" + hop + "/", Timeout: 600 * time.Millisecond})
	if err == nil {
		t.Fatal("twee hops van 400ms binnen een totaal van 600ms hoort te falen")
	}
	if d := time.Since(start); d > 1200*time.Millisecond {
		t.Fatalf("de call duurde %v — de termijn is geen totaal maar per hop", d)
	}
}

func TestMuxWeigertOngeldigeVormen(t *testing.T) {
	expectPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: geen panic", name)
			}
		}()
		fn()
	}
	h := func(w ResponseWriter, r *Request) {}

	expectPanic("segment na rest", func() { NewServeMux().HandleFunc("GET /a/{rest...}/b", h) })
	expectPanic("dubbele wildcardnaam", func() { NewServeMux().HandleFunc("GET /{x}/{x}", h) })
	expectPanic("lege accolades", func() { NewServeMux().HandleFunc("GET /a/{}", h) })
	expectPanic("naamloze rest", func() { NewServeMux().HandleFunc("GET /a/{...}", h) })
	expectPanic("segment na {$}", func() { NewServeMux().HandleFunc("GET /a/{$}/b", h) })
	m := NewServeMux()
	m.HandleFunc("GET /files/", h)
	expectPanic("subtree vs rest: zelfde dekking", func() { m.HandleFunc("GET /files/{rest...}", h) })
}

func TestTrageBodyGijzeltGeenGoroutine(t *testing.T) {
	got := make(chan error, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		_, err := io.Copy(io.Discard, r.Body)
		got <- err
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nhalf")

	select {
	case err := <-got:
		if err == nil {
			t.Fatal("de handler las een gestokte body als compleet")
		}
	case <-time.After(bodyTimeout + 3*time.Second):
		t.Fatal("de handler hangt nog — de body-termijn bestaat niet")
	}
}

func TestDoneOverleeftDeBodyTimeout(t *testing.T) {
	verdict := make(chan bool, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("body lezen: %v", err)
		}
		select {
		case <-r.Done():
			verdict <- true
		case <-time.After(bodyTimeout + time.Second):
			verdict <- false
		}
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nping")

	if <-verdict {
		t.Fatal("Done() vuurde terwijl de client er nog is — de bodyTimeout at de wachthond op")
	}
}

func TestPoolDialValtOnderDeTotaaltermijn(t *testing.T) {
	cl := &Client{}
	start := time.Now()
	_, err := cl.Do(Call{URL: "http://203.0.113.1:81/", Timeout: 300 * time.Millisecond})
	if err == nil {
		t.Fatal("een dial naar een zwart gat hoort te falen")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("de call duurde %v — de totaaltermijn mist het pool-pad", d)
	}
}

func TestServerEistEenGeldigeHost(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	for name, req := range map[string]string{
		"zonder Host":  "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
		"lege Host":    "GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n",
		"dubbele Host": "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nConnection: close\r\n\r\n",
		"rare methode": "B@D / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	} {
		if got := rawRoundTrip(t, addr, req); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", name, got)
		}
	}

	if got := rawRoundTrip(t, addr, "GET / HTTP/1.0\r\n\r\n"); !strings.Contains(got, "505") {
		t.Fatalf("HTTP/1.0 gaf %q, wil een 505", got)
	}
}

type closeSignal struct {
	net.Conn
	done chan struct{}
}

func (c closeSignal) Close() error { close(c.done); return c.Conn.Close() }

type fakeSink struct {
	deadline time.Time
	unarmed  int
}

func (f *fakeSink) Write(p []byte) (int, error) {
	if f.deadline.IsZero() {
		f.unarmed++
	}
	return len(p), nil
}
func (f *fakeSink) Read([]byte) (int, error)           { return 0, io.EOF }
func (f *fakeSink) Close() error                       { return nil }
func (f *fakeSink) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeSink) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (f *fakeSink) SetDeadline(t time.Time) error      { f.deadline = t; return nil }
func (f *fakeSink) SetReadDeadline(time.Time) error    { return nil }
func (f *fakeSink) SetWriteDeadline(t time.Time) error { f.deadline = t; return nil }

func TestGroteWriteWapentDeSchrijftermijn(t *testing.T) {
	f := &fakeSink{}
	c := &conn{nc: f, br: bufio.NewReaderSize(f, bufSize), bw: bufio.NewWriterSize(&timedWriter{nc: f}, bufSize)}
	w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: true, declared: -1}
	big := int64(3 * bufSize)
	w.Header().Set("Content-Length", strconv.FormatInt(big+2, 10))
	if _, err := w.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, big)); err != nil {
		t.Fatal(err)
	}
	if f.unarmed > 0 {
		t.Fatalf("%d socket-write(s) zonder schrijftermijn — een niet-lezende client gijzelt de handler vóór Flush", f.unarmed)
	}
}

func TestKaleLFIsGeenRegel(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.1\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("kale LF gaf %q, wil een 400", got)
	}
}

func TestContentLengthAlleenCijfers(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\nConnection: close\r\n\r\nAAAAA"); !strings.Contains(got, "400") {
		t.Fatalf("Content-Length +5 gaf %q, wil een 400", got)
	}

	srv := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok")
	if _, err := Do(Call{URL: "http://" + srv + "/"}); err == nil {
		t.Fatal("een antwoord met Content-Length +2 hoort een fout te zijn")
	}
}

func TestControlByteInHeaderIsFout(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	for name, req := range map[string]string{
		"CTL in waarde": "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x01b\r\nConnection: close\r\n\r\n",
		"losse CR":      "GET / HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\nConnection: close\r\n\r\n",
	} {
		if got := rawRoundTrip(t, addr, req); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", name, got)
		}
	}
}

func TestChunkgrootteAlleenHex(t *testing.T) {

	for _, size := range []string{"+3", " 3", "3 "} {
		srv := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"+size+"\r\nabc\r\n0\r\n\r\n")
		resp, err := Do(Call{URL: "http://" + srv + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatalf("chunkgrootte %q hoort een leesfout te zijn", size)
		}
		resp.Body.Close()
	}
}

func TestSpillLaatGeenTermijnAchter(t *testing.T) {
	f := &fakeSink{}
	c := &conn{nc: f, br: bufio.NewReaderSize(f, bufSize), bw: bufio.NewWriterSize(&timedWriter{nc: f}, bufSize)}
	w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: true, declared: -1}
	big := int64(3 * bufSize)
	w.Header().Set("Content-Length", strconv.FormatInt(big, 10))
	if _, err := w.Write(make([]byte, big)); err != nil {
		t.Fatal(err)
	}
	if !f.deadline.IsZero() {
		t.Fatal("na de write staat de schrijftermijn nog — hij verloopt stil tijdens de handler")
	}
}

func TestStatuscodeExactDrieCijfers(t *testing.T) {
	for _, status := range []string{"+200", "+20", "20", "2000", "0200", "2O0"} {
		srv := rawServer(t, "HTTP/1.1 "+status+" OK\r\nContent-Length: 2\r\n\r\nok")
		if _, err := Do(Call{URL: "http://" + srv + "/"}); err == nil {
			t.Fatalf("statuscode %q werd geaccepteerd", status)
		}
	}
}

func TestSyntaxfoutDraintNiet(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {})
	start := time.Now()
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\nHost: x\r\n\r\n")
	if !strings.Contains(got, "400") {
		t.Fatalf("kreeg %q, wil een 400", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("de 400 hield de verbinding %v vast — een pure syntaxfout hoort niet te drainen", d)
	}
}

func TestUitgaandeHeaderwaardeStrikt(t *testing.T) {

	_, err := Do(Call{URL: "http://127.0.0.1:1/", Header: Header{"X-A": "a\x00b"}})
	if err == nil || !strings.Contains(err.Error(), "illegal value") {
		t.Fatalf("kreeg %v, wil een illegal-value-fout vóór de dial", err)
	}

	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("X-A", "a\x00b")
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "200") || strings.Contains(got, "X-A") {
		t.Fatalf("antwoord %q: de kop met control-byte hoort overgeslagen", got)
	}
}

func TestDialContextWordtGeannuleerd(t *testing.T) {
	canceled := make(chan struct{})
	start := time.Now()
	_, err := Do(Call{
		URL:     "http://x/",
		Timeout: 150 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			close(canceled)
			return nil, ctx.Err()
		},
	})
	if err == nil {
		t.Fatal("een geannuleerde dial hoort een fout te zijn")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Do keerde pas na %v terug", d)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("de dialer zag de annulering nooit — de totaaltermijn reist niet als context mee")
	}
}

func TestHEADValtTerugOpGET(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /x", func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		io.WriteString(w, "hallo")
	})
	addr := leanServer(t, m.ServeHTTP)
	got := rawRoundTrip(t, addr, "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "200") || !strings.Contains(got, "Content-Length: 5") {
		t.Fatalf("HEAD op een GET-route gaf %q, wil 200 met Content-Length 5", got)
	}
	if strings.Contains(got, "hallo") {
		t.Fatal("het HEAD-antwoord draagt body-bytes")
	}
}

func TestExacteHEADRouteGaatVoorDeTerugval(t *testing.T) {
	for _, getEerst := range []bool{true, false} {
		m := NewServeMux()
		tagged := func(tag string) Handler {
			return func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", tag) }
		}
		if getEerst {
			m.HandleFunc("GET /x", tagged("get"))
			m.HandleFunc("HEAD /x", tagged("head"))
		} else {
			m.HandleFunc("HEAD /x", tagged("head"))
			m.HandleFunc("GET /x", tagged("get"))
		}
		addr := leanServer(t, m.ServeHTTP)
		got := rawRoundTrip(t, addr, "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if !strings.Contains(got, "X-Handler: head") {
			t.Fatalf("GET eerst=%v: antwoord %q — de exacte HEAD-route hoort te winnen", getEerst, got)
		}
	}
}

func TestResponseMetDubbeleFramingIsFout(t *testing.T) {
	for name, resp := range map[string]string{
		"TE plus CL": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"dubbele TE": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
	} {
		srv := rawServer(t, resp)
		if _, err := Do(Call{URL: "http://" + srv + "/"}); err == nil {
			t.Fatalf("%s: een dubbelzinnig geframed antwoord werd geaccepteerd", name)
		}
	}
}

func TestOngeldigeContentLengthGaatDeDraadNietOp(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "abc")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if strings.Contains(got, "abc") {
		t.Fatalf("antwoord %q: de ongeldige lengte staat op de draad", got)
	}
	if !strings.Contains(got, "Connection: close") || !strings.HasSuffix(got, "ok") {
		t.Fatalf("antwoord %q: wil Connection: close en de body op EOF-framing", got)
	}

	got = rawRoundTrip(t, addr, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
	if strings.Contains(got, "abc") {
		t.Fatalf("HEAD-antwoord %q: de ongeldige lengte staat op de draad", got)
	}
}

func TestTerugvalWintVanGeneriekeRoute(t *testing.T) {
	for _, getEerst := range []bool{true, false} {
		m := NewServeMux()
		tagged := func(tag string) Handler {
			return func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", tag) }
		}
		if getEerst {
			m.HandleFunc("GET /x", tagged("get"))
			m.HandleFunc("/x", tagged("elk"))
		} else {
			m.HandleFunc("/x", tagged("elk"))
			m.HandleFunc("GET /x", tagged("get"))
		}
		addr := leanServer(t, m.ServeHTTP)
		got := rawRoundTrip(t, addr, "HEAD /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if !strings.Contains(got, "X-Handler: get") {
			t.Fatalf("GET eerst=%v: antwoord %q — GET /x hoort ook voor HEAD van /x te winnen", getEerst, got)
		}
	}
}

func TestChunkExtensieEnTrailerStrikt(t *testing.T) {
	kapot := map[string]string{
		"extensie (weigeren wij volledig)": "3;ext=foo\r\nabc\r\n0\r\n\r\n",
		"lege extensienaam":                "3;=x\r\nabc\r\n0\r\n\r\n",
		"kale puntkomma":                   "3;\r\nabc\r\n0\r\n\r\n",
		"trailer zonder :":                 "3\r\nabc\r\n0\r\nkapotteregel\r\n\r\n",
		"framing in trailer":               "3\r\nabc\r\n0\r\nContent-Length: 5\r\n\r\n",
		"auth in trailer":                  "3\r\nabc\r\n0\r\nSet-Cookie: a=b\r\n\r\n",
	}
	for name, body := range kapot {
		srv := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"+body)
		resp, err := Do(Call{URL: "http://" + srv + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatalf("%s: hoort een leesfout te zijn", name)
		}
		resp.Body.Close()
	}

	srv := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: ok\r\n\r\n")
	resp, err := Do(Call{URL: "http://" + srv + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got, err := io.ReadAll(resp.Body); err != nil || string(got) != "abc" {
		t.Fatalf("nette trailer gaf (%q, %v), wil (abc, nil)", got, err)
	}
}

func TestMuxKruisendePatronenConflicteren(t *testing.T) {
	h := func(w ResponseWriter, r *Request) {}
	expectPanic := func(name string, patterns ...string) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: geen panic", name)
			}
		}()
		m := NewServeMux()
		for _, p := range patterns {
			m.HandleFunc(p, h)
		}
	}

	expectPanic("kruisende wildcards", "GET /a/{x}/{y}", "GET /{x}/b/c")
	expectPanic("kruisend met subtree", "GET /a/{x}/", "GET /{x}/b/")

	for name, patterns := range map[string][]string{
		"exact onder subtree":    {"GET /files/", "GET /files/x"},
		"methode onder elk":      {"/x", "GET /x"},
		"vast naast de subtree":  {"GET /logs", "GET /logs/"},
		"wildcard onder literal": {"GET /{x}", "GET /a"},
	} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%s: onterecht conflict: %v", name, p)
				}
			}()
			m := NewServeMux()
			for _, p := range patterns {
				m.HandleFunc(p, h)
			}
		}()
	}
}

func TestMuxGETKruistHEAD(t *testing.T) {
	h := func(w ResponseWriter, r *Request) {}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("GET /a/{x} + HEAD /{x}/b: geen panic, terwijl HEAD /a/b beide matcht")
			}
		}()
		m := NewServeMux()
		m.HandleFunc("GET /a/{x}", h)
		m.HandleFunc("HEAD /{x}/b", h)
	}()
	m := NewServeMux()
	m.HandleFunc("GET /x", h)
	m.HandleFunc("HEAD /x", h)
}

func TestMuxSlashIsEenAnderPad(t *testing.T) {
	m := NewServeMux()
	tagged := func(tag string) Handler {
		return func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", tag) }
	}
	m.HandleFunc("/admin", tagged("publiek"))
	m.HandleFunc("/admin/", tagged("beveiligd"))
	addr := leanServer(t, m.ServeHTTP)
	for pad, wil := range map[string]string{
		"/admin":   "X-Handler: publiek",
		"/admin/":  "X-Handler: beveiligd",
		"/admin/x": "X-Handler: beveiligd",
	} {
		if got := rawRoundTrip(t, addr, "GET "+pad+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, wil) {
			t.Fatalf("%s: antwoord %q, wil %s", pad, got, wil)
		}
	}

	m2 := NewServeMux()
	m2.HandleFunc("GET /health", tagged("gezond"))
	addr2 := leanServer(t, m2.ServeHTTP)
	if got := rawRoundTrip(t, addr2, "GET /health/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "404") {
		t.Fatalf("/health/ op een vast /health-patroon gaf %q, wil een 404", got)
	}
}

func TestRedirectAlleenVoorGETEnHEAD(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("/van", func(w ResponseWriter, r *Request) { Redirect(w, "/doel", 302) })
	m.HandleFunc("/doel", func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "4")
		io.WriteString(w, "doel")
	})
	addr := leanServer(t, m.ServeHTTP)

	resp, err := Do(Call{Method: "DELETE", URL: "http://" + addr + "/van"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("DELETE kreeg %d — de 3xx hoort bij de aanroeper te landen, niet stil herhaald", resp.StatusCode)
	}
	resp, err = Do(Call{URL: "http://" + addr + "/van"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "doel" {
		t.Fatalf("GET volgde de 302 niet: %q", body)
	}

	srv := rawServer(t, "HTTP/1.1 304 Not Modified\r\nLocation: http://x/\r\n\r\n")
	resp, err = Do(Call{URL: "http://" + srv + "/"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 304 {
		t.Fatalf("304 werd gevolgd (kreeg %d)", resp.StatusCode)
	}
}

func TestMethodeIsHoofdlettergevoelig(t *testing.T) {

	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		io.WriteString(w, "hallo")
	})
	if got := rawRoundTrip(t, addr, "head / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "hallo") {
		t.Fatalf("antwoord op 'head' mist de body: %q", got)
	}

	srv := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	resp, err := Do(Call{Method: "head", URL: "http://" + srv + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
		t.Fatalf("body op 'head' = %q, wil %q", body, "ok")
	}
}

func TestAmbigueEscapesWordenGeweigerd(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /objects/{key}", func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Key", r.PathValue("key"))
	})
	m.HandleFunc("GET /admin", func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Handler", "admin")
	})
	addr := leanServer(t, m.ServeHTTP)
	for name, pad := range map[string]string{
		"escaped slash": "/objects/secret%2Fmetadata",
		"escaped dots":  "/objects/%2E%2E",
		"dots plus pad": "/objects/%2e%2e%2fgeheim",
	} {
		if got := rawRoundTrip(t, addr, "GET "+pad+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", name, got)
		}
	}

	if got := rawRoundTrip(t, addr, "GET /%61dmin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "X-Handler: admin") {
		t.Fatalf("antwoord %q: een onschuldige escape hoort gewoon te routeren", got)
	}
}

func TestLegeBodyPooltDirect(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNoContent)
	})
	cl := &Client{}
	resp, err := cl.Do(Call{Method: "DELETE", URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n := cl.idleFor(addr); n != 1 {
		t.Fatalf("pool draagt %d verbindingen na een 204-Close, wil 1", n)
	}
}

func TestMiddlewareEnMuxZienHetzelfdePad(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("/admin", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "admin") })
	m.HandleFunc("/intern", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "intern") })
	var zagPad string
	middleware := func(w ResponseWriter, r *Request) {
		zagPad = r.Path
		if r.Path == "/admin" {
			r.Path = "/intern"
		}
		m.ServeHTTP(w, r)
	}
	addr := leanServer(t, middleware)

	got := rawRoundTrip(t, addr, "GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if zagPad != "/admin" {
		t.Fatalf("middleware zag %q — een ander pad dan de Mux routeert", zagPad)
	}
	if !strings.Contains(got, "X-Handler: intern") {
		t.Fatalf("antwoord %q: de rewrite door middleware is genegeerd", got)
	}
}

func TestEscapedLiteralInPatroonPanickt(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("geen panic op een percent-escape in een patroon-literal")
		}
	}()
	NewServeMux().HandleFunc("GET /objects/secret%2Fmetadata", func(w ResponseWriter, r *Request) {})
}

func TestLegeFramingheaderVerdwijntNiet(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	for name, req := range map[string]string{
		"lege plus echte CL": "POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\r\nContent-Length: 5\r\n\r\nAAAAA",
		"dubbele TE":         "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		if got := rawRoundTrip(t, addr, req); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", name, got)
		}
	}
}

func TestGeenPoolMetOngelezenBytes(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 204 No Content\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n")
	cl := &Client{}
	resp, err := cl.Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("status %d, wil 204", resp.StatusCode)
	}
	resp.Body.Close()
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("pool draagt %d verbindingen mét voorgeïnjecteerde bytes, wil 0", n)
	}
}

func TestIdleTimeoutRuimtZelfOp(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	cl := &Client{IdleTimeout: 200 * time.Millisecond}
	resp, err := cl.Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if n := cl.idleCount(); n != 1 {
		t.Fatalf("pool draagt %d verbindingen, wil 1 (opzet)", n)
	}
	time.Sleep(600 * time.Millisecond)
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("pool draagt na de idle-timeout nog %d verbindingen — niemand ruimt op", n)
	}
}

func TestStaleKeepAliveKrijgtEenHerkansing(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {

				bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}(c)
		}
	}()
	cl := &Client{}
	for i := 0; i < 2; i++ {
		resp, err := cl.Do(Call{URL: "http://" + l.Addr().String() + "/"})
		if err != nil {
			t.Fatalf("call %d: %v — de stale pool-verbinding kreeg geen herkansing", i+1, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(120 * time.Millisecond)
	}
}

func TestBodyDeadlineGeldtOokVoorGebufferdeBytes(t *testing.T) {
	srv := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
	resp, err := Do(Call{URL: "http://" + srv + "/", Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	time.Sleep(300 * time.Millisecond)
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("een verlopen totaaltermijn las gebufferde bytes gewoon door")
	}
}

type deadlineWeigeraar struct{ fakeSink }

func (deadlineWeigeraar) SetDeadline(time.Time) error { return errors.New("kapot") }

func TestKapotteDeadlineWisPooltNiet(t *testing.T) {
	cl := &Client{}
	if cl.put("x", &deadlineWeigeraar{}, nil) {
		t.Fatal("put accepteerde een verbinding waarvan de deadline-wis faalt")
	}
}

func TestCloseBreektGeblokkeerdeRead(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf")
		time.Sleep(2 * time.Second)
		c.Close()
	}()
	resp, err := Do(Call{URL: "http://" + l.Addr().String() + "/"})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				got <- err
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	resp.Body.Close()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("Close brak de geblokkeerde Read niet af")
	}
}

func TestEenRegelPerHeadernaam(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header()["content-length"] = "2"
		w.Header()["Content-Length"] = "2"
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if n := strings.Count(strings.ToLower(got), "content-length:"); n != 1 {
		t.Fatalf("%d Content-Length-regels op de draad, wil 1:\n%q", n, got)
	}
}

func TestHijackNaGebufferdeWriteWeigert(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, "x")
		if _, _, err := w.Hijack(); err == nil {
			t.Error("Hijack slaagde na een gebufferde Write")
		}
	})
	rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
}

func TestHandlerConnectionCloseWint(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.Contains(got, "Connection: close") || strings.Contains(got, "keep-alive") {
		t.Fatalf("antwoord %q: de handler-close is overschreven", got)
	}
}

func TestExpectIsEen417(t *testing.T) {
	raakte := false
	addr := leanServer(t, func(w ResponseWriter, r *Request) { raakte = true })
	for _, expect := range []string{"100-continue", "iets-anders"} {
		got := rawRoundTrip(t, addr,
			"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: "+expect+"\r\n\r\n")
		if !strings.Contains(got, "417") || !strings.Contains(got, "Connection: close") {
			t.Fatalf("Expect: %s gaf %q, wil een 417 met Connection: close", expect, got)
		}
	}
	if raakte {
		t.Fatal("de handler draaide voor een verzoek met Expect")
	}
}

func TestHEADHoudtExplicieteLengte(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "1234")
	})
	got := rawRoundTrip(t, addr, "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "Content-Length: 1234") {
		t.Fatalf("antwoord %q: de expliciete HEAD-lengte is overschreven", got)
	}
}

func TestRestHoudtSluitendeSlash(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("GET /files/{p...}", func(w ResponseWriter, r *Request) {
		w.Header().Set("X-P", "["+r.PathValue("p")+"]")
	})
	addr := leanServer(t, m.ServeHTTP)
	for pad, wil := range map[string]string{
		"/files/a/": "X-P: [a/]",
		"/files/a":  "X-P: [a]",
		"/files/":   "X-P: []",
	} {
		if got := rawRoundTrip(t, addr, "GET "+pad+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, wil) {
			t.Fatalf("%s: antwoord %q, wil %s", pad, got, wil)
		}
	}
}

func TestAlleenOriginForm(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	for name, req := range map[string]string{
		"absolute-form (vreemde host)": "GET http://evil/ HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n",
		"absolute-form (zelfde host)":  "GET http://goed/pad HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n",
		"asterisk-form (OPTIONS *)":    "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	} {
		if got := rawRoundTrip(t, addr, req); !strings.Contains(got, "400") {
			t.Fatalf("%s: antwoord %q, wil een 400", name, got)
		}
	}

	for _, req := range []string{
		"CONNECT ergens:443 HTTP/1.1\r\nHost: ergens\r\nConnection: close\r\n\r\n",
		"CONNECT / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	} {
		if got := rawRoundTrip(t, addr, req); !strings.Contains(got, "501") {
			t.Fatalf("CONNECT gaf %q, wil een 501", got)
		}
	}
	if got := rawRoundTrip(t, addr, "GET /pad HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "200") {
		t.Fatalf("origin-form gaf %q, wil 200", got)
	}
}

func TestOriginNormaliseertDefaultPoort(t *testing.T) {
	for _, paar := range [][2]string{
		{"http://h/a", "http://h:80/b"},
		{"https://h/a", "https://h:443/b"},
		{"http://H/a", "http://h/b"},
	} {
		a, _ := url.Parse(paar[0])
		b, _ := url.Parse(paar[1])
		if originOf(a) != originOf(b) {
			t.Fatalf("%s en %s horen dezelfde origin te zijn", paar[0], paar[1])
		}
	}
	a, _ := url.Parse("http://h/a")
	b, _ := url.Parse("http://h:8080/b")
	if originOf(a) == originOf(b) {
		t.Fatal("verschillende poorten zijn verschillende origins")
	}
}

func Test304HoudtInformatieveLengte(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(304)
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "Content-Length: 1234") {
		t.Fatalf("serverantwoord %q: de informatieve lengte is weg", got)
	}
	resp, err := Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 304 || resp.Length != 1234 {
		t.Fatalf("client las (%d, Length %d), wil (304, 1234)", resp.StatusCode, resp.Length)
	}
	if b, _ := io.ReadAll(resp.Body); len(b) != 0 {
		t.Fatalf("een 304 draagt geen bytes, kreeg %q", b)
	}
}

func TestSpecifiekWintOngeachtVolgorde(t *testing.T) {
	for _, algemeenEerst := range []bool{true, false} {
		m := NewServeMux()
		tagged := func(tag string) Handler {
			return func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", tag) }
		}
		if algemeenEerst {
			m.HandleFunc("/", tagged("wortel"))
			m.HandleFunc("/{x}/{rest...}", tagged("diep"))
		} else {
			m.HandleFunc("/{x}/{rest...}", tagged("diep"))
			m.HandleFunc("/", tagged("wortel"))
		}
		addr := leanServer(t, m.ServeHTTP)
		got := rawRoundTrip(t, addr, "GET /a/b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if !strings.Contains(got, "X-Handler: diep") {
			t.Fatalf("algemeen eerst=%v: antwoord %q — de specifiekste route hoort te winnen, niet de eerst geregistreerde", algemeenEerst, got)
		}
	}
}

func TestConflicterendeCasevariantenSluiten(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header()["Content-Length"] = "2"
		w.Header()["content-length"] = "5"
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if strings.Count(strings.ToLower(got), "content-length:") != 0 {
		t.Fatalf("antwoord %q: het CL-conflict staat (deels) op de draad", got)
	}
	if !strings.Contains(got, "Connection: close") || !strings.HasSuffix(got, "ok") {
		t.Fatalf("antwoord %q: wil close + body op EOF-framing", got)
	}
}

func TestStaleRetryAlleenReplaySafe(t *testing.T) {
	var deletes atomic.Int32
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				line, _ := bufio.NewReader(c).ReadString('\n')
				if strings.HasPrefix(line, "DELETE") {
					deletes.Add(1)
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}(c)
		}
	}()
	cl := &Client{}
	resp, err := cl.Do(Call{URL: "http://" + l.Addr().String() + "/"})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(120 * time.Millisecond)

	if _, err := cl.Do(Call{Method: "DELETE", URL: "http://" + l.Addr().String() + "/"}); err == nil {
		t.Fatal("een DELETE op een stale verbinding werd stil herhaald — dat is niet replay-safe")
	}
	if n := deletes.Load(); n != 0 {
		t.Fatalf("de server zag %d DELETE(s) — de herkansing voerde hem alsnog uit", n)
	}
}

func TestWriteIsEenCommit(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, "ok")
		w.WriteHeader(500)
	})
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, " 200 ") {
		t.Fatalf("antwoord %q: een WriteHeader ná een Write hoort te laat te zijn", got)
	}
	addr2 := leanServer(t, func(w ResponseWriter, r *Request) {
		w.WriteHeader(200)
		if _, _, err := w.Hijack(); err == nil {
			t.Error("Hijack slaagde na WriteHeader")
		}
	})
	rawRoundTrip(t, addr2, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
}

func TestHTTP10WordtGeweigerd(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.0\r\n\r\n"); !strings.Contains(got, "505") {
		t.Fatalf("HTTP/1.0 gaf %q, wil een 505", got)
	}
}

func TestServerRandvormen(t *testing.T) {
	m := NewServeMux()
	h := func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	}
	m.HandleFunc("GET /x", h)
	m.HandleFunc("PUT /x", h)
	addr := leanServer(t, m.ServeHTTP)

	got := rawRoundTrip(t, addr, "DELETE /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "405") || !strings.Contains(got, "Allow: ") ||
		!strings.Contains(got, "GET") || !strings.Contains(got, "PUT") ||
		!strings.Contains(got, "HEAD") {

		t.Fatalf("405 zonder (volledige, incl. HEAD) Allow: %q", got)
	}

	for _, host := range []string{"h.example:8080", "[::1]:80", "10.0.0.1", "a,b"} {
		if got := rawRoundTrip(t, addr, "GET /x HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "200") {
			t.Fatalf("Host %q gaf %q, wil 200", host, got)
		}
	}
	if got := rawRoundTrip(t, addr, "OPTIONS * HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("asterisk-form gaf %q, wil 400", got)
	}
}

func TestStroomWachtOpContinue(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n")
		body := make([]byte, 4)
		if _, err := io.ReadFull(br, body); err != nil {
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	resp, err := Do(Call{
		Method: "POST", URL: "http://" + l.Addr().String() + "/",
		BodyReader: strings.NewReader("ping"), BodyLen: 4,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "ping" {
		t.Fatalf("echo = %q, wil ping", b)
	}
}

func TestStilteOpExpectIsFout(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()
	_, err = Do(Call{
		Method: "PUT", URL: "http://" + l.Addr().String() + "/",
		BodyReader: striktGeenRead{t}, BodyLen: 4,
		HeaderTimeout: 200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "no verdict") {
		t.Fatalf("stilte op Expect gaf %v, wil een luide geen-oordeel-fout", err)
	}
}

type striktGeenRead struct{ t *testing.T }

func (g striktGeenRead) Read([]byte) (int, error) {
	g.t.Error("de stroom werd gelezen terwijl de server al had afgewezen")
	return 0, io.EOF
}

func TestVroegeAfwijzingSpaartDeStroom(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {})
	resp, err := Do(Call{
		Method: "POST", URL: "http://" + addr + "/",
		BodyReader: striktGeenRead{t}, BodyLen: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusExpectationFailed {
		t.Fatalf("status %d, wil 417", resp.StatusCode)
	}
}

func TestRegistratieFaaltVroeg(t *testing.T) {
	h := func(w ResponseWriter, r *Request) {}
	for name, fn := range map[string]func(){
		"kromme methode": func() { NewServeMux().HandleFunc("GE(T /x", h) },
		"nil-handler":    func() { NewServeMux().HandleFunc("GET /x", nil) },
		"dot-patroon":    func() { NewServeMux().HandleFunc("GET /a/../b", h) },

		"dubbele slash": func() { NewServeMux().HandleFunc("GET /a//b", h) },
		"lege wortel":   func() { NewServeMux().HandleFunc("//a", h) },
		"lege staart":   func() { NewServeMux().HandleFunc("/a//", h) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: geen panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestWriteHeaderPanicktOpOnzin(t *testing.T) {
	for _, status := range []int{0, -1, 1000, 100, 101, 103, 199} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("WriteHeader(%d): geen panic", status)
				}
			}()
			w := &respWriter{c: &conn{}, hdr: Header{}, status: StatusOK, declared: -1}
			w.WriteHeader(status)
		}()
	}
}

func TestPoolTotaalcap(t *testing.T) {
	cl := &Client{}
	for i := 0; i < 12; i++ {
		if !cl.put(fmt.Sprintf("host%d:80", i), &fakeSink{}, bufio.NewReader(&fakeSink{})) && i < defaultMaxIdleTotal {
			t.Fatalf("put %d geweigerd onder de cap", i)
		}
	}
	if n := cl.idleCount(); n > defaultMaxIdleTotal {
		t.Fatalf("pool draagt %d verbindingen, cap is %d", n, defaultMaxIdleTotal)
	}
}

func TestDrainVoorNetteClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go serveConn(server, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(client,
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nha"); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 512)
	got := ""
	for !strings.HasSuffix(got, "ok") {
		n, err := client.Read(buf)
		got += string(buf[:n])
		if err != nil {
			t.Fatalf("antwoord afgebroken na %q: %v", got, err)
		}
	}
	if !strings.Contains(got, " 200 ") {
		t.Fatalf("antwoord %q, wil een 200", got)
	}

	if _, err := io.WriteString(client, "lf"); err != nil {
		t.Fatalf("de server sloot zonder de body te drainen: %v", err)
	}
	if _, err := client.Read(buf); err == nil {
		t.Fatal("verwachtte de close na de drain")
	}
}

func TestChunkedGooitContentLengthWeg(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "")
		io.WriteString(w, "stuk1")
		w.Flush()
		io.WriteString(w, "stuk2")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "Transfer-Encoding: chunked") {
		t.Fatalf("antwoord %q, wil chunked", got)
	}
	if strings.Contains(strings.ToLower(got), "content-length") {
		t.Fatalf("antwoord %q draagt Content-Length naast Transfer-Encoding", got)
	}
}

func TestDoneEnHijackSluitenElkaarUit(t *testing.T) {

	w := &respWriter{c: &conn{watched: true}, hdr: Header{}, status: StatusOK, declared: -1}
	if _, _, err := w.Hijack(); err == nil || !strings.Contains(err.Error(), "Done") {
		t.Fatalf("Hijack na Done gaf %v, wil een weigering die Done noemt", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Done na Hijack: geen panic")
		}
	}()
	r := &Request{c: &conn{hijacked: true}}
	r.Done()
}

func TestRedirectWeigertHTTPSDowngrade(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 302 Found\r\nLocation: http://elders.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_, err := Do(Call{
		URL: "https://" + addr + "/pad?token=geheim",

		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			return net.DialTimeout(network, a, time.Second)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "degrade") {
		t.Fatalf("https→http gaf %v, wil een degradatie-weigering", err)
	}
}

func TestDoneClaimtVoorDeStart(t *testing.T) {

	maakConn := func() *conn {
		p1, p2 := net.Pipe()
		t.Cleanup(func() { p1.Close(); p2.Close() })
		return &conn{nc: p1, br: bufio.NewReader(p1)}
	}
	verwachtPanic := func(name string, r *Request) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: geen panic", name)
			}
		}()
		r.Done()
	}
	kop := maakConn()
	kop.headSent = true
	verwachtPanic("kop al verstuurd", &Request{c: kop, Body: emptyBody{}})

	body := &lengthReader{r: strings.NewReader("xx"), n: 2}
	r0 := &Request{c: maakConn(), Body: body}
	if r0.Done() == nil {
		t.Fatal("Done met ongelezen body gaf geen kanaal")
	}
	if body.n != 0 {
		t.Fatalf("Done liet %d bodybytes ongedraineerd voor de wachthond", body.n)
	}

	c := maakConn()
	r := &Request{c: c, Body: emptyBody{}}
	eerste := r.Done()
	c.headSent = true
	if tweede := r.Done(); tweede != eerste {
		t.Fatal("herhaalde Done gaf een ander kanaal")
	}
}

func TestExpectOordeelIsEenTermijn(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))

		time.Sleep(350 * time.Millisecond)
		io.WriteString(c, "HTTP/1.1 ")
		time.Sleep(350 * time.Millisecond)
		io.WriteString(c, "100 Continue\r\n\r\n")
		io.Copy(io.Discard, c)
	}()
	_, err = Do(Call{
		Method: "PUT", URL: "http://" + l.Addr().String() + "/",
		BodyReader: striktGeenRead{t}, BodyLen: 4,
		HeaderTimeout: 500 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "no verdict") {
		t.Fatalf("getreuzeld oordeel gaf %v, wil een no-verdict-fout binnen de éne termijn", err)
	}
}

func TestExpectHoortBijHetPakket(t *testing.T) {
	_, err := Do(Call{
		Method: "PUT", URL: "http://127.0.0.1:1/",
		BodyReader: strings.NewReader("x"), BodyLen: 1,
		Header: Header{"Expect": "100-continue"},
	})
	if err == nil || !strings.Contains(err.Error(), "set by the package") {
		t.Fatalf("caller-Expect gaf %v, wil de package-owned-weigering", err)
	}
}

func TestNietCanoniekIsEen400(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	for _, pad := range []string{"//admin", "/a//b", "/a//"} {
		if got := rawRoundTrip(t, addr, "GET "+pad+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
			t.Fatalf("%s gaf %q, wil een 400", pad, got)
		}
	}

	if got := rawRoundTrip(t, addr, "GET /a/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "200") {
		t.Fatalf("/a/ gaf %q, wil 200", got)
	}
}

func TestClientWeigertCONNECT(t *testing.T) {
	if _, err := Do(Call{Method: "CONNECT", URL: "http://127.0.0.1:1/"}); err == nil ||
		!strings.Contains(err.Error(), "CONNECT") {
		t.Fatalf("CONNECT gaf %v, wil een luide tunnel-weigering vóór de dial", err)
	}
}

func TestDoneOverleeftEenBodyVanBuiten(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		_ = r.Done()
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET /stream HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nX")
	if !strings.Contains(got, " 200 ") {
		t.Fatalf("GET-met-body op een Done-endpoint gaf %q, wil gewoon een 200", got)
	}
}

func TestWriteHeader205BlijftBodyloos205(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.WriteHeader(205)
		io.WriteString(w, "mag er niet uit")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, " 205 ") || !strings.Contains(got, "Content-Length: 0") ||
		strings.Contains(got, "mag er niet uit") {
		t.Fatalf("WriteHeader(205) gaf %q, wil een kale 205 met Content-Length: 0", got)
	}

	resp, err := Do(Call{URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 205 || resp.Length != 0 || len(b) != 0 {
		t.Fatalf("client las (%d, Length %d, body %q), wil (205, 0, leeg)", resp.StatusCode, resp.Length, b)
	}
}
