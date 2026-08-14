package leanhttp

// review13_test.go — de bevindingen van de review van 13-08, elk als test die
// tegen de oude code faalt: framing die zijn einde moet bewijzen, HEAD en 1xx
// aan de clientkant, en de strengheid van de serverparser.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rawServer is rauweServer (leanhttp_test.go) zonder het http://-schema: deze
// tests bouwen hun URL zelf. Eén serverscript, geen tweede kopie die kan
// afdrijven.
func rawServer(t *testing.T, response string) string {
	t.Helper()
	return strings.TrimPrefix(rauweServer(t, response), "http://")
}

// TestBodyKorterDanContentLengthIsGeenEOF — een server die 10 belooft en na 5
// sluit leverde vóór de fix een nette io.EOF: een half bestand als succes.
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

// TestChunkedZonderNulchunkIsGeenEOF — chunked zonder afsluitende nul-chunk is
// een incompleet bericht (RFC 9112 §8), geen einde.
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

// TestInterimAntwoordenWordenOvergeslagen — 100/103 zijn geen eindantwoord;
// vóór de fix kreeg de aanroeper de 103 en stond het échte antwoord nog op de
// verbinding (desync op keep-alive).
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

// TestHEADLeestGeenBody — het antwoord op HEAD draagt een Content-Length maar
// géén bytes; vóór de fix wachtte de client op een body die nooit komt (en las
// hij op keep-alive het vólgende antwoord als body).
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

// leanServer is serveer (serve_test.go) zonder het http://-schema: deze tests
// dialen de poort ook rauw (rawRoundTrip).
func leanServer(t *testing.T, h Handler) string {
	t.Helper()
	return strings.TrimPrefix(serveer(t, h), "http://")
}

// rawRoundTrip stuurt rauwe bytes en geeft alles terug wat de server antwoordt.
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

// TestServerWeigertSpatieVoorDubbelePunt — "Content-Length : 5" MOET een 400
// zijn (RFC 9112 §5.1). Vóór de fix werd het een onbekende header en bleven de
// vijf bodybytes staan als het begin van het volgende verzoek: desync/smuggling.
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

// TestServerWeigertTEPlusContentLength — beide framings tegelijk is hét
// smokkelsignaal (RFC 9112 §6.1): twee parsers kiezen elk hun eigen einde.
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

// TestServerWeigertVreemdeTE — élke niet-chunked Transfer-Encoding als chunked
// lezen legt het lichaamseinde op de verkeerde plek: 501.
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

// TestServerUploadBovenLimietIsFout — een chunked upload voorbij de limiet gaf
// de handler een stille EOF op precies 1 MiB: een half verzoek als compleet.
func TestServerUploadBovenLimietIsFout(t *testing.T) {
	sawErr := make(chan error, 1)
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		_, err := io.Copy(io.Discard, r.Body)
		sawErr <- err
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	chunk := strings.Repeat("A", 64<<10)
	for i := 0; i < (maxBodyBytes/(64<<10))+2; i++ { // ruim over de limiet
		if _, err := fmt.Fprintf(c, "%x\r\n%s\r\n", len(chunk), chunk); err != nil {
			break // de server mag de verbinding al dichtgooien
		}
	}
	fmt.Fprintf(c, "0\r\n\r\n")
	select {
	case err := <-sawErr:
		if err == nil {
			t.Fatal("de handler las een afgekapte upload zonder één fout te zien")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler kwam niet door de body heen")
	}
}

// TestMuxHandlerZietGeschoondPad — de documentatie zegt "een handler ziet nooit
// ..", maar de handler kreeg het oorspronkelijke pad (review 13-08).
func TestMuxHandlerZietGeschoondPad(t *testing.T) {
	m := NewServeMux()
	var saw string
	m.HandleFunc("GET /veilig/{rest...}", func(w ResponseWriter, r *Request) {
		saw = r.Path
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	addr := leanServer(t, m.ServeHTTP)
	rawRoundTrip(t, addr, "GET /veilig/a/../b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if strings.Contains(saw, "..") {
		t.Fatalf("handler zag %q — de .. hoort er vóór de handler uit", saw)
	}
	if saw != "/veilig/b" {
		t.Fatalf("handler zag %q, wil het geschoonde /veilig/b", saw)
	}
}

// TestClientGetGebruiktDePoolMetEigenDial — een Client mét eigen Dial (de
// TLS-vorm) hoort óók te poolen; vóór de fix deed elke Get een verse handshake
// en bleven de gepoolde verbindingen ongebruikt staan (review 13-08).
func TestClientGetGebruiktDePoolMetEigenDial(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	dials := 0
	cl := &Client{Dial: func(network, a string) (net.Conn, error) {
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

// TestClientWeigertHTTPSZonderTLSDialer — een zero-value Client stuurde een
// https-URL als PLAINTEXT naar poort 443 (de pool-dialer is nooit nil, dus de
// wacht in do() zag hem niet).
func TestClientWeigertHTTPSZonderTLSDialer(t *testing.T) {
	cl := &Client{}
	if _, err := cl.Get("https://example.invalid/"); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("https op een kale Client gaf %v, wil een TLS-configuratiefout", err)
	}
	if _, err := cl.Do(Call{URL: "https://example.invalid/"}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("Do https op een kale Client gaf %v, wil een TLS-configuratiefout", err)
	}
}

// TestRedirectStriptAuthorizationCrossOrigin — een token dat meereist naar een
// ándere host is een token dat je aan die host geeft.
func TestRedirectStriptAuthorizationCrossOrigin(t *testing.T) {
	var gotAuth string
	target := leanServer(t, func(w ResponseWriter, r *Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, "einde")
	})
	// 127.0.0.1 → localhost: zelfde machine, ándere hostnaam = andere origin.
	host, port, _ := net.SplitHostPort(target)
	_ = host
	hopAddr := leanServer(t, func(w ResponseWriter, r *Request) {
		Redirect(w, "http://localhost:"+port+"/", 302)
	})
	resp, err := Do(Call{URL: "http://" + hopAddr + "/", Header: Header{"Authorization": "Bearer geheim"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	if gotAuth != "" {
		t.Fatalf("Authorization %q kwam mee naar de andere origin", gotAuth)
	}
}

// TestServerUploadVanExactDeLimietIsGeldig — de eerste versie van de
// upload-grens keurde exact-1-MiB af: na de laatste byte stond de teller op
// nul terwijl de nul-chunk nog ongelezen was (review 13-08, tweede ronde).
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
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	chunk := strings.Repeat("A", 64<<10)
	for sent := 0; sent < maxBodyBytes; sent += len(chunk) {
		fmt.Fprintf(c, "%x\r\n%s\r\n", len(chunk), chunk)
	}
	fmt.Fprintf(c, "0\r\n\r\n")
	select {
	case r := <-got:
		if r.err != nil || r.n != maxBodyBytes {
			t.Fatalf("handler las (%d, %v), wil (%d, nil) — exact de limiet is geldig", r.n, r.err, maxBodyBytes)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler kwam niet door de body")
	}
}

// TestServerZietAfgebrokenContentLength — een client die 10 belooft en na 5
// sluit is een afgebroken verzoek; met io.LimitReader las de handler een half
// verzoek als compleet (review 13-08, tweede ronde).
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
	c.Close() // 5 van de 10 beloofde bytes
	select {
	case err := <-got:
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("handler las %v, wil io.ErrUnexpectedEOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler bleef hangen op de afgebroken body")
	}
}

// TestServerWeigertTEIdentity — "identity" is in een verzoek geen codering
// maar een gat: het verzoek werd bodyloos gelezen en de échte bytes werden het
// volgende verzoek (review 13-08, tweede ronde).
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

// TestWriterIsEigenaarVanDeFraming — een handler die zelf Transfer-Encoding
// zet terwijl de writer op het lengte-pad zit, produceerde TE én
// Content-Length met een ongechunkte body; en een expliciete CL bleef op een
// 204 staan (review 13-08, tweede ronde).
func TestWriterIsEigenaarVanDeFraming(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		if r.Path == "/te" {
			w.Header().Set("Transfer-Encoding", "chunked") // niet aan de handler
			io.WriteString(w, "body")
			return
		}
		w.Header().Set("Content-Length", "5") // hoort niet op een 204
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

// TestRedirectStriptOokBijAnderePoort — dezelfde hostnaam op een andere poort
// is een ándere origin: een token dat meereist bereikt een tweede dienst op
// dezelfde machine (review 13-08, tweede ronde).
func TestRedirectStriptOokBijAnderePoort(t *testing.T) {
	var gotAuth string
	target := leanServer(t, func(w ResponseWriter, r *Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	hop := leanServer(t, func(w ResponseWriter, r *Request) {
		Redirect(w, "http://"+target+"/", 302) // zelfde 127.0.0.1, andere poort
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

// TestEigenDialBlijftBuitenDePool — een per-call transport hoort niet in de
// gedeelde pool te belanden: een volgende Get zou een verbinding van een ánder
// transport krijgen (review 13-08, tweede ronde).
func TestEigenDialBlijftBuitenDePool(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	cl := &Client{}
	defer cl.CloseIdle()
	resp, err := cl.Do(Call{URL: "http://" + addr + "/", Dial: func(network, a string) (net.Conn, error) {
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

// TestConnectionAlsTokenlijst — "Connection: upgrade, close" draagt een close;
// als hele string vergeleken werd de verbinding tóch gepoold.
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

// TestClientWeigertVreemdeTEInRespons — élke niet-chunked TE als chunked lezen
// legt het einde op de verkeerde plek: luid falen.
func TestClientWeigertVreemdeTEInRespons(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nrommel")
	if _, err := Do(Call{URL: "http://" + addr + "/"}); err == nil || !strings.Contains(err.Error(), "Transfer-Encoding") {
		t.Fatalf("respons met TE: gzip gaf %v, wil een framing-fout", err)
	}
}

// TestRedirectNaarHTTPSGaatNooitPlaintext — een 301 van http naar https op een
// Client zonder TLS-dialer schreef het verzoek (mét Authorization, zelfde
// host!) plaintext naar poort 443: de schemewacht gold alleen voor de eerste
// URL (review 13-08, derde ronde).
func TestRedirectNaarHTTPSGaatNooitPlaintext(t *testing.T) {
	leaked := make(chan string, 1)
	// De "poort 443" van deze test: als hier óóit bytes aankomen, is het lek er.
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

// TestChunkAfgekaptVoorDeCRLF — sterft de verbinding precies tussen chunkdata
// en de afsluitende CRLF, dan gold de body als compleet en ging de dode
// verbinding de pool in (review 13-08, derde ronde).
func TestChunkAfgekaptVoorDeCRLF(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhallo")
	cl := &Client{}
	defer cl.CloseIdle()
	resp, err := cl.Do(Call{URL: "http://" + addr + "/"}) // Do: Get weigert chunked per contract
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

// TestPooledConnNestNiet — dial wikkelde de verbinding uit de pool in een
// verse pooledConn en put sloeg die wrapper op: elke hergebruiksronde een laag
// erbij, een poller van 1 req/s draagt er na een dag ~86k (review 13-08,
// derde ronde).
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

// TestDataPlusEOFPooltDeDodeVerbindingNiet — een verbinding die de laatste
// body-byte en zijn EOF in één Read levert (TLS-close_notify) is compleet om
// te lezen maar dood om te hergebruiken (review 13-08, derde ronde).
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

// dataPlusEOF levert alles in één Read, mét io.EOF erachteraan geplakt.
type dataPlusEOF struct{ data []byte }

func (d dataPlusEOF) Read(p []byte) (int, error) {
	n := copy(p, d.data)
	return n, io.EOF
}

// TestMuxDollarPanicktMetAlternatief — {$} is gesloopt (zevenentwintigste
// ronde): een vast pad (zonder slash) en een subtree (mét) dekken samen elke
// echte routetabel. Registreren panickt en noemt het alternatief.
func TestMuxDollarPanicktMetAlternatief(t *testing.T) {
	defer func() {
		p := recover()
		if p == nil || !strings.Contains(p.(string), "{$}") {
			t.Fatalf("geen (of onduidelijke) panic op {$}: %v", p)
		}
	}()
	NewServeMux().HandleFunc("GET /logs/{$}", func(w ResponseWriter, r *Request) {})
}

// TestHandlerKanContentLengthNietOverschrijden — de surplus-bytes van een
// handler die voorbij zijn eigen Content-Length schrijft stonden al op de
// draad toen finish het zag: op keep-alive het begin van het volgende
// antwoord. Nu: short-write plus fout, en exact N bytes op de draad
// (review 13-08, vijfde ronde).
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

// TestCallMethodInjectieGeweigerd — een methode met CRLF is een tweede verzoek
// in vermomming (review 13-08, vijfde ronde).
func TestCallMethodInjectieGeweigerd(t *testing.T) {
	_, err := Do(Call{URL: "http://127.0.0.1:1/", Method: "GET / HTTP/1.1\r\nX-Evil: 1\r\n\r\nGET"})
	if err == nil || !strings.Contains(err.Error(), "invalid method") {
		t.Fatalf("geïnjecteerde methode gaf %v, wil een method-validatiefout (vóór de dial)", err)
	}
}

// TestContentLengthMutatieOmzeiltDeControleNiet — een handler die de lengte ná
// zijn eerste write "bijwerkt" praatte finish om: die las de mutabele map, niet
// de draad. De maat is w.declared; de draad beloofde 10, dus de verbinding is
// op (review 13-08, zevende ronde).
func TestContentLengthMutatieOmzeiltDeControleNiet(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "10")
		io.WriteString(w, "12345") // de draadkop met CL=10 is nu gebouwd
		w.Header().Set("Content-Length", "5")
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	// Twee verzoeken gepijplijnd: het tweede mag NOOIT beantwoord worden — de
	// eerste response is onvolledig (5 van de beloofde 10 bytes), dus de
	// server hoort te sluiten.
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
	all, _ := io.ReadAll(c)
	if n := strings.Count(string(all), "HTTP/1.1 200"); n != 1 {
		t.Fatalf("%d antwoorden op een verbinding met een gebroken lengtebelofte, wil 1 (dan dicht)", n)
	}
}

// TestOverrunLaatDeVerbindingLeven — na het afkappen staat er op de draad een
// exact kloppende response, en de kop had keep-alive al beloofd: sluiten liet
// de client een net gepoolde verbinding op het volgende verzoek stuklopen.
// De handlerfout en de transportstatus zijn twee verschillende dingen
// (review 13-08, zevende ronde).
func TestOverrunLaatDeVerbindingLeven(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		io.WriteString(w, "12345")
		io.WriteString(w, "SMOKKEL") // afgekapt + fout voor de handler
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

// TestUitgaandeHeadernaamStrikt — ook een tab in een verzoekheadernaam is een
// injectie; en een respons met een ongeldige headernaam wordt geweigerd
// (dezelfde tokenwacht aan beide kanten, review 13-08, zevende ronde).
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

// TestHeaderTimeoutLooptNietTijdensDeUpload — het contract zegt "alleen het
// wachten op de antwoordkop", maar de termijn stond al tijdens het versturen
// van de body aan: een trage upload sneuvelde op de header-timeout terwijl er
// niets mis was (review 13-08, negende ronde). De server hieronder leest de
// body bewust trager dan de header-termijn.
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
		time.Sleep(400 * time.Millisecond) // de client-write loopt vol en blokkeert
		io.Copy(io.Discard, io.LimitReader(c, 1<<30))
		// io.Copy eindigt pas op EOF; antwoord vóór die tijd kan niet — dus
		// lees precies genoeg en antwoord dan. Simpeler: het antwoord komt
		// zodra de read-lus de buffer leeg heeft; de deadline hierboven dekt
		// de rest. (De client leest tot zijn eigen deadline.)
	}()

	body := bytes.Repeat([]byte("A"), 4<<20) // 4MB: ruim voorbij elke socketbuffer
	_, err = Do(Call{
		URL:           "http://" + l.Addr().String() + "/",
		Method:        "PUT",
		BodyReader:    bytes.NewReader(body),
		BodyLen:       int64(len(body)),
		HeaderTimeout: 150 * time.Millisecond, // korter dan de server-slaap
		Timeout:       10 * time.Second,
	})
	// De kop komt nooit (de server antwoordt niet) — maar de fout mag NIET
	// tijdens de upload vallen: met de oude volgorde faalde de body-write op
	// de header-termijn ("stream body ... timeout"), nu wacht de kop-lezer op
	// zijn eigen termijn ("read status line").
	if err == nil {
		t.Fatal("verwachtte een fout (de server antwoordt nooit)")
	}
	if strings.Contains(err.Error(), "stream body") {
		t.Fatalf("de upload sneuvelde op de header-termijn: %v", err)
	}
}

// TestVreemdeProtocolversieWordtGeweigerd — HTTP/9.9 accepteren betekent
// gokken over framing en persistentie; hij kon zelfs de pool in.
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

// TestMuxWeigertAmbigueRoutes — /users/{id} en /users/{name} verschillen
// alleen in de wildcardnaam (de tweede is onbereikbaar), en kruisende patronen
// met gelijke score werden stil door registratievolgorde beslist
// (review 13-08, negende ronde).
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

	// Verschíllende score blijft toegestaan: specificiteit beslist.
	m3 := NewServeMux()
	m3.HandleFunc("GET /a/{x}", h)
	m3.HandleFunc("GET /a/b", h) // hogere score, geen conflict
}

// TestTimeoutDektDeHeleRedirectKeten — elke redirect kreeg een verse Timeout:
// een call met 600ms kon door drie trage hops ~1,8s duren (review 13-08,
// tiende ronde). Twee hops van elk ~400ms tegen een totaal van 600ms.
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

// TestMuxWeigertOngeldigeVormen — segmenten ná {rest...}, dubbele
// wildcardnamen, lege accolades én de dekking-dubbeling /files/ vs
// /files/{rest...} (review 13-08, tiende ronde).
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

// TestTrageBodyGijzeltGeenGoroutine — een client die een Content-Length
// belooft en stilvalt liet een handler in io.ReadAll eeuwig wachten: de
// leestermijn werd vóór de handler gewist en de drain-termijn kwam nooit aan
// bod (review 13-08, tiende ronde).
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
	// ... en dan stilte, zonder te sluiten.
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("de handler las een gestokte body als compleet")
		}
	case <-time.After(bodyTimeout + 3*time.Second):
		t.Fatal("de handler hangt nog — de body-termijn bestaat niet")
	}
}

// TestDoneOverleeftDeBodyTimeout — serveConn wapent vóór de handler een
// leestermijn op een body-dragend verzoek; de wachthond van Done() leest op
// diezelfde verbinding, en een read-fout betekent voor hem "de kijker is weg".
// Een POST-streamer die eerst netjes zijn body las en dán Done() aanriep
// (precies wat de docs voorschrijven) zag zijn stream dus na ~5s spontaan
// verlaten (review 13-08, elfde ronde). Done() hoort de termijn te wissen,
// zoals Hijack dat doet. Deze test kost bewust bodyTimeout+1s: korter is geen
// bewijs.
func TestDoneOverleeftDeBodyTimeout(t *testing.T) {
	verdict := make(chan bool, 1) // true = Done vuurde terwijl de kijker er nog was
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
	// ... en dan blijven we rustig kijken, zonder te sluiten.
	if <-verdict {
		t.Fatal("Done() vuurde terwijl de client er nog is — de bodyTimeout at de wachthond op")
	}
}

// TestPoolDialValtOnderDeTotaaltermijn — de klem van de tiende ronde zat alleen
// in de kale dialer van do(); via een Client dialde de eigen fallback met de
// vaste dialTimeout, dus hing een Call.Timeout van 300ms alsnog 10s op een
// onbereikbare host (review 13-08, elfde ronde).
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

// TestServerEistEenGeldigeHost — HTTP/1.1 zonder Host, met lege Host of met
// twee Hosts is achter een proxy een routerings-smokkelgat; en een methode
// met rare bytes idem (review 13-08, tiende ronde).
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
	// HTTP/1.0 zonder Host blijft legaal.
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.0\r\n\r\n"); !strings.Contains(got, "200") {
		t.Fatalf("HTTP/1.0 zonder Host gaf %q, wil een 200", got)
	}
}

// TestEigenDialValtOnderDeTotaaltermijn — een eigen Call.Dial (een
// TLS-handshake bijvoorbeeld) kent alleen (network, addr) en hing dus vrolijk
// door terwijl de totaaltermijn al om was; en de verbinding die hij te láát
// alsnog oplevert moet dicht, anders lekt hij (review 13-08, twaalfde ronde).
func TestEigenDialValtOnderDeTotaaltermijn(t *testing.T) {
	closed := make(chan struct{})
	start := time.Now()
	_, err := Do(Call{
		URL:     "http://x/",
		Timeout: 150 * time.Millisecond,
		Dial: func(network, addr string) (net.Conn, error) {
			time.Sleep(600 * time.Millisecond) // een handshake die blijft hangen
			c1, _ := net.Pipe()
			return closeSignal{Conn: c1, done: closed}, nil
		},
	})
	if err == nil {
		t.Fatal("een dial voorbij de totaaltermijn hoort te falen")
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Fatalf("Do keerde pas na %v terug — de termijn wacht op de eigen dialer", d)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("de te laat opgeleverde verbinding is nooit gesloten — dat lekt")
	}
}

// closeSignal meldt zijn eigen Close — voor de lek-toets hierboven.
type closeSignal struct {
	net.Conn
	done chan struct{}
}

func (c closeSignal) Close() error { close(c.done); return c.Conn.Close() }

// fakeSink is een net.Conn-stub voor de schrijftermijn-test: hij noteert per
// socket-write of er op dat moment een schrijftermijn stond.
type fakeSink struct {
	deadline time.Time
	unarmed  int // socket-writes zónder termijn
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

// TestGroteWriteWapentDeSchrijftermijn — de schrijftermijn stond alleen in
// flush(), maar bufio schrijft bij een volle buffer of een grote p zélf al
// door naar de socket: een client die niet leest blokkeerde de handler dan al
// vóór zijn Flush, onbegrensd (review 13-08, twaalfde ronde).
func TestGroteWriteWapentDeSchrijftermijn(t *testing.T) {
	f := &fakeSink{}
	c := &conn{nc: f, br: bufio.NewReaderSize(f, bufSize), bw: bufio.NewWriterSize(&timedWriter{nc: f}, bufSize)}
	w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: true, declared: -1}
	big := int64(3 * bufSize)
	w.Header().Set("Content-Length", strconv.FormatInt(big+2, 10))
	if _, err := w.Write([]byte("hi")); err != nil { // kop eruit, rechtstreeks pad
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil { // wist de termijn — zoals tussen twee frames
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, big)); err != nil { // past nooit: schrijft dóór
		t.Fatal(err)
	}
	if f.unarmed > 0 {
		t.Fatalf("%d socket-write(s) zonder schrijftermijn — een niet-lezende client gijzelt de handler vóór Flush", f.unarmed)
	}
}

// TestKaleLFIsGeenRegel — een regel die op een kale LF eindigt is bij de ene
// parser een regel en bij de andere deel van de vorige: exact CRLF is de
// enige vorm zonder differentiaal (review 13-08, dertiende ronde).
func TestKaleLFIsGeenRegel(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.1\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("kale LF gaf %q, wil een 400", got)
	}
}

// TestContentLengthAlleenCijfers — ParseInt accepteerde "+5": voor ons een 5,
// voor een proxy ervóór mogelijk een fout of iets anders — precies het
// framing-verschil waar smuggling op drijft (review 13-08, dertiende ronde).
func TestContentLengthAlleenCijfers(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\nConnection: close\r\n\r\nAAAAA"); !strings.Contains(got, "400") {
		t.Fatalf("Content-Length +5 gaf %q, wil een 400", got)
	}
	// De clientkant weigert een antwoord met zo'n lengte net zo hard.
	srv := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok")
	if _, err := Do(Call{URL: "http://" + srv + "/"}); err == nil {
		t.Fatal("een antwoord met Content-Length +2 hoort een fout te zijn")
	}
}

// TestControlByteInHeaderIsFout — een CTL in een headerwaarde (of een losse
// CR, nu de regel exact op CRLF moet eindigen) is een injectievector, geen
// waarde (review 13-08, dertiende ronde).
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

// TestChunkgrootteAlleenHex — zelfde strengheid voor de chunk-framing: "+3"
// is geen grootte (review 13-08, dertiende ronde).
func TestChunkgrootteAlleenHex(t *testing.T) {
	// Exact 1*HEXDIG (RFC 9112 §7.1): ook OWS eromheen is een fout — juist
	// bij framing geen tolerantie (review 13-08, zeventiende ronde).
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

// TestSpillLaatGeenTermijnAchter — de gewapende termijn van een
// doorschrijvende write moet ná die write weer uit: hij verliep anders stil
// tijdens het rekenen van de handler, in strijd met "per schrijfronde, niet
// per antwoord" (review 13-08, dertiende ronde).
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

// TestStatuscodeExactDrieCijfers — Atoi accepteerde "+200" en " 20": de
// statuscode stuurt bodyAllowed, de 1xx-lus én de hergebruik-beslissing, dus
// hier geldt hetzelfde cijfers-only-regime als bij Content-Length
// (review 13-08, veertiende ronde).
func TestStatuscodeExactDrieCijfers(t *testing.T) {
	for _, status := range []string{"+200", "+20", "20", "2000", "0200", "2O0"} {
		srv := rawServer(t, "HTTP/1.1 "+status+" OK\r\nContent-Length: 2\r\n\r\nok")
		if _, err := Do(Call{URL: "http://" + srv + "/"}); err == nil {
			t.Fatalf("statuscode %q werd geaccepteerd", status)
		}
	}
}

// TestSyntaxfoutDraintNiet — de drain ná een 400 is er voor een aangekondigde
// body die nog binnenkomt; bij een pure syntaxfout is het verzoek al binnen
// en pinde de onvoorwaardelijke drain goroutine, socket en (op leannet)
// budget twee volle seconden per malformed request (review 13-08, vijftiende
// ronde).
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

// TestUitgaandeHeaderwaardeStrikt — reader en writers spreken dezelfde
// grammatica (validFieldValue): een NUL in een headerwaarde kwam uitgaand
// gewoon op de draad, waarna leanhttp hem zelf geweigerd zou hebben
// (review 13-08, vijftiende ronde).
func TestUitgaandeHeaderwaardeStrikt(t *testing.T) {
	// Clientkant: een fout vóór de dial, geen draadbytes.
	_, err := Do(Call{URL: "http://127.0.0.1:1/", Header: Header{"X-A": "a\x00b"}})
	if err == nil || !strings.Contains(err.Error(), "illegal value") {
		t.Fatalf("kreeg %v, wil een illegal-value-fout vóór de dial", err)
	}
	// Serverkant: de kop wordt overgeslagen, niet doorgegeven.
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

// TestDialContextWordtGeannuleerd — DialContext draagt de totaaltermijn als
// context-deadline, dus de dialer kan écht opgeven: bij Dial begrenst
// dialBounded alleen het wachten (review 13-08, vijftiende ronde).
func TestDialContextWordtGeannuleerd(t *testing.T) {
	canceled := make(chan struct{})
	start := time.Now()
	_, err := Do(Call{
		URL:     "http://x/",
		Timeout: 150 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done() // een dialer die netjes op zijn context let
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

// TestHEADValtTerugOpGET — net/http-semantiek: een GET-route bedient ook
// HEAD, met dezelfde kop en zonder body-bytes (review 13-08, vijftiende
// ronde).
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

// TestExacteHEADRouteGaatVoorDeTerugval — de GET→HEAD-terugval vuurt pas als
// er géén exacte HEAD-route is: beide routes krijgen dezelfde score, dus
// meteen vuren liet registratievolgorde beslissen — precies de ambiguïteit
// die conflictsWith elders afstraft (review 13-08, zestiende ronde).
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

// TestResponseMetDubbeleFramingIsFout — de client keurde elke TE-regel los
// goed en liet "chunked wint" beslissen, waarna de verbinding met een
// dubbelzinnig geframed antwoord de pool in kon: twee parsers kunnen op zo'n
// antwoord een ander einde zien (review 13-08, zeventiende ronde).
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

// TestOngeldigeContentLengthGaatDeDraadNietOp — "abc" of "+5" is zichtbare
// ASCII en glipte langs validFieldValue de draad op, mét keep-alive-belofte,
// terwijl dezelfde waarde inkomend een 400 is. Nu: kop eraf, verbinding
// dicht, framing op EOF (review 13-08, zeventiende ronde).
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
	// En óók op een HEAD: suppressBody sloeg de validatie eerst helemaal over
	// (review 13-08, negentiende ronde).
	got = rawRoundTrip(t, addr, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
	if strings.Contains(got, "abc") {
		t.Fatalf("HEAD-antwoord %q: de ongeldige lengte staat op de draad", got)
	}
}

// TestTerugvalWintVanGeneriekeRoute — "GET /x" is ook voor HEAD specifieker
// dan "/x": de terugval-kandidaat verloor eerst van élke exacte match, ook
// een lager gescoorde methode-loze route (review 13-08, zeventiende ronde).
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

// TestChunkExtensieEnTrailerStrikt — de chunkgrootte was al strikt, maar
// alles ná de ";" werd ongevalideerd weggegooid en trailers alleen
// overgeslagen: malformed extensies, kapotte trailerregels en verboden
// framing-trailers passeerden stil (review 13-08, negentiende ronde).
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
	// En een nette trailer blijft gewoon werken.
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

// TestMuxKruisendePatronenConflicteren — de oude toets liet overlappende
// patronen door zodra hun scóres verschilden, maar een score is een telsom,
// geen subsetrelatie: GET /a/{x}/{y} en GET /{x}/b/c matchen beide /a/b/c
// zonder dat één een subset is — "meer literals" koos dan de handler, en dus
// mogelijk de verkeerde autorisatie (review 13-08, eenentwintigste ronde).
// Alleen een strikte subset mag naast zijn superset bestaan (Go 1.22-regel).
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
	// Kruisers: overlap zonder subsetrelatie.
	expectPanic("kruisende wildcards", "GET /a/{x}/{y}", "GET /{x}/b/c")
	expectPanic("kruisend met subtree", "GET /a/{x}/", "GET /{x}/b/")
	// Strikte subsets blijven gewoon toegestaan.
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

// TestMuxGETKruistHEAD — methoden zijn sets (HEAD ⊂ GET ⊂ ""): GET /a/{x} en
// HEAD /{x}/b matchen beide HEAD /a/b zonder subsetrelatie en horen dus te
// conflicteren; de vorige toets zag GET en HEAD als disjunct (review 13-08,
// tweeëntwintigste ronde). De strikte subset HEAD /x onder GET /x blijft wél
// toegestaan.
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
	m.HandleFunc("HEAD /x", h) // strikte subset: mag
}

// TestMuxSlashIsEenAnderPad — /admin en /admin/ vielen bij het matchen samen
// en het vaste patroon won op scorepunten: precies de wortel van een
// beveiligde subtree belandde zo bij de publieke handler (review 13-08,
// tweeëntwintigste ronde). Het slash-model: vast = exact dit pad zonder
// slash, subtree = wortel mét slash plus alles eronder.
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
	// En een vast patroon matcht zijn slash-vorm niet.
	m2 := NewServeMux()
	m2.HandleFunc("GET /health", tagged("gezond"))
	addr2 := leanServer(t, m2.ServeHTTP)
	if got := rawRoundTrip(t, addr2, "GET /health/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "404") {
		t.Fatalf("/health/ op een vast /health-patroon gaf %q, wil een 404", got)
	}
}

// TestRedirectAlleenVoorGETEnHEAD — "geen body" was een proxy voor "veilig te
// herhalen": een bodyloze DELETE werd stil op de nieuwe URL heruitgevoerd, en
// zelfs een 304 mét Location werd gevolgd (review 13-08, tweeëntwintigste
// ronde). Alleen 301/302/303/307/308 en alleen GET/HEAD volgen automatisch.
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
	// 304 is cache-validatie, geen doorverwijzing — ook niet mét Location.
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

// TestMethodeIsHoofdlettergevoelig — methode-tokens zijn hoofdlettergevoelig
// (RFC 9110 §9.1): "head" is een ándere, custom methode dan HEAD. De server
// onderdrukte er wél de body voor (met een lengte in de kop: de client bleef
// op bytes wachten), en de client sloeg er een échte body voor over en poolde
// de verbinding met ongelezen bytes (review 13-08, drieëntwintigste ronde).
func TestMethodeIsHoofdlettergevoelig(t *testing.T) {
	// Serverkant: "head" krijgt gewoon de volledige body.
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		io.WriteString(w, "hallo")
	})
	if got := rawRoundTrip(t, addr, "head / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "hallo") {
		t.Fatalf("antwoord op 'head' mist de body: %q", got)
	}
	// Clientkant: een antwoord op "head" draagt een echte body en die hoort
	// gelezen te worden, niet overgeslagen als ware het HEAD.
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

// TestAmbigueEscapesWordenGeweigerd — het antwoord op de %2F/%2E-klasse is
// sinds de zevenentwintigste ronde WEIGEREN in plaats van afhandelen: een
// segment dat naar "/", "." of ".." decodeert is een 400 aan de deur, en een
// onschuldige escape (%61 = 'a') decodeert gewoon — middleware, Mux en
// handler zien daardoor per constructie hetzelfde pad.
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
	// Onschuldige escapes decoderen aan de deur: /%61dmin ís /admin.
	if got := rawRoundTrip(t, addr, "GET /%61dmin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "X-Handler: admin") {
		t.Fatalf("antwoord %q: een onschuldige escape hoort gewoon te routeren", got)
	}
}

// TestLegeBodyPooltDirect — een bewezen-lege body (204, HEAD, CL:0) is bij
// constructie al "gelezen": een caller die alleen netjes Close doet (de
// DELETE→204-route) sloot anders elke keer de verbinding en betaalde per
// delete een handshake (review 13-08, drieëntwintigste ronde).
func TestLegeBodyPooltDirect(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNoContent)
	})
	cl := &Client{}
	resp, err := cl.Do(Call{Method: "DELETE", URL: "http://" + addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() // zonder Read: het einde is al bewezen
	if n := cl.idleFor(addr); n != 1 {
		t.Fatalf("pool draagt %d verbindingen na een 204-Close, wil 1", n)
	}
}

// TestMiddlewareEnMuxZienHetzelfdePad — het pad wordt bij het parsen al
// geschoond (escaped vorm): middleware die /public/../admin goedkeurde zag
// een ander pad dan de Mux daarna routeerde, en een rewrite van r.Path door
// middleware werd genegeerd omdat de Mux een privé escaped pad las
// (review 13-08, vierentwintigste ronde).
func TestMiddlewareEnMuxZienHetzelfdePad(t *testing.T) {
	m := NewServeMux()
	m.HandleFunc("/admin", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "admin") })
	m.HandleFunc("/intern", func(w ResponseWriter, r *Request) { w.Header().Set("X-Handler", "intern") })
	var zagPad string
	middleware := func(w ResponseWriter, r *Request) {
		zagPad = r.Path
		if r.Path == "/admin" {
			r.Path = "/intern" // een rewrite hoort gewoon te tellen
		}
		m.ServeHTTP(w, r)
	}
	addr := leanServer(t, middleware)
	got := rawRoundTrip(t, addr, "GET /public/../admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if zagPad != "/admin" {
		t.Fatalf("middleware zag %q — een ander pad dan de Mux routeert", zagPad)
	}
	if !strings.Contains(got, "X-Handler: intern") {
		t.Fatalf("antwoord %q: de rewrite door middleware is genegeerd", got)
	}
}

// TestEscapedLiteralInPatroonPanickt — verzoekpaden zijn bij het parsen al
// gedecodeerd, dus een %-escape in een patroon-literal zou nooit matchen:
// bedradingsfout, paniek (review 13-08, zevenentwintigste ronde).
func TestEscapedLiteralInPatroonPanickt(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("geen panic op een percent-escape in een patroon-literal")
		}
	}()
	NewServeMux().HandleFunc("GET /objects/secret%2Fmetadata", func(w ResponseWriter, r *Request) {})
}

// TestLegeFramingheaderVerdwijntNiet — hdr.add zag een lege waarde als "niet
// aanwezig": "Content-Length:" + "Content-Length: 5" werd één geldige lengte,
// een klassiek smuggling-differentiaal. Framingheaders tellen nu per fysieke
// regel (review 13-08, vierentwintigste ronde).
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

// TestGeenPoolMetOngelezenBytes — een bewezen-lege body is direct compleet,
// maar de reader kan een ongevraagd vooruitgestuurd "antwoord" bevatten: dan
// zou call 2 zijn verzoek schrijven en dát lezen (review 13-08,
// vierentwintigste ronde). Nooit poolen met br.Buffered() != 0.
func TestGeenPoolMetOngelezenBytes(t *testing.T) {
	addr := rawServer(t, "HTTP/1.1 204 No Content\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n") // de smokkelwaar
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

// TestIdleTimeoutRuimtZelfOp — de sweep draaide alleen bij een vólgend
// verzoek: na het laatste verzoek bleef een gepoolde verbinding onbeperkt
// staan, en op leannet houdt die minstens 20KiB pot vast — precies het
// geheugendoel dat de pool moest dienen (review 13-08, vierentwintigste
// ronde). Nu timer-gedreven.
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
	time.Sleep(600 * time.Millisecond) // ruim voorbij timeout + marge
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("pool draagt na de idle-timeout nog %d verbindingen — niemand ruimt op", n)
	}
}

// --- ronde 25 ---

// TestStaleKeepAliveKrijgtEenHerkansing — een server die zijn idle
// keep-alive netjes sluit gaf de volgende call een zichtbare fout; nu één
// veilige herkansing (niets van het antwoord geconsumeerd, het hele verzoek
// gaat opnieuw) — review 13-08, vijfentwintigste ronde.
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
				// Eén antwoord (mét keep-alive-belofte), dan hard dicht.
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
		time.Sleep(120 * time.Millisecond) // de server sluit; de pool weet dat niet
	}
}

// TestBodyDeadlineGeldtOokVoorGebufferdeBytes — de conn-deadline dekt alleen
// socket-reads: bytes die de bufio al binnen had, lazen vrolijk door een
// verlopen Call.Timeout heen (review 13-08, vijfentwintigste ronde).
func TestBodyDeadlineGeldtOokVoorGebufferdeBytes(t *testing.T) {
	srv := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
	resp, err := Do(Call{URL: "http://" + srv + "/", Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	time.Sleep(300 * time.Millisecond) // de termijn verloopt; de bytes zijn al gebufferd
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("een verlopen totaaltermijn las gebufferde bytes gewoon door")
	}
}

// deadlineWeigeraar is een net.Conn waarvan de deadline-wis faalt.
type deadlineWeigeraar struct{ fakeSink }

func (deadlineWeigeraar) SetDeadline(time.Time) error { return errors.New("kapot") }

// TestKapotteDeadlineWisPooltNiet — een transport dat de deadline-wis weigert
// is niet herbruikbaar (review 13-08, vijfentwintigste ronde).
func TestKapotteDeadlineWisPooltNiet(t *testing.T) {
	cl := &Client{}
	if cl.put("x", &deadlineWeigeraar{}, nil) {
		t.Fatal("put accepteerde een verbinding waarvan de deadline-wis faalt")
	}
}

// TestCloseBreektGeblokkeerdeRead — het contract staat een Close toe die een
// geblokkeerde Read afbreekt; done/shut zijn nu bewaakt (race-detector dekt
// dit onder -race) — review 13-08, vijfentwintigste ronde.
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
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf") // en dan stilte
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

// TestEenRegelPerHeadernaam — directe mapwrites konden twee case-varianten
// van Content-Length op de draad zetten waarvan er één gevalideerd was
// (review 13-08, vijfentwintigste ronde).
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

// TestHijackNaGebufferdeWriteWeigert — de Write rapporteerde succes; een
// geslaagde Hijack liet die bytes stil verdwijnen (review 13-08,
// vijfentwintigste ronde).
func TestHijackNaGebufferdeWriteWeigert(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, "x") // gebufferd: nog niets de deur uit
		if _, _, err := w.Hijack(); err == nil {
			t.Error("Hijack slaagde na een gebufferde Write")
		}
	})
	rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
}

// TestHandlerConnectionCloseWint — de writer overschreef een expliciete
// handler-"Connection: close" met keep-alive (review 13-08, vijfentwintigste
// ronde).
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

// TestWriteHeader1xxIsGeenEindstatus — WriteHeader(103) maakte elke latere
// 200 onzichtbaar (review 13-08, vijfentwintigste ronde).
func TestWriteHeader1xxIsGeenEindstatus(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.WriteHeader(103)
		w.WriteHeader(200)
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, " 200 ") || strings.Contains(got, " 103 ") {
		t.Fatalf("antwoord %q: 103 werd als eindstatus behandeld", got)
	}
}

// TestHTTP10KrijgtGeenChunked — een 1.0-client kent die framing niet: een
// stream wordt daar close-delimited (review 13-08, vijfentwintigste ronde).
func TestHTTP10KrijgtGeenChunked(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, "stukje")
		w.Flush() // zonder lengte: op 1.1 wordt dit chunked
		io.WriteString(w, " twee")
	})
	got := rawRoundTrip(t, addr, "GET / HTTP/1.0\r\n\r\n")
	if strings.Contains(strings.ToLower(got), "chunked") {
		t.Fatalf("antwoord %q: chunked naar een HTTP/1.0-client", got)
	}
	if !strings.Contains(got, "Connection: close") || !strings.HasSuffix(got, "stukje twee") {
		t.Fatalf("antwoord %q: wil een close-delimited stroom", got)
	}
}

// TestExpect100Continue — de server stuurt de 100 zodat client en handler
// niet tot de bodyTimeout op elkaar wachten (review 13-08, vijfentwintigste
// ronde).
func TestExpect100Continue(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Write(b)
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "100") {
		t.Fatalf("geen 100 Continue (kreeg %q, %v) — client en handler wachten op elkaar", line, err)
	}
	br.ReadString('\n') // de lege regel van het interim
	fmt.Fprintf(c, "ping")
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "200") || !strings.HasSuffix(string(rest), "ping") {
		t.Fatalf("eindantwoord %q, wil 200 met de ge-echode body", rest)
	}
}

// TestHEADHoudtExplicieteLengte — een handler die op HEAD zélf een correcte
// lengte zette zonder bytes te schrijven, zag hem met nul overschreven
// (review 13-08, vijfentwintigste ronde).
func TestHEADHoudtExplicieteLengte(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "1234")
	})
	got := rawRoundTrip(t, addr, "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(got, "Content-Length: 1234") {
		t.Fatalf("antwoord %q: de expliciete HEAD-lengte is overschreven", got)
	}
}

// TestRestHoudtSluitendeSlash — /files/a/ hoort "a/" te vangen, niet "a"
// (review 13-08, vijfentwintigste ronde).
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

// TestAbsoluteFormEistZelfdeAuthority — een absolute-form target met een
// ándere Host laat twee parsers elk een andere routering kiezen
// (review 13-08, vijfentwintigste ronde).
func TestAbsoluteFormEistZelfdeAuthority(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "GET http://evil/ HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("antwoord %q, wil een 400", got)
	}
	if got := rawRoundTrip(t, addr, "GET http://goed/pad HTTP/1.1\r\nHost: goed\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "200") {
		t.Fatalf("kloppende authority gaf %q, wil 200", got)
	}
}

// TestOriginNormaliseertDefaultPoort — http://host en http://host:80 zijn
// dezelfde origin (review 13-08, vijfentwintigste ronde).
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

// Test304HoudtInformatieveLengte — RFC 9110 §8.6 staat een informatieve
// Content-Length op een 304 toe: server én client gooiden hem weg
// (review 13-08, vijfentwintigste ronde).
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

// TestSpecifiekWintOngeachtVolgorde — / en /{x}/{rest...} kregen in de
// score-vorm allebei 0, waarna registratievolgorde besliste. Er ís geen score
// meer: ServeHTTP kiest per verzoek de meest specifieke match (strikte
// subset) — review 13-08, zevenentwintigste ronde.
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

// TestConflicterendeCasevariantenSluiten — "Content-Length: 2" én
// "content-length: 5" via directe mapwrites: Get valideerde willekeurig de
// één terwijl de map-iteratie de ander uitgaf. Nu deterministisch: het
// conflict gaat er helemaal uit en de verbinding sluit — framing op EOF
// (review 13-08, zevenentwintigste ronde).
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

// TestStaleRetryAlleenReplaySafe — de herkansing van ronde 25 herhaalde élke
// call zonder BodyReader, ook een DELETE: dubbel uitvoeren. Nu alleen
// GET/HEAD (review 13-08, zevenentwintigste ronde).
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
	time.Sleep(120 * time.Millisecond) // de server sloot; de pool weet dat niet

	if _, err := cl.Do(Call{Method: "DELETE", URL: "http://" + l.Addr().String() + "/"}); err == nil {
		t.Fatal("een DELETE op een stale verbinding werd stil herhaald — dat is niet replay-safe")
	}
	if n := deletes.Load(); n != 0 {
		t.Fatalf("de server zag %d DELETE(s) — de herkansing voerde hem alsnog uit", n)
	}
}

// dataOndanksDeadline is een net.Conn-stub met leannet-semantiek: een read
// met beschikbare data levert die data óók bij een verstreken deadline.
type dataOndanksDeadline struct {
	fakeSink
	pending []byte
}

func (d *dataOndanksDeadline) Read(p []byte) (int, error) {
	if len(d.pending) > 0 {
		n := copy(p, d.pending)
		d.pending = d.pending[n:]
		return n, nil
	}
	return 0, os.ErrDeadlineExceeded
}

// TestIdleProbeWeertVoorgeinjecteerdeBytes — bytes die ná het poolen in de
// socketbuffer arriveerden (onzichtbaar voor br.Buffered) horen de
// verbinding bij het POPPEN te diskwalificeren (review 13-08,
// zevenentwintigste ronde). De stub draagt de leannet-semantiek; op de
// stdlib is de probe een no-op (verstreken deadline wint daar altijd).
func TestIdleProbeWeertVoorgeinjecteerdeBytes(t *testing.T) {
	vuil := &dataOndanksDeadline{pending: []byte("HTTP/1.1 200 OK\r\n")}
	if idleClean(vuil, bufio.NewReader(vuil)) {
		t.Fatal("een verbinding met voorgeïnjecteerde bytes werd schoon verklaard")
	}
	schoon := &dataOndanksDeadline{}
	if !idleClean(schoon, bufio.NewReader(schoon)) {
		t.Fatal("een stille verbinding werd afgekeurd")
	}
}

// TestWriteIsEenCommit — Write("ok") gevolgd door WriteHeader(500) leverde
// een 500 mét "ok" als foutbody, en WriteHeader(200) gevolgd door Hijack
// slaagde en liet de status stil verdwijnen (review 13-08, achtentwintigste
// ronde).
func TestWriteIsEenCommit(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		io.WriteString(w, "ok")
		w.WriteHeader(500) // te laat: de Write was de commit
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

// TestHTTP10Regels — chunked request-framing bestaat niet in 1.0 (400), en
// het antwoord spreekt de taal van de vrager: een HTTP/1.0-statusregel
// (review 13-08, achtentwintigste ronde).
func TestHTTP10Regels(t *testing.T) {
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	})
	if got := rawRoundTrip(t, addr, "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("chunked op 1.0 gaf %q, wil een 400", got)
	}
	if got := rawRoundTrip(t, addr, "GET / HTTP/1.0\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.0 ") {
		t.Fatalf("antwoord op 1.0 begint met %q, wil HTTP/1.0", got[:min(20, len(got))])
	}
}

// TestServerRandvormen — de 405 draagt Allow (RFC 9110 §15.5.6), een Host met
// pad- of witruimtetekens is een 400, en de asterisk-form weigeren we
// expliciet (review 13-08, achtentwintigste ronde).
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
		!strings.Contains(got, "GET") || !strings.Contains(got, "PUT") {
		t.Fatalf("405 zonder (volledige) Allow: %q", got)
	}
	if got := rawRoundTrip(t, addr, "GET /x HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("kromme Host gaf %q, wil 400", got)
	}
	if got := rawRoundTrip(t, addr, "OPTIONS * HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"); !strings.Contains(got, "400") {
		t.Fatalf("asterisk-form gaf %q, wil 400", got)
	}
}
