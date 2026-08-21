package leanhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCallContextAnnuleertDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := Do(Call{
			URL:     "http://cancel-dial.test/",
			Context: ctx,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(dialStarted)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		})
		done <- err
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("DialContext werd niet gestart")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Do na bare Context-cancel tijdens dial = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bare Call.Context maakte DialContext niet los")
	}
}

func TestCallContextAnnuleertActieveIO(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	requestSeen := make(chan struct{})
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				close(requestSeen)
				_, _ = io.Copy(io.Discard, br)
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Do(Call{
			URL:     "http://context.test/",
			Context: ctx,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return client, nil
			},
		})
		done <- err
	}()

	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("request bereikte de peer niet")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Do na cancel = %v, wil context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context-cancel maakte geblokkeerde response-read niet los")
	}
}

func TestCallContextStoptCallbackVoorPoolReuse(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	requests := make(chan struct{}, 2)
	go func() {
		br := bufio.NewReader(server)
		for range 2 {
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			requests <- struct{}{}
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	}()

	var dials atomic.Int32
	cl := &Client{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return client, nil
	}}
	defer cl.CloseIdle()
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := cl.Do(Call{URL: "http://pool.test/een", Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cancel() // must no longer be able to close the pooled connection

	resp, err = cl.Do(Call{URL: "http://pool.test/twee"})
	if err != nil {
		t.Fatalf("tweede call gebruikte een door oude context gesloten poolconn: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, wil 1 hergebruikte connection", got)
	}
	if len(requests) != 2 {
		t.Fatalf("server zag %d requests, wil 2", len(requests))
	}
}

func TestCallContextAnnuleertResponseBody(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	bodyStarted := make(chan struct{})
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
		close(bodyStarted)
		_, _ = io.Copy(io.Discard, br)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	resp, err := Do(Call{
		URL:     "http://body-context.test/",
		Context: ctx,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	<-bodyStarted
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("body-read na cancel = %v, wil context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context-cancel maakte geblokkeerde body-read niet los")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

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

func TestGroteBodyWordtNietAfgekapt(t *testing.T) {
	want := bytes.Repeat([]byte("0123456789abcdef"), 20_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
			http.Redirect(w, r, doel.URL+"/twee", http.StatusFound)
		case "/twee":
			http.Redirect(w, r, "/drie", http.StatusMovedPermanently)
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
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			dialedTo = addr
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

func TestDialHookNilConn(t *testing.T) {
	_, err := Do(Call{
		URL:         "https://x.example/y",
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("nil-verbinding zonder fout werd geaccepteerd")
	}
}

func TestChunkedWeigert(t *testing.T) {

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

func TestTeLangeHeaderregelWeigert(t *testing.T) {
	srv := rauweServer(t, "HTTP/1.1 200 OK\r\nX-Groot: "+strings.Repeat("A", bufSize+1)+"\r\nContent-Length: 1\r\n\r\nx")
	if _, err := Get(srv); err == nil || !strings.Contains(err.Error(), "header line exceeds") {
		t.Fatalf("err = %v, wil een te-lange-regel-fout", err)
	}
}

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

	resp, err := Do(Call{URL: srv.URL})
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
		<-r.Context().Done()
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

				buf := make([]byte, 4096)
				c.Read(buf)
				io.WriteString(c, antwoord)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestResponseURLNaRedirect(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/hier/", http.StatusFound)
		default:
			w.Write([]byte("aangekomen"))
		}
	}))
	defer srv.Close()

	resp, err := Do(Call{URL: srv.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if want := srv.URL + "/hier/"; resp.URL != want {
		t.Errorf("Response.URL = %q, want %q", resp.URL, want)
	}
}

func TestNoFollowGeeftDe3xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "consent", Value: "1", Path: "/"})
			http.Redirect(w, r, "/verder", http.StatusFound)
			return
		}
		w.Write([]byte("niet hier komen"))
	}))
	defer srv.Close()

	resp, err := Do(Call{URL: srv.URL + "/start", NoFollow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusFound {
		t.Fatalf("StatusCode = %d, want 302 — NoFollow volgde alsnog", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/verder" {
		t.Errorf("Location = %q", got)
	}
	if len(resp.SetCookie) != 1 {
		t.Fatalf("SetCookie = %v — de cookie van de 3xx-stap hoort hier te zijn", resp.SetCookie)
	}
	if resp.URL != srv.URL+"/start" {
		t.Errorf("Response.URL = %q, want de gevraagde URL", resp.URL)
	}
}

func TestBodyReaderStreamt(t *testing.T) {
	const payload = "dit-zijn-de-bytes-van-een-artifact"
	var gotLen string
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen = r.Header.Get("Content-Length")
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	resp, err := Do(Call{
		Method:     "PUT",
		URL:        srv.URL + "/object",
		BodyReader: strings.NewReader(payload),
		BodyLen:    int64(len(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusCreated {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if string(got) != payload {
		t.Errorf("server kreeg %q, want %q", got, payload)
	}
	if gotLen != fmt.Sprint(len(payload)) {
		t.Errorf("Content-Length = %q, want %d", gotLen, len(payload))
	}
}

func TestBodyReaderTeKort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()

	_, err := Do(Call{
		Method:     "PUT",
		URL:        srv.URL + "/object",
		BodyReader: strings.NewReader("kort"),
		BodyLen:    100,
	})
	if err == nil {
		t.Fatal("een te korte stroom werd geaccepteerd")
	}
	if !strings.Contains(err.Error(), "stream body") {
		t.Errorf("err = %v — hij hoort te zeggen waar het misging", err)
	}
}

func TestBodyReaderEnBodySamen(t *testing.T) {
	_, err := Do(Call{
		Method:     "PUT",
		URL:        "http://127.0.0.1:1/x",
		Body:       []byte("a"),
		BodyReader: strings.NewReader("b"),
		BodyLen:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("err = %v", err)
	}
}

func TestBodyReaderVolgtGeenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oud" {
			http.Redirect(w, r, "/nieuw", http.StatusFound)
			return
		}
		t.Error("Do volgde de redirect met een gestroomde body")
	}))
	defer srv.Close()

	resp, err := Do(Call{
		Method:     "PUT",
		URL:        srv.URL + "/oud",
		BodyReader: strings.NewReader("data"),
		BodyLen:    4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
}

func TestHeaderTimeoutRaaktBodyNiet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		time.Sleep(400 * time.Millisecond)
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	resp, err := Do(Call{URL: srv.URL, HeaderTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("de body liep op de kop-grens stuk: %v", err)
	}
	if string(body) != "data" {
		t.Errorf("body = %q", body)
	}
}

func TestHeaderTimeoutSlaatToe(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(5 * time.Second)
	}()

	start := time.Now()
	_, err = Do(Call{URL: "http://" + l.Addr().String() + "/", HeaderTimeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("een zwijgende server gaf toch een antwoord")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Do wachtte %v op een kop-grens van 200ms", d)
	}
}

func TestBodylessStatusBlokkeertNiet(t *testing.T) {
	for _, code := range []int{StatusNoContent, 304} {

		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			bufio.NewReader(c).ReadString('\n')
			fmt.Fprintf(c, "HTTP/1.1 %d Geen\r\nConnection: keep-alive\r\n\r\n", code)
			time.Sleep(3 * time.Second)
		}()

		done := make(chan error, 1)
		go func() {
			resp, err := Do(Call{Method: "DELETE", URL: "http://" + l.Addr().String() + "/x"})
			if err != nil {
				done <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != code {
				done <- fmt.Errorf("status = %d, want %d", resp.StatusCode, code)
				return
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				done <- err
				return
			}
			if len(b) != 0 {
				done <- fmt.Errorf("body = %q, want leeg", b)
				return
			}

			want := int64(-1)
			if code == StatusNoContent {
				want = 0
			}
			if resp.Length != want {
				done <- fmt.Errorf("Length = %d, want %d", resp.Length, want)
				return
			}
			done <- nil
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("status %d: %v", code, err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("status %d: de body bleef hangen op een verbinding die openbleef", code)
		}
		l.Close()
	}
}
