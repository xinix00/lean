package leanhttp

import (
	"bufio"
	"context"
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

type grownTestConn struct{ net.Conn }

func (grownTestConn) Grown() bool { return true }

func TestGrownVerbindingKomtNietInPool(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
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
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		_, _ = io.Copy(io.Discard, br)
	}()

	cl := &Client{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return grownTestConn{client}, nil
	}}
	resp, err := cl.Do(Call{URL: "http://grown.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("Grown-verbinding kwam met %d entries in pool", n)
	}
	<-serverDone
}

type gatedCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *gatedCloseConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.started)
		<-c.release
		err = c.Conn.Close()
	})
	return err
}

func TestContextCancelEnBodyClosePoolenNietTijdensCallback(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	gated := &gatedCloseConn{Conn: client, started: make(chan struct{}), release: make(chan struct{})}
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
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		_, _ = io.Copy(io.Discard, br)
	}()

	cl := &Client{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return gated, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := cl.Do(Call{URL: "http://cancel-race.test/", Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-gated.started:
	case <-time.After(time.Second):
		t.Fatal("context-callback begon de transport-close niet")
	}
	closed := make(chan error, 1)
	go func() { closed <- resp.Body.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Body.Close passeerde een actieve context-callback: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("context-geannuleerde verbinding stond tijdens callback in pool: %d", n)
	}
	close(gated.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if n := cl.idleCount(); n != 0 {
		t.Fatalf("context-geannuleerde verbinding eindigde alsnog in pool: %d", n)
	}
}

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
		io.CopyN(io.Discard, resp.Body, 10)
		resp.Body.Close()
	}
	if got := conns.n.Load(); got != 3 {
		t.Errorf("%d verbindingen, want 3 — een half gelezen body werd hergebruikt", got)
	}

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
		time.Sleep(40 * time.Millisecond)
	}
	if got := conns.n.Load(); got != 2 {
		t.Errorf("%d verbindingen, want 2 — een verlopen verbinding werd hergebruikt", got)
	}
}

func TestKeepAliveMaxIdle(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cl := &Client{MaxIdlePerHost: 1}
	defer cl.CloseIdle()

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

func TestGzipDoorlaat(t *testing.T) {
	addr, _ := servedBy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("server zag Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", "3")
		w.Write([]byte("abc"))
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

	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie staat óók in Header (%q) — daar kan hij alleen gevouwen staan", got)
	}
}

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

	time.Sleep(40 * time.Millisecond)

	resp, err = cl.Get("http://" + hostB + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if n := cl.idleCount(); n != 1 {
		t.Fatalf("pool draagt %d verbindingen, wil 1 (alleen host B) — een verlopen "+
			"verbinding naar een host die je niet meer belt blijft dus staan", n)
	}
	if cl.idleFor(hostA) != 0 {
		t.Fatal("de verlopen verbinding naar host A staat nog in de pool")
	}
}

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
	time.Sleep(40 * time.Millisecond)

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
