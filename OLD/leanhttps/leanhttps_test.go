package leanhttps

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xinix00/lean/leanhttp"
	"github.com/xinix00/lean/leantls"
)

func selfSigned(t *testing.T, names ...string) (tls.Certificate, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, pub
}

func tlsServer(t *testing.T, cert tls.Certificate, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestGepindeSleutel(t *testing.T) {
	cert, pub := selfSigned(t, "leader.internal")
	addr := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "leader.internal" {
			t.Errorf("Host = %q", r.Host)
		}
		w.Write([]byte("job list"))
	}))

	c := Client{TLS: &leantls.Config{PeerKey: pub}, Timeout: 5 * time.Second}
	call, err := c.call(leanhttp.Call{URL: "https://leader.internal/v1/jobs"})
	if err != nil {
		t.Fatal(err)
	}
	inner := call.DialContext
	call.DialContext = func(ctx context.Context, network, addr2 string) (net.Conn, error) {

		if !strings.HasPrefix(addr2, "leader.internal:") {
			t.Errorf("dial-adres = %q, want leader.internal:443", addr2)
		}
		return inner(ctx, network, addr)
	}
	resp, err := leanhttp.Do(call)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "job list" {
		t.Fatalf("body = %q", body)
	}
}

func TestVerkeerdePin(t *testing.T) {
	cert, _ := selfSigned(t, "leader.internal")
	addr := tlsServer(t, cert, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := Client{TLS: &leantls.Config{PeerKey: other}}
	call, err := c.call(leanhttp.Call{URL: "https://leader.internal/"})
	if err != nil {
		t.Fatal(err)
	}
	inner := call.DialContext
	call.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) { return inner(ctx, network, addr) }
	if _, err := leanhttp.Do(call); err == nil {
		t.Fatal("verkeerde pin werd geaccepteerd — dat is de hele belofte van de pin")
	}
}

func TestZonderVertrouwensmodel(t *testing.T) {
	var c Client
	_, err := c.Get("https://x.example/y")
	if err == nil {
		t.Fatal("lege Client werd geaccepteerd")
	}
	for _, want := range []string{"PeerKey", "VerifyPeer", "no default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v — moet %q noemen", err, want)
		}
	}
}

func TestServerNameWeigert(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := Client{TLS: &leantls.Config{PeerKey: pub, ServerName: "vast.example"}}
	_, err := c.Get("https://x.example/y")
	if err == nil || !strings.Contains(err.Error(), "ServerName") {
		t.Fatalf("err = %v — moet ServerName noemen", err)
	}
}

func TestIPZonderPin(t *testing.T) {
	c := Client{TLS: &leantls.Config{
		VerifyPeer: func([][]byte, string) (leantls.SignatureVerifier, error) { return nil, nil },
	}}
	_, err := c.dial(context.Background(), "tcp", "10.0.0.5:443")
	if err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("err = %v — een keten tegen een IP moet weigeren", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cp := Client{TLS: &leantls.Config{PeerKey: pub}}

	if _, err := cp.dial(context.Background(), "tcp", "127.0.0.1:1"); err != nil && strings.Contains(err.Error(), "IP address") {
		t.Fatalf("pin + IP werd geweigerd op de naam: %v", err)
	}
}

func TestConfigNietGemuteerd(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &leantls.Config{PeerKey: pub}
	c := Client{TLS: cfg}
	c.dial(context.Background(), "tcp", "eerste.example:443")
	if cfg.ServerName != "" {
		t.Fatalf("Config.ServerName is gemuteerd naar %q", cfg.ServerName)
	}
}

func TestLeanhttpBlijftTLSVrij(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/xinix00/lean/leanhttp").Output()
	if err != nil {
		t.Skipf("go list niet beschikbaar: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch dep {
		case "crypto/tls", "crypto/x509", "encoding/asn1", "github.com/xinix00/lean/leantls":
			t.Errorf("leanhttp importeert %s — het blok moet TLS-vrij blijven", dep)
		}
	}
}

func TestGeenEcdsaInPin(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/xinix00/lean/leanhttps").Output()
	if err != nil {
		t.Skipf("go list niet beschikbaar: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch dep {
		case "crypto/x509", "crypto/tls", "encoding/asn1":
			t.Errorf("leanhttps importeert %s — dat hoort pas mee te komen met x509verify", dep)
		}
	}
}

func TestTLSPoolHergebruik(t *testing.T) {
	cert, pub := selfSigned(t, "leader.internal")
	addr := tlsServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	pool := &leanhttp.Client{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return DialerContext(&leantls.Config{PeerKey: pub})(ctx, network, addr)
	}}
	for i := 0; i < 3; i++ {
		resp, err := pool.Do(leanhttp.Call{URL: "https://leader.internal/"})
		if err != nil {
			t.Fatalf("verzoek %d over de TLS-pool: %v", i+1, err)
		}
		if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
			t.Fatalf("verzoek %d: body %q", i+1, b)
		}
		resp.Body.Close()
	}
}

func TestDialerContextNilFaaltNetjes(t *testing.T) {
	dial := DialerContext(nil)
	_, err := dial(context.Background(), "tcp4", "host.example:443")
	if err == nil || !strings.Contains(err.Error(), "TLS is nil") {
		t.Fatalf("DialerContext(nil) gaf %v, wil de errNoConfig-uitleg", err)
	}
}
