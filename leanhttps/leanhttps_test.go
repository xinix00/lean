package leanhttps

import (
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

// selfSigned maakt een Ed25519-server-certificaat en geeft de publieke sleutel
// terug — dat is precies wat een pin is.
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

// tlsServer serveert body over TLS 1.3 met het gegeven certificaat en geeft
// zijn adres terug.
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

// TestGepindeSleutel: de goedkope modus, end-to-end over echte TLS 1.3.
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
	inner := call.Dial
	call.Dial = func(network, addr2 string) (net.Conn, error) {
		// De naam die leanhttp wil bereiken moet in addr staan (voor SNI),
		// maar de TCP-verbinding gaat naar de testserver.
		if !strings.HasPrefix(addr2, "leader.internal:") {
			t.Errorf("dial-adres = %q, want leader.internal:443", addr2)
		}
		return inner(network, addr)
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

// TestVerkeerdePin: een andere sleutel dan de server heeft moet weigeren. Dit
// is de hele veiligheidsbelofte van de gepinde modus.
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
	inner := call.Dial
	call.Dial = func(network, _ string) (net.Conn, error) { return inner(network, addr) }
	if _, err := leanhttp.Do(call); err == nil {
		t.Fatal("verkeerde pin werd geaccepteerd — dat is de hele belofte van de pin")
	}
}

// TestZonderVertrouwensmodel: geen TLS-config is een weigering met uitleg, geen
// stille default.
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

// TestServerNameWeigert: een vaste ServerName is bijna altijd fout (hij zou
// ook gelden na een redirect naar een andere host), dus weigeren we hem luid.
func TestServerNameWeigert(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := Client{TLS: &leantls.Config{PeerKey: pub, ServerName: "vast.example"}}
	_, err := c.Get("https://x.example/y")
	if err == nil || !strings.Contains(err.Error(), "ServerName") {
		t.Fatalf("err = %v — moet ServerName noemen", err)
	}
}

// TestIPZonderPin: een keten valideren tegen een IP-adres kan niet (er is geen
// naam), dus dat hoort luid te falen in plaats van tegen een lege naam te
// matchen. Mét een pin mag het wél — de sleutel ís dan de identiteit.
func TestIPZonderPin(t *testing.T) {
	c := Client{TLS: &leantls.Config{
		VerifyPeer: func([][]byte, string) (leantls.SignatureVerifier, error) { return nil, nil },
	}}
	_, err := c.dial("tcp", "10.0.0.5:443")
	if err == nil || !strings.Contains(err.Error(), "IP address") {
		t.Fatalf("err = %v — een keten tegen een IP moet weigeren", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cp := Client{TLS: &leantls.Config{PeerKey: pub}}
	// Mag niet op de IP-check stuiten; de dial faalt hierna op de verbinding
	// zelf en dat is prima. Loopback met poort 1: dat weigert meteen, waar een
	// routeerbaar adres een minuut TCP-timeout zou kosten.
	if _, err := cp.dial("tcp", "127.0.0.1:1"); err != nil && strings.Contains(err.Error(), "IP address") {
		t.Fatalf("pin + IP werd geweigerd op de naam: %v", err)
	}
}

// TestConfigNietGemuteerd: de dialer werkt op een kopie. Zou hij de config van
// de aanroeper muteren, dan zou de ServerName van de eerste host blijven staan
// en na een redirect de verkeerde naam valideren — precies de bug die dit
// pakket bestaat om te voorkomen.
func TestConfigNietGemuteerd(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &leantls.Config{PeerKey: pub}
	c := Client{TLS: cfg}
	c.dial("tcp", "eerste.example:443") // faalt (niets luistert), dat mag
	if cfg.ServerName != "" {
		t.Fatalf("Config.ServerName is gemuteerd naar %q", cfg.ServerName)
	}
}

// TestLeanhttpBlijftTLSVrij is de test die de lean-regel afdwingt: wie het
// BLOK importeert mag geen TLS meekrijgen. Alleen deze samenstelling ziet de
// twee samen. Zonder deze test verwatert het onderscheid tussen een blok en
// een framework bij de eerste import die iemand toevoegt.
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

// TestGeenEcdsaInPin bewaakt de andere helft van de belofte: de gepinde modus
// mag geen PKI meebrengen. ecdsa/x509 horen alleen te verschijnen als iemand
// x509verify importeert.
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
