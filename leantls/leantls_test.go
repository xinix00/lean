package leantls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xinix00/lean/leantls/x509verify"
)

// De echte toets van dit pakket: onze client tegen crypto/tls als server.
//
// Waarom dat meer bewijst dan losse unit-tests. Een handshake slaagt alleen als
// ÉLK onderdeel klopt — de key schedule, elk transcript-moment, de
// AEAD-nonces, de recordnummering, het DER-veld waar de sleutel in staat en de
// twee bewijzen (handtekening en Finished). Eén byte verkeerd en de Finished
// verifieert niet. De tegenpartij is hier een implementatie die de wereld al
// een decennium aanvalt, dus wat hier groen is, is niet groen omdat wij het
// zelf hebben opgeschreven.

// testServer zet een crypto/tls-server op met een self-signed Ed25519-cert en
// geeft zijn adres plus de publieke sleutel (de pin) terug.
func testServer(t *testing.T, min, max uint16, handler func(net.Conn)) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := selfSigned(t, pub, priv)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   min,
		MaxVersion:   max,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return ln.Addr().String(), pub
}

func selfSigned(t *testing.T, pub, priv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leantls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"leantls.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// echo stuurt terug wat het krijgt, tot het einde.
func echo(c net.Conn) {
	defer c.Close()
	io.Copy(c, c)
}

func TestClientAgainstStdlibServer(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)

	conn, err := Dial("tcp", addr, &Config{PeerKey: pin, ServerName: "leantls.test"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	msg := []byte("hallo van leantls")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("echo: got %q want %q", got, msg)
	}
}

// Zonder SNI moet het net zo goed werken: de pin doet het vertrouwen, niet de
// naam.
func TestClientWithoutSNI(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	conn.Close()
}

// Meer dan één record: dit dekt de fragmentatie op 2^14 én de recordnummering,
// want vanaf record twee is elke nonce anders.
func TestLargeTransfer(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	const n = 300 << 10 // ~19 records heen en terug
	send := make([]byte, n)
	if _, err := rand.Read(send); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	got := make([]byte, n)
	go func() {
		_, err := io.ReadFull(conn, got)
		done <- err
	}()
	if _, err := conn.Write(send); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range send {
		if send[i] != got[i] {
			t.Fatalf("byte %d differs: %#x != %#x", i, got[i], send[i])
		}
	}
}

// De pin is het hele vertrouwensmodel, dus een verkeerde sleutel MOET de
// handshake breken — en met een melding die zegt wat er mis is.
func TestWrongPinRefused(t *testing.T) {
	addr, _ := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Dial("tcp", addr, &Config{PeerKey: other})
	if err == nil {
		t.Fatal("een verkeerde pin werd geaccepteerd")
	}
	if !strings.Contains(err.Error(), "does not match the pin") {
		t.Errorf("melding zegt niet wat er mis is: %v", err)
	}
}

// Geen pin is geen "vertrouw alles" maar een weigering (lean-regel 2).
func TestNoPinRefused(t *testing.T) {
	for _, cfg := range []*Config{nil, {}, {PeerKey: make([]byte, 5)}} {
		if _, err := Client(nil, cfg); err == nil {
			t.Errorf("Config %+v werd geaccepteerd zonder geldige pin", cfg)
		}
	}
}

// Een server die alleen TLS 1.2 kan, moet luid falen en niet stil terugvallen.
func TestTLS12ServerRefused(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS12, tls.VersionTLS12, echo)
	_, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err == nil {
		t.Fatal("een TLS 1.2-server werd geaccepteerd")
	}
	// Go's server weigert zelf al (wij bieden alleen 1.3 aan), dus we toetsen
	// alleen dát het faalt en dat de melding niet leeg is.
	if err.Error() == "" {
		t.Error("lege foutmelding")
	}
	t.Logf("TLS 1.2-server: %v", err)
}

// Een certificaat met een andere sleutelsoort hoort te vertellen wát er niet
// kan, niet te stranden in een parse-fout.
func TestNonEd25519CertRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := selfSigned(t, &key.PublicKey, key)
	_, err = peerKeyFromCert(der)
	if err == nil {
		t.Fatal("een ECDSA-certificaat werd geaccepteerd")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("melding noemt Ed25519 niet: %v", err)
	}
}

// De sleutel uit een echt certificaat halen, zonder crypto/x509 — vergeleken
// met wat crypto/x509 er zelf uit haalt.
func TestPeerKeyFromCert(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := selfSigned(t, pub, priv)

	got, err := peerKeyFromCert(der)
	if err != nil {
		t.Fatalf("peerKeyFromCert: %v", err)
	}
	if !got.Equal(pub) {
		t.Errorf("sleutel wijkt af:\n got %x\nwant %x", got, pub)
	}

	// En de scheidsrechter: crypto/x509 moet dezelfde sleutel zien.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(parsed.PublicKey) {
		t.Error("crypto/x509 haalt een andere sleutel uit hetzelfde certificaat")
	}
}

// Afgekapte DER mag nooit paniekeren — dit is netwerkdata van een tegenpartij.
func TestTruncatedCertNeverPanics(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := selfSigned(t, pub, priv)
	for i := range der {
		if _, err := peerKeyFromCert(der[:i]); err == nil {
			t.Errorf("afgekapt op %d bytes werd geaccepteerd", i)
		}
	}
}

// close_notify: de andere kant moet het verschil zien tussen "klaar" en
// "weggevallen".
func TestCloseSendsCloseNotify(t *testing.T) {
	saw := make(chan error, 1)
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, func(c net.Conn) {
		defer c.Close()
		_, err := io.Copy(io.Discard, c)
		saw <- err
	})
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := conn.Write([]byte("tot ziens")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-saw:
		// Een nette afsluiting geeft de server een schone EOF (io.Copy geeft
		// dan nil); een weggevallen verbinding zou hier een fout geven.
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("server zag geen nette afsluiting: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server zag helemaal niets")
	}
}

// net.Conn mag door meerdere goroutines tegelijk gebruikt worden, en aan de
// zendkant is dat geen comfort-eis: twee Writes zonder slot kunnen twee records
// met hetzelfde recordnummer opleveren, en dat is een hergebruikte AEAD-nonce.
// De race-detector ziet dat niet (het is geen datarace op een Go-variabele maar
// een protocolfout), dus dit toetst het resultaat: alles komt heel aan.
func TestConcurrentWrites(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	const writers, each = 8, 4 << 10
	total := writers * each
	got := make([]byte, total)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, got)
		done <- err
	}()

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, each)
			for j := range buf {
				buf[j] = byte('a' + i)
			}
			if _, err := conn.Write(buf); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatalf("read: %v", err)
	}
	// De volgorde tussen schrijvers is onbepaald, maar elke byte moet van een
	// schrijver komen en het totaal moet kloppen — een hergebruikte nonce of een
	// half record zou hier als ontsleutelfout of als ontbrekende bytes vallen.
	count := map[byte]int{}
	for _, b := range got {
		count[b]++
	}
	for i := range writers {
		if n := count[byte('a'+i)]; n != each {
			t.Errorf("schrijver %d: %d van %d bytes aangekomen", i, n, each)
		}
	}
}

// De https-modus end-to-end: onze handshake, een echte crypto/tls-server, en de
// keten door crypto/x509. Dit dekt het pad dat de gepinde modus nooit raakt —
// een CertificateVerify met ECDSA of RSA-PSS in plaats van Ed25519.
//
// Twee sleutelsoorten, want dat is precies de verwisseling die in het wild
// voorkomt: github.com serveert ECDSA, objects.githubusercontent.com RSA.
func TestVerifyPeerModeAgainstStdlibServer(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			// Een eigen CA, en een servercertificaat eronder.
			caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			caTmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "leantls test CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			ca, _ := x509.ParseCertificate(caDER)
			pool := x509.NewCertPool()
			pool.AddCert(ca)

			var pub, priv any
			if kind == "ecdsa" {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				pub, priv = &k.PublicKey, k
			} else {
				k, _ := rsa.GenerateKey(rand.Reader, 2048)
				pub, priv = &k.PublicKey, k
			}
			leafTmpl := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "leantls.test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				DNSNames:     []string{"leantls.test"},
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, pub, caKey)
			if err != nil {
				t.Fatal(err)
			}

			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{leafDER, caDER},
					PrivateKey:  priv,
				}},
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go echo(c)
				}
			}()

			conn, err := Dial("tcp", ln.Addr().String(), &Config{
				ServerName:          "leantls.test",
				VerifyPeer:          x509verify.Chain(pool),
				SignatureAlgorithms: x509verify.SignatureAlgorithms,
			})
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			defer conn.Close()

			msg := []byte("https zonder crypto/tls")
			if _, err := conn.Write(msg); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(msg) {
				t.Errorf("echo: %q", got)
			}

			// En dezelfde server met een lege pool moet worden geweigerd: dan is
			// er geen anker, en dat is precies wat de keten hoort te breken.
			_, err = Dial("tcp", ln.Addr().String(), &Config{
				ServerName:          "leantls.test",
				VerifyPeer:          x509verify.Chain(x509.NewCertPool()),
				SignatureAlgorithms: x509verify.SignatureAlgorithms,
			})
			if err == nil {
				t.Error("een keten zonder vertrouwd anker werd geaccepteerd")
			}
		})
	}
}

// De twee modi sluiten elkaar uit, en geen van beide is ook een weigering.
func TestTrustModelRequired(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"niets", &Config{}, "no trust model"},
		{"beide", &Config{PeerKey: pub, VerifyPeer: func([][]byte, string) (SignatureVerifier, error) {
			return nil, nil
		}}, "not both"},
		{"haak zonder naam", &Config{VerifyPeer: func([][]byte, string) (SignatureVerifier, error) {
			return nil, nil
		}}, "ServerName is required"},
		{"pin van de verkeerde maat", &Config{PeerKey: make([]byte, 8)}, "an Ed25519 public key is"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Client(nil, c.cfg)
			if err == nil {
				t.Fatal("geaccepteerd")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("melding %q bevat niet %q", err, c.want)
			}
		})
	}
}

// TestHandshakeRespecteertDeConnDeadline — Dial zet sinds de dertiende ronde
// (review 13-08) een termijn op de verbinding vóór de handshake; dat werkt
// alleen als de handshake een conn-deadline ook echt honoreert. Een zwijgende
// peer (TCP op, handshake nooit) gijzelde anders goroutine én socket
// voorgoed — en elke laag erboven (leanhttp's dialBounded) kan een dialer
// alleen begrenzen als die zélf eindig is.
func TestHandshakeRespecteertDeConnDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go io.Copy(io.Discard, server) // de peer slikt de ClientHello en zwijgt

	client.SetDeadline(time.Now().Add(200 * time.Millisecond))
	got := make(chan error, 1)
	go func() {
		_, err := Client(client, &Config{PeerKey: make([]byte, ed25519.PublicKeySize)})
		got <- err
	}()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("een handshake tegen een zwijgende peer slaagde?!")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("de handshake hangt voorbij de conn-deadline — een zwijgende peer gijzelt de goroutine")
	}
}
