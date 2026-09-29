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

func TestClientWithoutSNI(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	conn.Close()
}

func TestLargeTransfer(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS13, tls.VersionTLS13, echo)
	conn, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	const n = 300 << 10
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

func TestNoPinRefused(t *testing.T) {
	for _, cfg := range []*Config{nil, {}, {PeerKey: make([]byte, 5)}} {
		if _, err := Client(nil, cfg); err == nil {
			t.Errorf("Config %+v werd geaccepteerd zonder geldige pin", cfg)
		}
	}
}

func TestTLS12ServerRefused(t *testing.T) {
	addr, pin := testServer(t, tls.VersionTLS12, tls.VersionTLS12, echo)
	_, err := Dial("tcp", addr, &Config{PeerKey: pin})
	if err == nil {
		t.Fatal("een TLS 1.2-server werd geaccepteerd")
	}

	if err.Error() == "" {
		t.Error("lege foutmelding")
	}
	t.Logf("TLS 1.2-server: %v", err)
}

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

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(parsed.PublicKey) {
		t.Error("crypto/x509 haalt een andere sleutel uit hetzelfde certificaat")
	}
}

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

		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("server zag geen nette afsluiting: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server zag helemaal niets")
	}
}

// blockedWriteConn models the adversarial case Close must resolve: the peer
// stopped reading, so a transport Write does not return until the transport is
// closed. It intentionally ignores write deadlines as a belt-and-suspenders
// check that Close's fallback timer still reaches the transport.
type blockedWriteConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once

	mu            sync.Mutex
	closeCalls    int
	writeDeadline time.Time
}

func newBlockedWriteConn() *blockedWriteConn {
	return &blockedWriteConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockedWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockedWriteConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockedWriteConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockedWriteConn) LocalAddr() net.Addr  { return nil }
func (c *blockedWriteConn) RemoteAddr() net.Addr { return nil }
func (c *blockedWriteConn) SetDeadline(t time.Time) error {
	return c.SetWriteDeadline(t)
}
func (c *blockedWriteConn) SetReadDeadline(time.Time) error { return nil }
func (c *blockedWriteConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *blockedWriteConn) state() (int, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCalls, c.writeDeadline
}

func encryptedConnForCloseTest(raw net.Conn) *Conn {
	c := &Conn{conn: raw}
	c.setWrite(trafficKeys{key: make([]byte, keyLen), iv: make([]byte, ivLen)})
	return c
}

type recordTimeoutError struct{}

func (*recordTimeoutError) Error() string   { return "record write timed out" }
func (*recordTimeoutError) Timeout() bool   { return true }
func (*recordTimeoutError) Temporary() bool { return true }

var errRecordWriteTimeout = &recordTimeoutError{}

// failSecondRecordConn accepts one complete TLS record and fails the next. A
// third Write would prove that application-level progress retry resumed a TLS
// stream after its record sequence/ciphertext became ambiguous.
type failSecondRecordConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (*failSecondRecordConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *failSecondRecordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 2 {
		return 0, errRecordWriteTimeout
	}
	return len(p), nil
}
func (c *failSecondRecordConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (*failSecondRecordConn) LocalAddr() net.Addr              { return nil }
func (*failSecondRecordConn) RemoteAddr() net.Addr             { return nil }
func (*failSecondRecordConn) SetDeadline(time.Time) error      { return nil }
func (*failSecondRecordConn) SetReadDeadline(time.Time) error  { return nil }
func (*failSecondRecordConn) SetWriteDeadline(time.Time) error { return nil }
func (c *failSecondRecordConn) state() (writes int, closed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.closed
}

func TestRecordWriteErrorIsPermanentAcrossApplicationRetry(t *testing.T) {
	raw := &failSecondRecordConn{}
	c := encryptedConnForCloseTest(raw)
	payload := make([]byte, maxPlain+1) // two TLS records

	n, err := c.Write(payload)
	if n != maxPlain || !errors.Is(err, errRecordWriteTimeout) {
		t.Fatalf("multi-record Write = %d, %v; wil %d bytes plus timeout", n, err, maxPlain)
	}
	seqAfterFailure := c.wSeq
	n, err = c.Write(payload[maxPlain:])
	if n != 0 || !errors.Is(err, errRecordWriteTimeout) {
		t.Fatalf("retry na recordfout = %d, %v; wil 0 plus dezelfde permanente fout", n, err)
	}
	if c.wSeq != seqAfterFailure {
		t.Fatalf("retry verbruikte TLS-recordsequentie %d -> %d", seqAfterFailure, c.wSeq)
	}
	if writes, _ := raw.state(); writes != 2 {
		t.Fatalf("retry schreef een derde record naar de corrupte stream: %d writes", writes)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if writes, closed := raw.state(); writes != 2 || !closed {
		t.Fatalf("Close na permanente writefout: writes=%d closed=%v", writes, closed)
	}
}

func TestCloseUnblocksConcurrentWrite(t *testing.T) {
	raw := newBlockedWriteConn()
	c := encryptedConnForCloseTest(raw)

	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("peer leest dit niet"))
		writeDone <- err
	}()
	select {
	case <-raw.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Write begon niet")
	}

	const closers = 8
	closeDone := make(chan error, closers)
	for range closers {
		go func() { closeDone <- c.Close() }()
	}
	select {
	case <-raw.closed:
	case <-time.After(time.Second):
		t.Fatal("Close bereikte het transport niet achter een geblokkeerde Write")
	}
	for range closers {
		if err := <-closeDone; err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	if err := <-writeDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("geblokkeerde Write eindigde met %v, wil net.ErrClosed", err)
	}
	if calls, _ := raw.state(); calls != 1 {
		t.Fatalf("onderliggende Close is %d keer aangeroepen, wil 1", calls)
	}
}

func TestBlockedCloseNotifyStillClosesTransport(t *testing.T) {
	raw := newBlockedWriteConn()
	c := encryptedConnForCloseTest(raw)

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case <-raw.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("close_notify werd niet geprobeerd")
	}
	select {
	case <-raw.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("geblokkeerde close_notify verhinderde de transport-close")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	calls, deadline := raw.state()
	if calls != 1 {
		t.Fatalf("onderliggende Close is %d keer aangeroepen, wil 1", calls)
	}
	if deadline.IsZero() {
		t.Fatal("close_notify kreeg geen begrensde write-deadline")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("tweede Close: %v", err)
	}
	if calls, _ := raw.state(); calls != 1 {
		t.Fatalf("tweede Close bereikte transport opnieuw: %d calls", calls)
	}
}

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

func TestVerifyPeerModeAgainstStdlibServer(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa"} {
		t.Run(kind, func(t *testing.T) {

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

func TestHandshakeRespecteertDeConnDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go io.Copy(io.Discard, server)

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
