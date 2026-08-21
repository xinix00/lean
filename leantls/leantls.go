// Package leantls is a standard-library-only TLS 1.3 client for networks you
// control: one version, cipher suite, key exchange, and a peer identified by a
// pinned Ed25519 key instead of a certificate chain.
//
// Measured with the same tamago/riscv64 main (`-w -T 0x84010000`, 2026-08-12):
//
//	board + fmt baseline ...................... 1.69 MB
//	+ this package, pinned key ................ 2.51 MB (+0.82)
//	+ this package plus x509verify chain ...... 3.73 MB (+2.04)
//	+ crypto/tls with CA root bundle .......... 4.09 MB (+2.40)
//
// Pinned mode saves 1.57 MB over crypto/tls. Chain mode alone saves 0.63 MB,
// but also unlocks leanhttp's larger saving. For the same HTTPS download:
//
//	net/http + crypto/tls ................. 5.53 MB
//	leanhttp + crypto/tls ................. 4.43 MB (-1.10)
//	leanhttp + leantls + x509verify ....... 3.80 MB (-1.73)
//
// Pinned mode avoids crypto/x509, encoding/asn1, math/big, RSA, NIST curves,
// and the CA bundle. It uses X25519, AES-128-GCM, SHA-256, HMAC, HKDF,
// Ed25519, and crypto/rand, linking no crypto/tls, crypto/x509, or encoding/asn1.
//
// # Pinned identity
//
// Ordinary HTTPS delegates identity to a CA chain. A pin instead distributes a
// known 32-byte Ed25519 public key with the node. The handshake requires the
// certificate key to equal it and verifies the transcript signature with that
// key. This removes CA, name, and validity ambiguity at the cost of distributing
// new pins when keys rotate, which fits a controlled fleet but not public hosts.
//
// # Deliberate limits
//
// Pinned mode performs no chain, CA, name, or validity checks; [Config.PeerKey]
// is the identity. [Config.VerifyPeer] enables caller-supplied chain validation,
// with leantls/x509verify providing the standard form. [Client] rejects a
// missing or ambiguous trust model.
//
// Only TLS 1.3, TLS_AES_128_GCM_SHA256, X25519, and Ed25519 are supported in
// pinned mode. There is no downgrade, session resumption, PSK, 0-RTT, client
// certificate, HelloRetryRequest, or renegotiation. Removing downgrade,
// compression, CBC, RSA-PKCS#1v1.5, and custom chain validation eliminates the
// usual dangerous TLS state space. RFC 8448 vectors test the key schedule;
// crypto/tls interoperability tests the transcript and record layer.
//
// # Usage
//
//	// A peer whose key is already known:
//	conn, err := leantls.Dial("tcp", "leader:7443", &leantls.Config{
//	    PeerKey: leaderKey, // 32 bytes from your own configuration
//	})
//
//	// A public certificate chain:
//	conn, err := leantls.Dial("tcp", "github.com:443", &leantls.Config{
//	    ServerName:          "github.com",
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	})
//
// The result is an ordinary net.Conn. This package knows neither HTTP nor the
// underlying network stack.
package leantls

import (
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config identifies the expected peer. Set exactly one trust model: PeerKey for
// a pin, or VerifyPeer for caller-supplied validation such as a certificate
// chain. Missing and ambiguous trust both fail.
type Config struct {
	// PeerKey is the Ed25519 public key the server must prove. This mode links no
	// PKI.
	PeerKey ed25519.PublicKey

	// VerifyPeer receives the wire certificate chain in leaf-first DER order and
	// the expected name, then returns a transcript-signature verifier. The hook
	// keeps crypto/x509's ~0.75 MB out of pinned builds; leantls/x509verify
	// provides standard HTTPS chain validation.
	VerifyPeer func(certs [][]byte, serverName string) (SignatureVerifier, error)

	// ServerName is sent as SNI and passed to VerifyPeer for certificate identity.
	// It is optional with PeerKey because the pin supplies identity.
	ServerName string

	// SignatureAlgorithms are offered for server CertificateVerify
	// (RFC 8446 §4.2.3). Empty means Ed25519 only. A VerifyPeer supporting more
	// should supply exactly those codes, such as x509verify.SignatureAlgorithms.
	SignatureAlgorithms []uint16
}

// SignatureVerifier checks server CertificateVerify. sigAlg is the selected
// TLS code, signed is the exact transcript input, and sig is the signature. Nil
// means success. The alias lets helper packages provide verifiers without
// importing leantls.
type SignatureVerifier = func(sigAlg uint16, signed, sig []byte) error

// Conn is a TLS 1.3 connection implementing net.Conn.
type Conn struct {
	conn net.Conn
	cfg  Config

	// Grown (method below) passes the transport's bulk-classification through
	// the TLS layer so a pool can apply its close-grown-connections rule to
	// TLS connections too.

	// One lock per direction preserves net.Conn concurrency without reusing an
	// AES-GCM sequence number/nonce. Read also processes post-handshake messages
	// and may acquire wmu while holding rmu.
	rmu sync.Mutex
	wmu sync.Mutex

	// closing prevents new writes from racing a close_notify. Close has a
	// separate once for the transport because its deadline fallback may have to
	// close the socket from a timer while Close itself is blocked in Write.
	closing       atomic.Bool
	closeOnce     sync.Once
	connCloseOnce sync.Once
	closeErr      error

	// Per-direction record state; sequence resets after every key change.
	wKeys trafficKeys
	wAEAD cipher.AEAD
	wSeq  uint64
	// writeErr is protected by wmu and permanent. Once a record write fails,
	// ciphertext may be partial and its sequence number has been consumed; a
	// later application retry cannot safely resume this TLS stream.
	writeErr error
	rKeys    trafficKeys
	rAEAD    cipher.AEAD
	rSeq     uint64

	transcript []byte // all handshake messages; cleared afterward
	hsBuf      []byte // incomplete handshake-message bytes
	plain      []byte // decrypted application data not yet returned
	readErr    error  // sticky: record-layer failures are permanent
}

var _ net.Conn = (*Conn)(nil)

// dialTimeout separately bounds TCP setup and TLS handshake so a silent peer
// cannot retain a goroutine and socket forever. It matches leanhttp's timeout.
const dialTimeout = 10 * time.Second

// A close_notify is only a courtesy once the caller has requested Close. A
// peer that stopped reading must not be able to retain the connection (and its
// owner) indefinitely. The record is tiny and normally enters the transport
// immediately; backpressure beyond this bound turns the graceful close into a
// transport close.
const closeNotifyTimeout = 250 * time.Millisecond

// Dial opens TCP and performs the handshake with [dialTimeout]. For custom
// deadlines, dial separately and call [Client]; for cancellation use
// [DialContext].
func Dial(network, addr string, cfg *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, cfg)
}

// DialContext adds cancellation to Dial. An earlier context deadline also caps
// the handshake so a dial cannot outlive its caller.
func DialContext(ctx context.Context, network, addr string, cfg *Config) (*Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(dialTimeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	c.SetDeadline(dl)
	tc, err := Client(c, cfg)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return tc, nil
}

// Client performs the handshake over an existing connection. On error, the
// caller must close the unusable underlying connection. Handshake is eager so
// trust failures occur here instead of during later application I/O.
func Client(conn net.Conn, cfg *Config) (*Conn, error) {
	if cfg == nil {
		return nil, errors.New("leantls: a Config is required")
	}
	pinned := len(cfg.PeerKey) > 0
	switch {
	case pinned && cfg.VerifyPeer != nil:
		return nil, errors.New("leantls: set either Config.PeerKey or Config.VerifyPeer, not both — " +
			"with both it is not clear which one decides whether the peer is trusted")
	case pinned && len(cfg.PeerKey) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("leantls: Config.PeerKey is %d bytes, an Ed25519 public key is %d",
			len(cfg.PeerKey), ed25519.PublicKeySize)
	case !pinned && cfg.VerifyPeer == nil:
		// Never invent a trust-all fallback.
		return nil, errors.New("leantls: no trust model — set Config.PeerKey for a pinned peer, " +
			"or Config.VerifyPeer to check a certificate chain yourself (see leantls/x509verify)")
	case !pinned && cfg.ServerName == "":
		return nil, errors.New("leantls: Config.ServerName is required with VerifyPeer — " +
			"a chain that is not checked against a name proves nothing about who you reached")
	}
	c := &Conn{conn: conn, cfg: *cfg}
	if err := c.handshake(); err != nil {
		return nil, err
	}
	return c, nil
}

// hash returns the transcript hash. Keeping a few KiB of bytes is simpler than
// cloning running hash state at five RFC 8446 §4.4.1 checkpoints; the transcript
// is cleared after handshake.
func (c *Conn) hash() []byte {
	sum := sha256.Sum256(c.transcript)
	return sum[:]
}

func (c *Conn) setRead(k trafficKeys) {
	c.rKeys, c.rAEAD, c.rSeq = k, aeadFor(k), 0
}

func (c *Conn) setWrite(k trafficKeys) {
	c.wKeys, c.wAEAD, c.wSeq = k, aeadFor(k), 0
}

// writeCCS sends the empty plaintext change_cipher_spec compatibility record.
func (c *Conn) writeCCS() error {
	return writeFull(c.conn, []byte{recCCS, 3, 3, 0, 1, 1})
}

// readHandshakeMsg returns and records the next handshake message. It buffers
// across record boundaries because records and messages do not align.
func (c *Conn) readHandshakeMsg() (byte, []byte, error) {
	for {
		if len(c.hsBuf) >= 4 {
			n := int(c.hsBuf[1])<<16 | int(c.hsBuf[2])<<8 | int(c.hsBuf[3])
			if len(c.hsBuf) >= 4+n {
				msg := c.hsBuf[:4+n]
				c.hsBuf = c.hsBuf[4+n:]
				c.transcript = append(c.transcript, msg...)
				return msg[0], msg[4:], nil
			}
		}
		typ, payload, err := c.readRecord()
		if err != nil {
			return 0, nil, err
		}
		switch typ {
		case recCCS:
			// TLS 1.3 middlebox compatibility (§5); not a handshake message.
		case recAlert:
			return 0, nil, alertError(payload)
		case recHandshake:
			if len(c.hsBuf)+len(payload) > maxHandshake {
				return 0, nil, fmt.Errorf("leantls: handshake message larger than %d bytes", maxHandshake)
			}
			c.hsBuf = append(c.hsBuf, payload...)
		default:
			return 0, nil, fmt.Errorf("leantls: unexpected record type %d during handshake", typ)
		}
	}
}

// maxHandshake prevents a peer from turning one handshake message into an
// unbounded allocation; certificate chains are normally only a few KiB.
const maxHandshake = 1 << 16

// Read returns application data and transparently handles post-handshake
// NewSessionTicket and KeyUpdate messages.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.plain) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		typ, payload, err := c.readRecord()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		switch typ {
		case recAppData:
			c.plain = payload
		case recAlert:
			c.readErr = alertError(payload)
			return 0, c.readErr
		case recCCS:
			// Ignore compatibility CCS even after handshake.
		case recHandshake:
			if err := c.postHandshake(payload); err != nil {
				c.readErr = err
				return 0, err
			}
		default:
			c.readErr = fmt.Errorf("leantls: unexpected record type %d", typ)
			return 0, c.readErr
		}
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

// postHandshake processes messages a server may send after handshake.
func (c *Conn) postHandshake(payload []byte) error {
	r := reader{buf: payload}
	for !r.empty() {
		typ, err := r.u8()
		if err != nil {
			return err
		}
		body, err := r.vec24()
		if err != nil {
			return err
		}
		switch typ {
		case hsNewSessionTicket:
			// Resumption is unsupported, but sending tickets is valid.
		case hsKeyUpdate:
			// RFC 8446 §4.6.3: update read keys and reciprocate when requested.
			req, err := body.u8()
			if err != nil {
				return err
			}
			c.setRead(c.rKeys.next())
			if req == 1 {
				// Unlock explicitly: multiple updates in one record must not
				// deadlock on a deferred unlock.
				c.wmu.Lock()
				err := c.writeRecord(recHandshake, keyUpdateMsg())
				if err == nil {
					c.setWrite(c.wKeys.next())
				}
				c.wmu.Unlock()
				if err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("leantls: unexpected post-handshake message type %d", typ)
		}
	}
	return nil
}

// Write sends application data fragmented at the RFC record limit.
func (c *Conn) Write(p []byte) (int, error) {
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing.Load() {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxPlain)
		if err := c.writeRecord(recAppData, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// Close sends a best-effort close_notify before closing, allowing the peer to
// distinguish a complete stream from a truncated connection. It never waits
// behind an application Write: closing the transport is what releases such a
// writer. A close_notify that itself blocks is bounded by a write deadline and
// an independent transport-close timer.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closing.Store(true)

		// Waiting for wmu can deadlock behind a Write whose peer stopped
		// reading. In that case the transport close below is the only safe way
		// to release it, so close_notify is no longer feasible.
		if c.wmu.TryLock() {
			if c.wAEAD != nil {
				// There is no deadline to restore: the transport is irrevocably
				// closed immediately after this best-effort alert.
				if err := c.conn.SetWriteDeadline(time.Now().Add(closeNotifyTimeout)); err == nil {
					timer := time.AfterFunc(closeNotifyTimeout, c.closeTransport)
					_ = c.writeRecord(recAlert, []byte{2, alertCloseNotify})
					timer.Stop()
				}
			}
			c.wmu.Unlock()
		}

		c.closeTransport()
	})
	return c.closeErr
}

func (c *Conn) closeTransport() {
	c.connCloseOnce.Do(func() { c.closeErr = c.conn.Close() })
}

// keyUpdateMsg reciprocates a requested update without requesting another,
// avoiding an infinite exchange.
func keyUpdateMsg() []byte {
	var b builder
	b.u8(hsKeyUpdate)
	b.u24len(func() { b.u8(0) }) // update_not_requested
	return b.buf
}

func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Grown geeft de bulk-classificatie van het onderliggende transport door
// (zie leannet tcpSock.Grown): zo geldt de pool-regel "gegroeid = sluiten,
// niet poolen" ook voor TLS-verbindingen. Een transport zonder het begrip
// is per definitie niet gegroeid.
func (c *Conn) Grown() bool {
	if g, ok := c.conn.(interface{ Grown() bool }); ok {
		return g.Grown()
	}
	return false
}
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// PeerKey returns the configured key proven by certificate inclusion and the
// transcript signature.
func (c *Conn) PeerKey() ed25519.PublicKey { return c.cfg.PeerKey }
