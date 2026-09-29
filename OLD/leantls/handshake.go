package leantls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
)

// TLS 1.3 client handshake (RFC 8446 §4) with one version, suite, group, and
// pinned-mode signature algorithm. Unsupported server choices fail instead of
// expanding negotiation state.
//
// Server flight:
//
//	ServerHello         → validate TLS 1.3 and the server key share
//	EncryptedExtensions → skip; no requested extension needs a response
//	Certificate         → establish peer identity
//	CertificateVerify   → verify the transcript signature
//	Finished            → verify transcript HMAC with the handshake secret
//
// CertificateVerify proves identity; Finished binds that identity to this key
// exchange and prevents a middlebox forwarding only the signature.

const (
	// Handshake message types encountered here (§4).
	hsClientHello         = 1
	hsServerHello         = 2
	hsNewSessionTicket    = 4
	hsEncryptedExtensions = 8
	hsCertificate         = 11
	hsCertificateRequest  = 13
	hsCertificateVerify   = 15
	hsFinished            = 20
	hsKeyUpdate           = 24

	// Extensions.
	extServerName        = 0
	extSupportedGroups   = 10
	extSignatureAlgs     = 13
	extSupportedVersions = 43
	extKeyShare          = 51

	versionTLS13 = 0x0304
	// TLS 1.3 puts 1.2 in legacy version fields and negotiates the real version
	// through an extension.
	legacyVersion = 0x0303

	groupX25519    = 0x001d
	sigEd25519     = 0x0807
	suiteAES128GCM = 0x1301
)

// helloRetryRandom is the fixed ServerHello.random requesting another group
// (§4.1.3). Because only X25519 is offered, receiving it fails clearly.
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// handshake completes the client side and installs application traffic keys.
func (c *Conn) handshake() error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("leantls: x25519: %w", err)
	}

	sessionID := make([]byte, 32)
	random := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return err
	}
	if _, err := rand.Read(random); err != nil {
		return err
	}

	// --- ClientHello -------------------------------------------------------
	ch := c.clientHello(random, sessionID, priv.PublicKey().Bytes())
	c.transcript = append(c.transcript, ch...)
	if err := c.writeRecord(recHandshake, ch); err != nil {
		return err
	}

	// --- ServerHello -------------------------------------------------------
	typ, body, err := c.readHandshakeMsg()
	if err != nil {
		return err
	}
	if typ != hsServerHello {
		return fmt.Errorf("leantls: expected ServerHello, got handshake type %d", typ)
	}
	serverShare, err := c.parseServerHello(body, sessionID)
	if err != nil {
		return err
	}

	// --- Keys ---------------------------------------------------------------
	peer, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return fmt.Errorf("leantls: server key share: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return fmt.Errorf("leantls: x25519: %w", err)
	}
	sec := newSecrets(shared)
	chsh := c.hash()
	cHS := keysFrom(deriveSecret(sec.handshake, "c hs traffic", chsh))
	sHS := keysFrom(deriveSecret(sec.handshake, "s hs traffic", chsh))
	c.setRead(sHS)
	c.setWrite(cHS)

	// --- Encrypted server flight -------------------------------------------
	if err := c.expect(hsEncryptedExtensions); err != nil {
		return err
	}

	typ, body, err = c.readHandshakeMsg()
	if err != nil {
		return err
	}
	if typ == hsCertificateRequest {
		return fmt.Errorf("leantls: the server asks for a client certificate — " +
			"this package does not do client authentication")
	}
	if typ != hsCertificate {
		return fmt.Errorf("leantls: expected Certificate, got handshake type %d", typ)
	}
	chain, err := parseCertificateList(body)
	if err != nil {
		return err
	}
	// This is the sole trust decision. Client already selected one mode:
	//
	//   - compare a pinned key without chain, names, or dates;
	//   - let the caller validate the wire chain and return a signature verifier.
	var verify SignatureVerifier
	if len(c.cfg.PeerKey) > 0 {
		certKey, err := peerKeyFromCert(chain[0])
		if err != nil {
			return err
		}
		if !certKey.Equal(c.cfg.PeerKey) {
			return fmt.Errorf("leantls: server key does not match the pin\n got  %x\n want %x",
				certKey, c.cfg.PeerKey)
		}
		verify = ed25519Verifier(certKey)
	} else {
		if verify, err = c.cfg.VerifyPeer(chain, c.cfg.ServerName); err != nil {
			return fmt.Errorf("leantls: peer rejected: %w", err)
		}
		if verify == nil {
			return errors.New("leantls: VerifyPeer accepted the peer but returned no signature verifier")
		}
	}

	// CertificateVerify covers the transcript through Certificate, so snapshot
	// before reading the next message.
	beforeCV := c.hash()
	typ, body, err = c.readHandshakeMsg()
	if err != nil {
		return err
	}
	if typ != hsCertificateVerify {
		return fmt.Errorf("leantls: expected CertificateVerify, got handshake type %d", typ)
	}
	if err := verifyCertificateVerify(body, verify, beforeCV); err != nil {
		return err
	}

	beforeFin := c.hash()
	typ, body, err = c.readHandshakeMsg()
	if err != nil {
		return err
	}
	if typ != hsFinished {
		return fmt.Errorf("leantls: expected Finished, got handshake type %d", typ)
	}
	if !hmac.Equal(body, finishedData(sHS.secret, beforeFin)) {
		return fmt.Errorf("leantls: server Finished does not verify — " +
			"the key exchange was tampered with, or we disagree about the transcript")
	}

	// --- Complete our side --------------------------------------------------
	// Application keys cover through server Finished, excluding our Finished.
	afterFin := c.hash()

	// Middleboxes still expect change_cipher_spec. TLS 1.3 sends these six bytes
	// as plaintext even after write keys exist, so use the dedicated writer.
	if err := c.writeCCS(); err != nil {
		return err
	}
	fin := &builder{}
	fin.u8(hsFinished)
	fin.u24len(func() { fin.bytes(finishedData(cHS.secret, afterFin)) })
	if err := c.writeRecord(recHandshake, fin.buf); err != nil {
		return err
	}

	c.setRead(keysFrom(deriveSecret(sec.master, "s ap traffic", afterFin)))
	c.setWrite(keysFrom(deriveSecret(sec.master, "c ap traffic", afterFin)))
	// Drop the completed transcript, including certificates.
	c.transcript = nil
	return nil
}

// sigAlgs returns configured algorithms or pinned-mode Ed25519 only. Never offer
// more than the active verifier can check.
func (c *Conn) sigAlgs() []uint16 {
	if len(c.cfg.SignatureAlgorithms) > 0 {
		return c.cfg.SignatureAlgorithms
	}
	return []uint16{sigEd25519}
}

// clientHello builds the fixed message around its three random fields.
func (c *Conn) clientHello(random, sessionID, share []byte) []byte {
	b := &builder{}
	b.u8(hsClientHello)
	b.u24len(func() {
		b.u16(legacyVersion)
		b.bytes(random)
		b.u8len(func() { b.bytes(sessionID) })
		b.u16len(func() { b.u16(suiteAES128GCM) })
		b.u8len(func() { b.u8(0) }) // Compression: none only.
		b.u16len(func() {
			if c.cfg.ServerName != "" {
				b.u16(extServerName)
				b.u16len(func() {
					b.u16len(func() {
						b.u8(0) // host_name
						b.u16len(func() { b.bytes([]byte(c.cfg.ServerName)) })
					})
				})
			}
			b.u16(extSupportedGroups)
			b.u16len(func() { b.u16len(func() { b.u16(groupX25519) }) })

			b.u16(extSignatureAlgs)
			b.u16len(func() {
				b.u16len(func() {
					for _, a := range c.sigAlgs() {
						b.u16(a)
					}
				})
			})

			b.u16(extSupportedVersions)
			b.u16len(func() { b.u8len(func() { b.u16(versionTLS13) }) })

			b.u16(extKeyShare)
			b.u16len(func() {
				b.u16len(func() {
					b.u16(groupX25519)
					b.u16len(func() { b.bytes(share) })
				})
			})
		})
	})
	return b.buf
}

// parseServerHello validates supported choices and returns the key share.
func (c *Conn) parseServerHello(body, sessionID []byte) ([]byte, error) {
	r := reader{buf: body}
	if _, err := r.u16(); err != nil { // legacy_version is not authoritative.
		return nil, err
	}
	random, err := r.take(32)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(random, helloRetryRandom) {
		return nil, fmt.Errorf("leantls: the server sent a HelloRetryRequest — " +
			"it wants a key exchange group other than X25519, which is the only one this package offers")
	}
	echo, err := r.vec8()
	if err != nil {
		return nil, err
	}
	// The compatibility session ID must echo our ClientHello.
	if !bytes.Equal(echo.buf, sessionID) {
		return nil, fmt.Errorf("leantls: the server echoed a different session id")
	}
	suite, err := r.u16()
	if err != nil {
		return nil, err
	}
	if suite != suiteAES128GCM {
		return nil, fmt.Errorf("leantls: the server chose cipher suite %#04x; this package only has "+
			"TLS_AES_128_GCM_SHA256 (%#04x)", suite, suiteAES128GCM)
	}
	// TLS 1.3 has no compression; accepting it would also reintroduce CRIME.
	if comp, err := r.u8(); err != nil {
		return nil, err
	} else if comp != 0 {
		return nil, fmt.Errorf("leantls: the server selected compression method %d; TLS 1.3 has none", comp)
	}
	exts, err := r.vec16()
	if err != nil {
		return nil, err
	}

	var share []byte
	sawVersion := false
	err = eachExtension(exts, func(typ uint16, body reader) error {
		switch typ {
		case extSupportedVersions:
			v, err := body.u16()
			if err != nil {
				return err
			}
			if v != versionTLS13 {
				return fmt.Errorf("leantls: the server selected version %#04x, not TLS 1.3", v)
			}
			sawVersion = true
		case extKeyShare:
			g, err := body.u16()
			if err != nil {
				return err
			}
			if g != groupX25519 {
				return fmt.Errorf("leantls: the server chose group %#04x, not X25519", g)
			}
			k, err := body.vec16()
			if err != nil {
				return err
			}
			share = bytes.Clone(k.buf)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Without supported_versions this is a TLS 1.2 server, not a valid downgrade.
	if !sawVersion {
		return nil, fmt.Errorf("leantls: the server did not select TLS 1.3 " +
			"(no supported_versions in ServerHello) — this package speaks TLS 1.3 only")
	}
	if len(share) == 0 {
		return nil, fmt.Errorf("leantls: the server sent no key share")
	}
	return share, nil
}

// expect reads and records one handshake message of the required type.
func (c *Conn) expect(want byte) error {
	typ, _, err := c.readHandshakeMsg()
	if err != nil {
		return err
	}
	if typ != want {
		return fmt.Errorf("leantls: expected handshake type %d, got %d", want, typ)
	}
	return nil
}

// parseCertificateList returns the wire DER chain leaf first. Pinned mode uses
// only the leaf but shares this one wire parser.
func parseCertificateList(body []byte) ([][]byte, error) {
	r := reader{buf: body}
	if _, err := r.vec8(); err != nil { // certificate_request_context
		return nil, err
	}
	list, err := r.vec24()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for !list.empty() {
		entry, err := list.vec24()
		if err != nil {
			return nil, err
		}
		if entry.len() == 0 {
			return nil, errors.New("leantls: the server sent an empty certificate in its chain")
		}
		out = append(out, bytes.Clone(entry.buf))
		// Skip per-certificate OCSP/SCT extensions; they do not establish identity.
		if _, err := list.vec16(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("leantls: the server sent an empty certificate list")
	}
	return out, nil
}

// ed25519Verifier checks pinned-mode signatures with the fixed key and algorithm.
func ed25519Verifier(key ed25519.PublicKey) SignatureVerifier {
	return func(alg uint16, signed, sig []byte) error {
		if alg != sigEd25519 {
			return fmt.Errorf("leantls: the server signed with algorithm %#04x; a pinned Ed25519 "+
				"peer must sign with Ed25519 (%#04x)", alg, sigEd25519)
		}
		if !ed25519.Verify(key, signed, sig) {
			return errors.New("leantls: the server's CertificateVerify signature is invalid")
		}
		return nil
	}
}

// verifyCertificateVerify invokes the verifier with the already-hashed
// transcript through Certificate. This package constructs §4.4.3 domain-
// separated signed content rather than delegating protocol framing.
func verifyCertificateVerify(body []byte, verify SignatureVerifier, transcriptHash []byte) error {
	r := reader{buf: body}
	alg, err := r.u16()
	if err != nil {
		return err
	}
	sig, err := r.vec16()
	if err != nil {
		return err
	}
	return verify(alg, certVerifyContent(transcriptHash, true), sig.buf)
}
