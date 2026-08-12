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

// De client-handshake van TLS 1.3 (RFC 8446 §4), in één rechte lijn: één
// versie, één suite, één groep, één signatuuralgoritme. Er is dus niets te
// onderhandelen en niets te kiezen — elke afwijking van de server is een fout
// en niet een geval om op te vangen. Dat is waarom dit bestand kort is.
//
// Wat de server ons stuurt en wat we ermee doen:
//
//	ServerHello         → de sleutelhelft van de server, versie 1.3 toetsen
//	EncryptedExtensions → overslaan (we vroegen niets dat een antwoord eist)
//	Certificate         → de Ed25519-sleutel eruit, tegen de pin leggen
//	CertificateVerify   → handtekening over het transcript, met die sleutel
//	Finished            → HMAC over het transcript, met het handshake-secret
//
// Die laatste drie zijn samen het hele bewijs: de handtekening zegt "wie de
// pin-sleutel heeft, praat hier", en de Finished zegt "en het is dezelfde partij
// die deze sleuteluitwisseling deed". Zonder de Finished zou een tussenpartij de
// sleuteluitwisseling kunnen overnemen en de handtekening doorsluizen.

const (
	// Handshake-berichttypes die wij tegenkomen (§4).
	hsClientHello         = 1
	hsServerHello         = 2
	hsNewSessionTicket    = 4
	hsEncryptedExtensions = 8
	hsCertificate         = 11
	hsCertificateRequest  = 13
	hsCertificateVerify   = 15
	hsFinished            = 20
	hsKeyUpdate           = 24

	// Extensies.
	extServerName        = 0
	extSupportedGroups   = 10
	extSignatureAlgs     = 13
	extSupportedVersions = 43
	extKeyShare          = 51

	versionTLS13 = 0x0304
	// legacyVersion is wat er in het version-veld van ClientHello/ServerHello
	// staat sinds 1.3: altijd 1.2, en de echte versie zit in een extensie.
	legacyVersion = 0x0303

	groupX25519    = 0x001d
	sigEd25519     = 0x0807
	suiteAES128GCM = 0x1301
)

// helloRetryRandom is de vaste ServerHello.random waarmee een server zegt "doe
// het opnieuw met een andere groep" (§4.1.3). Wij bieden alleen X25519 aan, dus
// als dit langskomt vraagt de server iets dat we niet hebben — dan is stoppen
// met een duidelijke melding het enige eerlijke antwoord.
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// handshake voert de volledige clientkant uit. Bij terugkeer staan de
// applicatiesleutels en is de verbinding bruikbaar.
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

	// --- sleutels ----------------------------------------------------------
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

	// --- de versleutelde vlucht van de server ------------------------------
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
	// HIER wordt de tegenpartij vertrouwd of niet, en het is de enige plek. Twee
	// vormen, en welke het is heeft Client al vastgesteld:
	//
	//   - een gepinde sleutel: één vergelijking, geen keten, geen namen, geen
	//     datums. Wat er niet is, kan ook niet fout gaan.
	//   - een haak van de aanroeper: die krijgt de keten zoals hij op de draad
	//     stond en geeft terug hoe de handtekening getoetst wordt.
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

	// CertificateVerify gaat over het transcript TOT EN MET Certificate, dus de
	// hash moet vóór het lezen van het volgende bericht genomen worden.
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

	// --- onze kant afsluiten ----------------------------------------------
	// De applicatiesleutels komen uit het transcript tot en met de Finished van
	// de server; onze eigen Finished zit er dus NIET in.
	afterFin := c.hash()

	// change_cipher_spec: betekent niets in 1.3, maar er staat nog genoeg
	// middleware op de wereld die een handshake zonder dit record laat vallen.
	// Zes bytes, en hij gaat plaintext (§5) — dus vóór we onze sleutels zetten
	// zou het ook mogen, maar de wAEAD-check in writeRecord doet dat niet, dus
	// sturen we hem hier expliciet als plaintext-record.
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
	// Het transcript is klaar met zijn werk; niet laten liggen (het bevat het
	// certificaat en groeit met elke post-handshake boodschap).
	c.transcript = nil
	return nil
}

// sigAlgs geeft de algoritmes die we aanbieden: wat de config zegt, of alleen
// Ed25519 als hij niets zegt. Die default hoort bij de gepinde modus en is
// bewust smal — een lijst die breder is dan wat je kunt toetsen, levert een
// handshake die pas bij de handtekening omvalt.
func (c *Conn) sigAlgs() []uint16 {
	if len(c.cfg.SignatureAlgorithms) > 0 {
		return c.cfg.SignatureAlgorithms
	}
	return []uint16{sigEd25519}
}

// clientHello bouwt het bericht. De inhoud is volledig vast op de drie random
// velden na, dus dit is een opsomming en geen keuze.
func (c *Conn) clientHello(random, sessionID, share []byte) []byte {
	b := &builder{}
	b.u8(hsClientHello)
	b.u24len(func() {
		b.u16(legacyVersion)
		b.bytes(random)
		b.u8len(func() { b.bytes(sessionID) })
		b.u16len(func() { b.u16(suiteAES128GCM) })
		b.u8len(func() { b.u8(0) }) // compressie: alleen "geen"
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

// parseServerHello toetst wat er te toetsen valt en geeft de key share terug.
func (c *Conn) parseServerHello(body, sessionID []byte) ([]byte, error) {
	r := reader{buf: body}
	if _, err := r.u16(); err != nil { // legacy_version, niet leidend
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
	// De echo moet kloppen: hij is er tegen middleboxes, maar een server die
	// hem verzint praat niet tegen ons ClientHello.
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
	// legacy_compression_method moet nul zijn: compressie bestaat niet in 1.3, en
	// compressie in TLS is historisch een lek (CRIME). Een server die hier iets
	// anders zet, praat een ander protocol dan wij.
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
	// Zonder supported_versions is dit géén TLS 1.3-server maar een 1.2-server
	// die ons ClientHello aannam. Luid stoppen: dit pakket kan 1.2 niet, en
	// stil doorgaan zou betekenen dat we met de verkeerde sleutels verder gaan.
	if !sawVersion {
		return nil, fmt.Errorf("leantls: the server did not select TLS 1.3 " +
			"(no supported_versions in ServerHello) — this package speaks TLS 1.3 only")
	}
	if len(share) == 0 {
		return nil, fmt.Errorf("leantls: the server sent no key share")
	}
	return share, nil
}

// expect leest één handshake-bericht en eist het type. Voor berichten waarvan we
// de inhoud niet nodig hebben (EncryptedExtensions): ze moeten in het transcript,
// en dat regelt readHandshakeMsg.
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

// parseCertificateList geeft de keten in DER, leaf eerst — precies zoals de
// server hem stuurde. Ook de gepinde modus loopt hierlangs en pakt er alleen
// het eerste certificaat uit: één plek die het draadformaat kent.
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
		// Per-certificaat extensies (OCSP-stapling, SCT's): overslaan, ze spelen
		// geen rol in wie de tegenpartij is.
		if _, err := list.vec16(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("leantls: the server sent an empty certificate list")
	}
	return out, nil
}

// ed25519Verifier is de verifier van de gepinde modus: één algoritme, en de
// sleutel staat vast.
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

// verifyCertificateVerify laat de verifier de handtekening toetsen.
// transcriptHash is de Transcript-Hash tot en met Certificate — dus al gehasht;
// er gaat hier geen tweede hash over (dat is een fout die geen enkele test
// zonder echte tegenpartij zou vinden).
//
// Wat er precies ondertekend is, rekent dit pakket uit en niet de verifier: die
// 64 spaties plus contextstring (§4.4.3) zijn de domain separation, en die hoort
// niet bij de aanroeper te liggen.
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
