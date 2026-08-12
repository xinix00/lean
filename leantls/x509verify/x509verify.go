// Package x509verify is de gewone https-vorm van vertrouwen voor leantls: een
// echte certificaatketen, gevalideerd door crypto/x509.
//
// Het staat apart van leantls omdat de kosten de keuze horen te volgen: wie een
// gepinde sleutel gebruikt, betaalt crypto/x509 niet — leantls importeert het
// niet.
//
// De meting, en let op de BASISLIJN — die hebben we eerst verkeerd gekozen.
// Gemeten (12-08, tamago/riscv64, `-w -T 0x84010000`, dezelfde download):
//
//	net/http + crypto/tls ...................... 5,53 MB   (wat een kern nu doet)
//	leanhttp + crypto/tls ..................... 4,43 MB   (-1,10)
//	leanhttp + leantls + dit pakket ........... 3,80 MB   (-1,73)
//
// Dus: **1,73 MB** voor de hele stapel, waarvan 0,63 MB van dit pakket plus
// leantls en 1,10 MB van leanhttp.
//
// Eerst stond hier dat dit pakket maar 0,36 MB opleverde en dat je beter
// crypto/tls moest gebruiken. Dat was tegen de verkeerde basislijn gemeten:
// crypto/tls LOS, terwijl niemand een bestand ophaalt met crypto/tls zonder
// net/http erbovenop. En de probe deed geen echte Dial, dus was de helft van
// crypto/tls wegge-optimaliseerd.
//
// Belangrijker nog is wat die stapel-meting laat zien: leanhttp weigert een
// https-URL zonder Call.Dial, en de enige Dial die je hem kon geven was
// crypto/tls — waarmee de hele PKI weer binnenkwam en leanhttp's eigen 1,10 MB
// niet te verzilveren was. Dit pakket plus leantls is wat die winst ontsluit.
// Dát is de reden dat het bestaat, niet zijn eigen 0,63 MB.
//
// Wat dit pakket wél goed doet: het laat de keten door crypto/x509 valideren in
// plaats van door eigen code. Dat is óók gemeten — een eigen X.509-parser plus
// ketenvalidatie plus rootvoorraad leverde ~0,2 MB op, tegen ~900 regels in
// precies de categorie waar de gaten in eigengebouwde TLS zitten (een leaf die
// als CA wordt geaccepteerd, een genegeerde pathLenConstraint, name constraints
// die niemand implementeert). Voor die 0,2 MB is de referentie beter, en die
// krijgt zijn rootvoorraad bovendien bijgewerkt met een `go get -u`.
//
// # Gebruik
//
//	// De roots: op een systeem met een trust store hoeft dit niet, op
//	// bare-metal wel — importeer golang.org/x/crypto/x509roots/fallback, of
//	// bouw zelf een pool.
//	conn, err := leantls.Dial("tcp", "github.com:443", &leantls.Config{
//	    ServerName:          "github.com",
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	})
package x509verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// De TLS-codes voor de handtekening van de server (RFC 8446 §4.2.3). Alleen wat
// een TLS 1.3-server MAG gebruiken voor CertificateVerify: PKCS#1v1.5 staat daar
// niet bij — dat mag sinds 1.3 alleen nog in certificaten, niet in de handshake.
const (
	ECDSASecp256r1SHA256 uint16 = 0x0403
	ECDSASecp384r1SHA384 uint16 = 0x0503
	ECDSASecp521r1SHA512 uint16 = 0x0603
	RSAPSSRSAeSHA256     uint16 = 0x0804
	RSAPSSRSAeSHA384     uint16 = 0x0805
	RSAPSSRSAeSHA512     uint16 = 0x0806
	Ed25519              uint16 = 0x0807
)

// SignatureAlgorithms is de lijst om in Config.SignatureAlgorithms te zetten:
// alles wat dit pakket kan toetsen, in de volgorde die we prefereren (ECDSA
// eerst — kortere handtekeningen en goedkoper op een kleine core).
//
// Aanbieden wat je kunt toetsen, en niets meer: een server kiest altijd uit deze
// lijst, dus een algoritme erin dat wij niet kunnen verifiëren levert een
// handshake die pas bij de handtekening omvalt.
var SignatureAlgorithms = []uint16{
	ECDSASecp256r1SHA256,
	ECDSASecp384r1SHA384,
	ECDSASecp521r1SHA512,
	RSAPSSRSAeSHA256,
	RSAPSSRSAeSHA384,
	RSAPSSRSAeSHA512,
	Ed25519,
}

// Chain geeft een verifier voor leantls.Config.VerifyPeer die de keten door
// crypto/x509 laat valideren tegen roots. roots nil = de trust store van het
// systeem (op bare-metal: wat golang.org/x/crypto/x509roots/fallback heeft
// gezet).
//
// Het resultaat is toe te wijzen aan leantls.Config.VerifyPeer zonder dat dit
// pakket leantls importeert — de typen zijn structureel gelijk, en zo blijft dit
// een bouwsteen in plaats van een schakel in een keten van pakketten.
func Chain(roots *x509.CertPool) func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
	return chainAt(roots, nil)
}

// ChainAt is Chain met een vaste tijd in plaats van "nu". Voor een node zonder
// klok is dit geen luxe maar het verschil tussen werken en niet werken: vóór NTP
// staat de klok op 1970 en dan is élk certificaat "nog niet geldig" (in HopOS
// gemeten als `x509: certificate is not yet valid` op elke download). Wie hier
// een tijd meegeeft, kiest expliciet welke — en weet dus ook dat hij daarmee de
// geldigheidscontrole naar zijn hand zet.
func ChainAt(roots *x509.CertPool, at time.Time) func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
	return chainAt(roots, &at)
}

func chainAt(roots *x509.CertPool, at *time.Time) func([][]byte, string) (func(uint16, []byte, []byte) error, error) {
	return func(certs [][]byte, serverName string) (func(uint16, []byte, []byte) error, error) {
		if len(certs) == 0 {
			return nil, errors.New("x509verify: empty certificate chain")
		}
		parsed := make([]*x509.Certificate, len(certs))
		for i, der := range certs {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("x509verify: certificate %d: %w", i, err)
			}
			parsed[i] = c
		}
		// De keten zoals de server hem stuurde is een SUGGESTIE: crypto/x509
		// bouwt zelf het pad en gebruikt de rest als tussenliggende kandidaten.
		// Dat is precies waarom dit pakket bestaat en wij het niet zelf doen —
		// cross-signing maakt "volg de keten van boven naar beneden" onjuist.
		inter := x509.NewCertPool()
		for _, c := range parsed[1:] {
			inter.AddCert(c)
		}
		opts := x509.VerifyOptions{
			DNSName:       serverName,
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if at != nil {
			opts.CurrentTime = *at
		}
		if _, err := parsed[0].Verify(opts); err != nil {
			return nil, err
		}
		return verifierFor(parsed[0].PublicKey), nil
	}
}

// verifierFor toetst de CertificateVerify met de sleutel van het leaf.
//
// Let op wat hier NIET gebeurt: hashen met een algoritme dat de server koos maar
// niet bij de sleutel past. De code zegt zowel het algoritme als de hash, en
// beide moeten kloppen bij de sleutel die in het certificaat stond — anders zou
// een server met een RSA-sleutel een ECDSA-code kunnen kiezen en omgekeerd.
func verifierFor(pub crypto.PublicKey) func(uint16, []byte, []byte) error {
	return func(alg uint16, signed, sig []byte) error {
		if alg == Ed25519 {
			k, ok := pub.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("x509verify: server chose Ed25519 but its certificate holds a %T", pub)
			}
			if !ed25519.Verify(k, signed, sig) {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
			return nil
		}

		h, err := hashFor(alg)
		if err != nil {
			return err
		}
		sum := digest(h, signed)

		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if !isECDSA(alg) {
				return fmt.Errorf("x509verify: server chose %#04x but its certificate holds an ECDSA key", alg)
			}
			// De curve moet bij de code horen: ecdsa_secp256r1_sha256 met een
			// P-384-sleutel is geen geldige keuze, en accepteren zou een
			// server laten kiezen welke sterkte hij levert.
			if want := curveFor(alg); k.Curve.Params().Name != want {
				return fmt.Errorf("x509verify: server chose %#04x (%s) but its key is on %s",
					alg, want, k.Curve.Params().Name)
			}
			if !ecdsa.VerifyASN1(k, sum, sig) {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
		case *rsa.PublicKey:
			if isECDSA(alg) {
				return fmt.Errorf("x509verify: server chose %#04x but its certificate holds an RSA key", alg)
			}
			// TLS 1.3 schrijft PSS voor met een zoutlengte gelijk aan de hash
			// (§4.2.3). PKCS#1v1.5 mag in de handshake niet meer, en dat is
			// geen detail: dat is de aanval van Bleichenbacher.
			if err := rsa.VerifyPSS(k, h, sum, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       h,
			}); err != nil {
				return errors.New("x509verify: CertificateVerify signature is invalid")
			}
		default:
			return fmt.Errorf("x509verify: cannot verify a signature with a %T key", pub)
		}
		return nil
	}
}

func hashFor(alg uint16) (crypto.Hash, error) {
	switch alg {
	case ECDSASecp256r1SHA256, RSAPSSRSAeSHA256:
		return crypto.SHA256, nil
	case ECDSASecp384r1SHA384, RSAPSSRSAeSHA384:
		return crypto.SHA384, nil
	case ECDSASecp521r1SHA512, RSAPSSRSAeSHA512:
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("x509verify: server chose signature algorithm %#04x, which this package "+
		"does not offer (see SignatureAlgorithms)", alg)
}

func digest(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	default:
		s := sha512.Sum512(b)
		return s[:]
	}
}

func isECDSA(alg uint16) bool {
	return alg == ECDSASecp256r1SHA256 || alg == ECDSASecp384r1SHA384 || alg == ECDSASecp521r1SHA512
}

func curveFor(alg uint16) string {
	switch alg {
	case ECDSASecp256r1SHA256:
		return "P-256"
	case ECDSASecp384r1SHA384:
		return "P-384"
	default:
		return "P-521"
	}
}
