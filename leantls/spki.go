package leantls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// De publieke sleutel uit een X.509-certificaat halen, zónder crypto/x509.
//
// Dit is het hele verschil tussen dit pakket en crypto/tls, dus het verdient
// uitleg. Wat wij van een certificaat willen weten is precies één ding: staat
// de sleutel erin die wij VERWACHTEN (Config.PeerKey)? Geen keten, geen
// naamvergelijking, geen geldigheidsduur, geen revocatie. Dat maakt de code
// hieronder mogelijk — en het is meteen de grens van dit pakket: hiermee kun je
// géén willekeurige publieke server verifiëren.
//
// Wat we dus doen: langs de DER-structuur lopen naar het veld
// subjectPublicKeyInfo, en eisen dat dat veld BYTE VOOR BYTE de vorm van een
// Ed25519-sleutel heeft. Die vorm is vast (RFC 8410 §4) — algoritme-OID
// 1.3.101.112, geen parameters, 32 bytes sleutel — dus er valt niets te
// interpreteren:
//
//	30 2a          SEQUENCE, 42 bytes            (SubjectPublicKeyInfo)
//	   30 05       SEQUENCE, 5 bytes             (AlgorithmIdentifier)
//	      06 03 2b 65 70                         (OID 1.3.101.112 = Ed25519)
//	   03 21 00    BIT STRING, 33 bytes, 0 unused
//	   <32 bytes>
//
// Een certificaat met een RSA- of ECDSA-sleutel valt hier dus om met een
// duidelijke melding, en niet met een vage parse-fout: dat is regel 2 van lean
// (luid falen) op de plek waar het het meest telt.
//
// De DER-loper hieronder leest nooit buiten zijn buffer en accepteert geen
// onbepaalde lengtes. Hij hoeft ook niet meer te kunnen: hij loopt langs zes
// velden van een structuur die de RFC vastlegt, en alles wat afwijkt is een
// fout in plaats van een geval om op te vangen.

// ed25519SPKIBody is de vaste INHOUD van een Ed25519-SubjectPublicKeyInfo (de
// 42 bytes binnen de buitenste SEQUENCE), op de sleutel na.
var ed25519SPKIBody = []byte{
	0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: OID 1.3.101.112
	0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 ongebruikte bits
}

const (
	derSequence  = 0x30
	derInteger   = 0x02
	derContext0  = 0xa0 // [0] EXPLICIT — het optionele version-veld
	derBitString = 0x03
)

var errDER = errors.New("leantls: malformed certificate (DER)")

// derValue leest één TLV op de kop van p en geeft tag, body en de rest.
func derValue(p []byte) (tag byte, body, rest []byte, err error) {
	if len(p) < 2 {
		return 0, nil, nil, errDER
	}
	tag = p[0]
	n := int(p[1])
	p = p[2:]
	switch {
	case n < 0x80:
		// korte vorm: de lengte staat in deze byte
	case n == 0x80:
		return 0, nil, nil, errDER // onbepaalde lengte bestaat niet in DER
	default:
		count := n & 0x7f
		if count > 4 || len(p) < count {
			return 0, nil, nil, errDER
		}
		n = 0
		for _, b := range p[:count] {
			n = n<<8 | int(b)
		}
		p = p[count:]
	}
	if n < 0 || len(p) < n {
		return 0, nil, nil, errDER
	}
	return tag, p[:n], p[n:], nil
}

// derSeq eist een SEQUENCE op de kop van p en geeft de inhoud.
func derSeq(p []byte) ([]byte, error) {
	tag, body, _, err := derValue(p)
	if err != nil {
		return nil, err
	}
	if tag != derSequence {
		return nil, errDER
	}
	return body, nil
}

// peerKeyFromCert haalt de Ed25519-sleutel uit een certificaat in DER-vorm.
func peerKeyFromCert(der []byte) (ed25519.PublicKey, error) {
	cert, err := derSeq(der) // Certificate ::= SEQUENCE
	if err != nil {
		return nil, err
	}
	tbs, err := derSeq(cert) // tbsCertificate ::= SEQUENCE
	if err != nil {
		return nil, err
	}

	// De velden vóór subjectPublicKeyInfo overslaan (RFC 5280 §4.1):
	// version is optioneel en dan [0] EXPLICIT; daarna serialNumber, signature,
	// issuer, validity en subject — elk precies één TLV.
	rest := tbs
	if len(rest) > 0 && rest[0] == derContext0 {
		if _, _, rest, err = derValue(rest); err != nil {
			return nil, err
		}
	}
	for i, want := range []byte{derInteger, derSequence, derSequence, derSequence, derSequence} {
		var tag byte
		tag, _, rest, err = derValue(rest)
		if err != nil {
			return nil, err
		}
		if tag != want {
			return nil, fmt.Errorf("%w: field %d has tag %#x, expected %#x", errDER, i, tag, want)
		}
	}

	// En dan staat subjectPublicKeyInfo vooraan. Zijn inhoud moet exact de
	// Ed25519-vorm hebben; alles anders is geen sleutel die dit pakket kan
	// gebruiken. Vergelijken op de INHOUD en niet op de bytes-inclusief-header,
	// zodat er geen aanname over de lengtecodering in de vergelijking sluipt.
	tag, spki, _, err := derValue(rest)
	if err != nil {
		return nil, err
	}
	if tag != derSequence || len(spki) != len(ed25519SPKIBody)+ed25519.PublicKeySize ||
		!bytes.Equal(spki[:len(ed25519SPKIBody)], ed25519SPKIBody) {
		return nil, fmt.Errorf("leantls: server certificate does not carry an Ed25519 key — "+
			"this package only speaks Ed25519 (SubjectPublicKeyInfo is %d bytes, tag %#x)", len(spki), tag)
	}
	return ed25519.PublicKey(bytes.Clone(spki[len(ed25519SPKIBody):])), nil
}
