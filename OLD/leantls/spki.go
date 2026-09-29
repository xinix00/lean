package leantls

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Extract a public key from X.509 without crypto/x509. Pinned mode needs only to
// determine whether the certificate contains Config.PeerKey; it performs no
// chain, name, validity, or revocation checks and cannot verify arbitrary public
// servers.
//
// Walk DER to subjectPublicKeyInfo and require the exact RFC 8410 §4 Ed25519
// form: OID 1.3.101.112, no parameters, and a 32-byte key:
//
//	30 2a          SEQUENCE, 42 bytes            (SubjectPublicKeyInfo)
//	   30 05       SEQUENCE, 5 bytes             (AlgorithmIdentifier)
//	      06 03 2b 65 70                         (OID 1.3.101.112 = Ed25519)
//	   03 21 00    BIT STRING, 33 bytes, 0 unused
//	   <32 bytes>
//
// RSA and ECDSA certificates fail clearly. The bounded DER walker rejects
// indefinite lengths and any deviation from the six required fields.

// ed25519SPKIBody is the fixed Ed25519 SubjectPublicKeyInfo content before the
// key bytes.
var ed25519SPKIBody = []byte{
	0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: OID 1.3.101.112
	0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
}

const (
	derSequence  = 0x30
	derInteger   = 0x02
	derContext0  = 0xa0 // [0] EXPLICIT, optional version field
	derBitString = 0x03
)

var errDER = errors.New("leantls: malformed certificate (DER)")

// derValue reads one leading TLV and returns its tag, body, and remainder.
func derValue(p []byte) (tag byte, body, rest []byte, err error) {
	if len(p) < 2 {
		return 0, nil, nil, errDER
	}
	tag = p[0]
	n := int(p[1])
	p = p[2:]
	switch {
	case n < 0x80:
		// Short form: length is in this byte.
	case n == 0x80:
		return 0, nil, nil, errDER // DER forbids indefinite length.
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

// derSeq requires a leading SEQUENCE and returns its contents.
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

// peerKeyFromCert extracts the Ed25519 key from a DER certificate.
func peerKeyFromCert(der []byte) (ed25519.PublicKey, error) {
	cert, err := derSeq(der) // Certificate ::= SEQUENCE
	if err != nil {
		return nil, err
	}
	tbs, err := derSeq(cert) // tbsCertificate ::= SEQUENCE
	if err != nil {
		return nil, err
	}

	// Skip RFC 5280 §4.1 fields before subjectPublicKeyInfo: optional explicit
	// version, then serialNumber, signature, issuer, validity, and subject.
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

	// Require exact Ed25519 subjectPublicKeyInfo contents while leaving length
	// encoding to the DER reader.
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
