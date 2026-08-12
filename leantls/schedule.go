package leantls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// De key schedule van TLS 1.3 (RFC 8446 §7.1). Dit is het hart van de
// handshake en tegelijk het deel dat het makkelijkst stil fout gaat: één
// verkeerd label of één transcript-hash op het verkeerde moment levert geen
// foutmelding maar een sleutel die niet klopt, en dan faalt pas de Finished —
// vier stappen verderop.
//
// Daarom staat het hier apart en wordt het los getoetst tegen de uitgewerkte
// handshake van RFC 8448 (schedule_test.go). Alles hieronder is één-op-één de
// tekst van de RFC; de commentaren noemen de paragraaf zodat je het naast
// elkaar kunt leggen.
//
// Eén hash (SHA-256) en één AEAD (AES-128-GCM), dus alle maten zijn constant:
// 32 bytes secret, 16 bytes sleutel, 12 bytes IV.

const (
	hashLen = sha256.Size // 32
	keyLen  = 16          // AES-128
	ivLen   = 12          // AEAD nonce
)

func newHash() hash.Hash { return sha256.New() }

// expandLabel is HKDF-Expand-Label uit §7.1:
//
//	HkdfLabel = { uint16 length; opaque label<7..255>; opaque context<0..255> }
//
// met "tls13 " vóór elk label. De lengte zit ZOWEL in de info als in het
// gevraagde aantal bytes; dat is geen redundantie in de RFC maar domain
// separation, dus beide moeten kloppen.
func expandLabel(secret []byte, label string, ctx []byte, n int) []byte {
	var b builder
	b.u16(uint16(n))
	b.u8len(func() { b.bytes([]byte("tls13 " + label)) })
	b.u8len(func() { b.bytes(ctx) })
	out, err := hkdf.Expand(newHash, secret, string(b.buf), n)
	if err != nil {
		// Kan alleen bij een onmogelijke lengte (n > 255*hashLen) of een lege
		// secret, en beide zijn hier programmeerfouten en geen netwerkdata.
		panic("leantls: HKDF-Expand: " + err.Error())
	}
	return out
}

// deriveSecret is Derive-Secret uit §7.1: expandLabel over een transcript-hash.
func deriveSecret(secret []byte, label string, transcript []byte) []byte {
	return expandLabel(secret, label, transcript, hashLen)
}

// extract is HKDF-Extract met de argumentvolgorde van de RFC-tekening (salt
// boven, IKM van links). Go's hkdf.Extract neemt ze omgekeerd, en dat is
// precies het soort verwisseling dat een sleutel stil verkeerd maakt.
func extract(salt, ikm []byte) []byte {
	out, err := hkdf.Extract(newHash, ikm, salt)
	if err != nil {
		panic("leantls: HKDF-Extract: " + err.Error())
	}
	return out
}

// secrets houdt de takken van de schedule vast die we nog nodig hebben.
type secrets struct {
	handshake []byte // Handshake Secret
	master    []byte // Master Secret
}

// zeros is de all-zero IKM/salt die de schedule op twee plekken voorschrijft.
var zeros = make([]byte, hashLen)

// newSecrets zet de schedule op tot en met het Master Secret. shared is de
// X25519-uitkomst; er is geen PSK, dus het Early Secret komt uit nullen.
//
//	         0 -> HKDF-Extract = Early Secret
//	Derive-Secret(., "derived", "") -> salt
//	 (EC)DHE -> HKDF-Extract = Handshake Secret
//	Derive-Secret(., "derived", "") -> salt
//	         0 -> HKDF-Extract = Master Secret
func newSecrets(shared []byte) secrets {
	early := extract(nil, zeros)
	hs := extract(deriveSecret(early, "derived", emptyHash()), shared)
	master := extract(deriveSecret(hs, "derived", emptyHash()), zeros)
	return secrets{handshake: hs, master: master}
}

// emptyHash is Transcript-Hash("") — de context van de twee "derived"-stappen.
func emptyHash() []byte {
	h := newHash()
	return h.Sum(nil)
}

// trafficKeys zijn de sleutel en de IV van één richting, plus het secret zelf
// (dat hebben we nog nodig voor de Finished en voor een KeyUpdate).
type trafficKeys struct {
	secret []byte
	key    []byte
	iv     []byte
}

// keysFrom leidt sleutel en IV af uit een traffic secret (§7.3).
func keysFrom(secret []byte) trafficKeys {
	return trafficKeys{
		secret: secret,
		key:    expandLabel(secret, "key", nil, keyLen),
		iv:     expandLabel(secret, "iv", nil, ivLen),
	}
}

// next is de sleutelwissel van een KeyUpdate (§7.2): het secret vernieuwt
// zichzelf met het label "traffic upd" en daaruit komen nieuwe sleutels.
func (t trafficKeys) next() trafficKeys {
	return keysFrom(expandLabel(t.secret, "traffic upd", nil, hashLen))
}

// finishedData is de verify_data van een Finished-bericht (§4.4.4):
// HMAC(finished_key, Transcript-Hash(alles tot en met het vorige bericht)).
func finishedData(baseSecret, transcript []byte) []byte {
	fk := expandLabel(baseSecret, "finished", nil, hashLen)
	m := hmac.New(newHash, fk)
	m.Write(transcript)
	return m.Sum(nil)
}

// certVerifyContent is wat er ONDER de handtekening van CertificateVerify zit
// (§4.4.3): 64 spaties, een contextstring, een nulbyte, en dan de
// transcript-hash. Die 64 spaties zijn er zodat een handtekening uit een ander
// protocol nooit als TLS-handtekening kan gelden — dus ze zijn geen opvulling
// en mogen niet weg.
func certVerifyContent(transcript []byte, server bool) []byte {
	who := "client"
	if server {
		who = "server"
	}
	out := make([]byte, 0, 64+40+len(transcript))
	for range 64 {
		out = append(out, 0x20)
	}
	out = append(out, []byte("TLS 1.3, "+who+" CertificateVerify")...)
	out = append(out, 0)
	return append(out, transcript...)
}

// nonce is de AEAD-nonce van record seq (§5.3): het 64-bits recordnummer
// links met nullen opgevuld tot de IV-lengte, dan XOR met de IV. Het
// recordnummer begint bij nul na élke sleutelwissel.
func nonce(iv []byte, seq uint64) []byte {
	out := make([]byte, len(iv))
	binary.BigEndian.PutUint64(out[len(out)-8:], seq)
	for i := range out {
		out[i] ^= iv[i]
	}
	return out
}
