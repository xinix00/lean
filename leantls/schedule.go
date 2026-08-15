package leantls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// TLS 1.3 key schedule (RFC 8446 §7.1), isolated and tested against the worked
// RFC 8448 handshake. A wrong label or transcript checkpoint silently derives
// bad keys and surfaces only at Finished, so each step mirrors the RFC.
// SHA-256 and AES-128-GCM fix sizes at a 32-byte secret, 16-byte key, and
// 12-byte IV.

const (
	hashLen = sha256.Size // 32
	keyLen  = 16          // AES-128
	ivLen   = 12          // AEAD nonce
)

func newHash() hash.Hash { return sha256.New() }

// expandLabel implements HKDF-Expand-Label from §7.1:
//
//	HkdfLabel = { uint16 length; opaque label<7..255>; opaque context<0..255> }
//
// with "tls13 " before each label. Length appears in both info and output size
// for domain separation.
func expandLabel(secret []byte, label string, ctx []byte, n int) []byte {
	var b builder
	b.u16(uint16(n))
	b.u8len(func() { b.bytes([]byte("tls13 " + label)) })
	b.u8len(func() { b.bytes(ctx) })
	out, err := hkdf.Expand(newHash, secret, string(b.buf), n)
	if err != nil {
		// Only impossible lengths or empty secrets reach this programmer error.
		panic("leantls: HKDF-Expand: " + err.Error())
	}
	return out
}

// deriveSecret implements §7.1 Derive-Secret over a transcript hash.
func deriveSecret(secret []byte, label string, transcript []byte) []byte {
	return expandLabel(secret, label, transcript, hashLen)
}

// extract preserves the RFC diagram's salt, IKM argument order while adapting
// Go's reversed hkdf.Extract signature.
func extract(salt, ikm []byte) []byte {
	out, err := hkdf.Extract(newHash, ikm, salt)
	if err != nil {
		panic("leantls: HKDF-Extract: " + err.Error())
	}
	return out
}

// secrets retains the schedule branches used later.
type secrets struct {
	handshake []byte // Handshake Secret
	master    []byte // Master Secret
}

// zeros is the all-zero IKM/salt required at two schedule steps.
var zeros = make([]byte, hashLen)

// newSecrets derives through Master Secret from the X25519 shared value. There
// is no PSK, so Early Secret starts from zeros.
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

// emptyHash is Transcript-Hash(""), used by both "derived" steps.
func emptyHash() []byte {
	h := newHash()
	return h.Sum(nil)
}

// trafficKeys contains one direction's key, IV, and secret retained for
// Finished and KeyUpdate.
type trafficKeys struct {
	secret []byte
	key    []byte
	iv     []byte
}

// keysFrom derives key and IV from a traffic secret (§7.3).
func keysFrom(secret []byte) trafficKeys {
	return trafficKeys{
		secret: secret,
		key:    expandLabel(secret, "key", nil, keyLen),
		iv:     expandLabel(secret, "iv", nil, ivLen),
	}
}

// next applies the §7.2 KeyUpdate using the "traffic upd" label.
func (t trafficKeys) next() trafficKeys {
	return keysFrom(expandLabel(t.secret, "traffic upd", nil, hashLen))
}

// finishedData returns §4.4.4 Finished verify_data over the prior transcript.
func finishedData(baseSecret, transcript []byte) []byte {
	fk := expandLabel(baseSecret, "finished", nil, hashLen)
	m := hmac.New(newHash, fk)
	m.Write(transcript)
	return m.Sum(nil)
}

// certVerifyContent builds §4.4.3 CertificateVerify input. Its 64 spaces,
// context, NUL, and transcript hash provide cross-protocol domain separation.
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

// nonce derives the §5.3 AEAD nonce by zero-extending seq to IV length and
// XORing the IV. Sequence restarts after each key update.
func nonce(iv []byte, seq uint64) []byte {
	out := make([]byte, len(iv))
	binary.BigEndian.PutUint64(out[len(out)-8:], seq)
	for i := range out {
		out[i] ^= iv[i]
	}
	return out
}
