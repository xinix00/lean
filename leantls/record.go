package leantls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// TLS 1.3 record layer (RFC 8446 §5). Three 1.3-specific rules stay together:
//
//   - TLSInnerPlaintext carries the real content type inside encryption; the
//     outer type is always application_data(23).
//   - The nonce comes from an untransmitted record sequence that resets after
//     each key update, so both sides must count identically (§5.3).
//   - AAD is the five wire header bytes, including ciphertext length.
//
// change_cipher_spec stays plaintext as a semantic-free middlebox compatibility
// record. This client sends one and ignores received copies.

const (
	recCCS       = 20
	recAlert     = 21
	recHandshake = 22
	recAppData   = 23

	// maxPlain is the RFC plaintext-fragment limit (2^14).
	maxPlain = 1 << 14
	// maxCipher includes content type, AEAD tag, and §5.2 allowance. Reject the
	// advertised length before allocating peer-controlled memory.
	maxCipher = maxPlain + 256

	// alertCloseNotify is the clean shutdown signal (§6.1).
	alertCloseNotify = 0
)

// aeadFor creates one direction's AES-128-GCM. The single suite needs no
// negotiation.
func aeadFor(k trafficKeys) cipher.AEAD {
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		panic("leantls: aes: " + err.Error()) // Schedule keys are always 16 bytes.
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic("leantls: gcm: " + err.Error())
	}
	return g
}

// writeFull performs exactly one underlying Write and rejects a short success.
// It deliberately does not retry: resuming a partial TLS record would corrupt
// the wire stream.
func writeFull(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

// writeRecord sends plaintext before keys exist and encrypted
// TLSInnerPlaintext afterward. Before Client returns the handshake owns the
// connection exclusively; afterward callers hold wmu. Every failure is sticky:
// its record sequence has been consumed and ciphertext may be partial.
func (c *Conn) writeRecord(typ byte, data []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}

	var wire []byte
	if c.wAEAD == nil {
		hdr := [5]byte{typ, 3, 3, byte(len(data) >> 8), byte(len(data))}
		wire = append(hdr[:], data...)
	} else {
		// TLSInnerPlaintext is content followed by its type. §5.4 padding is
		// optional and omitted to avoid bandwidth cost on small nodes.
		inner := make([]byte, 0, len(data)+1)
		inner = append(inner, data...)
		inner = append(inner, typ)

		hdr := [5]byte{recAppData, 3, 3, 0, 0}
		binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+c.wAEAD.Overhead()))

		wire = make([]byte, 0, len(hdr)+len(inner)+c.wAEAD.Overhead())
		wire = append(wire, hdr[:]...)
		wire = c.wAEAD.Seal(wire, nonce(c.wKeys.iv, c.wSeq), inner, hdr[:])
		c.wSeq++
	}

	c.writeErr = writeFull(c.conn, wire)
	return c.writeErr
}

// readRecord returns one record's actual content type and payload. For encrypted
// records, the type comes from TLSInnerPlaintext rather than the outer header.
func (c *Conn) readRecord() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n > maxCipher {
		return 0, nil, fmt.Errorf("leantls: record of %d bytes announced, limit is %d", n, maxCipher)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return 0, nil, err
	}

	// change_cipher_spec remains plaintext after keys are installed.
	if c.rAEAD == nil || hdr[0] == recCCS {
		return hdr[0], body, nil
	}

	plain, err := c.rAEAD.Open(body[:0], nonce(c.rKeys.iv, c.rSeq), body, hdr[:])
	if err != nil {
		// Decryption failure is fatal: skipping would desynchronize sequence
		// numbers and make every later record unreadable.
		return 0, nil, fmt.Errorf("leantls: record %d failed to decrypt", c.rSeq)
	}
	c.rSeq++

	// The final non-zero byte is content type; later zeros are §5.4 padding.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, fmt.Errorf("leantls: encrypted record carries no content type")
	}
	return plain[i], plain[:i], nil
}

// alertError maps alerts to readable errors. close_notify becomes io.EOF so
// callers observe an ordinary clean stream end.
func alertError(payload []byte) error {
	if len(payload) == 2 && payload[1] == alertCloseNotify {
		return io.EOF
	}
	if len(payload) != 2 {
		return fmt.Errorf("leantls: malformed alert")
	}
	return fmt.Errorf("leantls: peer sent alert level %d code %d (%s)",
		payload[0], payload[1], alertName(payload[1]))
}

// alertName names common operational alerts; uncommon §6 codes remain readable
// as numbers.
func alertName(code byte) string {
	switch code {
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 109:
		return "missing_extension"
	case 112:
		return "unrecognized_name"
	default:
		return "unnamed"
	}
}
