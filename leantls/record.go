package leantls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// De recordlaag van TLS 1.3 (RFC 8446 §5). Drie dingen die anders zijn dan in
// 1.2 en die precies daarom hier bij elkaar staan:
//
//   - Er is één ciphertext-vorm. Het echte contenttype zit BINNEN de versleuteling
//     (TLSInnerPlaintext), en buiten staat altijd application_data(23). Wie het
//     buitenste type gebruikt om te beslissen wat iets is, leest het verkeerde
//     veld.
//   - De nonce komt niet van de draad maar uit het recordnummer (§5.3). Dat
//     nummer begint bij nul na élke sleutelwissel en wordt nooit verstuurd, dus
//     zender en ontvanger moeten exact gelijk tellen — één overgeslagen record
//     en niets ontsleutelt meer.
//   - De AAD is de vijf headerbytes zoals ze op de draad staan, inclusief de
//     lengte van de ciphertext. Niet van de plaintext.
//
// change_cipher_spec blijft plaintext, ook ná de sleutelwissel: het is in 1.3
// een leeg middlebox-compatibiliteitsrecord zonder betekenis. Wij sturen er één
// en negeren alles wat we ervan terugkrijgen.

const (
	recCCS       = 20
	recAlert     = 21
	recHandshake = 22
	recAppData   = 23

	// maxPlain is de grens die de RFC aan een plaintext-fragment stelt (2^14).
	maxPlain = 1 << 14
	// maxCipher is wat een ciphertext-record hoogstens mag zijn: 2^14 plus het
	// contenttype, de AEAD-tag en de marge die §5.2 toestaat. Een header die
	// meer aankondigt weigeren we vóór we ook maar één byte body lezen — dat is
	// de enige plek waar een tegenpartij ons geheugen zou kunnen laten claimen.
	maxCipher = maxPlain + 256

	// alertCloseNotify is de nette afsluiting (§6.1).
	alertCloseNotify = 0
)

// aeadFor maakt de AES-128-GCM van een richting. Eén suite, dus dit is de enige
// plek waar een cipher gekozen wordt en er valt niets te negotiëren.
func aeadFor(k trafficKeys) cipher.AEAD {
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		panic("leantls: aes: " + err.Error()) // sleutel komt uit de schedule, altijd 16 bytes
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic("leantls: gcm: " + err.Error())
	}
	return g
}

// writeRecord schrijft één record. Vóór de sleutelwissel (aead == nil) gaat het
// plaintext de draad op; daarna versleuteld met het echte type erin verstopt.
func (c *Conn) writeRecord(typ byte, data []byte) error {
	if c.wAEAD == nil {
		hdr := [5]byte{typ, 3, 3, byte(len(data) >> 8), byte(len(data))}
		if _, err := c.conn.Write(append(hdr[:], data...)); err != nil {
			return err
		}
		return nil
	}

	// TLSInnerPlaintext: inhoud, dan het echte type. Geen padding — dat is
	// toegestaan (§5.4) en wat je ermee koopt (lengtes verhullen) betaal je in
	// bandbreedte op een node die daar weinig van heeft.
	inner := make([]byte, 0, len(data)+1)
	inner = append(inner, data...)
	inner = append(inner, typ)

	hdr := [5]byte{recAppData, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+c.wAEAD.Overhead()))

	out := make([]byte, 0, len(hdr)+len(inner)+c.wAEAD.Overhead())
	out = append(out, hdr[:]...)
	out = c.wAEAD.Seal(out, nonce(c.wKeys.iv, c.wSeq), inner, hdr[:])
	c.wSeq++
	_, err := c.conn.Write(out)
	return err
}

// readRecord leest één record en geeft het CONTENTTYPE en de payload. Bij een
// versleuteld record is dat het type van binnen, niet dat van de header.
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

	// change_cipher_spec blijft altijd plaintext, ook als de sleutels al staan.
	if c.rAEAD == nil || hdr[0] == recCCS {
		return hdr[0], body, nil
	}

	plain, err := c.rAEAD.Open(body[:0], nonce(c.rKeys.iv, c.rSeq), body, hdr[:])
	if err != nil {
		// Geen detail naar buiten: welk record faalde is voor een aanvaller
		// informatie en voor ons niets. Dat dit een harde fout is en geen
		// overgeslagen record is opzet — een gat in de recordnummering maakt
		// alles erna onleesbaar, dus doorgaan heeft geen betekenis.
		return 0, nil, fmt.Errorf("leantls: record %d failed to decrypt", c.rSeq)
	}
	c.rSeq++

	// Het echte type is de laatste byte die niet nul is; alles erachter is
	// padding (§5.4).
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, fmt.Errorf("leantls: encrypted record carries no content type")
	}
	return plain[i], plain[:i], nil
}

// alertError maakt van een alert-record een leesbare fout. close_notify is geen
// fout maar het einde: die geeft io.EOF, zodat een aanroeper hem als een gewoon
// streameinde behandelt.
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

// alertName geeft de codes die je in de praktijk tegenkomt een naam. Niet de
// hele tabel uit §6: wat hier staat is wat een operator moet kunnen lezen
// zonder de RFC ernaast, de rest is een nummer en dat is genoeg.
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
