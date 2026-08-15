package leantls

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

func TestScheduleRFC8448(t *testing.T) {
	shared := unhex(t, `8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
		35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d`)

	chsh := unhex(t, `86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
		d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8`)

	early := extract(nil, zeros)
	want(t, "early secret", early, unhex(t, `33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
		e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a`))

	derived := deriveSecret(early, "derived", emptyHash())
	want(t, `derive secret for handshake "tls13 derived"`, derived, unhex(t, `6f 26 15 a1 08 c7 02 c5
		67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba`))

	s := newSecrets(shared)
	want(t, "handshake secret", s.handshake, unhex(t, `1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
		01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac`))
	want(t, "master secret", s.master, unhex(t, `18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
		47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19`))

	chs := deriveSecret(s.handshake, "c hs traffic", chsh)
	want(t, `derive secret "tls13 c hs traffic"`, chs, unhex(t, `b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
		2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21`))

	shs := deriveSecret(s.handshake, "s hs traffic", chsh)
	want(t, `derive secret "tls13 s hs traffic"`, shs, unhex(t, `b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
		37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38`))

	k := keysFrom(shs)
	want(t, "server handshake key", k.key, unhex(t, `3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc`))
	want(t, "server handshake iv", k.iv, unhex(t, `5d 31 3e b2 67 12 76 ee 13 00 0b 30`))
}

func want(t *testing.T, what string, got, exp []byte) {
	t.Helper()
	if !bytes.Equal(got, exp) {
		t.Errorf("%s:\n got %x\nwant %x", what, got, exp)
	}
}

func TestNonce(t *testing.T) {
	iv := unhex(t, `5d 31 3e b2 67 12 76 ee 13 00 0b 30`)
	if got := nonce(iv, 0); !bytes.Equal(got, iv) {
		t.Errorf("record 0 hoort de IV zelf te zijn: %x", got)
	}

	got := nonce(iv, 1)
	if !bytes.Equal(got[:11], iv[:11]) || got[11] != iv[11]^1 {
		t.Errorf("record 1: %x", got)
	}

	got = nonce(iv, 1<<40)
	if bytes.Equal(got[:8], iv[:8]) {
		t.Errorf("hoge recordnummers raken de bovenste bytes niet: %x", got)
	}
}
