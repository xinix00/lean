package leanrand

import (
	"strings"
	"testing"
	"time"
)

func TestBytesLengte(t *testing.T) {
	if b := Bytes(32); len(b) != 32 {
		t.Errorf("len = %d", len(b))
	}
	if b := Bytes(0); b != nil {
		t.Errorf("Bytes(0) = %v, wilde nil", b)
	}
	if b := Bytes(-1); b != nil {
		t.Errorf("Bytes(-1) = %v, wilde nil", b)
	}
}

func TestBytesVultEchtVol(t *testing.T) {

	a, b := Bytes(64), Bytes(64)
	if string(a) == string(b) {
		t.Error("twee trekkingen van 64 bytes waren identiek")
	}
	nul := true
	for _, c := range a {
		if c != 0 {
			nul = false
			break
		}
	}
	if nul {
		t.Error("64 bytes waren allemaal nul")
	}
}

func TestNBlijftOnderDeGrens(t *testing.T) {
	for _, n := range []uint64{2, 3, 7, 10, 255, 256, 1000, 1 << 32, 1<<63 + 1, ^uint64(0)} {
		for i := 0; i < 2000; i++ {
			if v := N(n); v >= n {
				t.Fatalf("N(%d) = %d", n, v)
			}
		}
	}
}

func TestNLeegBereik(t *testing.T) {
	if N(0) != 0 || N(1) != 0 {
		t.Error("N(0) en N(1) horen 0 te zijn")
	}
}

func TestNIsRedelijkVlak(t *testing.T) {

	const bakken, per = 6, 10000
	tel := make([]int, bakken)
	for i := 0; i < bakken*per; i++ {
		tel[N(bakken)]++
	}
	for i, c := range tel {
		if c < per*85/100 || c > per*115/100 {
			t.Errorf("bak %d kreeg %d van de %d verwachte trekkingen (%v)", i, c, per, tel)
		}
	}
}

func TestHex(t *testing.T) {
	s := Hex(16)
	if len(s) != 32 {
		t.Fatalf("len = %d, wilde 32", len(s))
	}
	if strings.Trim(s, "0123456789abcdef") != "" {
		t.Errorf("Hex gaf iets dat geen hex is: %q", s)
	}
	if Hex(0) != "" {
		t.Error("Hex(0) hoort leeg te zijn")
	}
}

func TestID(t *testing.T) {
	s := ID(12)
	if len(s) != 12 {
		t.Fatalf("len = %d, wilde 12", len(s))
	}
	if strings.Trim(s, alfabet) != "" {
		t.Errorf("ID gaf een teken buiten het alfabet: %q", s)
	}
	if strings.ContainsAny(s, "ILOU") {
		t.Errorf("ID gaf een teken dat je verkeerd overtypt: %q", s)
	}
	if ID(0) != "" || ID(-3) != "" {
		t.Error("ID(<=0) hoort leeg te zijn")
	}
}

func TestIDsZijnUniek(t *testing.T) {

	const n = 20000
	gezien := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		s := ID(12)
		if gezien[s] {
			t.Fatalf("dubbele id na %d trekkingen: %q", i, s)
		}
		gezien[s] = true
	}
}

func TestIDAlfabetHeeftGeenDubbels(t *testing.T) {
	if len(alfabet) != 32 {
		t.Fatalf("alfabet is %d tekens; 32 is de reden dat er geen bias is", len(alfabet))
	}
	gezien := map[rune]bool{}
	for _, r := range alfabet {
		if gezien[r] {
			t.Fatalf("alfabet bevat %q twee keer", r)
		}
		gezien[r] = true
	}
}

func TestJitterBlijftInDeBand(t *testing.T) {
	const d = 100 * time.Millisecond
	laag, hoog := false, false
	for i := 0; i < 2000; i++ {
		v := Jitter(d)
		if v < d/2 || v >= d+d/2 {
			t.Fatalf("Jitter(%v) = %v, buiten [%v, %v)", d, v, d/2, d+d/2)
		}
		if v < d {
			laag = true
		} else {
			hoog = true
		}
	}
	if !laag || !hoog {
		t.Error("jitter kwam maar aan één kant van d uit")
	}
}

func TestJitterZonderWachttijd(t *testing.T) {
	if Jitter(0) != 0 {
		t.Error("Jitter(0) hoort 0 te zijn")
	}
	if Jitter(-time.Second) != -time.Second {
		t.Error("een negatieve duur hoort onveranderd terug te komen")
	}
}

func TestUint64VultAlleBits(t *testing.T) {

	var of uint64
	for i := 0; i < 200; i++ {
		of |= Uint64()
	}
	if of != ^uint64(0) {
		t.Errorf("na 200 trekkingen stonden niet alle bits ooit aan: %#x", of)
	}
}

func BenchmarkID12(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ID(12)
	}
}

func BenchmarkN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		N(1<<63 + 1)
	}
}
