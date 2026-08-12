package leannet

import (
	"bytes"
	"testing"
)

// TestRingExhaustive loopt de hele toestandsruimte af voor kleine ringen:
// elke maat, elke kop-positie, elke vulling, en verifieert schrijf/lees/wrap
// tegen een naïef model (een gewone slice). De les van lneto's ring (twee
// keer dezelfde fix, BEVINDINGEN #25): leeg-detectie en wrap-rekenkunde
// horen op één plek te wonen en uitputtend getest te zijn.
func TestRingExhaustive(t *testing.T) {
	for size := 1; size <= 8; size++ {
		for headStart := 0; headStart < size; headStart++ {
			for fill := 0; fill <= size; fill++ {
				r := ring{buf: make([]byte, size), head: headStart}
				var model []byte
				// Vullen met herkenbare bytes.
				seed := make([]byte, fill)
				for i := range seed {
					seed[i] = byte(0x40 + i)
				}
				if got := r.write(seed); got != fill {
					t.Fatalf("size=%d head=%d fill=%d: write=%d", size, headStart, fill, got)
				}
				model = append(model, seed...)
				if r.buffered() != len(model) || r.free() != size-len(model) {
					t.Fatalf("size=%d head=%d fill=%d: buffered=%d free=%d", size, headStart, fill, r.buffered(), r.free())
				}
				// Overschrijven mag niet: extra write levert 0 op bij vol.
				if r.free() == 0 && r.write([]byte{0xEE}) != 0 {
					t.Fatal("write into full ring accepted bytes")
				}
				// Halve read, dan bijschrijven (dwingt wrap af), dan alles lezen.
				h := len(model) / 2
				dst := make([]byte, h)
				if got := r.read(dst); got != h || !bytes.Equal(dst, model[:h]) {
					t.Fatalf("size=%d head=%d fill=%d: half read got %d %q want %q", size, headStart, fill, got, dst, model[:h])
				}
				model = model[h:]
				extra := make([]byte, size-len(model))
				for i := range extra {
					extra[i] = byte(0x60 + i)
				}
				r.write(extra)
				model = append(model, extra...)
				rest := make([]byte, len(model))
				if got := r.read(rest); got != len(model) || !bytes.Equal(rest, model) {
					t.Fatalf("size=%d head=%d fill=%d: rest=%q want %q", size, headStart, fill, rest, model)
				}
				if r.buffered() != 0 || r.head != 0 {
					t.Fatalf("empty ring not normalized: head=%d n=%d", r.head, r.n)
				}
			}
		}
	}
}

func TestRingPeekOffset(t *testing.T) {
	r := ring{buf: make([]byte, 8), head: 6} // dwing wrap af
	r.write([]byte("abcdefg"))
	got := make([]byte, 3)
	if n := r.peek(got, 2); n != 3 || string(got) != "cde" {
		t.Fatalf("peek(off=2) = %q (%d)", got[:n], n)
	}
	if n := r.peek(got, 6); n != 1 || got[0] != 'g' {
		t.Fatalf("peek(off=6) = %q (%d)", got[:n], n)
	}
	if n := r.peek(got, 7); n != 0 {
		t.Fatalf("peek past end = %d", n)
	}
	// peek consumeert niet.
	all := make([]byte, 7)
	if n := r.read(all); n != 7 || string(all) != "abcdefg" {
		t.Fatalf("read after peeks = %q", all[:n])
	}
}

func TestRingDropPanicsBeyondBuffered(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("drop beyond buffered did not panic")
		}
	}()
	r := ring{buf: make([]byte, 4)}
	r.write([]byte("ab"))
	r.drop(3)
}

func TestRingGrowPreservesOrderAcrossWrap(t *testing.T) {
	r := ring{buf: make([]byte, 4), head: 3}
	r.write([]byte("wxyz")) // wrapt over de fysieke rand
	r.grow(make([]byte, 16))
	if r.size() != 16 || r.head != 0 || r.buffered() != 4 {
		t.Fatalf("after grow: size=%d head=%d n=%d", r.size(), r.head, r.n)
	}
	got := make([]byte, 4)
	r.read(got)
	if string(got) != "wxyz" {
		t.Fatalf("contents after grow = %q", got)
	}
}

func TestTxRingSendAckRewind(t *testing.T) {
	tx := txRing{ring: ring{buf: make([]byte, 8)}}
	tx.writeApp([]byte("hallo"))
	if tx.unsent() != 5 {
		t.Fatalf("unsent = %d", tx.unsent())
	}
	// Verstuur in twee stukken.
	p := make([]byte, 3)
	if n := tx.nextSend(p); n != 3 || string(p) != "hal" {
		t.Fatalf("nextSend 1 = %q (%d)", p[:n], n)
	}
	if n := tx.nextSend(p); n != 2 || string(p[:n]) != "lo" {
		t.Fatalf("nextSend 2 = %q (%d)", p[:n], n)
	}
	if tx.unsent() != 0 || tx.buffered() != 5 {
		t.Fatalf("after full send: unsent=%d buffered=%d", tx.unsent(), tx.buffered())
	}
	// Peer bevestigt 2; er komt ruimte, verzonden-cursor schuift mee.
	tx.ack(2)
	if tx.buffered() != 3 || tx.unsent() != 0 {
		t.Fatalf("after ack: buffered=%d unsent=%d", tx.buffered(), tx.unsent())
	}
	// RTO: alles onbevestigde geldt weer als te verzenden (go-back-N).
	tx.rewind()
	if tx.unsent() != 3 {
		t.Fatalf("after rewind: unsent = %d", tx.unsent())
	}
	if n := tx.nextSend(p); n != 3 || string(p) != "llo" {
		t.Fatalf("retransmit read = %q (%d)", p[:n], n)
	}
	// Nieuwe app-bytes achter een gedeeltelijk bevestigde stroom.
	tx.writeApp([]byte("!!"))
	if tx.unsent() != 2 {
		t.Fatalf("new bytes unsent = %d", tx.unsent())
	}
}

func TestBudgetReserveRelease(t *testing.T) {
	b := budget{total: 100}
	if !b.reserve(60) || !b.reserve(40) {
		t.Fatal("reserve within budget refused")
	}
	if b.reserve(1) {
		t.Fatal("reserve beyond budget granted")
	}
	b.release(50)
	if b.free() != 50 {
		t.Fatalf("free = %d", b.free())
	}
	if !b.reserve(50) {
		t.Fatal("reserve after release refused")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("over-release did not panic")
		}
	}()
	b.release(101)
}
