package leannet

// ring.go provides the byte rings behind each connection:
//
//   - rxRing: the network appends in-order bytes and the application consumes
//     from the head. Free space is the receive window.
//   - txRing: the application appends bytes and a cursor tracks what was sent.
//     ACKs release the head; an RTO rewinds the cursor for go-back-N replay.
//
// Rings are not internally locked; their connection owns synchronization.
// Growth is explicit so the connection can account for it against budget.go.

// ring is a FIFO over a fixed byte slice. head is the read position and n the
// buffered length; tracking n distinguishes full from empty without losing a slot.
type ring struct {
	buf  []byte
	head int
	n    int
}

func (r *ring) size() int     { return len(r.buf) }
func (r *ring) buffered() int { return r.n }
func (r *ring) free() int     { return len(r.buf) - r.n }

// write copies as much of p as possible to the tail.
func (r *ring) write(p []byte) int {
	total := 0
	for len(p) > 0 && r.n < len(r.buf) {
		w := (r.head + r.n) % len(r.buf)
		// Contiguous span up to the physical edge or the head.
		chunk := len(r.buf) - w
		if free := len(r.buf) - r.n; chunk > free {
			chunk = free
		}
		if chunk > len(p) {
			chunk = len(p)
		}
		copy(r.buf[w:w+chunk], p[:chunk])
		r.n += chunk
		total += chunk
		p = p[chunk:]
	}
	return total
}

// peek copies available bytes starting off bytes after the head without consuming.
func (r *ring) peek(p []byte, off int) int {
	if off >= r.n {
		return 0
	}
	total := 0
	avail := r.n - off
	if len(p) > avail {
		p = p[:avail]
	}
	pos := (r.head + off) % len(r.buf)
	for len(p) > 0 {
		chunk := len(r.buf) - pos
		if chunk > len(p) {
			chunk = len(p)
		}
		copy(p[:chunk], r.buf[pos:pos+chunk])
		total += chunk
		p = p[chunk:]
		pos = (pos + chunk) % len(r.buf)
	}
	return total
}

// drop consumes k bytes. Exceeding buffered data panics because it indicates a
// sequence-accounting bug.
func (r *ring) drop(k int) {
	if k < 0 || k > r.n {
		panic("leannet: ring drop exceeds buffered")
	}
	r.head = (r.head + k) % len(r.buf)
	r.n -= k
	if r.n == 0 {
		r.head = 0 // normalize empty rings for predictable growth and tests
	}
}

// read copies from the head and consumes the bytes.
func (r *ring) read(p []byte) int {
	got := r.peek(p, 0)
	r.drop(got)
	return got
}

// grow moves the contents to the start of an equal or larger, already-accounted buffer.
func (r *ring) grow(newBuf []byte) {
	if len(newBuf) < r.n {
		panic("leannet: ring grow smaller than contents")
	}
	r.peek(newBuf[:r.n], 0)
	r.buf = newBuf
	r.head = 0
}

// ---- txRing: transmit buffer with send cursor ----

// txRing retains application bytes until acknowledged. sent counts buffered
// bytes transmitted at least once; the ring head represents snd.UNA.
type txRing struct {
	ring
	sent int
}

// writeApp buffers as many application bytes as fit.
func (t *txRing) writeApp(p []byte) int { return t.write(p) }

// unsent reports bytes still needing transmission, including after rewind.
func (t *txRing) unsent() int { return t.n - t.sent }

// nextSend copies unsent bytes and advances the cursor; ACKs release them later.
func (t *txRing) nextSend(p []byte) int {
	got := t.peek(p, t.sent)
	t.sent += got
	return got
}

// ack releases k acknowledged bytes and adjusts the send cursor. The connection
// rejects ACKs beyond transmitted data before calling this method.
func (t *txRing) ack(k int) {
	t.drop(k)
	t.sent -= k
	if t.sent < 0 {
		panic("leannet: tx ack beyond sent")
	}
}

// rewind marks every unacknowledged byte for go-back-N retransmission.
func (t *txRing) rewind() { t.sent = 0 }

// forceSent lets a cumulative ACK overtake a pending retransmission after
// rewind without moving beyond the send cursor.
func (t *txRing) forceSent(k int) {
	if k > t.n {
		k = t.n
	}
	if t.sent < k {
		t.sent = k
	}
}
