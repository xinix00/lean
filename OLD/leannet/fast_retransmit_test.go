package leannet

import "testing"

func TestTCPQueuedDuplicateACKsDoNotRestartRecovery(t *testing.T) {
	w := newTCPPair(t, 65535, 65535)
	w.connect()
	c := w.a
	if n, e := c.write(make([]byte, 60<<10)); e != nil || n != 60<<10 {
		t.Fatalf("write %d %v", n, e)
	}
	original := w.drain(c)
	var acks []tcpSeg
	// Lose one first data segment; peer emits one duplicate ACK per later segment.
	for _, seg := range original[1:] {
		w.b.recv(seg, w.now)
		acks = append(acks, w.drain(w.b)...)
	}
	before := c.cnt.bytesOut
	// ACKs already in flight arrive in receive batches before recovery data returns.
	for len(acks) > 0 {
		batch := min(4, len(acks))
		for _, ack := range acks[:batch] {
			c.recv(ack, w.now)
		}
		acks = acks[batch:]
		w.drain(c)
	}
	t.Logf("original %d segments, fast retransmits %d, replay bytes %d, ack progress %d", len(original), c.cnt.fastRetrans, c.cnt.bytesOut-before, c.una-(c.iss+1))
	if c.cnt.fastRetrans != 1 {
		t.Fatalf("one lost segment restarted same recovery %d times without ACK progress", c.cnt.fastRetrans)
	}
}
func TestTCPDuplicateACKCounterDoesNotWrap(t *testing.T) {
	w := newTCPPair(t, 65535, 65535)
	w.connect()
	c := w.a
	c.write(make([]byte, 4096))
	w.drain(c)
	ack := tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: uint16(c.sndWnd)}
	for i := 0; i < 260; i++ {
		c.recv(ack, w.now)
		w.drain(c)
	}
	if c.cnt.fastRetrans != 1 {
		t.Fatalf("duplicateACK uint8 wrap: fast retrans=%d", c.cnt.fastRetrans)
	}
}

func TestTCPFastRecoveryStaysLatchedWithoutProgress(t *testing.T) {
	for _, event := range []string{"old ACK", "window update", "rewound cursor"} {
		t.Run(event, func(t *testing.T) {
			w := newTCPPair(t, 65535, 65535)
			w.connect()
			c := w.a
			c.write(make([]byte, 8192))
			w.drain(c)
			ack := tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: uint16(c.sndWnd)}
			for i := 0; i < 3; i++ {
				c.recv(ack, w.now)
			}
			changed := ack
			switch event {
			case "old ACK":
				changed.ack--
			case "window update":
				changed.wnd--
			}
			c.recv(changed, w.now)
			w.drain(c)
			for i := 0; i < 6; i++ {
				c.recv(ack, w.now)
				w.drain(c)
			}
			if c.cnt.fastRetrans != 1 || c.dupacks != 3 {
				t.Fatalf("recovery rearmed without progress: fast=%d duplicates=%d", c.cnt.fastRetrans, c.dupacks)
			}
		})
	}
}

func TestTCPFastRecoveryRearmsOnProgressAndRetainsRTO(t *testing.T) {
	w := newTCPPair(t, 65535, 65535)
	w.connect()
	c := w.a
	c.write(make([]byte, 8192))
	w.drain(c)
	ack := tcpSeg{seq: c.rcvNxt, ack: c.una, flags: FlagACK, wnd: uint16(c.sndWnd)}
	for i := 0; i < 3; i++ {
		c.recv(ack, w.now)
	}
	w.drain(c)
	ack.ack += 1460
	c.recv(ack, w.now)
	if c.dupacks != 0 {
		t.Fatal("progress did not release recovery latch")
	}
	for i := 0; i < 3; i++ {
		c.recv(ack, w.now)
	}
	w.drain(c)
	if c.cnt.fastRetrans != 2 {
		t.Fatalf("next missing segment did not recover: fast=%d", c.cnt.fastRetrans)
	}
	if !c.timerOn {
		t.Fatal("unacknowledged retransmission lost RTO")
	}
	w.now = c.deadline
	replay := w.drain(c)
	bytes := 0
	for _, seg := range replay {
		bytes += len(seg.data)
	}
	if c.cnt.retrans != 1 || bytes != 8192-1460 {
		t.Fatalf("lost fast retransmission has no RTO fallback: rto=%d bytes=%d", c.cnt.retrans, bytes)
	}
}
