package leannet

import (
	"bytes"
	"testing"
	"time"
)

func congestionPair(t *testing.T, iss uint32) *tcpWire {
	w := newTCPPairISS(t, 1<<20, 1<<20, iss, 5000, 4)
	w.a.congestion = true
	w.b.congestion = true
	w.connect()
	return w
}

func TestTCPCongestionInitialWindowAndACKGrowth(t *testing.T) {
	w := congestionPair(t, 1000)
	c := w.a
	c.write(make([]byte, 64<<10))
	first := w.drain(c)
	if len(first) != 10 || c.cwnd != 14600 {
		t.Fatalf("initial burst=%d cwnd=%d", len(first), c.cwnd)
	}
	for _, seg := range first {
		w.b.recv(seg, w.now)
		for _, ack := range w.drain(w.b) {
			c.recv(ack, w.now)
		}
	}
	if c.cwnd != 29200 {
		t.Fatalf("slow start cwnd=%d", c.cwnd)
	}
	c.ssthresh = c.cwnd
	before := c.cwnd
	c.congestionACK(before - 1)
	if c.cwnd != before {
		t.Fatal("avoidance grew before full window ACKed")
	}
	c.congestionACK(1)
	if c.cwnd != before+c.peerMSS {
		t.Fatal("avoidance did not grow one MSS")
	}
}

func TestTCPCongestionReplayWrapAndPeerWindow(t *testing.T) {
	w := congestionPair(t, ^uint32(0)-4000)
	c := w.a
	c.write(make([]byte, 32<<10))
	w.drain(c)
	flight := seqDiff(c.maxSent, c.una)
	c.congestionLoss()
	c.goBackN()
	replay := w.drain(c)
	if len(replay) != 1 || len(replay[0].data) != 1460 || c.ssthresh != flight/2 {
		t.Fatalf("replay=%d threshold=%d flight=%d", len(replay), c.ssthresh, flight)
	}
	if c.congestionAvailable() != 0 {
		t.Fatal("rewound send cursor admitted extra replay")
	}
	c.goBackN()
	c.sndWnd = 700
	replay = w.drain(c)
	if len(replay) != 1 || len(replay[0].data) != 700 {
		t.Fatalf("replay ignored smaller peer window: %+v", replay)
	}
}

func TestTCPCongestionRTOAndZeroWindowProbe(t *testing.T) {
	w := congestionPair(t, 1000)
	c := w.a
	c.write(make([]byte, 32<<10))
	w.drain(c)
	w.now = c.deadline
	replay := w.drain(c)
	if c.cwnd != 1460 || len(replay) != 1 {
		t.Fatalf("RTO cwnd=%d replay=%d", c.cwnd, len(replay))
	}
	c.sndWnd = 0
	c.goBackN()
	c.probe = true
	replay = w.drain(c)
	if len(replay) != 1 || len(replay[0].data) != 1 {
		t.Fatalf("zero window probe=%+v", replay)
	}
}

func TestTCPTrustedMemoryKeepsReceiveWindowFastPath(t *testing.T) {
	w := newTCPPair(t, 65535, 65535)
	w.connect()
	w.a.write(make([]byte, 60<<10))
	if got := len(w.drain(w.a)); got <= 10 {
		t.Fatalf("memory path unexpectedly congestion limited: %d", got)
	}
}

func TestTCPCongestionProgressThrough64FrameQueue(t *testing.T) {
	w := congestionPair(t, 1000)
	const total = 8 << 20
	source := make([]byte, total)
	for i := range source {
		source[i] = byte(i*13 + i/257)
	}
	got := make([]byte, 0, total)
	written := 0
	drops := 0
	lostFirst := false
	drain := func(c *tcpConn, loss bool) []tcpSeg {
		var q []tcpSeg
		buf := make([]byte, 2048)
		for count := 0; ; count++ {
			if count > 2048 {
				t.Fatal("unbounded sender burst")
			}
			seg, ok := c.emit(buf, w.now)
			if !ok {
				return q
			}
			seg.data = append([]byte(nil), seg.data...)
			if loss && !lostFirst && len(seg.data) > 0 {
				lostFirst = true
				drops++
				continue
			}
			if len(q) == 64 {
				drops++
				continue
			}
			q = append(q, seg)
		}
	}
	for step := 0; step < 20000 && len(got) < total; step++ {
		if written < total {
			n, _ := w.a.write(source[written:])
			written += n
		}
		q := drain(w.a, true)
		var acks []tcpSeg
		for _, seg := range q {
			w.b.recv(seg, w.now)
			got = append(got, readAll(w.b)...)
			acks = append(acks, drain(w.b, false)...)
		}
		for _, ack := range acks {
			w.a.recv(ack, w.now)
		}
		w.advance(time.Millisecond)
		if len(q) == 0 && w.a.timerOn {
			w.now = max(w.now, w.a.deadline)
		}
	}
	if !bytes.Equal(got, source) {
		t.Fatalf("progress stopped at %d/%d, sent=%d fast=%d rto=%d", len(got), total, w.a.cnt.bytesOut, w.a.cnt.fastRetrans, w.a.cnt.retrans)
	}
	if w.a.cnt.bytesOut > 3*total {
		t.Fatalf("retransmission amplification: sent=%d target=%d", w.a.cnt.bytesOut, total)
	}
	t.Logf("delivered=%d sent=%d dropped=%d fast=%d rto=%d", len(got), w.a.cnt.bytesOut, drops, w.a.cnt.fastRetrans, w.a.cnt.retrans)
}

func TestTCPCongestionIdleRestart(t *testing.T) {
	for _, scenario := range []string{"idle", "active", "outstanding"} {
		t.Run(scenario, func(t *testing.T) {
			w := congestionPair(t, 1000)
			c := w.a
			c.write(make([]byte, 1460))
			w.pump()
			if c.maxSent != c.una {
				t.Fatal("fixture flight was not acknowledged")
			}
			c.cwnd = 40 * c.peerMSS
			c.cwndAcked = 100
			c.write(make([]byte, 60<<10))
			if scenario == "outstanding" {
				w.drain(c)
				c.goBackN()
			}
			if scenario != "active" {
				w.advance(c.currentRTO())
			}
			// Keep this check about idle restart; RTO has separate loss coverage.
			c.restartCongestionAfterIdle(w.now)
			if scenario == "idle" {
				if c.cwnd != c.initialCongestionWindow() || c.cwndAcked != 0 {
					t.Fatalf("idle restart cwnd=%d credit=%d", c.cwnd, c.cwndAcked)
				}
			} else if c.cwnd != 40*c.peerMSS || c.cwndAcked != 100 {
				t.Fatalf("%s reset active recovery window", scenario)
			}
		})
	}
}

func TestTCPCongestionFINPreservesClose(t *testing.T) {
	w := congestionPair(t, 1000)
	w.a.write(make([]byte, 32<<10))
	w.a.close()
	w.pump()
	if w.a.state != tcpFinWait2 || w.b.state != tcpCloseWait {
		t.Fatalf("FIN stalled: %v/%v", w.a.state, w.b.state)
	}
	if got := len(readAll(w.b)); got != 32<<10 {
		t.Fatalf("FIN lost payload: %d", got)
	}
}

func TestStackCongestionFollowsTrustedRoute(t *testing.T) {
	d, peer := &memDevice{}, &memDevice{}
	d.peer = peer
	peer.peer = d
	s := NewStack(d, Config{IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1}, Budget: 1 << 20, LinkTrusted: true}, 1)
	defer s.Close()
	for _, ip := range [][4]byte{{10, 0, 0, 2}, {192, 168, 1, 144}} {
		s.mu.Lock()
		c, err := s.newConnLocked(connKey{lport: 8080, rip: ip, rport: 9000})
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if c.tcp.congestion == s.trusted(ip) {
			t.Fatalf("wrong congestion policy for %v", ip)
		}
	}
}
