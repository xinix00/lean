package leannet

import (
	"testing"
	"time"
)

func TestStackFreshSeedsChangeEphemeralStart(t *testing.T) {
	a, b := newStackPair(t, 1<<20, 1<<20)
	a.mu.Lock()
	pa, _ := a.ephemeralPort(a.tcpPortInUse)
	a.mu.Unlock()
	b.mu.Lock()
	pb, _ := b.ephemeralPort(b.tcpPortInUse)
	b.mu.Unlock()
	if pa == pb || pa < ephemeralBase || pb < ephemeralBase {
		t.Fatalf("ports %d %d", pa, pb)
	}
	t.Logf("different ISS seeds choose ports %d and %d", pa, pb)
}
func TestTCPFreshTupleAgainstProtectedTimeWait(t *testing.T) {
	w := newTCPPair(t, 1024, 1024)
	w.connect()
	w.b.close()
	w.pump()
	w.a.close()
	w.pump()
	if w.b.state != tcpTimeWait {
		t.Fatalf("peer state %v", w.b.state)
	}
	// Model a remote host retaining this tuple across a node kernel replacement.
	// Apple XNU tcp_input.c ignores TIME_WAIT resets (RFC 1337); without
	// timestamps it only reopens for SYN sequence > old rcv_nxt.
	// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_input.c
	w.b.twDeadline = w.now + int64(time.Minute)
	w.b.closeDeadline = w.b.twDeadline
	w.dropAtoB = func(seg tcpSeg) bool { return seg.flags.Has(FlagRST) } // peer TIME_WAIT assassination protection
	fresh := &tcpConn{rx: ring{buf: make([]byte, 1024)}, tx: txRing{ring: ring{buf: make([]byte, 1024)}}}
	fresh.openActive(1000, 1460, 0)
	w.a = fresh
	for i := 0; i < 100 && w.a.state != tcpClosed; i++ {
		w.pump()
		w.advance(100 * time.Millisecond)
	}
	if w.a.state != tcpSynSent || w.a.refused || w.b.state != tcpTimeWait {
		t.Fatalf("fresh=%v refused=%v peer=%v", w.a.state, w.a.refused, w.b.state)
	}
	t.Log("fresh tuple remains SYN-SENT at the caller deadline; RST cannot clear protected TIME_WAIT")
	// A distinct tuple reaches a new listener embryo instead and establishes.
	w.dropAtoB = nil
	w.b = &tcpConn{rx: ring{buf: make([]byte, 1024)}, tx: txRing{ring: ring{buf: make([]byte, 1024)}}}
	w.b.openPassive(7000, 1460, 0)
	fresh = &tcpConn{rx: ring{buf: make([]byte, 1024)}, tx: txRing{ring: ring{buf: make([]byte, 1024)}}}
	fresh.openActive(1000, 1460, 0)
	w.a = fresh
	w.connect()
}

func TestStackSeededEphemeralRangeAndWrap(t *testing.T) {
	for _, seed := range []uint32{0, 1, 16383, 16384, ^uint32(0)} {
		d, p := &memDevice{}, &memDevice{}
		d.peer = p
		p.peer = d
		s := NewStack(d, Config{Prefix: 24, Budget: 1 << 20}, seed)
		t.Cleanup(s.Close)
		pick := func() (uint16, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.ephemeralPort(func(uint16) bool { return false })
		}
		first, _ := pick()
		if want := uint16(ephemeralBase) + uint16(seed%16384); first != want {
			t.Fatalf("seed %d: first=%d want=%d", seed, first, want)
		}
		seen := map[uint16]bool{first: true}
		for i := 1; i < 16384; i++ {
			port, err := pick()
			if err != nil || port < ephemeralBase || seen[port] {
				t.Fatalf("seed%d port%d repeat/outside/error %v", seed, port, err)
			}
			seen[port] = true
		}
		again, _ := pick()
		if again != first {
			t.Fatalf("full cycle did not wrap: %d -> %d", first, again)
		}
	}
}
