package leannet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func waitPendingNDP6(t *testing.T, s *Stack, peer [16]byte) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		e := s.v6.ndp.entries[peer]
		s.mu.Unlock()
		if e != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("IPv6 write did not start NDP resolution")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUDP6NDPWaiterLifecycle(t *testing.T) {
	peer := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	remote := &net.UDPAddr{IP: net.IP(peer[:]), Port: 5540}

	t.Run("give-up wakes with unreachable", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()

		result := make(chan error, 1)
		go func() {
			_, err := u.WriteTo([]byte("x"), remote)
			result <- err
		}()
		waitPendingNDP6(t, s, peer)
		s.mu.Lock()
		e := s.v6.ndp.entries[peer]
		if e == nil {
			s.mu.Unlock()
			t.Fatal("pending NDP entry disappeared")
		}
		e.tries = neighborQueryTries
		e.due = s.now()
		s.drain6Locked(s.now())
		s.mu.Unlock()

		select {
		case err := <-result:
			if !errors.Is(err, errUnreachable6) {
				t.Fatalf("write after NDP give-up = %v, want %v", err, errUnreachable6)
			}
		case <-time.After(time.Second):
			t.Fatal("NDP give-up did not wake the blocked writer")
		}
	})

	t.Run("write deadline", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		if err := u.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := u.WriteTo([]byte("x"), remote); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unresolved write = %v, want deadline exceeded", err)
		}
	})

	t.Run("close wakes", func(t *testing.T) {
		s, _ := newIPv6CoreStack(t)
		u, err := s.ListenUDP6(0)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := u.WriteTo([]byte("x"), remote)
			result <- err
		}()
		waitPendingNDP6(t, s, peer)
		if err := u.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after Close = %v, want %v", err, net.ErrClosed)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not wake the blocked IPv6 writer")
		}
	})
}
