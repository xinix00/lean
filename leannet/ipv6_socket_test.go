package leannet

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestUDP6LocalAddrIsWildcard(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.ListenUDP6(5540)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	la, ok := u.LocalAddr().(*net.UDPAddr)
	if !ok || !la.IP.IsUnspecified() || la.Port != 5540 || la.String() != "[::]:5540" {
		t.Fatalf("LocalAddr = %#v, want [::]:5540", u.LocalAddr())
	}
}

func TestSocket6AcceptsOnlyWildcardLocalAddress(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	ll := llAddrFromMAC(a.cfg.MAC)

	for name, laddr := range map[string]net.Addr{
		"own link-local": &net.UDPAddr{IP: net.IP(ll[:]), Port: 5540},
		"loopback":       &net.UDPAddr{IP: net.IPv6loopback, Port: 5540},
		"v4-mapped":      &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 5540},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := a.Socket(context.Background(), "udp6", afINET6, sockDGRAM, laddr, nil)
			if err == nil || got != nil {
				t.Fatalf("Socket = (%#v, %v), want (nil, error)", got, err)
			}
		})
	}
	a.mu.Lock()
	enabled := a.v6 != nil
	a.mu.Unlock()
	if enabled {
		t.Fatal("a rejected specific bind enabled the lazy IPv6 lane")
	}

	got, err := a.Socket(context.Background(), "udp6", afINET6, sockDGRAM,
		&net.UDPAddr{IP: net.IPv6zero, Port: 5540}, nil)
	if err != nil {
		t.Fatalf("wildcard Socket: %v", err)
	}
	u, ok := got.(*udpSock)
	if !ok {
		t.Fatalf("wildcard Socket returned %#v", got)
	}
	u.Close()
}

func TestUDP6PublicBoundariesRejectUnusableRemote(t *testing.T) {
	bad := []struct {
		name string
		ip   net.IP
	}{
		{"unspecified", net.IPv6zero},
		{"loopback", net.IPv6loopback},
		{"v4-mapped", net.ParseIP("::ffff:192.0.2.1")},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newStackPair(t, 1<<20, 1<<20)
			got, err := a.Socket(context.Background(), "udp6", afINET6, sockDGRAM, nil,
				&net.UDPAddr{IP: tc.ip, Port: 5540})
			if err == nil || got != nil {
				t.Fatalf("Socket = (%#v, %v), want (nil, error)", got, err)
			}
			a.mu.Lock()
			enabled := a.v6 != nil
			a.mu.Unlock()
			if enabled {
				t.Fatal("a rejected remote enabled the lazy IPv6 lane")
			}

			u, err := a.ListenUDP6(0)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: tc.ip, Port: 5540}); err == nil {
				t.Fatal("WriteTo accepted unusable remote")
			}

			ip16 := tc.ip.To16()
			if ip16 == nil {
				t.Fatal("test address is not 16 bytes")
			}
			d, err := a.DialUDP6([16]byte(ip16), 5540)
			if !errors.Is(err, errInvalidUDP6Remote) || d != nil {
				t.Fatalf("DialUDP6 = (%#v, %v), want (nil, %v)", d, err, errInvalidUDP6Remote)
			}
		})
	}
}

func TestSocket6AllowsLinkScopedMulticastRemote(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	group := net.ParseIP("ff02::fb")
	got, err := a.Socket(context.Background(), "udp6", afINET6, sockDGRAM, nil,
		&net.UDPAddr{IP: group, Port: 5353})
	if err != nil {
		t.Fatalf("dial ff02::fb: %v", err)
	}
	u, ok := got.(*udpSock)
	if !ok || !u.v6 || !u.connected {
		t.Fatalf("Socket returned %#v", got)
	}
	defer u.Close()
	if la := u.LocalAddr().(*net.UDPAddr); !la.IP.IsUnspecified() {
		t.Fatalf("connected LocalAddr = %s, want wildcard", la)
	}
	if ra := u.RemoteAddr().(*net.UDPAddr); !ra.IP.Equal(group) || ra.Port != 5353 {
		t.Fatalf("RemoteAddr = %s, want [ff02::fb]:5353", ra)
	}
}

func TestDialUDP6RejectsZeroPort(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	peer := llAddrFromMAC([6]byte{2, 0, 0, 0, 0, 2})
	if d, err := a.DialUDP6(peer, 0); !errors.Is(err, errInvalidUDP6Remote) || d != nil {
		t.Fatalf("DialUDP6 = (%#v, %v), want (nil, %v)", d, err, errInvalidUDP6Remote)
	}
	a.mu.Lock()
	enabled, used := a.v6 != nil, a.pot.used
	a.mu.Unlock()
	if enabled || used != 0 {
		t.Fatalf("rejected dial changed stack state: v6=%v, budget=%d", enabled, used)
	}
}

func TestUDP6WriteToIsV6Only(t *testing.T) {
	a, _ := newStackPair(t, 1<<20, 1<<20)
	u, err := a.ListenUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	for name, ip := range map[string]net.IP{
		"v4":        net.IPv4(192, 0, 2, 1),
		"v4-mapped": net.ParseIP("::ffff:192.0.2.1"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: ip, Port: 5540}); err == nil {
				t.Fatal("WriteTo accepted an IPv4 destination")
			}
		})
	}
}
