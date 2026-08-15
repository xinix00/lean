package leandhcp

// keepalive.go maintains a lease after network-stack bring-up. Acquire must use
// raw frames before a stack exists, but afterward the lock-free NIC RX rings
// need one owner. Renew and Rebind therefore use stack UDP sockets.
//
// It implements the RFC 2131 §4.4.5 state machine. At T2, rebinding switches
// from the original lessor to broadcast so another server can preserve a lease
// when the original disappears. Injected keeper seams make the full lifecycle
// testable without sockets or real-time waits.

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// State is an RFC 2131 lease state.
type State uint8

const (
	StateBound     State = iota // valid address, no action
	StateRenewing               // from T1: unicast to the lessor
	StateRebinding              // from T2: broadcast to any server
	StateExpired                // past expiry: the address is no longer ours
)

func (s State) String() string {
	switch s {
	case StateBound:
		return "bound"
	case StateRenewing:
		return "renewing"
	case StateRebinding:
		return "rebinding"
	case StateExpired:
		return "expired"
	}
	return "unknown"
}

// Maintenance timing. requestTimeout bounds one ACK wait; retryFloor is the
// RFC 2131 minimum interval that prevents retry storms.
const (
	requestTimeout = 10 * time.Second
	retryFloor     = 60 * time.Second
)

// errRefused is DHCPNAK: the address is no longer ours, so retrying on it would
// be actively wrong.
var errRefused = errors.New("server refused the lease (DHCPNAK)")

// timers returns T1, T2, and expiry from ACK receipt. All zero means an infinite
// or unknown lease. Invalid ordering falls back to RFC 2131 ratios 0.5 and
// 0.875; real routers have sent T1 = T2 = expiry, which erases rebinding.
func (l Lease) timers() (t1, t2, expiry time.Duration) {
	if l.LeaseSecs == 0 || l.LeaseSecs == 0xFFFFFFFF {
		return 0, 0, 0
	}
	sec := func(v uint32) time.Duration { return time.Duration(v) * time.Second }
	expiry = sec(l.LeaseSecs)
	t1, t2 = sec(l.T1Secs), sec(l.T2Secs)
	if t1 <= 0 || t1 >= expiry {
		t1 = expiry / 2
	}
	if t2 <= t1 || t2 >= expiry {
		t2 = expiry / 8 * 7
	}
	if t1 >= t2 { // T1 above 0.875·lease is the invalid value.
		t1 = expiry / 2
	}
	return t1, t2, expiry
}

// retryAfter returns half the time left to the next phase, floored by RFC 2131
// and capped at the phase boundary so rebinding never starts late.
func retryAfter(left time.Duration) time.Duration {
	wait := left / 2
	if wait < retryFloor {
		wait = retryFloor
	}
	if wait > left {
		wait = left
	}
	return wait
}

// Renew sends a unicast REQUEST to the lessor with ciaddr set to the lease IP
// and without options 50/54 (RFC 2131 §4.3.2).
func Renew(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
	return request(l, mac, timeout, l.Server, StateRenewing)
}

// Rebind broadcasts the same REQUEST so any server may answer when the lessor
// is unavailable. The BOOTP broadcast flag remains clear because the valid
// ciaddr accepts unicast replies; local ingress intentionally ignores broadcast
// IP replies.
func Rebind(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
	return request(l, mac, timeout, [4]byte{255, 255, 255, 255}, StateRebinding)
}

// renewXID supplies a fresh transaction ID per attempt. A process counter stays
// unique across SNTP wall-clock jumps; the HOP prefix aids packet captures.
var renewXID atomic.Uint32

// leaseConn abstracts *net.UDPConn so NAK handling, late-packet filtering, and
// lease merging can be tested without a real socket.
type leaseConn interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// listenLease opens DHCP client port 68 on the leased address.
var listenLease = func(ip [4]byte) (leaseConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(ip[:]), Port: 68})
}

// request sends one REQUEST to the lessor or broadcast address and waits for an
// ACK. A NAK wraps errRefused.
func request(l Lease, mac [6]byte, timeout time.Duration, server [4]byte, state State) (Lease, error) {
	conn, err := listenLease(l.IP)
	if err != nil {
		return Lease{}, fmt.Errorf("dhcp %s: bind :68: %w", state, err)
	}
	defer conn.Close()

	xid := 0x484F5200 | renewXID.Add(1)&0xff
	req := bootp(mac, xid, msgRequest, l.IP, false, nil)
	if _, err := conn.WriteToUDP(req, &net.UDPAddr{IP: net.IP(server[:]), Port: 67}); err != nil {
		return Lease{}, fmt.Errorf("dhcp %s: TX: %w", state, err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return Lease{}, fmt.Errorf("dhcp %s: no ACK within %v: %w", state, timeout, err)
		}
		if nl, ok := parseBootp(buf[:n], mac, xid, msgACK); ok {
			return merge(l, nl), nil
		}
		if _, ok := parseBootp(buf[:n], mac, xid, msgNAK); ok {
			return Lease{}, fmt.Errorf("dhcp %s: %w", state, errRefused)
		}
		// Ignore unrelated or late port-68 traffic within the deadline.
	}
}

// merge overlays a sparse renewal ACK on the current lease. Preserving omitted
// fields prevents a terse server from silently setting LeaseSecs to zero and
// disabling maintenance.
func merge(old, fresh Lease) Lease {
	if fresh.IP == ([4]byte{}) {
		fresh.IP = old.IP
	}
	if fresh.Mask == ([4]byte{}) {
		fresh.Mask = old.Mask
	}
	if fresh.GW == ([4]byte{}) {
		fresh.GW = old.GW
	}
	if fresh.DNS == ([4]byte{}) {
		fresh.DNS = old.DNS
	}
	if fresh.Server == ([4]byte{}) {
		fresh.Server = old.Server
	}
	if fresh.LeaseSecs == 0 {
		fresh.LeaseSecs, fresh.T1Secs, fresh.T2Secs = old.LeaseSecs, old.T1Secs, old.T2Secs
	}
	fresh.Acquired = true
	return fresh
}

// KeepAlive maintains a lease according to RFC 2131 §4.4.5: sleep until T1,
// renew by unicast with halving retries, rebind by broadcast after T2, and fail
// loudly at expiry. Start it only after hopnet installs the stack in
// net.SocketFunc; all traffic then stays clear of NIC RX ownership.
func KeepAlive(mac [6]byte, lease Lease) {
	if !lease.Acquired {
		return // Static configuration has no lease to maintain.
	}
	k := &keeper{
		mac:    mac,
		lease:  lease,
		sleep:  sleepChunked,
		renew:  Renew,
		rebind: Rebind,
		logf:   func(format string, a ...any) { fmt.Printf(format, a...) },
	}
	k.run()
}

// keeper isolates the state machine behind injected time, traffic, and logging
// seams so tests can cover a multi-day lifecycle in microseconds.
type keeper struct {
	mac   [6]byte
	lease Lease

	sleep  func(time.Duration)
	renew  func(Lease, [6]byte, time.Duration) (Lease, error)
	rebind func(Lease, [6]byte, time.Duration) (Lease, error)
	logf   func(format string, a ...any)
}

func (k *keeper) run() {
	for {
		t1, t2, expiry := k.lease.timers()
		if t1 <= 0 {
			return // Infinite or unknown lease: nothing to schedule.
		}
		k.sleep(t1)

		// Count elapsed time from our sleeps. Tamago's wall clock jumps from epoch
		// during boot SNTP, which would expire a wall-clock deadline immediately.
		elapsed := t1
		state := StateRenewing
		var fresh Lease
		for {
			var err error
			if state == StateRenewing {
				fresh, err = k.renew(k.lease, k.mac, requestTimeout)
			} else {
				fresh, err = k.rebind(k.lease, k.mac, requestTimeout)
			}
			if err == nil {
				break
			}
			if errors.Is(err, errRefused) {
				k.logf("dhcp: %s is no longer ours (%v) — a reboot acquires a new address HOPOS_DHCP_NAK\n",
					k.lease.IPString(), err)
				return
			}
			k.logf("dhcp: %v\n", err)

			elapsed += requestTimeout
			limit := t2
			if state == StateRebinding {
				limit = expiry
			}
			if left := limit - elapsed; left > 0 {
				wait := retryAfter(left)
				k.sleep(wait)
				elapsed += wait
				continue
			}
			if state == StateRenewing {
				state = StateRebinding
				k.logf("dhcp: no answer from %s before T2 — rebinding by broadcast HOPOS_DHCP_REBIND\n",
					ipStr(k.lease.Server))
				continue
			}
			k.logf("dhcp: lease on %s EXPIRED and could not be rebound; the address is no longer ours HOPOS_DHCP_EXPIRED\n",
				k.lease.IPString())
			return
		}

		// A different server may assign another address during rebind. The running
		// stack cannot apply it; continuing would use an address the server may
		// reassign to another client.
		if fresh.IP != k.lease.IP {
			k.logf("dhcp: server offered %s instead of %s; a running node cannot change address — "+
				"a reboot picks up the new one HOPOS_DHCP_MOVED\n", fresh.IPString(), k.lease.IPString())
			return
		}
		k.lease = fresh
		k.logf("dhcp: lease extended (%s) — %s, %ds to go HOPOS_DHCP_RENEW\n",
			state, k.lease.IPString(), k.lease.LeaseSecs)
	}
}

// sleepChunked limits a Tamago SNTP wall-clock jump to one minute of schedule
// error. A single long Sleep caused renewal at boot (measured 2026-07-11).
func sleepChunked(d time.Duration) {
	const chunk = time.Minute
	for ; d > chunk; d -= chunk {
		time.Sleep(chunk)
	}
	time.Sleep(d)
}
