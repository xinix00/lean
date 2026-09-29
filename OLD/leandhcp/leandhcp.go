// Package leandhcp is a minimal DHCPv4 client (RFC 2131). It performs the full
// DISCOVER→OFFER→REQUEST→ACK handshake on raw Ethernet before a network stack
// exists, using a two-method NIC contract compatible with any driver or tap.
//
// The network-stack boundary divides the package:
//
//   - leandhcp.go acquires a lease through raw NIC frames during bring-up.
//   - keepalive.go maintains it through a UDP socket after the stack owns RX,
//     implementing RFC 2131 §4.4.5 bound, renewing, and rebinding states.
//
// DISCOVER/OFFER was proven on a Pi 5 (probe6 run 5, 2026-07-10): a FRITZ!Box
// OFFER traversed the custom PCIe→RP1→GEM chain.
package leandhcp

import (
	"fmt"
	"math/bits"
	"time"
)

// NIC is the raw-frame contract, structurally matching go-net's NetworkDevice.
type NIC interface {
	Receive(buf []byte) (int, error)
	Transmit(buf []byte) error
}

// DHCP message types (option 53) understood by this client.
const (
	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgACK      = 5
	msgNAK      = 6
)

// Boot-path timing. roundWindow bounds a DORA round; ackGrace gives REQUEST a
// minimum response window even past the overall deadline (see await).
const (
	roundWindow = 3 * time.Second
	ackGrace    = time.Second
)

// Lease is the result of a successful handshake.
type Lease struct {
	IP     [4]byte
	Mask   [4]byte // option 1
	GW     [4]byte // option 3, first router
	DNS    [4]byte // option 6, first resolver; 0.0.0.0 means none
	Server [4]byte // option 54, the lessor

	// ACK lease timers in seconds: total duration (option 51; 0xFFFFFFFF means
	// infinite), renewal T1 (58), and rebinding T2 (59). Missing or invalid
	// values fall back to RFC 2131 ratios 0.5 and 0.875; see Lease.timers.
	LeaseSecs uint32
	T1Secs    uint32
	T2Secs    uint32

	// Acquired distinguishes an ACK-provided lease from the zero value. KeepAlive
	// operates only on acquired leases.
	Acquired bool
}

// be32 reads a four-byte big-endian DHCP option value.
func be32(d []byte) uint32 {
	return uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
}

func ipStr(a [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }

// IPString, GWString, and DNSString format lease addresses for configuration
// and diagnostics.
func (l Lease) IPString() string  { return ipStr(l.IP) }
func (l Lease) GWString() string  { return ipStr(l.GW) }
func (l Lease) DNSString() string { return ipStr(l.DNS) }

// CIDR returns "ip/prefix" for network-stack configuration.
func (l Lease) CIDR() string {
	m := uint32(l.Mask[0])<<24 | uint32(l.Mask[1])<<16 | uint32(l.Mask[2])<<8 | uint32(l.Mask[3])
	return fmt.Sprintf("%s/%d", ipStr(l.IP), bits.OnesCount32(m))
}

// Acquire runs the NIC handshake and returns a lease. It retries within timeout
// using a fresh xid per round so late offers cannot match a later attempt.
func Acquire(nic NIC, mac [6]byte, timeout time.Duration) (Lease, error) {
	deadline := time.Now().Add(timeout)
	// Retain the last RX error to distinguish an absent server from a broken NIC.
	var rxErr error
	for ronde := uint32(1); ; ronde++ {
		if !time.Now().Before(deadline) {
			if rxErr != nil {
				return Lease{}, fmt.Errorf("dhcp: no lease within %v; last NIC receive error: %w", timeout, rxErr)
			}
			return Lease{}, fmt.Errorf("dhcp: no lease within %v (no server answered)", timeout)
		}
		xid := 0x484F5000 | ronde // "HOP" + round

		if err := nic.Transmit(packet(mac, xid, msgDiscover, nil)); err != nil {
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		// DISCOVER binds no state, so the overall deadline may end this wait.
		offer, ok, err := await(nic, mac, xid, msgOffer, deadline, 0)
		if err != nil {
			rxErr = err
		}
		if !ok {
			continue
		}

		// REQUEST confirms the offer (option 50 = IP, option 54 = server).
		req := []byte{
			50, 4, offer.IP[0], offer.IP[1], offer.IP[2], offer.IP[3],
			54, 4, offer.Server[0], offer.Server[1], offer.Server[2], offer.Server[3],
		}
		if err := nic.Transmit(packet(mac, xid, msgRequest, req)); err != nil {
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		// REQUEST reserves the IP for this MAC, so give ACK a bounded minimum
		// window. Otherwise we could report timeout while the router holds a lease
		// the node never uses.
		ack, ok, err := await(nic, mac, xid, msgACK, deadline, ackGrace)
		if err != nil {
			rxErr = err
		}
		if ok {
			ack.Acquired = true
			return ack, nil
		}
	}
}

// await polls for msgtype with this xid until the round or overall deadline.
// least may extend the window for a response that must not be truncated.
//
// Time is checked only when the receive ring is empty: a queued response remains
// valid even if the window just closed. A bounded grace drain prevents broadcast
// traffic from extending bring-up forever. Receive errors are non-fatal per
// frame, but the last one is returned so a broken NIC is not reported as an
// absent DHCP server.
func await(nic NIC, mac [6]byte, xid uint32, msgtype byte, deadline time.Time, least time.Duration) (Lease, bool, error) {
	window := time.Now().Add(roundWindow)
	if window.After(deadline) {
		window = deadline
	}
	if floor := time.Now().Add(least); window.Before(floor) {
		window = floor
	}
	buf := make([]byte, 1536)
	var lastErr error
	for grace := graceFrames; ; {
		n, err := nic.Receive(buf)
		if err != nil {
			lastErr = err
		}
		if n > 0 {
			if l, ok := parse(buf[:n], mac, xid, msgtype); ok {
				return l, true, nil
			}
		}
		if !time.Now().Before(window) {
			if n == 0 || grace == 0 {
				return Lease{}, false, lastErr
			}
			grace-- // The window closed with queued input; keep draining.
			continue
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
		}
	}
}

// graceFrames bounds post-window draining: enough for ordinary queued traffic,
// small enough that a broadcast storm cannot block bring-up.
const graceFrames = 64

// packet builds one broadcast DHCP frame: IPv4 0.0.0.0→255.255.255.255, UDP
// 68→67 with its allowed zero checksum, and BOOTP/DHCP options.
func packet(mac [6]byte, xid uint32, msgtype byte, extra []byte) []byte {
	f := make([]byte, 14+20+8+300)
	for i := range 6 {
		f[i] = 0xff
	}
	copy(f[6:12], mac[:])
	f[12], f[13] = 0x08, 0x00

	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17 // IHL 5, TTL, UDP
	tot := len(f) - 14
	ip[2], ip[3] = byte(tot>>8), byte(tot)
	ip[16], ip[17], ip[18], ip[19] = 255, 255, 255, 255
	cs := checksum(ip)
	ip[10], ip[11] = byte(cs>>8), byte(cs)

	udp := f[34:42]
	udp[1], udp[3] = 68, 67
	ul := tot - 20
	udp[4], udp[5] = byte(ul>>8), byte(ul)

	// Broadcast DORA uses ciaddr 0 and requests a broadcast response.
	copy(f[42:], bootp(mac, xid, msgtype, [4]byte{}, true, extra))
	return f
}

// bootp builds a BOOTP/DHCP UDP payload. ciaddr contains the lease IP for RENEW;
// bcast requests broadcast replies during pre-address DORA. Options request the
// mask, router, DNS, lease, T1, and T2 fields.
func bootp(mac [6]byte, xid uint32, msgtype byte, ciaddr [4]byte, bcast bool, extra []byte) []byte {
	bp := make([]byte, 300)
	bp[0], bp[1], bp[2] = 1, 1, 6 // BOOTREQUEST, ethernet, hlen
	bp[4], bp[5], bp[6], bp[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)
	if bcast {
		bp[10] = 0x80 // broadcast-flag
	}
	copy(bp[12:16], ciaddr[:]) // ciaddr is set during RENEW (RFC 2131 §4.3.2).
	copy(bp[28:34], mac[:])
	copy(bp[236:240], []byte{99, 130, 83, 99}) // DHCP-magic
	o := append([]byte{53, 1, msgtype, 55, 6, 1, 3, 6, 51, 58, 59}, extra...)
	copy(bp[240:], append(o, 255))
	return bp
}

// checksum returns the standard 16-bit one's complement IP-header checksum.
func checksum(h []byte) uint16 {
	var s uint32
	for i := 0; i < len(h); i += 2 {
		s += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// parse validates a DHCP response frame for this xid, MAC, and message type.
func parse(f []byte, mac [6]byte, xid uint32, msgtype byte) (Lease, bool) {
	if len(f) < 14+20+8+240 || f[12] != 0x08 || f[13] != 0 || f[23] != 17 {
		return Lease{}, false
	}
	ihl := int(f[14]&0xf) * 4
	udp := f[14+ihl:]
	if len(udp) < 8+240 || udp[2] != 0 || udp[3] != 68 { // Destination port 68.
		return Lease{}, false
	}
	return parseBootp(udp[8:], mac, xid, msgtype)
}

// parseBootp extracts a lease from a BOOTP/DHCP UDP payload, shared by raw-frame
// bring-up and socket-based renewal.
func parseBootp(bp []byte, mac [6]byte, xid uint32, msgtype byte) (Lease, bool) {
	if len(bp) < 240 || bp[0] != 2 { // BOOTREPLY
		return Lease{}, false
	}
	if uint32(bp[4])<<24|uint32(bp[5])<<16|uint32(bp[6])<<8|uint32(bp[7]) != xid {
		return Lease{}, false
	}
	for i := range 6 {
		if bp[28+i] != mac[i] {
			return Lease{}, false
		}
	}

	var l Lease
	copy(l.IP[:], bp[16:20]) // yiaddr

	// Options: [code len data...], 0 = padding, 255 = end.
	opts := bp[240:]
	typeOK := false
	for i := 0; i+1 < len(opts); {
		code := opts[i]
		if code == 0 {
			i++
			continue
		}
		if code == 255 {
			break
		}
		ln := int(opts[i+1])
		if i+2+ln > len(opts) {
			break
		}
		d := opts[i+2 : i+2+ln]
		switch code {
		case 53:
			typeOK = ln == 1 && d[0] == msgtype
		case 1:
			if ln >= 4 {
				copy(l.Mask[:], d)
			}
		case 3:
			if ln >= 4 {
				copy(l.GW[:], d)
			}
		case 6:
			if ln >= 4 {
				copy(l.DNS[:], d)
			}
		case 54:
			if ln >= 4 {
				copy(l.Server[:], d)
			}
		case 51: // Lease duration in seconds.
			if ln >= 4 {
				l.LeaseSecs = be32(d)
			}
		case 58: // T1 renewal time.
			if ln >= 4 {
				l.T1Secs = be32(d)
			}
		case 59: // T2 rebinding time.
			if ln >= 4 {
				l.T2Secs = be32(d)
			}
		}
		i += 2 + ln
	}
	return l, typeOK
}
