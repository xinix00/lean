package leannet

// multicast.go adds link-local IPv4 multicast to the one-address stack: join a
// group to receive it, send with the direct RFC 1112 MAC mapping (no ARP, no
// gateway). UDP only, and only 224.0.0.0/24 — the link-local block that
// routers never forward (RFC 5771), which is also why TTL 255 is safe there
// (RFC 6762 §11). Wider multicast (239.0.0.0/8 and friends) is refused: with
// a TTL above 1 a multicast router could carry it beyond the LAN, and no
// consumer here needs it. A join is for the stack's lifetime: the only
// consumer (mDNS) never leaves, so there is no Leave, no nesting, and no
// refcount to get wrong. Groups are capped and cleared on Close, keeping the
// bounded-memory contract intact. There is no IGMP: home switches flood
// link-local multicast. The device below must already pass multicast frames;
// a NIC filter is not this stack's concern.

import "errors"

// maxGroups bounds the join set. mDNS needs one; the cap only exists so a
// caller bug cannot grow stack state without limit.
const maxGroups = 4

var (
	errNotLinkLocalMulticast = errors.New("leannet: only link-local multicast (224.0.0.0/24)")
	errGroupsFull            = errors.New("leannet: multicast group cap reached")
)

// isMulticastIP reports whether ip is in 224.0.0.0/4 (RFC 1112 §4) — the
// range that is never a valid unicast peer, source, or TCP destination.
func isMulticastIP(ip [4]byte) bool { return ip[0]&0xf0 == 0xe0 }

// isLinkLocalMulticast reports whether ip is a usable group in 224.0.0.0/24
// (RFC 5771): the only multicast this stack joins or transmits. The base
// address 224.0.0.0 itself is reserved and never assigned to a group
// (RFC 1112 §4), so it is excluded.
func isLinkLocalMulticast(ip [4]byte) bool {
	return ip[0] == 224 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
}

// multicastMAC maps a group to its Ethernet address: 01:00:5e plus the low 23
// bits of the group (RFC 1112 §6.4).
func multicastMAC(group [4]byte) [6]byte {
	return [6]byte{0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]}
}

// isMulticastMAC reports whether dst is an IPv4 multicast Ethernet address.
func isMulticastMAC(dst [6]byte) bool {
	return dst[0] == 0x01 && dst[1] == 0x00 && dst[2] == 0x5e
}

// JoinGroup subscribes the stack to a link-local multicast group, for the
// stack's lifetime. Joining a joined group is a no-op.
func (s *Stack) JoinGroup(group [4]byte) error {
	if !isLinkLocalMulticast(group) {
		return errNotLinkLocalMulticast
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errStackClosed
	}
	if _, ok := s.groups[group]; ok {
		return nil
	}
	if len(s.groups) >= maxGroups {
		return errGroupsFull
	}
	if s.groups == nil {
		s.groups = make(map[[4]byte]struct{})
	}
	s.groups[group] = struct{}{}
	return nil
}

// joinedLocked reports group membership; reading a nil map is fine.
func (s *Stack) joinedLocked(group [4]byte) bool {
	_, ok := s.groups[group]
	return ok
}
