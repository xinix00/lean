package leannet

// frame6.go provides allocation-free in-place views over IPv6 and ICMPv6
// (NDP) wire formats, plus the v6 pseudo-header checksum and the address
// arithmetic IPv6 needs (EUI-64 link-local, solicited-node groups, 33:33
// multicast MACs). Offsets follow RFCs 8200, 4861, and 4291.
//
// Deliberately absent, like the rest of this stack: extension headers and
// fragmentation. Matter and mDNS on a home link use neither; a packet that
// carries one is dropped and counted, never silently half-parsed.

import (
	"encoding/binary"
	"errors"
)

var (
	errNotIPv6    = errors.New("leannet: not an IPv6 header (version)")
	errIPv6ExtHdr = errors.New("leannet: IPv6 extension headers unsupported")
)

// EtherTypeIPv6 demultiplexes IPv6 frames; see frame.go for the IPv4 set.
const EtherTypeIPv6 uint16 = 0x86dd

// ProtoICMPv6 is IPv6's ICMP protocol number. UDP shares ProtoUDP with IPv4.
const ProtoICMPv6 byte = 58

// sizeIPv6 is the fixed IPv6 header: no options, extensions are next-headers.
const sizeIPv6 = 40

// hopLimitNDP is mandatory on every NDP packet (RFC 4861 §3): a hop limit
// below 255 proves the packet crossed a router and must be discarded.
const hopLimitNDP = 255

// hopLimitDefault is for ordinary unicast; link-local multicast (mDNS,
// RFC 6762 §11) also uses 255 there, matching the IPv4 half of this stack.
const hopLimitDefault = 64

// ---- IPv6 (RFC 8200) ----

// IPv6Frame is a view over the fixed IPv6 header and payload.
type IPv6Frame []byte

// ParseIPv6 validates version, length, and that the payload is fully present.
// Extension headers are rejected here so every caller sees only UDP or ICMPv6.
func ParseIPv6(b []byte) (IPv6Frame, error) {
	if len(b) < sizeIPv6 {
		return nil, errShortFrame
	}
	if b[0]>>4 != 6 {
		return nil, errNotIPv6
	}
	f := IPv6Frame(b)
	if int(f.PayloadLen()) > len(b)-sizeIPv6 {
		return nil, errShortFrame
	}
	switch f.NextHeader() {
	case ProtoUDP, ProtoICMPv6:
	default:
		return nil, errIPv6ExtHdr
	}
	return f, nil
}

func (f IPv6Frame) PayloadLen() uint16 { return binary.BigEndian.Uint16(f[4:6]) }
func (f IPv6Frame) NextHeader() byte   { return f[6] }
func (f IPv6Frame) HopLimit() byte     { return f[7] }
func (f IPv6Frame) Src() [16]byte      { return [16]byte(f[8:24]) }
func (f IPv6Frame) Dst() [16]byte      { return [16]byte(f[24:40]) }
func (f IPv6Frame) Payload() []byte    { return f[sizeIPv6 : sizeIPv6+int(f.PayloadLen())] }

// PutIPv6 writes a header for payloadLen bytes that follow it in b.
func PutIPv6(b []byte, next, hopLimit byte, src, dst [16]byte, payloadLen int) (int, error) {
	if len(b) < sizeIPv6+payloadLen || payloadLen > 0xffff {
		return 0, errShortFrame
	}
	b[0], b[1], b[2], b[3] = 0x60, 0, 0, 0 // version 6, no traffic class or flow
	binary.BigEndian.PutUint16(b[4:6], uint16(payloadLen))
	b[6] = next
	b[7] = hopLimit
	copy(b[8:24], src[:])
	copy(b[24:40], dst[:])
	return sizeIPv6, nil
}

// pseudoChecksum6 is RFC 8200 §8.1: 16-byte addresses, 32-bit length, and the
// next-header code. Used by both UDP (mandatory in v6) and ICMPv6.
func pseudoChecksum6(next byte, src, dst [16]byte, segment []byte) uint16 {
	var ph [40]byte
	copy(ph[0:16], src[:])
	copy(ph[16:32], dst[:])
	binary.BigEndian.PutUint32(ph[32:36], uint32(len(segment)))
	ph[39] = next
	return foldChecksum(sumBytes(sumBytes(0, ph[:]), segment))
}

// PutUDP6 mirrors PutUDP with the v6 pseudo-header. A zero checksum is
// forbidden in IPv6 (RFC 8200 §8.1), so the 0xffff substitution always applies.
func PutUDP6(b []byte, srcPort, dstPort uint16, src, dst [16]byte, payloadLen int) (int, error) {
	total := sizeUDP + payloadLen
	if len(b) < total || total > 0xffff {
		return 0, errShortFrame
	}
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(total))
	binary.BigEndian.PutUint16(b[6:8], 0)
	csum := pseudoChecksum6(ProtoUDP, src, dst, b[:total])
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(b[6:8], csum)
	return total, nil
}

// ChecksumOK6 verifies a UDP checksum against the v6 pseudo-header. Unlike
// IPv4, an absent (zero) checksum makes the datagram invalid (RFC 8200 §8.1).
func (f UDPFrame) ChecksumOK6(src, dst [16]byte) bool {
	if f.Checksum() == 0 {
		return false
	}
	return pseudoChecksum6(ProtoUDP, src, dst, f[:f.Len()]) == 0
}

// ---- ICMPv6 / NDP (RFC 4861) ----

// ICMPv6 types handled by this stack.
const (
	icmp6EchoRequest      byte = 128
	icmp6EchoReply        byte = 129
	icmp6RouterSolicit    byte = 133
	icmp6RouterAdvert     byte = 134
	icmp6NeighborSolicit  byte = 135
	icmp6NeighborAdvert   byte = 136
)

// NDP option types.
const (
	ndpOptSourceLLA  byte = 1
	ndpOptTargetLLA  byte = 2
	ndpOptPrefixInfo byte = 3
	ndpOptRouteInfo  byte = 24 // RFC 4191
)

// ICMPv6Frame is a view over an ICMPv6 message: type(1) code(1) csum(2) body.
type ICMPv6Frame []byte

func ParseICMPv6(b []byte, src, dst [16]byte) (ICMPv6Frame, error) {
	if len(b) < 4 {
		return nil, errShortFrame
	}
	if pseudoChecksum6(ProtoICMPv6, src, dst, b) != 0 {
		return nil, errShortFrame
	}
	return ICMPv6Frame(b), nil
}

func (f ICMPv6Frame) Type() byte   { return f[0] }
func (f ICMPv6Frame) Body() []byte { return f[4:] }

// ndpOptions walks the TLV options that follow an NDP body. Each visit gets
// the type and the full option (including its two header bytes). A zero
// length octet is a mandated discard of the whole packet (RFC 4861 §4.6).
func ndpOptions(b []byte, visit func(typ byte, opt []byte)) bool {
	for len(b) > 0 {
		if len(b) < 2 || b[1] == 0 {
			return false
		}
		n := int(b[1]) * 8
		if n > len(b) {
			return false
		}
		visit(b[0], b[:n])
		b = b[n:]
	}
	return true
}

// putNDP writes one ICMPv6/NDP message and its checksum. body already contains
// everything after the 4-byte ICMPv6 header.
func putNDP(b []byte, typ byte, body []byte, src, dst [16]byte) (int, error) {
	total := 4 + len(body)
	if len(b) < total {
		return 0, errShortFrame
	}
	b[0], b[1], b[2], b[3] = typ, 0, 0, 0
	copy(b[4:], body)
	csum := pseudoChecksum6(ProtoICMPv6, src, dst, b[:total])
	binary.BigEndian.PutUint16(b[2:4], csum)
	return total, nil
}

// ---- address arithmetic (RFC 4291) ----

var (
	allNodes6   = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	allRouters6 = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
)

// llAddrFromMAC forms the fe80:: link-local address with the modified EUI-64:
// the MAC split by ff:fe, universal/local bit flipped (RFC 4291 §2.5.1).
func llAddrFromMAC(mac [6]byte) [16]byte {
	var a [16]byte
	a[0], a[1] = 0xfe, 0x80
	a[8] = mac[0] ^ 0x02
	a[9], a[10] = mac[1], mac[2]
	a[11], a[12] = 0xff, 0xfe
	a[13], a[14], a[15] = mac[3], mac[4], mac[5]
	return a
}

// solicitedNode maps an address to its solicited-node group: ff02::1:ff plus
// the last three bytes (RFC 4291 §2.7.1). NDP solicitations arrive there.
func solicitedNode(a [16]byte) [16]byte {
	return [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a[13], a[14], a[15]}
}

// multicastMAC6 maps a group to 33:33 plus its last four bytes (RFC 2464 §7).
func multicastMAC6(group [16]byte) [6]byte {
	return [6]byte{0x33, 0x33, group[12], group[13], group[14], group[15]}
}

// isMulticastMAC6 reports whether dst is an IPv6 multicast Ethernet address.
func isMulticastMAC6(dst [6]byte) bool { return dst[0] == 0x33 && dst[1] == 0x33 }

// isMulticast6 reports ff00::/8 (RFC 4291 §2.4).
func isMulticast6(a [16]byte) bool { return a[0] == 0xff }

// isLinkLocal6 reports fe80::/10.
func isLinkLocal6(a [16]byte) bool { return a[0] == 0xfe && a[1]&0xc0 == 0x80 }

// isLinkScopedMulticast6 reports ff02::/16 — the only multicast this stack
// joins or transmits, mirroring the IPv4 half's link-local-only rule: wider
// scopes could be routed off the link and nothing here needs them.
func isLinkScopedMulticast6(a [16]byte) bool { return a[0] == 0xff && a[1] == 0x02 }

// isZero6 reports the unspecified address (::).
func isZero6(a [16]byte) bool { return a == ([16]byte{}) }

// prefixMatch6 reports whether a and b share their first bits bits.
func prefixMatch6(a, b [16]byte, bits int) bool {
	if bits < 0 || bits > 128 {
		return false
	}
	n := bits / 8
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	if r := bits % 8; r != 0 {
		mask := byte(0xff << (8 - r))
		return a[n]&mask == b[n]&mask
	}
	return true
}
