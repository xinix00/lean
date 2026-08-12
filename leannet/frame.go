package leannet

// frame.go — in-place views over de draadformaten: ethernet, ARP, IPv4, UDP,
// TCP en de internet-checksum. Geen allocaties: elke view is een []byte met
// getters/setters op vaste offsets, en elke Parse* weigert luid wat niet past.
// De offsets komen rechtstreeks uit de RFC's (826, 791, 768, 9293).

import (
	"encoding/binary"
	"errors"
)

var (
	errShortFrame  = errors.New("leannet: frame too short")
	errNotIPv4     = errors.New("leannet: not an IPv4 header (version/IHL)")
	errIPv4Options = errors.New("leannet: IPv4 options unsupported")
	errFragmented  = errors.New("leannet: fragmented IPv4 unsupported")
	errNotARP4     = errors.New("leannet: not an ethernet/IPv4 ARP packet")
	errBadTCPOff   = errors.New("leannet: TCP data offset out of range")
)

// EtherType-waarden die de stack demuxt.
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
)

// IP-protocolnummers.
const (
	ProtoICMP byte = 1
	ProtoTCP  byte = 6
	ProtoUDP  byte = 17
)

// Vaste headermaten (zonder opties).
const (
	sizeEth  = 14
	sizeARP  = 28
	sizeIPv4 = 20
	sizeUDP  = 8
	sizeTCP  = 20
)

// ---- Ethernet (DIX) ----

// EthFrame is een view over een ethernet-frame: dst(6) src(6) ethertype(2).
type EthFrame []byte

// ParseEth valideert de minimale lengte en geeft de view terug.
func ParseEth(b []byte) (EthFrame, error) {
	if len(b) < sizeEth {
		return nil, errShortFrame
	}
	return EthFrame(b), nil
}

func (f EthFrame) Dst() []byte       { return f[0:6] }
func (f EthFrame) Src() []byte       { return f[6:12] }
func (f EthFrame) EtherType() uint16 { return binary.BigEndian.Uint16(f[12:14]) }
func (f EthFrame) Payload() []byte   { return f[sizeEth:] }

func (f EthFrame) SetDst(mac [6]byte)     { copy(f[0:6], mac[:]) }
func (f EthFrame) SetSrc(mac [6]byte)     { copy(f[6:12], mac[:]) }
func (f EthFrame) SetEtherType(et uint16) { binary.BigEndian.PutUint16(f[12:14], et) }

// IsBroadcastDst rapporteert of het frame aan ff:ff:ff:ff:ff:ff gericht is.
func (f EthFrame) IsBroadcastDst() bool {
	d := f.Dst()
	return d[0]&d[1]&d[2]&d[3]&d[4]&d[5] == 0xff
}

// ---- ARP (alleen ethernet/IPv4, RFC 826) ----

// ARP-opcodes.
const (
	ARPRequest uint16 = 1
	ARPReply   uint16 = 2
)

// ARPFrame is een view over de 28-byte ethernet/IPv4-ARP-payload.
type ARPFrame []byte

// ParseARP valideert lengte én dat het echt ethernet/IPv4-ARP is (htype 1,
// ptype 0x0800, hlen 6, plen 4) — al het andere weigeren we luid.
func ParseARP(b []byte) (ARPFrame, error) {
	if len(b) < sizeARP {
		return nil, errShortFrame
	}
	f := ARPFrame(b)
	if binary.BigEndian.Uint16(f[0:2]) != 1 ||
		binary.BigEndian.Uint16(f[2:4]) != EtherTypeIPv4 ||
		f[4] != 6 || f[5] != 4 {
		return nil, errNotARP4
	}
	return f, nil
}

func (f ARPFrame) Op() uint16          { return binary.BigEndian.Uint16(f[6:8]) }
func (f ARPFrame) SenderHW() []byte    { return f[8:14] }
func (f ARPFrame) SenderProto() []byte { return f[14:18] }
func (f ARPFrame) TargetHW() []byte    { return f[18:24] }
func (f ARPFrame) TargetProto() []byte { return f[24:28] }

// PutARP schrijft een compleet ARP-pakket en geeft de geschreven lengte terug.
func PutARP(b []byte, op uint16, senderHW [6]byte, senderIP [4]byte, targetHW [6]byte, targetIP [4]byte) (int, error) {
	if len(b) < sizeARP {
		return 0, errShortFrame
	}
	binary.BigEndian.PutUint16(b[0:2], 1)
	binary.BigEndian.PutUint16(b[2:4], EtherTypeIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], op)
	copy(b[8:14], senderHW[:])
	copy(b[14:18], senderIP[:])
	copy(b[18:24], targetHW[:])
	copy(b[24:28], targetIP[:])
	return sizeARP, nil
}

// ---- IPv4 (RFC 791) ----

// IPv4Frame is een view over een IPv4-header zonder opties (IHL=5).
type IPv4Frame []byte

// ParseIPv4 valideert versie, IHL, totale lengte en fragmentatie. Opties en
// fragmenten doen we bewust niet (v1): weigeren met een eigen fout, zodat een
// teller/logregel bovenin precies kan zeggen wát er geweigerd is.
func ParseIPv4(b []byte) (IPv4Frame, error) {
	if len(b) < sizeIPv4 {
		return nil, errShortFrame
	}
	if b[0]>>4 != 4 {
		return nil, errNotIPv4
	}
	if b[0]&0x0f != 5 {
		return nil, errIPv4Options
	}
	f := IPv4Frame(b)
	if int(f.TotalLen()) > len(b) || f.TotalLen() < sizeIPv4 {
		return nil, errShortFrame
	}
	// Fragment-offset ≠ 0 of More Fragments gezet = een fragment.
	if fragField := binary.BigEndian.Uint16(b[6:8]); fragField&0x3fff != 0 {
		return nil, errFragmented
	}
	return f, nil
}

func (f IPv4Frame) TotalLen() uint16 { return binary.BigEndian.Uint16(f[2:4]) }
func (f IPv4Frame) TTL() byte        { return f[8] }
func (f IPv4Frame) Proto() byte      { return f[9] }
func (f IPv4Frame) Checksum() uint16 { return binary.BigEndian.Uint16(f[10:12]) }
func (f IPv4Frame) Src() [4]byte     { return [4]byte(f[12:16]) }
func (f IPv4Frame) Dst() [4]byte     { return [4]byte(f[16:20]) }

// Payload geeft de bytes ná de header, begrensd door TotalLen — nooit de
// padding die ethernet onder de 60-byte-minimumgrens toevoegt.
func (f IPv4Frame) Payload() []byte { return f[sizeIPv4:f.TotalLen()] }

// PutIPv4 schrijft een complete header (IHL=5, DF gezet, geen fragmentatie)
// inclusief checksum, en geeft de headerlengte terug.
func PutIPv4(b []byte, proto byte, src, dst [4]byte, payloadLen int) (int, error) {
	if len(b) < sizeIPv4 {
		return 0, errShortFrame
	}
	b[0] = 4<<4 | 5
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(sizeIPv4+payloadLen))
	binary.BigEndian.PutUint16(b[4:6], 0)      // identification: ongebruikt zonder fragmentatie
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF
	b[8] = 64                                  // TTL
	b[9] = proto
	binary.BigEndian.PutUint16(b[10:12], 0)
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:sizeIPv4]))
	return sizeIPv4, nil
}

// ChecksumOK hertelt de headerchecksum.
func (f IPv4Frame) ChecksumOK() bool { return checksum(f[:sizeIPv4]) == 0 }

// ---- UDP (RFC 768) ----

// UDPFrame is een view over een UDP-header + payload.
type UDPFrame []byte

func ParseUDP(b []byte) (UDPFrame, error) {
	if len(b) < sizeUDP {
		return nil, errShortFrame
	}
	f := UDPFrame(b)
	if int(f.Len()) > len(b) || f.Len() < sizeUDP {
		return nil, errShortFrame
	}
	return f, nil
}

func (f UDPFrame) SrcPort() uint16 { return binary.BigEndian.Uint16(f[0:2]) }
func (f UDPFrame) DstPort() uint16 { return binary.BigEndian.Uint16(f[2:4]) }
func (f UDPFrame) Len() uint16     { return binary.BigEndian.Uint16(f[4:6]) }
func (f UDPFrame) Payload() []byte { return f[sizeUDP:f.Len()] }

// PutUDP schrijft header + checksum over een al geplaatste payload op
// b[sizeUDP:sizeUDP+payloadLen] en geeft de totale UDP-lengte terug.
func PutUDP(b []byte, srcPort, dstPort uint16, src, dst [4]byte, payloadLen int) (int, error) {
	total := sizeUDP + payloadLen
	if len(b) < total || total > 0xffff {
		return 0, errShortFrame
	}
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(total))
	binary.BigEndian.PutUint16(b[6:8], 0)
	csum := pseudoChecksum(ProtoUDP, src, dst, b[:total])
	if csum == 0 {
		csum = 0xffff // RFC 768: 0 betekent "geen checksum", dus verstuur het complement
	}
	binary.BigEndian.PutUint16(b[6:8], csum)
	return total, nil
}

// ChecksumOK verifieert de UDP-checksum over de pseudo-header. Een checksum
// van 0 betekent "afwezig" en keuren we goed (RFC 768 staat het toe).
func (f UDPFrame) ChecksumOK(src, dst [4]byte) bool {
	if f.Checksum() == 0 {
		return true
	}
	return pseudoChecksum(ProtoUDP, src, dst, f[:f.Len()]) == 0
}

func (f UDPFrame) Checksum() uint16 { return binary.BigEndian.Uint16(f[6:8]) }

// ---- TCP (RFC 9293) — alleen de header-view; de machine leeft in tcp.go ----

// TCP-vlaggen.
type TCPFlags uint16

const (
	FlagFIN TCPFlags = 1 << 0
	FlagSYN TCPFlags = 1 << 1
	FlagRST TCPFlags = 1 << 2
	FlagPSH TCPFlags = 1 << 3
	FlagACK TCPFlags = 1 << 4
)

// Has rapporteert of alle vlaggen in mask gezet zijn.
func (f TCPFlags) Has(mask TCPFlags) bool { return f&mask == mask }

// TCPFrame is een view over een TCP-header + payload.
type TCPFrame []byte

func ParseTCP(b []byte) (TCPFrame, error) {
	if len(b) < sizeTCP {
		return nil, errShortFrame
	}
	f := TCPFrame(b)
	off := f.headerLen()
	if off < sizeTCP || off > len(b) {
		return nil, errBadTCPOff
	}
	return f, nil
}

func (f TCPFrame) SrcPort() uint16  { return binary.BigEndian.Uint16(f[0:2]) }
func (f TCPFrame) DstPort() uint16  { return binary.BigEndian.Uint16(f[2:4]) }
func (f TCPFrame) Seq() uint32      { return binary.BigEndian.Uint32(f[4:8]) }
func (f TCPFrame) Ack() uint32      { return binary.BigEndian.Uint32(f[8:12]) }
func (f TCPFrame) Flags() TCPFlags  { return TCPFlags(binary.BigEndian.Uint16(f[12:14]) & 0x01ff) }
func (f TCPFrame) Window() uint16   { return binary.BigEndian.Uint16(f[14:16]) }
func (f TCPFrame) Checksum() uint16 { return binary.BigEndian.Uint16(f[16:18]) }

func (f TCPFrame) headerLen() int { return int(f[12]>>4) * 4 }

// Options geeft de rauwe optie-bytes tussen de vaste header en de payload.
func (f TCPFrame) Options() []byte { return f[sizeTCP:f.headerLen()] }

// Payload geeft de databytes. De caller begrenst het frame op de
// IPv4-payload (ParseIPv4.Payload), dus len(f) ís de segmentlengte.
func (f TCPFrame) Payload() []byte { return f[f.headerLen():] }

// ChecksumOK verifieert de TCP-checksum over de pseudo-header.
func (f TCPFrame) ChecksumOK(src, dst [4]byte) bool {
	return pseudoChecksum(ProtoTCP, src, dst, f) == 0
}

// PutTCP schrijft een TCP-header met opties en checksum over een al geplaatste
// payload op b[sizeTCP+len(opts):] en geeft de totale segmentlengte terug.
// opts moet een veelvoud van 4 lang zijn (de caller padt met NOP/EOL).
func PutTCP(b []byte, srcPort, dstPort uint16, seq, ack uint32, flags TCPFlags, wnd uint16, opts []byte, src, dst [4]byte, payloadLen int) (int, error) {
	if len(opts)%4 != 0 || len(opts) > 40 {
		return 0, errBadTCPOff
	}
	hdr := sizeTCP + len(opts)
	total := hdr + payloadLen
	if len(b) < total {
		return 0, errShortFrame
	}
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	binary.BigEndian.PutUint16(b[12:14], uint16(hdr/4)<<12|uint16(flags))
	binary.BigEndian.PutUint16(b[14:16], wnd)
	binary.BigEndian.PutUint16(b[16:18], 0)
	binary.BigEndian.PutUint16(b[18:20], 0) // urgent pointer: ongebruikt
	copy(b[sizeTCP:hdr], opts)
	binary.BigEndian.PutUint16(b[16:18], pseudoChecksum(ProtoTCP, src, dst, b[:total]))
	return total, nil
}

// ---- Internet-checksum (RFC 1071) ----

// checksum vouwt de one's-complement-som van b en geeft het complement.
// Over een blok mét geldige checksum is de uitkomst 0.
func checksum(b []byte) uint16 {
	return foldChecksum(sumBytes(0, b))
}

// pseudoChecksum berekent de TCP/UDP-checksum inclusief de IPv4-pseudo-header
// (src, dst, protocol, lengte) over segment.
func pseudoChecksum(proto byte, src, dst [4]byte, segment []byte) uint16 {
	var ph [12]byte
	copy(ph[0:4], src[:])
	copy(ph[4:8], dst[:])
	ph[9] = proto
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(segment)))
	return foldChecksum(sumBytes(sumBytes(0, ph[:]), segment))
}

// sumBytes accumuleert 16-bit big-endian woorden in een 32-bit som; een
// oneven staartbyte telt als hoog byte van een laatste woord (RFC 1071).
func sumBytes(sum uint32, b []byte) uint32 {
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
