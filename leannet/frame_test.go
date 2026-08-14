package leannet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// refChecksum is een onafhankelijke, naïeve RFC 1071-implementatie waar de
// productie-checksum tegenaan gelegd wordt — het meetinstrument eerst.
func refChecksum(blocks ...[]byte) uint16 {
	var sum uint64
	var all []byte
	for _, b := range blocks {
		all = append(all, b...)
	}
	if len(all)%2 != 0 {
		all = append(all, 0)
	}
	for i := 0; i < len(all); i += 2 {
		sum += uint64(all[i])<<8 | uint64(all[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// TestChecksumGolden legt de checksum tegen het klassieke IPv4-voorbeeld:
// header met checksumveld 0xb861 telt op tot 0.
func TestChecksumGolden(t *testing.T) {
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := checksum(hdr); got != 0 {
		t.Fatalf("golden IPv4 header: checksum = %#04x, want 0", got)
	}
	// En zonder het checksumveld moet precies 0xb861 eruit rollen.
	blank := append([]byte(nil), hdr...)
	blank[10], blank[11] = 0, 0
	if got := checksum(blank); got != 0xb861 {
		t.Fatalf("golden IPv4 header: computed = %#04x, want 0xb861", got)
	}
}

func TestChecksumOddLength(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03}
	if got, want := checksum(b), refChecksum(b); got != want {
		t.Fatalf("odd-length checksum = %#04x, want %#04x", got, want)
	}
}

func TestEthRoundtrip(t *testing.T) {
	buf := make([]byte, sizeEth+4)
	f, err := ParseEth(buf)
	if err != nil {
		t.Fatal(err)
	}
	f.SetDst([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.SetSrc([6]byte{2, 0x48, 0x4f, 0x50, 0, 1})
	f.SetEtherType(EtherTypeARP)
	if f.EtherType() != EtherTypeARP {
		t.Errorf("ethertype = %#04x", f.EtherType())
	}
	if _, err := ParseEth(buf[:sizeEth-1]); err == nil {
		t.Error("short ethernet frame accepted")
	}
}

func TestARPRoundtrip(t *testing.T) {
	buf := make([]byte, 64)
	sh, si := [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{10, 100, 0, 1}
	th, ti := [6]byte{}, [4]byte{10, 100, 0, 2}
	n, err := PutARP(buf, ARPRequest, sh, si, th, ti)
	if err != nil || n != sizeARP {
		t.Fatalf("PutARP: n=%d err=%v", n, err)
	}
	f, err := ParseARP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if f.Op() != ARPRequest || !bytes.Equal(f.SenderHW(), sh[:]) ||
		!bytes.Equal(f.SenderProto(), si[:]) || !bytes.Equal(f.TargetProto(), ti[:]) {
		t.Fatalf("ARP fields corrupted: op=%d", f.Op())
	}
	// Niet-ethernet/IPv4-ARP wordt geweigerd.
	bad := append([]byte(nil), buf[:n]...)
	binary.BigEndian.PutUint16(bad[0:2], 6) // htype IEEE 802
	if _, err := ParseARP(bad); err == nil {
		t.Error("non-ethernet ARP accepted")
	}
}

func TestIPv4Roundtrip(t *testing.T) {
	buf := make([]byte, 128)
	src, dst := [4]byte{192, 168, 99, 1}, [4]byte{192, 168, 99, 2}
	payload := []byte("hello ipv4")
	copy(buf[sizeIPv4:], payload)
	n, err := PutIPv4(buf, ProtoUDP, src, dst, len(payload))
	if err != nil || n != sizeIPv4 {
		t.Fatalf("PutIPv4: n=%d err=%v", n, err)
	}
	// Parse over een buffer mét ethernet-padding erachter: Payload moet op
	// TotalLen knippen, niet op len(b).
	f, err := ParseIPv4(buf[:60])
	if err != nil {
		t.Fatal(err)
	}
	if !f.ChecksumOK() {
		t.Error("header checksum invalid")
	}
	if f.Proto() != ProtoUDP || f.Src() != src || f.Dst() != dst {
		t.Error("IPv4 fields corrupted")
	}
	if !bytes.Equal(f.Payload(), payload) {
		t.Fatalf("payload = %q (len %d), want %q", f.Payload(), len(f.Payload()), payload)
	}
	// Corruptie moet de checksum breken.
	buf[8]-- // TTL
	if f.ChecksumOK() {
		t.Error("checksum still valid after corruption")
	}
	buf[8]++

	// Opties en fragmenten weigeren luid, elk met hun eigen fout.
	withOpts := append([]byte(nil), buf[:60]...)
	withOpts[0] = 4<<4 | 6
	if _, err := ParseIPv4(withOpts); err != errIPv4Options {
		t.Errorf("options: err = %v", err)
	}
	frag := append([]byte(nil), buf[:60]...)
	binary.BigEndian.PutUint16(frag[6:8], 0x2000) // MF
	if _, err := ParseIPv4(frag); err != errFragmented {
		t.Errorf("fragment: err = %v", err)
	}
	frag2 := append([]byte(nil), buf[:60]...)
	binary.BigEndian.PutUint16(frag2[6:8], 0x0001) // offset 8
	if _, err := ParseIPv4(frag2); err != errFragmented {
		t.Errorf("fragment offset: err = %v", err)
	}
}

func TestUDPRoundtrip(t *testing.T) {
	buf := make([]byte, 128)
	src, dst := [4]byte{10, 100, 0, 1}, [4]byte{10, 100, 0, 2}
	payload := []byte("dns query")
	copy(buf[sizeUDP:], payload)
	n, err := PutUDP(buf, 5353, 53, src, dst, len(payload))
	if err != nil || n != sizeUDP+len(payload) {
		t.Fatalf("PutUDP: n=%d err=%v", n, err)
	}
	f, err := ParseUDP(buf[:n+6]) // + rommel erachter: Len moet knippen
	if err != nil {
		t.Fatal(err)
	}
	if f.SrcPort() != 5353 || f.DstPort() != 53 || !bytes.Equal(f.Payload(), payload) {
		t.Error("UDP fields corrupted")
	}
	if !f.ChecksumOK(src, dst) {
		t.Error("UDP checksum invalid")
	}
	// src↔dst wisselen verandert de som niet (commutatief) — een ander adres wél.
	if f.ChecksumOK(src, [4]byte{10, 100, 0, 3}) {
		t.Error("UDP checksum ignores the pseudo-header")
	}
	// Checksum 0 = afwezig = goedkeuren.
	binary.BigEndian.PutUint16(buf[6:8], 0)
	if !f.ChecksumOK(src, dst) {
		t.Error("absent UDP checksum rejected")
	}
}

func TestTCPRoundtrip(t *testing.T) {
	buf := make([]byte, 256)
	src, dst := [4]byte{192, 168, 99, 2}, [4]byte{140, 82, 121, 4}
	payload := []byte("GET / HTTP/1.1\r\n")
	opts := []byte{2, 4, 0x05, 0xb4} // MSS 1460
	copy(buf[sizeTCP+len(opts):], payload)
	n, err := PutTCP(buf, 49152, 443, 1000, 2000, FlagACK|FlagPSH, 0xfff0, opts, src, dst, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseTCP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case f.SrcPort() != 49152 || f.DstPort() != 443:
		t.Error("ports corrupted")
	case f.Seq() != 1000 || f.Ack() != 2000:
		t.Error("seq/ack corrupted")
	case !f.Flags().Has(FlagACK|FlagPSH) || f.Flags().Has(FlagSYN):
		t.Errorf("flags = %#x", f.Flags())
	case f.Window() != 0xfff0:
		t.Error("window corrupted")
	case !bytes.Equal(f.Options(), opts):
		t.Error("options corrupted")
	case !bytes.Equal(f.Payload(), payload):
		t.Error("payload corrupted")
	}
	if !f.ChecksumOK(src, dst) {
		t.Error("TCP checksum invalid")
	}
	buf[n-1] ^= 0xff
	if f.ChecksumOK(src, dst) {
		t.Error("checksum still valid after payload corruption")
	}
	buf[n-1] ^= 0xff

	// Opties moeten op 4 uitgelijnd zijn; een kapotte data-offset weigert.
	if _, err := PutTCP(buf, 1, 2, 0, 0, FlagSYN, 0, []byte{2, 4, 0}, src, dst, 0); err == nil {
		t.Error("unaligned options accepted")
	}
	bad := append([]byte(nil), buf[:n]...)
	bad[12] = 3 << 4 // offset 12 bytes < 20
	if _, err := ParseTCP(bad); err != errBadTCPOff {
		t.Errorf("bad offset: err = %v", err)
	}
}

// TestPseudoChecksumAgainstRef legt de pseudo-header-checksum tegen de
// referentie-implementatie voor een reeks lengtes (even, oneven, leeg).
func TestPseudoChecksumAgainstRef(t *testing.T) {
	src, dst := [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}
	for _, n := range []int{0, 1, 2, 3, 19, 20, 21, 1460} {
		seg := make([]byte, sizeTCP+n)
		for i := range seg {
			seg[i] = byte(i*7 + n)
		}
		var ph [12]byte
		copy(ph[0:4], src[:])
		copy(ph[4:8], dst[:])
		ph[9] = ProtoTCP
		binary.BigEndian.PutUint16(ph[10:12], uint16(len(seg)))
		if got, want := pseudoChecksum(ProtoTCP, src, dst, seg), refChecksum(ph[:], seg); got != want {
			t.Fatalf("len %d: pseudoChecksum = %#04x, want %#04x", n, got, want)
		}
	}
}
