package leannet

// icmp_test.go — golden roundtrip voor de echo-reply plus de weigeringen:
// kapotte checksum, verkeerd type, te kort, te kleine reply-buffer.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// icmpTestRequest bouwt een geldig echo-request met de onafhankelijke
// referentie-checksum uit frame_test.go — het meetinstrument eerst.
func icmpTestRequest(id, seq uint16, payload []byte) []byte {
	msg := make([]byte, sizeICMPEcho+len(payload))
	msg[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[sizeICMPEcho:], payload)
	binary.BigEndian.PutUint16(msg[2:4], refChecksum(msg))
	return msg
}

// TestICMPEchoGoldenRoundtrip: request in, reply uit — type 8→0, zelfde
// id/seq/payload, checksum herrekend; byte-voor-byte gelijk aan de
// onafhankelijk gebouwde verwachting.
func TestICMPEchoGoldenRoundtrip(t *testing.T) {
	payload := []byte("leannet echo 0123456789")
	req := icmpTestRequest(0x1234, 7, payload)

	reply := make([]byte, len(req))
	n, ok := icmpEcho(req, reply)
	if !ok || n != len(req) {
		t.Fatalf("icmpEcho = %d, %v; want %d, true", n, ok, len(req))
	}

	f, err := parseICMP(reply[:n])
	if err != nil {
		t.Fatal(err)
	}
	if f.typ() != icmpEchoReply || f.code() != 0 {
		t.Fatalf("reply type/code = %d/%d, want 0/0", f.typ(), f.code())
	}
	if f.id() != 0x1234 || f.seq() != 7 {
		t.Fatalf("reply id/seq = %#x/%d, want 0x1234/7", f.id(), f.seq())
	}
	if !bytes.Equal(f.payload(), payload) {
		t.Fatalf("reply payload = %q, want %q", f.payload(), payload)
	}
	if checksum(reply[:n]) != 0 {
		t.Fatal("reply checksum does not verify")
	}

	// Golden: de verwachting onafhankelijk opgebouwd met refChecksum.
	want := append([]byte(nil), req...)
	want[0] = icmpEchoReply
	want[2], want[3] = 0, 0
	binary.BigEndian.PutUint16(want[2:4], refChecksum(want))
	if !bytes.Equal(reply[:n], want) {
		t.Fatalf("reply = % x, want % x", reply[:n], want)
	}
}

// TestICMPEchoRejects: alles wat geen geldig echo-request is levert ok=false —
// vooral de kapotte checksum (die beantwoorden zou corruptie maskeren).
func TestICMPEchoRejects(t *testing.T) {
	reply := make([]byte, 64)

	// Kapotte checksum: één payload-byte geflipt ná het rekenen.
	bad := icmpTestRequest(1, 1, []byte("ping"))
	bad[len(bad)-1] ^= 0xff
	if _, ok := icmpEcho(bad, reply); ok {
		t.Fatal("echo request with broken checksum accepted")
	}

	// Verkeerd type: een echo-reply als input is geen request.
	rep := icmpTestRequest(1, 1, []byte("ping"))
	rep[0] = icmpEchoReply
	binary.BigEndian.PutUint16(rep[2:4], 0)
	binary.BigEndian.PutUint16(rep[2:4], refChecksum(rep))
	if _, ok := icmpEcho(rep, reply); ok {
		t.Fatal("echo reply accepted as a request")
	}

	// Verkeerde code (RFC 792: echo heeft code 0).
	code := icmpTestRequest(1, 1, []byte("ping"))
	code[1] = 3
	binary.BigEndian.PutUint16(code[2:4], 0)
	binary.BigEndian.PutUint16(code[2:4], refChecksum(code))
	if _, ok := icmpEcho(code, reply); ok {
		t.Fatal("echo request with nonzero code accepted")
	}

	// Te kort voor de echo-header.
	if _, ok := icmpEcho([]byte{icmpEchoRequest, 0, 0}, reply); ok {
		t.Fatal("short icmp message accepted")
	}

	// Reply-buffer die het bericht niet draagt.
	good := icmpTestRequest(1, 1, []byte("ping"))
	if _, ok := icmpEcho(good, make([]byte, len(good)-1)); ok {
		t.Fatal("undersized reply buffer accepted")
	}
}
