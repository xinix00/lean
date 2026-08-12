package leannet

// icmp.go — ICMPv4, alleen echo (RFC 792): genoeg om een node pingbaar te
// maken voor diagnose. Er is geen machine en geen staat — een echo-reply is
// een pure functie van het request, dus de stack-laag roept icmpEcho aan en
// verstuurt het resultaat direct.

import "encoding/binary"

// ICMPv4-types die we kennen.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// sizeICMPEcho is de vaste echo-header: type(1) code(1) checksum(2) id(2) seq(2).
const sizeICMPEcho = 8

// icmpFrame is een view over een ICMPv4-echo-bericht, in de stijl van
// frame.go: type/code op 0/1, checksum op 2-4, id op 4-6, seq op 6-8, daarna
// de payload.
type icmpFrame []byte

// parseICMP valideert de minimale lengte en geeft de view terug.
func parseICMP(b []byte) (icmpFrame, error) {
	if len(b) < sizeICMPEcho {
		return nil, errShortFrame
	}
	return icmpFrame(b), nil
}

func (f icmpFrame) typ() byte       { return f[0] }
func (f icmpFrame) code() byte      { return f[1] }
func (f icmpFrame) id() uint16      { return binary.BigEndian.Uint16(f[4:6]) }
func (f icmpFrame) seq() uint16     { return binary.BigEndian.Uint16(f[6:8]) }
func (f icmpFrame) payload() []byte { return f[sizeICMPEcho:] }

// icmpEcho bouwt uit een binnengekomen echo-request (de IPv4-payload) de
// echo-reply in replyBuf: type 8→0, zelfde code/id/seq/payload, checksum
// herrekend. ok=false voor alles wat geen geldig echo-request is — te kort,
// verkeerd type of code, een kapotte checksum (een corrupt request
// beantwoorden zou de corruptie maskeren), of een replyBuf die het bericht
// niet draagt.
func icmpEcho(reqPayload []byte, replyBuf []byte) (n int, ok bool) {
	req, err := parseICMP(reqPayload)
	if err != nil {
		return 0, false
	}
	if req.typ() != icmpEchoRequest || req.code() != 0 {
		return 0, false
	}
	if checksum(req) != 0 {
		return 0, false
	}
	if len(replyBuf) < len(req) {
		return 0, false
	}
	n = copy(replyBuf, req)
	replyBuf[0] = icmpEchoReply
	binary.BigEndian.PutUint16(replyBuf[2:4], 0)
	binary.BigEndian.PutUint16(replyBuf[2:4], checksum(replyBuf[:n]))
	return n, true
}
