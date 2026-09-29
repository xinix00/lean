package leannet

// icmp.go implements stateless ICMPv4 echo (RFC 792), enough for diagnostic pings.

import "encoding/binary"

// Supported ICMPv4 types.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// sizeICMPEcho is the fixed type/code/checksum/id/sequence header.
const sizeICMPEcho = 8

// icmpFrame is an in-place view over an ICMPv4 echo message.
type icmpFrame []byte

// parseICMP validates the minimum length and returns the view.
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

// icmpEcho builds an echo reply in replyBuf, preserving code, ID, sequence, and
// payload while changing type and checksum. It rejects malformed or corrupt
// requests and undersized output buffers.
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
