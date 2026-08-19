// Package leanh2 serves HTTP/2 on a connection you already chose and supply.
//
// It exists because the alternative cannot be used alone. golang.org/x/net's
// http2.Server.ServeConn takes an http.Handler, so reaching for HTTP/2 pulls in
// net/http, and net/http links crypto/tls and crypto/x509 whether or not the
// connection is ever encrypted.
//
// Measured with two equivalent mains, each serving one connection with a
// handler that writes "ok" (`-ldflags="-s -w"`, CGO_ENABLED=0, 2026-08-19):
//
//	golang.org/x/net/http2 + net/http ......... 5.10 MB
//	this package .............................. 2.22 MB (-2.88)
//
// 56% smaller, and the cause is structural rather than incidental: x/net/http2
// cannot be used without net/http, whose graph carries 69 crypto and net/http
// packages. This package carries its own [Request] and [Response], and HPACK
// lives inside it rather than in a second package to import — so it links no
// net/http, crypto/tls, or crypto/x509.
//
// # The server role only, and only that
//
// There is no listener, no dialer, and no client half. There is also no
// negotiation about which protocol version this is: the caller has already
// decided. That is what keeps the package small, and it is the shape the one
// measured consumer needs — a Cloudflare Tunnel dials OUT, and the edge then
// behaves as the HTTP/2 client on that outbound connection: it sends the
// preface, it opens every stream, and it never expects a request from this side.
//
// # HTTP/1.1 is the other choice, not the older one
//
// A higher protocol version is not a simplification. This package is about
// twice the code of leanhttp's server side, and it adds a stream state machine,
// two levels of flow control, header compression with two tables and a Huffman
// alphabet, and a settings negotiation. Serving HTTP/2 to a browser needs ALPN,
// which leantls does not have.
//
// So use leanhttp unless HTTP/2 is required. The two packages share no code and
// no types: importing one links nothing of the other. There is deliberately no
// sniffing between the versions here — four bytes cannot prove a preface
// follows, because PRI is a valid HTTP extension method — so a caller that must
// carry both chooses per listener.
//
// # What it holds
//
// Inside the profile the guarantees are complete, not partial. A header block is
// indivisible in both directions. Stream identifiers must be client-initiated,
// odd, and strictly increasing. Concurrent streams, the compressed bytes of one
// header block, and the decoded header list are all bounded. Both flow-control
// levels are accounted without losing the difference between them, an increment
// that would overflow is refused, and a DATA frame returns credit for its full
// flow-controlled payload including padding. Receive credit follows what the
// handler consumed, so no handler can stall the frame loop. GOAWAY carries the
// highest stream this side accepted and may still finish, so a peer never
// retries work that can still have side effects here.
//
// # Deliberate limits
//
// Refused, each ending the connection with an error that names the peer's
// mistake: a wrong preface; a frame above the announced maximum; malformed
// padding; DATA or HEADERS on stream 0; a PING that is not eight bytes on
// stream 0; a SETTINGS acknowledgement with a payload; an even, reused, or
// lower stream identifier; more concurrent streams than announced; a header
// block interrupted by another frame; compressed header bytes or a decoded
// header list above the limit; a request whose pseudo-headers are missing,
// duplicated, unknown, or out of order; an uppercase field name; a
// connection-specific field; WINDOW_UPDATE of zero or one that would overflow;
// and EOS inside a Huffman literal. Handler response fields are checked before
// they reach the wire; Content-Length is deliberately refused because DATA and
// END_STREAM are the one response-length state. Body writes for HEAD, 204, 205,
// and 304 fail instead of being silently emitted or discarded.
//
// Absent on purpose, with the state space removed rather than stubbed: the
// client role, a listener or dialer, TLS, ALPN and h2c upgrade, version
// sniffing, server push, CONNECT, sending trailers, 1xx responses, priority
// state or scheduling, and the HPACK encoder's dynamic table. An exact static-
// table match uses its index; every other response field goes out as a literal
// without indexing, so encoding creates no connection state.
//
// The caller chooses and supplies the connection, owns its deadline policy, and
// may close or deadline it to initiate a stop. Serve is invoked exactly once;
// Conn also closes the transport before that invocation returns, so blocked
// frame writers, Body readers, and stream waiters all wake up.
//
// KAM.md is normative for this boundary; this doc summarizes it.
package leanh2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// clientPreface is what the peer sends first (RFC 9113 §3.4).
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame types and flags.
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePushPromise  = 0x5
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9

	flagEndStream  = 0x1
	flagACK        = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20

	// The only two stream codes this side sends: NO_ERROR to say "stop sending,
	// the answer is complete", INTERNAL_ERROR for a handler that could not
	// finish. Peer protocol errors end Serve and close the connection.
	codeNoError       = 0x0
	codeInternalError = 0x2
)

// What this side announces, and therefore what it must survive.
//
// The receive window is the body buffer: a peer may hold at most this much
// unread body per stream, and credit is returned as the handler reads. Together
// with the stream cap that bounds the memory one connection can claim —
// maxConcurrentStreams × ourInitialWindow — instead of leaving it to the peer.
//
// The zero header table size keeps the peer from building a dynamic table at
// all, which removes a whole class of state on the decode side. The 16 KB frame
// size is the RFC floor and therefore the smallest buffers.
const (
	ourHeaderTableSize        = 0
	ourInitialWindow          = 64 << 10
	ourMaxFrame               = 1 << 14
	ourMaxHeaderList          = 1 << 16
	maxConcurrentStreams      = 32
	maxCompressedHeaders      = 64 << 10
	connectionWindowIncrement = 1 << 20
)

const (
	settingHeaderTableSize   = 0x1
	settingEnablePush        = 0x2
	settingMaxConcurrent     = 0x3
	settingInitialWindowSize = 0x4
	settingMaxFrameSize      = 0x5
	settingMaxHeaderListSize = 0x6
)

// windowMax is the largest a flow-control window may become (RFC 9113 §6.9.1).
const windowMax = int64(1)<<31 - 1

// Request is one request from the peer.
type Request struct {
	Method, Path, Scheme, Authority string
	Header                          map[string][]string
	// Body delivers the DATA frames of this stream in order. A request without
	// a body is immediately at EOF. Reading it is what returns flow-control
	// credit to the peer.
	Body io.ReadCloser
	// StreamID identifies the stream. It belongs in log lines: a connection
	// carrying ten concurrent requests is unreadable without it.
	StreamID uint32
}

// Get returns the first value of a header, or "".
func (r *Request) Get(name string) string {
	if v := r.Header[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Handler serves one stream. It may block: every stream gets its own goroutine,
// which is what concurrent streams are for — one slow request must not hold up
// the others.
type Handler func(*Request, *Response)

// Conn is one HTTP/2 connection.
type Conn struct {
	rw      io.ReadWriteCloser
	handler Handler
	logf    func(string, ...any)
	dec     *decoder

	// wmu serializes frame writes. Frames may not interleave, and several
	// streams write at once; a header block holds it across its CONTINUATION
	// frames because RFC 9113 §6.2 allows nothing between them.
	wmu            sync.Mutex
	transportClose sync.Once

	mu      sync.Mutex
	streams map[uint32]*stream
	// lastStreamID is the highest client-initiated identifier accepted. It is
	// what GOAWAY must report, and it makes identifier reuse detectable.
	lastStreamID uint32
	// pendingHeaders is the stream whose header block is still open, or 0. While
	// it is set, only CONTINUATION on that stream is accepted.
	pendingHeaders    uint32
	connWin           int64
	connCond          *sync.Cond
	peerInitialWindow int32
	streamSlots       int
	peerSettings      bool
	settingsAcked     bool
	serveStarted      bool
	ready             bool
	goingAway         bool
	closeErr          error

	// recvMu owns receive-window accounting. It is separate from mu because a
	// WINDOW_UPDATE write may block; that must not hold every stream-state lock.
	// Wire operations take wmu first, then briefly mu and recvMu; no path takes
	// either state lock and then waits for wmu.
	recvMu       sync.Mutex
	recvWin      int64
	recentResets map[uint32]int64 // remaining receive credit after our RST
	resetOrder   []uint32         // bounds recentResets without timer state
}

type stream struct {
	id   uint32
	c    *Conn
	body *body

	// win and the stream lifecycle are protected by Conn.mu. All send-window
	// decisions then happen in one place and two streams cannot spend the same
	// connection credit.
	win          int64
	closed       bool
	remoteEnded  bool
	headerBuf    []byte
	expectedBody int64 // -1 when content-length is absent
	receivedBody int64
	method       string
	receiving    int // DATA frames between state validation and body delivery

	// recvWin and recvClosed are protected by Conn.recvMu.
	recvWin        int64
	recvClosed     bool
	recvDiscarding bool
}

// NewConn wraps a full-duplex connection that is already open. rw must permit
// one concurrent Read and Write, and Close must wake both, as net.Conn does.
// logf may be nil. The caller may close or deadline rw to initiate shutdown.
// Serve must be called exactly once; Conn closes rw before that call returns.
func NewConn(rw io.ReadWriteCloser, handler Handler, logf func(string, ...any)) *Conn {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	c := &Conn{
		rw:                rw,
		handler:           handler,
		logf:              logf,
		dec:               newDecoder(4096, ourMaxHeaderList),
		streams:           map[uint32]*stream{},
		recentResets:      map[uint32]int64{},
		connWin:           65535,
		recvWin:           65535,
		peerInitialWindow: 65535,
	}
	c.connCond = sync.NewCond(&c.mu)
	return c
}

// Serve reads the preface, exchanges settings, and then serves frames until the
// connection ends. It returns the reason. A Conn serves exactly once.
func (c *Conn) Serve() error {
	c.mu.Lock()
	if c.serveStarted {
		c.mu.Unlock()
		return errors.New("leanh2: Serve called more than once")
	}
	c.serveStarted = true
	c.mu.Unlock()
	if err := c.readPreface(); err != nil {
		return c.serveError(err)
	}
	if err := c.writeSettings(); err != nil {
		return c.serveError(err)
	}
	// Raise the connection window once: the per-stream windows are small on
	// purpose, and without this the connection level becomes the bottleneck for
	// concurrent uploads.
	var inc [4]byte
	binary.BigEndian.PutUint32(inc[:], connectionWindowIncrement)
	if err := c.writeFrame(frameWindowUpdate, 0, 0, inc[:]); err != nil {
		return c.serveError(err)
	}
	c.recvMu.Lock()
	c.recvWin += connectionWindowIncrement
	c.recvMu.Unlock()
	c.mu.Lock()
	c.ready = true
	c.mu.Unlock()
	return c.serveError(c.loop())
}

func (c *Conn) serveError(err error) error {
	c.shutdown(err)
	if first := c.connectionError(); first != nil {
		return first
	}
	return err
}

func (c *Conn) readPreface() error {
	got := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(c.rw, got); err != nil {
		return fmt.Errorf("leanh2: reading the client preface: %w", err)
	}
	if string(got) != clientPreface {
		return errors.New("leanh2: peer did not send the HTTP/2 client preface")
	}
	return nil
}

func (c *Conn) writeSettings() error {
	var body []byte
	for _, kv := range [][2]uint32{
		{settingHeaderTableSize, ourHeaderTableSize},
		{settingEnablePush, 0},
		{settingMaxConcurrent, maxConcurrentStreams},
		{settingInitialWindowSize, ourInitialWindow},
		{settingMaxFrameSize, ourMaxFrame},
		{settingMaxHeaderListSize, ourMaxHeaderList},
	} {
		body = binary.BigEndian.AppendUint16(body, uint16(kv[0]))
		body = binary.BigEndian.AppendUint32(body, kv[1])
	}
	return c.writeFrame(frameSettings, 0, 0, body)
}

// writeFrame writes one frame. Every writer goes through here except a header
// block, which uses writeHeaderBlock to stay indivisible.
func (c *Conn) writeFrame(typ byte, flags byte, streamID uint32, body []byte) error {
	c.wmu.Lock()
	if err := c.connectionError(); err != nil {
		c.wmu.Unlock()
		return err
	}
	err := c.writeFrameLocked(typ, flags, streamID, body)
	failed := err != nil
	if failed {
		err = c.recordWriteFailure(err)
	}
	c.wmu.Unlock()
	if failed {
		c.endConnection(err)
	}
	return err
}

func (c *Conn) writeFrameLocked(typ byte, flags byte, streamID uint32, body []byte) error {
	if len(body) > 1<<24-1 {
		return errors.New("leanh2: frame body too large")
	}
	var head [9]byte
	head[0] = byte(len(body) >> 16)
	head[1] = byte(len(body) >> 8)
	head[2] = byte(len(body))
	head[3] = typ
	head[4] = flags
	binary.BigEndian.PutUint32(head[5:], streamID&0x7fffffff)
	if n, err := c.rw.Write(head[:]); err != nil {
		return err
	} else if n != len(head) {
		return io.ErrShortWrite
	}
	if len(body) > 0 {
		if n, err := c.rw.Write(body); err != nil {
			return err
		} else if n != len(body) {
			return io.ErrShortWrite
		}
	}
	return nil
}

// writeHeaderBlock writes HEADERS plus any CONTINUATION under one lock. Another
// stream's frame in between would make the whole connection invalid
// (RFC 9113 §6.2), and the write lock is the only thing that can prevent it.
func (c *Conn) writeStreamHeaderBlock(s *stream, block []byte, endStream bool) error {
	c.wmu.Lock()
	c.mu.Lock()
	if c.closeErr != nil || s.closed || c.streams[s.id] != s {
		err := c.closeErr
		if err == nil {
			err = errors.New("leanh2: stream closed")
		}
		c.mu.Unlock()
		c.wmu.Unlock()
		return err
	}
	c.mu.Unlock()
	err := c.writeHeaderBlockLocked(s.id, block, endStream, ourMaxFrame)
	failed := err != nil
	if failed {
		err = c.recordWriteFailure(err)
	}
	c.wmu.Unlock()
	if failed {
		c.endConnection(err)
	}
	return err
}

func (c *Conn) writeHeaderBlockLocked(streamID uint32, block []byte, endStream bool, max int) error {
	first, rest := block, []byte(nil)
	if len(block) > max {
		first, rest = block[:max], block[max:]
	}
	flags := byte(0)
	if len(rest) == 0 {
		flags |= flagEndHeaders
	}
	if endStream {
		flags |= flagEndStream
	}
	if err := c.writeFrameLocked(frameHeaders, flags, streamID, first); err != nil {
		return err
	}
	for len(rest) > 0 {
		chunk := rest
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		rest = rest[len(chunk):]
		f := byte(0)
		if len(rest) == 0 {
			f = flagEndHeaders
		}
		if err := c.writeFrameLocked(frameContinuation, f, streamID, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) loop() error {
	head := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c.rw, head); err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				return errors.New("leanh2: the peer closed the connection")
			}
			return err
		}
		length := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
		typ, flags := head[3], head[4]
		streamID := binary.BigEndian.Uint32(head[5:]) & 0x7fffffff
		if length > ourMaxFrame {
			return c.publishProtocolError(fmt.Errorf("leanh2: peer sent a %d byte frame above the announced %d", length, ourMaxFrame))
		}
		body := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(c.rw, body); err != nil {
				return err
			}
		}
		c.mu.Lock()
		first := !c.peerSettings
		if first && typ == frameSettings && streamID == 0 && flags&flagACK == 0 {
			c.peerSettings = true
		}
		c.mu.Unlock()
		if first && (typ != frameSettings || streamID != 0 || flags&flagACK != 0) {
			return c.publishProtocolError(errors.New("leanh2: the first peer frame after the preface is not non-ACK SETTINGS on stream 0"))
		}
		// A header block is one unit: while it is open, nothing else may arrive.
		if pending := c.pendingBlock(); pending != 0 {
			if typ != frameContinuation || streamID != pending {
				return c.publishProtocolError(fmt.Errorf("leanh2: frame type 0x%02x on stream %d interrupted the header block of stream %d",
					typ, streamID, pending))
			}
		} else if typ == frameContinuation {
			return c.publishProtocolError(errors.New("leanh2: CONTINUATION without an open header block"))
		}
		if err := c.dispatch(typ, flags, streamID, body); err != nil {
			return c.publishProtocolError(err)
		}
	}
}

// publishProtocolError is the inbound counterpart of recordWriteFailure. wmu
// is the barrier: output already holding it is in flight before the refusal;
// every writer after it observes closeErr and emits nothing.
func (c *Conn) publishProtocolError(err error) error {
	c.wmu.Lock()
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
	}
	first := c.closeErr
	c.connCond.Broadcast()
	c.mu.Unlock()
	c.wmu.Unlock()
	return first
}

func (c *Conn) pendingBlock() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pendingHeaders
}

func (c *Conn) dispatch(typ, flags byte, streamID uint32, body []byte) error {
	switch typ {
	case frameSettings:
		if streamID != 0 {
			return errors.New("leanh2: SETTINGS on a stream")
		}
		if flags&flagACK != 0 {
			if len(body) != 0 {
				return errors.New("leanh2: SETTINGS acknowledgement with a payload")
			}
			c.mu.Lock()
			if c.settingsAcked {
				c.mu.Unlock()
				return errors.New("leanh2: duplicate SETTINGS acknowledgement")
			}
			c.settingsAcked = true
			c.mu.Unlock()
			c.dec.setAllowed(ourHeaderTableSize)
			return nil
		}
		return c.applySettingsAndAck(body)

	case framePing:
		if streamID != 0 || len(body) != 8 {
			return fmt.Errorf("leanh2: PING of %d bytes on stream %d", len(body), streamID)
		}
		if flags&flagACK != 0 {
			return nil
		}
		// Answering matters more than it looks: a peer that measures liveness
		// this way may withhold every stream until it sees the ACK. The
		// Cloudflare Tunnel edge is one such peer (measured 19-08).
		return c.writeFrame(framePing, flagACK, 0, body)

	case frameWindowUpdate:
		return c.onWindowUpdate(streamID, body)

	case frameHeaders:
		return c.onHeaders(flags, streamID, body)

	case frameContinuation:
		return c.onContinuation(flags, streamID, body)

	case frameData:
		return c.onData(flags, streamID, body)

	case frameRSTStream:
		if len(body) != 4 || streamID == 0 {
			return fmt.Errorf("leanh2: RST_STREAM of %d bytes on stream %d", len(body), streamID)
		}
		return c.onReset(streamID)

	case framePushPromise:
		return errors.New("leanh2: PUSH_PROMISE is not supported by this server")

	case frameGoAway:
		if streamID != 0 || len(body) < 8 {
			return fmt.Errorf("leanh2: GOAWAY of %d bytes on stream %d", len(body), streamID)
		}
		reason, code := "", uint32(0)
		code = binary.BigEndian.Uint32(body[4:])
		reason = string(body[8:])
		return fmt.Errorf("leanh2: the peer sent GOAWAY (code %d) %s", code, reason)

	case framePriority:
		if streamID == 0 || len(body) != 5 {
			return fmt.Errorf("leanh2: PRIORITY of %d bytes on stream %d", len(body), streamID)
		}
		return nil // accepted and ignored: there is no scheduling here

	default:
		return nil // unknown types are ignored, as the RFC requires
	}
}

func (c *Conn) onWindowUpdate(streamID uint32, body []byte) error {
	if len(body) != 4 {
		return errors.New("leanh2: malformed WINDOW_UPDATE")
	}
	inc := int64(binary.BigEndian.Uint32(body) & 0x7fffffff)
	if inc == 0 {
		return errors.New("leanh2: WINDOW_UPDATE of zero")
	}
	if streamID == 0 {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.connWin+inc > windowMax {
			return errors.New("leanh2: WINDOW_UPDATE would overflow the connection window")
		}
		c.connWin += inc
		c.connCond.Broadcast()
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.streams[streamID]
	if s == nil {
		if streamID%2 == 0 || streamID > c.lastStreamID {
			return fmt.Errorf("leanh2: WINDOW_UPDATE on idle stream %d", streamID)
		}
		return nil // a window for a closed stream is not an error
	}
	if s.win+inc > windowMax {
		return fmt.Errorf("leanh2: WINDOW_UPDATE would overflow the window of stream %d", streamID)
	}
	s.win += inc
	c.connCond.Broadcast()
	return nil
}

// applySettingsAndAck serializes the setting transition with response DATA.
// A reservation made under the old initial window is revalidated by its writer
// before it can follow this ACK on the wire.
func (c *Conn) applySettingsAndAck(body []byte) error {
	if len(body)%6 != 0 {
		return errors.New("leanh2: malformed SETTINGS")
	}
	c.wmu.Lock()
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		c.wmu.Unlock()
		return err
	}
	err := c.applySettingsLocked(body)
	c.mu.Unlock()
	writeFailed := false
	if err == nil {
		err = c.writeFrameLocked(frameSettings, flagACK, 0, nil)
		writeFailed = err != nil
	}
	if writeFailed {
		err = c.recordWriteFailure(err)
	}
	c.wmu.Unlock()
	if writeFailed {
		c.endConnection(err)
	}
	return err
}

// applySettingsLocked validates and applies one SETTINGS payload under c.mu.
func (c *Conn) applySettingsLocked(body []byte) error {
	for o := 0; o+6 <= len(body); o += 6 {
		id := binary.BigEndian.Uint16(body[o:])
		v := binary.BigEndian.Uint32(body[o+2:])
		switch id {
		case settingInitialWindowSize:
			if int64(v) > windowMax {
				return errors.New("leanh2: INITIAL_WINDOW_SIZE too large")
			}
			// A changed initial window shifts every live stream's window by the
			// same difference (RFC 9113 §6.9.2).
			delta := int64(v) - int64(c.peerInitialWindow)
			if delta > 0 {
				for _, s := range c.streams {
					if s.win > windowMax-delta {
						return fmt.Errorf("leanh2: INITIAL_WINDOW_SIZE would overflow the window of stream %d", s.id)
					}
				}
			}
			c.peerInitialWindow = int32(v)
			for _, s := range c.streams {
				s.win += delta
			}
			c.connCond.Broadcast()
		case settingEnablePush:
			if v > 1 {
				return errors.New("leanh2: ENABLE_PUSH is not 0 or 1")
			}
		case settingMaxFrameSize:
			if v < 16384 || v > 1<<24-1 {
				return errors.New("leanh2: MAX_FRAME_SIZE out of range")
			}
		}
	}
	return nil
}

func (c *Conn) stream(id uint32) *stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *Conn) onHeaders(flags byte, streamID uint32, raw []byte) error {
	if streamID == 0 {
		return errors.New("leanh2: HEADERS on stream 0")
	}
	block, err := stripPadding(raw, flags)
	if err != nil {
		return err
	}
	if flags&flagPriority != 0 {
		if len(block) < 5 {
			return errors.New("leanh2: malformed HEADERS priority")
		}
		block = block[5:]
	}

	c.mu.Lock()
	switch {
	case c.closeErr != nil:
		err := c.closeErr
		c.mu.Unlock()
		return err
	case c.goingAway:
		c.mu.Unlock()
		return errors.New("leanh2: the peer opened a stream after GOAWAY")
	case streamID%2 == 0:
		c.mu.Unlock()
		return fmt.Errorf("leanh2: stream %d is not client-initiated", streamID)
	case streamID <= c.lastStreamID:
		c.mu.Unlock()
		return fmt.Errorf("leanh2: stream %d is not above the last accepted %d", streamID, c.lastStreamID)
	case c.streamSlots >= maxConcurrentStreams:
		c.mu.Unlock()
		return fmt.Errorf("leanh2: peer opened more than the announced %d concurrent streams", maxConcurrentStreams)
	}
	c.lastStreamID = streamID
	c.streamSlots++
	s := &stream{
		id:           streamID,
		c:            c,
		headerBuf:    block,
		remoteEnded:  flags&flagEndStream != 0,
		expectedBody: -1,
		recvWin:      ourInitialWindow,
	}
	s.win = int64(c.peerInitialWindow)
	s.body = newBody(s)
	c.streams[streamID] = s
	if flags&flagEndHeaders == 0 {
		c.pendingHeaders = streamID
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	return c.startStream(s)
}

func (c *Conn) onContinuation(flags byte, streamID uint32, block []byte) error {
	s := c.stream(streamID)
	if s == nil {
		return fmt.Errorf("leanh2: CONTINUATION for unknown stream %d", streamID)
	}
	if len(s.headerBuf)+len(block) > maxCompressedHeaders {
		return fmt.Errorf("leanh2: header block of stream %d above the %d byte limit",
			streamID, maxCompressedHeaders)
	}
	s.headerBuf = append(s.headerBuf, block...)
	if flags&flagEndHeaders == 0 {
		return nil
	}
	c.mu.Lock()
	c.pendingHeaders = 0
	c.mu.Unlock()
	return c.startStream(s)
}

// stripPadding removes the pad length and padding of a padded frame.
func stripPadding(raw []byte, flags byte) ([]byte, error) {
	if flags&flagPadded == 0 {
		return raw, nil
	}
	if len(raw) == 0 {
		return nil, errors.New("leanh2: padded frame without a pad length")
	}
	pad := int(raw[0])
	if 1+pad > len(raw) {
		return nil, errors.New("leanh2: padding beyond the frame")
	}
	return raw[1 : len(raw)-pad], nil
}

// startStream decodes the header block, checks it, and puts the handler to work.
func (c *Conn) startStream(s *stream) error {
	fields, err := c.dec.decode(s.headerBuf)
	if err != nil {
		return fmt.Errorf("leanh2: header block on stream %d: %w", s.id, err)
	}
	s.headerBuf = nil

	req, contentLength, err := requestFrom(fields)
	if err != nil {
		return fmt.Errorf("leanh2: request on stream %d: %w", s.id, err)
	}
	req.Body = s.body
	req.StreamID = s.id
	c.mu.Lock()
	if c.closeErr != nil || s.closed || c.streams[s.id] != s {
		err := c.closeErr
		if err == nil {
			err = errors.New("leanh2: stream closed before handler start")
		}
		c.mu.Unlock()
		return err
	}
	s.expectedBody = contentLength
	s.method = req.Method
	remoteEnded := s.remoteEnded
	c.mu.Unlock()
	if remoteEnded && contentLength > 0 {
		return fmt.Errorf("leanh2: request on stream %d ended before its content-length of %d", s.id, contentLength)
	}
	if remoteEnded {
		s.body.close(nil)
	}
	res := &Response{s: s}

	go func() {
		defer c.releaseStreamSlot()
		defer func() {
			// A handler that panics kills its own stream and nothing else. On a
			// node without a supervisor that is the difference between one
			// broken request and a dead service.
			if r := recover(); r != nil {
				c.logf("leanh2: handler for stream %d panicked: %v", s.id, r)
				res.fail(codeInternalError)
			}
		}()
		c.handler(req, res)
		res.finish()
	}()
	return nil
}

func (c *Conn) releaseStreamSlot() {
	c.mu.Lock()
	if c.streamSlots > 0 {
		c.streamSlots--
	}
	c.mu.Unlock()
}

// connectionFields are the HTTP/1.1 connection-specific fields that have no
// meaning here and must be refused (RFC 9113 §8.2.2).
var connectionFields = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "upgrade": true,
}

// requestFrom turns a decoded header list into a request, or refuses it. The
// pseudo-header rules are RFC 9113 §8.3: exactly one :method, :scheme, and
// :path, at most one :authority, nothing else, and none after a regular field.
func requestFrom(fields []field) (*Request, int64, error) {
	req := &Request{Header: map[string][]string{}}
	seen := map[string]bool{}
	regular := false
	for _, f := range fields {
		if f.name == "" {
			return nil, -1, errors.New("empty field name")
		}
		if !validFieldValue(f.value) {
			return nil, -1, fmt.Errorf("field %q has an invalid value", f.name)
		}
		if f.name[0] == ':' {
			if regular {
				return nil, -1, fmt.Errorf("pseudo-header %s after a regular field", f.name)
			}
			if seen[f.name] {
				return nil, -1, fmt.Errorf("duplicate %s", f.name)
			}
			seen[f.name] = true
			switch f.name {
			case ":method":
				req.Method = f.value
			case ":scheme":
				req.Scheme = f.value
			case ":path":
				req.Path = f.value
			case ":authority":
				req.Authority = f.value
			default:
				return nil, -1, fmt.Errorf("unknown pseudo-header %s", f.name)
			}
			continue
		}
		regular = true
		if !validLowerToken(f.name) {
			return nil, -1, fmt.Errorf("field name %q is not lowercase or not an HTTP token", f.name)
		}
		if connectionFields[f.name] {
			return nil, -1, fmt.Errorf("connection-specific field %q", f.name)
		}
		if f.name == "te" && f.value != "trailers" {
			return nil, -1, fmt.Errorf("te: %q", f.value)
		}
		req.Header[f.name] = append(req.Header[f.name], f.value)
	}
	// HTTP/2 permits a peer to split Cookie for compression. Join once, after
	// parsing, so the generic view required by RFC 9113 §8.2.3 does not turn a
	// long split cookie into quadratic allocation and copying.
	if cookies := req.Header["cookie"]; len(cookies) > 1 {
		n := 2 * (len(cookies) - 1)
		for _, cookie := range cookies {
			n += len(cookie)
		}
		joined := make([]byte, 0, n)
		for i, cookie := range cookies {
			if i > 0 {
				joined = append(joined, ';', ' ')
			}
			joined = append(joined, cookie...)
		}
		req.Header["cookie"] = []string{string(joined)}
	}
	for _, want := range []string{":method", ":scheme", ":path"} {
		if !seen[want] {
			return nil, -1, fmt.Errorf("missing %s", want)
		}
	}
	if !validToken(req.Method) {
		return nil, -1, errors.New("empty or invalid :method")
	}
	if req.Method == "CONNECT" {
		return nil, -1, errors.New("CONNECT is not supported")
	}
	if req.Scheme == "" {
		return nil, -1, errors.New("empty :scheme")
	}
	if req.Path == "" {
		return nil, -1, errors.New("empty :path")
	}
	contentLength, err := contentLength(req.Header["content-length"])
	if err != nil {
		return nil, -1, err
	}
	return req, contentLength, nil
}

func validLowerToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return false
		}
		if !tokenByte(c) {
			return false
		}
	}
	return true
}

func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenByte(s[i]) {
			return false
		}
	}
	return true
}

func tokenByte(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

func validFieldValue(s string) bool {
	if len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x7f || c < 0x20 && c != '\t' {
			return false
		}
	}
	return true
}

// contentLength accepts one strict unsigned decimal value. A missing value is
// -1, matching the fact that HTTP/2 DATA has its own stream boundary.
func contentLength(values []string) (int64, error) {
	if len(values) == 0 {
		return -1, nil
	}
	if len(values) != 1 {
		return -1, errors.New("more than one content-length")
	}
	v := values[0]
	if v == "" {
		return -1, errors.New("empty content-length")
	}
	var n int64
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return -1, fmt.Errorf("content-length %q is not unsigned decimal", v)
		}
		d := int64(v[i] - '0')
		if n > (1<<63-1-d)/10 {
			return -1, errors.New("content-length overflows int64")
		}
		n = n*10 + d
	}
	return n, nil
}

func (c *Conn) onData(flags byte, streamID uint32, raw []byte) error {
	if streamID == 0 {
		return errors.New("leanh2: DATA on stream 0")
	}
	content, err := stripPadding(raw, flags)
	if err != nil {
		return err
	}
	c.mu.Lock()
	s := c.streams[streamID]
	if s == nil && (streamID%2 == 0 || streamID > c.lastStreamID) {
		c.mu.Unlock()
		return fmt.Errorf("leanh2: DATA on idle stream %d", streamID)
	}
	if s != nil {
		if s.remoteEnded {
			c.mu.Unlock()
			return fmt.Errorf("leanh2: DATA after END_STREAM on stream %d", streamID)
		}
		next := s.receivedBody + int64(len(content))
		if s.expectedBody >= 0 && next > s.expectedBody {
			c.mu.Unlock()
			return fmt.Errorf("leanh2: stream %d body exceeds content-length %d", streamID, s.expectedBody)
		}
		s.receivedBody = next
		if flags&flagEndStream != 0 {
			if s.expectedBody >= 0 && next != s.expectedBody {
				c.mu.Unlock()
				return fmt.Errorf("leanh2: stream %d ended after %d body bytes, content-length is %d",
					streamID, next, s.expectedBody)
			}
			s.remoteEnded = true
		}
		s.receiving++
	}
	c.mu.Unlock()

	active, discarding, err := c.takeReceive(streamID, s, len(raw))
	if err != nil {
		c.completeReceive(s, err)
		return err
	}
	if !active || discarding {
		// A reset can race with DATA already in flight. The bytes still consumed
		// connection credit, so discard and return exactly that level. Body.Close
		// does the same without replenishing the stream: a compliant peer then
		// stops at its existing window until the response resets the remote half.
		c.completeReceive(s, nil)
		err := c.returnCredit(nil, len(raw), false)
		if flags&flagEndStream != 0 {
			c.recvMu.Lock()
			c.forgetResetLocked(streamID)
			c.recvMu.Unlock()
		}
		return err
	}
	// Credit is returned when the handler consumes, not on arrival: that is what
	// keeps this loop from ever blocking on a handler, and it is why the
	// announced window bounds what one stream may hold. The padding is credited
	// straight away, since no handler will ever read it.
	pad := len(raw) - len(content)
	dropped := 0
	if len(content) > 0 {
		if err := s.body.deliver(content); err != nil {
			if !errors.Is(err, errBodyClosed) {
				c.completeReceive(s, err)
				return err
			}
			// The handler deliberately stopped reading. Discard and credit it; the
			// response finish path will reset the remote half.
			dropped = len(content)
			c.logf("leanh2: stream %d body dropped: %v", s.id, err)
		}
	}
	if flags&flagEndStream != 0 {
		s.body.close(nil)
	}
	c.completeReceive(s, nil)
	if pad > 0 {
		if err := c.returnCredit(s, pad, true); err != nil {
			return err
		}
	}
	if dropped > 0 {
		return c.returnCredit(nil, dropped, false)
	}
	return nil
}

func (c *Conn) completeReceive(s *stream, err error) {
	if s == nil {
		return
	}
	c.mu.Lock()
	if err != nil && c.closeErr == nil {
		c.closeErr = err
	}
	if s.receiving > 0 {
		s.receiving--
	}
	c.connCond.Broadcast()
	c.mu.Unlock()
}

// takeReceive debits the actual flow-controlled payload before it is accepted.
// It returns false when the stream closed concurrently and only connection
// accounting remains.
func (c *Conn) takeReceive(streamID uint32, s *stream, n int) (bool, bool, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if int64(n) > c.recvWin {
		return false, false, errors.New("leanh2: peer exceeded the announced connection receive window")
	}
	active := s != nil && !s.recvClosed
	if !active {
		remaining, recent := c.recentResets[streamID]
		if !recent {
			return false, false, fmt.Errorf("leanh2: DATA on closed stream %d", streamID)
		}
		if int64(n) > remaining {
			return false, false, fmt.Errorf("leanh2: peer exceeded the remaining receive window of reset stream %d", streamID)
		}
		c.recvWin -= int64(n)
		c.recentResets[streamID] = remaining - int64(n)
		return false, true, nil
	}
	if active && int64(n) > s.recvWin {
		return false, false, fmt.Errorf("leanh2: peer exceeded the announced receive window of stream %d", s.id)
	}
	c.recvWin -= int64(n)
	if active {
		s.recvWin -= int64(n)
	}
	return active, active && s.recvDiscarding, nil
}

// returnCredit sends WINDOW_UPDATE for consumed or deliberately discarded
// bytes. The receive lock spans these two tiny writes so DATA cannot observe
// credit before it is actually on the wire. No general stream-state lock is
// held during I/O.
func (c *Conn) returnCredit(s *stream, n int, streamCredit bool) error {
	if n <= 0 {
		return nil
	}
	var inc [4]byte
	binary.BigEndian.PutUint32(inc[:], uint32(n))

	// Wire ownership comes first. That makes a terminal connection state and a
	// WINDOW_UPDATE indivisible to every other writer, while shutdown may still
	// close the transport to release a blocked Write.
	c.wmu.Lock()
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		c.wmu.Unlock()
		return err
	}
	c.recvMu.Lock()
	c.mu.Unlock()
	creditStream := streamCredit && s != nil && !s.recvClosed && !s.recvDiscarding
	if c.recvWin+int64(n) > windowMax || creditStream && s.recvWin+int64(n) > windowMax {
		c.recvMu.Unlock()
		c.wmu.Unlock()
		return errors.New("leanh2: receive-window credit would overflow")
	}
	var err error
	if creditStream {
		err = c.writeFrameLocked(frameWindowUpdate, 0, s.id, inc[:])
	}
	if err == nil {
		err = c.writeFrameLocked(frameWindowUpdate, 0, 0, inc[:])
	}
	if err == nil {
		c.recvWin += int64(n)
		if creditStream {
			s.recvWin += int64(n)
		}
	}
	c.recvMu.Unlock()
	failed := err != nil
	if failed {
		err = c.recordWriteFailure(err)
	}
	c.wmu.Unlock()
	if failed {
		c.endConnection(err)
	}
	return err
}

func (c *Conn) shutdown(err error) {
	c.endConnection(err)
}

// recordWriteFailure runs while wmu is held. Publishing the terminal state
// before releasing wire ownership prevents a queued writer from slipping one
// more frame onto a broken connection.
func (c *Conn) recordWriteFailure(err error) error {
	err = fmt.Errorf("leanh2: writing a frame: %w", err)
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
	}
	first := c.closeErr
	c.connCond.Broadcast()
	c.mu.Unlock()
	return first
}

func (c *Conn) endConnection(err error) {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = err
	}
	streams := make([]*stream, 0, len(c.streams))
	for _, s := range c.streams {
		s.closed = true
		streams = append(streams, s)
	}
	c.streams = map[uint32]*stream{}
	c.pendingHeaders = 0
	c.ready = false
	c.connCond.Broadcast()
	c.mu.Unlock()
	// Close before waiting for receive accounting: a WINDOW_UPDATE writer may
	// be blocked in the transport while holding recvMu. Closing is what releases
	// it, allowing Serve and every Body reader to finish deterministically.
	c.transportClose.Do(func() {
		_ = c.rw.Close()
	})
	c.recvMu.Lock()
	for _, s := range streams {
		s.recvClosed = true
	}
	c.recvMu.Unlock()
	for _, s := range streams {
		s.body.discard(err)
	}
}

func (c *Conn) connectionError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// detachStream removes the live wire state. The caller holds wmu, which makes
// this removal a barrier: every later stream writer observes closed before it
// can emit a frame.
func (c *Conn) detachStream(s *stream, err error, rememberReset bool) int {
	c.mu.Lock()
	if c.streams[s.id] == s {
		delete(c.streams, s.id)
	}
	s.closed = true
	c.connCond.Broadcast()
	c.mu.Unlock()
	c.recvMu.Lock()
	s.recvClosed = true
	if rememberReset {
		c.rememberResetLocked(s.id, s.recvWin)
	}
	c.recvMu.Unlock()
	return s.body.discard(err)
}

func (c *Conn) rememberResetLocked(id uint32, remaining int64) {
	if _, exists := c.recentResets[id]; exists {
		c.recentResets[id] = remaining
		return
	}
	if len(c.resetOrder) == maxConcurrentStreams {
		delete(c.recentResets, c.resetOrder[0])
		copy(c.resetOrder, c.resetOrder[1:])
		c.resetOrder = c.resetOrder[:len(c.resetOrder)-1]
	}
	c.recentResets[id] = remaining
	c.resetOrder = append(c.resetOrder, id)
}

func (c *Conn) forgetResetLocked(id uint32) {
	if _, ok := c.recentResets[id]; !ok {
		return
	}
	delete(c.recentResets, id)
	for i, got := range c.resetOrder {
		if got == id {
			copy(c.resetOrder[i:], c.resetOrder[i+1:])
			c.resetOrder = c.resetOrder[:len(c.resetOrder)-1]
			return
		}
	}
}

func (c *Conn) onReset(streamID uint32) error {
	c.wmu.Lock()
	c.mu.Lock()
	s := c.streams[streamID]
	if s == nil && (streamID%2 == 0 || streamID > c.lastStreamID) {
		c.mu.Unlock()
		c.wmu.Unlock()
		return fmt.Errorf("leanh2: RST_STREAM on idle stream %d", streamID)
	}
	for s != nil && s.receiving > 0 && c.streams[streamID] == s {
		c.connCond.Wait()
	}
	if s != nil && c.streams[streamID] != s {
		s = nil
	}
	c.mu.Unlock()
	if s == nil {
		c.recvMu.Lock()
		c.forgetResetLocked(streamID)
		c.recvMu.Unlock()
		c.wmu.Unlock()
		return nil // a reset for a stream already closed can race on the wire
	}
	n := c.detachStream(s, errors.New("leanh2: the peer reset this stream"), false)
	c.wmu.Unlock()
	return c.returnCredit(nil, n, false)
}

// GoAway announces that this side is stopping. It reports the highest stream it
// accepted and may still finish, then accepts no new stream. Reporting less
// could make the peer retry work that can still have side effects here.
func (c *Conn) GoAway(code uint32, reason string) error {
	if max := ourMaxFrame - 8; len(reason) > max {
		return fmt.Errorf("leanh2: GOAWAY reason is %d bytes, maximum is %d", len(reason), max)
	}
	c.mu.Lock()
	if !c.ready {
		err := c.closeErr
		if err == nil {
			err = errors.New("leanh2: Serve has not completed the HTTP/2 startup")
		}
		c.mu.Unlock()
		return err
	}
	if c.goingAway {
		c.mu.Unlock()
		return nil
	}
	c.goingAway = true
	last := c.lastStreamID
	c.mu.Unlock()
	body := make([]byte, 8, 8+len(reason))
	binary.BigEndian.PutUint32(body[0:], last&0x7fffffff)
	binary.BigEndian.PutUint32(body[4:], code)
	body = append(body, reason...)
	return c.writeFrame(frameGoAway, 0, 0, body)
}

// body is the request body: a bounded buffer filled by the frame loop and
// drained by the handler, where draining returns flow-control credit.
//
// It is not an io.Pipe on purpose. A pipe hands off synchronously, so the frame
// loop would block until the handler read — and then one slow handler stops
// PING, SETTINGS, and every other stream on the connection. The peer can never
// overrun this buffer, because its window is exactly the buffer's size and
// credit follows consumption.
type body struct {
	s   *stream
	mu  sync.Mutex
	c   *sync.Cond
	buf []byte
	err error // set once: io.EOF for a clean end, or the reason
}

var errBodyClosed = errors.New("leanh2: body closed by the handler")

func newBody(s *stream) *body {
	b := &body{s: s}
	b.c = sync.NewCond(&b.mu)
	return b
}

// deliver appends what the frame loop received. It never blocks.
func (b *body) deliver(p []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return fmt.Errorf("%w: %v", errBodyClosed, b.err)
	}
	if len(b.buf)+len(p) > ourInitialWindow {
		// Only reachable if the peer ignored its window, so it is the peer's
		// mistake and not back pressure to absorb.
		return errors.New("leanh2: peer exceeded the announced stream window")
	}
	b.buf = append(b.buf, p...)
	b.c.Broadcast()
	return nil
}

func (b *body) close(err error) {
	if err == nil {
		err = io.EOF
	}
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.c.Broadcast()
	b.mu.Unlock()
}

// discard atomically releases buffered bytes and wakes a blocked reader. Its
// return value is connection credit that the caller must return exactly once.
func (b *body) discard(err error) int {
	if err == nil {
		err = errBodyClosed
	}
	b.mu.Lock()
	n := len(b.buf)
	b.buf = nil
	if b.err == nil || b.err == io.EOF && n > 0 {
		b.err = err
	}
	b.c.Broadcast()
	b.mu.Unlock()
	return n
}

func (b *body) Read(p []byte) (int, error) {
	b.mu.Lock()
	for len(b.buf) == 0 && b.err == nil {
		b.c.Wait()
	}
	if len(b.buf) == 0 {
		err := b.err
		b.mu.Unlock()
		return 0, err
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	b.mu.Unlock()
	// Credit for what the handler took, so the peer may send that much more.
	if err := b.s.c.returnCredit(b.s, n, true); err != nil {
		return n, err
	}
	return n, nil
}

// Close stops the handler's interest in the body. Buffered bytes are discarded
// and credited; [Response.finish] tells the peer to stop sending the rest.
func (b *body) Close() error {
	b.s.c.recvMu.Lock()
	if !b.s.recvClosed {
		b.s.recvDiscarding = true
	}
	b.s.c.recvMu.Unlock()
	n := b.discard(errBodyClosed)
	return b.s.c.returnCredit(nil, n, false)
}

// cleanEOF reports only a real peer END_STREAM after all bytes were consumed.
// Handler Close and reset are deliberately different states.
func (b *body) cleanEOF() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err == io.EOF && len(b.buf) == 0
}

// Response is the answering half of one stream. Writing may start while the
// request body is still arriving: a bidirectional stream stays open as long as
// the connection does.
type Response struct {
	s           *stream
	mu          sync.Mutex
	sent        bool
	done        bool
	bodyAllowed bool
	failed      error
}

// WriteHeader sends the status and headers. Once per stream.
func (r *Response) WriteHeader(status int, header map[string][]string) error {
	fields, bodyAllowed, err := r.responseFields(status, header)
	if err != nil {
		r.mu.Lock()
		if r.failed == nil {
			r.failed = err
		}
		r.mu.Unlock()
		return err
	}
	r.s.c.mu.Lock()
	closed := r.s.closed || r.s.c.streams[r.s.id] != r.s
	r.s.c.mu.Unlock()
	if closed {
		return errors.New("leanh2: stream closed")
	}
	r.mu.Lock()
	if r.failed != nil {
		err := r.failed
		r.mu.Unlock()
		return err
	}
	if r.sent || r.done {
		r.mu.Unlock()
		return errors.New("leanh2: headers already sent")
	}
	r.sent = true
	r.bodyAllowed = bodyAllowed
	r.mu.Unlock()
	if err := r.s.c.writeStreamHeaderBlock(r.s, encodeFields(nil, fields), false); err != nil {
		r.mu.Lock()
		if r.failed == nil {
			r.failed = err
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *Response) responseFields(status int, header map[string][]string) ([]field, bool, error) {
	if status < 200 || status > 599 {
		return nil, false, fmt.Errorf("leanh2: response status %d is outside 200..599", status)
	}
	r.s.c.mu.Lock()
	method := r.s.method
	r.s.c.mu.Unlock()
	bodyAllowed := method != "HEAD" && status != 204 && status != 205 && status != 304
	fields := []field{{name: ":status", value: itoa(status)}}
	total := len(":status") + 3 + 32
	for name, values := range header {
		name = lower(name)
		if !validLowerToken(name) {
			return nil, false, fmt.Errorf("leanh2: response field name %q is invalid", name)
		}
		if connectionFields[name] || name == "te" || name == "trailer" {
			return nil, false, fmt.Errorf("leanh2: response field %q is not permitted", name)
		}
		// DATA/END_STREAM already supplies exact response framing, and the only
		// measured consumer deliberately strips origin Content-Length. Rejecting it
		// removes a second length state that could disagree with the stream.
		if name == "content-length" {
			return nil, false, errors.New("leanh2: response content-length is not supported")
		}
		for _, v := range values {
			if !validFieldValue(v) {
				return nil, false, fmt.Errorf("leanh2: response field %q has an invalid value", name)
			}
			total += len(name) + len(v) + 32
			if total > ourMaxHeaderList {
				return nil, false, fmt.Errorf("leanh2: response header list above the %d byte limit", ourMaxHeaderList)
			}
			fields = append(fields, field{name: name, value: v})
		}
	}
	return fields, bodyAllowed, nil
}

// Write sends body bytes as DATA frames and respects both windows. It blocks
// when the peer grants no room, which is the point: that back pressure is what
// carries a large response through a narrow uplink without buffering here.
func (r *Response) Write(p []byte) (int, error) {
	if err := r.ensureHeader(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	allowed, done := r.bodyAllowed, r.done
	r.mu.Unlock()
	if done {
		return 0, errors.New("leanh2: response finished")
	}
	if len(p) > 0 && !allowed {
		return 0, errors.New("leanh2: this response status or method has no body")
	}
	written := 0
	for len(p) > 0 {
		n, err := r.s.reserve(len(p))
		if err != nil {
			return written, err
		}
		retry, err := r.s.c.writeStreamData(r.s, p[:n], int64(n))
		if err != nil {
			return written, err
		}
		if retry {
			continue
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// writeStreamData turns a send-window reservation into one DATA frame. wmu is
// also the RST barrier: if peer cancellation won it first, no frame follows the
// reset and both reserved windows are refunded.
func (c *Conn) writeStreamData(s *stream, p []byte, reserved int64) (bool, error) {
	c.wmu.Lock()
	c.mu.Lock()
	if c.closeErr != nil || s.closed || c.streams[s.id] != s {
		err := c.closeErr
		if err == nil {
			err = errors.New("leanh2: stream closed")
		}
		c.connWin += reserved
		s.win += reserved
		c.connCond.Broadcast()
		c.mu.Unlock()
		c.wmu.Unlock()
		return false, err
	}
	// A peer can lower INITIAL_WINDOW_SIZE after reserve. If that made the
	// unreserved remainder negative, this claim may no longer follow the
	// SETTINGS ACK. Put it back and let reserve wait under the new window.
	if s.win < 0 {
		c.connWin += reserved
		s.win += reserved
		c.connCond.Broadcast()
		c.mu.Unlock()
		c.wmu.Unlock()
		return true, nil
	}
	c.mu.Unlock()
	err := c.writeFrameLocked(frameData, 0, s.id, p)
	failed := err != nil
	if failed {
		err = c.recordWriteFailure(err)
	}
	c.wmu.Unlock()
	if failed {
		c.endConnection(err)
	}
	return false, err
}

func (r *Response) ensureHeader() error {
	r.mu.Lock()
	sent := r.sent
	r.mu.Unlock()
	if sent {
		return nil
	}
	return r.WriteHeader(200, nil)
}

// reserve waits until both windows have room and claims the same amount from
// each. Claiming from the stream first and shrinking afterwards would lose the
// difference permanently, and that loss stalls a stream that is entirely valid.
func (s *stream) reserve(want int) (int, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	for {
		if s.c.closeErr != nil {
			return 0, s.c.closeErr
		}
		if s.closed || s.c.streams[s.id] != s {
			return 0, errors.New("leanh2: stream closed")
		}
		if s.c.connWin > 0 && s.win > 0 {
			n := int64(want)
			if max := int64(ourMaxFrame); n > max {
				n = max
			}
			if n > s.c.connWin {
				n = s.c.connWin
			}
			if n > s.win {
				n = s.win
			}
			s.c.connWin -= n
			s.win -= n
			return int(n), nil
		}
		s.c.connCond.Wait()
	}
}

// finish closes the stream cleanly. A request body the handler never read is
// cancelled rather than left half open: the peer must learn it can stop.
func (r *Response) finish() {
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		return
	}
	sent := r.sent
	failed := r.failed
	r.mu.Unlock()
	if failed != nil {
		r.fail(codeInternalError)
		return
	}
	if !sent {
		if err := r.WriteHeader(200, nil); err != nil {
			r.fail(codeInternalError)
			return
		}
	}
	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
	clean := r.s.body.cleanEOF()
	c := r.s.c
	c.wmu.Lock()
	c.mu.Lock()
	for r.s.receiving > 0 && c.streams[r.s.id] == r.s && c.closeErr == nil {
		c.connCond.Wait()
	}
	if c.closeErr != nil || r.s.closed || c.streams[r.s.id] != r.s {
		c.mu.Unlock()
		c.wmu.Unlock()
		return
	}
	remoteEnded := r.s.remoteEnded
	c.mu.Unlock()

	err := c.writeFrameLocked(frameData, flagEndStream, r.s.id, nil)
	needReset := !clean && !remoteEnded
	if err == nil && needReset {
		var code [4]byte
		binary.BigEndian.PutUint32(code[:], codeNoError)
		err = c.writeFrameLocked(frameRSTStream, 0, r.s.id, code[:])
	}
	if err != nil {
		err = c.recordWriteFailure(err)
		c.wmu.Unlock()
		c.endConnection(err)
		return
	}
	n := c.detachStream(r.s, errors.New("leanh2: stream finished"), needReset)
	c.wmu.Unlock()
	if n > 0 {
		_ = c.returnCredit(nil, n, false)
	}
}

// fail resets the stream with a code, for a handler that could not finish.
func (r *Response) fail(code uint32) {
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		return
	}
	r.done = true
	r.mu.Unlock()
	c := r.s.c
	c.wmu.Lock()
	c.mu.Lock()
	for r.s.receiving > 0 && c.streams[r.s.id] == r.s && c.closeErr == nil {
		c.connCond.Wait()
	}
	if c.closeErr != nil || r.s.closed || c.streams[r.s.id] != r.s {
		c.mu.Unlock()
		c.wmu.Unlock()
		return
	}
	rememberReset := !r.s.remoteEnded
	c.mu.Unlock()
	var body [4]byte
	binary.BigEndian.PutUint32(body[:], code)
	err := c.writeFrameLocked(frameRSTStream, 0, r.s.id, body[:])
	if err != nil {
		err = c.recordWriteFailure(err)
		c.wmu.Unlock()
		c.endConnection(err)
		return
	}
	n := c.detachStream(r.s, errors.New("leanh2: stream reset"), rememberReset)
	c.wmu.Unlock()
	if n > 0 {
		_ = c.returnCredit(nil, n, false)
	}
}

// itoa and lower keep strconv and strings out of the image for two operations.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func lower(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
