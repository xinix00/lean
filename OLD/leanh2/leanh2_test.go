package leanh2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// peer is the other side of a connection, driving frames by hand. Tests speak
// the wire, not this package's internals: that is the only way a framing test
// can catch a framing mistake.
type peer struct {
	t    *testing.T
	conn net.Conn
}

// newPeer pairs the connection with a loopback socket and not net.Pipe: a pipe
// is unbuffered, so both sides block on their own write until the other reads,
// and every test that sends two frames before reading would deadlock on the
// answer in between. A socket has the kernel buffer that a real peer has.
func newPeer(t *testing.T, handler Handler) (*peer, *Conn, chan error) {
	return newPeerWithSettings(t, handler, true)
}

// newPeerWithSettings leaves the mandatory first SETTINGS frame out only for
// tests that prove the server rejects that exact omission.
func newPeerWithSettings(t *testing.T, handler Handler, sendSettings bool) (*peer, *Conn, chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	type accepted struct {
		conn net.Conn
		err  error
	}
	incoming := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		incoming <- accepted{c, err}
	}()
	theirs, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	got := <-incoming
	if got.err != nil {
		t.Fatal(got.err)
	}
	t.Cleanup(func() { got.conn.Close(); theirs.Close() })

	c := NewConn(got.conn, handler, func(string, ...any) {})
	done := make(chan error, 1)
	go func() { done <- c.Serve() }()
	p := &peer{t: t, conn: theirs}
	p.write([]byte(clientPreface))
	if sendSettings {
		p.frame(frameSettings, 0, 0, nil)
	}
	return p, c, done
}

func (p *peer) write(b []byte) {
	p.t.Helper()
	if err := p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.conn.Write(b); err != nil {
		p.t.Fatalf("write: %v", err)
	}
}

func (p *peer) frame(typ, flags byte, stream uint32, body []byte) {
	p.t.Helper()
	head := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(head[5:], stream)
	p.write(append(head, body...))
}

// read returns the next frame the connection wrote.
func (p *peer) read() (typ, flags byte, stream uint32, body []byte) {
	p.t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		p.t.Fatal(err)
	}
	head := make([]byte, 9)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		p.t.Fatalf("read frame header: %v", err)
	}
	length := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
	body = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(p.conn, body); err != nil {
			p.t.Fatalf("read frame body: %v", err)
		}
	}
	return head[3], head[4], binary.BigEndian.Uint32(head[5:]) & 0x7fffffff, body
}

// readQuiet is read for a goroutine: it reports the end of the connection as
// type 0xff instead of failing the test from a non-test goroutine.
func (p *peer) readQuiet() (typ, flags byte, stream uint32, body []byte) {
	_ = p.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	head := make([]byte, 9)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		return 0xff, 0, 0, nil
	}
	length := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
	body = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(p.conn, body); err != nil {
			return 0xff, 0, 0, nil
		}
	}
	return head[3], head[4], binary.BigEndian.Uint32(head[5:]) & 0x7fffffff, body
}

// readUntil skips frames until one of type typ arrives, so a test does not
// break when settings or window updates are interleaved.
func (p *peer) readUntil(typ byte) (flags byte, stream uint32, body []byte) {
	p.t.Helper()
	for i := 0; i < 20; i++ {
		gotType, gotFlags, gotStream, gotBody := p.read()
		if gotType == typ {
			return gotFlags, gotStream, gotBody
		}
	}
	p.t.Fatalf("no frame of type 0x%02x within twenty frames", typ)
	return 0, 0, nil
}

// headers encodes a minimal GET request block for the given path.
func headerBlock(path string) []byte {
	return encodeFields(nil, []field{
		{":method", "GET"}, {":scheme", "https"}, {":path", path}, {":authority", "example.test"},
	})
}

// The settings exchange, both directions, plus the ACK. Everything else in this
// file assumes it works.
func TestSettingsHandshake(t *testing.T) {
	p, _, done := newPeer(t, func(*Request, *Response) {})
	defer p.conn.Close()

	typ, flags, stream, body := p.read()
	if typ != frameSettings || flags != 0 || stream != 0 {
		t.Fatalf("first frame = type 0x%02x flags 0x%02x stream %d, want SETTINGS", typ, flags, stream)
	}
	if len(body) != 6*6 {
		t.Fatalf("SETTINGS body is %d bytes, want exactly six entries", len(body))
	}
	// The zero header table size is a documented choice; a change here changes
	// what the decoder must handle.
	seen := map[uint16]uint32{}
	for o := 0; o+6 <= len(body); o += 6 {
		id := binary.BigEndian.Uint16(body[o:])
		if _, duplicate := seen[id]; duplicate {
			t.Errorf("setting 0x%x appears more than once", id)
		}
		seen[id] = binary.BigEndian.Uint32(body[o+2:])
	}
	for id, want := range map[uint16]uint32{
		settingHeaderTableSize:   ourHeaderTableSize,
		settingEnablePush:        0,
		settingMaxConcurrent:     maxConcurrentStreams,
		settingInitialWindowSize: ourInitialWindow,
		settingMaxFrameSize:      ourMaxFrame,
		settingMaxHeaderListSize: ourMaxHeaderList,
	} {
		if got, ok := seen[id]; !ok || got != want {
			t.Errorf("setting 0x%x = %d (present %v), want %d", id, got, ok, want)
		}
	}

	// newPeer already sent the mandatory initial client SETTINGS. Its ACK is the
	// second SETTINGS frame from the server.
	flags, _, _ = p.readUntil(frameSettings)
	if flags&flagACK == 0 {
		t.Error("peer SETTINGS was not acknowledged")
	}
	p.conn.Close()
	<-done
}

// A PING must be answered with its payload. Some peers open no stream until
// they see the ACK, so this is not a nicety.
func TestPingIsAnswered(t *testing.T) {
	p, _, done := newPeer(t, func(*Request, *Response) {})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	p.frame(framePing, 0, 0, payload)
	flags, _, body := p.readUntil(framePing)
	if flags&flagACK == 0 {
		t.Error("PING answer without the ACK flag")
	}
	if !bytes.Equal(body, payload) {
		t.Errorf("PING answer carried %v, want %v", body, payload)
	}
	p.conn.Close()
	<-done
}

// PRIORITY is deprecated in RFC 9113. Its two syntactically valid wire forms
// remain harmless input, but they allocate no state and affect no scheduling.
func TestPriorityIsAcceptedAndIgnored(t *testing.T) {
	reached := make(chan struct{}, 1)
	p, _, done := newPeer(t, func(_ *Request, res *Response) {
		reached <- struct{}{}
		_ = res.WriteHeader(204, nil)
	})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	priority := []byte{0, 0, 0, 0, 15}
	p.frame(framePriority, 0, 1, priority)
	block := append(append([]byte(nil), priority...), headerBlock("/priority")...)
	p.frame(frameHeaders, flagPriority|flagEndHeaders|flagEndStream, 1, block)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("valid PRIORITY input prevented request delivery")
	}
	p.conn.Close()
	<-done
}

// A request without a body reaches the handler with the pseudo-headers split
// out, and its answer comes back as HEADERS plus DATA plus END_STREAM.
func TestRequestAndResponse(t *testing.T) {
	var got *Request
	var wg sync.WaitGroup
	wg.Add(1)
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		got = req
		if _, err := io.ReadAll(req.Body); err != nil {
			t.Errorf("request body: %v", err)
		}
		res.WriteHeader(200, map[string][]string{"content-type": {"text/plain"}})
		res.Write([]byte("hallo"))
		wg.Done()
	})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/pad?q=1"))
	wg.Wait()

	if got.Method != "GET" || got.Path != "/pad?q=1" || got.Authority != "example.test" {
		t.Errorf("request = %+v", got)
	}
	if got.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", got.StreamID)
	}
	if _, ok := got.Header[":method"]; ok {
		t.Error("pseudo-header leaked into Header")
	}

	flags, stream, block := p.readUntil(frameHeaders)
	if flags&flagEndHeaders == 0 || stream != 1 {
		t.Errorf("response HEADERS flags 0x%02x stream %d", flags, stream)
	}
	fields, err := newDecoder(4096, 0).decode(block)
	if err != nil {
		t.Fatalf("response headers do not decode: %v", err)
	}
	if fields[0].name != ":status" || fields[0].value != "200" {
		t.Errorf("first field = %v, want :status 200", fields[0])
	}

	_, _, data := p.readUntil(frameData)
	if string(data) != "hallo" {
		t.Errorf("DATA = %q", data)
	}
	end, _, _ := p.readUntil(frameData)
	if end&flagEndStream == 0 {
		t.Error("stream did not end with END_STREAM")
	}
	p.conn.Close()
	<-done
}

// A request body arrives through Body, and every DATA frame must be answered
// with WINDOW_UPDATE on both the stream and the connection — without that the
// peer stalls once the initial window is spent.
func TestRequestBodyReturnsWindow(t *testing.T) {
	bodies := make(chan string, 1)
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		b, _ := io.ReadAll(req.Body)
		bodies <- string(b)
		res.WriteHeader(204, nil)
	})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/upload"))
	p.frame(frameData, 0, 1, []byte("twaalf bytes"))
	p.frame(frameData, flagEndStream, 1, nil)

	if b := <-bodies; b != "twaalf bytes" {
		t.Errorf("body = %q", b)
	}
	// Credit follows consumption, so twelve bytes come back on the stream and on
	// the connection. The connection also gets one large bump at startup; that
	// one is not this measurement.
	var onStream, onConn bool
	for i := 0; i < 8 && !(onStream && onConn); i++ {
		typ, _, stream, body := p.read()
		if typ != frameWindowUpdate {
			continue
		}
		inc := binary.BigEndian.Uint32(body)
		if inc == connectionWindowIncrement {
			continue
		}
		if inc != 12 {
			t.Errorf("WINDOW_UPDATE of %d, want 12", inc)
		}
		if stream == 0 {
			onConn = true
		} else {
			onStream = true
		}
	}
	if !onStream || !onConn {
		t.Errorf("window returned on stream=%v conn=%v, want both", onStream, onConn)
	}
	p.conn.Close()
	<-done
}

// Flow control is the part where a mistake shows up only under load: a writer
// must block when the window is spent and continue on WINDOW_UPDATE, and it may
// never write a frame larger than the peer's maximum.
func TestWriteRespectsWindowAndFrameSize(t *testing.T) {
	const payload = 40000 // more than one 16 KB frame, more than the window below
	const window = 10000
	written := make(chan error, 1)
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		res.WriteHeader(200, nil)
		_, err := res.Write(bytes.Repeat([]byte("x"), payload))
		written <- err
	})
	p.readUntil(frameSettings)

	// Announce a small stream window and the RFC minimum frame size.
	var settings []byte
	settings = binary.BigEndian.AppendUint16(settings, settingInitialWindowSize)
	settings = binary.BigEndian.AppendUint32(settings, window)
	settings = binary.BigEndian.AppendUint16(settings, settingMaxFrameSize)
	settings = binary.BigEndian.AppendUint32(settings, 16384)
	p.frame(frameSettings, 0, 0, settings)
	p.readUntil(frameSettings) // the ACK

	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/blob"))
	p.readUntil(frameHeaders)

	// One reader owns the socket; the test only counts what it reports. Sharing
	// a counter with the test goroutine would be a race, not a measurement.
	sizes := make(chan int, 64)
	oversized := make(chan int, 1)
	go func() {
		for {
			typ, _, _, body := p.readQuiet()
			if typ == 0xff {
				close(sizes)
				return
			}
			if typ != frameData {
				continue
			}
			if len(body) > 16384 {
				select {
				case oversized <- len(body):
				default:
				}
			}
			sizes <- len(body)
		}
	}()

	got := 0
	for got < window {
		select {
		case n, ok := <-sizes:
			if !ok {
				t.Fatalf("connection ended after %d of %d bytes", got, payload)
			}
			got += n
		case <-time.After(5 * time.Second):
			t.Fatalf("stalled at %d of %d bytes inside the window", got, payload)
		}
	}
	if got > window {
		t.Fatalf("wrote %d bytes into a window of %d", got, window)
	}
	select {
	case n := <-oversized:
		t.Fatalf("DATA frame of %d bytes above the announced 16384", n)
	default:
	}
	// The window is spent: nothing more may arrive, and Write must still be in
	// progress.
	select {
	case n := <-sizes:
		t.Fatalf("%d more bytes arrived past the window", n)
	case err := <-written:
		t.Fatalf("Write returned early with %v after %d of %d bytes", err, got, payload)
	case <-time.After(150 * time.Millisecond):
	}

	// Grant the rest on both levels; the write must then complete.
	var inc [4]byte
	binary.BigEndian.PutUint32(inc[:], payload)
	p.frame(frameWindowUpdate, 0, 1, inc[:])
	p.frame(frameWindowUpdate, 0, 0, inc[:])

	deadline := time.After(5 * time.Second)
	for got < payload {
		select {
		case n, ok := <-sizes:
			if !ok {
				t.Fatalf("connection ended after %d of %d bytes", got, payload)
			}
			got += n
		case <-deadline:
			t.Fatalf("stalled at %d of %d bytes after WINDOW_UPDATE", got, payload)
		}
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not return after all bytes arrived")
	}
	select {
	case n := <-oversized:
		t.Fatalf("DATA frame of %d bytes above the announced 16384", n)
	default:
	}
	p.conn.Close()
	<-done
}

// A header block split over CONTINUATION is one block: the handler must see the
// whole request, not the first frame's worth.
func TestContinuationJoinsTheBlock(t *testing.T) {
	paths := make(chan string, 1)
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		paths <- req.Path
		res.WriteHeader(204, nil)
	})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	block := headerBlock("/gesplitst")
	cut := len(block) / 2
	p.frame(frameHeaders, 0, 1, block[:cut])
	p.frame(frameContinuation, flagEndHeaders, 1, block[cut:])
	if got := <-paths; got != "/gesplitst" {
		t.Errorf("path = %q, want /gesplitst", got)
	}
	p.conn.Close()
	<-done
}

// A handler that panics kills its own stream and nothing else: the connection
// stays up and the next request is served.
func TestPanicKillsOnlyItsStream(t *testing.T) {
	second := make(chan string, 1)
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		if req.Path == "/klap" {
			panic("opzettelijk")
		}
		second <- req.Path
		res.WriteHeader(200, nil)
	})
	defer p.conn.Close()
	p.readUntil(frameSettings)

	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/klap"))
	if _, stream, _ := p.readUntil(frameRSTStream); stream != 1 {
		t.Errorf("RST_STREAM on stream %d, want 1", stream)
	}
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/verder"))
	select {
	case got := <-second:
		if got != "/verder" {
			t.Errorf("second request = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not survive the panic")
	}
	p.conn.Close()
	<-done
}

// The refusals. Each of these is a peer mistake that must end the connection
// with a named error instead of being absorbed.
func TestRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(*peer)
		want string
	}{
		{"frame above our maximum", func(p *peer) {
			head := []byte{0, 0x80, 0x01, frameData, 0, 0, 0, 0, 1} // 32769 bytes
			p.write(head)
		}, "above the announced"},
		{"WINDOW_UPDATE of zero", func(p *peer) {
			p.frame(frameWindowUpdate, 0, 0, []byte{0, 0, 0, 0})
		}, "WINDOW_UPDATE of zero"},
		{"HEADERS on stream 0", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders, 0, headerBlock("/"))
		}, "HEADERS on stream 0"},
		{"malformed padded DATA", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/"))
			p.frame(frameData, flagPadded, 1, []byte{0xff, 1, 2})
		}, "padding beyond the frame"},
		{"undecodable header block", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders, 1, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
		}, "header block on stream"},
		{"GOAWAY", func(p *peer) {
			body := make([]byte, 8)
			p.frame(frameGoAway, 0, 0, append(body, "genoeg"...))
		}, "GOAWAY"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, done := newPeer(t, func(req *Request, res *Response) {
				io.Copy(io.Discard, req.Body)
			})
			defer p.conn.Close()
			p.readUntil(frameSettings)
			c.send(p)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("connection ended without an error")
				}
				if !contains(err.Error(), c.want) {
					t.Errorf("error = %q, want it to mention %q", err, c.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("connection stayed up")
			}
		})
	}
}

// A wrong preface is refused before anything else happens.
func TestWrongPreface(t *testing.T) {
	ours, theirs := net.Pipe()
	c := NewConn(ours, func(*Request, *Response) {}, nil)
	done := make(chan error, 1)
	go func() { done <- c.Serve() }()
	// In a goroutine: the pipe is unbuffered and Serve stops reading after the
	// 24 preface bytes, so a blocking write here would hang the test instead of
	// showing the refusal.
	go theirs.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	select {
	case err := <-done:
		if err == nil || !contains(err.Error(), "client preface") {
			t.Errorf("error = %v, want it to mention the preface", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no error on a wrong preface")
	}
	theirs.Close()
}

// GoAway announces the shutdown once, so a second call is not a second frame.
func TestGoAwayOnlyOnce(t *testing.T) {
	p, c, done := newPeer(t, func(*Request, *Response) {})
	defer p.conn.Close()
	p.readUntil(frameSettings)
	// newPeer sent the mandatory client SETTINGS; drain its acknowledgement so
	// the final direct read below measures only the second GoAway call.
	p.readUntil(frameSettings)

	if err := c.GoAway(0, "stoppen"); err != nil {
		t.Fatal(err)
	}
	_, _, body := p.readUntil(frameGoAway)
	if !bytes.Contains(body, []byte("stoppen")) {
		t.Errorf("GOAWAY body = %q", body)
	}
	if err := c.GoAway(0, "nogmaals"); err != nil {
		t.Fatalf("second GoAway: %v", err)
	}
	// Nothing more may follow; a PING proves the connection is still ours.
	p.frame(framePing, 0, 0, []byte{9, 9, 9, 9, 9, 9, 9, 9})
	if typ, _, _, _ := p.read(); typ != framePing {
		t.Errorf("frame after the second GoAway = type 0x%02x, want PING", typ)
	}
	p.conn.Close()
	<-done
}

func contains(s, sub string) bool {
	return len(sub) == 0 || bytes.Contains([]byte(s), []byte(sub))
}

// The stream-identifier discipline: client-initiated, odd, strictly increasing.
// Without it a peer can reuse an identifier and overwrite a live stream.
func TestStreamIdentifierDiscipline(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(*peer)
		want string
	}{
		{"even identifier", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 2, headerBlock("/"))
		}, "not client-initiated"},
		{"reused identifier", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/"))
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/"))
		}, "not above the last accepted"},
		{"lower identifier", func(p *peer) {
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 5, headerBlock("/"))
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/"))
		}, "not above the last accepted"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, done := newPeer(t, func(req *Request, res *Response) { res.WriteHeader(204, nil) })
			p.readUntil(frameSettings)
			c.send(p)
			assertConnectionError(t, done, c.want)
		})
	}
}

// A header block is indivisible in both directions. Inbound: nothing may arrive
// between HEADERS and its CONTINUATION. RFC 9113 §6.2 makes this a connection
// error, not a stream error.
func TestHeaderBlockIsIndivisibleInbound(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(*peer)
		want string
	}{
		{"another frame inside the block", func(p *peer) {
			block := headerBlock("/half")
			p.frame(frameHeaders, 0, 1, block[:len(block)/2])
			p.frame(framePing, 0, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}, "interrupted the header block"},
		{"CONTINUATION on another stream", func(p *peer) {
			block := headerBlock("/half")
			p.frame(frameHeaders, 0, 1, block[:len(block)/2])
			p.frame(frameContinuation, flagEndHeaders, 3, block[len(block)/2:])
		}, "interrupted the header block"},
		{"CONTINUATION without a block", func(p *peer) {
			p.frame(frameContinuation, flagEndHeaders, 1, headerBlock("/"))
		}, "without an open header block"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, done := newPeer(t, func(req *Request, res *Response) { res.WriteHeader(204, nil) })
			p.readUntil(frameSettings)
			c.send(p)
			assertConnectionError(t, done, c.want)
		})
	}
}

// Outbound: two streams answering at once may not interleave their header
// blocks. The block is larger than the peer's frame maximum, so each response
// spans HEADERS plus CONTINUATION and an interleave would be visible.
func TestHeaderBlockIsIndivisibleOutbound(t *testing.T) {
	// A header value large enough to force CONTINUATION at the 16 KB floor.
	big := make([]byte, 20000)
	for i := range big {
		big[i] = 'a'
	}
	release := make(chan struct{})
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		<-release // both handlers write at the same moment
		res.WriteHeader(200, map[string][]string{"x-big": {string(big)}})
	})
	p.readUntil(frameSettings)

	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/een"))
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/twee"))
	close(release)

	// Read frames and check that between a HEADERS and its END_HEADERS nothing
	// for another stream appears.
	open := uint32(0)
	blocks := 0
	for blocks < 2 {
		typ, flags, stream, _ := p.read()
		switch typ {
		case frameHeaders:
			if open != 0 {
				t.Fatalf("HEADERS for stream %d while the block of %d was open", stream, open)
			}
			if flags&flagEndHeaders == 0 {
				open = stream
			} else {
				blocks++
			}
		case frameContinuation:
			if stream != open {
				t.Fatalf("CONTINUATION for stream %d while the block of %d was open", stream, open)
			}
			if flags&flagEndHeaders != 0 {
				open = 0
				blocks++
			}
		default:
			if open != 0 {
				t.Fatalf("frame type 0x%02x arrived inside the header block of stream %d", typ, open)
			}
		}
	}
	p.conn.Close()
	<-done
}

// More concurrent streams than announced is refused: the cap is what bounds the
// goroutines, buffers and map entries one peer can claim.
func TestConcurrentStreamCap(t *testing.T) {
	hold := make(chan struct{})
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		<-hold
		res.WriteHeader(204, nil)
	})
	p.readUntil(frameSettings)
	for i := 0; i <= maxConcurrentStreams; i++ {
		p.frame(frameHeaders, flagEndHeaders|flagEndStream, uint32(1+2*i), headerBlock("/vast"))
	}
	assertConnectionError(t, done, "more than the announced")
	close(hold)
}

// GOAWAY must name the highest stream that was accepted and may still finish.
// Zero would invite a retry of work that can still have side effects here.
func TestGoAwayReportsLastStream(t *testing.T) {
	served := make(chan struct{}, 2)
	p, c, done := newPeer(t, func(req *Request, res *Response) {
		res.WriteHeader(204, nil)
		served <- struct{}{}
	})
	p.readUntil(frameSettings)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/een"))
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 5, headerBlock("/twee"))
	<-served
	<-served

	if err := c.GoAway(0, "klaar"); err != nil {
		t.Fatal(err)
	}
	_, _, body := p.readUntil(frameGoAway)
	if last := binary.BigEndian.Uint32(body[0:]) & 0x7fffffff; last != 5 {
		t.Errorf("GOAWAY last stream = %d, want 5", last)
	}
	// And no new stream after it.
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 7, headerBlock("/na"))
	assertConnectionError(t, done, "after GOAWAY")
}

// The request rules of RFC 9113 §8.3 and §8.2.2. Each of these reaches a handler
// in a permissive implementation, which is exactly the class of bug that ends up
// as a request smuggling advisory.
func TestInvalidRequestsAreRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		fields []field
		want   string
	}{
		{"no :method", []field{{":scheme", "https"}, {":path", "/"}}, "missing :method"},
		{"no :path", []field{{":method", "GET"}, {":scheme", "https"}}, "missing :path"},
		{"empty :path", []field{{":method", "GET"}, {":scheme", "https"}, {":path", ""}}, "empty :path"},
		{"duplicate :method", []field{{":method", "GET"}, {":method", "POST"},
			{":scheme", "https"}, {":path", "/"}}, "duplicate :method"},
		{"unknown pseudo-header", []field{{":method", "GET"}, {":scheme", "https"},
			{":path", "/"}, {":protocol", "websocket"}}, "unknown pseudo-header"},
		{"pseudo-header after a field", []field{{":method", "GET"}, {":scheme", "https"},
			{"x-a", "1"}, {":path", "/"}}, "after a regular field"},
		{"uppercase field name", []field{{":method", "GET"}, {":scheme", "https"},
			{":path", "/"}, {"X-Upper", "1"}}, "not lowercase"},
		{"connection field", []field{{":method", "GET"}, {":scheme", "https"},
			{":path", "/"}, {"connection", "keep-alive"}}, "connection-specific"},
		{"transfer-encoding", []field{{":method", "GET"}, {":scheme", "https"},
			{":path", "/"}, {"transfer-encoding", "chunked"}}, "connection-specific"},
		{"te other than trailers", []field{{":method", "GET"}, {":scheme", "https"},
			{":path", "/"}, {"te", "gzip"}}, "te:"},
		{"two content-lengths", []field{{":method", "POST"}, {":scheme", "https"},
			{":path", "/"}, {"content-length", "1"}, {"content-length", "2"}}, "more than one content-length"},
	} {
		t.Run(c.name, func(t *testing.T) {
			reached := make(chan string, 1)
			p, _, done := newPeer(t, func(req *Request, res *Response) {
				reached <- req.Path
				res.WriteHeader(204, nil)
			})
			p.readUntil(frameSettings)
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, encodeFields(nil, c.fields))
			assertConnectionError(t, done, c.want)
			select {
			case path := <-reached:
				t.Errorf("handler was reached with path %q", path)
			default:
			}
		})
	}
}

// Frame-level shape checks: a peer that gets these wrong is broken, and going
// along with it hides the breakage.
func TestFrameShapeRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(*peer)
		want string
	}{
		{"PING of the wrong length", func(p *peer) {
			p.frame(framePing, 0, 0, []byte{1, 2, 3})
		}, "PING of 3 bytes"},
		{"PING on a stream", func(p *peer) {
			p.frame(framePing, 0, 1, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}, "on stream 1"},
		{"SETTINGS ACK with a payload", func(p *peer) {
			p.frame(frameSettings, flagACK, 0, []byte{0, 3, 0, 0, 0, 1})
		}, "acknowledgement with a payload"},
		{"SETTINGS on a stream", func(p *peer) {
			p.frame(frameSettings, 0, 1, nil)
		}, "SETTINGS on a stream"},
		{"DATA on stream 0", func(p *peer) {
			p.frame(frameData, 0, 0, []byte("x"))
		}, "DATA on stream 0"},
		{"RST_STREAM of the wrong length", func(p *peer) {
			p.frame(frameRSTStream, 0, 1, []byte{0, 0})
		}, "RST_STREAM of 2 bytes"},
		{"WINDOW_UPDATE that overflows", func(p *peer) {
			var inc [4]byte
			binary.BigEndian.PutUint32(inc[:], 0x7fffffff)
			p.frame(frameWindowUpdate, 0, 0, inc[:])
			p.frame(frameWindowUpdate, 0, 0, inc[:])
		}, "would overflow"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, done := newPeer(t, func(req *Request, res *Response) { res.WriteHeader(204, nil) })
			p.readUntil(frameSettings)
			c.send(p)
			assertConnectionError(t, done, c.want)
		})
	}
}

// A handler that answers without reading the body must not leave the stream half
// open: the peer has to learn that it can stop sending.
func TestUnreadBodyIsCancelled(t *testing.T) {
	p, _, done := newPeer(t, func(req *Request, res *Response) {
		res.WriteHeader(204, nil) // deliberately never touches req.Body
	})
	p.readUntil(frameSettings)
	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/upload"))
	p.frame(frameData, 0, 1, []byte("blijft staan"))

	if _, stream, body := p.readUntil(frameRSTStream); stream != 1 {
		t.Errorf("RST_STREAM on stream %d, want 1 (code %d)", stream, binary.BigEndian.Uint32(body))
	}
	p.conn.Close()
	<-done
}

// assertConnectionError waits for Serve to end and checks the reason names the
// peer's mistake. A refusal that ends the connection silently is not a refusal.
func assertConnectionError(t *testing.T, done chan error, want string) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connection ended without an error")
		}
		if !contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection stayed up")
	}
}
