package leanh2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

const adversarialWait = time.Second

// adversarialHandshake performs the client half of the SETTINGS exchange. In
// particular, the first client frame after the preface is a non-ACK SETTINGS.
func adversarialHandshake(t *testing.T, p *peer, settings []byte) {
	t.Helper()
	p.readUntil(frameSettings) // the server's settings
	flags, stream, _ := p.readUntil(frameSettings)
	if flags&flagACK == 0 || stream != 0 {
		t.Fatalf("initial SETTINGS answer has flags 0x%02x on stream %d", flags, stream)
	}
	if settings != nil {
		p.frame(frameSettings, 0, 0, settings)
		flags, stream, _ = p.readUntil(frameSettings)
		if flags&flagACK == 0 || stream != 0 {
			t.Fatalf("SETTINGS answer has flags 0x%02x on stream %d", flags, stream)
		}
	}
	p.frame(frameSettings, flagACK, 0, nil) // acknowledge the server's settings
}

func adversarialClose(p *peer) {
	_ = p.conn.Close()
}

func adversarialWantConnectionError(t *testing.T, done chan error, want string) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil {
			t.Error("connection ended without an error")
		} else if !contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	case <-time.After(adversarialWait):
		t.Errorf("connection accepted input that should be refused (%s)", want)
	}
}

// waitForReserveWaiters is a test-only barrier. Both writers have a zero stream
// window, so seeing both parked inside reserve proves that both attempted their
// connection-window claim before either stream is released. This makes the
// cross-stream race deterministic rather than hoping the scheduler overlaps two
// writes.
func waitForReserveWaiters(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(adversarialWait)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		waiters := 0
		for _, stack := range bytes.Split(buf[:n], []byte("\n\n")) {
			if bytes.Contains(stack, []byte("(*stream).reserve")) &&
				bytes.Contains(stack, []byte("sync.(*Cond).Wait")) {
				waiters++
			}
		}
		if waiters >= want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("only observed fewer than %d writers waiting in reserve", want)
}

// Two streams may observe the same connection credit, but only one may claim
// it. Stream credit is released simultaneously after both writers are waiting;
// the second write must remain blocked until a connection WINDOW_UPDATE.
func TestAdversarialConcurrentResponsesShareConnectionWindow(t *testing.T) {
	type call struct {
		req *Request
		res *Response
	}
	calls := make(chan call, 2)
	releaseHandlers := make(chan struct{})
	p, c, _ := newPeer(t, func(req *Request, res *Response) {
		calls <- call{req, res}
		<-releaseHandlers
	})
	defer func() {
		close(releaseHandlers)
		adversarialClose(p)
	}()
	var settings []byte
	settings = binary.BigEndian.AppendUint16(settings, settingInitialWindowSize)
	settings = binary.BigEndian.AppendUint32(settings, 0)
	adversarialHandshake(t, p, settings)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/one"))
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 3, headerBlock("/two"))
	a, b := <-calls, <-calls
	if a.req.StreamID > b.req.StreamID {
		a, b = b, a
	}

	// A peer cannot lower the connection window on the wire. Put it in the state
	// reached after 65,534 response bytes without making this regression large.
	c.mu.Lock()
	c.connWin = 1
	c.mu.Unlock()

	type result struct {
		stream uint32
		err    error
	}
	results := make(chan result, 2)
	for _, v := range []call{a, b} {
		v := v
		go func() {
			_, err := v.res.Write([]byte("x"))
			results <- result{v.req.StreamID, err}
		}()
	}
	waitForReserveWaiters(t, 2)

	var one [4]byte
	binary.BigEndian.PutUint32(one[:], 1)
	p.frame(frameWindowUpdate, 0, 1, one[:])

	first := <-results
	if first.err != nil {
		t.Fatalf("first stream %d write: %v", first.stream, first.err)
	}
	if first.stream != 1 {
		t.Fatalf("stream %d wrote before only stream 1 received credit", first.stream)
	}
	p.frame(frameWindowUpdate, 0, 3, one[:])

	// With an atomic two-level claim, the remaining writer is now parked on the
	// empty connection window. The buggy split claim returns both writes.
	var second result
	overclaimed := false
	select {
	case second = <-results:
		overclaimed = true
	case <-time.After(100 * time.Millisecond):
		p.frame(frameWindowUpdate, 0, 0, one[:])
		select {
		case second = <-results:
		case <-time.After(adversarialWait):
			t.Fatal("second writer did not continue after connection WINDOW_UPDATE")
		}
	}
	if second.err != nil {
		t.Errorf("second stream %d write: %v", second.stream, second.err)
	}
	if overclaimed {
		t.Error("both response streams claimed the same one byte of connection window")
	}
}

func TestAdversarialInitialWindowShiftCannotOverflowStream(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p, _, done := newPeer(t, func(_ *Request, res *Response) {
		close(started)
		<-release
		_ = res.WriteHeader(204, nil)
	})
	defer func() {
		close(release)
		adversarialClose(p)
	}()
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/held"))
	<-started

	var inc [4]byte
	binary.BigEndian.PutUint32(inc[:], uint32(windowMax-65535))
	p.frame(frameWindowUpdate, 0, 1, inc[:]) // stream window is exactly 2^31-1
	var settings []byte
	settings = binary.BigEndian.AppendUint16(settings, settingInitialWindowSize)
	settings = binary.BigEndian.AppendUint32(settings, 65536) // shift it by +1
	p.frame(frameSettings, 0, 0, settings)
	adversarialWantConnectionError(t, done, "overflow")
}

func TestAdversarialReceiveWindowsAreEnforced(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		release := make(chan struct{})
		p, _, done := newPeer(t, func(*Request, *Response) { <-release })
		defer func() {
			close(release)
			adversarialClose(p)
		}()
		adversarialHandshake(t, p, nil)
		p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/stream-window"))
		chunk := make([]byte, ourMaxFrame)
		for i := 0; i < ourInitialWindow/ourMaxFrame; i++ {
			p.frame(frameData, 0, 1, chunk)
		}
		p.frame(frameData, 0, 1, []byte{1})
		adversarialWantConnectionError(t, done, "receive window of stream")
	})

	t.Run("connection across streams", func(t *testing.T) {
		release := make(chan struct{})
		p, _, done := newPeer(t, func(*Request, *Response) { <-release })
		defer func() {
			close(release)
			adversarialClose(p)
		}()
		adversarialHandshake(t, p, nil)
		chunk := make([]byte, ourMaxFrame)
		// Sixteen full stream windows plus 65,535 bytes consume the exact
		// connection window this side announced: the RFC default plus our bump.
		for stream := uint32(1); stream <= 31; stream += 2 {
			p.frame(frameHeaders, flagEndHeaders, stream, headerBlock("/connection-window"))
			for i := 0; i < ourInitialWindow/ourMaxFrame; i++ {
				p.frame(frameData, 0, stream, chunk)
			}
		}
		p.frame(frameHeaders, flagEndHeaders, 33, headerBlock("/connection-window"))
		for i := 0; i < 3; i++ {
			p.frame(frameData, 0, 33, chunk)
		}
		p.frame(frameData, 0, 33, make([]byte, ourMaxFrame-1))
		p.frame(frameData, 0, 33, []byte{1})
		adversarialWantConnectionError(t, done, "connection receive window")
	})
}

func TestAdversarialUnreadBodyReturnsConnectionCredit(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p, c, _ := newPeer(t, func(_ *Request, res *Response) {
		close(started)
		<-release
		_ = res.WriteHeader(204, nil)
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/discard"))
	<-started
	payload := []byte("unread but still flow-controlled")
	p.frame(frameData, 0, 1, payload)

	deadline := time.Now().Add(adversarialWait)
	for {
		c.mu.Lock()
		s := c.streams[1]
		c.mu.Unlock()
		c.recvMu.Lock()
		buffered := s != nil && s.recvWin == ourInitialWindow-int64(len(payload))
		c.recvMu.Unlock()
		if buffered {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("DATA did not enter the request-body buffer")
		}
		runtime.Gosched()
	}
	close(release)

	var reset, connectionCredit bool
	for i := 0; i < 20 && !(reset && connectionCredit); i++ {
		typ, _, stream, body := p.read()
		switch typ {
		case frameRSTStream:
			reset = stream == 1
		case frameWindowUpdate:
			connectionCredit = stream == 0 && binary.BigEndian.Uint32(body) == uint32(len(payload))
		}
	}
	if !reset || !connectionCredit {
		t.Errorf("unread body cleanup reset=%v connection-credit=%v, want both", reset, connectionCredit)
	}
}

func adversarialWaitForSlots(t *testing.T, c *Conn, want int) {
	t.Helper()
	deadline := time.Now().Add(adversarialWait)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := c.streamSlots
		c.mu.Unlock()
		if got == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("handler slots did not become %d", want)
}

func TestAdversarialPeerResetEmitsNoLaterStreamFrame(t *testing.T) {
	started := make(chan struct{})
	readDone := make(chan error, 1)
	p, c, _ := newPeer(t, func(req *Request, _ *Response) {
		close(started)
		_, err := io.ReadAll(req.Body)
		readDone <- err
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/cancel"))
	<-started
	p.frame(frameRSTStream, 0, 1, []byte{0, 0, 0, 0})
	if err := <-readDone; err == nil {
		t.Error("peer reset looked like clean request EOF")
	}
	adversarialWaitForSlots(t, c, 0)

	p.frame(framePing, 0, 0, []byte("12345678"))
	for i := 0; i < 20; i++ {
		typ, _, stream, _ := p.read()
		if stream == 1 {
			t.Fatalf("frame type 0x%02x was emitted after peer RST_STREAM", typ)
		}
		if typ == framePing {
			return
		}
	}
	t.Fatal("connection did not answer PING after stream cancellation")
}

func TestAdversarialDataAfterFullyClosedStreamIsRefused(t *testing.T) {
	started := make(chan struct{})
	p, c, done := newPeer(t, func(_ *Request, res *Response) {
		close(started)
		_ = res.WriteHeader(204, nil)
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/closed"))
	<-started
	adversarialWaitForSlots(t, c, 0)
	p.frame(frameData, 0, 1, []byte("late"))
	adversarialWantConnectionError(t, done, "DATA on closed stream")
}

func TestAdversarialReservedDataIsRecheckedAfterInitialWindowDecrease(t *testing.T) {
	headersWritten := make(chan struct{})
	startWrite := make(chan struct{})
	writeDone := make(chan error, 1)
	p, c, _ := newPeer(t, func(_ *Request, res *Response) {
		if err := res.WriteHeader(200, nil); err != nil {
			writeDone <- err
			return
		}
		close(headersWritten)
		<-startWrite
		_, err := res.Write(make([]byte, ourMaxFrame))
		writeDone <- err
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/window-shift"))
	<-headersWritten

	// Hold the wire after the handler has sent its HEADERS. The DATA writer may
	// reserve under the old window but cannot emit yet.
	c.wmu.Lock()
	close(startWrite)
	deadline := time.Now().Add(adversarialWait)
	for {
		c.mu.Lock()
		s := c.streams[1]
		reserved := s != nil && s.win == 65535-ourMaxFrame
		c.mu.Unlock()
		if reserved {
			break
		}
		if time.Now().After(deadline) {
			c.wmu.Unlock()
			t.Fatal("response DATA did not reserve the old stream window")
		}
		runtime.Gosched()
	}
	var settings []byte
	settings = binary.BigEndian.AppendUint16(settings, settingInitialWindowSize)
	settings = binary.BigEndian.AppendUint32(settings, 0)
	c.mu.Lock()
	if err := c.applySettingsLocked(settings); err != nil {
		c.mu.Unlock()
		c.wmu.Unlock()
		t.Fatal(err)
	}
	c.mu.Unlock()
	if err := c.writeFrameLocked(frameSettings, flagACK, 0, nil); err != nil {
		c.wmu.Unlock()
		t.Fatal(err)
	}
	c.wmu.Unlock()

	select {
	case err := <-writeDone:
		t.Fatalf("DATA followed the lowering SETTINGS ACK: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	var inc [4]byte
	binary.BigEndian.PutUint32(inc[:], ourMaxFrame)
	p.frame(frameWindowUpdate, 0, 1, inc[:])
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("Write after new stream credit: %v", err)
		}
	case <-time.After(adversarialWait):
		t.Fatal("Write did not resume under the new stream window")
	}
}

type blockingCreditConn struct {
	mu          sync.Mutex
	r           *bytes.Reader
	updates     int
	closed      chan struct{}
	blocked     chan struct{}
	blockedOnce sync.Once
	closeOnce   sync.Once
}

type countingConn struct {
	mu      sync.Mutex
	r       *bytes.Reader
	writes  int
	closes  int
	shortAt int
}

func (c *countingConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *countingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == c.shortAt {
		return 0, nil
	}
	return len(p), nil
}

func (c *countingConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return nil
}

func (c *countingConn) counts() (writes, closes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.closes
}

func TestAdversarialPublicControlWaitsForStartup(t *testing.T) {
	rw := &countingConn{r: bytes.NewReader(nil)}
	c := NewConn(rw, func(*Request, *Response) {}, nil)
	if err := c.GoAway(0, "too early"); err == nil {
		t.Error("GoAway before Serve startup succeeded")
	}
	if writes, closes := rw.counts(); writes != 0 || closes != 0 {
		t.Fatalf("pre-start controls caused %d writes and %d closes", writes, closes)
	}
}

func TestAdversarialTerminalCloseIsOnce(t *testing.T) {
	for _, shortAt := range []int{1, 2} { // frame header, then frame body
		t.Run(fmt.Sprintf("write-%d", shortAt), func(t *testing.T) {
			rw := &countingConn{r: bytes.NewReader([]byte(clientPreface)), shortAt: shortAt}
			err := NewConn(rw, func(*Request, *Response) {}, nil).Serve()
			if err == nil || !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("Serve error = %v, want short write", err)
			}
			_, closes := rw.counts()
			if closes != 1 {
				t.Fatalf("terminal Close calls = %d, want exactly one", closes)
			}
		})
	}
}

func (c *blockingCreditConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF {
		<-c.blocked
	}
	return n, err
}

func (c *blockingCreditConn) Write(p []byte) (int, error) {
	if len(p) == 9 && p[3] == frameWindowUpdate {
		c.mu.Lock()
		c.updates++
		n := c.updates
		c.mu.Unlock()
		if n == 2 {
			c.blockedOnce.Do(func() { close(c.blocked) })
			<-c.closed
			return 0, errors.New("test connection closed")
		}
	}
	select {
	case <-c.closed:
		return 0, errors.New("test connection closed")
	default:
		return len(p), nil
	}
}

func (c *blockingCreditConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func adversarialFrame(typ, flags byte, stream uint32, body []byte) []byte {
	head := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(head[5:], stream)
	return append(head, body...)
}

func TestAdversarialPeerEOFReleasesBlockedCreditWrite(t *testing.T) {
	input := []byte(clientPreface)
	input = append(input, adversarialFrame(frameSettings, 0, 0, nil)...)
	input = append(input, adversarialFrame(frameHeaders, flagEndHeaders, 1, headerBlock("/credit"))...)
	input = append(input, adversarialFrame(frameData, flagEndStream, 1, []byte("x"))...)
	rw := &blockingCreditConn{
		r:       bytes.NewReader(input),
		closed:  make(chan struct{}),
		blocked: make(chan struct{}),
	}
	c := NewConn(rw, func(req *Request, _ *Response) { _, _ = io.ReadAll(req.Body) }, nil)
	done := make(chan error, 1)
	go func() { done <- c.Serve() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve returned nil after peer EOF")
		}
	case <-time.After(adversarialWait):
		_ = rw.Close()
		t.Fatal("Serve waited for an external Close while WINDOW_UPDATE was blocked")
	}
}

func TestAdversarialCloseAfterBodyEOFStaysClean(t *testing.T) {
	served := make(chan error, 1)
	p, c, _ := newPeer(t, func(req *Request, res *Response) {
		_, err := io.ReadAll(req.Body)
		if err == nil {
			err = req.Body.Close()
		}
		if err == nil {
			err = res.WriteHeader(204, nil)
		}
		served <- err
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/clean-close"))
	p.frame(frameData, flagEndStream, 1, []byte("body"))
	if err := <-served; err != nil {
		t.Fatalf("handler: %v", err)
	}
	adversarialWaitForSlots(t, c, 0)
	p.frame(framePing, 0, 0, []byte("abcdefgh"))
	for i := 0; i < 20; i++ {
		typ, _, stream, _ := p.read()
		if typ == frameRSTStream && stream == 1 {
			t.Fatal("read-to-EOF followed by Body.Close caused RST_STREAM")
		}
		if typ == framePing {
			return
		}
	}
	t.Fatal("connection did not answer PING after clean Body.Close")
}

func TestAdversarialFirstPeerFrameMustBeSettings(t *testing.T) {
	p, _, done := newPeerWithSettings(t, func(*Request, *Response) {}, false)
	defer adversarialClose(p)
	p.readUntil(frameSettings)
	p.frame(framePing, 0, 0, []byte("12345678"))
	adversarialWantConnectionError(t, done, "SETTINGS")
}

func TestAdversarialClientPushPromiseIsRefused(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p, _, done := newPeer(t, func(*Request, *Response) {
		close(started)
		<-release
	})
	defer func() {
		close(release)
		adversarialClose(p)
	}()
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/open"))
	<-started
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 2)
	body = append(body, headerBlock("/pushed")...)
	p.frame(0x5, flagEndHeaders, 1, body) // PUSH_PROMISE, forbidden from a client
	adversarialWantConnectionError(t, done, "PUSH")
}

func TestAdversarialRequestHeadersAreRefusedBeforeHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []field
		want   string
	}{
		{
			name: "CONNECT in origin form",
			fields: []field{{":method", "CONNECT"}, {":scheme", "https"},
				{":path", "/"}, {":authority", "example.test"}},
			want: "CONNECT",
		},
		{
			name: "non-numeric content-length",
			fields: []field{{":method", "POST"}, {":scheme", "https"}, {":path", "/"},
				{":authority", "example.test"}, {"content-length", "not-a-number"}},
			want: "content-length",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := make(chan struct{}, 1)
			p, _, done := newPeer(t, func(*Request, *Response) { reached <- struct{}{} })
			defer adversarialClose(p)
			adversarialHandshake(t, p, nil)
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, encodeFields(nil, tc.fields))
			select {
			case <-reached:
				t.Errorf("handler was reached for invalid request: %s", tc.want)
			case err := <-done:
				if err == nil || !contains(err.Error(), tc.want) {
					t.Errorf("error = %v, want it to mention %q", err, tc.want)
				}
			case <-time.After(adversarialWait):
				t.Errorf("invalid request was neither served nor refused: %s", tc.want)
			}
		})
	}
}

func TestAdversarialSplitCookiesBecomeOneRequestField(t *testing.T) {
	req, _, err := requestFrom([]field{
		{":method", "GET"}, {":scheme", "https"}, {":path", "/"},
		{"cookie", "a=1"}, {"cookie", "b=2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Get("cookie"); got != "a=1; b=2" {
		t.Fatalf("Cookie = %q, want %q", got, "a=1; b=2")
	}
	if len(req.Header["cookie"]) != 1 {
		t.Fatalf("Cookie has %d values after normalization, want 1", len(req.Header["cookie"]))
	}
}

func TestAdversarialContentLengthMustMatchData(t *testing.T) {
	readErr := make(chan error, 1)
	p, _, _ := newPeer(t, func(req *Request, res *Response) {
		_, err := io.ReadAll(req.Body)
		readErr <- err
		_ = res.WriteHeader(204, nil)
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	fields := []field{{":method", "POST"}, {":scheme", "https"}, {":path", "/"},
		{":authority", "example.test"}, {"content-length", "2"}}
	p.frame(frameHeaders, flagEndHeaders, 1, encodeFields(nil, fields))
	p.frame(frameData, flagEndStream, 1, []byte("x"))
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("one DATA byte satisfied content-length 2")
		}
	case <-time.After(adversarialWait):
		t.Fatal("handler did not finish reading the short request body")
	}
}

// A stream-level reset is also an acceptable loud refusal here; silently
// crediting and discarding the frame is not.
func adversarialWantStreamOrConnectionRefusal(t *testing.T, p *peer, done chan error, stream uint32) {
	t.Helper()
	rst := make(chan uint32, 1)
	go func() {
		for i := 0; i < 20; i++ {
			typ, _, gotStream, _ := p.readQuiet()
			if typ == frameRSTStream {
				rst <- gotStream
				return
			}
			if typ == 0xff {
				return // the connection-error result on done is authoritative
			}
		}
		rst <- 0
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("connection ended without naming the invalid stream frame")
		}
	case got := <-rst:
		if got != stream {
			t.Errorf("refusal reset stream %d, want %d", got, stream)
		}
	case <-time.After(adversarialWait):
		t.Error("invalid stream frame was silently accepted")
	}
}

func TestAdversarialDataAfterRemoteEndStreamIsRefused(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p, _, done := newPeer(t, func(*Request, *Response) {
		close(started)
		<-release
	})
	defer func() {
		close(release)
		adversarialClose(p)
	}()
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/ended"))
	<-started
	p.frame(frameData, 0, 1, []byte("late"))
	adversarialWantStreamOrConnectionRefusal(t, p, done, 1)
}

func TestAdversarialFramesOnIdleStreamAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  byte
		body []byte
	}{
		{"DATA", frameData, []byte("idle")},
		{"RST_STREAM", frameRSTStream, []byte{0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, done := newPeer(t, func(*Request, *Response) {})
			defer adversarialClose(p)
			adversarialHandshake(t, p, nil)
			p.frame(tc.typ, 0, 1, tc.body)
			adversarialWantStreamOrConnectionRefusal(t, p, done, 1)
		})
	}
}

func TestAdversarialResponseRejectsInformationalStatus(t *testing.T) {
	writeErr := make(chan error, 1)
	p, _, _ := newPeer(t, func(_ *Request, res *Response) {
		writeErr <- res.WriteHeader(103, nil)
	})
	defer adversarialClose(p)
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/early"))
	select {
	case err := <-writeErr:
		if err == nil {
			t.Error("WriteHeader accepted murdered 1xx response")
		}
	case <-time.After(adversarialWait):
		t.Fatal("handler did not call WriteHeader")
	}
}

func TestAdversarialResponseRejectsInvalidHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header map[string][]string
	}{
		{"pseudo-header injection", map[string][]string{":status": {"201"}}},
		{"connection-specific field", map[string][]string{"connection": {"keep-alive"}}},
		{"trailer field", map[string][]string{"trailer": {"x-checksum"}}},
		{"response content-length", map[string][]string{"content-length": {"1"}}},
		{"invalid field name", map[string][]string{"bad name": {"value"}}},
		{"newline in field value", map[string][]string{"x-value": {"ok\r\nsmuggled: yes"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeErr := make(chan error, 1)
			p, _, _ := newPeer(t, func(_ *Request, res *Response) {
				writeErr <- res.WriteHeader(200, tc.header)
			})
			defer adversarialClose(p)
			adversarialHandshake(t, p, nil)
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, headerBlock("/headers"))
			select {
			case err := <-writeErr:
				if err == nil {
					t.Error("WriteHeader accepted an invalid HTTP/2 response field")
				}
			case <-time.After(adversarialWait):
				t.Fatal("handler did not call WriteHeader")
			}
		})
	}
}

func TestAdversarialRequestTrailersAreRefused(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p, _, done := newPeer(t, func(*Request, *Response) {
		close(started)
		<-release
	})
	defer func() {
		close(release)
		adversarialClose(p)
	}()
	adversarialHandshake(t, p, nil)
	p.frame(frameHeaders, flagEndHeaders, 1, headerBlock("/trailers"))
	<-started
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1,
		encodeFields(nil, []field{{"x-checksum", "done"}}))
	adversarialWantConnectionError(t, done, "not above the last accepted")
}

func TestAdversarialBodylessResponsesSuppressData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		status int
	}{
		{"HEAD", "HEAD", 200},
		{"204", "GET", 204},
		{"205", "GET", 205},
		{"304", "GET", 304},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrote := make(chan error, 1)
			p, _, _ := newPeer(t, func(_ *Request, res *Response) {
				if err := res.WriteHeader(tc.status, nil); err != nil {
					wrote <- err
					return
				}
				n, err := res.Write([]byte("body"))
				if err == nil && n != 4 {
					err = io.ErrShortWrite
				}
				wrote <- err
			})
			defer adversarialClose(p)
			adversarialHandshake(t, p, nil)
			fields := []field{{":method", tc.method}, {":scheme", "https"},
				{":path", "/bodyless"}, {":authority", "example.test"}}
			p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, encodeFields(nil, fields))
			if err := <-wrote; err == nil {
				t.Error("handler body write on a bodyless response was not refused")
			}

			var payload []byte
			for i := 0; i < 20; i++ {
				typ, flags, stream, body := p.read()
				if typ != frameData || stream != 1 {
					continue
				}
				payload = append(payload, body...)
				if flags&flagEndStream != 0 {
					break
				}
			}
			if len(payload) != 0 {
				t.Errorf("bodyless response sent DATA payload %q", payload)
			}
		})
	}
}

func TestAdversarialHPACKTableIsZeroAfterSettingsACK(t *testing.T) {
	reached := make(chan uint32, 1)
	p, _, done := newPeerWithSettings(t, func(req *Request, res *Response) {
		reached <- req.StreamID
		_ = res.WriteHeader(204, nil)
	}, false)
	defer adversarialClose(p)

	// SETTINGS is the first client frame. Once we acknowledge the server's
	// HEADER_TABLE_SIZE=0 setting, even a one-byte dynamic table is forbidden.
	p.frame(frameSettings, 0, 0, nil)
	p.readUntil(frameSettings) // server settings
	flags, _, _ := p.readUntil(frameSettings)
	if flags&flagACK == 0 {
		t.Fatal("server did not acknowledge client settings")
	}
	p.frame(frameSettings, flagACK, 0, nil)

	block := appendInt(nil, 0x20, 5, 1) // dynamic table size update to 1
	block = append(block, headerBlock("/after-ack")...)
	p.frame(frameHeaders, flagEndHeaders|flagEndStream, 1, block)
	select {
	case stream := <-reached:
		t.Errorf("handler reached on stream %d after HPACK table grew above announced zero", stream)
	case err := <-done:
		if err == nil || !contains(err.Error(), "table size") {
			t.Errorf("error = %v, want HPACK table-size refusal", err)
		}
	case <-time.After(adversarialWait):
		t.Error("HPACK table growth was neither served nor refused")
	}
}
