package leanhttp

// The server side supports small applications that serve content themselves,
// including SURF's screen image, frame stream, and web KVM.
//
// The model is intentionally small: one handler, Content-Length responses until
// Flush switches to chunked, and Hijack for protocols such as WebSocket. It has
// no HTTP/2, TLS, or pipelining. HTTP/2 lives in leanh2, a separate package on
// purpose: importing this one links nothing of it, and a caller that must carry
// both versions chooses per listener.
//
// Essential features are:
//
//   - keep-alive for known-length responses;
//   - Flush for frame streams and SSE;
//   - Hijack after an HTTP protocol upgrade;
//   - Request.Done so streaming handlers detect disconnected clients.
//
// Handler panics are not recovered. HopOS treats panic as fatal by design.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// This server handles APIs and small forms rather than uploads.
	maxBodyBytes = 1 << 20

	// Switch unknown-length responses to chunked above this threshold so a
	// forgotten Content-Length cannot buffer into an OOM.
	autoChunkBytes = 64 << 10

	// Bound a fresh connection's request header to avoid stalled goroutines.
	requestTimeout = 15 * time.Second

	// Close reused connections after this much inactivity.
	idleTimeout = 60 * time.Second

	// Apply per write, not per response, so long streams survive but stalled
	// clients do not retain a goroutine.
	writeTimeout = 30 * time.Second

	// Drain rejected requests briefly so the response arrives instead of RST.
	drainTimeout = 2 * time.Second

	// Bound handler body reads so a client cannot promise Content-Length and then
	// retain a goroutine and descriptor indefinitely.
	bodyTimeout = 5 * time.Second
)

// Handler serves one request. Route on r.Path or use Mux.
type Handler func(w ResponseWriter, r *Request)

// ResponseWriter writes one response. Flush and Hijack are always available.
type ResponseWriter interface {
	// Header returns response headers; modify them before the first Write.
	Header() Header

	// WriteHeader sets the status code; the default is 200 and only the first call counts.
	WriteHeader(status int)

	// Write writes body bytes. Without Content-Length or Flush, the server buffers
	// the response and calculates its length.
	Write(p []byte) (int, error)

	// Flush sends pending output. The first Flush without Content-Length switches
	// to chunked streaming.
	Flush() error

	// Hijack transfers the raw connection before the response starts. The caller
	// becomes responsible for writing and closing it.
	Hijack() (net.Conn, *bufio.ReadWriter, error)
}

// Request is one incoming request.
type Request struct {
	Method string // "GET", "POST", …
	// Path is percent-decoded and canonical. Parsing rejects ambiguous escapes,
	// dot segments, and duplicate slashes so middleware, Mux, and handlers share
	// one interpretation.
	Path       string
	RawQuery   string // everything after "?"; see Query
	Proto      string // "HTTP/1.1"
	Header     Header
	Body       io.Reader // never nil; bounded by maxBodyBytes
	RemoteAddr string

	// ContentLength is the declared body length, or -1 when absent, matching net/http.
	ContentLength int64

	c *conn

	vals      map[string]string // populated by Mux wildcards
	query     url.Values
	queryOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{}
	keepAlive bool
}

// PathValue returns a matched wildcard value, or "" when absent.
func (r *Request) PathValue(name string) string { return r.vals[name] }

// Query parses and caches the query string.
func (r *Request) Query() url.Values {
	r.queryOnce.Do(func() {
		r.query, _ = url.ParseQuery(r.RawQuery) // malformed queries yield empty values
	})
	return r.query
}

// Done closes when the client disconnects, allowing long-running stream
// handlers to stop.
//
// Calling Done claims the read side for a watcher and disables reuse. Read the
// request body first, and call Done before the first Flush so the response can
// advertise Connection: close.
//
// Done and Hijack are mutually exclusive because the read side has one owner.
// Done after Hijack, or after response headers were sent, panics as a handler bug.
//
// An unread body is client input, not a handler bug, so Done drains it briefly
// rather than panicking. Repeated Done calls are safe after ownership is claimed.
func (r *Request) Done() <-chan struct{} {
	if r.done == nil {
		switch {
		case r.c.hijacked:
			panic("leanhttp: Request.Done after Hijack — the connection's read side belongs to the hijacker")
		case r.c.headSent:
			panic("leanhttp: Request.Done after the response started — claim done before your first Flush")
		}
		if !bodyDrained(r.Body) {
			r.c.nc.SetReadDeadline(time.Now().Add(drainTimeout))
			io.Copy(io.Discard, r.Body)
		}
	}
	r.doneOnce.Do(func() {
		r.done = make(chan struct{})
		r.c.watched = true
		// Clear the body deadline so the watcher does not mistake its expiry for
		// a disconnected stream client.
		r.c.nc.SetReadDeadline(time.Time{})
		go func() {
			defer close(r.done)
			// Discard input until FIN, RST, or local Close ends the read.
			io.Copy(io.Discard, r.c.br)
		}()
	})
	return r.done
}

// Serve accepts until the listener closes and serves each connection in a goroutine.
func Serve(l net.Listener, h Handler) error {
	// Back off temporary accept errors to prevent a faulty listener from spinning
	// at 100% CPU.
	//
	// A nil connection without error is unrecoverable and fails explicitly.
	const maxDelay = 100 * time.Millisecond
	var delay time.Duration
	for {
		nc, err := l.Accept()
		switch {
		case err != nil:
			var ne net.Error
			// Retry timeout and Temporary errors such as descriptor exhaustion.
			if !errors.As(err, &ne) || (!ne.Timeout() && !ne.Temporary()) {
				return err
			}
			if delay == 0 {
				delay = time.Millisecond
			} else if delay *= 2; delay > maxDelay {
				delay = maxDelay
			}
			time.Sleep(delay)
			continue
		case nc == nil:
			return errors.New("leanhttp: listener returned no connection and no error")
		}
		delay = 0
		go serveConn(nc, h)
	}
}

// ListenAndServe listens on addr, such as ":80", and serves requests.
func ListenAndServe(addr string, h Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer l.Close()
	return Serve(l, h)
}

// conn is one connection being served.
type conn struct {
	nc       net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	hijacked bool // handler owns the connection
	watched  bool // Done watcher owns reads, so do not reuse
	headSent bool // response head was sent; Done is now too late
}

// timedWriter applies a deadline to every actual socket write. bufio decides
// when writes occur, keeping deadline setup out of higher-level operations.
type timedWriter struct{ nc net.Conn }

func (t *timedWriter) Write(p []byte) (int, error) {
	t.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	n, err := t.nc.Write(p)
	t.nc.SetWriteDeadline(time.Time{})
	return n, err
}

func serveConn(nc net.Conn, h Handler) {
	c := &conn{nc: nc, br: bufio.NewReaderSize(nc, bufSize), bw: bufio.NewWriterSize(&timedWriter{nc: nc}, bufSize)}
	defer func() {
		if !c.hijacked {
			nc.Close()
		}
	}()

	for first := true; ; first = false {
		limit := idleTimeout
		if first {
			limit = requestTimeout
		}
		nc.SetReadDeadline(time.Now().Add(limit))

		r, err := readRequest(c)
		if err != nil {
			// EOF and timeout mean the client left; malformed requests get a response.
			var perr parseError
			if errors.As(err, &perr) {
				writeBare(nc, perr.status, perr.Error())
				// Drain only when headers announced a body. This lets an error
				// response arrive without letting bare syntax errors retain resources.
				if perr.drain {
					nc.SetReadDeadline(time.Now().Add(drainTimeout))
					io.CopyN(io.Discard, c.br, maxBodyBytes)
				}
			}
			return
		}
		// Body reads retain their timeout; bodyless requests clear it so an SSE
		// handler may stream indefinitely. Content-Length: 0 is also drained.
		if bodyDrained(r.Body) {
			nc.SetReadDeadline(time.Time{})
		} else {
			nc.SetReadDeadline(time.Now().Add(bodyTimeout))
		}

		// Every Expect was rejected during parsing; there is no 100-Continue state.
		// Method tokens are case-sensitive, so only exact HEAD suppresses a body.
		c.headSent = false // reset per request on a reused connection
		w := &respWriter{c: c, hdr: Header{}, status: StatusOK, keepAlive: r.keepAlive,
			head: r.Method == "HEAD", declared: -1}
		h(w, r)
		if c.hijacked {
			return
		}
		if err := w.finish(); err != nil || !w.keepAlive || c.watched {
			// Before a clean close, briefly drain unread valid body bytes. Closing
			// with unread TCP data may reset and discard the response send queue.
			if err == nil && !c.watched && !bodyDrained(r.Body) {
				nc.SetReadDeadline(time.Now().Add(drainTimeout))
				io.Copy(io.Discard, r.Body)
			}
			return
		}
		// Drain before reuse so the next request starts at its own line. Bound the
		// drain; failure makes reuse unsafe. Avoid deadline churn when already drained.
		if !bodyDrained(r.Body) {
			nc.SetReadDeadline(time.Now().Add(drainTimeout))
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			nc.SetReadDeadline(time.Time{})
		}
	}
}

// bodyDrained reports no body, Content-Length zero, or fully consumed fixed length.
func bodyDrained(r io.Reader) bool {
	switch b := r.(type) {
	case emptyBody:
		return true
	case *lengthReader:
		return b.n <= 0
	}
	return false
}

// parseError carries the response status and whether an announced body should
// be drained briefly so the response arrives instead of RST.
type parseError struct {
	status int
	msg    string
	drain  bool
}

func (e parseError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return parseError{status: StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

// readRequest parses one request line, header block, and body framing.
func readRequest(c *conn) (*Request, error) {
	// EOF or timeout means the client left. A present but malformed request line
	// deserves 400 rather than a silent close.
	classify := func(err error) error {
		if errors.Is(err, io.EOF) {
			return err
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return err
		}
		return badRequest("%v", err)
	}
	budget := maxHeaderBytes
	line, err := readLine(c.br, &budget)
	if err != nil {
		return nil, classify(err)
	}
	if line == "" { // RFC 9112 §2.2 permits one leading CRLF
		if line, err = readLine(c.br, &budget); err != nil {
			return nil, classify(err)
		}
	}

	method, rest, ok := strings.Cut(line, " ")
	if !ok {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	if !validToken(method) {
		// Strict method tokens avoid proxy routing differentials.
		return nil, badRequest("leanhttp: invalid method %q", method)
	}
	if method == "CONNECT" {
		// CONNECT requests a tunnel, which this server never provides.
		return nil, parseError{StatusNotImplemented, "leanhttp: CONNECT is not supported", false}
	}
	target, proto, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	// Unsupported HTTP versions get 505; non-HTTP syntax gets 400.
	if !strings.HasPrefix(proto, "HTTP/") {
		return nil, badRequest("leanhttp: malformed request line %q", line)
	}
	if proto != "HTTP/1.1" {
		// Server input is exactly HTTP/1.1. The client still accepts HTTP/1.0
		// responses for servers such as Python's http.server.
		return nil, parseError{status: 505, msg: fmt.Sprintf("leanhttp: unsupported protocol %q", proto)}
	}
	if target == "" || target[0] != '/' {
		// Support only origin-form targets (RFC 9112 §3.2.1). Asterisk invents a
		// route, absolute-form duplicates Host authority, and CONNECT owns authority-form.
		return nil, badRequest("leanhttp: only origin-form request targets are supported, got %q", target)
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, badRequest("leanhttp: bad request target %q", target)
	}
	// Reject escapes that decode into path structure; see cleanEscapes.
	if !cleanEscapes(u.EscapedPath()) {
		return nil, badRequest("leanhttp: ambiguous percent-escape in path %q", u.EscapedPath())
	}
	// Require the same canonical decoded path predicate as Mux. Reject rather
	// than normalize to avoid a second interpretation.
	if !canonicalPath(u.Path) {
		return nil, badRequest("leanhttp: non-canonical request path %q", u.Path)
	}

	hdr := Header{}
	hosts, cls, tes := 0, 0, 0
	if err := readHeaderBlock(c.br, &budget, func(k, v string) error {
		// Count framing headers per physical line before hdr.add folds values;
		// otherwise an empty first Content-Length can disappear into a valid second one.
		switch {
		case strings.EqualFold(k, "Host"):
			hosts++
		case strings.EqualFold(k, "Content-Length"):
			cls++
		case strings.EqualFold(k, "Transfer-Encoding"):
			tes++
		}
		hdr.add(k, v)
		return nil
	}); err != nil {
		// Once a request started, any malformed or interrupted header block is 400.
		return nil, badRequest("leanhttp: read headers: %v", err)
	}

	// HTTP/1.1 requires exactly one non-empty Host (RFC 9112 §3.2). Missing,
	// empty, or repeated values create proxy routing differentials. This server
	// does not route by Host; if that changes, add an explicit allowlist.
	if hosts != 1 || hdr.Get("Host") == "" {
		return nil, badRequest("leanhttp: HTTP/1.1 requires exactly one non-empty Host header (got %d)", hosts)
	}

	r := &Request{
		ContentLength: -1, // no Content-Length seen; set below when present
		Method:        method,
		Path:          u.Path, // proven canonical above
		RawQuery:      u.RawQuery,
		Proto:         proto,
		Header:        hdr,
		Body:          emptyBody{},
		RemoteAddr:    c.nc.RemoteAddr().String(),
		c:             c,
	}
	// HTTP/1.1 stays open unless the Connection token list contains close.
	r.keepAlive = !connectionHas(hdr.Get("Connection"), "close")

	// Reject all Expect values with 417, which RFC 9110 §10.1.1 permits. No
	// internal caller needs the 100-Continue state machine. Do not drain because
	// an Expect client is waiting before sending its body.
	if hdr.Get("Expect") != "" {
		return nil, parseError{StatusExpectationFailed,
			fmt.Sprintf("leanhttp: Expect %q is not supported", hdr.Get("Expect")), false}
	}

	switch {
	case cls > 1 || tes > 1:
		// Reject repeated framing headers, including empty lines (RFC 9112 §6).
		return nil, parseError{StatusBadRequest,
			"leanhttp: repeated framing header", true}
	case tes == 1 && cls == 1:
		// TE plus CL lets intermediaries disagree on body boundaries (RFC 9112 §6.1).
		return nil, parseError{StatusBadRequest,
			"leanhttp: both Transfer-Encoding and Content-Length", true}
	case tes == 1:
		// Request bodies require Content-Length. No consumer uses chunked uploads;
		// the client still supports chunked responses for SSE.
		return nil, parseError{StatusNotImplemented,
			"leanhttp: Transfer-Encoding is not supported for requests; send a Content-Length", true}
	case cls == 1:
		// Strict decimal parsing rejects forms such as "+5" that a proxy may
		// interpret differently.
		n, ok := parseDecimal(hdr.Get("Content-Length"))
		if !ok {
			// Content-Length suggests a body may already be arriving; drain briefly.
			return nil, parseError{StatusBadRequest,
				fmt.Sprintf("leanhttp: bad Content-Length %q", hdr.Get("Content-Length")), true}
		}
		if n > maxBodyBytes {
			return nil, parseError{StatusRequestEntityTooLarge,
				fmt.Sprintf("leanhttp: body of %d bytes exceeds the %d-byte limit", n, maxBodyBytes), true}
		}
		r.ContentLength = n
		// Exact-length reads turn an early close into io.ErrUnexpectedEOF rather
		// than letting the handler treat a partial request as complete.
		r.Body = &lengthReader{r: c.br, n: n}
	}
	return r, nil
}

// emptyBody is an immediately exhausted readable body.
type emptyBody struct{}

func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }

// validToken implements RFC 9110 §5.6.2, excluding whitespace that can hide a
// framing header before its colon.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// respWriter is one request's ResponseWriter.
type respWriter struct {
	c         *conn
	hdr       Header
	status    int
	statusSet bool
	buf       bytes.Buffer // buffered until finish determines the length
	started   bool         // response head was sent
	chunked   bool
	written   int64 // body bytes sent, for length validation
	declared  int64 // wire Content-Length on the direct path; -1 means absent
	keepAlive bool
	head      bool // HEAD response has GET headers but no body bytes
	err       error
}

// errWroteTooMuch prevents bytes beyond Content-Length from becoming the next
// response on a keep-alive connection.
var errWroteTooMuch = errors.New("leanhttp: handler wrote past its declared Content-Length")

var errHijacked = errors.New("leanhttp: connection was hijacked")

func (w *respWriter) Header() Header { return w.hdr }

// suppressBody keeps headers but discards body bytes for HEAD and bodyless statuses.
func (w *respWriter) suppressBody() bool { return w.head || !bodyAllowed(w.status) }

func (w *respWriter) WriteHeader(status int) {
	if status < 200 || status > 599 {
		// Only final 200–599 statuses are valid. Protocol upgrades use Hijack and
		// write their own 101 response.
		panic("leanhttp: WriteHeader with a non-final status")
	}
	// 205 remains 205 and is bodyless; the writer must not silently remap status.
	if w.statusSet || w.started || w.buf.Len() > 0 {
		// First commit wins; buffered Write also commits status.
		return
	}
	w.status, w.statusSet = status, true
}

func (w *respWriter) Write(p []byte) (int, error) {
	switch {
	case w.c.hijacked:
		return 0, errHijacked
	case w.err != nil:
		return 0, w.err
	case !w.started:
		// Buffer unknown length until finish can add Content-Length. A declared
		// length writes directly and avoids duplicating large bodies in memory.
		if w.hdr.Get("Content-Length") == "" {
			if w.buf.Len()+len(p) <= autoChunkBytes {
				return w.buf.Write(p)
			}
			// Beyond the threshold, switch to chunked instead of unbounded buffering.
			if err := w.startChunked(); err != nil {
				return 0, err
			}
			return w.writeBody(p)
		}
		w.writeHead()
	}
	return w.writeBody(p)
}

// startChunked is shared by threshold-triggered Write and explicit Flush.
func (w *respWriter) startChunked() error {
	w.chunked = true
	return w.flushHead()
}

// flushHead sends headers and buffered data, then releases the backing array.
func (w *respWriter) flushHead() error {
	pending := w.buf.Bytes()
	w.writeHead()
	if len(pending) > 0 {
		if _, err := w.writeBody(pending); err != nil {
			return err
		}
	}
	w.buf = bytes.Buffer{}
	return nil
}

func (w *respWriter) Flush() error {
	switch {
	case w.c.hijacked:
		return errHijacked
	case w.err != nil:
		return w.err
	case !w.started:
		// Flushing unknown length selects chunked; buffered data is the first chunk.
		if w.hdr.Get("Content-Length") == "" {
			if err := w.startChunked(); err != nil {
				return err
			}
			break
		}
		// Declared length remains the framing after flushing buffered output.
		if err := w.flushHead(); err != nil {
			return err
		}
	}
	return w.flush()
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.started || w.buf.Len() > 0 || w.statusSet {
		// Buffered writes and status also commit; Hijack must not discard them.
		return nil, nil, errors.New("leanhttp: Hijack after the response already started")
	}
	if w.c.watched {
		// Request.Done already owns reads; Hijack cannot introduce a second reader.
		return nil, nil, errors.New("leanhttp: Hijack after Request.Done — the read side already has an owner")
	}
	if w.c.hijacked {
		return nil, nil, errHijacked
	}
	w.c.hijacked = true
	// Clear request deadlines; the hijacker owns timing from here.
	w.c.nc.SetDeadline(time.Time{})
	// Use a fresh direct writer so the hijacker does not inherit timedWriter's
	// per-write deadline. c.bw is empty because Hijack precedes writes.
	return w.c.nc, bufio.NewReadWriter(w.c.br, bufio.NewWriterSize(w.c.nc, bufSize)), nil
}

// writeHead writes the status line and headers into the output buffer.
func (w *respWriter) writeHead() {
	w.started = true
	w.c.headSent = true // Done is too late once the head is on the wire
	// Resolve case variants before validation. Merge equal values; remove all
	// conflicting variants and close so EOF is the only unambiguous framing.
	byFold := make(map[string][]string, len(w.hdr))
	for k := range w.hdr {
		lk := strings.ToLower(k)
		byFold[lk] = append(byFold[lk], k)
	}
	for _, keys := range byFold {
		if len(keys) < 2 {
			continue
		}
		conflict := false
		for _, k := range keys[1:] {
			if w.hdr[k] != w.hdr[keys[0]] {
				conflict = true
			}
			delete(w.hdr, k)
		}
		if conflict {
			delete(w.hdr, keys[0])
			w.keepAlive = false
		}
	}
	// The writer owns framing; ignore handler-supplied Transfer-Encoding to avoid
	// TE plus Content-Length with an unchunked body.
	w.hdr.Del("Transfer-Encoding")
	// Respect an explicit handler request to close.
	if connectionHas(w.hdr.Get("Connection"), "close") {
		w.keepAlive = false
	}
	if w.suppressBody() {
		w.chunked = false // bodyless responses have no framing or zero chunk
		if w.status == StatusNoContent {
			// 204 must not carry length; 304 and HEAD may carry it as metadata.
			w.hdr.Del("Content-Length")
		}
		if w.status == 205 && !w.head {
			// RFC 9112 §6.3 requires explicit zero framing for 205.
			w.hdr.Set("Content-Length", "0")
		}
	}
	if w.chunked {
		w.hdr.Set("Transfer-Encoding", "chunked")
		// Chunked is self-framing; remove even an empty Content-Length to avoid TE+CL.
		w.hdr.Del("Content-Length")
	}
	// Strictly parse every Content-Length, including HEAD metadata. Invalid
	// values are removed and force EOF framing rather than unsafe keep-alive.
	if cl := w.hdr.Get("Content-Length"); cl != "" {
		n, ok := parseDecimal(cl)
		switch {
		case !ok:
			w.hdr.Del("Content-Length")
			w.keepAlive = false
		case !w.chunked && !w.suppressBody():
			w.declared = n // every later write is bounded by this wire value
		}
	}
	// Request.Done's watcher consumes the connection after this response, so it
	// must advertise close rather than leave a dead connection in a client pool.
	if w.keepAlive && !w.c.watched {
		w.hdr.Set("Connection", "keep-alive")
	} else {
		w.hdr.Set("Connection", "close")
	}
	fmt.Fprintf(w.c.bw, "HTTP/1.1 %d %s\r\n", w.status, statusText(w.status))
	for k, v := range w.hdr {
		// Drop invalid names or control-bearing values that could inject another
		// response. Case variants were already collapsed to one line.
		if !validToken(k) || !validFieldValue(v) {
			continue
		}
		fmt.Fprintf(w.c.bw, "%s: %s\r\n", k, v)
	}
	w.c.bw.WriteString("\r\n")
}

// writeBody writes body bytes using the selected framing.
func (w *respWriter) writeBody(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, w.err
	}
	if w.suppressBody() {
		// Let shared GET/HEAD handlers write successfully while suppressing bytes.
		return len(p), nil
	}
	if w.declared >= 0 {
		// Enforce Content-Length per write; surplus bytes could otherwise become
		// the next response before finish notices.
		if allowed := w.declared - w.written; int64(len(p)) > allowed {
			p = p[:allowed]
			n := 0
			if len(p) > 0 {
				n, _ = w.writeBodyRaw(p)
			}
			// Report this handler error directly. The truncated wire response still
			// matches its promised length, so transport state remains usable.
			return n, errWroteTooMuch
		}
	}
	return w.writeBodyRaw(p)
}

// writeBodyRaw writes selected framing without length validation.
func (w *respWriter) writeBodyRaw(p []byte) (int, error) {
	if w.chunked {
		fmt.Fprintf(w.c.bw, "%x\r\n", len(p))
	}
	n, err := w.c.bw.Write(p)
	w.written += int64(n)
	if err == nil && w.chunked {
		_, err = w.c.bw.WriteString("\r\n")
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// flush sends bufio output; timedWriter prevents a non-reading client from
// retaining the goroutine.
func (w *respWriter) flush() error {
	err := w.c.bw.Flush()
	if err != nil && w.err == nil {
		w.err = err
	}
	return err
}

// finish adds Content-Length to buffered responses or the final zero chunk.
func (w *respWriter) finish() error {
	if w.c.hijacked {
		return nil
	}
	switch {
	case !w.started:
		body := w.buf.Bytes()
		// suppressBody handles bytes; here only headers decide whether length is valid.
		if bodyAllowed(w.status) && !(w.head && w.hdr.Get("Content-Length") != "") {
			// HEAD reports the corresponding GET length (RFC 9110 §9.3.2), but
			// preserve an explicit handler length when it wrote no body bytes.
			w.hdr.Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.writeHead()
		w.writeBody(body)
	case w.chunked:
		w.c.bw.WriteString("0\r\n\r\n")
	default:
		// On the direct path, mismatch against the immutable wire declaration
		// disables reuse. Later header-map mutations cannot alter framing already sent.
		if !w.suppressBody() && (w.declared < 0 || w.declared != w.written) {
			w.keepAlive = false
		}
	}
	if err := w.flush(); err != nil {
		return err
	}
	return w.err
}

// bodyAllowed excludes informational, 204, 205, and 304 responses. 205 still
// receives explicit Content-Length: 0 because RFC 9112 §6.3 does not make it
// implicitly bodyless for framing.
func bodyAllowed(status int) bool {
	return status >= 200 && status != StatusNoContent && status != 205 && status != 304
}

// writeBare responds to an unreadable request and closes the connection.
func writeBare(nc net.Conn, status int, msg string) {
	nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	fmt.Fprintf(nc, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s\n", status, statusText(status), len(msg)+1, msg)
}

// Error sends a status and plain-text explanation.
func Error(w ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

// Redirect sends the requested redirect status and location.
func Redirect(w ResponseWriter, location string, status int) {
	w.Header().Set("Location", location)
	w.WriteHeader(status)
	io.WriteString(w, "redirecting to "+location+"\n")
}

// statusText covers statuses emitted by this package and its consumers.
func statusText(status int) string {
	switch status {
	case StatusOK:
		return "OK"
	case StatusCreated:
		return "Created"
	case StatusNoContent:
		return "No Content"
	case 205:
		return "Reset Content"
	case 304:
		return "Not Modified"
	case StatusFound:
		return "Found"
	case StatusBadRequest:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case StatusNotFound:
		return "Not Found"
	case StatusMethodNotAllowed:
		return "Method Not Allowed"
	case 411:
		return "Length Required"
	case StatusRequestEntityTooLarge:
		return "Request Entity Too Large"
	case StatusExpectationFailed:
		return "Expectation Failed"
	case StatusInternalServerError:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 505:
		return "HTTP Version Not Supported"
	}
	return "Status"
}
