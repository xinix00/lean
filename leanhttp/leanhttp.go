// Package leanhttp provides a small HTTP/1.1 client and server without TLS for
// LAN peers, local APIs, pages, and streams.
//
// net/http links crypto/tls even when no HTTPS URL is opened. Measured in HopOS
// app images on 2026-07-26:
//
//	applib only ................. 1.71 MB
//	+ appnet (gVisor) ........... 4.70 MB
//	+ net/http .................. 7.99 MB
//	+ this package .............. 5.06 MB
//
// About 54% of net/http's addition was TLS/PKI. Three applications saved about
// 2.9 MB each and linked no crypto/tls symbols:
//
//	display  8.68 MB -> 5.88 MB
//	launcher 8.42 MB -> 5.48 MB
//	taskman  8.45 MB -> 5.54 MB
//
// Deliberate limits:
//
//   - HTTPS requires an explicit encrypted [Call.DialContext] and otherwise
//     fails loudly, preserving the no-TLS link boundary.
//   - Package-level [Do] and [Get] use one connection per request. [Client]
//     pools keep-alive connections only after complete body reads.
//   - There is no HTTP/2, automatic decompression, or cookie jar. Compression
//     is pass-through via Accept-Encoding and [Response.Encoding]; cookies live
//     in leancookie.
//
// [Do] reads and [Flush] writes chunked transfer for SSE and frame streams.
// [Get] requires Content-Length because it promises a known size. Redirects are
// bounded and limited to bodyless GET/HEAD. Header parsing is bounded per line
// and cumulatively; server request bodies are bounded separately.
package leanhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// dialTimeout bounds setup without limiting the download itself.
	dialTimeout = 10 * time.Second

	// maxRedirects matches net/http's default cap.
	maxRedirects = 10

	// expectTimeout bounds a streaming upload's wait for 100 or a final status
	// when HeaderTimeout/Timeout are looser. Silence fails; the body is not sent.
	expectTimeout = 10 * time.Second

	// bufSize also caps one header line through readLine's ReadSlice.
	bufSize = 8 << 10

	// maxHeaderBytes bounds many individually valid small lines.
	maxHeaderBytes = 64 << 10
)

// Status codes named by this package, without duplicating net/http's full list.
const (
	StatusOK                    = 200
	StatusCreated               = 201
	StatusNoContent             = 204
	StatusFound                 = 302
	StatusBadRequest            = 400
	StatusNotFound              = 404
	StatusMethodNotAllowed      = 405
	StatusRequestEntityTooLarge = 413
	StatusExpectationFailed     = 417
	StatusInternalServerError   = 500
	StatusNotImplemented        = 501
)

// Header is a field collection. Get, Set, and Del are case-insensitive while
// preserving sender or wire spelling.
type Header map[string]string

// Get returns key's value case-insensitively, or "" when absent.
func (h Header) Get(key string) string {
	if v, ok := h[key]; ok { // Fast path for exact stored spelling.
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// Set assigns key and removes differently cased duplicates.
func (h Header) Set(key, value string) {
	h.Del(key)
	h[key] = value
}

// Del removes key case-insensitively.
func (h Header) Del(key string) {
	for k := range h {
		if strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
}

// add folds repeated fields into an RFC 9110 §5.3 comma list.
func (h Header) add(key, value string) {
	if cur := h.Get(key); cur != "" {
		value = cur + ", " + value
	}
	h.Set(key, value)
}

// Call is one outbound [Do] request. Do owns Host, Content-Length, Connection,
// and default Accept-Encoding.
type Call struct {
	Method  string        // "" means GET
	URL     string        // http://, or https:// with an encrypted DialContext
	Header  Header        // additional request headers; may be nil
	Body    []byte        // nil means no body
	Timeout time.Duration // total deadline including body reads; zero means none

	// HeaderTimeout bounds only response-header waiting, not body transfer. This
	// lets large downloads remain unbounded while rejecting silent servers.
	HeaderTimeout time.Duration

	// BodyReader streams instead of buffering and requires BodyLen because this
	// package does not chunk uploads. It is mutually exclusive with Body. Streams
	// are not replayable, so redirects are returned. Expect: 100-continue avoids
	// sending a large body after an early rejection; silence fails after the
	// decision deadline.
	BodyReader io.Reader
	BodyLen    int64

	// DialContext overrides plain tcp4 setup for proxies, test doubles, or TLS
	// such as leanhttps.DialerContext. addr retains the hostname for SNI and
	// changes across redirects. ctx carries the total deadline over all hops.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NoFollow returns 3xx to the caller. Cookie-jar users must follow manually
	// because each hop may set cookies needed by the next.
	NoFollow bool
}

// Response is one reply. Body is unread response data and must be closed.
// Length is Content-Length, or -1 for chunked and EOF-delimited bodies.
type Response struct {
	StatusCode int
	Status     string // code plus reason, such as "404 Not Found"
	Header     Header
	Body       io.ReadCloser
	Length     int64

	// URL is the final response URL after redirects, for resolving relative links.
	URL string

	// Encoding is Content-Encoding, or "". Callers that set Accept-Encoding must
	// wrap Body themselves.
	Encoding string

	// SetCookie preserves each Set-Cookie field separately. Unlike ordinary
	// repeated fields, cookies cannot be comma-folded because values and Expires
	// dates contain commas. Header therefore excludes them.
	SetCookie []string

	chunked bool // lets Get distinguish chunked from absent length
}

// Get performs an HTTP/1.1 GET, follows bounded redirects, and requires status
// 200 with Content-Length. Use [Do] for other response forms.
func Get(raw string) (*Response, error) { return GetCall(Call{URL: raw}) }

// GetCall is Get with Call controls such as headers, deadlines, and DialContext.
func GetCall(c Call) (*Response, error) {
	resp, err := Do(c)
	if err != nil {
		return nil, err
	}
	return checkGet(resp)
}

// checkGet applies Get's 200 plus Content-Length contract.
func checkGet(resp *Response) (*Response, error) {
	switch {
	case resp.StatusCode != StatusOK:
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: HTTP %s", resp.Status)
	case resp.chunked:
		// Artifact staging requires a known length; fail before partial work.
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: chunked/encoded transfer is not supported here — serve the artifact with a Content-Length")
	case resp.Length < 0:
		resp.Body.Close()
		return nil, fmt.Errorf("leanhttp: no Content-Length in response")
	}
	return resp, nil
}

// Do executes one request and returns all statuses, including 4xx/5xx. It follows
// redirects only for bodyless GET/HEAD because other methods are not safely
// replayable.
func Do(c Call) (*Response, error) { return doVia(c, nil) }

// doVia executes Do using via's pool and dialer, or a one-shot connection when
// nil. Keeping transport separate prevents pool state masquerading as per-call
// configuration.
func doVia(c Call, via *Client) (*Response, error) {
	// One absolute deadline covers dial and every redirect hop.
	var total time.Time
	if c.Timeout > 0 {
		total = time.Now().Add(c.Timeout)
	}
	loc := c.URL
	for range maxRedirects + 1 {
		resp, err := do(c, via, loc, total)
		if err != nil && errors.Is(err, errStalePooled) && c.BodyReader == nil &&
			(c.Method == "" || c.Method == "GET" || c.Method == "HEAD") &&
			!errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
			// Retry one stale pooled connection only for replay-safe GET/HEAD,
			// bypassing any second stale idle connection while preserving pooling.
			fresh := c
			fresh.DialContext = normalizeDial(via.DialContext)
			resp, err = do(fresh, via, loc, total)
		}
		if err != nil {
			return nil, err
		}
		// Follow only RFC 9110 §15.4 redirect statuses for replay-safe GET/HEAD.
		// Other methods and 3xx statuses return to the caller.
		next := ""
		if !c.NoFollow && c.Body == nil && c.BodyReader == nil &&
			(c.Method == "" || c.Method == "GET" || c.Method == "HEAD") {
			switch resp.StatusCode {
			case 301, 302, 303, 307, 308:
				next = resp.Header.Get("Location")
			}
		}
		if next == "" {
			return resp, nil
		}
		// Close the unneeded 3xx body/connection before opening the next hop.
		resp.Body.Close()
		base, err := url.Parse(loc)
		if err != nil {
			return nil, fmt.Errorf("leanhttp: bad URL %q: %w", loc, err)
		}
		ref, err := url.Parse(next)
		if err != nil {
			return nil, fmt.Errorf("leanhttp: bad Location %q: %w", next, err)
		}
		dest := base.ResolveReference(ref)
		// Never follow HTTPS→HTTP: the target itself may contain sensitive path,
		// query, or signed-token data. NoFollow lets callers decide explicitly.
		if strings.EqualFold(base.Scheme, "https") && !strings.EqualFold(dest.Scheme, "https") {
			return nil, fmt.Errorf("leanhttp: refusing redirect from %s to %s: https must not degrade to plain http", loc, dest)
		}
		// Preserve caller headers only within the same scheme/host/port origin.
		// Strip all cross-origin fields because only the caller knows which are
		// sensitive.
		if originOf(dest) != originOf(base) {
			c.Header = nil
		}
		loc = dest.String() // Relative Location is allowed.
	}
	return nil, fmt.Errorf("leanhttp: too many redirects (>%d) starting at %s", maxRedirects, c.URL)
}

// Internally, DialContext is the only dialer form and carries the total deadline.

// normalizeDial returns dc or a standard-library dialer whose own timeout and
// context deadline combine by earliest expiry.
func normalizeDial(dc func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if dc != nil {
		return dc
	}
	return (&net.Dialer{Timeout: dialTimeout}).DialContext
}

// errStalePooled marks a reused connection that failed before the first response
// byte, permitting one safe replay of GET/HEAD.
var errStalePooled = errors.New("leanhttp: pooled connection went stale")

// originOf normalizes scheme, host, and default port into one origin.
func originOf(u *url.URL) string {
	host := u.Host
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			host += ":80"
		case "https":
			host += ":443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(host)
}

// do executes one hop: connect, write the request, and read response headers.
func do(c Call, via *Client, raw string, total time.Time) (_ *Response, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: bad URL %q: %w", raw, err)
	}
	// HTTPS requires an explicit call or client dialer. Check every hop so an
	// HTTP→HTTPS redirect can never send plaintext to port 443.
	hasTLS := c.DialContext != nil || (via != nil && via.DialContext != nil)
	port := "80"
	switch {
	case u.Scheme == "http":
	case u.Scheme == "https" && hasTLS:
		port = "443"
	case u.Scheme == "https":
		return nil, fmt.Errorf("leanhttp: https:// needs a Call.DialContext that returns an "+
			"encrypted connection (this package links no TLS) — use leanhttps, or set DialContext yourself: %s", raw)
	default:
		return nil, fmt.Errorf("leanhttp: only http:// and https:// are supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("leanhttp: URL %q has no host", raw)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(addr, port)
	}

	req, err := requestBytes(c, u, via != nil)
	if err != nil {
		return nil, err
	}

	// Carry the total deadline through every dial path, including pool misses.
	ctx := context.Background()
	if !total.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, total)
		defer cancel()
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if c.DialContext == nil && via != nil {
		dial = via.dial // Try the pool first; its tail normalizes client dialing.
	} else {
		dial = normalizeDial(c.DialContext)
	}
	conn, err := dial(ctx, "tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("leanhttp: dial %s: %w", addr, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("leanhttp: DialContext returned no connection and no error for %s", addr)
	}
	// Every later failure closes; success transfers ownership through Body.
	handedOff := false
	defer func() {
		if !handedOff {
			conn.Close()
		}
	}()
	// total covers all I/O and redirects. HeaderTimeout may shorten only the
	// header phase; afterward the body receives the remaining total time.
	if !total.IsZero() {
		// A transport rejecting the requested deadline is unusable.
		if err := conn.SetDeadline(total); err != nil {
			return nil, fmt.Errorf("leanhttp: set deadline: %w", err)
		}
	}
	// Expect needs a reader before any streamed body byte is sent.
	var br *bufio.Reader
	if pc, ok := conn.(*pooledConn); ok {
		br = pc.br // Pooling preserves the reader with the connection.
	} else {
		br = bufio.NewReaderSize(conn, bufSize)
	}

	// A reused connection failing before any response byte is safely retryable.
	_, pooled := conn.(*pooledConn)
	stale := func(err error) error {
		if pooled {
			return fmt.Errorf("%w: %w", errStalePooled, err)
		}
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, stale(fmt.Errorf("leanhttp: write request: %w", err))
	}
	// Send exactly BodyLen; a short reader would leave the server waiting forever.
	sendStream := func() error {
		n, err := io.CopyN(conn, c.BodyReader, c.BodyLen)
		switch {
		case err != nil:
			return fmt.Errorf("leanhttp: stream body after %d of %d bytes: %w", n, c.BodyLen, err)
		case n != c.BodyLen:
			return fmt.Errorf("leanhttp: BodyReader gave %d bytes, Content-Length promised %d", n, c.BodyLen)
		}
		return nil
	}
	bodySent := c.BodyReader == nil
	if c.BodyReader != nil {
		// RFC 9110 §10.1.1 Expect: wait under one absolute decision deadline
		// for complete 100/final headers. 100 sends the body; early rejection
		// avoids it; silence or partial headers fail.
		wacht := time.Now().Add(expectTimeout)
		if c.HeaderTimeout > 0 {
			if h := time.Now().Add(c.HeaderTimeout); h.Before(wacht) {
				wacht = h // The verdict is a header, so HeaderTimeout applies.
			}
		}
		if !total.IsZero() && total.Before(wacht) {
			wacht = total
		}
		if err := conn.SetDeadline(wacht); err != nil {
			return nil, fmt.Errorf("leanhttp: set deadline: %w", err)
		}
	} else {
		if len(c.Body) > 0 {
			if _, err := conn.Write(c.Body); err != nil {
				return nil, fmt.Errorf("leanhttp: write body: %w", err)
			}
		}
	}
	// Arm HeaderTimeout only while waiting for headers, never during upload, and
	// never past total. The 100 branch re-arms it after streaming.
	armHeader := func() error {
		if c.HeaderTimeout <= 0 {
			return nil
		}
		if head := time.Now().Add(c.HeaderTimeout); total.IsZero() || head.Before(total) {
			if err := conn.SetDeadline(head); err != nil {
				return fmt.Errorf("leanhttp: set header deadline: %w", err)
			}
		}
		return nil
	}
	if c.BodyReader == nil {
		// Streaming already has its single decision deadline; do not refresh it.
		if err := armHeader(); err != nil {
			return nil, err
		}
	}

	// Pooled connections retain their bufio.Reader and any read-ahead bytes.
	budget := maxHeaderBytes

	// Consume 1xx headers and continue to the final response under one cumulative
	// header budget. Returning an interim would desynchronize keep-alive. 101 is
	// an unsupported protocol switch.
	var code int
	var proto, status string
	firstRead := true
	for {
		line, err := readLine(br, &budget)
		if err != nil {
			if firstRead {
				if c.BodyReader != nil && !bodySent {
					// Name an incomplete Expect verdict rather than a generic timeout.
					return nil, fmt.Errorf("leanhttp: no verdict on Expect: 100-continue (want 100 or a final status): %w", err)
				}
				// Retry stale pooled connections only before consuming any response.
				return nil, stale(fmt.Errorf("leanhttp: read status line: %w", err))
			}
			return nil, fmt.Errorf("leanhttp: read status line: %w", err)
		}
		firstRead = false
		if code, proto, err = statusCode(line); err != nil {
			return nil, err
		}
		if code < 100 || code > 199 {
			_, status, _ = strings.Cut(line, " ") // "HTTP/1.1 404 Not Found" → "404 Not Found"
			break
		}
		if code == 101 {
			return nil, fmt.Errorf("leanhttp: server switched protocols (101); this package speaks HTTP/1.1 only")
		}
		// Consume the interim header block.
		if err := readHeaderBlock(br, &budget, nil); err != nil {
			return nil, fmt.Errorf("leanhttp: read interim headers: %w", err)
		}
		if code == 100 && !bodySent {
			// A 100 permits upload. Clear HeaderTimeout during streaming, then re-arm.
			if err := conn.SetDeadline(total); err != nil {
				return nil, fmt.Errorf("leanhttp: clear header deadline: %w", err)
			}
			if err := sendStream(); err != nil {
				return nil, err
			}
			bodySent = true
			if err := armHeader(); err != nil {
				return nil, err
			}
		}
	}

	hdr := Header{}
	var setCookie []string
	var length int64 = -1
	var chunked bool
	headerErr := readHeaderBlock(br, &budget, func(k, v string) error {
		switch {
		case strings.EqualFold(k, "Content-Length"):
			// Duplicate lengths are ambiguous framing, never last-wins.
			if length >= 0 {
				return fmt.Errorf("leanhttp: duplicate Content-Length")
			}
			// Accept bare decimal digits only; parsers disagree about forms like +5.
			n, ok := parseDecimal(v)
			if !ok {
				return fmt.Errorf("leanhttp: bad Content-Length %q", v)
			}
			length = n
		case strings.EqualFold(k, "Transfer-Encoding"):
			// Accept exactly one chunked field; anything else makes body framing
			// ambiguous and must never enter the pool.
			if chunked {
				return fmt.Errorf("leanhttp: duplicate Transfer-Encoding in response")
			}
			if !strings.EqualFold(v, "chunked") {
				return fmt.Errorf("leanhttp: unsupported Transfer-Encoding %q in response", v)
			}
			chunked = true
		case strings.EqualFold(k, "Set-Cookie"):
			// Do not fold or add to Header; see Response.SetCookie.
			setCookie = append(setCookie, v)
			return nil
		}
		hdr.add(k, v)
		return nil
	})
	if headerErr != nil {
		return nil, fmt.Errorf("leanhttp: read headers: %w", headerErr)
	}
	// RFC 9112 §6.1 forbids both framings; reject rather than choose and pool an
	// ambiguous response.
	if chunked && length >= 0 {
		return nil, fmt.Errorf("leanhttp: both Transfer-Encoding and Content-Length in response")
	}

	// HEAD has no body but preserves informational Content-Length (§6.3).
	isHEAD := c.Method == "HEAD" // Method tokens are case-sensitive (RFC 9110 §9.1).
	var rd io.Reader
	switch {
	case isHEAD:
		rd, chunked = emptyBody{}, false
	case !bodyAllowed(code):
		// RFC 9112 §6.3 makes 204/304 bodyless regardless of advertised framing;
		// waiting for EOF would hang on keep-alive until idle timeout.
		rd, chunked = emptyBody{}, false
		if code == StatusNoContent || code == 205 {
			length = 0 // RFC 9110 makes 204/205 empty.
		}
		// RFC 9110 §8.6 permits informational Content-Length on 304.
	case chunked:
		rd, length = &chunkReader{br: br}, -1
	case length >= 0:
		// lengthReader distinguishes a complete length from a truncated EOF.
		rd = &lengthReader{r: br, n: length}
	default:
		rd = br // No framing: body ends with the connection.
	}

	// Restore the total deadline after headers, clearing phase-only deadlines when
	// total is zero.
	if c.HeaderTimeout > 0 || c.BodyReader != nil {
		if err := conn.SetDeadline(total); err != nil {
			return nil, fmt.Errorf("leanhttp: restore deadline: %w", err)
		}
	}

	// Reuse requires a framed end and server persistence. HTTP/1.0 closes by
	// default unless it explicitly says keep-alive (RFC 9112 §9.3).
	connHdr := hdr.Get("Connection")
	keepAliveOK := proto != "HTTP/1.0" || connectionHas(connHdr, "keep-alive")
	bodyless := isHEAD || !bodyAllowed(code)
	reuse := via != nil && keepAliveOK && (bodyless || chunked || length >= 0) &&
		!connectionHas(connHdr, "close") && bodySent

	handedOff = true
	b := body{r: rd, c: conn, deadline: total}
	// Proven-empty bodies are complete immediately; chunked completes only after
	// its zero chunk.
	if bodyless || (!chunked && length == 0) {
		b.done = true
	}
	if reuse {
		b.pool, b.key, b.br = via, addr, br
	}
	return &Response{
		StatusCode: code,
		Status:     status,
		Header:     hdr,
		Body:       &b,
		Length:     length,
		URL:        raw,
		Encoding:   hdr.Get("Content-Encoding"),
		SetCookie:  setCookie,
		chunked:    chunked,
	}, nil
}

// requestBytes builds request headers and rejects injection syntax.
func requestBytes(c Call, u *url.URL, keepAlive bool) ([]byte, error) {
	method := c.Method
	if method == "" {
		method = "GET"
	} else if !validToken(method) {
		// Whitespace or CRLF in a method is request-line injection.
		return nil, fmt.Errorf("leanhttp: invalid method %q", c.Method)
	}
	if method == "CONNECT" {
		// CONNECT needs raw tunnel handoff after 2xx, which this client does not
		// expose; serializing it as an ordinary request would be unsafe.
		return nil, errors.New("leanhttp: CONNECT is not supported (this client is never a tunnel)")
	}
	var b bytes.Buffer
	// identity is the default because this package does not decompress. Callers
	// may opt in and inspect Response.Encoding without linking compress/gzip here.
	enc := "identity"
	if v := c.Header.Get("Accept-Encoding"); v != "" {
		enc = v
	}
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	// Host without an implicit default port, matching net/http.
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: %s\r\nConnection: %s\r\n",
		method, u.RequestURI(), u.Host, enc, conn)
	switch {
	case c.Body != nil && c.BodyReader != nil:
		return nil, errors.New("leanhttp: set Body or BodyReader, not both")
	case c.BodyReader != nil:
		if c.BodyLen < 0 {
			return nil, errors.New("leanhttp: BodyReader needs a BodyLen (this package does not chunk uploads)")
		}
		// A non-replayable stream asks for an RFC 9110 §10.1.1 verdict first.
		fmt.Fprintf(&b, "Content-Length: %d\r\nExpect: 100-continue\r\n", c.BodyLen)
	case c.Body != nil:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(c.Body))
	}
	for k, v := range c.Header {
		switch {
		case !validToken(k):
			// Tabs and controls in names are injection, not header syntax.
			return nil, fmt.Errorf("leanhttp: illegal header name %q", k)
		case !validFieldValue(v):
			// Apply incoming field grammar; NUL and VT are injection too.
			return nil, fmt.Errorf("leanhttp: illegal value for header %q", k)
		// Package-owned framing and connection fields cannot be overridden.
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Content-Length"),
			strings.EqualFold(k, "Connection"), strings.EqualFold(k, "Transfer-Encoding"),
			strings.EqualFold(k, "Expect"):
			return nil, fmt.Errorf("leanhttp: header %q is set by the package, not by the caller", k)
		case strings.EqualFold(k, "Accept-Encoding"):
			continue // Already written; do not duplicate.
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// readHeaderBlock parses fields through the empty line for both client and
// server. each may be nil when consuming an interim block.
func readHeaderBlock(br *bufio.Reader, budget *int, each func(k, v string) error) error {
	for {
		line, err := readLine(br, budget)
		if err != nil {
			return err
		}
		if line == "" {
			return nil // Empty line ends the header block.
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("leanhttp: malformed header %q", line)
		}
		// RFC 9112 §5.1 requires a token with no whitespace before `:`. Lenience
		// would let adjacent parsers disagree about message framing.
		if !validToken(k) {
			return fmt.Errorf("leanhttp: invalid header name %q", k)
		}
		if each == nil {
			continue
		}
		if err := each(k, trimOWS(v)); err != nil {
			return err
		}
	}
}

// readLine reads one strict CRLF line under a cumulative budget. It rejects bare
// LF and control bytes so this parser cannot disagree with an upstream proxy.
// ReadSlice bounds each line by bufSize.
func readLine(br *bufio.Reader, budget *int) (string, error) {
	raw, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", fmt.Errorf("header line exceeds %d bytes", bufSize)
	}
	if err != nil {
		return "", err
	}
	if *budget -= len(raw); *budget < 0 {
		return "", fmt.Errorf("headers exceed %d bytes", maxHeaderBytes)
	}
	if len(raw) < 2 || raw[len(raw)-2] != '\r' {
		return "", fmt.Errorf("leanhttp: line not terminated by CRLF")
	}
	// raw aliases bufio storage; string conversion copies it before the next read.
	line := string(raw[:len(raw)-2])
	if !validFieldValue(line) {
		return "", fmt.Errorf("leanhttp: control byte in line %q", line)
	}
	return line, nil
}

// validFieldValue implements RFC 9110 §5.5 for readers and writers: HTAB,
// visible ASCII, and obs-text are allowed; other controls are not.
func validFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// trimOWS removes only RFC 9110 §5.6.3 SP and HTAB, avoiding broader Unicode or
// control-space normalization.
func trimOWS(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// parseDecimal accepts only ASCII digits. The length cap keeps the result in
// int64 and prevents framing differences over signs or alternate syntax.
func parseDecimal(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

// parseHex is the bare-hex equivalent used for chunk sizes.
func parseHex(s string) (int64, bool) {
	if s == "" || len(s) > 15 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		var d int64
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | d
	}
	return n, true
}

// connectionHas searches the Connection comma list for one token.
func connectionHas(header, token string) bool {
	// Cut avoids allocating a slice per request/response.
	for header != "" {
		var part string
		part, header, _ = strings.Cut(header, ",")
		if strings.EqualFold(trimOWS(part), token) {
			return true
		}
	}
	return false
}

// statusCode extracts code and protocol from an HTTP status line.
func statusCode(line string) (int, string, error) {
	proto, rest, found := strings.Cut(line, " ")
	// Distinguish malformed non-HTTP input from a syntactic unsupported version.
	if !found || !strings.HasPrefix(proto, "HTTP/") {
		return 0, "", fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	if proto != "HTTP/1.0" && proto != "HTTP/1.1" {
		// Unknown versions have unknown framing and persistence semantics.
		return 0, "", fmt.Errorf("leanhttp: unsupported protocol in status line %q", line)
	}
	// RFC 9112 §4 requires exactly three bare decimal digits.
	num, _, _ := strings.Cut(rest, " ")
	code, ok := parseDecimal(num)
	if !ok || len(num) != 3 || code < 100 || code > 599 {
		return 0, "", fmt.Errorf("leanhttp: malformed status line %q", line)
	}
	return int(code), proto, nil
}

// body binds framing, bufio read-ahead, and the underlying connection. Close
// aborts blocked reads and returns the connection to a pool only after the body
// end is proven; otherwise unread bytes could become the next status line.
type body struct {
	r    io.Reader
	c    net.Conn
	br   *bufio.Reader
	pool *Client
	key  string

	// deadline also covers bufio read-ahead, which bypasses socket deadlines.
	deadline time.Time

	// mu protects Read completion against concurrent Close cancellation.
	mu   sync.Mutex
	done bool // body end was proven
	shut bool // Close already ran
}

func (b *body) Read(p []byte) (int, error) {
	if !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := b.r.Read(p)
	if err == io.EOF {
		// Only a proven framed end enables pooling. Incomplete framing returns
		// io.ErrUnexpectedEOF; EOF-delimited bodies are never poolable.
		b.mu.Lock()
		b.done = true
		b.mu.Unlock()
	}
	return n, err
}

// lengthReader reads exactly n bytes and converts premature EOF into
// io.ErrUnexpectedEOF.
type lengthReader struct {
	r io.Reader
	n int64

	// connEOF records EOF delivered with the final bytes. The body is complete,
	// but the dead connection cannot be pooled.
	connEOF bool
}

func (l *lengthReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if err == io.EOF {
		l.connEOF = true
		if l.n > 0 {
			return n, io.ErrUnexpectedEOF
		}
		err = nil // Body is complete; the next Read returns clean EOF.
	}
	// At n == 0 the end is proven; the next Read returns EOF.
	return n, err
}

func (b *body) Close() error {
	b.mu.Lock()
	if b.shut {
		b.mu.Unlock()
		return nil
	}
	b.shut = true
	done := b.done
	b.mu.Unlock()
	if !done {
		// Incomplete means close immediately without inspecting a reader that may
		// still be active in another goroutine.
		return b.c.Close()
	}
	// A complete body may still sit on a connection that also returned EOF.
	dead := false
	if lr, ok := b.r.(*lengthReader); ok {
		dead = lr.connEOF
	}
	// Never pool read-ahead bytes after a proven end; they are unsolicited data.
	clean := b.br == nil || b.br.Buffered() == 0
	if b.pool != nil && !dead && clean && b.pool.put(b.key, b.c, b.br) {
		return nil // Connection remains alive in the pool.
	}
	return b.c.Close()
}

// chunkReader decodes hexadecimal size, data, and CRLF chunks, ending at the
// zero chunk plus optional trailers.
type chunkReader struct {
	br   *bufio.Reader
	n    int64 // remaining bytes in the current chunk
	done bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.n == 0 {
		if err := c.next(); err != nil {
			return 0, err
		}
		if c.done {
			return 0, io.EOF
		}
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.br.Read(p)
	c.n -= int64(n)
	if err == io.EOF {
		// Any EOF before the zero chunk is incomplete under RFC 9112 §8.
		err = io.ErrUnexpectedEOF
	}
	if c.n == 0 && err == nil {
		// Consume the chunk's trailing CRLF.
		crlf, err := c.line()
		if err == io.EOF {
			// EOF before trailing CRLF is truncated even when all data bytes arrived.
			return n, io.ErrUnexpectedEOF
		}
		if err != nil {
			return n, err
		}
		if crlf != "" {
			return n, fmt.Errorf("leanhttp: chunk not terminated by CRLF")
		}
	}
	return n, err
}

// line reads one chunk-framing line. Long-lived streams have unbounded chunk
// counts, so only the per-line bufSize applies.
func (c *chunkReader) line() (string, error) {
	budget := bufSize
	return readLine(c.br, &budget)
}

// forbiddenTrailers are RFC 9110 §6.5.1 framing, routing, connection,
// authentication, cache/conditional, and content fields. Fail closed even
// though this parser ignores trailer values, because another hop may not.
var forbiddenTrailers = map[string]bool{
	"transfer-encoding": true, "content-length": true, "host": true,
	"connection": true, "upgrade": true, "te": true, "trailer": true,
	"content-type": true, "content-encoding": true, "content-range": true,
	"cache-control": true, "expect": true, "max-forwards": true,
	"pragma": true, "range": true, "if-match": true, "if-none-match": true,
	"if-modified-since": true, "if-unmodified-since": true, "if-range": true,
	"authorization": true, "www-authenticate": true, "cookie": true,
	"set-cookie": true, "proxy-authenticate": true, "proxy-authorization": true,
	"age": true, "location": true, "retry-after": true, "vary": true,
}

// next reads the next chunk header and sets done after the zero-chunk trailers.
func (c *chunkReader) next() error {
	line, err := c.line()
	if err == io.EOF {
		// A clean connection EOF is still incomplete without a zero chunk.
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	// RFC 9112 §7.1 requires exact 1*HEXDIG with no sign or OWS.
	size, ext, hasExt := strings.Cut(line, ";")
	n, ok := parseHex(size)
	if !ok {
		return fmt.Errorf("leanhttp: malformed chunk size %q", line)
	}
	if hasExt {
		// Deliberate RFC 9112 §7.1.1 deviation: reject all chunk extensions.
		// Safely ignoring them requires a complete quote-aware ABNF parser, and no
		// measured peer sends them; partial validation creates framing ambiguity.
		_ = ext
		return fmt.Errorf("leanhttp: chunk extensions are not supported: %q", line)
	}
	if n == 0 {
		// Consume the finite trailer block under a cumulative budget. Errors before
		// the empty line leave the body incomplete and unpoolable.
		budget := maxHeaderBytes
		for {
			t, err := readLine(c.br, &budget)
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			if err != nil {
				return err
			}
			if t == "" {
				c.done = true
				return nil
			}
			// Trailers use header grammar but may not alter framing or routing.
			k, _, found := strings.Cut(t, ":")
			if !found || !validToken(k) {
				return fmt.Errorf("leanhttp: malformed trailer line %q", t)
			}
			if forbiddenTrailers[strings.ToLower(k)] {
				return fmt.Errorf("leanhttp: forbidden trailer field %q", k)
			}
		}
	}
	c.n = n
	return nil
}
