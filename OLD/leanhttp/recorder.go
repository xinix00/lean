package leanhttp

// recorder.go — the test double for a response, the same idea as
// httptest.ResponseRecorder. It lives in the package rather than in a test
// file because handler tests in every consumer need it, and unlike net/http
// this package has no separate httptest sibling.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
)

// Recorder records what a handler wrote. Use NewRecorder.
type Recorder struct {
	// Code is the status the handler sent; 0 means it never sent one, which is
	// itself worth asserting (a handler that returns without writing leaves the
	// client waiting for the transport's implicit 200).
	Code int

	// Hdr is the response header set.
	Hdr Header

	// Body is everything written. A pointer, like httptest.ResponseRecorder's,
	// so json.NewDecoder(rec.Body) reads without a & at every call site.
	Body *bytes.Buffer

	// Flushes counts Flush calls, so a test can prove a stream actually
	// streamed instead of buffering to the end.
	Flushes int
}

// NewRecorder returns a Recorder ready for use.
func NewRecorder() *Recorder { return &Recorder{Hdr: make(Header, 4), Body: new(bytes.Buffer)} }

func (r *Recorder) Header() Header { return r.Hdr }

func (r *Recorder) WriteHeader(status int) {
	if status < 200 || status > 599 {
		panic("leanhttp: WriteHeader with a non-final status")
	}
	if r.Code == 0 {
		r.Code = status
	}
}

func (r *Recorder) Write(p []byte) (int, error) {
	// A zero-length buffered Write commits nothing; an explicit length takes the
	// real writer's direct path and does commit its implicit 200.
	if len(p) > 0 || r.Hdr.Get("Content-Length") != "" {
		r.WriteHeader(StatusOK)
	}
	return r.Body.Write(p)
}

func (r *Recorder) Flush() error {
	r.WriteHeader(StatusOK)
	r.Flushes++
	return nil
}

// Hijack always fails: a recorder has no connection to take over. A handler
// that needs one needs a real transport.
func (r *Recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("leanhttp: a Recorder has no connection to hijack")
}

// String is the recorded body, for assertions.
func (r *Recorder) String() string { return r.Body.String() }

// NewRequest builds a request for a handler test. target is "/path?query";
// body may be nil for a bodyless request. A non-nil body must expose Len, as
// bytes.Buffer, bytes.Reader, and strings.Reader do, so the synthetic request
// has the same fixed-length framing as a request accepted by this server.
//
// The request has no connection behind it: Done returns a channel that never
// closes and Context never ends, exactly like a client that stays. A test
// that needs cancellation narrows the lifetime with [Request.WithContext].
func NewRequest(method, target string, body io.Reader) *Request {
	u, err := url.ParseRequestURI(target)
	if err != nil || target == "" || target[0] != '/' ||
		!cleanEscapes(u.EscapedPath()) || !canonicalPath(u.Path) {
		panic("leanhttp: invalid NewRequest target " + target)
	}
	header := make(Header, 4)
	length := int64(-1)
	if body == nil {
		body = emptyBody{}
	} else if sized, ok := body.(interface{ Len() int }); ok {
		n := sized.Len()
		if n < 0 {
			panic("leanhttp: NewRequest body has a negative length")
		}
		if n > maxBodyBytes {
			panic("leanhttp: NewRequest body exceeds the server limit")
		}
		length = int64(n)
		header.Set("Content-Length", strconv.FormatInt(length, 10))
		body = &lengthReader{r: body, n: length}
	} else {
		panic("leanhttp: NewRequest body has no known length")
	}
	r := &Request{
		Method:        method,
		Path:          u.Path,
		RawQuery:      u.RawQuery,
		Proto:         "HTTP/1.1",
		Header:        header,
		Body:          body,
		RemoteAddr:    "127.0.0.1:0",
		ContentLength: length,
		done:          make(chan struct{}), // never closed: the "client" stays
	}
	// Burn the once so Done cannot try to claim a connection that is not there.
	r.doneOnce.Do(func() {})
	return r
}

// WithPathValues sets the wildcard values a mux would have captured, so a
// handler can be tested without routing it. It returns r for chaining.
func (r *Request) WithPathValues(kv map[string]string) *Request {
	r.vals = kv
	return r
}
