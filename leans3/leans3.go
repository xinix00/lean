// Package leans3 implements SigV4 signing and the S3 object operations GET,
// PUT, DELETE, and LIST, including streaming bodies and conditional ETag-based
// CAS traffic.
//
// It replaces two custom SigV4 implementations in one stack:
//
//	hoplock/s3/sigv4.go .......................... ~200 lines, complete
//	hop/internal/runner/download_s3.go ........... ~100 lines, GET only
//
// The smaller copy omitted URI escaping, session tokens, and path-style
// addressing. Spaces or `+` in a key therefore produced invalid signatures.
//
// Avoiding net/http also matters because it links crypto/tls unconditionally.
// For the same signed HTTPS GET on darwin/arm64 with Go 1.26.4 and
// `-ldflags=-w` (2026-08-12):
//
//	net/http + crypto/tls .............. 5.68 MB (without signing)
//	this package over leanhttps ........ 3.95 MB (-1.73, including signing)
//
// # Deliberate limits
//
// There are no streaming signatures, SigV4a, presigned URLs, IMDS/IAM
// credentials, multipart upload, versioning, object lock, or tagging. PUT uses
// a known Content-Length and payload hash; [Client.PutFrom] rejects a missing
// hash rather than silently choosing [UnsignedPayload]. One object maps to one
// request; orchestration and provider-specific retry policy belong above it.
//
// # Contexts
//
// Operations map a [context.Context] deadline to leanhttp Call.Timeout and
// reject an already canceled context. Bare cancellation after a call starts is
// not observed: leanhttp has no context seam, and closing one request's pooled
// connection safely would require a watcher goroutine per call.
//
// # Composition
//
// leans3 is a protocol block, not a composition, so it imports leanhttps rather
// than duplicating its SNI and trust-model seam. This means a plain-HTTP MinIO
// consumer still links the reachable PKI path.
package leans3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xinix00/lean/leanhttp"
	"github.com/xinix00/lean/leanhttps"
	"github.com/xinix00/lean/leantls"
	"github.com/xinix00/lean/leantls/x509verify"
)

// HTTP methods used here; leanhttp intentionally has no method constants.
const (
	methodGet    = "GET"
	methodPut    = "PUT"
	methodDelete = "DELETE"
)

// Status codes not named by leanhttp.
const (
	statusConflict           = 409
	statusPreconditionFailed = 412
)

// UnsignedPayload marks content excluded from the signature. Use it only with
// [Client.PutFrom] over HTTPS for non-replayable sources. Without TLS the body
// is mutable in transit, and several providers reject it for writes.
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// Sentinel errors represent expected protocol outcomes rather than outages.
var (
	// ErrNotFound reports a 404 for an absent key.
	ErrNotFound = errors.New("leans3: no such key")

	// ErrPreconditionFailed reports a 412, or a provider's 409 for a concurrent
	// If-None-Match race. Nothing was written.
	ErrPreconditionFailed = errors.New("leans3: precondition failed")
)

// StatusError represents any other unsuccessful response. Body retains a
// bounded prefix because S3 reports causes such as SignatureDoesNotMatch and
// AccessDenied in XML.
type StatusError struct {
	Op     string // "GET", "PUT", "DELETE", "LIST"
	Key    string // affected key or prefix
	Code   int    // 403, 500, …
	Status string // wire status, such as "403 Forbidden"
	Body   string // trimmed response-body prefix
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("leans3: %s %s: status %s: %s", e.Op, e.Key, e.Status, e.Body)
}

// Client accesses one bucket at one endpoint and is safe for concurrent use.
// Configure it as a struct literal, then use it by pointer without copying: it
// owns a keep-alive pool that avoids a TCP and TLS handshake per request.
type Client struct {
	// Endpoint is the service base URL, for example
	// "https://s3.us-east-1.amazonaws.com" of
	// "https://<account>.r2.cloudflarestorage.com". Required.
	Endpoint string

	// Bucket is the required bucket name.
	Bucket string

	// Region is the required credential-scope region; use "auto" for R2.
	Region string

	// AccessKeyID and SecretAccessKey are required static credentials.
	AccessKeyID     string
	SecretAccessKey string

	// SessionToken is sent as X-Amz-Security-Token when set (STS).
	SessionToken string

	// UsePathStyle puts the bucket in the path instead of the hostname. MinIO and
	// most non-AWS providers require it; R2 supports both forms.
	UsePathStyle bool

	// Dial overrides connection setup for proxies, Unix sockets, or tests. Nil
	// selects certificate-validating TLS for HTTPS and plain TCP for HTTP.
	// Overriding an HTTPS dialer also assumes responsibility for encryption.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Now overrides signature time. Nil uses time.Now; tests need this seam for
	// deterministic signatures.
	Now func() time.Time

	mu   sync.Mutex
	pool *leanhttp.Client
}

// request holds one outbound call before signing. Keeping method, URL, and
// headers together prevents the signed request from diverging from the wire.
type request struct {
	op     string // operation name for errors
	key    string // key or prefix for errors
	method string
	url    *url.URL
	header leanhttp.Header // may be nil

	// Set either body for in-memory payloads or stream plus streamLen.
	body      []byte
	stream    io.Reader
	streamLen int64

	// payloadHash is the body's hexadecimal SHA-256 or [UnsignedPayload].
	payloadHash string
}

// do signs r and sends it through the Client's pool.
//
// Host, Content-Length, Connection, and Accept-Encoding stay out of r.header;
// leanhttp owns them and canonicalRequest signs accordingly.
func (c *Client) do(ctx context.Context, r request) (*leanhttp.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hdr := r.header
	if hdr == nil {
		hdr = leanhttp.Header{}
	}
	signRequest(r.method, r.url, hdr, credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Region:          c.Region,
	}, r.payloadHash, c.now())

	pool, err := c.client()
	if err != nil {
		return nil, err
	}
	resp, err := pool.Do(leanhttp.Call{
		Method:     r.method,
		URL:        r.url.String(),
		Header:     hdr,
		Body:       r.body,
		BodyReader: r.stream,
		BodyLen:    r.streamLen,
		Timeout:    timeoutFor(ctx),
		// A SigV4 signature covers this host and path. Following a redirect would
		// invalidate it and could leak signed headers such as a session token.
		NoFollow: true,
	})
	if err != nil {
		return nil, fmt.Errorf("leans3: %s %s: %w", r.op, r.key, err)
	}
	// leanhttp centrally handles bodyless 204 and 304 responses (RFC 9112 §6.3),
	// preventing S3 DELETE from waiting until the server's idle timeout.
	return resp, nil
}

// fail maps an unsuccessful response to its error while bounding body reads.
func (c *Client) fail(op, key string, resp *leanhttp.Response) error {
	switch resp.StatusCode {
	case leanhttp.StatusNotFound, statusPreconditionFailed, statusConflict:
		// Expected misses and CAS races are common. Drain their small XML bodies
		// within bounds to keep the TLS connection reusable; larger bodies close it.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		if resp.StatusCode == leanhttp.StatusNotFound {
			return ErrNotFound
		}
		return ErrPreconditionFailed
	}
	const maxBody = 4 << 10
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &StatusError{
		Op:     op,
		Key:    key,
		Code:   resp.StatusCode,
		Status: resp.Status,
		Body:   strings.TrimSpace(string(body)),
	}
}

// client returns the lazily constructed connection pool.
func (c *Client) client() (*leanhttp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pool == nil {
		dial, err := c.dialer()
		if err != nil {
			return nil, err
		}
		c.pool = &leanhttp.Client{DialContext: dial}
	}
	return c.pool, nil
}

// dialer selects transport from Endpoint. Nil means leanhttp's plain HTTP dial.
//
// Nil roots use x509.SystemCertPool: the host trust store or roots embedded in
// a bare-metal image. There is deliberately no skip-verify option.
func (c *Client) dialer() (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if c.Dial != nil {
		return c.Dial, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("leans3: parse Endpoint: %w", err)
	}
	switch u.Scheme {
	case "https":
		return leanhttps.DialerContext(&leantls.Config{
			VerifyPeer:          x509verify.Chain(nil),
			SignatureAlgorithms: x509verify.SignatureAlgorithms,
		}), nil
	case "http":
		return nil, nil
	default:
		return nil, fmt.Errorf("leans3: Endpoint scheme must be http or https, got %q", u.Scheme)
	}
}

// CloseIdle closes unused pooled connections without affecting active requests.
func (c *Client) CloseIdle() {
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()
	if pool != nil {
		pool.CloseIdle()
	}
}

// timeoutFor maps a context deadline to leanhttp's per-call timeout.
func timeoutFor(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	if d := time.Until(deadline); d > 0 {
		return d
	}
	return time.Nanosecond // Already expired: fail on first I/O instead of blocking.
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// URLFor returns the request URL for key using this Client's addressing style.
// It supports custom operations without duplicating path/host-style logic.
func (c *Client) URLFor(key string) (*url.URL, error) {
	if key == "" {
		return nil, errors.New("leans3: key is required")
	}
	u, err := c.bucketURL()
	if err != nil {
		return nil, err
	}
	u.Path += strings.TrimPrefix(key, "/")
	return u, nil
}

// bucketURL returns the trailing-slash bucket URL without a key. URLFor extends
// it; LIST uses it directly.
func (c *Client) bucketURL() (*url.URL, error) {
	if c.Endpoint == "" {
		return nil, errors.New("leans3: Endpoint is required")
	}
	if c.Bucket == "" {
		return nil, errors.New("leans3: Bucket is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("leans3: parse Endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("leans3: Endpoint must include scheme and host: %q", c.Endpoint)
	}
	if c.UsePathStyle {
		u.Path = "/" + c.Bucket + "/"
	} else {
		u.Host = c.Bucket + "." + u.Host
		u.Path = "/"
	}
	return u, nil
}
