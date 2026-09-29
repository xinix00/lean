// Package leanhttps provides HTTPS for bare-metal Go by composing [leanhttp]
// with [leantls]. It adds no protocol behavior; it centralizes three error-prone
// integration details:
//
//  1. SNI follows each dial host, including cross-host redirects.
//  2. The caller's explicit pinned-key or certificate-chain trust model reaches
//     leantls unchanged.
//  3. leanhttp invokes the dialer per request and closes redirect connections.
//
// Importing [leanhttp] directly still links no TLS; this package is the sole
// seam between them, and a test protects that composition boundary.
//
// Measured with the same tamago/riscv64 main (`-w -T 0x84010000`, 2026-08-12):
//
//	board + fmt baseline ....................... 2.09 MB
//	net/http + crypto/tls + CA bundle .......... 5.77 MB
//	this package, leantls/x509verify chain ..... 3.75 MB (-2.01)
//	this package, pinned key ................... 2.65 MB (-3.12)
//
// The chain variants both perform HTTPS with certificate validation. Most of
// the saving comes from replacing net/http, which links crypto/tls
// unconditionally.
//
// # Usage
//
// For a known peer without PKI in the image:
//
//	c := leanhttps.Client{TLS: &leantls.Config{PeerKey: leaderKey}}
//	resp, err := c.Get("https://leader.internal/v1/jobs")
//
// For a public server with a certificate chain:
//
//	c := leanhttps.Client{TLS: &leantls.Config{
//	    VerifyPeer:          x509verify.Chain(nil),
//	    SignatureAlgorithms: x509verify.SignatureAlgorithms,
//	}}
//	resp, err := c.Get("https://github.com/org/repo/releases/download/tag/app.elf")
//
// Leave ServerName empty. This package sets it to each connection's dial host;
// a fixed value would incorrectly apply across a redirect chain and is rejected.
package leanhttps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xinix00/lean/leanhttp"
	"github.com/xinix00/lean/leantls"
)

// Client performs HTTPS requests. TLS is mandatory because inventing a default
// trust model would silently defeat peer authentication.
type Client struct {
	// TLS defines trust through PeerKey (pinned) or VerifyPeer (certificate
	// chain). ServerName must remain empty; see the package documentation.
	TLS *leantls.Config

	// Timeout covers one request including its body. Zero allows indefinite
	// streams.
	Timeout time.Duration
}

var errNoConfig = errors.New("leanhttps: Client.TLS is nil — set PeerKey (a pinned peer) or VerifyPeer (a chain); there is no default")

// Get retrieves one URL. Like [leanhttp.Get], it treats non-200 status as an
// error. Use [Client.Do] for other methods.
func (c Client) Get(url string) (*leanhttp.Response, error) {
	call, err := c.call(leanhttp.Call{URL: url})
	if err != nil {
		return nil, err
	}
	return leanhttp.GetCall(call)
}

// Do executes one request. Like [leanhttp.Do], it returns error statuses to the
// caller rather than treating them as Go errors.
func (c Client) Do(call leanhttp.Call) (*leanhttp.Response, error) {
	call, err := c.call(call)
	if err != nil {
		return nil, err
	}
	return leanhttp.Do(call)
}

// DialerContext returns the TLS dialer for a [leanhttp.Client], enabling pooled
// keep-alive over TLS.
//
//	pool := &leanhttp.Client{DialContext: leanhttps.DialerContext(tlsCfg)}
//
// It does not mutate cfg and derives ServerName from each dial address.
func DialerContext(cfg *leantls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return Client{TLS: cfg}.dial
}

// call attaches the TLS dialer to a leanhttp.Call.
func (c Client) call(call leanhttp.Call) (leanhttp.Call, error) {
	if c.TLS == nil {
		return call, errNoConfig
	}
	if c.TLS.ServerName != "" {
		return call, fmt.Errorf("leanhttps: leave Config.ServerName empty (%q) — "+
			"this package sets it per connection, so it follows a redirect to another host",
			c.TLS.ServerName)
	}
	if call.Timeout == 0 {
		call.Timeout = c.Timeout
	}
	// DialContext carries the total deadline through TCP dial and handshake, so
	// canceled HTTP work cannot leave a live dial behind.
	call.DialContext = c.dial
	return call, nil
}

// dial creates an encrypted connection, deriving SNI from the current dial
// address rather than the original URL.
func (c Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.TLS == nil {
		// DialerContext(nil) bypasses call, so preserve a readable dial error
		// instead of panicking on c.TLS below.
		return nil, errNoConfig
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// Certificate chains need a name; pinned keys already supply identity.
	if c.TLS.PeerKey == nil && net.ParseIP(host) != nil {
		return nil, fmt.Errorf("leanhttps: %s is an IP address, so there is no name to verify a "+
			"chain against — use a hostname, or pin the peer's key", host)
	}
	cfg := *c.TLS // Copy: dialing must not mutate caller configuration.
	cfg.ServerName = strings.TrimSuffix(host, ".")
	return leantls.DialContext(ctx, network, addr, &cfg)
}
