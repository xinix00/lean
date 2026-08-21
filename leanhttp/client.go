package leanhttp

// client.go implements client-side keep-alive with one pool per host. The pool
// is logic-only and therefore adds no linked cost when Client is unused.
//
// Its central safety rule lives in body.Close: only reuse a connection after
// reading the response body to EOF. Otherwise the next request could parse the
// unread response tail as its status line. When uncertain, close it.

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"
)

// Two idle connections support parallel page resources without flooding the
// server. Thirty seconds stays well below common server-side idle timeouts.
const (
	defaultMaxIdlePerHost = 2
	defaultIdleTimeout    = 30 * time.Second

	// A global cap prevents a burst of unique hosts from reserving leannet's
	// entire buffer budget until the idle timeout.
	defaultMaxIdleTotal = 8
)

// Client performs requests with keep-alive. It is safe for concurrent use; its
// zero value uses the standard dialer, two idle connections per host, and a
// 30-second idle timeout.
//
// Package-level [Do] and [Get] still use one connection per request.
type Client struct {
	// DialContext creates a connection; nil uses the standard tcp4 dialer. It
	// shares [Call.DialContext]'s contract, so a TLS dialer can be pooled too.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// MaxIdlePerHost limits unused connections per host; 0 means 2.
	MaxIdlePerHost int

	// MaxIdleTotal limits unused connections across all hosts; 0 means 8.
	MaxIdleTotal int

	// IdleTimeout controls how long an unused connection is retained; 0 means
	// 30 seconds, deliberately below common server-side values.
	IdleTimeout time.Duration

	mu   sync.Mutex
	idle map[string][]idleConn

	// sweepTimer releases idle connections even when no later request triggers
	// dial's sweep. On leannet each one can retain at least 20 KiB of budget.
	sweepTimer *time.Timer
}

type idleConn struct {
	c    net.Conn
	br   *bufio.Reader // belongs to the connection, not the request
	when time.Time
}

// Do performs one request through the pool. Like [Do], it does not treat an
// error status as a transport error.
func (cl *Client) Do(call Call) (*Response, error) {
	if call.DialContext != nil {
		// A per-call transport must not enter the pool: a later request could
		// otherwise receive a connection from a different transport.
		return Do(call)
	}
	// Pass the transport separately: do() uses via.Dial for scheme validation
	// and via.dial for pooling, so it cannot masquerade as Call.DialContext.
	return doVia(call, cl)
}

// Get is [Get] over the pool and requires status 200 with Content-Length.
func (cl *Client) Get(url string) (*Response, error) {
	resp, err := doVia(Call{URL: url}, cl)
	if err != nil {
		return nil, err
	}
	return checkGet(resp)
}

// CloseIdle closes all unused connections without affecting active requests.
func (cl *Client) CloseIdle() {
	cl.mu.Lock()
	idle := cl.idle
	cl.idle = nil
	cl.mu.Unlock()
	for _, list := range idle {
		for _, ic := range list {
			ic.c.Close()
		}
	}
}

// dial returns a pooled connection or creates one through the normalized
// dialer. The context carries call cancellation and its earliest total deadline.
//
// Sweep before dialing: expired pooled connections may exhaust the network
// budget and make the dial fail, so a sweep in put would never be reached.
func (cl *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// Sweep and pop share a critical section, making every remaining connection
	// fresh by definition.
	cl.mu.Lock()
	stale := cl.sweepLocked()
	cl.mu.Unlock()
	for _, ic := range stale {
		// Close outside the lock. A graceful close may retain buffers until its
		// FIN completes, so an immediate dial may need its normal retry.
		ic.c.Close()
	}
	for {
		cl.mu.Lock()
		c, br := cl.popLocked(addr)
		cl.mu.Unlock()
		if c == nil {
			break
		}
		// Reject already-buffered unsolicited data. Do not probe with Read: it
		// corrupts stateful TLS readers, races later arrivals, and would require
		// a permanent read-loop owner. Retrying handles a closed idle connection
		// for GET/HEAD, but cannot distinguish a valid unsolicited response; the
		// origin is therefore required to be protocol-correct. See KAM.md.
		if br.Buffered() == 0 {
			return &pooledConn{Conn: c, br: br}, nil
		}
		c.Close()
	}
	return normalizeDial(cl.DialContext)(ctx, network, addr)
}

// popLocked returns the warmest connection for addr. dial already swept the
// pool in the same critical section. cl.mu must be held.
func (cl *Client) popLocked(addr string) (net.Conn, *bufio.Reader) {
	list := cl.idle[addr]
	if len(list) == 0 {
		return nil, nil
	}
	ic := list[len(list)-1] // most recently returned is warmest
	if len(list) == 1 {
		delete(cl.idle, addr)
	} else {
		cl.idle[addr] = list[:len(list)-1]
	}
	return ic.c, ic.br
}

// put returns a fully consumed connection. False means the pool rejected it
// and the caller must close it.
func (cl *Client) put(addr string, c net.Conn, br *bufio.Reader) bool {
	// Unwrap before storing; otherwise each reuse adds another pooledConn layer
	// and every Read eventually traverses an unbounded chain.
	if pc, ok := c.(*pooledConn); ok {
		c = pc.Conn
	}
	// "Fast always has an end": a connection whose rings grew was a bulk
	// transfer, and its advertised window pins budget for as long as it idles
	// open (leannet: the promise cannot shrink left). Close it instead of
	// pooling — the promise dies with the close and the budget returns at
	// once. Slow streams (SSE, chat) never grow and pool as always. The cost
	// is one fresh handshake per bulk reuse — exactly the rare, already
	// expensive case.
	if g, ok := c.(interface{ Grown() bool }); ok && g.Grown() {
		return false
	}
	max := cl.MaxIdlePerHost
	if max == 0 {
		max = defaultMaxIdlePerHost
	}
	maxTotal := cl.MaxIdleTotal
	if maxTotal == 0 {
		maxTotal = defaultMaxIdleTotal
	}
	// Never carry a previous request's deadline into the next one. A transport
	// that cannot clear it is not reusable.
	if c.SetDeadline(time.Time{}) != nil {
		return false
	}
	// dial already sweeps before every request; the timer covers inactivity.
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(cl.idle[addr]) >= max {
		return false
	}
	total := 0
	for _, list := range cl.idle {
		total += len(list)
	}
	if total >= maxTotal {
		return false
	}
	if cl.idle == nil {
		cl.idle = make(map[string][]idleConn)
	}
	cl.idle[addr] = append(cl.idle[addr], idleConn{c: c, br: br, when: time.Now()})
	cl.scheduleSweepLocked()
	return true
}

// scheduleSweepLocked keeps one timer active while the pool is non-empty. The
// margin avoids firing just before expiry; retention remains below roughly
// twice the idle timeout. cl.mu must be held.
func (cl *Client) scheduleSweepLocked() {
	if cl.sweepTimer != nil {
		return
	}
	timeout := cl.IdleTimeout
	if timeout == 0 {
		timeout = defaultIdleTimeout
	}
	cl.sweepTimer = time.AfterFunc(timeout+timeout/4, cl.timedSweep)
}

// timedSweep closes expired connections and reschedules while any remain.
func (cl *Client) timedSweep() {
	cl.mu.Lock()
	cl.sweepTimer = nil
	stale := cl.sweepLocked()
	if len(cl.idle) > 0 {
		cl.scheduleSweepLocked()
	}
	cl.mu.Unlock()
	for _, ic := range stale {
		ic.c.Close()
	}
}

// sweepLocked removes expired connections for every host and returns them for
// closing. cl.mu must be held.
//
// Sweeping only the requested host leaked idle connections to hosts never used
// again. This matters on leannet, where open connections retain and grow their
// buffer allocation. It once exhausted a LicheeRV node's budget after image
// downloads and prevented the watchdog from opening its heartbeat connection.
func (cl *Client) sweepLocked() []idleConn {
	timeout := cl.IdleTimeout
	if timeout == 0 {
		timeout = defaultIdleTimeout
	}
	now := time.Now() // one clock read for the entire sweep
	var stale []idleConn
	for addr, list := range cl.idle {
		keep := list[:0]
		for _, ic := range list {
			if now.Sub(ic.when) < timeout {
				keep = append(keep, ic)
				continue
			}
			stale = append(stale, ic)
		}
		if len(keep) == 0 {
			delete(cl.idle, addr)
			continue
		}
		cl.idle[addr] = keep
	}
	return stale
}

// pooledConn preserves the bufio.Reader attached to a reused connection so
// already-buffered bytes are not lost.
type pooledConn struct {
	net.Conn
	br *bufio.Reader
}

// idleCount and idleFor expose pool state only to package tests.
func (cl *Client) idleCount() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	n := 0
	for _, list := range cl.idle {
		n += len(list)
	}
	return n
}

func (cl *Client) idleFor(addr string) int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return len(cl.idle[addr])
}
