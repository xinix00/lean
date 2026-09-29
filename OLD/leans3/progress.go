package leans3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// progressConn bounds each blocked transport operation while allowing a long
// S3 transfer to continue for as long as bytes keep moving. The idle policy is
// fixed for the physical connection and therefore survives keep-alive pooling
// without per-request reconfiguration.
type progressConn struct {
	net.Conn

	mu       sync.Mutex
	idle     time.Duration
	readCap  time.Time
	writeCap time.Time
}

func (c *progressConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCap, c.writeCap = t, t
	return c.Conn.SetDeadline(t)
}

func (c *progressConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCap = t
	return c.Conn.SetReadDeadline(t)
}

func (c *progressConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCap = t
	return c.Conn.SetWriteDeadline(t)
}

func (c *progressConn) armRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A wrapped TLS Read may write a post-handshake response, such as a requested
	// TLS 1.3 KeyUpdate. Bound that hidden write to this operation too.
	return c.Conn.SetDeadline(progressDeadline(time.Now(), c.idle, c.readCap))
}

func (c *progressConn) armWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Arm both directions so no stale half-duplex deadline survives into hidden
	// TLS work. The next operation restores its own absolute cap.
	return c.Conn.SetDeadline(progressDeadline(time.Now(), c.idle, c.writeCap))
}

func progressDeadline(now time.Time, idle time.Duration, absolute time.Time) time.Time {
	d := now.Add(idle)
	if !absolute.IsZero() && absolute.Before(d) {
		return absolute
	}
	return d
}

func (c *progressConn) Read(p []byte) (int, error) {
	if err := c.armRead(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	// Some transports report bytes with the timeout that ended the syscall. Those
	// bytes are progress; only an absolute cap makes that timeout terminal.
	if n > 0 && c.renewableTimeout(err, false) {
		err = nil
	}
	return n, err
}

func (c *progressConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		if err := c.armWrite(); err != nil {
			return 0, err
		}
		// Delegate even an empty write: wrappers such as leantls use Write(nil)
		// to report a permanent record error or a connection closed for writing.
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		if err := c.armWrite(); err != nil {
			return total, err
		}
		n, err := c.Conn.Write(p)
		if n > 0 {
			total += n
			p = p[n:]
		}
		switch {
		case err == nil && n > 0:
			continue
		case n > 0 && c.renewableTimeout(err, true):
			// leannet can return partial progress with the deadline that ended this
			// attempt. Renew and finish the same application write.
			continue
		case err != nil:
			return total, err
		default:
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func (c *progressConn) renewableTimeout(err error, write bool) bool {
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
		return false
	}
	c.mu.Lock()
	cap := c.readCap
	if write {
		cap = c.writeCap
	}
	c.mu.Unlock()
	return cap.IsZero() || time.Now().Before(cap)
}

// Grown preserves leannet/leantls bulk classification through the wrapper so
// leanhttp can close a grown connection instead of retaining its buffers.
func (c *progressConn) Grown() bool {
	if g, ok := c.Conn.(interface{ Grown() bool }); ok {
		return g.Grown()
	}
	return false
}

func withProgress(dial func(context.Context, string, string) (net.Conn, error), idle time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil || conn == nil {
			return conn, err
		}
		return &progressConn{Conn: conn, idle: idle}, nil
	}
}
