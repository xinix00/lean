package leans3

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

var errStaleWriteDeadline = errors.New("write used the stale operation deadline")

// deadlineTraceConn models the raw transport beneath TLS. After the request
// write, a hidden TLS write succeeds only when the outer Read refreshed the
// write deadline too.
type deadlineTraceConn struct {
	mu sync.Mutex

	readDeadline  time.Time
	writeDeadline time.Time
	deadlineGen   uint64
	writeGen      uint64
	requestGen    uint64
	writes        int
}

func (*deadlineTraceConn) Read([]byte) (int, error) {
	return 0, errors.New("unexpected raw read")
}

func (c *deadlineTraceConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 1 {
		c.requestGen = c.writeGen
		return len(p), nil
	}
	if c.writeGen <= c.requestGen {
		return 0, errStaleWriteDeadline
	}
	return len(p), nil
}

func (*deadlineTraceConn) Close() error { return nil }

func (*deadlineTraceConn) LocalAddr() net.Addr  { return progressTestAddr("local") }
func (*deadlineTraceConn) RemoteAddr() net.Addr { return progressTestAddr("remote") }

func (c *deadlineTraceConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineGen++
	c.readDeadline = t
	c.writeDeadline = t
	c.writeGen = c.deadlineGen
	c.mu.Unlock()
	return nil
}

func (c *deadlineTraceConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineGen++
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *deadlineTraceConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineGen++
	c.writeDeadline = t
	c.writeGen = c.deadlineGen
	c.mu.Unlock()
	return nil
}

func (c *deadlineTraceConn) deadlines() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline, c.writeDeadline
}

type progressTestAddr string

func (a progressTestAddr) Network() string { return "progress-test" }
func (a progressTestAddr) String() string  { return string(a) }

// tlsKeyUpdateConn models leantls.Conn.Read: a requested post-handshake
// KeyUpdate writes its answer directly to the raw connection before returning
// application bytes.
type tlsKeyUpdateConn struct{ raw *deadlineTraceConn }

func (c *tlsKeyUpdateConn) Read(p []byte) (int, error) {
	if _, err := c.raw.Write([]byte("key-update")); err != nil {
		return 0, err
	}
	return copy(p, "x"), nil
}

func (c *tlsKeyUpdateConn) Write(p []byte) (int, error) { return c.raw.Write(p) }
func (c *tlsKeyUpdateConn) Close() error                { return c.raw.Close() }
func (c *tlsKeyUpdateConn) LocalAddr() net.Addr         { return c.raw.LocalAddr() }
func (c *tlsKeyUpdateConn) RemoteAddr() net.Addr        { return c.raw.RemoteAddr() }
func (c *tlsKeyUpdateConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}
func (c *tlsKeyUpdateConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}
func (c *tlsKeyUpdateConn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

func TestProgressConnReadRefreshesHiddenTLSWriteDeadline(t *testing.T) {
	raw := &deadlineTraceConn{}
	pc := &progressConn{Conn: &tlsKeyUpdateConn{raw: raw}, idle: time.Second}

	if _, err := pc.Write([]byte("request")); err != nil {
		t.Fatalf("request write: %v", err)
	}
	buf := make([]byte, 1)
	if n, err := pc.Read(buf); err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("read na verborgen TLS-write = %d, %v, %q", n, err, buf[:n])
	}
}

func TestProgressConnCapsPerOperationEnKanZeWissen(t *testing.T) {
	raw := &deadlineTraceConn{}
	pc := &progressConn{Conn: raw, idle: 24 * time.Hour}
	readCap := time.Now().Add(time.Minute)
	writeCap := readCap.Add(time.Minute)

	if err := pc.SetReadDeadline(readCap); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetWriteDeadline(writeCap); err != nil {
		t.Fatal(err)
	}
	if err := pc.armRead(); err != nil {
		t.Fatal(err)
	}
	if gotRead, gotWrite := raw.deadlines(); !gotRead.Equal(readCap) || !gotWrite.Equal(readCap) {
		t.Fatalf("read-arm deadlines = (%v, %v), wil %v op beide", gotRead, gotWrite, readCap)
	}
	if err := pc.armWrite(); err != nil {
		t.Fatal(err)
	}
	if gotRead, gotWrite := raw.deadlines(); !gotRead.Equal(writeCap) || !gotWrite.Equal(writeCap) {
		t.Fatalf("write-arm deadlines = (%v, %v), wil %v op beide", gotRead, gotWrite, writeCap)
	}
	if err := pc.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if gotRead, gotWrite := raw.deadlines(); !gotRead.IsZero() || !gotWrite.IsZero() {
		t.Fatalf("deadline-reset liet (%v, %v) achter", gotRead, gotWrite)
	}
}

type grownProgressConn struct{ *deadlineTraceConn }

func (*grownProgressConn) Grown() bool { return true }

func TestProgressConnGeeftGrownDoor(t *testing.T) {
	pc := &progressConn{Conn: &grownProgressConn{&deadlineTraceConn{}}, idle: time.Second}
	if !pc.Grown() {
		t.Fatal("progress-wrapper verborg Grown")
	}
}

type stickyZeroWriteConn struct{ *deadlineTraceConn }

func (*stickyZeroWriteConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

func TestProgressConnDelegeertLegeWrite(t *testing.T) {
	pc := &progressConn{Conn: &stickyZeroWriteConn{&deadlineTraceConn{}}, idle: time.Second}
	if _, err := pc.Write(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write(nil) = %v, wil onderliggende sticky fout", err)
	}
}
