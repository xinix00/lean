package leannet

import (
	"bytes"
	"testing"
	"time"
)

// TestJumboMSS: twee stacks met MTU 65535 op één prefix moeten segmenten
// van (bijna) 64 KiB uitwisselen — de MSS volgt Config.MTU per bestemming.
func TestJumboMSS(t *testing.T) {
	const mtu = 65535
	da, db := &memDevice{}, &memDevice{}
	da.peer, db.peer = db, da
	a := NewStack(da, Config{IP: [4]byte{10, 0, 0, 1}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 1}, Budget: 8 << 20, MaxBufPerConn: 1 << 20, AdvWS: 4, MTU: mtu}, 1)
	b := NewStack(db, Config{IP: [4]byte{10, 0, 0, 2}, Prefix: 24, MAC: [6]byte{2, 0, 0, 0, 0, 2}, Budget: 8 << 20, MaxBufPerConn: 1 << 20, AdvWS: 4, MTU: mtu}, 2)
	stop := make(chan struct{})
	rx := func(s *Stack, d *memDevice) {
		buf := make([]byte, mtu+EthernetMaximumSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _ := d.Receive(buf)
			if n == 0 {
				time.Sleep(50 * time.Microsecond)
				continue
			}
			s.RecvInboundPacket(buf[:n])
		}
	}
	go rx(a, da)
	go rx(b, db)
	t.Cleanup(func() { close(stop); a.Close(); b.Close() })

	l, err := b.Listen(80)
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 1<<20)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- nil
			return
		}
		buf := make([]byte, 0, len(msg))
		tmp := make([]byte, 128<<10)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for len(buf) < len(msg) {
			n, err := c.Read(tmp)
			if err != nil {
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		got <- buf
	}()
	c, err := a.DialTCP([4]byte{10, 0, 0, 2}, 80, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if g := <-got; !bytes.Equal(g, msg) {
		t.Fatalf("ontvangen %d van %d bytes", len(g), len(msg))
	}
	sa, sb := a.Stats(), b.Stats()
	t.Logf("a: out %d segs %d B (avg %d); b: in %d segs %d B", sa.TCPSegsOut, sa.TCPBytesOut, sa.TCPBytesOut/max(sa.TCPSegsOut, 1), sb.TCPSegsIn, sb.TCPBytesIn)
	if avg := sa.TCPBytesOut / max(sa.TCPSegsOut, 1); avg < 16<<10 {
		t.Fatalf("gemiddeld segment %d B: jumbo-MSS niet onderhandeld", avg)
	}
}
