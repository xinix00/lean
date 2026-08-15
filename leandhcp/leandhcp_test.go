package leandhcp

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type testNIC struct {
	mu    sync.Mutex
	rx    [][]byte
	tx    [][]byte
	rxErr error
	txErr error
	flood []byte

	onTX func(n *testNIC, frame []byte)
}

func (n *testNIC) Transmit(buf []byte) error {
	if n.txErr != nil {
		return n.txErr
	}
	cp := append([]byte(nil), buf...)
	n.mu.Lock()
	n.tx = append(n.tx, cp)
	f := n.onTX
	n.mu.Unlock()
	if f != nil {
		f(n, cp)
	}
	return nil
}

func (n *testNIC) Receive(buf []byte) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.flood != nil {
		return copy(buf, n.flood), n.rxErr
	}
	if len(n.rx) == 0 {
		return 0, n.rxErr
	}
	f := n.rx[0]
	n.rx = n.rx[1:]
	return copy(buf, f), n.rxErr
}

func (n *testNIC) push(frame []byte) {
	n.mu.Lock()
	n.rx = append(n.rx, frame)
	n.mu.Unlock()
}

func (n *testNIC) sent() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][]byte(nil), n.tx...)
}

func reply(req []byte, msgtype byte, yiaddr [4]byte, extra []byte) []byte {
	bp := req[42:]
	xid := be32(bp[4:8])
	var mac [6]byte
	copy(mac[:], bp[28:34])

	f := make([]byte, 14+20+8+300)
	copy(f[0:6], mac[:])
	copy(f[6:12], []byte{2, 0, 0, 0, 0, 9})
	f[12], f[13] = 0x08, 0x00

	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	tot := len(f) - 14
	ip[2], ip[3] = byte(tot>>8), byte(tot)
	copy(ip[12:16], []byte{192, 168, 1, 1})
	copy(ip[16:20], yiaddr[:])
	cs := checksum(ip)
	ip[10], ip[11] = byte(cs>>8), byte(cs)

	udp := f[34:42]
	udp[1], udp[3] = 67, 68
	ul := tot - 20
	udp[4], udp[5] = byte(ul>>8), byte(ul)

	out := f[42:]
	out[0], out[1], out[2] = 2, 1, 6
	out[4], out[5], out[6], out[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)
	copy(out[16:20], yiaddr[:])
	copy(out[28:34], mac[:])
	copy(out[236:240], []byte{99, 130, 83, 99})
	copy(out[240:], append(append([]byte{53, 1, msgtype}, extra...), 255))
	return f
}

var lessor = []byte{
	1, 4, 255, 255, 255, 0,
	3, 4, 192, 168, 1, 1,
	6, 4, 192, 168, 1, 1,
	54, 4, 192, 168, 1, 1,
	51, 4, 0, 0, 0x0e, 0x10,
	58, 4, 0, 0, 0x07, 0x08,
	59, 4, 0, 0, 0x0c, 0x4e,
}

func dhcpServer(yiaddr [4]byte) func(*testNIC, []byte) {
	return func(n *testNIC, frame []byte) {
		switch msgTypeOf(frame) {
		case msgDiscover:
			n.push(reply(frame, msgOffer, yiaddr, lessor))
		case msgRequest:
			n.push(reply(frame, msgACK, yiaddr, lessor))
		}
	}
}

func msgTypeOf(frame []byte) byte {
	opts := frame[42+240:]
	for i := 0; i+1 < len(opts); {
		if opts[i] == 0 {
			i++
			continue
		}
		if opts[i] == 255 {
			return 0
		}
		ln := int(opts[i+1])
		if opts[i] == 53 && ln == 1 {
			return opts[i+2]
		}
		i += 2 + ln
	}
	return 0
}

func TestAcquireDORA(t *testing.T) {
	nic := &testNIC{onTX: dhcpServer([4]byte{192, 168, 1, 33})}
	l, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Acquired {
		t.Error("Acquired is false na een ACK")
	}
	if got := l.CIDR(); got != "192.168.1.33/24" {
		t.Errorf("CIDR = %q", got)
	}
	if l.GWString() != "192.168.1.1" || l.DNSString() != "192.168.1.1" {
		t.Errorf("gw %s dns %s", l.GWString(), l.DNSString())
	}
	if l.Server != ([4]byte{192, 168, 1, 1}) {
		t.Errorf("Server = %v", l.Server)
	}
	if l.LeaseSecs != 3600 || l.T1Secs != 1800 || l.T2Secs != 3150 {
		t.Errorf("timers = %d/%d/%d, want 3600/1800/3150", l.LeaseSecs, l.T1Secs, l.T2Secs)
	}

	tx := nic.sent()
	if len(tx) != 2 {
		t.Fatalf("%d pakketten verstuurd, want 2", len(tx))
	}
	if msgTypeOf(tx[0]) != msgDiscover || msgTypeOf(tx[1]) != msgRequest {
		t.Fatalf("types %d en %d, want DISCOVER en REQUEST", msgTypeOf(tx[0]), msgTypeOf(tx[1]))
	}
	if be32(tx[0][46:50]) != be32(tx[1][46:50]) {
		t.Error("REQUEST gebruikte een andere xid dan de DISCOVER van dezelfde ronde")
	}

	if !hasOption(tx[1], 50, []byte{192, 168, 1, 33}) {
		t.Error("REQUEST bevestigt het aangeboden IP niet (optie 50)")
	}
	if !hasOption(tx[1], 54, []byte{192, 168, 1, 1}) {
		t.Error("REQUEST noemt de server niet (optie 54)")
	}
}

func hasOption(frame []byte, code byte, want []byte) bool {
	opts := frame[42+240:]
	for i := 0; i+1 < len(opts); {
		if opts[i] == 0 {
			i++
			continue
		}
		if opts[i] == 255 {
			return false
		}
		ln := int(opts[i+1])
		if i+2+ln > len(opts) {
			return false
		}
		if opts[i] == code && string(opts[i+2:i+2+ln]) == string(want) {
			return true
		}
		i += 2 + ln
	}
	return false
}

func TestDiscoverVorm(t *testing.T) {
	nic := &testNIC{}
	Acquire(nic, [6]byte{2, 0, 0, 0, 0, 7}, 10*time.Millisecond)
	tx := nic.sent()
	if len(tx) == 0 {
		t.Fatal("niets verstuurd")
	}
	f := tx[0]
	for i := range 6 {
		if f[i] != 0xff {
			t.Fatalf("dst = %x, want broadcast", f[:6])
		}
	}
	if string(f[6:12]) != string([]byte{2, 0, 0, 0, 0, 7}) {
		t.Errorf("src = %x, want ons MAC", f[6:12])
	}
	if f[12] != 0x08 || f[13] != 0x00 {
		t.Errorf("ethertype = %x, want IPv4", f[12:14])
	}
	if checksum(f[14:34]) != 0 {
		t.Error("IP-header-checksum klopt niet")
	}
	if int(f[16])<<8|int(f[17]) != len(f)-14 {
		t.Error("IP total length dekt het frame niet")
	}
	if f[35] != 68 || f[37] != 67 {
		t.Errorf("UDP-poorten %d→%d, want 68→67", f[35], f[37])
	}
	if f[42] != 1 || f[43] != 1 || f[44] != 6 {
		t.Error("BOOTP-kop is geen BOOTREQUEST over ethernet")
	}
	if f[52]&0x80 == 0 {
		t.Error("broadcast-flag staat uit — het antwoord komt dan als unicast en " +
			"kan op het RX-filter stuklopen")
	}
	if string(f[42+236:42+240]) != string([]byte{99, 130, 83, 99}) {
		t.Error("DHCP-magic ontbreekt")
	}

	if !hasOption(f, 55, []byte{1, 3, 6, 51, 58, 59}) {
		t.Error("parameter-request (optie 55) vraagt niet om 1/3/6/51/58/59")
	}
}

func TestAcquireGeenServer(t *testing.T) {
	nic := &testNIC{}
	start := time.Now()
	_, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("lease uit een leeg segment")
	}
	if !strings.Contains(err.Error(), "no server answered") {
		t.Errorf("err = %v", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("Acquire duurde %v op een timeout van 200ms", elapsed)
	}
}

func TestAcquireNICFout(t *testing.T) {
	boom := errors.New("rx ring desync")
	nic := &testNIC{rxErr: boom}
	_, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 150*time.Millisecond)
	if err == nil {
		t.Fatal("geen fout")
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v — de RX-fout van de NIC hoort mee naar boven", err)
	}
}

func TestAcquireTXFout(t *testing.T) {
	nic := &testNIC{txErr: errors.New("link down")}
	start := time.Now()
	if _, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 10*time.Second); err == nil {
		t.Fatal("geen fout")
	}
	if time.Since(start) > time.Second {
		t.Error("Acquire bleef pollen terwijl zenden faalde")
	}
}

func TestAcquireLaatsteTick(t *testing.T) {
	nic := &testNIC{}
	nic.onTX = func(n *testNIC, frame []byte) {
		switch msgTypeOf(frame) {
		case msgDiscover:
			n.push(reply(frame, msgOffer, [4]byte{192, 168, 1, 44}, lessor))
		case msgRequest:

			time.Sleep(120 * time.Millisecond)
			n.push(reply(frame, msgACK, [4]byte{192, 168, 1, 44}, lessor))
		}
	}
	start := time.Now()
	l, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("een verkregen lease werd als timeout gemeld: %v", err)
	}
	if l.IP != ([4]byte{192, 168, 1, 44}) {
		t.Errorf("IP = %v", l.IP)
	}

	if d := time.Since(start); d > 50*time.Millisecond+ackGrace+time.Second {
		t.Errorf("Acquire duurde %v — de grace hoort begrensd te zijn", d)
	}
}

func TestAwaitLeestWatErAlLigt(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	req := packet(mac, 0x484F5001, msgRequest, nil)
	nic := &testNIC{}
	nic.push(reply(req, msgACK, [4]byte{10, 1, 2, 3}, lessor))

	l, ok, err := await(nic, mac, 0x484F5001, msgACK, time.Now().Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("await negeerde een antwoord dat al in de ring lag")
	}
	if l.IP != ([4]byte{10, 1, 2, 3}) {
		t.Errorf("IP = %v", l.IP)
	}
}

func TestAwaitStormLoopt(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	junk := make([]byte, 300)
	nic := &testNIC{flood: junk}

	done := make(chan struct{})
	go func() {
		await(nic, mac, 1, msgACK, time.Now().Add(-time.Hour), 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("await bleef hangen op een frame-storm voorbij zijn window")
	}
}

func TestAcquireTweedeRonde(t *testing.T) {
	nic := &testNIC{}
	var rondes int
	nic.onTX = func(n *testNIC, frame []byte) {
		if msgTypeOf(frame) == msgDiscover {
			rondes++
			if rondes == 1 {
				return
			}

			oud := n.sent()[0]
			n.push(reply(oud, msgOffer, [4]byte{10, 9, 9, 9}, lessor))
			n.push(reply(frame, msgOffer, [4]byte{192, 168, 1, 55}, lessor))
			return
		}
		n.push(reply(frame, msgACK, [4]byte{192, 168, 1, 55}, lessor))
	}
	l, err := Acquire(nic, [6]byte{2, 0, 0, 0, 0, 1}, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if l.IP != ([4]byte{192, 168, 1, 55}) {
		t.Errorf("IP = %v — een laat OFFER van de vorige ronde werd aangenomen", l.IP)
	}
	if rondes < 2 {
		t.Errorf("%d rondes, want minstens 2", rondes)
	}
}

func TestAcquireNegeertVreemdeFrames(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	nic := &testNIC{}
	nic.onTX = func(n *testNIC, frame []byte) {
		if msgTypeOf(frame) != msgDiscover {
			n.push(reply(frame, msgACK, [4]byte{192, 168, 1, 66}, lessor))
			return
		}
		goed := reply(frame, msgOffer, [4]byte{192, 168, 1, 66}, lessor)

		verkeerdeXID := append([]byte(nil), goed...)
		verkeerdeXID[46] ^= 0xff
		verkeerdMAC := append([]byte(nil), goed...)
		verkeerdMAC[42+28] ^= 0xff
		verkeerdType := reply(frame, msgNAK, [4]byte{192, 168, 1, 66}, lessor)
		afgekapt := goed[:60]
		rommel := make([]byte, 100)
		for i := range rommel {
			rommel[i] = byte(i * 3)
		}

		for _, f := range [][]byte{rommel, afgekapt, verkeerdeXID, verkeerdMAC, verkeerdType, goed} {
			n.push(f)
		}
	}
	l, err := Acquire(nic, mac, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if l.IP != ([4]byte{192, 168, 1, 66}) {
		t.Errorf("IP = %v", l.IP)
	}
}

func TestParseRommelPanicktNooit(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	base := reply(packet(mac, 7, msgRequest, nil), msgACK, [4]byte{1, 2, 3, 4}, lessor)

	for n := range len(base) + 1 {
		parse(base[:n], mac, 7, msgACK)
		if n >= 42 {
			parseBootp(base[42:n], mac, 7, msgACK)
		}
	}

	for i := range base {
		f := append([]byte(nil), base...)
		f[i] ^= 0xff
		parse(f, mac, 7, msgACK)
	}

	for _, ln := range []byte{0, 1, 200, 255} {
		f := append([]byte(nil), base...)
		for i := 42 + 240; i+1 < len(f); i += 2 {
			f[i], f[i+1] = 58, ln
		}
		parse(f, mac, 7, msgACK)
	}

	for n := range 400 {
		f := make([]byte, n)
		for i := range f {
			f[i] = byte(i*7 + n)
		}
		parse(f, mac, 7, msgACK)
	}
}

func TestLeaseTekstvormen(t *testing.T) {
	l := Lease{
		IP:   [4]byte{10, 0, 0, 7},
		Mask: [4]byte{255, 255, 240, 0},
		GW:   [4]byte{10, 0, 0, 1},
	}
	if got := l.CIDR(); got != "10.0.0.7/20" {
		t.Errorf("CIDR = %q", got)
	}
	if got := l.IPString(); got != "10.0.0.7" {
		t.Errorf("IPString = %q", got)
	}
	if got := (Lease{}).DNSString(); got != "0.0.0.0" {
		t.Errorf("lege DNS = %q", got)
	}
}
