package leandhcp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func bound() Lease {
	return Lease{
		IP:        [4]byte{192, 168, 1, 33},
		Mask:      [4]byte{255, 255, 255, 0},
		GW:        [4]byte{192, 168, 1, 1},
		DNS:       [4]byte{192, 168, 1, 1},
		Server:    [4]byte{192, 168, 1, 1},
		LeaseSecs: 3600,
		T1Secs:    1800,
		T2Secs:    3150,
		Acquired:  true,
	}
}

type proefKeeper struct {
	*keeper
	slept   []time.Duration
	renews  int
	rebinds int
	log     strings.Builder
}

func newProefKeeper(l Lease) *proefKeeper {
	p := &proefKeeper{}
	p.keeper = &keeper{
		mac:   [6]byte{2, 0, 0, 0, 0, 1},
		lease: l,
		sleep: func(d time.Duration) { p.slept = append(p.slept, d) },
		logf:  func(f string, a ...any) { fmt.Fprintf(&p.log, f, a...) },
	}
	return p
}

func (p *proefKeeper) totaal() time.Duration {
	var t time.Duration
	for _, d := range p.slept {
		t += d
	}
	return t
}

func TestTimers(t *testing.T) {
	for _, tc := range []struct {
		naam        string
		l           Lease
		t1, t2, exp time.Duration
	}{
		{
			naam: "server stuurt alles",
			l:    Lease{LeaseSecs: 3600, T1Secs: 1800, T2Secs: 3150},
			t1:   30 * time.Minute, t2: 52*time.Minute + 30*time.Second, exp: time.Hour,
		},
		{
			naam: "alleen lease-tijd: RFC-verhoudingen",
			l:    Lease{LeaseSecs: 800},
			t1:   400 * time.Second, t2: 700 * time.Second, exp: 800 * time.Second,
		},
		{
			naam: "T1 = T2 = lease (bestaat in het veld)",
			l:    Lease{LeaseSecs: 3600, T1Secs: 3600, T2Secs: 3600},
			t1:   30 * time.Minute, t2: 52*time.Minute + 30*time.Second, exp: time.Hour,
		},
		{
			naam: "T1 boven 0.875·lease",
			l:    Lease{LeaseSecs: 3600, T1Secs: 3400},
			t1:   30 * time.Minute, t2: 52*time.Minute + 30*time.Second, exp: time.Hour,
		},
		{
			naam: "T2 onder T1",
			l:    Lease{LeaseSecs: 3600, T1Secs: 1800, T2Secs: 600},
			t1:   30 * time.Minute, t2: 52*time.Minute + 30*time.Second, exp: time.Hour,
		},
		{naam: "oneindig", l: Lease{LeaseSecs: 0xFFFFFFFF}},
		{naam: "onbekend", l: Lease{}},
	} {
		t1, t2, exp := tc.l.timers()
		if t1 != tc.t1 || t2 != tc.t2 || exp != tc.exp {
			t.Errorf("%s: timers = %v/%v/%v, want %v/%v/%v", tc.naam, t1, t2, exp, tc.t1, tc.t2, tc.exp)
		}
		if exp > 0 && !(0 < t1 && t1 < t2 && t2 < exp) {
			t.Errorf("%s: de orde 0 < T1 < T2 < lease is geschonden: %v/%v/%v", tc.naam, t1, t2, exp)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct{ left, want time.Duration }{
		{time.Hour, 30 * time.Minute},
		{4 * time.Minute, 2 * time.Minute},
		{3 * time.Minute, 90 * time.Second},
		{100 * time.Second, retryFloor},
		{90 * time.Second, retryFloor},
		{30 * time.Second, 30 * time.Second},
		{time.Second, time.Second},
	} {
		if got := retryAfter(tc.left); got != tc.want {
			t.Errorf("retryAfter(%v) = %v, want %v", tc.left, got, tc.want)
		}
	}
}

func TestKeeperRenewtOpT1(t *testing.T) {
	p := newProefKeeper(bound())
	p.renew = func(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
		p.renews++
		if p.renews == 3 {
			l.LeaseSecs = 0xFFFFFFFF
			return l, nil
		}
		return l, nil
	}
	p.rebind = func(Lease, [6]byte, time.Duration) (Lease, error) {
		t.Error("rebind werd gebruikt terwijl de lessor antwoordde")
		return Lease{}, errors.New("niet gebruiken")
	}
	p.run()

	if p.renews != 3 {
		t.Errorf("%d renews, want 3", p.renews)
	}
	for i, d := range p.slept[:2] {
		if d != 30*time.Minute {
			t.Errorf("slaapje %d = %v, want T1 (30m)", i, d)
		}
	}
	if strings.Count(p.log.String(), "HOPOS_DHCP_RENEW") != 3 {
		t.Errorf("log = %q", p.log.String())
	}
}

func TestKeeperRebindtOpT2(t *testing.T) {
	p := newProefKeeper(bound())
	weg := errors.New("no ACK within 10s")
	p.renew = func(Lease, [6]byte, time.Duration) (Lease, error) {
		p.renews++
		return Lease{}, weg
	}
	p.rebind = func(l Lease, _ [6]byte, _ time.Duration) (Lease, error) {
		p.rebinds++
		l.LeaseSecs = 0xFFFFFFFF
		return l, nil
	}
	p.run()

	if p.renews == 0 {
		t.Error("er is nooit een unicast-renew geprobeerd")
	}
	if p.rebinds != 1 {
		t.Fatalf("%d rebinds, want 1 — de rebind-fase werd niet bereikt", p.rebinds)
	}

	t1, t2, _ := bound().timers()
	besteed := p.totaal() + time.Duration(p.renews)*requestTimeout
	if besteed < t2 {
		t.Errorf("overgestapt na %v, terwijl T2 op %v ligt", besteed, t2)
	}
	if besteed > t2+retryFloor {
		t.Errorf("pas na %v overgestapt; T2 ligt op %v", besteed, t2)
	}
	if p.slept[0] != t1 {
		t.Errorf("eerste slaapje %v, want T1 %v", p.slept[0], t1)
	}
	if !strings.Contains(p.log.String(), "HOPOS_DHCP_REBIND") {
		t.Errorf("de overstap is niet te zien in de log: %q", p.log.String())
	}
}

func TestKeeperVerlooptEnZwijgtNiet(t *testing.T) {
	p := newProefKeeper(bound())
	stil := errors.New("no ACK within 10s")
	p.renew = func(Lease, [6]byte, time.Duration) (Lease, error) { p.renews++; return Lease{}, stil }
	p.rebind = func(Lease, [6]byte, time.Duration) (Lease, error) { p.rebinds++; return Lease{}, stil }
	p.run()

	if p.renews == 0 || p.rebinds == 0 {
		t.Fatalf("renews %d, rebinds %d — beide fasen horen geprobeerd te zijn", p.renews, p.rebinds)
	}
	_, _, expiry := bound().timers()
	besteed := p.totaal() + time.Duration(p.renews+p.rebinds)*requestTimeout
	if besteed > expiry+retryFloor {
		t.Errorf("bleef %v proberen op een lease van %v", besteed, expiry)
	}
	log := p.log.String()
	if !strings.Contains(log, "HOPOS_DHCP_EXPIRED") {
		t.Errorf("het verlopen van de lease is stil gebleven: %q", log)
	}
	if !strings.Contains(log, "192.168.1.33") {
		t.Error("de melding noemt het adres niet")
	}
}

func TestKeeperNAKStoptMeteen(t *testing.T) {
	p := newProefKeeper(bound())

	p.renew = func(Lease, [6]byte, time.Duration) (Lease, error) {
		p.renews++
		return Lease{}, fmt.Errorf("dhcp renewing: %w", errRefused)
	}
	p.rebind = func(Lease, [6]byte, time.Duration) (Lease, error) {
		t.Error("rebind na een NAK — dat is geen antwoord op een weigering")
		return Lease{}, nil
	}
	p.run()

	if p.renews != 1 {
		t.Errorf("%d pogingen na een NAK, want 1", p.renews)
	}
	if !strings.Contains(p.log.String(), "HOPOS_DHCP_NAK") {
		t.Errorf("log = %q", p.log.String())
	}
}

func TestKeeperAnderAdresStopt(t *testing.T) {
	p := newProefKeeper(bound())
	p.renew = func(l Lease, _ [6]byte, _ time.Duration) (Lease, error) {
		p.renews++
		l.IP = [4]byte{192, 168, 1, 99}
		return l, nil
	}
	p.run()

	if p.renews != 1 {
		t.Errorf("%d pogingen, want 1", p.renews)
	}
	log := p.log.String()
	if !strings.Contains(log, "HOPOS_DHCP_MOVED") {
		t.Errorf("log = %q", log)
	}
	if !strings.Contains(log, "192.168.1.99") || !strings.Contains(log, "192.168.1.33") {
		t.Error("de melding noemt niet beide adressen")
	}
}

func TestKeeperOneindigeLease(t *testing.T) {
	l := bound()
	l.LeaseSecs, l.T1Secs, l.T2Secs = 0xFFFFFFFF, 0, 0
	p := newProefKeeper(l)
	p.renew = func(Lease, [6]byte, time.Duration) (Lease, error) {
		t.Error("een oneindige lease werd vernieuwd")
		return Lease{}, nil
	}
	p.run()
	if len(p.slept) != 0 {
		t.Errorf("er is %v geslapen op een oneindige lease", p.slept)
	}
}

func TestKeepAliveZonderLease(t *testing.T) {
	klaar := make(chan struct{})
	go func() { KeepAlive([6]byte{}, Lease{}); close(klaar) }()
	select {
	case <-klaar:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepAlive bleef draaien op een lease die er niet is")
	}
}

func TestMergeDraagtDoor(t *testing.T) {
	oud := bound()
	kaal := Lease{IP: oud.IP}
	got := merge(oud, kaal)
	if got != oud {
		t.Errorf("merge = %+v, want alles uit de oude lease (%+v)", got, oud)
	}
	if !got.Acquired {
		t.Error("Acquired is niet gezet")
	}

	nieuw := Lease{IP: oud.IP, LeaseSecs: 7200, T1Secs: 3600, T2Secs: 6300, DNS: [4]byte{9, 9, 9, 9}}
	got = merge(oud, nieuw)
	if got.LeaseSecs != 7200 || got.T1Secs != 3600 || got.T2Secs != 6300 {
		t.Errorf("verse timers werden niet overgenomen: %+v", got)
	}
	if got.DNS != ([4]byte{9, 9, 9, 9}) {
		t.Errorf("verse DNS werd niet overgenomen: %v", got.DNS)
	}
	if got.Mask != oud.Mask || got.GW != oud.GW {
		t.Error("ontbrekende velden werden niet doorgedragen")
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{
		StateBound: "bound", StateRenewing: "renewing",
		StateRebinding: "rebinding", StateExpired: "expired", State(9): "unknown",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d) = %q, want %q", s, got, want)
		}
	}
}

func TestRenewRequestVorm(t *testing.T) {
	l := bound()
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	bp := bootp(mac, 0x484F5201, msgRequest, l.IP, false, nil)

	if bp[0] != 1 {
		t.Error("geen BOOTREQUEST")
	}
	if bp[10]&0x80 != 0 {
		t.Error("broadcast-flag staat aan in een renew — het antwoord komt dan " +
			"als broadcast en dat negeert onze eigen ingress")
	}
	if string(bp[12:16]) != string(l.IP[:]) {
		t.Errorf("ciaddr = %v, want het lease-IP %v", bp[12:16], l.IP)
	}
	if string(bp[28:34]) != string(mac[:]) {
		t.Error("chaddr is niet ons MAC")
	}

	frame := append(make([]byte, 42), bp...)
	for _, code := range []byte{50, 54} {
		if hasOptionCode(frame, code) {
			t.Errorf("optie %d staat in een renew-REQUEST", code)
		}
	}
	if !hasOption(frame, 53, []byte{msgRequest}) {
		t.Error("optie 53 zegt niet REQUEST")
	}
}

func hasOptionCode(frame []byte, code byte) bool {
	opts := frame[42+240:]
	for i := 0; i+1 < len(opts); {
		if opts[i] == 0 {
			i++
			continue
		}
		if opts[i] == 255 {
			return false
		}
		if opts[i] == code {
			return true
		}
		i += 2 + int(opts[i+1])
	}
	return false
}

type proefConn struct {
	sentTo []*net.UDPAddr
	sent   [][]byte
	closed bool

	msgtype byte
	yiaddr  [4]byte
	extra   []byte
	vooraf  [][]byte

	pending [][]byte
}

func (c *proefConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	c.sentTo = append(c.sentTo, addr)
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.pending = append(c.pending, c.vooraf...)
	if c.msgtype != 0 {
		c.pending = append(c.pending, bootpReply(b, c.msgtype, c.yiaddr, c.extra))
	}
	return len(b), nil
}

func (c *proefConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if len(c.pending) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	f := c.pending[0]
	c.pending = c.pending[1:]
	return copy(b, f), &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 67}, nil
}

func (c *proefConn) SetReadDeadline(time.Time) error { return nil }
func (c *proefConn) Close() error                    { c.closed = true; return nil }

func metConn(t *testing.T, c leaseConn) {
	t.Helper()
	oud := listenLease
	listenLease = func([4]byte) (leaseConn, error) { return c, nil }
	t.Cleanup(func() { listenLease = oud })
}

func bootpReply(req []byte, msgtype byte, yiaddr [4]byte, extra []byte) []byte {
	bp := make([]byte, 300)
	bp[0], bp[1], bp[2] = 2, 1, 6
	copy(bp[4:8], req[4:8])
	copy(bp[28:34], req[28:34])
	copy(bp[16:20], yiaddr[:])
	copy(bp[236:240], []byte{99, 130, 83, 99})
	copy(bp[240:], append(append([]byte{53, 1, msgtype}, extra...), 255))
	return bp
}

func TestRenewGaatNaarDeLessor(t *testing.T) {
	l := bound()
	c := &proefConn{}
	metConn(t, c)

	if _, err := Renew(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second); err == nil {
		t.Fatal("een stille server gaf toch een lease")
	}
	if len(c.sentTo) != 1 || !c.sentTo[0].IP.Equal(net.IP(l.Server[:])) || c.sentTo[0].Port != 67 {
		t.Fatalf("renew ging naar %v, want %v:67", c.sentTo, l.Server)
	}
	if !c.closed {
		t.Error("de socket bleef open — poort 68 blijft dan bezet voor de volgende poging")
	}
}

func TestRebindGaatBroadcast(t *testing.T) {
	l := bound()
	c := &proefConn{}
	metConn(t, c)

	if _, err := Rebind(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second); err == nil {
		t.Fatal("stilte gaf toch een lease")
	}
	if len(c.sentTo) != 1 || !c.sentTo[0].IP.Equal(net.IPv4bcast) {
		t.Fatalf("rebind ging naar %v, want 255.255.255.255", c.sentTo)
	}
	if string(c.sent[0][12:16]) != string(l.IP[:]) {
		t.Errorf("ciaddr = %v, want %v", c.sent[0][12:16], l.IP)
	}
	if c.sent[0][10]&0x80 != 0 {
		t.Error("broadcast-flag staat aan — het antwoord komt dan als broadcast " +
			"terug en dat negeert onze eigen ingress")
	}
}

func TestRequestACK(t *testing.T) {
	l := bound()
	c := &proefConn{msgtype: msgACK, yiaddr: l.IP, extra: []byte{51, 4, 0, 0, 0x1c, 0x20}}
	metConn(t, c)

	got, err := Renew(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.LeaseSecs != 7200 {
		t.Errorf("LeaseSecs = %d, want 7200 uit de ACK", got.LeaseSecs)
	}
	if got.Mask != l.Mask || got.GW != l.GW || got.Server != l.Server || got.DNS != l.DNS {
		t.Errorf("de karige ACK wiste velden: %+v", got)
	}
	if !got.Acquired {
		t.Error("Acquired is niet gezet")
	}
}

func TestRequestNAK(t *testing.T) {
	l := bound()
	metConn(t, &proefConn{msgtype: msgNAK, yiaddr: l.IP})
	_, err := Renew(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second)
	if !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want errRefused", err)
	}
	if !strings.Contains(err.Error(), "renewing") {
		t.Errorf("err = %v — de fase hoort in het bericht", err)
	}
}

func TestRequestSlaatVreemdVerkeerOver(t *testing.T) {
	l := bound()
	andere := make([]byte, 300)
	andere[0] = 2
	andere[4] = 0xff
	metConn(t, &proefConn{msgtype: msgACK, yiaddr: l.IP, vooraf: [][]byte{
		make([]byte, 10),
		make([]byte, 300),
		andere,
	}})

	got, err := Renew(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second)
	if err != nil {
		t.Fatalf("vreemd verkeer op :68 verpestte de renew: %v", err)
	}
	if got.IP != l.IP {
		t.Errorf("IP = %v", got.IP)
	}
}

func TestSleepChunked(t *testing.T) {
	for _, d := range []time.Duration{-time.Hour, 0, 5 * time.Millisecond} {
		start := time.Now()
		sleepChunked(d)
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Errorf("sleepChunked(%v) duurde %v", d, elapsed)
		}
	}
}
