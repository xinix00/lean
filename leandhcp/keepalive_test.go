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

// bound is een verkregen lease van een uur, met de timers die een router stuurt.
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

// proefKeeper geeft een keeper waarvan alle tijd en al het verkeer door de test
// loopt: geen sockets, geen wachten. slept houdt bij hoeveel er "geslapen" is,
// log wat er gemeld is.
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

// totaal is alle geslapen tijd bij elkaar.
func (p *proefKeeper) totaal() time.Duration {
	var t time.Duration
	for _, d := range p.slept {
		t += d
	}
	return t
}

// TestTimers: de drie momenten van een lease, inclusief de getallen die servers
// in het veld echt sturen. Een server die T1 = T2 = lease stuurt mag de
// staatmachine niet laten ontsporen — dan gelden de RFC-verhoudingen.
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

// TestRetryAfter: halveren, met de RFC-vloer van 60s, maar nooit voorbij de
// fasegrens — anders begint de rebind te laat.
func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct{ left, want time.Duration }{
		{time.Hour, 30 * time.Minute},
		{4 * time.Minute, 2 * time.Minute},
		{3 * time.Minute, 90 * time.Second},
		{100 * time.Second, retryFloor}, // helft (50s) is onder de vloer
		{90 * time.Second, retryFloor},
		{30 * time.Second, 30 * time.Second}, // vloer zou de grens voorbij slapen
		{time.Second, time.Second},
	} {
		if got := retryAfter(tc.left); got != tc.want {
			t.Errorf("retryAfter(%v) = %v, want %v", tc.left, got, tc.want)
		}
	}
}

// TestKeeperRenewtOpT1: de gewone dag. Slapen tot T1, unicast-renew, en daarna
// weer tot T1 van de nieuwe lease — geen rebind in zicht.
func TestKeeperRenewtOpT1(t *testing.T) {
	p := newProefKeeper(bound())
	p.renew = func(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
		p.renews++
		if p.renews == 3 {
			l.LeaseSecs = 0xFFFFFFFF // oneindig: de keeper is klaar
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

// TestKeeperRebindtOpT2 is het gat dat deze ronde dicht ging: de lessor is weg
// (verhuisde router, nieuwe DHCP-server) en de unicast-renew kan per definitie
// niet meer slagen. Vóór de splitsing bleef het daar zes pogingen op hangen en
// verloor de node zijn adres; nu stapt hij op T2 over op broadcast, en dát is
// precies de storing waar REBINDING voor bestaat.
func TestKeeperRebindtOpT2(t *testing.T) {
	p := newProefKeeper(bound())
	weg := errors.New("no ACK within 10s")
	p.renew = func(Lease, [6]byte, time.Duration) (Lease, error) {
		p.renews++
		return Lease{}, weg
	}
	p.rebind = func(l Lease, _ [6]byte, _ time.Duration) (Lease, error) {
		p.rebinds++
		l.LeaseSecs = 0xFFFFFFFF // gelukt: klaar
		return l, nil
	}
	p.run()

	if p.renews == 0 {
		t.Error("er is nooit een unicast-renew geprobeerd")
	}
	if p.rebinds != 1 {
		t.Fatalf("%d rebinds, want 1 — de rebind-fase werd niet bereikt", p.rebinds)
	}
	// Het overstappen hoort op T2 te gebeuren, niet eerder en niet later: alle
	// renew-pogingen samen (slaap + timeout per poging) vallen binnen T2.
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

// TestKeeperVerlooptEnZwijgtNiet: antwoordt niemand, dan is het adres op de
// lease-tijd niet meer van ons. Dat moet luid gemeld worden (de node hangt er
// dan aan een watchdog-reboot), en de machine mag NIET langer dan de lease-tijd
// blijven proberen — dan zou hij een adres verdedigen dat al vergeven is.
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

// TestKeeperNAKStoptMeteen: een NAK is geen "probeer later" maar een weigering.
// Doorpraten op dat IP zou betekenen dat we een adres gebruiken dat de server
// aan iemand anders mag geven.
func TestKeeperNAKStoptMeteen(t *testing.T) {
	p := newProefKeeper(bound())
	// De fout is ingepakt (zoals request hem teruggeeft), dus de machine moet op
	// de foutWAARDE kijken en niet op tekst.
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

// TestKeeperAnderAdresStopt: een rebind mag bij een andere server uitkomen en
// die mag een ander adres geven. Toepassen kan niet (de stack staat op één IP),
// dus is stoppen-met-uitleg het enige eerlijke antwoord. Stil doorgaan zou
// betekenen dat de server ons oude adres straks aan iemand anders geeft.
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

// TestKeeperOneindigeLease: niets te timen, dus ook niets te doen — en zeker
// geen lus die elke tick wakker wordt.
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

// TestKeepAliveZonderLease: een board met statische config heeft geen lease, en
// dan hoort hier niets te draaien.
func TestKeepAliveZonderLease(t *testing.T) {
	klaar := make(chan struct{})
	go func() { KeepAlive([6]byte{}, Lease{}); close(klaar) }()
	select {
	case <-klaar:
	case <-time.After(2 * time.Second):
		t.Fatal("KeepAlive bleef draaien op een lease die er niet is")
	}
}

// TestMergeDraagtDoor: een ACK op een renew herhaalt de opties vaak niet. Wat
// ontbreekt komt uit de oude lease — inclusief de lease-tijden, want zonder die
// zou timers() nul teruggeven en zou het onderhoud stilzwijgend stoppen.
func TestMergeDraagtDoor(t *testing.T) {
	oud := bound()
	kaal := Lease{IP: oud.IP} // een server die alleen yiaddr terugstuurt
	got := merge(oud, kaal)
	if got != oud {
		t.Errorf("merge = %+v, want alles uit de oude lease (%+v)", got, oud)
	}
	if !got.Acquired {
		t.Error("Acquired is niet gezet")
	}

	// Wat de server wél stuurt, wint.
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

// TestStateString: de staatnamen komen in de console-log terecht, dus ze mogen
// niet stil "%!v(uint8=2)" worden.
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

// TestRenewRequestVorm: een REQUEST in de renew-fase heeft een ándere vorm dan
// de REQUEST van de handshake (RFC 2131 §4.3.2). ciaddr draagt het IP, en optie
// 50/54 horen er JUIST niet in te staan — sommige servers antwoorden op zo'n
// mengvorm met een NAK, en dan verlies je de lease terwijl alles in orde was.
// De broadcast-flag blijft uit: we hebben een geldig adres en kunnen unicast
// ontvangen, en dat moet ook, want onze eigen ingress negeert broadcast-IP's.
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
	// Frame-loos, dus de optie-zoeker van de andere test wil een frame-offset:
	// bouw er een nepframe om.
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

// hasOptionCode zoekt of een optiecode voorkomt, ongeacht de waarde.
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

// proefConn speelt de socket: sentTo bewaart waar we heen schreven, en het
// antwoord wordt gebouwd op de xid die de client zélf net schreef — dat is de
// eenvoudigste manier om server te zijn zonder de xid-teller na te bouwen.
// Poort 68 is geprivilegieerd, dus een echte bind kan hier niet.
type proefConn struct {
	sentTo []*net.UDPAddr
	sent   [][]byte
	closed bool

	// Het antwoord op elke write: msgtype 0 = niets terugsturen (stille server).
	msgtype byte
	yiaddr  [4]byte
	extra   []byte
	vooraf  [][]byte // verkeer dat vóór ons antwoord uit de socket komt

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
		return 0, nil, os.ErrDeadlineExceeded // de leesdeadline verstreek
	}
	f := c.pending[0]
	c.pending = c.pending[1:]
	return copy(b, f), &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 67}, nil
}

func (c *proefConn) SetReadDeadline(time.Time) error { return nil }
func (c *proefConn) Close() error                    { c.closed = true; return nil }

// metConn laat request over c lopen in plaats van over een echte socket.
func metConn(t *testing.T, c leaseConn) {
	t.Helper()
	oud := listenLease
	listenLease = func([4]byte) (leaseConn, error) { return c, nil }
	t.Cleanup(func() { listenLease = oud })
}

// bootpReply bouwt het antwoord van een server op de UDP-payload die wij
// verstuurden — los van een frame, zoals het uit de socket komt.
func bootpReply(req []byte, msgtype byte, yiaddr [4]byte, extra []byte) []byte {
	bp := make([]byte, 300)
	bp[0], bp[1], bp[2] = 2, 1, 6 // BOOTREPLY
	copy(bp[4:8], req[4:8])       // dezelfde xid
	copy(bp[28:34], req[28:34])   // dezelfde chaddr
	copy(bp[16:20], yiaddr[:])
	copy(bp[236:240], []byte{99, 130, 83, 99})
	copy(bp[240:], append(append([]byte{53, 1, msgtype}, extra...), 255))
	return bp
}

// TestRenewGaatNaarDeLessor: unicast naar de server uit optie 54, en de socket
// gaat daarna dicht (anders houdt elke poging poort 68 bezet).
func TestRenewGaatNaarDeLessor(t *testing.T) {
	l := bound()
	c := &proefConn{} // stille server
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

// TestRebindGaatBroadcast is de kern van de rebind-fase: níet naar de lessor
// (die is juist stil) maar naar 255.255.255.255, zodat elke server op het
// segment mag antwoorden. ciaddr moet mee, anders weet die server niet welk
// adres we willen HOUDEN en geeft hij ons een nieuw.
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

// TestRequestACK: de gewone uitkomst. Een karige ACK (alleen yiaddr en een
// nieuwe lease-tijd) mag de rest van de lease niet wissen.
func TestRequestACK(t *testing.T) {
	l := bound()
	c := &proefConn{msgtype: msgACK, yiaddr: l.IP, extra: []byte{51, 4, 0, 0, 0x1c, 0x20}} // 7200s
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

// TestRequestNAK: een NAK draagt errRefused — dat is precies wat de staatmachine
// nodig heeft om te stoppen in plaats van door te blijven vragen.
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

// TestRequestSlaatVreemdVerkeerOver: op poort 68 komt ook ander verkeer langs
// (een laat antwoord, een broadcast voor een andere client). Dat mag de lease
// niet in de weg zitten: doorlezen tot de deadline.
func TestRequestSlaatVreemdVerkeerOver(t *testing.T) {
	l := bound()
	andere := make([]byte, 300)
	andere[0] = 2    // BOOTREPLY, maar
	andere[4] = 0xff // een andere xid
	metConn(t, &proefConn{msgtype: msgACK, yiaddr: l.IP, vooraf: [][]byte{
		make([]byte, 10),  // te kort voor BOOTP
		make([]byte, 300), // geen BOOTREPLY
		andere,            // andermans transactie
	}})

	got, err := Renew(l, [6]byte{2, 0, 0, 0, 0, 1}, time.Second)
	if err != nil {
		t.Fatalf("vreemd verkeer op :68 verpestte de renew: %v", err)
	}
	if got.IP != l.IP {
		t.Errorf("IP = %v", got.IP)
	}
}

// TestSleepChunked: de kloksprong-les. Kort slapen mag geen lus worden, en de
// som van de plakken is de gevraagde tijd (dat laatste is per constructie zo;
// wat hier telt is dat de randen — 0 en negatief — meteen terugkomen).
func TestSleepChunked(t *testing.T) {
	for _, d := range []time.Duration{-time.Hour, 0, 5 * time.Millisecond} {
		start := time.Now()
		sleepChunked(d)
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Errorf("sleepChunked(%v) duurde %v", d, elapsed)
		}
	}
}
