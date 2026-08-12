package leannet

// arp_test.go — de ARP-lessen uit BEVINDINGEN.md (#8, #12, #20, #21) als
// regressietest, met geïnjecteerde monotone tijd: geen sleep, geen wandklok.

import (
	"bytes"
	"testing"
	"time"
)

// Vaste adressen voor alle ARP-tests (arp-prefix: tcp_test.go leeft in
// hetzelfde package).
var (
	arpTestOurIP    = [4]byte{192, 168, 99, 2}
	arpTestOurMAC   = [6]byte{0x02, 0x48, 0x4f, 0x50, 0x00, 0x02}
	arpTestPeerIP   = [4]byte{192, 168, 99, 1}
	arpTestPeerMAC  = [6]byte{0x02, 0x48, 0x4f, 0x50, 0x00, 0x01}
	arpTestEvilMAC  = [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x66}
	arpTestOtherIP  = [4]byte{192, 168, 99, 9}
	arpTestOtherMAC = [6]byte{0x02, 0x48, 0x4f, 0x50, 0x00, 0x09}
)

// arpPkt bouwt een binnenkomend ARP-pakket via PutARP/ParseARP zelf — de
// views zijn elders al goldengetest.
func arpPkt(t *testing.T, op uint16, senderHW [6]byte, senderIP [4]byte, targetHW [6]byte, targetIP [4]byte) ARPFrame {
	t.Helper()
	buf := make([]byte, sizeARP)
	if _, err := PutARP(buf, op, senderHW, senderIP, targetHW, targetIP); err != nil {
		t.Fatal(err)
	}
	f, err := ParseARP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// arpDrain telt hoeveel pakketten emit op één moment produceert.
func arpDrain(t *testing.T, tab *arpTable, now int64) int {
	t.Helper()
	buf := make([]byte, sizeARP)
	count := 0
	for {
		if _, ok := tab.emit(buf, now); !ok {
			return count
		}
		count++
	}
}

// arpEstablish doorloopt de volledige cyclus: resolve → query → reply → hit.
func arpEstablish(t *testing.T, tab *arpTable, ip [4]byte, mac [6]byte, now int64) {
	t.Helper()
	if _, ok := tab.resolve(ip, now); ok {
		t.Fatal("resolve hit before any query")
	}
	buf := make([]byte, sizeARP)
	if _, ok := tab.emit(buf, now); !ok {
		t.Fatal("no query emitted for pending resolve")
	}
	tab.recv(arpPkt(t, ARPReply, mac, ip, tab.ourMAC, tab.ourIP), now)
	got, ok := tab.resolve(ip, now)
	if !ok || got != mac {
		t.Fatalf("resolve after reply = %v, %v; want %v, true", got, ok, mac)
	}
}

// TestARPResolveCycle: de normale gang — resolve mist, emit legt precies één
// request op de draad, de reply lost op, en er valt daarna niets meer te
// emitten.
func TestARPResolveCycle(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	now := int64(0)

	if _, ok := tab.resolve(arpTestPeerIP, now); ok {
		t.Fatal("resolve hit on empty table")
	}

	buf := make([]byte, sizeARP)
	n, ok := tab.emit(buf, now)
	if !ok {
		t.Fatal("no query emitted")
	}
	q, err := ParseARP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if q.Op() != ARPRequest {
		t.Fatalf("op = %d, want request", q.Op())
	}
	if !bytes.Equal(q.SenderHW(), arpTestOurMAC[:]) || !bytes.Equal(q.SenderProto(), arpTestOurIP[:]) {
		t.Fatalf("query sender = %x/%x, want our mac/ip", q.SenderHW(), q.SenderProto())
	}
	if !bytes.Equal(q.TargetProto(), arpTestPeerIP[:]) {
		t.Fatalf("query target proto = %x, want peer ip", q.TargetProto())
	}
	if _, ok := tab.emit(buf, now); ok {
		t.Fatal("second emit produced a packet; retry due only after the interval")
	}

	tab.recv(arpPkt(t, ARPReply, arpTestPeerMAC, arpTestPeerIP, arpTestOurMAC, arpTestOurIP), now+1)
	mac, ok := tab.resolve(arpTestPeerIP, now+2)
	if !ok || mac != arpTestPeerMAC {
		t.Fatalf("resolve after reply = %v, %v; want %v, true", mac, ok, arpTestPeerMAC)
	}
	if arpDrain(t, tab, now+2) != 0 {
		t.Fatal("resolved entry still emits packets")
	}
}

// TestARPDedup (#12): twee resolves voor hetzelfde IP zijn één entry en één
// query op de draad — de map-sleutel ís de dedup.
func TestARPDedup(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	now := int64(0)

	tab.resolve(arpTestPeerIP, now)
	tab.resolve(arpTestPeerIP, now)
	if len(tab.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(tab.entries))
	}
	if got := arpDrain(t, tab, now); got != 1 {
		t.Fatalf("emitted %d queries for two resolves, want 1", got)
	}
	// Ook ná de query blijft een derde resolve deduppen: geen extra pakket
	// vóór het retry-moment.
	tab.resolve(arpTestPeerIP, now+1)
	if got := arpDrain(t, tab, now+1); got != 0 {
		t.Fatalf("emitted %d extra queries after dedup, want 0", got)
	}
}

// TestARPForeignReplyIgnored (#8): een reply die niet aan ons gericht en niet
// gratuitous is maakt géén entry aan en overschrijft géén gevestigde entry —
// het poisoning-scenario waarop lneto omviel.
func TestARPForeignReplyIgnored(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	now := int64(0)

	// Zonder pending query: broadcast-reply voor andermans gesprek → niets.
	tab.recv(arpPkt(t, ARPReply, arpTestEvilMAC, arpTestPeerIP, arpTestOtherMAC, arpTestOtherIP), now)
	if len(tab.entries) != 0 {
		t.Fatal("foreign reply created an entry")
	}
	if tab.cntIgnored != 1 {
		t.Fatalf("cntIgnored = %d, want 1", tab.cntIgnored)
	}

	// Ook een aan óns gerichte reply voor een IP zonder pending query maakt
	// niets aan.
	tab.recv(arpPkt(t, ARPReply, arpTestEvilMAC, arpTestOtherIP, arpTestOurMAC, arpTestOurIP), now)
	if len(tab.entries) != 0 {
		t.Fatal("unsolicited reply to us created an entry")
	}

	// Gevestigde entry (de "gateway") wordt níét overschreven door een
	// broadcast-reply met target ≠ ons.
	arpEstablish(t, tab, arpTestPeerIP, arpTestPeerMAC, now)
	tab.recv(arpPkt(t, ARPReply, arpTestEvilMAC, arpTestPeerIP, arpTestOtherMAC, arpTestOtherIP), now+1)
	mac, ok := tab.resolve(arpTestPeerIP, now+2)
	if !ok || mac != arpTestPeerMAC {
		t.Fatalf("established entry poisoned: mac = %v, want %v", mac, arpTestPeerMAC)
	}
}

// TestARPGratuitousRefresh (#8, keerzijde): een gratuitous reply
// (sender == target) ververst een bestáánde entry wél — MAC én TTL — maar
// maakt voor een onbekend IP niets aan.
func TestARPGratuitousRefresh(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	sec := int64(time.Second)

	arpEstablish(t, tab, arpTestPeerIP, arpTestPeerMAC, 0)

	// Peer verhuist naar een nieuw MAC en kondigt dat gratuitous aan op t=60s.
	newMAC := [6]byte{0x02, 0x48, 0x4f, 0x50, 0x00, 0x11}
	tab.recv(arpPkt(t, ARPReply, newMAC, arpTestPeerIP, newMAC, arpTestPeerIP), 60*sec)
	mac, ok := tab.resolve(arpTestPeerIP, 60*sec)
	if !ok || mac != newMAC {
		t.Fatalf("gratuitous refresh: mac = %v, %v; want %v, true", mac, ok, newMAC)
	}
	if tab.cntMACChanged != 1 {
		t.Fatalf("cntMACChanged = %d, want 1", tab.cntMACChanged)
	}

	// De refresh verlengde de TTL: op t=130s (verlopen t.o.v. t=0, niet
	// t.o.v. t=60s) leeft de entry nog.
	if _, ok := tab.resolve(arpTestPeerIP, 130*sec); !ok {
		t.Fatal("refresh did not extend the TTL")
	}

	// Gratuitous voor een IP dat wij niet kennen: geen nieuwe entry.
	tab.recv(arpPkt(t, ARPReply, arpTestOtherMAC, arpTestOtherIP, arpTestOtherMAC, arpTestOtherIP), 60*sec)
	if _, exists := tab.entries[arpTestOtherIP]; exists {
		t.Fatal("gratuitous reply created an entry for an unknown ip")
	}
}

// TestARPExpiry: een opgelost antwoord verloopt na arpEntryTTL; de volgende
// resolve start een verse query.
func TestARPExpiry(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	arpEstablish(t, tab, arpTestPeerIP, arpTestPeerMAC, 0)

	if _, ok := tab.resolve(arpTestPeerIP, arpEntryTTL-1); !ok {
		t.Fatal("entry expired before its TTL")
	}
	if _, ok := tab.resolve(arpTestPeerIP, arpEntryTTL); ok {
		t.Fatal("entry survived its TTL")
	}
	if got := arpDrain(t, tab, arpEntryTTL); got != 1 {
		t.Fatalf("emitted %d queries after expiry-restart, want 1", got)
	}
}

// TestARPRetryAndGiveUp: vaste tussenpoos, arpQueryTries pogingen, dan luid
// opgeven — teller omhoog, noAnswer-status voor de wachtende resolve, en na
// arpFailTTL mag een verse poging.
func TestARPRetryAndGiveUp(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	sec := int64(time.Second)

	tab.resolve(arpTestPeerIP, 0)
	for i := 0; i < arpQueryTries; i++ {
		now := int64(i) * sec
		if got := arpDrain(t, tab, now); got != 1 {
			t.Fatalf("try %d: emitted %d queries, want 1", i+1, got)
		}
		// Halverwege de tussenpoos is er niets te doen.
		if got := arpDrain(t, tab, now+sec/2); got != 0 {
			t.Fatalf("try %d: retry emitted before its interval", i+1)
		}
	}

	// Na de laatste tussenpoos: opgeven, geen zesde query.
	giveUp := int64(arpQueryTries) * sec
	if got := arpDrain(t, tab, giveUp); got != 0 {
		t.Fatal("query emitted after give-up point")
	}
	if tab.cntGaveUp != 1 {
		t.Fatalf("cntGaveUp = %d, want 1", tab.cntGaveUp)
	}
	if !tab.noAnswer(arpTestPeerIP, giveUp) {
		t.Fatal("noAnswer = false after give-up")
	}

	// De failed-status is een negatieve cache: resolve start géén nieuwe query.
	if _, ok := tab.resolve(arpTestPeerIP, giveUp+1); ok {
		t.Fatal("resolve hit on failed entry")
	}
	if got := arpDrain(t, tab, giveUp+1); got != 0 {
		t.Fatal("resolve on failed entry restarted the query early")
	}

	// Na arpFailTTL mag het opnieuw: verse pending, verse query, teller blijft 1.
	fresh := giveUp + arpFailTTL
	if tab.noAnswer(arpTestPeerIP, fresh) {
		t.Fatal("noAnswer sticks past arpFailTTL")
	}
	if _, ok := tab.resolve(arpTestPeerIP, fresh); ok {
		t.Fatal("resolve hit without any reply")
	}
	if got := arpDrain(t, tab, fresh); got != 1 {
		t.Fatalf("emitted %d queries on fresh cycle, want 1", got)
	}
	if tab.cntGaveUp != 1 {
		t.Fatalf("cntGaveUp = %d after restart, want still 1", tab.cntGaveUp)
	}
}

// TestARPAnswersRequest: een request voor óns IP zet een reply klaar die emit
// als eerste verstuurt, met de vrager als target.
func TestARPAnswersRequest(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	now := int64(0)

	tab.recv(arpPkt(t, ARPRequest, arpTestPeerMAC, arpTestPeerIP, [6]byte{}, arpTestOurIP), now)

	buf := make([]byte, sizeARP)
	n, ok := tab.emit(buf, now)
	if !ok {
		t.Fatal("no reply emitted for a request to our ip")
	}
	r, err := ParseARP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if r.Op() != ARPReply {
		t.Fatalf("op = %d, want reply", r.Op())
	}
	if !bytes.Equal(r.SenderHW(), arpTestOurMAC[:]) || !bytes.Equal(r.SenderProto(), arpTestOurIP[:]) {
		t.Fatalf("reply sender = %x/%x, want our mac/ip", r.SenderHW(), r.SenderProto())
	}
	if !bytes.Equal(r.TargetHW(), arpTestPeerMAC[:]) || !bytes.Equal(r.TargetProto(), arpTestPeerIP[:]) {
		t.Fatalf("reply target = %x/%x, want peer mac/ip", r.TargetHW(), r.TargetProto())
	}
	if _, ok := tab.emit(buf, now); ok {
		t.Fatal("reply queue not drained after one emit")
	}

	// Een request voor andermans IP verdient géén reply van ons.
	tab.recv(arpPkt(t, ARPRequest, arpTestPeerMAC, arpTestPeerIP, [6]byte{}, arpTestOtherIP), now)
	if _, ok := tab.emit(buf, now); ok {
		t.Fatal("replied to a request for someone else's ip")
	}
}

// TestARPSeed (#21): een statische seed lost meteen op, verloopt nooit en
// wint van gratuitous verkeer. De subnet-check hoort bij de stack-laag — de
// tabel accepteert hier bewust élk IP.
func TestARPSeed(t *testing.T) {
	tab := newARPTable(arpTestOurIP, arpTestOurMAC)
	sec := int64(time.Second)

	tab.seed(arpTestPeerIP, arpTestPeerMAC)
	mac, ok := tab.resolve(arpTestPeerIP, 0)
	if !ok || mac != arpTestPeerMAC {
		t.Fatalf("seeded resolve = %v, %v; want %v, true", mac, ok, arpTestPeerMAC)
	}

	// Ver voorbij elke TTL: nog steeds een hit, en nul pakketten op de draad.
	if _, ok := tab.resolve(arpTestPeerIP, 1000*sec); !ok {
		t.Fatal("static seed expired")
	}
	if got := arpDrain(t, tab, 1000*sec); got != 0 {
		t.Fatalf("seed caused %d packets on the wire, want 0", got)
	}

	// Gratuitous verkeer verandert een seed niet.
	tab.recv(arpPkt(t, ARPReply, arpTestEvilMAC, arpTestPeerIP, arpTestEvilMAC, arpTestPeerIP), 1000*sec)
	if mac, _ := tab.resolve(arpTestPeerIP, 1000*sec); mac != arpTestPeerMAC {
		t.Fatalf("gratuitous reply overwrote a static seed: mac = %v", mac)
	}

	// Een seed vervangt een lopende query: de wachtende resolver ziet de hit.
	tab.resolve(arpTestOtherIP, 0)
	tab.seed(arpTestOtherIP, arpTestOtherMAC)
	if mac, ok := tab.resolve(arpTestOtherIP, 0); !ok || mac != arpTestOtherMAC {
		t.Fatalf("seed over pending = %v, %v; want %v, true", mac, ok, arpTestOtherMAC)
	}
}

// TestARPLearnPassive: het passieve pad (de stack meldt src van unicast-IPv4
// aan óns). Strikter dan lneto's PassivePeers: aanmaken en TTL verversen mag,
// een MAC WIJZIGEN nooit — anders zou een gespoofd data-frame de gateway-entry
// kunnen omleiden zonder ook maar één ARP-pakket.
func TestARPLearnPassive(t *testing.T) {
	const t0 = int64(1_000_000_000)
	ourIP := [4]byte{10, 0, 0, 1}
	tbl := newARPTable(ourIP, [6]byte{2, 0, 0, 0, 0, 1})
	peer, mac := [4]byte{10, 0, 0, 9}, [6]byte{9, 9, 9, 9, 9, 1}

	// Onbekend IP: aanmaken mag (dat is de winst — nul ARP voor een beller).
	tbl.learn(peer, mac, t0)
	if got, ok := tbl.resolve(peer, t0); !ok || got != mac {
		t.Fatalf("passive learn did not resolve: %x ok=%v", got, ok)
	}
	// Zelfde MAC later: alleen de TTL verschuift (entry blijft leven voorbij
	// zijn oorspronkelijke verloop).
	tbl.learn(peer, mac, t0+arpEntryTTL-1)
	if _, ok := tbl.resolve(peer, t0+arpEntryTTL+1); !ok {
		t.Fatal("passive refresh did not extend the TTL")
	}
	// Ander MAC via dataverkeer: NEGEREN.
	evil := [6]byte{0xde, 0xad, 0, 0, 0, 1}
	tbl.learn(peer, evil, t0+arpEntryTTL+2)
	if got, _ := tbl.resolve(peer, t0+arpEntryTTL+2); got == evil {
		t.Fatal("passive learning overwrote a MAC; a spoofed data frame could reroute traffic")
	}
	// Ons eigen IP leren is zinloos en mag geen entry maken.
	tbl.learn(ourIP, [6]byte{1, 2, 3, 4, 5, 6}, t0)
	if _, exists := tbl.entries[ourIP]; exists {
		t.Fatal("passive learning created an entry for our own IP")
	}
	// Een lopende query lost wél op als het antwoord als dataverkeer komt.
	other := [4]byte{10, 0, 0, 20}
	tbl.resolve(other, t0) // start query
	tbl.learn(other, [6]byte{7, 7, 7, 7, 7, 7}, t0)
	if got, ok := tbl.resolve(other, t0); !ok || got != [6]byte{7, 7, 7, 7, 7, 7} {
		t.Fatal("data-plane answer did not satisfy a pending query")
	}
}

// TestARPStaticSeedSurvivesEverything: een geseede buur verloopt niet en
// wordt door niets overschreven — het deterministische net van appnet leunt
// erop.
func TestARPStaticSeedSurvivesEverything(t *testing.T) {
	const t0 = int64(1_000_000_000)
	tbl := newARPTable([4]byte{10, 100, 0, 5}, [6]byte{2, 0, 0, 0, 0, 5})
	gw, mac := [4]byte{10, 100, 0, 1}, [6]byte{2, 0, 0, 0, 0, 0}
	tbl.seed(gw, mac)

	// Ver in de toekomst nog geldig.
	if got, ok := tbl.resolve(gw, t0+100*arpEntryTTL); !ok || got != mac {
		t.Fatalf("static seed expired: %x ok=%v", got, ok)
	}
	// Gratuitous reply met een ander MAC: geen effect.
	buf := make([]byte, sizeARP)
	evil := [6]byte{0xba, 0xad, 0, 0, 0, 1}
	PutARP(buf, ARPReply, evil, gw, evil, gw)
	f, _ := ParseARP(buf)
	tbl.recv(f, t0)
	if got, _ := tbl.resolve(gw, t0); got != mac {
		t.Fatal("gratuitous reply overwrote a static seed")
	}
	// Passief leren: ook geen effect.
	tbl.learn(gw, evil, t0)
	if got, _ := tbl.resolve(gw, t0); got != mac {
		t.Fatal("passive learning overwrote a static seed")
	}
	// En er gaat geen query de deur uit voor een geseed adres.
	if _, ok := tbl.emit(make([]byte, 64), t0); ok {
		t.Fatal("seeded address still produced an ARP query")
	}
}
