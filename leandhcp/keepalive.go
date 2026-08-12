package leandhcp

// keepalive.go — de lease levend houden ná de bring-up, als de netstack er is.
//
// Twee dingen scheiden dit van leandhcp.go. Het eerste is de weg: Acquire praat
// in rauwe frames omdat er dan nog geen stack is, maar zodra hopnet's rxLoop de
// NIC-RX bezit (de driverringen zijn lock-vrij, dus een tweede Receive-lus zou
// ze desynchroniseren) mag hier geen NIC meer aan te pas komen. Renew en Rebind
// openen dus een UDP-socket op de stack, en die doet de RX-demux en de
// TX-serialisatie zelf.
//
// Het tweede is de RFC-2131-staatmachine (§4.4.5), en die was hier eerder
// samengevouwen: KeepAlive deed de T1-renew en probeerde daarna zes keer met
// dertig seconden ertussen, wat op niets uit de lease sloeg. Dat is het gat dat
// telt: de unicast-renew gaat naar de lessor, en juist als DIE weg is (nieuwe
// router, verhuisde DHCP-server) faalt hij tot in het oneindige terwijl er een
// andere server op het segment staat die de lease zou verlengen. Daarvoor
// bestaat REBINDING: op T2 stapt de client over op broadcast en vraagt het aan
// wie het wil horen. Zonder die stap verliest de node zijn IP bij precies de
// storing waar DHCP een antwoord voor heeft.
//
// De hele machine is testbaar zonder sockets en zonder te wachten: alle tijd en
// al het verkeer lopen door de naden van keeper (sleep/renew/rebind/logf).

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// State is de RFC-2131-staat van een lease.
type State uint8

const (
	StateBound     State = iota // we hebben een geldig adres, niets te doen
	StateRenewing               // vanaf T1: unicast naar de lessor
	StateRebinding              // vanaf T2: broadcast naar elke server
	StateExpired                // voorbij de lease-tijd: het adres is niet meer van ons
)

func (s State) String() string {
	switch s {
	case StateBound:
		return "bound"
	case StateRenewing:
		return "renewing"
	case StateRebinding:
		return "rebinding"
	case StateExpired:
		return "expired"
	}
	return "unknown"
}

// Tijden van het onderhoudspad. requestTimeout is hoe lang één poging op een
// ACK wacht; retryFloor is de RFC-2131-vloer onder de tijd tussen pogingen (hij
// bestaat om een server niet te bestormen).
const (
	requestTimeout = 10 * time.Second
	retryFloor     = 60 * time.Second
)

// errRefused is een DHCPNAK: de server zegt dat dit adres niet (meer) van ons
// is. Dat is geen "probeer straks nog eens" — het is een weigering, en er
// doorheen blijven praten op dat IP is actief fout.
var errRefused = errors.New("server refused the lease (DHCPNAK)")

// timers geeft de drie momenten van een lease, gerekend vanaf het binnenkomen
// van de ACK: T1 (renewen), T2 (rebinden) en het einde. Alle drie nul betekent
// "niets te timen" — een oneindige (0xFFFFFFFF) of onbekende lease.
//
// De server mag T1 en T2 zelf kiezen, maar niet alles wat hij stuurt is
// bruikbaar: er zijn routers in het veld die T1 = T2 = lease sturen, en dan zou
// de rebind-fase nul tijd hebben. Alles buiten de orde 0 < T1 < T2 < lease valt
// daarom terug op de RFC-2131-verhoudingen (0.5 en 0.875) in plaats van de
// staatmachine te laten ontsporen op een getal van iemand anders.
func (l Lease) timers() (t1, t2, expiry time.Duration) {
	if l.LeaseSecs == 0 || l.LeaseSecs == 0xFFFFFFFF {
		return 0, 0, 0
	}
	sec := func(v uint32) time.Duration { return time.Duration(v) * time.Second }
	expiry = sec(l.LeaseSecs)
	t1, t2 = sec(l.T1Secs), sec(l.T2Secs)
	if t1 <= 0 || t1 >= expiry {
		t1 = expiry / 2
	}
	if t2 <= t1 || t2 >= expiry {
		t2 = expiry / 8 * 7
	}
	if t1 >= t2 { // de server zette T1 bóven 0.875·lease: dan is T1 het foute getal
		t1 = expiry / 2
	}
	return t1, t2, expiry
}

// retryAfter geeft de wachttijd tot de volgende poging: de helft van wat er nog
// rest tot de volgende fase, met retryFloor als vloer (RFC 2131 §4.4.5). Nooit
// méér dan wat er rest — anders zouden we de fasegrens voorbij slapen en de
// rebind te laat beginnen, en de vloer beschermt de server tegen een storm, niet
// de grens tegen zichzelf.
func retryAfter(left time.Duration) time.Duration {
	wait := left / 2
	if wait < retryFloor {
		wait = retryFloor
	}
	if wait > left {
		wait = left
	}
	return wait
}

// Renew vernieuwt de lease bij de lessor: een unicast REQUEST met ciaddr =
// lease-IP en zonder optie 50/54 (RFC 2131 §4.3.2). Dit is de goedkope weg —
// één pakket naar één server die ons al kent.
func Renew(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
	return request(l, mac, timeout, l.Server, StateRenewing)
}

// Rebind is dezelfde REQUEST als broadcast, voor als de lessor niet meer
// antwoordt: elke DHCP-server op het segment mag hem beantwoorden. De
// broadcast-flag in de BOOTP-header blijft UIT — we hebben een geldig IP en
// kunnen unicast ontvangen, dus het antwoord komt op ciaddr terug. Dat is geen
// detail: onze eigen ingress negeert broadcast-IP's, dus een geantwoord
// broadcast zouden we niet zien.
func Rebind(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
	return request(l, mac, timeout, [4]byte{255, 255, 255, 255}, StateRebinding)
}

// renewXID levert een verse transactie-id per poging. Niet uit de wandklok: die
// stapt bij boot (SNTP) en is dus geen bron van uniciteit; een teller in het
// proces is dat wél. De "HOP"-voorloop maakt onze pakketten herkenbaar in een
// capture, net als bij Acquire.
var renewXID atomic.Uint32

// leaseConn is de UDP-socket die request gebruikt; *net.UDPConn voldoet eraan.
// Hij bestaat als type zodat de logica erboven (NAK herkennen, late pakketten
// overslaan, de lease samenvoegen) los van een echte socket te proeven is. De
// bind zelf is één regel en die staat wél op ijzer en in QEMU.
type leaseConn interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// listenLease opent de client-poort op ons eigen adres. Poort 68 is niet
// onderhandelbaar: servers antwoorden daarop.
var listenLease = func(ip [4]byte) (leaseConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(ip[:]), Port: 68})
}

// request doet één REQUEST naar server (de lessor of het broadcastadres) en
// wacht op de ACK. Een NAK is een fout die errRefused draagt.
func request(l Lease, mac [6]byte, timeout time.Duration, server [4]byte, state State) (Lease, error) {
	conn, err := listenLease(l.IP)
	if err != nil {
		return Lease{}, fmt.Errorf("dhcp %s: bind :68: %w", state, err)
	}
	defer conn.Close()

	xid := 0x484F5200 | renewXID.Add(1)&0xff
	req := bootp(mac, xid, msgRequest, l.IP, false, nil)
	if _, err := conn.WriteToUDP(req, &net.UDPAddr{IP: net.IP(server[:]), Port: 67}); err != nil {
		return Lease{}, fmt.Errorf("dhcp %s: TX: %w", state, err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return Lease{}, fmt.Errorf("dhcp %s: no ACK within %v: %w", state, timeout, err)
		}
		if nl, ok := parseBootp(buf[:n], mac, xid, msgACK); ok {
			return merge(l, nl), nil
		}
		if _, ok := parseBootp(buf[:n], mac, xid, msgNAK); ok {
			return Lease{}, fmt.Errorf("dhcp %s: %w", state, errRefused)
		}
		// Iets anders of iets laats op :68 — binnen de deadline doorlezen.
	}
}

// merge legt een vers antwoord over de bestaande lease. Een ACK op een RENEW
// herhaalt masker/router/DNS/server vaak niet, en soms zelfs de lease-tijden
// niet; wat ontbreekt draagt de oude lease. Zonder deze regel zou een karige
// server ons LeaseSecs op nul zetten en daarmee de hele timing (en dus het
// onderhoud) stilzwijgend uitzetten.
func merge(old, fresh Lease) Lease {
	if fresh.IP == ([4]byte{}) {
		fresh.IP = old.IP
	}
	if fresh.Mask == ([4]byte{}) {
		fresh.Mask = old.Mask
	}
	if fresh.GW == ([4]byte{}) {
		fresh.GW = old.GW
	}
	if fresh.DNS == ([4]byte{}) {
		fresh.DNS = old.DNS
	}
	if fresh.Server == ([4]byte{}) {
		fresh.Server = old.Server
	}
	if fresh.LeaseSecs == 0 {
		fresh.LeaseSecs, fresh.T1Secs, fresh.T2Secs = old.LeaseSecs, old.T1Secs, old.T2Secs
	}
	fresh.Acquired = true
	return fresh
}

// KeepAlive houdt de lease levend in een eigen goroutine, volgens RFC 2131
// §4.4.5: slapen tot T1, dan RENEWING (unicast naar de lessor, met halverende
// pogingen); antwoordt die niet vóór T2, dan REBINDING (broadcast, idem tot de
// lease-tijd om is); daarna is het adres niet meer van ons en zegt het dat luid.
//
// RX-veilig: alles loopt over de netstack, dus dit raakt de NIC-RX niet en mag
// náást hopnet's rxLoop draaien. Start het PAS nadat hopnet de stack in
// net.SocketFunc hing (hopnet.Up doet dat op het juiste moment).
func KeepAlive(mac [6]byte, lease Lease) {
	if !lease.Acquired {
		return // niets te onderhouden; een statische config heeft geen lease
	}
	k := &keeper{
		mac:    mac,
		lease:  lease,
		sleep:  sleepChunked,
		renew:  Renew,
		rebind: Rebind,
		logf:   func(format string, a ...any) { fmt.Printf(format, a...) },
	}
	k.run()
}

// keeper is de staatmachine los van de buitenwereld. De vier naden onderaan
// dragen álle tijd en álle pakketten, zodat een test de hele cyclus (bound →
// renewing → rebinding → expired) in microseconden doorloopt in plaats van in
// dagen — en dus ook de paden die je op ijzer nooit uitlokt.
type keeper struct {
	mac   [6]byte
	lease Lease

	sleep  func(time.Duration)
	renew  func(Lease, [6]byte, time.Duration) (Lease, error)
	rebind func(Lease, [6]byte, time.Duration) (Lease, error)
	logf   func(format string, a ...any)
}

func (k *keeper) run() {
	for {
		t1, t2, expiry := k.lease.timers()
		if t1 <= 0 {
			return // oneindige of onbekende lease: er is niets te timen
		}
		k.sleep(t1)

		// elapsed is de tijd sinds de ACK, door ONS geteld uit de eigen slaapjes.
		// Niet van de klok afgelezen: tamago heeft één tijdbasis en die stapt bij
		// boot (epoch → nu, via SNTP), dus een wandklok-deadline zou hier in één
		// keer aflopen. Dezelfde les als sleepChunked.
		elapsed := t1
		state := StateRenewing
		var fresh Lease
		for {
			var err error
			if state == StateRenewing {
				fresh, err = k.renew(k.lease, k.mac, requestTimeout)
			} else {
				fresh, err = k.rebind(k.lease, k.mac, requestTimeout)
			}
			if err == nil {
				break
			}
			if errors.Is(err, errRefused) {
				k.logf("dhcp: %s is no longer ours (%v) — a reboot acquires a new address HOPOS_DHCP_NAK\n",
					k.lease.IPString(), err)
				return
			}
			k.logf("dhcp: %v\n", err)

			elapsed += requestTimeout
			limit := t2
			if state == StateRebinding {
				limit = expiry
			}
			if left := limit - elapsed; left > 0 {
				wait := retryAfter(left)
				k.sleep(wait)
				elapsed += wait
				continue
			}
			if state == StateRenewing {
				state = StateRebinding
				k.logf("dhcp: no answer from %s before T2 — rebinding by broadcast HOPOS_DHCP_REBIND\n",
					ipStr(k.lease.Server))
				continue
			}
			k.logf("dhcp: lease on %s EXPIRED and could not be rebound; the address is no longer ours HOPOS_DHCP_EXPIRED\n",
				k.lease.IPString())
			return
		}

		// Een rebind mag bij een ándere server uitkomen, en die mag een ánder
		// adres geven. Dat kunnen we niet toepassen: de stack is bij bring-up op
		// één IP geconfigureerd. Doorgaan zou betekenen dat de server denkt dat
		// we het nieuwe adres hebben terwijl we het oude gebruiken — en dan deelt
		// hij ons oude adres straks aan iemand anders uit.
		if fresh.IP != k.lease.IP {
			k.logf("dhcp: server offered %s instead of %s; a running node cannot change address — "+
				"a reboot picks up the new one HOPOS_DHCP_MOVED\n", fresh.IPString(), k.lease.IPString())
			return
		}
		k.lease = fresh
		k.logf("dhcp: lease extended (%s) — %s, %ds to go HOPOS_DHCP_RENEW\n",
			state, k.lease.IPString(), k.lease.LeaseSecs)
	}
}

// sleepChunked slaapt d in plakken van een minuut en telt zelf: tamago heeft
// ÉÉN tijdbasis, dus een SNTP-kloksprong (epoch→nu bij boot) laat een kale
// Sleep(d) in één keer aflopen — dat wás de "renewal bij boot" (gemeten
// 2026-07-11). Geplakt kost een sprong hooguit één plak.
func sleepChunked(d time.Duration) {
	const chunk = time.Minute
	for ; d > chunk; d -= chunk {
		time.Sleep(chunk)
	}
	time.Sleep(d)
}
