// Package leandhcp is een minimale DHCPv4-client (RFC 2131): de volledige
// DISCOVER→OFFER→REQUEST→ACK-handshake op rauwe ethernet-frames, vóór er een
// netstack bestaat — precies genoeg om een lease te halen waarmee je je
// eigen stack configureert. Polled, één poging per timeout-window; de
// aanroeper bepaalt het geduld. Het NIC-contract is twee methodes (rauwe
// frames in en uit), dus élke driver of tap past erop.
//
// De DISCOVER/OFFER-helft is boardvast bewezen op de Pi 5 (probe6 run 5,
// 2026-07-10: OFFER 192.168.178.33 van een FRITZ!Box door onze eigen
// PCIe→RP1→GEM-keten).
package leandhcp

import (
	"fmt"
	"math/bits"
	"net"
	"time"
)

// NIC is het rauwe-frame-contract (structureel gelijk aan go-net's
// NetworkDevice; gem.Net en virtionet.Net voldoen er beide aan).
type NIC interface {
	Receive(buf []byte) (int, error)
	Transmit(buf []byte) error
}

// Lease is het resultaat van een geslaagde handshake.
type Lease struct {
	IP     [4]byte
	Mask   [4]byte // optie 1
	GW     [4]byte // optie 3 (eerste router)
	DNS    [4]byte // optie 6 (eerste resolver; 0.0.0.0 = geen)
	Server [4]byte // optie 54 (de lessor)

	// Lease-timers uit de ACK (seconden). LeaseSecs = optie 51 (totale duur;
	// 0xFFFFFFFF = oneindig). T1Secs = optie 58 (renew-tijd); afwezig (0) →
	// val terug op 0.5·LeaseSecs voor de vernieuwing (KeepAlive).
	LeaseSecs uint32
	T1Secs    uint32

	// Acquired markeert een echt uit een ACK verkregen lease (vs. de nulwaarde);
	// KeepAlive draait alleen op een verkregen lease.
	Acquired bool
}

// be32 leest een 4-byte big-endian veld (DHCP-optiewaarden 51/58).
func be32(d []byte) uint32 {
	return uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
}

func ipStr(a [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }

// IPString/GWString/DNSString geven de velden in tekstvorm
// (board.NetConfig, diagnose).
func (l Lease) IPString() string  { return ipStr(l.IP) }
func (l Lease) GWString() string  { return ipStr(l.GW) }
func (l Lease) DNSString() string { return ipStr(l.DNS) }

// CIDR geeft "ip/prefix" — de vorm die de netstack (gnet.Interface) eet.
func (l Lease) CIDR() string {
	m := uint32(l.Mask[0])<<24 | uint32(l.Mask[1])<<16 | uint32(l.Mask[2])<<8 | uint32(l.Mask[3])
	return fmt.Sprintf("%s/%d", ipStr(l.IP), bits.OnesCount32(m))
}

// Acquire draait de handshake op de NIC en geeft de lease. Retries binnen de
// timeout (per ronde 3s wachten op het antwoord); xid per ronde vers zodat
// een laat OFFER van een vorige ronde ons niet in de war brengt.
func Acquire(nic NIC, mac [6]byte, timeout time.Duration) (Lease, error) {
	deadline := time.Now().Add(timeout)
	// rxErr is de laatste RX-fout van de NIC. Als er nooit een lease komt is dít
	// het verschil tussen "geen DHCP-server op dit segment" en "deze NIC levert
	// geen frames" — twee diagnoses die de operator naar twee andere plekken
	// sturen, en de tweede zag hij tot nu toe nooit.
	var rxErr error
	for ronde := uint32(1); ; ronde++ {
		if !time.Now().Before(deadline) {
			if rxErr != nil {
				return Lease{}, fmt.Errorf("dhcp: no lease within %v; last NIC receive error: %w", timeout, rxErr)
			}
			return Lease{}, fmt.Errorf("dhcp: no lease within %v (no server answered)", timeout)
		}
		xid := 0x484F5000 | ronde // "HOP" + ronde

		if err := nic.Transmit(packet(mac, xid, 1, nil)); err != nil { // DISCOVER
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		offer, ok, err := await(nic, mac, xid, 2, deadline) // OFFER
		if err != nil {
			rxErr = err
		}
		if !ok {
			continue
		}

		// REQUEST bevestigt het aanbod (optie 50 = het IP, 54 = de server).
		req := []byte{
			50, 4, offer.IP[0], offer.IP[1], offer.IP[2], offer.IP[3],
			54, 4, offer.Server[0], offer.Server[1], offer.Server[2], offer.Server[3],
		}
		if err := nic.Transmit(packet(mac, xid, 3, req)); err != nil {
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		ack, ok, err := await(nic, mac, xid, 5, deadline) // ACK
		if err != nil {
			rxErr = err
		}
		if ok {
			ack.Acquired = true
			return ack, nil
		}
	}
}

// Renew vernieuwt de lease met een unicast RFC-2131-RENEW (ciaddr = lease-IP,
// een REQUEST rechtstreeks naar de lessor, géén optie 50/54) — maar via de
// gVisor-netstack (het net-pakket), niet via rauwe frames. Dat is de kern van de
// RX-veiligheid: na bring-up bezit hopnet's rxLoop de NIC-RX (de driverringen
// zijn lock-vrij, dus een tweede Receive-lus zou ze desynchroniseren), maar de
// stack doet zelf de RX-demux (UDP-poort 68) én de TX-serialisatie. Renew leent
// dus geen NIC — het opent een UDP-socket op de stack. Vereist dat hopnet de
// stack al in net.SocketFunc hing (Up doet dat vóór het KeepAlive start).
func Renew(l Lease, mac [6]byte, timeout time.Duration) (Lease, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(l.IP[:]), Port: 68})
	if err != nil {
		return Lease{}, fmt.Errorf("dhcp renew: bind :68: %w", err)
	}
	defer conn.Close()

	xid := uint32(time.Now().UnixNano()) | 1
	req := bootp(mac, xid, 3, l.IP, false, nil) // REQUEST, ciaddr = lease-IP, unicast
	if _, err := conn.WriteToUDP(req, &net.UDPAddr{IP: net.IP(l.Server[:]), Port: 67}); err != nil {
		return Lease{}, fmt.Errorf("dhcp renew: TX: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return Lease{}, fmt.Errorf("dhcp renew: no ACK within %v: %w", timeout, err)
		}
		nl, ok := parseBootp(buf[:n], mac, xid, 5) // ACK
		if !ok {
			continue // ander of laat pakket op :68 — binnen de deadline doorlezen
		}
		nl.Acquired = true
		// Een RENEW-ACK herhaalt masker/router/DNS/server soms niet; draag de
		// bestaande waarde dan door (de lease-tijden komen wél altijd mee).
		if nl.Mask == ([4]byte{}) {
			nl.Mask = l.Mask
		}
		if nl.GW == ([4]byte{}) {
			nl.GW = l.GW
		}
		if nl.DNS == ([4]byte{}) {
			nl.DNS = l.DNS
		}
		if nl.Server == ([4]byte{}) {
			nl.Server = l.Server
		}
		return nl, nil
	}
}

// KeepAlive houdt de lease levend in een eigen goroutine: het slaapt tot T1
// (optie 58, of anders 0.5·lease-tijd) en doet dan een unicast-RENEW via de
// netstack (Renew). Lukt dat niet, dan blijft het tot ~T2 kort proberen; daarna
// geeft het luid op (de node behoudt zijn IP tot de router het heruitdeelt — een
// reboot re-acquire't; een broadcast-rebind op T2 is de nette vervolgstap).
//
// RX-veilig: Renew loopt volledig over de netstack, dus KeepAlive raakt de
// NIC-RX niet en mag náást hopnet's rxLoop draaien. Start het PAS nadat hopnet
// de stack in net.SocketFunc hing (hopnet.Up doet dat op het juiste moment).
func KeepAlive(mac [6]byte, lease Lease) {
	for {
		wait := lease.renewAfter()
		if wait <= 0 {
			return // onbekende of oneindige lease: niets te timen
		}
		sleepChunked(wait)

		renewed := false
		for attempt := 0; attempt < 6; attempt++ {
			l, err := Renew(lease, mac, 10*time.Second)
			if err == nil {
				lease = l
				renewed = true
				fmt.Printf("dhcp: lease renewed — %s (%ds remaining) HOPOS_DHCP_RENEW\n",
					lease.IPString(), lease.LeaseSecs)
				break
			}
			fmt.Printf("dhcp: renew attempt %d failed (%v)\n", attempt+1, err)
			time.Sleep(30 * time.Second)
		}
		if !renewed {
			fmt.Printf("dhcp: lease NOT renewed — keeping %s until the router reclaims it HOPOS_DHCP_RENEW_FAIL\n",
				lease.IPString())
			return
		}
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

// renewAfter geeft de wachttijd tot de eerstvolgende vernieuwing: T1 (optie 58)
// indien bekend, anders de helft van de lease-tijd. 0 = geen timing (onbekende
// of oneindige lease → geen vernieuwing).
func (l Lease) renewAfter() time.Duration {
	switch {
	case l.LeaseSecs == 0xFFFFFFFF:
		return 0 // oneindige lease: nooit vernieuwen
	case l.T1Secs > 0:
		return time.Duration(l.T1Secs) * time.Second
	case l.LeaseSecs > 0:
		return time.Duration(l.LeaseSecs/2) * time.Second
	default:
		return 0
	}
}

// await polt tot msgtype (2=OFFER, 5=ACK) voor onze xid binnenkomt, of tot
// het ronde-window (3s, begrensd door de totale deadline) sluit.
//
// De fout van Receive gaat MEE naar boven. Hij werd hier weggegooid, en dat maakte
// van elke kapotte NIC een "geen DHCP-server": drie seconden stil pollen op een
// driver die bij elk frame hetzelfde meldt, en dan een timeout-melding die de
// operator naar zijn router stuurt in plaats van naar de kabel of de driver. Een
// RX-fout is bovendien niet per definitie fataal (een enkel frame kan best
// afketsen), dus de ronde loopt door en de LAATSTE fout gaat mee — de aanroeper
// kiest of hij hem noemt.
func await(nic NIC, mac [6]byte, xid uint32, msgtype byte, deadline time.Time) (Lease, bool, error) {
	window := time.Now().Add(3 * time.Second)
	if window.After(deadline) {
		window = deadline
	}
	buf := make([]byte, 1536)
	var lastErr error
	for time.Now().Before(window) {
		n, err := nic.Receive(buf)
		if err != nil {
			lastErr = err
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		if l, ok := parse(buf[:n], mac, xid, msgtype); ok {
			return l, true, nil
		}
	}
	return Lease{}, false, lastErr
}

// packet bouwt één DHCP-frame: ethernet-broadcast, IPv4 0.0.0.0 →
// 255.255.255.255, UDP 68→67 (checksum 0 = uit, mag bij IPv4), BOOTP met
// broadcast-flag (het antwoord komt dan als broadcast — onafhankelijk van
// het RX-unicast-filter), DHCP-magic + optie 53 (msgtype) + extra + 255.
func packet(mac [6]byte, xid uint32, msgtype byte, extra []byte) []byte {
	f := make([]byte, 14+20+8+300)
	for i := range 6 {
		f[i] = 0xff
	}
	copy(f[6:12], mac[:])
	f[12], f[13] = 0x08, 0x00

	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17 // IHL 5, TTL, UDP
	tot := len(f) - 14
	ip[2], ip[3] = byte(tot>>8), byte(tot)
	ip[16], ip[17], ip[18], ip[19] = 255, 255, 255, 255
	cs := checksum(ip)
	ip[10], ip[11] = byte(cs>>8), byte(cs)

	udp := f[34:42]
	udp[1], udp[3] = 68, 67
	ul := tot - 20
	udp[4], udp[5] = byte(ul>>8), byte(ul)

	// De BOOTP-payload: broadcast-DORA (ciaddr 0, broadcast-flag aan → het
	// antwoord komt als broadcast, onafhankelijk van het RX-unicast-filter).
	copy(f[42:], bootp(mac, xid, msgtype, [4]byte{}, true, extra))
	return f
}

// bootp bouwt de BOOTP/DHCP-boodschap (de UDP-payload los van het frame):
// op/htype/hlen, xid, ciaddr (het lease-IP bij een RENEW, anders 0), chaddr,
// DHCP-magic en de opties (53 msgtype + 55 parameter-request voor masker/
// router/DNS/lease/T1/T2 + de aanroeper-extra's + einde 255). bcast zet de
// broadcast-flag (DISCOVER/DORA bij boot, nog zonder IP); een unicast RENEW,
// die al een IP heeft en rechtstreeks met de lessor praat, laat 'm uit.
func bootp(mac [6]byte, xid uint32, msgtype byte, ciaddr [4]byte, bcast bool, extra []byte) []byte {
	bp := make([]byte, 300)
	bp[0], bp[1], bp[2] = 1, 1, 6 // BOOTREQUEST, ethernet, hlen
	bp[4], bp[5], bp[6], bp[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)
	if bcast {
		bp[10] = 0x80 // broadcast-flag
	}
	copy(bp[12:16], ciaddr[:]) // ciaddr: gezet bij RENEW (RFC 2131 §4.3.2)
	copy(bp[28:34], mac[:])
	copy(bp[236:240], []byte{99, 130, 83, 99}) // DHCP-magic
	o := append([]byte{53, 1, msgtype, 55, 5, 1, 3, 6, 51, 58}, extra...)
	copy(bp[240:], append(o, 255))
	return bp
}

// checksum is de standaard 16-bit one's-complement over de IP-header.
func checksum(h []byte) uint16 {
	var s uint32
	for i := 0; i < len(h); i += 2 {
		s += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// parse valideert een frame als DHCP-antwoord (BOOTREPLY, onze xid en MAC,
// optie 53 = msgtype) en licht de lease-velden eruit.
func parse(f []byte, mac [6]byte, xid uint32, msgtype byte) (Lease, bool) {
	if len(f) < 14+20+8+240 || f[12] != 0x08 || f[13] != 0 || f[23] != 17 {
		return Lease{}, false
	}
	ihl := int(f[14]&0xf) * 4
	udp := f[14+ihl:]
	if len(udp) < 8+240 || udp[2] != 0 || udp[3] != 68 { // dst-poort 68
		return Lease{}, false
	}
	return parseBootp(udp[8:], mac, xid, msgtype)
}

// parseBootp licht de lease uit een BOOTP/DHCP-boodschap (de UDP-payload, los
// van het frame — de vorm die zowel het boot-pad (parse na frame-unwrap) als
// de netstack-RENEW (Renew leest de payload rechtstreeks uit de socket) voedt):
// BOOTREPLY, onze xid en chaddr, optie 53 = msgtype.
func parseBootp(bp []byte, mac [6]byte, xid uint32, msgtype byte) (Lease, bool) {
	if len(bp) < 240 || bp[0] != 2 { // BOOTREPLY
		return Lease{}, false
	}
	if uint32(bp[4])<<24|uint32(bp[5])<<16|uint32(bp[6])<<8|uint32(bp[7]) != xid {
		return Lease{}, false
	}
	for i := range 6 {
		if bp[28+i] != mac[i] {
			return Lease{}, false
		}
	}

	var l Lease
	copy(l.IP[:], bp[16:20]) // yiaddr

	// Opties: [code len data...], 0 = pad, 255 = einde.
	opts := bp[240:]
	typeOK := false
	for i := 0; i+1 < len(opts); {
		code := opts[i]
		if code == 0 {
			i++
			continue
		}
		if code == 255 {
			break
		}
		ln := int(opts[i+1])
		if i+2+ln > len(opts) {
			break
		}
		d := opts[i+2 : i+2+ln]
		switch code {
		case 53:
			typeOK = ln == 1 && d[0] == msgtype
		case 1:
			if ln >= 4 {
				copy(l.Mask[:], d)
			}
		case 3:
			if ln >= 4 {
				copy(l.GW[:], d)
			}
		case 6:
			if ln >= 4 {
				copy(l.DNS[:], d)
			}
		case 54:
			if ln >= 4 {
				copy(l.Server[:], d)
			}
		case 51: // lease-tijd (seconden)
			if ln >= 4 {
				l.LeaseSecs = be32(d)
			}
		case 58: // T1 (renew-tijd)
			if ln >= 4 {
				l.T1Secs = be32(d)
			}
		}
		i += 2 + ln
	}
	return l, typeOK
}
