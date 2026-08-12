// Package leandhcp is een minimale DHCPv4-client (RFC 2131): de volledige
// DISCOVER→OFFER→REQUEST→ACK-handshake op rauwe ethernet-frames, vóór er een
// netstack bestaat — precies genoeg om een lease te halen waarmee je je
// eigen stack configureert. Polled, één poging per timeout-window; de
// aanroeper bepaalt het geduld. Het NIC-contract is twee methodes (rauwe
// frames in en uit), dus élke driver of tap past erop.
//
// Het pakket heeft twee helften, en de scheiding is de netstack:
//
//   - leandhcp.go — de bring-up. Rauwe frames op de NIC, want er is nog niets
//     anders. Dit is Acquire.
//   - keepalive.go — de lease levend houden, ná de bring-up. Dat gaat over de
//     stack (een UDP-socket), want de RX-lus van de NIC heeft dan één eigenaar.
//     Dit is de staatmachine van RFC 2131 §4.4.5: bound, renewing, rebinding.
//
// De DISCOVER/OFFER-helft is boardvast bewezen op de Pi 5 (probe6 run 5,
// 2026-07-10: OFFER 192.168.178.33 van een FRITZ!Box door onze eigen
// PCIe→RP1→GEM-keten).
package leandhcp

import (
	"fmt"
	"math/bits"
	"time"
)

// NIC is het rauwe-frame-contract (structureel gelijk aan go-net's
// NetworkDevice; gem.Net en virtionet.Net voldoen er beide aan).
type NIC interface {
	Receive(buf []byte) (int, error)
	Transmit(buf []byte) error
}

// DHCP-boodschapstypes (optie 53) die deze client kent.
const (
	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgACK      = 5
	msgNAK      = 6
)

// Tijden van het boot-pad. roundWindow is hoe lang één DORA-ronde op antwoord
// wacht; ackGrace is de minimum-tijd die een REQUEST krijgt, óók voorbij de
// deadline (zie await).
const (
	roundWindow = 3 * time.Second
	ackGrace    = time.Second
)

// Lease is het resultaat van een geslaagde handshake.
type Lease struct {
	IP     [4]byte
	Mask   [4]byte // optie 1
	GW     [4]byte // optie 3 (eerste router)
	DNS    [4]byte // optie 6 (eerste resolver; 0.0.0.0 = geen)
	Server [4]byte // optie 54 (de lessor)

	// Lease-timers uit de ACK (seconden). LeaseSecs = optie 51 (totale duur;
	// 0xFFFFFFFF = oneindig), T1Secs = optie 58 (renew-tijd), T2Secs = optie 59
	// (rebind-tijd). Ontbreken ze of zijn ze onzin, dan gelden de RFC-2131
	// -verhoudingen 0.5 en 0.875 — zie Lease.timers.
	LeaseSecs uint32
	T1Secs    uint32
	T2Secs    uint32

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

		if err := nic.Transmit(packet(mac, xid, msgDiscover, nil)); err != nil {
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		// Een DISCOVER bindt niets: loopt de deadline hier af, dan is er niets
		// verloren en is "geen server" het eerlijke antwoord (least = 0).
		offer, ok, err := await(nic, mac, xid, msgOffer, deadline, 0)
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
		if err := nic.Transmit(packet(mac, xid, msgRequest, req)); err != nil {
			return Lease{}, fmt.Errorf("dhcp: TX: %w", err)
		}
		// Een REQUEST bindt WEL: de server reserveert het IP op onze MAC zodra
		// hij hem ziet. Daarom krijgt de ACK een minimum-window, ook als de
		// deadline er middenin valt — anders melden we een timeout voor een
		// lease die we hebben gekregen, en houdt de router een binding voor een
		// adres dat de node niet gebruikt. De overschrijding is begrensd
		// (ackGrace) en dus geen open eind.
		ack, ok, err := await(nic, mac, xid, msgACK, deadline, ackGrace)
		if err != nil {
			rxErr = err
		}
		if ok {
			ack.Acquired = true
			return ack, nil
		}
	}
}

// await polt tot msgtype (OFFER of ACK) voor onze xid binnenkomt, of tot het
// ronde-window (roundWindow, begrensd door de totale deadline) sluit. least
// tilt het window op tot minstens die duur vanaf nu, óók voorbij de deadline:
// de aanroeper zegt daarmee "dit antwoord is te belangrijk om af te kappen".
//
// De klok wordt alleen bekeken als de ring LEEG is. Dat is de laatste-tick-regel
// (lneto-bevinding #16): een antwoord dat er al ligt, is een antwoord — ook als
// het window net dichtging. Anders is de duurste uitkomst mogelijk die er is:
// de server heeft het IP aan onze MAC vergeven, wij rapporteren "geen server
// antwoordde", en de operator gaat naar zijn router kijken terwijl de lease daar
// gewoon staat. De grace-drain is wél begrensd, want op een druk segment blijft
// de ring vollopen en zou "leegmaken" nooit klaar zijn.
//
// De fout van Receive gaat MEE naar boven. Hij werd hier weggegooid, en dat maakte
// van elke kapotte NIC een "geen DHCP-server": drie seconden stil pollen op een
// driver die bij elk frame hetzelfde meldt, en dan een timeout-melding die de
// operator naar zijn router stuurt in plaats van naar de kabel of de driver. Een
// RX-fout is bovendien niet per definitie fataal (een enkel frame kan best
// afketsen), dus de ronde loopt door en de LAATSTE fout gaat mee — de aanroeper
// kiest of hij hem noemt.
func await(nic NIC, mac [6]byte, xid uint32, msgtype byte, deadline time.Time, least time.Duration) (Lease, bool, error) {
	window := time.Now().Add(roundWindow)
	if window.After(deadline) {
		window = deadline
	}
	if floor := time.Now().Add(least); window.Before(floor) {
		window = floor
	}
	buf := make([]byte, 1536)
	var lastErr error
	for grace := graceFrames; ; {
		n, err := nic.Receive(buf)
		if err != nil {
			lastErr = err
		}
		if n > 0 {
			if l, ok := parse(buf[:n], mac, xid, msgtype); ok {
				return l, true, nil
			}
		}
		if !time.Now().Before(window) {
			if n == 0 || grace == 0 {
				return Lease{}, false, lastErr
			}
			grace-- // het window is dicht, maar er lág nog een frame: doorlezen
			continue
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
		}
	}
}

// graceFrames begrenst hoeveel frames await na het sluiten van zijn window nog
// uit de ring haalt. Ruim voor het handjevol frames dat op een normaal segment
// naast ons antwoord staat, en klein genoeg dat een broadcast-storm de
// bring-up niet kan ophouden.
const graceFrames = 64

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
	o := append([]byte{53, 1, msgtype, 55, 6, 1, 3, 6, 51, 58, 59}, extra...)
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
		case 59: // T2 (rebind-tijd)
			if ln >= 4 {
				l.T2Secs = be32(d)
			}
		}
		i += 2 + ln
	}
	return l, typeOK
}
