// Package leannet is een kleine TCP/IP-stack voor bare-metal Go (tamago):
// ethernet, ARP, IPv4, ICMP-echo, UDP en TCP, plus een socket-laag die
// net.Conn/net.Listener/net.PacketConn levert voor net.SocketFunc. Stdlib-only.
//
// Het gemeten probleem (2026-08-11, HopOS op een 64MB-raam): de vorige stack
// (lneto + go-net, ~13k regels via twee forks) claimde geheugen naar
// CONFIGURATIE in plaats van naar gebruik — 2MB per listener vooraf plus 256KB
// per uitgaande dial uit één TCPBufferSize-knop. Dat was op QEMU reproduceerbaar
// een OOM binnen 151 seconden download-last. Dezelfde review (29 bevindingen,
// BEVINDINGEN.md in onze lneto-clone) bewees dat een verloren kale FIN daar
// nooit hergezonden wordt: verbindingen die tijdens het sluiten één frame
// verliezen wedgen stil, en acht daarvan maakten een 8-slots listener blijvend
// doof — op ijzer gezien als de dode console-poort van 11-08.
//
// leannet draait dat om. Er is één totale pot, Config.Budget: "hier heb je 2MB
// (klein board) of 40MB (server), deel het zelf in." MaxBufPerConn is alleen
// een optionele klem op het aandeel van één verbinding, geen tweede pot. Niets
// wordt vooraf geclaimd; elke verbinding start met 16 KiB ontvangst- en 4 KiB
// zendruimte en groeit op gemeten druk (een volle ontvangstring, of een Write
// die niet past terwijl de peer meer venster biedt), standaard geklemd op
// Budget/4 per verbinding en op wat de pot vrij heeft. Past zelfs de floor niet,
// dan weigert de stack luid in plaats van stil te verhongeren.
//
// Retransmissie werkt op sequence-ruimte, niet op "data": SYN en FIN doen
// gewoon mee en worden dus hergezonden. De klok in alle timer-contracten is
// monotoon. Out-of-order ontvangst wordt in v1 niet gereassembleerd maar
// gedropt met een directe dup-ACK, zodat de peer fast-retransmit kan doen.
//
// De motivering staat in het [ontwerpdossier]. De bevroren,
// package-overstijgende scope en release-gate staan in de [KAM].
//
// [ontwerpdossier]: https://github.com/xinix00/lean/blob/main/leannet/DESIGN.md
// [KAM]: https://github.com/xinix00/lean/blob/main/KAM.md
package leannet
