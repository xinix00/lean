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
// leannet draait dat om. Er is één knop, Config.Budget: "hier heb je 2MB
// (klein board) of 40MB (server), deel het zelf in." Niets wordt vooraf
// geclaimd; elke verbinding start op een floor van enkele KiB en groeit op
// gemeten gebruik (zendkant volgt de congestion window, ontvangkant volgt wat
// de applicatie werkelijk per RTT uitleest), geklemd op Budget/4 per verbinding
// en op wat de pot vrij heeft. Past zelfs de floor niet, dan weigert de stack
// luid in plaats van stil te verhongeren.
//
// Retransmissie werkt op sequence-ruimte, niet op "data": SYN en FIN doen
// gewoon mee en worden dus hergezonden. De klok in alle timer-contracten is
// monotoon. Out-of-order ontvangst wordt in v1 niet gereassembleerd maar
// gedropt met een directe dup-ACK, zodat de peer fast-retransmit kan doen.
//
// Ontwerpdossier: hop-os/docs/leannet-ontwerp.md.
package leannet
