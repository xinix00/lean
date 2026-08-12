# leannet — waarom dit ding bestaat, en waarom het zo klein is

Dit document is er voor de vraag die over een jaar gesteld wordt: *waarom
staat hier geen SACK / geen reassembly / geen IPv6, en mag ik het toevoegen?*
Het antwoord is bijna altijd "alleen met een meting erbij", en hieronder staat
waarom.

## Het idee in één alinea

leannet is een TCP/IP-stack voor bare-metal Go die precies doet wat HopOS
nodig heeft en niets meer: een node bereikbaar maken (listeners voor de
agent/leader/console), artifacts binnenhalen (uitgaande TCP over TLS), en
namen en tijd ophalen (UDP voor DNS en SNTP). Alles daarbuiten is bewust
afwezig, niet nog-niet-gebouwd. Het geheugen komt uit één pot die de operator
in één getal instelt, en het schaalt met *gebruik* in plaats van met
configuratie.

## Waarom niet een bestaande stack

We hebben er twee gedragen en zijn bij beide weggelopen, met redenen die
allebei in code te controleren zijn:

**gVisor** (tot 09-08-2026). Werkte, en was fors: ~90k gelinkte regels, ~2,7MB
van elk app-image, 340k allocaties per 64MiB op het RX-pad, een
goroutine-handoff per segment. Op een node met 64MB is dat geen detail.

**lneto + go-net** (09-08 tot 12-08-2026). Veel dunner en snel (RX 26→61MB/s
op de bank), maar we gebruikten ~13k regels via **twee forks** met eigen tags,
en het moeilijke deel bleek niet af. Een review van 11-08 leverde 29
bevindingen op (`~/Git/lneto/BEVINDINGEN.md`), waaronder: een verloren kale FIN
werd nooit hergezonden (verbinding hangt stil, pool-slot lekt), een RTO in
FIN-WAIT-1 gooide de FIN uit de boekhouding, LAST-ACK aborteerde op élke ACK,
en de retransmissietimer liep op de wandklok terwijl de stack zelf zijn klok
via NTP verzet. Vier van die bevindingen zaten in onze eigen PR-takken: we
waren al mede-eigenaar van de complexiteit zonder de merge-rechten.

De doorslag was niet "het is stuk" maar **de reparatieroute**: een fix bereikte
onze nodes alleen via PR-diplomatie of via fork-onderhoud (`replace` werkt
alleen in de hoofdmodule, dus onze apps bouwden stil tegen ongepatchte
upstream). Voor de omvang van wat wij écht gebruiken is zelf bouwen goedkoper
dan dat onderhouden.

## Wat er bewust NIET in zit

Elke regel hieronder is een keuze met een reden, geen gat. Wie een van deze
dingen toevoegt, voegt ook de meting toe die aantoont dat het nodig was.

| niet aanwezig | waarom niet | wanneer wél |
|---|---|---|
| **Congestion control (cwnd, slow start)** | Downloads worden geremd door de *zender* (GitHub, Bunny); onze eigen uploads zijn heartbeats en API-antwoorden. Er is geen pad waar wij een congested link volpompen. | Zodra een node grote uploads over een congested WAN doet. De klemplek ligt klaar: de zendlus klemt nu alleen op `sndWnd`; cwnd wordt een tweede klem. |
| **Out-of-order reassembly (SACK, reorder-buffer)** | Een out-of-order segment wordt gedropt mét onmiddellijke dup-ACK; de peer herstelt via fast retransmit. RFC-legaal, en het scheelt de helft van de complexiteit — precies de helft waar lneto's bugs zaten. | Als de meetbank op écht ijzer aantoont dat reordering (niet verlies) de doorvoer kost. Op onze LAN's en via één gateway is reordering zeldzaam. |
| **IPv6 / NDP** | Geen enkele HopOS-omgeving vraagt het; de interne netten zijn IPv4 (`10.100.0.0/24`) en de LAN-kant komt uit DHCPv4. lneto's NDP droeg dezelfde race als zijn ARP — dubbel werk voor nul gebruik. | Als een deployment het eist. Het is een nieuwe demux-tak plus een buurtabel, niet een verbouwing. |
| **IPv4-fragmentatie en -opties** | Geweigerd met een eigen fout + teller. Fragmenten zijn op onze paden pathologisch (DF staat aan, MTU is 1500 overal); opties komen niet voor. Stil accepteren zou de teller onzichtbaar maken. | Nooit, tenzij een pad ze aantoonbaar stuurt. Dan is het een reassembly-laag met alle bijbehorende aanvals-oppervlak. |
| **TCP timestamps / PAWS** | Alleen nodig tegen sequence-wrap binnen één RTT (dat vergt >1Gbit/s aanhoudend) en voor fijnere RTT-metingen. Karn's algoritme is genoeg voor onze RTO. | Bij multi-gigabit doorvoer per verbinding. |
| **Nagle** | Staat uit. Embedded verkeer is klein en latency-gevoelig (heartbeats, API-calls); coalescing zou vertraging toevoegen waar niemand om vroeg. | Nooit als default. Eventueel een socket-optie. |
| **SYN-cookies** | De opgeef-grens (5 handshake-RTO's) plus de floor-per-verbinding en de budget-pot maken een flood duur zonder cookie-machinerie: een embryo kost enkele KiB en sterft binnen ~6 seconden. | Als een publieke node aantoonbaar geflood wordt. |
| **Urgent pointer, PSH-semantiek als API** | Niemand gebruikt het; `PSH` wordt gezet op data en verder genegeerd. | Nooit. |
| **Een logging-framework in de stack** | De stack logt niet, hij *telt* (`CntDropBadFrame`, `CntRefusedNoBudget`, ARP-tellers). De console van HopOS is een busy-wait per byte: één print per frame heeft op 11-08 een LicheeRV binnen 250s gedood. Wie het datapad laat praten, sloopt het datapad. | Nooit in het datapad. Tellers uitlezen mag altijd. |
| **Een tweede globale buffer-knop** | Inkomend/uitgaand of kern/app splitst op de verkeerde as: bulk en control bestaan in beide richtingen. De as die telt is per socket, en alleen de socket kent die. | Nooit. Zie het budgetmodel hieronder. |

## Wat er wél in zit, en waarom precies zo

**Eén knop: `Config.Budget`.** "Hier heb je 2MB (klein board) of 40MB (server),
deel het zelf in." Niets wordt vooraf geclaimd — een listener kost nul, een
dial kost nul extra. Elke verbinding start op een floor en verdubbelt op
*gemeten druk*: de ontvangstring als de peer hem tot de rand vult, de zendring
als een `Write` hem vult én de peer meer venster biedt dan de ring groot is.
Grow-only, geklemd op `Budget/4` per verbinding en op wat de pot vrij heeft;
bij close gaat alles terug.

De floors zijn asymmetrisch (16KiB ontvangen, 4KiB zenden) en dat is het enige
getal hier dat *niet* uit "groeien op druk" volgt. Reden: aan de ontvangkant
bepaalt de peer het tempo, en die begint met een initial congestion window van
10 segmenten (RFC 6928). Adverteren wij minder dan die burst, dan kan hij er
niet aan beginnen — en bij een snelle lezer loopt onze ring nooit vol, dus komt
de verdubbeling die dat zou repareren er nooit. Dan is óns venster permanent de
rem in plaats van de link. Aan de zendkant bestaat dat probleem niet: daar zet
de applicatie zelf de druk. (Het is hetzelfde getal dat gVisor als
receive-vloer kiest, om precies deze reden; zijn RTT-schatter erboven hebben we
niet nodig, deze vloer wel — gevonden bij het nalopen van het meetscenario vóór
de eerste ijzer-test, niet op ijzer.)

Dat mechanisme is bewust botter dan gVisors RTT-schatter (die het
ontvangstvenster dimensioneert op wat de app per RTT uitleest). Het kost
`log2(cap/floor)` RTT's opwarmen — op LAN onmeetbaar, op een 25ms-pad ~300ms —
en het heeft één eigenschap die een schatter mist: **het signaal ís de
werkelijkheid** (ring vol, venster geboden) in plaats van een voorspelling
ervan, dus het kan niet uit de pas lopen. Als "gewoon goed" volstaat, is dat
goed genoeg; gVisor is 300× de omvang.

Het probleem dat dit oploste, met getallen: de vorige stack claimde 2MB per
listener vooraf plus 256KB per uitgaande dial, uit één `TCPBufferSize`-knop.
Op een HOP-raam van 64MB was dat een reproduceerbare OOM binnen 151 seconden
download-last.

**Retransmissie werkt op sequence-ruimte, niet op "data".** SYN en FIN nemen
een sequencenummer in, dus ze rollen mee in het gewone go-back-N-pad: een RTO
spoelt `nxt` terug naar `una` en de zendlus regenereert vanaf daar wat er ook
stond — data, data+FIN, of een kale FIN. Er bestaat geen aparte vlaggen-wachtrij
die leeg kan raken terwijl het segment op de lijn verdwenen is. Dat is precies
de klasse waar lneto's drie hoge bevindingen zaten, en daarom is het hier geen
fix maar een ontwerpkeuze: `tcp.go`'s `txRing` maakt retransmissie een
*her-lezing* van dezelfde ring.

**Alle tijd is monotoon en wordt ingespoten.** De machines (`tcp`, `arp`)
krijgen `now int64` als parameter en houden geen klok. De stack gebruikt
`time.Since(start)`, nooit `time.Now().UnixNano()` — die verspringt als SNTP de
klok zet, en een RTO-deadline die daarop rekent vuurt dan meteen of nooit. Het
tweede voordeel is testbaarheid: élk faalscenario is deterministisch zonder
`sleep`.

**De stack logt niet en beslist niet over beleid.** Weigeren doet hij luid
(RST + teller): pot leeg, backlog vol, ARP gaf op. Stil vasthouden is de
ergste toestand die er is — dat was de console-dood van 11-08, waarbij acht
afgebroken browserverbindingen een listener blijvend doof maakten.

**De pomp slaapt tot de vroegste deadline.** Geen vaste tick: een idle stack
heeft geen wektijd staan en kost dus nul CPU. Dat is een harde eis op een node
die zijn core wil laten slapen (`metal/cpu/idle`), en een regressietest waakt
erover.

**Eén mutex over alle machine-staat.** Niet omdat het het snelst is, maar
omdat "welke lock hoort bij deze cache-entry" een bug-generator is (lneto had
een race op `CacheRemove` met een vergrendelde wrapper die er ongebruikt naast
lag). Knelt het ooit, dan is een tweede buffer de uitweg, niet een fijner slot.

## De vorm van de code

Vier lagen, van onder naar boven, elk in één bestand:

1. `frame.go` — in-place views over de draadformaten. Geen allocaties, elke
   `Parse*` weigert luid wat niet past.
2. `budget.go` + `ring.go` — de pot en de rings. `txRing` verankert de
   zendring in sequence-ruimte (kop = `snd.UNA`, cursor = verzonden).
3. `tcp.go`, `arp.go`, `udp.go`, `icmp.go` — pure machines: geen goroutines,
   geen klok, geen I/O. Ze eten en produceren segmenten.
4. `stack.go` — de enige laag met locks en een goroutine: demux, routing, de
   TX-pomp, de poorttabellen.
5. `socket.go` — de rand naar Go's `net`-pakket (`net.SocketFunc` op tamago).

Die scheiding is waar de testbaarheid vandaan komt: de FIN-familie,
sequence-wrap en RFC 5961 worden getest op de *machine*, zonder draad, klok of
goroutine erbij.

## Hoe we weten dat het werkt

- ~80 tests, 91% statement-coverage, `-race` groen. Alle 29 bevindingen uit de
  lneto-review zijn verantwoord: als test, of met een reden waarom de faalvorm
  hier niet kan bestaan (de dekkingstabel staat in hop-os' `TODO.md`).
- De gVisor-klassiekers: sequence-wraparound (bulk + close over 2³²), blind-RST
  challenge-ACK, mid-connection SYN, venster-krimp, duplicaat-data, tiny-MSS.
- Een rommeltest die elke laag onvertrouwde bytes voert (kapotte checksums,
  afgekapte headers, een optielijst met lengte 0): alles geteld en gedropt, nul
  panics, nul verbindingen.
- Op QEMU draagt hij de hele HopOS-keten: agent + leader, SNTP, DNS, TLS naar
  GitHub, de slot-demo met alle 20 markers.

## De regel voor toevoegingen

Dit pakket hoort in `lean` omdat het aan de drie regels van die repo voldoet:
het lost een gemeten probleem op (met getal en datum in de pakketdoc), het
faalt luid, en het staat alleen (stdlib-only). Een uitbreiding hoort aan
dezelfde lat te worden gehouden — en aan deze:

> Een feature komt erin als een meting laat zien dat zijn afwezigheid iets
> kost. Niet omdat een andere stack hem heeft.
