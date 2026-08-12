# TODO — lean

Wat er nog moet, per pakket. De regel voor nieuwe pakketten staat in
[README.md](README.md); de regel voor nieuwe features in een bestaand pakket is
dezelfde: een meting die aantoont dat de afwezigheid iets kost.

## leannet — af, maar niet op ijzer geweest

Gebouwd 11/12-08-2026 als vervanger van lneto+go-net in HopOS. Ontwerp,
afwegingen en de lijst met bewust-niet-gebouwd:
[leannet/DESIGN.md](leannet/DESIGN.md).

Stand: ~80 tests, 91% coverage, `-race` groen, compileert onder de
tamago-toolchain (riscv64 + arm64). HopOS draait er volledig op in QEMU (agent
+ leader, SNTP, DNS, TLS-download van GitHub, slot-demo 20/20 markers, 200×
verbindings-churn schoon, 8 vastgehouden verbindingen + verse = 200).

**Flaky test GEFIXT 12-08.** `TestStackBudgetRecovery` viel één keer om in een
volledige `-race`-run (assertie, géén DATA RACE). Oorzaak: de server sloot zijn
verbinding meteen na Accept, dus "is het slot nog bezet?" hing aan de vraag of
TIME-WAIT (~1s) al verstreken was vóór de tweede dial — onder de race-detector
is alles langzamer. De server houdt de verbinding nu vast tot de test hem
vrijgeeft: geen tijdafhankelijkheid meer. 6× `-race` in isolatie en 2× de hele
suite met `-race` groen.

**Na v0.2.0 gebouwd (12-08, ongecommit) — twee gaten die het ijzer vond:**

- [x] **Zelf-verkeer (loopback).** Een wereld kon niet bij zichzelf: een dial
      naar het eigen IP vroeg op de draad "who has mijzelf", en dat antwoordt
      niemand (een switch floodt naar iedereen BEHALVE de bron), dus kwam er na
      vijf pogingen `no route to host`. Op ijzer stond cloudflared na een
      rolling update op het slot-IP dat zijn eigen config als origin noemde en
      wees die fout vijf lagen weg van de oorzaak. Nu: `routeLocked` geeft voor
      het eigen adres de eigen MAC, `sendEthLocked` legt zulke frames in een
      loopback-wachtrij, en de pomp voert ze door dezelfde ingress-demux
      (`ingressLocked`). Werkt voor TCP en UDP; drie regressietests.
- [x] **RST voor een dichte poort** (RFC 9293 §3.10.7.1). Die ontbrak
      volledig: élke dial naar een poort waar niets luistert zat zijn deadline
      uit in plaats van meteen "connection refused" te krijgen — voor een
      health-check of een net verhuisd origin is dat het verschil tussen zoeken
      en weten. Een RST lokt nooit een RST uit (storm-test).

**Eerst, en het is de enige echte open vraag:**

- [ ] **Op ijzer verifiëren.** LicheeRV Nano (RISC-V, 100Mbit dwmac) en Radxa
      Zero 3E. De lat, gemeten met de vorige stack: RX ≥ 8,84 MB/s zonder
      drops, en voorbij de 250s-grens blijven leven. QEMU kan dit niet
      beantwoorden: slirp termineert TCP op de host, dus de guest-RTT is altijd
      microseconden — venstergedrag en de echte DMA-keten meet je alleen daar.
- [ ] **netmeter-A/B**: dezelfde bank die de vorige twee wissels beoordeelde
      (hop-os `metal/cmd/netmeter`). Cijfers naast de lneto-getallen leggen:
      RX/TX-plafond, allocaties per fase, GC-druk.
- [ ] **De OOM-reproductie moet overleven**: HOP-raam van 64MB + SSE-last op
      `/v1/events`. Dat scenario doodde de vorige stack binnen 151s door
      buffer-preallocatie; het budgetmodel hoort er onverstoorbaar door te
      komen. Daarna kan de GOGC-25-pleister in HopOS' `cpu/memlimit` mogelijk
      terug naar Go's ~10%-richtlijn — óók meten.

**Daarna, in deze volgorde:**

- [ ] Doorvoer-profiel per laag op ijzer: waar gaat de tijd heen (checksum,
      kopie, demux)? De bank heeft de tellers al; leannet mag er tellers bij
      krijgen als ze buiten het datapad blijven.
- [ ] Opwarmcurve meten op een echt WAN-pad: verdubbelen-per-vol kost
      `log2(cap/floor)` RTT's. Als een download daardoor meetbaar later op
      volle snelheid komt, is gVisors RTT-schatter de verfijning (de naad is
      er: beide groeibeslissingen lopen door één `growRing`).
- [ ] `TIME-WAIT` is nu 1s en een constante. Configureerbaar maken zodra een
      omgeving het vraagt (2MSL van 4 minuten past niet op een embedded node,
      maar 1s is een keuze zonder meting).
- [ ] Overweeg een `Stats()`-methode die de tellers als struct teruggeeft, in
      plaats van exported velden op `Stack` (nu leest HopOS ze onder de
      stack-mutex mee; dat werkt, maar het is geen contract).

**Bewust niet op deze lijst** (zie DESIGN.md voor de reden per punt):
congestion control, out-of-order reassembly/SACK, IPv6/NDP,
IPv4-fragmentatie, TCP timestamps/PAWS, Nagle, SYN-cookies, logging in de
stack, een tweede buffer-knop.

## leanhttp — uitgebreid 12-08 zodat een browser hem kan gebruiken

Dereks vraag: kunnen de basis-delen die een browser nodig heeft er wél in, in
plaats van dat de volgende gebruiker naar net/http grijpt (en 3,2 MB betaalt)?
Ja, en het legde onderweg een echte bug bloot.

- [x] **Call.Dial** — een algemene dialer-naad (proxy, unix-socket, testdubbel,
      TLS). Zonder deze naad is https onmogelijk zonder TLS in dit pakket te
      linken; mét de naad blijft het pakket TLS-vrij en knoopt de aanroeper de
      twee (leanhttps doet dat).
- [x] **Client met keep-alive** — een pool per host. De veiligheidsregel is
      één: een verbinding gaat alleen terug als de body TOT HET EINDE gelezen
      is, want anders leest het volgende verzoek de staart van dit antwoord als
      zijn statusregel. Getest met een verbindingsteller (10 verzoeken → 1
      verbinding; halve bodies → 3 verbindingen, geen desync).
- [x] **gzip doorlaatbaar** — Accept-Encoding is nu van de aanroeper (default
      blijft identity) en Response.Encoding zegt wat er terugkwam. compress/gzip
      blijft dus buiten dit pakket: wie het wil, wikkelt Body zelf.
- [x] **Response.SetCookie, ongevouwen — dit was een BUG.** Herhaalde headers
      werden tot één komma-lijst gevouwen (RFC 9110 §5.3, correct), maar
      Set-Cookie is dé uitzondering: cookie-waarden en Expires-datums bevatten
      zelf komma's, dus gevouwen is de lijst niet meer te splitsen. Wie cookies
      las kreeg er één waar er twee stonden — en dat merk je pas als een login
      niet blijft plakken. Nu apart en per regel.
- [x] **GetCall** — Get met de rest van de Call erbij (headers, termijn, Dial),
      zoals Do dat voor Get al was.

## leancookie (nieuw 12-08)

- [ ] Geen open punten. Bewust NIET: public-suffix-lijst (honderden KB's,
      maandelijks anders — dus host-only als default, met een AllowDomain-hook
      voor wie het zelf kan weten), SameSite (navigatiebeleid van een browser,
      geen jar-beleid), __Host-/__Secure-voorvoegsels.

## leanhttps (nieuw 12-08, de eerste samenstelling)

- [ ] Geen open punten. Gemeten: 3,75 MB tegen 5,77 MB voor
      net/http+crypto/tls+CA-bundel, en 2,65 MB met een gepinde peer.
- [ ] Wél te overwegen als iemand het nodig heeft: een server-kant. Nu is dit
      alleen een client; https serveren vraagt leantls' serverhelft (die er nog
      niet is).

## leandhcp

- [ ] `StateRenewing`/`StateRebinding` netjes scheiden: `KeepAlive` doet nu de
      T1-renew, maar de rebinding-fase (T2, broadcast naar een andere server)
      is samengevouwen. Nog nooit een probleem gemeten op onze netten; wél een
      RFC-2131-gat.
- [ ] De klasse-les uit de lneto-review die hier wél geldt: een lease die in de
      *laatste* tick binnenkomt mag niet als deadline-fout gerapporteerd worden.
      Nakijken of `Acquire` dat goed doet (in lneto's DHCP-client was dat
      bevinding #16).

## Repo-breed

- [ ] **Taggen zodra HopOS er tegen aan wil bouwen zonder replace.** In
      `hop-os/metal/go.mod` staat nu een dev-`replace` naar deze werkboom; die
      mag niet gecommit worden. Volgorde: hier committen + taggen (v0.2.0 — nieuw
      pakket, geen breuk), dan in hop-os de replace weg en de require bumpen.
- [ ] De README-tabel krijgt een `leannet`-regel bij het taggen (met het
      gemeten probleem in één zin, zoals de andere twee).
