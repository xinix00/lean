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

**Bijna-eerst: één flaky test.** `TestStackBudgetRecovery` viel 12-08 één keer om
in een volledige `-race`-run van het pakket (assertie, géén DATA RACE-melding);
in isolatie en in drie volgende volledige runs groen. Ziet eruit als een te
strakke deadline terwijl de race-detector alles vertraagt.

- [ ] de test deadline-gedreven maken i.p.v. op een vaste tijd, zodat een
      langzame runner hem niet omgooit — anders wordt hij op een drukke machine
      of in CI een terugkerende valse alarmbel

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

## leanhttp

- [ ] Geen open punten. (HTTP/1.1 zonder TLS; wat het niet kan, weigert het
      luid — dat was de opzet.)

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
