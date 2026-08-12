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

**Na v0.3.0 gebouwd (12-08, ongecommit):**

- [x] **Broadcast de deur uit.** De routelaag deed er iets stils-fouts mee:
      255.255.255.255 valt buiten élk subnet, dus ging het als *unicast* naar de
      gateway (die het terecht negeert), en een subnet-gericht adres (x.x.x.255)
      ging de ARP-molen in naar een adres dat niemand bezit — vijf pogingen, dan
      "no route to host". Nu gaan beide naar `ff:ff:ff:ff:ff:ff` zonder ARP. De
      klant is de DHCP-rebind hieronder; zonder deze regel bestond die fase
      alleen op papier. Inkomende broadcast blijft dicht, met de reden in
      DESIGN.md.

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
- [ ] **De clientkant kent de bodyless-regel niet (204/304).** De serverkant wel
      (serve_test.go toetst hem), maar `do` geeft een antwoord zonder
      Content-Length en zonder chunks een body die tot EOF leest — en op een
      keep-alive-verbinding komt dat EOF pas als de server zijn idle-timeout
      haalt. Gevonden door leans3: een S3-DELETE en een hoplockserver-DELETE
      antwoorden béide met 204, dus élke delete bleef staan tot de server hem
      verveeld dichtgooide (in de test: een `go test` die zijn timeout haalde).
      RFC 9112 §6.3 zegt dat 204 en 304 nooit een body hebben; drie regels in
      `do` (lengte 0 in plaats van "tot EOF") lossen het op voor iedereen. Nu
      omzeild in leans3 en in hoplockserver/client met een eigen `emptyBody` —
      dat hoort niet in twee aanroepers te staan.

## leans3 (nieuw 12-08)

Verhuisd uit hoplock/s3, en de reden was een dubbeling: er stonden twee eigen
SigV4's in één stapel (`hoplock/s3/sigv4.go` volledig, `hop
internal/runner/download_s3.go` alleen-GET en zonder URI-escaping). De
signeercode zelf is niet nieuw — hij heeft tegen AWS, R2, MinIO en Hetzner/Ceph
RGW gelopen — maar hij staat hier voor het eerst als blok.

- [ ] **hop's tweede signeerder opruimen.** `internal/runner/download_s3.go` kan
      `leans3` gebruiken (of alleen zijn signeerder): dat haalt de zwakkere kopie
      weg, en daarmee de klasse fouten die hij nu heeft — een key met een spatie
      of een '+' signeert fout, geen sessietoken, alleen virtual-hosted. Alleen
      vastgesteld, nog niet gedaan.
- [ ] **De meting staat, maar op een HOST.** 5,68 → 3,95 MB voor dezelfde
      getekende https-GET (darwin/arm64, `-ldflags=-w`); wat het in een
      tamago-image doet is nog niet gemeten, want daarvoor moet er een board
      onder de link staan. Verwachting: hetzelfde bedrag, want het is dezelfde
      1,73 MB die x509verify op riscv64 meet.
- [ ] **Niet op ijzer geweest** in deze vorm. hoplock/s3 en HopOS bouwen erop en
      de host-tests zijn groen, maar sinds de verhuizing heeft er geen echte
      provider aan de andere kant gestaan.
- [ ] Bewust NIET: streaming signatures (STREAMING-AWS4-HMAC-SHA256-PAYLOAD),
      multipart upload, presigned URL's, sigv4a, credentials uit IMDS/IAM,
      HEAD/CopyObject. Voor dat laatste is `Client.URLFor` de naad: wie een
      operatie nodig heeft die hier niet in zit, signeert hem zelf op de juiste
      URL in plaats van de adresseringsstijl na te bouwen.

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

## leandhcp — beide punten gedaan 12-08, en het pakket heeft nu tests

Het had er nul. Nu 30 tests, 95% coverage, `-race` groen; de hele
DORA-handshake en de hele lease-cyclus draaien op een nep-NIC en een nep-socket,
dus in microseconden in plaats van in uren.

- [x] **`StateRenewing`/`StateRebinding` gescheiden.** Het gat was groter dan
      "een RFC-punt": `KeepAlive` probeerde zes keer een unicast-renew met 30s
      ertussen, en dat getal sloeg op niets uit de lease. Juist als de lessor
      wég is (verhuisde router, nieuwe DHCP-server) kan die renew per definitie
      niet slagen — en dan verloor de node zijn adres terwijl er een andere
      server op het segment staat die de lease zou verlengen. Nu: optie 59 (T2)
      wordt gevraagd en gelezen, `Lease.timers` geeft T1/T2/einde (met de
      RFC-verhoudingen 0.5/0.875 als de server onzin stuurt — T1 = T2 = lease
      bestaat in het veld), de pogingen halveren de resttijd met een vloer van
      60s (§4.4.5) en stoppen exact op de fasegrens, en op T2 stapt hij over op
      broadcast. Verloopt de lease alsnog, dan zegt hij dat luid
      (`HOPOS_DHCP_EXPIRED`) in plaats van stil te stoppen.
- [x] **Laatste tick (lneto-bevinding #16) — er zát een gat.** `await` keek naar
      de klok vóór hij las, dus een antwoord dat al in de ring lag ging verloren
      zodra het window dicht was. De duurste vorm: de server heeft het IP aan
      onze MAC vergeven, wij melden "no server answered", de node boot zonder
      net en de router houdt een binding voor een adres dat niemand gebruikt.
      Nu wordt de klok alleen bekeken als de ring LEEG is (begrensd, want een
      druk segment houdt de ring nooit leeg), en een REQUEST krijgt bovendien
      een minimum-window omdat híj bindt waar een DISCOVER niets bindt. Twee
      tests die tegen de oude code aantoonbaar falen.
- [x] Onderweg meegekomen: een DHCPNAK werd genegeerd (nu `errRefused` → meteen
      stoppen met `HOPOS_DHCP_NAK`, want doorpraten op een geweigerd adres is
      actief fout), en een karige ACK kon `LeaseSecs` op nul zetten en daarmee
      het hele onderhoud stilzwijgend uitzetten (`merge` draagt nu ook de
      timers door).
- [ ] Een rebind die bij een ándere server uitkomt kan een ánder adres geven, en
      dat kunnen we niet toepassen: de stack staat sinds bring-up op één IP. Nu
      meldt hij het luid en stopt (`HOPOS_DHCP_MOVED`) — de node hangt dan aan
      een reboot. Netter zou zijn: de stack ter plekke herconfigureren. Dat is
      een naad in hopnet, geen leandhcp-werk.
- [ ] Servers die een rebind-antwoord tóch als broadcast terugsturen zien we
      niet (leannet negeert inkomende broadcast-IP's, zie leannet/DESIGN.md).
      RFC-conform hoeft dat niet te gebeuren zolang wij de broadcast-flag uit
      laten, en dat doen we. Pas repareren als een echte router het doet.

## Repo-breed

- [x] Taggen: v0.3.0 staat, `hop-os/metal/go.mod` require't hem zonder replace,
      en de README-tabel heeft zijn `leannet`-regel.
- [ ] **Volgende tag** (v0.4.0: nieuwe exports `State`, `Rebind`, `Lease.T2Secs`
      — geen breuk). Daarna in hop-os de require bumpen. Tijdens het werken
      hoort er een dev-`replace` in `hop-os/metal/go.mod` te staan; die mag niet
      mee in een commit.
