# KAM — het bevroren HTTP/TCP-profiel

Dit document legt de scope vast van `leanhttp`, `leanhttps`, `leans3` en
`leannet`. Het is geen lijst van alles wat HTTP en TCP kunnen. Het is de lijst
van wat deze repository **belooft goed te doen**, wat zij bewust smaller maakt
en wat zij luid weigert.

De KAM kent drie uitkomsten:

- **KEEP** — nodig voor een gemeten gebruiker. Dit gedrag is contract en een
  fout erin blokkeert een release.
- **ADAPT** — de behoefte is echt, maar de grens mag kleiner zijn dan de
  algemene standaard zolang die grens expliciet en veilig is.
- **MURDER** — geen gemeten gebruiker. De feature en zijn toestandsruimte gaan
  eruit; invoer die erop leunt wordt waar mogelijk luid geweigerd.

Lean betekent dus minder oppervlak, niet minder correctheid. Binnen het
ondersteunde profiel gelden framing, deadlines, eigenaarschap, beveiliging en
resourcevrijgave volledig. Gedrag buiten het profiel is geen stilzwijgende
compatibiliteitsbelofte en ook geen TODO: het komt pas terug na een meting die
laat zien dat de afwezigheid iets kost.

Dit bestand is normatief voor de scope. `README.md` en package-docs vatten haar
samen, `leannet/DESIGN.md` motiveert de transportkeuzes en `TODO.md` houdt de
backlog, bewijsstatus en historische afvinklijst bij. `TODO.md` kan de KAM niet
stil uitbreiden. Een tegenspraak tussen die documenten is een documentatiebug.

## Het deploymentprofiel

De stack draagt deze concrete keten:

- een plain-HTTP/1.1-server voor lokale API's, bestanden, redirects,
  browserstreams en een rauwe protocolovername;
- een HTTP-client voor API-calls en artifactdownloads, eventueel via
  `leanhttps`, met seriële keep-alive per verbinding;
- een SigV4-S3-client voor de objectoperaties die Hop en HopOS werkelijk
  gebruiken;
- een IPv4/TCP/UDP-stack voor bare-metal nodes, met één begrensde bufferpot.

"Meerdere dingen over één kanaal" betekent **opeenvolgende verzoeken en
antwoorden op een keep-alive-verbinding**. Speculatieve HTTP-pipelining en
multiplexing zijn geen contract.

## Beslismatrix

| onderdeel | KEEP | ADAPT | MURDER |
|---|---|---|---|
| HTTP-server | HTTP/1.1, seriële keep-alive, vaste en gestreamde antwoorden, `HEAD`, `204`/`205`/`304`, `Done`, `Hijack` | alleen origin-form, requestbody met bekende lengte, WebSocket via rauwe takeover | HTTP/1.0/2, CONNECT, request-chunking/trailers, server-side Expect-machine, algemene 1xx-machine |
| Mux | methode+pad, exact/subtree, `{segment}`, `{rest...}`, `GET`→`HEAD`, `404`/`405`+`Allow` | canonieke paden of weigeren; immutable na start | host-routing, `{$}`, escaped/dot-routing, slashnormalisatie, net/http-compatibiliteitswerk |
| HTTP-client | HTTP/1.1 uitgaand, 1.0/1.1 inkomend, redirects voor GET/HEAD, responseframing, deadlines, keep-alivepool | vaste-lengte streamupload met een strikt Expect-oordeel; compressie als pass-through | request-chunking, automatische decompressie, CONNECT/upgrade, algemene retrymachine |
| TLS/S3 | expliciet trustmodel, SNI per verbinding, SigV4 en de gebruikte objectoperaties | TLS als dialercompositie; getekende S3-calls volgen nooit redirects | TLS-server, stil skip-verify, multipart, streaming SigV4, SigV4a, presigned URL's, IMDS/IAM |
| leannet | Ethernet, ARP, IPv4, ICMP echo, UDP, TCP, deadlines, close en begrensd geheugen | verliesherstel zonder OOO-buffer/SACK; één IPv4-identiteit, één totale budgetpot en een optionele per-verbindingklem | IPv6/NDP, fragmentatie, congestion control, timestamps, Nagle, SYN-cookies, logging in het datapad |

De tabel is de samenvatting. De normatieve grenzen staan hieronder.

## leanhttp-server en Mux

### KEEP

De server MOET:

- uitsluitend een syntactisch eenduidig HTTP/1.1-verzoek aan een handler geven;
- iedere headerregel tot 8 KiB en alle requestheaders samen tot 64 KiB
  begrenzen;
- precies één niet-lege `Host` eisen en alleen origin-form targets accepteren;
- per verbinding verzoeken sequentieel blijven verwerken zolang beide kanten
  keep-alive toestaan;
- een requestbody alleen dragen met precies één geldige `Content-Length`, tot
  maximaal 1 MiB; een korte body is `io.ErrUnexpectedEOF`, nooit succes;
- een ongelezen requestbody begrensd draineren vóór hergebruik en, waar het
  transport nog gezond is, vóór een nette close;
- responseframing ondubbelzinnig houden: een bekende `Content-Length` of
  writer-owned chunked framing, nooit beide;
- een antwoord zonder bekende lengte tot maximaal 64 KiB bufferen en daarna
  automatisch naar chunked framing overschakelen;
- bij `HEAD`, `204`, `205` en `304` geen bodybytes versturen en `205` met een
  expliciete `Content-Length: 0` ondubbelzinnig framen;
- handlerstatussen `200`–`599` dragen; redirects en foutstatussen blijven de
  keuze van de webserver;
- tijdelijke acceptfouten met begrensde backoff overleven en requestparsing,
  requestbody-reads en responsewrites met de vastgelegde deadlines begrenzen.

`Flush` is de gestroomde response-naad. Zonder vooraf bekende lengte kiest de
writer chunked framing. `Hijack` is de protocolovername-naad: de hijacker
schrijft zelf de `101`-handshake en bezit daarna bytes, framing en lifecycle.
Leanhttp implementeert geen WebSocket-handshake of WebSocket-frames.

`Request.Done` is de disconnect-naad voor een langdurige HTTP-stream. De
aanroep draagt de leeskant aan `Done` over. Als de requestbody nog niet
volledig gelezen is, doet de server eerst een begrensde drainpoging; daarna
consumeert één wachthond de resterende invoer tot disconnect. Zo kan een
geldige, door de client bepaalde body geen ownership-panic veroorzaken.
Daarvoor gelden drie harde eigendomsregels:

1. een handler die de bodyinhoud nodig heeft leest haar vóór `Done`;
2. na `Done` leest de handler niet meer uit `Request.Body`, en `Done` wordt
   geclaimd vóór de eerste responsekop de draad op gaat;
3. `Done` en `Hijack` sluiten elkaar uit.

Alleen de laatste twee grenzen zijn programmeerfouten die MAGGEN fail-fast
panicken: zij worden volledig door de handler bestuurd. `Serve` herstelt
handler-panics bewust niet; zo'n programmeerfout kan dus het proces beëindigen.
Recoverybeleid, als een consumer dat wil, hoort expliciet om de handler heen
en maakt de eigendomsregels niet optioneel.

De server veronderstelt dat een door de listener geleverde `net.Conn`
deadlines werkelijk ondersteunt; fouten van de deadline-setters worden niet
als apart HTTP-antwoord teruggegeven. De `Done`-wachthond leest bewust zonder
deadline tot disconnect, en na `Hijack` beheert de overnemer alle deadlines.

De Mux draagt alleen:

- een exact pad, eventueel voorafgegaan door een methode;
- een patroon met afsluitende slash als subtree;
- `{naam}` voor één segment en `{naam...}` voor de rest;
- de regel dat een `GET`-route ook `HEAD` bedient, waarbij een expliciete
  `HEAD`-route wint;
- de meest specifieke route op basis van een strikte subsetrelatie;
- `404` bij geen padmatch en `405` met `Allow` bij alleen een methodemismatch.

De routetabel is immutable zodra serving begint. Registratiefouten panicken
vóór serving; synchronisatie op elk verzoek voor dynamische registratie hoort
niet in dit profiel.

Ook routepatronen moeten canoniek zijn. Registratie van een patroon met onder
meer dubbele slashes of dotsegmenten panickt vóór serving; de Mux normaliseert
geen patroon naar een andere routebetekenis.

### ADAPT

Padinterpretatie heeft precies één vorm. Een requestpad begint met `/`, bevat
geen lege binnensegmenten en geen `.` of `..`. Percent-escapes die na decoding
een padscheiding of dotsegment worden, zijn ambigu en worden geweigerd. De
parser antwoordt daarop met `400`; een handmatig of door middleware gebouwd
niet-canoniek `Request.Path` matcht in de Mux niet en krijgt `404`.

Bij registratie en requestdispatch is er bewust geen normalisatiestap en geen
automatische slashredirect. Eén invoer krijgt niet eerst een
middlewarebetekenis en daarna een andere routerbetekenis.

### MURDER

De server weigert expliciet:

- HTTP/1.0 en andere versies (`505`);
- `CONNECT` (`501`);
- absolute-, authority- en asterisk-form request-targets (`400`);
- request-`Transfer-Encoding`, inclusief chunked (`501`);
- dubbele framing of `Transfer-Encoding` naast `Content-Length` (`400`);
- een niet-lege `Expect` (`417`);
- een requestbody groter dan 1 MiB (`413`).

`WriteHeader` accepteert geen 1xx. `101` loopt uitsluitend via `Hijack`. `205`
wordt als eigen finale status gedragen, is altijd bodyloos en krijgt
`Content-Length: 0`; de writer verandert haar niet stil in een andere status.

De Mux doet geen host-routing, `{$}`, escaped routing, padopschoning,
automatische slashredirects of volledige `net/http.ServeMux`-algebra.

## leanhttp-client

### KEEP

De client MOET:

- HTTP/1.1-verzoeken schrijven en HTTP/1.0- en HTTP/1.1-antwoorden begrijpen;
- iedere response/statusregel tot 8 KiB en alle interims plus de finale
  responsekop samen tot 64 KiB begrenzen;
- `Do` iedere finale status aan de aanroeper geven en bij `Get` exact `200`
  plus een bekende `Content-Length` eisen;
- bodies met `Content-Length`, chunked framing of EOF correct begrenzen, met
  `HEAD`, `204`, `205` en `304` als bewezen bodyloos;
- een afgebroken vaste-lengtebody als fout melden;
- `Timeout` als één absolute termijn over dial, redirects, kop en body
  handhaven; `HeaderTimeout` geldt uitsluitend voor antwoordkop/oordeel;
- alleen een bewezen volledig gelezen response teruggeven aan de pool;
- idle verbindingen zowel per host als totaal begrenzen en tijdgestuurd
  sluiten;
- maximaal één verse stale-keep-alive-herkansing doen, uitsluitend voor
  replay-safe `GET`/`HEAD` vóór een bruikbaar antwoord;
- alleen `301`, `302`, `303`, `307` en `308` automatisch volgen, uitsluitend
  voor bodyloze `GET`/`HEAD` en maximaal tien hops;
- bij een cross-origin redirect alle callerheaders verwijderen en een
  HTTPS→HTTP-downgrade weigeren.

De package-level calls poolen niet: iedere redirect-hop gebruikt een eigen
verbinding met `Connection: close`. `Client` is de expliciete keep-alivevorm.

### ADAPT

Een kleine body is `[]byte`. Een grote upload gebruikt `BodyReader` plus een
exacte `BodyLen`; request-chunking bestaat niet. Zo'n stroom is niet
replaybaar en verstuurt daarom eerst `Expect: 100-continue`.

De server MOET binnen één absolute oordeeltermijn een complete `100` of een
finale responsekop sturen. Stilte, een gedeeltelijk oordeel of alleen andere
interims tot de deadline is een fout en sluit de verbinding. Er is geen
"stuur na één seconde toch"-fallback. Na `100` wordt de kopdeadline voor de
upload gewist en wordt een geconfigureerde `HeaderTimeout` voor het finale
antwoord opnieuw gezet. Is zowel `HeaderTimeout` als `Timeout` nul, dan heeft
dat finale antwoord — net als een gewone call — bewust geen deadline.

Compressie is pass-through: de default is `identity`; wie zelf
`Accept-Encoding` zet, leest zelf `Response.Encoding` en pakt zelf uit.

### MURDER en geaccepteerde grens

De client doet geen request-chunking, automatische decompressie,
protocolupgrade of algemene retry van muterende requests. Een `101` is een
fout. `CONNECT` wordt vóór dial en serialisatie hard geweigerd; de client heeft
geen ondersteunde tunnelnaad. Callerheaders mogen niet het pakket-eigendom van
`Host`, framing, `Connection` of `Expect` dupliceren. `Accept-Encoding` is
juist de expliciete pass-through-uitzondering.

Chunked responses dragen alleen kale hex-groottes. Ook syntactisch geldige
chunk-extensies worden fail-closed geweigerd: een volledige quote-bewuste
extensieparser heeft geen gemeten gebruiker. Trailers worden begrensd en op
grammatica/verboden velden gecontroleerd, maar hun waarden worden niet aan de
caller blootgesteld.

De keep-alivepool heeft bewust geen permanente read-loop per idle verbinding.
Daarom geldt het poolcontract voor een protocolcorrecte origin die tijdens
idle geen ongevraagde responsebytes injecteert. Reeds gebufferde bytes worden
ontdekt en de verbinding gaat dicht; bytes die pas na die controle arriveren
vereisen voor volledige verdediging een blijvende reader-eigenaar, en die
machine is buiten scope. De stale-herkansing beschermt tegen een gesloten idle
verbinding, niet tegen een syntactisch geldig vervalst antwoord.

## leanhttps en leans3

### leanhttps

`leanhttps` is uitsluitend de compositie van `leanhttp` en `leantls`:

- een expliciet trustmodel — gepinde peerkey of certificaatverificatie — is
  verplicht;
- SNI komt per verbinding uit het actuele dialadres, zodat een toegestane
  redirect naar een andere host de juiste naam verifieert;
- de callerconfig wordt niet gemuteerd;
- TLS-keep-alive gebruikt `leanhttp.Client` met
  `leanhttps.DialerContext(...)`.

Een nil-config en certificaatvalidatie tegen een kaal IP-adres worden luid
geweigerd. `ServerName` is package-owned en hoort bij de caller leeg te zijn:
`Client` weigert een vooraf gezette waarde; de losse `DialerContext`
overschrijft haar veilig in een configkopie met de actuele dialhost.
`leanhttps` heeft geen serverhelft en voegt geen HTTP- of TLS-protocol toe.

### leans3

`leans3` draagt SigV4 met statische credentials en optioneel sessietoken,
virtual-hosted en path-style adressen, en de gebruikte objectoperaties:
`Get`, `GetTo`, `Put`, `PutFrom`, conditionele PUT/DELETE, ETag en gepagineerde
`ListObjectsV2`.

Daarbij gelden deze invarianten:

- iedere PUT heeft een bekende lengte en payloadhash;
- `UnsignedPayload` mag uitsluitend bij een HTTPS-endpoint; wie met een custom
  `Client.DialContext` het standaardtransport vervangt, neemt zelf de plicht
  over om geauthenticeerde encryptie en peer-validatie te behouden;
- een getekend verzoek volgt nooit redirects: origin, target en headers zijn
  onderdeel van de handtekening;
- verwachte 404/409/412-bodies en andere foutbodies worden begrensd gelezen,
  zodat een gewone miss/CAS-race de TLS-pool niet onnodig sloopt;
- grote objecten gebruiken `GetTo`/`PutFrom` en worden niet verplicht volledig
  gebufferd.

Geen streaming SigV4, multipart, SigV4a, presigned URL's, IMDS/IAM-credentials,
HEAD/CopyObject, versioning, object-lock, tagging of S3-level retries. Een
GET/LIST kan wel de ene generieke, pre-response stale-keep-alive-herkansing van
`leanhttp` krijgen; muterende S3-operaties worden niet herhaald. Een operatie
komt pas in het pakket wanneer een echte consumer haar nodig heeft.

Een S3-context wordt vóór de call gecontroleerd en zijn deadline wordt als
HTTP-totaaltermijn doorgegeven. Een kale annulering zonder deadline breekt een
al lopende call niet af; wie dat nodig heeft moet eerst een algemene,
annuleerbare `leanhttp.Call`-naad meten en ontwerpen.

Iedere LIST-pagina is op 4 MiB begrensd. `List(max <= 0)` verzamelt echter
bewust alle keys uit alle pagina's in één slice en kan dus met het aantal
objecten meegroeien; callers op een kleine node geven een positieve `max`.

## leannet

### KEEP

`leannet` draagt Ethernet, ARP, IPv4, ICMP echo, UDP en TCP voor één
IPv4-identiteit, plus `net.Conn`, `net.Listener`, `net.PacketConn` en de
Tamago-socketnaad.

De transportkern MOET:

- alle verbindingsbuffers binnen `Config.Budget` houden;
- per TCP-verbinding beginnen met 16 KiB RX en 4 KiB TX, op gemeten druk
  groeien, lege overmaat tijdens idle weer inkrimpen en bij close/reap het
  resterende budget teruggeven;
- SYN, data en FIN in dezelfde sequence-ruimte administreren en na verlies
  opnieuw kunnen versturen;
- cumulatieve ACKs valideren tegen wat werkelijk verzonden is, ook tijdens
  een retransmitrewind;
- reset als fout leveren, niet als EOF;
- geblokkeerde I/O via wake/deadline sturen en bij `Close` deblokkeren;
- uitsluitend monotone tijd voor protocoltimers gebruiken;
- ARP-opgeven op één plek in de pomp uitvoeren, luid falen en alle wachters
  wekken;
- volle budgetten, backlogs en onbereikbare routes als expliciete fout of RST
  behandelen, nooit als een stille permanente wacht.

Bij socket-`Close` komt het ongelezen RX-budget direct terug. TX-budget komt
terug zodra de FIN bevestigd is of de verbinding wordt gereaped. De bewust
kleine sluitgrenzen zijn 20 seconden in FIN-WAIT-2 en 1 seconde in TIME-WAIT;
ze zijn resourcebeleid voor deze nodes, geen algemene internet-default.

### ADAPT en MURDER

Out-of-order TCP-data wordt gedropt met een onmiddellijke dup-ACK; de peer
herstelt via retransmissie. Dat is de gekozen kleine verliesmachine, niet een
half gebouwde SACK-machine.

Niet aanwezig: congestion control, out-of-order reassembly/SACK, IPv6/NDP,
IPv4-fragmentatie en IPv4-opties, TCP timestamps/PAWS, Nagle, SYN-cookies,
urgent-data-API, inkomende broadcast-IP en logging in het datapad. De
motivering en de voorwaarden waaronder iets terug mag komen staan in
[`leannet/DESIGN.md`](leannet/DESIGN.md).

## Consumerplichten

De kleine kern kan alleen klein blijven als seams niet opnieuw half in elke
consumer worden gebouwd:

- een streamhandler die de requestbody nodig heeft leest haar vóór `Done`.
  Anders draagt `Done` de ongelezen body over aan de begrensde serverdrain.
  Daarna raakt de handler `Request.Body` niet meer aan. De harde grens is vóór
  de responsekop op de draad staat; de simpele consumerdiscipline is daarom:
  claim vóór `WriteHeader`, `Write` of `Flush`;
- een hijacker gebruikt niet ook `Done` of de gewone `ResponseWriter`;
- een caller die verbindingen wil hergebruiken leest een response tot het
  bewezen einde en sluit haar altijd;
- een ondertekend protocol volgt niet generiek redirects maar valideert en
  tekent iedere hop zelf; `leans3` kiest daarom `NoFollow`;
- een custom `DialContext` respecteert contextannulering/deadlines en levert
  een verbinding waarop deadlines werkelijk werken;
- een custom S3-dialer voor een HTTPS-endpoint behoudt zelf geauthenticeerde
  encryptie en peer-validatie, in het bijzonder bij `UnsignedPayload`;
- consumers bouwen standalone tegen een gepubliceerde Lean-versie; een
  lokale workspace of `replace` naar een lokaal pad is ontwikkelgereedschap,
  geen releasebewijs.

## Release-gate

Een wijziging aan dit profiel mag pas door wanneer alle relevante poorten
groen zijn.

### Repository

```sh
git diff --check
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

Nieuwe regressies krijgen bij voorkeur een test op de laag waar de invariant
hoort: parser/framing en lifecycle in `leanhttp`, de pure TCP/ARP-machine in
`leannet`, en compositiefouten bij `leanhttps`/`leans3`.

### Source-gate voor consumers

Vóór tags wordt de gemeten keten in één lokale workspace aan de kandidaatbron
gekoppeld. Lokale `replace`-regels mogen hier bestaan, want dit is een
bronintegratietest en nog geen releasebewijs. De gate bevat:

- gewone tests, race-tests en `go vet` voor Hop, hoplock en hoplockserver;
- een Tamago-compilecheck van Hop's alternatieve HTTP-bestanden:
  `go test -run '^$' -tags tamago ./pkg/hophttp`;
- gewone tests, race-tests en `go vet` voor surfserve tegen de lokale Lean;
- exact twee surfserve-regressies: `GET /stream` met een niet-lege
  `Content-Length` geeft een 4xx en de server blijft daarna bruikbaar; een
  bodyloze niet-GET op `/stream` geeft `405`.

In de bestaande sibling-workspace zijn de eerste drie regels uitvoerbaar als:

```sh
go test -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go test -race -count=1 ./hop/... ../hoplock/... ./hoplockserver/...
go vet ./hop/... ../hoplock/... ./hoplockserver/...
go -C hop test -run '^$' -tags tamago ./pkg/hophttp
```

Surfserve staat niet in de gewone ontwikkelworkspace. Koppel de kandidaat
daarom in een tijdelijk, niet-gecommit `go.work` aan uitsluitend de Lean- en
hop-os-surf-werkbomen en voer met dát `GOWORK` de hosttests op
`./stack/surfserve` uit. Het officiële surfserve-buildscript zet zelf
`GOWORK=off`; dat is dus pas ná publicatie een bewijs voor de kandidaattag.

```sh
LEAN_CANDIDATE=/pad/naar/lean
SURF_CANDIDATE=/pad/naar/hop-os-surf
KAM_WORKDIR="$(mktemp -d)"
go -C "$KAM_WORKDIR" work init "$LEAN_CANDIDATE" "$SURF_CANDIDATE"
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" test -count=1 ./stack/surfserve
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" test -race -count=1 ./stack/surfserve
GOWORK="$KAM_WORKDIR/go.work" go -C "$SURF_CANDIDATE" vet ./stack/surfserve
```

De tijdelijke directory blijft buiten alle repositories en wordt na de gate
verwijderd.

`go test ./...` is voor hop-os-surf geen geldige hostgate: de metal-commands
zijn Tamago-only. Test in deze pre-tag gate alleen de relevante hostpakketten.

### Release-gate voor consumers

Na tag en dependencybump draaien Hop, hoplock en hoplockserver opnieuw buiten
de lokale workspace:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go list -m all
```

Surfserve gebruikt in plaats van `./...` zijn hostgate op
`./stack/surfserve` plus het officiële `tools/test.sh`, omdat dat script de
Tamago-builds draagt en de overige metal-commands niet met de hosttoolchain
gebouwd kunnen worden. Voor Hop blijft ook de expliciete `-tags tamago`-compile
van `./pkg/hophttp` verplicht.

```sh
GOWORK=off go test -count=1 ./stack/surfserve
GOWORK=off go test -race -count=1 ./stack/surfserve
GOWORK=off go vet ./stack/surfserve
GOWORK=off ./tools/test.sh
```

`tools/test.sh` krijgt daarbij de gepinde Tamago-toolchain via zijn bestaande
`TAMAGO`-configuratie.

Elke modulelijst MOET de nieuwe tags tonen en MAG geen `replace` naar een
lokaal bestandssysteempad bevatten — relatief en absoluut zijn allebei geen
releasebewijs. Draai deze gate vanuit een schone checkout van de te publiceren
commits; `GOWORK=off` schakelt een `replace` in `go.mod` namelijk niet uit.

De gate gebruikt één expliciet gepinde toolchain, voor deze KAM Go 1.26.4.
Consumer-CI MAG niet op een oudere `setup-go`-versie vertrouwen of een
toevallige automatische toolchain-download als bewijs tellen. Een latere
toolchain wordt samen met deze regel en de CI-configuratie bewust verhoogd.

Vóór taggen staan er geen lokale-pad-`replace`-regels in een te publiceren
`go.mod`. Eerst wordt Lean gepubliceerd, daarna worden consumers in
afhankelijkheidsvolgorde verhoogd en standalone opnieuw gebouwd. Hardware-,
netmeter- en 64MiB-OOM-validatie van
`leannet` blijft als deploymentbewijs in [`TODO.md`](TODO.md) staan; een groene
hosttest mag die claim niet vervangen.

## Wijzigingsregel

Een uitbreiding van deze KAM bevat tegelijk:

1. de meting of concrete consumer die de ontbrekende feature nodig heeft;
2. de kleinste expliciete contractwijziging;
3. een regressietest op de eigenaarlaag en, bij een seam, een consumertest;
4. de bijgewerkte KEEP/ADAPT/MURDER-beslissing in dit document;
5. bewijs dat hard geweigerde invoer nog steeds luid en begrensd faalt.

Zonder die vijf blijft de feature buiten scope. Dat is geen gebrek aan
standaardtrouw; het is de veiligheidsgrens waardoor de gedragen subset wel
volledig te reviewen blijft.
