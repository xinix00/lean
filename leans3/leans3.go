// Package leans3 praat S3: SigV4-signeren plus de objectoperaties (GET, PUT,
// DELETE, listen), inclusief de streamende vormen en het conditionele verkeer
// (If-Match, If-None-Match, ETag) waar een CAS-protocol op leunt.
//
// Het bestaat om een meting, en de meting is een DUBBELING. In één stapel
// stonden twee eigen SigV4-implementaties:
//
//	hoplock/s3/sigv4.go .......................... ~200 regels, volledig
//	hop/internal/runner/download_s3.go ........... ~100 regels, alleen GET
//
// Die tweede is niet de helft van de eerste maar de zwakkere: geen
// URI-escaping (een key met een spatie of een '+' signeert fout), geen
// sessietoken, alleen virtual-hosted adressering. Dat is precies het soort
// kopie dat ontstaat als het blok ontbreekt — iemand heeft één GET nodig, ziet
// de 200 regels niet zitten, en schrijft 100 die het in de gewone gevallen
// doen. De derde gebruiker schrijft er weer 100.
//
// De tweede meting is waarom hij hier woont en niet op net/http: net/http
// linkt crypto/tls onvoorwaardelijk, en in een kern-image dat op een node van
// 64MB draait kost die keten ~2 MB. Gemeten 12-08 met twee binaries die
// dezelfde ene taak doen — één getekende https-GET naar een S3-endpoint —
// darwin/arm64, go1.26.4, `-ldflags=-w`:
//
//	net/http + crypto/tls .............. 5,68 MB   (en dat signeert nog niet)
//	dit pakket op leanhttps ............ 3,95 MB   (-1,73, signeren erbij)
//
// Dat is dezelfde 1,73 MB die leantls/x509verify voor de hele stapel op
// tamago/riscv64 meet, dus de winst zit waar hij daar zit: niet in TLS maar in
// net/http, dat crypto/tls meeneemt of je hem gebruikt of niet.
//
// # Wat dit NIET doet
//
//   - Streaming signatures (STREAMING-AWS4-HMAC-SHA256-PAYLOAD). Een PUT
//     draagt dus een Content-Length en een payload-hash die de aanroeper
//     kent; [Client.PutFrom] weigert luid zonder hash in plaats van stil
//     [UnsignedPayload] te sturen (dat mag alleen over https, en meerdere
//     providers wijzen het op een write af).
//   - sigv4a (multi-region), presigned URL's, credentials uit IMDS/IAM.
//     Statische sleutels, eventueel met sessietoken.
//   - multipart upload, versioning, object-lock, tagging. Eén object is één
//     verzoek; wat een orkestrator of een lease-laag daarmee doet — sleutel-
//     indeling, retries op een provider-eigenaardigheid, wie mag schrijven —
//     hoort niet hier.
//
// # Over de invoer die geen invoer is
//
// De operaties nemen een [context.Context], maar alleen zijn DEADLINE wordt
// gebruikt: die wordt leanhttp's Call.Timeout. Een kale cancel volgt dit
// pakket niet — leanhttp kent geen context, en met een verbindingspool eronder
// is "sluit de verbinding van dit verzoek" niet veilig te doen zonder een
// goroutine per aanroep die op ctx.Done wacht. Een al afgebroken context
// weigert wél meteen. Dat staat hier omdat élke aanroeper een context heeft en
// de deadline anders geruisloos verdwijnt.
//
// # Over de import van leanhttps
//
// Dit pakket importeert een SAMENSTELLING, en de README zegt dat een
// samenstelling dat niet doet ("one level deep"). De reden dat het hier tóch
// klopt: leans3 is geen samenstelling maar een blok met een eigen protocol
// (SigV4 en de S3-API), en het alternatief is de knoop die leanhttps al legt —
// SNI per verbinding, poort 443 mét vertrouwensmodel — hier over te schrijven.
// Dat is de dubbeling die dit pakket juist bestrijdt.
//
// Wie geen https praat (MinIO op een LAN) betaalt daar wél de PKI-keten voor:
// de schemakeuze is bereikbaar vanuit elke aanroep, dus de linker kan hem niet
// weggooien. Dat is de prijs van één knop minder aan de gebruikerskant.
package leans3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xinix00/lean/leanhttp"
	"github.com/xinix00/lean/leanhttps"
	"github.com/xinix00/lean/leantls"
	"github.com/xinix00/lean/leantls/x509verify"
)

// HTTP-methodes die dit pakket gebruikt; leanhttp heeft er geen constanten voor.
const (
	methodGet    = "GET"
	methodPut    = "PUT"
	methodDelete = "DELETE"
)

// Statuscodes die leanhttp zelf niet noemt.
const (
	statusConflict           = 409
	statusPreconditionFailed = 412
)

// UnsignedPayload is de literal die zegt "ik signeer de inhoud niet". Alleen
// voor [Client.PutFrom] van een bron die niet twee keer te lezen is, en alleen
// over https: zonder TLS is een niet-gesigneerde payload onderweg te wijzigen.
// Meerdere S3-compatibele providers weigeren hem op een write, dus het is een
// uitweg en geen default.
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// Sentinels. Ze zijn er omdat de twee gevallen waarin een niet-2xx GEEN
// storing is, aan de aanroeper toebehoren: een object dat er niet is (een
// schone start), en een voorwaarde die niet gold (iemand anders was eerder).
var (
	// ErrNotFound is een 404: de key bestaat niet.
	ErrNotFound = errors.New("leans3: no such key")

	// ErrPreconditionFailed is een 412 (of de 409 die sommige providers voor
	// een gelijktijdige If-None-Match-race sturen): de If-Match/If-None-Match
	// gold niet, dus er is niets geschreven.
	ErrPreconditionFailed = errors.New("leans3: precondition failed")
)

// StatusError is elk ánder niet-succes: de status zoals de server hem stuurde
// plus het begin van de body. Die body staat er omdat S3 de echte reden in een
// XML-antwoord zet (SignatureDoesNotMatch, AccessDenied, NoSuchBucket) en hem
// weglaten een debug-sessie kost.
type StatusError struct {
	Op     string // "GET", "PUT", "DELETE", "LIST"
	Key    string // key of prefix waar het om ging
	Code   int    // 403, 500, …
	Status string // "403 Forbidden", zoals op de draad
	Body   string // begin van de antwoordbody, getrimd
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("leans3: %s %s: status %s: %s", e.Op, e.Key, e.Status, e.Body)
}

// Client praat met één bucket op één endpoint. Vul hem als struct-literal; de
// vereiste velden zijn geëxporteerd. Hij is veilig voor gelijktijdig gebruik.
//
// Gebruik hem per POINTER en kopieer hem niet zodra hij gebruikt is: hij bezit
// een verbindingspool (keep-alive per host), en dat is geen luxe — een
// lease-vernieuwing gaat elke paar seconden, en zonder pool betaalt elke ronde
// een TCP-handdruk plus over https een sleuteluitwisseling.
type Client struct {
	// Endpoint is de basis-URL van de dienst, bijvoorbeeld
	// "https://s3.us-east-1.amazonaws.com" of
	// "https://<account>.r2.cloudflarestorage.com". Verplicht.
	Endpoint string

	// Bucket is de bucketnaam. Verplicht.
	Bucket string

	// Region is de regio in de credential-scope van de signatuur. Verplicht;
	// "auto" voor Cloudflare R2.
	Region string

	// AccessKeyID en SecretAccessKey zijn de statische sleutels. Verplicht.
	AccessKeyID     string
	SecretAccessKey string

	// SessionToken gaat als X-Amz-Security-Token mee als hij gezet is (STS).
	SessionToken string

	// UsePathStyle zet de bucket in het PAD ("<endpoint>/<bucket>/<key>") in
	// plaats van in de hostnaam ("<bucket>.<endpoint>/<key>"). Nodig voor
	// MinIO en de meeste niet-AWS-providers; bij R2 mag beide.
	UsePathStyle bool

	// Dial vervangt de manier van verbinden. nil — het normale geval — kiest
	// op het schema van Endpoint: https krijgt een TLS-dialer die de
	// certificaatketen valideert, http verbindt kaal (dan linkt leanhttp zelf
	// niets van TLS). Zet hem voor een proxy, een unix-socket of een test die
	// een lokale server onder een virtual-hosted bucketnaam moet bereiken —
	// en weet dan dat je de versleuteling vervangt.
	Dial func(network, addr string) (net.Conn, error)

	// Now vervangt de klok in de signatuur. nil = time.Now. Voor tests: een
	// signatuur is per definitie tijdgebonden, dus zonder deze naad is er geen
	// deterministische assertie mogelijk.
	Now func() time.Time

	mu   sync.Mutex
	pool *leanhttp.Client
}

// request is één uitgaande aanroep vóór het signeren. Hij bestaat omdat SigV4
// precies een (methode, URL, headers)-drietal dekt: die drie op één plek
// verzamelen is wat verhindert dat de signeerder en de draad uit elkaar lopen.
type request struct {
	op     string // voor de foutmelding: "GET", "PUT", …
	key    string // idem
	method string
	url    *url.URL
	header leanhttp.Header // mag nil zijn

	// body is een body in het geheugen; stream plus streamLen is dezelfde
	// body als stroom, voor payloads die niet in het geheugen horen. Zet één
	// van de twee.
	body      []byte
	stream    io.Reader
	streamLen int64

	// payloadHash is de hex-sha256 van de body, of [UnsignedPayload].
	payloadHash string
}

// do signeert r en stuurt hem over de pool van deze Client.
//
// Host, Content-Length, Connection en Accept-Encoding staan bewust NIET in
// r.header: leanhttp schrijft die zelf en weigert luid als de aanroeper ze
// zet. Dat is precies wat de signeerder verwacht — zie canonicalRequest.
func (c *Client) do(ctx context.Context, r request) (*leanhttp.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hdr := r.header
	if hdr == nil {
		hdr = leanhttp.Header{}
	}
	signRequest(r.method, r.url, hdr, credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Region:          c.Region,
	}, r.payloadHash, c.now())

	pool, err := c.client()
	if err != nil {
		return nil, err
	}
	resp, err := pool.Do(leanhttp.Call{
		Method:     r.method,
		URL:        r.url.String(),
		Header:     hdr,
		Body:       r.body,
		BodyReader: r.stream,
		BodyLen:    r.streamLen,
		Timeout:    timeoutFor(ctx),
	})
	if err != nil {
		return nil, fmt.Errorf("leans3: %s %s: %w", r.op, r.key, err)
	}
	// Een 204 of 304 zonder body hoeft hier niet meer opgevangen te worden:
	// leanhttp doet dat sinds 12-08 zelf (RFC 9112 §6.3). Dit pakket vond die
	// bug — een S3-DELETE antwoordt met 204, en zonder de regel stond élke
	// delete stil op een read die nooit een byte kon opleveren, tot de server
	// zijn idle-timeout haalde. De test daarop staat hieronder én in leanhttp.
	return resp, nil
}

// fail vertaalt een niet-succes-antwoord naar de fout die erbij hoort. Hij
// leest de body BEGRENSD: een stukgelopen of hostiele stream mag de heap niet
// laten groeien.
func (c *Client) fail(op, key string, resp *leanhttp.Response) error {
	switch resp.StatusCode {
	case leanhttp.StatusNotFound:
		return ErrNotFound
	case statusPreconditionFailed, statusConflict:
		return ErrPreconditionFailed
	}
	const maxBody = 4 << 10
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &StatusError{
		Op:     op,
		Key:    key,
		Code:   resp.StatusCode,
		Status: resp.Status,
		Body:   strings.TrimSpace(string(body)),
	}
}

// client geeft de pool, gebouwd bij het eerste gebruik.
func (c *Client) client() (*leanhttp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pool == nil {
		dial, err := c.dialer()
		if err != nil {
			return nil, err
		}
		c.pool = &leanhttp.Client{Dial: dial}
	}
	return c.pool, nil
}

// dialer kiest het transport op het schema van Endpoint. Een nil-dialer is het
// antwoord voor http: leanhttp verbindt dan zelf kaal.
//
// De roots zijn nil, dus x509.SystemCertPool: op een host is dat de trust
// store van het OS, op bare-metal wat het image meebakte (importeer
// golang.org/x/crypto/x509roots/fallback in de main). Er is bewust geen
// skip-verify-knop — een bucket met sleutels erin is de laatste plek waar je
// met de verkeerde tegenpartij wil praten.
func (c *Client) dialer() (func(network, addr string) (net.Conn, error), error) {
	if c.Dial != nil {
		return c.Dial, nil
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("leans3: parse Endpoint: %w", err)
	}
	switch u.Scheme {
	case "https":
		return leanhttps.Dialer(&leantls.Config{
			VerifyPeer:          x509verify.Chain(nil),
			SignatureAlgorithms: x509verify.SignatureAlgorithms,
		}), nil
	case "http":
		return nil, nil
	default:
		return nil, fmt.Errorf("leans3: Endpoint scheme must be http or https, got %q", u.Scheme)
	}
}

// CloseIdle sluit de ongebruikte verbindingen in de pool. Voor wie klaar is,
// of wiens netwerk onder hem is weggevallen; een lopend verzoek raakt hij niet.
func (c *Client) CloseIdle() {
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()
	if pool != nil {
		pool.CloseIdle()
	}
}

// timeoutFor maakt van een context-deadline leanhttp's termijn per aanroep.
// Geen deadline = geen termijn, net als een http.Client zonder Timeout.
func timeoutFor(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	if d := time.Until(deadline); d > 0 {
		return d
	}
	return time.Nanosecond // al voorbij: falen op de eerste read, niet blokkeren
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// URLFor geeft de request-URL voor key, in de adresseringsstijl van deze
// Client. Openbaar omdat een aanroeper die zijn eigen verzoek wil doen (een
// HEAD, een operatie die hier niet in zit) precies deze URL nodig heeft — en
// hem anders zelf samenstelt, met de kans op de fout die pad-stijl en
// host-stijl door elkaar haalt.
func (c *Client) URLFor(key string) (*url.URL, error) {
	if key == "" {
		return nil, errors.New("leans3: key is required")
	}
	u, err := c.bucketURL()
	if err != nil {
		return nil, err
	}
	u.Path += strings.TrimPrefix(key, "/")
	return u, nil
}

// bucketURL is de URL van de bucket zelf (afsluitende slash, geen key): de
// basis die URLFor met een key verlengt en die een listing as-is gebruikt.
// Pad-stijl: "<endpoint>/<bucket>/". Host-stijl: "<bucket>.<endpoint-host>/".
func (c *Client) bucketURL() (*url.URL, error) {
	if c.Endpoint == "" {
		return nil, errors.New("leans3: Endpoint is required")
	}
	if c.Bucket == "" {
		return nil, errors.New("leans3: Bucket is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("leans3: parse Endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("leans3: Endpoint must include scheme and host: %q", c.Endpoint)
	}
	if c.UsePathStyle {
		u.Path = "/" + c.Bucket + "/"
	} else {
		u.Host = c.Bucket + "." + u.Host
		u.Path = "/"
	}
	return u, nil
}
