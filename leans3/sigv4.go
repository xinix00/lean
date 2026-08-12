package leans3

// AWS Signature Version 4 — de vorm die S3 wil voor een verzoek met een body
// die je al kent (geen streaming signature).
//
// Specificatie:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
//
// Deze code komt uit hoplock/s3 en is daar op echte providers gelopen (AWS,
// Cloudflare R2, MinIO, Hetzner/Ceph RGW). De canonieke vorm is dus geen
// interpretatie van de specificatie maar de vorm die werkt; wie hem verandert,
// verandert élke signatuur en krijgt SignatureDoesNotMatch op álles. Er staan
// tests op de vorm, niet alleen op het resultaat.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xinix00/lean/leanhttp"
)

const (
	sigAlgorithm  = "AWS4-HMAC-SHA256"
	sigService    = "s3"
	sigTerminator = "aws4_request"
)

// credentials draagt alles wat SigV4 nodig heeft.
type credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

// signRequest hangt Authorization, X-Amz-Date en X-Amz-Content-Sha256 aan hdr —
// de header-map die op de draad gaat. payloadHash is de hex-sha256 van de body
// of [UnsignedPayload].
//
// Het signeert een (methode, URL, headers)-drietal in plaats van een
// verzoek-object, want leanhttp heeft geen verzoektype: een Call draagt exact
// deze map, dus wat hier gesigneerd wordt is wat er verstuurd wordt.
func signRequest(method string, u *url.URL, hdr leanhttp.Header, creds credentials, payloadHash string, now time.Time) {
	if payloadHash == "" {
		payloadHash = UnsignedPayload
	}

	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	scope := dateStamp + "/" + creds.Region + "/" + sigService + "/" + sigTerminator

	hdr.Set("X-Amz-Date", amzDate)
	hdr.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		hdr.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	canonicalReq, signedHeaders := canonicalRequest(method, u, hdr, payloadHash)

	stringToSign := strings.Join([]string{
		sigAlgorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalReq)),
	}, "\n")

	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, creds.Region)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigAlgorithm, creds.AccessKeyID, scope, signedHeaders, signature)
	hdr.Set("Authorization", auth)
}

// canonicalRequest bouwt de canonieke verzoekstring en de signed-headers-lijst.
//
// Twee dingen aan de gesigneerde header-verzameling lijken vergeten en zijn dat
// niet — verander één van de twee en S3 wijst élke aanroep af:
//
//   - "host" komt uit u.Host en wordt NOOIT uit hdr gelezen. leanhttp schrijft
//     de Host-regel zelf, uit diezelfde u.Host, en weigert een aanroeper die de
//     header zet — dus u.Host signeren is precies de string die de server leest.
//   - Content-Length staat niet in hdr (leanhttp schrijft hem, uit de
//     bodylengte) en wordt dus niet gesigneerd. Dat is hoe deze signeerder het
//     altijd deed: ook net/http hield hem buiten req.Header, dus de signatuur
//     dekte hem nooit.
func canonicalRequest(method string, u *url.URL, hdr leanhttp.Header, payloadHash string) (string, string) {
	type header struct{ name, value string }
	hdrs := []header{{"host", u.Host}}

	for name, value := range hdr {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "host" {
			continue
		}
		hdrs = append(hdrs, header{lower, strings.TrimSpace(value)})
	}
	sort.Slice(hdrs, func(i, j int) bool { return hdrs[i].name < hdrs[j].name })

	var headerLines []string
	var signedNames []string
	for _, h := range hdrs {
		headerLines = append(headerLines, h.name+":"+h.value)
		signedNames = append(signedNames, h.name)
	}
	canonicalHeaders := strings.Join(headerLines, "\n") + "\n"
	signedHeaders := strings.Join(signedNames, ";")

	parts := []string{
		method,
		canonicalURI(u.Path),
		canonicalQuery(u),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}
	return strings.Join(parts, "\n"), signedHeaders
}

// canonicalURI escapet elk padsegment volgens de unreserved-verzameling van
// RFC 3986. Slashes tussen segmenten blijven letterlijk. Een leeg pad wordt "/".
func canonicalURI(p string) string {
	if p == "" {
		return "/"
	}
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = uriEscape(s, false)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery sorteert de query-parameters op key (en op waarde als een key
// zich herhaalt) en escapet ze opnieuw met de SigV4-regels.
func canonicalQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, raw := range strings.Split(u.RawQuery, "&") {
		eq := strings.IndexByte(raw, '=')
		var k, v string
		if eq < 0 {
			k = raw
		} else {
			k, v = raw[:eq], raw[eq+1:]
		}
		dk, _ := url.QueryUnescape(k)
		dv, _ := url.QueryUnescape(v)
		pairs = append(pairs, kv{uriEscape(dk, true), uriEscape(dv, true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.k+"="+p.v)
	}
	return strings.Join(out, "&")
}

// uriEscape is de SigV4-escaperegel: percent-encode elke byte buiten de
// unreserved-verzameling (A-Z, a-z, 0-9, '-', '_', '.', '~'). Met encodeSlash
// false blijft '/' letterlijk — dat is de vorm voor het pad.
//
// Dit is het stuk dat de tweede, met de hand geschreven signeerder in hop
// overslaat: een key met een spatie of een '+' erin signeert dan een andere
// string dan de server ziet, en de fout die je terugkrijgt zegt "signature
// mismatch" en niet "je pad is niet geëscaped".
func uriEscape(s string, encodeSlash bool) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&15])
		}
	}
	return b.String()
}

func deriveSigningKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(sigService))
	return hmacSHA256(kService, []byte(sigTerminator))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// hexSHA256 is de payload-hash-vorm die S3 wil: lowercase hex.
func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// emptyPayloadHash is de hash van een body van nul bytes, en dus wat een GET,
// een DELETE en een listing signeren.
//
// Bewust niet [UnsignedPayload] voor die drie: dat mag alleen over https en
// meerdere providers weigeren het op een write, terwijl de echte hash van een
// lege body altijd goed is. In hoplock stond dit per operatie verschillend
// ingesteld — de lease-DELETE signeerde de lege hash, de object-DELETE
// UNSIGNED-PAYLOAD — en dat verschil was geen keuze maar een slip.
var emptyPayloadHash = hexSHA256(nil)
