package leans3

// AWS Signature Version 4 for requests with known bodies; streaming signatures
// are outside scope.
//
// Specification:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
//
// This code ran against AWS, Cloudflare R2, MinIO, and Hetzner/Ceph RGW in
// hoplock/s3. Tests protect the canonical form because changing it invalidates
// every signature.

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

// credentials contains the inputs needed by SigV4.
type credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

// signRequest adds Authorization, X-Amz-Date, and X-Amz-Content-Sha256 to the
// header map sent on the wire. payloadHash is hexadecimal SHA-256 or
// [UnsignedPayload]. Signing method, URL, and headers directly matches the data
// represented by a leanhttp Call.
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

// canonicalRequest builds the canonical request and signed-header list.
//
// Two apparent omissions are intentional:
//
//   - host comes from u.Host because leanhttp owns and writes that field.
//   - Content-Length remains unsigned because leanhttp derives and writes it
//     from body length, matching the signer's historical net/http behavior.
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

// canonicalURI escapes each path segment using RFC 3986 unreserved characters,
// preserving separators. An empty path becomes "/".
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

// canonicalQuery re-escapes parameters using SigV4 rules and sorts by key then
// value.
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

// uriEscape percent-encodes bytes outside the SigV4 unreserved set. A false
// encodeSlash preserves path separators. Omitting this step makes keys with
// spaces or `+` sign a different string from the server's request target.
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

// hexSHA256 returns S3's lowercase hexadecimal payload-hash form.
func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// emptyPayloadHash signs the zero-byte body used by GET, DELETE, and LIST. It is
// safer and more widely supported than [UnsignedPayload].
var emptyPayloadHash = hexSHA256(nil)
