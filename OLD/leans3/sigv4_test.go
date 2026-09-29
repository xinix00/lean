package leans3

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xinix00/lean/leanhttp"
)

func TestURIEscape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"abc", false, "abc"},
		{"a b", false, "a%20b"},
		{"a/b", false, "a/b"},
		{"a/b", true, "a%2Fb"},
		{"a+b=c", false, "a%2Bb%3Dc"},
		{"~unreserved-_.set", false, "~unreserved-_.set"},
		{"path with spaces/and+specials", false, "path%20with%20spaces/and%2Bspecials"},
		{"", false, ""},
		{"\n", false, "%0A"},
	}
	for _, c := range cases {
		got := uriEscape(c.in, c.encodeSlash)
		if got != c.want {
			t.Errorf("uriEscape(%q, %v) = %q, want %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}

func TestCanonicalQuery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"a=1", "a=1"},
		{"b=2&a=1", "a=1&b=2"},
		{"a=2&a=1", "a=1&a=2"},
		{"key=val with space", "key=val%20with%20space"},
		{"a", "a="},
		{"with%20encoded=already", "with%20encoded=already"},
	}
	for _, c := range cases {
		u := &url.URL{RawQuery: c.raw}
		got := canonicalQuery(u)
		if got != c.want {
			t.Errorf("canonicalQuery(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestCanonicalURI(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/foo/bar", "/foo/bar"},
		{"/foo bar/baz", "/foo%20bar/baz"},
		{"/foo+bar/baz~q", "/foo%2Bbar/baz~q"},
	}
	for _, c := range cases {
		got := canonicalURI(c.in)
		if got != c.want {
			t.Errorf("canonicalURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDeriveSigningKeyDeterministisch(t *testing.T) {
	t.Parallel()
	k1 := deriveSigningKey("secret", "20260101", "us-east-1")
	k2 := deriveSigningKey("secret", "20260101", "us-east-1")
	if hex.EncodeToString(k1) != hex.EncodeToString(k2) {
		t.Error("deriveSigningKey not deterministic")
	}
	if len(k1) != 32 {
		t.Errorf("signing key length = %d, want 32 (sha256 output)", len(k1))
	}

	if hex.EncodeToString(k1) == hex.EncodeToString(deriveSigningKey("secret", "20260102", "us-east-1")) {
		t.Error("signing key did not change with different date")
	}
	if hex.EncodeToString(k1) == hex.EncodeToString(deriveSigningKey("secret", "20260101", "us-west-2")) {
		t.Error("signing key did not change with different region")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSignRequestZetDeVerwachteHeaders(t *testing.T) {
	t.Parallel()
	u := mustURL(t, "https://bucket.s3.us-east-1.amazonaws.com/lock.json")

	hdr := leanhttp.Header{"Content-Type": "application/json", "If-None-Match": "*"}

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	signRequest(methodPut, u, hdr, credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
	}, hexSHA256([]byte("payload")), now)

	if got := hdr.Get("X-Amz-Date"); got != "20260115T120000Z" {
		t.Errorf("X-Amz-Date = %q, want 20260115T120000Z", got)
	}
	if got := hdr.Get("X-Amz-Content-Sha256"); got == "" {
		t.Error("X-Amz-Content-Sha256 not set")
	}
	auth := hdr.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260115/us-east-1/s3/aws4_request,") {
		t.Errorf("Authorization missing expected prefix: %q", auth)
	}
	for _, marker := range []string{"SignedHeaders=", "Signature="} {
		if !strings.Contains(auth, marker) {
			t.Errorf("Authorization missing %q: %q", marker, auth)
		}
	}

	signedHeaders := extractSignedHeaders(auth)
	for _, want := range []string{"content-type", "host", "if-none-match", "x-amz-content-sha256", "x-amz-date"} {
		if !contains(signedHeaders, want) {
			t.Errorf("SignedHeaders missing %q: %v", want, signedHeaders)
		}
	}
}

func TestSignRequestSessieToken(t *testing.T) {
	t.Parallel()
	hdr := leanhttp.Header{}
	signRequest(methodGet, mustURL(t, "https://bucket.s3.us-east-1.amazonaws.com/lock.json"), hdr, credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "secret",
		SessionToken:    "session-tok",
		Region:          "us-east-1",
	}, hexSHA256(nil), time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))

	if got := hdr.Get("X-Amz-Security-Token"); got != "session-tok" {
		t.Errorf("X-Amz-Security-Token = %q, want session-tok", got)
	}
	if !strings.Contains(hdr.Get("Authorization"), "x-amz-security-token") {
		t.Errorf("session token not in SignedHeaders: %q", hdr.Get("Authorization"))
	}
}

func TestSignRequestDeterministischBijVasteKlok(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	mk := func() leanhttp.Header {
		hdr := leanhttp.Header{}
		signRequest(methodGet, mustURL(t, "https://bucket.s3.us-east-1.amazonaws.com/lock.json"), hdr, credentials{
			AccessKeyID:     "AKID",
			SecretAccessKey: "secret",
			Region:          "us-east-1",
		}, hexSHA256(nil), now)
		return hdr
	}
	a := mk().Get("Authorization")
	b := mk().Get("Authorization")
	if a != b {
		t.Errorf("signing not deterministic for fixed inputs:\n  a=%s\n  b=%s", a, b)
	}
}

func TestCanonicalRequestGesigneerdeHeaders(t *testing.T) {
	t.Parallel()
	u := mustURL(t, "https://bucket.s3.us-east-1.amazonaws.com/lock.json")
	hdr := leanhttp.Header{
		"Content-Type":  "application/json",
		"Authorization": "must-not-be-signed",
		"X-Amz-Date":    "20260115T120000Z",
	}
	canonical, signed := canonicalRequest(methodPut, u, hdr, UnsignedPayload)

	if signed != "content-type;host;x-amz-date" {
		t.Errorf("SignedHeaders = %q, want content-type;host;x-amz-date", signed)
	}
	if !strings.Contains(canonical, "host:bucket.s3.us-east-1.amazonaws.com\n") {
		t.Errorf("canonical request must sign host from the URL:\n%s", canonical)
	}
	if strings.Contains(canonical, "content-length") {
		t.Errorf("Content-Length must stay out of the signature:\n%s", canonical)
	}
}

func TestLegePayloadHash(t *testing.T) {
	t.Parallel()
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if emptyPayloadHash != want {
		t.Errorf("emptyPayloadHash = %q, want %q", emptyPayloadHash, want)
	}
}

func extractSignedHeaders(auth string) []string {
	const marker = "SignedHeaders="
	i := strings.Index(auth, marker)
	if i < 0 {
		return nil
	}
	rest := auth[i+len(marker):]
	end := strings.IndexByte(rest, ',')
	if end > 0 {
		rest = rest[:end]
	}
	return strings.Split(rest, ";")
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
