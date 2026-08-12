package leans3

// De tests van de objectkant. De tegenpartij is net/http's server (de strenge
// tegenpartij, zoals overal in lean): hij ziet precies wat er op de draad staat,
// dus de asserties pinnen het gedrag — URL's, headers, paginering — en niet de
// interne bouw.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestGeenNetHTTP is de test die de reden van dit pakket afdwingt. Zodra er
// ergens één net/http-import binnenglipt, linkt elke gebruiker crypto/tls mee
// en is de ~2 MB terug — en dat merk je pas als een kern-image niet meer past.
// De tests hierónder mogen net/http wél gebruiken (de strenge tegenpartij);
// die staan niet in de dep-lijst van het pakket.
func TestGeenNetHTTP(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/xinix00/lean/leans3").Output()
	if err != nil {
		t.Skipf("go list niet beschikbaar: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "net/http" || dep == "crypto/tls" {
			t.Errorf("leans3 importeert %s — dat is precies wat dit pakket vervangt", dep)
		}
	}
}

// klant geeft een Client die tegen srv praat, in pad-stijl (een httptest-server
// heeft geen wildcard-DNS voor een bucket in de hostnaam).
func klant(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := &Client{
		Endpoint:        srv.URL,
		Bucket:          "bkt",
		Region:          "eu-test-1",
		AccessKeyID:     "AK",
		SecretAccessKey: "SK",
		UsePathStyle:    true,
	}
	t.Cleanup(c.CloseIdle)
	return c
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestGetLeestObjectEnETag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/bkt/state/cluster" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("GET not signed")
		}
		// Een GET signeert de hash van een LEGE body, niet UNSIGNED-PAYLOAD:
		// dat laatste mag alleen over https en providers weigeren het.
		if got := r.Header.Get("X-Amz-Content-Sha256"); got != hexSum(nil) {
			t.Errorf("X-Amz-Content-Sha256 = %q, want the empty-payload hash", got)
		}
		w.Header().Set("ETag", `"etag-1"`)
		fmt.Fprint(w, `{"jobs":[]}`)
	}))
	defer srv.Close()

	data, etag, err := klant(t, srv).Get(context.Background(), "state/cluster")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != `{"jobs":[]}` {
		t.Errorf("body = %q", data)
	}
	if etag != `"etag-1"` {
		t.Errorf("etag = %q, want %q", etag, `"etag-1"`)
	}
}

func TestGetAfwezigIsErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such key", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, _, err := klant(t, srv).Get(context.Background(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get absent: got %v, want ErrNotFound", err)
	}
}

// Een 403 is géén sentinel: hij hoort met status én body terug te komen, want
// S3 zet de echte reden (SignatureDoesNotMatch, AccessDenied) in die body.
func TestStatusFoutDraagtDeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>", http.StatusForbidden)
	}))
	defer srv.Close()

	_, _, err := klant(t, srv).Get(context.Background(), "k")
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("want a *StatusError, got %T: %v", err, err)
	}
	if se.Code != http.StatusForbidden || !strings.Contains(se.Body, "SignatureDoesNotMatch") {
		t.Errorf("StatusError = %+v", se)
	}
	if !strings.Contains(se.Error(), "403 Forbidden") {
		t.Errorf("Error() = %q, want the status in it", se.Error())
	}
}

func TestGetToStreamtBody(t *testing.T) {
	payload := bytes.Repeat([]byte("leans3-stream!"), 4096) // ~57KB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/bkt/apps/c/j/data.bin" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("GET not signed")
		}
		w.Write(payload)
	}))
	defer srv.Close()

	var got bytes.Buffer
	n, _, err := klant(t, srv).GetTo(context.Background(), "apps/c/j/data.bin", &got)
	if err != nil {
		t.Fatalf("GetTo: %v", err)
	}
	if n != int64(len(payload)) || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("streamed %d bytes, want %d (content match: %v)", n, len(payload), bytes.Equal(got.Bytes(), payload))
	}
}

func TestGetToAfwezigSchrijftNiets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such key", http.StatusNotFound)
	}))
	defer srv.Close()

	var got bytes.Buffer
	n, _, err := klant(t, srv).GetTo(context.Background(), "absent", &got)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if n != 0 || got.Len() != 0 {
		t.Fatalf("wrote %d bytes for an absent object", got.Len())
	}
}

// failAfter neemt limit bytes aan en faalt dan — het "lokale schijf vol"-pad.
type failAfter struct{ limit int }

func (f *failAfter) Write(p []byte) (int, error) {
	if len(p) > f.limit {
		n := f.limit
		f.limit = 0
		return n, errors.New("disk full")
	}
	f.limit -= len(p)
	return len(p), nil
}

func TestGetToSchrijffoutBreektAf(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte{0xAB}, 64<<10))
	}))
	defer srv.Close()

	_, _, err := klant(t, srv).GetTo(context.Background(), "big", &failAfter{limit: 8 << 10})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("want the writer's error back, got: %v", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a writer error must not look like a missing object")
	}
}

func TestPutStuurtLengteHashEnBody(t *testing.T) {
	payload := []byte(`{"jobs":["a"]}`)
	var gotBody []byte
	var gotLen int64
	var gotHash, gotType, gotCond string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/bkt/state/cluster" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		gotLen = r.ContentLength
		gotHash = r.Header.Get("X-Amz-Content-Sha256")
		gotType = r.Header.Get("Content-Type")
		gotCond = r.Header.Get("If-None-Match")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("ETag", `"etag-7"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	etag, err := klant(t, srv).Put(context.Background(), "state/cluster", payload,
		&PutOptions{ContentType: "application/json", IfNoneMatch: "*"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if etag != `"etag-7"` {
		t.Errorf("etag = %q, want %q", etag, `"etag-7"`)
	}
	if gotLen != int64(len(payload)) {
		t.Errorf("Content-Length %d, want %d", gotLen, len(payload))
	}
	if gotHash != hexSum(payload) {
		t.Errorf("X-Amz-Content-Sha256 %q, want %q", gotHash, hexSum(payload))
	}
	if gotType != "application/json" || gotCond != "*" {
		t.Errorf("Content-Type %q, If-None-Match %q", gotType, gotCond)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("body mismatch: got %q", gotBody)
	}
}

// Een leeg object moet nog steeds een Content-Length: 0 aankondigen: zonder die
// header antwoordt S3 411 Length Required.
func TestPutLeegObjectHeeftLengteNul(t *testing.T) {
	gotLen := int64(-1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen = r.ContentLength
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := klant(t, srv).Put(context.Background(), "empty", nil, nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if gotLen != 0 {
		t.Errorf("Content-Length = %d, want 0", gotLen)
	}
}

func TestPutVoorwaardeFaalt(t *testing.T) {
	for _, code := range []int{http.StatusPreconditionFailed, http.StatusConflict} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "exists", code)
		}))
		_, err := klant(t, srv).Put(context.Background(), "k", []byte("x"), &PutOptions{IfNoneMatch: "*"})
		if !errors.Is(err, ErrPreconditionFailed) {
			t.Errorf("status %d: got %v, want ErrPreconditionFailed", code, err)
		}
		srv.Close()
	}
}

func TestPutFromStuurtLengteHashEnBody(t *testing.T) {
	payload := bytes.Repeat([]byte("42"), 32<<10) // 64KB
	hash := hexSum(payload)

	var gotBody []byte
	var gotLen int64
	var gotHash, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/bkt/apps/c/j/out.bin" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		gotLen = r.ContentLength
		gotHash = r.Header.Get("X-Amz-Content-Sha256")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := klant(t, srv).PutFrom(context.Background(), "apps/c/j/out.bin",
		bytes.NewReader(payload), int64(len(payload)), hash, nil)
	if err != nil {
		t.Fatalf("PutFrom: %v", err)
	}
	if gotLen != int64(len(payload)) {
		t.Errorf("Content-Length %d, want %d (a chunked upload would break S3)", gotLen, len(payload))
	}
	if gotHash != hash {
		t.Errorf("X-Amz-Content-Sha256 %q, want %q", gotHash, hash)
	}
	if gotAuth == "" {
		t.Error("PUT not signed")
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("body mismatch: got %d bytes", len(gotBody))
	}
}

func TestPutFromKorteBronFaaltLuid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Kondig 100 bytes aan, lever er 10: het transport moet weigeren een stil
	// afgekapt object te versturen.
	_, err := klant(t, srv).PutFrom(context.Background(), "torn",
		strings.NewReader("0123456789"), 100, hexSum([]byte("whatever")), nil)
	if err == nil {
		t.Fatal("short source accepted — a torn upload must be an error")
	}
}

// Zonder hash kan een stroom niet gesigneerd worden, en stil UNSIGNED-PAYLOAD
// sturen zou de payload-integriteit weggeven zonder dat iemand het ziet.
func TestPutFromZonderHashWeigert(t *testing.T) {
	c := &Client{Endpoint: "https://s3.example.com", Bucket: "b", Region: "r", AccessKeyID: "a", SecretAccessKey: "s"}
	_, err := c.PutFrom(context.Background(), "k", strings.NewReader("x"), 1, "", nil)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want a loud refusal about the missing hash, got %v", err)
	}
}

// Een DELETE die met 204 antwoordt is de regressie waar dit pakket bijna in
// bleef hangen: een 204 heeft geen Content-Length en geen chunks, dus een lezer
// die "tot EOF" leest wacht op een keep-alive-verbinding tot de server hem
// verveeld dichtgooit. Deze test faalt met een timeout als die regel weg is.
func TestDelete204BlijftNietHangen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("unexpected method %s", r.Method)
		}
		if got := r.Header.Get("If-Match"); got != `"etag-1"` {
			t.Errorf("If-Match = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	done := make(chan error, 1)
	go func() {
		done <- klant(t, srv).Delete(context.Background(), "k", &DeleteOptions{IfMatch: `"etag-1"`})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Delete: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Delete on a 204 blocked: a bodyless response must not be read until EOF")
	}
}

func TestDeleteAfwezigEnVoorwaarde(t *testing.T) {
	code := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", code)
	}))
	defer srv.Close()
	c := klant(t, srv)

	if err := c.Delete(context.Background(), "k", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: got %v, want ErrNotFound", err)
	}
	code = http.StatusPreconditionFailed
	if err := c.Delete(context.Background(), "k", &DeleteOptions{IfMatch: "x"}); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("412: got %v, want ErrPreconditionFailed", err)
	}
}

func TestListPagineertMetToken(t *testing.T) {
	var prefixes, tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bkt/" {
			t.Errorf("list path %q, want /bkt/", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("list-type") != "2" {
			t.Errorf("list-type %q, want 2", q.Get("list-type"))
		}
		prefixes = append(prefixes, q.Get("prefix"))
		tok := q.Get("continuation-token")
		tokens = append(tokens, tok)
		if tok == "" {
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page2</NextContinuationToken>
  <Contents><Key>apps/c/j/a.txt</Key></Contents>
  <Contents><Key>apps/c/j/b.txt</Key></Contents>
</ListBucketResult>`)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents><Key>apps/c/j/c.txt</Key></Contents>
</ListBucketResult>`)
	}))
	defer srv.Close()

	keys, truncated, err := klant(t, srv).List(context.Background(), "apps/c/j/", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if truncated {
		t.Error("truncated = true without a cap")
	}
	want := []string{"apps/c/j/a.txt", "apps/c/j/b.txt", "apps/c/j/c.txt"}
	if len(keys) != len(want) {
		t.Fatalf("got %d keys %v, want %v", len(keys), keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("key[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
	if len(tokens) != 2 || tokens[1] != "page2" {
		t.Errorf("continuation tokens %v, want [\"\" page2]", tokens)
	}
	for _, p := range prefixes {
		if p != "apps/c/j/" {
			t.Errorf("prefix %q, want apps/c/j/", p)
		}
	}
}

func TestListCapMeldtAfkapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>k1</Key></Contents>
  <Contents><Key>k2</Key></Contents>
  <Contents><Key>k3</Key></Contents>
  <Contents><Key>k4</Key></Contents>
</ListBucketResult>`)
	}))
	defer srv.Close()

	keys, truncated, err := klant(t, srv).List(context.Background(), "", 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 || !truncated {
		t.Fatalf("got %d keys (truncated=%v), want 2 keys with truncated=true", len(keys), truncated)
	}
}

// De adresseringsstijl valt niet tegen een httptest-server op 127.0.0.1 te
// testen (er is geen wildcard-DNS voor "bkt.127.0.0.1"), dus hier staat de
// URL-samenstelling zelf vast.
func TestURLSamenstelling(t *testing.T) {
	t.Parallel()
	vhost := &Client{Endpoint: "https://s3.example.com", Bucket: "bkt", Region: "r", AccessKeyID: "a", SecretAccessKey: "s"}
	u, err := vhost.bucketURL()
	if err != nil {
		t.Fatalf("bucketURL: %v", err)
	}
	if u.Host != "bkt.s3.example.com" || u.Path != "/" {
		t.Fatalf("bucket URL %q, want host bkt.s3.example.com path /", u.String())
	}
	ou, err := vhost.URLFor("a/b.txt")
	if err != nil {
		t.Fatalf("URLFor: %v", err)
	}
	if ou.Host != "bkt.s3.example.com" || ou.Path != "/a/b.txt" {
		t.Fatalf("object URL %q, want host bkt.s3.example.com path /a/b.txt", ou.String())
	}

	path := &Client{Endpoint: "https://s3.example.com", Bucket: "bkt", UsePathStyle: true, Region: "r", AccessKeyID: "a", SecretAccessKey: "s"}
	pu, err := path.URLFor("a/b.txt")
	if err != nil {
		t.Fatalf("URLFor: %v", err)
	}
	if pu.Host != "s3.example.com" || pu.Path != "/bkt/a/b.txt" {
		t.Fatalf("object URL %q, want host s3.example.com path /bkt/a/b.txt", pu.String())
	}
}

// Ontbrekende of onmogelijke configuratie faalt luid en vóór het netwerk.
func TestConfiguratieFaaltLuid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := []struct {
		naam string
		c    *Client
		key  string
		want string
	}{
		{"geen endpoint", &Client{Bucket: "b"}, "k", "Endpoint is required"},
		{"geen bucket", &Client{Endpoint: "https://s3.example.com"}, "k", "Bucket is required"},
		{"geen key", &Client{Endpoint: "https://s3.example.com", Bucket: "b"}, "", "key is required"},
		{"schema", &Client{Endpoint: "ftp://s3.example.com", Bucket: "b"}, "k", "must be http or https"},
		{"endpoint zonder schema", &Client{Endpoint: "s3.example.com", Bucket: "b"}, "k", "must include scheme and host"},
	}
	for _, c := range cases {
		_, _, err := c.c.Get(ctx, c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error containing %q", c.naam, err, c.want)
		}
	}
}

// Een afgebroken context doet geen verzoek. De DEADLINE wordt wél doorgegeven
// (als leanhttp's termijn); een kale cancel halverwege niet — dat staat in de
// pakketdoc.
func TestAfgebrokenContextDoetNiets(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := klant(t, srv).Get(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if hits != 0 {
		t.Errorf("server saw %d requests for a cancelled context", hits)
	}
}
