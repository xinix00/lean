package leanhttp

// request_test.go — Request.Context (de done-brug als context, en zijn
// laziness-regels) en de testdoubles uit recorder.go.

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Request.Context: op een synthetische request (NewRequest) eindigt hij nooit;
// WithContext versmalt hem; op een echte verbinding eindigt hij wanneer de
// client weggaat.
func TestRequestContext(t *testing.T) {
	r := NewRequest(MethodGet, "/x?a=1", nil)
	ctx := r.Context()
	select {
	case <-ctx.Done():
		t.Fatal("de lifetime van een synthetische request hoort niet te eindigen")
	default:
	}
	if ctx.Err() != nil {
		t.Fatalf("Err: %v", ctx.Err())
	}

	narrow, cancel := context.WithCancel(context.Background())
	cancel()
	if r.WithContext(narrow).Context().Err() == nil {
		t.Fatal("WithContext versmalde de lifetime niet")
	}

	// Echte verbinding: client weg ⇒ Context eindigt.
	sawEnd := make(chan struct{})
	addr := leanServer(t, func(w ResponseWriter, r *Request) {
		ctx := r.Context() // claimt de lifetime vóór de eerste Flush
		w.Flush()
		<-ctx.Done()
		close(sawEnd)
	})
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // laat de handler de lifetime claimen
	c.Close()
	select {
	case <-sawEnd:
	case <-time.After(2 * time.Second):
		t.Fatal("Context eindigde niet toen de client wegging")
	}
}

func TestRecorder(t *testing.T) {
	rec := NewRecorder()
	if rec.Code != 0 {
		t.Fatalf("verse recorder heeft Code %d, wil 0 (niets gestuurd)", rec.Code)
	}
	rec.Header().Set("Content-Type", "text/plain")
	io.WriteString(rec, "hoi")
	rec.Flush()
	if rec.Code != StatusOK || rec.String() != "hoi" || rec.Flushes != 1 {
		t.Fatalf("code=%d body=%q flushes=%d", rec.Code, rec.String(), rec.Flushes)
	}
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("Hijack op een Recorder hoort te falen")
	}
	empty := NewRecorder()
	empty.Write(nil)
	empty.WriteHeader(StatusBadRequest)
	if empty.Code != StatusBadRequest {
		t.Fatalf("lege Write committeerde status %d, wil de latere 400", empty.Code)
	}

	r := NewRequest(MethodPost, "/caf%C3%A9?x=2", strings.NewReader("body")).
		WithPathValues(map[string]string{"id": "b"})
	if r.PathValue("id") != "b" || r.Query().Get("x") != "2" || r.Path != "/café" {
		t.Fatalf("request niet goed opgebouwd: %+v", r)
	}
	if r.ContentLength != 4 || r.Header.Get("Content-Length") != "4" {
		t.Fatalf("bodylengte = %d / %q, wil 4", r.ContentLength, r.Header.Get("Content-Length"))
	}
	select {
	case <-r.Done():
		t.Fatal("Done van een synthetische request hoort nooit te sluiten")
	default:
	}

	for _, target := range []string{"/a//b", "/a%2Fb"} {
		t.Run("target_"+strconv.Quote(target), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("NewRequest accepteerde een target dat de server afwijst")
				}
			}()
			NewRequest(MethodGet, target, nil)
		})
	}
	t.Run("body_zonder_lengte", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewRequest maakte een requestbody die de server niet kan ontvangen")
			}
		}()
		body := struct{ io.Reader }{strings.NewReader("x")}
		NewRequest(MethodPost, "/", body)
	})
	t.Run("body_te_groot", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewRequest accepteerde een body die de server afwijst")
			}
		}()
		NewRequest(MethodPost, "/", strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))
	})

	for _, status := range []int{199, 600} {
		t.Run("status_"+strconv.Itoa(status), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Recorder accepteerde een status die de echte writer afwijst")
				}
			}()
			NewRecorder().WriteHeader(status)
		})
	}
}
