package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// spyHandler is a slog.Handler that remembers the messages it was given.
type spyHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *spyHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *spyHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *spyHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *spyHandler) WithGroup(string) slog.Handler      { return h }

func (h *spyHandler) saw(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if m == msg {
			return true
		}
	}
	return false
}

// FuzzHandler throws arbitrary requests at the whole handler chain. Whatever the
// input, the server must answer with a valid status, never panic inside a
// handler (the recover middleware would turn that into a 500), and never leave
// an upload behind.
func FuzzHandler(f *testing.F) {
	spy := &spyHandler{}
	s := newTestServer(f, withAnalyzer(echoAnalyzer), func(c *Config) { c.Logger = slog.New(spy) })

	okBody, okType, err := buildUpload("file", "seed.bin", []byte("seed content https://example.com"))
	if err != nil {
		f.Fatal(err)
	}
	seeds := []struct {
		method, target, host, ctype, origin string
		body                                []byte
	}{
		{"GET", "/api/health", testHost, "", "", nil},
		{"GET", "/", testHost, "", "", nil},
		{"GET", "/api/analyses", testHost, "", "", nil},
		{"GET", "/api/analyses/an_000000000000", testHost, "", "", nil},
		{"GET", "/api/analyses/an_000000000000/strings?category=url&q=a&limit=5&offset=1", testHost, "", "", nil},
		{"DELETE", "/api/analyses/an_000000000000", testHost, "", "", nil},
		{"POST", "/api/analyze", testHost, okType, "", okBody.Bytes()},
		{"POST", "/api/analyze", testHost, okType, "http://evil.example", okBody.Bytes()},
		{"POST", "/api/analyze", testHost, "multipart/form-data; boundary=x", "", []byte("--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../a\"\r\n\r\nzz\r\n--x--\r\n")},
		{"OPTIONS", "/api/analyze", testHost, "", "http://evil.example", nil},
		{"GET", "/api/events", testHost, "", "", nil},
		{"GET", "/api/openapi.json", testHost, "", "", nil},
		{"GET", "/%2e%2e/%2e%2e/etc/passwd", testHost, "", "", nil},
		{"GET", "/api/analyses/%00", "evil.example", "", "", nil},
		{"PATCH", "/api//analyses///x", "[::1]:80", "", "", nil},
	}
	for _, sd := range seeds {
		f.Add(sd.method, sd.target, sd.host, sd.ctype, sd.origin, sd.body)
	}

	f.Fuzz(func(t *testing.T, method, target, host, ctype, origin string, body []byte) {
		if method == "" || strings.ContainsAny(method, " \t\r\n") || !strings.HasPrefix(target, "/") {
			t.Skip("not a request a real server would hand to a handler")
		}
		u, err := url.ParseRequestURI(target)
		if err != nil {
			t.Skip("unparsable request target")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // streaming handlers must return at once
		req := (&http.Request{
			Method:        method,
			URL:           u,
			Host:          host,
			Header:        http.Header{},
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			RequestURI: target,
		}).WithContext(ctx)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)

		if rec.Code < 100 || rec.Code > 599 {
			t.Fatalf("invalid status %d", rec.Code)
		}
		if spy.saw("handler panic") {
			t.Fatalf("a handler panicked for %s %q (Host %q)", method, target, host)
		}
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("unexpected 500 for %s %q: %.200s", method, target, rec.Body.String())
		}
		if entries, err := os.ReadDir(s.tempDir); err != nil || len(entries) != 0 {
			t.Fatalf("upload left behind after %s %q: %v (%v)", method, target, entries, err)
		}
	})
}
