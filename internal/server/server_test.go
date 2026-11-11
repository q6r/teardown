package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/version"
)

// testHost is the Host header the helpers send: a loopback name with a port.
const testHost = "127.0.0.1:7777"

// testLogger returns a logger that discards everything.
func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestServer builds a server whose private directory lives under t.TempDir
// and whose logs are discarded.
func newTestServer(t testing.TB, mutate ...func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		TempDir: t.TempDir(),
		Stderr:  io.Discard,
		Logger:  testLogger(),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

// withAnalyzer is a Config mutator installing an analyzer.
func withAnalyzer(fn AnalyzeFunc) func(*Config) {
	return func(c *Config) { c.Analyze = fn }
}

// newRequest builds a request addressed to testHost with alternating
// header-name, header-value arguments.
func newRequest(method, target string, body io.Reader, headers ...string) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = testHost
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return req
}

// do sends a request straight to the handler (no network) and records the answer.
func do(t *testing.T, h http.Handler, method, target string, body io.Reader, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRequest(method, target, body, headers...))
	return rec
}

// sampleBytes returns n deterministic bytes of mostly printable text.
func sampleBytes(n int) []byte {
	if n == 0 {
		return []byte{}
	}
	return bytes.Repeat([]byte("teardown sample data 0123456789\n"), n/32+1)[:n]
}

// buildUpload builds a multipart body with one file part and returns it with
// its Content-Type. It does not need a *testing.T, so goroutines can use it.
func buildUpload(field, filename string, content []byte) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	pw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := pw.Write(content); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return &buf, mw.FormDataContentType(), nil
}

// formUpload is buildUpload for the test goroutine.
func formUpload(t *testing.T, field, filename string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	body, ctype, err := buildUpload(field, filename, content)
	if err != nil {
		t.Fatal(err)
	}
	return body, ctype
}

// uploadAsync uploads content straight to the handler without touching a
// *testing.T, so it may run in a goroutine.
func uploadAsync(h http.Handler, filename string, content []byte) (*httptest.ResponseRecorder, error) {
	body, ctype, err := buildUpload("file", filename, content)
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newRequest(http.MethodPost, "/api/analyze", body, "Content-Type", ctype))
	return rec, nil
}

// rawUpload builds a multipart body whose Content-Disposition is written
// verbatim, so tests can send header values the standard writer would escape.
func rawUpload(t *testing.T, disposition string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", disposition)
	h.Set("Content-Type", "application/octet-stream")
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

// postUpload uploads content as "file" with the given file name.
func postUpload(t *testing.T, h http.Handler, filename string, content []byte, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, ctype := formUpload(t, "file", filename, content)
	return do(t, h, http.MethodPost, "/api/analyze", body, append([]string{"Content-Type", ctype}, headers...)...)
}

// decode unmarshals a recorded JSON body into v.
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("response is not valid JSON (%v): %.300s", err, rec.Body.String())
	}
}

// uploadResult is the decoded body of a 201 answer.
type uploadResult struct {
	ID     string        `json:"id"`
	Report report.Report `json:"report"`
}

// mustUpload uploads content and fails the test unless the server answers 201.
func mustUpload(t *testing.T, h http.Handler, filename string, content []byte) uploadResult {
	t.Helper()
	rec := postUpload(t, h, filename, content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %q: status %d: %s", filename, rec.Code, rec.Body.String())
	}
	var res uploadResult
	decode(t, rec, &res)
	return res
}

// errorCode decodes the error envelope and returns its code.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env errorEnvelope
	decode(t, rec, &env)
	if env.Error.Code == "" || env.Error.Message == "" {
		t.Fatalf("error envelope is incomplete: %s", rec.Body.String())
	}
	return env.Error.Code
}

// fakeReport returns a small valid report for injected analyzers.
func fakeReport(name string, size int64) *report.Report {
	r := report.New(name, size, "test")
	r.Type = report.Type{
		ID: report.TypePE, Family: report.FamilyExecutable, Label: "PE32+ executable (test)",
		MIME: "application/vnd.microsoft.portable-executable", Confidence: report.ConfidenceHigh,
	}
	r.Risk = report.Risk{Score: 42, Label: report.RiskMedium, Basis: []string{"test fixture"}}
	r.Normalize()
	return r
}

// echoAnalyzer is an analyzer that reports the display name the server chose.
func echoAnalyzer(_ context.Context, path string, opts analyze.Options) (*report.Report, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return fakeReport(opts.Name, st.Size()), nil
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertNoUploads fails unless the server's private directory is empty.
func assertNoUploads(t *testing.T, s *Server) {
	t.Helper()
	waitFor(t, 3*time.Second, "the upload directory to be empty", func() bool {
		entries, err := os.ReadDir(s.tempDir)
		return err == nil && len(entries) == 0
	})
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestConfigDefaults(t *testing.T) {
	got, err := Config{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != DefaultAddr || got.MaxUpload != DefaultMaxUpload || got.Keep != DefaultKeep {
		t.Errorf("defaults not applied: %+v", got)
	}
	if got.Concurrency < 1 || got.Concurrency > 4 {
		t.Errorf("Concurrency = %d, want 1..4", got.Concurrency)
	}
	if got.AnalyzeTimeout != analyze.DefaultTimeout {
		t.Errorf("AnalyzeTimeout = %v", got.AnalyzeTimeout)
	}
	if got.Stderr == nil || got.Logger == nil || got.Analyze == nil {
		t.Error("Stderr, Logger and Analyze must default to non-nil values")
	}
	explicit, err := Config{Addr: "[::1]:9", MaxUpload: 7, Keep: 3, Concurrency: 2, AnalyzeTimeout: time.Second}.withDefaults()
	if err != nil || explicit.Addr != "[::1]:9" || explicit.MaxUpload != 7 || explicit.Keep != 3 || explicit.Concurrency != 2 || explicit.AnalyzeTimeout != time.Second {
		t.Errorf("explicit values must survive: %+v, %v", explicit, err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"negative max upload", Config{MaxUpload: -1}},
		{"max upload beyond the ceiling", Config{MaxUpload: maxUploadCeiling + 1}},
		{"max upload at the int64 limit", Config{MaxUpload: 1<<63 - 1}},
		{"negative keep", Config{Keep: -1}},
		{"keep above the ceiling", Config{Keep: maxKeep + 1}},
		{"negative concurrency", Config{Concurrency: -1}},
		{"concurrency above the ceiling", Config{Concurrency: maxConcurrency + 1}},
		{"negative analyze timeout", Config{AnalyzeTimeout: -time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.cfg.withDefaults(); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("New must reject the configuration too")
			}
		})
	}
	if _, err := New(Config{TempDir: filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("a missing temp parent must be an error")
	}
}

func TestNewCreatesAndCloseRemovesPrivateDir(t *testing.T) {
	parent := t.TempDir()
	s, err := New(Config{TempDir: parent, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "teardown-") {
		t.Fatalf("expected exactly one teardown-* directory, got %v (%v)", entries, err)
	}
	if info, err := os.Stat(s.tempDir); err != nil || !info.IsDir() {
		t.Fatalf("private dir missing: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
	if _, err := os.Stat(s.tempDir); !os.IsNotExist(err) {
		t.Fatalf("private dir still exists after Close: %v", err)
	}
}

func TestHealth(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s.Handler(), http.MethodGet, "/api/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	want := fmt.Sprintf(`{"status":"ok","version":%q}`, version.String())
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
	// (A recorder keeps the body of a HEAD answer; the net/http server drops it.)
	if head := do(t, s.Handler(), http.MethodHead, "/api/health", nil); head.Code != http.StatusOK {
		t.Errorf("HEAD = %d", head.Code)
	}
}
