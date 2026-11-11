package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

func TestAnalyzeHappyPath(t *testing.T) {
	s := newTestServer(t) // the real analyzer
	content := sampleBytes(5000)

	rec := postUpload(t, s.Handler(), "sample.bin", content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var res uploadResult
	decode(t, rec, &res)

	if !idPattern.MatchString(res.ID) {
		t.Errorf("id %q does not match an_<12 hex>", res.ID)
	}
	if got := rec.Header().Get("Location"); got != "/api/analyses/"+res.ID {
		t.Errorf("Location = %q", got)
	}
	sum := sha256.Sum256(content)
	if got := res.Report.Hashes.SHA256; got != hex.EncodeToString(sum[:]) {
		t.Errorf("report sha256 = %s, want %x", got, sum)
	}
	if res.Report.Schema != report.Schema {
		t.Errorf("schema = %q", res.Report.Schema)
	}
	if res.Report.File.Name != "sample.bin" || res.Report.File.Size != int64(len(content)) {
		t.Errorf("file = %+v", res.Report.File)
	}

	// The contract keys the dashboard relies on are all present.
	var raw struct {
		Report map[string]json.RawMessage `json:"report"`
	}
	decode(t, rec, &raw)
	for _, key := range []string{"schema", "tool", "generatedAt", "file", "type", "hashes", "entropy", "sections", "imports", "strings", "hardening", "details", "findings", "risk", "limitations"} {
		if _, ok := raw.Report[key]; !ok {
			t.Errorf("report is missing key %q", key)
		}
	}

	assertNoUploads(t, s)

	// The stored copy is identical to what the POST returned.
	get := do(t, s.Handler(), http.MethodGet, "/api/analyses/"+res.ID, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET status %d", get.Code)
	}
	var posted struct {
		Report map[string]any `json:"report"`
	}
	var fetched map[string]any
	decode(t, rec, &posted)
	decode(t, get, &fetched)
	if !reflect.DeepEqual(posted.Report, fetched) {
		t.Error("GET /api/analyses/{id} differs from the report returned by POST")
	}
}

func TestAnalyzeEmptyFile(t *testing.T) {
	s := newTestServer(t)
	res := mustUpload(t, s.Handler(), "empty.bin", nil)
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if res.Report.File.Size != 0 || res.Report.Hashes.SHA256 != emptySHA256 {
		t.Errorf("empty upload report = %+v / %s", res.Report.File, res.Report.Hashes.SHA256)
	}
	assertNoUploads(t, s)
}

func TestAnalyzeRejectsBadRequests(t *testing.T) {
	ok, okType := formUpload(t, "file", "a.bin", []byte("abc"))
	wrongField, wrongType := formUpload(t, "upload", "a.bin", []byte("abc"))
	twoParts, twoType := twoPartUpload(t)
	truncated := ok.Bytes()[:ok.Len()-12] // cut inside the closing boundary
	const boundary = "XBOUNDARY"

	tests := []struct {
		name        string
		method      string
		contentType string
		body        []byte
		wantStatus  int
		wantCode    string
		wantAllow   string
	}{
		{"json body", http.MethodPost, "application/json", []byte(`{"file":"x"}`), 415, codeUnsupportedMedia, ""},
		{"no content type", http.MethodPost, "", []byte("abc"), 415, codeUnsupportedMedia, ""},
		{"urlencoded form", http.MethodPost, "application/x-www-form-urlencoded", []byte("file=abc"), 415, codeUnsupportedMedia, ""},
		{"multipart without boundary", http.MethodPost, "multipart/form-data", []byte("abc"), 400, codeBadMultipart, ""},
		{"wrong field name", http.MethodPost, wrongType, wrongField.Bytes(), 400, codeMissingFile, ""},
		{"empty multipart", http.MethodPost, "multipart/form-data; boundary=" + boundary, []byte("--" + boundary + "--\r\n"), 400, codeMissingFile, ""},
		{"truncated body", http.MethodPost, okType, truncated, 400, codeBadMultipart, ""},
		{"garbage body", http.MethodPost, "multipart/form-data; boundary=" + boundary, []byte("this is not multipart"), 400, codeBadMultipart, ""},
		{"two parts", http.MethodPost, twoType, twoParts.Bytes(), 400, codeUnexpectedPart, ""},
		{"GET", http.MethodGet, "", nil, 405, codeMethodNotAllowed, "POST"},
		{"PUT", http.MethodPut, "", nil, 405, codeMethodNotAllowed, "POST"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			var headers []string
			if tc.contentType != "" {
				headers = []string{"Content-Type", tc.contentType}
			}
			rec := do(t, s.Handler(), tc.method, "/api/analyze", bytes.NewReader(tc.body), headers...)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorCode(t, rec); got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tc.wantAllow)
			}
			assertNoUploads(t, s)
			if n := s.store.len(); n != 0 {
				t.Errorf("%d analyses stored after a rejected request", n)
			}
		})
	}
}

// twoPartUpload builds a body with a valid "file" part followed by a second part.
func twoPartUpload(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	body, ctype := formUpload(t, "file", "a.bin", []byte("abc"))
	boundary := strings.TrimPrefix(ctype, "multipart/form-data; boundary=")
	b := strings.TrimSuffix(body.String(), "--"+boundary+"--\r\n")
	b += "--" + boundary + "\r\nContent-Disposition: form-data; name=\"extra\"\r\n\r\nmore\r\n--" + boundary + "--\r\n"
	return bytes.NewBufferString(b), ctype
}

func TestAnalyzeSizeCapIsExact(t *testing.T) {
	const limit = 1024
	tests := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{"below the cap", limit - 1, http.StatusCreated},
		{"exactly the cap", limit, http.StatusCreated},
		{"one byte over", limit + 1, http.StatusRequestEntityTooLarge},
		{"far over", 64 * 1024, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, func(c *Config) { c.MaxUpload = limit }, withAnalyzer(echoAnalyzer))
			rec := postUpload(t, s.Handler(), "big.bin", sampleBytes(tc.size))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %.200s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusRequestEntityTooLarge {
				if code := errorCode(t, rec); code != codeTooLarge {
					t.Errorf("code = %q", code)
				}
				if n := s.store.len(); n != 0 {
					t.Errorf("%d analyses stored for an oversize upload", n)
				}
			}
			assertNoUploads(t, s)
		})
	}
}

// failingBody fails the test if anything reads it.
type failingBody struct{ t *testing.T }

func (f failingBody) Read([]byte) (int, error) {
	f.t.Error("the server read a body it should have refused by Content-Length alone")
	return 0, errors.New("must not be read")
}
func (failingBody) Close() error { return nil }

func TestAnalyzeRefusesOversizeContentLengthWithoutReading(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.MaxUpload = 100 })
	req := newRequest(http.MethodPost, "/api/analyze", nil, "Content-Type", "multipart/form-data; boundary=x")
	req.Body = failingBody{t}
	req.ContentLength = 100 + multipartOverhead + 1
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || errorCode(t, rec) != codeTooLarge {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAnalyzeStreamingBodyLimitIsEnforced(t *testing.T) {
	// With no Content-Length (chunked upload) the limit is enforced while reading:
	// a part header far beyond the allowance must fail with 413, not be buffered.
	s := newTestServer(t, func(c *Config) { c.MaxUpload = 1024 }, withAnalyzer(echoAnalyzer))
	huge := strings.Repeat("a", 3<<20)
	body, ctype := rawUpload(t, `form-data; name="file"; filename="`+huge+`"`, []byte("x"))
	req := newRequest(http.MethodPost, "/api/analyze", body, "Content-Type", ctype)
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || errorCode(t, rec) != codeTooLarge {
		t.Fatalf("status = %d: %.200s", rec.Code, rec.Body.String())
	}
	assertNoUploads(t, s)
}

func TestAnalyzeDisplayNames(t *testing.T) {
	long := strings.Repeat("a", 5000) + ".exe"
	tests := []struct {
		name        string
		disposition string
		want        string // "" for the long name, whose shape is checked instead
	}{
		{"plain", `form-data; name="file"; filename="sample.bin"`, "sample.bin"},
		{"unix traversal", `form-data; name="file"; filename="../../etc/passwd"`, "passwd"},
		{"windows traversal", `form-data; name="file"; filename="..\..\windows\system32\evil.dll"`, "evil.dll"},
		{"windows drive path", `form-data; name="file"; filename="C:\Windows\x.exe"`, "x.exe"},
		{"escaped windows path", `form-data; name="file"; filename="C:\\Windows\\y.exe"`, "y.exe"},
		{"absolute path", `form-data; name="file"; filename="/etc/shadow"`, "shadow"},
		{"no filename parameter", `form-data; name="file"`, fallbackName},
		{"empty filename", `form-data; name="file"; filename=""`, fallbackName},
		{"dots only", `form-data; name="file"; filename=".."`, fallbackName},
		{"whitespace only", `form-data; name="file"; filename="   "`, fallbackName},
		{"collapsed spaces", `form-data; name="file"; filename="a    b.txt"`, "a b.txt"},
		{"nul and newline via RFC 2231", `form-data; name="file"; filename*=UTF-8''a%00b%0d%0ac.exe`, "ab c.exe"},
		{"right-to-left override", "form-data; name=\"file\"; filename=\"photo\u202Efdp.exe\"", "photofdp.exe"},
		{"unicode kept", `form-data; name="file"; filename="café ✓.exe"`, "café ✓.exe"},
		{"very long keeps the extension", `form-data; name="file"; filename="` + long + `"`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, withAnalyzer(echoAnalyzer))
			body, ctype := rawUpload(t, tc.disposition, []byte("data"))
			rec := do(t, s.Handler(), http.MethodPost, "/api/analyze", body, "Content-Type", ctype)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status %d: %.300s", rec.Code, rec.Body.String())
			}
			var res uploadResult
			decode(t, rec, &res)
			got := res.Report.File.Name
			if tc.want == "" {
				if len(got) > maxNameBytes || !strings.HasSuffix(got, ".exe") {
					t.Fatalf("long name became %d bytes %.40q", len(got), got)
				}
			} else if got != tc.want {
				t.Fatalf("display name = %q, want %q", got, tc.want)
			}
			assertNoUploads(t, s)
		})
	}
}

func TestUploadNeverTouchesFilesOutsideItsDirectory(t *testing.T) {
	parent := t.TempDir()
	s := newTestServer(t, func(c *Config) { c.TempDir = parent }, withAnalyzer(echoAnalyzer))
	body, ctype := rawUpload(t, `form-data; name="file"; filename="../../../escape.txt"`, []byte("x"))
	if rec := do(t, s.Handler(), http.MethodPost, "/api/analyze", body, "Content-Type", ctype); rec.Code != http.StatusCreated {
		t.Fatalf("status %d", rec.Code)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected only the private directory under the temp parent, got %v (%v)", entries, err)
	}
	assertNoUploads(t, s)
}

func TestConcurrentUploads(t *testing.T) {
	s := newTestServer(t) // real analyzer, real HTTP
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	const n = 12
	type outcome struct {
		res    uploadResult
		sha    string
		status int
		err    error
	}
	results := make([]outcome, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			content := append(sampleBytes(2000+i*37), byte(i)) // distinct per upload
			sum := sha256.Sum256(content)
			results[i].sha = hex.EncodeToString(sum[:])
			body, ctype, err := buildUpload("file", fmt.Sprintf("file-%d.bin", i), content)
			if err != nil {
				results[i].err = err
				return
			}
			resp, err := http.Post(ts.URL+"/api/analyze", ctype, body)
			if err != nil {
				results[i].err = err
				return
			}
			defer resp.Body.Close()
			results[i].status = resp.StatusCode
			results[i].err = json.NewDecoder(resp.Body).Decode(&results[i].res)
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, r := range results {
		if r.err != nil || r.status != http.StatusCreated {
			t.Fatalf("upload %d: status %d, err %v", i, r.status, r.err)
		}
		if seen[r.res.ID] {
			t.Errorf("duplicate id %s", r.res.ID)
		}
		seen[r.res.ID] = true
		if r.res.Report.Hashes.SHA256 != r.sha {
			t.Errorf("upload %d: report hash %s does not belong to the upload (%s)", i, r.res.Report.Hashes.SHA256, r.sha)
		}
		if want := fmt.Sprintf("file-%d.bin", i); r.res.Report.File.Name != want {
			t.Errorf("upload %d: name %q, want %q", i, r.res.Report.File.Name, want)
		}
	}
	if got := s.store.len(); got != n {
		t.Errorf("stored %d analyses, want %d", got, n)
	}
	assertNoUploads(t, s)
}

// gatedAnalyzer blocks every analysis until gate is closed and records how many
// run at once.
type gatedAnalyzer struct {
	gate    chan struct{}
	started chan struct{}
	running atomic.Int32
	peak    atomic.Int32
}

func newGatedAnalyzer() *gatedAnalyzer {
	return &gatedAnalyzer{gate: make(chan struct{}), started: make(chan struct{}, 64)}
}

func (g *gatedAnalyzer) analyze(ctx context.Context, path string, opts analyze.Options) (*report.Report, error) {
	now := g.running.Add(1)
	defer g.running.Add(-1)
	for {
		peak := g.peak.Load()
		if now <= peak || g.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	g.started <- struct{}{}
	select {
	case <-g.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return echoAnalyzer(ctx, path, opts)
}

func TestConcurrencyLimitIsHonoured(t *testing.T) {
	g := newGatedAnalyzer()
	s := newTestServer(t, func(c *Config) { c.Concurrency = 2 }, withAnalyzer(g.analyze))

	const total = 6
	codes := make(chan int, total)
	for i := range total {
		go func() {
			rec, err := uploadAsync(s.Handler(), fmt.Sprintf("f%d.bin", i), sampleBytes(100))
			if err != nil {
				codes <- -1
				return
			}
			codes <- rec.Code
		}()
	}
	for range 2 {
		select {
		case <-g.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the first two analyses did not start")
		}
	}
	select {
	case <-g.started:
		t.Fatal("a third analysis started although Concurrency is 2")
	case <-time.After(200 * time.Millisecond):
	}
	if got := g.running.Load(); got != 2 {
		t.Fatalf("running = %d, want 2", got)
	}

	close(g.gate)
	for range total {
		select {
		case code := <-codes:
			if code != http.StatusCreated {
				t.Errorf("status %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("queued uploads did not finish")
		}
	}
	if got := g.peak.Load(); got != 2 {
		t.Errorf("peak concurrency = %d, want 2", got)
	}
	assertNoUploads(t, s)
}

func TestBusyServerAnswers503(t *testing.T) {
	g := newGatedAnalyzer()
	s := newTestServer(t, func(c *Config) { c.Concurrency = 1 }, withAnalyzer(g.analyze))
	s.queueWait = 40 * time.Millisecond

	first := make(chan int, 1)
	go func() {
		rec, err := uploadAsync(s.Handler(), "first.bin", sampleBytes(10))
		if err != nil {
			first <- -1
			return
		}
		first <- rec.Code
	}()
	<-g.started

	rec := postUpload(t, s.Handler(), "second.bin", sampleBytes(10))
	if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != codeBusy {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 must carry Retry-After")
	}
	close(g.gate)
	if code := <-first; code != http.StatusCreated {
		t.Errorf("first upload status %d", code)
	}
	// The slot is free again.
	if rec := postUpload(t, s.Handler(), "third.bin", sampleBytes(10)); rec.Code != http.StatusCreated {
		t.Errorf("third upload status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadQueueIsBounded(t *testing.T) {
	g := newGatedAnalyzer()
	s := newTestServer(t, func(c *Config) { c.Concurrency = 1 }, withAnalyzer(g.analyze))
	s.maxQueued = 2
	s.queueWait = 10 * time.Second // long: the refusal below must not be the timeout

	codes := make(chan int, 3)
	upload := func(name string) {
		rec, err := uploadAsync(s.Handler(), name, sampleBytes(10))
		if err != nil {
			codes <- -1
			return
		}
		codes <- rec.Code
	}
	go upload("holder.bin")
	<-g.started
	go upload("queued-1.bin")
	go upload("queued-2.bin")
	waitFor(t, 5*time.Second, "two uploads to queue", func() bool { return s.waiting.Load() == 2 })

	start := time.Now()
	rec := postUpload(t, s.Handler(), "one-too-many.bin", sampleBytes(10))
	if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != codeBusy {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("a full queue must refuse at once, it took %s", elapsed)
	}
	if got := s.waiting.Load(); got != 2 {
		t.Errorf("waiting = %d after a refused request, want 2", got)
	}

	close(g.gate)
	for range 3 {
		select {
		case code := <-codes:
			if code != http.StatusCreated {
				t.Errorf("queued upload finished with %d", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("queued uploads did not finish")
		}
	}
	if got := s.waiting.Load(); got != 0 {
		t.Errorf("waiting = %d after everything finished", got)
	}
}

func TestQueuedUploadLeavesWhenClientGoes(t *testing.T) {
	g := newGatedAnalyzer()
	s := newTestServer(t, func(c *Config) { c.Concurrency = 1 }, withAnalyzer(g.analyze))

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = uploadAsync(s.Handler(), "first.bin", sampleBytes(10))
	}()
	<-g.started

	ctx, cancel := context.WithCancel(context.Background())
	body, ctype := formUpload(t, "file", "queued.bin", sampleBytes(10))
	req := newRequest(http.MethodPost, "/api/analyze", body, "Content-Type", ctype).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a queued request did not return after its client went away")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("nothing should be written for a vanished client, got %q", rec.Body.String())
	}
	close(g.gate)
	<-firstDone
}

func TestAnalysisFailures(t *testing.T) {
	boom := errors.New("open /secret/server/path/upload-123: boom")
	tests := []struct {
		name       string
		analyzer   AnalyzeFunc
		wantStatus int
		wantCode   string
	}{
		{"error", func(context.Context, string, analyze.Options) (*report.Report, error) { return nil, boom }, 500, codeAnalysisFailed},
		{"timeout", func(context.Context, string, analyze.Options) (*report.Report, error) {
			return nil, fmt.Errorf("hashing x: %w", context.DeadlineExceeded)
		}, 504, codeAnalysisTimeout},
		{"no report", func(context.Context, string, analyze.Options) (*report.Report, error) { return nil, nil }, 500, codeAnalysisFailed},
		{"panic", func(context.Context, string, analyze.Options) (*report.Report, error) { panic("parser bug") }, 500, codeAnalysisFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, func(c *Config) { c.Concurrency = 1 }, withAnalyzer(tc.analyzer))
			rec := postUpload(t, s.Handler(), "x.bin", sampleBytes(10))
			if rec.Code != tc.wantStatus || errorCode(t, rec) != tc.wantCode {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "upload-") {
				t.Errorf("the response leaks server internals: %s", rec.Body.String())
			}
			if s.store.len() != 0 {
				t.Error("a failed analysis must not be stored")
			}
			assertNoUploads(t, s)
			// The slot was released: another request is served (and fails the same way, not 503).
			if again := postUpload(t, s.Handler(), "y.bin", sampleBytes(10)); again.Code != tc.wantStatus {
				t.Errorf("second request status %d, want %d", again.Code, tc.wantStatus)
			}
		})
	}
}

func TestAnalysisAbandonedWhenClientDisconnects(t *testing.T) {
	started := make(chan struct{})
	s := newTestServer(t, withAnalyzer(func(ctx context.Context, _ string, _ analyze.Options) (*report.Report, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	sub := mustSubscribe(t, s.hub)
	defer s.hub.unsubscribe(sub)

	ctx, cancel := context.WithCancel(context.Background())
	body, ctype := formUpload(t, "file", "slow.bin", sampleBytes(10))
	req := newRequest(http.MethodPost, "/api/analyze", body, "Content-Type", ctype).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler ignored the client disconnect")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("nothing should be written for a vanished client, got %q", rec.Body.String())
	}
	var names []string
	for len(names) < 2 {
		select {
		case ev := <-sub.ch:
			names = append(names, ev.name)
		case <-time.After(2 * time.Second):
			t.Fatalf("expected started and failed events, got %v", names)
		}
	}
	if names[0] != eventStarted || names[1] != eventFailed {
		t.Errorf("events = %v", names)
	}
	assertNoUploads(t, s)
}

func TestAnalyzerReceivesOptions(t *testing.T) {
	var got analyze.Options
	var existed bool
	s := newTestServer(t, func(c *Config) { c.AnalyzeTimeout = 7 * time.Second },
		withAnalyzer(func(ctx context.Context, path string, opts analyze.Options) (*report.Report, error) {
			got = opts
			_, err := os.Stat(path)
			existed = err == nil
			return echoAnalyzer(ctx, path, opts)
		}))
	mustUpload(t, s.Handler(), "opts.bin", sampleBytes(10)) // runs the analyzer synchronously
	if got.Name != "opts.bin" || got.Timeout != 7*time.Second {
		t.Errorf("analyzer options = %+v", got)
	}
	if !existed {
		t.Error("the upload must exist on disk while it is analysed")
	}
}

func TestDeadlineReader(t *testing.T) {
	t.Run("pushes the deadline forward and clears it", func(t *testing.T) {
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		d := &deadlineReader{r: strings.NewReader("hello"), rc: http.NewResponseController(w), start: time.Now(), log: testLogger()}
		before := time.Now()
		if _, err := d.Read(make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
		if len(w.read) != 1 || w.read[0].Before(before.Add(uploadIdleTimeout-time.Second)) || w.read[0].After(time.Now().Add(uploadIdleTimeout)) {
			t.Fatalf("deadline after one read = %v", w.read)
		}
		d.finish()
		if len(w.read) != 2 || !w.read[1].IsZero() {
			t.Fatalf("finish must clear the deadline, got %v", w.read)
		}
	})
	t.Run("never exceeds the total budget", func(t *testing.T) {
		w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		start := time.Now().Add(-uploadTotalTimeout + 2*time.Second)
		d := &deadlineReader{r: strings.NewReader("hello"), rc: http.NewResponseController(w), start: start, log: testLogger()}
		_, _ = d.Read(make([]byte, 1))
		if limit := start.Add(uploadTotalTimeout); len(w.read) != 1 || w.read[0].After(limit) {
			t.Fatalf("deadline %v passes the total limit %v", w.read, limit)
		}
	})
	t.Run("degrades quietly where deadlines are unsupported", func(t *testing.T) {
		d := &deadlineReader{r: strings.NewReader("hello"), rc: http.NewResponseController(httptest.NewRecorder()), start: time.Now(), log: testLogger()}
		buf := make([]byte, 5)
		if n, err := d.Read(buf); n != 5 || err != nil {
			t.Fatalf("Read = %d, %v", n, err)
		}
		if !d.unsupported {
			t.Error("the reader should remember that deadlines are unsupported")
		}
		d.finish() // must not panic
	})
}

// deadlineRecorder is a ResponseRecorder that records read deadlines.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.read = append(d.read, t)
	return nil
}

func TestFormatBytes(t *testing.T) {
	tests := map[int64]string{
		0:                 "0 B",
		1023:              "1023 B",
		1024:              "1 KiB",
		1536:              "1.5 KiB",
		256 << 20:         "256 MiB",
		(256 << 20) + 512: "256.0 MiB",
		3 << 30:           "3 GiB",
	}
	for n, want := range tests {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
