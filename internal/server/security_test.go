package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func assertSecurityHeaders(t *testing.T, label string, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	exact := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	}
	for name, want := range exact {
		if got := h.Get(name); got != want {
			t.Errorf("%s: %s = %q, want %q", label, name, got, want)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "img-src 'self' data:", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("%s: CSP %q lacks %q", label, csp, directive)
		}
	}
	if !strings.HasPrefix(csp, "default-src 'self'; img-src 'self' data:") {
		t.Errorf("%s: CSP must start with the documented policy, got %q", label, csp)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			t.Errorf("%s: unexpected CORS header %s", label, name)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	id := mustUpload(t, s.Handler(), "a.bin", sampleBytes(10)).ID
	tests := []struct {
		name, method, target string
		host                 string
		headers              []string
		wantStatus           int
		wantCache            string
	}{
		{"dashboard", "GET", "/", "", nil, 200, "no-cache"},
		{"health", "GET", "/api/health", "", nil, 200, "no-store"},
		{"openapi", "GET", "/api/openapi.json", "", nil, 200, "no-store"},
		{"list", "GET", "/api/analyses", "", nil, 200, "no-store"},
		{"report", "GET", "/api/analyses/" + id, "", nil, 200, "no-store"},
		{"api 404", "GET", "/api/nothing", "", nil, 404, "no-store"},
		{"unknown id", "GET", "/api/analyses/an_000000000000", "", nil, 404, "no-store"},
		{"dashboard 404", "GET", "/missing.js", "", nil, 404, ""},
		{"bad content type", "POST", "/api/analyze", "", []string{"Content-Type", "text/plain"}, 415, "no-store"},
		{"405", "PUT", "/api/health", "", nil, 405, "no-store"},
		{"bad host", "GET", "/api/health", "evil.example", nil, 403, "no-store"},
		{"bad origin", "POST", "/api/analyze", "", []string{"Origin", "http://evil.example"}, 403, "no-store"},
		{"options", "OPTIONS", "/api/analyze", "", nil, 405, "no-store"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(tc.method, tc.target, nil, tc.headers...)
			if tc.host != "" {
				req.Host = tc.host
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %.200s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			assertSecurityHeaders(t, tc.name, rec)
			if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
				t.Errorf("Cache-Control = %q, want %q", got, tc.wantCache)
			}
		})
	}
}

func TestHostAllowList(t *testing.T) {
	s := newTestServer(t)
	tests := []struct {
		host string
		want int
	}{
		{"127.0.0.1:7777", 200},
		{"127.0.0.1", 200},
		{"localhost", 200},
		{"localhost:1234", 200},
		{"LOCALHOST:80", 200},
		{"localhost.", 200},
		{"[::1]:7777", 200},
		{"[::1]", 200},
		{"127.0.0.2:9", 200},
		{"evil.example", 403},
		{"evil.example:7777", 403},
		{"127.0.0.1.evil.example", 403},
		{"localhost.evil.com", 403},
		{"sub.localhost", 403},
		{"", 403},
		{"0.0.0.0:7777", 403},
		{"10.0.0.5:7777", 403},
		{"192.168.1.10", 403},
		{"[::2]:1", 403},
		{"localhost@evil.example", 403},
		{"127.0.0.1:7777@evil.example", 403},
		{"127.0.0.1:port", 403},
		{"127.0.0.1:", 403},
		{"2130706433", 403}, // decimal spelling of 127.0.0.1: browsers normalise it, so a raw one is suspicious
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			req := newRequest(http.MethodGet, "/api/health", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("Host %q -> %d, want %d", tc.host, rec.Code, tc.want)
			}
			if tc.want == http.StatusForbidden {
				if code := errorCode(t, rec); code != codeForbiddenHost {
					t.Errorf("code = %q", code)
				}
			}
		})
	}
}

func TestHostGuardAppliesToTheDashboardToo(t *testing.T) {
	s := newTestServer(t)
	req := newRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHostGuardIsOffForNonLoopbackBinds(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7777", ":7777", "192.168.1.5:7777", "[::]:7777", "example.internal:7777"} {
		t.Run(addr, func(t *testing.T) {
			s := newTestServer(t, func(c *Config) { c.Addr = addr })
			if s.loopback {
				t.Fatalf("%q must not count as loopback", addr)
			}
			req := newRequest(http.MethodGet, "/api/health", nil)
			req.Host = "files.corp.example:7777"
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: the operator exposed the server on purpose", rec.Code)
			}
		})
	}
	for _, addr := range []string{"127.0.0.1:7777", "localhost:7777", "[::1]:7777", "127.0.0.2:1"} {
		if !isLoopbackAddr(addr) {
			t.Errorf("%q must count as loopback", addr)
		}
	}
}

func TestOriginGuard(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	h := s.Handler()
	known := mustUpload(t, h, "keep.bin", sampleBytes(10)).ID

	body := func() (string, []byte) {
		b, ct := formUpload(t, "file", "x.bin", sampleBytes(10))
		return ct, b.Bytes()
	}
	post := func(headers ...string) int {
		ct, b := body()
		req := newRequest(http.MethodPost, "/api/analyze", strings.NewReader(string(b)), append([]string{"Content-Type", ct}, headers...)...)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden {
			if code := errorCode(t, rec); code != codeForbiddenOrigin {
				t.Errorf("code = %q", code)
			}
		}
		return rec.Code
	}

	tests := []struct {
		name    string
		headers []string
		want    int
	}{
		{"no origin (curl, scripts)", nil, 201},
		{"same origin", []string{"Origin", "http://127.0.0.1:7777"}, 201},
		{"same origin, other case", []string{"Origin", "http://127.0.0.1:7777", "Sec-Fetch-Site", "same-origin"}, 201},
		{"direct navigation", []string{"Sec-Fetch-Site", "none"}, 201},
		{"foreign origin", []string{"Origin", "http://evil.example"}, 403},
		{"foreign origin on the same host name but another port", []string{"Origin", "http://127.0.0.1:3000"}, 403},
		{"localhost is not the same origin as 127.0.0.1", []string{"Origin", "http://localhost:7777"}, 403},
		{"opaque origin", []string{"Origin", "null"}, 403},
		{"garbage origin", []string{"Origin", "::::"}, 403},
		{"file origin", []string{"Origin", "file://"}, 403},
		{"scheme-less origin", []string{"Origin", "127.0.0.1:7777"}, 403},
		{"cross-site fetch metadata", []string{"Sec-Fetch-Site", "cross-site"}, 403},
		{"same-site fetch metadata", []string{"Sec-Fetch-Site", "same-site"}, 403},
		{"fetch metadata cannot excuse a foreign origin", []string{"Origin", "http://evil.example", "Sec-Fetch-Site", "same-origin"}, 403},
	}
	for _, tc := range tests {
		t.Run("POST "+tc.name, func(t *testing.T) {
			if got := post(tc.headers...); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("DELETE from a foreign origin keeps the report", func(t *testing.T) {
		rec := do(t, h, http.MethodDelete, "/api/analyses/"+known, nil, "Origin", "http://evil.example")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d", rec.Code)
		}
		if _, ok := s.store.get(known); !ok {
			t.Fatal("a cross-origin DELETE removed the analysis")
		}
	})
	t.Run("DELETE from the dashboard's own origin works", func(t *testing.T) {
		rec := do(t, h, http.MethodDelete, "/api/analyses/"+known, nil, "Origin", "http://127.0.0.1:7777")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("reads are not subject to the origin check but never carry CORS headers", func(t *testing.T) {
		rec := do(t, h, http.MethodGet, "/api/analyses", nil, "Origin", "http://evil.example")
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		assertSecurityHeaders(t, "cross-origin read", rec)
	})
}

func TestNoCORSPreflight(t *testing.T) {
	s := newTestServer(t)
	for _, target := range []string{"/api/analyze", "/api/analyses", "/api/health", "/"} {
		rec := do(t, s.Handler(), http.MethodOptions, target, nil,
			"Origin", "http://evil.example",
			"Access-Control-Request-Method", "POST",
			"Access-Control-Request-Headers", "content-type")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("OPTIONS %s = %d, want 405", target, rec.Code)
		}
		for name := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(name), "access-control-") {
				t.Errorf("OPTIONS %s answered with %s", target, name)
			}
		}
	}
}

func TestDashboardServing(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s.Handler(), http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<title>teardown</title>") {
		t.Errorf("the embedded index.html is not served:\n%.300s", rec.Body.String())
	}
	if head := do(t, s.Handler(), http.MethodHead, "/", nil); head.Code != http.StatusOK {
		t.Errorf("HEAD / = %d", head.Code)
	}
	redirect := do(t, s.Handler(), http.MethodGet, "/index.html", nil)
	if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "./" {
		t.Errorf("/index.html = %d -> %q", redirect.Code, redirect.Header().Get("Location"))
	}
}

func TestStaticFilesFromAnyFS(t *testing.T) {
	s := newTestServer(t)
	s.web = fstest.MapFS{
		"index.html":          {Data: []byte("<!doctype html><title>t</title>")},
		"app.js":              {Data: []byte("console.log(1)")},
		"app.css":             {Data: []byte("a{}")},
		"icon.svg":            {Data: []byte("<svg/>")},
		"data.json":           {Data: []byte("{}")},
		"font.woff2":          {Data: []byte("wOF2")},
		"sub/page.html":       {Data: []byte("<p>sub</p>")},
		"sub/deeper/note.txt": {Data: []byte("note")},
		"noext":               {Data: []byte("raw")},
	}
	tests := []struct {
		path     string
		wantCode int
		wantType string
	}{
		{"/", 200, "text/html; charset=utf-8"},
		{"/app.js", 200, "text/javascript; charset=utf-8"},
		{"/app.css", 200, "text/css; charset=utf-8"},
		{"/icon.svg", 200, "image/svg+xml"},
		{"/data.json", 200, "application/json; charset=utf-8"},
		{"/font.woff2", 200, "font/woff2"},
		{"/sub/page.html", 200, "text/html; charset=utf-8"},
		{"/sub/deeper/note.txt", 200, "text/plain; charset=utf-8"},
		{"/sub", 404, ""},
		{"/sub/", 404, ""},
		{"/sub/deeper", 404, ""},
		{"/missing.html", 404, ""},
		{"/APP.JS", 404, ""},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := do(t, s.Handler(), http.MethodGet, tc.path, nil)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantCode == 200 {
				if ct := rec.Header().Get("Content-Type"); ct != tc.wantType {
					t.Errorf("Content-Type = %q, want %q", ct, tc.wantType)
				}
				if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
					t.Errorf("Cache-Control = %q, want no-cache", cc)
				}
			} else {
				errorCode(t, rec) // a JSON envelope, never a directory listing
			}
		})
	}
	// A file system without index.html does not fall back to a directory listing.
	s.web = fstest.MapFS{"only.txt": {Data: []byte("x")}}
	if rec := do(t, s.Handler(), http.MethodGet, "/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("/ without index.html = %d, want 404", rec.Code)
	}
}

func TestStaticPathTraversalIsContained(t *testing.T) {
	s := newTestServer(t)
	s.web = fstest.MapFS{"index.html": {Data: []byte("home")}, "inside.txt": {Data: []byte("inside")}}
	for _, target := range []string{
		"/../../secret",
		"/%2e%2e/secret",
		"/..%2f..%2fsecret",
		"//etc/passwd",
		"/./../inside.txt/../../x",
		"/sub/../../..",
	} {
		rec := do(t, s.Handler(), http.MethodGet, target, nil)
		switch {
		case rec.Code == http.StatusNotFound:
		case rec.Code/100 == 3: // the mux redirects to the cleaned path
			if loc := rec.Header().Get("Location"); strings.Contains(loc, "..") || strings.HasPrefix(loc, "//") {
				t.Errorf("GET %s redirects to the unclean %q", target, loc)
			}
		default:
			t.Errorf("GET %s = %d, want a redirect or 404", target, rec.Code)
		}
	}
}
