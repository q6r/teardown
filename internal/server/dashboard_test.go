package server

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestDashboardIsServedWithEveryAssetItNeeds loads index.html the way a browser
// does and fetches every stylesheet, script and icon it references: each must be
// answered with the right content type (a wrong one makes a browser refuse the
// script under nosniff) and the strict security headers.
func TestDashboardIsServedWithEveryAssetItNeeds(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, newRequest("GET", target, nil))
		return rec
	}

	index := get("/")
	if index.Code != http.StatusOK || !strings.HasPrefix(index.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET / = %d %q", index.Code, index.Header().Get("Content-Type"))
	}
	if !strings.Contains(index.Body.String(), "<title>teardown</title>") {
		t.Error("GET / does not serve the dashboard page")
	}

	wantType := map[string]string{".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
	refs := regexp.MustCompile(`(?:href|src)="([^"#/][^":]*)"`).FindAllStringSubmatch(index.Body.String(), -1)
	if len(refs) < 6 {
		t.Fatalf("index.html references only %d local files", len(refs))
	}
	for _, m := range refs {
		rec := get("/" + m[1])
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Errorf("GET /%s = %d with %d bytes", m[1], rec.Code, rec.Body.Len())
			continue
		}
		ext := m[1][strings.LastIndex(m[1], "."):]
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, wantType[ext]) {
			t.Errorf("GET /%s has Content-Type %q, want %s", m[1], got, wantType[ext])
		}
		if rec.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("GET /%s Cache-Control = %q, want no-cache", m[1], rec.Header().Get("Cache-Control"))
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-") {
			t.Errorf("GET /%s Content-Security-Policy = %q", m[1], csp)
		}
	}
}
