package server

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestMatchTemplate(t *testing.T) {
	tests := []struct {
		tpl, path string
		want      bool
	}{
		{"/api/health", "/api/health", true},
		{"/api/health", "/api/health/", false},
		{"/api/health", "/api/healthz", false},
		{"/api/analyses/{id}", "/api/analyses/an_1", true},
		{"/api/analyses/{id}", "/api/analyses/", false},
		{"/api/analyses/{id}", "/api/analyses", false},
		{"/api/analyses/{id}", "/api/analyses/an_1/strings", false},
		{"/api/analyses/{id}/strings", "/api/analyses/an_1/strings", true},
		{"/api/analyses/{id}/strings", "/api/analyses/an_1/other", false},
		{"/", "/", true},
		{"/", "/api/health", false},
		{"/", "", false},
	}
	for _, tc := range tests {
		if got := matchTemplate(tc.tpl, tc.path); got != tc.want {
			t.Errorf("matchTemplate(%q, %q) = %v, want %v", tc.tpl, tc.path, got, tc.want)
		}
	}
}

func TestAllowedMethods(t *testing.T) {
	s := newTestServer(t)
	tests := []struct {
		path string
		want []string
	}{
		{"/api/health", []string{"GET", "HEAD"}},
		{"/api/analyze", []string{"POST"}},
		{"/api/analyses", []string{"GET", "HEAD"}},
		{"/api/analyses/an_000000000000", []string{"DELETE", "GET", "HEAD"}},
		{"/api/analyses/an_000000000000/strings", []string{"GET", "HEAD"}},
		{"/api/events", []string{"GET", "HEAD"}},
		{"/api/nothing", nil},
		{"/api/analyses/a/b/c", nil},
	}
	for _, tc := range tests {
		if got := allowedMethods(s.table, tc.path); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("allowedMethods(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRouteTableHasUniquePatterns(t *testing.T) {
	s := newTestServer(t)
	seen := map[string]bool{}
	for _, rt := range s.table {
		if seen[rt.pattern()] {
			t.Errorf("duplicate route %q", rt.pattern())
		}
		seen[rt.pattern()] = true
		if rt.handler == nil {
			t.Errorf("route %q has no handler", rt.pattern())
		}
	}
}

func TestUnroutedRequestsGetJSONErrors(t *testing.T) {
	s := newTestServer(t)
	tests := []struct {
		method, path string
		wantStatus   int
		wantCode     string
		wantAllow    string
	}{
		{"GET", "/api/nothing", 404, codeNotFound, ""},
		{"GET", "/api", 404, codeNotFound, ""},
		{"POST", "/api/nothing", 404, codeNotFound, ""},
		{"GET", "/api/analyses/an_000000000000/strings/extra", 404, codeNotFound, ""},
		{"GET", "/api/analyze", 405, codeMethodNotAllowed, "POST"},
		{"PUT", "/api/analyses", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"POST", "/api/analyses", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"PATCH", "/api/analyses/an_000000000000", 405, codeMethodNotAllowed, "DELETE, GET, HEAD"},
		{"POST", "/api/health", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"DELETE", "/api/events", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"OPTIONS", "/api/health", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"POST", "/", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"DELETE", "/index.html", 405, codeMethodNotAllowed, "GET, HEAD"},
		{"GET", "/definitely-not-a-file.txt", 404, codeNotFound, ""},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := do(t, s.Handler(), tc.method, tc.path, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := errorCode(t, rec); got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Errorf("Allow = %q, want %q", got, tc.wantAllow)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q", ct)
			}
		})
	}
}

func TestMethodMessageIsClipped(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s.Handler(), strings.Repeat("X", 500), "/api/health", nil)
	if rec.Code != http.StatusMethodNotAllowed || rec.Body.Len() > 400 {
		t.Fatalf("status %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestClip(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly5", 8, "exactly5"},
		{"abcdefghij", 4, "abcd…"},
		{"héllo wörld", 5, "héllo…"},
		{"", 3, ""},
	}
	for _, tc := range tests {
		if got := clip(tc.in, tc.n); got != tc.want {
			t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
