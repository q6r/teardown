package server

import (
	"net/http"
	"slices"
	"strings"
)

// route is one entry of the route table. The table is the single source of
// truth for what the server answers: it registers the ServeMux patterns, drives
// the 405 Allow header, and is cross-checked against openapi.json by tests.
type route struct {
	method  string
	path    string // ServeMux path pattern; also the OpenAPI path template
	handler http.HandlerFunc
}

// pattern returns the ServeMux pattern ("GET /api/health").
func (r route) pattern() string { return r.method + " " + r.path }

// routes builds the route table bound to s.
func (s *Server) routes() []route {
	return []route{
		{http.MethodGet, "/api/health", s.handleHealth},
		{http.MethodPost, "/api/analyze", s.handleAnalyze},
		{http.MethodGet, "/api/analyses", s.handleList},
		{http.MethodGet, "/api/analyses/{id}", s.handleGet},
		{http.MethodDelete, "/api/analyses/{id}", s.handleDelete},
		{http.MethodGet, "/api/analyses/{id}/strings", s.handleStrings},
		{http.MethodGet, "/api/events", s.handleEvents},
		{http.MethodGet, "/api/openapi.json", s.handleOpenAPI},
		{http.MethodGet, "/", s.handleStatic},
	}
}

// isAPIPath reports whether p belongs to the JSON API namespace.
func isAPIPath(p string) bool { return p == "/api" || strings.HasPrefix(p, "/api/") }

// handleFallback answers everything the method-specific routes did not claim:
// wrong methods on API paths (405 with Allow), unknown API paths (404), and
// non-GET requests for the dashboard (405). All of them use the JSON envelope.
func (s *Server) handleFallback(w http.ResponseWriter, r *http.Request) {
	allowed := allowedMethods(s.table, r.URL.Path)
	if !isAPIPath(r.URL.Path) {
		allowed = []string{http.MethodGet, http.MethodHead}
	}
	if len(allowed) == 0 {
		writeError(w, http.StatusNotFound, codeNotFound, "no such endpoint; see /api/openapi.json for the list of routes")
		return
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, codeMethodNotAllowed, "method "+clip(r.Method, 16)+" is not allowed here; allowed: "+strings.Join(allowed, ", "))
}

// allowedMethods lists the methods the table accepts for a request path
// (HEAD is implied by GET), sorted; empty when no route matches the path.
func allowedMethods(table []route, p string) []string {
	var out []string
	for _, rt := range table {
		if !matchTemplate(rt.path, p) {
			continue
		}
		out = append(out, rt.method)
		if rt.method == http.MethodGet {
			out = append(out, http.MethodHead)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// matchTemplate reports whether path p matches a route template such as
// /api/analyses/{id}: segments must be equal except that a {name} segment
// accepts any non-empty value.
func matchTemplate(tpl, p string) bool {
	ts, ps := strings.Split(tpl, "/"), strings.Split(p, "/")
	if len(ts) != len(ps) {
		return false
	}
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if ps[i] == "" {
				return false
			}
			continue
		}
		if t != ps[i] {
			return false
		}
	}
	return true
}

// clip shortens s to at most n runes for safe inclusion in a message.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
