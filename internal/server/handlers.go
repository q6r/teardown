package server

import (
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/version"
)

// Strings endpoint bounds.
const (
	defaultStringsLimit = 100
	maxStringsLimit     = 1000
	maxQueryBytes       = 256
)

type healthBody struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthBody{Status: "ok", Version: version.String()})
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.summaries())
}

// lookup resolves the {id} path value, answering 404 itself when it does not
// name a stored analysis. The identifier is never echoed back.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) (*record, bool) {
	id := r.PathValue("id")
	if idPattern.MatchString(id) {
		if rec, ok := s.store.get(id); ok {
			return rec, true
		}
	}
	writeError(w, http.StatusNotFound, codeNotFound,
		"no analysis with that id; it may have been deleted or evicted from the in-memory ring (see GET /api/analyses)")
	return nil, false
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	if rec, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, rec.report)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.lookup(w, r)
	if !ok {
		return
	}
	s.store.remove(rec.id)
	w.WriteHeader(http.StatusNoContent)
}

type stringsPage struct {
	Total  int                 `json:"total"`
	Offset int                 `json:"offset"`
	Limit  int                 `json:"limit"`
	Items  []report.StringItem `json:"items"`
}

func (s *Server) handleStrings(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.lookup(w, r)
	if !ok {
		return
	}
	q, err := parseStringsQuery(r.URL.Query())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, q.page(rec.report.Strings.Items))
}

// stringsQuery is the validated query of GET /api/analyses/{id}/strings.
type stringsQuery struct {
	categories map[string]bool
	needle     string // lower-cased
	limit      int
	offset     int
}

func parseStringsQuery(v url.Values) (stringsQuery, *apiError) {
	q := stringsQuery{limit: defaultStringsLimit}
	valid := report.StringCategories()
	for _, raw := range v["category"] {
		for _, c := range strings.Split(raw, ",") {
			c = strings.ToLower(strings.TrimSpace(c))
			if c == "" {
				continue
			}
			if !slices.Contains(valid, c) {
				return q, invalid("unknown category " + strconv.Quote(clip(c, 40)) + "; valid categories: " + strings.Join(valid, ", "))
			}
			if q.categories == nil {
				q.categories = map[string]bool{}
			}
			q.categories[c] = true
		}
	}
	if needle := v.Get("q"); needle != "" {
		if len(needle) > maxQueryBytes {
			return q, invalid("q must be at most " + strconv.Itoa(maxQueryBytes) + " bytes")
		}
		q.needle = strings.ToLower(needle)
	}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxStringsLimit {
			return q, invalid("limit must be an integer between 1 and " + strconv.Itoa(maxStringsLimit))
		}
		q.limit = n
	}
	if raw := v.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return q, invalid("offset must be an integer >= 0")
		}
		q.offset = n
	}
	return q, nil
}

func invalid(message string) *apiError {
	return &apiError{status: http.StatusBadRequest, code: codeInvalidParameter, message: message}
}

// page filters items (keeping their order) and returns the requested window
// together with the total number of matches.
func (q stringsQuery) page(items []report.StringItem) stringsPage {
	out := stringsPage{Offset: q.offset, Limit: q.limit, Items: []report.StringItem{}}
	for _, it := range items {
		if q.categories != nil && !q.categories[it.Category] {
			continue
		}
		if q.needle != "" && !strings.Contains(strings.ToLower(it.Value), q.needle) {
			continue
		}
		out.Total++
		if out.Total > q.offset && len(out.Items) < q.limit {
			out.Items = append(out.Items, it)
		}
	}
	return out
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	extendWriteDeadline(w, writeTimeout)
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(openAPIDocument)))
	_, _ = w.Write(openAPIDocument)
}

// staticTypes pins the Content-Type of dashboard assets. The platform MIME
// registry (notably on Windows) can map .js to text/plain, which a browser
// refuses to execute under X-Content-Type-Options: nosniff.
var staticTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".webp":        "image/webp",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
}

// handleStatic serves the embedded dashboard: index.html at "/", other files by
// path, never a directory listing.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		s.handleFallback(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	info, err := fs.Stat(s.web, name)
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, codeNotFound, "no such file")
		return
	}
	if ct, ok := staticTypes[strings.ToLower(path.Ext(name))]; ok {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.FileServerFS(s.web).ServeHTTP(w, r)
}
