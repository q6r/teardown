package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"time"
)

// contentSecurityPolicy is sent with every response. The dashboard is made of
// same-origin files only: no inline script, no inline style, no remote fetches.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// statusWriter records whether and how a response was started. It exposes the
// wrapped writer through Unwrap so http.ResponseController keeps working.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// baseWriter strips every wrapper so net/http features that rely on the
// concrete writer type (http.MaxBytesReader's connection-close hint) work.
func baseWriter(w http.ResponseWriter) http.ResponseWriter {
	for {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = u.Unwrap()
	}
}

// outer is the outermost middleware: it recovers from handler panics and logs
// every request at debug level.
func (s *Server) outer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("handler panic",
					"method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				if !sw.wrote {
					writeError(sw, http.StatusInternalServerError, codeInternal, "the server hit an unexpected error; see its log")
				}
			}
		}()
		next.ServeHTTP(sw, r)
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds())
	})
}

// securityHeaders sets the headers every response carries, errors included.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if isAPIPath(r.URL.Path) {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// hostGuard rejects requests whose Host header is not a loopback name. This is
// the defence against DNS rebinding: a page on attacker.example that resolves
// to 127.0.0.1 still sends "Host: attacker.example". It only applies when the
// server is bound to a loopback address; an operator who exposes the server on
// purpose has been warned and the allowed host names cannot be known.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	if !s.loopback {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			s.log.Warn("rejected request with a non-loopback Host header", "host", clip(r.Host, 80), "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, codeForbiddenHost,
				"this server only answers requests addressed to 127.0.0.1, localhost or [::1] (DNS-rebinding protection)")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard is the CSRF defence for state-changing requests: browsers always
// attach Origin to cross-origin POST and DELETE requests, and it must name this
// server. Clients that send no Origin (curl, scripts) are unaffected.
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) && !sameOriginRequest(r) {
			s.log.Warn("rejected cross-origin state-changing request", "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, codeForbiddenOrigin,
				"cross-origin requests are not allowed; call this API from the dashboard it serves or from a non-browser client")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

// sameOriginRequest reports whether a request's Origin and Sec-Fetch-Site
// headers, when present, show it came from this server's own origin.
func sameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false // includes the opaque origin "null"
	}
	return strings.EqualFold(u.Host, r.Host)
}

// isLoopbackHost reports whether a Host header value names the local machine:
// localhost or any loopback IP literal, with or without a port.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, port, err := net.SplitHostPort(hostport); err == nil {
		if !isPort(port) {
			return false
		}
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// isPort reports whether s is a decimal TCP port: net.SplitHostPort does not
// check, and a Host such as "127.0.0.1:7777@evil.example" must not pass.
func isPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isLoopbackAddr reports whether a listen address ("host:port") is confined to
// the local machine. A missing or unspecified host listens on every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
