// Package server implements teardown's HTTP API and hosts the embedded
// dashboard.
//
// The API is plain JSON over net/http. Uploads are streamed into a private
// temporary directory under random names, analysed with package analyze and
// deleted immediately afterwards; the resulting reports live in a bounded
// in-memory ring. The analysed files are never executed.
//
// The server is unauthenticated by design, so it binds to the loopback
// interface by default, answers only requests addressed to a loopback host
// name (DNS-rebinding defence), refuses cross-origin state-changing requests
// (CSRF defence) and never sends CORS headers. See docs/api/http.md for the
// full security model and the route reference.
package server

import (
	"context"
	_ "embed" // for the OpenAPI document
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/web"
)

// Defaults and hard limits.
const (
	// DefaultAddr is where "teardown serve" listens unless told otherwise.
	DefaultAddr = "127.0.0.1:7777"
	// DefaultMaxUpload is the largest accepted upload in bytes (256 MiB).
	DefaultMaxUpload int64 = 256 << 20
	// DefaultKeep is how many analyses the in-memory ring retains.
	DefaultKeep = 50

	// maxUploadCeiling (1 PiB) keeps MaxUpload plus the multipart allowance far
	// from integer overflow.
	maxUploadCeiling int64 = 1 << 50
	maxKeep                = 10_000
	maxConcurrency         = 256
	// multipartOverhead is the allowance on top of MaxUpload for multipart framing.
	multipartOverhead = 1 << 20
	// queueWait is how long an upload waits for a free analysis slot.
	queueWait = 30 * time.Second
	// maxQueued bounds how many uploads may wait for a slot at once; more get 503
	// immediately instead of piling up connections.
	maxQueued = 64
)

//go:embed openapi.json
var openAPIDocument []byte

// AnalyzeFunc analyses the file at path. It matches [analyze.File], which is
// the default; tests and embedders may substitute their own.
type AnalyzeFunc func(ctx context.Context, path string, opts analyze.Options) (*report.Report, error)

// Config configures a [Server]. The zero value is valid: every zero field is
// replaced by its default.
type Config struct {
	// Addr is the listen address for [Run] (default [DefaultAddr]). A loopback
	// address enables the Host-header allow-list; anything else prints a warning.
	Addr string
	// MaxUpload is the largest accepted upload in bytes (default [DefaultMaxUpload]).
	MaxUpload int64
	// Keep is the size of the in-memory ring of analyses (default [DefaultKeep], max 10000).
	Keep int
	// TempDir is the parent of the server's private upload directory (default os.TempDir()).
	TempDir string
	// Concurrency bounds simultaneous analyses (default min(4, NumCPU), max 256).
	// Further uploads wait for a slot for up to 30 seconds, then get 503.
	Concurrency int
	// AnalyzeTimeout bounds one analysis (default [analyze.DefaultTimeout]).
	AnalyzeTimeout time.Duration
	// Stderr receives the start-up banner and warnings (default os.Stderr).
	Stderr io.Writer
	// Logger receives structured logs (default: text handler on Stderr, info level).
	Logger *slog.Logger
	// Analyze replaces the analyzer (default [analyze.File]).
	Analyze AnalyzeFunc
}

// withDefaults validates c and fills in defaults.
func (c Config) withDefaults() (Config, error) {
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	switch {
	case c.MaxUpload < 0 || c.MaxUpload > maxUploadCeiling:
		return c, fmt.Errorf("max upload must be between 1 byte and %s", formatBytes(maxUploadCeiling))
	case c.MaxUpload == 0:
		c.MaxUpload = DefaultMaxUpload
	}
	switch {
	case c.Keep < 0 || c.Keep > maxKeep:
		return c, fmt.Errorf("keep must be between 1 and %d", maxKeep)
	case c.Keep == 0:
		c.Keep = DefaultKeep
	}
	switch {
	case c.Concurrency < 0 || c.Concurrency > maxConcurrency:
		return c, fmt.Errorf("concurrency must be between 1 and %d", maxConcurrency)
	case c.Concurrency == 0:
		c.Concurrency = min(4, runtime.NumCPU())
	}
	switch {
	case c.AnalyzeTimeout < 0:
		return c, errors.New("analyze timeout must not be negative")
	case c.AnalyzeTimeout == 0:
		c.AnalyzeTimeout = analyze.DefaultTimeout
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(c.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if c.Analyze == nil {
		c.Analyze = analyze.File
	}
	return c, nil
}

// Server is the HTTP API. Create it with [New]; it is safe for concurrent use.
type Server struct {
	cfg      Config
	log      *slog.Logger
	tempDir  string
	loopback bool

	store   *store
	hub     *hub
	sem     chan struct{}
	waiting atomic.Int32 // uploads currently queued for a slot

	table   []route
	mux     *http.ServeMux
	handler http.Handler
	web     fs.FS
	now     func() time.Time

	// Limits and timings that tests shorten.
	queueWait time.Duration
	maxQueued int
	keepAlive time.Duration

	done      chan struct{} // closed when streaming connections must end
	doneOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

// New validates cfg, creates the server's private upload directory and builds
// the handler chain. Call [Server.Close] to remove the directory.
func New(cfg Config) (*Server, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(cfg.TempDir, "teardown-")
	if err != nil {
		return nil, fmt.Errorf("create private upload directory: %w", err)
	}
	s := &Server{
		cfg:       cfg,
		log:       cfg.Logger,
		tempDir:   dir,
		loopback:  isLoopbackAddr(cfg.Addr),
		store:     newStore(cfg.Keep),
		hub:       newHub(maxSubscribers),
		sem:       make(chan struct{}, cfg.Concurrency),
		web:       web.FS(),
		now:       time.Now,
		queueWait: queueWait,
		maxQueued: maxQueued,
		keepAlive: keepAliveEvery,
		done:      make(chan struct{}),
	}
	s.table = s.routes()
	s.mux = http.NewServeMux()
	for _, rt := range s.table {
		s.mux.HandleFunc(rt.pattern(), rt.handler)
	}
	s.mux.HandleFunc("/", s.handleFallback)
	s.handler = s.outer(securityHeaders(s.hostGuard(s.originGuard(s.mux))))
	return s, nil
}

// Handler returns the complete handler, middleware included.
func (s *Server) Handler() http.Handler { return s.handler }

// Close ends streaming connections and removes the private upload directory.
// It is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.stopStreams()
		if err := os.RemoveAll(s.tempDir); err != nil {
			s.closeErr = fmt.Errorf("remove upload directory: %w", err)
		}
	})
	return s.closeErr
}

// stopStreams ends every SSE connection and refuses new ones.
func (s *Server) stopStreams() {
	s.doneOnce.Do(func() {
		close(s.done)
		s.hub.close()
	})
}
