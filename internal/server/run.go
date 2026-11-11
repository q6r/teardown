package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 64 << 10
	shutdownGrace     = 10 * time.Second
)

// Run listens on cfg.Addr and serves until ctx is cancelled. It prints the
// address to cfg.Stderr (with a loud warning when the address is not loopback),
// shuts down gracefully and removes the private upload directory.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}
	return Serve(ctx, ln, cfg)
}

// Serve is like [Run] on an existing listener, which it takes ownership of.
// The listener's address, not cfg.Addr, decides whether the server counts as
// loopback-only.
func Serve(ctx context.Context, ln net.Listener, cfg Config) (err error) {
	cfg.Addr = ln.Addr().String()
	s, err := New(cfg)
	if err != nil {
		_ = ln.Close()
		return err
	}
	defer func() {
		if cerr := s.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	srv := newHTTPServer(s.Handler(), s.log)
	srv.RegisterOnShutdown(s.stopStreams)
	spare := newSpareConns()
	srv.ConnState = spare.track
	announce(s.cfg.Stderr, cfg.Addr, s.loopback)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	select {
	case err := <-served:
		return serveResult(err)
	case <-ctx.Done():
	}

	spare.closeAll()
	grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(grace); err != nil {
		closeErr := srv.Close()
		serveErr := serveResult(<-served)
		return fmt.Errorf("shutdown did not finish within %s, connections were closed: %w", shutdownGrace, errors.Join(err, closeErr, serveErr))
	}
	return serveResult(<-served)
}

// serveResult turns what http.Server.Serve returned into a result for the
// caller: http.ErrServerClosed is how a server that was shut down ends, not a
// failure.
func serveResult(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve: %w", err)
}

// newHTTPServer returns the http.Server used by Serve. There is deliberately no
// ReadTimeout or WriteTimeout: uploads and event streams are long-lived, and
// the handlers manage their own per-request deadlines.
func newHTTPServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// spareConns remembers the connections that were accepted but have not sent a
// request yet. Browsers open such spare connections ahead of time, and
// net/http's Shutdown counts each of them as busy until it is more than five
// seconds old, which would eat the grace period that belongs to requests really
// in flight. At shutdown they are closed at once: nothing was asked of them.
type spareConns struct {
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

func newSpareConns() *spareConns {
	return &spareConns{conns: make(map[net.Conn]struct{})}
}

// track is the http.Server.ConnState hook.
func (sc *spareConns) track(c net.Conn, state http.ConnState) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	switch {
	case state != http.StateNew:
		delete(sc.conns, c) // it sent a request, or it is gone
	case sc.closing:
		_ = c.Close() // accepted while shutting down: it will not be served
	default:
		sc.conns[c] = struct{}{}
	}
}

// closeAll closes every connection that has not sent a request yet, and every
// one that is accepted from now on until the server is gone.
func (sc *spareConns) closeAll() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.closing = true
	for c := range sc.conns {
		_ = c.Close()
	}
	clear(sc.conns)
}

// announce prints the start-up banner, plus the exposure warning for
// non-loopback addresses.
func announce(w io.Writer, addr string, loopback bool) {
	_, _ = fmt.Fprintf(w, "teardown dashboard: http://%s\n", addr)
	if loopback {
		_, _ = fmt.Fprintln(w, "listening on the loopback interface only; press Ctrl+C to stop")
		return
	}
	_, _ = fmt.Fprintf(w, `
!!! WARNING !!! teardown is listening on %s, which other machines can reach.
The API is unauthenticated: anyone who can connect may upload files for analysis,
read every stored report and use this machine's disk, CPU and memory.
The Host-header allow-list is disabled for this address.
Bind 127.0.0.1 unless you mean it, or put an authenticating reverse proxy in front.

`, addr)
}
