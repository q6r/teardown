// Package mcp implements a Model Context Protocol server over stdio so that AI
// agents can run teardown's static analysis on files.
//
// The wire format is newline-delimited JSON-RPC 2.0: one message per line on the
// input, one message per line on the output. Standard output carries protocol
// messages only; diagnostics go to Config.Stderr. The server negotiates the
// protocol versions 2024-11-05, 2025-03-26 and 2025-06-18 and offers five
// read-only tools (analyze_file, list_strings, hash_file, entropy_profile and
// diff_files).
//
// Security model: files are readable only inside the configured root
// directories. Every access goes through os.Root, so ".." escapes and symbolic
// links or junctions that leave a root are refused by the operating-system
// layer, and only regular files are opened. A path may name a place inside a
// root by any name the operating system gives it (through a symbolic link above
// it, or by an 8.3 short name on Windows): the directories above the file are
// resolved like the roots are before the two are compared. Files are analysed
// statically and never executed. Result size is capped and every failure is
// returned as a tool result with isError set rather than as a protocol error.
//
// The server does not enforce the initialize handshake order: a request that
// arrives before initialize is served using the newest protocol version.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/version"
)

// protocolLatest is the newest protocol version the server speaks; it is the
// answer when a client asks for a version the server does not know.
const protocolLatest = "2025-06-18"

func supportedProtocol(v string) bool {
	switch v {
	case "2024-11-05", "2025-03-26", "2025-06-18":
		return true
	}
	return false
}

// Config configures [Serve]. The zero value is valid.
type Config struct {
	// Roots are the directories files may be read from. Empty means the current
	// working directory. Every root must exist and be a directory.
	Roots []string
	// Stderr receives log lines; nil means os.Stderr.
	Stderr io.Writer
	// MaxOutput caps the bytes of text in one tool result (default 256 KiB,
	// minimum 1 KiB). Larger results are trimmed, then rejected.
	MaxOutput int
	// Timeout bounds one tool call (default [analyze.DefaultTimeout]).
	Timeout time.Duration
}

const (
	defaultMaxOutput = 256 << 10
	minMaxOutput     = 1 << 10
	// maxInFlight bounds queued plus running tool calls.
	maxInFlight = 64
	// maxConcurrent bounds tool calls that run at the same time.
	maxConcurrent = 4
)

func (c Config) normalize() Config {
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if c.MaxOutput <= 0 {
		c.MaxOutput = defaultMaxOutput
	}
	c.MaxOutput = max(c.MaxOutput, minMaxOutput)
	if c.Timeout <= 0 {
		c.Timeout = analyze.DefaultTimeout
	}
	return c
}

// analyzer is the analysis back end. Tests replace it to inject slow or
// oversized results.
type analyzer struct {
	reader  func(context.Context, io.ReaderAt, int64, analyze.Options) (*report.Report, error)
	quick   func(context.Context, io.ReaderAt, int64, analyze.Options) (*analyze.Summary, error)
	strings func(context.Context, io.ReaderAt, int64, analyze.Options) (report.Strings, error)
}

func realAnalyzer() analyzer {
	return analyzer{reader: analyze.Reader, quick: analyze.Quick, strings: analyze.Strings}
}

// Serve runs the MCP server until in reaches EOF or ctx is cancelled. On EOF it
// waits for running tool calls to finish and answer, then returns nil. When ctx
// is cancelled it stops the running calls and returns the cancellation cause. A
// failure to write to out ends the session with that error. It returns an error
// before serving anything when a configured root is not an existing directory.
//
// If ctx is cancelled while a goroutine is blocked reading in, that goroutine is
// released when in is closed or returns.
func Serve(ctx context.Context, in io.Reader, out io.Writer, cfg Config) error {
	return serve(ctx, in, out, cfg, realAnalyzer())
}

func serve(ctx context.Context, in io.Reader, out io.Writer, cfg Config, an analyzer) error {
	s, err := newServer(out, cfg, an)
	if err != nil {
		return err
	}
	defer s.roots.Close()
	return s.run(ctx, in)
}

// server holds the state of one MCP session.
type server struct {
	cfg   Config
	log   *slog.Logger
	roots *rootSet
	an    analyzer
	tools []*tool
	out   *lineWriter
	sem   chan struct{}
	wg    sync.WaitGroup

	mu       sync.Mutex
	protocol string
	calls    map[string]*call
}

func newServer(out io.Writer, cfg Config, an analyzer) (*server, error) {
	cfg = cfg.normalize()
	roots, err := openRoots(cfg.Roots)
	if err != nil {
		return nil, err
	}
	return &server{
		cfg:      cfg,
		log:      slog.New(slog.NewTextHandler(cfg.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		roots:    roots,
		an:       an,
		tools:    newTools(),
		out:      &lineWriter{w: out},
		sem:      make(chan struct{}, maxConcurrent),
		protocol: protocolLatest,
		calls:    map[string]*call{},
	}, nil
}

// run reads messages until EOF or cancellation.
func (s *server) run(ctx context.Context, in io.Reader) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	s.out.onFail = func(err error) { cancel(fmt.Errorf("mcp: writing to the client failed: %w", err)) }
	s.log.Info("serving MCP on stdio", "version", version.String(), "roots", s.roots.names(), "maxOutput", s.cfg.MaxOutput, "timeout", s.cfg.Timeout.String())

	done := make(chan struct{})
	defer close(done)
	events := make(chan lineEvent)
	go readLines(bufio.NewReaderSize(in, 64<<10), maxLine, events, done)

	var readErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case ev, ok := <-events:
			if !ok {
				break loop
			}
			if ev.err != nil {
				readErr = fmt.Errorf("mcp: reading input: %w", ev.err)
				break loop
			}
			s.handleEvent(ctx, ev)
		}
	}
	if ctx.Err() != nil {
		s.cancelAll()
	}
	s.wg.Wait()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return readErr
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// handleEvent processes one input line.
func (s *server) handleEvent(ctx context.Context, ev lineEvent) {
	if ev.tooLong {
		s.log.Warn("discarded an over-long input line", "limitBytes", maxLine)
		s.reply(errResponse(nil, codeInvalidRequest, fmt.Sprintf("message too large: input lines are limited to %d bytes and this one was discarded", maxLine)))
		return
	}
	line := bytes.TrimSpace(bytes.TrimPrefix(ev.line, utf8BOM))
	if len(line) == 0 {
		return
	}
	if line[0] == '[' {
		s.handleBatch(ctx, line)
		return
	}
	it := s.prepare(ctx, line)
	if it.call != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.reply(s.execute(it))
		}()
		return
	}
	s.reply(s.execute(it))
}

// handleBatch processes a JSON-RPC batch: calls run concurrently, everything
// else in order, and one array of responses is written when all are done.
func (s *server) handleBatch(ctx context.Context, line []byte) {
	elems, err := splitBatch(line)
	if err != nil {
		s.reply(errResponse(nil, codeParseError, "parse error: the line is not valid JSON"))
		return
	}
	if len(elems) == 0 {
		s.reply(errResponse(nil, codeInvalidRequest, "invalid request: a batch must not be empty"))
		return
	}
	items := make([]*prepared, len(elems))
	for i, e := range elems {
		items[i] = s.prepare(ctx, bytes.TrimSpace(e))
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		results := make([]*response, len(items))
		var calls sync.WaitGroup
		for i, it := range items {
			if it.call == nil {
				results[i] = s.execute(it)
				continue
			}
			calls.Add(1)
			go func() {
				defer calls.Done()
				results[i] = s.execute(it)
			}()
		}
		calls.Wait()
		var out []*response
		for _, r := range results {
			if r != nil {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			return
		}
		if err := s.out.send(out); err != nil {
			s.log.Error("cannot write a batch response", "error", err)
		}
	}()
}

// reply writes a response unless there is none to send.
func (s *server) reply(resp *response) {
	if resp == nil {
		return
	}
	if err := s.out.send(resp); err != nil {
		s.log.Error("cannot write a response", "error", err)
	}
}

// errClientCancelled is the cancellation cause of a call the client cancelled.
var errClientCancelled = errors.New("cancelled by the client")
