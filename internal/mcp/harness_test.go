package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

const waitFor = 10 * time.Second

// syncBuffer is a goroutine-safe bytes.Buffer used to capture the log.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// rpcMsg is the subset of a JSON-RPC response the tests inspect.
type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// toolRes is a decoded tools/call result.
type toolRes struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

func (r toolRes) text() string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

// testClient drives a server over in-memory pipes.
type testClient struct {
	t      *testing.T
	in     *io.PipeWriter
	lines  chan string
	done   chan error
	stderr *syncBuffer

	once sync.Once
	err  error
}

// startServer runs serve on in-memory pipes. Closing the input (EOF) ends the
// session; the cleanup does that and waits for the server to stop, so create
// temp directories before calling it.
func startServer(t *testing.T, cfg Config, an analyzer) *testClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &testClient{t: t, in: inW, lines: make(chan string, 4096), done: make(chan error, 1), stderr: &syncBuffer{}}
	cfg.Stderr = c.stderr
	if len(cfg.Roots) == 0 {
		cfg.Roots = []string{t.TempDir()}
	}
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 64<<10), 32<<20)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()
	go func() {
		err := serve(context.Background(), inR, outW, cfg, an)
		outW.Close()
		inR.Close()
		c.done <- err
	}()
	t.Cleanup(func() { c.finish() })
	return c
}

// finish closes the input, waits for the server to stop and returns any output
// that was not consumed yet together with the error Serve returned.
func (c *testClient) finish() ([]string, error) {
	c.once.Do(func() {
		c.in.Close()
		select {
		case c.err = <-c.done:
		case <-time.After(waitFor):
			c.t.Error("the server did not stop after EOF on its input")
		}
	})
	var rest []string
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				return rest, c.err
			}
			rest = append(rest, l)
		case <-time.After(waitFor):
			c.t.Error("the server's output did not close")
			return rest, c.err
		}
	}
}

// send writes one raw line.
func (c *testClient) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatalf("writing to the server: %v", err)
	}
}

// sendJSON marshals v and sends it as one line.
func (c *testClient) sendJSON(v any) {
	c.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	c.send(string(b))
}

// recvLine returns the next output line.
func (c *testClient) recvLine() string {
	c.t.Helper()
	select {
	case l, ok := <-c.lines:
		if !ok {
			c.t.Fatal("the server closed its output unexpectedly")
		}
		return l
	case <-time.After(waitFor):
		c.t.Fatal("timed out waiting for a server message")
		return ""
	}
}

// recv returns the next output line decoded as a response.
func (c *testClient) recv() rpcMsg {
	c.t.Helper()
	line := c.recvLine()
	var m rpcMsg
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		c.t.Fatalf("output line is not a JSON object: %v: %q", err, line)
	}
	return m
}

// expectSilence asserts that nothing else is pending after a ping round trip,
// which proves earlier notifications produced no output.
func (c *testClient) expectSilence() {
	c.t.Helper()
	c.sendJSON(map[string]any{"jsonrpc": "2.0", "id": "silence-check", "method": "ping"})
	m := c.recv()
	if string(m.ID) != `"silence-check"` {
		c.t.Fatalf("unexpected output before the ping answer: %+v", m)
	}
}

// request sends a request and returns its response.
func (c *testClient) request(id any, method string, params any) rpcMsg {
	c.t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	c.sendJSON(msg)
	m := c.recv()
	want, _ := json.Marshal(id)
	if string(m.ID) != string(want) {
		c.t.Fatalf("response id = %s, want %s (%+v)", m.ID, want, m)
	}
	return m
}

// initialize performs the handshake with the given protocol version.
func (c *testClient) initialize(version string) rpcMsg {
	c.t.Helper()
	m := c.request(1, "initialize", map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "0"},
	})
	c.sendJSON(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return m
}

// callTool calls a tool and decodes its result.
func (c *testClient) callTool(id any, name string, args any) toolRes {
	c.t.Helper()
	m := c.request(id, "tools/call", map[string]any{"name": name, "arguments": args})
	return decodeToolResult(c.t, m)
}

func decodeToolResult(t *testing.T, m rpcMsg) toolRes {
	t.Helper()
	if m.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", m.Error)
	}
	var res toolRes
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("bad tool result %s: %v", m.Result, err)
	}
	return res
}

// mustJSON asserts a successful tool result and returns its JSON text decoded.
func mustJSON(t *testing.T, res toolRes) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool returned an error: %s", res.text())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.text()), &out); err != nil {
		t.Fatalf("tool text is not a JSON object: %v\n%s", err, res.text())
	}
	return out
}

// mustErrorText asserts an isError result and returns its message.
func mustErrorText(t *testing.T, res toolRes) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected an isError result, got: %.300s", res.text())
	}
	return res.text()
}

// writeFile creates dir/name (and parents) with the given content.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sampleBytes is deterministic, non-trivial content.
func sampleBytes(n int, seed byte) []byte {
	b := make([]byte, n)
	x := uint32(seed) + 1
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// bigReport builds a large synthetic report for output-cap tests.
func bigReport(nStrings int) *report.Report {
	r := report.New("big.bin", 1<<20, "test")
	r.Type = report.Type{ID: report.TypePE, Family: report.FamilyExecutable, Label: "PE32+ executable (x86-64)", MIME: "application/vnd.microsoft.portable-executable", Confidence: report.ConfidenceHigh, Tags: []string{"exe", "64-bit"}}
	r.Hashes = report.Hashes{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), Imphash: strings.Repeat("d", 32)}
	windows := make([]float64, 512)
	for i := range windows {
		windows[i] = 6 + float64(i%100)/100
	}
	r.Entropy = report.Entropy{Overall: 6.5, WindowSize: 2048, Windows: windows}
	for i := range 12 {
		r.Sections = append(r.Sections, report.Section{Name: fmt.Sprintf(".sec%d", i), VirtualSize: 4096, RawSize: 4096, Offset: uint64(i) * 4096, Entropy: 5.5, Flags: []string{"R", "X"}})
	}
	for i := range 20 {
		imp := report.Import{Library: fmt.Sprintf("lib%02d.dll", i), Count: 300}
		for j := range 300 {
			imp.Functions = append(imp.Functions, fmt.Sprintf("Function%03d_%02d", j, i))
		}
		r.Imports = append(r.Imports, imp)
	}
	for i := range 400 {
		r.Exports = append(r.Exports, fmt.Sprintf("Export%03d", i))
	}
	cats := report.StringCategories()
	r.Strings.Total = nStrings
	r.Strings.MinLength = 5
	r.Strings.ByCategory = map[string]int{}
	for i := range nStrings {
		cat := cats[i%len(cats)]
		it := report.StringItem{Value: fmt.Sprintf("string-%05d-%s", i, strings.Repeat("x", 30)), Offset: int64(i) * 40, Encoding: "ascii", Category: cat}
		if cat == report.CatSecret {
			it.Value, it.Redacted, it.Kind = "AKIA…(20 chars)", true, "aws-access-key-id"
		}
		r.Strings.Items = append(r.Strings.Items, it)
		r.Strings.ByCategory[cat]++
	}
	entries := make([]any, 500)
	for i := range entries {
		entries[i] = map[string]any{"name": fmt.Sprintf("dir/file%03d.txt", i), "size": i, "compressedSize": i / 2}
	}
	r.Details = map[string]any{"archive": map[string]any{"kind": "zip", "entries": entries, "entryCount": 500}}
	for i := range 5 {
		r.Findings = append(r.Findings, report.Finding{
			ID: fmt.Sprintf("test.finding-%d", i), Title: "A test finding", Severity: report.SeverityMedium, Category: report.CategoryHardening, Confidence: report.ConfidenceMedium,
			Evidence: []string{"evidence one", "evidence two", "evidence three", "evidence four", "evidence five", "evidence six"}, Limitations: []string{"only a test"},
		})
	}
	r.Risk = report.Risk{Score: 42, Label: report.RiskMedium, Basis: []string{"five medium findings"}}
	r.Normalize()
	return r
}

// stubAnalyzer returns a fast analyzer whose behaviour tests override per field.
func stubAnalyzer(rep *report.Report) analyzer {
	an := realAnalyzer()
	an.reader = func(_ context.Context, _ io.ReaderAt, size int64, opts analyze.Options) (*report.Report, error) {
		cp := *rep
		cp.File = report.File{Name: opts.Name, Size: size}
		return &cp, nil
	}
	return an
}
