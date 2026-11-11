package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

func TestInitializeNegotiation(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		want      string
		wantTitle bool
	}{
		{"oldest", "2024-11-05", "2024-11-05", false},
		{"middle", "2025-03-26", "2025-03-26", false},
		{"newest", "2025-06-18", "2025-06-18", true},
		{"unknown older", "1999-01-01", "2025-06-18", true},
		{"unknown newer", "2030-12-31", "2025-06-18", true},
		{"garbage", "latest", "2025-06-18", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := startServer(t, Config{}, realAnalyzer())
			m := c.request(1, "initialize", map[string]any{
				"protocolVersion": tc.requested,
				"capabilities":    map[string]any{},
				"clientInfo":      map[string]any{"name": "t", "version": "1"},
			})
			if m.Error != nil {
				t.Fatalf("error: %+v", m.Error)
			}
			var res struct {
				ProtocolVersion string `json:"protocolVersion"`
				Capabilities    struct {
					Tools struct {
						ListChanged *bool `json:"listChanged"`
					} `json:"tools"`
				} `json:"capabilities"`
				ServerInfo struct {
					Name    string `json:"name"`
					Title   string `json:"title"`
					Version string `json:"version"`
				} `json:"serverInfo"`
				Instructions string `json:"instructions"`
			}
			if err := json.Unmarshal(m.Result, &res); err != nil {
				t.Fatal(err)
			}
			if res.ProtocolVersion != tc.want {
				t.Errorf("protocolVersion = %q, want %q", res.ProtocolVersion, tc.want)
			}
			if res.Capabilities.Tools.ListChanged == nil || *res.Capabilities.Tools.ListChanged {
				t.Errorf("capabilities.tools.listChanged must be present and false: %s", m.Result)
			}
			if res.ServerInfo.Name != "teardown" || res.ServerInfo.Version == "" {
				t.Errorf("serverInfo = %+v", res.ServerInfo)
			}
			if (res.ServerInfo.Title != "") != tc.wantTitle {
				t.Errorf("serverInfo.title = %q, want present=%v", res.ServerInfo.Title, tc.wantTitle)
			}
			if !strings.Contains(res.Instructions, "never executes") {
				t.Errorf("instructions must say files are never executed: %q", res.Instructions)
			}
		})
	}
}

func TestInitializeInvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params any
	}{
		{"no params", nil},
		{"params is an array", []any{"2025-06-18"}},
		{"params is a string", "2025-06-18"},
		{"missing protocolVersion", map[string]any{"capabilities": map[string]any{}}},
		{"empty protocolVersion", map[string]any{"protocolVersion": ""}},
		{"protocolVersion not a string", map[string]any{"protocolVersion": 20250618}},
	}
	c := startServer(t, Config{}, realAnalyzer())
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := c.request(100+i, "initialize", tc.params)
			if m.Error == nil || m.Error.Code != codeInvalidParams {
				t.Fatalf("want -32602, got %+v / %s", m.Error, m.Result)
			}
		})
	}
}

func TestNotificationsProduceNoOutputAndPingAnswers(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	for _, line := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`,
		`{"jsonrpc":"2.0","method":"notifications/something-new","params":{"a":1}}`,
		`{"jsonrpc":"2.0","method":"ping"}`,
		`{"jsonrpc":"2.0","method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"hash_file","arguments":{"path":"x"}}}`,
		`{"jsonrpc":"2.0","method":"nonexistent/method"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
	} {
		c.send(line)
	}
	c.expectSilence()
	m := c.request(7, "ping", nil)
	if m.Error != nil || strings.TrimSpace(string(m.Result)) != "{}" {
		t.Fatalf("ping result = %s / %+v, want {}", m.Result, m.Error)
	}
}

func TestMethodNotFoundAndIDEcho(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	for _, id := range []string{`7`, `"abc"`, `"7"`, `1.5`, `9007199254740993`, `-3`, `"é\n"`} {
		c.send(`{"jsonrpc":"2.0","id":` + id + `,"method":"does/not/exist"}`)
		m := c.recv()
		if m.Error == nil || m.Error.Code != codeMethodNotFound {
			t.Fatalf("id %s: want -32601, got %+v", id, m.Error)
		}
		if got, want := compactJSON(t, m.ID), compactJSON(t, json.RawMessage(id)); got != want {
			t.Errorf("id echoed as %s, want %s", got, want)
		}
		if m.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q", m.JSONRPC)
		}
	}
	// A notification method used as a request is not a known request method.
	m := c.request(8, "notifications/initialized", nil)
	if m.Error == nil || m.Error.Code != codeMethodNotFound {
		t.Fatalf("got %+v", m.Error)
	}
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return b.String()
}

func TestInvalidMessages(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCode int
		wantID   string
	}{
		{"truncated json", `{"jsonrpc":`, codeParseError, "null"},
		{"garbage", `hello`, codeParseError, "null"},
		{"bare number", `42`, codeInvalidRequest, "null"},
		{"bare string", `"hi"`, codeInvalidRequest, "null"},
		{"null", `null`, codeInvalidRequest, "null"},
		{"wrong version", `{"jsonrpc":"1.0","id":3,"method":"ping"}`, codeInvalidRequest, "3"},
		{"missing version", `{"id":3,"method":"ping"}`, codeInvalidRequest, "3"},
		{"missing method", `{"jsonrpc":"2.0","id":4}`, codeInvalidRequest, "4"},
		{"method not a string", `{"jsonrpc":"2.0","id":5,"method":7}`, codeInvalidRequest, "5"},
		{"empty method", `{"jsonrpc":"2.0","id":6,"method":""}`, codeInvalidRequest, "6"},
		{"id is an object", `{"jsonrpc":"2.0","id":{},"method":"ping"}`, codeInvalidRequest, "null"},
		{"id is null", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, codeInvalidRequest, "null"},
		{"id is a boolean", `{"jsonrpc":"2.0","id":true,"method":"ping"}`, codeInvalidRequest, "null"},
		{"empty batch", `[]`, codeInvalidRequest, "null"},
		{"broken batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"},`, codeParseError, "null"},
	}
	c := startServer(t, Config{}, realAnalyzer())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.send(tc.line)
			m := c.recv()
			if m.Error == nil || m.Error.Code != tc.wantCode {
				t.Fatalf("error = %+v, want code %d", m.Error, tc.wantCode)
			}
			if string(m.ID) != tc.wantID {
				t.Errorf("id = %s, want %s", m.ID, tc.wantID)
			}
		})
	}
	// The session survives every kind of garbage.
	c.expectSilence()
}

func TestClientResponsesAreIgnored(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	c.send(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	c.send(`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"no"}}`)
	c.expectSilence()
}

func TestBatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "x.bin", sampleBytes(2048, 1))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())

	c.send(`[` +
		`{"jsonrpc":"2.0","id":1,"method":"ping"},` +
		`{"jsonrpc":"2.0","method":"notifications/initialized"},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"},` +
		`{"jsonrpc":"2.0","id":3,"method":"nope"},` +
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hash_file","arguments":{"path":"x.bin"}}},` +
		`{"x":1}]`)
	var got []rpcMsg
	if err := json.Unmarshal([]byte(c.recvLine()), &got); err != nil {
		t.Fatalf("batch response is not an array: %v", err)
	}
	wantIDs := []string{"1", "2", "3", "4", "null"}
	if len(got) != len(wantIDs) {
		t.Fatalf("got %d responses, want %d: %+v", len(got), len(wantIDs), got)
	}
	for i, m := range got {
		if string(m.ID) != wantIDs[i] {
			t.Errorf("response %d has id %s, want %s", i, m.ID, wantIDs[i])
		}
	}
	if got[2].Error == nil || got[2].Error.Code != codeMethodNotFound || got[4].Error == nil || got[4].Error.Code != codeInvalidRequest {
		t.Errorf("error entries wrong: %+v / %+v", got[2].Error, got[4].Error)
	}
	if res := decodeToolResult(t, got[3]); res.IsError || !strings.Contains(res.text(), `"sha256"`) {
		t.Errorf("batched tool call failed: %+v", res)
	}

	// A batch of notifications yields no response at all.
	c.send(`[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","method":"ping"}]`)
	c.expectSilence()
}

func TestBlankLinesCRLFAndBOM(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	c.send("")
	c.send("   \t ")
	c.send("\xef\xbb\xbf" + `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := c.recv(); string(m.ID) != "1" || m.Error != nil {
		t.Fatalf("BOM line: %+v", m)
	}
	if _, err := io.WriteString(c.in, `{"jsonrpc":"2.0","id":2,"method":"ping"}`+"\r\n"); err != nil {
		t.Fatal(err)
	}
	if m := c.recv(); string(m.ID) != "2" || m.Error != nil {
		t.Fatalf("CRLF line: %+v", m)
	}
}

func TestLastLineWithoutNewlineIsProcessed(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	if _, err := io.WriteString(c.in, `{"jsonrpc":"2.0","id":5,"method":"ping"}`); err != nil {
		t.Fatal(err)
	}
	c.in.Close()
	rest, err := c.finish()
	if err != nil {
		t.Fatalf("Serve returned %v, want nil on EOF", err)
	}
	if len(rest) != 1 || !strings.Contains(rest[0], `"id":5`) {
		t.Fatalf("output after EOF = %q", rest)
	}
}

func TestStdoutCarriesOnlyProtocolMessages(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(1024, 3))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	c.initialize("2025-06-18")
	c.callTool(2, "analyze_file", map[string]any{"path": "a.bin"})
	c.callTool(3, "analyze_file", map[string]any{"path": "missing.bin"})
	c.send(`not json`)
	c.send(`{"jsonrpc":"2.0","id":4,"method":"nope"}`)
	c.sendJSON(map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
	for range 3 { // the parse error, the method error and the tools/list answer
		line := c.recvLine()
		assertProtocolLine(t, line)
	}
	rest, err := c.finish()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range rest {
		assertProtocolLine(t, l)
	}
	logs := c.stderr.String()
	if !strings.Contains(logs, "serving MCP on stdio") {
		t.Errorf("startup line missing from the log: %q", logs)
	}
	if strings.Contains(logs, `"jsonrpc"`) {
		t.Errorf("protocol messages leaked into the log: %q", logs)
	}
}

func assertProtocolLine(t *testing.T, line string) {
	t.Helper()
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("output line contains a raw line break: %q", line)
	}
	var v any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Errorf("output line is not JSON: %q", line)
		return
	}
	check := func(m map[string]any) {
		if m["jsonrpc"] != "2.0" {
			t.Errorf("message without jsonrpc 2.0: %q", line)
		}
		_, hasResult := m["result"]
		_, hasError := m["error"]
		if hasResult == hasError {
			t.Errorf("a response must carry exactly one of result and error: %q", line)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		check(x)
	case []any:
		for _, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				t.Errorf("batch element is not an object: %q", line)
				continue
			}
			check(m)
		}
	default:
		t.Errorf("unexpected top-level value in %q", line)
	}
}

func TestOverlongLineIsRejectedAndSessionContinues(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	c.send(strings.Repeat("a", maxLine+10))
	m := c.recv()
	if m.Error == nil || m.Error.Code != codeInvalidRequest || !strings.Contains(m.Error.Message, "too large") {
		t.Fatalf("over-long line: %+v", m.Error)
	}
	if string(m.ID) != "null" {
		t.Errorf("id = %s, want null", m.ID)
	}
	c.expectSilence()
	// A line of exactly the limit is still accepted for parsing (and is rejected as
	// invalid JSON rather than as too large).
	pad := strings.Repeat(" ", maxLine-len(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	c.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + pad)
	if m := c.recv(); string(m.ID) != "1" || m.Error != nil {
		t.Fatalf("a line of exactly the limit must be processed: %+v", m)
	}
}

func TestEOFWaitsForRunningCalls(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	an, started, release, _ := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}}, an)
	c.sendJSON(hashCall(1, "a.bin"))
	<-started
	c.in.Close() // EOF while the call is still running
	time.AfterFunc(100*time.Millisecond, release)
	rest, err := c.finish()
	if err != nil {
		t.Fatalf("Serve = %v, want nil", err)
	}
	if len(rest) != 1 || !strings.Contains(rest[0], `"id":1`) || !strings.Contains(rest[0], `"isError":false`) {
		t.Fatalf("the running call must be answered before Serve returns: %q", rest)
	}
}

func TestContextCancellationStopsServe(t *testing.T) {
	inR, inW := io.Pipe()
	t.Cleanup(func() { inW.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, inR, io.Discard, Config{Roots: []string{t.TempDir()}, Stderr: io.Discard}, realAnalyzer())
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve = %v, want context.Canceled", err)
		}
	case <-time.After(waitFor):
		t.Fatal("Serve did not return after cancellation")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestWriteFailureEndsTheSession(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
	err := serve(context.Background(), in, failingWriter{}, Config{Roots: []string{t.TempDir()}, Stderr: io.Discard}, realAnalyzer())
	if err == nil || !strings.Contains(err.Error(), "writing to the client failed") {
		t.Fatalf("Serve = %v", err)
	}
}

func TestStartupRejectsBadRoots(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "f.txt", []byte("x"))
	tests := []struct {
		name  string
		roots []string
		want  string
	}{
		{"missing", []string{dir + "/does-not-exist"}, "does-not-exist"},
		{"a file", []string{file}, "not a directory"},
		{"second root bad", []string{dir, dir + "/nope"}, "nope"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := serve(context.Background(), strings.NewReader(""), io.Discard, Config{Roots: tc.roots, Stderr: io.Discard}, realAnalyzer())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Serve = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// blockingHook returns an analyzer whose quick() blocks until released or its
// context ends, and channels reporting that it started.
func blockingHook(t *testing.T) (an analyzer, started chan struct{}, release func(), observed chan error) {
	t.Helper()
	started = make(chan struct{}, 16)
	observed = make(chan error, 16)
	gate := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	an = realAnalyzer()
	an.quick = func(ctx context.Context, _ io.ReaderAt, size int64, opts analyze.Options) (*analyze.Summary, error) {
		select {
		case started <- struct{}{}:
		default: // nobody is waiting for more start signals
		}
		select {
		case <-gate:
			return &analyze.Summary{File: report.File{Name: opts.Name, Size: size}, Type: report.Type{ID: "data", Tags: []string{}}}, nil
		case <-ctx.Done():
			select {
			case observed <- context.Cause(ctx):
			default:
			}
			return nil, ctx.Err()
		}
	}
	return an, started, release, observed
}

func hashCall(id any, path string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": "hash_file", "arguments": map[string]any{"path": path}}}
}

func TestPingIsAnsweredWhileAnAnalysisRuns(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	an, started, release, _ := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}}, an)

	c.sendJSON(hashCall(10, "a.bin"))
	<-started
	c.sendJSON(map[string]any{"jsonrpc": "2.0", "id": 11, "method": "ping"})
	if m := c.recv(); string(m.ID) != "11" {
		t.Fatalf("expected the ping answer first, got id %s", m.ID)
	}
	release()
	m := c.recv()
	if string(m.ID) != "10" {
		t.Fatalf("expected the tool answer, got id %s", m.ID)
	}
	if res := decodeToolResult(t, m); res.IsError {
		t.Fatalf("tool failed: %s", res.text())
	}
}

func TestCancellationSuppressesTheResponse(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	an, started, _, observed := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}}, an)

	c.sendJSON(hashCall(21, "a.bin"))
	<-started
	c.sendJSON(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 21, "reason": "user pressed stop"}})
	select {
	case cause := <-observed:
		if !errors.Is(cause, errClientCancelled) {
			t.Fatalf("the tool saw cancellation cause %v", cause)
		}
	case <-time.After(waitFor):
		t.Fatal("the running tool was not cancelled")
	}
	c.expectSilence() // the next message is the ping answer, not a response to call 21
	rest, err := c.finish()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range rest {
		if strings.Contains(l, `"id":21`) {
			t.Fatalf("a cancelled request must not be answered: %s", l)
		}
	}
}

func TestToolCallTimeout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	an, _, _, _ := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}, Timeout: 80 * time.Millisecond}, an)
	res := c.callTool(1, "hash_file", map[string]any{"path": "a.bin"})
	msg := mustErrorText(t, res)
	if !strings.Contains(msg, "did not finish within") {
		t.Fatalf("message = %q", msg)
	}
	// The server keeps working after a timeout.
	c.expectSilence()
}

func TestDuplicateRequestIDIsRejected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	an, started, release, _ := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}}, an)
	c.sendJSON(hashCall(5, "a.bin"))
	<-started
	c.sendJSON(hashCall(5, "a.bin"))
	m := c.recv()
	if m.Error == nil || m.Error.Code != codeInvalidRequest || !strings.Contains(m.Error.Message, "already in progress") {
		t.Fatalf("duplicate id: %+v", m.Error)
	}
	release()
	if m := c.recv(); string(m.ID) != "5" || m.Error != nil {
		t.Fatalf("the original call must still be answered: %+v", m)
	}
}

func TestConcurrentCallsAreBounded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	var running, peak atomic.Int32
	an := realAnalyzer()
	an.quick = func(_ context.Context, _ io.ReaderAt, size int64, opts analyze.Options) (*analyze.Summary, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		running.Add(-1)
		return &analyze.Summary{File: report.File{Name: opts.Name, Size: size}}, nil
	}
	c := startServer(t, Config{Roots: []string{root}}, an)
	const calls = 12
	for i := range calls {
		c.sendJSON(hashCall(i+1, "a.bin"))
	}
	for range calls {
		if m := c.recv(); m.Error != nil {
			t.Fatalf("error: %+v", m.Error)
		}
	}
	if got := peak.Load(); got > maxConcurrent || got < 2 {
		t.Fatalf("peak concurrency = %d, want between 2 and %d", got, maxConcurrent)
	}
}

func TestInFlightLimitReturnsABusyResult(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(64, 1))
	an, started, release, _ := blockingHook(t)
	c := startServer(t, Config{Roots: []string{root}}, an)
	for i := range maxInFlight {
		c.sendJSON(hashCall(i+1, "a.bin"))
	}
	<-started
	c.sendJSON(hashCall(9999, "a.bin"))
	m := c.recv()
	if string(m.ID) != "9999" {
		t.Fatalf("expected the busy answer first, got id %s", m.ID)
	}
	if msg := mustErrorText(t, decodeToolResult(t, m)); !strings.Contains(msg, "busy") {
		t.Fatalf("message = %q", msg)
	}
	release()
	for range maxInFlight {
		c.recv()
	}
}
