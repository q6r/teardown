package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/cli"
	"github.com/q6r/teardown/internal/mcp"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// This file checks that the surfaces that show the code behind a finding tell one
// story: analyze (the blocks of its findings), xrefs, disasm and the MCP tools
// find_calls and disassemble agree, for the sample dropper, on addresses, file
// offsets, sections, import names and the notes of every instruction.

// runCLI runs the command line with in-memory streams.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	env := cli.Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(string) string { return "" },
		IsTTY:  func(io.Writer) bool { return false },
		Now:    func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) },
	}
	code = cli.Run(context.Background(), args, env)
	return out.String(), errb.String(), code
}

// mcpResult is the part of a tools/call result the tests read.
type mcpResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// mcpSession runs one MCP session over the files in dir and returns the result
// of each tools/call, in order.
func mcpSession(t *testing.T, dir string, calls ...map[string]any) []mcpResult {
	t.Helper()
	var in bytes.Buffer
	send := func(v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		in.Write(raw)
		in.WriteByte('\n')
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "0"},
	}})
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	for i, c := range calls {
		send(map[string]any{"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": c})
	}
	var out bytes.Buffer
	if err := mcp.Serve(context.Background(), &in, &out, mcp.Config{Roots: []string{dir}, Stderr: io.Discard}); err != nil {
		t.Fatalf("the MCP session failed: %v", err)
	}
	results := make([]mcpResult, len(calls))
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("not a JSON-RPC message: %v: %s", err, line)
		}
		if msg.ID >= 100 && msg.ID < 100+len(calls) {
			if err := json.Unmarshal(msg.Result, &results[msg.ID-100]); err != nil {
				t.Fatal(err)
			}
		}
	}
	return results
}

// findingBlocks returns the disasm blocks of the findings of an analyze --json report.
func analyzeBlocks(t *testing.T, path string) map[string][]report.CodeBlock {
	t.Helper()
	out, errText, code := runCLI(t, "analyze", path, "--json")
	if code != 0 {
		t.Fatalf("analyze exit %d: %s", code, errText)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("analyze --json is not a report: %v", err)
	}
	blocks := map[string][]report.CodeBlock{}
	for _, f := range rep.Findings {
		if err := f.ValidateCode(); err != nil {
			t.Errorf("finding %s: %v", f.ID, err)
		}
		if len(f.Code) > report.MaxCodeBlocks {
			t.Errorf("finding %s has %d code blocks, the cap is %d", f.ID, len(f.Code), report.MaxCodeBlocks)
		}
		for _, b := range f.Code {
			if b.Kind == report.CodeKindDisasm {
				blocks[f.ID] = append(blocks[f.ID], b)
			}
		}
	}
	return blocks
}

func callLine(t *testing.T, b report.CodeBlock) report.CodeLine {
	t.Helper()
	var hit []report.CodeLine
	for _, l := range b.Lines {
		if l.Highlight {
			hit = append(hit, l)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("block %q has %d highlighted lines", b.Title, len(hit))
	}
	return hit[0]
}

func TestTheSurfacesTellOneStory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.bin")
	if err := os.WriteFile(path, testfixtures.SamplePE(), 0o644); err != nil {
		t.Fatal(err)
	}

	// The imports that have call sites, from the list command.
	listOut, errText, code := runCLI(t, "xrefs", path, "--list", "--json")
	if code != 0 {
		t.Fatalf("xrefs --list exit %d: %s", code, errText)
	}
	var called []struct {
		API       string `json:"api"`
		CallSites int    `json:"callSites"`
	}
	if err := json.Unmarshal([]byte(listOut), &called); err != nil || len(called) < 10 {
		t.Fatalf("%d imports listed (%v):\n%s", len(called), err, listOut)
	}

	// xrefs and find_calls, for every called import.
	xrefsBlocks := map[string][]report.CodeBlock{}
	var calls []map[string]any
	for _, c := range called {
		out, errText, code := runCLI(t, "xrefs", path, c.API, "--json")
		if code != 0 {
			t.Fatalf("xrefs %s: exit %d: %s", c.API, code, errText)
		}
		var blocks []report.CodeBlock
		if err := json.Unmarshal([]byte(out), &blocks); err != nil {
			t.Fatalf("xrefs %s --json is not a list of code blocks: %v", c.API, err)
		}
		if len(blocks) != c.CallSites {
			t.Errorf("--list says %d call sites for %s, xrefs shows %d", c.CallSites, c.API, len(blocks))
		}
		xrefsBlocks[c.API] = blocks
		calls = append(calls, map[string]any{"name": "find_calls", "arguments": map[string]any{"path": "dropper.bin", "api": c.API}})
	}
	results := mcpSession(t, dir, calls...)

	for i, c := range called {
		if results[i].IsError || len(results[i].Content) != 1 {
			t.Fatalf("find_calls %s failed: %+v", c.API, results[i])
		}
		var doc struct {
			Total int `json:"total"`
			Sites []struct {
				API     string           `json:"api"`
				Kind    string           `json:"kind"`
				Address report.Addr      `json:"address"`
				Offset  int64            `json:"offset"`
				Section string           `json:"section"`
				Code    report.CodeBlock `json:"code"`
			} `json:"sites"`
		}
		if err := json.Unmarshal([]byte(results[i].Content[0].Text), &doc); err != nil {
			t.Fatalf("find_calls %s: %v", c.API, err)
		}
		want := xrefsBlocks[c.API]
		if doc.Total != len(want) || len(doc.Sites) != len(want) {
			t.Fatalf("%s: find_calls has %d sites (total %d), xrefs has %d", c.API, len(doc.Sites), doc.Total, len(want))
		}
		for j, s := range doc.Sites {
			if !reflect.DeepEqual(s.Code, want[j]) {
				t.Errorf("%s site %d: find_calls and xrefs show different code:\n%+v\n%+v", c.API, j, s.Code, want[j])
			}
			hit := callLine(t, s.Code)
			if s.Address != hit.Address || s.Offset != hit.Offset || s.Section != s.Code.Section || s.API != c.API || hit.Note == "" || !strings.HasPrefix(hit.Note, c.API) {
				t.Errorf("%s site %d: %+v does not describe its highlighted line %+v", c.API, j, s, hit)
			}
		}
	}

	// analyze: every block of every finding is the xrefs block of the same call.
	seen := 0
	for id, blocks := range analyzeBlocks(t, path) {
		for _, b := range blocks {
			hit := callLine(t, b)
			api := hit.Note
			if i := strings.Index(api, " ("); i >= 0 {
				api = api[:i] // "X (through the thunk at 0x...)"
			}
			var match *report.CodeBlock
			for k := range xrefsBlocks[api] {
				if callLine(t, xrefsBlocks[api][k]).Address == hit.Address {
					match = &xrefsBlocks[api][k]
				}
			}
			if match == nil {
				t.Errorf("finding %s: no xrefs call site of %s at %v", id, api, hit.Address)
				continue
			}
			if !reflect.DeepEqual(b, *match) {
				t.Errorf("finding %s: the block of %s at %v differs from the one xrefs shows:\n%+v\n%+v", id, api, hit.Address, b, *match)
			}
			seen++
		}
	}
	if seen < 12 {
		t.Errorf("only %d finding blocks were compared", seen)
	}

	// disasm: the window of every block, instruction for instruction, note for note.
	disasmed := 0
	for api, blocks := range xrefsBlocks {
		for _, b := range blocks {
			out, errText, code := runCLI(t, "disasm", path, "--at", b.Lines[0].Address.String(), "-n", itoa(len(b.Lines)), "--json")
			if code != 0 {
				t.Fatalf("disasm at %v: exit %d: %s", b.Lines[0].Address, code, errText)
			}
			var d report.CodeBlock
			if err := json.Unmarshal([]byte(out), &d); err != nil {
				t.Fatal(err)
			}
			if err := d.Validate(); err != nil {
				t.Errorf("disasm block is not valid: %v", err)
			}
			if d.Section != b.Section || d.Arch != b.Arch || d.Address != b.Address || d.Offset != b.Offset || len(d.Lines) != len(b.Lines) {
				t.Fatalf("%s: disasm block header %+v, xrefs %+v", api, d, b)
			}
			for i := range b.Lines {
				got, want := d.Lines[i], b.Lines[i]
				want.Highlight = false
				if got != want {
					t.Errorf("%s line %d: disasm says %+v, xrefs %+v", api, i, got, want)
				}
			}
			disasmed++
		}
	}
	if disasmed < 12 {
		t.Errorf("only %d windows were compared", disasmed)
	}
}

// TestEveryOutputOfTheCodeSurfacesIsBounded checks the caps: how much one call
// of each surface can print, however many call sites there are.
func TestEveryOutputOfTheCodeSurfacesIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropper.bin")
	if err := os.WriteFile(path, testfixtures.SamplePE(), 0o644); err != nil {
		t.Fatal(err)
	}
	bounds := []struct {
		args  []string
		bytes int
	}{
		{[]string{"xrefs", path, "VirtualAllocEx", "--before", "40", "--after", "20"}, 24 << 10},
		{[]string{"xrefs", path, "--list"}, 8 << 10},
		{[]string{"disasm", path, "-n", "256"}, 64 << 10},
		{[]string{"hexdump", path, "-n", "4096"}, 32 << 10},
		{[]string{"analyze", path, "--code-all"}, 320 << 10},
		{[]string{"analyze", path, "--json"}, 512 << 10},
		{[]string{"analyze", path, "--md"}, 320 << 10},
	}
	for _, b := range bounds {
		out, _, code := runCLI(t, b.args...)
		if code != 0 || len(out) > b.bytes {
			t.Errorf("%v: exit %d, %d bytes (bound %d)", b.args, code, len(out), b.bytes)
		}
	}
	for id, blocks := range analyzeBlocks(t, path) {
		for _, b := range blocks {
			if len(b.Lines) > report.MaxCodeLines {
				t.Errorf("finding %s: a block of %d lines, the cap is %d", id, len(b.Lines), report.MaxCodeLines)
			}
		}
	}
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}
