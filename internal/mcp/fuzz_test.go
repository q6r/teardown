package mcp

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
)

// fuzzRoot creates a root directory with one small file and an outside secret.
func fuzzRoot(f *testing.F) (root string, secret []byte) {
	f.Helper()
	base := f.TempDir()
	root = filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		f.Fatal(err)
	}
	for name, data := range map[string][]byte{
		filepath.Join(root, "a.bin"):         sampleBytes(512, 1),
		filepath.Join(root, "sub", "b.bin"):  sampleBytes(256, 2),
		filepath.Join(base, "outside.bin"):   []byte("FUZZ-OUTSIDE-SECRET"),
		filepath.Join(base, "root-evil.bin"): []byte("FUZZ-OUTSIDE-SECRET"),
	} {
		if err := os.WriteFile(name, data, 0o644); err != nil {
			f.Fatal(err)
		}
	}
	return root, []byte("FUZZ-OUTSIDE-SECRET")
}

// FuzzHandleLine feeds arbitrary input lines to the message handler: it must
// never panic, and every line it writes must be a valid JSON-RPC response.
func FuzzHandleLine(f *testing.F) {
	root, secret := fuzzRoot(f)
	for _, seed := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"f","version":"1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hash_file","arguments":{"path":"a.bin"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"analyze_file","arguments":{"path":"sub/b.bin","detail":"full","minString":3}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_strings","arguments":{"path":"a.bin","category":"url,ip","limit":5}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"entropy_profile","arguments":{"path":"../outside.bin"}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"diff_files","arguments":{"a":"a.bin","b":"sub/b.bin"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"x"},{"x":1}]`,
		`[]`, `{}`, `null`, `42`, `"text"`, `{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, `{"jsonrpc":"2.0","id":"x","method":1}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"hash_file","arguments":{"path":"` + strings.Repeat("a", 5000) + `"}}}`,
		strings.Repeat("[", 200),
		"\xef\xbb\xbf" + `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
	} {
		f.Add([]byte(seed))
	}
	var buf bytes.Buffer
	s, err := newServer(&buf, Config{Roots: []string{root}, Stderr: io.Discard, Timeout: 5 * time.Second}, stubAnalyzer(bigReport(5)))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(s.roots.Close)
	f.Fuzz(func(t *testing.T, data []byte) {
		// One server serves every iteration; the output buffer and the negotiated
		// protocol are reset so an input behaves the same wherever it appears.
		buf.Reset()
		s.out = &lineWriter{w: &buf}
		s.setProtocol(protocolLatest)
		s.handleEvent(context.Background(), lineEvent{line: data})
		s.wg.Wait()

		out := buf.Bytes()
		if bytes.Contains(out, secret) {
			t.Fatalf("the outside file leaked: %q", out)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(out, []byte("\n")), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var v any
			if err := json.Unmarshal(line, &v); err != nil {
				t.Fatalf("output line is not JSON: %q (%v)", line, err)
			}
			switch x := v.(type) {
			case map[string]any:
				checkResponseShape(t, x, line)
			case []any:
				for _, e := range x {
					m, ok := e.(map[string]any)
					if !ok {
						t.Fatalf("batch element is not an object: %q", line)
					}
					checkResponseShape(t, m, line)
				}
			default:
				t.Fatalf("unexpected output value: %q", line)
			}
		}
	})
}

func checkResponseShape(t *testing.T, m map[string]any, line []byte) {
	t.Helper()
	if m["jsonrpc"] != "2.0" {
		t.Fatalf("response without jsonrpc 2.0: %q", line)
	}
	if _, ok := m["id"]; !ok {
		t.Fatalf("response without id: %q", line)
	}
	_, hasResult := m["result"]
	_, hasError := m["error"]
	if hasResult == hasError {
		t.Fatalf("response must carry exactly one of result and error: %q", line)
	}
}

// FuzzParseTree checks the ordered JSON tree: whatever it accepts it must be
// able to print as valid, semantically identical JSON.
func FuzzParseTree(f *testing.F) {
	for _, seed := range []string{
		`{}`, `[]`, `null`, `{"a":[1,2,{"b":"c"}],"d":1e5}`, `{"s":"\u0000\ud800 \"x\""}`, `[[[[]]]]`,
		`{"a":1,"a":2}`, `123456789012345678901234567890`, `"unterminated`, `{"k":}`, strings.Repeat("[", 300),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := parseTree(data)
		if err != nil {
			return
		}
		for name, out := range map[string][]byte{"compact": n.compact(), "pretty": []byte(n.pretty())} {
			if !json.Valid(out) {
				t.Fatalf("%s output is not valid JSON: %q", name, out)
			}
		}
		dec := func(b []byte) any {
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber()
			var v any
			if err := d.Decode(&v); err != nil {
				t.Fatalf("decode: %v", err)
			}
			return v
		}
		// Duplicate keys collapse in encoding/json, so compare only when the tree has none.
		if !hasDuplicateKeys(n) && !reflect.DeepEqual(dec(data), dec(n.compact())) {
			t.Fatalf("compact changed the value: in %q out %q", data, n.compact())
		}
	})
}

func hasDuplicateKeys(n *node) bool {
	if n.kind == kindObject {
		seen := map[string]bool{}
		for _, k := range n.keys {
			if seen[k] {
				return true
			}
			seen[k] = true
		}
	}
	for _, k := range n.kids {
		if hasDuplicateKeys(k) {
			return true
		}
	}
	return false
}

// FuzzOpenPath tries arbitrary path strings against a root: no panic, and a
// successful open must be a file inside the root, never the outside secret.
func FuzzOpenPath(f *testing.F) {
	root, secret := fuzzRoot(f)
	rs, err := openRoots([]string{root})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(rs.Close)
	for _, seed := range []string{
		"a.bin", "sub/b.bin", "./a.bin", "sub/../a.bin", "../outside.bin", "..", ".", "", "sub", "..\\outside.bin",
		filepath.Join(root, "a.bin"), filepath.Join(root, "..", "outside.bin"), "%2e%2e/outside.bin", "a.bin\x00", "NUL",
		`\\.\NUL`, "C:a.bin", "a.bin::$DATA", "file:///a.bin", strings.Repeat("../", 40) + "outside.bin", "sub/../../root-evil.bin",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		of, err := rs.open(p)
		if err != nil {
			return
		}
		defer of.Close()
		got, rerr := io.ReadAll(io.NewSectionReader(of, 0, of.size))
		if rerr != nil {
			t.Fatalf("reading %q: %v", p, rerr)
		}
		if bytes.Contains(got, secret) {
			t.Fatalf("open(%q) exposed the outside file", p)
		}
	})
}
