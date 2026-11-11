package mcp

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hexMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// listTools returns the tools/list result for a negotiated protocol version.
func listTools(t *testing.T, version string) []map[string]any {
	t.Helper()
	c := startServer(t, Config{}, realAnalyzer())
	c.initialize(version)
	m := c.request(2, "tools/list", nil)
	if m.Error != nil {
		t.Fatalf("tools/list: %+v", m.Error)
	}
	var res struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

func TestToolsListContract(t *testing.T) {
	wantNames := []string{"analyze_file", "list_strings", "hash_file", "entropy_profile", "diff_files"}
	tests := []struct {
		version         string
		wantAnnotations bool
		wantTitle       bool
	}{
		{"2024-11-05", false, false},
		{"2025-03-26", true, false},
		{"2025-06-18", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			tools := listTools(t, tc.version)
			var names []string
			for _, tool := range tools {
				name, _ := tool["name"].(string)
				names = append(names, name)
				if d, _ := tool["description"].(string); len(d) < 40 {
					t.Errorf("%s: description is too short: %q", name, d)
				}
				_, hasTitle := tool["title"]
				if hasTitle != tc.wantTitle {
					t.Errorf("%s: title present = %v, want %v", name, hasTitle, tc.wantTitle)
				}
				ann, hasAnn := tool["annotations"].(map[string]any)
				if hasAnn != tc.wantAnnotations {
					t.Errorf("%s: annotations present = %v, want %v", name, hasAnn, tc.wantAnnotations)
				}
				if hasAnn {
					if ann["readOnlyHint"] != true || ann["destructiveHint"] != false || ann["idempotentHint"] != true || ann["openWorldHint"] != false {
						t.Errorf("%s: annotations = %v", name, ann)
					}
					if title, _ := ann["title"].(string); title == "" {
						t.Errorf("%s: annotations.title is empty", name)
					}
				}
				checkInputSchema(t, name, tool["inputSchema"])
			}
			if !slices.Equal(names, wantNames) {
				t.Fatalf("tool names = %v, want %v", names, wantNames)
			}
		})
	}
}

func checkInputSchema(t *testing.T, name string, raw any) {
	t.Helper()
	schema, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%s: inputSchema is not an object", name)
	}
	if schema["type"] != "object" {
		t.Errorf("%s: schema type = %v", name, schema["type"])
	}
	if schema["additionalProperties"] != false {
		t.Errorf("%s: additionalProperties must be false", name)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok || len(props) == 0 {
		t.Fatalf("%s: no properties", name)
	}
	for pname, p := range props {
		prop, ok := p.(map[string]any)
		if !ok {
			t.Errorf("%s.%s: not an object", name, pname)
			continue
		}
		if typ, _ := prop["type"].(string); typ == "" {
			t.Errorf("%s.%s: missing type", name, pname)
		}
		if d, _ := prop["description"].(string); d == "" {
			t.Errorf("%s.%s: missing description", name, pname)
		}
	}
	req, _ := schema["required"].([]any)
	if len(req) == 0 {
		t.Errorf("%s: required must list at least the path argument", name)
	}
	for _, r := range req {
		if _, ok := props[r.(string)]; !ok {
			t.Errorf("%s: required %q is not a property", name, r)
		}
	}
}

// TestSchemasAgreeWithHandlers feeds the same arguments to the schema validator
// and to the real handlers: whatever the schema rejects must fail as an isError
// result, and arguments the schema accepts must not fail for schema reasons.
func TestSchemasAgreeWithHandlers(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(512, 1))
	writeFile(t, root, "b.bin", sampleBytes(512, 2))
	schemas := map[string]map[string]any{}
	for _, tool := range listTools(t, "2025-06-18") {
		schemas[tool["name"].(string)] = tool["inputSchema"].(map[string]any)
	}
	type tc struct {
		tool string
		args map[string]any
		// schemaOK is whether the schema accepts the arguments; callOK whether the
		// call is expected to succeed (it can fail for reasons a schema cannot express).
		schemaOK, callOK bool
	}
	tests := []tc{
		{"analyze_file", map[string]any{"path": "a.bin"}, true, true},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 3, "maxStrings": 1, "detail": "full"}, true, true},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 256, "maxStrings": 10000, "detail": "summary"}, true, true},
		{"analyze_file", map[string]any{}, false, false},
		{"analyze_file", map[string]any{"path": 5}, false, false},
		{"analyze_file", map[string]any{"path": ""}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "extra": 1}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 2}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 257}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 5.5}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "maxStrings": 0}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "maxStrings": 10001}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "detail": "everything"}, false, false},
		{"analyze_file", map[string]any{"path": "a.bin", "detail": 1}, false, false},
		{"list_strings", map[string]any{"path": "a.bin"}, true, true},
		{"list_strings", map[string]any{"path": "a.bin", "category": "url,ip", "query": "x", "minLength": 3, "limit": 1000, "offset": 0}, true, true},
		{"list_strings", map[string]any{"path": "a.bin", "limit": 0}, false, false},
		{"list_strings", map[string]any{"path": "a.bin", "limit": 1001}, false, false},
		{"list_strings", map[string]any{"path": "a.bin", "offset": -1}, false, false},
		{"list_strings", map[string]any{"path": "a.bin", "minLength": 2}, false, false},
		{"list_strings", map[string]any{"path": "a.bin", "query": 5}, false, false},
		{"list_strings", map[string]any{"path": "a.bin", "category": "bogus"}, true, false}, // an enum a schema cannot express
		{"hash_file", map[string]any{"path": "a.bin"}, true, true},
		{"hash_file", map[string]any{}, false, false},
		{"hash_file", map[string]any{"path": "a.bin", "algorithm": "md5"}, false, false},
		{"entropy_profile", map[string]any{"path": "a.bin"}, true, true},
		{"entropy_profile", map[string]any{"path": []string{"a.bin"}}, false, false},
		{"diff_files", map[string]any{"a": "a.bin", "b": "b.bin"}, true, true},
		{"diff_files", map[string]any{"a": "a.bin"}, false, false},
		{"diff_files", map[string]any{"b": "b.bin"}, false, false},
		{"diff_files", map[string]any{"a": "a.bin", "b": "b.bin", "c": "x"}, false, false},
	}
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	for i, tc := range tests {
		raw, _ := json.Marshal(tc.args)
		var decoded any
		_ = json.Unmarshal(raw, &decoded)
		violations := validateSchema(schemas[tc.tool], decoded)
		if (len(violations) == 0) != tc.schemaOK {
			t.Errorf("%s %s: schema verdict ok=%v (violations %v), want %v", tc.tool, raw, len(violations) == 0, violations, tc.schemaOK)
		}
		res := c.callTool(1000+i, tc.tool, tc.args)
		if res.IsError == tc.callOK {
			t.Errorf("%s %s: isError=%v, want %v (%.200s)", tc.tool, raw, res.IsError, !tc.callOK, res.text())
		}
	}
}

func TestAnalyzeFileOnARealFile(t *testing.T) {
	root := t.TempDir()
	data := sampleBytes(6000, 7)
	writeFile(t, root, "sub/sample.bin", data)
	tests := []struct {
		version        string
		wantStructured bool
	}{
		{"2024-11-05", false},
		{"2025-03-26", false},
		{"2025-06-18", true},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
			c.initialize(tc.version)
			res := c.callTool(2, "analyze_file", map[string]any{"path": "sub/sample.bin"})
			doc := mustJSON(t, res)
			if len(res.Content) != 1 || res.Content[0].Type != "text" {
				t.Fatalf("content = %+v", res.Content)
			}
			if doc["schema"] != report.Schema {
				t.Errorf("schema = %v", doc["schema"])
			}
			file := doc["file"].(map[string]any)
			if file["name"] != "sample.bin" || file["size"] != float64(len(data)) {
				t.Errorf("file = %v (the report must carry the base name only)", file)
			}
			hashes := doc["hashes"].(map[string]any)
			if hashes["sha256"] != hexSHA256(data) || hashes["md5"] != hexMD5(data) {
				t.Errorf("hashes = %v", hashes)
			}
			if doc["detail"] != "summary" || doc["truncated"] != false {
				t.Errorf("detail/truncated = %v/%v", doc["detail"], doc["truncated"])
			}
			if _, has := doc["note"]; has {
				t.Errorf("a small report needs no note")
			}
			if !strings.HasPrefix(res.text(), "{\n  \"schema\": \"teardown.report/v1\",") {
				t.Errorf("text must be pretty-printed in report key order, got: %.120q", res.text())
			}
			if tc.wantStructured {
				var structured map[string]any
				if err := json.Unmarshal(res.StructuredContent, &structured); err != nil {
					t.Fatalf("structuredContent: %v (%s)", err, res.StructuredContent)
				}
				if !reflect.DeepEqual(structured, doc) {
					t.Error("structuredContent differs from the text content")
				}
			} else if len(res.StructuredContent) != 0 {
				t.Errorf("structuredContent must be absent for %s", tc.version)
			}
		})
	}
}

func TestToolsPassOptionsAndBaseNameToTheAnalyzer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "deep/dir/x.bin", sampleBytes(100, 1))
	var mu sync.Mutex
	var got []analyze.Options
	an := stubAnalyzer(bigReport(3))
	base := an.reader
	an.reader = func(ctx context.Context, r io.ReaderAt, size int64, opts analyze.Options) (*report.Report, error) {
		mu.Lock()
		got = append(got, opts)
		mu.Unlock()
		return base(ctx, r, size, opts)
	}
	an.strings = func(_ context.Context, _ io.ReaderAt, _ int64, opts analyze.Options) (report.Strings, error) {
		mu.Lock()
		got = append(got, opts)
		mu.Unlock()
		return report.Strings{MinLength: opts.MinString, ByCategory: map[string]int{}}, nil
	}
	c := startServer(t, Config{Roots: []string{root}, Timeout: 90e9}, an)
	c.callTool(1, "analyze_file", map[string]any{"path": "deep/dir/x.bin", "minString": 9, "maxStrings": 77})
	c.callTool(2, "list_strings", map[string]any{"path": "deep/dir/x.bin", "minLength": 11})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("analyzer calls = %d", len(got))
	}
	if o := got[0]; o.Name != "x.bin" || o.MinString != 9 || o.MaxStrings != 77 || o.Timeout != 90e9 {
		t.Errorf("analyze_file options = %+v", o)
	}
	if o := got[1]; o.Name != "x.bin" || o.MinString != 11 || o.MaxStrings != listMaxStrings {
		t.Errorf("list_strings options = %+v", o)
	}
}

func TestSummaryTrimsLongLists(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "big.bin", sampleBytes(100, 1))
	c := startServer(t, Config{Roots: []string{root}}, stubAnalyzer(bigReport(3000)))
	doc := mustJSON(t, c.callTool(1, "analyze_file", map[string]any{"path": "big.bin"}))

	items := doc["strings"].(map[string]any)["items"].([]any)
	if len(items) != summaryStrings {
		t.Fatalf("strings.items = %d, want %d", len(items), summaryStrings)
	}
	if first := items[0].(map[string]any); first["category"] != report.CatSecret {
		t.Errorf("the most interesting category (secret) must come first, got %v", first["category"])
	}
	for i := 1; i < len(items); i++ {
		if items[i].(map[string]any)["offset"].(float64) < items[i-1].(map[string]any)["offset"].(float64) {
			t.Fatal("kept strings must stay in file order")
		}
	}
	for _, imp := range doc["imports"].([]any) {
		if n := len(imp.(map[string]any)["functions"].([]any)); n != summaryFunctions {
			t.Fatalf("functions kept = %d", n)
		}
	}
	if n := len(doc["details"].(map[string]any)["archive"].(map[string]any)["entries"].([]any)); n != summaryList {
		t.Errorf("details.archive.entries = %d, want %d", n, summaryList)
	}
	if n := len(doc["exports"].([]any)); n != summaryExports {
		t.Errorf("exports = %d, want %d", n, summaryExports)
	}
	if doc["truncated"] != true || !strings.Contains(doc["note"].(string), "list_strings") {
		t.Errorf("truncated/note = %v / %v", doc["truncated"], doc["note"])
	}
	notes := map[string]map[string]any{}
	for _, n := range doc["trimmed"].([]any) {
		m := n.(map[string]any)
		notes[m["path"].(string)] = m
	}
	if m := notes["strings.items"]; m == nil || m["kept"] != float64(summaryStrings) || m["total"] != float64(3000) {
		t.Errorf("trimmed strings note = %v", m)
	}
	for _, key := range []string{"findings", "hardening", "risk", "limitations", "hashes", "sections"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("summary dropped %q", key)
		}
	}
	if n := len(doc["findings"].([]any)); n != 5 {
		t.Errorf("findings = %d, summary must keep every finding", n)
	}
}

func TestFullDetailIsOnlyLimitedByTheCap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "big.bin", sampleBytes(100, 1))
	// A report that fits entirely: nothing is trimmed in full mode.
	small := stubAnalyzer(bigReport(30))
	c := startServer(t, Config{Roots: []string{root}, MaxOutput: 4 << 20}, small)
	doc := mustJSON(t, c.callTool(1, "analyze_file", map[string]any{"path": "big.bin", "detail": "full"}))
	if n := len(doc["strings"].(map[string]any)["items"].([]any)); n != 30 {
		t.Errorf("full detail must keep all 30 strings, got %d", n)
	}
	if doc["truncated"] != false || doc["detail"] != "full" {
		t.Errorf("truncated/detail = %v/%v", doc["truncated"], doc["detail"])
	}
	if n := len(doc["details"].(map[string]any)["archive"].(map[string]any)["entries"].([]any)); n != 500 {
		t.Errorf("full detail must keep all 500 entries, got %d", n)
	}
}

func TestOutputCapIsNeverExceeded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "big.bin", sampleBytes(100, 1))
	for _, limit := range []int{minMaxOutput, 3 << 10, 8 << 10, 20 << 10, 64 << 10} {
		for _, detail := range []string{"summary", "full"} {
			t.Run(fmt.Sprintf("%d/%s", limit, detail), func(t *testing.T) {
				c := startServer(t, Config{Roots: []string{root}, MaxOutput: limit}, stubAnalyzer(bigReport(1200)))
				res := c.callTool(1, "analyze_file", map[string]any{"path": "big.bin", "detail": detail})
				if res.IsError {
					// Acceptable only for the smallest caps, and only with the explanatory message.
					if limit > 3<<10 || !strings.Contains(res.text(), "output limit") {
						t.Fatalf("unexpected error at cap %d: %s", limit, res.text())
					}
					return
				}
				if len(res.text()) > limit {
					t.Fatalf("text is %d bytes, cap is %d", len(res.text()), limit)
				}
				doc := mustJSON(t, res)
				if doc["truncated"] != true {
					t.Errorf("a trimmed result must say truncated:true")
				}
				if doc["schema"] != report.Schema || doc["hashes"] == nil || doc["risk"] == nil {
					t.Errorf("identity of the report lost: %.200s", res.text())
				}
				if len(doc["trimmed"].([]any)) == 0 {
					t.Error("trimmed notes are missing")
				}
			})
		}
	}
}

func TestResultThatCannotBeTrimmedIsAnError(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "big.bin", sampleBytes(100, 1))
	rep := bigReport(5)
	rep.Type.Label = strings.Repeat("x", 100_000) // a scalar no step can shorten
	c := startServer(t, Config{Roots: []string{root}, MaxOutput: 8 << 10}, stubAnalyzer(rep))
	msg := mustErrorText(t, c.callTool(1, "analyze_file", map[string]any{"path": "big.bin"}))
	if !strings.Contains(msg, "output limit") || !strings.Contains(msg, "8192") {
		t.Fatalf("message = %q", msg)
	}
	if len(msg) > 1024 {
		t.Errorf("an error message must always fit the cap, got %d bytes", len(msg))
	}
}

func TestListStrings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	items := []report.StringItem{
		{Value: "https://example.com/path?a=1&b=2", Offset: 10, Encoding: "ascii", Category: report.CatURL},
		{Value: "http://Evil.EXAMPLE.org/x", Offset: 80, Encoding: "utf16le", Category: report.CatURL},
		{Value: "10.0.0.7", Offset: 120, Encoding: "ascii", Category: report.CatIP},
		{Value: "AKIA…(20 chars)", Offset: 200, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
		{Value: "C:\\Windows\\System32\\cmd.exe", Offset: 300, Encoding: "ascii", Category: report.CatPath},
	}
	for i := range 250 {
		items = append(items, report.StringItem{Value: fmt.Sprintf("plain string number %03d", i), Offset: int64(1000 + i*30), Encoding: "ascii", Category: report.CatPlain})
	}
	an := realAnalyzer()
	var minSeen int
	an.strings = func(_ context.Context, _ io.ReaderAt, _ int64, opts analyze.Options) (report.Strings, error) {
		minSeen = opts.MinString
		return report.Strings{Total: 400, MinLength: opts.MinString, Truncated: true, ByCategory: map[string]int{"url": 2, "plain": 250}, Items: items}, nil
	}
	c := startServer(t, Config{Roots: []string{root}}, an)

	type page struct {
		total, offset, limit, returned int
		next                           float64
		firstValue                     string
	}
	tests := []struct {
		name string
		args map[string]any
		want page
	}{
		{"defaults", map[string]any{"path": "a.bin"}, page{255, 0, 100, 100, 100, "https://example.com/path?a=1&b=2"}},
		{"second page", map[string]any{"path": "a.bin", "offset": 100}, page{255, 100, 100, 100, 200, "plain string number 095"}},
		{"last page", map[string]any{"path": "a.bin", "offset": 200, "limit": 1000}, page{255, 200, 1000, 55, 0, "plain string number 195"}},
		{"beyond the end", map[string]any{"path": "a.bin", "offset": 5000}, page{255, 5000, 100, 0, 0, ""}},
		{"one category", map[string]any{"path": "a.bin", "category": "url"}, page{2, 0, 100, 2, 0, "https://example.com/path?a=1&b=2"}},
		{"two categories, case-insensitive", map[string]any{"path": "a.bin", "category": " URL , ip "}, page{3, 0, 100, 3, 0, "https://example.com/path?a=1&b=2"}},
		{"query ignores case", map[string]any{"path": "a.bin", "query": "EXAMPLE"}, page{2, 0, 100, 2, 0, "https://example.com/path?a=1&b=2"}},
		{"query and category", map[string]any{"path": "a.bin", "query": "evil", "category": "url"}, page{1, 0, 100, 1, 0, "http://Evil.EXAMPLE.org/x"}},
		{"paging inside matches", map[string]any{"path": "a.bin", "category": "url,ip,secret", "limit": 2, "offset": 1}, page{4, 1, 2, 2, 3, "http://Evil.EXAMPLE.org/x"}},
		{"redacted values are matched redacted", map[string]any{"path": "a.bin", "query": "akia"}, page{1, 0, 100, 1, 0, "AKIA…(20 chars)"}},
		{"no match", map[string]any{"path": "a.bin", "query": "no-such-string"}, page{0, 0, 100, 0, 0, ""}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustJSON(t, c.callTool(10+i, "list_strings", tc.args))
			if doc["total"] != float64(tc.want.total) || doc["offset"] != float64(tc.want.offset) || doc["limit"] != float64(tc.want.limit) {
				t.Errorf("total/offset/limit = %v/%v/%v, want %d/%d/%d", doc["total"], doc["offset"], doc["limit"], tc.want.total, tc.want.offset, tc.want.limit)
			}
			got := doc["items"].([]any)
			if len(got) != tc.want.returned || doc["returned"] != float64(tc.want.returned) {
				t.Fatalf("items = %d, returned = %v, want %d", len(got), doc["returned"], tc.want.returned)
			}
			if tc.want.returned > 0 && got[0].(map[string]any)["value"] != tc.want.firstValue {
				t.Errorf("first value = %v, want %q", got[0].(map[string]any)["value"], tc.want.firstValue)
			}
			if tc.want.next == 0 {
				if _, has := doc["nextOffset"]; has {
					t.Errorf("nextOffset must be absent on the last page: %v", doc["nextOffset"])
				}
			} else if doc["nextOffset"] != tc.want.next {
				t.Errorf("nextOffset = %v, want %v", doc["nextOffset"], tc.want.next)
			}
			if doc["stringsFound"] != float64(400) || doc["scanTruncated"] != true || doc["truncated"] != false {
				t.Errorf("stringsFound/scanTruncated/truncated = %v/%v/%v", doc["stringsFound"], doc["scanTruncated"], doc["truncated"])
			}
		})
	}
	doc := mustJSON(t, c.callTool(99, "list_strings", map[string]any{"path": "a.bin", "minLength": 12}))
	if minSeen != 12 || doc["minLength"] != float64(12) {
		t.Errorf("minLength was not passed through: %d / %v", minSeen, doc["minLength"])
	}
	// Secrets never appear in full: the redacted marker is all that the tool ever sees.
	secret := mustJSON(t, c.callTool(98, "list_strings", map[string]any{"path": "a.bin", "category": "secret"}))
	it := secret["items"].([]any)[0].(map[string]any)
	if it["redacted"] != true || it["kind"] != "aws-access-key-id" {
		t.Errorf("secret item = %v", it)
	}
}

func TestListStringsPageShrinksToTheOutputCap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	var items []report.StringItem
	for i := range 1000 {
		items = append(items, report.StringItem{Value: fmt.Sprintf("%04d-%s", i, strings.Repeat("v", 200)), Offset: int64(i), Encoding: "ascii", Category: report.CatPlain})
	}
	an := realAnalyzer()
	an.strings = func(context.Context, io.ReaderAt, int64, analyze.Options) (report.Strings, error) {
		return report.Strings{Total: 1000, MinLength: 5, ByCategory: map[string]int{"plain": 1000}, Items: items}, nil
	}
	c := startServer(t, Config{Roots: []string{root}, MaxOutput: 12 << 10}, an)
	res := c.callTool(1, "list_strings", map[string]any{"path": "a.bin", "limit": 1000})
	doc := mustJSON(t, res)
	if len(res.text()) > 12<<10 {
		t.Fatalf("text %d bytes exceeds the cap", len(res.text()))
	}
	returned := int(doc["returned"].(float64))
	if returned == 0 || returned >= 1000 || doc["truncated"] != true {
		t.Fatalf("returned = %d, truncated = %v", returned, doc["truncated"])
	}
	if doc["nextOffset"] != float64(returned) {
		t.Errorf("nextOffset = %v, want %d so the caller can continue", doc["nextOffset"], returned)
	}
	if !strings.Contains(doc["note"].(string), "nextOffset") {
		t.Errorf("note = %v", doc["note"])
	}
}

func TestHashFile(t *testing.T) {
	root := t.TempDir()
	data := sampleBytes(10_000, 9)
	writeFile(t, root, "h.bin", data)
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	doc := mustJSON(t, c.callTool(1, "hash_file", map[string]any{"path": "h.bin"}))
	hashes := doc["hashes"].(map[string]any)
	if hashes["md5"] != hexMD5(data) || hashes["sha256"] != hexSHA256(data) || len(hashes["sha1"].(string)) != 40 {
		t.Errorf("hashes = %v", hashes)
	}
	if _, ok := hashes["imphash"]; !ok {
		t.Error("imphash key must be present (empty when not a PE)")
	}
	file := doc["file"].(map[string]any)
	if file["name"] != "h.bin" || file["size"] != float64(len(data)) {
		t.Errorf("file = %v", file)
	}
	if typ := doc["type"].(map[string]any); typ["id"] == "" || typ["id"] == nil {
		t.Errorf("type = %v", typ)
	}
	if _, has := doc["truncated"]; has {
		t.Error("hash_file results are never trimmed and carry no truncated key")
	}
}

func TestEntropyProfile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "zeros.bin", make([]byte, 5000))
	writeFile(t, root, "noise.bin", sampleBytes(64<<10, 4))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())

	zeros := mustJSON(t, c.callTool(1, "entropy_profile", map[string]any{"path": "zeros.bin"}))
	if zeros["overall"] != float64(0) {
		t.Errorf("entropy of zeros = %v", zeros["overall"])
	}
	noise := mustJSON(t, c.callTool(2, "entropy_profile", map[string]any{"path": "noise.bin"}))
	if o := noise["overall"].(float64); o < 7.9 || o > 8 {
		t.Errorf("entropy of noise = %v", o)
	}
	windows := noise["windows"].([]any)
	if size := noise["windowSize"].(float64); len(windows) == 0 || len(windows) > 512 || size < 256 || float64(len(windows))*size < float64(64<<10) {
		t.Errorf("windowSize %v with %d windows does not cover the file", size, len(windows))
	}
	if !strings.Contains(noise["scale"].(string), "bits per byte") {
		t.Errorf("scale = %v", noise["scale"])
	}
	if _, ok := noise["sections"].([]any); !ok {
		t.Errorf("sections must be an array: %v", noise["sections"])
	}

	// Section entropy comes from the full analysis.
	rep := bigReport(1)
	c2 := startServer(t, Config{Roots: []string{root}}, stubAnalyzer(rep))
	doc := mustJSON(t, c2.callTool(3, "entropy_profile", map[string]any{"path": "zeros.bin"}))
	secs := doc["sections"].([]any)
	if len(secs) != 12 || secs[0].(map[string]any)["name"] != ".sec0" || secs[0].(map[string]any)["entropy"] != 5.5 {
		t.Errorf("sections = %v", secs)
	}
	if typ := doc["type"].(map[string]any); typ["id"] != "pe" {
		t.Errorf("type = %v", typ)
	}
}

func TestDiffFiles(t *testing.T) {
	root := t.TempDir()
	a := sampleBytes(4000, 1)
	b := append(sampleBytes(4000, 1), []byte("appended payload")...)
	writeFile(t, root, "a.bin", a)
	writeFile(t, root, "b.bin", b)
	writeFile(t, root, "a-copy.bin", a)
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())

	doc := mustJSON(t, c.callTool(1, "diff_files", map[string]any{"a": "a.bin", "b": "b.bin"}))
	sideA, sideB := doc["a"].(map[string]any), doc["b"].(map[string]any)
	if sideA["sha256"] != hexSHA256(a) || sideB["sha256"] != hexSHA256(b) || sideA["name"] != "a.bin" || sideB["size"] != float64(len(b)) {
		t.Errorf("identities = %v / %v", sideA, sideB)
	}
	d := doc["diff"].(map[string]any)
	if d["schema"] != "teardown.diff/v1" || d["identical"] != false {
		t.Errorf("diff = %.200v", d)
	}

	same := mustJSON(t, c.callTool(2, "diff_files", map[string]any{"a": "a.bin", "b": "a-copy.bin"}))
	if same["diff"].(map[string]any)["identical"] != true {
		t.Errorf("identical files must diff as identical: %v", same["diff"])
	}

	msg := mustErrorText(t, c.callTool(3, "diff_files", map[string]any{"a": "a.bin", "b": "missing.bin"}))
	if !strings.Contains(msg, `argument "b"`) || !strings.Contains(msg, "not found") {
		t.Errorf("message = %q", msg)
	}
	msg = mustErrorText(t, c.callTool(4, "diff_files", map[string]any{"a": "../outside.bin", "b": "b.bin"}))
	if !strings.Contains(msg, `argument "a"`) || !strings.Contains(msg, "outside the allowed roots") {
		t.Errorf("message = %q", msg)
	}
}

func TestDiffFilesFirstFailureWins(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	writeFile(t, root, "b.bin", sampleBytes(100, 2))
	an := realAnalyzer()
	an.reader = func(ctx context.Context, _ io.ReaderAt, size int64, opts analyze.Options) (*report.Report, error) {
		if opts.Name == "b.bin" {
			return nil, fmt.Errorf("parser exploded on %s", opts.Name)
		}
		<-ctx.Done() // the other analysis is cancelled by the failure
		return nil, ctx.Err()
	}
	c := startServer(t, Config{Roots: []string{root}}, an)
	msg := mustErrorText(t, c.callTool(1, "diff_files", map[string]any{"a": "a.bin", "b": "b.bin"}))
	if !strings.Contains(msg, "file b") || !strings.Contains(msg, "parser exploded") {
		t.Fatalf("the real failure must be reported, not the cancellation: %q", msg)
	}
}

func TestUnknownToolAndMalformedCallParams(t *testing.T) {
	c := startServer(t, Config{}, realAnalyzer())
	tests := []struct {
		name   string
		params any
		want   string
	}{
		{"unknown tool", map[string]any{"name": "rm_rf", "arguments": map[string]any{}}, "unknown tool"},
		{"no params", nil, "expected a JSON object"},
		{"params is an array", []any{1}, "expected a JSON object"},
		{"missing name", map[string]any{"arguments": map[string]any{}}, "missing tool name"},
		{"empty name", map[string]any{"name": ""}, "missing tool name"},
		{"name is a number", map[string]any{"name": 7}, "invalid params"},
		{"arguments is an array", map[string]any{"name": "hash_file", "arguments": []any{"x"}}, "arguments must be an object"},
		{"arguments is a string", map[string]any{"name": "hash_file", "arguments": "x"}, "arguments must be an object"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := c.request(200+i, "tools/call", tc.params)
			if m.Error == nil || m.Error.Code != codeInvalidParams || !strings.Contains(m.Error.Message, tc.want) {
				t.Fatalf("got %+v / %s, want -32602 mentioning %q", m.Error, m.Result, tc.want)
			}
		})
	}
	// Absent or null arguments are an empty object: the failure is the missing path.
	msg := mustErrorText(t, decodeToolResult(t, c.request(300, "tools/call", map[string]any{"name": "hash_file"})))
	if !strings.Contains(msg, `missing required argument "path"`) {
		t.Errorf("message = %q", msg)
	}
	msg = mustErrorText(t, decodeToolResult(t, c.request(301, "tools/call", map[string]any{"name": "hash_file", "arguments": nil})))
	if !strings.Contains(msg, `missing required argument "path"`) {
		t.Errorf("message = %q", msg)
	}
}

func TestToolArgumentErrorMessagesNameTheProblem(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	tests := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"analyze_file", map[string]any{"path": 5}, `argument "path" must be a string`},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": "x"}, `argument "minString" must be an integer`},
		{"analyze_file", map[string]any{"path": "a.bin", "minString": 2}, `argument "minString" must be between 3 and 256`},
		{"analyze_file", map[string]any{"path": "a.bin", "maxStrings": 0}, `argument "maxStrings" must be between 1 and 10000`},
		{"analyze_file", map[string]any{"path": "a.bin", "detail": "x"}, `argument "detail" must be "summary" or "full"`},
		{"analyze_file", map[string]any{"path": "a.bin", "bogus": true}, `unknown argument "bogus"`},
		{"list_strings", map[string]any{"path": "a.bin", "category": "nope"}, "valid categories are secret, url"},
		{"list_strings", map[string]any{"path": "a.bin", "limit": 5000}, `argument "limit" must be between 1 and 1000`},
		{"list_strings", map[string]any{"path": "a.bin", "offset": -4}, `argument "offset" must be between 0`},
		{"diff_files", map[string]any{"a": "a.bin"}, `missing required argument "b"`},
		{"hash_file", map[string]any{"path": true}, `argument "path" must be a string (got bool)`},
	}
	for i, tc := range tests {
		msg := mustErrorText(t, c.callTool(i+1, tc.tool, tc.args))
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s %v: message %q does not contain %q", tc.tool, tc.args, msg, tc.want)
		}
	}
}

func TestPanicInAToolIsContained(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	an := realAnalyzer()
	an.reader = func(context.Context, io.ReaderAt, int64, analyze.Options) (*report.Report, error) {
		var m map[string]int
		m["boom"] = 1 // a nil map write panics
		return nil, nil
	}
	c := startServer(t, Config{Roots: []string{root}}, an)
	msg := mustErrorText(t, c.callTool(1, "analyze_file", map[string]any{"path": "a.bin"}))
	if !strings.Contains(msg, "internal error") || strings.Contains(msg, "nil map") {
		t.Errorf("message = %q (it must not leak the panic text)", msg)
	}
	c.expectSilence()
	if !strings.Contains(c.stderr.String(), "panic in a tool") {
		t.Errorf("the panic must be logged, log = %q", c.stderr.String())
	}
}

func TestAnalysisErrorsAreToolResults(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", sampleBytes(100, 1))
	an := realAnalyzer()
	an.reader = func(context.Context, io.ReaderAt, int64, analyze.Options) (*report.Report, error) {
		return nil, fmt.Errorf("hashing a.bin: %w", io.ErrUnexpectedEOF)
	}
	c := startServer(t, Config{Roots: []string{root}}, an)
	msg := mustErrorText(t, c.callTool(1, "analyze_file", map[string]any{"path": "a.bin"}))
	if !strings.HasPrefix(msg, "analysis failed: hashing a.bin") {
		t.Errorf("message = %q", msg)
	}
}
