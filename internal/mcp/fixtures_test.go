package mcp

import (
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// fakeSecrets are the pattern-valid, non-functional credentials that
// testfixtures.SamplePE embeds. None of them may ever appear in a tool result.
var fakeSecrets = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_" + strings.Repeat("a1b2c3", 6),
}

// TestRealFixturesThroughTheServer analyses one fixture per supported family
// with the real pipeline and checks the properties that every report must have,
// whatever the format: the detected type, the static-only limitation, risk
// bounds, and findings that always carry evidence and limitations.
func TestRealFixturesThroughTheServer(t *testing.T) {
	root := t.TempDir()
	fixtures := []struct {
		file string
		data []byte
		want string
	}{
		{"sample.exe", testfixtures.SamplePE(), report.TypePE},
		{"tiny.elf", testfixtures.ELF(testfixtures.ELFOptions{}), report.TypeELF},
		{"tiny.macho", testfixtures.MachO(testfixtures.MachOOptions{}), report.TypeMachO},
		{"slip.zip", testfixtures.ZipSlip(), report.TypeZip},
		{"demo.apk", testfixtures.APK(testfixtures.APKOptions{Permissions: []string{"android.permission.INTERNET"}}), report.TypeAPK},
		{"app.asar", testfixtures.AsarElectronApp(), report.TypeAsar},
		{"model.gguf", testfixtures.GGUF(testfixtures.GGUFOptions{}), report.TypeGGUF},
		{"tiny.wasm", testfixtures.WasmSample(), report.TypeWasm},
	}
	for _, fx := range fixtures {
		writeFile(t, root, fx.file, fx.data)
	}
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	for i, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			doc := mustJSON(t, c.callTool(i+1, "analyze_file", map[string]any{"path": fx.file}))
			typ := doc["type"].(map[string]any)
			if typ["id"] != fx.want {
				t.Errorf("type.id = %v, want %v (%v)", typ["id"], fx.want, typ["label"])
			}
			if doc["schema"] != report.Schema || doc["file"].(map[string]any)["name"] != fx.file {
				t.Errorf("identity wrong: %v / %v", doc["schema"], doc["file"])
			}
			if lims, _ := doc["limitations"].([]any); len(lims) == 0 || !strings.Contains(lims[0].(string), "never executed") {
				t.Errorf("limitations = %v", doc["limitations"])
			}
			risk := doc["risk"].(map[string]any)
			if score := risk["score"].(float64); score < 0 || score > 100 {
				t.Errorf("risk score %v out of range", score)
			}
			for _, f := range doc["findings"].([]any) {
				finding := f.(map[string]any)
				if ev, ok := finding["evidence"].([]any); !ok || ev == nil {
					t.Errorf("finding %v has no evidence array", finding["id"])
				}
				if lim, ok := finding["limitations"].([]any); !ok || len(lim) == 0 {
					t.Errorf("finding %v must state its limitations", finding["id"])
				}
				if _, err := report.ParseSeverity(finding["severity"].(string)); err != nil {
					t.Errorf("finding %v: %v", finding["id"], err)
				}
			}
		})
	}
}

// TestSecretsNeverLeaveTheServer runs the secret-bearing sample through every
// tool and checks that no fake credential appears in any response.
func TestSecretsNeverLeaveTheServer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sample.exe", testfixtures.SamplePE())
	writeFile(t, root, "other.bin", sampleBytes(2048, 5))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	c.initialize("2025-06-18")

	var outputs []string
	collect := func(res toolRes) {
		outputs = append(outputs, res.text(), string(res.StructuredContent))
	}
	for _, detail := range []string{"summary", "full"} {
		res := c.callTool(1, "analyze_file", map[string]any{"path": "sample.exe", "detail": detail})
		mustJSON(t, res)
		collect(res)
	}
	for _, args := range []map[string]any{
		{"path": "sample.exe"},
		{"path": "sample.exe", "category": "secret"},
		{"path": "sample.exe", "query": "AKIA"},
		{"path": "sample.exe", "query": "ghp_"},
		{"path": "sample.exe", "query": "IOSFODNN7"},
		{"path": "sample.exe", "minLength": 3, "limit": 1000},
	} {
		res := c.callTool(2, "list_strings", args)
		mustJSON(t, res)
		collect(res)
	}
	for _, tool := range []string{"hash_file", "entropy_profile"} {
		collect(c.callTool(3, tool, map[string]any{"path": "sample.exe"}))
	}
	collect(c.callTool(4, "diff_files", map[string]any{"a": "sample.exe", "b": "other.bin"}))
	collect(c.callTool(5, "diff_files", map[string]any{"a": "other.bin", "b": "sample.exe"}))
	for i, out := range outputs {
		for _, secret := range fakeSecrets {
			if strings.Contains(out, secret) {
				t.Errorf("output %d contains the secret %q", i, secret)
			}
		}
	}

	// The redacted form is what the caller sees.
	doc := mustJSON(t, c.callTool(6, "list_strings", map[string]any{"path": "sample.exe", "category": "secret"}))
	items := doc["items"].([]any)
	if len(items) < 2 {
		t.Fatalf("expected the two embedded secrets, got %v", items)
	}
	prefixes := map[string]bool{}
	for _, it := range items {
		m := it.(map[string]any)
		if m["redacted"] != true || m["category"] != report.CatSecret || m["kind"] == nil || m["kind"] == "" {
			t.Errorf("secret item = %v", m)
		}
		v := m["value"].(string)
		prefixes[v[:4]] = true
		if !strings.Contains(v, "…") {
			t.Errorf("a redacted value must show an ellipsis and a length: %q", v)
		}
	}
	if !prefixes["AKIA"] || !prefixes["ghp_"] {
		t.Errorf("redacted prefixes = %v", prefixes)
	}
	// A search for the middle of a secret finds nothing: only the redacted form is searchable.
	miss := mustJSON(t, c.callTool(7, "list_strings", map[string]any{"path": "sample.exe", "query": "IOSFODNN7"}))
	if miss["total"] != float64(0) {
		t.Errorf("a query inside a secret must not match, total = %v", miss["total"])
	}
}

// TestRealListStringsFindsIndicators checks classification end to end on a
// file with known content.
func TestRealListStringsFindsIndicators(t *testing.T) {
	root := t.TempDir()
	data := []byte("\x00\x01padding\x00https://example.test/payload.bin\x00\x02\x03connect to 203.0.113.9 now\x00user@example.com\x00\xff\xfe")
	writeFile(t, root, "ind.bin", data)
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	doc := mustJSON(t, c.callTool(1, "list_strings", map[string]any{"path": "ind.bin", "category": "url,ip,email", "minLength": 6}))
	found := map[string]bool{}
	for _, it := range doc["items"].([]any) {
		m := it.(map[string]any)
		found[m["category"].(string)] = true
		if m["offset"].(float64) < 0 || m["offset"].(float64) >= float64(len(data)) {
			t.Errorf("offset out of range: %v", m)
		}
	}
	for _, cat := range []string{"url", "email"} {
		if !found[cat] {
			t.Errorf("category %s not found in %v", cat, doc["items"])
		}
	}
}

// TestSummaryTrimsARealArchive checks the summary view against a real report
// whose details hold a very long list.
func TestSummaryTrimsARealArchive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "many.zip", testfixtures.ZipMany(3000))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	res := c.callTool(1, "analyze_file", map[string]any{"path": "many.zip"})
	doc := mustJSON(t, res)
	archive, ok := doc["details"].(map[string]any)["archive"].(map[string]any)
	if !ok {
		t.Fatalf("details.archive missing: %v", doc["details"])
	}
	entries := archive["entries"].([]any)
	if len(entries) != summaryList {
		t.Errorf("entries = %d, want the summary limit %d", len(entries), summaryList)
	}
	if archive["entryCount"].(float64) < 3000 {
		t.Errorf("the true entry count must survive trimming: %v", archive["entryCount"])
	}
	if doc["truncated"] != true || len(res.text()) > defaultMaxOutput {
		t.Errorf("truncated = %v, text = %d bytes", doc["truncated"], len(res.text()))
	}
}
