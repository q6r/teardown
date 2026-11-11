package report

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNewIsFullyAllocatedAndEncodesWithoutNull(t *testing.T) {
	r := New("a.bin", 12, "1.2.3")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "null") {
		t.Fatalf("encoded report contains null: %s", raw)
	}
	if r.Schema != Schema || r.Tool.Name != ToolName || r.Tool.Version != "1.2.3" {
		t.Fatalf("unexpected header: %+v %+v", r.Schema, r.Tool)
	}
	if !slices.Contains(r.Limitations, StaticOnly) {
		t.Fatalf("static-only limitation missing: %v", r.Limitations)
	}
}

// TestJSONKeysAreStable pins the public contract: renaming or dropping a key is
// a breaking change and must be a conscious decision.
func TestJSONKeysAreStable(t *testing.T) {
	r := New("a.bin", 1, "dev")
	r.GeneratedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	r.Sections = []Section{{Name: ".text", Flags: []string{FlagR, FlagX}, Reasons: []string{"x"}}}
	r.Imports = []Import{{Library: "k.dll", Count: 1, Functions: []string{"f"}}}
	r.Strings.Items = []StringItem{{Value: "v", Kind: "k"}}
	r.Hardening = []Hardening{{ID: HardenASLR, Status: StatusEnabled}}
	r.Findings = []Finding{{ID: "x.y", Severity: SeverityLow}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"":                {"schema", "tool", "generatedAt", "durationMs", "file", "type", "hashes", "entropy", "sections", "imports", "exports", "strings", "hardening", "details", "findings", "risk", "limitations"},
		"tool":            {"name", "version"},
		"file":            {"name", "size"},
		"type":            {"id", "family", "label", "mime", "confidence", "tags"},
		"hashes":          {"md5", "sha1", "sha256", "imphash"},
		"entropy":         {"overall", "windowSize", "windows"},
		"strings":         {"total", "minLength", "truncated", "byCategory", "items"},
		"risk":            {"score", "label", "basis"},
		"sections.0":      {"name", "virtualSize", "rawSize", "offset", "entropy", "flags", "suspicious", "reasons"},
		"imports.0":       {"library", "count", "functions"},
		"strings.items.0": {"value", "offset", "encoding", "category", "redacted", "kind"},
		"hardening.0":     {"id", "label", "status", "detail"},
		"findings.0":      {"id", "title", "severity", "category", "confidence", "evidence", "limitations"},
	}
	for path, keys := range want {
		obj := dig(t, m, path)
		got := make([]string, 0, len(obj))
		for k := range obj {
			got = append(got, k)
		}
		slices.Sort(got)
		w := slices.Clone(keys)
		slices.Sort(w)
		if !reflect.DeepEqual(got, w) {
			t.Errorf("keys at %q:\n got %v\nwant %v", path, got, w)
		}
	}
}

func dig(t *testing.T, m map[string]any, path string) map[string]any {
	t.Helper()
	var cur any = m
	if path == "" {
		return m
	}
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			cur = node[part]
		case []any:
			if part != "0" || len(node) == 0 {
				t.Fatalf("bad path %q", path)
			}
			cur = node[0]
		default:
			t.Fatalf("bad path %q at %q", path, part)
		}
	}
	obj, ok := cur.(map[string]any)
	if !ok {
		t.Fatalf("path %q is not an object: %T", path, cur)
	}
	return obj
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"info", SeverityInfo, false},
		{" HIGH ", SeverityHigh, false},
		{"Critical", SeverityCritical, false},
		{"", "", true},
		{"urgent", "", true},
	}
	for _, tc := range tests {
		got, err := ParseSeverity(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSeverity(%q) = %q, %v", tc.in, got, err)
		}
	}
	if !SeverityHigh.AtLeast(SeverityMedium) || SeverityLow.AtLeast(SeverityMedium) {
		t.Error("AtLeast ordering is wrong")
	}
	if Severity("bogus").AtLeast(SeverityInfo) || SeverityCritical.AtLeast("bogus") {
		t.Error("unknown severities must never satisfy AtLeast")
	}
	if got := Severities(); len(got) != 5 || got[0] != SeverityInfo || got[4] != SeverityCritical {
		t.Errorf("Severities() = %v", got)
	}
}

func TestMeetsAndMaxSeverity(t *testing.T) {
	r := New("x", 0, "dev")
	if _, ok := r.MaxSeverity(); ok {
		t.Fatal("empty report must have no max severity")
	}
	if r.Meets(SeverityInfo) {
		t.Fatal("empty report meets nothing")
	}
	r.Findings = []Finding{{Severity: SeverityLow}, {Severity: SeverityHigh}, {Severity: SeverityInfo}}
	if got, _ := r.MaxSeverity(); got != SeverityHigh {
		t.Errorf("MaxSeverity = %v", got)
	}
	if !r.Meets(SeverityHigh) || r.Meets(SeverityCritical) {
		t.Error("Meets threshold logic is wrong")
	}
	if c := r.CountBySeverity(); c[SeverityLow] != 1 || c[SeverityHigh] != 1 || c[SeverityMedium] != 0 {
		t.Errorf("CountBySeverity = %v", c)
	}
}

func TestSectionFlagsAndHelpers(t *testing.T) {
	s := Section{Flags: []string{FlagR, FlagW, FlagX}}
	if !s.Writable() || !s.Executable() {
		t.Error("flag helpers are wrong")
	}
	if (Section{Flags: []string{FlagR}}).Executable() {
		t.Error("read-only section reported executable")
	}
	r := New("x", 0, "dev")
	r.Hardening = []Hardening{{ID: HardenPIE, Status: StatusEnabled}}
	if h, ok := r.HardeningByID(HardenPIE); !ok || h.Status != StatusEnabled {
		t.Error("HardeningByID did not find pie")
	}
	if _, ok := r.HardeningByID(HardenASLR); ok {
		t.Error("HardeningByID found a missing entry")
	}
	r.AddLimitation("a")
	r.AddLimitation("a")
	if n := strings.Count(strings.Join(r.Limitations, "|"), "a"); n < 1 || len(r.Limitations) != 2 {
		t.Errorf("AddLimitation did not dedupe: %v", r.Limitations)
	}
}

func TestStringCategoriesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range StringCategories() {
		if seen[c] {
			t.Errorf("duplicate category %q", c)
		}
		seen[c] = true
	}
	if !seen[CatPlain] || !seen[CatSecret] {
		t.Error("plain and secret must be listed")
	}
}
