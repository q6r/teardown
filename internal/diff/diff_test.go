package diff

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

func rep(name, sha string) *report.Report {
	r := report.New(name, 1000, "test")
	r.Hashes.SHA256 = sha
	r.Type = report.Type{ID: report.TypePE, Label: "PE32+ executable", Tags: []string{"exe", "64-bit"}}
	r.Entropy.Overall = 5.5
	return r
}

func TestIdenticalFiles(t *testing.T) {
	a, b := rep("a.exe", "aa"), rep("b.exe", "aa")
	res := Compare(a, b)
	if !res.Identical || len(res.Summary) != 1 || !strings.Contains(res.Summary[0], "identical") {
		t.Fatalf("result = %+v", res)
	}
	if res.Type != nil {
		t.Fatalf("no type change expected: %+v", res.Type)
	}
}

func TestNilReportsAreTolerated(t *testing.T) {
	res := Compare(nil, nil)
	if res.Identical || res.Schema != Schema {
		t.Fatalf("result = %+v", res)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatal(err)
	}
}

func TestCompareDoesNotMutateInputs(t *testing.T) {
	a, b := rep("a", "aa"), rep("b", "bb")
	b.Sections = []report.Section{{Name: ".text", Flags: []string{"R", "X"}}}
	before, _ := json.Marshal([]*report.Report{a, b})
	Compare(a, b)
	after, _ := json.Marshal([]*report.Report{a, b})
	if string(before) != string(after) {
		t.Fatal("Compare mutated its inputs")
	}
}

func TestStructuredDiff(t *testing.T) {
	a, b := rep("old.exe", "aa"), rep("new.exe", "bb")
	a.File.Size, b.File.Size = 1000, 3000
	a.Hashes.Imphash, b.Hashes.Imphash = "i1", "i2"

	a.Type.Tags = []string{"exe", "64-bit"}
	b.Type = report.Type{ID: report.TypePE, Label: "PE32+ executable", Tags: []string{"64-bit", "upx"}}

	a.Sections = []report.Section{
		{Name: ".text", RawSize: 100, VirtualSize: 120, Entropy: 6.1, Flags: []string{"R", "X"}},
		{Name: ".data", RawSize: 50, Entropy: 2.0, Flags: []string{"R", "W"}},
		{Name: ".gone", RawSize: 1},
	}
	b.Sections = []report.Section{
		{Name: ".text", RawSize: 100, VirtualSize: 120, Entropy: 7.8, Flags: []string{"R", "W", "X"}},
		{Name: ".data", RawSize: 50, Entropy: 2.0, Flags: []string{"R", "W"}},
		{Name: "UPX1", RawSize: 5},
	}
	a.Imports = []report.Import{{Library: "KERNEL32.dll", Count: 2, Functions: []string{"ExitProcess", "GetTickCount"}}}
	b.Imports = []report.Import{
		{Library: "kernel32.DLL", Count: 2, Functions: []string{"ExitProcess", "VirtualAlloc"}},
		{Library: "WS2_32.dll", Count: 1, Functions: []string{"connect"}},
	}
	a.Exports, b.Exports = []string{"a", "b"}, []string{"b", "c"}
	a.Strings = report.Strings{ByCategory: map[string]int{"url": 1}, Items: []report.StringItem{{Value: "old string", Category: "plain"}, {Value: "shared", Category: "plain"}}}
	b.Strings = report.Strings{ByCategory: map[string]int{"url": 3}, Items: []report.StringItem{{Value: "http://x.test", Category: "url"}, {Value: "shared", Category: "plain"}}}
	a.Hardening = []report.Hardening{{ID: "aslr", Label: "ASLR", Status: "enabled"}, {ID: "dep", Label: "DEP", Status: "enabled"}}
	b.Hardening = []report.Hardening{{ID: "aslr", Label: "ASLR", Status: "disabled"}, {ID: "dep", Label: "DEP", Status: "enabled"}, {ID: "cfg", Label: "CFG", Status: "enabled"}}
	a.Findings = []report.Finding{
		{ID: "x.kept", Severity: report.SeverityLow}, {ID: "x.gone", Severity: report.SeverityMedium, Title: "gone"},
		{ID: "x.bumped", Severity: report.SeverityLow, Title: "bumped"},
	}
	b.Findings = []report.Finding{
		{ID: "x.kept", Severity: report.SeverityLow}, {ID: "packing.upx", Severity: report.SeverityMedium, Title: "UPX"},
		{ID: "x.bumped", Severity: report.SeverityHigh, Title: "bumped"},
	}
	a.Risk = report.Risk{Score: 5, Label: "low"}
	b.Risk = report.Risk{Score: 50, Label: "high"}

	res := Compare(a, b)
	if res.Identical {
		t.Fatal("not identical")
	}
	if res.Type == nil || res.Type.ID != nil || !slices.Equal(res.Type.TagsAdded, []string{"upx"}) || !slices.Equal(res.Type.TagsRemoved, []string{"exe"}) {
		t.Fatalf("type = %+v", res.Type)
	}
	if !slices.Equal(res.Sections.Added, []string{"UPX1"}) || !slices.Equal(res.Sections.Removed, []string{".gone"}) {
		t.Fatalf("sections = %+v", res.Sections)
	}
	if len(res.Sections.Changed) != 1 || res.Sections.Changed[0].Name != ".text" || res.Sections.Changed[0].Entropy == nil || res.Sections.Changed[0].Flags == nil || res.Sections.Changed[0].RawSize != nil {
		t.Fatalf("changed sections = %+v", res.Sections.Changed)
	}
	if !slices.Equal(res.Imports.Added, []string{"kernel32.dll!VirtualAlloc", "ws2_32.dll!connect"}) || !slices.Equal(res.Imports.Removed, []string{"kernel32.dll!GetTickCount"}) {
		t.Fatalf("imports = %+v", res.Imports)
	}
	if !slices.Equal(res.Exports.Added, []string{"c"}) || !slices.Equal(res.Exports.Removed, []string{"a"}) {
		t.Fatalf("exports = %+v", res.Exports)
	}
	if res.Strings.AddedCount != 1 || res.Strings.Added[0].Value != "http://x.test" || res.Strings.RemovedCount != 1 || res.Strings.ByCategory["url"] != (Change[int]{1, 3}) {
		t.Fatalf("strings = %+v", res.Strings)
	}
	wantH := []StatusDiff{{"aslr", "ASLR", "enabled", "disabled"}, {"cfg", "CFG", "absent", "enabled"}}
	if !slices.Equal(res.Hardening, wantH) {
		t.Fatalf("hardening = %+v", res.Hardening)
	}
	if len(res.Findings.Added) != 1 || res.Findings.Added[0].ID != "packing.upx" || len(res.Findings.Removed) != 1 || res.Findings.Removed[0].ID != "x.gone" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Findings.Changed) != 1 || res.Findings.Changed[0].From != report.SeverityLow || res.Findings.Changed[0].Severity != report.SeverityHigh || res.Findings.Unchanged != 1 {
		t.Fatalf("changed findings = %+v", res.Findings)
	}
	if res.Risk.Delta != 45 || res.Risk.LabelTo != "high" {
		t.Fatalf("risk = %+v", res.Risk)
	}

	joined := strings.Join(res.Summary, "\n")
	for _, want := range []string{
		"SHA-256 differs", "size 1000 -> 3000 bytes (+2000)", "tags added: upx", "tags removed: exe", "import hash changed",
		"section(s) added: UPX1", "section(s) removed: .gone", "section .text entropy 6.10 -> 7.80", "section .text flags RX -> RWX",
		"imports: +2 -1 functions", "exports: +1 -1", "strings: +1 new, -1 gone", "hardening aslr: enabled -> disabled",
		"new finding packing.upx (medium)", "finding gone x.gone (medium)", "finding x.bumped severity low -> high", "risk 5 (low) -> 50 (high), +45",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary lacks %q:\n%s", want, joined)
		}
	}
	for _, line := range res.Summary {
		for _, r := range line {
			if r > 0x7e {
				t.Errorf("summary must be ASCII: %q", line)
			}
		}
	}
}

func TestHashOnlyDifference(t *testing.T) {
	res := Compare(rep("a", "aa"), rep("b", "bb"))
	last := res.Summary[len(res.Summary)-1]
	if !strings.Contains(last, "no structural difference") {
		t.Fatalf("summary = %v", res.Summary)
	}
}

func TestListsAreCappedButCountsAreExact(t *testing.T) {
	a, b := rep("a", "aa"), rep("b", "bb")
	fns := make([]string, 0, 500)
	for i := range 500 {
		fns = append(fns, "f"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26))
	}
	b.Imports = []report.Import{{Library: "lib", Count: len(fns), Functions: fns}}
	res := Compare(a, b)
	unique := map[string]bool{}
	for _, f := range fns {
		unique[f] = true
	}
	if res.Imports.AddedCount != len(unique) || len(res.Imports.Added) != maxListed {
		t.Fatalf("added = %d listed, %d counted (want %d counted)", len(res.Imports.Added), res.Imports.AddedCount, len(unique))
	}
}

func TestJSONShapeIsStable(t *testing.T) {
	raw, err := json.Marshal(Compare(rep("a", "aa"), rep("b", "bb")))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "a", "b", "identical", "sections", "imports", "exports", "strings", "hardening", "findings", "risk", "summary", "limitations"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if strings.Contains(string(raw), "null") {
		t.Errorf("diff JSON must not contain null: %s", raw)
	}
}
