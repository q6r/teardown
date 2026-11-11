package analyze_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// This is an external test package because the renderers import package analyze.

// golden compares got with testdata/name, or rewrites the file when the -update
// flag of the package's tests is set.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if f := flag.Lookup("update"); f != nil && f.Value.String() == "true" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (create it with: go test ./internal/analyze -run TestDropperGolden -update)", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the output:\n%s\n(rewrite it with: go test ./internal/analyze -run TestDropperGolden -update)", path, got)
	}
}

// TestDropperGolden pins how the call sites of the dropper read in every output
// that shows code: the JSON of the finding and its text and Markdown renderings.
func TestDropperGolden(t *testing.T) {
	data := testfixtures.SamplePE()
	fixed := func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }
	rep, err := analyze.Reader(context.Background(), bytes.NewReader(data), int64(len(data)), analyze.Options{Name: "dropper.bin", Now: fixed})
	if err != nil {
		t.Fatal(err)
	}
	var f report.Finding
	for _, x := range rep.Findings {
		if x.ID == "imports.process-injection" {
			f = x
		}
	}
	if f.ID == "" || len(f.Code) == 0 {
		t.Fatal("the dropper has no process-injection finding with code")
	}

	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "dropper-injection.json", string(raw)+"\n")

	// A report that holds only this finding keeps the goldens independent of the rest of the analysis.
	one := report.New("dropper.bin", int64(len(data)), "0.2.0")
	one.GeneratedAt = rep.GeneratedAt
	one.Type = rep.Type
	one.Findings = []report.Finding{f}
	one.Risk = report.Risk{Score: 14, Label: report.RiskLow, Basis: []string{"+14  imports.process-injection (high severity, medium confidence)"}}
	one.Normalize()

	var text bytes.Buffer
	if err := render.Text(&text, one, render.Options{Width: 100, CodeAll: true}); err != nil {
		t.Fatal(err)
	}
	golden(t, "dropper-injection.txt", text.String())
	var md bytes.Buffer
	if err := render.Markdown(&md, one); err != nil {
		t.Fatal(err)
	}
	golden(t, "dropper-injection.md", md.String())

	var page bytes.Buffer
	if err := render.HTML(&page, one); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"call to KERNEL32.dll!VirtualAllocEx in .text", "call qword ptr [rip+0x10b1]"} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("the HTML report lacks %q", want)
		}
	}
}
