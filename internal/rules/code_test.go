package rules

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// fakeCode is a CodeSource that has a given number of call sites for chosen APIs.
type fakeCode struct {
	sites    map[string]int // "Library!Function" -> call sites
	complete bool
	asked    map[string]int // the limit each API was asked with
}

func (f *fakeCode) CallBlocks(api string, limit int) ([]report.CodeBlock, int) {
	if f.asked == nil {
		f.asked = map[string]int{}
	}
	f.asked[api] = limit
	n := f.sites[api]
	var blocks []report.CodeBlock
	for i := range min(n, limit) {
		blocks = append(blocks, report.CodeBlock{
			Kind: report.CodeKindDisasm, Title: fmt.Sprintf("call %d to %s in .text", i, api), Section: ".text",
			Lines:       []report.CodeLine{{Text: "call", Highlight: true}},
			Limitations: []string{"test"},
		})
	}
	return blocks, n
}

func (f *fakeCode) Complete() bool { return f.complete }

func titles(blocks []report.CodeBlock) []string {
	out := make([]string, len(blocks))
	for i, b := range blocks {
		out[i] = b.Title
	}
	return out
}

func injectionReport() *report.Report {
	r := base("dropper.exe", report.TypePE, report.FamilyExecutable, 40<<10)
	r.Imports = imports("KERNEL32.dll", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess")
	return r
}

func TestProcessInjectionGetsTheCodeOfTheChainFirst(t *testing.T) {
	src := &fakeCode{complete: true, sites: map[string]int{
		"KERNEL32.dll!VirtualAllocEx": 1, "KERNEL32.dll!WriteProcessMemory": 2, "KERNEL32.dll!CreateRemoteThread": 1, "KERNEL32.dll!OpenProcess": 3,
	}}
	res := EvaluateWith(injectionReport(), Options{Code: src})
	f := find(t, res.Findings, "imports.process-injection")

	// One call of each function first (allocate, write, execute, then the handle), then the second ones.
	want := []string{
		"call 0 to KERNEL32.dll!VirtualAllocEx in .text",
		"call 0 to KERNEL32.dll!WriteProcessMemory in .text",
		"call 0 to KERNEL32.dll!CreateRemoteThread in .text",
		"call 0 to KERNEL32.dll!OpenProcess in .text",
		"call 1 to KERNEL32.dll!WriteProcessMemory in .text",
		"call 1 to KERNEL32.dll!OpenProcess in .text",
		"call 2 to KERNEL32.dll!OpenProcess in .text",
	}
	if got := titles(f.Code); !slices.Equal(got, want) {
		t.Fatalf("blocks:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if last := f.Evidence[len(f.Evidence)-1]; last != "code: 7 call sites in .text (see the code blocks)" {
		t.Errorf("evidence line = %q", last)
	}
	for api, limit := range src.asked {
		if limit != callSitesPerAPI {
			t.Errorf("%s was asked for %d blocks, want %d", api, limit, callSitesPerAPI)
		}
	}
	if err := f.ValidateCode(); err != nil {
		t.Error(err)
	}
	if len(f.Limitations) != 3 {
		t.Errorf("every API has a call: no limitation is added, got %q", f.Limitations)
	}
}

func TestCodeAttachedToAFindingIsBounded(t *testing.T) {
	src := &fakeCode{complete: true, sites: map[string]int{
		"KERNEL32.dll!VirtualAllocEx": 40, "KERNEL32.dll!WriteProcessMemory": 40, "KERNEL32.dll!CreateRemoteThread": 40, "KERNEL32.dll!OpenProcess": 40,
	}}
	f := find(t, EvaluateWith(injectionReport(), Options{Code: src}).Findings, "imports.process-injection")
	if len(f.Code) != report.MaxCodeBlocks {
		t.Fatalf("%d blocks, want the cap of %d", len(f.Code), report.MaxCodeBlocks)
	}
	// Three rounds over the four functions fill the twelve blocks: nobody has more than three of them.
	count := map[string]int{}
	for _, b := range f.Code {
		count[strings.Fields(b.Title)[3]]++
	}
	for api, n := range count {
		if n != 3 {
			t.Errorf("%s has %d blocks, want 3 (%v)", api, n, count)
		}
	}
	if last := f.Evidence[len(f.Evidence)-1]; last != "code: 160 call sites in .text, the first 12 are shown (see the code blocks)" {
		t.Errorf("evidence line = %q", last)
	}
}

func TestFlaggedFunctionsWithoutACallAreSaid(t *testing.T) {
	// Only VirtualAllocEx is called anywhere.
	src := &fakeCode{complete: true, sites: map[string]int{"KERNEL32.dll!VirtualAllocEx": 1}}
	f := find(t, EvaluateWith(injectionReport(), Options{Code: src}).Findings, "imports.process-injection")
	if len(f.Code) != 1 {
		t.Fatalf("code = %d blocks", len(f.Code))
	}
	last := f.Limitations[len(f.Limitations)-1]
	// In the order of relevance: write, execute, then the handle.
	want := "No call was found for KERNEL32.dll!WriteProcessMemory, KERNEL32.dll!CreateRemoteThread, KERNEL32.dll!OpenProcess, so no code is shown for them."
	if last != want {
		t.Errorf("limitation = %q, want %q", last, want)
	}

	// None is called: the finding says so instead of staying silent, and says when the scan was cut short.
	for _, complete := range []bool{true, false} {
		src := &fakeCode{complete: complete, sites: map[string]int{}}
		f := find(t, EvaluateWith(injectionReport(), Options{Code: src}).Findings, "imports.process-injection")
		if len(f.Code) != 0 {
			t.Fatalf("code = %d blocks", len(f.Code))
		}
		last := f.Limitations[len(f.Limitations)-1]
		if !strings.HasPrefix(last, "No call to these functions was found") || strings.Contains(last, "cut short") == complete {
			t.Errorf("complete=%v: limitation = %q", complete, last)
		}
		for _, e := range f.Evidence {
			if strings.HasPrefix(e, "code:") {
				t.Errorf("no code, so no code evidence line: %q", e)
			}
		}
	}
}

func TestAttachingCodeChangesNeitherSeveritiesNorScore(t *testing.T) {
	r := peScenario()
	plain := Evaluate(r)
	src := &fakeCode{complete: true, sites: map[string]int{}}
	for _, lib := range r.Imports {
		for _, fn := range lib.Functions {
			src.sites[lib.Library+"!"+fn] = 2
		}
	}
	with := EvaluateWith(r, Options{Code: src})
	if plain.Risk.Score != with.Risk.Score || !slices.Equal(plain.Risk.Basis, with.Risk.Basis) {
		t.Errorf("risk changed: %+v vs %+v", plain.Risk, with.Risk)
	}
	if !slices.Equal(ids(plain.Findings), ids(with.Findings)) {
		t.Fatalf("finding ids changed: %v vs %v", ids(plain.Findings), ids(with.Findings))
	}
	attached := 0
	for i, f := range with.Findings {
		p := plain.Findings[i]
		if f.Severity != p.Severity || f.Confidence != p.Confidence || f.Title != p.Title || f.Category != p.Category {
			t.Errorf("%s: severity, confidence, title or category changed", f.ID)
		}
		if !strings.HasPrefix(f.ID, "imports.") {
			if len(f.Code) != 0 || !slices.Equal(f.Evidence, p.Evidence) {
				t.Errorf("%s is not an import finding but gained code or evidence", f.ID)
			}
			continue
		}
		if len(p.Code) != 0 {
			t.Errorf("%s: Evaluate must not attach code", f.ID)
		}
		if len(f.Code) > 0 {
			attached++
			if err := f.ValidateCode(); err != nil {
				t.Errorf("%s: %v", f.ID, err)
			}
		}
	}
	if attached < 5 {
		t.Errorf("only %d import findings got code: %v", attached, ids(with.Findings))
	}
}

func TestNoCodeSourceAttachesNothing(t *testing.T) {
	a, b := Evaluate(injectionReport()), EvaluateWith(injectionReport(), Options{})
	if len(a.Findings) != len(b.Findings) {
		t.Fatal("findings differ")
	}
	for i := range a.Findings {
		if len(a.Findings[i].Code) != 0 || len(b.Findings[i].Code) != 0 || !slices.Equal(a.Findings[i].Limitations, b.Findings[i].Limitations) {
			t.Errorf("%s: a missing source must leave the finding as the rules made it", a.Findings[i].ID)
		}
	}
}
