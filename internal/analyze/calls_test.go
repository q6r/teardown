package analyze

import (
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

func findingByID(t *testing.T, rep *report.Report, id string) report.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %q not found in %v", id, findingIDs(rep))
	return report.Finding{}
}

// highlighted returns the highlighted line of a block.
func highlighted(t *testing.T, b report.CodeBlock) report.CodeLine {
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

// TestDropperInjectionFindingShowsTheCalls is the end-to-end check of the code
// evidence: the sample dropper imports the process-injection chain and its code
// calls it, so the finding carries the three call sites. The addresses were
// worked out by hand from the code the fixture documents (a stub that starts at
// .text offset 0x10, after the entry code) by adding up the lengths of its
// instructions: VirtualAllocEx is called at offset 0xe9, WriteProcessMemory at
// 0x114 and CreateRemoteThread at 0x144, and each displacement leads to the
// slot of its import in the address table at RVA 0x2188.
func TestDropperInjectionFindingShowsTheCalls(t *testing.T) {
	rep := analyzeBytes(t, "dropper.bin", testfixtures.SamplePE())
	f := findingByID(t, rep, "imports.process-injection")
	if f.Severity != report.SeverityHigh || f.Confidence != report.ConfidenceMedium {
		t.Errorf("the code must not change the verdict: %s/%s", f.Severity, f.Confidence)
	}
	if err := f.ValidateCode(); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		api, bytes, text string
		addr             report.Addr
		offset           int64
	}{
		// The six section headers push the raw data of .text to file offset 0x400.
		{"KERNEL32.dll!VirtualAllocEx", "ff 15 b1 10 00 00", "call qword ptr [rip+0x10b1]", 0x1400010e9, 0x4e9},
		{"KERNEL32.dll!WriteProcessMemory", "ff 15 8e 10 00 00", "call qword ptr [rip+0x108e]", 0x140001114, 0x514},
		{"KERNEL32.dll!CreateRemoteThread", "ff 15 66 10 00 00", "call qword ptr [rip+0x1066]", 0x140001144, 0x544},
		{"KERNEL32.dll!OpenProcess", "ff 15 ef 10 00 00", "call qword ptr [rip+0x10ef]", 0x1400010c3, 0x4c3},
	}
	if len(f.Code) != len(want) {
		t.Fatalf("%d code blocks, want %d: %v", len(f.Code), len(want), blockTitles(f.Code))
	}
	for i, w := range want {
		b := f.Code[i]
		hit := highlighted(t, b)
		if b.Kind != report.CodeKindDisasm || b.Title != "call to "+w.api+" in .text" || b.Section != ".text" || b.Arch != "x86-64" {
			t.Errorf("block %d = %q (%s, %s, %s)", i, b.Title, b.Kind, b.Section, b.Arch)
		}
		if hit.Address != w.addr || hit.Offset != w.offset || hit.Bytes != w.bytes || hit.Text != w.text || hit.Note != w.api {
			t.Errorf("block %d highlighted line = %+v, want %s %s at %v", i, hit, w.bytes, w.text, w.addr)
		}
		if len(b.Limitations) == 0 || b.Truncated {
			t.Errorf("block %d: limitations %q, truncated %v", i, b.Limitations, b.Truncated)
		}
	}
	if last := f.Evidence[len(f.Evidence)-1]; last != "code: 4 call sites in .text (see the code blocks)" {
		t.Errorf("evidence = %q", f.Evidence)
	}
	// The arguments are visible: the block of VirtualAllocEx shows the constants set up for it.
	var texts []string
	for _, l := range f.Code[0].Lines {
		texts = append(texts, l.Text)
	}
	for _, line := range []string{"mov r8d, 0x1000", "mov r9d, 0x3000", "mov dword ptr [rsp+0x20], 0x40"} {
		if !slices.Contains(texts, line) {
			t.Errorf("the VirtualAllocEx block lacks %q: %q", line, texts)
		}
	}
}

func blockTitles(blocks []report.CodeBlock) []string {
	var out []string
	for _, b := range blocks {
		out = append(out, b.Title)
	}
	return out
}

func TestDropperOtherImportFindings(t *testing.T) {
	rep := analyzeBytes(t, "dropper.bin", testfixtures.SamplePE())

	dl := findingByID(t, rep, "imports.download-and-execute")
	if got := blockTitles(dl.Code); !slices.Equal(got, []string{
		"call to URLMON.dll!URLDownloadToFileA in .text", "call to KERNEL32.dll!CreateProcessW through a thunk in .text",
	}) {
		t.Errorf("download-and-execute blocks = %q", got)
	}
	thunk := highlighted(t, dl.Code[1])
	if !strings.HasPrefix(thunk.Text, "call 0x") || !strings.Contains(thunk.Note, "through the thunk at 0x") {
		t.Errorf("thunk call line = %+v", thunk)
	}

	// The sample imports crypto functions that no code calls: the finding says so.
	crypto := findingByID(t, rep, "imports.crypto")
	last := crypto.Limitations[len(crypto.Limitations)-1]
	if len(crypto.Code) != 0 || !strings.HasPrefix(last, "No call to these functions was found") {
		t.Errorf("crypto: %d blocks, last limitation %q", len(crypto.Code), last)
	}

	// Functions that are only partly called are named.
	key := findingByID(t, rep, "imports.keylogging")
	if len(key.Code) != 2 || !strings.Contains(key.Limitations[len(key.Limitations)-1], "GetForegroundWindow") {
		t.Errorf("keylogging: %d blocks, limitations %q", len(key.Code), key.Limitations)
	}

	for _, f := range rep.Findings {
		if err := f.ValidateCode(); err != nil {
			t.Error(err)
		}
		if !strings.HasPrefix(f.ID, "imports.") && f.Category == report.CategoryImports {
			t.Errorf("unexpected import finding %s", f.ID)
		}
	}
}

// TestCodeEvidenceSurvivesHostileInput analyses every Nth prefix of the sample
// and copies with damaged code: whatever happens, the report is complete and
// every block it carries is valid.
func TestCodeEvidenceSurvivesHostileInput(t *testing.T) {
	good := testfixtures.SamplePE()
	check := func(name string, data []byte) {
		rep := analyzeBytes(t, "x.exe", data)
		for _, f := range rep.Findings {
			if err := f.ValidateCode(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	for n := 0; n <= 0x900; n += 41 {
		check("prefix", good[:n])
	}
	for i := 0x200; i < 0x400; i += 3 {
		for _, v := range []byte{0x00, 0xff, 0x0f} {
			data := slices.Clone(good)
			data[i] = v
			check("damaged", data)
		}
	}
}

// TestNonX86ImagesGetNoCode: an image whose machine type is not x86 or x86-64
// is analysed as before, without code and without noise.
func TestNonX86ImagesGetNoCode(t *testing.T) {
	data := slices.Clone(testfixtures.SamplePE())
	data[testfixtures.PEOffset+4], data[testfixtures.PEOffset+5] = 0x64, 0xaa // IMAGE_FILE_MACHINE_ARM64
	rep := analyzeBytes(t, "arm.exe", data)
	f := findingByID(t, rep, "imports.process-injection")
	if len(f.Code) != 0 || strings.Contains(strings.Join(f.Limitations, " "), "No call") {
		t.Errorf("ARM64 image: %d blocks, limitations %q", len(f.Code), f.Limitations)
	}
	for _, x := range rep.Findings {
		if x.ID == "parser.error" || x.ID == "analysis.incomplete" {
			t.Errorf("unexpected %s: %v", x.ID, x.Evidence)
		}
	}
}
