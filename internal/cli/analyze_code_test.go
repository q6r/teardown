package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

// codeBlockTitle is the title of the n-th code block of codeReport.
func codeBlockTitle(n int) string { return fmt.Sprintf("Call site %d of VirtualAllocEx", n) }

// codeReport is a report whose one finding carries five disassembly blocks of
// three lines each, with the middle line flagged.
func codeReport() *report.Report {
	r := report.New("dropper.bin", 4096, "test")
	r.Type = report.Type{ID: report.TypePE, Family: report.FamilyExecutable, Label: "PE32+ executable (x86-64)", MIME: "application/vnd.microsoft.portable-executable", Confidence: report.ConfidenceHigh}
	var blocks []report.CodeBlock
	for n := 1; n <= 5; n++ {
		base := report.Addr(0x140001000 + n*0x100)
		blocks = append(blocks, report.CodeBlock{
			Kind: report.CodeKindDisasm, Title: codeBlockTitle(n), Section: ".text", Offset: int64(0x400 + n*0x100), Address: base, Arch: "x86-64",
			Lines: []report.CodeLine{
				{Address: base, Offset: int64(0x400 + n*0x100), Bytes: "31 c0", Text: "xor eax, eax"},
				{Address: base + 2, Offset: int64(0x402 + n*0x100), Bytes: "ff 15 b7 1f 00 00", Text: "call qword ptr [rip+0x1fb7]", Note: "KERNEL32.dll!VirtualAllocEx", Highlight: true},
				{Address: base + 8, Offset: int64(0x408 + n*0x100), Bytes: "c3", Text: "ret"},
			},
			Limitations: []string{"Linear sweep: data can be shown as code."},
		})
	}
	r.Findings = []report.Finding{{
		ID: "imports.process-injection", Title: "Imports cover the full process-injection chain", Severity: report.SeverityHigh,
		Category: report.CategoryImports, Confidence: report.ConfidenceMedium, Evidence: []string{"VirtualAllocEx"}, Code: blocks,
		Limitations: []string{"An import is not a call."},
	}}
	r.Risk = report.Risk{Score: 40, Label: report.RiskMedium, Basis: []string{"one high finding"}}
	r.Normalize()
	return r
}

// runStubbed runs the CLI with an analysis that returns rep whatever the file.
func runStubbed(t *testing.T, rep *report.Report, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(string) string { return "" },
		IsTTY:  func(io.Writer) bool { return false },
		Now:    func() time.Time { return fixedNow },
		Analyze: func(context.Context, string, analyze.Options) (*report.Report, error) {
			cp := *rep
			return &cp, nil
		},
	}
	code := Run(context.Background(), args, env)
	return result{code, out.String(), errb.String()}
}

func titlesIn(s string) []int {
	var found []int
	for n := 1; n <= 5; n++ {
		if strings.Contains(s, codeBlockTitle(n)) {
			found = append(found, n)
		}
	}
	return found
}

func TestAnalyzeShowsTheCodeBehindFindingsAndHonoursTheFlags(t *testing.T) {
	input := write(t, "dropper.bin", []byte("x"))
	rep := codeReport()

	def := runStubbed(t, rep, "analyze", input)
	if def.code != exitOK {
		t.Fatalf("exit %d: %s", def.code, def.err)
	}
	if got := titlesIn(def.out); fmt.Sprint(got) != "[1 2 3]" {
		t.Errorf("the default shows the first %d blocks, got %v:\n%s", 3, got, def.out)
	}
	for _, want := range []string{"code: 5 blocks", "call qword ptr [rip+0x1fb7]", "; KERNEL32.dll!VirtualAllocEx", "(+2 more code blocks, see --code-all or --json)", "limits: Linear sweep"} {
		if !strings.Contains(def.out, want) {
			t.Errorf("the default output lacks %q:\n%s", want, def.out)
		}
	}

	all := runStubbed(t, rep, "analyze", input, "--code-all")
	if got := titlesIn(all.out); fmt.Sprint(got) != "[1 2 3 4 5]" || strings.Contains(all.out, "more code block") {
		t.Errorf("--code-all must show every block, got %v:\n%s", got, all.out)
	}

	none := runStubbed(t, rep, "analyze", input, "--no-code")
	if none.code != exitOK || len(titlesIn(none.out)) != 0 || strings.Contains(none.out, "code:") || strings.Contains(none.out, "VirtualAllocEx") && strings.Contains(none.out, "call qword") {
		t.Errorf("--no-code must leave the code out:\n%s", none.out)
	}
	if !strings.Contains(none.out, "imports.process-injection") {
		t.Errorf("--no-code must keep the finding itself:\n%s", none.out)
	}

	both := runStubbed(t, rep, "analyze", input, "--no-code", "--code-all")
	if both.code != exitUsage || !strings.Contains(both.err, "choose one of --no-code or --code-all") {
		t.Errorf("exit %d stderr %q", both.code, both.err)
	}
}

func TestAnalyzeNoCodeAppliesToEveryOutputFormat(t *testing.T) {
	input := write(t, "dropper.bin", []byte("x"))
	rep := codeReport()

	t.Run("json keeps all the blocks by default", func(t *testing.T) {
		r := runStubbed(t, rep, "analyze", input, "--json")
		var got report.Report
		if err := json.Unmarshal([]byte(r.out), &got); err != nil {
			t.Fatal(err)
		}
		if r.code != exitOK || len(got.Findings) != 1 || len(got.Findings[0].Code) != 5 {
			t.Fatalf("exit %d, code blocks %d", r.code, len(got.Findings[0].Code))
		}
		if b := got.Findings[0].Code[0]; b.Lines[1].Address != 0x140001102 || !b.Lines[1].Highlight || b.Lines[1].Note != "KERNEL32.dll!VirtualAllocEx" {
			t.Errorf("block 0 = %+v", b)
		}
		if !strings.Contains(r.out, `"address": "0x140001102"`) {
			t.Errorf("addresses must be strings:\n%s", r.out)
		}
	})
	t.Run("json without code has no code member", func(t *testing.T) {
		r := runStubbed(t, rep, "analyze", input, "--json", "--no-code")
		if r.code != exitOK || strings.Contains(r.out, `"code"`) || strings.Contains(r.out, "VirtualAllocEx") && strings.Contains(r.out, "call qword") {
			t.Errorf("exit %d:\n%s", r.code, r.out)
		}
		var got report.Report
		if err := json.Unmarshal([]byte(r.out), &got); err != nil || len(got.Findings) != 1 {
			t.Errorf("the report must stay valid and keep its findings: %v", err)
		}
	})
	t.Run("markdown", func(t *testing.T) {
		with := runStubbed(t, rep, "analyze", input, "--md")
		without := runStubbed(t, rep, "analyze", input, "--md", "--no-code")
		if !strings.Contains(with.out, codeBlockTitle(1)) || strings.Contains(without.out, codeBlockTitle(1)) || strings.Contains(without.out, "call qword") {
			t.Errorf("with:\n%s\nwithout:\n%s", with.out, without.out)
		}
	})
	t.Run("sarif", func(t *testing.T) {
		with := runStubbed(t, rep, "analyze", input, "--sarif")
		without := runStubbed(t, rep, "analyze", input, "--sarif", "--no-code")
		if with.code != exitOK || without.code != exitOK || !json.Valid([]byte(without.out)) || strings.Contains(without.out, "call qword") {
			t.Errorf("exit %d/%d:\n%s", with.code, without.code, without.out)
		}
	})
	t.Run("html", func(t *testing.T) {
		dir := t.TempDir()
		withFile, withoutFile := filepath.Join(dir, "with.html"), filepath.Join(dir, "without.html")
		if r := runStubbed(t, rep, "analyze", input, "--html", withFile); r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		if r := runStubbed(t, rep, "analyze", input, "--html", withoutFile, "--no-code"); r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		with, _ := os.ReadFile(withFile)
		without, _ := os.ReadFile(withoutFile)
		if !bytes.Contains(with, []byte(codeBlockTitle(1))) || bytes.Contains(without, []byte(codeBlockTitle(1))) || bytes.Contains(without, []byte("call qword")) {
			t.Errorf("--html must carry the code blocks and --no-code must remove them (%d vs %d bytes)", len(with), len(without))
		}
	})
	t.Run("the gate ignores the code", func(t *testing.T) {
		for _, flag := range []string{"--no-code", "--code-all"} {
			if r := runStubbed(t, rep, "analyze", input, flag, "--fail-on", "high"); r.code != exitFailOn {
				t.Errorf("%s: exit %d", flag, r.code)
			}
		}
	})
	if rep.Findings[0].Code == nil || len(rep.Findings[0].Code) != 5 {
		t.Error("the report given to the command must not be modified")
	}
}
