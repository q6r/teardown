package render

import (
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

func rowsBlock() report.CodeBlock {
	return report.CodeBlock{
		Kind: report.CodeKindDisasm, Title: "call to KERNEL32.dll!VirtualAllocEx in .text", Section: ".text", Address: 0x140001042, Arch: "x86-64",
		Lines: []report.CodeLine{
			{Address: 0x140001042, Offset: 0x442, Bytes: "31 d2", Text: "xor edx, edx"},
			{Address: 0x140001044, Offset: 0x444, Bytes: "ff 15 b7 1f 00 00", Text: "call qword ptr [rip+0x1fb7]", Note: "KERNEL32.dll!VirtualAllocEx", Highlight: true},
			{Address: 0x14000104a, Offset: 0x44a, Bytes: "c3", Text: "ret"},
		},
		Limitations: []string{"Linear sweep: data can be shown as code.", "Not a decompiler."},
	}
}

func TestCodeRowsAreTheRowsOfTheReport(t *testing.T) {
	rows := CodeRows(rowsBlock(), Options{})
	// The bytes column is as wide as the widest line (17 characters) plus two spaces.
	want := []string{
		"  0x140001042  31 d2" + strings.Repeat(" ", 14) + "xor edx, edx",
		"> 0x140001044  ff 15 b7 1f 00 00  call qword ptr [rip+0x1fb7]  ; KERNEL32.dll!VirtualAllocEx",
		"  0x14000104a  c3" + strings.Repeat(" ", 17) + "ret",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}

	// They are the very rows the terminal report prints under a finding.
	var sb strings.Builder
	rep := report.New("a.exe", 1, "test")
	rep.Findings = []report.Finding{{ID: "x.y", Title: "t", Severity: report.SeverityInfo, Category: report.CategoryImports, Confidence: report.ConfidenceLow, Code: []report.CodeBlock{rowsBlock()}}}
	if err := Text(&sb, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if !strings.Contains(sb.String(), "          "+r+"\n") {
			t.Errorf("the report does not print the row %q", r)
		}
	}

	if coloured := CodeRows(rowsBlock(), Options{Color: true}); !strings.Contains(strings.Join(coloured, "\n"), "\x1b[") {
		t.Error("colour is applied when asked for")
	}
}

func TestCodeRowsNeverPrintControlCharacters(t *testing.T) {
	// Built in code: an escape typed in a source file can be decoded by an editor
	// into the character itself, which this test must not contain.
	bidiOverride, nextLine, lineSeparator := string(rune(0x202e)), string(rune(0x85)), string(rune(0x2028))
	b := rowsBlock()
	b.Lines[1].Text = "call \x1b[31mevil" + bidiOverride + nextLine
	b.Lines[1].Note = "KERNEL32.dll!\x1b]0;title\x07"
	b.Limitations = []string{"limit \x1b[2J" + lineSeparator}
	all := strings.Join(CodeRows(b, Options{}), "\n") + strings.Join(CodeLimits([]report.CodeBlock{b}, Options{}), "\n")
	for _, c := range all {
		if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || c == 0x202e || c == 0x2028) {
			t.Errorf("the output carries the character %U: %q", c, all)
		}
	}
}

func TestCodeRowsKeepTheCapsOfTheModel(t *testing.T) {
	b := rowsBlock()
	b.Lines = nil
	for i := range 200 {
		b.Lines = append(b.Lines, report.CodeLine{Address: report.Addr(0x1000 + i), Offset: int64(i), Text: "nop", Highlight: i == 150})
	}
	rows := CodeRows(b, Options{})
	if len(rows) != report.MaxCodeLines {
		t.Fatalf("%d rows, the cap is %d", len(rows), report.MaxCodeLines)
	}
	flagged := 0
	for _, r := range rows {
		if strings.HasPrefix(r, "> ") {
			flagged++
		}
	}
	if flagged != 1 {
		t.Errorf("the window around the flagged line must keep it: %d flagged rows", flagged)
	}
}

func TestCodeLimitsSaysEachOnceAndWraps(t *testing.T) {
	a, b := rowsBlock(), rowsBlock()
	b.Limitations = []string{"Not a decompiler.", "A second block's own limit that is long enough to wrap onto a second line when the terminal is narrow, as limits often are."}
	got := CodeLimits([]report.CodeBlock{a, b}, Options{Width: 60})
	text := strings.Join(got, "\n")
	if strings.Count(text, "Not a decompiler.") != 1 || strings.Count(text, "Linear sweep") != 1 {
		t.Errorf("each limitation is said once:\n%s", text)
	}
	if !strings.HasPrefix(got[0], "limits: Linear sweep") {
		t.Errorf("first line = %q", got[0])
	}
	for _, l := range got {
		if len([]rune(l)) > 60 {
			t.Errorf("line %q is wider than the terminal (60)", l)
		}
	}
	var wrapped []string
	for _, l := range got {
		if strings.HasPrefix(l, "        ") {
			wrapped = append(wrapped, l)
		}
	}
	if len(wrapped) == 0 {
		t.Errorf("a long limitation wraps onto aligned continuation lines:\n%s", text)
	}
	if CodeLimits(nil, Options{}) != nil {
		t.Error("no blocks, no limits")
	}
}
