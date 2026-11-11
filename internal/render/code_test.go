package render

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/web"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/name, or rewrites the file with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (create the golden files with: go test ./internal/render -run TestGolden -update)", path, err)
	}
	want := string(raw)
	if got == want {
		return
	}
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < max(len(g), len(w)); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			t.Fatalf("%s differs at line %d (regenerate with -update if the change is intended):\n got %q\nwant %q", path, i+1, gl, wl)
		}
	}
}

func renderText(t *testing.T, rep *report.Report, o Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Text(&buf, rep, o); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func renderMarkdown(t *testing.T, rep *report.Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestCodeSampleIsAValidModel keeps the sample honest: it must obey the rules it exists to exercise.
func TestCodeSampleIsAValidModel(t *testing.T) {
	rep := codeSampleReport()
	blocks := 0
	for _, f := range rep.Findings {
		if err := f.ValidateCode(); err != nil {
			t.Errorf("%v", err)
		}
		blocks += len(f.Code)
	}
	if blocks != 6 {
		t.Errorf("the sample has %d blocks, want 6 (four call sites, one hex window, one script)", blocks)
	}
}

// asmRow spells one row of the first sample block the way the terminal prints
// it: a two-character mark, the address, the bytes padded to the widest row of
// the block (23 characters) and the instruction.
func asmRow(mark, addr, bytes, text string) string {
	return mark + addr + "  " + bytes + strings.Repeat(" ", 23-len(bytes)) + "  " + text
}

func TestTextShowsTheCodeBehindAFinding(t *testing.T) {
	rep := codeSampleReport()
	out := renderText(t, rep, Options{Width: 100})
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("plain output must not contain escape bytes")
	}
	for _, want := range []string{
		"      code: 4 blocks",
		"Call site of KERNEL32.dll!VirtualAllocEx  (.text · 0x14000101c · x86-64)",
		"Call site of KERNEL32.dll!WriteProcessMemory", "Call site of KERNEL32.dll!CreateRemoteThread",
		asmRow("> ", "0x140001036", "ff 15 c4 1f 00 00", "call qword ptr [rip+0x1fc4]  ; KERNEL32.dll!VirtualAllocEx"),
		asmRow("  ", "0x14000103c", "48 89 45 f0", "mov qword ptr [rbp-0x10], rax"),
		"(+1 more code block, see --code-all or --json)",
		"Bytes around the URL at file offset 0x1a58  (.rdata · file offset 0x1a40)",
		"> 00001a50  6e 74 3a 20 00 00 00 00 68 74 74 70 3a 2f 2f 32  |nt: ....http://2|",
		"  00001a40  00 00 00 00 00 00 00 00 55 73 65 72 2d 41 67 65  |........User-Age|",
		"Window settings in the main process  (app/main.js)",
		"> 18 | ", "  15 | const { app, BrowserWindow } = require('electron');",
		"limits: x86 and x86-64 only: other instruction sets are not decoded.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q", want)
		}
	}
	if strings.Contains(out, "Call site of KERNEL32.dll!OpenProcess") {
		t.Error("the fourth block must stay hidden without CodeAll")
	}
	if n := strings.Count(out, "limits: "); n != 3 {
		t.Errorf("%d limits lines, want one for each of the three findings with code", n)
	}
	if strings.Contains(out, "A linear sweep") {
		t.Error("the default output states only the first limitation, like the finding does")
	}
	if verbose := renderText(t, rep, Options{Verbose: true}); !strings.Contains(verbose, "A linear sweep: data inside a code section") {
		t.Error("-v states every limitation of the code")
	}
	// Findings without code print exactly what they printed before.
	if !strings.Contains(out, "hardening.no-cfg") {
		t.Fatal("the finding without code is missing")
	}
}

func TestTextAlignsTheColumnsOfABlock(t *testing.T) {
	rep := codeSampleReport()
	out := renderText(t, rep, Options{Width: 100})
	rows := 0
	for _, line := range codeSection(out) {
		for _, l := range rep.Findings[0].Code[0].Lines {
			if !strings.Contains(line, l.Address.String()+"  ") {
				continue
			}
			rows++
			if got := strings.Index(line, l.Text); got != 50 {
				t.Errorf("the instruction %q starts at column %d, want 50 in:\n%s", l.Text, got, line)
			}
			if got := strings.Index(line, l.Bytes); got != 25 {
				t.Errorf("the bytes of %q start at column %d, want 25 in:\n%s", l.Text, got, line)
			}
		}
	}
	if rows != 9 {
		t.Fatalf("found %d rows of the first block, want 9", rows)
	}
}

func TestTextCodeOptions(t *testing.T) {
	rep := codeSampleReport()
	all := renderText(t, rep, Options{CodeAll: true})
	if !strings.Contains(all, "Call site of KERNEL32.dll!OpenProcess") || strings.Contains(all, "more code blocks") {
		t.Errorf("CodeAll shows all four blocks and no hint:\n%s", all)
	}

	hidden := renderText(t, rep, Options{HideCode: true, CodeAll: true})
	if strings.Contains(hidden, "code:") || strings.Contains(hidden, "0x140001036") || strings.Contains(hidden, "limits:") {
		t.Errorf("HideCode leaves no code in the output:\n%s", hidden)
	}
	if hidden != renderText(t, rep.WithoutCode(), Options{}) {
		t.Error("hiding the code must give the output of a report that has none")
	}
	for _, f := range rep.Findings {
		if len(f.Code) == 0 {
			continue
		}
		if !strings.Contains(hidden, f.ID) {
			t.Errorf("hiding the code must not hide finding %s", f.ID)
		}
	}
	if len(rep.Findings[0].Code) != 4 {
		t.Error("rendering must not change the report")
	}
}

func TestTextKeepsTheFlaggedLineInTheWindow(t *testing.T) {
	long := report.CodeBlock{Kind: report.CodeKindDisasm, Title: "a long function", Limitations: []string{"x"}}
	for i := range 64 {
		long.Lines = append(long.Lines, report.CodeLine{Address: report.Addr(0x1000 + i), Offset: int64(i), Bytes: "90", Text: "nop", Highlight: i == 50})
	}
	rep := report.New("x", 1, "dev")
	rep.Findings = []report.Finding{{ID: "a.b", Title: "t", Severity: report.SeverityLow, Evidence: []string{"e"}, Code: []report.CodeBlock{long}}}

	out := renderText(t, rep, Options{})
	rows := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "          ") && strings.Contains(l, "nop") {
			rows++
		}
	}
	if rows != DefaultCodeLines {
		t.Errorf("%d rows shown, want %d", rows, DefaultCodeLines)
	}
	if !strings.Contains(out, "> 0x1032  90") {
		t.Errorf("the flagged line fell out of the window:\n%s", out)
	}
	if !strings.Contains(out, "(lines 39-62 of 64: --code-all shows the whole block, --json has it all)") {
		t.Errorf("the output must say which lines it shows:\n%s", out)
	}
	if all := renderText(t, rep, Options{CodeAll: true}); strings.Contains(all, "(lines ") || strings.Count(all, "nop") != 64 {
		t.Errorf("CodeAll shows the whole block (64 lines)")
	}
}

func TestTextCodeColourAddsOnlyEmphasis(t *testing.T) {
	rep := codeSampleReport()
	plain := renderText(t, rep, Options{})
	coloured := renderText(t, rep, Options{Color: true})
	if !strings.ContainsRune(coloured, 0x1b) {
		t.Fatal("colour output must contain escape sequences")
	}
	if stripped := ansi.ReplaceAllString(coloured, ""); stripped != plain {
		t.Error("colours must not change a single visible character of the output")
	}
}

func TestTextCodeInASCIIMode(t *testing.T) {
	out := renderText(t, codeSampleReport(), Options{ASCII: true, Width: 100})
	for _, want := range []string{"(.text | 0x14000101c | x86-64)", "(app/main.js)"} {
		if !strings.Contains(out, want) {
			t.Errorf("ASCII output lacks %q", want)
		}
	}
	for _, line := range codeSection(out) {
		if strings.Contains(line, "·") {
			t.Errorf("ASCII mode printed a middle dot in a code heading: %q", line)
		}
	}
}

func TestTextHandlesBlocksThatCannotBeShown(t *testing.T) {
	rep := report.New("x", 1, "dev")
	rep.Findings = []report.Finding{{ID: "a.b", Title: "t", Severity: report.SeverityLow, Evidence: []string{"e"}, Code: []report.CodeBlock{{Kind: report.CodeKindDisasm}, {Kind: "future", Title: "something new", Lines: []report.CodeLine{{Text: "x", Highlight: true}}}}}}
	out := renderText(t, rep, Options{})
	if strings.Contains(out, "code: 2 blocks") || !strings.Contains(out, "code: 1 block\n") {
		t.Errorf("a block without lines is dropped and an unknown kind is still shown:\n%s", out)
	}
	if !strings.Contains(out, "something new") || !strings.Contains(out, "limits: The producer of this block stated no limits") {
		t.Errorf("an unknown kind is shown as plain lines with the stated default limits:\n%s", out)
	}
	rep.Findings[0].Code = []report.CodeBlock{{Kind: report.CodeKindDisasm}}
	if out := renderText(t, rep, Options{}); strings.Contains(out, "code:") {
		t.Errorf("a finding whose only block is empty prints no code section:\n%s", out)
	}
}

// hostileCode carries attacker-controlled text in every field of two blocks, all
// within the caps, so a renderer that mishandles any of them shows up.
func hostileCode() []report.CodeBlock {
	lineSep, paraSep, rlo := string(rune(0x2028)), string(rune(0x2029)), string(rune(0x202e))
	closer := "</script><img src=x onerror=alert(1)>"
	fence := "```" + "\n# pwned\n"
	return []report.CodeBlock{
		{
			Kind: report.CodeKindDisasm, Title: closer + rlo + "gnp", File: "a.js\n" + fence, Section: lineSep + paraSep, Arch: "x86-64\x1b[31m",
			Offset: 8, Address: 0x1000,
			Lines: []report.CodeLine{
				{Address: 0x1000, Offset: 8, Bytes: "90", Text: "nop" + closer, Note: "<!--" + rlo + "\x1b]0;pwned\x07"},
				{Address: 0x1001, Offset: 9, Bytes: "c3", Text: "ret" + lineSep + "x" + paraSep + "y" + fence + "```` ```", Highlight: true},
			},
			Limitations: []string{closer, "x" + lineSep + "\x1b[2J"},
		},
		{
			Kind: report.CodeKindSource, Title: fence, File: "a.js\n```evil", Offset: 3,
			Lines:       []report.CodeLine{{Offset: 3, Line: 1, Text: "eval('\x00\x07\x7f')" + closer + strings.Repeat("A", 100)}},
			Limitations: []string{"plain text"},
		},
	}
}

func TestTextNeutralisesHostileCode(t *testing.T) {
	rep := codeSampleReport()
	rep.Findings[0].Code = hostileCode()
	out := renderText(t, rep, Options{Color: true, CodeAll: true})
	stripped := ansi.ReplaceAllString(out, "")
	for _, bad := range []string{"\x1b", "\x07", "\x00", "\x7f", string(rune(0x2028)), string(rune(0x2029)), string(rune(0x202e))} {
		if strings.Contains(stripped, bad) {
			t.Errorf("the output contains the raw character %q", bad)
		}
	}
	for _, want := range []string{`\x1b[31m`, "[U+2028]", "[U+2029]", "[U+202E]", `\x0a`, `\x00\x07\x7f`} {
		if !strings.Contains(stripped, want) {
			t.Errorf("the hostile character must be spelled out as %q", want)
		}
	}
}

func TestTextBoundsHugeCode(t *testing.T) {
	huge := report.CodeBlock{Kind: report.CodeKindDisasm, Title: strings.Repeat("t", 100000), Limitations: []string{strings.Repeat("l", 100000)}}
	for i := range 1000 {
		huge.Lines = append(huge.Lines, report.CodeLine{Address: report.Addr(i), Bytes: strings.Repeat("ab ", 500), Text: strings.Repeat("x", 100000), Note: strings.Repeat("n", 100000)})
	}
	rep := report.New("x", 1, "dev")
	f := report.Finding{ID: "a.b", Title: "t", Severity: report.SeverityLow, Evidence: []string{"e"}}
	for range 3000 {
		f.Code = append(f.Code, huge)
	}
	rep.Findings = []report.Finding{f}
	for name, o := range map[string]Options{"default": {}, "all": {CodeAll: true}, "verbose": {Verbose: true, CodeAll: true}} {
		out := renderText(t, rep, o)
		if limit := 400 << 10; len(out) > limit {
			t.Errorf("%s: %d KiB of output for a hostile report, want at most %d KiB", name, len(out)>>10, limit>>10)
		}
		if !strings.Contains(out, "code: 3000 blocks") || !strings.Contains(out, "more code blocks") {
			t.Errorf("%s: the output must say how much code there is and that it is not all shown", name)
		}
	}
}

func TestMarkdownShowsCodeAsFencedBlocks(t *testing.T) {
	out := renderMarkdown(t, codeSampleReport())
	for _, want := range []string{
		"Code:\n\n#### Code: Call site of KERNEL32.dll!VirtualAllocEx\n\n.text · 0x14000101c · x86-64\n\n```asm\n  0x14000101c  48 8b 4d f8",
		asmRow("> ", "0x140001036", "ff 15 c4 1f 00 00", "call qword ptr [rip+0x1fc4]  ; KERNEL32.dll!VirtualAllocEx\n"),
		"#### Code: Call site of KERNEL32.dll!OpenProcess", // Markdown shows every block
		"```text\n  00001a40  00 00 00 00 00 00 00 00 55 73 65 72 2d 41 67 65  |........User-Age|\n> 00001a50",
		"```js\n  15 | const { app, BrowserWindow } = require('electron');\n  16 |\n  17 | function createWindow() {\n> 18 |",
		"Limitations of the code shown:\n\n- x86 and x86-64 only: other instruction sets are not decoded.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the Markdown lacks %q", want)
		}
	}
	if n := strings.Count(out, "- x86 and x86-64 only"); n != 1 {
		t.Errorf("the limitations shared by four blocks are listed once, found %d times", n)
	}
	// The order inside a finding: evidence, the code, then how it can be wrong.
	e, c, l := strings.Index(out, "Evidence:"), strings.Index(out, "Code:\n\n####"), strings.Index(out, "Limitations:")
	if e < 0 || c <= e || l <= c {
		t.Errorf("order of the sections is wrong: evidence %d, code %d, limitations %d", e, c, l)
	}
	if without := renderMarkdown(t, codeSampleReport().WithoutCode()); strings.Contains(without, "```") || strings.Contains(without, "Code:") {
		t.Error("a report without code has no code in its Markdown")
	}
}

// stripFences removes the fenced code blocks from Markdown and reports whether
// they were all opened and closed properly (a closing fence is a line of at
// least as many backticks as the opening one and nothing else).
func stripFences(md string) (outside string, balanced bool) {
	var keep []string
	fence := 0
	for _, l := range strings.Split(md, "\n") {
		trimmed := strings.TrimLeft(l, " ")
		run := len(trimmed) - len(strings.TrimLeft(trimmed, "`"))
		switch {
		case fence == 0 && run >= 3 && len(l)-len(trimmed) <= 3 && !strings.Contains(trimmed[run:], "`"):
			fence = run
		case fence > 0 && run >= fence && strings.TrimSpace(trimmed) == strings.Repeat("`", run) && len(l)-len(trimmed) <= 3:
			fence = 0
		case fence == 0:
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n"), fence == 0
}

func TestMarkdownCodeCannotBreakOutOfItsFence(t *testing.T) {
	rep := codeSampleReport()
	rep.Findings[0].Code = hostileCode()
	out := renderMarkdown(t, rep)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatal("raw control bytes in the Markdown")
	}
	outside, balanced := stripFences(out)
	if !balanced {
		t.Fatal("a fenced block is never closed: hostile content swallowed the rest of the report")
	}
	if regexp.MustCompile(`(?m)(^|[^\\])<`).MatchString(outside) {
		t.Errorf("an unescaped < reached the Markdown outside a fenced block:\n%s", outside)
	}
	if regexp.MustCompile(`(?m)^\s*#+\s*pwned`).MatchString(outside) || strings.Contains(outside, "```evil") {
		t.Errorf("hostile text became a heading or a fence of its own:\n%s", outside)
	}
	if !strings.Contains(out, "`````\n") {
		t.Error("a line that contains a run of four backticks needs a fence of five")
	}
	if !strings.Contains(out, "```text\n") || strings.Contains(out, "```evil") {
		t.Error("the language of a fence comes from a fixed list, never from the file name")
	}
}

func TestMarkdownFenceLanguageComesFromAFixedList(t *testing.T) {
	for file, want := range map[string]string{"app/main.js": "js", "A.MJS": "js", "x.py": "python", "x.json": "json", "weird.js`x": "text", "noext": "text", "x.exe": "text", "": "text"} {
		if got := fenceLanguage(report.CodeBlock{Kind: report.CodeKindSource, File: file}); got != want {
			t.Errorf("fenceLanguage(%q) = %q, want %q", file, got, want)
		}
	}
	if fenceLanguage(report.CodeBlock{Kind: report.CodeKindDisasm, File: "a.js"}) != "asm" || fenceLanguage(report.CodeBlock{Kind: report.CodeKindHex}) != "text" {
		t.Error("disassembly is asm and a hex dump is plain text")
	}
}

func TestJSONCarriesTheCodeUnderFindings(t *testing.T) {
	rep := codeSampleReport()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	code, ok := doc.Findings[0]["code"].([]any)
	if !ok || len(code) != 4 {
		t.Fatalf("findings[0].code = %v", doc.Findings[0]["code"])
	}
	first := code[0].(map[string]any)
	lines := first["lines"].([]any)
	hit := lines[5].(map[string]any)
	if first["kind"] != "disasm" || first["address"] != "0x14000101c" || hit["highlight"] != true || hit["address"] != "0x140001036" || hit["note"] != "KERNEL32.dll!VirtualAllocEx" {
		t.Errorf("the first block or its flagged line is wrong: %v", first)
	}
	if _, has := doc.Findings[3]["code"]; has {
		t.Error("a finding without code must not carry a code key")
	}
	if strings.Contains(mustJSON(t, sampleReport()), `"code"`) {
		t.Error("a report without code must encode exactly as before")
	}
	var back report.Report
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back.Findings, rep.Findings) {
		t.Errorf("the code did not survive a round trip (%v)", err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSARIFNamesTheFlaggedCodeLines(t *testing.T) {
	rep := codeSampleReport()
	var buf bytes.Buffer
	if err := SARIF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Message   struct{ Text string }
				Locations []any `json:"locations"`
				Props     struct {
					Code []map[string]any `json:"code"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	results := doc.Runs[0].Results
	if len(results) != 4 {
		t.Fatalf("%d results", len(results))
	}
	inj := results[0]
	if !strings.Contains(inj.Message.Text, ". Code: 0x140001036 call qword ptr [rip+0x1fc4] (KERNEL32.dll!VirtualAllocEx)") {
		t.Errorf("the message must name the first call site: %q", inj.Message.Text)
	}
	if len(inj.Props.Code) != 4 || inj.Props.Code[1]["address"] != "0x140001065" || inj.Props.Code[1]["note"] != "KERNEL32.dll!WriteProcessMemory" || inj.Props.Code[1]["kind"] != "disasm" {
		t.Errorf("the code property lists the flagged line of each block: %v", inj.Props.Code)
	}
	if len(inj.Locations) != 1 {
		t.Error("the structure of a result does not change: one location")
	}
	if got := results[1].Message.Text; !strings.Contains(got, "Code: file offset 0x1a50 nt: ....http://2") {
		t.Errorf("a hex block is described by its offset: %q", got)
	}
	if got := results[2].Message.Text; !strings.Contains(got, "Code: app/main.js line 18 ") {
		t.Errorf("a source block is described by its file and line: %q", got)
	}
	if results[3].Props.Code != nil || strings.Contains(results[3].Message.Text, "Code:") {
		t.Error("a finding without code is unchanged")
	}
	rep.Findings[0].Code = hostileCode()
	buf.Reset()
	if err := SARIF(&buf, rep); err != nil || bytes.ContainsRune(buf.Bytes(), 0x1b) {
		t.Errorf("hostile code in SARIF: %v", err)
	}
}

func TestHTMLCarriesTheCodeInItsIslandAndSummary(t *testing.T) {
	rep := codeSampleReport()
	page := renderHTML(t, rep)
	var back report.Report
	if err := json.Unmarshal([]byte(islandOf(t, page)), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Findings, rep.Findings) {
		t.Error("code within the caps must reach the island unchanged")
	}
	fallback := noscriptPattern.FindString(page)
	for _, want := range []string{
		"<h4>Code</h4>", "<p>Call site of KERNEL32.dll!VirtualAllocEx (.text | 0x14000101c | x86-64)</p>",
		"&gt; 0x140001036  ff 15 c4 1f 00 00        call qword ptr [rip+0x1fc4]  ; KERNEL32.dll!VirtualAllocEx",
		"<p>1 more code block is in the interactive report.</p>", "<h4>Limitations of the code shown</h4>",
	} {
		if !strings.Contains(fallback, want) {
			t.Errorf("the no-script summary lacks %q", want)
		}
	}
	if strings.Contains(fallback, "OpenProcess</p>") || strings.Contains(strings.ToLower(fallback), "<script") {
		t.Error("the summary shows the first blocks only and never a script")
	}
}

// TestHTMLClipsHugeCodeBeforeEmbeddingIt: a report that carries thousands of
// blocks of enormous lines cannot make the page grow without bound.
func TestHTMLClipsHugeCodeBeforeEmbeddingIt(t *testing.T) {
	huge := report.CodeBlock{Kind: report.CodeKindDisasm, Title: strings.Repeat("t", 5000), Limitations: []string{strings.Repeat("l", 5000)}}
	for i := range 500 {
		huge.Lines = append(huge.Lines, report.CodeLine{Address: report.Addr(i), Text: strings.Repeat("x", 5000), Note: strings.Repeat("n", 5000), Highlight: i == 400})
	}
	rep := codeSampleReport()
	for range 3000 {
		rep.Findings[0].Code = append(rep.Findings[0].Code, huge)
	}
	page := renderHTML(t, rep)
	if limit := 2 << 20; len(page) > limit {
		t.Fatalf("the page is %d KiB, want at most %d KiB", len(page)>>10, limit>>10)
	}
	var back report.Report
	if err := json.Unmarshal([]byte(islandOf(t, page)), &back); err != nil {
		t.Fatal(err)
	}
	blocks := back.Findings[0].Code
	if len(blocks) != report.MaxCodeBlocks {
		t.Fatalf("%d blocks in the island, want %d", len(blocks), report.MaxCodeBlocks)
	}
	for i, b := range blocks {
		if err := b.Validate(); err != nil {
			t.Errorf("block %d of the island breaks the model: %v", i, err)
		}
	}
	last := blocks[len(blocks)-1].Limitations
	if !strings.Contains(last[len(last)-1], "more code blocks of this finding were left out") {
		t.Errorf("the last block must say that others were left out: %q", last)
	}
	if len(rep.Findings[0].Code) != 3004 {
		t.Error("rendering must not change the report")
	}
}

// TestHTMLCodeCannotBreakOut: the hostile blocks go through the same checks as
// every other field (see TestHTMLHostileInputCannotBreakOut, whose report now
// carries them); this one adds what is specific to code.
func TestHTMLCodeCannotBreakOut(t *testing.T) {
	rep := codeSampleReport()
	rep.Findings[0].Code = hostileCode()
	page := renderHTML(t, rep)
	isl := islandOf(t, page)
	if i := strings.IndexAny(isl, "<>&"+string(rune(0x2028))+string(rune(0x2029))); i >= 0 {
		t.Fatalf("raw %q inside the island", isl[i])
	}
	var back report.Report
	if err := json.Unmarshal([]byte(isl), &back); err != nil || !reflect.DeepEqual(back.Findings[0].Code, rep.Findings[0].Code) {
		t.Fatalf("the hostile code must reach the island intact, only escaped (%v)", err)
	}
	if n := strings.Count(strings.ToLower(page), "<script"); n != 2 {
		t.Errorf("%d script elements, want 2", n)
	}
	fallback := noscriptPattern.FindString(page)
	if strings.Contains(fallback, "<img") || strings.Contains(fallback, "</script") || !strings.Contains(fallback, "&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;") {
		t.Errorf("the no-script summary must show the hostile text as escaped text:\n%s", fallback)
	}
	for _, r := range []rune{0x2028, 0x2029, 0x202e, 0x1b, 0x07, 0} {
		if strings.ContainsRune(page, r) {
			t.Errorf("the page contains a raw %U", r)
		}
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	raw, err := fs.ReadFile(web.FS(), name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestCodePanelCapsMatchTheModel keeps the numbers the dashboard script repeats
// in step with the model, so the panel and the Go renderers clip alike.
func TestCodePanelCapsMatchTheModel(t *testing.T) {
	js := readAsset(t, "report-view.js")
	for name, want := range map[string]int{
		"MAX_CODE_BLOCKS": report.MaxCodeBlocks, "MAX_CODE_LINES": report.MaxCodeLines, "MAX_CODE_CHARS": report.MaxCodeLineChars,
	} {
		m := regexp.MustCompile(`const ` + name + ` = (\d+);`).FindStringSubmatch(js)
		if m == nil {
			t.Errorf("%s is not declared in report-view.js", name)
			continue
		}
		if got, _ := strconv.Atoi(m[1]); got != want {
			t.Errorf("%s = %d in report-view.js, the model says %d", name, got, want)
		}
	}
	for _, kind := range []string{report.CodeKindDisasm, report.CodeKindHex, report.CodeKindSource} {
		if !strings.Contains(js, kind+": {") {
			t.Errorf("report-view.js does not know the code kind %q", kind)
		}
	}
}

func TestGoldenOutputs(t *testing.T) {
	rep := codeSampleReport()

	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "code-report.json", string(raw)+"\n")
	golden(t, "code-report.txt", renderText(t, rep, Options{Width: 100}))
	golden(t, "code-report.all.txt", renderText(t, rep, Options{Width: 100, CodeAll: true, Verbose: true}))
	golden(t, "code-report.md", renderMarkdown(t, rep))

	var sarif bytes.Buffer
	if err := SARIF(&sarif, rep); err != nil {
		t.Fatal(err)
	}
	golden(t, "code-report.sarif", sarif.String())

	// The page is pinned without the parts that belong to the dashboard files, so editing the
	// dashboard does not rewrite the golden file: the policy, the styles, the scripts and the data island
	// are replaced by markers (each of them has its own checks).
	page := renderHTML(t, rep)
	page = cspPattern.ReplaceAllString(page, `<meta http-equiv="Content-Security-Policy" content="[policy]">`)
	page = islandPattern.ReplaceAllString(page, `<script type="application/json" id="report-data">[report]</script>`)
	page = inlineStyle.ReplaceAllString(page, "<style>[styles]</style>")
	page = inlineScript.ReplaceAllString(page, "<script>[scripts]</script>")
	golden(t, "code-report.html.txt", page)
}
