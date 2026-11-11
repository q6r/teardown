package render

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/diff"
	"github.com/q6r/teardown/internal/report"
)

const hostile = "\x1b]0;pwned\x07\x1b[31m<script>alert(1)</script>|`x`\n[link](http://evil)"

func sampleReport() *report.Report {
	r := report.New("sample.exe", 204_800, "0.1.0")
	r.GeneratedAt = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	r.DurationMs = 12
	r.Type = report.Type{ID: report.TypePE, Family: report.FamilyExecutable, Label: "PE32+ executable (x86-64, console)", Confidence: report.ConfidenceHigh, Tags: []string{"exe", "64-bit"}}
	r.Hashes = report.Hashes{MD5: "d41d8cd98f00b204e9800998ecf8427e", SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709", SHA256: strings.Repeat("ab", 32), Imphash: "0123456789abcdef0123456789abcdef"}
	r.Entropy = report.Entropy{Overall: 6.4, WindowSize: 4096, Windows: []float64{1, 3, 5, 7.9, 6, 2, 0, 8}}
	r.Sections = []report.Section{
		{Name: ".text", VirtualSize: 4096, RawSize: 4096, Entropy: 7.8, Flags: []string{"R", "X"}},
		{Name: hostile, VirtualSize: 100, RawSize: 100, Entropy: 1, Flags: []string{"R", "W", "X"}, Suspicious: true, Reasons: []string{hostile}},
	}
	r.Imports = []report.Import{{Library: "KERNEL32.dll", Count: 3, Functions: []string{"ExitProcess", "GetTickCount", hostile}}, {Library: "WS2_32.dll", Count: 1, Functions: []string{"connect"}}}
	r.Exports = []string{"Exported1", "Exported2"}
	r.Hardening = []report.Hardening{
		{ID: report.HardenASLR, Label: "ASLR", Status: report.StatusEnabled, Detail: "DYNAMIC_BASE"},
		{ID: report.HardenDEP, Label: "DEP", Status: report.StatusDisabled, Detail: hostile},
		{ID: report.HardenCFG, Label: "CFG", Status: report.StatusUnknown, Detail: "?"},
		{ID: report.HardenSEH, Label: "SEH", Status: report.StatusNA, Detail: "x64"},
	}
	r.Strings = report.Strings{Total: 1234, MinLength: 5, Truncated: true, ByCategory: map[string]int{report.CatURL: 2, report.CatSecret: 1, report.CatPlain: 1230}, Items: []report.StringItem{
		{Value: "https://example.com/" + hostile, Offset: 0x10, Encoding: "ascii", Category: report.CatURL},
		{Value: "AKIA…(20 chars)", Offset: 0x20, Encoding: "utf16le", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
	}}
	r.Details["pe"] = map[string]any{"machine": "x86-64", "bits": 64, "signed": false, "pdbPath": hostile, "packerHints": []string{"UPX0"}}
	r.Findings = []report.Finding{{
		ID: "packing.upx", Title: "File is packed " + hostile, Severity: report.SeverityHigh, Category: report.CategoryPacking, Confidence: report.ConfidenceMedium,
		Evidence: []string{"e1 " + hostile, "e2", "e3", "e4", "e5"}, Limitations: []string{"first limit", "second limit"},
	}}
	r.Risk = report.Risk{Score: 62, Label: report.RiskHigh, Basis: []string{"+14  packing.upx", "score 62 => high"}}
	return r
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestTextPlainHasNoEscapesAndShowsEveryBlock(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport(), Options{Color: false, Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("plain output must not contain escape bytes:\n%q", out)
	}
	for _, want := range []string{
		"teardown", "sample.exe", "PE32+ executable", "RISK", "62/100", "HIGH", "Hashes", "imphash", "Entropy", "6.40 of 8.00",
		"Format details", "machine", "Hardening", "✔", "✘", "Sections (2)", "7.80", "Imports (2 libraries, 4 functions)", "KERNEL32.dll",
		"Exports (2)", "Strings", "1,234 found", "list truncated", "url 2", "[HIGH]", "packing.upx", "confidence medium", "evidence:",
		"limitation: first limit", "+2 more evidence lines", "Limitations", "never executed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "second limit") {
		t.Error("non-verbose output shows only the first limitation")
	}
	if strings.Contains(out, "<script>") && !strings.Contains(out, `\x1b`) {
		t.Error("hostile bytes must be visibly escaped, not silently dropped")
	}
}

func TestTextVerboseShowsBasisAndAllEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport(), Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"+14 packing.upx", "second limit", "e5", "ExitProcess"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output lacks %q", want)
		}
	}
}

func TestTextColorOnlyEmitsOwnSequences(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport(), Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.ContainsRune(out, 0x1b) {
		t.Fatal("colour output must contain ANSI sequences")
	}
	stripped := ansi.ReplaceAllString(out, "")
	if strings.ContainsRune(stripped, 0x1b) || strings.ContainsRune(stripped, 0x07) {
		t.Fatalf("hostile escape sequences survived sanitising: %q", stripped)
	}
}

func TestTextASCIIMode(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport(), Options{ASCII: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, r := range []string{"█", "░", "✔", "✘", "▁", "──"} {
		if strings.Contains(out, r) {
			t.Errorf("ASCII mode printed %q", r)
		}
	}
}

func TestTextEmptyReportIsStillWellFormed(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, report.New("empty", 0, "dev"), Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "no findings") || !strings.Contains(out, "Strings") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestMarkdownEscapesUntrustedText(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("raw control bytes in markdown:\n%q", out)
	}
	// Code spans are rendered literally by Markdown engines; everything else must be escaped.
	if outside := stripCodeSpans(out); strings.Contains(outside, "<script>") || strings.Contains(outside, "<img") {
		t.Fatalf("unescaped HTML outside code spans:\n%s", outside)
	}
	for _, want := range []string{"# teardown report:", "## Findings (1)", "### [HIGH]", "## Hardening", "| Name | Virtual |", "## Imports", "## Strings", "## Limitations", "## Risk basis"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	// Every table row must keep the header's column count despite pipes in hostile values.
	lines := strings.Split(out, "\n")
	expected := 0
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "|") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "|-"):
			expected = strings.Count(strings.ReplaceAll(l, `\|`, ""), "|")
		case strings.HasPrefix(l, "|") && expected > 0:
			if got := strings.Count(strings.ReplaceAll(l, `\|`, ""), "|"); got != expected {
				t.Errorf("table row has %d unescaped pipes, header has %d: %s", got, expected, l)
			}
		default:
			expected = 0
		}
	}
}

// stripCodeSpans removes Markdown code spans (any fence length) from s.
func stripCodeSpans(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '`' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		n := 0
		for i+n < len(s) && s[i+n] == '`' {
			n++
		}
		fence := strings.Repeat("`", n)
		rest := s[i+n:]
		closeAt, found := -1, false
		for j := 0; j < len(rest); j++ {
			if rest[j] != '`' {
				continue
			}
			k := 0
			for j+k < len(rest) && rest[j+k] == '`' {
				k++
			}
			if k == n {
				closeAt, found = j, true
				break
			}
			j += k - 1
		}
		if !found {
			sb.WriteString(fence)
			i += n
			continue
		}
		i += n + closeAt + len(fence)
	}
	return sb.String()
}

func TestCodeSpanFencing(t *testing.T) {
	tests := map[string]string{
		"plain":      "`plain`",
		"a`b":        "``a`b``",
		"a``b":       "```a``b```",
		"`leading":   "`` `leading ``",
		"trailing`":  "`` trailing` ``",
		"with\nline": "`with\\x0aline`",
	}
	for in, want := range tests {
		if got := code(in); got != want {
			t.Errorf("code(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := bar(0.5, 10, false); got != "█████░░░░░" {
		t.Errorf("bar = %q", got)
	}
	if got := bar(2, 4, true); got != "####" {
		t.Errorf("bar clamps above 1: %q", got)
	}
	if got := bar(-1, 4, true); got != "...." {
		t.Errorf("bar clamps below 0: %q", got)
	}
	if got := spark([]float64{0, 8}, 2, false); got != "▁█" {
		t.Errorf("spark = %q", got)
	}
	if got := spark(make([]float64, 100), 10, true); len(got) != 10 {
		t.Errorf("spark must downsample to the width: %q", got)
	}
	if spark(nil, 10, false) != "" {
		t.Error("spark of nothing is empty")
	}
	for in, want := range map[int64]string{-1: "0 B", 0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 3 << 30: "3.0 GiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -4321: "-4,321"} {
		if got := groupInt(in); got != want {
			t.Errorf("groupInt(%d) = %q, want %q", in, got, want)
		}
	}
	if got := clip("héllo wörld", 6); got != "héllo…" {
		t.Errorf("clip = %q", got)
	}
	if got := wrapText("aaa bbb ccc ddd", 9); len(got) != 2 || got[0] != "aaa bbb" || got[1] != "ccc ddd" {
		t.Errorf("wrapText = %q", got)
	}
	if (Options{Width: 10}).width() != 60 || (Options{}).width() != 100 || (Options{Width: 120}).width() != 120 {
		t.Error("width clamping is wrong")
	}
}

func TestStringsHashAndDiffViews(t *testing.T) {
	var buf bytes.Buffer
	s := report.Strings{Total: 2, MinLength: 5, Truncated: true, Items: []report.StringItem{
		{Value: "hello world", Offset: 0x10, Encoding: "ascii", Category: report.CatPlain},
		{Value: hostile, Offset: 0x20, Encoding: "utf16le", Category: report.CatURL},
	}}
	if err := Strings(&buf, s, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := StringsFooter(&buf, 2, s, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "0x00000010 a plain") || !strings.Contains(out, "u url") || strings.ContainsRune(out, 0x1b) {
		t.Fatalf("strings output:\n%q", out)
	}
	if !strings.Contains(out, "2 of 2 strings shown") || !strings.Contains(out, "truncated") {
		t.Fatalf("footer missing:\n%s", out)
	}

	buf.Reset()
	sum := &analyze.Summary{File: report.File{Name: "x", Size: 10}, Type: report.Type{Label: "data"}, Hashes: report.Hashes{MD5: "m", SHA1: "s1", SHA256: "s256", Imphash: "imp"}, Entropy: report.Entropy{Overall: 4}}
	if err := Hash(&buf, sum, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"md5      m", "sha1     s1", "sha256   s256", "imphash  imp", "entropy"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("hash output lacks %q:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	a, b := sampleReport(), sampleReport()
	b.File.Name = "new.exe"
	b.Hashes.SHA256 = strings.Repeat("cd", 32)
	b.Sections = append(b.Sections, report.Section{Name: "UPX1"})
	b.Findings = append(b.Findings, report.Finding{ID: "x.new", Title: "new thing", Severity: report.SeverityLow})
	if err := Diff(&buf, diff.Compare(a, b), Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"teardown diff", "new.exe", "── Summary", "Sections added", "+ UPX1", "Findings added", "x.new"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("diff output lacks %q:\n%s", want, buf.String())
		}
	}
}
