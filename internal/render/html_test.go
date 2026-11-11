package render

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/rules"
	"github.com/q6r/teardown/web"
)

var (
	islandPattern   = regexp.MustCompile(`(?s)<script type="application/json" id="report-data">(.*?)</script>`)
	noscriptPattern = regexp.MustCompile(`(?s)<noscript>.*?</noscript>`)
	inlineScript    = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	inlineStyle     = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	cspPattern      = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`)
)

func renderHTML(t *testing.T, rep *report.Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := HTML(&buf, rep); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	return buf.String()
}

func islandOf(t *testing.T, page string) string {
	t.Helper()
	m := islandPattern.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the page has no JSON island")
	}
	return m[1]
}

// jsonEscape spells a rune the way encoding/json escapes it inside a string.
func jsonEscape(r rune) string { return fmt.Sprintf("\\u%04x", r) }

// hostileReport carries attacker-controlled text in every place a report holds some.
func hostileReport() *report.Report {
	lineSep, paraSep, rlo := string(rune(0x2028)), string(rune(0x2029)), string(rune(0x202e))
	closer := "</script><img src=x onerror=alert(1)>"
	comment := "<!--<script>alert(1)</script>-->"
	sneaky := "a" + lineSep + "b" + paraSep + "c & <b>bold</b> " + rlo + "gnp.exe"

	rep := sampleReport()
	rep.File.Name = closer + lineSep
	rep.Tool.Version = closer
	rep.Type.Label = comment
	rep.Type.Tags = []string{closer, sneaky}
	rep.Sections[0].Name = closer
	rep.Sections[1].Reasons = []string{comment, sneaky}
	rep.Imports[0].Library = closer
	rep.Imports[0].Functions = []string{comment, sneaky, "\x1b]0;pwned\x07"}
	rep.Exports = []string{closer, lineSep + paraSep}
	rep.Strings.Items = []report.StringItem{
		{Value: closer + sneaky, Offset: 1, Encoding: "ascii", Category: report.CatURL},
		{Value: comment, Offset: 2, Encoding: "utf16le", Category: report.CatSecret, Redacted: true, Kind: closer},
	}
	rep.Hardening[0].Label, rep.Hardening[0].Detail = closer, sneaky
	rep.Details["pe"] = map[string]any{"pdbPath": closer, "packerHints": []string{comment, sneaky}, closer: sneaky}
	rep.Findings[0].ID, rep.Findings[0].Title = closer, sneaky
	rep.Findings[0].Evidence = []string{closer, comment, sneaky}
	rep.Findings[0].Limitations = []string{closer, lineSep}
	rep.Risk.Label = closer
	rep.Risk.Basis = []string{comment, sneaky}
	rep.Limitations = append(rep.Limitations, closer, sneaky)
	return rep
}

// TestHTMLHostileInputCannotBreakOut pushes </script><img src=x onerror=alert(1)>,
// an HTML comment opener, ampersands, a right-to-left override and the line and
// paragraph separators U+2028 and U+2029 through every field of a report and
// checks what the page does with them.
func TestHTMLHostileInputCannotBreakOut(t *testing.T) {
	rep := hostileReport()
	page := renderHTML(t, rep)
	isl := islandOf(t, page)
	lineSep, paraSep := string(rune(0x2028)), string(rune(0x2029))

	t.Run("the JSON island holds none of the five dangerous characters", func(t *testing.T) {
		if i := strings.IndexAny(isl, "<>&"+lineSep+paraSep); i >= 0 {
			t.Fatalf("raw %q inside the island: %q", isl[i], isl[max(0, i-30):min(len(isl), i+30)])
		}
		for _, r := range []rune{'<', '>', '&', 0x2028, 0x2029} {
			if !strings.Contains(isl, jsonEscape(r)) {
				t.Errorf("the escaped form %s of %U is missing: the hostile text was not escaped", jsonEscape(r), r)
			}
		}
	})

	t.Run("the island still decodes to exactly the report that went in", func(t *testing.T) {
		var back report.Report
		if err := json.Unmarshal([]byte(isl), &back); err != nil {
			t.Fatalf("the island is not valid JSON: %v", err)
		}
		want, _ := json.Marshal(rep)
		got, _ := json.Marshal(&back)
		if !bytes.Equal(want, got) {
			t.Fatal("the island does not round-trip: JSON.parse would see different text than the analysis produced")
		}
		if back.File.Name != rep.File.Name || back.Findings[0].Evidence[0] != "</script><img src=x onerror=alert(1)>" {
			t.Errorf("hostile text was altered instead of escaped: %q", back.File.Name)
		}
	})

	t.Run("the page keeps exactly its own script and style elements", func(t *testing.T) {
		lower := strings.ToLower(page)
		if n := strings.Count(lower, "<script"); n != 2 {
			t.Errorf("%d <script elements, want 2 (the island and the code): a payload opened one", n)
		}
		if n := strings.Count(lower, "</script"); n != 2 {
			t.Errorf("%d </script terminators, want 2: a payload closed one early", n)
		}
		if strings.Count(lower, "<style") != 1 || strings.Count(lower, "</style") != 1 {
			t.Error("the page must contain exactly one style element")
		}
		for _, markup := range []string{"<img", "<b>", "<!--<script"} {
			if strings.Contains(lower, markup) {
				t.Errorf("injected markup %q reached the page", markup)
			}
		}
	})

	t.Run("no separator or direction override reaches the page unescaped", func(t *testing.T) {
		for _, r := range []rune{0x2028, 0x2029, 0x202e} {
			if strings.ContainsRune(page, r) {
				t.Errorf("the page contains a raw %U", r)
			}
		}
	})

	t.Run("the title and the no-script summary are escaped text", func(t *testing.T) {
		title := regexp.MustCompile(`<title>(.*?)</title>`).FindStringSubmatch(page)
		if title == nil || strings.ContainsAny(title[1], "<>") {
			t.Errorf("the title is not escaped: %q", title)
		}
		fallback := noscriptPattern.FindString(page)
		if fallback == "" {
			t.Fatal("no <noscript> fallback")
		}
		for _, want := range []string{"&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;", "[U+2028]", "[U+2029]", "[U+202E]"} {
			if !strings.Contains(fallback, want) {
				t.Errorf("the fallback lacks %q", want)
			}
		}
	})
}

// codeOnly drops the report data (the island and the no-script summary), which
// legitimately contains whatever the analysed file contained, including URLs.
func codeOnly(page string) string {
	return noscriptPattern.ReplaceAllString(islandPattern.ReplaceAllString(page, ""), "")
}

func TestHTMLMakesNoExternalReferences(t *testing.T) {
	page := renderHTML(t, sampleReport())
	code := codeOnly(page)
	for _, u := range regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}[^\s"'<>)]*`).FindAllString(code, -1) {
		if !strings.Contains(u, "www.w3.org/") {
			t.Errorf("the page refers to %q; an exported report must not depend on the network", u)
		}
	}
	markup := inlineStyle.ReplaceAllString(inlineScript.ReplaceAllString(code, ""), "")
	for _, banned := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)<(?:link|img|iframe|object|embed|audio|video|source|base|form|input)\b`),
		regexp.MustCompile(`(?i)\s(?:src|href|action|data|srcset|poster)\s*=`),
	} {
		if m := banned.FindString(markup); m != "" {
			t.Errorf("the page markup contains %q, which would load or navigate", m)
		}
	}
	css := strings.Join(inlineStyle.FindAllString(code, -1), "\n")
	for _, bad := range []string{"@import", "@font-face"} {
		if strings.Contains(css, bad) {
			t.Errorf("the styles contain %s", bad)
		}
	}
	for _, m := range regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(css, -1) {
		if !strings.HasPrefix(strings.Trim(m[1], `"'`), "data:") {
			t.Errorf("the styles load %q; only data: URLs are allowed", m[1])
		}
	}
}

func TestHTMLContentSecurityPolicyMatchesTheInlineBlocks(t *testing.T) {
	page := renderHTML(t, sampleReport())
	m := cspPattern.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no Content-Security-Policy meta tag")
	}
	policy := m[1]
	if !strings.HasPrefix(page[strings.Index(page, "<head>"):], "<head>\n<meta charset=\"utf-8\">\n<meta http-equiv=") {
		t.Error("the policy must come first in <head>, before any style or script")
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "*", "connect-src", "http:", "https:", "blob:"} {
		if strings.Contains(policy, bad) {
			t.Errorf("policy %q contains %q", policy, bad)
		}
	}
	for _, want := range []string{"default-src 'none'", "img-src data:", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy %q lacks %q", policy, want)
		}
	}
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	scripts, styles := inlineScript.FindAllStringSubmatch(page, -1), inlineStyle.FindAllStringSubmatch(page, -1)
	if len(scripts) != 1 || len(styles) != 1 {
		t.Fatalf("want one inline script and one inline style, got %d and %d", len(scripts), len(styles))
	}
	if !strings.Contains(policy, "script-src "+hash(scripts[0][1])+";") {
		t.Errorf("script-src does not allow the inline script's hash %s in %q", hash(scripts[0][1]), policy)
	}
	if !strings.Contains(policy, "style-src "+hash(styles[0][1])+";") {
		t.Errorf("style-src does not allow the inline style's hash %s in %q", hash(styles[0][1]), policy)
	}
}

func TestHTMLNoscriptFallbackKeepsTheReadableSummary(t *testing.T) {
	rep := sampleReport()
	page := renderHTML(t, rep)
	fallback := noscriptPattern.FindString(page)
	for _, want := range []string{
		"<h1>sample.exe</h1>", "PE32+ executable (x86-64, console)", "62/100 high", report.StaticOnly,
		"Findings (1)", "packing.upx", "first limit", rep.Hashes.SHA256, "Turn on JavaScript",
	} {
		if !strings.Contains(fallback, want) {
			t.Errorf("the no-script summary lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(fallback), "<script") {
		t.Error("the no-script summary must not contain a script element")
	}
}

func TestHTMLIsDeterministicAndStaysSmall(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep report.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	a, b := renderHTML(t, &rep), renderHTML(t, &rep)
	if a != b {
		t.Fatal("the same report must produce the same bytes")
	}
	island := len(islandOf(t, a))
	if overhead := len(a) - island; overhead > 320<<10 {
		t.Errorf("the page adds %d KiB around the data; the inlined styles, scripts and fallback should stay below 320 KiB", overhead>>10)
	}
	if len(a) > 400<<10 {
		t.Errorf("the page for the sample report is %d KiB; expected below 400 KiB", len(a)>>10)
	}
	t.Logf("page %d KiB, of which the report data is %d KiB", len(a)>>10, island>>10)
}

func TestHTMLRendersEverySampleFile(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "samples", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no sample files found (%v)", err)
	}
	for _, f := range files {
		rep, err := analyze.File(context.Background(), f, analyze.Options{})
		if err != nil {
			t.Fatalf("analyze %s: %v", f, err)
		}
		page := renderHTML(t, rep)
		var back report.Report
		if err := json.Unmarshal([]byte(islandOf(t, page)), &back); err != nil || back.File.Name != filepath.Base(f) {
			t.Errorf("%s: the island does not decode to the report (%v)", f, err)
		}
	}
}

// TestHTMLBodyIsBuiltByTheBootScript: the exported page carries no layout markup of its
// own. Its body holds the no-script summary, the JSON island and the script; the shell
// (rail, top bar, sub bar, status bar) and the report are built from the island by
// report-boot.js, with the report sections as #fragment links that work from file://.
func TestHTMLBodyIsBuiltByTheBootScript(t *testing.T) {
	page := renderHTML(t, sampleReport())
	body := page[strings.Index(page, "<body"):]
	markup := inlineScript.ReplaceAllString(islandPattern.ReplaceAllString(noscriptPattern.ReplaceAllString(body, ""), ""), "")
	for _, skeleton := range []string{"<header", "<main", "<nav", "<footer", "<button", "report-root"} {
		if strings.Contains(markup, skeleton) {
			t.Errorf("the body contains %q outside the no-script summary: the page layout is built by the shell, not written into the file", skeleton)
		}
	}
	m := inlineScript.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the page has no inline script")
	}
	for _, want := range []string{"A.shell(", "anchors: true", "getElementById('report-data')"} {
		if !strings.Contains(m[1], want) {
			t.Errorf("the inlined script lacks %q: the exported page would not build its layout from the island", want)
		}
	}
}

// TestEscapeInvisibleKeepsTheValueAndHidesTheCharacters covers a BMP format
// character (the right-to-left override) and an astral one (a tag character, which
// JSON must write as a surrogate pair).
func TestEscapeInvisibleKeepsTheValueAndHidesTheCharacters(t *testing.T) {
	rlo, tag, bom := string(rune(0x202e)), string(rune(0xe0041)), string(rune(0xfeff))
	value := "x" + rlo + "y" + tag + "z" + bom + "é日"
	doc, err := json.Marshal(map[string]string{"k": value})
	if err != nil {
		t.Fatal(err)
	}
	got := escapeInvisible(doc)
	for _, r := range []rune{0x202e, 0xe0041, 0xfeff} {
		if bytes.ContainsRune(got, r) {
			t.Errorf("%U is still raw in %q", r, got)
		}
	}
	for _, want := range []string{jsonEscape(0x202e), jsonEscape(0xdb40) + jsonEscape(0xdc41), jsonEscape(0xfeff), "é日"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	var back map[string]string
	if err := json.Unmarshal(got, &back); err != nil || back["k"] != value {
		t.Errorf("the escaped document must decode to the original value: %q, %v", back["k"], err)
	}
}

func TestVisibleSpellsOutInvisibleCharacters(t *testing.T) {
	tests := map[string]string{
		"plain text": "plain text",
		"héllo 日本語":  "héllo 日本語",
		"a\x1bb":     `a\x1bb`,
		"a\x00b":     `a\x00b`,
		"a\xffb":     `a\xffb`,
	}
	for in, want := range tests {
		if got := visible(in); got != want {
			t.Errorf("visible(%q) = %q, want %q", in, got, want)
		}
	}
	got := visible("a" + string(rune(0x202e)) + "b" + string(rune(0x2028)) + string(rune(0x200b)) + string(rune(0xfeff)))
	if want := "a[U+202E]b[U+2028][U+200B][U+FEFF]"; got != want {
		t.Errorf("visible = %q, want %q", got, want)
	}
}

// TestViewConstantsMatchTheEngine keeps the numbers that report-view.js repeats in
// step with the Go engine, so the page can never contradict the analysis.
func TestViewConstantsMatchTheEngine(t *testing.T) {
	src, err := fs.ReadFile(web.FS(), "report-view.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)

	m := regexp.MustCompile(`const PACKING_THRESHOLD = ([0-9.]+);`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("PACKING_THRESHOLD is not declared in report-view.js")
	}
	if got, _ := strconv.ParseFloat(m[1], 64); got != rules.HighEntropySection {
		t.Errorf("PACKING_THRESHOLD = %v, the engine uses %v", got, rules.HighEntropySection)
	}

	m = regexp.MustCompile(`const RISK_BANDS = \[(\d+), (\d+), (\d+)\];`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("RISK_BANDS is not declared in report-view.js")
	}
	var bands [3]int
	for i := range bands {
		bands[i], _ = strconv.Atoi(m[i+1])
	}
	for score := 0; score <= 100; score++ {
		want := report.RiskLow
		switch {
		case score >= bands[2]:
			want = report.RiskCritical
		case score >= bands[1]:
			want = report.RiskHigh
		case score >= bands[0]:
			want = report.RiskMedium
		}
		if got := rules.Label(score); got != want {
			t.Fatalf("score %d is %q in the engine but %q with the view's bands %v", score, got, want, bands)
		}
	}

	m = regexp.MustCompile(`const SEVERITIES = \[([^\]]*)\];`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("SEVERITIES is not declared in report-view.js")
	}
	var wantSev []string
	for _, s := range report.Severities() {
		wantSev = append([]string{"'" + string(s) + "'"}, wantSev...) // most severe first
	}
	if got := strings.Join(strings.Split(m[1], ", "), ","); got != strings.Join(wantSev, ",") {
		t.Errorf("SEVERITIES = %s, want %s", got, strings.Join(wantSev, ", "))
	}

	for _, key := range []string{report.StatusEnabled, report.StatusDisabled, report.StatusUnknown, report.StatusNA} {
		if !strings.Contains(js, "'"+key+"':") && !strings.Contains(js, key+": {") {
			t.Errorf("report-view.js has no entry for the hardening status %q", key)
		}
	}
	for _, label := range []string{report.RiskLow, report.RiskMedium, report.RiskHigh, report.RiskCritical} {
		if !strings.Contains(js, label+": { kind:") {
			t.Errorf("report-view.js has no entry for the risk label %q", label)
		}
	}
}
