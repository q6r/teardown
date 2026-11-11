package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

var fixedNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

type result struct {
	code     int
	out, err string
}

type testEnv struct {
	vars  map[string]string
	tty   bool
	stdin string
}

func run(t *testing.T, te testEnv, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{
		Stdin:  strings.NewReader(te.stdin),
		Stdout: &out,
		Stderr: &errb,
		Getenv: func(k string) string { return te.vars[k] },
		IsTTY:  func(io.Writer) bool { return te.tty },
		Now:    func() time.Time { return fixedNow },
	}
	code := Run(context.Background(), args, env)
	return result{code, out.String(), errb.String()}
}

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rwxPE is a PE with a writable+executable section: it triggers structure.rwx-section (medium).
func rwxPE() []byte {
	return testfixtures.PE(testfixtures.PEOptions{
		Sections: []testfixtures.PESection{{Name: ".rwx", Data: make([]byte, 600), Characteristics: 0xE0000020}},
	})
}

func TestHelpAndUsage(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		inStdout []string
		inStderr []string
	}{
		{"no arguments", nil, exitUsage, nil, []string{"Usage:", "Commands:", "analyze"}},
		{"--help", []string{"--help"}, exitOK, []string{"Usage:", "Commands:", "Exit codes:", "NO_COLOR", "--fail-on"}, nil},
		{"-h", []string{"-h"}, exitOK, []string{"Commands:"}, nil},
		{"help", []string{"help"}, exitOK, []string{"Commands:"}, nil},
		{"help analyze", []string{"help", "analyze"}, exitOK, []string{"teardown analyze <file> [flags]", "--fail-on SEVERITY", "Examples:", "CI gating:"}, nil},
		{"analyze -h", []string{"analyze", "-h"}, exitOK, []string{"--html FILE", "-v, --verbose", "(default 5)"}, nil},
		{"strings --help", []string{"strings", "--help"}, exitOK, []string{"-c, --category LIST", "secret"}, nil},
		{"unknown command", []string{"frobnicate"}, exitUsage, nil, []string{`unknown command "frobnicate"`}},
		{"typo suggests", []string{"analize"}, exitUsage, nil, []string{`did you mean "analyze"`}},
		{"help unknown", []string{"help", "nope"}, exitUsage, nil, []string{"unknown command"}},
		{"unknown flag", []string{"analyze", "--nope", "x"}, exitUsage, nil, []string{"flag provided but not defined", "teardown analyze --help"}},
		{"missing file", []string{"analyze"}, exitUsage, nil, []string{"expected exactly one file"}},
		{"two files", []string{"analyze", "a", "b"}, exitUsage, nil, []string{"expected exactly one file, got 2"}},
		{"json and md", []string{"analyze", "x", "--json", "--md"}, exitUsage, nil, []string{"choose one of --json, --md, --sarif or --html"}},
		{"html and output", []string{"analyze", "x", "--html", "o.html", "-o", "o.json"}, exitUsage, nil, []string{"--output does not apply to --html"}},
		{"bad fail-on", []string{"analyze", "x", "--fail-on", "urgent"}, exitUsage, nil, []string{"--fail-on:", "unknown severity"}},
		{"bad color", []string{"analyze", "x", "--color", "rainbow"}, exitUsage, nil, []string{"--color must be"}},
		{"bad min-string", []string{"analyze", "x", "--min-string", "0"}, exitUsage, nil, []string{"--min-string must be between"}},
		{"bad int", []string{"analyze", "x", "--max-strings", "lots"}, exitUsage, nil, []string{"not a whole number"}},
		{"bad timeout", []string{"analyze", "x", "--timeout", "soon"}, exitUsage, nil, []string{"not a duration"}},
		{"diff needs two", []string{"diff", "a"}, exitUsage, nil, []string{"expected exactly two files"}},
		{"hash needs one", []string{"hash"}, exitUsage, nil, []string{"expected at least one file"}},
		{"strings bad category", []string{"strings", "x", "--category", "urls"}, exitUsage, nil, []string{`unknown category "urls"`, "valid:"}},
		{"serve bad addr", []string{"serve", "--addr", "nonsense"}, exitUsage, nil, []string{"--addr must look like HOST:PORT"}},
		{"serve bad port", []string{"serve", "--addr", "127.0.0.1:99999"}, exitUsage, nil, []string{"port"}},
		{"serve bad size", []string{"serve", "--max-upload", "lots"}, exitUsage, nil, []string{"not a size"}},
		{"serve extra arg", []string{"serve", "now"}, exitUsage, nil, []string{"unexpected argument"}},
		{"completion needs shell", []string{"completion"}, exitUsage, nil, []string{"expected one shell"}},
		{"completion bad shell", []string{"completion", "tcsh"}, exitUsage, nil, []string{`unknown shell "tcsh"`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, testEnv{}, tc.args...)
			if r.code != tc.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, tc.wantCode, r.out, r.err)
			}
			for _, w := range tc.inStdout {
				if !strings.Contains(r.out, w) {
					t.Errorf("stdout lacks %q:\n%s", w, r.out)
				}
			}
			for _, w := range tc.inStderr {
				if !strings.Contains(r.err, w) {
					t.Errorf("stderr lacks %q:\n%s", w, r.err)
				}
			}
		})
	}
}

func TestEveryCommandIsDocumented(t *testing.T) {
	for _, c := range commands() {
		if c.summary == "" {
			t.Errorf("%s has no summary", c.name)
		}
		fs := newFlagSet(c.name)
		c.register(fs)
		for _, s := range fs.specs {
			if s.usage == "" {
				t.Errorf("%s --%s has no usage text", c.name, s.name)
			}
			if !s.boolean && s.meta == "" {
				t.Errorf("%s --%s takes a value but has no metavar", c.name, s.name)
			}
		}
		if c.name != "version" && c.name != "completion" && len(c.examples) == 0 {
			t.Errorf("%s has no examples", c.name)
		}
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-V"}} {
		r := run(t, testEnv{}, args...)
		if r.code != exitOK || !strings.HasPrefix(r.out, "teardown ") {
			t.Errorf("%v: code %d out %q", args, r.code, r.out)
		}
	}
	r := run(t, testEnv{}, "version", "--json")
	var info map[string]any
	if err := json.Unmarshal([]byte(r.out), &info); err != nil || info["version"] == "" || info["go"] == "" {
		t.Fatalf("version --json = %q (%v)", r.out, err)
	}
}

func TestAnalyzeHumanOutputAndColorRules(t *testing.T) {
	path := write(t, "sample.exe", rwxPE())
	plain := run(t, testEnv{}, "analyze", path)
	if plain.code != exitOK {
		t.Fatalf("exit %d: %s", plain.code, plain.err)
	}
	for _, want := range []string{"sample.exe", "PE", "RISK", "sha256", "Hardening", "Sections", "structure.rwx-section", "Limitations"} {
		if !strings.Contains(plain.out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.ContainsRune(plain.out, 0x1b) {
		t.Fatal("no colour expected when stdout is not a terminal")
	}

	tests := []struct {
		name      string
		te        testEnv
		args      []string
		wantColor bool
	}{
		{"terminal gets colour", testEnv{tty: true}, nil, true},
		{"NO_COLOR wins over a terminal", testEnv{tty: true, vars: map[string]string{"NO_COLOR": "1"}}, nil, false},
		{"empty NO_COLOR is ignored", testEnv{tty: true, vars: map[string]string{"NO_COLOR": ""}}, nil, true},
		{"dumb terminal", testEnv{tty: true, vars: map[string]string{"TERM": "dumb"}}, nil, false},
		{"--color always overrides NO_COLOR", testEnv{vars: map[string]string{"NO_COLOR": "1"}}, []string{"--color", "always"}, true},
		{"--color never", testEnv{tty: true}, []string{"--color", "never"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.te, append([]string{"analyze", path}, tc.args...)...)
			if got := strings.ContainsRune(r.out, 0x1b); got != tc.wantColor {
				t.Fatalf("colour = %v, want %v", got, tc.wantColor)
			}
		})
	}

	ascii := run(t, testEnv{vars: map[string]string{"LANG": "C"}}, "analyze", path)
	if strings.ContainsAny(ascii.out, "█░✔✘") {
		t.Fatal("a C locale must produce ASCII-only symbols")
	}
	if v := run(t, testEnv{}, "analyze", path, "-v"); !strings.Contains(v.out, "points per finding") {
		t.Fatal("--verbose must show the risk arithmetic")
	}
}

func TestAnalyzeJSONAndMarkdownAndOutputFile(t *testing.T) {
	path := write(t, "sample.exe", rwxPE())

	r := run(t, testEnv{}, "analyze", path, "--json")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, r.out)
	}
	if rep.Schema != report.Schema || rep.File.Name != "sample.exe" || rep.Type.ID != report.TypePE || rep.Hashes.SHA256 == "" {
		t.Fatalf("report header wrong: %+v %+v", rep.File, rep.Type)
	}
	if !rep.GeneratedAt.Equal(fixedNow) {
		t.Errorf("the injected clock must be used: %v", rep.GeneratedAt)
	}

	md := run(t, testEnv{}, "analyze", path, "--md")
	if !strings.HasPrefix(md.out, "# teardown report:") {
		t.Fatalf("markdown = %q", md.out[:min(60, len(md.out))])
	}

	out := filepath.Join(t.TempDir(), "r.json")
	r = run(t, testEnv{}, "analyze", path, "--json", "-o", out)
	if r.code != exitOK || r.out != "" {
		t.Fatalf("with -o stdout must be empty: code %d out %q err %q", r.code, r.out, r.err)
	}
	if raw, err := os.ReadFile(out); err != nil || !json.Valid(raw) {
		t.Fatalf("output file: %v", err)
	}

	same := run(t, testEnv{}, "analyze", path, "--json", "-o", path)
	if same.code != exitError || !strings.Contains(same.err, "refusing to overwrite the input file") {
		t.Fatalf("overwriting the input must be refused: %d %s", same.code, same.err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, rwxPE()) {
		t.Fatal("input file was modified")
	}
}

func TestAnalyzeSARIF(t *testing.T) {
	path := write(t, "sample.exe", rwxPE())
	r := run(t, testEnv{}, "analyze", path, "--sarif")
	if r.code != exitOK {
		t.Fatalf("code %d err %q", r.code, r.err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil || doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("--sarif must print a SARIF 2.1.0 log with results: %v\n%s", err, r.out)
	}
	if bad := run(t, testEnv{}, "analyze", path, "--sarif", "--json"); bad.code != exitUsage || !strings.Contains(bad.err, "choose one of") {
		t.Fatalf("--sarif with --json must be a usage error, got %d %q", bad.code, bad.err)
	}
}

func TestAnalyzeHTML(t *testing.T) {
	path := write(t, "sample.exe", rwxPE())
	out := filepath.Join(t.TempDir(), "report.html")
	r := run(t, testEnv{}, "analyze", path, "--html", out)
	if r.code != exitOK || !strings.Contains(r.out, "wrote "+out) {
		t.Fatalf("code %d out %q err %q", r.code, r.out, r.err)
	}
	raw, err := os.ReadFile(out)
	page := string(raw)
	if err != nil || !strings.HasPrefix(page, "<!doctype html>") || !strings.Contains(page, `id="report-data"`) ||
		!strings.Contains(page, `http-equiv="Content-Security-Policy"`) || !strings.Contains(page, "<noscript>") {
		t.Fatalf("html file is not the single-file report: %v", err)
	}
	if bad := run(t, testEnv{}, "analyze", path, "--html", path); bad.code != exitError {
		t.Fatalf("html over the input must fail, got %d", bad.code)
	}
}

func TestFailOnGate(t *testing.T) {
	path := write(t, "sample.exe", rwxPE())
	tests := []struct {
		threshold string
		want      int
	}{
		{"info", exitFailOn},
		{"medium", exitFailOn},
		{"MEDIUM", exitFailOn},
		{"high", exitOK},
		{"critical", exitOK},
	}
	for _, tc := range tests {
		t.Run(tc.threshold, func(t *testing.T) {
			r := run(t, testEnv{}, "analyze", path, "--json", "--fail-on", tc.threshold)
			if r.code != tc.want {
				t.Fatalf("exit = %d, want %d (stderr %q)", r.code, tc.want, r.err)
			}
			if tc.want == exitFailOn {
				if !strings.Contains(r.err, "structure.rwx-section") {
					t.Errorf("stderr must name the offending findings: %q", r.err)
				}
				if !json.Valid([]byte(r.out)) {
					t.Error("stdout must stay valid JSON even when the gate trips")
				}
			}
		})
	}
	clean := write(t, "clean.txt", []byte("just some text, nothing to see here\n"))
	if r := run(t, testEnv{}, "analyze", clean, "--fail-on", "low"); r.code != exitOK {
		t.Fatalf("clean text file must pass the gate: %d %s", r.code, r.err)
	}
}

func TestAnalyzeErrors(t *testing.T) {
	dir := t.TempDir()
	missing := run(t, testEnv{}, "analyze", filepath.Join(dir, "nope.bin"))
	if missing.code != exitError || !strings.Contains(missing.err, "teardown analyze:") {
		t.Fatalf("missing file: %d %q", missing.code, missing.err)
	}
	isDir := run(t, testEnv{}, "analyze", dir)
	if isDir.code != exitError || !strings.Contains(isDir.err, "not a regular file") {
		t.Fatalf("directory: %d %q", isDir.code, isDir.err)
	}
	empty := write(t, "empty", nil)
	if r := run(t, testEnv{}, "analyze", empty, "--json"); r.code != exitOK || !json.Valid([]byte(r.out)) {
		t.Fatalf("an empty file is a valid input: %d %s", r.code, r.err)
	}
}

func TestInterspersedFlags(t *testing.T) {
	path := write(t, "a.bin", []byte("hello world, this is a test file with a URL http://example.com/x"))
	for _, args := range [][]string{
		{"analyze", path, "--json"},
		{"analyze", "--json", path},
		{"--", "analyze"}, // "--" is not a subcommand
	} {
		r := run(t, testEnv{}, args...)
		if args[0] == "--" {
			if r.code != exitUsage {
				t.Errorf("%v: code %d", args, r.code)
			}
			continue
		}
		if r.code != exitOK || !json.Valid([]byte(r.out)) {
			t.Errorf("%v: code %d err %s", args, r.code, r.err)
		}
	}
	// "--" ends flag parsing, so a file named like a flag can be analysed.
	odd := write(t, "--weird", []byte("data"))
	dir, base := filepath.Split(odd)
	t.Chdir(dir)
	if r := run(t, testEnv{}, "analyze", "--json", "--", base); r.code != exitOK {
		t.Fatalf("-- terminator: %d %s", r.code, r.err)
	}
}

func TestStringsCommand(t *testing.T) {
	data := []byte("\x00\x01 visit http://example.com/path now \x00 contact admin@example.org \x00 plain words here \x00AKIAIOSFODNN7EXAMPLE\x00")
	path := write(t, "s.bin", data)

	all := run(t, testEnv{}, "strings", path)
	if all.code != exitOK || !strings.Contains(all.out, "plain words here") || !strings.Contains(all.out, "http://example.com/path") {
		t.Fatalf("code %d out %s err %s", all.code, all.out, all.err)
	}
	if !strings.Contains(all.err, "strings shown") {
		t.Errorf("summary footer must go to stderr: %q", all.err)
	}
	if strings.Contains(all.out, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(all.err, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("a secret was printed in full")
	}
	if !strings.Contains(all.out, "AKIA…(20 chars)") {
		t.Fatalf("redacted secret missing:\n%s", all.out)
	}

	urls := run(t, testEnv{}, "strings", path, "-c", "url,email")
	if strings.Contains(urls.out, "plain words") || !strings.Contains(urls.out, "admin@example.org") {
		t.Fatalf("category filter wrong:\n%s", urls.out)
	}

	j := run(t, testEnv{}, "strings", path, "--json", "--category", "secret")
	var out struct {
		File    report.File
		Matched int
		Items   []report.StringItem
	}
	if err := json.Unmarshal([]byte(j.out), &out); err != nil {
		t.Fatal(err)
	}
	if out.Matched != 1 || len(out.Items) != 1 || !out.Items[0].Redacted || out.File.Name != "s.bin" {
		t.Fatalf("json = %+v", out)
	}
	none := run(t, testEnv{}, "strings", path, "--json", "--category", "registry")
	if !strings.Contains(none.out, `"items": []`) {
		t.Fatalf("no match must give an empty array, not null:\n%s", none.out)
	}
}

func TestHashCommand(t *testing.T) {
	a := write(t, "a.bin", []byte("abc"))
	b := write(t, "b.bin", []byte(""))
	one := run(t, testEnv{}, "hash", a, "--json")
	var sum map[string]any
	if err := json.Unmarshal([]byte(one.out), &sum); err != nil {
		t.Fatalf("one file must print an object: %v\n%s", err, one.out)
	}
	if hashes := sum["hashes"].(map[string]any); hashes["sha256"] != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %v", hashes["sha256"])
	}
	two := run(t, testEnv{}, "hash", a, b, "--json")
	var arr []map[string]any
	if err := json.Unmarshal([]byte(two.out), &arr); err != nil || len(arr) != 2 {
		t.Fatalf("several files must print an array: %v\n%s", err, two.out)
	}
	human := run(t, testEnv{}, "hash", a)
	if !strings.Contains(human.out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") || !strings.Contains(human.out, "entropy") {
		t.Fatalf("human output:\n%s", human.out)
	}
	partial := run(t, testEnv{}, "hash", a, filepath.Join(t.TempDir(), "missing"), "--json")
	if partial.code != exitError || !strings.Contains(partial.err, "teardown hash:") {
		t.Fatalf("a missing file must fail the command: %d %q", partial.code, partial.err)
	}
	if !strings.Contains(partial.out, "ba7816bf") {
		t.Errorf("the readable file must still be reported:\n%s", partial.out)
	}
}

func TestDiffCommand(t *testing.T) {
	a := write(t, "a.exe", testfixtures.PE(testfixtures.PEOptions{}))
	b := write(t, "b.exe", rwxPE())
	r := run(t, testEnv{}, "diff", a, b, "--json")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	var d struct {
		Schema    string
		Identical bool
		Sections  struct{ Added []string }
		Findings  struct{ Added []struct{ ID string } }
		Summary   []string
	}
	if err := json.Unmarshal([]byte(r.out), &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != "teardown.diff/v1" || d.Identical || !contains(d.Sections.Added, ".rwx") || len(d.Findings.Added) == 0 {
		t.Fatalf("diff = %+v", d)
	}
	human := run(t, testEnv{}, "diff", a, b)
	if !strings.Contains(human.out, "teardown diff") || !strings.Contains(human.out, "structure.rwx-section") {
		t.Fatalf("human diff:\n%s", human.out)
	}
	same := run(t, testEnv{}, "diff", a, a, "--json")
	if !strings.Contains(same.out, `"identical": true`) {
		t.Fatalf("same file must be identical:\n%s", same.out)
	}
	if bad := run(t, testEnv{}, "diff", a, filepath.Join(t.TempDir(), "x")); bad.code != exitError {
		t.Fatalf("missing file: %d", bad.code)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestCompletionScriptsAreGeneratedFromTheCommandTable(t *testing.T) {
	for _, shell := range completionShells {
		t.Run(shell, func(t *testing.T) {
			r := run(t, testEnv{}, "completion", shell)
			if r.code != exitOK || len(r.out) < 500 {
				t.Fatalf("code %d, %d bytes", r.code, len(r.out))
			}
			for _, c := range commands() {
				if !strings.Contains(r.out, c.name) {
					t.Errorf("%s completion lacks command %q", shell, c.name)
				}
			}
			for _, flagName := range []string{"fail-on", "min-string", "max-upload", "root", "category"} {
				if !strings.Contains(r.out, flagName) {
					t.Errorf("%s completion lacks --%s", shell, flagName)
				}
			}
			if strings.ContainsRune(r.out, '\r') {
				t.Error("scripts must use LF line endings")
			}
		})
	}
	if r := run(t, testEnv{}, "completion", "pwsh"); r.code != exitOK {
		t.Errorf("pwsh alias: %d", r.code)
	}
}

func TestParseInterspersed(t *testing.T) {
	var j bool
	var n int
	f := newFlagSet("x")
	f.Bool(&j, "json", "", "u")
	f.Int(&n, "n", "", "N", 0, "u")
	pos, err := f.Parse([]string{"a", "--json", "b", "-n", "5", "--", "--json", "c"})
	if err != nil || !j || n != 5 || strings.Join(pos, ",") != "a,b,--json,c" {
		t.Fatalf("pos=%v j=%v n=%d err=%v", pos, j, n, err)
	}
	if _, err := f.Parse([]string{"--nope"}); err == nil {
		t.Fatal("unknown flags must fail")
	}
	if _, err := f.Parse([]string{"-h"}); !helpRequested(err) {
		t.Fatalf("-h must signal help, got %v", err)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"64k", 64 << 10, false},
		{"64KiB", 64 << 10, false},
		{"256MiB", 256 << 20, false},
		{"256 mib", 256 << 20, false},
		{"1.5GiB", 3 << 29, false},
		{"100MB", 100_000_000, false},
		{"2GB", 2_000_000_000, false},
		{"7B", 7, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-5", 0, true},
		{"0", 0, true},
		{"2TiB", 0, true},
		{"NaN", 0, true},
	}
	for _, tc := range tests {
		got, err := parseSize(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseSize(%q) = %d, %v; want %d (err %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
	for _, n := range []int64{1, 1023, 1 << 10, 5 << 20, 3 << 30, 1500} {
		back, err := parseSize(formatSize(n))
		if err != nil || back != n {
			t.Errorf("round trip %d -> %q -> %d (%v)", n, formatSize(n), back, err)
		}
	}
}

func TestEditDistanceAndSuggest(t *testing.T) {
	if editDistance("kitten", "sitting") != 3 || editDistance("", "abc") != 3 || editDistance("same", "same") != 0 {
		t.Error("editDistance is wrong")
	}
	if suggest("strngs") != "strings" || suggest("zzzzzzzz") != "" {
		t.Errorf("suggest = %q / %q", suggest("strngs"), suggest("zzzzzzzz"))
	}
}

func TestTerminalHelpers(t *testing.T) {
	get := func(m map[string]string) Env { return Env{Getenv: func(k string) string { return m[k] }} }
	if terminalWidth(get(map[string]string{"COLUMNS": "120"})) != 120 || terminalWidth(get(map[string]string{"COLUMNS": "abc"})) != 0 ||
		terminalWidth(get(map[string]string{"COLUMNS": "5"})) != 0 || terminalWidth(get(nil)) != 0 {
		t.Error("terminalWidth is wrong")
	}
	if !asciiOnly(false, get(map[string]string{"LC_ALL": "C"})) || asciiOnly(false, get(map[string]string{"LANG": "en_US.UTF-8"})) ||
		!asciiOnly(true, get(nil)) || !asciiOnly(false, get(map[string]string{"TEARDOWN_ASCII": "1"})) || asciiOnly(false, get(nil)) {
		t.Error("asciiOnly is wrong")
	}
}

var urlRe = regexp.MustCompile(`http://127\.0\.0\.1:\d+`)

// lockedBuffer lets the test read stderr while the server goroutine writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestServeStartsAnsweringAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := &lockedBuffer{}
	env := Env{Stdout: io.Discard, Stderr: stderr, Getenv: func(string) string { return "" }, IsTTY: func(io.Writer) bool { return false }}
	done := make(chan int, 1)
	go func() { done <- Run(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--keep", "5"}, env) }()

	var base string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && base == "" {
		base = urlRe.FindString(stderr.String())
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		cancel()
		t.Fatalf("server never announced its address: %q", stderr.String())
	}
	resp, err := http.Get(base + "/api/health")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health = %d %s", resp.StatusCode, body)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("serve exit code = %d, stderr: %s", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop after cancellation")
	}
}

func TestMCPSpeaksOnlyProtocolOnStdout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.bin"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdin := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	r := run(t, testEnv{stdin: stdin}, "mcp", "--root", dir)
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 responses (initialize, tools/list), got %d:\n%s", len(lines), r.out)
	}
	for _, l := range lines {
		var msg map[string]any
		if err := json.Unmarshal([]byte(l), &msg); err != nil || msg["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line is not JSON-RPC: %q", l)
		}
	}
	if !strings.Contains(lines[1], "analyze_file") || !strings.Contains(lines[1], "diff_files") {
		t.Errorf("tools/list lacks the expected tools: %s", lines[1])
	}
	if bad := run(t, testEnv{}, "mcp", "--root", filepath.Join(dir, "does-not-exist")); bad.code != exitError {
		t.Fatalf("a missing root must fail: %d %s", bad.code, bad.err)
	}
}
