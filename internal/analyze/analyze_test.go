package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

var update = flag.Bool("update", false, "rewrite testdata/sample-report.json")

func fixedClock() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }

func analyzeBytes(t *testing.T, name string, data []byte) *report.Report {
	t.Helper()
	rep, err := Reader(context.Background(), bytes.NewReader(data), int64(len(data)), Options{Name: name, Now: fixedClock})
	if err != nil {
		t.Fatalf("analyze %s: %v", name, err)
	}
	return rep
}

func findingIDs(rep *report.Report) []string {
	ids := make([]string, len(rep.Findings))
	for i, f := range rep.Findings {
		ids[i] = f.ID
	}
	return ids
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func TestFixtureTypesFindingsAndFacts(t *testing.T) {
	githubSlip := testfixtures.ZipSlip()
	tests := []struct {
		name       string
		data       []byte
		wantType   string
		wantTags   []string
		wantFind   []string
		wantAbsent []string
		wantDetail []string
	}{
		{name: "minimal pe", data: testfixtures.PE(testfixtures.PEOptions{}), wantType: report.TypePE, wantTags: []string{"exe", "64-bit"},
			wantFind: []string{"signature.unsigned"}, wantDetail: []string{"pe"}},
		{name: "signed pe", data: testfixtures.PE(testfixtures.PEOptions{Signed: true}), wantType: report.TypePE,
			wantAbsent: []string{"signature.unsigned"}, wantDetail: []string{"pe"}},
		{name: "pe with rwx section", wantType: report.TypePE,
			data:     testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{{Name: ".rwx", Data: make([]byte, 700), Characteristics: testfixtures.PESectionRWX}}}),
			wantFind: []string{"structure.rwx-section"}},
		{name: "pe with upx sections", wantType: report.TypePE, wantTags: []string{"upx"},
			data: testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{
				{Name: "UPX0", NoRaw: true, VirtualSize: 0x10000, Characteristics: testfixtures.PESectionRWX},
				{Name: "UPX1", Data: make([]byte, 600), Characteristics: testfixtures.PESectionCode},
			}}),
			wantFind: []string{"packing.upx"}},
		{name: "pe with pdb path", wantType: report.TypePE, data: testfixtures.PE(testfixtures.PEOptions{PDBPath: `C:\build\x.pdb`}),
			wantFind: []string{"privacy.pdb-path"}},
		{name: "pe with known packer section", wantType: report.TypePE,
			data:     testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{{Name: ".aspack", Data: make([]byte, 700), Characteristics: testfixtures.PESectionCode}}}),
			wantFind: []string{"packing.known-packer"}},
		{name: "pe without dep", wantType: report.TypePE, data: testfixtures.PE(testfixtures.PEOptions{DllCharsClear: 0x0100}), wantFind: []string{"hardening.no-dep"}},
		{name: "pe with overlay", wantType: report.TypePE, data: testfixtures.PE(testfixtures.PEOptions{Overlay: make([]byte, 5000)}), wantFind: []string{"structure.overlay"}},
		{name: "pe from the future", wantType: report.TypePE, data: testfixtures.PE(testfixtures.PEOptions{Timestamp: 2_100_000_000}), wantFind: []string{"structure.timestamp-anomaly"}},
		{name: "dll", wantType: report.TypePE, wantTags: []string{"dll"}, data: testfixtures.PE(testfixtures.PEOptions{DLL: true})},
		{name: "dotnet", wantType: report.TypePE, wantTags: []string{"dotnet"}, data: testfixtures.PE(testfixtures.PEOptions{DotNet: true})},
		{name: "elf", wantType: report.TypeELF, data: testfixtures.ELF(testfixtures.ELFOptions{}), wantDetail: []string{"elf"}},
		{name: "elf without nx", wantType: report.TypeELF, data: testfixtures.ELF(testfixtures.ELFOptions{Stack: testfixtures.ELFStackRWX}),
			wantFind: []string{"hardening.no-nx"}},
		{name: "elf insecure rpath", wantType: report.TypeELF, data: testfixtures.ELF(testfixtures.ELFOptions{RunPath: []string{"/tmp/x"}}),
			wantFind: []string{"structure.insecure-rpath"}},
		{name: "elf rwx segment", wantType: report.TypeELF,
			data:     testfixtures.ELF(testfixtures.ELFOptions{Segments: []testfixtures.ELFSegment{{Type: testfixtures.ELFSegmentLoad, Flags: 7, Data: make([]byte, 64)}}}),
			wantFind: []string{"structure.rwx-segment"}},
		{name: "elf with libc imports", wantType: report.TypeELF,
			data: testfixtures.ELF(testfixtures.ELFOptions{Imports: []testfixtures.ELFImport{
				{Name: "socket", Library: "libc.so.6", Version: "GLIBC_2.2.5"}, {Name: "connect", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
				{Name: "dup2", Library: "libc.so.6", Version: "GLIBC_2.2.5"}, {Name: "execve", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
			}}),
			wantFind: []string{"imports.reverse-shell-pattern"}},
		{name: "go binary", wantType: report.TypeELF, wantTags: []string{"go"}, wantDetail: []string{"go", "elf"},
			data: testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{Settings: []testfixtures.GoBuildInfoSetting{
				{Key: "-buildmode", Value: "exe"}, {Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"}, {Key: "vcs.time", Value: "2026-11-01T10:00:00Z"}, {Key: "vcs.modified", Value: "true"},
			}}),
			wantFind: []string{"build.go-vcs"}},
		{name: "zip slip", wantType: report.TypeZip, data: githubSlip, wantFind: []string{"archive.zip-slip"}, wantDetail: []string{"archive"}},
		{name: "overlapping zip", wantType: report.TypeZip, data: testfixtures.ZipOverlapping(), wantFind: []string{"archive.zip-bomb"}},
		{name: "duplicate names", wantType: report.TypeZip, data: testfixtures.ZipDuplicateNames(), wantFind: []string{"archive.duplicate-names"}},
		{name: "jar", wantType: report.TypeJar, data: testfixtures.JAR(testfixtures.JAROptions{MainClass: "demo.Main"}), wantDetail: []string{"archive"}, wantAbsent: []string{"signature.unsigned"}},
		{name: "apk", wantType: report.TypeAPK, wantDetail: []string{"archive"}, wantFind: []string{"android.sensitive-permissions", "signature.unsigned"},
			data: testfixtures.APK(testfixtures.APKOptions{Permissions: []string{
				"android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO",
			}})},
		{name: "signed apk", wantType: report.TypeAPK, data: testfixtures.APK(testfixtures.APKOptions{V1Signed: true}), wantAbsent: []string{"signature.unsigned"}},
		{name: "aab", wantType: report.TypeAAB, data: testfixtures.AAB(testfixtures.AABOptions{}), wantDetail: []string{"archive"}},
		{name: "electron asar", wantType: report.TypeAsar, data: testfixtures.AsarElectronApp(), wantDetail: []string{"asar"},
			wantFind: []string{"application.electron-app", "application.electron-risky-settings"}},
		{name: "wasm", wantType: report.TypeWasm, data: testfixtures.WasmSample(), wantDetail: []string{"wasm"}},
		{name: "gguf model", wantType: report.TypeGGUF, data: testfixtures.GGUF(testfixtures.GGUFOptions{}), wantDetail: []string{"gguf"}},
		{name: "text", wantType: report.TypeText, data: []byte("just some text\nand a second line\n")},
		{name: "empty", wantType: report.TypeData, data: nil},
		{name: "shebang script", wantType: report.TypeScript, data: []byte("#!/bin/sh\necho hello\n")},
		{name: "masquerading executable", wantType: report.TypePE, data: testfixtures.PE(testfixtures.PEOptions{}), wantFind: []string{"file.type-mismatch"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := strings.ReplaceAll(tc.name, " ", "_") + ".bin"
			if tc.name == "masquerading executable" {
				name = "holiday-photo.jpg"
			}
			rep := analyzeBytes(t, name, tc.data)
			if rep.Type.ID != tc.wantType {
				t.Fatalf("type = %q (%s), want %q", rep.Type.ID, rep.Type.Label, tc.wantType)
			}
			for _, tag := range tc.wantTags {
				if !rep.HasTag(tag) {
					t.Errorf("missing tag %q in %v", tag, rep.Type.Tags)
				}
			}
			ids := findingIDs(rep)
			for _, id := range tc.wantFind {
				if !slices.Contains(ids, id) {
					t.Errorf("missing finding %q in %v", id, ids)
				}
			}
			for _, id := range tc.wantAbsent {
				if slices.Contains(ids, id) {
					t.Errorf("unexpected finding %q", id)
				}
			}
			for _, key := range tc.wantDetail {
				if _, ok := rep.Details[key]; !ok {
					t.Errorf("missing details[%q]; have %v", key, keysOf(rep.Details))
				}
			}
			for _, id := range ids {
				if id == "parser.error" {
					t.Errorf("a valid fixture must not trip the parser: %+v", rep.Findings)
				}
			}
			if rep.Schema != report.Schema || len(rep.Hashes.SHA256) != 64 || len(rep.Limitations) < 2 || rep.File.Size != int64(len(tc.data)) {
				t.Errorf("report header is incomplete: %+v", rep.File)
			}
			if rep.Risk.Label == "" || len(rep.Risk.Basis) < 2 {
				t.Errorf("risk must be scored and explained: %+v", rep.Risk)
			}
			if _, err := json.Marshal(rep); err != nil {
				t.Errorf("report must marshal: %v", err)
			}
		})
	}
}

func keysOf(m map[string]any) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestPEFixtureFactsReachTheReport(t *testing.T) {
	rep := analyzeBytes(t, "x.exe", testfixtures.SamplePE())
	if len(rep.Sections) < 6 || len(rep.Imports) != 5 || rep.Hashes.Imphash == "" {
		t.Fatalf("sections %d imports %d imphash %q", len(rep.Sections), len(rep.Imports), rep.Hashes.Imphash)
	}
	byName := map[string]report.Section{}
	for _, s := range rep.Sections {
		byName[s.Name] = s
	}
	if s := byName[".packed"]; s.Entropy < 7.5 || !s.Executable() {
		t.Errorf(".packed = %+v", s)
	}
	if s := byName[".rwx"]; !s.Writable() || !s.Executable() {
		t.Errorf(".rwx = %+v", s)
	}
	want := []string{
		"packing.high-entropy-section", "structure.rwx-section", "imports.process-injection", "imports.keylogging",
		"imports.download-and-execute", "imports.crypto", "imports.networking", "secrets.aws-access-key-id", "secrets.github-token",
		"indicators.network", "indicators.suspicious-commands", "indicators.persistence-registry", "privacy.pdb-path",
		"hardening.no-aslr", "signature.unsigned", "structure.overlay",
	}
	ids := findingIDs(rep)
	for _, id := range want {
		if !slices.Contains(ids, id) {
			t.Errorf("missing finding %q\nhave: %v", id, ids)
		}
	}
	if rep.Risk.Score < 45 {
		t.Errorf("a dropper-shaped sample should score at least high, got %d (%s)", rep.Risk.Score, rep.Risk.Label)
	}
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i-1].Severity.Rank() < rep.Findings[i].Severity.Rank() {
			t.Fatal("findings must be sorted by severity")
		}
	}
}

// TestSecretsNeverAppearInFull is the redaction promise: whatever route a
// secret takes into the analysis, no output form contains it.
func TestSecretsNeverAppearInFull(t *testing.T) {
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("Zy9x", 9)
	slackToken := "xoxb-" + "123456789012-" + "abcdefABCDEF1234"
	secrets := []string{awsKey, ghToken, slackToken}
	blob := []byte("config\x00key=" + awsKey + "\x00" + ghToken + "\x00" + slackToken + "\x00")

	inputs := map[string][]byte{
		"plain blob": blob,
		"pe": testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{
			{Name: ".cfg", Data: blob, Characteristics: testfixtures.PESectionRData},
		}, PDBPath: `C:\src\` + awsKey + `\x.pdb`}),
		"zip entry name": testfixtures.Zip(testfixtures.ZipEntry{Name: "dir/" + ghToken + ".txt", Data: []byte("x"), Store: true}),
		"go ldflags": testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{Settings: []testfixtures.GoBuildInfoSetting{
			{Key: "-ldflags", Value: "-X main.token=" + ghToken + " -X main.key=" + awsKey},
		}}),
		"asar package": testfixtures.Asar(testfixtures.AsarFile{Path: "package.json", Data: []byte(`{"name":"demo","version":"1.0.0","main":"main.js","description":"` + slackToken + `"}`)}),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			rep := analyzeBytes(t, "secrets.bin", data)
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets {
				if bytes.Contains(raw, []byte(s)) {
					t.Fatalf("report contains the raw secret %q:\n%s", s, raw)
				}
			}
		})
	}
	rep := analyzeBytes(t, "blob.bin", blob)
	var kinds []string
	for _, it := range rep.Strings.Items {
		if it.Category == report.CatSecret {
			if !it.Redacted || it.Kind == "" || !strings.Contains(it.Value, "…(") {
				t.Errorf("secret item not redacted: %+v", it)
			}
			kinds = append(kinds, it.Kind)
		}
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"aws-access-key-id", "github-token", "slack-token"}) {
		t.Fatalf("secret kinds = %v", kinds)
	}
	for _, id := range []string{"secrets.aws-access-key-id", "secrets.github-token", "secrets.slack-token"} {
		if !slices.Contains(findingIDs(rep), id) {
			t.Errorf("missing %s", id)
		}
	}
}

func TestGuardConvertsPanicsIntoParserErrorFindings(t *testing.T) {
	rep := report.New("x", 1, "dev")
	s := &stages{ctx: context.Background(), rep: rep, timeout: time.Second}
	s.run("demo", func() error {
		var m map[string]int
		m["boom"] = 1 // nil map write
		return nil
	})
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.ID != "parser.error" || !strings.Contains(f.Title, "crashed") || len(f.Limitations) < 2 {
		t.Fatalf("finding = %+v", f)
	}
	joined := strings.Join(f.Evidence, "\n")
	if !strings.Contains(joined, "nil map") || !strings.Contains(joined, "location:") {
		t.Fatalf("evidence = %v", f.Evidence)
	}

	s.run("plain", func() error { return errors.New("bad header") })
	s.run("late", func() error { return context.DeadlineExceeded })
	s.run("cancelled", func() error { return context.Canceled })
	s.run("fine", func() error { return nil })
	ids := findingIDs(rep)
	if !slices.Equal(ids, []string{"parser.error", "parser.error", "analysis.incomplete"}) {
		t.Fatalf("ids = %v (cancellation and success must not add findings)", ids)
	}
	s.notes("demo", []string{"skipped table"})
	if last := rep.Findings[len(rep.Findings)-1]; last.ID != "parser.warning" || last.Severity != report.SeverityInfo {
		t.Fatalf("notes finding = %+v", last)
	}
}

func TestCorruptInputDegradesGracefully(t *testing.T) {
	good := testfixtures.SamplePE()
	for _, n := range []int{2, 64, 100, 200, 400, 1000, len(good) / 2} {
		rep := analyzeBytes(t, "cut.exe", good[:n])
		if rep.Schema != report.Schema || rep.Hashes.SHA256 == "" {
			t.Fatalf("truncated to %d: report is incomplete", n)
		}
		for _, f := range rep.Findings {
			if len(f.Evidence) == 0 || len(f.Limitations) == 0 {
				t.Fatalf("truncated to %d: finding %s lacks evidence or limitations", n, f.ID)
			}
		}
	}
	rep := analyzeBytes(t, "mz.exe", append([]byte("MZ"), repeat(0xff, 200)...))
	if rep.Risk.Label == "" {
		t.Fatal("garbage after an MZ magic must still be scored")
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := make([]byte, 1<<20)
	if _, err := Reader(ctx, bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Reader(context.Background(), bytes.NewReader(data), int64(len(data)), Options{Timeout: time.Nanosecond}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("a 1ns budget must fail with a timeout message, got %v", err)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	data := testfixtures.SamplePE()
	a, _ := json.Marshal(analyzeBytes(t, "sample.exe", data))
	b, _ := json.Marshal(analyzeBytes(t, "sample.exe", data))
	if !bytes.Equal(a, b) {
		t.Fatal("the same input and clock must give byte-identical reports")
	}
}

func TestQuickAndStringsAndFile(t *testing.T) {
	data := testfixtures.SamplePE()
	path := filepath.Join(t.TempDir(), "dir-name.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	sum, err := QuickFile(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := File(ctx, path, Options{Now: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if sum.File.Name != "dir-name.exe" || sum.Hashes != full.Hashes || sum.Type.ID != report.TypePE || sum.Hashes.Imphash == "" {
		t.Fatalf("quick summary disagrees with the full report: %+v vs %+v", sum.Hashes, full.Hashes)
	}
	if sum.Entropy.Overall != full.Entropy.Overall || len(sum.Entropy.Windows) != len(full.Entropy.Windows) {
		t.Fatal("entropy differs between Quick and Reader")
	}

	sres, err := StringsFile(ctx, path, Options{MinString: 8})
	if err != nil {
		t.Fatal(err)
	}
	if sres.File.Name != "dir-name.exe" || sres.Strings.MinLength != 8 || sres.Strings.Total == 0 {
		t.Fatalf("strings result = %+v", sres.File)
	}

	if _, err := File(ctx, t.TempDir(), Options{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directories must be rejected, got %v", err)
	}
	if _, err := File(ctx, filepath.Join(t.TempDir(), "missing"), Options{}); err == nil {
		t.Fatal("a missing file must fail")
	}
}

// noParserNotice is the limitation added for types that are recognised but not parsed.
const noParserNotice = "No format-specific parser exists for"

func hasLimitation(rep *report.Report, fragment string) bool {
	return slices.ContainsFunc(rep.Limitations, func(l string) bool { return strings.Contains(l, fragment) })
}

func TestRecognisedOnlyTypesSayNoParserExists(t *testing.T) {
	sqlite := analyzeBytes(t, "app.db", append([]byte("SQLite format 3\x00"), make([]byte, 4096)...))
	if sqlite.Type.ID != report.TypeSQLite {
		t.Fatalf("type = %q, want sqlite", sqlite.Type.ID)
	}
	if !hasLimitation(sqlite, noParserNotice) {
		t.Errorf("a recognised-only type must say that no parser exists: %v", sqlite.Limitations)
	}
	if _, ok := sqlite.Details["sqlite"]; ok {
		t.Errorf("no parser exists, so details must not claim one: %v", keysOf(sqlite.Details))
	}

	model := analyzeBytes(t, "model.gguf", testfixtures.GGUF(testfixtures.GGUFOptions{Architecture: "llama", Name: "demo"}))
	if hasLimitation(model, noParserNotice) {
		t.Errorf("GGUF has a parser and must not claim otherwise: %v", model.Limitations)
	}
	raw, err := json.Marshal(model.Details["gguf"])
	if err != nil || !strings.Contains(string(raw), `"architecture":"llama"`) || !strings.Contains(string(raw), `"name":"demo"`) {
		t.Errorf("GGUF details are missing the header facts: %s (%v)", raw, err)
	}
}

func TestNameIsSanitised(t *testing.T) {
	rep := analyzeBytes(t, "evil\x1b[31m\nname.exe", []byte("x"))
	if strings.ContainsAny(rep.File.Name, "\x1b\n") {
		t.Fatalf("control characters in the name: %q", rep.File.Name)
	}
	long := strings.Repeat("a", 1000)
	if got := analyzeBytes(t, long, []byte("x")).File.Name; len([]rune(got)) > 256 {
		t.Fatalf("name not bounded: %d runes", len([]rune(got)))
	}
	if got := analyzeBytes(t, "", []byte("x")).File.Name; got != "(unnamed)" {
		t.Fatalf("default name = %q", got)
	}
}

func TestStringLimitsAreHonoured(t *testing.T) {
	var sb strings.Builder
	for i := range 500 {
		sb.WriteString("string number ")
		sb.WriteString(strings.Repeat("x", i%7+1))
		sb.WriteByte(byte('a' + i%26))
		sb.WriteByte(0)
	}
	rep, err := Reader(context.Background(), strings.NewReader(sb.String()), int64(sb.Len()), Options{MaxStrings: 50, MinString: 6, Now: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Strings.Items) > 50 || !rep.Strings.Truncated || rep.Strings.Total < 400 || rep.Strings.MinLength != 6 {
		t.Fatalf("strings = total %d items %d truncated %v min %d", rep.Strings.Total, len(rep.Strings.Items), rep.Strings.Truncated, rep.Strings.MinLength)
	}
	if !slices.ContainsFunc(rep.Limitations, func(s string) bool { return strings.Contains(s, "string list holds") }) {
		t.Fatalf("truncation must be a report-level limitation: %v", rep.Limitations)
	}
}

func TestSelfAnalysis(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable path: %v", err)
	}
	rep, err := File(context.Background(), exe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantType := map[string]string{"windows": report.TypePE, "darwin": report.TypeMachO}[runtime.GOOS]
	if wantType == "" {
		wantType = report.TypeELF
	}
	if rep.Type.ID != wantType || rep.Type.Family != report.FamilyExecutable {
		t.Fatalf("the Go test binary is %s/%s (%s), want %s", rep.Type.ID, rep.Type.Family, rep.Type.Label, wantType)
	}
	if len(rep.Sections) < 3 || rep.Strings.Total < 1000 || len(rep.Hardening) == 0 {
		t.Errorf("sections %d strings %d hardening %d", len(rep.Sections), rep.Strings.Total, len(rep.Hardening))
	}
	if !rep.HasTag("go") {
		t.Errorf("a Go binary must be tagged go: %v", rep.Type.Tags)
	}
	raw, _ := json.Marshal(rep.Details["go"])
	if !bytes.Contains(raw, []byte(`"goVersion"`)) || !bytes.Contains(raw, []byte(runtime.Version())) {
		t.Errorf("go build info missing or wrong (want %s): %s", runtime.Version(), raw)
	}
	for _, f := range rep.Findings {
		if f.ID == "parser.error" || f.ID == "analysis.incomplete" {
			t.Errorf("self analysis must be clean: %+v", f)
		}
	}
	if runtime.GOOS == "windows" {
		if _, ok := rep.Details["pe"]; !ok || rep.Hashes.Imphash == "" {
			t.Errorf("the test binary must have PE details and an imphash")
		}
	}
}

func TestLargeInputStaysFast(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	data := testfixtures.SamplePE()
	big := append(bytes.Clone(data), make([]byte, 24<<20)...)
	start := time.Now()
	rep := analyzeBytes(t, "big.exe", big)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("24 MiB took %s", d)
	}
	if rep.Type.ID != report.TypePE || len(rep.Entropy.Windows) > 512 || len(rep.Strings.Items) > DefaultMaxStrings {
		t.Fatalf("bounds violated: type %s windows %d strings %d", rep.Type.ID, len(rep.Entropy.Windows), len(rep.Strings.Items))
	}
}

var secretLike = regexp.MustCompile(`AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}`)

func FuzzAnalyze(f *testing.F) {
	seeds := [][]byte{
		testfixtures.SamplePE(), testfixtures.PE(testfixtures.PEOptions{}), testfixtures.ELF(testfixtures.ELFOptions{}),
		testfixtures.ZipSlip(), testfixtures.APK(testfixtures.APKOptions{}), testfixtures.AsarElectronApp(), testfixtures.WasmSample(),
		testfixtures.JAR(testfixtures.JAROptions{}), []byte("#!/bin/sh\necho hi\n"), []byte("AKIAIOSFODNN7EXAMPLE and text"), nil,
	}
	for _, s := range seeds {
		f.Add(s)
		if len(s) > 80 {
			f.Add(s[:len(s)/2])
			f.Add(s[:77])
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("keep fuzz inputs small")
		}
		rep, err := Reader(context.Background(), bytes.NewReader(data), int64(len(data)), Options{Name: "fuzz.bin", Now: fixedClock, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("Reader failed on a readable input: %v", err)
		}
		for _, f := range rep.Findings {
			if f.ID == "parser.error" && strings.Contains(strings.Join(f.Evidence, " "), "internal error") {
				t.Fatalf("a parser panicked (the recover hid a bug): %+v", f)
			}
			if len(f.Evidence) == 0 || len(f.Limitations) == 0 {
				t.Fatalf("finding %s lacks evidence or limitations", f.ID)
			}
		}
		raw, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if m := secretLike.Find(raw); m != nil && !bytes.Contains(data, m) {
			t.Fatalf("a secret-like value appeared that was not in the input: %q", m)
		}
		if secretLike.Match(raw) {
			t.Fatalf("a full secret leaked into the report: %s", secretLike.Find(raw))
		}
	})
}

// TestSampleReport pins the JSON contract against a real fixture. Regenerate
// testdata/sample-report.json (also used by docs and the dashboard) with:
//
//	go test ./internal/analyze -run TestSampleReport -update
func TestSampleReport(t *testing.T) {
	rep := analyzeBytes(t, "sample.exe", testfixtures.SamplePE())
	got, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("..", "..", "testdata", "sample-report.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with -update)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale or the report changed; if the change is intended regenerate it with: go test ./internal/analyze -run TestSampleReport -update", path)
	}
	var back report.Report
	if err := json.Unmarshal(want, &back); err != nil || back.Schema != report.Schema {
		t.Fatalf("the sample must decode into report.Report: %v", err)
	}
}
