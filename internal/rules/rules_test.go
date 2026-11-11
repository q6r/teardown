package rules

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/report"
)

var update = flag.Bool("update", false, "rewrite docs/rules.md from the rule catalogue")

var testNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func base(name, typeID, family string, size int64) *report.Report {
	r := report.New(name, size, "test")
	r.GeneratedAt = testNow
	r.Type = report.Type{ID: typeID, Family: family, Label: strings.ToUpper(typeID) + " test file", Confidence: report.ConfidenceHigh, Tags: []string{}}
	return r
}

func sec(name string, entropy float64, raw uint64, flags ...string) report.Section {
	return report.Section{Name: name, RawSize: raw, VirtualSize: raw, Entropy: entropy, Flags: flags}
}

func imports(lib string, fns ...string) []report.Import {
	return []report.Import{{Library: lib, Count: len(fns), Functions: fns}}
}

func ids(fs []report.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func find(t *testing.T, fs []report.Finding, id string) report.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %q not found among %v", id, ids(fs))
	return report.Finding{}
}

func peScenario() *report.Report {
	r := base("setup.bin", report.TypePE, report.FamilyExecutable, 200<<10)
	r.Type.Tags = []string{"upx", "pyinstaller", "exe"}
	r.Sections = []report.Section{
		sec(".text", 7.83, 20<<10, report.FlagR, report.FlagX),
		{Name: ".rwx", RawSize: 4096, Entropy: 3.1, Flags: []string{report.FlagR, report.FlagW, report.FlagX}, Suspicious: true, Reasons: []string{"writable and executable"}},
		{Name: ".weird", RawSize: 0, Entropy: 0, Flags: []string{report.FlagR, report.FlagX}, Suspicious: true, Reasons: []string{"unusual name", "executable section with no raw data"}},
		sec(".rsrc", 7.5, 8192, report.FlagR),
		sec("UPX1", 3.0, 100, report.FlagR),
	}
	r.Imports = []report.Import{
		{Library: "KERNEL32.dll", Count: 14, Functions: []string{
			"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "IsDebuggerPresent",
			"CreateProcessW", "OpenSCManagerA", "CreateServiceA", "StartServiceA", "LoadLibraryA", "GetProcAddress",
			"AdjustTokenPrivileges", "LookupPrivilegeValueA", "OpenProcessToken",
		}},
		{Library: "USER32.dll", Count: 3, Functions: []string{"SetWindowsHookExA", "GetAsyncKeyState", "GetForegroundWindow"}},
		{Library: "NTDLL.dll", Count: 2, Functions: []string{"NtQueryInformationProcess", "ZwQuerySystemInformation"}},
		{Library: "ADVAPI32.dll", Count: 2, Functions: []string{"CryptEncrypt", "CryptAcquireContextA"}},
		{Library: "WS2_32.dll", Count: 2, Functions: []string{"WSAStartup", "connect"}},
		{Library: "URLMON.dll", Count: 1, Functions: []string{"URLDownloadToFileA"}},
	}
	r.Hardening = []report.Hardening{
		{ID: report.HardenASLR, Label: "ASLR", Status: report.StatusDisabled, Detail: "DYNAMIC_BASE not set"},
		{ID: report.HardenDEP, Label: "DEP", Status: report.StatusDisabled, Detail: "NX_COMPAT not set"},
		{ID: report.HardenCFG, Label: "CFG", Status: report.StatusDisabled, Detail: "GUARD_CF not set"},
		{ID: report.HardenSEH, Label: "SEH", Status: report.StatusDisabled, Detail: "no SafeSEH table"},
		{ID: report.HardenHighEntropyVA, Label: "HIGH_ENTROPY_VA", Status: report.StatusDisabled, Detail: "not set"},
		{ID: report.HardenSigned, Label: "Authenticode", Status: report.StatusDisabled, Detail: "no certificate table"},
		{ID: report.HardenForceIntegrity, Label: "FORCE_INTEGRITY", Status: report.StatusDisabled, Detail: "not set"},
	}
	r.Details["pe"] = map[string]any{
		"kind": "exe", "entryPoint": "0x9000", "entrySection": ".rsrc", "overlaySize": 120 << 10,
		"timestamp": "2031-01-01T00:00:00Z", "pdbPath": `C:\Users\alice\src\implant\Release\implant.pdb`,
		"packerHints": []string{".aspack", "UPX0"},
	}
	r.Strings = report.Strings{Total: 12, MinLength: 5, ByCategory: map[string]int{report.CatURL: 2, report.CatIP: 2}, Items: []report.StringItem{
		{Value: "AKIA…(20 chars)", Offset: 0x100, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
		{Value: "ghp_…(40 chars)", Offset: 0x200, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "github-token"},
		{Value: "xoxb…(30 chars)", Offset: 0x300, Encoding: "utf16le", Category: report.CatSecret, Redacted: true, Kind: "slack-token"},
		{Value: "----…(31 chars)", Offset: 0x400, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "pem-private-key"},
		{Value: "eyJh…(120 chars)", Offset: 0x500, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "jwt"},
		{Value: "mysT…(18 chars)", Offset: 0x600, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "mystery"},
		{Value: "https://c2.example.net/gate.php", Offset: 0x700, Encoding: "ascii", Category: report.CatURL},
		{Value: "203.0.113.7", Offset: 0x710, Encoding: "ascii", Category: report.CatIP},
		{Value: "192.168.1.10", Offset: 0x720, Encoding: "ascii", Category: report.CatIP},
		{Value: "evil.example.net", Offset: 0x730, Encoding: "ascii", Category: report.CatDomain},
		{Value: "ops@example.net", Offset: 0x740, Encoding: "ascii", Category: report.CatEmail},
		{Value: "powershell -nop -w hidden -enc SQBFAFgA", Offset: 0x800, Encoding: "ascii", Category: report.CatCommand},
		{Value: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, Offset: 0x900, Encoding: "ascii", Category: report.CatRegistry},
	}}
	return r
}

func elfScenario() *report.Report {
	r := base("agent", report.TypeELF, report.FamilyExecutable, 90<<10)
	r.Imports = imports(report.UnspecifiedLibrary, "socket", "connect", "dup2", "execve", "ptrace", "process_vm_writev")
	r.Hardening = []report.Hardening{
		{ID: report.HardenPIE, Label: "PIE", Status: report.StatusDisabled, Detail: "ET_EXEC"},
		{ID: report.HardenNX, Label: "NX", Status: report.StatusDisabled, Detail: "GNU_STACK is executable"},
		{ID: report.HardenRELRO, Label: "RELRO", Status: report.StatusDisabled, Detail: "no PT_GNU_RELRO"},
		{ID: report.HardenCanary, Label: "Stack canary", Status: report.StatusDisabled, Detail: "no __stack_chk_fail"},
		{ID: report.HardenFortify, Label: "FORTIFY", Status: report.StatusDisabled, Detail: "no _chk imports"},
	}
	r.Details["elf"] = map[string]any{
		"rpath": []string{"."}, "runpath": []string{"/tmp/libs", "relative/dir", "$ORIGIN/../lib"},
		"segments": []map[string]any{{"type": "LOAD", "flags": []string{"R", "W", "X"}, "vaddr": "0x400000"}},
	}
	return r
}

func partialRelroScenario() *report.Report {
	r := base("lib.so", report.TypeELF, report.FamilyExecutable, 50<<10)
	r.Hardening = []report.Hardening{{ID: report.HardenRELRO, Label: "RELRO", Status: report.StatusEnabled, Detail: "partial RELRO (no BIND_NOW)"}}
	return r
}

func archiveScenario() *report.Report {
	r := base("update.apk", report.TypeAPK, report.FamilyPackage, 5<<20)
	r.Details["archive"] = map[string]any{
		"kind": "apk", "entryCount": 40, "totalCompressed": 5 << 20, "totalUncompressed": uint64(3) << 30, "ratio": 614.4,
		"maxRatio": 5000.0, "maxRatioEntry": "assets/blob.bin", "unsafeNames": []string{"../../evil.sh", "/etc/cron.d/x"},
		"nested": []string{"assets/inner.apk", "lib/arm64/payload.so"}, "encryptedEntries": 3, "overlappingEntries": 2,
		"duplicateNames": 1, "signed": false,
		"android": map[string]any{"signingBlock": false, "permissions": []string{
			"android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.SEND_SMS",
			"android.permission.BIND_ACCESSIBILITY_SERVICE", "com.example.permission.PRIVATE",
		}},
	}
	return r
}

func asarScenario() *report.Report {
	r := base("app.asar", report.TypeAsar, report.FamilyPackage, 3<<20)
	r.Details["asar"] = map[string]any{
		"package": map[string]any{"name": "demo", "version": "1.2.3", "main": "main.js", "electron": "^28.0.0"},
		"hints":   []map[string]any{{"id": "node-integration", "evidence": "main.js: nodeIntegration: true"}},
	}
	return r
}

func goScenario() *report.Report {
	r := base("tool.exe", report.TypePE, report.FamilyExecutable, 4<<20)
	r.Details["go"] = map[string]any{
		"goVersion": "go1.26.5", "path": "example.com/tool",
		"vcs": map[string]any{"system": "git", "revision": "0123456789abcdef", "time": "2026-11-01T00:00:00Z", "modified": true},
	}
	return r
}

func minimalImportScenario() *report.Report {
	r := base("loader.exe", report.TypePE, report.FamilyExecutable, 30<<10)
	r.Imports = imports("KERNEL32.dll", "LoadLibraryA", "GetProcAddress", "ExitProcess")
	return r
}

func entropyFileScenario() *report.Report {
	r := base("blob.bin", report.TypeDOS, report.FamilyExecutable, 64<<10)
	r.Entropy = report.Entropy{Overall: 7.9, WindowSize: 256}
	return r
}

func maskedScenarios() []*report.Report {
	photo := base("photo.png", report.TypePE, report.FamilyExecutable, 1<<20)
	double := base("invoice.pdf.exe", report.TypePE, report.FamilyExecutable, 1<<20)
	return []*report.Report{photo, double}
}

func allScenarios() []*report.Report {
	out := []*report.Report{
		peScenario(), elfScenario(), partialRelroScenario(), archiveScenario(), asarScenario(),
		goScenario(), minimalImportScenario(), entropyFileScenario(),
	}
	return append(out, maskedScenarios()...)
}

func TestEveryCataloguedRuleFiresAndEveryFindingIsDocumented(t *testing.T) {
	catalogued := map[string]bool{}
	for _, info := range Catalog() {
		for _, id := range info.IDs {
			if catalogued[id] {
				t.Errorf("finding id %q is listed twice in the catalogue", id)
			}
			catalogued[id] = true
		}
	}
	fired := map[string]bool{}
	for _, rep := range allScenarios() {
		res := Evaluate(rep)
		for _, f := range res.Findings {
			fired[f.ID] = true
			if !catalogued[f.ID] {
				t.Errorf("finding %q is emitted but missing from the catalogue", f.ID)
			}
		}
	}
	for id := range catalogued {
		if !fired[id] {
			t.Errorf("catalogued finding %q never fired in any scenario", id)
		}
	}
}

func TestFindingInvariants(t *testing.T) {
	for _, rep := range allScenarios() {
		res := Evaluate(rep)
		for _, f := range res.Findings {
			t.Run(rep.File.Name+"/"+f.ID, func(t *testing.T) {
				if f.Title == "" || f.Category == "" {
					t.Error("title and category are required")
				}
				if f.Severity.Rank() < 0 {
					t.Errorf("invalid severity %q", f.Severity)
				}
				if f.Confidence != report.ConfidenceLow && f.Confidence != report.ConfidenceMedium && f.Confidence != report.ConfidenceHigh {
					t.Errorf("invalid confidence %q", f.Confidence)
				}
				if len(f.Evidence) == 0 {
					t.Error("a finding without evidence is just an opinion")
				}
				if len(f.Limitations) == 0 {
					t.Error("every finding must state how it can be wrong")
				}
				if !strings.Contains(f.ID, ".") {
					t.Errorf("id %q should be dotted (category.name)", f.ID)
				}
				for _, e := range f.Evidence {
					if strings.Contains(e, "AKIAIOSFODNN7EXAMPLE") {
						t.Errorf("evidence leaks a raw secret: %q", e)
					}
				}
			})
		}
	}
}

func TestEvaluateIsPureSortedAndKeepsExistingFindings(t *testing.T) {
	rep := peScenario()
	pre := report.Finding{ID: "parser.warning", Title: "w", Severity: report.SeverityInfo, Category: report.CategoryParser, Confidence: report.ConfidenceHigh, Evidence: []string{"e"}, Limitations: []string{"l"}}
	rep.Findings = []report.Finding{pre}
	before := len(rep.Findings)
	res := Evaluate(rep)
	if len(rep.Findings) != before || rep.Risk.Score != 0 {
		t.Fatal("Evaluate must not modify the report")
	}
	if !slices.Contains(ids(res.Findings), "parser.warning") {
		t.Fatal("pre-existing findings must be kept")
	}
	for i := 1; i < len(res.Findings); i++ {
		a, b := res.Findings[i-1], res.Findings[i]
		if a.Severity.Rank() < b.Severity.Rank() || (a.Severity == b.Severity && a.ID > b.ID) {
			t.Fatalf("findings not sorted at %d: %s(%s) before %s(%s)", i, a.ID, a.Severity, b.ID, b.Severity)
		}
	}
	again := Evaluate(rep)
	if fmt.Sprint(ids(again.Findings)) != fmt.Sprint(ids(res.Findings)) || again.Risk.Score != res.Risk.Score {
		t.Fatal("Evaluate must be deterministic")
	}
}

func TestCleanReportHasNoFindingsAndLowRisk(t *testing.T) {
	r := base("hello", report.TypeELF, report.FamilyExecutable, 10<<10)
	r.Sections = []report.Section{sec(".text", 5.9, 4096, report.FlagR, report.FlagX), sec(".data", 2.0, 512, report.FlagR, report.FlagW)}
	r.Hardening = []report.Hardening{
		{ID: report.HardenPIE, Status: report.StatusEnabled}, {ID: report.HardenNX, Status: report.StatusEnabled},
		{ID: report.HardenRELRO, Status: report.StatusEnabled, Detail: "full RELRO"}, {ID: report.HardenCanary, Status: report.StatusEnabled},
		{ID: report.HardenSigned, Status: report.StatusNA},
	}
	res := Evaluate(r)
	if len(res.Findings) != 0 {
		t.Fatalf("clean report produced findings: %v", ids(res.Findings))
	}
	if res.Risk.Score != 0 || res.Risk.Label != report.RiskLow || len(res.Risk.Basis) == 0 {
		t.Fatalf("risk = %+v", res.Risk)
	}
}

func TestPackingRules(t *testing.T) {
	tests := []struct {
		name     string
		sections []report.Section
		wantID   string
		wantSev  report.Severity
		wantConf report.Confidence
	}{
		{"executable section", []report.Section{sec(".text", 7.6, 4096, report.FlagR, report.FlagX)}, "packing.high-entropy-section", report.SeverityMedium, report.ConfidenceMedium},
		{"data only", []report.Section{sec(".rsrc", 7.9, 4096, report.FlagR)}, "packing.high-entropy-section", report.SeverityLow, report.ConfidenceLow},
		{"below threshold", []report.Section{sec(".text", 7.19, 4096, report.FlagR, report.FlagX)}, "", "", ""},
		{"tiny section is ignored", []report.Section{sec(".text", 7.9, 512, report.FlagR, report.FlagX)}, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := base("x.exe", report.TypePE, report.FamilyExecutable, 1<<20)
			r.Sections = tc.sections
			res := Evaluate(r)
			if tc.wantID == "" {
				if slices.Contains(ids(res.Findings), "packing.high-entropy-section") {
					t.Fatalf("unexpected finding: %v", ids(res.Findings))
				}
				return
			}
			f := find(t, res.Findings, tc.wantID)
			if f.Severity != tc.wantSev || f.Confidence != tc.wantConf {
				t.Fatalf("got %s/%s want %s/%s", f.Severity, f.Confidence, tc.wantSev, tc.wantConf)
			}
			if !strings.Contains(strings.Join(f.Limitations, " "), "legitimately high-entropy") {
				t.Errorf("entropy findings must say compressed resources are high-entropy too: %v", f.Limitations)
			}
		})
	}
}

func TestHighEntropyIgnoresNonExecutableFamilies(t *testing.T) {
	r := base("data.zip", report.TypeZip, report.FamilyArchive, 1<<20)
	r.Entropy.Overall = 7.99
	r.Sections = []report.Section{sec("x", 7.99, 1<<20, report.FlagR)}
	if res := Evaluate(r); len(res.Findings) != 0 {
		t.Fatalf("compressed archives are always high entropy: %v", ids(res.Findings))
	}
}

func TestImportClusterThresholds(t *testing.T) {
	tests := []struct {
		name    string
		typeID  string
		fns     []string
		want    string
		wantSev report.Severity
	}{
		{"single injection API is not enough", report.TypePE, []string{"WriteProcessMemory"}, "", ""},
		{"write + execute is two stages", report.TypePE, []string{"WriteProcessMemory", "CreateRemoteThread"}, "imports.process-injection", report.SeverityMedium},
		{"full chain", report.TypePE, []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, "imports.process-injection", report.SeverityHigh},
		{"zw spelling folds into nt", report.TypePE, []string{"ZwUnmapViewOfSection", "NtWriteVirtualMemory"}, "imports.process-injection", report.SeverityMedium},
		{"ansi/wide suffix tolerated", report.TypePE, []string{"SetWindowsHookExW", "GetAsyncKeyState"}, "imports.keylogging", report.SeverityMedium},
		{"hook alone is not keylogging", report.TypePE, []string{"SetWindowsHookExA"}, "", ""},
		{"IsDebuggerPresent alone is CRT noise", report.TypePE, []string{"IsDebuggerPresent"}, "", ""},
		{"two anti-debug APIs", report.TypePE, []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}, "imports.anti-debug", report.SeverityLow},
		{"four anti-debug APIs", report.TypePE, []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"}, "imports.anti-debug", report.SeverityMedium},
		{"download without launch", report.TypePE, []string{"URLDownloadToFileA"}, "", ""},
		{"download and launch", report.TypePE, []string{"URLDownloadToFileW", "ShellExecuteExW"}, "imports.download-and-execute", report.SeverityMedium},
		{"reverse shell on elf", report.TypeELF, []string{"socket", "connect", "dup2", "execve"}, "imports.reverse-shell-pattern", report.SeverityMedium},
		{"reverse shell needs unix target", report.TypePE, []string{"socket", "connect", "dup2", "execve"}, "imports.networking", report.SeverityInfo},
		{"service install", report.TypePE, []string{"OpenSCManagerW", "CreateServiceW", "StartServiceW"}, "imports.service-manipulation", report.SeverityLow},
		{"service control without install", report.TypePE, []string{"OpenSCManagerW", "OpenServiceW", "StartServiceW"}, "", ""},
		{"crypto info", report.TypePE, []string{"CryptAcquireContextW", "CryptEncrypt"}, "imports.crypto", report.SeverityInfo},
		{"networking info", report.TypePE, []string{"WSAStartup", "socket"}, "imports.networking", report.SeverityInfo},
		{"token privileges", report.TypePE, []string{"OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueW"}, "imports.token-privileges", report.SeverityLow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := base("x", tc.typeID, report.FamilyExecutable, 1<<20)
			r.Imports = imports("lib", tc.fns...)
			res := Evaluate(r)
			var got []report.Finding
			for _, f := range res.Findings {
				if strings.HasPrefix(f.ID, "imports.") && f.ID != "imports.minimal-import-table" {
					got = append(got, f)
				}
			}
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected findings %v", ids(got))
				}
				return
			}
			f := find(t, got, tc.want)
			if f.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSev)
			}
			if tc.typeID == report.TypePE && strings.Contains(tc.name, "unix target") && slices.Contains(ids(got), "imports.reverse-shell-pattern") {
				t.Error("the reverse-shell heuristic must not fire on PE files")
			}
			if !strings.Contains(strings.Join(f.Limitations, " "), "proves nothing") && tc.want != "imports.minimal-import-table" {
				t.Errorf("import findings must state that API presence alone proves nothing: %v", f.Limitations)
			}
		})
	}
}

func TestMinimalImportTable(t *testing.T) {
	r := minimalImportScenario()
	if !slices.Contains(ids(Evaluate(r).Findings), "imports.minimal-import-table") {
		t.Fatal("expected minimal import table finding")
	}
	r.Imports = imports("KERNEL32.dll", "LoadLibraryA", "GetProcAddress", "A", "B", "C", "D", "E", "F", "G")
	if slices.Contains(ids(Evaluate(r).Findings), "imports.minimal-import-table") {
		t.Fatal("nine imports is no longer minimal")
	}
	r = minimalImportScenario()
	r.Type.ID = report.TypeELF
	if slices.Contains(ids(Evaluate(r).Findings), "imports.minimal-import-table") {
		t.Fatal("the heuristic is PE-only")
	}
}

func TestHardeningFindings(t *testing.T) {
	res := Evaluate(elfScenario())
	for _, id := range []string{"hardening.no-pie", "hardening.no-nx", "hardening.no-relro", "hardening.no-canary", "hardening.no-fortify"} {
		find(t, res.Findings, id)
	}
	if f := find(t, res.Findings, "hardening.no-pie"); f.Severity != report.SeverityMedium {
		t.Errorf("no-pie severity = %s", f.Severity)
	}
	partial := find(t, Evaluate(partialRelroScenario()).Findings, "hardening.partial-relro")
	if partial.Severity != report.SeverityInfo {
		t.Errorf("partial relro severity = %s", partial.Severity)
	}
	// Unknown / n-a statuses never produce findings.
	r := base("x", report.TypePE, report.FamilyExecutable, 1000)
	r.Hardening = []report.Hardening{{ID: report.HardenASLR, Status: report.StatusUnknown}, {ID: report.HardenDEP, Status: report.StatusNA}}
	if res := Evaluate(r); len(res.Findings) != 0 {
		t.Fatalf("unexpected: %v", ids(res.Findings))
	}
}

func TestSecretsFindingsNeverEchoRawValuesAndMentionTruncation(t *testing.T) {
	r := base("x", report.TypePE, report.FamilyExecutable, 1000)
	r.Strings.Truncated = true
	r.Strings.Items = []report.StringItem{{Value: "AKIA…(20 chars)", Offset: 16, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"}}
	f := find(t, Evaluate(r).Findings, "secrets.aws-access-key-id")
	if f.Severity != report.SeverityHigh || f.Confidence != report.ConfidenceMedium {
		t.Fatalf("got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence[0], "offset 0x10") || !strings.Contains(f.Evidence[0], "AKIA…(20 chars)") {
		t.Fatalf("evidence = %v", f.Evidence)
	}
	if !strings.Contains(strings.Join(f.Limitations, " "), "truncated") {
		t.Fatalf("truncation must be disclosed: %v", f.Limitations)
	}
}

func TestNetworkIndicatorSeverity(t *testing.T) {
	r := base("x", report.TypePE, report.FamilyExecutable, 1000)
	r.Strings.Items = []report.StringItem{{Value: "10.0.0.5", Category: report.CatIP}, {Value: "127.0.0.1", Category: report.CatIP}, {Value: "https://example.com/docs", Category: report.CatURL}}
	r.Strings.ByCategory = map[string]int{report.CatIP: 2, report.CatURL: 1}
	f := find(t, Evaluate(r).Findings, "indicators.network")
	if f.Severity != report.SeverityInfo {
		t.Fatalf("private/loopback addresses and plain URLs are info, got %s", f.Severity)
	}
	r.Strings.Items = append(r.Strings.Items, report.StringItem{Value: "198.51.100.23", Category: report.CatIP})
	if f := find(t, Evaluate(r).Findings, "indicators.network"); f.Severity != report.SeverityLow {
		t.Fatalf("a public literal IP raises it to low, got %s", f.Severity)
	}
}

func TestRunOnStringsAreNotIndicators(t *testing.T) {
	runOn := strings.Repeat("filler text ", 40) + "powershell -nop -enc AAAA " + "http://127.0.0.1:7777 " + strings.Repeat("more ", 40)
	r := base("x", report.TypeELF, report.FamilyExecutable, 1<<20)
	r.Strings.Items = []report.StringItem{
		{Value: runOn, Category: report.CatCommand}, {Value: runOn, Category: report.CatURL},
		{Value: runOn, Category: report.CatIP}, {Value: runOn, Category: report.CatRegistry},
	}
	if res := Evaluate(r); len(res.Findings) != 0 {
		t.Fatalf("concatenated string tables must not produce indicators: %v", ids(res.Findings))
	}
}

func TestCommandSeverity(t *testing.T) {
	r := base("x", report.TypePE, report.FamilyExecutable, 1000)
	r.Strings.Items = []report.StringItem{{Value: "cmd.exe /c dir", Category: report.CatCommand}}
	if f := find(t, Evaluate(r).Findings, "indicators.suspicious-commands"); f.Severity != report.SeverityLow {
		t.Fatalf("plain command should be low, got %s", f.Severity)
	}
	r.Strings.Items = append(r.Strings.Items, report.StringItem{Value: "powershell -nop -w hidden -enc AAAA", Category: report.CatCommand})
	if f := find(t, Evaluate(r).Findings, "indicators.suspicious-commands"); f.Severity != report.SeverityMedium {
		t.Fatalf("encoded hidden powershell should be medium, got %s", f.Severity)
	}
}

func TestArchiveRules(t *testing.T) {
	res := Evaluate(archiveScenario())
	slip := find(t, res.Findings, "archive.zip-slip")
	if slip.Severity != report.SeverityHigh || len(slip.Evidence) != 2 {
		t.Fatalf("zip-slip = %+v", slip)
	}
	bomb := find(t, res.Findings, "archive.zip-bomb")
	if bomb.Severity != report.SeverityHigh || bomb.Confidence != report.ConfidenceHigh {
		t.Fatalf("overlapping entries make the bomb high/high, got %s/%s", bomb.Severity, bomb.Confidence)
	}
	perms := find(t, res.Findings, "android.sensitive-permissions")
	if perms.Severity != report.SeverityMedium {
		t.Fatalf("accessibility service permission is powerful, got %s", perms.Severity)
	}
	if !strings.Contains(strings.Join(perms.Limitations, " "), "heuristic") {
		t.Fatal("permission finding must call itself heuristic")
	}
	for _, e := range perms.Evidence {
		if strings.Contains(e, "INTERNET") || strings.Contains(e, "PRIVATE") {
			t.Errorf("non-sensitive permission listed: %s", e)
		}
	}
	find(t, res.Findings, "signature.unsigned")

	// A plain, signed, normal archive stays quiet.
	quiet := base("a.zip", report.TypeZip, report.FamilyArchive, 1000)
	quiet.Details["archive"] = map[string]any{"kind": "zip", "entryCount": 3, "ratio": 2.5, "totalUncompressed": 5000, "totalCompressed": 2000}
	if res := Evaluate(quiet); len(res.Findings) != 0 {
		t.Fatalf("unexpected: %v", ids(res.Findings))
	}
}

func TestZipBombRatioRules(t *testing.T) {
	r := base("b.zip", report.TypeZip, report.FamilyArchive, 1<<20)
	r.Details["archive"] = map[string]any{"kind": "zip", "totalCompressed": 1 << 20, "totalUncompressed": uint64(2) << 30, "ratio": 2048.0, "maxRatio": 2048.0, "maxRatioEntry": "zero.bin"}
	f := find(t, Evaluate(r).Findings, "archive.zip-bomb")
	if f.Severity != report.SeverityMedium || len(f.Evidence) != 2 {
		t.Fatalf("ratio-based bomb should be medium with two evidence lines: %+v", f)
	}
}

func TestElectronGoPDBAndFileRules(t *testing.T) {
	asar := Evaluate(asarScenario())
	find(t, asar.Findings, "application.electron-app")
	hint := find(t, asar.Findings, "application.electron-risky-settings")
	if hint.Severity != report.SeverityLow || hint.Confidence != report.ConfidenceLow {
		t.Fatalf("node-integration hints are evidence only: %s/%s", hint.Severity, hint.Confidence)
	}
	if !strings.Contains(strings.Join(hint.Limitations, " "), "not as a verdict") {
		t.Fatal("hints must say they are not a verdict")
	}
	vcs := find(t, Evaluate(goScenario()).Findings, "build.go-vcs")
	if vcs.Severity != report.SeverityInfo || !strings.Contains(strings.Join(vcs.Evidence, " "), "dirty") {
		t.Fatalf("vcs = %+v", vcs)
	}
	find(t, Evaluate(peScenario()).Findings, "privacy.pdb-path")

	masked := maskedScenarios()
	find(t, Evaluate(masked[0]).Findings, "file.type-mismatch")
	find(t, Evaluate(masked[1]).Findings, "file.double-extension")
	// A genuine image named .png is fine, and a PE named .exe is fine.
	img := base("photo.png", report.TypePNG, report.FamilyImage, 1000)
	if res := Evaluate(img); len(res.Findings) != 0 {
		t.Fatalf("unexpected: %v", ids(res.Findings))
	}
}

func TestPEStructureRules(t *testing.T) {
	res := Evaluate(peScenario())
	entry := find(t, res.Findings, "structure.entry-point-anomaly")
	if entry.Severity != report.SeverityMedium {
		t.Fatalf("entry in a non-executable section is medium, got %s", entry.Severity)
	}
	overlay := find(t, res.Findings, "structure.overlay")
	if overlay.Severity != report.SeverityLow {
		t.Fatalf("an overlay of >= 50%% is low, got %s", overlay.Severity)
	}
	find(t, res.Findings, "structure.timestamp-anomaly")
	rwx := find(t, res.Findings, "structure.rwx-section")
	if len(rwx.Evidence) != 1 || !strings.Contains(rwx.Evidence[0], ".rwx") {
		t.Fatalf("rwx evidence = %v", rwx.Evidence)
	}
	susp := find(t, res.Findings, "structure.suspicious-section")
	for _, e := range susp.Evidence {
		if strings.HasPrefix(e, ".rwx:") {
			t.Errorf("RWX-only sections are already reported by structure.rwx-section: %v", susp.Evidence)
		}
	}

	// Reproducible-build markers turn the timestamp into a hash: never an anomaly.
	repro := base("repro.exe", report.TypePE, report.FamilyExecutable, 1000)
	repro.Sections = []report.Section{sec(".text", 5, 1024, report.FlagR, report.FlagX)}
	repro.Details["pe"] = map[string]any{"entryPoint": "0x0", "timestamp": "1979-02-19T18:32:04Z", "reproducible": true}
	if res := Evaluate(repro); len(res.Findings) != 0 {
		t.Fatalf("reproducible timestamps must not be flagged: %v", ids(res.Findings))
	}

	// Deterministic builds (timestamp 0 => "") and entry point 0 (DLLs without one) stay quiet.
	quiet := base("x.dll", report.TypePE, report.FamilyExecutable, 1000)
	quiet.Sections = []report.Section{sec(".text", 5, 1024, report.FlagR, report.FlagX)}
	quiet.Details["pe"] = map[string]any{"entryPoint": "0x0", "timestamp": "", "overlaySize": 10}
	if res := Evaluate(quiet); len(res.Findings) != 0 {
		t.Fatalf("unexpected: %v", ids(res.Findings))
	}
}

func TestELFStructureRules(t *testing.T) {
	res := Evaluate(elfScenario())
	seg := find(t, res.Findings, "structure.rwx-segment")
	if !strings.Contains(seg.Evidence[0], "0x400000") {
		t.Fatalf("evidence = %v", seg.Evidence)
	}
	rp := find(t, res.Findings, "structure.insecure-rpath")
	joined := strings.Join(rp.Evidence, "|")
	for _, want := range []string{"current directory", "/tmp/libs", "relative/dir"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rpath evidence misses %q: %v", want, rp.Evidence)
		}
	}
	if strings.Contains(joined, "ORIGIN") {
		t.Errorf("$ORIGIN is a normal, safe-by-convention entry: %v", rp.Evidence)
	}
}

func TestAPITablesAreCanonical(t *testing.T) {
	tables := map[string][]string{
		"remote alloc": apiRemoteAlloc, "remote write": apiRemoteWrite, "remote exec": apiRemoteExec,
		"open process": apiOpenProcess, "hooks": apiHooks, "keys": apiKeys, "window context": apiWindowContext,
		"anti debug": apiAntiDebug, "crypto": apiCrypto, "network": apiNetwork, "download": apiDownload,
		"launch": apiLaunch, "service": apiService, "service install": apiServiceInstall, "token": apiToken,
		"load library": apiLoadLibrary, "get proc": apiGetProc, "sh socket": apiShSocket, "sh conn": apiShConn,
		"sh dup": apiShDup, "sh exec": apiShExec,
	}
	for name, table := range tables {
		seen := map[string]bool{}
		for _, api := range table {
			if api != strings.ToLower(api) || api != normalizeAPI(api) {
				t.Errorf("%s: %q is not canonical (want %q)", name, api, normalizeAPI(api))
			}
			if seen[api] {
				t.Errorf("%s: duplicate %q", name, api)
			}
			seen[api] = true
		}
		if !slices.IsSorted(table) {
			t.Errorf("%s: table is not sorted", name)
		}
	}
}

func TestNormalizeAPI(t *testing.T) {
	tests := map[string]string{
		"VirtualAllocEx":       "virtualallocex",
		"ZwWriteVirtualMemory": "ntwritevirtualmemory",
		"_socket":              "socket",
		"__imp_connect":        "connect",
		"MessageBoxA@16":       "messageboxa",
		"memcpy_chk":           "memcpy_chk",
	}
	for in, want := range tests {
		if got := normalizeAPI(in); got != want {
			t.Errorf("normalizeAPI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRiskArithmeticAndCaps(t *testing.T) {
	f := func(id, cat string, sev report.Severity, conf report.Confidence) report.Finding {
		return report.Finding{ID: id, Category: cat, Severity: sev, Confidence: conf}
	}
	tests := []struct {
		name      string
		findings  []report.Finding
		wantScore int
		wantLabel string
		wantBasis []string
	}{
		{"no findings", nil, 0, report.RiskLow, []string{"no finding carries points"}},
		{"info carries nothing", []report.Finding{f("a.b", report.CategoryBuild, report.SeverityInfo, report.ConfidenceHigh)}, 0, report.RiskLow, nil},
		{"single high/high", []report.Finding{f("secrets.x", report.CategorySecrets, report.SeverityHigh, report.ConfidenceHigh)}, 20, report.RiskMedium, []string{"+20  secrets.x"}},
		{"rounding", []report.Finding{f("a.b", report.CategoryImports, report.SeverityLow, report.ConfidenceMedium)}, 3, report.RiskLow, []string{"+3  a.b"}},
		{"hardening is capped at 15", []report.Finding{
			f("h.1", report.CategoryHardening, report.SeverityMedium, report.ConfidenceHigh),
			f("h.2", report.CategoryHardening, report.SeverityMedium, report.ConfidenceHigh),
			f("h.3", report.CategoryHardening, report.SeverityMedium, report.ConfidenceHigh),
		}, 15, report.RiskLow, []string{`category "hardening" capped at 15 (was 30)`}},
		{"independent categories add up", []report.Finding{
			f("p.1", report.CategoryPacking, report.SeverityMedium, report.ConfidenceHigh),
			f("i.1", report.CategoryImports, report.SeverityHigh, report.ConfidenceMedium),
			f("s.1", report.CategorySecrets, report.SeverityHigh, report.ConfidenceHigh),
		}, 44, report.RiskMedium, nil},
		{"total limited to 100", []report.Finding{
			f("a", report.CategorySecrets, report.SeverityCritical, report.ConfidenceHigh),
			f("b", report.CategoryImports, report.SeverityCritical, report.ConfidenceHigh),
			f("c", report.CategoryArchive, report.SeverityCritical, report.ConfidenceHigh),
		}, 100, report.RiskCritical, []string{"total 120 limited to 100"}},
		{"label boundaries high", []report.Finding{
			f("a", report.CategorySecrets, report.SeverityCritical, report.ConfidenceHigh),
			f("b", report.CategoryImports, report.SeverityHigh, report.ConfidenceHigh),
			f("c", report.CategoryArchive, report.SeverityLow, report.ConfidenceHigh),
			f("d", report.CategoryPacking, report.SeverityLow, report.ConfidenceMedium),
		}, 67, report.RiskHigh, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Score(tc.findings)
			if got.Score != tc.wantScore || got.Label != tc.wantLabel {
				t.Fatalf("score/label = %d/%s, want %d/%s\nbasis: %s", got.Score, got.Label, tc.wantScore, tc.wantLabel, strings.Join(got.Basis, "\n"))
			}
			joined := strings.Join(got.Basis, "\n")
			for _, want := range tc.wantBasis {
				if !strings.Contains(joined, want) {
					t.Errorf("basis lacks %q:\n%s", want, joined)
				}
			}
			if len(got.Basis) < 2 {
				t.Errorf("the basis must always explain the arithmetic: %v", got.Basis)
			}
		})
	}
}

func TestLabelBoundaries(t *testing.T) {
	for score, want := range map[int]string{0: "low", 19: "low", 20: "medium", 44: "medium", 45: "high", 69: "high", 70: "critical", 100: "critical"} {
		if got := Label(score); got != want {
			t.Errorf("Label(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestRealisticScenariosLandWhereExpected(t *testing.T) {
	if res := Evaluate(goScenario()); res.Risk.Label != report.RiskLow {
		t.Errorf("a Go build with VCS info is low risk, got %s (%d)", res.Risk.Label, res.Risk.Score)
	}
	if res := Evaluate(peScenario()); res.Risk.Score < 45 {
		t.Errorf("the packed, injecting, secret-carrying PE should be at least high, got %s (%d)", res.Risk.Label, res.Risk.Score)
	}
}

func TestSampleAndHumanBytes(t *testing.T) {
	if got := sample([]string{"a", "b", "c"}, 2); len(got) != 3 || got[2] != "(+1 more)" {
		t.Errorf("sample = %v", got)
	}
	if got := sample([]string{"a"}, 2); len(got) != 1 {
		t.Errorf("sample = %v", got)
	}
	for in, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := clip("héllo wörld", 5); got != "héllo…" {
		t.Errorf("clip = %q", got)
	}
}

// TestCatalogDocIsUpToDate keeps docs/rules.md in sync with the rule catalogue.
// Regenerate it with: go test ./internal/rules -run TestCatalogDoc -update
func TestCatalogDocIsUpToDate(t *testing.T) {
	want := markdown()
	path := filepath.Join("..", "..", "docs", "rules.md")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with -update)", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s is out of date; regenerate it with: go test ./internal/rules -run TestCatalogDoc -update", path)
	}
}
