package pe

import (
	"context"
	dpe "debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

func parseFile(t *testing.T, path string) *Result {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("cannot open %s: %v", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(context.Background(), f, st.Size(), limits.ForSize(st.Size()))
	if err != nil {
		t.Fatalf("Parse(%s): %v", path, err)
	}
	checkInvariants(t, res, st.Size(), limits.ForSize(st.Size()))
	return res
}

func importedLibrary(res *Result, name string) (report.Import, bool) {
	for _, imp := range res.Imports {
		if strings.EqualFold(imp.Library, name) {
			return imp, true
		}
	}
	return report.Import{}, false
}

// TestParseTestBinary parses the Go test binary itself, a genuine PE32+ image
// on Windows.
func TestParseTestBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Go test binary is a PE image only on Windows")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	res := parseFile(t, exe)
	d := res.Details
	if d.Kind != "exe" || d.Subsystem != "windows-cui" {
		t.Errorf("kind %q subsystem %q", d.Kind, d.Subsystem)
	}
	wantMachine, wantBits := map[string]string{"amd64": "x86-64", "arm64": "ARM64", "386": "x86"}[runtime.GOARCH], 64
	if runtime.GOARCH == "386" {
		wantBits = 32
	}
	if d.Machine != wantMachine || d.Bits != wantBits {
		t.Errorf("machine %q bits %d, want %q %d", d.Machine, d.Bits, wantMachine, wantBits)
	}
	if len(res.Sections) < 3 {
		t.Errorf("sections = %v", sectionNames(res))
	}
	for _, want := range []string{".text", ".rdata", ".data"} {
		if !slices.Contains(sectionNames(res), want) {
			t.Errorf("section %s missing from %v", want, sectionNames(res))
		}
	}
	if k32, ok := importedLibrary(res, "kernel32.dll"); !ok || k32.Count == 0 {
		t.Errorf("kernel32.dll import missing: %+v", res.Imports)
	}
	st := hardeningStatus(res)
	for _, id := range []string{report.HardenASLR, report.HardenDEP} {
		if st[id] != report.StatusEnabled && st[id] != report.StatusDisabled {
			t.Errorf("hardening %s = %q", id, st[id])
		}
	}
	if res.ImpHash == "" || len(res.ImpHash) != 32 {
		t.Errorf("imphash = %q", res.ImpHash)
	}
	if d.ImportCount == 0 || d.EntrySection != ".text" {
		t.Errorf("importCount %d entrySection %q", d.ImportCount, d.EntrySection)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a well-formed linker output must parse without notes: %v", res.Notes)
	}
	for _, s := range res.Sections {
		if s.Suspicious {
			t.Errorf("section %s of a normal Go binary flagged: %v", s.Name, s.Reasons)
		}
	}
}

// TestParseGoBuilds cross-compiles a tiny stdlib-only program for three
// Windows architectures and parses the results. It needs the go tool.
func TestParseGoBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compilation in short mode")
	}
	t.Parallel() // overlaps the toolchain's work with the robustness sweeps
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module hello\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\nimport \"os\"\n\nfunc main() { os.Stdout.WriteString(\"hello\\n\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		goarch, machine string
		bits            int
	}{
		{"amd64", "x86-64", 64},
		{"386", "x86", 32},
		{"arm64", "ARM64", 64},
	}
	for _, tc := range tests {
		t.Run(tc.goarch, func(t *testing.T) {
			t.Parallel()
			out := filepath.Join(dir, "hello-"+tc.goarch+".exe")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+tc.goarch, "CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local", "GOFLAGS=")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("go build for windows/%s failed (toolchain without that target?): %v\n%s", tc.goarch, err, output)
			}
			res := parseFile(t, out)
			d := res.Details
			if d.Machine != tc.machine || d.Bits != tc.bits || d.Kind != "exe" || d.Subsystem != "windows-cui" {
				t.Errorf("details = %+v", d)
			}
			if _, ok := importedLibrary(res, "kernel32.dll"); !ok {
				t.Errorf("kernel32.dll import missing: %+v", res.Imports)
			}
			for _, want := range []string{".text", ".rdata", ".data", ".idata"} {
				if !slices.Contains(sectionNames(res), want) {
					t.Errorf("section %s missing from %v", want, sectionNames(res))
				}
			}
			if d.Signed || d.DotNet || len(d.PackerHints) != 0 {
				t.Errorf("a plain Go binary is not signed, managed or packed: %+v", d)
			}
			if len(res.Notes) != 0 {
				t.Errorf("notes = %v", res.Notes)
			}
			if tc.bits == 32 && hardeningStatus(res)[report.HardenHighEntropyVA] != report.StatusNA {
				t.Errorf("hardening = %v", hardeningStatus(res))
			}
		})
	}
}

// TestImportsAgreeWithDebugPE compares the import lists of real system images
// with the standard library's reader (read-only, Windows only).
func TestImportsAgreeWithDebugPE(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if runtime.GOOS != "windows" || root == "" {
		t.Skip("needs Windows system images")
	}
	for _, name := range []string{"cmd.exe", "kernel32.dll", "ntdll.dll", "notepad.exe", "user32.dll"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, "System32", name)
			ref, err := dpe.Open(path)
			if err != nil {
				t.Skipf("debug/pe cannot open %s: %v", path, err)
			}
			defer ref.Close()
			want, err := ref.ImportedSymbols()
			if err != nil || len(want) == 0 {
				t.Skipf("debug/pe has no reference import list for %s (%v)", name, err)
			}
			res := parseFile(t, path)
			var got []string
			for _, imp := range res.Imports {
				if strings.HasSuffix(imp.Library, delayLibSuffix) {
					continue
				}
				for _, fn := range imp.Functions {
					if !strings.HasPrefix(fn, "#") {
						got = append(got, fmt.Sprintf("%s:%s", fn, imp.Library))
					}
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s: %d imports parsed, debug/pe lists %d; first difference: %s", name, len(got), len(want), firstDifference(got, want))
			}
		})
	}
}

func firstDifference(a, b []string) string {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return fmt.Sprintf("index %d: %q vs %q", i, a[i], b[i])
		}
	}
	return fmt.Sprintf("lengths %d vs %d", len(a), len(b))
}

// firstExisting returns the first of the paths (relative to %SystemRoot%) that exists.
func firstExisting(t *testing.T, root string, rel ...string) string {
	t.Helper()
	for _, r := range rel {
		path := filepath.Join(root, r)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Skipf("none of %v exists", rel)
	return ""
}

// TestParseSystemImages parses a 32-bit executable, a kernel driver and a
// managed assembly shipped with Windows (read-only, Windows only).
func TestParseSystemImages(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if runtime.GOOS != "windows" || root == "" {
		t.Skip("needs Windows system images")
	}
	t.Run("32-bit console executable", func(t *testing.T) {
		res := parseFile(t, firstExisting(t, root, `SysWOW64\cmd.exe`))
		d := res.Details
		if d.Bits != 32 || d.Machine != "x86" || d.Kind != "exe" || d.Subsystem != "windows-cui" {
			t.Errorf("details = %+v", d)
		}
		if st := hardeningStatus(res); st[report.HardenHighEntropyVA] != report.StatusNA || st[report.HardenSEH] == report.StatusUnknown {
			t.Errorf("hardening = %v", st)
		}
		if len(res.Notes) != 0 {
			t.Errorf("notes = %v", res.Notes)
		}
	})
	t.Run("kernel driver", func(t *testing.T) {
		res := parseFile(t, firstExisting(t, root, `System32\drivers\beep.sys`, `System32\drivers\null.sys`, `System32\drivers\disk.sys`))
		d := res.Details
		if d.Kind != "driver" || d.Subsystem != "native" {
			t.Errorf("details = %+v", d)
		}
		if _, ok := importedLibrary(res, "ntoskrnl.exe"); !ok {
			t.Errorf("a driver imports ntoskrnl.exe: %+v", res.Imports)
		}
		if len(res.Notes) != 0 {
			t.Errorf("notes = %v", res.Notes)
		}
	})
	managed := func(t *testing.T, path string, bits int) *Result {
		t.Helper()
		res := parseFile(t, path)
		d := res.Details
		if !d.DotNet || !strings.HasPrefix(d.DotNetVersion, "v4.0.") || !slices.Contains(d.DotNetFlags, "ILONLY") || d.Bits != bits {
			t.Errorf("details = %+v", d)
		}
		if st := hardeningStatus(res); st[report.HardenCFG] != report.StatusNA || st[report.HardenSEH] != report.StatusNA {
			t.Errorf("IL-only code is neither CFG- nor SafeSEH-relevant: %v", st)
		}
		if !strings.HasSuffix(strings.ToLower(d.PDBPath), "msbuild.pdb") {
			t.Errorf("pdbPath = %q", d.PDBPath)
		}
		if len(res.Notes) != 0 {
			t.Errorf("notes = %v", res.Notes)
		}
		return res
	}
	t.Run("managed 32-bit assembly", func(t *testing.T) {
		res := managed(t, firstExisting(t, root, `Microsoft.NET\Framework\v4.0.30319\MSBuild.exe`), 32)
		if mscoree, ok := importedLibrary(res, "mscoree.dll"); !ok || !slices.Contains(mscoree.Functions, "_CorExeMain") {
			t.Errorf("a 32-bit managed executable imports mscoree.dll!_CorExeMain: %+v", res.Imports)
		}
	})
	t.Run("managed 64-bit assembly has no import table", func(t *testing.T) {
		res := managed(t, firstExisting(t, root, `Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`), 64)
		if len(res.Imports) != 0 || res.ImpHash != "" || res.Details.EntryPoint != "0x0" {
			t.Errorf("imports %+v imphash %q entry %s", res.Imports, res.ImpHash, res.Details.EntryPoint)
		}
	})
}

// TestParseSystemDLLExports checks export parsing, including forwarders, on a
// large real library (read-only, Windows only).
func TestParseSystemDLLExports(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if runtime.GOOS != "windows" || root == "" {
		t.Skip("needs Windows system images")
	}
	res := parseFile(t, filepath.Join(root, "System32", "kernel32.dll"))
	d := res.Details
	if d.Kind != "dll" || !strings.EqualFold(d.ExportName, "kernel32.dll") {
		t.Errorf("kind %q exportName %q", d.Kind, d.ExportName)
	}
	if d.ExportCount < 1000 || len(res.Exports) < 1000 {
		t.Errorf("exportCount %d, listed %d", d.ExportCount, len(res.Exports))
	}
	if !slices.Contains(res.Exports, "CreateFileW") {
		t.Error("CreateFileW is not in the export list")
	}
	forwarders := 0
	for _, e := range res.Exports {
		if strings.Contains(e, " -> ") {
			forwarders++
		}
	}
	if forwarders == 0 {
		t.Error("kernel32.dll forwards many exports to ntdll; none were recognised")
	}
	if !d.Signed || d.SignatureType != "pkcs7-signed-data" {
		t.Logf("kernel32.dll certificate table not found inside the file (catalog-signed images carry none): signed=%v", d.Signed)
	}
	if len(res.Notes) != 0 {
		t.Errorf("notes = %v", res.Notes)
	}
}
