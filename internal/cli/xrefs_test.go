package cli

import (
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// dropperPath writes the sample dropper, a PE whose code calls the imports of
// the process-injection chain, and returns its path.
func dropperPath(t *testing.T) string {
	t.Helper()
	return write(t, "dropper.bin", testfixtures.SamplePE())
}

func TestXrefsShowsTheCallSitesOfAnImport(t *testing.T) {
	path := dropperPath(t)
	r := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	wantInOrder := []string{
		"dropper.bin: KERNEL32.dll!VirtualAllocEx\n",
		"1 call site (PE x86-64, linear sweep of the executable sections)\n",
		"  #1  call [IAT]  0x1400010e9  (file offset 0x4e9, section .text)\n",
		"      0x1400010bd  41 b8 a4 01 00 00        mov r8d, 0x1a4\n",
		"    > 0x1400010e9  ff 15 b1 10 00 00        call qword ptr [rip+0x10b1]  ; KERNEL32.dll!VirtualAllocEx\n",
		"      0x1400010fe  4c 8d 05 fb 1e 00 00     lea r8, [rip+0x1efb]  ; 0x140003000 in .data\n",
		"  limits: x86-64 code decoded as a linear sweep",
		"not a decompiler",
	}
	rest := r.out
	for _, want := range wantInOrder {
		i := strings.Index(rest, want)
		if i < 0 {
			t.Fatalf("the output lacks %q after the previous part:\n%s", want, r.out)
		}
		rest = rest[i+len(want):]
	}
	if strings.Count(r.out, "> 0x") != 1 {
		t.Errorf("exactly one line is flagged:\n%s", r.out)
	}
	// The window is bounded: 8 instructions before, the call and 4 after.
	if rows := strings.Count(r.out, "\n      0x") + strings.Count(r.out, "\n    > 0x"); rows != 13 {
		t.Errorf("%d rows, want 8 + 1 + 4", rows)
	}
	for _, c := range r.out {
		if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
			t.Fatalf("the output carries the control character %U", c)
		}
	}

	t.Run("a call through an import thunk", func(t *testing.T) {
		r := run(t, testEnv{}, "xrefs", path, "createprocess", "--before", "1", "--after", "1")
		if r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		for _, want := range []string{
			"dropper.bin: KERNEL32.dll!CreateProcessW\n",
			"#1  call thunk  0x14000116b  (file offset 0x56b, section .text, through the thunk at 0x140001180)",
			"    > 0x14000116b  e8 10 00 00 00  call 0x140001180  ; KERNEL32.dll!CreateProcessW (through the thunk at 0x140001180)\n",
		} {
			if !strings.Contains(r.out, want) {
				t.Errorf("the output lacks %q:\n%s", want, r.out)
			}
		}
		if rows := strings.Count(r.out, "\n      0x") + strings.Count(r.out, "\n    > 0x"); rows != 3 {
			t.Errorf("%d rows, want 1 + 1 + 1:\n%s", rows, r.out)
		}
	})
	t.Run("the window can be the call alone", func(t *testing.T) {
		r := run(t, testEnv{}, "xrefs", path, "kernel32.dll!writeprocessmemory", "--before", "0", "--after", "0")
		if r.code != exitOK || strings.Count(r.out, "\n    > 0x140001114  ff 15 8e 10 00 00  call qword ptr [rip+0x108e]  ; KERNEL32.dll!WriteProcessMemory\n") != 1 || strings.Contains(r.out, "\n      0x") {
			t.Errorf("exit %d:\n%s", r.code, r.out)
		}
	})
	t.Run("an import that is not called", func(t *testing.T) {
		// The sample imports CryptEncrypt and never calls it.
		r := run(t, testEnv{}, "xrefs", path, "CryptEncrypt")
		if r.code != exitOK || !strings.Contains(r.out, "ADVAPI32.dll!CryptEncrypt\nimported, but no call to it was found in the executable sections") || strings.Contains(r.out, "#1") {
			t.Errorf("exit %d:\n%s", r.code, r.out)
		}
	})
}

func TestXrefsListsTheCalledImports(t *testing.T) {
	path := dropperPath(t)
	r := run(t, testEnv{}, "xrefs", path, "--list")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	for _, want := range []string{
		"dropper.bin\n",
		" imports have call sites (PE x86-64, linear sweep of the executable sections)\n",
		"  KERNEL32.dll!VirtualAllocEx      1 call site\n",
		"  KERNEL32.dll!CreateProcessW      1 call site\n", // called through a thunk: one call site, not two
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the list lacks %q:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "CryptEncrypt") {
		t.Errorf("an import nothing calls must not be listed:\n%s", r.out)
	}

	j := run(t, testEnv{}, "xrefs", path, "--list", "--json")
	var list []calledImport
	if err := json.Unmarshal([]byte(j.out), &list); err != nil || j.code != exitOK {
		t.Fatalf("exit %d, not JSON: %v\n%s", j.code, err, j.out)
	}
	byAPI := map[string]calledImport{}
	for _, c := range list {
		byAPI[c.API] = c
	}
	if c := byAPI["KERNEL32.dll!VirtualAllocEx"]; c.Library != "KERNEL32.dll" || c.Function != "VirtualAllocEx" || c.CallSites != 1 {
		t.Errorf("VirtualAllocEx = %+v", c)
	}
	if _, listed := byAPI["ADVAPI32.dll!CryptEncrypt"]; listed || len(list) < 10 {
		t.Errorf("%d imports listed, CryptEncrypt listed: %v", len(list), listed)
	}
}

func TestXrefsJSONIsAListOfCodeBlocks(t *testing.T) {
	path := dropperPath(t)
	r := run(t, testEnv{}, "xrefs", path, "WriteProcessMemory", "--json")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	var blocks []report.CodeBlock
	if err := json.Unmarshal([]byte(r.out), &blocks); err != nil {
		t.Fatalf("stdout is not a list of code blocks: %v\n%s", err, r.out)
	}
	if len(blocks) != 1 {
		t.Fatalf("%d blocks", len(blocks))
	}
	b := blocks[0]
	if err := b.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}
	var hit report.CodeLine
	for _, l := range b.Lines {
		if l.Highlight {
			hit = l
		}
	}
	if b.Kind != report.CodeKindDisasm || b.Section != ".text" || b.Arch != "x86-64" || hit.Address != 0x140001114 || hit.Offset != 0x514 ||
		hit.Bytes != "ff 15 8e 10 00 00" || hit.Note != "KERNEL32.dll!WriteProcessMemory" || b.Title != "call to KERNEL32.dll!WriteProcessMemory in .text" {
		t.Errorf("block = %+v, call line = %+v", b, hit)
	}
	if !strings.Contains(r.out, `"address": "0x140001114"`) {
		t.Errorf("addresses must be strings in the JSON:\n%s", r.out)
	}

	// An import nothing calls gives an empty list, not null.
	none := run(t, testEnv{}, "xrefs", path, "CryptEncrypt", "--json")
	if none.code != exitOK || strings.TrimSpace(none.out) != "[]" {
		t.Errorf("exit %d: %q", none.code, none.out)
	}
}

func TestXrefsMaxCapsTheSitesAndSaysSo(t *testing.T) {
	var calls []testfixtures.PECall
	for range 6 {
		calls = append(calls, testfixtures.PECall{Function: "VirtualAllocEx", Args: []testfixtures.PEArg{{Kind: testfixtures.PEArgZero}}})
	}
	data := testfixtures.PE(testfixtures.PEOptions{
		Imports: []testfixtures.PEImport{{Library: "KERNEL32.dll", Functions: []string{"VirtualAllocEx"}}},
		Calls:   calls,
	})
	path := write(t, "many.exe", data)

	r := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx", "--max", "2", "--before", "0", "--after", "0")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	if !strings.Contains(r.out, "6 call sites, the first 2 shown (PE x86-64") || !strings.Contains(r.out, "(2 of 6 call sites: --max N shows more, up to 100)") ||
		strings.Count(r.out, "  #") != 2 {
		t.Errorf("output:\n%s", r.out)
	}
	all := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx", "--before", "0", "--after", "0")
	if strings.Count(all.out, "  #") != 6 || strings.Contains(all.out, "shown") {
		t.Errorf("the default shows up to 10 sites:\n%s", all.out)
	}
	j := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx", "--json", "--max", "3")
	var blocks []report.CodeBlock
	if err := json.Unmarshal([]byte(j.out), &blocks); err != nil || len(blocks) != 3 {
		t.Errorf("%d blocks (%v)", len(blocks), err)
	}
}

func TestXrefsColourAndHostileNames(t *testing.T) {
	path := dropperPath(t)
	if r := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx", "--color", "always"); !strings.Contains(r.out, "\x1b[") {
		t.Errorf("--color always must colour the output:\n%q", r.out)
	}
	if r := run(t, testEnv{}, "xrefs", path, "VirtualAllocEx", "--color", "never"); strings.Contains(r.out, "\x1b") {
		t.Errorf("--color never must not colour:\n%q", r.out)
	}
	if r := run(t, testEnv{tty: true, vars: map[string]string{"NO_COLOR": "1"}}, "xrefs", path, "VirtualAllocEx"); strings.Contains(r.out, "\x1b") {
		t.Errorf("NO_COLOR must be honoured:\n%q", r.out)
	}
	if r := run(t, testEnv{tty: true}, "xrefs", path, "VirtualAllocEx"); !strings.Contains(r.out, "\x1b[") {
		t.Errorf("a terminal gets colour by default:\n%q", r.out)
	}

	// A name with escape sequences never reaches the terminal raw.
	r := run(t, testEnv{}, "xrefs", path, "\x1b[31mevil\x00"+string(rune(0x202e)))
	if r.code != exitError || !strings.Contains(r.err, `\x1b[31mevil\x00`) {
		t.Errorf("exit %d stderr %q", r.code, r.err)
	}
	for _, c := range r.err {
		if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
			t.Errorf("stderr carries the control character %U: %q", c, r.err)
		}
	}
}

func TestXrefsBadInput(t *testing.T) {
	path := dropperPath(t)
	elf := write(t, "hello.elf", testfixtures.ELF(testfixtures.ELFOptions{}))
	text := write(t, "notes.txt", []byte("not a program at all, just some text that is long enough to be sniffed as text"))
	empty := write(t, "empty.bin", nil)
	arm := testfixtures.SamplePE()
	arm[testfixtures.PEOffset+4], arm[testfixtures.PEOffset+5] = 0x64, 0xaa // IMAGE_FILE_MACHINE_ARM64
	armPath := write(t, "arm.exe", arm)
	// An image whose only code section is marked as data has nothing to search.
	noCodeImage := testfixtures.PE(testfixtures.PEOptions{Imports: []testfixtures.PEImport{{Library: "k.dll", Functions: []string{"A"}}}})
	binary.LittleEndian.PutUint32(noCodeImage[testfixtures.PESectionHeaderOffset(64, 0)+36:], testfixtures.PESectionData)
	noCode := write(t, "nocode.exe", noCodeImage)
	dir := t.TempDir()
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no arguments", []string{"xrefs"}, exitUsage, "expected a file and the name of an import (or --list), got 0 arguments"},
		{"only a file", []string{"xrefs", path}, exitUsage, "expected a file and the name of an import (or --list), got 1 arguments"},
		{"three arguments", []string{"xrefs", path, "A", "B"}, exitUsage, "got 3 arguments"},
		{"list with a name", []string{"xrefs", path, "A", "--list"}, exitUsage, "--list takes exactly one file, got 2 arguments"},
		{"blank name", []string{"xrefs", path, "   "}, exitUsage, "the name of the import is empty"},
		{"name too long", []string{"xrefs", path, strings.Repeat("A", 257)}, exitUsage, "longer than 256 characters"},
		{"before below zero", []string{"xrefs", path, "A", "--before", "-1"}, exitUsage, "--before must be between 0 and 40"},
		{"before over the cap", []string{"xrefs", path, "A", "--before", "41"}, exitUsage, "--before must be between 0 and 40"},
		{"after over the cap", []string{"xrefs", path, "A", "--after", "21"}, exitUsage, "--after must be between 0 and 20"},
		{"huge after", []string{"xrefs", path, "A", "--after", "1000000000"}, exitUsage, "--after must be between 0 and 20"},
		{"max zero", []string{"xrefs", path, "A", "--max", "0"}, exitUsage, "--max must be between 1 and 100"},
		{"max over the cap", []string{"xrefs", path, "A", "--max", "101"}, exitUsage, "--max must be between 1 and 100"},
		{"max overflow", []string{"xrefs", path, "A", "--max", "99999999999999999999"}, exitUsage, "not a whole number"},
		{"bad colour", []string{"xrefs", path, "A", "--color", "purple"}, exitUsage, "--color must be auto, always or never"},
		{"unknown flag", []string{"xrefs", path, "A", "--all"}, exitUsage, "flag provided but not defined"},
		{"no such import", []string{"xrefs", path, "NoSuchApi"}, exitError, `no import of this file matches "NoSuchApi"; imports with call sites include KERNEL32.dll!`},
		{"another library's name", []string{"xrefs", path, "other.dll!VirtualAllocEx"}, exitError, "no import of this file matches"},
		{"an elf", []string{"xrefs", elf, "A"}, exitError, "this file is ELF x86-64: xrefs finds the calls to the imports of PE images for x86 and x86-64 only"},
		{"text", []string{"xrefs", text, "A"}, exitError, "this file is not a PE image"},
		{"an empty file", []string{"xrefs", empty, "A"}, exitError, "this file is not a PE image"},
		{"arm64", []string{"xrefs", armPath, "A"}, exitError, "this file is PE ARM64: xrefs finds the calls to the imports of PE images for x86 and x86-64 only"},
		{"no executable section", []string{"xrefs", noCode, "A"}, exitError, "no executable section with bytes in the file"},
		{"directory", []string{"xrefs", dir, "A"}, exitError, "is not a regular file"},
		{"missing file", []string{"xrefs", filepath.Join(dir, "nope"), "A"}, exitError, "cannot open"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, testEnv{}, tc.args...)
			if r.code != tc.wantCode || !strings.Contains(r.err, tc.wantErr) {
				t.Fatalf("exit %d (want %d), stderr %q (want %q)", r.code, tc.wantCode, r.err, tc.wantErr)
			}
			if r.out != "" {
				t.Errorf("a failed command must print nothing on stdout, got %q", r.out)
			}
		})
	}
}

func TestXrefsIsInTheHelpAndTheCompletions(t *testing.T) {
	if help := run(t, testEnv{}, "--help"); !strings.Contains(help.out, "xrefs") || !strings.Contains(help.out, "teardown xrefs app.exe VirtualAllocEx") {
		t.Errorf("--help lacks xrefs:\n%s", help.out)
	}
	h := run(t, testEnv{}, "xrefs", "--help")
	for _, want := range []string{"teardown xrefs <file> <api> [flags]", "--before N", "--after N", "--max N", "--list", "--json", "--color WHEN", "(default 8)", "(default 4)", "(default 10)", "Examples:", "never executed"} {
		if !strings.Contains(h.out, want) {
			t.Errorf("xrefs --help lacks %q:\n%s", want, h.out)
		}
	}
	for _, shell := range completionShells {
		r := run(t, testEnv{}, "completion", shell)
		for _, want := range []string{"xrefs", "before", "after", "list"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("%s completion lacks %q", shell, want)
			}
		}
	}
	if got := run(t, testEnv{}, "xref"); !strings.Contains(got.err, `did you mean "xrefs"?`) {
		t.Errorf("a typo gets a suggestion: %q", got.err)
	}
}
