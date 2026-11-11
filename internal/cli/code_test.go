package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// codeFunc is a small x86-64 function written from the architecture manual (the
// opcode map and the ModRM tables), not produced by the decoder under test.
var codeFunc = []byte{
	0x55,             // push rbp
	0x48, 0x89, 0xe5, // mov rbp, rsp
	0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
	0x48, 0x8d, 0x0d, 0x10, 0, 0, 0, // lea rcx, [rip+0x10]
	0xff, 0x15, 0xf0, 0x0f, 0, 0, // call qword ptr [rip+0xff0]
	0x31, 0xc0, // xor eax, eax
	0x48, 0x83, 0xc4, 0x20, // add rsp, 0x20
	0x5d, // pop rbp
	0xc3, // ret
}

var (
	codeFuncText = []string{
		"push rbp", "mov rbp, rsp", "sub rsp, 0x20", "lea rcx, [rip+0x10]", "call qword ptr [rip+0xff0]",
		"xor eax, eax", "add rsp, 0x20", "pop rbp", "ret",
	}
	codeFuncLens = []int{1, 3, 4, 7, 6, 2, 4, 1, 1}
)

// codePE is a PE file on disk whose fourth section, ".code", holds codeFunc
// followed by int3 up to 0x200 bytes. The expected addresses come from the
// fixture's own headers.
type codePE struct {
	path      string
	file      []byte
	imageBase uint64
	codeVA    uint64
	codeOff   int64
}

func writeCodePE(t *testing.T, machine uint16) codePE {
	t.Helper()
	section := append(bytes.Clone(codeFunc), bytes.Repeat([]byte{0xcc}, 0x200-len(codeFunc))...)
	file := testfixtures.PE(testfixtures.PEOptions{
		Machine:  machine,
		Sections: []testfixtures.PESection{{Name: ".code", Data: section, Characteristics: testfixtures.PESectionCode}},
	})
	le := binary.LittleEndian
	hdr := file[testfixtures.PESectionHeaderOffset(64, 3):]
	base := le.Uint64(file[testfixtures.PEOptionalOffset+24:])
	return codePE{
		path:      write(t, "fixture.exe", file),
		file:      file,
		imageBase: base,
		codeVA:    base + uint64(le.Uint32(hdr[12:])),
		codeOff:   int64(le.Uint32(hdr[20:])),
	}
}

// rows lays out the expected listing rows of the instructions codeFunc[from:to]
// the way the command does: address, bytes padded to the widest, text.
func (fx codePE) rows(from, to int) []string {
	var out []string
	off := 0
	for i := range codeFuncText {
		if i >= from && i < to {
			row := fmt.Sprintf("0x%x  %-20s  %s", fx.codeVA+uint64(off), hexOf(codeFunc[off:off+codeFuncLens[i]]), codeFuncText[i])
			if i == 3 {
				// lea rcx, [rip+0x10] refers to a place in the section itself: the listing
				// says where, like the code of the findings does.
				row += fmt.Sprintf("  ; 0x%x in .code", fx.codeVA+uint64(off+codeFuncLens[i]+0x10))
			}
			out = append(out, row)
		}
		off += codeFuncLens[i]
	}
	return out
}

func hexOf(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

// body returns the lines of a listing that are not header or footer comments.
func body(listing string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(listing, "\n"), "\n") {
		if !strings.HasPrefix(l, ";") {
			out = append(out, l)
		}
	}
	return out
}

func TestHexdumpPrintsTheRowsAndSummarisesOnStderr(t *testing.T) {
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}
	copy(data[0x20:], "Hello, hexdump!!")
	path := write(t, "blob.bin", data)

	r := run(t, testEnv{}, "hexdump", path, "--at", "0x10", "-n", "32")
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.err)
	}
	want := "0000000010  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  |................|\n" +
		"0000000020  48 65 6c 6c 6f 2c 20 68 65 78 64 75 6d 70 21 21  |Hello, hexdump!!|\n"
	if r.out != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.out, want)
	}
	if r.err != "32 bytes shown (file offsets 0x10 to 0x2f of 300); continue with --at 0x30\n" {
		t.Errorf("stderr = %q", r.err)
	}

	t.Run("decimal offsets and the end of the file", func(t *testing.T) {
		r := run(t, testEnv{}, "hexdump", path, "--at", "290", "--length", "100")
		if r.code != exitOK || len(strings.Split(strings.TrimSpace(r.out), "\n")) != 1 || !strings.HasPrefix(r.out, "0000000122  22 23 24") {
			t.Fatalf("exit %d out %q", r.code, r.out)
		}
		if r.err != "10 bytes shown (file offsets 0x122 to 0x12b of 300); end of file\n" {
			t.Errorf("stderr = %q", r.err)
		}
	})
	t.Run("the default window is 128 bytes", func(t *testing.T) {
		r := run(t, testEnv{}, "hexdump", path)
		if rows := strings.Count(r.out, "\n"); r.code != exitOK || rows != 8 || !strings.HasPrefix(r.out, "0000000000  00 01 02") {
			t.Fatalf("exit %d, %d rows", r.code, rows)
		}
	})
	t.Run("flags may follow the file", func(t *testing.T) {
		a := run(t, testEnv{}, "hexdump", "--at", "16", "-n", "16", path)
		b := run(t, testEnv{}, "hexdump", path, "--at", "16", "-n", "16")
		if a.code != exitOK || a.out != b.out || !strings.HasPrefix(a.out, "0000000010  10 11") {
			t.Errorf("%q vs %q", a.out, b.out)
		}
	})
	t.Run("non-printable bytes are dots", func(t *testing.T) {
		hostile := write(t, "hostile.bin", []byte("a\x1b[31mred\x00\xff\n\rz"))
		r := run(t, testEnv{}, "hexdump", hostile)
		if r.code != exitOK || strings.ContainsRune(r.out, 0x1b) || !strings.Contains(r.out, "|a.[31mred....z|") {
			t.Fatalf("stdout %q", r.out)
		}
	})
}

func TestHexdumpJSONIsACodeBlock(t *testing.T) {
	fx := writeCodePE(t, 0)
	r := run(t, testEnv{}, "hexdump", fx.path, "--at", fmt.Sprint(fx.codeOff+1), "-n", "16", "--json")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	var b report.CodeBlock
	if err := json.Unmarshal([]byte(r.out), &b); err != nil {
		t.Fatalf("stdout is not a code block: %v\n%s", err, r.out)
	}
	if b.Kind != report.CodeKindHex || b.Section != ".code" || b.Offset != fx.codeOff+1 || len(b.Lines) != 1 || !b.Truncated {
		t.Fatalf("block = %+v", b)
	}
	if l := b.Lines[0]; l.Bytes != "48 89 e5 48 83 ec 20 48 8d 0d 10 00 00 00 ff 15" || l.Text != "H..H.. H........" || l.Offset != fx.codeOff+1 {
		t.Errorf("line = %+v", l)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}
	if !strings.Contains(b.Title, "fixture.exe") || len(b.Limitations) == 0 {
		t.Errorf("title %q limitations %v", b.Title, b.Limitations)
	}
}

func TestHexdumpBadInput(t *testing.T) {
	path := write(t, "blob.bin", bytes.Repeat([]byte{1}, 100))
	empty := write(t, "empty.bin", nil)
	dir := t.TempDir()
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no file", []string{"hexdump"}, exitUsage, "expected exactly one file"},
		{"two files", []string{"hexdump", path, path}, exitUsage, "expected exactly one file, got 2"},
		{"length zero", []string{"hexdump", path, "-n", "0"}, exitUsage, "--length must be between 1 and 4096"},
		{"length negative", []string{"hexdump", path, "--length", "-4"}, exitUsage, "--length must be between 1 and 4096"},
		{"length over the cap", []string{"hexdump", path, "-n", "4097"}, exitUsage, "--length must be between 1 and 4096"},
		{"huge length", []string{"hexdump", path, "-n", "1000000000"}, exitUsage, "--length must be between 1 and 4096"},
		{"length overflow", []string{"hexdump", path, "-n", "99999999999999999999"}, exitUsage, "not a whole number"},
		{"length not a number", []string{"hexdump", path, "-n", "lots"}, exitUsage, "not a whole number"},
		{"offset not a number", []string{"hexdump", path, "--at", "start"}, exitUsage, "--at:"},
		{"offset negative", []string{"hexdump", path, "--at", "-1"}, exitUsage, "--at:"},
		{"offset only 0x", []string{"hexdump", path, "--at", "0x"}, exitUsage, "--at:"},
		{"offset octal-looking is decimal", []string{"hexdump", path, "--at", "0o17"}, exitUsage, "--at:"},
		{"offset too large", []string{"hexdump", path, "--at", "0xffffffffffffffff"}, exitUsage, "not a file offset"},
		{"offset past the end", []string{"hexdump", path, "--at", "100"}, exitError, "file offset 100 is outside the file (the file has 100 bytes)"},
		{"offset far past the end", []string{"hexdump", path, "--at", "0x7fffffffffffffff"}, exitError, "outside the file"},
		{"empty file", []string{"hexdump", empty}, exitError, "the file is empty"},
		{"directory", []string{"hexdump", dir}, exitError, "is not a regular file"},
		{"missing file", []string{"hexdump", filepath.Join(dir, "nope")}, exitError, "cannot open"},
		{"unknown flag", []string{"hexdump", path, "--width", "8"}, exitUsage, "flag provided but not defined"},
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

func TestDisasmListing(t *testing.T) {
	fx := writeCodePE(t, 0)
	r := run(t, testEnv{}, "disasm", fx.path, "--at", fmt.Sprintf("0x%x", fx.codeVA), "-n", "9")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	wantHeader := fmt.Sprintf("; fixture.exe: PE, x86-64, section .code, 9 instructions from 0x%x (file offset 0x%x)\n", fx.codeVA, fx.codeOff)
	if !strings.HasPrefix(r.out, wantHeader) {
		t.Errorf("header:\n%s\nwant it to start with:\n%s", r.out, wantHeader)
	}
	if got, want := body(r.out), fx.rows(0, 9); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, want := range []string{"; Linear sweep:", "; x86 and x86-64 only;", "Not a decompiler"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the listing must state its limits, missing %q:\n%s", want, r.out)
		}
	}
	if want := fmt.Sprintf("; more code follows: continue with --at 0x%x\n", fx.codeVA+29); !strings.HasSuffix(r.out, want) {
		t.Errorf("footer: want it to end with %q, got:\n%s", want, r.out)
	}

	t.Run("a file offset", func(t *testing.T) {
		r := run(t, testEnv{}, "disasm", fx.path, "--offset", fmt.Sprint(fx.codeOff+8), "-n", "3")
		if r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		want := fmt.Sprintf("; fixture.exe: PE, x86-64, section .code, 3 instructions from 0x%x (file offset 0x%x)\n", fx.codeVA+8, fx.codeOff+8)
		if !strings.HasPrefix(r.out, want) || strings.Join(body(r.out), "\n") != strings.Join(fx.rows(3, 6), "\n") {
			t.Errorf("listing:\n%s", r.out)
		}
	})
	t.Run("the entry point when no start is given", func(t *testing.T) {
		r := run(t, testEnv{}, "disasm", fx.path, "-n", "2")
		if r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		if !strings.Contains(r.out, fmt.Sprintf("from the entry point 0x%x (file offset 0x", fx.imageBase+0x1000)) || !strings.Contains(r.out, "section .text") {
			t.Errorf("header:\n%s", r.out)
		}
		if rows := body(r.out); len(rows) != 2 || !strings.HasSuffix(rows[0], "xor eax, eax") || !strings.HasSuffix(rows[1], "ret") {
			t.Errorf("rows = %q", rows)
		}
	})
	t.Run("the window ends with the section", func(t *testing.T) {
		r := run(t, testEnv{}, "disasm", fx.path, "--at", fmt.Sprintf("0x%x", fx.codeVA+0x1fc), "-n", "50")
		if r.code != exitOK || len(body(r.out)) != 4 || strings.Contains(r.out, "more code follows") {
			t.Fatalf("exit %d:\n%s", r.code, r.out)
		}
	})
	t.Run("raw bytes need an architecture", func(t *testing.T) {
		raw := write(t, "blob.bin", append([]byte("12345678"), codeFunc...))
		if r := run(t, testEnv{}, "disasm", raw, "--offset", "8"); r.code != exitError || !strings.Contains(r.err, "cannot tell the instruction set") {
			t.Errorf("exit %d stderr %q", r.code, r.err)
		}
		r := run(t, testEnv{}, "disasm", raw, "--offset", "8", "--arch", "x86-64", "-n", "2")
		if r.code != exitOK {
			t.Fatalf("exit %d: %s", r.code, r.err)
		}
		if !strings.Contains(r.out, "; blob.bin: raw bytes, x86-64, 2 instructions from file offset 0x8\n") ||
			!strings.Contains(r.out, "addresses shown are file offsets") ||
			!strings.Contains(r.out, "0x8  55        push rbp\n0x9  48 89 e5  mov rbp, rsp\n") {
			t.Errorf("listing:\n%s", r.out)
		}
		if !strings.HasSuffix(r.out, "; more code follows: continue with --offset 0xc\n") {
			t.Errorf("footer:\n%s", r.out)
		}
	})
	t.Run("the 32-bit decoder", func(t *testing.T) {
		raw := write(t, "blob32.bin", []byte{0x55, 0x89, 0xe5, 0xc3})
		r := run(t, testEnv{}, "disasm", raw, "--arch", "x86")
		if r.code != exitOK || !strings.Contains(r.out, "push ebp") || !strings.Contains(r.out, "mov ebp, esp") {
			t.Errorf("exit %d:\n%s", r.code, r.out)
		}
	})
}

func TestDisasmJSONIsACodeBlock(t *testing.T) {
	fx := writeCodePE(t, 0)
	r := run(t, testEnv{}, "disasm", fx.path, "--at", fmt.Sprintf("0x%x", fx.codeVA), "-n", "9", "--json")
	if r.code != exitOK || r.err != "" {
		t.Fatalf("exit %d stderr %q", r.code, r.err)
	}
	var b report.CodeBlock
	if err := json.Unmarshal([]byte(r.out), &b); err != nil {
		t.Fatalf("stdout is not a code block: %v\n%s", err, r.out)
	}
	if b.Kind != report.CodeKindDisasm || b.Arch != "x86-64" || b.Section != ".code" || b.Offset != fx.codeOff || uint64(b.Address) != fx.codeVA || len(b.Lines) != 9 || !b.Truncated {
		t.Fatalf("block = %+v", b)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}
	call := b.Lines[4]
	if call.Text != "call qword ptr [rip+0xff0]" || call.Bytes != "ff 15 f0 0f 00 00" || uint64(call.Address) != fx.codeVA+15 || call.Offset != fx.codeOff+15 {
		t.Errorf("call line = %+v", call)
	}
	if !strings.Contains(r.out, fmt.Sprintf("%q", fmt.Sprintf("0x%x", fx.codeVA+15))) {
		t.Errorf("addresses must be strings in the JSON:\n%s", r.out)
	}
}

func TestDisasmBadInput(t *testing.T) {
	fx := writeCodePE(t, 0)
	arm := writeCodePE(t, 0xaa64)
	empty := write(t, "empty.bin", nil)
	dir := t.TempDir()
	at := fmt.Sprintf("0x%x", fx.codeVA)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no file", []string{"disasm"}, exitUsage, "expected exactly one file"},
		{"two files", []string{"disasm", fx.path, fx.path}, exitUsage, "expected exactly one file, got 2"},
		{"both starts", []string{"disasm", fx.path, "--at", at, "--offset", "0"}, exitUsage, "choose one of --at and --offset"},
		{"count zero", []string{"disasm", fx.path, "-n", "0"}, exitUsage, "--count must be between 1 and 256"},
		{"count over the cap", []string{"disasm", fx.path, "-n", "257"}, exitUsage, "--count must be between 1 and 256"},
		{"huge count", []string{"disasm", fx.path, "--count", "1000000"}, exitUsage, "--count must be between 1 and 256"},
		{"count overflow", []string{"disasm", fx.path, "-n", "99999999999999999999"}, exitUsage, "not a whole number"},
		{"unknown arch", []string{"disasm", fx.path, "--arch", "arm64"}, exitUsage, `--arch must be x86 or x86-64, not "arm64"`},
		{"address not a number", []string{"disasm", fx.path, "--at", "main"}, exitUsage, "--at:"},
		{"empty address", []string{"disasm", fx.path, "--at", ""}, exitUsage, "--at:"},
		{"negative offset", []string{"disasm", fx.path, "--offset", "-5"}, exitUsage, "--offset:"},
		{"offset too large", []string{"disasm", fx.path, "--offset", "0x8000000000000000"}, exitUsage, "not a file offset"},
		{"address in no section", []string{"disasm", fx.path, "--at", "0x1234"}, exitError, "address 0x1234 is not inside any section"},
		{"address of the headers", []string{"disasm", fx.path, "--at", fmt.Sprintf("0x%x", fx.imageBase)}, exitError, "mapped ranges: .text 0x"},
		{"offset past the end", []string{"disasm", fx.path, "--offset", "99999999"}, exitError, "outside the file"},
		{"not x86", []string{"disasm", arm.path}, exitError, "this file is PE ARM64: only x86 and x86-64 code can be disassembled"},
		{"empty file", []string{"disasm", empty, "--arch", "x86"}, exitError, "the file is empty"},
		{"directory", []string{"disasm", dir}, exitError, "is not a regular file"},
		{"missing file", []string{"disasm", filepath.Join(dir, "nope")}, exitError, "cannot open"},
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

	// An explicit instruction set overrides a header that says ARM64.
	r := run(t, testEnv{}, "disasm", arm.path, "--at", fmt.Sprintf("0x%x", arm.codeVA), "--arch", "x86-64", "-n", "1")
	if r.code != exitOK || !strings.Contains(r.out, "push rbp") || !strings.Contains(r.out, "header of the file says ARM64") {
		t.Errorf("exit %d:\n%s%s", r.code, r.out, r.err)
	}
}

func TestDisasmAndHexdumpNeverPrintRawControlCharacters(t *testing.T) {
	// Every byte value, so the sweep meets every opcode, prefix and invalid form.
	all := make([]byte, 0, 1024)
	for i := range 1024 {
		all = append(all, byte(i*7+i/256))
	}
	path := write(t, "noise.bin", all)
	for _, args := range [][]string{
		{"disasm", path, "--arch", "x86-64", "-n", "256"},
		{"disasm", path, "--arch", "x86", "-n", "256"},
		{"hexdump", path, "-n", "1024"},
	} {
		r := run(t, testEnv{}, args...)
		if r.code != exitOK {
			t.Fatalf("%v: exit %d: %s", args, r.code, r.err)
		}
		for _, c := range r.out + r.err {
			if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
				t.Fatalf("%v printed the control character %U", args, c)
			}
		}
	}
}

func TestCodeCommandsPrintHostileFileNamesSafely(t *testing.T) {
	// Names with a C1 control (accepted by every file system this runs on) and
	// with an escape character (refused by Windows, which skips that case).
	names := []struct{ name, escaped string }{
		{"ev" + string(rune(0x85)) + "il", `ev\x85il`},
		{"ev" + string(rune(0x1b)) + "[31mil", `ev\x1b[31mil`},
	}
	for _, n := range names {
		t.Run(n.escaped, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), n.name)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Skipf("this file system refuses the file name (%v)", err)
			}
			file := filepath.Join(t.TempDir(), n.name+".bin")
			if err := os.WriteFile(file, codeFunc, 0o644); err != nil {
				t.Skipf("this file system refuses the file name (%v)", err)
			}
			for _, args := range [][]string{{"disasm", dir}, {"hexdump", dir}, {"disasm", filepath.Join(dir, "missing")}} {
				r := run(t, testEnv{}, args...)
				if r.code != exitError || !strings.Contains(r.err, n.escaped) {
					t.Fatalf("%v: exit %d, stderr %q must show the escaped name %q", args, r.code, r.err, n.escaped)
				}
				for _, c := range r.err {
					if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
						t.Errorf("%v: stderr carries the control character %U: %q", args, c, r.err)
					}
				}
			}
			r := run(t, testEnv{}, "disasm", file, "--arch", "x86-64", "-n", "1")
			if r.code != exitOK || !strings.Contains(r.out, "; "+n.escaped+".bin: raw bytes") {
				t.Errorf("the file name in the listing header must be escaped:\n%q", r.out)
			}
			for _, c := range r.out {
				if c != '\n' && (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
					t.Errorf("the listing carries the control character %U", c)
				}
			}
		})
	}
}

func TestNewCommandsAreInTheHelpAndTheCompletions(t *testing.T) {
	help := run(t, testEnv{}, "--help")
	for _, want := range []string{"disasm", "hexdump", "teardown disasm app.exe --at"} {
		if !strings.Contains(help.out, want) {
			t.Errorf("--help lacks %q", want)
		}
	}
	for _, cmd := range []string{"disasm", "hexdump"} {
		h := run(t, testEnv{}, "help", cmd)
		if h.code != exitOK || !strings.Contains(h.out, "Examples:") || !strings.Contains(h.out, "--json") || !strings.Contains(h.out, "-n, --") {
			t.Errorf("help %s:\n%s", cmd, h.out)
		}
	}
	if h := run(t, testEnv{}, "disasm", "--help"); !strings.Contains(h.out, "--arch ARCH") || !strings.Contains(h.out, "--at ADDR") || !strings.Contains(h.out, "--offset OFFSET") || !strings.Contains(h.out, "(default 24)") {
		t.Errorf("disasm --help:\n%s", h.out)
	}
	if h := run(t, testEnv{}, "hexdump", "--help"); !strings.Contains(h.out, "--at OFFSET") || !strings.Contains(h.out, "(default 128)") {
		t.Errorf("hexdump --help:\n%s", h.out)
	}
	for _, shell := range completionShells {
		r := run(t, testEnv{}, "completion", shell)
		for _, want := range []string{"disasm", "hexdump", "arch", "no-code", "code-all", "offset", "length", "count"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("%s completion lacks %q", shell, want)
			}
		}
	}
	if bash := run(t, testEnv{}, "completion", "bash"); !strings.Contains(bash.out, `--arch) COMPREPLY=( $(compgen -W "x86 x86-64"`) {
		t.Errorf("bash completion must offer the architectures:\n%s", bash.out)
	}
}

func TestShortNIsAPlainNumberEverywhere(t *testing.T) {
	// "-n" is the short form of three different flags in three commands; the
	// completion scripts share flag kinds by spelling, so none may be a file or
	// a directory.
	for _, c := range commands() {
		fs := newFlagSet(c.name)
		c.register(fs)
		for _, s := range fs.specs {
			if s.short == "n" && (s.file || s.dir || len(s.allowed) > 0) {
				t.Errorf("%s --%s: -n must stay a plain number in the completions", c.name, s.name)
			}
		}
	}
}
