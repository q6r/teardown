package mcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// codePE is a PE image whose fourth section, ".code", holds codeFunc followed
// by int3 up to 0x200 bytes. The expected addresses come from the fixture's own
// headers.
type codePE struct {
	file      []byte
	imageBase uint64
	codeVA    uint64
	codeOff   int64
}

func buildCodePE(machine uint16) codePE {
	section := append(bytes.Clone(codeFunc), bytes.Repeat([]byte{0xcc}, 0x200-len(codeFunc))...)
	file := testfixtures.PE(testfixtures.PEOptions{
		Machine:  machine,
		Sections: []testfixtures.PESection{{Name: ".code", Data: section, Characteristics: testfixtures.PESectionCode}},
	})
	le := binary.LittleEndian
	hdr := file[testfixtures.PESectionHeaderOffset(64, 3):]
	base := le.Uint64(file[testfixtures.PEOptionalOffset+24:])
	return codePE{file: file, imageBase: base, codeVA: base + uint64(le.Uint32(hdr[12:])), codeOff: int64(le.Uint32(hdr[20:]))}
}

// patternBytes are n bytes 0, 1, 2, ... (wrapping), so a window's content
// follows from its offset.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// codeLines returns the lines array of a tool result.
func codeLines(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	code, ok := doc["code"].(map[string]any)
	if !ok {
		t.Fatalf("result has no code block: %v", doc)
	}
	raw, _ := code["lines"].([]any)
	lines := make([]map[string]any, len(raw))
	for i, l := range raw {
		lines[i] = l.(map[string]any)
	}
	return lines
}

func TestCodeToolsAreDescribedAndBounded(t *testing.T) {
	byName := map[string]map[string]any{}
	for _, tool := range listTools(t, "2025-06-18") {
		byName[tool["name"].(string)] = tool
	}
	for _, name := range []string{"disassemble", "read_bytes"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("tool %s is not listed", name)
		}
		desc := tool["description"].(string)
		if !strings.Contains(desc, "never executed") && !strings.Contains(desc, "without executing") {
			t.Errorf("%s: the description must say the file is never executed: %q", name, desc)
		}
	}
	props := func(name string) map[string]any {
		return byName[name]["inputSchema"].(map[string]any)["properties"].(map[string]any)
	}
	prop := func(tool, key, field string) any { return props(tool)[key].(map[string]any)[field] }

	if prop("read_bytes", "length", "maximum") != float64(4096) || prop("read_bytes", "length", "minimum") != float64(1) || prop("read_bytes", "length", "default") != float64(128) {
		t.Errorf("read_bytes length bounds = %v", props("read_bytes")["length"])
	}
	if prop("read_bytes", "offset", "minimum") != float64(0) {
		t.Errorf("read_bytes offset = %v", props("read_bytes")["offset"])
	}
	if prop("disassemble", "count", "maximum") != float64(256) || prop("disassemble", "count", "default") != float64(24) {
		t.Errorf("disassemble count = %v", props("disassemble")["count"])
	}
	arch := prop("disassemble", "arch", "enum").([]any)
	if len(arch) != 2 || arch[0] != "x86" || arch[1] != "x86-64" {
		t.Errorf("disassemble arch enum = %v", arch)
	}
	if prop("disassemble", "address", "type") != "string" || prop("disassemble", "address", "pattern") == nil {
		t.Errorf("disassemble address = %v", props("disassemble")["address"])
	}
	if desc := byName["disassemble"]["description"].(string); !strings.Contains(desc, "linear sweep") || !strings.Contains(desc, "not a decompiler") || !strings.Contains(desc, "ARM64") {
		t.Errorf("the disassemble description must state its limits: %q", desc)
	}
	for _, name := range []string{"disassemble", "read_bytes"} {
		checkInputSchema(t, name, byName[name]["inputSchema"])
		if req, _ := byName[name]["inputSchema"].(map[string]any)["required"].([]any); len(req) != 1 || req[0] != "path" {
			t.Errorf("%s: only the path is required, got %v", name, req)
		}
	}
}

// TestCodeToolSchemasAgreeWithHandlers feeds the same arguments to the schema
// validator and to the real handlers, like TestSchemasAgreeWithHandlers does for
// the older tools.
func TestCodeToolSchemasAgreeWithHandlers(t *testing.T) {
	root := t.TempDir()
	fx := buildCodePE(0)
	writeFile(t, root, "code.exe", fx.file)
	schemas := map[string]map[string]any{}
	for _, tool := range listTools(t, "2025-06-18") {
		schemas[tool["name"].(string)] = tool["inputSchema"].(map[string]any)
	}
	addr := fmt.Sprintf("0x%x", fx.codeVA)
	type tc struct {
		tool             string
		args             map[string]any
		schemaOK, callOK bool
	}
	tests := []tc{
		{"read_bytes", map[string]any{"path": "code.exe"}, true, true},
		{"read_bytes", map[string]any{"path": "code.exe", "offset": 0, "length": 1}, true, true},
		{"read_bytes", map[string]any{"path": "code.exe", "offset": 100, "length": 4096}, true, true},
		{"read_bytes", map[string]any{}, false, false},
		{"read_bytes", map[string]any{"path": ""}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "length": 0}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "length": 4097}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "length": 1.5}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "offset": -1}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "offset": "5"}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "extra": true}, false, false},
		{"read_bytes", map[string]any{"path": "code.exe", "offset": 1 << 40}, true, false}, // past the end: only the file knows
		{"disassemble", map[string]any{"path": "code.exe"}, true, true},
		{"disassemble", map[string]any{"path": "code.exe", "address": addr, "count": 1}, true, true},
		{"disassemble", map[string]any{"path": "code.exe", "address": "4194304"}, true, false}, // decimal is allowed; no section holds it
		{"disassemble", map[string]any{"path": "code.exe", "offset": 0x400, "count": 256}, true, true},
		{"disassemble", map[string]any{"path": "code.exe", "arch": "x86"}, true, true},
		{"disassemble", map[string]any{"path": "code.exe", "arch": "x86-64"}, true, true},
		{"disassemble", map[string]any{}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "count": 0}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "count": 257}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "arch": "arm64"}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "arch": 64}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "address": 4096}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "offset": -4}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "bogus": 1}, false, false},
		{"disassemble", map[string]any{"path": "code.exe", "address": "main"}, true, false}, // a pattern the validator subset does not check
		{"disassemble", map[string]any{"path": "code.exe", "address": addr, "offset": 5}, true, false},
	}
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	for i, tc := range tests {
		raw, _ := json.Marshal(tc.args)
		var decoded any
		_ = json.Unmarshal(raw, &decoded)
		violations := validateSchema(schemas[tc.tool], decoded)
		if (len(violations) == 0) != tc.schemaOK {
			t.Errorf("%s %s: schema verdict ok=%v (violations %v), want %v", tc.tool, raw, len(violations) == 0, violations, tc.schemaOK)
		}
		res := c.callTool(2000+i, tc.tool, tc.args)
		if res.IsError == tc.callOK {
			t.Errorf("%s %s: isError=%v, want %v (%.200s)", tc.tool, raw, res.IsError, !tc.callOK, res.text())
		}
	}
}

func TestReadBytes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "blob.bin", patternBytes(300))
	fx := buildCodePE(0)
	writeFile(t, root, "code.exe", fx.file)
	writeFile(t, root, "empty.bin", nil)
	for _, version := range []string{"2024-11-05", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
			c.initialize(version)

			res := c.callTool(1, "read_bytes", map[string]any{"path": "blob.bin", "offset": 16, "length": 32})
			doc := mustJSON(t, res)
			if (version == "2025-06-18") != (len(res.StructuredContent) > 0) {
				t.Errorf("structuredContent present = %v", len(res.StructuredContent) > 0)
			}
			file := doc["file"].(map[string]any)
			code := doc["code"].(map[string]any)
			if file["name"] != "blob.bin" || file["size"] != float64(300) || doc["length"] != float64(32) || doc["truncated"] != false {
				t.Errorf("file %v length %v truncated %v", file, doc["length"], doc["truncated"])
			}
			if code["kind"] != "hex" || code["offset"] != float64(16) || code["truncated"] != true || !strings.Contains(code["title"].(string), "blob.bin") {
				t.Errorf("code block = %v", code)
			}
			if lims, _ := code["limitations"].([]any); len(lims) == 0 {
				t.Error("a block always states its limitations")
			}
			if next := doc["next"].(map[string]any); next["offset"] != float64(48) || next["address"] != nil {
				t.Errorf("next = %v", next)
			}
			lines := codeLines(t, doc)
			if len(lines) != 2 || lines[0]["offset"] != float64(16) || lines[0]["bytes"] != "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" || lines[0]["text"] != "................" || lines[1]["offset"] != float64(32) {
				t.Errorf("lines = %v", lines)
			}
			if !strings.HasPrefix(res.text(), "{\n  \"file\": {") {
				t.Errorf("text must be pretty-printed with the file first: %.80q", res.text())
			}
		})
	}
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())

	t.Run("defaults", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(1, "read_bytes", map[string]any{"path": "blob.bin"}))
		if lines := codeLines(t, doc); len(lines) != 8 || doc["length"] != float64(128) || doc["next"].(map[string]any)["offset"] != float64(128) {
			t.Errorf("%d lines, length %v, next %v", len(lines), doc["length"], doc["next"])
		}
	})
	t.Run("the end of the file", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(2, "read_bytes", map[string]any{"path": "blob.bin", "offset": 290, "length": 100}))
		code := doc["code"].(map[string]any)
		if doc["length"] != float64(10) || doc["next"] != nil || code["truncated"] != nil || len(codeLines(t, doc)) != 1 {
			t.Errorf("length %v next %v truncated %v", doc["length"], doc["next"], code["truncated"])
		}
		if l := codeLines(t, doc)[0]; l["bytes"] != "22 23 24 25 26 27 28 29 2a 2b" || l["text"] != "\"#$%&'()*+" {
			t.Errorf("line = %v", l)
		}
	})
	t.Run("the largest window", func(t *testing.T) {
		writeFile(t, root, "big.bin", patternBytes(10_000))
		doc := mustJSON(t, c.callTool(3, "read_bytes", map[string]any{"path": "big.bin", "length": 4096}))
		if doc["length"] != float64(4096) || len(codeLines(t, doc)) != 256 || doc["next"].(map[string]any)["offset"] != float64(4096) || doc["truncated"] != false {
			t.Errorf("length %v lines %d truncated %v", doc["length"], len(codeLines(t, doc)), doc["truncated"])
		}
	})
	t.Run("a PE names its section", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(4, "read_bytes", map[string]any{"path": "code.exe", "offset": fx.codeOff + 1, "length": 16}))
		code := doc["code"].(map[string]any)
		if code["section"] != ".code" || codeLines(t, doc)[0]["bytes"] != "48 89 e5 48 83 ec 20 48 8d 0d 10 00 00 00 ff 15" {
			t.Errorf("code = %v", code)
		}
		if codeLines(t, doc)[0]["text"] != "H..H.. H........" {
			t.Errorf("ascii = %q", codeLines(t, doc)[0]["text"])
		}
	})
	t.Run("hostile bytes stay printable", func(t *testing.T) {
		writeFile(t, root, "hostile.bin", []byte("a\x1b[31m\x00\x85\xff<script>\n"))
		res := c.callTool(5, "read_bytes", map[string]any{"path": "hostile.bin"})
		doc := mustJSON(t, res)
		lines := codeLines(t, doc)
		if len(lines) != 2 || lines[0]["text"] != "a.[31m...<script" || lines[1]["text"] != ">." {
			t.Errorf("ascii rows = %v", lines)
		}
		if strings.ContainsAny(res.text(), "\x1b\x00"+string(rune(0x85))) {
			t.Errorf("raw control characters in the result: %q", res.text())
		}
	})
	t.Run("errors", func(t *testing.T) {
		tests := []struct {
			args map[string]any
			want string
		}{
			{map[string]any{"path": "blob.bin", "offset": 300}, "file offset 300 is outside the file (the file has 300 bytes)"},
			{map[string]any{"path": "blob.bin", "offset": 1 << 40}, "outside the file"},
			{map[string]any{"path": "empty.bin"}, "the file is empty"},
			{map[string]any{"path": "blob.bin", "offset": -1}, `argument "offset" must be between 0 and`},
			{map[string]any{"path": "blob.bin", "length": 0}, `argument "length" must be between 1 and 4096 (got 0)`},
			{map[string]any{"path": "blob.bin", "length": 4097}, `argument "length" must be between 1 and 4096 (got 4097)`},
			{map[string]any{"path": "blob.bin", "length": 1e9}, `argument "length" must be between 1 and 4096`},
			{map[string]any{"path": "blob.bin", "length": 1.5}, `argument "length" must be an integer`},
			{map[string]any{"path": "blob.bin", "offset": "5"}, `argument "offset" must be an integer`},
			{map[string]any{"path": "blob.bin", "offset": 1e30}, `argument "offset" must be an integer`},
			{map[string]any{"path": "blob.bin", "extra": 1}, `unknown argument "extra"`},
			{map[string]any{}, `missing required argument "path"`},
			{map[string]any{"path": "nope.bin"}, "file not found"},
			{map[string]any{"path": "."}, "a directory"},
		}
		for i, tc := range tests {
			if msg := mustErrorText(t, c.callTool(100+i, "read_bytes", tc.args)); !strings.Contains(msg, tc.want) {
				t.Errorf("%v: message %q does not contain %q", tc.args, msg, tc.want)
			}
		}
	})
}

func TestDisassemble(t *testing.T) {
	root := t.TempDir()
	fx := buildCodePE(0)
	writeFile(t, root, "code.exe", fx.file)
	writeFile(t, root, "raw.bin", append([]byte("12345678"), codeFunc...))
	writeFile(t, root, "arm.exe", buildCodePE(0xaa64).file)
	writeFile(t, root, "empty.bin", nil)
	writeFile(t, root, "code.elf", testfixtures.ELF(testfixtures.ELFOptions{TextData: codeFunc}))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	c.initialize("2025-06-18")
	addr := func(v uint64) string { return fmt.Sprintf("0x%x", v) }

	checkLines := func(t *testing.T, doc map[string]any, from, to int, firstAddr uint64, firstOff int64) {
		t.Helper()
		lines := codeLines(t, doc)
		if len(lines) != to-from {
			t.Fatalf("%d lines, want %d", len(lines), to-from)
		}
		a, o := firstAddr, firstOff
		for i, l := range lines {
			if l["text"] != codeFuncText[from+i] || l["address"] != addr(a) || l["offset"] != float64(o) {
				t.Errorf("line %d = %v, want %q at %s offset %d", i, l, codeFuncText[from+i], addr(a), o)
			}
			a += uint64(codeFuncLens[from+i])
			o += int64(codeFuncLens[from+i])
		}
	}

	t.Run("by address", func(t *testing.T) {
		res := c.callTool(1, "disassemble", map[string]any{"path": "code.exe", "address": addr(fx.codeVA), "count": 9})
		doc := mustJSON(t, res)
		code := doc["code"].(map[string]any)
		if doc["start"] != "address" || code["kind"] != "disasm" || code["arch"] != "x86-64" || code["section"] != ".code" || code["address"] != addr(fx.codeVA) || code["offset"] != float64(fx.codeOff) {
			t.Fatalf("start %v code %v", doc["start"], code)
		}
		checkLines(t, doc, 0, 9, fx.codeVA, fx.codeOff)
		next := doc["next"].(map[string]any)
		if next["address"] != addr(fx.codeVA+29) || next["offset"] != float64(fx.codeOff+29) || code["truncated"] != true || doc["truncated"] != false {
			t.Errorf("next %v code.truncated %v truncated %v", next, code["truncated"], doc["truncated"])
		}
		lims, _ := code["limitations"].([]any)
		if len(lims) < 2 || !strings.Contains(fmt.Sprint(lims), "Linear sweep") || !strings.Contains(fmt.Sprint(lims), "x86 and x86-64 only") {
			t.Errorf("limitations = %v", lims)
		}
		if _, has := doc["length"]; has {
			t.Error("a disassembly has no length member")
		}
		var structured map[string]any
		if err := json.Unmarshal(res.StructuredContent, &structured); err != nil || structured["start"] != "address" {
			t.Errorf("structuredContent: %v", err)
		}
	})
	t.Run("addresses may be written in decimal or upper-case hex", func(t *testing.T) {
		for _, form := range []string{fmt.Sprint(fx.codeVA + 8), "0X" + strings.ToUpper(fmt.Sprintf("%x", fx.codeVA+8))} {
			doc := mustJSON(t, c.callTool(2, "disassemble", map[string]any{"path": "code.exe", "address": form, "count": 3}))
			checkLines(t, doc, 3, 6, fx.codeVA+8, fx.codeOff+8)
		}
	})
	t.Run("by offset", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(3, "disassemble", map[string]any{"path": "code.exe", "offset": fx.codeOff + 4, "count": 2}))
		if doc["start"] != "offset" {
			t.Errorf("start = %v", doc["start"])
		}
		checkLines(t, doc, 2, 4, fx.codeVA+4, fx.codeOff+4)
	})
	t.Run("the entry point by default", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(4, "disassemble", map[string]any{"path": "code.exe", "count": 2}))
		code := doc["code"].(map[string]any)
		lines := codeLines(t, doc)
		if doc["start"] != "entry point" || code["section"] != ".text" || code["address"] != addr(fx.imageBase+0x1000) || lines[0]["text"] != "xor eax, eax" || lines[1]["text"] != "ret" {
			t.Errorf("start %v code %v lines %v", doc["start"], code, lines)
		}
	})
	t.Run("an ELF image", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(5, "disassemble", map[string]any{"path": "code.elf", "count": 9}))
		for i, l := range codeLines(t, doc) {
			if l["text"] != codeFuncText[i] {
				t.Errorf("line %d = %v", i, l)
			}
		}
		if doc["start"] != "entry point" || !strings.HasPrefix(doc["code"].(map[string]any)["section"].(string), "LOAD ") {
			t.Errorf("start %v code %v", doc["start"], doc["code"])
		}
	})
	t.Run("raw bytes need an architecture and have no addresses", func(t *testing.T) {
		msg := mustErrorText(t, c.callTool(6, "disassemble", map[string]any{"path": "raw.bin", "offset": 8}))
		if !strings.Contains(msg, "cannot tell the instruction set") {
			t.Errorf("message = %q", msg)
		}
		doc := mustJSON(t, c.callTool(7, "disassemble", map[string]any{"path": "raw.bin", "offset": 8, "arch": "x86-64", "count": 2}))
		code := doc["code"].(map[string]any)
		next := doc["next"].(map[string]any)
		if code["address"] != nil || code["section"] != nil || next["address"] != nil || next["offset"] != float64(12) {
			t.Errorf("code %v next %v", code, next)
		}
		for i, l := range codeLines(t, doc) {
			if l["address"] != nil || l["text"] != codeFuncText[i] || l["offset"] != float64(8+[]int{0, 1}[i]) {
				t.Errorf("line %d = %v", i, l)
			}
		}
		if !strings.Contains(fmt.Sprint(code["limitations"]), "addresses shown are file offsets") {
			t.Errorf("limitations = %v", code["limitations"])
		}
	})
	t.Run("the 32-bit decoder", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(8, "disassemble", map[string]any{"path": "code.exe", "address": addr(fx.codeVA), "arch": "x86", "count": 2}))
		// In 32-bit mode 0x48 is "dec eax", not a REX prefix.
		if lines := codeLines(t, doc); lines[0]["text"] != "push ebp" || lines[1]["text"] != "dec eax" || doc["code"].(map[string]any)["arch"] != "x86" {
			t.Errorf("lines = %v", lines)
		}
	})
	t.Run("a window that ends with the section has no next", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(9, "disassemble", map[string]any{"path": "code.exe", "address": addr(fx.codeVA + 0x1fc), "count": 50}))
		if len(codeLines(t, doc)) != 4 || doc["next"] != nil || doc["code"].(map[string]any)["truncated"] != nil {
			t.Errorf("next %v lines %d", doc["next"], len(codeLines(t, doc)))
		}
	})
	t.Run("errors", func(t *testing.T) {
		tests := []struct {
			args map[string]any
			want string
		}{
			{map[string]any{"path": "code.exe", "address": addr(fx.codeVA), "offset": 1}, `give either argument "address" or argument "offset"`},
			{map[string]any{"path": "code.exe", "address": "0x1234"}, "address 0x1234 is not inside any section"},
			{map[string]any{"path": "code.exe", "address": addr(fx.imageBase)}, "mapped ranges: .text 0x"},
			{map[string]any{"path": "code.exe", "address": "main"}, `argument "address": "main" is not a number`},
			{map[string]any{"path": "code.exe", "address": "-1"}, `argument "address":`},
			{map[string]any{"path": "code.exe", "address": "0x"}, `argument "address":`},
			{map[string]any{"path": "code.exe", "address": ""}, `argument "address":`},
			{map[string]any{"path": "code.exe", "address": "0x10000000000000000"}, "too large"},
			{map[string]any{"path": "code.exe", "address": 4096}, `argument "address" must be a string`},
			{map[string]any{"path": "code.exe", "offset": 1 << 40}, "outside the file"},
			{map[string]any{"path": "code.exe", "offset": -1}, `argument "offset" must be between 0 and`},
			{map[string]any{"path": "code.exe", "count": 0}, `argument "count" must be between 1 and 256 (got 0)`},
			{map[string]any{"path": "code.exe", "count": 257}, `argument "count" must be between 1 and 256 (got 257)`},
			{map[string]any{"path": "code.exe", "count": 1e9}, `argument "count" must be between 1 and 256`},
			{map[string]any{"path": "code.exe", "arch": "arm64"}, `argument "arch" must be "x86" or "x86-64" (got "arm64")`},
			{map[string]any{"path": "arm.exe"}, "this file is PE ARM64: only x86 and x86-64 code can be disassembled"},
			{map[string]any{"path": "empty.bin", "arch": "x86"}, "the file is empty"},
			{map[string]any{"path": "nope.bin"}, "file not found"},
			{map[string]any{"path": "."}, "a directory"},
			{map[string]any{}, `missing required argument "path"`},
		}
		for i, tc := range tests {
			if msg := mustErrorText(t, c.callTool(100+i, "disassemble", tc.args)); !strings.Contains(msg, tc.want) {
				t.Errorf("%v: message %q does not contain %q", tc.args, msg, tc.want)
			}
		}
		// An explicit instruction set overrides a header that says ARM64, and says so.
		arm := buildCodePE(0xaa64)
		doc := mustJSON(t, c.callTool(300, "disassemble", map[string]any{"path": "arm.exe", "address": addr(arm.codeVA), "arch": "x86-64", "count": 1}))
		if !strings.Contains(fmt.Sprint(doc["code"].(map[string]any)["limitations"]), "header of the file says ARM64") {
			t.Errorf("limitations = %v", doc["code"].(map[string]any)["limitations"])
		}
	})
}

// TestCodeToolsStayInsideTheRoots runs hostile paths through both tools: every
// one must come back as an isError result and none may expose the outside file,
// in text or as hex.
func TestCodeToolsStayInsideTheRoots(t *testing.T) {
	fx := newConfinementFixture(t)
	c := startServer(t, Config{Roots: []string{fx.root}}, realAnalyzer())
	secretHex := hexOf(fx.secret)

	hostile := []string{
		"../outside.bin", "../root-evil/secret.bin", "sub/../../outside.bin",
		filepath.Join(fx.base, "outside.bin"), filepath.Join(fx.evil, "secret.bin"),
		filepath.Join(fx.root, "..", "outside.bin"), "%2e%2e/outside.bin", "....//outside.bin", "..;/outside.bin",
		"sub", ".", "", "ok.bin\x00../outside.bin", "file:///etc/passwd", strings.Repeat("../", 50) + "outside.bin",
	}
	if os.PathSeparator == '\\' {
		hostile = append(hostile, `..\outside.bin`, `sub\..\..\outside.bin`, `..\root-evil\secret.bin`, "NUL", `\\.\NUL`,
			filepath.ToSlash(filepath.Join(fx.base, "outside.bin")), "ok.bin::$DATA", `\\localhost\c$\Windows\notepad.exe`)
	}
	check := func(label string, res toolRes) {
		t.Helper()
		text := mustErrorText(t, res)
		if strings.Contains(text, string(fx.secret)) || strings.Contains(text, secretHex) || strings.Contains(text, hexSHA256(fx.secret)) {
			t.Fatalf("%s exposed the outside file: %s", label, text)
		}
	}
	for i, p := range hostile {
		check(fmt.Sprintf("read_bytes(%q)", p), c.callTool(1000+i*4, "read_bytes", map[string]any{"path": p}))
		check(fmt.Sprintf("disassemble(%q)", p), c.callTool(1001+i*4, "disassemble", map[string]any{"path": p, "arch": "x86-64"}))
		check(fmt.Sprintf("disassemble(%q, offset)", p), c.callTool(1002+i*4, "disassemble", map[string]any{"path": p, "offset": 0, "arch": "x86"}))
		check(fmt.Sprintf("find_calls(%q)", p), c.callTool(1003+i*4, "find_calls", map[string]any{"path": p, "api": "ExitProcess"}))
	}

	t.Run("symbolic links that leave the root", func(t *testing.T) {
		for name, target := range map[string]string{"link-file": filepath.Join(fx.base, "outside.bin"), "link-rel": filepath.Join("..", "outside.bin")} {
			if err := os.Symlink(target, filepath.Join(fx.root, name)); err != nil {
				t.Skipf("this environment cannot create symbolic links (%v)", err)
			}
		}
		for i, name := range []string{"link-file", "link-rel"} {
			for tool, args := range map[string]map[string]any{
				"read_bytes":  {"path": name},
				"disassemble": {"path": name, "arch": "x86-64"},
				"find_calls":  {"path": name, "api": "ExitProcess"},
			} {
				msg := mustErrorText(t, c.callTool(2000+i, tool, args))
				if !strings.Contains(msg, "leaves the allowed roots") || strings.Contains(msg, secretHex) {
					t.Errorf("%s(%s): %q", tool, name, msg)
				}
			}
		}
	})

	// The file inside the root still reads, and shows its own bytes.
	doc := mustJSON(t, c.callTool(3000, "read_bytes", map[string]any{"path": "ok.bin"}))
	if got := codeLines(t, doc)[0]["bytes"]; got != hexOf(fx.okData[:16]) {
		t.Errorf("bytes = %v, want %s", got, hexOf(fx.okData[:16]))
	}
	for _, p := range []string{filepath.Join(fx.root, "ok.bin"), "./ok.bin", "sub/../ok.bin"} {
		mustJSON(t, c.callTool(3001, "read_bytes", map[string]any{"path": p, "length": 4}))
	}
}

func hexOf(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}

func TestCodeToolsRefuseOversizedInput(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.bin", patternBytes(64))
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())

	long := strings.Repeat("a", maxPathBytes+1)
	for _, tool := range []string{"read_bytes", "disassemble", "find_calls"} {
		args := map[string]any{"path": long}
		if tool == "find_calls" {
			args["api"] = "ExitProcess"
		}
		if msg := mustErrorText(t, c.callTool(1, tool, args)); !strings.Contains(msg, "longer than") {
			t.Errorf("%s: %q", tool, msg)
		}
	}
	// A line over the protocol limit is discarded and the session goes on.
	c.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_bytes","arguments":{"path":"` + strings.Repeat("b", maxLine) + `"}}}`)
	if m := c.recv(); m.Error == nil || m.Error.Code != codeInvalidRequest || !strings.Contains(m.Error.Message, "too large") {
		t.Fatalf("response to an oversized line: %+v", m)
	}
	doc := mustJSON(t, c.callTool(8, "read_bytes", map[string]any{"path": "a.bin", "length": 4}))
	if doc["length"] != float64(4) {
		t.Errorf("the session must go on after an oversized line: %v", doc)
	}
}

// TestCodeToolsFitTheOutputCap shrinks the cap and checks that the windows give
// up lines, say so, and still tell where to continue.
func TestCodeToolsFitTheOutputCap(t *testing.T) {
	root := t.TempDir()
	fx := buildCodePE(0)
	writeFile(t, root, "code.exe", fx.file)
	writeFile(t, root, "big.bin", patternBytes(8192))
	for _, limit := range []int{minMaxOutput, 3 << 10, 8 << 10, 24 << 10} {
		for _, tool := range []string{"read_bytes", "disassemble"} {
			t.Run(fmt.Sprintf("%s/%d", tool, limit), func(t *testing.T) {
				c := startServer(t, Config{Roots: []string{root}, MaxOutput: limit}, realAnalyzer())
				args := map[string]any{"path": "big.bin", "length": 4096}
				if tool == "disassemble" {
					args = map[string]any{"path": "code.exe", "address": fmt.Sprintf("0x%x", fx.codeVA), "count": 256}
				}
				res := c.callTool(1, tool, args)
				if res.IsError {
					if limit > minMaxOutput || !strings.Contains(res.text(), "output limit") {
						t.Fatalf("unexpected error at cap %d: %s", limit, res.text())
					}
					return
				}
				if len(res.text()) > limit {
					t.Fatalf("text is %d bytes, cap is %d", len(res.text()), limit)
				}
				doc := mustJSON(t, res)
				lines := codeLines(t, doc)
				if len(lines) == 0 {
					t.Fatal("a window keeps at least one line")
				}
				if doc["truncated"] != true {
					t.Fatalf("a trimmed result must say truncated:true (%d lines)", len(lines))
				}
				if len(doc["trimmed"].([]any)) == 0 || !strings.Contains(doc["note"].(string), "next") {
					t.Errorf("trimmed %v note %v", doc["trimmed"], doc["note"])
				}
				// "next" continues exactly where the kept lines end.
				last := lines[len(lines)-1]
				size := float64((len(last["bytes"].(string)) + 1) / 3)
				next := doc["next"].(map[string]any)
				if next["offset"] != last["offset"].(float64)+size {
					t.Errorf("next %v does not follow the last line %v", next, last)
				}
				if tool == "disassemble" {
					var lastAddr uint64
					if _, err := fmt.Sscanf(last["address"].(string), "0x%x", &lastAddr); err != nil || next["address"] != fmt.Sprintf("0x%x", lastAddr+uint64(size)) {
						t.Errorf("next address %v does not follow %v", next["address"], last["address"])
					}
				} else {
					first := lines[0]
					if doc["length"] != float64(len(lines)*16) || first["offset"] != float64(0) {
						t.Errorf("length %v for %d rows", doc["length"], len(lines))
					}
				}
				if doc["code"].(map[string]any)["truncated"] != true {
					t.Error("the block must say that the code goes on")
				}
			})
		}
	}
}
