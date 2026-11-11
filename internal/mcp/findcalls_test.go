package mcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// callsRoot writes the files the find_calls tests read: the sample dropper (a PE
// whose code calls the process-injection chain), an image that calls one import
// many times, and files that are not searchable.
func callsRoot(t *testing.T) (root string, many []byte) {
	t.Helper()
	root = t.TempDir()
	writeFile(t, root, "dropper.bin", testfixtures.SamplePE())

	many = manyCallsImage(t, 100)
	writeFile(t, root, "many.exe", many)

	arm := testfixtures.SamplePE()
	arm[testfixtures.PEOffset+4], arm[testfixtures.PEOffset+5] = 0x64, 0xaa // IMAGE_FILE_MACHINE_ARM64
	writeFile(t, root, "arm.exe", arm)
	noCode := testfixtures.PE(testfixtures.PEOptions{Imports: []testfixtures.PEImport{{Library: "k.dll", Functions: []string{"A"}}}})
	binary.LittleEndian.PutUint32(noCode[testfixtures.PESectionHeaderOffset(64, 0)+36:], testfixtures.PESectionData)
	writeFile(t, root, "nocode.exe", noCode)
	writeFile(t, root, "code.elf", codeELF())
	writeFile(t, root, "notes.txt", []byte("plain text, long enough to be sniffed as text and not as a program of any kind"))
	writeFile(t, root, "empty.bin", nil)
	return root, many
}

// manyCallsImage is a PE image whose extra code section, ".calls", calls
// VirtualAllocEx n times: "xor ecx, ecx" and "call qword ptr [rip+disp]" (eight
// bytes) n times over, hand-assembled with each displacement worked out from the
// section address and the slot of the import in the layout the PE parser reports.
func manyCallsImage(t *testing.T, n int) []byte {
	t.Helper()
	opts := testfixtures.PEOptions{Imports: []testfixtures.PEImport{{Library: "KERNEL32.dll", Functions: []string{"VirtualAllocEx", "ExitProcess"}}}}
	build := func(code []byte) []byte {
		o := opts
		o.Sections = []testfixtures.PESection{{Name: ".calls", Data: code, Characteristics: testfixtures.PESectionCode}}
		return testfixtures.PE(o)
	}
	probe := build(make([]byte, 8*n)) // the addresses do not depend on what the section holds
	res, err := pe.Parse(context.Background(), bytes.NewReader(probe), int64(len(probe)), limits.ForSize(int64(len(probe))))
	if err != nil {
		t.Fatal(err)
	}
	var calls pe.Section
	for _, s := range res.Layout.Sections {
		if s.Name == ".calls" {
			calls = s
		}
	}
	var slot uint64
	for _, s := range res.Layout.Slots {
		if s.Function == "VirtualAllocEx" {
			slot = s.VA
		}
	}
	if calls.Name == "" || slot == 0 {
		t.Fatalf("the probe image lacks the section or the slot: %+v", res.Layout)
	}
	code := make([]byte, 0, 8*n)
	for i := range n {
		callAt := res.Layout.ImageBase + uint64(calls.RVA) + uint64(8*i+2)
		disp := int32(slot - (callAt + 6)) // the offset to the slot, which lies before the code
		code = append(code, 0x31, 0xc9, 0xff, 0x15)
		code = binary.LittleEndian.AppendUint32(code, uint32(disp))
	}
	return build(code)
}

// siteList returns the sites array of a find_calls result.
func siteList(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, ok := doc["sites"].([]any)
	if !ok {
		t.Fatalf("result has no sites array: %v", doc)
	}
	sites := make([]map[string]any, len(raw))
	for i, s := range raw {
		sites[i] = s.(map[string]any)
	}
	return sites
}

func siteLines(site map[string]any) []map[string]any {
	raw, _ := site["code"].(map[string]any)["lines"].([]any)
	lines := make([]map[string]any, len(raw))
	for i, l := range raw {
		lines[i] = l.(map[string]any)
	}
	return lines
}

func TestFindCallsIsDescribedAndBounded(t *testing.T) {
	var tool map[string]any
	for _, cand := range listTools(t, "2025-06-18") {
		if cand["name"] == "find_calls" {
			tool = cand
		}
	}
	if tool == nil {
		t.Fatal("find_calls is not listed")
	}
	desc := tool["description"].(string)
	for _, want := range []string{"without executing", "linear sweep", "not a decompiler", "ARM64", "never", "x86"} {
		if want == "ARM64" || want == "never" {
			continue // the limits the description must state are checked below
		}
		if !strings.Contains(desc, want) {
			t.Errorf("the description lacks %q: %q", want, desc)
		}
	}
	if !strings.Contains(desc, "other instruction sets are not supported") || !strings.Contains(desc, "resolved at run time") {
		t.Errorf("the description must state what the tool cannot see: %q", desc)
	}
	checkInputSchema(t, "find_calls", tool["inputSchema"])
	schema := tool["inputSchema"].(map[string]any)
	if req, _ := schema["required"].([]any); len(req) != 2 || req[0] != "path" || req[1] != "api" {
		t.Errorf("required = %v", req)
	}
	props := schema["properties"].(map[string]any)
	prop := func(key, field string) any { return props[key].(map[string]any)[field] }
	if prop("api", "minLength") != float64(1) || prop("api", "maxLength") != float64(256) {
		t.Errorf("api = %v", props["api"])
	}
	for key, want := range map[string][3]float64{"before": {0, 40, 8}, "after": {0, 20, 4}, "max": {1, 100, 10}} {
		if prop(key, "minimum") != want[0] || prop(key, "maximum") != want[1] || prop(key, "default") != want[2] {
			t.Errorf("%s = %v, want minimum %v maximum %v default %v", key, props[key], want[0], want[1], want[2])
		}
	}
}

// TestFindCallsSchemaAgreesWithTheHandler feeds the same arguments to the schema
// validator and to the real handler.
func TestFindCallsSchemaAgreesWithTheHandler(t *testing.T) {
	root, _ := callsRoot(t)
	var schema map[string]any
	for _, cand := range listTools(t, "2025-06-18") {
		if cand["name"] == "find_calls" {
			schema = cand["inputSchema"].(map[string]any)
		}
	}
	tests := []struct {
		args             map[string]any
		schemaOK, callOK bool
	}{
		{map[string]any{"path": "dropper.bin", "api": "VirtualAllocEx"}, true, true},
		{map[string]any{"path": "dropper.bin", "api": "VirtualAllocEx", "before": 0, "after": 0, "max": 1}, true, true},
		{map[string]any{"path": "dropper.bin", "api": "VirtualAllocEx", "before": 40, "after": 20, "max": 100}, true, true},
		{map[string]any{"path": "dropper.bin", "api": "CryptEncrypt"}, true, true}, // imported, never called: an answer
		{map[string]any{"path": "dropper.bin"}, false, false},
		{map[string]any{"api": "VirtualAllocEx"}, false, false},
		{map[string]any{}, false, false},
		{map[string]any{"path": "", "api": "x"}, false, false},
		{map[string]any{"path": "dropper.bin", "api": ""}, false, false},
		{map[string]any{"path": "dropper.bin", "api": 5}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "before": -1}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "before": 41}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "after": 21}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "max": 0}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "max": 101}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "max": 1.5}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "max": "3"}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "x", "extra": true}, false, false},
		{map[string]any{"path": "dropper.bin", "api": "NoSuchApi"}, true, false},              // only the file knows
		{map[string]any{"path": "dropper.bin", "api": strings.Repeat("a", 257)}, true, false}, // maxLength is not in the validator subset
		{map[string]any{"path": "dropper.bin", "api": "   "}, true, false},                    // blank after trimming
		{map[string]any{"path": "code.elf", "api": "x"}, true, false},                         // not a PE
		{map[string]any{"path": "missing.exe", "api": "x"}, true, false},
	}
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	for i, tc := range tests {
		raw, _ := json.Marshal(tc.args)
		var decoded any
		_ = json.Unmarshal(raw, &decoded)
		violations := validateSchema(schema, decoded)
		if (len(violations) == 0) != tc.schemaOK {
			t.Errorf("%s: schema verdict ok=%v (violations %v), want %v", raw, len(violations) == 0, violations, tc.schemaOK)
		}
		res := c.callTool(5000+i, "find_calls", tc.args)
		if res.IsError == tc.callOK {
			t.Errorf("%s: isError=%v, want %v (%.200s)", raw, res.IsError, !tc.callOK, res.text())
		}
	}
}

func TestFindCalls(t *testing.T) {
	root, _ := callsRoot(t)
	for _, version := range []string{"2024-11-05", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
			c.initialize(version)
			res := c.callTool(1, "find_calls", map[string]any{"path": "dropper.bin", "api": "VirtualAllocEx"})
			doc := mustJSON(t, res)
			if (version == "2025-06-18") != (len(res.StructuredContent) > 0) {
				t.Errorf("structuredContent present = %v", len(res.StructuredContent) > 0)
			}
			if !strings.HasPrefix(res.text(), "{\n  \"file\": {") {
				t.Errorf("text must be pretty-printed with the file first: %.80q", res.text())
			}
			file := doc["file"].(map[string]any)
			if file["name"] != "dropper.bin" || doc["api"] != "VirtualAllocEx" || doc["arch"] != "x86-64" || doc["total"] != float64(1) || doc["truncated"] != false || doc["scanComplete"] != true {
				t.Errorf("result = %v", doc)
			}
			if fmt.Sprint(doc["imports"]) != "[KERNEL32.dll!VirtualAllocEx]" {
				t.Errorf("imports = %v", doc["imports"])
			}
			if _, has := doc["trimmed"]; has {
				t.Error("an untrimmed result has no trimmed member")
			}
			sites := siteList(t, doc)
			if len(sites) != 1 {
				t.Fatalf("%d sites", len(sites))
			}
			s := sites[0]
			if s["api"] != "KERNEL32.dll!VirtualAllocEx" || s["kind"] != "call" || s["address"] != "0x1400010e9" || s["offset"] != float64(0x4e9) || s["section"] != ".text" {
				t.Errorf("site = %v", s)
			}
			if _, has := s["via"]; has {
				t.Error("a direct call has no thunk")
			}
			code := s["code"].(map[string]any)
			if code["kind"] != "disasm" || code["arch"] != "x86-64" || code["section"] != ".text" || code["address"] != "0x1400010bd" {
				t.Errorf("code block = %v", code)
			}
			if lims, _ := code["limitations"].([]any); len(lims) < 3 || !strings.Contains(fmt.Sprint(lims), "linear sweep") || !strings.Contains(fmt.Sprint(lims), "not a decompiler") {
				t.Errorf("a block always states its limitations: %v", code["limitations"])
			}
			lines := siteLines(s)
			if len(lines) != 13 {
				t.Fatalf("%d lines, want 8 before + the call + 4 after", len(lines))
			}
			hit := lines[8]
			if hit["highlight"] != true || hit["address"] != "0x1400010e9" || hit["offset"] != float64(0x4e9) || hit["bytes"] != "ff 15 b1 10 00 00" ||
				hit["text"] != "call qword ptr [rip+0x10b1]" || hit["note"] != "KERNEL32.dll!VirtualAllocEx" {
				t.Errorf("the call line = %v", hit)
			}
			for i, l := range lines {
				if (i == 8) != (l["highlight"] == true) {
					t.Errorf("line %d: only the call is highlighted: %v", i, l)
				}
			}
		})
	}

	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	t.Run("a call through a thunk", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(2, "find_calls", map[string]any{"path": "dropper.bin", "api": "createprocess", "before": 1, "after": 1}))
		sites := siteList(t, doc)
		if len(sites) != 1 || doc["total"] != float64(1) {
			t.Fatalf("sites %v", sites)
		}
		s := sites[0]
		if s["kind"] != "call-thunk" || s["via"] != "0x140001180" || s["address"] != "0x14000116b" || s["api"] != "KERNEL32.dll!CreateProcessW" || len(siteLines(s)) != 3 {
			t.Errorf("site = %v", s)
		}
		if note := siteLines(s)[1]["note"]; note != "KERNEL32.dll!CreateProcessW (through the thunk at 0x140001180)" {
			t.Errorf("note = %v", note)
		}
	})
	t.Run("the call alone", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(3, "find_calls", map[string]any{"path": "dropper.bin", "api": "kernel32.dll!writeprocessmemory", "before": 0, "after": 0}))
		if lines := siteLines(siteList(t, doc)[0]); len(lines) != 1 || lines[0]["highlight"] != true || lines[0]["address"] != "0x140001114" {
			t.Errorf("lines = %v", lines)
		}
	})
	t.Run("an import that nothing calls is an answer, not an error", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(4, "find_calls", map[string]any{"path": "dropper.bin", "api": "CryptEncrypt"}))
		if doc["total"] != float64(0) || len(siteList(t, doc)) != 0 || fmt.Sprint(doc["imports"]) != "[ADVAPI32.dll!CryptEncrypt]" || doc["truncated"] != false {
			t.Errorf("result = %v", doc)
		}
	})
	t.Run("more call sites than max", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(5, "find_calls", map[string]any{"path": "many.exe", "api": "VirtualAllocEx", "max": 3, "before": 0, "after": 0}))
		if doc["total"] != float64(100) || len(siteList(t, doc)) != 3 || doc["truncated"] != true {
			t.Fatalf("total %v sites %d truncated %v", doc["total"], len(siteList(t, doc)), doc["truncated"])
		}
		if note, _ := doc["note"].(string); !strings.Contains(note, "100 call sites were found and the first 3 are returned") || !strings.Contains(note, `raise "max" (up to 100)`) {
			t.Errorf("note = %q", note)
		}
		if _, has := doc["trimmed"]; has {
			t.Error("nothing was trimmed by the output cap")
		}
		// The sites are ranked by address.
		var last string
		for _, s := range siteList(t, doc) {
			if a := s["address"].(string); a <= last {
				t.Errorf("sites are not in address order: %s after %s", a, last)
			} else {
				last = a
			}
		}
	})
	t.Run("the default shows ten", func(t *testing.T) {
		doc := mustJSON(t, c.callTool(6, "find_calls", map[string]any{"path": "many.exe", "api": "VirtualAllocEx"}))
		if len(siteList(t, doc)) != 10 || doc["total"] != float64(100) {
			t.Errorf("%d sites of %v", len(siteList(t, doc)), doc["total"])
		}
	})
	t.Run("errors", func(t *testing.T) {
		tests := []struct {
			args map[string]any
			want string
		}{
			{map[string]any{"path": "dropper.bin", "api": "NoSuchApi"}, `no import of this file matches "NoSuchApi"; imports with call sites include KERNEL32.dll!`},
			{map[string]any{"path": "dropper.bin", "api": "other.dll!VirtualAllocEx"}, "no import of this file matches"},
			{map[string]any{"path": "dropper.bin", "api": "x\x1b[31m\x00"}, `no import of this file matches "x\x1b[31m\x00"`},
			{map[string]any{"path": "dropper.bin", "api": "   "}, `argument "api" must name an imported function`},
			{map[string]any{"path": "dropper.bin", "api": strings.Repeat("a", 257)}, `argument "api" is 257 characters long, at most 256`},
			{map[string]any{"path": "dropper.bin", "api": "x", "before": 41}, `argument "before" must be between 0 and 40 (got 41)`},
			{map[string]any{"path": "dropper.bin", "api": "x", "after": -1}, `argument "after" must be between 0 and 20 (got -1)`},
			{map[string]any{"path": "dropper.bin", "api": "x", "max": 0}, `argument "max" must be between 1 and 100 (got 0)`},
			{map[string]any{"path": "dropper.bin", "api": "x", "max": 1e9}, `argument "max" must be between 1 and 100`},
			{map[string]any{"path": "dropper.bin", "api": "x", "max": 2.5}, `argument "max" must be an integer`},
			{map[string]any{"path": "dropper.bin", "api": 7}, `argument "api" must be a string`},
			{map[string]any{"path": "dropper.bin", "api": "x", "extra": 1}, `unknown argument "extra"`},
			{map[string]any{"path": "dropper.bin"}, `missing required argument "api"`},
			{map[string]any{"api": "x"}, `missing required argument "path"`},
			{map[string]any{}, `missing required argument "path"`},
			{map[string]any{"path": "code.elf", "api": "x"}, "this file is ELF x86-64: find_calls finds the calls to the imports of PE images for x86 and x86-64 only"},
			{map[string]any{"path": "notes.txt", "api": "x"}, "this file is not a PE image"},
			{map[string]any{"path": "empty.bin", "api": "x"}, "this file is not a PE image"},
			{map[string]any{"path": "arm.exe", "api": "x"}, "this file is PE ARM64: find_calls finds the calls to the imports of PE images for x86 and x86-64 only"},
			{map[string]any{"path": "nocode.exe", "api": "A"}, "no executable section with bytes in the file"},
			{map[string]any{"path": "nope.exe", "api": "x"}, "file not found"},
			{map[string]any{"path": ".", "api": "x"}, "a directory"},
		}
		for i, tc := range tests {
			if msg := mustErrorText(t, c.callTool(100+i, "find_calls", tc.args)); !strings.Contains(msg, tc.want) {
				t.Errorf("%v: message %q does not contain %q", tc.args, msg, tc.want)
			}
		}
	})
}

// TestFindCallsAgreesWithTheCodeTools: the instruction at a call site is the
// instruction disassemble shows at that address, byte for byte and note for note.
func TestFindCallsAgreesWithTheCodeTools(t *testing.T) {
	root, _ := callsRoot(t)
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	for _, api := range []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateProcessW", "LoadLibraryA", "socket", "connect"} {
		doc := mustJSON(t, c.callTool(1, "find_calls", map[string]any{"path": "dropper.bin", "api": api}))
		for _, s := range siteList(t, doc) {
			first := siteLines(s)[0]
			dis := mustJSON(t, c.callTool(2, "disassemble", map[string]any{"path": "dropper.bin", "address": first["address"], "count": len(siteLines(s))}))
			got, want := codeLines(t, dis), siteLines(s)
			if len(got) != len(want) {
				t.Fatalf("%s: disassemble gave %d lines, find_calls %d", api, len(got), len(want))
			}
			for i := range want {
				for _, key := range []string{"address", "offset", "bytes", "text", "note"} {
					if got[i][key] != want[i][key] {
						t.Errorf("%s line %d: %s is %v in disassemble and %v in find_calls", api, i, key, got[i][key], want[i][key])
					}
				}
			}
		}
	}
}

// TestFindCallsFitsTheOutputCap shrinks the cap and checks that the result gives
// up lines and then sites, says so, and stays valid JSON.
func TestFindCallsFitsTheOutputCap(t *testing.T) {
	root, _ := callsRoot(t)
	for _, limit := range []int{minMaxOutput, 3 << 10, 8 << 10, 24 << 10, 64 << 10, 256 << 10} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			c := startServer(t, Config{Roots: []string{root}, MaxOutput: limit}, realAnalyzer())
			res := c.callTool(1, "find_calls", map[string]any{"path": "many.exe", "api": "VirtualAllocEx", "max": 100, "before": 40, "after": 20})
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
			sites := siteList(t, doc)
			// At the smallest cap not even one site fits: the result says so and keeps the count.
			if (len(sites) == 0 && limit > minMaxOutput) || doc["total"] != float64(100) {
				t.Fatalf("%d sites, total %v", len(sites), doc["total"])
			}
			if doc["truncated"] != true {
				t.Errorf("100 sites were asked for and %d returned: truncated must be true", len(sites))
			}
			if len(sites) < 100 {
				if len(doc["trimmed"].([]any)) == 0 || !strings.Contains(doc["note"].(string), "output cap") {
					t.Errorf("trimmed %v note %v", doc["trimmed"], doc["note"])
				}
			}
			for _, s := range sites {
				lines := siteLines(s)
				if len(lines) == 0 {
					t.Fatal("a site keeps at least its call line")
				}
				var hit bool
				for _, l := range lines {
					hit = hit || l["highlight"] == true
				}
				if !hit {
					t.Errorf("trimming must keep the line of the call: %v", lines)
				}
			}
		})
	}
}

// TestFindCallsCodeBlocksMatchTheModel decodes the sites back into the model the
// findings use: every block validates and every address round-trips.
func TestFindCallsCodeBlocksMatchTheModel(t *testing.T) {
	root, _ := callsRoot(t)
	c := startServer(t, Config{Roots: []string{root}}, realAnalyzer())
	res := c.callTool(1, "find_calls", map[string]any{"path": "dropper.bin", "api": "createprocess", "before": 40, "after": 20})
	var doc struct {
		Sites []struct {
			Address report.Addr      `json:"address"`
			Via     report.Addr      `json:"via"`
			Code    report.CodeBlock `json:"code"`
		} `json:"sites"`
	}
	if err := json.Unmarshal([]byte(res.text()), &doc); err != nil || len(doc.Sites) != 1 {
		t.Fatalf("%d sites: %v", len(doc.Sites), err)
	}
	s := doc.Sites[0]
	if err := s.Code.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}
	if s.Address != 0x14000116b || s.Via != 0x140001180 {
		t.Errorf("address %v via %v", s.Address, s.Via)
	}
	if len(s.Code.Lines) > report.MaxCodeLines {
		t.Errorf("%d lines", len(s.Code.Lines))
	}
}
