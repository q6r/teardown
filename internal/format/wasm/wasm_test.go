package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// uleb encodes v as unsigned LEB128.
func uleb(v uint64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

func str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

// section frames a payload with an id and a LEB128 size.
func section(id byte, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	return append(append([]byte{id}, uleb(uint64(len(body)))...), body...)
}

// module concatenates the 8-byte header and the sections.
func module(sections ...[]byte) []byte {
	return append([]byte("\x00asm\x01\x00\x00\x00"), bytes.Join(sections, nil)...)
}

func parse(t testing.TB, data []byte, lim limits.Limits) *Result {
	t.Helper()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	checkResult(t, res, int64(len(data)))
	return res
}

// checkResult asserts the invariants every Result must satisfy, whatever the input.
func checkResult(t testing.TB, res *Result, size int64) {
	t.Helper()
	clean := func(what, s string) {
		if !utf8.ValidString(s) {
			t.Fatalf("%s %q is not valid UTF-8", what, s)
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Fatalf("%s %q contains the control character %U", what, s, r)
			}
		}
	}
	if res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Notes == nil {
		t.Fatal("slices in Result must never be nil")
	}
	for _, s := range res.Sections {
		clean("section name", s.Name)
		if s.Name == "" || s.Flags == nil || s.Entropy < 0 || s.Entropy > 8 {
			t.Fatalf("bad section %+v", s)
		}
		if s.Offset+s.RawSize > uint64(size) {
			t.Fatalf("section %+v lies outside the %d-byte file", s, size)
		}
	}
	for _, imp := range res.Imports {
		clean("import module", imp.Library)
		if imp.Functions == nil || imp.Count < len(imp.Functions) {
			t.Fatalf("bad import %+v", imp)
		}
		for _, f := range imp.Functions {
			clean("import", f)
		}
	}
	for _, e := range res.Exports {
		clean("export", e)
	}
	for _, n := range res.Notes {
		clean("note", n)
	}
	d := res.Details
	if d.Memories == nil || d.CustomSections == nil || d.Producers == nil || d.Features == nil {
		t.Fatal("slices in Details must never be nil")
	}
	if d.Start < -1 || d.SectionCount < 0 || d.ImportCount < 0 || d.ExportCount < 0 || d.FunctionCount < 0 {
		t.Fatalf("negative count in %+v", d)
	}
	if d.Kind != kindModule && d.Kind != kindComponent {
		t.Fatalf("Kind = %q", d.Kind)
	}
	for _, s := range d.CustomSections {
		clean("custom section", s)
	}
	for _, p := range d.Producers {
		clean("producer", p.Field+p.Name+p.Version)
	}
	for _, f := range d.Features {
		clean("feature", f)
	}
	if _, err := json.Marshal(res.Details); err != nil {
		t.Fatalf("Details does not marshal: %v", err)
	}
}

func hasNote(res *Result, substr string) bool {
	return slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, substr) })
}

func u64p(v uint64) *uint64 { return &v }

func TestParseSample(t *testing.T) {
	data := testfixtures.WasmSample()
	res := parse(t, data, limits.Limits{})

	wantNames := []string{"type", "import", "function", "memory", "export", "code", "data",
		"custom:name", "custom:producers", "custom:target_features"}
	var gotNames []string
	next := int64(8) // sections tile the file: each header starts where the last payload ended
	for _, s := range res.Sections {
		gotNames = append(gotNames, s.Name)
		wantOff := next + 1 + int64(len(uleb(s.RawSize)))
		if int64(s.Offset) != wantOff {
			t.Errorf("section %s offset = %d, want %d", s.Name, s.Offset, wantOff)
		}
		next = int64(s.Offset + s.RawSize)
		if s.VirtualSize != 0 {
			t.Errorf("section %s VirtualSize = %d, want 0", s.Name, s.VirtualSize)
		}
		wantFlags := []string{}
		if s.Name == "code" {
			wantFlags = []string{report.FlagX}
		}
		if !slices.Equal(s.Flags, wantFlags) {
			t.Errorf("section %s flags = %v, want %v", s.Name, s.Flags, wantFlags)
		}
	}
	if next != int64(len(data)) {
		t.Errorf("sections end at %d, file is %d bytes", next, len(data))
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("sections = %v, want %v", gotNames, wantNames)
	}

	wantImports := []report.Import{{Library: "env", Count: 1, Functions: []string{"func puts"}}}
	if !reflect.DeepEqual(res.Imports, wantImports) {
		t.Errorf("imports = %+v, want %+v", res.Imports, wantImports)
	}
	if want := []string{"func main", "memory memory"}; !slices.Equal(res.Exports, want) {
		t.Errorf("exports = %v, want %v", res.Exports, want)
	}
	want := Details{
		Kind: "module", Version: 1, SectionCount: 10, TypeCount: 2, FunctionCount: 1, ImportCount: 1, ExportCount: 2,
		Memories: []Memory{{Min: 1, Max: u64p(2)}}, Start: -1, DataSegments: 1,
		CustomSections: []string{"name", "producers", "target_features"}, HasNameSection: true,
		Producers: []Producer{{Field: "language", Name: "C11"}, {Field: "processed-by", Name: "clang", Version: "17.0.0"}},
		Features:  []string{"+bulk-memory", "+simd128"},
	}
	if !reflect.DeepEqual(res.Details, want) {
		t.Errorf("details = %+v\nwant      %+v", res.Details, want)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a clean module must have no notes, got %v", res.Notes)
	}
}

func TestDetailsJSONContract(t *testing.T) {
	res := parse(t, testfixtures.WasmSample(), limits.Limits{})
	raw, err := json.Marshal(res.Details)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{"customSections", "dataSegments", "elementSegments", "exportCount", "features", "functionCount",
		"globals", "hasNameSection", "importCount", "kind", "memories", "producers", "sectionCount", "start", "tables",
		"typeCount", "version"}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("Details keys:\n got %v\nwant %v", got, want)
	}
	mem := m["memories"].([]any)[0].(map[string]any)
	if mem["min"] != float64(1) || mem["max"] != float64(2) || mem["shared"] != false || mem["memory64"] != false {
		t.Errorf("memory = %v", mem)
	}
	unbounded := parse(t, testfixtures.Wasm(testfixtures.WasmOptions{Memories: []testfixtures.WasmMemoryType{{Min: 3}}}), limits.Limits{})
	raw, _ = json.Marshal(unbounded.Details.Memories)
	if string(raw) != `[{"min":3,"max":null,"shared":false,"memory64":false}]` {
		t.Errorf("unbounded memory encodes as %s", raw)
	}
}

func TestParseEmptyModule(t *testing.T) {
	res := parse(t, testfixtures.Wasm(testfixtures.WasmOptions{}), limits.Limits{})
	if len(res.Sections) != 0 || len(res.Notes) != 0 || res.Details.Start != -1 || res.Details.SectionCount != 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestParseEveryKind(t *testing.T) {
	two := uint32(2)
	data := testfixtures.Wasm(testfixtures.WasmOptions{
		Types: []testfixtures.WasmFuncType{{Params: []byte{testfixtures.WasmI32}}},
		Imports: []testfixtures.WasmImport{
			{Module: "env", Name: "log", Kind: testfixtures.WasmKindFunc},
			{Module: "env", Name: "mem", Kind: testfixtures.WasmKindMemory, Limits: testfixtures.WasmMemoryType{Min: 2, Max: 8, HasMax: true, Shared: true}},
			{Module: "env", Name: "table", Kind: testfixtures.WasmKindTable, Limits: testfixtures.WasmMemoryType{Min: 4}},
			{Module: "wasi_snapshot_preview1", Name: "fd_write", Kind: testfixtures.WasmKindFunc},
			{Module: "env", Name: "sp", Kind: testfixtures.WasmKindGlobal, ValType: testfixtures.WasmI64, Mutable: true},
			{Module: "env", Name: "exc", Kind: testfixtures.WasmKindTag},
		},
		Functions: []uint32{0, 0},
		Tables:    2,
		Memories:  []testfixtures.WasmMemoryType{{Min: 1 << 20, Memory64: true}},
		Globals:   3,
		Exports:   []testfixtures.WasmExport{{Name: "table", Kind: testfixtures.WasmKindTable}, {Name: "g", Kind: testfixtures.WasmKindGlobal}, {Name: "t", Kind: testfixtures.WasmKindTag}},
		Start:     &two,
		Data:      [][]byte{[]byte("a"), []byte("bc")},
		DataCount: true,
		Custom:    []testfixtures.WasmCustom{{Name: ".debug_info", Data: []byte{1, 2, 3}}},
	})
	res := parse(t, data, limits.Limits{})

	wantImports := []report.Import{
		{Library: "env", Count: 5, Functions: []string{"func log", "memory mem", "table table", "global sp", "tag exc"}},
		{Library: "wasi_snapshot_preview1", Count: 1, Functions: []string{"func fd_write"}},
	}
	if !reflect.DeepEqual(res.Imports, wantImports) {
		t.Errorf("imports = %+v\nwant      %+v", res.Imports, wantImports)
	}
	if want := []string{"table table", "global g", "tag t"}; !slices.Equal(res.Exports, want) {
		t.Errorf("exports = %v, want %v", res.Exports, want)
	}
	d := res.Details
	if d.ImportCount != 6 || d.ExportCount != 3 || d.FunctionCount != 2 || d.Tables != 3 || d.Globals != 4 ||
		d.Start != 2 || d.DataSegments != 2 || d.TypeCount != 1 {
		t.Errorf("details = %+v", d)
	}
	wantMems := []Memory{{Min: 2, Max: u64p(8), Shared: true}, {Min: 1 << 20, Memory64: true}}
	if !reflect.DeepEqual(d.Memories, wantMems) {
		t.Errorf("memories = %+v, want %+v", d.Memories, wantMems)
	}
	if want := []string{".debug_info"}; !slices.Equal(d.CustomSections, want) {
		t.Errorf("custom sections = %v", d.CustomSections)
	}
	if d.HasNameSection {
		t.Error("no name section was written")
	}
	if len(res.Notes) != 0 {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantErr  string // when set Parse must fail with this text
		wantNote string
		check    func(t *testing.T, res *Result)
	}{
		{name: "empty file", data: nil, wantErr: "shorter than the 8-byte header"},
		{name: "seven bytes", data: []byte("\x00asm\x01\x00\x00"), wantErr: "shorter than the 8-byte header"},
		{name: "wrong magic", data: []byte("\x7fELF\x02\x01\x01\x00\x00\x00"), wantErr: `\0asm`},
		{
			name: "unknown version", data: []byte("\x00asm\x02\x00\x00\x00"), wantNote: "unsupported binary version 2",
			check: func(t *testing.T, res *Result) {
				if res.Details.Version != 2 || res.Details.Kind != kindModule {
					t.Errorf("details = %+v", res.Details)
				}
			},
		},
		{
			name: "section runs past the end", data: append(module(), 0x01, 100, 0xaa, 0xbb, 0xcc), wantNote: "declares 100 bytes but only 3 remain",
			check: func(t *testing.T, res *Result) {
				if len(res.Sections) != 1 || res.Sections[0].RawSize != 3 {
					t.Errorf("sections = %+v", res.Sections)
				}
			},
		},
		{name: "section id without a size", data: append(module(), 0x01), wantNote: "truncated section header"},
		{name: "malformed size", data: append(module(), 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), wantNote: "malformed size"},
		{name: "oversized size", data: append(module(), 0x01, 0xff, 0xff, 0xff, 0xff, 0x1f), wantNote: "malformed size"},
		{name: "sections out of order", data: module(section(7, uleb(0)), section(1, uleb(0))), wantNote: "type section at offset"},
		{name: "repeated section", data: module(section(3, uleb(0)), section(3, uleb(0))), wantNote: "repeated"},
		{name: "unknown section id", data: module(section(99)), wantNote: "unknown section id 99"},
		{
			name: "unknown import kind", data: module(section(2, uleb(1), str("m"), str("f"), []byte{9, 0})),
			wantNote: "import section is malformed after 0 imports",
			check: func(t *testing.T, res *Result) {
				if len(res.Imports) != 0 || res.Details.ImportCount != 0 {
					t.Errorf("imports = %+v", res.Imports)
				}
			},
		},
		{
			name: "import count larger than the data", data: module(section(2, uleb(100), str("m"), str("f"), []byte{0, 0})),
			wantNote: "malformed after 1 imports",
			check: func(t *testing.T, res *Result) {
				if len(res.Imports) != 1 || res.Details.ImportCount != 1 {
					t.Errorf("imports = %+v", res.Imports)
				}
			},
		},
		{name: "huge vector count", data: module(section(3, []byte{0xff, 0xff, 0xff, 0xff, 0x0f})), wantNote: "count is ignored"},
		{name: "empty function section", data: module(section(3)), wantNote: "does not start with a valid integer"},
		{
			name: "function and code counts disagree", data: module(section(3, uleb(2), []byte{0, 0}), section(10, uleb(1), []byte{2, 0, 0x0b})),
			wantNote: "declares 2 functions but the code section has 1 bodies",
		},
		{name: "functions without code", data: module(section(3, uleb(1), []byte{0})), wantNote: "no code section"},
		{name: "code without functions", data: module(section(10, uleb(1), []byte{2, 0, 0x0b})), wantNote: "no function section"},
		{
			name: "datacount disagrees", data: module(section(12, uleb(3)), section(11, uleb(1), []byte{0, 0x41, 0, 0x0b, 0})),
			wantNote: "datacount section declares 3",
		},
		{name: "empty start section", data: module(section(8)), wantNote: "start section is malformed"},
		{name: "invalid memory limits", data: module(section(5, uleb(1), []byte{0x30, 0x01})), wantNote: "memory section is malformed"},
		{
			name: "custom section name longer than the section", data: module(section(0, []byte{0xff, 0x01, 'a'})),
			check: func(t *testing.T, res *Result) {
				if len(res.Sections) != 1 || res.Sections[0].Name != "custom:?" {
					t.Errorf("sections = %+v", res.Sections)
				}
			},
		},
		{name: "malformed producers", data: module(section(0, str("producers"), uleb(5), str("language"))), wantNote: "producers section is malformed"},
		{name: "malformed target_features", data: module(section(0, str("target_features"), uleb(2), []byte{'+'}, str("simd128"))),
			wantNote: "target_features section is malformed"},
		{
			name: "control characters in names", data: module(section(7, uleb(1), str("\x1b[31mred"), []byte{0, 0})),
			check: func(t *testing.T, res *Result) {
				if len(res.Exports) != 1 || res.Exports[0] != `func \x1b[31mred` {
					t.Errorf("exports = %q", res.Exports)
				}
			},
		},
		{
			name: "feature with an unexpected prefix", data: module(section(0, str("target_features"), uleb(1), []byte{'!'}, str("x"))),
			check: func(t *testing.T, res *Result) {
				if !slices.Equal(res.Details.Features, []string{"?x"}) {
					t.Errorf("features = %v", res.Details.Features)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse(context.Background(), bytes.NewReader(tc.data), int64(len(tc.data)), limits.Limits{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || res != nil {
					t.Fatalf("got %v, %v; want an error containing %q and no result", res, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			checkResult(t, res, int64(len(tc.data)))
			if tc.wantNote != "" && !hasNote(res, tc.wantNote) {
				t.Errorf("notes %q lack %q", res.Notes, tc.wantNote)
			}
			if tc.check != nil {
				tc.check(t, res)
			}
		})
	}
}

func TestParseComponent(t *testing.T) {
	data := append([]byte("\x00asm\x0d\x00\x01\x00"), bytes.Join([][]byte{
		section(1, []byte{0, 0}), section(7, uleb(0)), section(0, str("x"), []byte{9}), section(10, uleb(0)),
	}, nil)...)
	res := parse(t, data, limits.Limits{})
	d := res.Details
	if d.Kind != kindComponent || d.Version != 13 || d.Layer != 1 || d.SectionCount != 4 {
		t.Fatalf("details = %+v", d)
	}
	var names []string
	for _, s := range res.Sections {
		names = append(names, s.Name)
		if len(s.Flags) != 0 {
			t.Errorf("section %s must not carry flags in a component", s.Name)
		}
	}
	if want := []string{"core:module", "type", "custom:x", "import"}; !slices.Equal(names, want) {
		t.Errorf("sections = %v, want %v", names, want)
	}
	if !hasNote(res, "component") || len(res.Imports) != 0 || len(res.Exports) != 0 {
		t.Errorf("notes %v, imports %v, exports %v", res.Notes, res.Imports, res.Exports)
	}
}

func TestParseHonoursLimits(t *testing.T) {
	var entries [][]byte
	for i := range 6 {
		entries = append(entries, str(fmt.Sprintf("m%d", i)), str("f"), []byte{0, 0})
	}
	entries = append(entries, str("m0"), str("g"), []byte{0, 0}) // a second import from m0
	var exports [][]byte
	for i := range 7 {
		exports = append(exports, str(fmt.Sprintf("e%d", i)), []byte{0, 0})
	}
	data := module(
		section(2, uleb(7), bytes.Join(entries, nil)),
		section(7, uleb(7), bytes.Join(exports, nil)),
		section(0, str("a")), section(0, str("b")),
	)

	t.Run("lists are capped and counts stay true", func(t *testing.T) {
		res := parse(t, data, limits.Limits{MaxList: 5})
		if len(res.Imports) != 5 || res.Details.ImportCount != 7 {
			t.Errorf("imports = %d modules, ImportCount = %d", len(res.Imports), res.Details.ImportCount)
		}
		if res.Imports[0].Library != "m0" || res.Imports[0].Count != 2 {
			t.Errorf("first import = %+v", res.Imports[0])
		}
		if len(res.Exports) != 5 || res.Details.ExportCount != 7 {
			t.Errorf("exports = %d, ExportCount = %d", len(res.Exports), res.Details.ExportCount)
		}
		if !hasNote(res, "list of modules is capped") {
			t.Errorf("notes = %v", res.Notes)
		}
	})
	t.Run("sections are capped", func(t *testing.T) {
		res := parse(t, data, limits.Limits{MaxList: 3})
		if len(res.Sections) != 3 || res.Details.SectionCount != 3 || !hasNote(res, "stopped after 3 sections") {
			t.Errorf("sections = %d, SectionCount = %d, notes = %v", len(res.Sections), res.Details.SectionCount, res.Notes)
		}
	})
	t.Run("metadata limit", func(t *testing.T) {
		res := parse(t, data, limits.Limits{MaxMeta: 24})
		if !hasNote(res, "metadata limit") {
			t.Errorf("notes = %v", res.Notes)
		}
	})
}

func TestParseStopsWhenContextEnds(t *testing.T) {
	data := testfixtures.WasmSample()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil || res.Details.Kind != kindModule {
		t.Fatalf("a partial result is expected, got %+v", res)
	}
	checkResult(t, res, int64(len(data)))
}

func TestParseCapsNotes(t *testing.T) {
	var sections [][]byte
	for range 100 {
		sections = append(sections, section(99)) // each unknown id yields a note
	}
	res := parse(t, module(sections...), limits.Limits{})
	if len(res.Notes) != maxNotes+1 || !strings.Contains(res.Notes[maxNotes], "60 further notes omitted") {
		t.Fatalf("notes = %d, last = %q", len(res.Notes), res.Notes[len(res.Notes)-1])
	}
}

func TestSectionEntropy(t *testing.T) {
	noise := make([]byte, 4096)
	rand.New(rand.NewSource(1)).Read(noise)
	data := testfixtures.Wasm(testfixtures.WasmOptions{Custom: []testfixtures.WasmCustom{
		{Name: "noise", Data: noise},
		{Name: "zeros", Data: make([]byte, 4096)},
	}})
	res := parse(t, data, limits.Limits{})
	if len(res.Sections) != 2 {
		t.Fatalf("sections = %+v", res.Sections)
	}
	if e := res.Sections[0].Entropy; e < 7.5 {
		t.Errorf("entropy of random data = %v, want > 7.5", e)
	}
	if e := res.Sections[1].Entropy; e > 0.1 {
		t.Errorf("entropy of zeros = %v, want ~0", e)
	}
}

func TestParseIsDeterministic(t *testing.T) {
	data := testfixtures.WasmSample()
	a, b := parse(t, data, limits.Limits{}), parse(t, data, limits.Limits{})
	if !reflect.DeepEqual(a, b) {
		t.Fatal("two parses of the same bytes differ")
	}
}

// robustnessInputs are the modules the sweeps start from.
func robustnessInputs() map[string][]byte {
	two := uint32(2)
	return map[string][]byte{
		"sample": testfixtures.WasmSample(),
		"every kind": testfixtures.Wasm(testfixtures.WasmOptions{
			Types: []testfixtures.WasmFuncType{{Params: []byte{testfixtures.WasmI32}, Results: []byte{testfixtures.WasmF64}}},
			Imports: []testfixtures.WasmImport{
				{Module: "env", Name: "f", Kind: testfixtures.WasmKindFunc},
				{Module: "env", Name: "m", Kind: testfixtures.WasmKindMemory, Limits: testfixtures.WasmMemoryType{Min: 1, Max: 2, HasMax: true}},
				{Module: "env", Name: "t", Kind: testfixtures.WasmKindTable, Limits: testfixtures.WasmMemoryType{Min: 1}},
				{Module: "env", Name: "g", Kind: testfixtures.WasmKindGlobal, ValType: testfixtures.WasmI32},
				{Module: "env", Name: "x", Kind: testfixtures.WasmKindTag},
			},
			Functions: []uint32{0}, Tables: 1, Globals: 1, Start: &two, Data: [][]byte{{1, 2, 3}}, DataCount: true,
			Memories: []testfixtures.WasmMemoryType{{Min: 1, Memory64: true}},
			Exports:  []testfixtures.WasmExport{{Name: "e", Kind: testfixtures.WasmKindFunc, Index: 1}},
			Custom:   []testfixtures.WasmCustom{{Name: "x", Data: []byte{9}}},
		}),
		"component": []byte("\x00asm\x0d\x00\x01\x00\x01\x02\x00\x00\x07\x01\x00"),
		"malformed": module(section(2, uleb(3), str("m"), str("f"), []byte{9, 0}), section(1, uleb(0))),
	}
}

// TestParseNeverPanics truncates every input at every length (all lengths up to
// 4 KiB, then every 97th) and overwrites each of the first 512 bytes with 0x00,
// 0xFF and 0x80. Parse must return promptly without panicking.
func TestParseNeverPanics(t *testing.T) {
	run := func(name string, data []byte) {
		t.Helper()
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if err != nil {
			if res != nil {
				t.Fatalf("%s: a result must not accompany a header error", name)
			}
			return
		}
		checkResult(t, res, int64(len(data)))
	}
	for name, data := range robustnessInputs() {
		for n := 0; n <= len(data); {
			run(fmt.Sprintf("%s truncated to %d", name, n), data[:n])
			if n < 4096 {
				n++
			} else {
				n += 97
			}
		}
		mutated := slices.Clone(data)
		for i := range min(512, len(mutated)) {
			orig := mutated[i]
			for _, v := range []byte{0x00, 0xff, 0x80} {
				mutated[i] = v
				run(fmt.Sprintf("%s byte %d = %#x", name, i, v), mutated)
			}
			mutated[i] = orig
		}
	}
}

func TestParseWithMisleadingSize(t *testing.T) {
	// A source that claims to be larger than it is must not hang or panic.
	data := testfixtures.WasmSample()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data))+1<<20, limits.Limits{})
	if err != nil && res == nil {
		t.Fatalf("unexpected error %v", err)
	}
	if res != nil {
		clean := slices.ContainsFunc(res.Sections, func(s report.Section) bool { return s.Name == "type" })
		if !clean {
			t.Errorf("sections = %+v", res.Sections)
		}
	}
}
