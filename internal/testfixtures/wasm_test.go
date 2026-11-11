package testfixtures

import (
	"bytes"
	"context"
	"slices"
	"testing"

	wasmfmt "github.com/q6r/teardown/internal/format/wasm"
	"github.com/q6r/teardown/internal/limits"
)

func TestWasm_ZeroValueIsTheHeader(t *testing.T) {
	if got, want := Wasm(WasmOptions{}), []byte("\x00asm\x01\x00\x00\x00"); !bytes.Equal(got, want) {
		t.Fatalf("Wasm(WasmOptions{}) = % x, want % x", got, want)
	}
}

func TestWasm_ULEB(t *testing.T) {
	tests := []struct {
		in   uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{624485, []byte{0xe5, 0x8e, 0x26}},
		{1<<32 - 1, []byte{0xff, 0xff, 0xff, 0xff, 0x0f}},
	}
	for _, tc := range tests {
		if got := wasmULEB(tc.in); !bytes.Equal(got, tc.want) {
			t.Errorf("wasmULEB(%d) = % x, want % x", tc.in, got, tc.want)
		}
	}
}

// wasmReadULEB is an independent decoder used to check the builder's framing.
func wasmReadULEB(b []byte) (v uint64, n int) {
	for shift := uint(0); n < len(b) && n < 10; shift += 7 {
		c := b[n]
		n++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, n
		}
	}
	return 0, 0
}

// wasmWalk checks that the sections tile the file exactly and appear in the
// order the specification requires, and returns the section ids with the first
// LEB128 integer of each payload (the vector length for most sections).
func wasmWalk(t *testing.T, data []byte) (ids []byte, firsts []uint64) {
	t.Helper()
	rank := map[byte]int{1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8, 8: 9, 9: 10, 12: 11, 10: 12, 11: 13}
	if !bytes.HasPrefix(data, []byte("\x00asm\x01\x00\x00\x00")) {
		t.Fatalf("bad header % x", data[:min(8, len(data))])
	}
	last := 0
	for off := 8; off < len(data); {
		id := data[off]
		size, n := wasmReadULEB(data[off+1:])
		if n == 0 {
			t.Fatalf("bad section size at offset %d", off+1)
		}
		payload := off + 1 + n
		if payload+int(size) > len(data) {
			t.Fatalf("section %d at offset %d overruns the file", id, off)
		}
		if r, ok := rank[id]; ok {
			if r <= last {
				t.Fatalf("section %d at offset %d is out of order", id, off)
			}
			last = r
		} else if id != 0 {
			t.Fatalf("unknown section id %d", id)
		}
		first, _ := wasmReadULEB(data[payload : payload+int(size)])
		ids, firsts = append(ids, id), append(firsts, first)
		off = payload + int(size)
	}
	return ids, firsts
}

func TestWasm_SampleIsStructurallyValid(t *testing.T) {
	ids, firsts := wasmWalk(t, WasmSample())
	wantIDs := []byte{1, 2, 3, 5, 7, 10, 11, 0, 0, 0}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("section ids = %v, want %v", ids, wantIDs)
	}
	// Vector sizes: 2 types, 1 import, 1 function, 1 memory, 2 exports, 1 body, 1 segment.
	if want := []uint64{2, 1, 1, 1, 2, 1, 1}; !slices.Equal(firsts[:7], want) {
		t.Fatalf("vector lengths = %v, want %v", firsts[:7], want)
	}
}

func TestWasm_Deterministic(t *testing.T) {
	if !bytes.Equal(WasmSample(), WasmSample()) {
		t.Fatal("WasmSample differs between calls")
	}
}

// TestWasm_RoundTrip builds modules from options and checks that the parser in
// internal/format/wasm reads back exactly what was asked for.
func TestWasm_RoundTrip(t *testing.T) {
	zero := uint32(0)
	tests := []struct {
		name string
		opts WasmOptions
		// expected parser output
		sections, imports, importModules, exports, functions int
		tables, globals, memories, data, customs             int
		start                                                int64
		producers, features                                  int
	}{
		{name: "header only", start: -1},
		{
			name: "functions and exports",
			opts: WasmOptions{
				Types: []WasmFuncType{{}, {Params: []byte{WasmI32}}}, Functions: []uint32{0, 1, 1},
				Exports: []WasmExport{{Name: "a", Kind: WasmKindFunc}, {Name: "b", Kind: WasmKindFunc, Index: 1}},
			},
			sections: 4, exports: 2, functions: 3, start: -1,
		},
		{
			name: "imports from two modules",
			opts: WasmOptions{
				Types: []WasmFuncType{{}},
				Imports: []WasmImport{
					{Module: "a", Name: "x", Kind: WasmKindFunc}, {Module: "b", Name: "y", Kind: WasmKindFunc},
					{Module: "a", Name: "z", Kind: WasmKindGlobal, ValType: WasmF32},
				},
			},
			sections: 2, imports: 3, importModules: 2, globals: 1, start: -1,
		},
		{
			name: "memories tables globals data start",
			opts: WasmOptions{
				Types: []WasmFuncType{{}}, Functions: []uint32{0}, Tables: 2, Globals: 3, Start: &zero,
				Memories: []WasmMemoryType{{Min: 1}, {Min: 2, Max: 4, HasMax: true}},
				Data:     [][]byte{{1}, {2, 3}},
			},
			sections: 8, functions: 1, tables: 2, globals: 3, memories: 2, data: 2, start: 0,
		},
		{
			name: "custom sections",
			opts: WasmOptions{
				NameSection: true, Producers: []WasmProducer{{Field: "language", Name: "Rust", Version: "1.80"}},
				Features: []string{"+atomics", "-simd128", "=mutable-globals"}, Custom: []WasmCustom{{Name: "x", Data: []byte{1}}},
			},
			sections: 4, customs: 4, producers: 1, features: 3, start: -1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := Wasm(tc.opts)
			wasmWalk(t, data)
			res, err := wasmfmt.Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Notes) != 0 {
				t.Errorf("a valid fixture produced notes: %v", res.Notes)
			}
			d := res.Details
			got := []int{len(res.Sections), d.ImportCount, len(res.Imports), len(res.Exports), d.FunctionCount, d.Tables,
				d.Globals, len(d.Memories), d.DataSegments, len(d.CustomSections), len(d.Producers), len(d.Features)}
			want := []int{tc.sections, tc.imports, tc.importModules, tc.exports, tc.functions, tc.tables,
				tc.globals, tc.memories, tc.data, tc.customs, tc.producers, tc.features}
			if !slices.Equal(got, want) {
				t.Errorf("sections, imports, modules, exports, functions, tables, globals, memories, data, customs, producers, features:\n got %v\nwant %v", got, want)
			}
			if d.Start != tc.start {
				t.Errorf("Start = %d, want %d", d.Start, tc.start)
			}
		})
	}
}
