package testfixtures

// WebAssembly value types for [WasmFuncType] and [WasmImport].
const (
	WasmI32 byte = 0x7f
	WasmI64 byte = 0x7e
	WasmF32 byte = 0x7d
	WasmF64 byte = 0x7c
)

// WasmKind is the kind of an imported or exported item.
type WasmKind byte

// The kinds of imports and exports.
const (
	WasmKindFunc   WasmKind = 0
	WasmKindTable  WasmKind = 1
	WasmKindMemory WasmKind = 2
	WasmKindGlobal WasmKind = 3
	WasmKindTag    WasmKind = 4
)

// WasmFuncType is a function signature made of value types.
type WasmFuncType struct {
	Params, Results []byte
}

// WasmMemoryType holds the limits of a memory (or of an imported table).
type WasmMemoryType struct {
	Min      uint32
	Max      uint32
	HasMax   bool
	Shared   bool
	Memory64 bool
}

// WasmImport is one import; only the fields that belong to Kind are used.
type WasmImport struct {
	Module, Name string
	Kind         WasmKind
	// Type is the type index of a function or tag import.
	Type uint32
	// Limits are the limits of a memory or table import.
	Limits WasmMemoryType
	// ValType and Mutable describe a global import.
	ValType byte
	Mutable bool
}

// WasmExport is one export.
type WasmExport struct {
	Name  string
	Kind  WasmKind
	Index uint32
}

// WasmCustom is a custom section.
type WasmCustom struct {
	Name string
	Data []byte
}

// WasmProducer is one value of the "producers" custom section.
type WasmProducer struct {
	Field, Name, Version string
}

// WasmOptions describes a WebAssembly module for [Wasm]. The zero value is the
// smallest valid module: the 8-byte header alone.
type WasmOptions struct {
	Types   []WasmFuncType
	Imports []WasmImport
	// Functions lists the type index of every defined function; each gets a
	// trivial body.
	Functions []uint32
	// Tables is the number of funcref tables to define.
	Tables   int
	Memories []WasmMemoryType
	// Globals is the number of immutable i32 globals to define.
	Globals int
	Exports []WasmExport
	// Start is the index of the start function, nil for none.
	Start *uint32
	// Data lists active data segments for memory 0.
	Data [][]byte
	// DataCount emits a datacount section before the code section.
	DataCount bool
	// Custom sections are appended after the standard ones, in order.
	Custom []WasmCustom
	// Producers, Features and NameSection add the well-known custom sections
	// "producers", "target_features" and "name".
	Producers   []WasmProducer
	Features    []string
	NameSection bool
}

// Wasm builds a WebAssembly module with the standard sections in their required
// order followed by the custom sections.
func Wasm(o WasmOptions) []byte {
	out := []byte("\x00asm\x01\x00\x00\x00")
	add := func(id byte, payload []byte) {
		out = append(out, id)
		out = append(out, wasmULEB(uint64(len(payload)))...)
		out = append(out, payload...)
	}

	if len(o.Types) > 0 {
		items := make([][]byte, len(o.Types))
		for i, t := range o.Types {
			item := []byte{0x60}
			item = append(item, wasmVecBytes(t.Params)...)
			item = append(item, wasmVecBytes(t.Results)...)
			items[i] = item
		}
		add(1, wasmVec(items))
	}
	if len(o.Imports) > 0 {
		items := make([][]byte, len(o.Imports))
		for i, im := range o.Imports {
			items[i] = wasmImportBytes(im)
		}
		add(2, wasmVec(items))
	}
	if len(o.Functions) > 0 {
		items := make([][]byte, len(o.Functions))
		for i, ti := range o.Functions {
			items[i] = wasmULEB(uint64(ti))
		}
		add(3, wasmVec(items))
	}
	if o.Tables > 0 {
		items := make([][]byte, o.Tables)
		for i := range items {
			items[i] = append([]byte{0x70}, wasmLimits(WasmMemoryType{Min: 1})...)
		}
		add(4, wasmVec(items))
	}
	if len(o.Memories) > 0 {
		items := make([][]byte, len(o.Memories))
		for i, m := range o.Memories {
			items[i] = wasmLimits(m)
		}
		add(5, wasmVec(items))
	}
	if o.Globals > 0 {
		items := make([][]byte, o.Globals)
		for i := range items {
			items[i] = []byte{WasmI32, 0x00, 0x41, 0x00, 0x0b} // i32, immutable, i32.const 0, end
		}
		add(6, wasmVec(items))
	}
	if len(o.Exports) > 0 {
		items := make([][]byte, len(o.Exports))
		for i, e := range o.Exports {
			item := wasmName(e.Name)
			item = append(item, byte(e.Kind))
			items[i] = append(item, wasmULEB(uint64(e.Index))...)
		}
		add(7, wasmVec(items))
	}
	if o.Start != nil {
		add(8, wasmULEB(uint64(*o.Start)))
	}
	if o.DataCount {
		add(12, wasmULEB(uint64(len(o.Data))))
	}
	if len(o.Functions) > 0 {
		items := make([][]byte, len(o.Functions))
		for i := range items {
			items[i] = []byte{0x02, 0x00, 0x0b} // body of 2 bytes: no locals, end
		}
		add(10, wasmVec(items))
	}
	if len(o.Data) > 0 {
		items := make([][]byte, len(o.Data))
		for i, d := range o.Data {
			item := []byte{0x00, 0x41, 0x00, 0x0b} // active, memory 0, offset i32.const 0
			item = append(item, wasmULEB(uint64(len(d)))...)
			items[i] = append(item, d...)
		}
		add(11, wasmVec(items))
	}

	custom := func(name string, data []byte) {
		add(0, append(wasmName(name), data...))
	}
	if o.NameSection {
		sub := wasmName("demo")
		custom("name", append([]byte{0x00}, append(wasmULEB(uint64(len(sub))), sub...)...))
	}
	if len(o.Producers) > 0 {
		// Group the values by field, keeping first-seen field order.
		var fields []string
		values := map[string][][]byte{}
		for _, p := range o.Producers {
			if _, ok := values[p.Field]; !ok {
				fields = append(fields, p.Field)
			}
			values[p.Field] = append(values[p.Field], append(wasmName(p.Name), wasmName(p.Version)...))
		}
		items := make([][]byte, len(fields))
		for i, f := range fields {
			items[i] = append(wasmName(f), wasmVec(values[f])...)
		}
		custom("producers", wasmVec(items))
	}
	if len(o.Features) > 0 {
		items := make([][]byte, len(o.Features))
		for i, f := range o.Features {
			items[i] = append([]byte{f[0]}, wasmName(f[1:])...)
		}
		custom("target_features", wasmVec(items))
	}
	for _, c := range o.Custom {
		custom(c.Name, c.Data)
	}
	return out
}

// WasmSample returns a small but realistic module: two function types, one
// imported and one defined function, a memory, two exports, a data segment and
// the name, producers and target_features custom sections.
func WasmSample() []byte {
	return Wasm(WasmOptions{
		Types: []WasmFuncType{
			{Params: []byte{WasmI32}, Results: []byte{WasmI32}},
			{Params: []byte{WasmI32, WasmI32}},
		},
		Imports:   []WasmImport{{Module: "env", Name: "puts", Kind: WasmKindFunc, Type: 0}},
		Functions: []uint32{0},
		Memories:  []WasmMemoryType{{Min: 1, Max: 2, HasMax: true}},
		Exports: []WasmExport{
			{Name: "main", Kind: WasmKindFunc, Index: 1},
			{Name: "memory", Kind: WasmKindMemory, Index: 0},
		},
		Data:        [][]byte{[]byte("hello")},
		NameSection: true,
		Producers: []WasmProducer{
			{Field: "language", Name: "C11"},
			{Field: "processed-by", Name: "clang", Version: "17.0.0"},
		},
		Features: []string{"+bulk-memory", "+simd128"},
	})
}

func wasmImportBytes(im WasmImport) []byte {
	b := append(wasmName(im.Module), wasmName(im.Name)...)
	b = append(b, byte(im.Kind))
	switch im.Kind {
	case WasmKindFunc:
		b = append(b, wasmULEB(uint64(im.Type))...)
	case WasmKindTable:
		b = append(b, 0x70)
		b = append(b, wasmLimits(im.Limits)...)
	case WasmKindMemory:
		b = append(b, wasmLimits(im.Limits)...)
	case WasmKindGlobal:
		b = append(b, im.ValType, boolByte(im.Mutable))
	case WasmKindTag:
		b = append(b, 0x00)
		b = append(b, wasmULEB(uint64(im.Type))...)
	}
	return b
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// wasmLimits encodes memory limits: a flag byte, the minimum and the optional maximum.
func wasmLimits(m WasmMemoryType) []byte {
	flags := byte(0)
	if m.HasMax {
		flags |= 1
	}
	if m.Shared {
		flags |= 2
	}
	if m.Memory64 {
		flags |= 4
	}
	b := append([]byte{flags}, wasmULEB(uint64(m.Min))...)
	if m.HasMax {
		b = append(b, wasmULEB(uint64(m.Max))...)
	}
	return b
}

// wasmULEB encodes v as an unsigned LEB128 integer.
func wasmULEB(v uint64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b = append(b, c|0x80)
			continue
		}
		return append(b, c)
	}
}

func wasmName(s string) []byte { return append(wasmULEB(uint64(len(s))), s...) }

func wasmVec(items [][]byte) []byte {
	b := wasmULEB(uint64(len(items)))
	for _, it := range items {
		b = append(b, it...)
	}
	return b
}

// wasmVecBytes encodes a vector of single-byte items.
func wasmVecBytes(items []byte) []byte { return append(wasmULEB(uint64(len(items))), items...) }
