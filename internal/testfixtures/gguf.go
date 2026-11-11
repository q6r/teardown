package testfixtures

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// GGUFTensor describes one tensor of a GGUF fixture. Data is always laid out as
// 4-byte elements so offsets stay consistent whatever Type says.
type GGUFTensor struct {
	Name string
	Dims []uint64
	// Type is the ggml type id (0 = F32, 1 = F16, ...).
	Type uint32
}

// GGUFKV is one extra metadata key/value. Value may be a string, bool, any
// fixed-size integer, float32, float64, or a slice of string, uint32, int32,
// float32 or uint64 (written as a GGUF array).
type GGUFKV struct {
	Key   string
	Value any
}

// GGUFOptions configures [GGUF]. The zero value produces a valid version-3
// llama model with two small tensors.
type GGUFOptions struct {
	// Version is 1, 2 or 3 (default 3). Version 1 uses 32-bit counts and lengths.
	Version uint32
	// Architecture is general.architecture (default "llama").
	Architecture string
	// Name is general.name (default "teardown-fixture").
	Name string
	// ContextLength is "<arch>.context_length" (default 4096).
	ContextLength uint64
	// FileType is general.file_type (default 1, MOSTLY_F16).
	FileType *uint32
	// Alignment is general.alignment (default 32).
	Alignment uint32
	// Extra metadata appended after the standard keys.
	Extra []GGUFKV
	// Tensors replaces the default tensor list when non-nil.
	Tensors []GGUFTensor
	// NoTensors writes a header without any tensor (and without data).
	NoTensors bool
}

// GGUF builds a GGUF model file: header, metadata, tensor infos, padding and
// zeroed tensor data.
func GGUF(o GGUFOptions) []byte {
	if o.Version == 0 {
		o.Version = 3
	}
	if o.Architecture == "" {
		o.Architecture = "llama"
	}
	if o.Name == "" {
		o.Name = "teardown-fixture"
	}
	if o.ContextLength == 0 {
		o.ContextLength = 4096
	}
	fileType := uint32(1)
	if o.FileType != nil {
		fileType = *o.FileType
	}
	if o.Alignment == 0 {
		o.Alignment = 32
	}
	tensors := o.Tensors
	if tensors == nil && !o.NoTensors {
		tensors = []GGUFTensor{
			{Name: "token_embd.weight", Dims: []uint64{8, 4}, Type: 0},
			{Name: "output_norm.weight", Dims: []uint64{4}, Type: 0},
		}
	}
	if o.NoTensors {
		tensors = nil
	}

	kvs := []GGUFKV{
		{"general.architecture", o.Architecture},
		{"general.name", o.Name},
		{o.Architecture + ".context_length", uint32(o.ContextLength)},
		{"general.file_type", fileType},
		{"general.quantization_version", uint32(2)},
		{"general.alignment", o.Alignment},
	}
	kvs = append(kvs, o.Extra...)

	w := ggufWriter{version: o.Version}
	w.raw([]byte("GGUF"))
	w.u32(o.Version)
	w.count(uint64(len(tensors)))
	w.count(uint64(len(kvs)))
	for _, kv := range kvs {
		w.str(kv.Key)
		w.value(kv.Value)
	}

	var offset uint64
	offsets := make([]uint64, len(tensors))
	for i, t := range tensors {
		offsets[i] = offset
		elems := uint64(1)
		for _, d := range t.Dims {
			elems *= d
		}
		offset += elems * 4
	}
	for i, t := range tensors {
		w.str(t.Name)
		w.u32(uint32(len(t.Dims)))
		for _, d := range t.Dims {
			w.count(d)
		}
		w.u32(t.Type)
		w.u64(offsets[i])
	}
	if len(tensors) > 0 {
		for w.buf.Len()%int(o.Alignment) != 0 {
			w.buf.WriteByte(0)
		}
		w.raw(make([]byte, offset))
	}
	return w.buf.Bytes()
}

// ggufWriter encodes GGUF primitives (little endian).
type ggufWriter struct {
	buf     bytes.Buffer
	version uint32
}

func (w *ggufWriter) raw(b []byte) { w.buf.Write(b) }

func (w *ggufWriter) u32(v uint32) {
	w.buf.Write(binary.LittleEndian.AppendUint32(nil, v))
}

func (w *ggufWriter) u64(v uint64) {
	w.buf.Write(binary.LittleEndian.AppendUint64(nil, v))
}

// count writes a length or count: 32-bit in version 1, 64-bit afterwards.
func (w *ggufWriter) count(v uint64) {
	if w.version == 1 {
		w.u32(uint32(v))
		return
	}
	w.u64(v)
}

func (w *ggufWriter) str(s string) {
	w.count(uint64(len(s)))
	w.buf.WriteString(s)
}

// GGUF value type ids.
const (
	ggufTypeUint8   = 0
	ggufTypeInt8    = 1
	ggufTypeUint16  = 2
	ggufTypeInt16   = 3
	ggufTypeUint32  = 4
	ggufTypeInt32   = 5
	ggufTypeFloat32 = 6
	ggufTypeBool    = 7
	ggufTypeString  = 8
	ggufTypeArray   = 9
	ggufTypeUint64  = 10
	ggufTypeInt64   = 11
	ggufTypeFloat64 = 12
)

func (w *ggufWriter) value(v any) {
	switch x := v.(type) {
	case uint8:
		w.u32(ggufTypeUint8)
		w.buf.WriteByte(x)
	case int8:
		w.u32(ggufTypeInt8)
		w.buf.WriteByte(byte(x))
	case uint16:
		w.u32(ggufTypeUint16)
		w.buf.Write(binary.LittleEndian.AppendUint16(nil, x))
	case int16:
		w.u32(ggufTypeInt16)
		w.buf.Write(binary.LittleEndian.AppendUint16(nil, uint16(x)))
	case uint32:
		w.u32(ggufTypeUint32)
		w.u32(x)
	case int32:
		w.u32(ggufTypeInt32)
		w.u32(uint32(x))
	case float32:
		w.u32(ggufTypeFloat32)
		w.u32(math.Float32bits(x))
	case bool:
		w.u32(ggufTypeBool)
		if x {
			w.buf.WriteByte(1)
		} else {
			w.buf.WriteByte(0)
		}
	case string:
		w.u32(ggufTypeString)
		w.str(x)
	case uint64:
		w.u32(ggufTypeUint64)
		w.u64(x)
	case int64:
		w.u32(ggufTypeInt64)
		w.u64(uint64(x))
	case float64:
		w.u32(ggufTypeFloat64)
		w.u64(math.Float64bits(x))
	case []string:
		w.u32(ggufTypeArray)
		w.u32(ggufTypeString)
		w.count(uint64(len(x)))
		for _, s := range x {
			w.str(s)
		}
	case []uint32:
		w.u32(ggufTypeArray)
		w.u32(ggufTypeUint32)
		w.count(uint64(len(x)))
		for _, n := range x {
			w.u32(n)
		}
	case []int32:
		w.u32(ggufTypeArray)
		w.u32(ggufTypeInt32)
		w.count(uint64(len(x)))
		for _, n := range x {
			w.u32(uint32(n))
		}
	case []float32:
		w.u32(ggufTypeArray)
		w.u32(ggufTypeFloat32)
		w.count(uint64(len(x)))
		for _, n := range x {
			w.u32(math.Float32bits(n))
		}
	case []uint64:
		w.u32(ggufTypeArray)
		w.u32(ggufTypeUint64)
		w.count(uint64(len(x)))
		for _, n := range x {
			w.u64(n)
		}
	default:
		panic(fmt.Sprintf("testfixtures: unsupported GGUF value type %T", v))
	}
}
