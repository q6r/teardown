package testfixtures

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// ggufCursor is a deliberately independent GGUF decoder used to prove that the
// builder emits structurally valid files; it shares no code with the parser.
type ggufCursor struct {
	t       *testing.T
	b       []byte
	pos     int
	version uint32
}

func (c *ggufCursor) take(n int) []byte {
	c.t.Helper()
	if n < 0 || c.pos+n > len(c.b) {
		c.t.Fatalf("read of %d bytes at %d overruns the %d byte file", n, c.pos, len(c.b))
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out
}

func (c *ggufCursor) u32() uint32 { return binary.LittleEndian.Uint32(c.take(4)) }
func (c *ggufCursor) u64() uint64 { return binary.LittleEndian.Uint64(c.take(8)) }

func (c *ggufCursor) count() uint64 {
	if c.version == 1 {
		return uint64(c.u32())
	}
	return c.u64()
}

func (c *ggufCursor) str() string { return string(c.take(int(c.count()))) }

// skipValue consumes one value of the given type and returns its decoded form for scalars.
func (c *ggufCursor) skipValue(typ uint32) any {
	switch typ {
	case ggufTypeUint8, ggufTypeInt8, ggufTypeBool:
		return uint64(c.take(1)[0])
	case ggufTypeUint16, ggufTypeInt16:
		return uint64(binary.LittleEndian.Uint16(c.take(2)))
	case ggufTypeUint32, ggufTypeInt32:
		return uint64(c.u32())
	case ggufTypeFloat32:
		return float64(math.Float32frombits(c.u32()))
	case ggufTypeUint64, ggufTypeInt64:
		return c.u64()
	case ggufTypeFloat64:
		return math.Float64frombits(c.u64())
	case ggufTypeString:
		return c.str()
	case ggufTypeArray:
		elem := c.u32()
		n := c.count()
		for range n {
			c.skipValue(elem)
		}
		return nil
	}
	c.t.Fatalf("unknown value type %d", typ)
	return nil
}

func TestGGUF_FixtureIsStructurallyValid(t *testing.T) {
	tests := []struct {
		name string
		opts GGUFOptions
	}{
		{"default v3", GGUFOptions{}},
		{"v2", GGUFOptions{Version: 2}},
		{"v1", GGUFOptions{Version: 1}},
		{"alignment 64", GGUFOptions{Alignment: 64}},
		{"arrays and scalars", GGUFOptions{Extra: []GGUFKV{
			{"tokenizer.ggml.tokens", []string{"a", "bb", "ccc"}},
			{"tokenizer.ggml.scores", []float32{0.5, -1}},
			{"tokenizer.ggml.token_type", []int32{1, 2, 3}},
			{"x.u8", uint8(7)}, {"x.i8", int8(-7)}, {"x.u16", uint16(7)}, {"x.i16", int16(-7)},
			{"x.i32", int32(-7)}, {"x.u64", uint64(1 << 40)}, {"x.i64", int64(-1 << 40)},
			{"x.f32", float32(1.5)}, {"x.f64", 2.5}, {"x.bool", true}, {"x.ids", []uint32{1, 2}}, {"x.big", []uint64{1}},
		}}},
		{"custom tensors", GGUFOptions{Tensors: []GGUFTensor{{Name: "a", Dims: []uint64{2, 3, 4}, Type: 12}, {Name: "b", Dims: []uint64{5}, Type: 1}}}},
		{"no tensors", GGUFOptions{NoTensors: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := GGUF(tc.opts)
			wantVersion := tc.opts.Version
			if wantVersion == 0 {
				wantVersion = 3
			}
			c := &ggufCursor{t: t, b: data}
			if !bytes.Equal(c.take(4), []byte("GGUF")) {
				t.Fatal("bad magic")
			}
			c.version = c.u32()
			if c.version != wantVersion {
				t.Fatalf("version = %d, want %d", c.version, wantVersion)
			}
			tensorCount, kvCount := c.count(), c.count()
			alignment := uint64(32)
			for range kvCount {
				key := c.str()
				typ := c.u32()
				v := c.skipValue(typ)
				if key == "general.alignment" {
					alignment = v.(uint64)
				}
			}
			var dataLen, maxEnd uint64
			for range tensorCount {
				_ = c.str()
				nd := c.u32()
				elems := uint64(1)
				for range nd {
					elems *= c.count()
				}
				_ = c.u32()
				off := c.u64()
				maxEnd = max(maxEnd, off+elems*4)
				dataLen = maxEnd
			}
			if tensorCount > 0 {
				start := (uint64(c.pos) + alignment - 1) / alignment * alignment
				if uint64(len(data)) != start+dataLen {
					t.Fatalf("file is %d bytes, header ends at %d (aligned %d) and data needs %d", len(data), c.pos, start, dataLen)
				}
			} else if c.pos != len(data) {
				t.Fatalf("header-only file has %d trailing bytes", len(data)-c.pos)
			}
		})
	}
}

func TestGGUF_FixtureIsDeterministic(t *testing.T) {
	a, b := GGUF(GGUFOptions{}), GGUF(GGUFOptions{})
	if !bytes.Equal(a, b) {
		t.Fatal("two builds differ")
	}
	if bytes.Equal(a, GGUF(GGUFOptions{Name: "other"})) {
		t.Fatal("options must change the output")
	}
}

func TestGGUF_UnsupportedValuePanicsLoudly(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("an unsupported value type must panic so a bad fixture is never silently written")
		}
	}()
	GGUF(GGUFOptions{Extra: []GGUFKV{{"x", struct{}{}}}})
}
