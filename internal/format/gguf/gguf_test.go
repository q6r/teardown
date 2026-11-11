package gguf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

func parseBytes(t *testing.T, data []byte, lim limits.Limits) *Result {
	t.Helper()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := json.Marshal(res.Details); err != nil {
		t.Fatalf("details are not JSON encodable: %v", err)
	}
	return res
}

func TestParseDefaultFixture(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		data := testfixtures.GGUF(testfixtures.GGUFOptions{Version: version})
		res := parseBytes(t, data, limits.Limits{})
		d := res.Details
		if d.Version != version || d.TensorCount != 2 || d.KVCount != 6 {
			t.Errorf("v%d: version/counts = %d/%d/%d", version, d.Version, d.TensorCount, d.KVCount)
		}
		if d.Architecture != "llama" || d.Name != "teardown-fixture" || d.ContextLength != 4096 {
			t.Errorf("v%d: identity = %q %q %d", version, d.Architecture, d.Name, d.ContextLength)
		}
		if d.FileType == nil || *d.FileType != 1 || d.FileTypeName != "MOSTLY_F16" {
			t.Errorf("v%d: file type = %v %q", version, d.FileType, d.FileTypeName)
		}
		if d.QuantizationVersion == nil || *d.QuantizationVersion != 2 || d.Alignment != 32 {
			t.Errorf("v%d: quantization/alignment = %v/%d", version, d.QuantizationVersion, d.Alignment)
		}
		if d.ParameterCount != 36 || d.TensorTypes["F32"] != 2 || len(d.Tensors) != 2 || d.TensorsTruncated {
			t.Errorf("v%d: tensors = %d params, %v types, %d listed", version, d.ParameterCount, d.TensorTypes, len(d.Tensors))
		}
		if d.Tensors[0].Name != "token_embd.weight" || len(d.Tensors[0].Dims) != 2 || d.Tensors[0].Type != "F32" {
			t.Errorf("v%d: first tensor = %+v", version, d.Tensors[0])
		}
		if d.DataOffset%32 != 0 || d.DataOffset < d.HeaderSize || d.DataOffset+144 != int64(len(data)) {
			t.Errorf("v%d: header %d, data offset %d, file %d", version, d.HeaderSize, d.DataOffset, len(data))
		}
		if len(res.Notes) != 0 {
			t.Errorf("v%d: unexpected notes %v", version, res.Notes)
		}
		if d.Metadata["general.name"] != "teardown-fixture" || d.Metadata["llama.context_length"] != uint64(4096) {
			t.Errorf("v%d: metadata = %v", version, d.Metadata)
		}
	}
}

func TestParseMetadataValues(t *testing.T) {
	fileType := uint32(99)
	vocab := make([]string, 1000)
	for i := range vocab {
		vocab[i] = strings.Repeat("t", i%7+1)
	}
	data := testfixtures.GGUF(testfixtures.GGUFOptions{
		FileType:  &fileType,
		Alignment: 64,
		Name:      "evil\x1b[31mname" + strings.Repeat("x", 600),
		Extra: []testfixtures.GGUFKV{
			{Key: "tokenizer.ggml.model", Value: "gpt2"},
			{Key: "tokenizer.ggml.tokens", Value: vocab},
			{Key: "tokenizer.ggml.scores", Value: []float32{1, 2, 3}},
			{Key: "general.license", Value: "apache-2.0"},
			{Key: "general.author", Value: "someone"},
			{Key: "general.size_label", Value: "7B"},
			{Key: "x.nan", Value: float32(math.NaN())},
			{Key: "x.inf", Value: math.Inf(-1)},
			{Key: "x.neg", Value: int32(-5)},
			{Key: "x.flag", Value: true},
		},
	})
	res := parseBytes(t, data, limits.Limits{})
	d := res.Details
	if d.TokenizerModel != "gpt2" || d.License != "apache-2.0" || d.Author != "someone" || d.SizeLabel != "7B" {
		t.Errorf("string fields = %q %q %q %q", d.TokenizerModel, d.License, d.Author, d.SizeLabel)
	}
	if d.FileType == nil || *d.FileType != 99 || d.FileTypeName != "" {
		t.Errorf("unknown file type must be numeric only: %v %q", d.FileType, d.FileTypeName)
	}
	if got := d.Metadata["tokenizer.ggml.tokens"]; got != "array<string>[1000]" {
		t.Errorf("string array summary = %v", got)
	}
	if got := d.Metadata["tokenizer.ggml.scores"]; got != "array<float32>[3]" {
		t.Errorf("float array summary = %v", got)
	}
	if d.Metadata["x.nan"] != "NaN" || d.Metadata["x.inf"] != "-Inf" {
		t.Errorf("non-finite floats must become strings: %v %v", d.Metadata["x.nan"], d.Metadata["x.inf"])
	}
	if d.Metadata["x.neg"] != int64(-5) || d.Metadata["x.flag"] != true {
		t.Errorf("scalars = %v %v", d.Metadata["x.neg"], d.Metadata["x.flag"])
	}
	if strings.Contains(d.Name, "\x1b") || !strings.HasPrefix(d.Name, `evil\x1b[31mname`) || !strings.HasSuffix(d.Name, "…") || len(d.Name) > 4*maxKeptString+4 {
		t.Errorf("name must be escaped and capped, got %d bytes: %q", len(d.Name), d.Name[:20])
	}
	if d.DataOffset%64 != 0 || d.Alignment != 64 {
		t.Errorf("alignment %d, data offset %d", d.Alignment, d.DataOffset)
	}
	if d.ParameterCount != 36 || len(res.Notes) != 0 {
		t.Errorf("tensors after a big array must still parse: params %d notes %v", d.ParameterCount, res.Notes)
	}
}

func TestParseTensorTypesAndLimits(t *testing.T) {
	var tensors []testfixtures.GGUFTensor
	for i := range 8 {
		tensors = append(tensors, testfixtures.GGUFTensor{Name: "t" + string(rune('a'+i)), Dims: []uint64{2, uint64(i + 1)}, Type: []uint32{0, 1, 12, 12, 999, 30, 2, 2}[i]})
	}
	data := testfixtures.GGUF(testfixtures.GGUFOptions{Tensors: tensors, Extra: []testfixtures.GGUFKV{{Key: "a.b", Value: "c"}, {Key: "a.c", Value: "d"}}})
	res := parseBytes(t, data, limits.Limits{MaxList: 3})
	d := res.Details
	want := map[string]int{"F32": 1, "F16": 1, "Q4_K": 2, "type999": 1, "BF16": 1, "Q4_0": 2}
	for k, n := range want {
		if d.TensorTypes[k] != n {
			t.Errorf("TensorTypes[%q] = %d, want %d (%v)", k, d.TensorTypes[k], n, d.TensorTypes)
		}
	}
	if len(d.Tensors) != 3 || !d.TensorsTruncated {
		t.Errorf("tensor sample = %d, truncated = %v; want 3 and true", len(d.Tensors), d.TensorsTruncated)
	}
	if len(d.Metadata) != 3 || !d.MetadataTruncated {
		t.Errorf("metadata = %d entries, truncated = %v; want 3 and true", len(d.Metadata), d.MetadataTruncated)
	}
	if d.TensorCount != 8 || d.ParameterCount != 2*(1+2+3+4+5+6+7+8) {
		t.Errorf("counts must cover every tensor even when the sample is capped: %d tensors, %d params", d.TensorCount, d.ParameterCount)
	}
}

func TestParseHeaderOnlyFile(t *testing.T) {
	res := parseBytes(t, testfixtures.GGUF(testfixtures.GGUFOptions{NoTensors: true}), limits.Limits{})
	d := res.Details
	if d.TensorCount != 0 || d.ParameterCount != 0 || len(d.Tensors) != 0 || d.TensorsTruncated || len(res.Notes) != 0 {
		t.Errorf("header-only file: %+v notes %v", d, res.Notes)
	}
}

func TestParseInvalidAlignmentIsNoted(t *testing.T) {
	res := parseBytes(t, testfixtures.GGUF(testfixtures.GGUFOptions{Alignment: 48}), limits.Limits{})
	if res.Details.Alignment != 32 || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "general.alignment") {
		t.Errorf("alignment %d, notes %v", res.Details.Alignment, res.Notes)
	}
}

func TestParseRejectsUnusableHeaders(t *testing.T) {
	le32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "magic"},
		{"too short", []byte("GG"), "magic"},
		{"other format", []byte("GGML\x01\x00\x00\x00"), "magic"},
		{"no version", []byte("GGUF"), "version"},
		{"version zero", append([]byte("GGUF"), le32(0)...), "version 0"},
		{"future version", append([]byte("GGUF"), le32(9)...), "version 9"},
		{"big endian", append([]byte("GGUF"), 0x00, 0x00, 0x00, 0x03), "big-endian"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse(context.Background(), bytes.NewReader(tc.data), int64(len(tc.data)), limits.Limits{})
			if err == nil || res != nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, %v; want an error containing %q", res, err, tc.wantErr)
			}
		})
	}
}

// header builds GGUF v3 bytes: magic, version, counts and the given raw body.
func header(tensors, kvs uint64, body ...[]byte) []byte {
	b := []byte("GGUF")
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint64(b, tensors)
	b = binary.LittleEndian.AppendUint64(b, kvs)
	return append(b, bytes.Join(body, nil)...)
}

func gstr(s string) []byte {
	return append(binary.LittleEndian.AppendUint64(nil, uint64(len(s))), s...)
}

func TestParseSurvivesHostileCounts(t *testing.T) {
	u32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
	u64 := func(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
	tests := []struct {
		name     string
		data     []byte
		wantNote string
	}{
		{"huge counts and nothing else", header(1<<62, 1<<62), "stopped early"},
		{"huge key length", header(0, 1, u64(1<<40)), "stopped early"},
		{"huge string value", header(0, 1, gstr("k"), u32(tString), u64(1<<50)), "stopped early"},
		{"huge numeric array", header(0, 1, gstr("k"), u32(tArray), u32(tUint32), u64(1<<62)), "stopped early"},
		{"huge string array", header(0, 1, gstr("k"), u32(tArray), u32(tString), u64(1<<62)), "stopped early"},
		{"nested arrays forever", header(0, 1, gstr("k"), u32(tArray), u32(tArray), u64(1<<30), u32(tArray), u32(tArray), u64(1<<30)), "stopped early"},
		{"unknown value type", header(0, 1, gstr("k"), u32(77)), "unknown value type"},
		{"unknown array element type", header(0, 1, gstr("k"), u32(tArray), u32(77), u64(1)), "unknown element type"},
		{"absurd dimension count", header(1, 0, gstr("t"), u32(1<<30)), "dimensions"},
		{"tensor list cut short", header(5, 0, gstr("t"), u32(1), u64(4), u32(0), u64(0)), "read 1 of 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			res := parseBytes(t, tc.data, limits.Limits{})
			if time.Since(start) > time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
			if !strings.Contains(strings.Join(res.Notes, "|"), tc.wantNote) {
				t.Fatalf("notes = %v, want one containing %q", res.Notes, tc.wantNote)
			}
			if res.Details.ParameterCount != 0 {
				t.Errorf("an incomplete tensor list must not report a parameter count, got %d", res.Details.ParameterCount)
			}
		})
	}
}

func TestParseTruncatedFileGivesPartialResult(t *testing.T) {
	data := testfixtures.GGUF(testfixtures.GGUFOptions{Extra: []testfixtures.GGUFKV{{Key: "tokenizer.ggml.tokens", Value: []string{"a", "b", "c"}}}})
	full := parseBytes(t, data, limits.Limits{})
	for _, cut := range []int{9, 20, 40, 80, int(full.Details.HeaderSize) - 5, int(full.Details.DataOffset) - 1, len(data) - 1} {
		res, err := Parse(context.Background(), bytes.NewReader(data[:cut]), int64(cut), limits.Limits{})
		if err != nil {
			t.Fatalf("cut at %d: %v", cut, err)
		}
		if len(res.Notes) == 0 {
			t.Errorf("cut at %d: a truncated file must carry a note", cut)
		}
	}
	// Cut inside the tensor data: header is fine, the offsets point past the end.
	res := parseBytes(t, data[:full.Details.DataOffset+4], limits.Limits{})
	if !strings.Contains(strings.Join(res.Notes, "|"), "past the end") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestParseHonoursContext(t *testing.T) {
	extra := make([]testfixtures.GGUFKV, 3000)
	for i := range extra {
		extra[i] = testfixtures.GGUFKV{Key: "k" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)), Value: uint32(i)}
	}
	data := testfixtures.GGUF(testfixtures.GGUFOptions{Extra: extra})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if !errors.Is(err, context.Canceled) || res == nil {
		t.Fatalf("got %v, %v; want a partial result and context.Canceled", res, err)
	}
}

func TestParseNeverPanics(t *testing.T) {
	fixtures := map[string][]byte{
		"v3":     testfixtures.GGUF(testfixtures.GGUFOptions{Extra: []testfixtures.GGUFKV{{Key: "a", Value: []string{"x", "y"}}, {Key: "b", Value: float32(1)}}}),
		"v1":     testfixtures.GGUF(testfixtures.GGUFOptions{Version: 1}),
		"v2":     testfixtures.GGUF(testfixtures.GGUFOptions{Version: 2, NoTensors: true}),
		"nested": header(0, 1, gstr("k"), binary.LittleEndian.AppendUint32(nil, tArray), binary.LittleEndian.AppendUint32(nil, tArray), binary.LittleEndian.AppendUint64(nil, 2)),
	}
	call := func(name string, data []byte) {
		start := time.Now()
		_, _ = Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%s took %v", name, d)
		}
	}
	for name, data := range fixtures {
		for n := 0; n <= len(data); n++ {
			if n > 4096 && n%97 != 0 {
				continue
			}
			call(name, data[:n])
		}
		for i := 0; i < min(512, len(data)); i++ {
			for _, v := range []byte{0x00, 0xff, 0x80} {
				mutated := bytes.Clone(data)
				mutated[i] = v
				call(name, mutated)
			}
		}
	}
}
