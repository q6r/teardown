package gguf

import (
	"bytes"
	"context"
	"testing"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		testfixtures.GGUF(testfixtures.GGUFOptions{}),
		testfixtures.GGUF(testfixtures.GGUFOptions{Version: 1}),
		testfixtures.GGUF(testfixtures.GGUFOptions{Version: 2, NoTensors: true}),
		testfixtures.GGUF(testfixtures.GGUFOptions{Extra: []testfixtures.GGUFKV{
			{Key: "tokenizer.ggml.tokens", Value: []string{"a", "bb"}},
			{Key: "x", Value: float32(1.5)},
			{Key: "y", Value: []uint32{1, 2, 3}},
		}}),
		header(1<<62, 1<<62),
		header(0, 1, gstr("k"), []byte{9, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}),
	}
	for _, s := range seeds {
		f.Add(s)
		for _, n := range []int{4, 8, 24, len(s) / 2, len(s) - 1} {
			if n > 0 && n < len(s) {
				f.Add(s[:n])
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if err != nil {
			if res != nil {
				t.Fatal("an error must come with a nil result")
			}
			return
		}
		if res == nil {
			t.Fatal("nil result without an error")
		}
		d := res.Details
		if d.Version == 0 || d.Version > maxVersion {
			t.Fatalf("version %d accepted", d.Version)
		}
		if len(d.Metadata) > limits.Default().MaxList || len(d.Tensors) > maxSampledTensor {
			t.Fatalf("lists exceed their caps: %d metadata, %d tensors", len(d.Metadata), len(d.Tensors))
		}
	})
}
