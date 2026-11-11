package wasm

import (
	"bytes"
	"context"
	"testing"

	"github.com/q6r/teardown/internal/limits"
)

// FuzzParse feeds arbitrary bytes to Parse, once with limits proportional to the
// input and once with tiny limits that force every cap. Parse is called directly
// (no recover) so any panic or hang is a failure.
func FuzzParse(f *testing.F) {
	for _, data := range robustnessInputs() {
		f.Add(data)
		if len(data) > 12 {
			f.Add(data[:len(data)/2])
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		size := int64(len(data))
		for _, lim := range []limits.Limits{limits.ForSize(size), {MaxList: 2, MaxMeta: 32}} {
			res, err := Parse(context.Background(), bytes.NewReader(data), size, lim)
			if err != nil {
				if res != nil {
					t.Fatalf("a result must not accompany an error: %v", err)
				}
				continue
			}
			checkResult(t, res, size)
		}
	})
}
