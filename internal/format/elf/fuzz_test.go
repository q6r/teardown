package elf

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/q6r/teardown/internal/limits"
)

// FuzzParse feeds arbitrary bytes to the parser directly (no recover): any
// panic, hang or invariant violation is a bug.
func FuzzParse(f *testing.F) {
	for _, data := range corpus() {
		f.Add(data)
		f.Add(data[:len(data)/2])
		f.Add(data[:min(len(data), 120)])
	}
	f.Add([]byte{})
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("\x7fELF\x02\x01\x01\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if err != nil {
			if res != nil {
				t.Fatalf("error %v with a non-nil result", err)
			}
			return
		}
		if res == nil || len(res.Hardening) != 5 {
			t.Fatalf("incomplete result %+v", res)
		}
		if _, err := json.Marshal(res); err != nil {
			t.Fatalf("result does not encode: %v", err)
		}
	})
}
