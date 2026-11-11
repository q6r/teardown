package macho

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
	f.Add([]byte("\xcf\xfa\xed\xfe"))
	f.Add([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if err != nil {
			if res != nil {
				t.Fatalf("error %v with a non-nil result", err)
			}
			return
		}
		if res == nil || len(res.Hardening) != 5 || len(res.Details.Slices) == 0 {
			t.Fatalf("incomplete result %+v", res)
		}
		if p := res.Details.PrimarySlice; p < 0 || p >= len(res.Details.Slices) {
			t.Fatalf("primary slice %d out of range", p)
		}
		if _, err := json.Marshal(res); err != nil {
			t.Fatalf("result does not encode: %v", err)
		}
	})
}
