package asar_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/format/asar"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

// FuzzParse feeds arbitrary bytes to the ASAR parser. It must never panic or
// hang, and a result must always be usable.
func FuzzParse(f *testing.F) {
	for _, b := range sweepInputs() {
		f.Add(b)
		f.Add(b[:len(b)/2])
	}
	f.Add(testfixtures.AsarRaw(`{"files":{"a":{"files":{"b":{"size":1,"offset":"0","unpacked":true,"link":"x"}}}}}`, nil))
	f.Add(testfixtures.AsarRaw(`{"files":{}}`, nil))
	f.Add([]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := asar.Parse(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{MaxList: 64})
		if res == nil {
			if err == nil {
				t.Fatal("nil result without an error")
			}
			return
		}
		d := res.Details
		if len(d.Files) > 64 || d.FileCount < len(d.Files) || d.Files == nil || d.Hints == nil {
			t.Fatalf("inconsistent details: %d listed of %d", len(d.Files), d.FileCount)
		}
	})
}
