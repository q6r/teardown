package sniff

import (
	"bytes"
	"testing"
)

// FuzzDetect throws arbitrary bytes, and sizes that disagree with the data, at
// Detect. It calls Detect directly (no recover) so any panic or hang is a failure.
func FuzzDetect(f *testing.F) {
	for _, fx := range fixtures(f) {
		f.Add(fx.data, uint16(0))
		if len(fx.data) > 8 {
			f.Add(fx.data[:len(fx.data)/2], uint16(0))
			f.Add(fx.data, uint16(4096)) // the reader claims to be bigger than it is
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, extra uint16) {
		size := int64(len(data)) + int64(extra)
		got := Detect(bytes.NewReader(data), size)
		if p := invariantProblem(got); p != "" {
			t.Fatalf("%s (input %q, size %d)", p, data, size)
		}
	})
}
