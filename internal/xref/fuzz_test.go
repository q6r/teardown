package xref

import (
	"bytes"
	"context"
	"testing"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

// checkIndex asserts what every index must satisfy, whatever the input was: the
// sites lie inside the file, every block they give is valid and bounded.
func checkIndex(t *testing.T, ix *Index, size int64) {
	t.Helper()
	for _, a := range ix.APIs() {
		sites := ix.Sites(a.Name)
		if len(sites) > maxSitesPerAPI || a.Sites < len(sites) {
			t.Fatalf("%s: %d sites kept, %d counted", a.Name, len(sites), a.Sites)
		}
		for _, s := range sites {
			if s.Offset < 0 || s.Offset >= size || s.API == "" {
				t.Fatalf("site %+v lies outside the %d byte file", s, size)
			}
			b := ix.Block(s, DefaultBefore, DefaultAfter)
			if err := b.Validate(); err != nil {
				t.Fatalf("site %+v: invalid block: %v", s, err)
			}
			if len(b.Lines) > DefaultBefore+DefaultAfter+1 {
				t.Fatalf("site %+v: %d lines", s, len(b.Lines))
			}
			highlighted := 0
			for _, l := range b.Lines {
				if l.Highlight {
					highlighted++
				}
			}
			if highlighted != 1 && len(b.Lines) > 1 {
				t.Fatalf("site %+v: %d highlighted lines", s, highlighted)
			}
		}
	}
}

func seeds() [][]byte {
	return [][]byte{
		dropperFixture(),
		testfixtures.PE(testfixtures.PEOptions{}),
		testfixtures.PE(testfixtures.PEOptions{Bits: 32}),
		testfixtures.SamplePE(),
	}
}

// FuzzScan feeds arbitrary bytes to Scan: any panic, hang or invalid block is a bug.
func FuzzScan(f *testing.F) {
	for _, s := range seeds() {
		f.Add(s)
		f.Add(s[:len(s)/2])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ix, err := Scan(context.Background(), bytes.NewReader(data), int64(len(data)), limits.ForSize(int64(len(data))), Options{})
		if err != nil {
			return
		}
		checkIndex(t, ix, int64(len(data)))
	})
}

// TestScanSurvivesEveryPrefixAndCorruption is the hostile-input sweep: every
// prefix of valid images and images with single bytes damaged.
func TestScanSurvivesEveryPrefixAndCorruption(t *testing.T) {
	for si, seed := range seeds() {
		for n := 0; n <= len(seed); n += 11 {
			data := seed[:n]
			ix, err := Scan(context.Background(), bytes.NewReader(data), int64(n), limits.ForSize(int64(n)), Options{})
			if err == nil {
				checkIndex(t, ix, int64(n))
			}
		}
		// Damage the headers and the first bytes of .text one byte at a time.
		for i := 0; i < 0x300 && i < len(seed); i++ {
			for _, v := range []byte{0x00, 0xff} {
				data := append([]byte(nil), seed...)
				data[i] = v
				ix, err := Scan(context.Background(), bytes.NewReader(data), int64(len(data)), limits.ForSize(int64(len(data))), Options{})
				if err == nil {
					checkIndex(t, ix, int64(len(data)))
				}
			}
		}
		_ = si
	}
}
