package zipscan_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/zipscan"
)

// FuzzScan feeds arbitrary bytes to the directory walker and then reads the
// entries it returned: neither step may panic, hang or break its invariants.
func FuzzScan(f *testing.F) {
	for _, b := range sweepInputs() {
		f.Add(b)
		f.Add(b[:len(b)/2])
		f.Add(b[:max(len(b)-10, 0)])
		f.Add(b[:max(len(b)-22, 0)])
	}
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		const keep = 16
		d, err := zipscan.Walk(ctx, bytes.NewReader(b), int64(len(b)), keep, func(zipscan.Entry) {})
		if d == nil {
			if err == nil {
				t.Fatal("nil directory without an error")
			}
			return
		}
		if len(d.Entries) > keep || d.Count < len(d.Entries) {
			t.Fatalf("inconsistent counts: kept %d of %d", len(d.Entries), d.Count)
		}
		for _, e := range d.Entries {
			_, _ = zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 1<<16)
			_, _ = zipscan.Peek(bytes.NewReader(b), int64(len(b)), e, 8)
		}

		// Differential check: whenever the standard library accepts the input
		// and zipscan saw nothing unusual, both must list the same entries.
		zr, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if zerr != nil && !errors.Is(zerr, zip.ErrInsecurePath) {
			return
		}
		if len(d.Warnings) != 0 || d.Recovered {
			return
		}
		if d.Count != len(zr.File) {
			t.Fatalf("zipscan counts %d entries, archive/zip %d", d.Count, len(zr.File))
		}
		for i, e := range d.Entries {
			if f := zr.File[i]; e.Name != binio.Printable(f.Name, 512) || e.Method != f.Method ||
				e.CompressedSize != f.CompressedSize64 || e.UncompressedSize != f.UncompressedSize64 {
				t.Fatalf("entry %d: zipscan %+v, archive/zip %+v", i, e, f.FileHeader)
			}
		}
	})
}
