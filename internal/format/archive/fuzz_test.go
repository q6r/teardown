package archive_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/format/archive"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

// FuzzParse feeds arbitrary bytes to the archive parser under every container
// kind. It must never panic or hang, and a result must always be usable.
func FuzzParse(f *testing.F) {
	for _, in := range sweepInputs() {
		f.Add(in.data, in.kind)
		f.Add(in.data[:len(in.data)/2], in.kind)
		f.Add(in.data[:max(len(in.data)-22, 0)], in.kind)
	}
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), report.TypeZip)
	f.Fuzz(func(t *testing.T, b []byte, kind string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := archive.Parse(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{MaxList: 64}, kind)
		if res == nil {
			if err == nil {
				t.Fatal("nil result without an error")
			}
			return
		}
		d := res.Details
		if len(d.Entries) > 64 || d.EntryCount < len(d.Entries) || d.Manifest == nil || d.Nested == nil || d.UnsafeNames == nil {
			t.Fatalf("inconsistent details: %d entries of %d", len(d.Entries), d.EntryCount)
		}
	})
}
