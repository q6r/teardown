package zipscan_test

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/testfixtures"
	"github.com/q6r/teardown/internal/zipscan"
)

var errTruncated = binio.ErrTruncated

func TestReadTable(t *testing.T) {
	content := bytes.Repeat([]byte("0123456789"), 1000)
	b := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "stored.bin", Data: content, Store: true},
		testfixtures.ZipEntry{Name: "deflated.bin", Data: content},
		testfixtures.ZipEntry{Name: "empty", Store: true},
	)
	d := scan(t, b, 10)
	stored, deflated, empty := d.Entries[0], d.Entries[1], d.Entries[2]

	tests := []struct {
		name    string
		entry   zipscan.Entry
		max     int64
		wantLen int
		wantErr error
	}{
		{"stored", stored, 1 << 20, len(content), nil},
		{"deflated", deflated, 1 << 20, len(content), nil},
		{"empty", empty, 10, 0, nil},
		{"exact limit", stored, int64(len(content)), len(content), nil},
		{"stored over limit", stored, 100, 100, zipscan.ErrTooLarge},
		{"deflated over limit", deflated, 100, 100, zipscan.ErrTooLarge},
		{"zero limit with content", deflated, 0, 0, zipscan.ErrTooLarge},
		{"negative limit", stored, -5, 0, zipscan.ErrTooLarge},
		{"empty with zero limit", empty, 0, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), tc.entry, tc.max)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
			if tc.wantLen > 0 && !bytes.Equal(got, content[:tc.wantLen]) {
				t.Fatal("content differs from the original prefix")
			}
		})
	}
}

func TestReadRefusesUnreadableEntries(t *testing.T) {
	b := testfixtures.Zip(testfixtures.ZipEntry{Name: "a", Data: []byte("data"), Store: true})
	e := scan(t, b, 1).Entries[0]
	r := bytes.NewReader(b)

	encrypted := e
	encrypted.Encrypted = true
	if _, err := zipscan.Read(r, int64(len(b)), encrypted, 100); !errors.Is(err, zipscan.ErrEncrypted) {
		t.Errorf("encrypted: %v", err)
	}
	bzip := e
	bzip.Method = 12
	if _, err := zipscan.Read(r, int64(len(b)), bzip, 100); !errors.Is(err, zipscan.ErrUnsupported) {
		t.Errorf("bzip2: %v", err)
	}
	wrongOffset := e
	wrongOffset.LocalOffset = 3
	if _, err := zipscan.Read(r, int64(len(b)), wrongOffset, 100); !errors.Is(err, zipscan.ErrCorrupt) {
		t.Errorf("wrong offset: %v", err)
	}
	outside := e
	outside.LocalOffset = int64(len(b)) + 10
	if _, err := zipscan.Read(r, int64(len(b)), outside, 100); !errors.Is(err, errTruncated) {
		t.Errorf("outside: %v", err)
	}
	negative := e
	negative.LocalOffset = -1
	if _, err := zipscan.Read(r, int64(len(b)), negative, 100); !errors.Is(err, errTruncated) {
		t.Errorf("negative: %v", err)
	}
}

func TestReadReturnsPartialDataFromTruncatedArchives(t *testing.T) {
	content := bytes.Repeat([]byte("abcdefgh"), 500)
	for _, store := range []bool{true, false} {
		name := map[bool]string{true: "stored", false: "deflated"}[store]
		t.Run(name, func(t *testing.T) {
			b := testfixtures.Zip(testfixtures.ZipEntry{Name: "big", Data: content, Store: store})
			e := scan(t, b, 1).Entries[0]
			cut := b[:30+len("big")+int(e.CompressedSize)/2+20]
			got, err := zipscan.Read(bytes.NewReader(cut), int64(len(cut)), e, 1<<20)
			if !errors.Is(err, errTruncated) {
				t.Fatalf("err = %v, want truncation", err)
			}
			if len(got) == 0 || len(got) >= len(content) || !bytes.HasPrefix(content, got) {
				t.Fatalf("partial data: %d bytes (want a non-empty strict prefix)", len(got))
			}
		})
	}
}

func TestReadDoesNotInflateBombs(t *testing.T) {
	b := testfixtures.ZipHighRatio(64 << 20) // 64 MiB of zeros in about 64 KiB
	e := scan(t, b, 1).Entries[0]
	var got []byte
	var err error
	// Inflating the whole entry would allocate at least 64 MiB; a bounded read
	// must stay in the neighbourhood of the limit.
	if alloc := allocated(func() { got, err = zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 64<<10) }); alloc > 4<<20 {
		t.Fatalf("a 64 KiB bounded read allocated %d bytes", alloc)
	}
	if !errors.Is(err, zipscan.ErrTooLarge) || len(got) != 64<<10 {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	if alloc := allocated(func() { got, err = zipscan.Peek(bytes.NewReader(b), int64(len(b)), e, 16) }); alloc > 1<<20 || len(got) != 16 || err != nil {
		t.Fatalf("Peek: %d bytes, %v, allocated %d", len(got), err, alloc)
	}
}

// allocated returns how many bytes fn allocated, measured from the runtime's
// cumulative counter, which does not depend on how busy the machine is.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestReadIgnoresALyingUncompressedSize(t *testing.T) {
	b := testfixtures.Zip(testfixtures.ZipEntry{Name: "a", Data: []byte("tiny"), Store: true})
	e := scan(t, b, 1).Entries[0]
	e.UncompressedSize = 1 << 62 // must not drive an allocation
	got, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 1<<20)
	if err != nil || string(got) != "tiny" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestPeek(t *testing.T) {
	content := []byte("PK\x03\x04 nested archive magic and more bytes after it")
	b := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "stored", Data: content, Store: true},
		testfixtures.ZipEntry{Name: "deflated", Data: content},
		testfixtures.ZipEntry{Name: "short", Data: []byte("ab"), Store: true},
		testfixtures.ZipEntry{Name: "bomb", Data: make([]byte, 32<<20)},
	)
	d := scan(t, b, 10)
	tests := []struct {
		name string
		idx  int
		n    int
		want string
	}{
		{"stored", 0, 4, "PK\x03\x04"},
		{"deflated", 1, 4, "PK\x03\x04"},
		{"shorter than requested", 2, 16, "ab"},
		{"zero", 0, 0, ""},
		{"negative", 0, -1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := zipscan.Peek(bytes.NewReader(b), int64(len(b)), d.Entries[tc.idx], tc.n)
			if err != nil || string(got) != tc.want {
				t.Fatalf("Peek = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	start := time.Now()
	got, err := zipscan.Peek(bytes.NewReader(b), int64(len(b)), d.Entries[3], 8)
	if err != nil || len(got) != 8 || time.Since(start) > time.Second {
		t.Fatalf("peeking into a bomb: %d bytes, %v, %v", len(got), err, time.Since(start))
	}
	if _, err := zipscan.Peek(bytes.NewReader(b), int64(len(b)), zipscan.Entry{Method: 12}, 4); !errors.Is(err, zipscan.ErrUnsupported) {
		t.Fatalf("unsupported method: %v", err)
	}
}

func TestRecoverySkipsNestedArchives(t *testing.T) {
	inner := testfixtures.Zip(testfixtures.ZipEntry{Name: "inner.txt", Data: []byte(strings.Repeat("i", 64)), Store: true})
	outer := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "nested.zip", Data: inner, Store: true},
		// More than the end-record search window of data after the nested
		// archive, so its own end record is out of reach once the outer one is gone.
		testfixtures.ZipEntry{Name: "padding.bin", Data: bytes.Repeat([]byte{'p'}, 80<<10), Store: true},
		testfixtures.ZipEntry{Name: "after.txt", Data: []byte("after"), Store: true},
	)
	// Without the outer end record, recovery walks the local headers and must
	// step over the nested archive's descriptors and central directory.
	d := scan(t, outer[:len(outer)-22], 10)
	got := names(d)
	if len(got) != 3 || got[0] != "nested.zip" || got[1] != "padding.bin" || got[2] != "after.txt" {
		t.Fatalf("names = %v, warnings = %v", got, d.Warnings)
	}
	if !d.Recovered {
		t.Error("Recovered must be set")
	}
}

func TestRecoveryIsCheapWithDescriptorLookalikes(t *testing.T) {
	// 4 MiB of descriptor signatures inside the first entry: a million
	// candidates, none of which may cost a read or be accepted.
	bait := bytes.Repeat([]byte("PK\x07\x08"), 1<<20)
	good := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "bait.bin", Data: bait, Store: true},
		testfixtures.ZipEntry{Name: "after.txt", Data: []byte("after"), Store: true},
	)
	cut := good[:bytes.Index(good, []byte("PK\x01\x02"))] // no central directory, no end record
	start := time.Now()
	d := scan(t, cut, 10)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("recovery took %v", elapsed)
	}
	got := names(d)
	if len(got) != 2 || got[0] != "bait.bin" || got[1] != "after.txt" || d.Entries[0].CompressedSize != uint64(len(bait)) {
		t.Fatalf("names = %v, bait size = %d, warnings = %v", got, d.Entries[0].CompressedSize, d.Warnings)
	}
}

func TestScanWarnsWhenArchivesAreConcatenated(t *testing.T) {
	first := testfixtures.Zip(testfixtures.ZipEntry{Name: "first.txt", Data: []byte("1"), Store: true})
	b := testfixtures.ZipWithPrefix(first, testfixtures.ZipEntry{Name: "second.txt", Data: []byte("2"), Store: true})
	d := scan(t, b, 10)
	if d.Count != 1 || d.Entries[0].Name != "second.txt" || d.PrefixBytes != int64(len(first)) {
		t.Fatalf("count=%d names=%v prefix=%d", d.Count, names(d), d.PrefixBytes)
	}
	if !hasWarning(d, "another ZIP archive precedes this one") {
		t.Fatalf("missing warning: %v", d.Warnings)
	}
}
