package zipscan_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/testfixtures"
	"github.com/q6r/teardown/internal/zipscan"
)

func scan(t *testing.T, b []byte, maxEntries int) *zipscan.Directory {
	t.Helper()
	d, err := zipscan.Scan(context.Background(), bytes.NewReader(b), int64(len(b)), maxEntries)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return d
}

func names(d *zipscan.Directory) []string {
	out := make([]string, len(d.Entries))
	for i, e := range d.Entries {
		out[i] = e.Name
	}
	return out
}

func store(name, data string) testfixtures.ZipEntry {
	return testfixtures.ZipEntry{Name: name, Data: []byte(data), Store: true}
}

func hasWarning(d *zipscan.Directory, substr string) bool {
	for _, w := range d.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// stdlibZip builds an archive with the standard library, optionally with a comment.
func stdlibZip(t *testing.T, comment string, entries ...testfixtures.ZipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if comment != "" {
		if err := zw.SetComment(comment); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range entries {
		method := zip.Deflate
		if e.Store {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.Name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanAgreesWithStandardLibrary(t *testing.T) {
	entries := []testfixtures.ZipEntry{
		{Name: "a.txt", Data: []byte("alpha")},
		{Name: "dir/", Store: true},
		{Name: "dir/b.bin", Data: bytes.Repeat([]byte{1, 2, 3, 4}, 5000)},
		store("c.txt", "stored content"),
		{Name: "unicode/ação-日本.txt", Data: []byte("utf8")},
		{Name: "empty.txt", Store: true},
	}
	b := testfixtures.Zip(entries...)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	d := scan(t, b, 100)
	if d.Count != len(zr.File) || len(d.Entries) != len(zr.File) {
		t.Fatalf("count = %d/%d, want %d", d.Count, len(d.Entries), len(zr.File))
	}
	var comp, uncomp uint64
	for i, f := range zr.File {
		e := d.Entries[i]
		if e.Name != f.Name || e.Method != f.Method || e.CRC32 != f.CRC32 ||
			e.CompressedSize != f.CompressedSize64 || e.UncompressedSize != f.UncompressedSize64 {
			t.Errorf("entry %d: got %+v, want %+v", i, e, f.FileHeader)
		}
		if e.IsDir != f.FileInfo().IsDir() {
			t.Errorf("entry %q IsDir = %v", e.Name, e.IsDir)
		}
		comp += f.CompressedSize64
		uncomp += f.UncompressedSize64
		if e.IsDir {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := io.ReadAll(rc)
		rc.Close()
		got, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 1<<20)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("Read(%q) = %d bytes, %v; want %d bytes", e.Name, len(got), err, len(want))
		}
	}
	if d.TotalCompressed != comp || d.TotalUncompressed != uncomp {
		t.Errorf("totals = %d/%d, want %d/%d", d.TotalCompressed, d.TotalUncompressed, comp, uncomp)
	}
	if d.Truncated || d.Recovered || d.PrefixBytes != 0 || d.Zip64 || len(d.Warnings) != 0 {
		t.Errorf("clean archive reported anomalies: %+v", d)
	}
	if e, ok := d.Find("c.txt"); !ok || e.Method != 0 {
		t.Errorf("Find(c.txt) = %+v, %v", e, ok)
	}
	if _, ok := d.Find("missing"); ok {
		t.Error("Find must not invent entries")
	}
}

// randomArchive builds a seeded, varied archive with the standard library: stored
// and deflated entries, directories, non-ASCII names, empty entries and a comment.
func randomArchive(t *testing.T, rng *rand.Rand) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if rng.IntN(3) == 0 {
		if err := zw.SetComment(strings.Repeat("c", rng.IntN(200))); err != nil {
			t.Fatal(err)
		}
	}
	alphabet := []string{"a", "b", "dir", "é", "日本", "x-y", "_", "0"}
	for range rng.IntN(40) {
		var name strings.Builder
		for range 1 + rng.IntN(4) {
			name.WriteString(alphabet[rng.IntN(len(alphabet))])
			name.WriteByte('/')
		}
		n := strings.TrimSuffix(name.String(), "/")
		if rng.IntN(6) == 0 {
			n += "/"
		}
		hdr := &zip.FileHeader{Name: n, Method: zip.Deflate}
		if rng.IntN(3) == 0 {
			hdr.Method = zip.Store
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(n, "/") {
			data := make([]byte, rng.IntN(3000))
			for i := range data {
				data[i] = byte(rng.IntN(1 + rng.IntN(255)))
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanMatchesStandardLibraryOnRandomArchives(t *testing.T) {
	rng := rand.New(rand.NewPCG(20260110, 7))
	for i := range 150 {
		b := randomArchive(t, rng)
		if prefix := rng.IntN(3); prefix == 0 {
			b = append(bytes.Repeat([]byte{0xAB}, rng.IntN(500)), b...)
		}
		zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatalf("archive %d: the standard library rejected its own writer's output: %v", i, err)
		}
		d := scan(t, b, 1000)
		if d.Count != len(zr.File) || len(d.Warnings) != 0 || d.Recovered {
			t.Fatalf("archive %d: count=%d want %d warnings=%v", i, d.Count, len(zr.File), d.Warnings)
		}
		for j, f := range zr.File {
			e := d.Entries[j]
			if e.Name != f.Name || e.Method != f.Method || e.CRC32 != f.CRC32 ||
				e.CompressedSize != f.CompressedSize64 || e.UncompressedSize != f.UncompressedSize64 {
				t.Fatalf("archive %d entry %d: got %+v, want %+v", i, j, e, f.FileHeader)
			}
			if e.IsDir {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			want, _ := io.ReadAll(rc)
			rc.Close()
			got, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 1<<20)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("archive %d entry %q: Read = %d bytes, %v; want %d bytes", i, e.Name, len(got), err, len(want))
			}
		}
	}
}

func TestScanTable(t *testing.T) {
	two := []testfixtures.ZipEntry{store("one", "1"), store("two", "22")}
	tests := []struct {
		name  string
		input []byte
		max   int
		check func(t *testing.T, d *zipscan.Directory)
	}{
		{"empty archive", testfixtures.Zip(), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 0 || len(d.Entries) != 0 || d.Truncated {
				t.Fatalf("%+v", d)
			}
		}},
		{"comment", stdlibZip(t, "built by tests", two...), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Comment != "built by tests" || d.Count != 2 {
				t.Fatalf("comment=%q count=%d", d.Comment, d.Count)
			}
		}},
		{"comment with control characters is escaped", stdlibZip(t, "a\x1b[31mb", two...), 10, func(t *testing.T, d *zipscan.Directory) {
			if strings.ContainsRune(d.Comment, 0x1b) {
				t.Fatalf("comment still contains ESC: %q", d.Comment)
			}
		}},
		{"self-extractor prefix", testfixtures.ZipWithPrefix(bytes.Repeat([]byte("MZ"), 300), two...), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.PrefixBytes != 600 || d.Count != 2 || d.BadOffsets != 0 {
				t.Fatalf("prefix=%d count=%d bad=%d warnings=%v", d.PrefixBytes, d.Count, d.BadOffsets, d.Warnings)
			}
		}},
		{"zip64 end records", testfixtures.Zip64(2, two...), 10, func(t *testing.T, d *zipscan.Directory) {
			if !d.Zip64 || d.Count != 2 || len(d.Warnings) != 0 {
				t.Fatalf("zip64=%v count=%d warnings=%v", d.Zip64, d.Count, d.Warnings)
			}
		}},
		{"zip64 declaring an absurd count", testfixtures.Zip64(1<<40, two...), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 2 || !hasWarning(d, "declares") {
				t.Fatalf("count=%d warnings=%v", d.Count, d.Warnings)
			}
		}},
		{"entry cap keeps true counts", testfixtures.ZipMany(300), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 300 || len(d.Entries) != 10 || !d.Truncated {
				t.Fatalf("count=%d kept=%d truncated=%v", d.Count, len(d.Entries), d.Truncated)
			}
		}},
		{"zero cap retains nothing", testfixtures.ZipMany(5), 0, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 5 || len(d.Entries) != 0 || !d.Truncated {
				t.Fatalf("%+v", d)
			}
		}},
		{"negative cap retains nothing", testfixtures.ZipMany(5), -3, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 5 || len(d.Entries) != 0 {
				t.Fatalf("%+v", d)
			}
		}},
		{"more than 65535 entries (zip64 written by the standard library)", testfixtures.ZipMany(70000), 5, func(t *testing.T, d *zipscan.Directory) {
			if d.Count != 70000 || !d.Zip64 {
				t.Fatalf("count=%d zip64=%v warnings=%v", d.Count, d.Zip64, d.Warnings)
			}
		}},
		{"overlapping entries", testfixtures.ZipOverlapping(), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Overlapping < 1 || d.Count != 3 {
				t.Fatalf("overlapping=%d count=%d", d.Overlapping, d.Count)
			}
		}},
		{"duplicate names", testfixtures.ZipDuplicateNames(), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.Duplicates != 1 || d.Overlapping != 0 {
				t.Fatalf("dups=%d overlapping=%d", d.Duplicates, d.Overlapping)
			}
		}},
		{"high compression ratio", testfixtures.ZipHighRatio(4 << 20), 10, func(t *testing.T, d *zipscan.Directory) {
			if d.MaxRatio < 1000 || d.MaxRatioEntry != "zeros.bin" {
				t.Fatalf("ratio=%v entry=%q", d.MaxRatio, d.MaxRatioEntry)
			}
		}},
		{"hostile names keep the raw form and escape the printable one", testfixtures.ZipSlip(), 20, func(t *testing.T, d *zipscan.Directory) {
			var nul zipscan.Entry
			for _, e := range d.Entries {
				if strings.HasPrefix(e.RawName, "ok.txt") {
					nul = e
				}
			}
			if nul.RawName != "ok.txt\x00../../hidden" || nul.Name != `ok.txt\x00../../hidden` {
				t.Fatalf("raw=%q name=%q", nul.RawName, nul.Name)
			}
			if d.Count != 8 {
				t.Fatalf("count = %d", d.Count)
			}
		}},
		{"no sizes lost without a descriptor", testfixtures.Zip(testfixtures.ZipEntry{Name: "d/", Store: true}), 10, func(t *testing.T, d *zipscan.Directory) {
			if !d.Entries[0].IsDir {
				t.Fatalf("%+v", d.Entries[0])
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, scan(t, tc.input, tc.max)) })
	}
}

func TestScanSkipsFakeEndRecordsInTheComment(t *testing.T) {
	entries := []testfixtures.ZipEntry{store("real.txt", "payload"), store("other.txt", "more")}
	// A fake end record claiming an empty archive, hidden in the comment, must
	// not hide the real directory (a parser trusting it would see no entries).
	fake := "PK\x05\x06" + strings.Repeat("\x00", 18)
	d := scan(t, stdlibZip(t, fake, entries...), 10)
	if d.Count != 2 || d.Entries[0].Name != "real.txt" {
		t.Fatalf("count=%d names=%v", d.Count, names(d))
	}
}

func TestScanWarnsAboutAmbiguousEndRecords(t *testing.T) {
	entries := []testfixtures.ZipEntry{store("real.txt", "payload")}
	plain := stdlibZip(t, "", entries...)
	// A second, valid end record hidden in the comment of the first one points
	// at the same directory: harmless here, but tools may disagree in general.
	eocd := len(plain) - 22
	lookalike := make([]byte, 22)
	copy(lookalike, "PK\x05\x06")
	copy(lookalike[8:], plain[eocd+8:eocd+20]) // entry counts, directory size
	copy(lookalike[16:], plain[eocd+16:eocd+20])
	d := scan(t, stdlibZip(t, string(lookalike), entries...), 10)
	if d.Count != 1 || d.Entries[0].Name != "real.txt" {
		t.Fatalf("count=%d names=%v", d.Count, names(d))
	}
	if !hasWarning(d, "end-of-central-directory records found") {
		t.Fatalf("missing ambiguity warning: %v", d.Warnings)
	}
}

func TestScanRecoversFromDamagedArchives(t *testing.T) {
	entries := []testfixtures.ZipEntry{
		store("first.txt", strings.Repeat("a", 100)),
		{Name: "second.txt", Data: bytes.Repeat([]byte("b"), 400)},
		store("third.txt", strings.Repeat("c", 50)),
	}
	good := testfixtures.Zip(entries...)
	cdStart := bytes.Index(good, []byte("PK\x01\x02"))

	tests := []struct {
		name      string
		input     []byte
		wantNames []string
		wantWarn  string
	}{
		{"truncated end record", testfixtures.ZipTruncatedEOCD(entries...), []string{"first.txt", "second.txt", "third.txt"}, "central directory was found by scanning"},
		{"end record removed entirely", good[:len(good)-22], []string{"first.txt", "second.txt", "third.txt"}, "central directory was found by scanning"},
		{"cut inside the central directory", good[:cdStart+60], []string{"first.txt"}, ""},
		{"cut inside the entry data, descriptors located", good[:cdStart-20], []string{"first.txt", "second.txt"}, "recovered from local headers"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := scan(t, tc.input, 10)
			if !d.Recovered {
				t.Errorf("Recovered = false; warnings = %v", d.Warnings)
			}
			got := names(d)
			if len(got) < len(tc.wantNames) {
				t.Fatalf("names = %v, want at least %v (warnings %v)", got, tc.wantNames, d.Warnings)
			}
			for i, n := range tc.wantNames {
				if got[i] != n {
					t.Errorf("name %d = %q, want %q", i, got[i], n)
				}
			}
			if tc.wantWarn != "" && !hasWarning(d, tc.wantWarn) {
				t.Errorf("warnings %v lack %q", d.Warnings, tc.wantWarn)
			}
			if len(d.Warnings) == 0 {
				t.Error("a damaged archive must come with a warning")
			}
		})
	}
}

func TestScanRejectsNonArchives(t *testing.T) {
	tests := map[string][]byte{
		"empty":          {},
		"too small":      []byte("PK"),
		"text":           []byte(strings.Repeat("just some text, nothing to see here\n", 20)),
		"zeros":          make([]byte, 4096),
		"png magic":      append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...),
		"only a comment": []byte(strings.Repeat("x", 65536)),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			d, err := zipscan.Scan(context.Background(), bytes.NewReader(input), int64(len(input)), 10)
			if !errors.Is(err, zipscan.ErrNotZip) || d != nil {
				t.Fatalf("got %+v, %v; want ErrNotZip", d, err)
			}
		})
	}
}

func TestScanCountsBadOffsets(t *testing.T) {
	b := testfixtures.Zip(store("a", "1"), store("b", "2"))
	second := bytes.LastIndex(b, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint32(b[second+42:], 0x7FFFFFF0)
	d := scan(t, b, 10)
	if d.BadOffsets != 1 || d.Count != 2 {
		t.Fatalf("bad=%d count=%d", d.BadOffsets, d.Count)
	}
	if _, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), d.Entries[1], 100); !errors.Is(err, errTruncated) {
		t.Fatalf("Read of an out-of-range entry: %v", err)
	}
}

func TestWalkVisitsEveryRecord(t *testing.T) {
	b := testfixtures.ZipMany(3000)
	var visited int
	var last string
	d, err := zipscan.Walk(context.Background(), bytes.NewReader(b), int64(len(b)), 10, func(e zipscan.Entry) {
		visited++
		last = e.RawName
	})
	if err != nil {
		t.Fatal(err)
	}
	if visited != 3000 || d.Count != 3000 || len(d.Entries) != 10 || last != "f002999" {
		t.Fatalf("visited=%d count=%d kept=%d last=%q", visited, d.Count, len(d.Entries), last)
	}
}

func TestScanHonoursCancellation(t *testing.T) {
	b := testfixtures.ZipMany(5000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := zipscan.Scan(ctx, bytes.NewReader(b), int64(len(b)), 10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if d == nil || d.Count == 5000 {
		t.Fatalf("a cancelled scan must return a partial directory, got %+v", d)
	}
}

func TestScanSurfacesReadErrors(t *testing.T) {
	boom := errors.New("disk on fire")
	if _, err := zipscan.Scan(context.Background(), failingReader{boom}, 1000, 10); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

type failingReader struct{ err error }

func (f failingReader) ReadAt([]byte, int64) (int, error) { return 0, f.err }

// handZip64 builds, by hand, an archive whose only record keeps its sizes and
// local offset in the ZIP64 extra field (sentinel values in the fixed header).
func handZip64(name string, data []byte, prefix int) []byte {
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0xAA}, prefix))
	localOff := b.Len()
	le := binary.LittleEndian
	local := make([]byte, 30)
	le.PutUint32(local, 0x04034b50)
	le.PutUint16(local[4:], 45)
	le.PutUint32(local[18:], uint32(len(data)))
	le.PutUint32(local[22:], uint32(len(data)))
	le.PutUint16(local[26:], uint16(len(name)))
	b.Write(local)
	b.WriteString(name)
	b.Write(data)

	cdStart := b.Len()
	extra := make([]byte, 4+24)
	le.PutUint16(extra, 0x0001)
	le.PutUint16(extra[2:], 24)
	le.PutUint64(extra[4:], uint64(len(data)))
	le.PutUint64(extra[12:], uint64(len(data)))
	le.PutUint64(extra[20:], uint64(localOff-prefix))
	cd := make([]byte, 46)
	le.PutUint32(cd, 0x02014b50)
	le.PutUint16(cd[4:], 45)
	le.PutUint16(cd[6:], 45)
	le.PutUint32(cd[16:], 0)
	le.PutUint32(cd[20:], 0xFFFFFFFF)
	le.PutUint32(cd[24:], 0xFFFFFFFF)
	le.PutUint16(cd[28:], uint16(len(name)))
	le.PutUint16(cd[30:], uint16(len(extra)))
	le.PutUint32(cd[42:], 0xFFFFFFFF)
	b.Write(cd)
	b.WriteString(name)
	b.Write(extra)
	cdSize := b.Len() - cdStart

	end64Off := b.Len()
	rec := make([]byte, 56)
	copy(rec, "PK\x06\x06")
	le.PutUint64(rec[4:], 44)
	le.PutUint64(rec[24:], 1)
	le.PutUint64(rec[32:], 1)
	le.PutUint64(rec[40:], uint64(cdSize))
	le.PutUint64(rec[48:], uint64(cdStart-prefix))
	b.Write(rec)
	loc := make([]byte, 20)
	copy(loc, "PK\x06\x07")
	le.PutUint64(loc[8:], uint64(end64Off-prefix))
	le.PutUint32(loc[16:], 1)
	b.Write(loc)
	end := make([]byte, 22)
	copy(end, "PK\x05\x06")
	le.PutUint16(end[8:], 0xFFFF)
	le.PutUint16(end[10:], 0xFFFF)
	le.PutUint32(end[12:], 0xFFFFFFFF)
	le.PutUint32(end[16:], 0xFFFFFFFF)
	b.Write(end)
	return b.Bytes()
}

func TestScanReadsZip64ExtraFields(t *testing.T) {
	data := []byte("zip64 payload")
	for _, prefix := range []int{0, 37} {
		t.Run(fmt.Sprintf("prefix %d", prefix), func(t *testing.T) {
			b := handZip64("big.bin", data, prefix)
			d := scan(t, b, 10)
			if !d.Zip64 || d.Count != 1 {
				t.Fatalf("zip64=%v count=%d warnings=%v", d.Zip64, d.Count, d.Warnings)
			}
			e := d.Entries[0]
			if e.UncompressedSize != uint64(len(data)) || e.CompressedSize != uint64(len(data)) || e.LocalOffset != int64(prefix) {
				t.Fatalf("entry = %+v", e)
			}
			if d.PrefixBytes != int64(prefix) {
				t.Fatalf("PrefixBytes = %d", d.PrefixBytes)
			}
			got, err := zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 100)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("Read = %q, %v", got, err)
			}
		})
	}
}

func TestScanWithTrickyPrefixKeepsCentralDirectoryReadable(t *testing.T) {
	// A prefix that itself contains a lone end-record signature must not confuse the search.
	prefix := append([]byte("stub PK\x05\x06 stub"), make([]byte, 100)...)
	b := testfixtures.ZipWithPrefix(prefix, store("x", "1"))
	d := scan(t, b, 10)
	if d.Count != 1 || d.Entries[0].Name != "x" || d.PrefixBytes != int64(len(prefix)) {
		t.Fatalf("count=%d prefix=%d warnings=%v", d.Count, d.PrefixBytes, d.Warnings)
	}
}

func TestScanIsFastOnLargeDirectories(t *testing.T) {
	b := testfixtures.ZipMany(70000)
	start := time.Now()
	scan(t, b, 100)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("scanning 70000 entries took %v", elapsed)
	}
}

// sweepInputs are the archives used by the robustness sweeps.
func sweepInputs() map[string][]byte {
	return map[string][]byte{
		"plain":       testfixtures.Zip(store("a.txt", "alpha"), testfixtures.ZipEntry{Name: "b.bin", Data: bytes.Repeat([]byte{7}, 300)}),
		"zip64":       testfixtures.Zip64(2, store("one", "1"), store("two", "2")),
		"prefix":      testfixtures.ZipWithPrefix([]byte("MZ stub"), store("x", "1")),
		"overlapping": testfixtures.ZipOverlapping(),
		"hand zip64":  handZip64("n", []byte("d"), 5),
		"slip":        testfixtures.ZipSlip(),
	}
}

func TestScanNeverPanics(t *testing.T) {
	for name, input := range sweepInputs() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			run := func(b []byte) {
				d, err := zipscan.Walk(ctx, bytes.NewReader(b), int64(len(b)), 8, func(zipscan.Entry) {})
				if err == nil && d == nil {
					t.Fatal("nil directory without an error")
				}
				if d != nil {
					for _, e := range d.Entries {
						_, _ = zipscan.Read(bytes.NewReader(b), int64(len(b)), e, 1<<16)
						_, _ = zipscan.Peek(bytes.NewReader(b), int64(len(b)), e, 8)
					}
				}
			}
			for n := 0; n <= len(input); n++ {
				if n > 4096 && n%97 != 0 {
					continue
				}
				run(input[:n])
			}
			for i := 0; i < min(512, len(input)); i++ {
				for _, v := range []byte{0x00, 0xFF, 0x80} {
					mutated := bytes.Clone(input)
					mutated[i] = v
					run(mutated)
				}
			}
		})
	}
}
