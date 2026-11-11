package testfixtures

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"testing"
)

// zipOpen opens b with the standard library, tolerating the insecure-path
// notice that deliberately unsafe fixtures trigger.
func zipOpen(t *testing.T, b []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		t.Fatalf("archive/zip rejected the fixture: %v", err)
	}
	return zr
}

func zipReadAll(t *testing.T, f *zip.File) []byte {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("open %q: %v", f.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %q: %v", f.Name, err)
	}
	return data
}

func TestZip_RoundTripAndMethods(t *testing.T) {
	entries := []ZipEntry{
		{Name: "a.txt", Data: []byte("alpha"), Store: true},
		{Name: "dir/b.txt", Data: bytes.Repeat([]byte("beta "), 100)},
		{Name: "empty", Store: true},
	}
	zr := zipOpen(t, Zip(entries...))
	if len(zr.File) != len(entries) {
		t.Fatalf("entries = %d, want %d", len(zr.File), len(entries))
	}
	for i, e := range entries {
		f := zr.File[i]
		if f.Name != e.Name {
			t.Errorf("entry %d name = %q, want %q", i, f.Name, e.Name)
		}
		if got := zipReadAll(t, f); !bytes.Equal(got, e.Data) {
			t.Errorf("entry %q content differs", e.Name)
		}
		wantMethod := zip.Deflate
		if e.Store {
			wantMethod = zip.Store
		}
		if f.Method != wantMethod {
			t.Errorf("entry %q method = %d, want %d", e.Name, f.Method, wantMethod)
		}
	}
}

func TestZip_IsDeterministic(t *testing.T) {
	a := Zip(ZipEntry{Name: "x", Data: []byte("data"), Store: true})
	b := Zip(ZipEntry{Name: "x", Data: []byte("data"), Store: true})
	if !bytes.Equal(a, b) {
		t.Fatal("Zip must be deterministic")
	}
}

func TestZip_SlipNames(t *testing.T) {
	zr := zipOpen(t, ZipSlip())
	want := []string{
		"docs/readme.txt", "../../evil.sh", `..\..\Windows\Temp\evil.dll`, "/etc/cron.d/backdoor",
		`C:\Users\Public\evil.exe`, `\\attacker\share\evil.lnk`, "nested/../../escape.txt", "ok.txt\x00../../hidden",
	}
	if len(zr.File) != len(want) {
		t.Fatalf("entries = %d, want %d", len(zr.File), len(want))
	}
	for i, name := range want {
		if zr.File[i].Name != name {
			t.Errorf("entry %d = %q, want %q", i, zr.File[i].Name, name)
		}
	}
}

func TestZip_HighRatio(t *testing.T) {
	zr := zipOpen(t, ZipHighRatio(1<<20))
	f := zr.File[0]
	if f.UncompressedSize64 != 1<<20 {
		t.Fatalf("uncompressed = %d", f.UncompressedSize64)
	}
	if ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64); ratio < 500 {
		t.Fatalf("ratio = %.0f, want a bomb-like value", ratio)
	}
}

func TestZip_WithPrefixIsStillReadable(t *testing.T) {
	prefix := bytes.Repeat([]byte("MZ stub "), 64)
	b := ZipWithPrefix(prefix, ZipEntry{Name: "in.txt", Data: []byte("inside"), Store: true})
	if !bytes.HasPrefix(b, prefix) {
		t.Fatal("prefix missing")
	}
	zr := zipOpen(t, b)
	if got := zipReadAll(t, zr.File[0]); string(got) != "inside" {
		t.Fatalf("content = %q", got)
	}
}

func TestZip_TruncatedEOCDIsRejectedByTheStandardLibrary(t *testing.T) {
	b := ZipTruncatedEOCD(ZipEntry{Name: "a", Data: []byte("a"), Store: true})
	if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("a zip without an end record must not open")
	}
	if !bytes.Contains(b, []byte("PK\x01\x02")) {
		t.Fatal("the central directory must still be present")
	}
}

func TestZip_OverlappingEntriesShareData(t *testing.T) {
	zr := zipOpen(t, ZipOverlapping())
	if len(zr.File) != 3 {
		t.Fatalf("entries = %d", len(zr.File))
	}
	first, err := zr.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	last, err := zr.File[2].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	if first != last {
		t.Fatalf("offsets %d and %d must coincide", first, last)
	}
}

func TestZip_DuplicateNames(t *testing.T) {
	zr := zipOpen(t, ZipDuplicateNames())
	seen := map[string]int{}
	for _, f := range zr.File {
		seen[f.Name]++
	}
	if seen["same.txt"] != 2 || seen["other.txt"] != 1 {
		t.Fatalf("names = %v", seen)
	}
}

func TestZip_ManyUsesZip64Records(t *testing.T) {
	b := ZipMany(70000)
	zr := zipOpen(t, b)
	if len(zr.File) != 70000 {
		t.Fatalf("entries = %d", len(zr.File))
	}
	if !bytes.Contains(b[len(b)-200:], []byte("PK\x06\x06")) {
		t.Fatal("expected a ZIP64 end-of-central-directory record")
	}
}

func TestZip_Zip64Tail(t *testing.T) {
	entries := []ZipEntry{{Name: "one", Data: []byte("1"), Store: true}, {Name: "two", Data: []byte("22"), Store: true}}
	honest := Zip64(2, entries...)
	zr := zipOpen(t, honest)
	if len(zr.File) != 2 || zr.File[1].Name != "two" {
		t.Fatalf("honest ZIP64 archive misread: %d entries", len(zr.File))
	}
	liar := Zip64(1<<40, entries...)
	if _, err := zip.NewReader(bytes.NewReader(liar), int64(len(liar))); err == nil {
		t.Fatal("the standard library must reject an impossible declared count")
	}
}
