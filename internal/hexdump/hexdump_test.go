package hexdump

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// seq returns n bytes 0, 1, 2, ... (wrapping at 256).
func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestWindow(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		offset    int64
		n         int
		wantRows  int // number of rows
		wantBytes int // total bytes in the rows
		wantFirst Row // first row
		wantTrunc bool
	}{
		{
			name: "one full row", data: seq(32), offset: 0, n: 16,
			wantRows: 1, wantBytes: 16,
			wantFirst: Row{Offset: 0, Hex: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", ASCII: "................", Len: 16},
		},
		{
			name: "partial last row", data: seq(32), offset: 0, n: 20,
			wantRows: 2, wantBytes: 20,
			wantFirst: Row{Offset: 0, Hex: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", ASCII: "................", Len: 16},
		},
		{
			name: "offset in the middle", data: seq(64), offset: 0x21, n: 4,
			wantRows: 1, wantBytes: 4,
			wantFirst: Row{Offset: 0x21, Hex: "21 22 23 24", ASCII: "!\"#$", Len: 4},
		},
		{
			name: "printable ASCII and DEL", data: []byte("Hi, there!\x00\x7f\x80~ A"), offset: 0, n: 16,
			wantRows: 1, wantBytes: 16,
			wantFirst: Row{Offset: 0, Hex: "48 69 2c 20 74 68 65 72 65 21 00 7f 80 7e 20 41", ASCII: "Hi, there!...~ A", Len: 16},
		},
		{
			name: "default window is 128 bytes", data: seq(300), offset: 0, n: 0,
			wantRows: 8, wantBytes: 128,
			wantFirst: Row{Offset: 0, Hex: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", ASCII: "................", Len: 16},
		},
		{
			name: "negative n means default", data: seq(300), offset: 16, n: -5,
			wantRows: 8, wantBytes: 128,
			wantFirst: Row{Offset: 16, Hex: "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f", ASCII: "................", Len: 16},
		},
		{
			name: "clamped to the end of the data", data: seq(40), offset: 30, n: 64,
			wantRows: 1, wantBytes: 10, wantTrunc: true,
			wantFirst: Row{Offset: 30, Hex: "1e 1f 20 21 22 23 24 25 26 27", ASCII: ".. !\"#$%&'", Len: 10},
		},
		{
			name: "default window clamped to a short file", data: seq(5), offset: 0, n: 0,
			wantRows: 1, wantBytes: 5, wantTrunc: true,
			wantFirst: Row{Offset: 0, Hex: "00 01 02 03 04", ASCII: ".....", Len: 5},
		},
		{
			name: "exactly the remaining bytes is not truncated", data: seq(40), offset: 30, n: 10,
			wantRows: 1, wantBytes: 10,
			wantFirst: Row{Offset: 30, Hex: "1e 1f 20 21 22 23 24 25 26 27", ASCII: ".. !\"#$%&'", Len: 10},
		},
		{
			name: "capped at MaxWindow", data: seq(MaxWindow + 100), offset: 0, n: MaxWindow * 4,
			wantRows: MaxWindow / BytesPerRow, wantBytes: MaxWindow, wantTrunc: true,
			wantFirst: Row{Offset: 0, Hex: "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", ASCII: "................", Len: 16},
		},
		{
			name: "huge n does not overflow", data: seq(100), offset: 99, n: int(^uint(0) >> 1),
			wantRows: 1, wantBytes: 1, wantTrunc: true,
			wantFirst: Row{Offset: 99, Hex: "63", ASCII: "c", Len: 1},
		},
		{
			name: "single byte data", data: []byte{0xff}, offset: 0, n: 1,
			wantRows: 1, wantBytes: 1,
			wantFirst: Row{Offset: 0, Hex: "ff", ASCII: ".", Len: 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, trunc, err := Window(tc.data, tc.offset, tc.n)
			if err != nil {
				t.Fatalf("Window: %v", err)
			}
			if len(rows) != tc.wantRows {
				t.Fatalf("got %d rows, want %d", len(rows), tc.wantRows)
			}
			total := 0
			for i, r := range rows {
				total += r.Len
				if r.Offset != tc.offset+int64(i*BytesPerRow) {
					t.Errorf("row %d offset = %#x", i, r.Offset)
				}
				if r.Len < 1 || r.Len > BytesPerRow || (i < len(rows)-1 && r.Len != BytesPerRow) {
					t.Errorf("row %d has Len %d", i, r.Len)
				}
			}
			if total != tc.wantBytes {
				t.Errorf("rows cover %d bytes, want %d", total, tc.wantBytes)
			}
			if rows[0] != tc.wantFirst {
				t.Errorf("first row = %+v, want %+v", rows[0], tc.wantFirst)
			}
			if trunc != tc.wantTrunc {
				t.Errorf("truncated = %v, want %v", trunc, tc.wantTrunc)
			}
		})
	}
}

func TestWindowErrors(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		offset int64
	}{
		{"empty data", nil, 0},
		{"empty slice", []byte{}, 0},
		{"negative offset", seq(10), -1},
		{"most negative offset", seq(10), -1 << 63},
		{"offset at the end", seq(10), 10},
		{"offset past the end", seq(10), 11},
		{"huge offset", seq(10), 1<<63 - 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, trunc, err := Window(tc.data, tc.offset, 16)
			if !errors.Is(err, ErrOffset) {
				t.Fatalf("err = %v, want ErrOffset", err)
			}
			if rows != nil || trunc {
				t.Errorf("got rows %v, truncated %v alongside an error", rows, trunc)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	data := []byte("The quick brown fox jumps over")
	rows, _, err := Window(data, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "0000000000  54 68 65 20 71 75 69 63 6b 20 62 72 6f 77 6e 20  |The quick brown |\n" +
		"0000000010  66 6f 78 20 6a 75 6d 70 73 20 6f 76 65 72" + strings.Repeat(" ", 6) + "  |fox jumps over|\n"
	if got := Format(rows); got != want {
		t.Errorf("Format =\n%q\nwant\n%q", got, want)
	}

	code := []byte{0x48, 0x8b, 0x4c, 0x24, 0x08, 0x48, 0x89, 0xc8, 0xc3}
	rows, _, err = Window(append(make([]byte, 0x1a40), code...), 0x1a40, 128)
	if err != nil {
		t.Fatal(err)
	}
	want = "0000001a40  48 8b 4c 24 08 48 89 c8 c3" + strings.Repeat(" ", 21) + "  |H.L$.H...|\n"
	if got := Format(rows); got != want {
		t.Errorf("Format =\n%q\nwant\n%q", got, want)
	}

	if got := Format(nil); got != "" {
		t.Errorf("Format(nil) = %q", got)
	}
}

func TestFormatWideOffsetAndHostileRows(t *testing.T) {
	rows := []Row{{Offset: 0x123456789abc, Hex: "41\x1b 42", ASCII: "A\x1b\nB", Len: 2}}
	got := Format(rows)
	want := "123456789abc  41 42" + strings.Repeat(" ", 47-5) + "  |A..B|\n"
	if got != want {
		t.Errorf("Format =\n%q\nwant\n%q", got, want)
	}
	for _, c := range []byte(got) {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			t.Fatalf("control character %#x in output", c)
		}
	}
}

// FuzzWindow checks the invariants of Window and Format for arbitrary input.
func FuzzWindow(f *testing.F) {
	f.Add([]byte("hello world"), int64(0), 0)
	f.Add(seq(300), int64(17), 100)
	f.Add(seq(5000), int64(1), 1<<20)
	f.Add([]byte{}, int64(0), 16)
	f.Add([]byte{1}, int64(-1), -1)
	f.Add([]byte{1, 2, 3}, int64(1<<62), 1)
	f.Fuzz(func(t *testing.T, data []byte, offset int64, n int) {
		rows, trunc, err := Window(data, offset, n)
		if err != nil {
			if !errors.Is(err, ErrOffset) || rows != nil || trunc {
				t.Fatalf("bad error result: %v %v %v", err, rows, trunc)
			}
			if offset >= 0 && offset < int64(len(data)) {
				t.Fatalf("valid offset %d rejected for %d bytes", offset, len(data))
			}
			return
		}
		if offset < 0 || offset >= int64(len(data)) {
			t.Fatalf("invalid offset %d accepted for %d bytes", offset, len(data))
		}
		want := n
		if want <= 0 {
			want = DefaultWindow
		}
		wantBytes := min(want, MaxWindow, len(data)-int(offset))
		if trunc != (wantBytes < want) {
			t.Fatalf("truncated = %v, requested %d, returned %d", trunc, want, wantBytes)
		}
		var covered []byte
		for i, r := range rows {
			if r.Len < 1 || r.Len > BytesPerRow || (i < len(rows)-1 && r.Len != BytesPerRow) {
				t.Fatalf("row %d: Len %d", i, r.Len)
			}
			if r.Offset != offset+int64(i*BytesPerRow) {
				t.Fatalf("row %d: offset %d", i, r.Offset)
			}
			if len(r.ASCII) != r.Len || len(r.Hex) != r.Len*3-1 {
				t.Fatalf("row %d: Hex %q ASCII %q for Len %d", i, r.Hex, r.ASCII, r.Len)
			}
			for j := 0; j < len(r.ASCII); j++ {
				if c := r.ASCII[j]; c < 0x20 || c > 0x7e {
					t.Fatalf("row %d: non-printable %#x in ASCII column", i, c)
				}
			}
			start := int(offset) + i*BytesPerRow
			chunk := data[start : start+r.Len]
			covered = append(covered, chunk...)
			var back []byte
			for _, field := range strings.Fields(r.Hex) {
				var v byte
				for _, c := range []byte(field) {
					v = v<<4 | byte(strings.IndexByte("0123456789abcdef", c))
				}
				back = append(back, v)
			}
			if !bytes.Equal(back, chunk) {
				t.Fatalf("row %d: Hex %q does not match the data % x", i, r.Hex, chunk)
			}
		}
		if len(covered) != wantBytes {
			t.Fatalf("rows cover %d bytes, want %d", len(covered), wantBytes)
		}
		text := Format(rows)
		if strings.Count(text, "\n") != len(rows) {
			t.Fatalf("Format produced %d lines for %d rows", strings.Count(text, "\n"), len(rows))
		}
		for _, c := range []byte(text) {
			if c != '\n' && (c < 0x20 || c > 0x7e) {
				t.Fatalf("control character %#x in Format output", c)
			}
		}
	})
}
