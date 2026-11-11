package binio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadAt(t *testing.T) {
	data := []byte("0123456789")
	r := bytes.NewReader(data)
	size := int64(len(data))
	tests := []struct {
		name    string
		off, n  int64
		want    string
		wantErr error
	}{
		{"start", 0, 4, "0123", nil},
		{"middle", 3, 3, "345", nil},
		{"exact end", 6, 4, "6789", nil},
		{"empty at end", 10, 0, "", nil},
		{"past end", 8, 5, "", ErrTruncated},
		{"negative offset", -1, 2, "", ErrTruncated},
		{"negative length", 2, -1, "", ErrTruncated},
		{"offset past size", 11, 0, "", ErrTruncated},
		{"overflow length", 1, 1 << 62, "", ErrTruncated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadAt(r, size, tc.off, tc.n)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

type failingReaderAt struct{ err error }

func (f failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, f.err }

func TestReadAtPropagatesIOErrorAndShortReads(t *testing.T) {
	boom := errors.New("boom")
	if _, err := ReadAt(failingReaderAt{boom}, 100, 0, 10); !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	// The source claims 100 bytes but only has 4: a lying size must not hang or panic.
	if _, err := ReadAt(bytes.NewReader([]byte("abcd")), 100, 0, 10); !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated for a short source, got %v", err)
	}
}

func TestReadUpTo(t *testing.T) {
	r := bytes.NewReader([]byte("abcdef"))
	tests := []struct {
		off, n int64
		want   string
	}{
		{0, 3, "abc"},
		{4, 100, "ef"},
		{6, 4, ""},
		{-2, 4, ""},
		{2, 0, ""},
	}
	for _, tc := range tests {
		got, err := ReadUpTo(r, 6, tc.off, tc.n)
		if err != nil || string(got) != tc.want {
			t.Errorf("ReadUpTo(%d,%d) = %q, %v; want %q", tc.off, tc.n, got, err, tc.want)
		}
	}
}

func TestCString(t *testing.T) {
	long := strings.Repeat("a", 300)
	tests := []struct {
		name    string
		data    string
		off     int64
		max     int
		want    string
		wantErr error
	}{
		{"simple", "hello\x00world", 0, 64, "hello", nil},
		{"offset", "hello\x00world\x00", 6, 64, "world", nil},
		{"empty", "\x00abc", 0, 64, "", nil},
		{"no terminator at eof", "abc", 0, 64, "abc", ErrTruncated},
		{"capped", long + "\x00", 0, 10, strings.Repeat("a", 10), nil},
		{"spans chunks", long + "\x00tail", 0, 1000, long, nil},
		{"offset out of range", "abc", 5, 64, "", ErrTruncated},
		{"zero max", "abc", 0, 0, "", ErrTruncated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.data)
			got, err := CString(r, int64(len(tc.data)), tc.off, tc.max)
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Fatalf("got %q, %v; want %q, %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestCursorLittleEndianAndStickyError(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	c := NewCursor(b, binary.LittleEndian)
	if got := c.U8(); got != 0x01 {
		t.Errorf("U8 = %#x", got)
	}
	if got := c.U16(); got != 0x0302 {
		t.Errorf("U16 = %#x", got)
	}
	if got := c.U32(); got != 0x07060504 {
		t.Errorf("U32 = %#x", got)
	}
	if c.Pos() != 7 || c.Remaining() != 8 {
		t.Errorf("Pos/Remaining = %d/%d", c.Pos(), c.Remaining())
	}
	if got := c.U64(); got != 0x0f0e0d0c0b0a0908 {
		t.Errorf("U64 = %#x", got)
	}
	if c.Err() != nil {
		t.Fatalf("unexpected error %v", c.Err())
	}
	// Reading past the end sets the sticky error and yields zeros forever after.
	if c.U32() != 0 || !errors.Is(c.Err(), ErrTruncated) {
		t.Fatal("over-read must return 0 and set ErrTruncated")
	}
	c.Seek(0)
	if c.U8() != 0 || c.Bytes(1) != nil {
		t.Fatal("cursor must stay failed after an error")
	}
}

func TestCursorBigEndianSeekSkipBytes(t *testing.T) {
	c := NewCursor([]byte{0, 1, 0, 0, 0, 2, 9, 9, 9}, binary.BigEndian)
	if c.U16() != 1 || c.U32() != 2 {
		t.Fatal("big-endian decode failed")
	}
	c.Skip(1)
	if got := c.Bytes(2); !bytes.Equal(got, []byte{9, 9}) {
		t.Fatalf("Bytes = %v", got)
	}
	if cap(c.Bytes(0)) != 0 && c.Err() != nil {
		t.Fatal("zero-length read must not fail")
	}
	c.Seek(100)
	if !errors.Is(c.Err(), ErrTruncated) {
		t.Fatal("Seek out of range must set the error")
	}

	neg := NewCursor([]byte{1, 2, 3}, binary.LittleEndian)
	neg.Skip(-1)
	if !errors.Is(neg.Err(), ErrTruncated) {
		t.Fatal("negative skip must set the error")
	}
}

func TestCursorCString(t *testing.T) {
	c := NewCursor([]byte("ab\x00cd"), binary.LittleEndian)
	if got := c.CString(); got != "ab" {
		t.Errorf("first = %q", got)
	}
	if got := c.CString(); got != "cd" || !errors.Is(c.Err(), ErrTruncated) {
		t.Errorf("unterminated = %q, err %v", got, c.Err())
	}
	if c.CString() != "" {
		t.Error("failed cursor must return empty strings")
	}
}

func TestPrintable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain", "hello", 0, "hello"},
		{"unicode kept", "café ✓", 0, "café ✓"},
		{"escape sequence neutralised", "\x1b[31mred\x1b[0m", 0, `\x1b[31mred\x1b[0m`},
		{"newline and tab escaped", "a\nb\tc", 0, `a\x0ab\x09c`},
		{"invalid utf8", "a\xffb", 0, `a\xffb`},
		{"c1 control", "a\u009bb", 0, `a\x9bb`},
		{"del", "a\x7fb", 0, `a\x7fb`},
		{"cut to max runes", "abcdefgh", 3, "abc…"},
		{"max not reached", "abc", 3, "abc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Printable(tc.in, tc.max); got != tc.want {
				t.Fatalf("Printable(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

func TestFixedString(t *testing.T) {
	if got := FixedString([]byte{'.', 't', 'e', 'x', 't', 0, 0, 0}); got != ".text" {
		t.Errorf("got %q", got)
	}
	if got := FixedString([]byte{'a', 'b', 0, 'c'}); got != "ab" {
		t.Errorf("must stop at first NUL, got %q", got)
	}
	if got := FixedString([]byte("full8chr")); got != "full8chr" {
		t.Errorf("got %q", got)
	}
}

var _ io.ReaderAt = failingReaderAt{}
