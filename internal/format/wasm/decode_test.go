package wasm

import (
	"errors"
	"strings"
	"testing"
)

func TestLEB32(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint32
		wantLen int
		wantErr error
	}{
		{"zero", []byte{0x00}, 0, 1, nil},
		{"one byte max", []byte{0x7f}, 127, 1, nil},
		{"two bytes", []byte{0x80, 0x01}, 128, 2, nil},
		{"two bytes max", []byte{0xff, 0x7f}, 16383, 2, nil},
		{"three bytes", []byte{0x80, 0x80, 0x01}, 16384, 3, nil},
		{"spec example", []byte{0xe5, 0x8e, 0x26}, 624485, 3, nil},
		{"non-minimal zero", []byte{0x80, 0x80, 0x00}, 0, 3, nil},
		{"max uint32", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 1<<32 - 1, 5, nil},
		{"overflows 32 bits", []byte{0xff, 0xff, 0xff, 0xff, 0x1f}, 0, 0, errLEB},
		{"continuation on the fifth byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 0, 0, errLEB},
		{"truncated", []byte{0x80}, 0, 0, errTruncated},
		{"empty", nil, 0, 0, errTruncated},
		{"trailing bytes are left alone", []byte{0x05, 0xaa, 0xbb}, 5, 1, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, n, err := leb32(tc.in)
			if !errors.Is(err, tc.wantErr) || got != tc.want || n != tc.wantLen {
				t.Fatalf("leb32(% x) = %d, %d, %v; want %d, %d, %v", tc.in, got, n, err, tc.want, tc.wantLen, tc.wantErr)
			}
		})
	}
}

func TestLEB64(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint64
		wantLen int
		wantErr error
	}{
		{"zero", []byte{0x00}, 0, 1, nil},
		{"five bytes", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 1<<32 - 1, 5, nil},
		{"above 32 bits", []byte{0x80, 0x80, 0x80, 0x80, 0x10}, 1 << 32, 5, nil},
		{"max uint64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, 1<<64 - 1, 10, nil},
		{"overflows 64 bits", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, 0, 0, errLEB},
		{"eleven bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 0, 0, errLEB},
		{"truncated", []byte{0x80, 0x80}, 0, 0, errTruncated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, n, err := leb64(tc.in)
			if !errors.Is(err, tc.wantErr) || got != tc.want || n != tc.wantLen {
				t.Fatalf("leb64(% x) = %d, %d, %v; want %d, %d, %v", tc.in, got, n, err, tc.want, tc.wantLen, tc.wantErr)
			}
		})
	}
}

func TestReaderStickyError(t *testing.T) {
	d := &reader{b: []byte{0x05, 'h', 'e', 'l', 'l', 'o', 0x7f}}
	if got := d.name(64); got != "hello" {
		t.Fatalf("name = %q", got)
	}
	if got := d.byte(); got != 0x7f || d.err != nil {
		t.Fatalf("byte = %#x, err %v", got, d.err)
	}
	if d.i != len(d.b) {
		t.Fatal("reader should be at the end")
	}
	if d.byte() != 0 || !errors.Is(d.err, errTruncated) {
		t.Fatal("reading past the end must fail with errTruncated")
	}
	if d.u32() != 0 || d.u64() != 0 || d.name(8) != "" {
		t.Fatal("a failed reader must keep returning zero values")
	}
}

func TestReaderName(t *testing.T) {
	long := strings.Repeat("a", 1000)
	tests := []struct {
		name    string
		in      []byte
		max     int
		want    string
		wantErr bool
		wantPos int
	}{
		{"empty name", []byte{0x00, 0xaa}, 8, "", false, 1},
		{"escape characters are neutralised", append([]byte{0x04}, "\x1b[0m"...), 16, `\x1b[0m`, false, 5},
		{"invalid utf-8", []byte{0x02, 0xff, 'a'}, 16, `\xffa`, false, 3},
		{"cut to max runes but fully consumed", append([]byte{0xe8, 0x07}, long...), 10, strings.Repeat("a", 10) + "…", false, 1002},
		{"length beyond the data", []byte{0x09, 'a'}, 8, "", true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &reader{b: tc.in}
			got := d.name(tc.max)
			if got != tc.want || (d.err != nil) != tc.wantErr || d.i != tc.wantPos {
				t.Fatalf("name = %q, err %v, pos %d; want %q, err %v, pos %d", got, d.err, d.i, tc.want, tc.wantErr, tc.wantPos)
			}
		})
	}
}

func TestReaderValType(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantPos int
		wantErr bool
	}{
		{"i32", []byte{0x7f}, 1, false},
		{"v128", []byte{0x7b}, 1, false},
		{"funcref", []byte{0x70}, 1, false},
		{"externref", []byte{0x6f}, 1, false},
		{"anyref shorthand", []byte{0x6e}, 1, false},
		{"ref null with a type index", []byte{0x63, 0x80, 0x01}, 3, false},
		{"ref with a heap type", []byte{0x64, 0x70}, 2, false},
		{"unknown byte", []byte{0x01}, 1, true},
		{"truncated heap type", []byte{0x63, 0x80}, 2, true},
		{"empty", nil, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &reader{b: tc.in}
			d.valType()
			if d.i != tc.wantPos || (d.err != nil) != tc.wantErr {
				t.Fatalf("pos %d, err %v; want pos %d, err %v", d.i, d.err, tc.wantPos, tc.wantErr)
			}
		})
	}
}

func TestReaderLimits(t *testing.T) {
	tests := []struct {
		name                     string
		in                       []byte
		lo, hi                   uint64
		hasMax, shared, memory64 bool
		wantErr                  bool
		wantPos                  int
	}{
		{"minimum only", []byte{0x00, 0x01}, 1, 0, false, false, false, false, 2},
		{"minimum and maximum", []byte{0x01, 0x01, 0x10}, 1, 16, true, false, false, false, 3},
		{"shared needs a maximum", []byte{0x03, 0x02, 0x04}, 2, 4, true, true, false, false, 3},
		{"64-bit memory", []byte{0x05, 0x80, 0x80, 0x80, 0x80, 0x10, 0x80, 0x80, 0x80, 0x80, 0x20}, 1 << 32, 1 << 33, true, false, true, false, 11},
		{"custom page size", []byte{0x08, 0x01, 0x10}, 1, 0, false, false, false, false, 3},
		{"unknown flag bits", []byte{0x10, 0x01}, 0, 0, false, false, false, true, 1},
		{"truncated maximum", []byte{0x01, 0x01}, 1, 0, true, false, false, true, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &reader{b: tc.in}
			lo, hi, hasMax, shared, is64 := d.limits()
			if (d.err != nil) != tc.wantErr || d.i != tc.wantPos {
				t.Fatalf("err %v, pos %d; want err %v, pos %d", d.err, d.i, tc.wantErr, tc.wantPos)
			}
			if tc.wantErr {
				return
			}
			if lo != tc.lo || hi != tc.hi || hasMax != tc.hasMax || shared != tc.shared || is64 != tc.memory64 {
				t.Fatalf("limits = %d %d %v %v %v; want %d %d %v %v %v", lo, hi, hasMax, shared, is64,
					tc.lo, tc.hi, tc.hasMax, tc.shared, tc.memory64)
			}
		})
	}
}
