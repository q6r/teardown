package zipscan

import (
	"encoding/binary"
	"math"
	"testing"
)

func extraField(id uint16, values ...uint64) []byte {
	b := make([]byte, 4, 4+8*len(values))
	binary.LittleEndian.PutUint16(b, id)
	binary.LittleEndian.PutUint16(b[2:], uint16(8*len(values)))
	for _, v := range values {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return b
}

func TestZip64Fields(t *testing.T) {
	const s = 0xFFFFFFFF
	tests := []struct {
		name                          string
		extra                         []byte
		uncomp, comp, off             uint64
		wantUncomp, wantComp, wantOff uint64
	}{
		{"all three", extraField(1, 10, 20, 30), s, s, s, 10, 20, 30},
		{"only offset", extraField(1, 99), 5, 6, s, 5, 6, 99},
		{"sizes only", extraField(1, 10, 20), s, s, 7, 10, 20, 7},
		{"no sentinel keeps header values", extraField(1, 10, 20, 30), 1, 2, 3, 1, 2, 3},
		{"unknown field first", append(extraField(0x5455, 1), extraField(1, 10, 20, 30)...), s, s, s, 10, 20, 30},
		{"missing zip64 field", extraField(0x5455, 1), s, s, s, s, s, s},
		{"short data keeps sentinels for the rest", extraField(1, 10), s, s, s, 10, s, s},
		{"declared length beyond the slice", append(extraField(1, 10, 20)[:4+8], 0xFF), s, s, 0, 10, s, 0},
		{"empty", nil, s, s, s, s, s, s},
		{"garbage shorter than a header", []byte{1, 0, 8}, s, s, s, s, s, s},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, c, o := zip64Fields(tc.extra, tc.uncomp, tc.comp, tc.off)
			if u != tc.wantUncomp || c != tc.wantComp || o != tc.wantOff {
				t.Fatalf("got %d/%d/%d, want %d/%d/%d", u, c, o, tc.wantUncomp, tc.wantComp, tc.wantOff)
			}
		})
	}
}

func TestSatAdd(t *testing.T) {
	if got := satAdd(1, 2); got != 3 {
		t.Errorf("satAdd(1,2) = %d", got)
	}
	if got := satAdd(math.MaxUint64-1, 5); got != math.MaxUint64 {
		t.Errorf("must saturate, got %d", got)
	}
}

func TestMakeEntryClassification(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		flags, method    uint16
		wantDir, wantEnc bool
	}{
		{"plain file", "a/b.txt", 0, 8, false, false},
		{"directory", "a/", 0, 0, true, false},
		{"traditional encryption", "x", 1, 8, false, true},
		{"strong encryption", "x", 0x40, 8, false, true},
		{"aes", "x", 0, 99, false, true},
		{"empty name", "", 0, 0, false, false},
	}
	for _, tc := range tests {
		e := makeEntry([]byte(tc.raw), tc.flags, tc.method, 0, 1, 1, 0)
		if e.IsDir != tc.wantDir || e.Encrypted != tc.wantEnc {
			t.Errorf("%s: IsDir=%v Encrypted=%v", tc.name, e.IsDir, e.Encrypted)
		}
	}
}

func TestMakeEntryBoundsLongNames(t *testing.T) {
	long := make([]byte, 60000)
	for i := range long {
		long[i] = 'a'
	}
	e := makeEntry(long, 0, 0, 0, 0, 0, 0)
	if len(e.RawName) != maxRawName {
		t.Errorf("RawName length = %d, want %d", len(e.RawName), maxRawName)
	}
	if n := len([]rune(e.Name)); n > maxNameRunes+1 {
		t.Errorf("Name has %d runes, want at most %d", n, maxNameRunes+1)
	}
}
