package codeview

import (
	"bytes"
	"testing"

	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// seedImages are valid images of every supported format, so the fuzzer starts
// from structure that gets past the magic numbers.
func seedImages() [][]byte {
	return [][]byte{
		testfixtures.PE(testfixtures.PEOptions{}),
		testfixtures.PE(testfixtures.PEOptions{Bits: 32}),
		testfixtures.ELF(testfixtures.ELFOptions{TextData: testFunc}),
		testfixtures.ELF(testfixtures.ELFOptions{Bits: 32}),
		testfixtures.MachO(testfixtures.MachOOptions{TextData: testFunc, Main: true}),
		testfixtures.MachOFat(testfixtures.MachO(testfixtures.MachOOptions{})),
		[]byte("MZ"), {0x7f, 'E', 'L', 'F', 2, 1}, {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1},
	}
}

// FuzzDetect checks that whatever the headers say, every segment lies inside
// the file, the lookups agree with each other and nothing panics.
func FuzzDetect(f *testing.F) {
	for _, img := range seedImages() {
		f.Add(img)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		size := int64(len(data))
		im := Detect(bytes.NewReader(data), size)
		for _, s := range im.Segments {
			if s.Length <= 0 || s.Offset < 0 || s.Offset > size || s.Length > size-s.Offset {
				t.Fatalf("segment %+v lies outside the %d-byte file", s, size)
			}
			seg, off, ok := im.AtAddress(s.Addr)
			if !ok || off < seg.Offset || off >= seg.Offset+seg.Length {
				t.Fatalf("the first byte of %+v does not map back into a segment: %+v %d %v", s, seg, off, ok)
			}
			if seg2, addr, ok := im.AtOffset(s.Offset); !ok || addr < seg2.Addr {
				t.Fatalf("the first offset of %+v does not map to an address: %+v %#x %v", s, seg2, addr, ok)
			}
		}
		_ = im.Label()
	})
}

// FuzzDisassemble sweeps arbitrary files from arbitrary starts: the result is
// bounded, stays inside the file and describes consecutive bytes.
func FuzzDisassemble(f *testing.F) {
	for _, img := range seedImages() {
		f.Add(img, uint64(0), int64(0), 0, uint8(0))
		f.Add(img, uint64(0x140001000), int64(0x200), 24, uint8(1))
	}
	f.Fuzz(func(t *testing.T, data []byte, addr uint64, off int64, count int, mode uint8) {
		src := Source{R: bytes.NewReader(data), Size: int64(len(data)), Name: "fuzz"}
		req := Request{Addr: addr, Offset: off, Count: count}
		switch mode % 4 {
		case 1:
			req.HasAddr = true
		case 2:
			req.HasOffset = true
		case 3:
			req.HasAddr, req.HasOffset = true, true
		}
		if mode&4 != 0 {
			req.Arch = ArchX86
		} else if mode&8 != 0 {
			req.Arch = ArchX8664
		}
		d, err := Disassemble(src, req)
		if err != nil {
			return
		}
		b := d.Block
		if len(b.Lines) == 0 || len(b.Lines) > MaxInstructions {
			t.Fatalf("%d lines", len(b.Lines))
		}
		pos := b.Offset
		for _, l := range b.Lines {
			if l.Offset != pos || l.Bytes == "" || l.Text == "" {
				t.Fatalf("line %+v does not follow the previous one at %d", l, pos)
			}
			pos += int64((len(l.Bytes) + 1) / 3)
		}
		if b.Offset < 0 || pos > int64(len(data)) || pos != d.NextOffset {
			t.Fatalf("window [%d, %d) in a %d-byte file, next %d", b.Offset, pos, len(data), d.NextOffset)
		}
		// Blocks of up to 64 lines are valid code blocks; longer windows only
		// differ in the number of lines.
		if len(b.Lines) <= report.MaxCodeLines {
			if err := b.Validate(); err != nil {
				t.Fatalf("invalid block: %v", err)
			}
		}
	})
}

// FuzzHex checks the dump window against the bytes of the file.
func FuzzHex(f *testing.F) {
	f.Add([]byte("hello, world"), int64(0), 0)
	f.Add(bytes.Repeat([]byte{0xff}, 5000), int64(4999), 1<<20)
	f.Fuzz(func(t *testing.T, data []byte, off int64, n int) {
		w, err := Hex(Source{R: bytes.NewReader(data), Size: int64(len(data)), Name: "fuzz"}, off, n)
		if err != nil {
			return
		}
		if w.Length < 1 || w.Length > hexdump.MaxWindow || off+int64(w.Length) > int64(len(data)) || w.Next != off+int64(w.Length) {
			t.Fatalf("window of %d bytes at %d of %d, next %d", w.Length, off, len(data), w.Next)
		}
		var got []byte
		for _, r := range w.Rows {
			if r.Len < 1 || r.Len > hexdump.BytesPerRow || len(r.ASCII) != r.Len {
				t.Fatalf("row %+v", r)
			}
			got = append(got, r.ASCII...)
		}
		if len(got) != w.Length {
			t.Fatalf("rows hold %d bytes, the window %d", len(got), w.Length)
		}
	})
}
