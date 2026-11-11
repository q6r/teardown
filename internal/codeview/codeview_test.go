package codeview

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// testFunc is a small x86-64 function written from the architecture manual (the
// opcode map and the ModRM tables), not produced by the decoder under test.
var testFunc = []byte{
	0x55,             // push rbp
	0x48, 0x89, 0xe5, //             mov rbp, rsp
	0x48, 0x83, 0xec, 0x20, //       sub rsp, 0x20
	0x48, 0x8d, 0x0d, 0x10, 0, 0, 0, // lea rcx, [rip+0x10]
	0xff, 0x15, 0xf0, 0x0f, 0, 0, //  call qword ptr [rip+0xff0]
	0x31, 0xc0, //                   xor eax, eax
	0x48, 0x83, 0xc4, 0x20, //       add rsp, 0x20
	0x5d, //                         pop rbp
	0xc3, //                         ret
}

// testFuncText and testFuncLens are what the sweep over testFunc must print.
var (
	testFuncText = []string{
		"push rbp", "mov rbp, rsp", "sub rsp, 0x20", "lea rcx, [rip+0x10]", "call qword ptr [rip+0xff0]",
		"xor eax, eax", "add rsp, 0x20", "pop rbp", "ret",
	}
	testFuncLens = []int{1, 3, 4, 7, 6, 2, 4, 1, 1}
)

// codeSection is testFunc padded with int3 to one file-alignment unit.
func codeSection() []byte {
	return append(bytes.Clone(testFunc), bytes.Repeat([]byte{0xcc}, 0x200-len(testFunc))...)
}

// peFixture is a PE whose fourth section, ".code", holds codeSection(). The
// expected addresses are read from the fixture's own headers.
type peFixture struct {
	file      []byte
	imageBase uint64
	codeVA    uint64 // virtual address of the first byte of .code
	codeOff   int64  // file offset of the first byte of .code
}

func newPEFixture(t *testing.T, bits int, machine uint16) peFixture {
	t.Helper()
	file := testfixtures.PE(testfixtures.PEOptions{
		Bits:     bits,
		Machine:  machine,
		Sections: []testfixtures.PESection{{Name: ".code", Data: codeSection(), Characteristics: testfixtures.PESectionCode}},
	})
	le := binary.LittleEndian
	fx := peFixture{file: file}
	if bits == 32 {
		fx.imageBase = uint64(le.Uint32(file[testfixtures.PEOptionalOffset+28:]))
	} else {
		fx.imageBase = le.Uint64(file[testfixtures.PEOptionalOffset+24:])
	}
	hdr := file[testfixtures.PESectionHeaderOffset(bits, 3):]
	if string(hdr[:5]) != ".code" {
		t.Fatalf("the fourth section is %q, not .code", hdr[:8])
	}
	fx.codeVA = fx.imageBase + uint64(le.Uint32(hdr[12:]))
	fx.codeOff = int64(le.Uint32(hdr[20:]))
	return fx
}

func source(data []byte) Source {
	return Source{R: bytes.NewReader(data), Size: int64(len(data)), Name: "fixture.bin"}
}

func TestParseNumber(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"0", 0, false},
		{"10", 10, false},
		{"010", 10, false}, // a leading zero never means octal
		{"0x10", 16, false},
		{"0X1A40", 0x1a40, false},
		{"0x140001030", 0x140001030, false},
		{" 0x20 ", 0x20, false},
		{"18446744073709551615", math.MaxUint64, false},
		{"0xffffffffffffffff", math.MaxUint64, false},
		{"", 0, true},
		{"0x", 0, true},
		{"-1", 0, true},
		{"+1", 0, true},
		{"1_000", 0, true},
		{"0b101", 0, true},
		{"0o17", 0, true},
		{"12abc", 0, true},
		{"0xg", 0, true},
		{"0x10000000000000000", 0, true},
		{"18446744073709551616", 0, true},
		{"1.5", 0, true},
	}
	for _, tc := range tests {
		got, err := ParseNumber(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseNumber(%q) = %d, %v; want %d (error %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
	if _, err := ParseNumber("a\x1b[31mb"); err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("an error must not carry control characters: %v", err)
	}
}

func TestHexWindow(t *testing.T) {
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}
	data[0x20] = 'H'
	data[0x21] = 'i'

	w, err := Hex(source(data), 0x1e, 40)
	if err != nil {
		t.Fatal(err)
	}
	if w.Length != 40 || len(w.Rows) != 3 || !w.More || w.Next != 0x1e+40 {
		t.Fatalf("length %d rows %d more %v next %d", w.Length, len(w.Rows), w.More, w.Next)
	}
	first := w.Rows[0]
	if first.Offset != 0x1e || first.Len != 16 ||
		first.Hex != "1e 1f 48 69 22 23 24 25 26 27 28 29 2a 2b 2c 2d" || first.ASCII != "..Hi\"#$%&'()*+,-" {
		t.Errorf("first row = %+v", first)
	}
	if last := w.Rows[2]; last.Offset != 0x1e+32 || last.Len != 8 {
		t.Errorf("last row = %+v", last)
	}
	b := w.Block
	if b.Kind != report.CodeKindHex || b.Offset != 0x1e || len(b.Lines) != 3 || !b.Truncated || len(b.Limitations) == 0 {
		t.Fatalf("block = %+v", b)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}
	if l := b.Lines[1]; l.Offset != 0x1e+16 || l.Bytes != w.Rows[1].Hex || l.Text != w.Rows[1].ASCII {
		t.Errorf("line 1 = %+v", l)
	}
	if !strings.Contains(b.Title, "fixture.bin") || !strings.Contains(b.Title, "0x1e") {
		t.Errorf("title = %q", b.Title)
	}
	if text := hexdump.Format(w.Rows); !strings.HasPrefix(text, "000000001e  1e 1f 48 69 ") || !strings.HasSuffix(text, "|\n") {
		t.Errorf("formatted rows:\n%s", text)
	}
}

func TestHexWindowBounds(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 10_000)
	tests := []struct {
		name         string
		offset       int64
		n            int
		wantLen      int
		wantMore     bool
		wantNext     int64
		wantFirstRow int
	}{
		{"default window", 0, 0, hexdump.DefaultWindow, true, hexdump.DefaultWindow, 16},
		{"negative count means the default", 0, -5, hexdump.DefaultWindow, true, hexdump.DefaultWindow, 16},
		{"capped at the window limit", 0, 1 << 30, hexdump.MaxWindow, true, hexdump.MaxWindow, 16},
		{"cut by the end of the file", 9_990, 100, 10, false, 10_000, 10},
		{"exactly the last byte", 9_999, 4096, 1, false, 10_000, 1},
		{"unaligned start", 5, 20, 20, true, 25, 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := Hex(source(data), tc.offset, tc.n)
			if err != nil {
				t.Fatal(err)
			}
			if w.Length != tc.wantLen || w.More != tc.wantMore || w.Next != tc.wantNext || w.Rows[0].Len != tc.wantFirstRow {
				t.Errorf("length %d more %v next %d first row %d; want %d %v %d %d", w.Length, w.More, w.Next, w.Rows[0].Len, tc.wantLen, tc.wantMore, tc.wantNext, tc.wantFirstRow)
			}
			if w.Block.Truncated != tc.wantMore || w.Block.Offset != tc.offset {
				t.Errorf("block truncated %v offset %d", w.Block.Truncated, w.Block.Offset)
			}
		})
	}
	for _, off := range []int64{-1, 10_000, 10_001, math.MaxInt64, math.MinInt64} {
		_, err := Hex(source(data), off, 16)
		if !IsRequestError(err) || !strings.Contains(err.Error(), "outside the file") {
			t.Errorf("offset %d: error %v", off, err)
		}
	}
	if _, err := Hex(source(nil), 0, 16); !IsRequestError(err) || !strings.Contains(err.Error(), "the file is empty") {
		t.Errorf("an empty file has no window: %v", err)
	}
}

func TestHexWindowNamesTheSection(t *testing.T) {
	fx := newPEFixture(t, 64, 0)
	w, err := Hex(source(fx.file), fx.codeOff+1, 16)
	if err != nil {
		t.Fatal(err)
	}
	if w.Block.Section != ".code" || w.Rows[0].Hex != "48 89 e5 48 83 ec 20 48 8d 0d 10 00 00 00 ff 15" {
		t.Errorf("section %q, first row %+v", w.Block.Section, w.Rows[0])
	}
	if w, err = Hex(source(fx.file), 0, 16); err != nil || w.Block.Section != "" || !strings.HasPrefix(w.Rows[0].Hex, "4d 5a 90 00") {
		t.Errorf("the DOS header is in no section: %+v (%v)", w.Block, err)
	}
}

func TestDetectPE(t *testing.T) {
	t.Run("pe32+", func(t *testing.T) {
		fx := newPEFixture(t, 64, 0)
		im := Detect(bytes.NewReader(fx.file), int64(len(fx.file)))
		if im.Format != FormatPE || im.Arch != ArchX8664 || im.Label() != "PE x86-64" {
			t.Fatalf("image = %+v", im)
		}
		if !im.HasEntry || im.Entry != fx.imageBase+0x1000 {
			t.Errorf("entry = %#x (%v), want %#x", im.Entry, im.HasEntry, fx.imageBase+0x1000)
		}
		var names []string
		for _, s := range im.Segments {
			names = append(names, s.Name)
		}
		if strings.Join(names, " ") != ".text .rdata .data .code" {
			t.Fatalf("segments = %v", names)
		}
		code := im.Segments[3]
		if code.Addr != fx.codeVA || code.Offset != fx.codeOff || code.Length != 0x200 || !code.Exec {
			t.Errorf(".code = %+v, want address %#x offset %#x", code, fx.codeVA, fx.codeOff)
		}
		if im.Segments[1].Exec {
			t.Error(".rdata must not be executable")
		}
		seg, off, ok := im.AtAddress(fx.codeVA + 0x15)
		if !ok || seg.Name != ".code" || off != fx.codeOff+0x15 {
			t.Errorf("AtAddress = %+v %d %v", seg, off, ok)
		}
		seg, addr, ok := im.AtOffset(fx.codeOff + 0x1ff)
		if !ok || seg.Name != ".code" || addr != fx.codeVA+0x1ff {
			t.Errorf("AtOffset = %+v %#x %v", seg, addr, ok)
		}
		if _, _, ok := im.AtAddress(fx.codeVA + 0x200); ok {
			t.Error("the address after the section must not map")
		}
		if _, _, ok := im.AtAddress(fx.imageBase); ok {
			t.Error("the image base is the headers, which no section maps")
		}
		if _, _, ok := im.AtOffset(0); ok {
			t.Error("the headers are in no section")
		}
	})
	t.Run("pe32", func(t *testing.T) {
		fx := newPEFixture(t, 32, 0)
		im := Detect(bytes.NewReader(fx.file), int64(len(fx.file)))
		if im.Format != FormatPE || im.Arch != ArchX86 || fx.imageBase != 0x400000 || im.Entry != 0x401000 || im.Segments[3].Addr != fx.codeVA {
			t.Errorf("image = %+v (base %#x)", im, fx.imageBase)
		}
	})
	t.Run("other machines are named, not decoded", func(t *testing.T) {
		for machine, want := range map[uint16]string{0xaa64: "ARM64", 0x1c4: "ARMNT", 0x5064: "RISC-V64", 0x1234: "machine 0x1234"} {
			fx := newPEFixture(t, 64, machine)
			if im := Detect(bytes.NewReader(fx.file), int64(len(fx.file))); im.Arch != want || im.Format != FormatPE {
				t.Errorf("machine %#x: arch %q, want %q", machine, im.Arch, want)
			}
		}
	})
	t.Run("sections with no data in the file are left out", func(t *testing.T) {
		file := testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{{Name: ".bss", NoRaw: true}}})
		im := Detect(bytes.NewReader(file), int64(len(file)))
		for _, s := range im.Segments {
			if s.Name == ".bss" {
				t.Errorf("a section without raw data holds no bytes to read: %+v", s)
			}
		}
	})
	t.Run("not a PE", func(t *testing.T) {
		for name, data := range map[string][]byte{
			"empty":         nil,
			"mz only":       []byte("MZ"),
			"dos stub only": append([]byte("MZ"), make([]byte, 100)...),
			"bad e_lfanew":  append(append([]byte("MZ"), make([]byte, 0x3a)...), 0xff, 0xff, 0xff, 0x7f),
			"text":          []byte("just some text, long enough to have a few more than sixty-four bytes of it."),
		} {
			if im := Detect(bytes.NewReader(data), int64(len(data))); im.Format != "" || len(im.Segments) != 0 {
				t.Errorf("%s: image = %+v", name, im)
			}
		}
	})
}

func TestDetectNeverPanicsOnTruncatedImages(t *testing.T) {
	images := map[string][]byte{
		"pe":    newPEFixture(t, 64, 0).file,
		"elf":   testfixtures.ELF(testfixtures.ELFOptions{TextData: testFunc}),
		"elf32": testfixtures.ELF(testfixtures.ELFOptions{Bits: 32}),
		"macho": testfixtures.MachO(testfixtures.MachOOptions{TextData: testFunc, Main: true}),
		"fat":   testfixtures.MachOFat(testfixtures.MachO(testfixtures.MachOOptions{}), testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM64})),
	}
	for name, img := range images {
		for n := 0; n <= len(img); n += max(1, len(img)/700) {
			cut := img[:n]
			im := Detect(bytes.NewReader(cut), int64(len(cut)))
			for _, s := range im.Segments {
				if s.Length <= 0 || s.Offset < 0 || s.Offset+s.Length > int64(len(cut)) {
					t.Fatalf("%s cut at %d: segment %+v lies outside the file", name, n, s)
				}
			}
		}
	}
}

func TestDetectELF(t *testing.T) {
	file := testfixtures.ELF(testfixtures.ELFOptions{TextData: testFunc})
	im := Detect(bytes.NewReader(file), int64(len(file)))
	if im.Format != FormatELF || im.Arch != ArchX8664 || im.Label() != "ELF x86-64" {
		t.Fatalf("image = %+v", im)
	}
	// Find the executable PT_LOAD by walking the program headers by hand.
	le := binary.LittleEndian
	phoff, phentsize, phnum := le.Uint64(file[32:]), int(le.Uint16(file[54:])), int(le.Uint16(file[56:]))
	var vaddr, offset uint64
	found := false
	for i := range phnum {
		p := file[int(phoff)+i*phentsize:]
		if le.Uint32(p) == 1 && le.Uint32(p[4:])&1 != 0 {
			offset, vaddr, found = le.Uint64(p[8:]), le.Uint64(p[16:]), true
			break
		}
	}
	if !found {
		t.Fatal("the fixture has no executable PT_LOAD")
	}
	textOff := int64(bytes.Index(file, testFunc))
	if textOff < int64(offset) {
		t.Fatalf("the code at %d is before its segment at %d", textOff, offset)
	}
	wantAddr := vaddr + uint64(textOff) - offset
	seg, addr, ok := im.AtOffset(textOff)
	if !ok || addr != wantAddr || !seg.Exec || !strings.HasPrefix(seg.Name, "LOAD ") || !strings.HasSuffix(seg.Name, "(r-x)") {
		t.Errorf("AtOffset(%d) = %+v %#x %v, want %#x", textOff, seg, addr, ok, wantAddr)
	}
	if _, back, ok := im.AtAddress(wantAddr); !ok || back != textOff {
		t.Errorf("AtAddress(%#x) = %d %v, want %d", wantAddr, back, ok, textOff)
	}
	if !im.HasEntry || im.Entry != wantAddr {
		t.Errorf("entry = %#x, want the start of .text at %#x", im.Entry, wantAddr)
	}

	other := testfixtures.ELF(testfixtures.ELFOptions{Machine: testfixtures.ELFMachineAArch64})
	if im := Detect(bytes.NewReader(other), int64(len(other))); im.Arch != "ARM64" {
		t.Errorf("arch = %q", im.Arch)
	}
	i386 := testfixtures.ELF(testfixtures.ELFOptions{Bits: 32, Machine: testfixtures.ELFMachine386})
	if im := Detect(bytes.NewReader(i386), int64(len(i386))); im.Arch != ArchX86 || len(im.Segments) == 0 {
		t.Errorf("32-bit image = %+v", im)
	}
	object := testfixtures.ELF(testfixtures.ELFOptions{Type: testfixtures.ELFTypeRel})
	if im := Detect(bytes.NewReader(object), int64(len(object))); im.Format != FormatELF || len(im.Segments) != 0 {
		t.Errorf("an object file has no program headers: %+v", im)
	}
}

func TestDetectMachO(t *testing.T) {
	file := testfixtures.MachO(testfixtures.MachOOptions{TextData: testFunc, Main: true})
	im := Detect(bytes.NewReader(file), int64(len(file)))
	if im.Format != FormatMachO || im.Arch != ArchX8664 || im.Label() != "Mach-O x86-64" {
		t.Fatalf("image = %+v", im)
	}
	textOff := int64(bytes.Index(file, testFunc))
	seg, addr, ok := im.AtOffset(textOff)
	if !ok || seg.Name != "__TEXT,__text" || !seg.Exec || addr != 0x100000000+uint64(textOff) {
		t.Errorf("AtOffset(%d) = %+v %#x %v", textOff, seg, addr, ok)
	}
	if !im.HasEntry || im.Entry != addr {
		t.Errorf("entry = %#x (%v), want the start of __text at %#x", im.Entry, im.HasEntry, addr)
	}
	if data := segmentNamed(im, "__DATA,__data"); data.Exec || data.Length == 0 {
		t.Errorf("__data = %+v", data)
	}

	t.Run("32-bit and other cpus", func(t *testing.T) {
		f32 := testfixtures.MachO(testfixtures.MachOOptions{Bits: 32})
		if im := Detect(bytes.NewReader(f32), int64(len(f32))); im.Arch != ArchX86 || segmentNamed(im, "__TEXT,__text").Length == 0 {
			t.Errorf("32-bit image = %+v", im)
		}
		arm := testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM64})
		if im := Detect(bytes.NewReader(arm), int64(len(arm))); im.Arch != "ARM64" {
			t.Errorf("arch = %q", im.Arch)
		}
	})
	t.Run("universal binary picks the x86-64 slice", func(t *testing.T) {
		arm := testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM64})
		x64 := testfixtures.MachO(testfixtures.MachOOptions{TextData: testFunc})
		fat := testfixtures.MachOFat(arm, x64)
		im := Detect(bytes.NewReader(fat), int64(len(fat)))
		if im.Arch != ArchX8664 {
			t.Fatalf("arch = %q", im.Arch)
		}
		if _, _, ok := im.AtOffset(int64(bytes.Index(fat, testFunc))); !ok {
			t.Errorf("the code of the x86-64 slice must map at its offset in the fat file: %+v", im.Segments)
		}
		armOnly := testfixtures.MachOFat(arm)
		if im := Detect(bytes.NewReader(armOnly), int64(len(armOnly))); im.Arch != "ARM64" {
			t.Errorf("a fat file without x86 reports its first slice: %q", im.Arch)
		}
	})
	t.Run("a Java class file is not a universal binary", func(t *testing.T) {
		class := append([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34}, make([]byte, 64)...)
		if im := Detect(bytes.NewReader(class), int64(len(class))); im.Format != "" {
			t.Errorf("image = %+v", im)
		}
	})
}

func segmentNamed(im Image, name string) Segment {
	for _, s := range im.Segments {
		if s.Name == name {
			return s
		}
	}
	return Segment{}
}

func TestDisassembleByAddressOffsetAndEntry(t *testing.T) {
	fx := newPEFixture(t, 64, 0)
	src := source(fx.file)

	check := func(t *testing.T, d *Disassembly, startOff int64, startAddr uint64, texts []string, lens []int) {
		t.Helper()
		b := d.Block
		if b.Kind != report.CodeKindDisasm || b.Arch != ArchX8664 || b.Section != ".code" || b.Offset != startOff || uint64(b.Address) != startAddr {
			t.Fatalf("block header = %s %s %s offset %d address %v", b.Kind, b.Arch, b.Section, b.Offset, b.Address)
		}
		if len(b.Lines) != len(texts) {
			t.Fatalf("%d lines, want %d: %+v", len(b.Lines), len(texts), b.Lines)
		}
		off, addr := startOff, startAddr
		for i, l := range b.Lines {
			if l.Text != texts[i] || l.Offset != off || uint64(l.Address) != addr || l.Bytes != hexBytes(fx.file[off:off+int64(lens[i])]) {
				t.Errorf("line %d = %+v, want %q at offset %d address %#x", i, l, texts[i], off, addr)
			}
			off += int64(lens[i])
			addr += uint64(lens[i])
		}
		if err := b.Validate(); err != nil {
			t.Errorf("the block is not valid: %v", err)
		}
	}

	t.Run("by address", func(t *testing.T) {
		d, err := Disassemble(src, Request{Addr: fx.codeVA, HasAddr: true, Count: 9})
		if err != nil {
			t.Fatal(err)
		}
		check(t, d, fx.codeOff, fx.codeVA, testFuncText, testFuncLens)
		if d.Start != StartAddress || !d.More || !d.HasNextAddr || d.NextAddr != fx.codeVA+29 || d.NextOffset != fx.codeOff+29 || !d.Block.Truncated {
			t.Errorf("start %q more %v next %#x/%d truncated %v", d.Start, d.More, d.NextAddr, d.NextOffset, d.Block.Truncated)
		}
	})
	t.Run("by address in the middle", func(t *testing.T) {
		d, err := Disassemble(src, Request{Addr: fx.codeVA + 8, HasAddr: true, Count: 3})
		if err != nil {
			t.Fatal(err)
		}
		check(t, d, fx.codeOff+8, fx.codeVA+8, testFuncText[3:6], testFuncLens[3:6])
		if d.NextAddr != fx.codeVA+8+7+6+2 {
			t.Errorf("next address = %#x", d.NextAddr)
		}
	})
	t.Run("by offset", func(t *testing.T) {
		d, err := Disassemble(src, Request{Offset: fx.codeOff + 4, HasOffset: true, Count: 2})
		if err != nil {
			t.Fatal(err)
		}
		check(t, d, fx.codeOff+4, fx.codeVA+4, testFuncText[2:4], testFuncLens[2:4])
		if d.Start != StartOffset {
			t.Errorf("start = %q", d.Start)
		}
	})
	t.Run("without a start it begins at the entry point", func(t *testing.T) {
		d, err := Disassemble(src, Request{Count: 3})
		if err != nil {
			t.Fatal(err)
		}
		if d.Start != StartEntry || d.Block.Section != ".text" || d.Block.Address != report.Addr(fx.imageBase+0x1000) {
			t.Fatalf("start %q section %q address %v", d.Start, d.Block.Section, d.Block.Address)
		}
		// The fixture's .text is "xor eax, eax; ret" followed by int3 padding.
		want := []string{"xor eax, eax", "ret", "int3"}
		for i, l := range d.Block.Lines {
			if l.Text != want[i] {
				t.Errorf("line %d = %q, want %q", i, l.Text, want[i])
			}
		}
	})
	t.Run("default count", func(t *testing.T) {
		d, err := Disassemble(src, Request{Addr: fx.codeVA, HasAddr: true})
		if err != nil || len(d.Block.Lines) != DefaultInstructions {
			t.Fatalf("%d lines (%v), want %d", len(d.Block.Lines), err, DefaultInstructions)
		}
	})
	t.Run("count is capped", func(t *testing.T) {
		d, err := Disassemble(src, Request{Addr: fx.codeVA, HasAddr: true, Count: 1 << 20})
		if err != nil || len(d.Block.Lines) != MaxInstructions || !d.More {
			t.Fatalf("%d lines (%v) more %v, want %d", len(d.Block.Lines), err, d.More, MaxInstructions)
		}
	})
	t.Run("the window stops at the end of the section", func(t *testing.T) {
		d, err := Disassemble(src, Request{Addr: fx.codeVA + 0x1f0, HasAddr: true, Count: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Block.Lines) != 16 || d.More || d.Block.Truncated || d.NextOffset != fx.codeOff+0x200 {
			t.Errorf("%d lines more %v truncated %v next %d", len(d.Block.Lines), d.More, d.Block.Truncated, d.NextOffset)
		}
		if last := d.Block.Lines[15]; last.Text != "int3" || last.Offset != fx.codeOff+0x1ff {
			t.Errorf("last line = %+v", last)
		}
	})
	t.Run("an instruction cut by the end of the section is not completed from the next one", func(t *testing.T) {
		// Two bytes at the very end of the section: a call rel32 needs five.
		file := bytes.Clone(fx.file)
		copy(file[fx.codeOff+0x1fe:], []byte{0xe8, 0x00})
		d, err := Disassemble(source(file), Request{Addr: fx.codeVA + 0x1fe, HasAddr: true, Count: 10})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range d.Block.Lines {
			if !strings.HasPrefix(l.Text, "db 0x") || l.Offset >= fx.codeOff+0x200 {
				t.Errorf("line %+v reads beyond the section or hides a cut instruction", l)
			}
		}
	})
}

func TestDisassembleExplainsWhatItCannotDo(t *testing.T) {
	fx := newPEFixture(t, 64, 0)
	src := source(fx.file)
	tests := []struct {
		name string
		src  Source
		req  Request
		want string
	}{
		{"address and offset", src, Request{HasAddr: true, HasOffset: true}, "either an address or a file offset"},
		{"address in no section", src, Request{Addr: 0x1234, HasAddr: true}, "address 0x1234 is not inside any section"},
		{"address lists the ranges", src, Request{Addr: fx.codeVA + 0x200, HasAddr: true}, ".code 0x"},
		{"address in the headers", src, Request{Addr: fx.imageBase, HasAddr: true}, "mapped ranges: .text 0x"},
		{"offset past the end", src, Request{Offset: int64(len(fx.file)), HasOffset: true}, "outside the file"},
		{"negative offset", src, Request{Offset: -1, HasOffset: true}, "outside the file"},
		{"unknown arch", src, Request{Arch: "arm64"}, `unknown architecture "arm64"`},
		{"empty file", source(nil), Request{Arch: ArchX8664}, "the file is empty"},
		{"raw file without an arch", source([]byte("hello")), Request{HasOffset: true}, "cannot tell the instruction set"},
		{"address on a raw file", source([]byte("hello")), Request{Arch: ArchX86, Addr: 0, HasAddr: true}, "no address map"},
		{"arm64 pe", source(newPEFixture(t, 64, 0xaa64).file), Request{}, "only x86 and x86-64 code can be disassembled"},
		{"arm64 elf", source(testfixtures.ELF(testfixtures.ELFOptions{Machine: testfixtures.ELFMachineAArch64})), Request{}, "ELF ARM64"},
		{"arm64 macho", source(testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM64})), Request{}, "Mach-O ARM64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Disassemble(tc.src, tc.req)
			if err == nil {
				t.Fatalf("expected an error, got %+v", d.Block)
			}
			if !IsRequestError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q (request error %v) does not contain %q", err, IsRequestError(err), tc.want)
			}
		})
	}
}

func TestDisassembleRawFilesAndForcedArchitectures(t *testing.T) {
	t.Run("raw bytes with an explicit architecture", func(t *testing.T) {
		data := append([]byte("ignored prefix"), testFunc...)
		off := int64(len("ignored prefix"))
		d, err := Disassemble(source(data), Request{Offset: off, HasOffset: true, Arch: ArchX8664, Count: 9})
		if err != nil {
			t.Fatal(err)
		}
		b := d.Block
		if b.Address != 0 || b.Section != "" || b.Offset != off || d.HasNextAddr || d.Image.Format != "" {
			t.Fatalf("a raw window has no addresses: %+v", b)
		}
		for i, l := range b.Lines {
			if l.Address != 0 || l.Text != testFuncText[i] {
				t.Errorf("line %d = %+v", i, l)
			}
		}
		if !strings.Contains(strings.Join(b.Limitations, " "), "addresses shown are file offsets") {
			t.Errorf("limitations = %v", b.Limitations)
		}
		// A branch target in the raw view is in the file-offset space.
		d, err = Disassemble(source([]byte{0xeb, 0x02, 0x90, 0x90, 0xc3}), Request{Arch: ArchX8664, Count: 2})
		if err != nil || d.Start != StartFile || d.Block.Lines[0].Text != "jmp 0x4" {
			t.Errorf("jmp in raw bytes = %+v (%v)", d.Block.Lines, err)
		}
	})
	t.Run("an architecture named by the request wins and says so", func(t *testing.T) {
		fx := newPEFixture(t, 64, 0)
		d, err := Disassemble(source(fx.file), Request{Addr: fx.codeVA, HasAddr: true, Arch: ArchX86, Count: 2})
		if err != nil {
			t.Fatal(err)
		}
		if d.Block.Arch != ArchX86 || d.Block.Lines[0].Text != "push ebp" {
			t.Errorf("32-bit decoding gave %+v", d.Block.Lines[0])
		}
		if !strings.Contains(strings.Join(d.Block.Limitations, " "), "set to x86 by the request") {
			t.Errorf("limitations = %v", d.Block.Limitations)
		}
	})
	t.Run("an arm64 file can be read as x86-64 when asked", func(t *testing.T) {
		fx := newPEFixture(t, 64, 0xaa64)
		d, err := Disassemble(source(fx.file), Request{Addr: fx.codeVA, HasAddr: true, Arch: ArchX8664, Count: 1})
		if err != nil || d.Block.Lines[0].Text != "push rbp" {
			t.Fatalf("%+v (%v)", d.Block.Lines, err)
		}
		if !strings.Contains(strings.Join(d.Block.Limitations, " "), "header of the file says ARM64") {
			t.Errorf("limitations = %v", d.Block.Limitations)
		}
	})
	t.Run("bytes that no section holds code in are flagged", func(t *testing.T) {
		fx := newPEFixture(t, 64, 0)
		im := Detect(bytes.NewReader(fx.file), int64(len(fx.file)))
		rdata := segmentNamed(im, ".rdata")
		d, err := Disassemble(source(fx.file), Request{Addr: rdata.Addr, HasAddr: true, Count: 4})
		if err != nil {
			t.Fatal(err)
		}
		if d.Block.Section != ".rdata" || !strings.Contains(strings.Join(d.Block.Limitations, " "), "not marked as holding code") {
			t.Errorf("section %q limitations %v", d.Block.Section, d.Block.Limitations)
		}
	})
	t.Run("a start in the headers has no addresses", func(t *testing.T) {
		fx := newPEFixture(t, 64, 0)
		d, err := Disassemble(source(fx.file), Request{Offset: 0, HasOffset: true, Count: 3})
		if err != nil {
			t.Fatal(err)
		}
		if d.Block.Address != 0 || d.Block.Section != "" || d.Block.Arch != ArchX8664 {
			t.Errorf("block = %+v", d.Block)
		}
	})
}

func TestDisassembleElfAndMachO(t *testing.T) {
	elf := testfixtures.ELF(testfixtures.ELFOptions{TextData: testFunc})
	d, err := Disassemble(source(elf), Request{Count: 9})
	if err != nil {
		t.Fatal(err)
	}
	if d.Start != StartEntry || d.Block.Address == 0 || !strings.HasPrefix(d.Block.Section, "LOAD ") {
		t.Fatalf("start %q block %+v", d.Start, d.Block)
	}
	for i, l := range d.Block.Lines {
		if l.Text != testFuncText[i] {
			t.Errorf("elf line %d = %q, want %q", i, l.Text, testFuncText[i])
		}
	}

	macho := testfixtures.MachO(testfixtures.MachOOptions{TextData: testFunc, Main: true})
	d, err = Disassemble(source(macho), Request{Count: 9})
	if err != nil {
		t.Fatal(err)
	}
	if d.Start != StartEntry || d.Block.Section != "__TEXT,__text" {
		t.Fatalf("start %q block %+v", d.Start, d.Block)
	}
	for i, l := range d.Block.Lines {
		if l.Text != testFuncText[i] {
			t.Errorf("macho line %d = %q, want %q", i, l.Text, testFuncText[i])
		}
	}
}

func TestRequestErrorIsDistinguishedFromReadFailures(t *testing.T) {
	if IsRequestError(errors.New("disk on fire")) || !IsRequestError(requestErrorf("x")) {
		t.Error("IsRequestError is wrong")
	}
	wrapped := errors.Join(errors.New("context"), requestErrorf("inner"))
	if !IsRequestError(wrapped) {
		t.Error("a wrapped request error must still be recognised")
	}
}

func TestBlocksNameTheFileSafely(t *testing.T) {
	name := "evil" + string(rune(0x1b)) + "[31m" + string(rune(0x85)) + ".bin"
	src := Source{R: bytes.NewReader(testFunc), Size: int64(len(testFunc)), Name: name}
	d, err := Disassemble(src, Request{Arch: ArchX8664, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	w, err := Hex(src, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{d.Block.Title, w.Block.Title} {
		for _, r := range title {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				t.Errorf("title %q holds the control character %U", title, r)
			}
		}
		if err := (&report.CodeBlock{Kind: report.CodeKindHex, Title: title, Lines: []report.CodeLine{{Text: "x"}}, Limitations: []string{"x"}}).Validate(); err != nil {
			t.Errorf("title %q is not valid in a block: %v", title, err)
		}
	}
}
