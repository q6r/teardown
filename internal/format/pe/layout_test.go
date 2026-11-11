package pe

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

// slotValue reads the pointer-sized cell of an import slot out of the file.
func slotValue(t *testing.T, data []byte, l Layout, s ImportSlot) uint64 {
	t.Helper()
	_, off, ok := l.SectionAtVA(s.VA)
	if !ok {
		t.Fatalf("slot %s at %#x is not inside a section", s.Display(), s.VA)
	}
	if l.Bits == 32 {
		return uint64(binary.LittleEndian.Uint32(data[off:]))
	}
	return binary.LittleEndian.Uint64(data[off:])
}

// nameAt reads the NUL-terminated function name of a hint/name entry at rva.
func nameAt(t *testing.T, data []byte, l Layout, rva uint32) string {
	t.Helper()
	_, off, ok := l.SectionAtVA(l.ImageBase + uint64(rva))
	if !ok {
		t.Fatalf("hint/name entry at RVA %#x is not inside a section", rva)
	}
	rest := data[off+2:] // the entry starts with a two-byte hint
	return string(rest[:bytes.IndexByte(rest, 0)])
}

func TestLayoutSlotOfTheDefaultFixture(t *testing.T) {
	res := parseBytes(t, testfixtures.PE(testfixtures.PEOptions{}))
	l := res.Layout
	if l.Machine != 0x8664 || l.Bits != 64 || l.ImageBase != 0x140000000 {
		t.Fatalf("layout header = machine %#x, %d bits, base %#x", l.Machine, l.Bits, l.ImageBase)
	}
	// By hand: .rdata starts at RVA 0x2000 with 16 scratch bytes, the 40-byte import
	// directory (to 0x2038), the hint/name entry "ExitProcess" (14 bytes with its
	// hint), the DLL name "kernel32.dll" (13 bytes, to 0x2053), padding to 0x2058,
	// the name table (16 bytes with its terminator) and then the address table.
	want := []ImportSlot{{RVA: 0x2068, VA: 0x140002068, Library: "kernel32.dll", Function: "ExitProcess"}}
	if !slices.Equal(l.Slots, want) {
		t.Fatalf("slots = %+v, want %+v", l.Slots, want)
	}
	if got := want[0].Display(); got != "kernel32.dll!ExitProcess" {
		t.Errorf("Display() = %q", got)
	}
	if s, ok := l.SlotAt(0x140002068); !ok || s.Function != "ExitProcess" {
		t.Errorf("SlotAt = %+v, %v", s, ok)
	}
	if _, ok := l.SlotAt(0x140002070); ok {
		t.Error("the terminator of the address table is not a slot")
	}
}

func TestLayoutSlotsPointAtTheirNames(t *testing.T) {
	imports := []testfixtures.PEImport{
		{Library: "KERNEL32.dll", Functions: []string{"ExitProcess", "GetStdHandle", "VirtualAllocEx"}},
		{Library: "WS2_32.dll", Functions: []string{"#23", "WSAStartup", "connect"}},
	}
	tests := []struct {
		name string
		opts testfixtures.PEOptions
		bits int
	}{
		{"pe32+", testfixtures.PEOptions{Imports: imports}, 64},
		{"pe32", testfixtures.PEOptions{Imports: imports, Bits: 32}, 32},
		{"pe32+ with delay-load", testfixtures.PEOptions{Imports: imports, DelayImports: []testfixtures.PEImport{{Library: "shell32.dll", Functions: []string{"ShellExecuteW", "#42"}}}}, 64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := testfixtures.PE(tc.opts)
			res := parseBytes(t, data)
			l := res.Layout
			if l.Bits != tc.bits {
				t.Fatalf("bits = %d, want %d", l.Bits, tc.bits)
			}

			// One slot per listed function, in the order of the import lists.
			var want []string
			for _, lib := range res.Imports {
				for _, fn := range lib.Functions {
					want = append(want, lib.Library+"!"+fn)
				}
			}
			var got []string
			for _, s := range l.Slots {
				got = append(got, s.Display())
			}
			if !slices.Equal(got, want) {
				t.Fatalf("slots = %v, want %v", got, want)
			}

			// Each slot of the file holds what the import table says about its function.
			ordinalBit := uint64(1) << 63
			if l.Bits == 32 {
				ordinalBit = 1 << 31
			}
			seen := map[uint64]bool{}
			for _, s := range l.Slots {
				if seen[s.VA] {
					t.Errorf("two slots share the address %#x", s.VA)
				}
				seen[s.VA] = true
				if s.VA != l.ImageBase+uint64(s.RVA) {
					t.Errorf("%s: VA %#x does not match RVA %#x", s.Display(), s.VA, s.RVA)
				}
				v := slotValue(t, data, l, s)
				if strings.HasPrefix(s.Function, "#") {
					if v&ordinalBit == 0 || "#"+strconv.FormatUint(v&0xffff, 10) != s.Function {
						t.Errorf("%s: the slot holds %#x, want an import by ordinal", s.Display(), v)
					}
					continue
				}
				if name := nameAt(t, data, l, uint32(v&0x7fffffff)); name != s.Function {
					t.Errorf("%s: the slot points at the name %q", s.Display(), name)
				}
			}
			if tc.opts.DelayImports != nil {
				delay := 0
				for _, s := range l.Slots {
					if s.Delay != strings.HasSuffix(s.Library, " (delay-load)") {
						t.Errorf("%s: Delay = %v", s.Display(), s.Delay)
					}
					if s.Delay {
						delay++
					}
				}
				if delay != 2 {
					t.Errorf("%d delay-load slots, want 2", delay)
				}
			}
		})
	}
}

func TestLayoutMapsAddressesBothWays(t *testing.T) {
	data := testfixtures.PE(testfixtures.PEOptions{Imports: []testfixtures.PEImport{{Library: "k.dll", Functions: []string{"A"}}}})
	res := parseBytes(t, data)
	l := res.Layout
	if len(l.Sections) != 3 || l.Sections[0].Name != ".text" || !l.Sections[0].Executable() || l.Sections[1].Executable() {
		t.Fatalf("sections = %+v", l.Sections)
	}
	text := l.Sections[0]
	if text.RVA != 0x1000 || text.RawOffset != 0x200 || text.RawSize != 0x200 || text.Mapped() != 0x200 {
		t.Fatalf(".text = %+v", text)
	}

	for i, s := range l.Sections {
		for _, d := range []int64{0, 1, s.Mapped() / 2, s.Mapped() - 1} {
			off := int64(s.RawOffset) + d
			idx, va, ok := l.SectionAtOffset(off)
			if !ok || idx != i || va != l.ImageBase+uint64(s.RVA)+uint64(d) {
				t.Errorf("SectionAtOffset(%#x) = %d, %#x, %v", off, idx, va, ok)
				continue
			}
			idx, back, ok := l.SectionAtVA(va)
			if !ok || idx != i || back != off {
				t.Errorf("SectionAtVA(%#x) = %d, %#x, %v; want section %d, offset %#x", va, idx, back, ok, i, off)
			}
		}
	}
	for _, va := range []uint64{0, l.ImageBase - 1, l.ImageBase + 0xfff, l.ImageBase + 0x1200, l.ImageBase + 0xffffffff, l.ImageBase + 1<<40, ^uint64(0)} {
		if idx, off, ok := l.SectionAtVA(va); ok {
			t.Errorf("SectionAtVA(%#x) = %d, %#x: the address is in no section", va, idx, off)
		}
	}
	for _, off := range []int64{-1, 0, 0x1ff, int64(len(data)), int64(len(data)) + 5} {
		if idx, va, ok := l.SectionAtOffset(off); ok {
			t.Errorf("SectionAtOffset(%#x) = %d, %#x: the offset is in no section", off, idx, va)
		}
	}
}

func TestLayoutMappedStopsAtTheVirtualSize(t *testing.T) {
	s := Section{VirtualSize: 0x80, RawSize: 0x200, RawLen: 0x200}
	if s.Mapped() != 0x80 {
		t.Errorf("Mapped() = %#x, want the virtual size 0x80", s.Mapped())
	}
	s = Section{VirtualSize: 0x400, RawSize: 0x200, RawLen: 0x100}
	if s.Mapped() != 0x100 {
		t.Errorf("Mapped() = %#x, want the bytes that exist in the file", s.Mapped())
	}
	s = Section{RawSize: 0x200, RawLen: 0x200}
	if s.Mapped() != 0x200 {
		t.Errorf("Mapped() = %#x, want the raw length when the virtual size is zero", s.Mapped())
	}
	if (Section{Characteristics: 0x20}).Executable() != true || (Section{Characteristics: 0x40000040}).Executable() {
		t.Error("Executable() must follow IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE")
	}
}

func TestLayoutOfDamagedImages(t *testing.T) {
	good := testfixtures.PE(testfixtures.PEOptions{})
	// Every prefix of a valid image either fails cleanly or gives a layout whose
	// slots and sections all map to bytes that exist.
	for n := 0; n <= len(good); n += 7 {
		data := good[:n]
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(n), limits.ForSize(int64(n)))
		if err != nil {
			continue
		}
		l := res.Layout
		for _, s := range l.Sections {
			if s.RawLen < 0 || s.RawLen > int64(s.RawSize) || (s.RawLen > 0 && int64(s.RawOffset)+s.RawLen > int64(n)) {
				t.Fatalf("prefix %d: section %+v reaches past the file", n, s)
			}
		}
		for _, s := range l.Slots {
			if s.VA != l.ImageBase+uint64(s.RVA) {
				t.Fatalf("prefix %d: slot %+v", n, s)
			}
		}
	}

	// A table whose address array is not where the name array says is still bounded.
	bad := slices.Clone(good)
	binary.LittleEndian.PutUint32(bad[testfixtures.PEDataDirectoryOffset(64, 1):], 0xfffffff0)
	res := parseBytes(t, bad)
	if len(res.Layout.Slots) != 0 {
		t.Errorf("an import directory outside the file gave slots: %+v", res.Layout.Slots)
	}
}

func TestLayoutSlotsAreCappedLikeTheLists(t *testing.T) {
	var fns []string
	for i := range 300 {
		fns = append(fns, "Fn"+strconv.Itoa(i))
	}
	data := testfixtures.PE(testfixtures.PEOptions{Imports: []testfixtures.PEImport{{Library: "big.dll", Functions: fns}}})
	lim := limits.Limits{MaxList: 100}
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), lim)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Imports[0].Functions); got != 100 {
		t.Fatalf("recorded functions = %d, want the cap of 100", got)
	}
	if got := len(res.Layout.Slots); got != 100 {
		t.Errorf("slots = %d, want as many as the recorded functions (100)", got)
	}
	if res.Layout.Slots[99].Function != "Fn99" || res.Layout.Slots[99].RVA != res.Layout.Slots[0].RVA+99*8 {
		t.Errorf("the last slot = %+v", res.Layout.Slots[99])
	}
}

// TestLoadLayoutIsTheLayoutOfParse: the light reader the code views use must map
// addresses exactly as the full parse does, for whole images and for damaged ones.
func TestLoadLayoutIsTheLayoutOfParse(t *testing.T) {
	imports := []testfixtures.PEImport{
		{Library: "KERNEL32.dll", Functions: []string{"ExitProcess", "VirtualAllocEx"}},
		{Library: "WS2_32.dll", Functions: []string{"#23", "connect"}},
	}
	delay := []testfixtures.PEImport{{Library: "shell32.dll", Functions: []string{"ShellExecuteW", "#42"}}}
	images := map[string][]byte{
		"default":    testfixtures.PE(testfixtures.PEOptions{}),
		"imports":    testfixtures.PE(testfixtures.PEOptions{Imports: imports}),
		"pe32":       testfixtures.PE(testfixtures.PEOptions{Imports: imports, Bits: 32}),
		"delay-load": testfixtures.PE(testfixtures.PEOptions{Imports: imports, DelayImports: delay}),
	}
	for name, whole := range images {
		for n := 0; n <= len(whole); n += max(1, len(whole)/97) {
			data := whole[:n]
			lim := limits.ForSize(int64(n))
			want, _ := Parse(context.Background(), bytes.NewReader(data), int64(n), lim)
			got, err := LoadLayout(context.Background(), bytes.NewReader(data), int64(n), lim, true)
			if (want == nil) != (got == nil) {
				t.Fatalf("%s cut at %d: Parse result %v, LoadLayout result %v (error %v)", name, n, want != nil, got != nil, err)
			}
			if want == nil {
				if err == nil {
					t.Errorf("%s cut at %d: LoadLayout returned neither a layout nor an error", name, n)
				}
				continue
			}
			if !reflect.DeepEqual(*got, want.Layout) {
				t.Fatalf("%s cut at %d:\nLoadLayout %+v\nParse      %+v", name, n, *got, want.Layout)
			}
			bare, err := LoadLayout(context.Background(), bytes.NewReader(data), int64(n), lim, false)
			if err != nil || bare == nil {
				t.Fatalf("%s cut at %d: LoadLayout without slots: %v", name, n, err)
			}
			noSlots := want.Layout
			noSlots.Slots = []ImportSlot{}
			if !reflect.DeepEqual(*bare, noSlots) {
				t.Fatalf("%s cut at %d: without slots %+v, want %+v", name, n, *bare, noSlots)
			}
		}
	}

	l, err := LoadLayout(context.Background(), bytes.NewReader(images["imports"]), int64(len(images["imports"])), limits.ForSize(int64(len(images["imports"]))), true)
	if err != nil || !l.HasEntry || l.Entry != l.ImageBase+0x1000 || len(l.Slots) != 4 {
		t.Errorf("layout = %+v (%v)", l, err)
	}
	if _, err := LoadLayout(context.Background(), strings.NewReader("this is not a PE image, just text of some length, enough for a header"), 70, limits.ForSize(70), true); err == nil {
		t.Error("a file that is not a PE image has no layout")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if l, err := LoadLayout(cancelled, bytes.NewReader(images["imports"]), int64(len(images["imports"])), limits.Limits{}, true); l != nil || err == nil {
		t.Errorf("a cancelled load must stop at once: %v, %v", l, err)
	}
}

func TestMachineNameIsExported(t *testing.T) {
	for machine, want := range map[uint16]string{0x14c: "x86", 0x8664: "x86-64", 0xaa64: "ARM64", 0x1234: "0x1234"} {
		if got := MachineName(machine); got != want {
			t.Errorf("MachineName(%#x) = %q, want %q", machine, got, want)
		}
	}
}
