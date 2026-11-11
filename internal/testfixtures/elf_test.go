package testfixtures

import (
	"bytes"
	"debug/elf"
	"slices"
	"testing"
)

func elfOpen(t *testing.T, data []byte) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/elf rejected the fixture: %v", err)
	}
	return f
}

func elfSectionNames(f *elf.File) []string {
	var names []string
	for _, s := range f.Sections[1:] {
		names = append(names, s.Name)
	}
	return names
}

func elfProgTypes(f *elf.File) []elf.ProgType {
	var types []elf.ProgType
	for _, p := range f.Progs {
		types = append(types, p.Type)
	}
	return types
}

func TestELF_ZeroValueIsMinimalDynamicPIE(t *testing.T) {
	f := elfOpen(t, ELF(ELFOptions{}))
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_DYN || f.Machine != elf.EM_X86_64 {
		t.Fatalf("header = %v %v %v %v", f.Class, f.Data, f.Type, f.Machine)
	}
	wantSections := []string{".interp", ".text", ".dynsym", ".dynstr", ".dynamic", ".shstrtab"}
	// The order follows the layout groups: read-only first, writable after.
	if got := elfSectionNames(f); !slices.Equal(got, []string{".interp", ".dynsym", ".dynstr", ".text", ".dynamic", ".shstrtab"}) {
		t.Fatalf("sections = %v (set %v)", got, wantSections)
	}
	wantProgs := []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}
	if got := elfProgTypes(f); !slices.Equal(got, wantProgs) {
		t.Fatalf("program headers = %v, want %v", got, wantProgs)
	}
	if f.Section(".symtab") != nil {
		t.Error("the zero value must be stripped (no .symtab)")
	}
	text := f.Section(".text")
	if f.Entry != text.Addr {
		t.Errorf("entry %#x != .text address %#x", f.Entry, text.Addr)
	}
	if text.Flags&elf.SHF_EXECINSTR == 0 || text.Flags&elf.SHF_ALLOC == 0 {
		t.Errorf(".text flags = %v", text.Flags)
	}
}

func TestELF_IsDeterministic(t *testing.T) {
	opts := ELFOptions{Needed: []string{"libc.so.6"}, Imports: []ELFImport{{Name: "puts", Library: "libc.so.6", Version: "GLIBC_2.2.5"}}, Symbols: []string{"main"}}
	if !bytes.Equal(ELF(opts), ELF(opts)) {
		t.Fatal("two builds of the same options differ")
	}
}

func TestELF_HeaderVariants(t *testing.T) {
	tests := []struct {
		name      string
		opts      ELFOptions
		class     elf.Class
		data      elf.Data
		typ       elf.Type
		machine   elf.Machine
		progTypes []elf.ProgType
	}{
		{"elf32 little endian arm", ELFOptions{Bits: 32, Machine: ELFMachineARM}, elf.ELFCLASS32, elf.ELFDATA2LSB, elf.ET_DYN, elf.EM_ARM,
			[]elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}},
		{"elf32 big endian", ELFOptions{Bits: 32, BigEndian: true, Machine: ELFMachine386}, elf.ELFCLASS32, elf.ELFDATA2MSB, elf.ET_DYN, elf.EM_386,
			[]elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}},
		{"elf64 big endian aarch64", ELFOptions{BigEndian: true, Machine: ELFMachineAArch64}, elf.ELFCLASS64, elf.ELFDATA2MSB, elf.ET_DYN, elf.EM_AARCH64,
			[]elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}},
		{"fixed address executable", ELFOptions{Type: ELFTypeExec}, elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64,
			[]elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}},
		{"static executable", ELFOptions{Type: ELFTypeExec, Static: true}, elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64,
			[]elf.ProgType{elf.PT_LOAD, elf.PT_GNU_STACK}},
		{"shared object without interpreter", ELFOptions{NoInterp: true}, elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_DYN, elf.EM_X86_64,
			[]elf.ProgType{elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}},
		{"relocatable object", ELFOptions{Type: ELFTypeRel}, elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_REL, elf.EM_X86_64, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := elfOpen(t, ELF(tc.opts))
			if f.Class != tc.class || f.Data != tc.data || f.Type != tc.typ || f.Machine != tc.machine {
				t.Fatalf("header = %v %v %v %v", f.Class, f.Data, f.Type, f.Machine)
			}
			if got := elfProgTypes(f); !slices.Equal(got, tc.progTypes) {
				t.Fatalf("program headers = %v, want %v", got, tc.progTypes)
			}
		})
	}
}

func TestELF_FixedAddressExecutableUsesBase(t *testing.T) {
	f := elfOpen(t, ELF(ELFOptions{Type: ELFTypeExec}))
	if got := f.Section(".text").Addr; got < 0x400000 {
		t.Fatalf(".text at %#x, want >= 0x400000", got)
	}
	f32 := elfOpen(t, ELF(ELFOptions{Type: ELFTypeExec, Bits: 32}))
	if got := f32.Section(".text").Addr; got < 0x08048000 {
		t.Fatalf("32-bit .text at %#x, want >= 0x08048000", got)
	}
}

func TestELF_DynamicSectionContents(t *testing.T) {
	data := ELF(ELFOptions{
		Needed:   []string{"libc.so.6", "libm.so.6"},
		RPath:    []string{"/opt/a", "$ORIGIN/lib"},
		RunPath:  []string{"/opt/b"},
		Soname:   "libfixture.so.1",
		DynFlags: ELFDynFlagBindNow, DynFlags1: ELFDynFlag1Now | ELFDynFlag1PIE, BindNowTag: true,
	})
	f := elfOpen(t, data)
	libs, err := f.ImportedLibraries()
	if err != nil || !slices.Equal(libs, []string{"libc.so.6", "libm.so.6"}) {
		t.Fatalf("needed = %v, %v", libs, err)
	}
	for tag, want := range map[elf.DynTag]string{elf.DT_RPATH: "/opt/a:$ORIGIN/lib", elf.DT_RUNPATH: "/opt/b", elf.DT_SONAME: "libfixture.so.1"} {
		got, err := f.DynString(tag)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("%v = %v, %v; want %q", tag, got, err, want)
		}
	}
	if v, err := f.DynValue(elf.DT_FLAGS); err != nil || len(v) != 1 || v[0] != uint64(elf.DF_BIND_NOW) {
		t.Errorf("DT_FLAGS = %v, %v", v, err)
	}
	if v, err := f.DynValue(elf.DT_FLAGS_1); err != nil || len(v) != 1 || v[0] != uint64(elf.DF_1_NOW|elf.DF_1_PIE) {
		t.Errorf("DT_FLAGS_1 = %v, %v", v, err)
	}
	if v, err := f.DynValue(elf.DT_BIND_NOW); err != nil || len(v) != 1 {
		t.Errorf("DT_BIND_NOW = %v, %v", v, err)
	}
}

func TestELF_VersionedImportsExportsAndSymbols(t *testing.T) {
	for _, bits := range []int{64, 32} {
		data := ELF(ELFOptions{
			Bits: bits,
			Imports: []ELFImport{
				{Name: "puts", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
				{Name: "malloc", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
				{Name: "sqrt", Library: "libm.so.6", Version: "GLIBC_2.29"},
				{Name: "__stack_chk_fail", Library: "libc.so.6", Version: "GLIBC_2.4"},
				{Name: "plain"},
				{Name: "__gmon_start__", Weak: true},
			},
			Exports: []string{"api_one", "api_two"},
			Symbols: []string{"main", "helper"},
		})
		f := elfOpen(t, data)
		syms, err := f.DynamicSymbols()
		if err != nil {
			t.Fatalf("bits %d: %v", bits, err)
		}
		type row struct{ name, lib, ver string }
		var got []row
		for _, s := range syms {
			got = append(got, row{s.Name, s.Library, s.Version})
		}
		want := []row{
			{"puts", "libc.so.6", "GLIBC_2.2.5"}, {"malloc", "libc.so.6", "GLIBC_2.2.5"},
			{"sqrt", "libm.so.6", "GLIBC_2.29"}, {"__stack_chk_fail", "libc.so.6", "GLIBC_2.4"},
			{"plain", "", ""}, {"__gmon_start__", "", ""}, {"api_one", "", ""}, {"api_two", "", ""},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("bits %d: dynamic symbols\n got %v\nwant %v", bits, got, want)
		}
		if elf.ST_BIND(syms[5].Info) != elf.STB_WEAK || syms[5].Section != elf.SHN_UNDEF {
			t.Errorf("bits %d: weak import = %+v", bits, syms[5])
		}
		if syms[6].Section == elf.SHN_UNDEF {
			t.Errorf("bits %d: export must be defined: %+v", bits, syms[6])
		}
		table, err := f.Symbols()
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, s := range table {
			names = append(names, s.Name)
		}
		if !slices.Equal(names, []string{"fixture.c", "main", "helper"}) {
			t.Errorf("bits %d: .symtab = %v", bits, names)
		}
	}
}

func TestELF_ProgramHeaderOptions(t *testing.T) {
	tests := []struct {
		name string
		opts ELFOptions
		want []elf.ProgType
		// flags of PT_GNU_STACK when present
		stack elf.ProgFlag
	}{
		{"default stack", ELFOptions{}, []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}, elf.PF_R | elf.PF_W},
		{"executable stack", ELFOptions{Stack: ELFStackRWX}, []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK}, elf.PF_R | elf.PF_W | elf.PF_X},
		{"no stack header", ELFOptions{Stack: ELFStackNone}, []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC}, 0},
		{"relro", ELFOptions{RELRO: true}, []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_RELRO, elf.PT_GNU_STACK}, elf.PF_R | elf.PF_W},
		{"notes", ELFOptions{BuildID: bytes.Repeat([]byte{0xab}, 20), GoBuildID: "go-id"}, []elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_NOTE, elf.PT_GNU_STACK}, elf.PF_R | elf.PF_W},
		{"extra segment", ELFOptions{Segments: []ELFSegment{{Type: ELFSegmentLoad, Flags: ELFSegmentFlagR | ELFSegmentFlagW | ELFSegmentFlagX, Data: []byte("payload")}}},
			[]elf.ProgType{elf.PT_INTERP, elf.PT_LOAD, elf.PT_LOAD, elf.PT_DYNAMIC, elf.PT_GNU_STACK, elf.PT_LOAD}, elf.PF_R | elf.PF_W},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := elfOpen(t, ELF(tc.opts))
			if got := elfProgTypes(f); !slices.Equal(got, tc.want) {
				t.Fatalf("program headers = %v, want %v", got, tc.want)
			}
			for _, p := range f.Progs {
				if p.Type == elf.PT_GNU_STACK && p.Flags != tc.stack {
					t.Errorf("PT_GNU_STACK flags = %v, want %v", p.Flags, tc.stack)
				}
			}
		})
	}
}

func TestELF_NotesAndDebugSections(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	f := elfOpen(t, ELF(ELFOptions{BuildID: id, GoBuildID: "abc/def", DebugInfo: true}))
	bid := f.Section(".note.gnu.build-id")
	if bid == nil || bid.Type != elf.SHT_NOTE {
		t.Fatalf("missing build-id note: %v", elfSectionNames(f))
	}
	data, err := bid.Data()
	if err != nil || !bytes.HasSuffix(data, id) {
		t.Fatalf("build-id note = %x, %v", data, err)
	}
	if f.Section(".note.go.buildid") == nil || f.Section(".debug_info") == nil {
		t.Fatalf("missing sections: %v", elfSectionNames(f))
	}
}

func TestELF_ExtraSectionsAreRoutedByFlags(t *testing.T) {
	f := elfOpen(t, ELF(ELFOptions{Sections: []ELFSection{
		{Name: ".rodata", Flags: ELFSectionFlagAlloc, Data: []byte("ro")},
		{Name: ".evil", Flags: ELFSectionFlagAlloc | ELFSectionFlagWrite | ELFSectionFlagExec, Data: []byte{0xcc}},
		{Name: ".comment", Data: []byte("GCC")},
		{Name: ".bss2", Type: ELFSectionNobits, Flags: ELFSectionFlagAlloc | ELFSectionFlagWrite, Data: make([]byte, 64)},
	}}))
	byName := map[string]*elf.Section{}
	for _, s := range f.Sections {
		byName[s.Name] = s
	}
	if byName[".rodata"].Flags&elf.SHF_WRITE != 0 || byName[".rodata"].Flags&elf.SHF_ALLOC == 0 {
		t.Errorf(".rodata flags = %v", byName[".rodata"].Flags)
	}
	if want := elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_EXECINSTR; byName[".evil"].Flags != want {
		t.Errorf(".evil flags = %v", byName[".evil"].Flags)
	}
	if byName[".comment"].Flags&elf.SHF_ALLOC != 0 {
		t.Errorf(".comment must be unmapped")
	}
	if byName[".bss2"].Type != elf.SHT_NOBITS || byName[".bss2"].Size != 64 {
		t.Errorf(".bss2 = %+v", byName[".bss2"].SectionHeader)
	}
	// Every mapped section must be covered by a PT_LOAD segment.
	for name, s := range byName {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS {
			continue
		}
		covered := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && s.Addr >= p.Vaddr && s.Addr+s.Size <= p.Vaddr+p.Filesz {
				covered = true
			}
		}
		if !covered {
			t.Errorf("section %s (%#x+%d) is not covered by a PT_LOAD", name, s.Addr, s.Size)
		}
	}
}

func TestELF_NoSectionHeaderTable(t *testing.T) {
	f := elfOpen(t, ELF(ELFOptions{NoSections: true}))
	if len(f.Sections) != 0 {
		t.Fatalf("sections = %v", elfSectionNames(f))
	}
	if len(f.Progs) == 0 {
		t.Fatal("program headers must remain")
	}
}

func TestELF_TextDataOverride(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAA, 0x55}, 64)
	f := elfOpen(t, ELF(ELFOptions{TextData: payload}))
	got, err := f.Section(".text").Data()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf(".text = %x, %v", got, err)
	}
}
