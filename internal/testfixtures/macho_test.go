package testfixtures

import (
	"bytes"
	"debug/macho"
	"slices"
	"testing"
)

func machoOpen(t *testing.T, data []byte) *macho.File {
	t.Helper()
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/macho rejected the fixture: %v", err)
	}
	return f
}

func machoLoadCommands(f *macho.File) []uint32 {
	var cmds []uint32
	for _, l := range f.Loads {
		cmds = append(cmds, f.ByteOrder.Uint32(l.Raw()))
	}
	return cmds
}

func machoSegmentNames(f *macho.File) []string {
	var names []string
	for _, l := range f.Loads {
		if s, ok := l.(*macho.Segment); ok {
			names = append(names, s.Name)
		}
	}
	return names
}

func TestMachO_ZeroValueIsMinimalPIEExecutable(t *testing.T) {
	f := machoOpen(t, MachO(MachOOptions{}))
	if f.Cpu != macho.CpuAmd64 || f.Type != macho.TypeExec || f.Magic != macho.Magic64 {
		t.Fatalf("header = %v %v %#x", f.Cpu, f.Type, f.Magic)
	}
	if f.Flags != MachOFlagNoUndefs|MachOFlagDyldLink|MachOFlagTwoLevel|MachOFlagPIE {
		t.Errorf("flags = %#x", f.Flags)
	}
	if got := machoSegmentNames(f); !slices.Equal(got, []string{"__PAGEZERO", "__TEXT", "__DATA"}) {
		t.Errorf("segments = %v", got)
	}
	var secs []string
	for _, s := range f.Sections {
		secs = append(secs, s.Seg+","+s.Name)
	}
	if !slices.Equal(secs, []string{"__TEXT,__text", "__DATA,__data"}) {
		t.Errorf("sections = %v", secs)
	}
	text := f.Section("__text")
	if text == nil || text.Offset == 0 || text.Size != 16 {
		t.Fatalf("__text = %+v", text)
	}
	data, err := text.Data()
	if err != nil || data[15] != 0xc3 {
		t.Errorf("text data = %x, %v", data, err)
	}
	if f.Symtab != nil || f.Dysymtab != nil {
		t.Error("the zero value has no symbols")
	}
}

func TestMachO_IsDeterministic(t *testing.T) {
	opts := MachOOptions{Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, Undefined: []MachOSymbol{{Name: "_puts", Ordinal: 1}}, CodeSignature: true}
	if !bytes.Equal(MachO(opts), MachO(opts)) {
		t.Fatal("two builds of the same options differ")
	}
}

func TestMachO_HeaderVariants(t *testing.T) {
	tests := []struct {
		name  string
		opts  MachOOptions
		cpu   macho.Cpu
		typ   macho.Type
		magic uint32
		flags uint32
		segs  []string
	}{
		{"arm64 executable", MachOOptions{CPU: MachOCPUARM64}, macho.CpuArm64, macho.TypeExec, macho.Magic64,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagPIE, []string{"__PAGEZERO", "__TEXT", "__DATA"}},
		{"32-bit x86", MachOOptions{Bits: 32}, macho.Cpu386, macho.TypeExec, macho.Magic32,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagPIE, []string{"__PAGEZERO", "__TEXT", "__DATA"}},
		{"32-bit big endian", MachOOptions{Bits: 32, BigEndian: true}, macho.Cpu386, macho.TypeExec, macho.Magic32,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagPIE, []string{"__PAGEZERO", "__TEXT", "__DATA"}},
		{"64-bit big endian", MachOOptions{BigEndian: true}, macho.CpuAmd64, macho.TypeExec, macho.Magic64,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagPIE, []string{"__PAGEZERO", "__TEXT", "__DATA"}},
		{"dylib", MachOOptions{Type: MachOTypeDylib, InstallName: "@rpath/libx.dylib"}, macho.CpuAmd64, macho.TypeDylib, macho.Magic64,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel, []string{"__TEXT", "__DATA"}},
		{"bundle", MachOOptions{Type: MachOTypeBundle}, macho.CpuAmd64, macho.TypeBundle, macho.Magic64,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel, []string{"__TEXT", "__DATA"}},
		{"object", MachOOptions{Type: MachOTypeObject}, macho.CpuAmd64, macho.TypeObj, macho.Magic64,
			machoFlagSubsectionsViaSyms, []string{"__TEXT", "__DATA"}},
		{"non-PIE with executable stack", MachOOptions{DropFlags: MachOFlagPIE, AddFlags: MachOFlagAllowStackExecute}, macho.CpuAmd64, macho.TypeExec, macho.Magic64,
			MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagAllowStackExecute, []string{"__PAGEZERO", "__TEXT", "__DATA"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := machoOpen(t, MachO(tc.opts))
			if f.Cpu != tc.cpu || f.Type != tc.typ || f.Magic != tc.magic || f.Flags != tc.flags {
				t.Fatalf("header = %v %v %#x flags %#x", f.Cpu, f.Type, f.Magic, f.Flags)
			}
			if got := machoSegmentNames(f); !slices.Equal(got, tc.segs) {
				t.Errorf("segments = %v, want %v", got, tc.segs)
			}
			if tc.opts.BigEndian && f.ByteOrder.String() != "BigEndian" {
				t.Errorf("byte order = %v", f.ByteOrder)
			}
		})
	}
}

func TestMachO_DylibsRPathsUUIDAndLoadCommands(t *testing.T) {
	uuid := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, bits := range []int{64, 32} {
		f := machoOpen(t, MachO(MachOOptions{
			Bits:           bits,
			Dylibs:         []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"},
			WeakDylibs:     []string{"/usr/lib/libweak.dylib"},
			ReexportDylibs: []string{"/usr/lib/libre.dylib"},
			RPaths:         []string{"@executable_path/../Frameworks", "/opt/lib"},
			UUID:           uuid, CodeSignature: true, EncryptionInfo: true, CryptID: 1,
			BuildPlatform: 1, MinOS: 0x000e0000, SDK: 0x000e0200, Main: true,
		}))
		libs, err := f.ImportedLibraries()
		if err != nil {
			t.Fatal(err)
		}
		// debug/macho only exposes LC_LOAD_DYLIB; weak and re-exported dylibs stay raw load commands.
		if want := []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"}; !slices.Equal(libs, want) {
			t.Errorf("bits %d dylibs = %v", bits, libs)
		}
		cmds := machoLoadCommands(f)
		for _, c := range []uint32{machoLCUUID, machoLCBuildVersion, machoLCMain, machoLCRPath, machoLCLoadWeak, machoLCReexport, machoLCCodeSignature, machoLCEncryption, machoLCEncryption64} {
			present := slices.Contains(cmds, c)
			// A 64-bit file carries LC_ENCRYPTION_INFO_64 instead of LC_ENCRYPTION_INFO, a 32-bit file the reverse.
			wantPresent := (c != machoLCEncryption || bits != 64) && (c != machoLCEncryption64 || bits != 32)
			if present != wantPresent {
				t.Errorf("bits %d: load command %#x present=%v, want %v (all: %#x)", bits, c, present, wantPresent, cmds)
			}
		}
	}
}

func TestMachO_SymbolsAndOrdinals(t *testing.T) {
	for _, bits := range []int{64, 32} {
		f := machoOpen(t, MachO(MachOOptions{
			Bits: bits, Dylibs: []string{"/usr/lib/libSystem.B.dylib"},
			Defined:   []string{"_main", "_helper"},
			Undefined: []MachOSymbol{{Name: "_puts", Ordinal: 1}, {Name: "___stack_chk_fail", Ordinal: 1}, {Name: "_dyld_stub_binder"}},
		}))
		if f.Symtab == nil || f.Dysymtab == nil {
			t.Fatalf("bits %d: symtab %v dysymtab %v", bits, f.Symtab, f.Dysymtab)
		}
		var names []string
		for _, s := range f.Symtab.Syms {
			names = append(names, s.Name)
		}
		if !slices.Equal(names, []string{"_main", "_helper", "_puts", "___stack_chk_fail", "_dyld_stub_binder"}) {
			t.Errorf("bits %d: symbols = %v", bits, names)
		}
		imports, err := f.ImportedSymbols()
		if err != nil || !slices.Equal(imports, []string{"_puts", "___stack_chk_fail", "_dyld_stub_binder"}) {
			t.Errorf("bits %d: imported symbols = %v, %v", bits, imports, err)
		}
		if f.Symtab.Syms[2].Desc>>8 != 1 || f.Symtab.Syms[4].Desc>>8 != 0 {
			t.Errorf("library ordinals = %d, %d", f.Symtab.Syms[2].Desc>>8, f.Symtab.Syms[4].Desc>>8)
		}
		if f.Dysymtab.Iundefsym != 2 || f.Dysymtab.Nundefsym != 3 || f.Dysymtab.Nextdefsym != 2 {
			t.Errorf("dysymtab = %+v", f.Dysymtab.DysymtabCmd)
		}
		text := f.Section("__text")
		if f.Symtab.Syms[0].Value != text.Addr {
			t.Errorf("defined symbol value %#x != __text address %#x", f.Symtab.Syms[0].Value, text.Addr)
		}
	}
}

func TestMachO_SegmentsProtectionsAndZerofill(t *testing.T) {
	f := machoOpen(t, MachO(MachOOptions{Segments: []MachOSegment{
		{Name: "__TEXT", InitProt: MachOProtRead | MachOProtExecute, Sections: []MachOSection{{Name: "__text", Data: []byte{0xc3}}, {Name: "__cstring", Data: []byte("hi\x00")}}},
		{Name: "__EVIL", InitProt: 7, Sections: []MachOSection{{Name: "__rwx", Data: []byte{0xcc, 0xcc}}}},
		{Name: "__DATA", InitProt: MachOProtRead | MachOProtWrite, MaxProt: 7, Sections: []MachOSection{{Name: "__bss", Data: make([]byte, 4096), Zerofill: true}}},
	}}))
	byName := map[string]*macho.Segment{}
	for _, l := range f.Loads {
		if s, ok := l.(*macho.Segment); ok {
			byName[s.Name] = s
		}
	}
	if byName["__EVIL"].Prot != 7 || byName["__TEXT"].Prot != 5 || byName["__DATA"].Maxprot != 7 {
		t.Errorf("protections: evil %d text %d data max %d", byName["__EVIL"].Prot, byName["__TEXT"].Prot, byName["__DATA"].Maxprot)
	}
	bss := f.Section("__bss")
	if bss.Size != 4096 || bss.Offset != 0 || bss.Flags&0xff != 1 {
		t.Errorf("__bss = %+v", bss.SectionHeader)
	}
	if byName["__DATA"].Filesz != 0 || byName["__DATA"].Memsz < 4096 {
		t.Errorf("__DATA file/mem size = %d/%d", byName["__DATA"].Filesz, byName["__DATA"].Memsz)
	}
	// Every file-backed section lies inside its segment's file range.
	for _, s := range f.Sections {
		seg := byName[s.Seg]
		if s.Offset != 0 && (uint64(s.Offset) < seg.Offset || uint64(s.Offset)+s.Size > seg.Offset+seg.Filesz) {
			t.Errorf("section %s,%s escapes its segment", s.Seg, s.Name)
		}
	}
}

func TestMachO_VersionMinAndLinkeditOnlyForContent(t *testing.T) {
	f := machoOpen(t, MachO(MachOOptions{VersionMin: 0x000a0f00, SDK: 0x000a0f00}))
	if !slices.Contains(machoLoadCommands(f), machoLCVersionMinMac) {
		t.Error("LC_VERSION_MIN_MACOSX missing")
	}
	if slices.Contains(machoSegmentNames(f), "__LINKEDIT") {
		t.Error("__LINKEDIT must only appear when there are symbols or a signature")
	}
	signed := machoOpen(t, MachO(MachOOptions{CodeSignature: true}))
	if !slices.Contains(machoSegmentNames(signed), "__LINKEDIT") {
		t.Error("a signature needs __LINKEDIT")
	}
	noSym := machoOpen(t, MachO(MachOOptions{NoSymtab: true, Undefined: []MachOSymbol{{Name: "_x"}}}))
	if noSym.Symtab != nil {
		t.Error("NoSymtab must omit LC_SYMTAB")
	}
}

func TestMachO_FatContainer(t *testing.T) {
	amd64 := MachO(MachOOptions{})
	arm64 := MachO(MachOOptions{CPU: MachOCPUARM64, SubCPU: 2})
	data := MachOFat(amd64, arm64)
	ff, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/macho rejected the fat fixture: %v", err)
	}
	if len(ff.Arches) != 2 || ff.Arches[0].Cpu != macho.CpuAmd64 || ff.Arches[1].Cpu != macho.CpuArm64 || ff.Arches[1].SubCpu != 2 {
		t.Fatalf("arches = %+v", ff.Arches)
	}
	for i, a := range ff.Arches {
		if a.Type != macho.TypeExec {
			t.Errorf("arch %d type = %v", i, a.Type)
		}
		if a.Offset%4096 != 0 {
			t.Errorf("arch %d offset %d is not 4 KiB aligned", i, a.Offset)
		}
	}
	if !bytes.Equal(data[ff.Arches[0].Offset:ff.Arches[0].Offset+uint32(len(amd64))], amd64) {
		t.Error("first slice content differs")
	}
	// A big-endian thin slice is described correctly in the fat header.
	be := MachOFat(MachO(MachOOptions{Bits: 32, BigEndian: true}))
	bf, err := macho.NewFatFile(bytes.NewReader(be))
	if err != nil || bf.Arches[0].Cpu != macho.Cpu386 {
		t.Errorf("big-endian slice: %+v, %v", bf, err)
	}
}
