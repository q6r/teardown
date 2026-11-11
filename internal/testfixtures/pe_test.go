package testfixtures

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"reflect"
	"testing"
)

func peOpen(t *testing.T, b []byte) *pe.File {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("debug/pe rejected the fixture: %v", err)
	}
	return f
}

func TestPE_DefaultIsValidPE32Plus(t *testing.T) {
	b := PE(PEOptions{})
	f := peOpen(t, b)
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("machine = %#x", f.Machine)
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("optional header is %T, want *pe.OptionalHeader64", f.OptionalHeader)
	}
	if oh.ImageBase != 0x140000000 || oh.Subsystem != 3 || oh.NumberOfRvaAndSizes != 16 {
		t.Errorf("optional header = %+v", oh)
	}
	if oh.DllCharacteristics != 0x8160 {
		t.Errorf("DllCharacteristics = %#x, want 0x8160", oh.DllCharacteristics)
	}
	names := make([]string, 0, len(f.Sections))
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	if want := []string{".text", ".rdata", ".data"}; !reflect.DeepEqual(names, want) {
		t.Errorf("sections = %v, want %v", names, want)
	}
	syms, err := f.ImportedSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ExitProcess:kernel32.dll"}; !reflect.DeepEqual(syms, want) {
		t.Errorf("imports = %v, want %v", syms, want)
	}
	if string(b[:2]) != "MZ" || string(b[PEOffset:PEOffset+4]) != "PE\x00\x00" {
		t.Error("DOS or PE signature misplaced")
	}
}

func TestPE_ThirtyTwoBitAndVariants(t *testing.T) {
	tests := []struct {
		name      string
		o         PEOptions
		machine   uint16
		is64      bool
		wantChars uint16
		wantSub   uint16
	}{
		{"pe32", PEOptions{Bits: 32}, pe.IMAGE_FILE_MACHINE_I386, false, 0x0122, 3},
		{"dll64", PEOptions{DLL: true}, pe.IMAGE_FILE_MACHINE_AMD64, true, 0x2022, 2},
		{"dll32", PEOptions{Bits: 32, DLL: true}, pe.IMAGE_FILE_MACHINE_I386, false, 0x2122, 2},
		{"driver", PEOptions{Driver: true}, pe.IMAGE_FILE_MACHINE_AMD64, true, 0x1022, 1},
		{"arm64", PEOptions{Machine: pe.IMAGE_FILE_MACHINE_ARM64}, pe.IMAGE_FILE_MACHINE_ARM64, true, 0x0022, 3},
		{"chars adjusted", PEOptions{CharsSet: PECharRelocsStripped, CharsClear: PECharLargeAddressAware}, pe.IMAGE_FILE_MACHINE_AMD64, true, 0x0003, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := peOpen(t, PE(tc.o))
			if f.Machine != tc.machine || f.Characteristics != tc.wantChars {
				t.Errorf("machine %#x chars %#x, want %#x %#x", f.Machine, f.Characteristics, tc.machine, tc.wantChars)
			}
			switch oh := f.OptionalHeader.(type) {
			case *pe.OptionalHeader64:
				if !tc.is64 || oh.Subsystem != tc.wantSub {
					t.Errorf("PE32+ header %+v", oh)
				}
			case *pe.OptionalHeader32:
				if tc.is64 || oh.Subsystem != tc.wantSub {
					t.Errorf("PE32 header %+v", oh)
				}
			default:
				t.Fatalf("unexpected optional header %T", oh)
			}
		})
	}
}

func TestPE_ImportsAndDirectories(t *testing.T) {
	o := PEOptions{
		Imports: []PEImport{
			{Library: "kernel32.dll", Functions: []string{"ExitProcess", "GetStdHandle"}},
			{Library: "ws2_32.dll", Functions: []string{"#23", "WSAStartup"}},
		},
		DelayImports:      []PEImport{{Library: "shell32.dll", Functions: []string{"ShellExecuteW"}}},
		Exports:           []PEExport{{Name: "zeta"}, {Name: "alpha"}, {Name: "fwd", Forwarder: "NTDLL.RtlAllocateHeap"}},
		ExportOrdinalOnly: 2,
		PDBPath:           `C:\build\fixture.pdb`,
		TLSCallbacks:      2,
		GuardCF:           true,
		SecurityCookie:    true,
		DotNet:            true,
	}
	for _, bits := range []int{64, 32} {
		o.Bits = bits
		b := PE(o)
		f := peOpen(t, b)
		syms, err := f.ImportedSymbols()
		if err != nil {
			t.Fatal(err)
		}
		// debug/pe skips imports by ordinal.
		want := []string{"ExitProcess:kernel32.dll", "GetStdHandle:kernel32.dll", "WSAStartup:ws2_32.dll"}
		if !reflect.DeepEqual(syms, want) {
			t.Errorf("bits %d: imports = %v, want %v", bits, syms, want)
		}
		for _, idx := range []int{0, 1, 6, 9, 10, 13, 14} {
			off := PEDataDirectoryOffset(bits, idx)
			if rva := binary.LittleEndian.Uint32(b[off:]); rva == 0 {
				t.Errorf("bits %d: data directory %d is empty", bits, idx)
			}
		}
	}
}

func TestPE_SectionsLongNamesAndRaw(t *testing.T) {
	b := PE(PEOptions{Sections: []PESection{
		{Name: "UPX0", NoRaw: true, VirtualSize: 0x10000, Characteristics: PESectionRWX},
		{Name: ".debug_abbrev", Data: []byte("abc")},
		{Name: ".custom", Data: bytes.Repeat([]byte{7}, 700), Characteristics: PESectionRData},
	}})
	f := peOpen(t, b)
	if len(f.Sections) != 6 {
		t.Fatalf("sections = %d", len(f.Sections))
	}
	upx, dbg, custom := f.Sections[3], f.Sections[4], f.Sections[5]
	if upx.Name != "UPX0" || upx.Size != 0 || upx.VirtualSize != 0x10000 || upx.Characteristics != PESectionRWX {
		t.Errorf("UPX0 = %+v", upx.SectionHeader)
	}
	if dbg.Name != ".debug_abbrev" {
		t.Errorf("long name resolved to %q", dbg.Name)
	}
	if custom.Size != 0x400 || custom.VirtualSize != 700 {
		t.Errorf(".custom sizes = %d/%d", custom.Size, custom.VirtualSize)
	}
	data, err := custom.Data()
	if err != nil || data[0] != 7 {
		t.Errorf(".custom data = %v, %v", data[:1], err)
	}
}

func TestPE_SignedAndOverlay(t *testing.T) {
	plain := PE(PEOptions{})
	over := PE(PEOptions{Overlay: []byte("0123456789")})
	signed := PE(PEOptions{Overlay: []byte("0123456789"), Signed: true})
	if len(over) != len(plain)+10 {
		t.Errorf("overlay grew the file by %d, want 10", len(over)-len(plain))
	}
	if !bytes.Equal(over[:len(plain)], plain) {
		t.Error("overlay must not alter the image")
	}
	off := PEDataDirectoryOffset(64, 4)
	certAt := binary.LittleEndian.Uint32(signed[off:])
	certLen := binary.LittleEndian.Uint32(signed[off+4:])
	if int(certAt)+int(certLen) != len(signed) || certAt%8 != 0 {
		t.Errorf("certificate at %d len %d in a %d byte file", certAt, certLen, len(signed))
	}
	if got := binary.LittleEndian.Uint16(signed[certAt+6:]); got != 2 {
		t.Errorf("certificate type = %d, want 2 (PKCS#7)", got)
	}
	peOpen(t, signed)
}

func TestPE_IsDeterministicAndIndependentOfInput(t *testing.T) {
	o := PEOptions{Exports: []PEExport{{Name: "b"}, {Name: "a"}}, PDBPath: "x.pdb", Timestamp: 1700000000}
	first, second := PE(o), PE(o)
	if !bytes.Equal(first, second) {
		t.Fatal("PE is not deterministic")
	}
	if o.Exports[0].Name != "b" {
		t.Fatal("PE must not reorder the caller's slices")
	}
}

func TestPE_NoImportsAndOffsets(t *testing.T) {
	b := PE(PEOptions{NoImports: true})
	off := PEDataDirectoryOffset(64, 1)
	if binary.LittleEndian.Uint32(b[off:]) != 0 {
		t.Error("NoImports must leave the import directory empty")
	}
	if got := PESectionHeaderOffset(64, 0); got != PEOptionalOffset+240 {
		t.Errorf("section header offset = %d", got)
	}
	if got := PESectionHeaderOffset(32, 2); got != PEOptionalOffset+224+80 {
		t.Errorf("section header offset = %d", got)
	}
	if string(b[PESectionHeaderOffset(64, 0):][:5]) != ".text" {
		t.Error("first section header is not .text")
	}
}
