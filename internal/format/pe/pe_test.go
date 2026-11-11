package pe

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

func parseBytes(t *testing.T, data []byte) *Result {
	t.Helper()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func hardeningStatus(res *Result) map[string]string {
	m := map[string]string{}
	for _, h := range res.Hardening {
		m[h.ID] = h.Status
	}
	return m
}

func sectionNames(res *Result) []string {
	names := make([]string, 0, len(res.Sections))
	for _, s := range res.Sections {
		names = append(names, s.Name)
	}
	return names
}

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

func TestParseDefaultFixture(t *testing.T) {
	res := parseBytes(t, testfixtures.PE(testfixtures.PEOptions{}))

	if want := []string{".text", ".rdata", ".data"}; !reflect.DeepEqual(sectionNames(res), want) {
		t.Fatalf("sections = %v, want %v", sectionNames(res), want)
	}
	text, data := res.Sections[0], res.Sections[2]
	if text.VirtualSize != 0x200 || text.RawSize != 0x200 || text.Offset != 0x200 {
		t.Errorf(".text = %+v", text)
	}
	if !reflect.DeepEqual(text.Flags, []string{"R", "X"}) || !reflect.DeepEqual(data.Flags, []string{"R", "W"}) {
		t.Errorf("flags: .text %v, .data %v", text.Flags, data.Flags)
	}
	if text.Entropy <= 0 || text.Entropy >= 1 {
		t.Errorf(".text entropy = %v, want a small positive value (padding bytes)", text.Entropy)
	}
	for _, s := range res.Sections {
		if s.Suspicious || len(s.Reasons) != 0 {
			t.Errorf("section %s must not be suspicious: %v", s.Name, s.Reasons)
		}
	}

	wantImports := []report.Import{{Library: "kernel32.dll", Count: 1, Functions: []string{"ExitProcess"}}}
	if !reflect.DeepEqual(res.Imports, wantImports) {
		t.Errorf("imports = %+v", res.Imports)
	}
	if len(res.Exports) != 0 || res.Exports == nil {
		t.Errorf("exports = %#v, want an empty non-nil slice", res.Exports)
	}
	if res.ImpHash != "f9ade0aa18f660a34a4fa23392e21838" {
		t.Errorf("imphash = %q", res.ImpHash)
	}

	wantHardening := map[string]string{
		report.HardenASLR: "enabled", report.HardenHighEntropyVA: "enabled", report.HardenDEP: "enabled",
		report.HardenCFG: "disabled", report.HardenSEH: "n/a", report.HardenForceIntegrity: "disabled",
		report.HardenSigned: "disabled",
	}
	if got := hardeningStatus(res); !reflect.DeepEqual(got, wantHardening) {
		t.Errorf("hardening = %v, want %v", got, wantHardening)
	}
	for _, h := range res.Hardening {
		if h.Label == "" || h.Detail == "" {
			t.Errorf("hardening %s needs a label and a detail: %+v", h.ID, h)
		}
	}

	want := Details{
		Kind: "exe", Machine: "x86-64", Bits: 64, Subsystem: "windows-cui", Timestamp: "", TimestampRaw: 0,
		EntryPoint: "0x1000", EntrySection: ".text", ImageBase: "0x140000000", LinkerVersion: "14.29",
		OSVersion: "6.0", SubsystemVersion: "6.0", SizeOfImage: res.Details.SizeOfImage, Checksum: "0x0",
		Characteristics:    []string{"EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"},
		DllCharacteristics: []string{"HIGH_ENTROPY_VA", "DYNAMIC_BASE", "NX_COMPAT", "TERMINAL_SERVER_AWARE"},
		DotNetFlags:        []string{}, PackerHints: []string{}, DelayImportLibraries: []string{}, ImportCount: 1,
	}
	if !reflect.DeepEqual(res.Details, want) {
		t.Errorf("details =\n%+v\nwant\n%+v", res.Details, want)
	}
	if res.Details.SizeOfImage == 0 || res.Details.SizeOfImage%0x1000 != 0 {
		t.Errorf("SizeOfImage = %#x", res.Details.SizeOfImage)
	}
	if len(res.Notes) != 0 || res.Notes == nil {
		t.Errorf("notes = %#v, want an empty non-nil slice", res.Notes)
	}
}

func TestParseVariants(t *testing.T) {
	// The fixture lays the PDB GUID out as bytes 0xA0..0xAF.
	const guid = "A3A2A1A0-A5A4-A7A6-A8A9-AAABACADAEAF"
	tests := []struct {
		name  string
		opts  testfixtures.PEOptions
		check func(t *testing.T, res *Result)
	}{
		{
			name: "pe32 executable",
			opts: testfixtures.PEOptions{Bits: 32},
			check: func(t *testing.T, res *Result) {
				d := res.Details
				if d.Bits != 32 || d.Machine != "x86" || d.ImageBase != "0x400000" {
					t.Errorf("details = %+v", d)
				}
				st := hardeningStatus(res)
				if st[report.HardenHighEntropyVA] != "n/a" {
					t.Errorf("32-bit images have no high-entropy ASLR: %v", st)
				}
				if st[report.HardenSEH] != "disabled" {
					t.Errorf("x86 without NO_SEH or a SafeSEH table must report seh disabled: %v", st)
				}
			},
		},
		{
			name: "dll with exports, forwarder and ordinal-only exports",
			opts: testfixtures.PEOptions{
				DLL: true, ExportOrdinalOnly: 2, ExportDLLName: "lib.dll", Timestamp: 1700000000,
				Exports: []testfixtures.PEExport{{Name: "zeta"}, {Name: "alpha"}, {Name: "fwd", Forwarder: "NTDLL.RtlAllocateHeap"}},
			},
			check: func(t *testing.T, res *Result) {
				if res.Details.Kind != "dll" || res.Details.Subsystem != "windows-gui" {
					t.Errorf("details = %+v", res.Details)
				}
				want := []string{"alpha", "fwd -> NTDLL.RtlAllocateHeap", "zeta", "#4", "#5"}
				if !reflect.DeepEqual(res.Exports, want) {
					t.Errorf("exports = %v, want %v", res.Exports, want)
				}
				if res.Details.ExportCount != 5 || res.Details.ExportName != "lib.dll" {
					t.Errorf("exportCount %d, exportName %q", res.Details.ExportCount, res.Details.ExportName)
				}
				if res.Details.Timestamp != "2023-11-14T22:13:20Z" || res.Details.TimestampRaw != 1700000000 {
					t.Errorf("timestamp = %q / %d", res.Details.Timestamp, res.Details.TimestampRaw)
				}
			},
		},
		{
			name: "driver",
			opts: testfixtures.PEOptions{Driver: true},
			check: func(t *testing.T, res *Result) {
				if res.Details.Kind != "driver" || res.Details.Subsystem != "native" {
					t.Errorf("details = %+v", res.Details)
				}
				if res.ImpHash != "cb90de765539416b74a75a1beff7fce4" {
					t.Errorf("imphash = %q (.exe extensions are kept, like pefile)", res.ImpHash)
				}
			},
		},
		{
			name: "native subsystem exe that imports a kernel module is a driver",
			opts: testfixtures.PEOptions{Subsystem: 1, Imports: []testfixtures.PEImport{{Library: "HAL.dll", Functions: []string{"HalReturnToFirmware"}}}},
			check: func(t *testing.T, res *Result) {
				if res.Details.Kind != "driver" {
					t.Errorf("kind = %q", res.Details.Kind)
				}
			},
		},
		{
			name: "native subsystem exe without kernel imports stays an exe",
			opts: testfixtures.PEOptions{Subsystem: 1},
			check: func(t *testing.T, res *Result) {
				if res.Details.Kind != "exe" {
					t.Errorf("kind = %q", res.Details.Kind)
				}
			},
		},
		{
			name: "pdb path",
			opts: testfixtures.PEOptions{PDBPath: `C:\Users\alice\src\app\build\app.pdb`},
			check: func(t *testing.T, res *Result) {
				d := res.Details
				if d.PDBPath != `C:\Users\alice\src\app\build\app.pdb` || d.PDBGUID != guid || d.PDBAge != 1 {
					t.Errorf("pdb = %q %q %d", d.PDBPath, d.PDBGUID, d.PDBAge)
				}
			},
		},
		{
			name: "signed with overlay",
			opts: testfixtures.PEOptions{Signed: true, Overlay: []byte("0123456789abcdef")},
			check: func(t *testing.T, res *Result) {
				d := res.Details
				if !d.Signed || d.SignatureType != "pkcs7-signed-data" || d.SignatureSize != 56 {
					t.Errorf("signature = %v %q %d", d.Signed, d.SignatureType, d.SignatureSize)
				}
				if d.OverlaySize != 16 {
					t.Errorf("overlay = %d, want 16 (the certificate table is not overlay)", d.OverlaySize)
				}
				if hardeningStatus(res)[report.HardenSigned] != "enabled" {
					t.Errorf("hardening = %v", hardeningStatus(res))
				}
			},
		},
		{
			name: "overlay only",
			opts: testfixtures.PEOptions{Overlay: bytes.Repeat([]byte{0x41}, 1234)},
			check: func(t *testing.T, res *Result) {
				if res.Details.OverlaySize != 1234 || res.Details.Signed {
					t.Errorf("details = %+v", res.Details)
				}
			},
		},
		{
			name: "dotnet executable",
			opts: testfixtures.PEOptions{DotNet: true, DotNetVersion: "v2.0.50727"},
			check: func(t *testing.T, res *Result) {
				d := res.Details
				if !d.DotNet || d.DotNetVersion != "v2.0.50727" || !reflect.DeepEqual(d.DotNetFlags, []string{"ILONLY"}) {
					t.Errorf("dotnet = %v %q %v", d.DotNet, d.DotNetVersion, d.DotNetFlags)
				}
				st := hardeningStatus(res)
				if st[report.HardenCFG] != "n/a" {
					t.Errorf("managed code is not CFG-instrumented: %v", st)
				}
				if res.ImpHash != "f34d5f2d4577ed6d9ceec516c1f5a744" {
					t.Errorf("imphash = %q", res.ImpHash)
				}
			},
		},
		{
			name: "tls callbacks (64-bit)",
			opts: testfixtures.PEOptions{TLSCallbacks: 3},
			check: func(t *testing.T, res *Result) {
				if res.Details.TLSCallbacks != 3 {
					t.Errorf("tlsCallbacks = %d", res.Details.TLSCallbacks)
				}
			},
		},
		{
			name: "tls callbacks (32-bit)",
			opts: testfixtures.PEOptions{Bits: 32, TLSCallbacks: 2},
			check: func(t *testing.T, res *Result) {
				if res.Details.TLSCallbacks != 2 {
					t.Errorf("tlsCallbacks = %d", res.Details.TLSCallbacks)
				}
			},
		},
		{
			name: "safeseh table on x86",
			opts: testfixtures.PEOptions{Bits: 32, SafeSEH: true},
			check: func(t *testing.T, res *Result) {
				if hardeningStatus(res)[report.HardenSEH] != "enabled" {
					t.Errorf("hardening = %v", res.Hardening)
				}
			},
		},
		{
			name: "no-seh flag on x86",
			opts: testfixtures.PEOptions{Bits: 32, DllCharsSet: testfixtures.PEDllNoSEH},
			check: func(t *testing.T, res *Result) {
				if hardeningStatus(res)[report.HardenSEH] != "enabled" {
					t.Errorf("hardening = %v", res.Hardening)
				}
			},
		},
		{
			name: "control flow guard and stack cookie (64-bit)",
			opts: testfixtures.PEOptions{GuardCF: true, SecurityCookie: true},
			check: func(t *testing.T, res *Result) {
				if hardeningStatus(res)[report.HardenCFG] != "enabled" || !res.Details.SecurityCookie {
					t.Errorf("hardening %v cookie %v", hardeningStatus(res), res.Details.SecurityCookie)
				}
				for _, h := range res.Hardening {
					if h.ID == report.HardenCFG && h.Detail != "GUARD_CF is set and the load configuration has a CF function table" {
						t.Errorf("cfg detail = %q", h.Detail)
					}
				}
			},
		},
		{
			name: "control flow guard and stack cookie (32-bit)",
			opts: testfixtures.PEOptions{Bits: 32, GuardCF: true, SecurityCookie: true, SafeSEH: true},
			check: func(t *testing.T, res *Result) {
				st := hardeningStatus(res)
				if st[report.HardenCFG] != "enabled" || st[report.HardenSEH] != "enabled" || !res.Details.SecurityCookie {
					t.Errorf("hardening %v cookie %v", st, res.Details.SecurityCookie)
				}
			},
		},
		{
			name: "delay-load imports",
			opts: testfixtures.PEOptions{DelayImports: []testfixtures.PEImport{{Library: "shell32.dll", Functions: []string{"ShellExecuteW", "#42"}}}},
			check: func(t *testing.T, res *Result) {
				want := []report.Import{
					{Library: "kernel32.dll", Count: 1, Functions: []string{"ExitProcess"}},
					{Library: "shell32.dll (delay-load)", Count: 2, Functions: []string{"ShellExecuteW", "#42"}},
				}
				if !reflect.DeepEqual(res.Imports, want) {
					t.Errorf("imports = %+v", res.Imports)
				}
				if !reflect.DeepEqual(res.Details.DelayImportLibraries, []string{"shell32.dll"}) || res.Details.ImportCount != 3 {
					t.Errorf("details = %+v", res.Details)
				}
				if res.ImpHash != "f9ade0aa18f660a34a4fa23392e21838" {
					t.Errorf("delay-load imports must not change the imphash: %q", res.ImpHash)
				}
			},
		},
		{
			name: "imports by ordinal and several libraries",
			opts: testfixtures.PEOptions{Imports: []testfixtures.PEImport{
				{Library: "KERNEL32.dll", Functions: []string{"ExitProcess", "GetStdHandle"}},
				{Library: "WS2_32.dll", Functions: []string{"#23", "WSAStartup"}},
			}},
			check: func(t *testing.T, res *Result) {
				want := []report.Import{
					{Library: "KERNEL32.dll", Count: 2, Functions: []string{"ExitProcess", "GetStdHandle"}},
					{Library: "WS2_32.dll", Count: 2, Functions: []string{"#23", "WSAStartup"}},
				}
				if !reflect.DeepEqual(res.Imports, want) {
					t.Errorf("imports = %+v", res.Imports)
				}
				if res.ImpHash != "926befcbba3e1a078d005010acb10795" {
					t.Errorf("imphash = %q (ordinal 23 of ws2_32 is socket)", res.ImpHash)
				}
			},
		},
		{
			name: "no import table",
			opts: testfixtures.PEOptions{NoImports: true},
			check: func(t *testing.T, res *Result) {
				if len(res.Imports) != 0 || res.ImpHash != "" || res.Details.ImportCount != 0 {
					t.Errorf("imports %+v imphash %q", res.Imports, res.ImpHash)
				}
			},
		},
		{
			name: "aslr disabled",
			opts: testfixtures.PEOptions{DllCharsClear: testfixtures.PEDllDynamicBase},
			check: func(t *testing.T, res *Result) {
				if hardeningStatus(res)[report.HardenASLR] != "disabled" {
					t.Errorf("hardening = %v", res.Hardening)
				}
			},
		},
		{
			name: "dynamic base with stripped relocations is ineffective",
			opts: testfixtures.PEOptions{CharsSet: testfixtures.PECharRelocsStripped},
			check: func(t *testing.T, res *Result) {
				for _, h := range res.Hardening {
					if h.ID == report.HardenASLR && (h.Status != "disabled" || !bytes.Contains([]byte(h.Detail), []byte("ineffective"))) {
						t.Errorf("aslr = %+v", h)
					}
				}
			},
		},
		{
			name: "dep and high entropy cleared, force integrity set",
			opts: testfixtures.PEOptions{
				DllCharsClear: testfixtures.PEDllNXCompat | testfixtures.PEDllHighEntropyVA,
				DllCharsSet:   testfixtures.PEDllForceIntegrity,
			},
			check: func(t *testing.T, res *Result) {
				st := hardeningStatus(res)
				if st[report.HardenDEP] != "disabled" || st[report.HardenHighEntropyVA] != "disabled" || st[report.HardenForceIntegrity] != "enabled" {
					t.Errorf("hardening = %v", st)
				}
			},
		},
		{
			name: "arm64",
			opts: testfixtures.PEOptions{Machine: 0xaa64},
			check: func(t *testing.T, res *Result) {
				if res.Details.Machine != "ARM64" || res.Details.Bits != 64 {
					t.Errorf("details = %+v", res.Details)
				}
				if hardeningStatus(res)[report.HardenSEH] != "n/a" {
					t.Errorf("hardening = %v", res.Hardening)
				}
			},
		},
		{
			name: "unknown machine",
			opts: testfixtures.PEOptions{Machine: 0x1234},
			check: func(t *testing.T, res *Result) {
				if res.Details.Machine != "0x1234" {
					t.Errorf("machine = %q", res.Details.Machine)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseBytes(t, testfixtures.PE(tc.opts))
			if len(res.Notes) != 0 {
				t.Errorf("a valid fixture must parse without notes: %v", res.Notes)
			}
			tc.check(t, res)
		})
	}
}

func TestParseSectionAssessment(t *testing.T) {
	b := testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{
		{Name: "UPX0", NoRaw: true, VirtualSize: 0x20000, Characteristics: testfixtures.PESectionRWX},
		{Name: "UPX1", Data: bytes.Repeat([]byte{0x5a}, 600), Characteristics: testfixtures.PESectionRWX},
		{Name: ".evil", Data: []byte("x"), Characteristics: testfixtures.PESectionCode},
		{Name: ".debug_abbrev", Data: []byte("abc"), Characteristics: testfixtures.PESectionRData},
		{Name: ".CRT", Data: []byte("abc"), Characteristics: testfixtures.PESectionRData},
		{Name: "PAGEwx1", Data: []byte("abc"), Characteristics: testfixtures.PESectionCode},
		{Name: ".bss", NoRaw: true, VirtualSize: 0x400000, Characteristics: testfixtures.PESectionBSS},
		{Name: ".rwx", Data: []byte("abc"), Characteristics: testfixtures.PESectionRWX},
	}})
	res := parseBytes(t, b)
	if len(res.Notes) != 0 {
		t.Fatalf("notes = %v", res.Notes)
	}
	bySuspicion := map[string][]string{}
	for _, s := range res.Sections {
		if s.Suspicious != (len(s.Reasons) > 0) {
			t.Errorf("%s: Suspicious=%v but reasons=%v", s.Name, s.Suspicious, s.Reasons)
		}
		bySuspicion[s.Name] = s.Reasons
	}
	contains := func(name, fragment string) {
		t.Helper()
		for _, r := range bySuspicion[name] {
			if bytes.Contains([]byte(r), []byte(fragment)) {
				return
			}
		}
		t.Errorf("section %s: no reason contains %q (reasons: %v)", name, fragment, bySuspicion[name])
	}
	contains("UPX0", "RWX")
	contains("UPX0", "typical of UPX")
	contains("UPX0", "no raw data")
	contains("UPX0", "16x its raw size")
	contains("UPX1", "typical of UPX")
	contains(".evil", `unusual section name ".evil"`)
	contains(".rwx", "writable and executable")
	for _, name := range []string{".text", ".rdata", ".data", ".debug_abbrev", ".CRT", "PAGEwx1", ".bss"} {
		if len(bySuspicion[name]) != 0 {
			t.Errorf("section %s must not be suspicious: %v", name, bySuspicion[name])
		}
	}
	if !reflect.DeepEqual(res.Details.PackerHints, []string{"UPX"}) {
		t.Errorf("packerHints = %v", res.Details.PackerHints)
	}
	if got := sectionNames(res); !slices.Contains(got, ".debug_abbrev") {
		t.Errorf("long section name was not resolved through the COFF string table: %v", got)
	}
	for _, s := range res.Sections {
		if s.Name == "UPX0" && (s.RawSize != 0 || s.VirtualSize != 0x20000) {
			t.Errorf("UPX0 sizes = %d/%d", s.VirtualSize, s.RawSize)
		}
	}
	// The COFF string table must not be counted as overlay.
	if res.Details.OverlaySize != 0 {
		t.Errorf("overlay = %d, want 0", res.Details.OverlaySize)
	}
}

func TestParseOverlappingSections(t *testing.T) {
	b := testfixtures.PE(testfixtures.PEOptions{})
	// Make .data start inside .rdata (virtual and raw ranges both overlap).
	second := testfixtures.PESectionHeaderOffset(64, 1)
	third := testfixtures.PESectionHeaderOffset(64, 2)
	put32(b, third+12, binary.LittleEndian.Uint32(b[second+12:])+0x10)
	put32(b, third+20, binary.LittleEndian.Uint32(b[second+20:])+0x10)
	res := parseBytes(t, b)
	reasons := res.Sections[2].Reasons
	var virt, raw bool
	for _, r := range reasons {
		virt = virt || bytes.Contains([]byte(r), []byte(`virtual range overlaps section ".rdata"`))
		raw = raw || bytes.Contains([]byte(r), []byte(`raw data overlaps section ".rdata"`))
	}
	if !virt || !raw {
		t.Errorf("reasons = %v", reasons)
	}
	if res.Sections[1].Suspicious {
		t.Errorf("only the later section is reported: %v", res.Sections[1].Reasons)
	}
}

func TestParseSectionsOverlappingHeaders(t *testing.T) {
	b := testfixtures.PE(testfixtures.PEOptions{})
	first := testfixtures.PESectionHeaderOffset(64, 0)
	put32(b, first+12, 0x100) // VirtualAddress inside the headers
	put32(b, first+20, 0x100) // PointerToRawData inside the headers
	res := parseBytes(t, b)
	reasons := res.Sections[0].Reasons
	var virt, raw bool
	for _, r := range reasons {
		virt = virt || bytes.Contains([]byte(r), []byte("virtual range overlaps the PE headers"))
		raw = raw || bytes.Contains([]byte(r), []byte("raw data overlaps the PE headers"))
	}
	if !virt || !raw {
		t.Errorf("reasons = %v", reasons)
	}
}

func TestParseManyExportsAreCappedButCounted(t *testing.T) {
	exports := make([]testfixtures.PEExport, 300)
	for i := range exports {
		exports[i] = testfixtures.PEExport{Name: "fn" + string(rune('a'+i/26/26%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26))}
	}
	b := testfixtures.PE(testfixtures.PEOptions{DLL: true, Exports: exports, ExportOrdinalOnly: 20})
	res, err := Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{MaxList: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Exports) != 50 || res.Details.ExportCount != 320 {
		t.Fatalf("exports %d, exportCount %d; want 50 and 320", len(res.Exports), res.Details.ExportCount)
	}
	if !hasNote(res, "only the first 50 exports are recorded") {
		t.Errorf("notes = %v", res.Notes)
	}
	full := parseBytes(t, b)
	if len(full.Exports) != 320 || full.Exports[300] != "#301" || len(full.Notes) != 0 {
		t.Errorf("default limits: %d exports, last %q, notes %v", len(full.Exports), full.Exports[len(full.Exports)-1], full.Notes)
	}
}

func hasNote(res *Result, fragment string) bool {
	for _, n := range res.Notes {
		if bytes.Contains([]byte(n), []byte(fragment)) {
			return true
		}
	}
	return false
}

func TestParseImportListsAreCappedButCounted(t *testing.T) {
	var libs []testfixtures.PEImport
	for i := range 12 {
		fns := make([]string, 0, 40)
		for j := range 40 {
			fns = append(fns, "Func"+string(rune('A'+i))+string(rune('a'+j%26))+string(rune('0'+j/26)))
		}
		libs = append(libs, testfixtures.PEImport{Library: "lib" + string(rune('a'+i)) + ".dll", Functions: fns})
	}
	b := testfixtures.PE(testfixtures.PEOptions{Imports: libs})
	res, err := Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{MaxList: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Imports) != 8 {
		t.Fatalf("libraries recorded = %d, want 8", len(res.Imports))
	}
	// Per-library cap 8, overall cap 4x8 = 32 recorded names: the first four libraries use it up.
	listed := 0
	for i, lib := range res.Imports {
		wantListed := 8
		if i >= 4 {
			wantListed = 0
		}
		if lib.Count != 40 || len(lib.Functions) != wantListed {
			t.Errorf("%s: count %d, listed %d; want 40 and %d", lib.Library, lib.Count, len(lib.Functions), wantListed)
		}
		listed += len(lib.Functions)
	}
	if listed != 32 {
		t.Errorf("recorded %d function names, want 32", listed)
	}
	if res.Details.ImportCount != 12*40 {
		t.Errorf("importCount = %d, want %d (true total across all libraries)", res.Details.ImportCount, 12*40)
	}
	if !hasNote(res, "only the first 8 import libraries are recorded") || !hasNote(res, "imported function lists are capped") {
		t.Errorf("notes = %v", res.Notes)
	}
	if res.ImpHash == "" {
		t.Error("the import hash covers every import, not only the recorded ones")
	}
	full := parseBytes(t, b)
	if len(full.Imports) != 12 || full.ImpHash != res.ImpHash {
		t.Errorf("full parse: %d libs, imphash %q vs %q", len(full.Imports), full.ImpHash, res.ImpHash)
	}
}
