package macho

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

func parse(t *testing.T, data []byte, lim limits.Limits) *Result {
	t.Helper()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func hardeningOf(t *testing.T, res *Result, id string) report.Hardening {
	t.Helper()
	for _, h := range res.Hardening {
		if h.ID == id {
			return h
		}
	}
	t.Fatalf("hardening %q missing from %+v", id, res.Hardening)
	return report.Hardening{}
}

func noteMentions(res *Result, sub string) bool {
	return slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func sectionByName(res *Result, name string) (report.Section, bool) {
	for _, s := range res.Sections {
		if s.Name == name {
			return s, true
		}
	}
	return report.Section{}, false
}

func TestParse_ZeroValueFixture(t *testing.T) {
	res := parse(t, testfixtures.MachO(testfixtures.MachOOptions{}), limits.Limits{})
	d := res.Details
	if d.Fat || d.PrimarySlice != 0 || len(d.Slices) != 1 {
		t.Fatalf("details = %+v", d)
	}
	s := d.Slices[0]
	if s.CPU != "x86_64" || s.Type != "executable" || s.Bits != 64 || s.Endian != "little" || s.Offset != 0 || s.Error != "" {
		t.Errorf("slice = %+v", s)
	}
	if !slices.Equal(s.Flags, []string{"NOUNDEFS", "DYLDLINK", "TWOLEVEL", "PIE"}) {
		t.Errorf("flags = %v", s.Flags)
	}
	if len(s.Segments) != 3 || s.Segments[0].Name != "__PAGEZERO" || s.Segments[1].Name != "__TEXT" || s.Segments[2].Name != "__DATA" {
		t.Fatalf("segments = %+v", s.Segments)
	}
	if !slices.Equal(s.Segments[1].Flags, []string{"R", "X"}) || !slices.Equal(s.Segments[2].Flags, []string{"R", "W"}) || s.Segments[0].FileSize != 0 {
		t.Errorf("segment flags = %+v", s.Segments)
	}
	if s.Segments[0].VMSize != 0x100000000 || s.Segments[1].VMAddr != "0x100000000" {
		t.Errorf("address layout = %+v", s.Segments)
	}
	if s.UUID != "" || s.Signed || s.Encrypted || s.Platform != "" || s.EntryOffset != "" || len(s.Dylibs) != 0 || len(s.RPaths) != 0 {
		t.Errorf("optional facts must be empty: %+v", s)
	}
	var names []string
	for _, sec := range res.Sections {
		names = append(names, sec.Name)
	}
	if !slices.Equal(names, []string{"__TEXT,__text", "__DATA,__data"}) {
		t.Errorf("sections = %v (the empty __PAGEZERO must not be listed)", names)
	}
	if text, _ := sectionByName(res, "__TEXT,__text"); !slices.Equal(text.Flags, []string{"R", "X"}) || text.RawSize != 16 || text.VirtualSize != 16 || text.Suspicious || text.Offset == 0 {
		t.Errorf("__text = %+v", text)
	}
	if len(res.Notes) != 0 {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestParse_HardeningMatrix(t *testing.T) {
	const (
		en = report.StatusEnabled
		di = report.StatusDisabled
		na = report.StatusNA
		un = report.StatusUnknown
	)
	canary := []testfixtures.MachOSymbol{{Name: "___stack_chk_fail", Ordinal: 1}, {Name: "_puts", Ordinal: 1}}
	tests := []struct {
		name                          string
		opts                          testfixtures.MachOOptions
		pie, nx, canary, signed, encr string
	}{
		{"zero value", testfixtures.MachOOptions{}, en, en, un, di, na},
		{"non-PIE executable", testfixtures.MachOOptions{DropFlags: testfixtures.MachOFlagPIE}, di, en, un, di, na},
		{"executable stack allowed", testfixtures.MachOOptions{AddFlags: testfixtures.MachOFlagAllowStackExecute}, en, di, un, di, na},
		{"no heap execution", testfixtures.MachOOptions{AddFlags: testfixtures.MachOFlagNoHeapExecute}, en, en, un, di, na},
		{"signed with canary", testfixtures.MachOOptions{CodeSignature: true, Undefined: canary, Dylibs: []string{"/usr/lib/libSystem.B.dylib"}}, en, en, en, en, na},
		{"symbols without canary", testfixtures.MachOOptions{Undefined: []testfixtures.MachOSymbol{{Name: "_puts", Ordinal: 1}}}, en, en, di, di, na},
		{"encrypted app", testfixtures.MachOOptions{EncryptionInfo: true, CryptID: 1}, en, en, un, di, en},
		{"encryption info with cryptid 0", testfixtures.MachOOptions{EncryptionInfo: true, CryptID: 0}, en, en, un, di, di},
		{"dylib", testfixtures.MachOOptions{Type: testfixtures.MachOTypeDylib, CodeSignature: true}, na, en, un, en, na},
		{"object", testfixtures.MachOOptions{Type: testfixtures.MachOTypeObject}, na, na, un, na, na},
		{"32-bit big endian", testfixtures.MachOOptions{Bits: 32, BigEndian: true, CodeSignature: true, Undefined: canary}, en, en, en, en, na},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, testfixtures.MachO(tc.opts), limits.Limits{})
			for id, want := range map[string]string{
				report.HardenPIE: tc.pie, report.HardenNX: tc.nx, report.HardenCanary: tc.canary,
				report.HardenSigned: tc.signed, report.HardenEncrypted: tc.encr,
			} {
				if got := hardeningOf(t, res, id); got.Status != want || got.Label == "" || got.Detail == "" {
					t.Errorf("%s = %+v, want status %s", id, got, want)
				}
			}
			if len(res.Hardening) != 5 {
				t.Errorf("want exactly five entries, got %d", len(res.Hardening))
			}
		})
	}
}

func TestParse_GoBinaryHasNoCanaryVerdict(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_pthread_create", Ordinal: 1}},
		Segments: []testfixtures.MachOSegment{
			{Name: "__TEXT", InitProt: 5, Sections: []testfixtures.MachOSection{{Name: "__text", Data: []byte{0xc3}}, {Name: "__gopclntab", Data: []byte("pcln")}}},
		},
	})
	if got := hardeningOf(t, parse(t, data, limits.Limits{}), report.HardenCanary); got.Status != report.StatusNA {
		t.Errorf("canary = %+v, want n/a for a Go binary", got)
	}
}

func TestParse_FactsFromLoadCommands(t *testing.T) {
	uuid := []byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	for _, bits := range []int{64, 32} {
		for _, big := range []bool{false, true} {
			data := testfixtures.MachO(testfixtures.MachOOptions{
				Bits: bits, BigEndian: big, CPU: testfixtures.MachOCPUARM64, SubCPU: 2,
				Dylibs: []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"}, WeakDylibs: []string{"/usr/lib/libweak.dylib"},
				ReexportDylibs: []string{"/usr/lib/libre.dylib"}, RPaths: []string{"@executable_path/../Frameworks", "/opt/lib"},
				UUID: uuid, CodeSignature: true, BuildPlatform: 1, MinOS: 0x000e0000, SDK: 0x000e0201, Main: true,
			})
			s := parse(t, data, limits.Limits{}).Details.Slices[0]
			if s.CPU != "arm64e" {
				t.Errorf("bits=%d big=%v cpu = %q, want arm64e for sub-type 2", bits, big, s.CPU)
			}
			if !slices.Equal(s.Dylibs, []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib", "/usr/lib/libweak.dylib", "/usr/lib/libre.dylib"}) {
				t.Errorf("dylibs = %v (weak and re-exported dylibs belong in the list, in command order)", s.Dylibs)
			}
			if !slices.Equal(s.RPaths, []string{"@executable_path/../Frameworks", "/opt/lib"}) || s.UUID != "DEADBEEF-0001-0203-0405-060708090A0B" {
				t.Errorf("rpaths/uuid = %v %q", s.RPaths, s.UUID)
			}
			if !s.Signed || s.Encrypted || s.Platform != "macos" || s.MinOS != "14.0" || s.SDK != "14.2.1" || s.EntryOffset == "" {
				t.Errorf("signed/encrypted/platform = %v %v %q %q %q %q", s.Signed, s.Encrypted, s.Platform, s.MinOS, s.SDK, s.EntryOffset)
			}
			wantBits, wantEndian := 64, "little"
			if bits == 32 {
				wantBits = 32
			}
			if big {
				wantEndian = "big"
			}
			if s.Bits != wantBits || s.Endian != wantEndian {
				t.Errorf("bits/endian = %d/%s", s.Bits, s.Endian)
			}
		}
	}
}

func TestParse_VersionMinAndInstallName(t *testing.T) {
	s := parse(t, testfixtures.MachO(testfixtures.MachOOptions{
		Type: testfixtures.MachOTypeDylib, InstallName: "@rpath/libx.dylib", VersionMin: 0x000a0f00, SDK: 0x000b0000,
	}), limits.Limits{}).Details.Slices[0]
	if s.InstallName != "@rpath/libx.dylib" || s.Platform != "macos" || s.MinOS != "10.15" || s.SDK != "11.0" || s.Type != "dylib" {
		t.Errorf("slice = %+v", s)
	}
	for platform, want := range map[uint32]string{1: "macos", 2: "ios", 6: "maccatalyst", 7: "ios-simulator", 11: "visionos"} {
		got := parse(t, testfixtures.MachO(testfixtures.MachOOptions{BuildPlatform: platform, MinOS: 0x00110000}), limits.Limits{}).Details.Slices[0]
		if got.Platform != want || got.MinOS != "17.0" {
			t.Errorf("platform %d = %q / %q", platform, got.Platform, got.MinOS)
		}
	}
}

func TestParse_ImportsAreGroupedByDylibOrdinal(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, WeakDylibs: []string{"/System/Library/Frameworks/Security.framework/Security"},
		Defined: []string{"_main", "__mh_execute_header", "_helper"},
		Undefined: []testfixtures.MachOSymbol{
			{Name: "_puts", Ordinal: 1}, {Name: "_malloc", Ordinal: 1}, {Name: "_SecItemCopyMatching", Ordinal: 2},
			{Name: "_dyld_stub_binder"}, {Name: "_bogus", Ordinal: 9}, {Name: "_lookup", Ordinal: 0xfe},
		},
	})
	res := parse(t, data, limits.Limits{})
	type row struct {
		lib   string
		count int
		funcs []string
	}
	var got []row
	for _, imp := range res.Imports {
		got = append(got, row{imp.Library, imp.Count, imp.Functions})
	}
	want := []row{
		{"/System/Library/Frameworks/Security.framework/Security", 1, []string{"SecItemCopyMatching"}},
		{"/usr/lib/libSystem.B.dylib", 2, []string{"malloc", "puts"}},
		{report.UnspecifiedLibrary, 3, []string{"bogus", "dyld_stub_binder", "lookup"}},
	}
	if len(got) != len(want) {
		t.Fatalf("imports = %+v", got)
	}
	for i := range want {
		if got[i].lib != want[i].lib || got[i].count != want[i].count || !slices.Equal(got[i].funcs, want[i].funcs) {
			t.Errorf("import %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !slices.Equal(res.Exports, []string{"_mh_execute_header", "helper", "main"}) {
		t.Errorf("exports = %v (one leading underscore is stripped)", res.Exports)
	}
	if res.Details.ImportCount != 6 || res.Details.ExportCount != 3 || res.Details.Slices[0].SymbolCount != 9 {
		t.Errorf("counts = %d/%d symbols %d", res.Details.ImportCount, res.Details.ExportCount, res.Details.Slices[0].SymbolCount)
	}
}

func TestParse_FlatNamespaceIgnoresOrdinals(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{
		DropFlags: testfixtures.MachOFlagTwoLevel, Dylibs: []string{"/usr/lib/libSystem.B.dylib"},
		Undefined: []testfixtures.MachOSymbol{{Name: "_puts", Ordinal: 1}},
	})
	res := parse(t, data, limits.Limits{})
	if len(res.Imports) != 1 || res.Imports[0].Library != report.UnspecifiedLibrary {
		t.Fatalf("imports = %+v", res.Imports)
	}
}

func TestParse_SectionsFlagsReasonsAndEntropy(t *testing.T) {
	noise := make([]byte, 4096)
	state := uint32(1)
	for i := range noise {
		state = state*1664525 + 1013904223
		noise[i] = byte(state >> 24)
	}
	data := testfixtures.MachO(testfixtures.MachOOptions{
		CodeSignature: true,
		Segments: []testfixtures.MachOSegment{
			{Name: "__TEXT", InitProt: 5, Sections: []testfixtures.MachOSection{{Name: "__text", Data: noise}, {Name: "__cstring", Data: bytes.Repeat([]byte{0}, 256)}}},
			{Name: "__EVIL", InitProt: 7, Sections: []testfixtures.MachOSection{{Name: "__rwx", Data: []byte{0xcc, 0xcc}}}},
			{Name: "__DATA", InitProt: 3, Sections: []testfixtures.MachOSection{{Name: "__bss", Data: make([]byte, 8192), Zerofill: true}}},
		},
	})
	res := parse(t, data, limits.Limits{})
	text, _ := sectionByName(res, "__TEXT,__text")
	if text.Entropy < 7.5 || text.Suspicious {
		t.Errorf("__text = %+v", text)
	}
	if cs, _ := sectionByName(res, "__TEXT,__cstring"); cs.Entropy != 0 {
		t.Errorf("__cstring = %+v", cs)
	}
	rwx, _ := sectionByName(res, "__EVIL,__rwx")
	if !rwx.Suspicious || !slices.Equal(rwx.Flags, []string{"R", "W", "X"}) || !slices.Contains(rwx.Reasons, "writable and executable segment") {
		t.Errorf("__rwx = %+v", rwx)
	}
	bss, _ := sectionByName(res, "__DATA,__bss")
	if bss.RawSize != 0 || bss.VirtualSize != 8192 || bss.Offset != 0 || bss.Entropy != 0 {
		t.Errorf("__bss = %+v", bss)
	}
	link, ok := sectionByName(res, "__LINKEDIT")
	if !ok || link.RawSize == 0 || !slices.Equal(link.Flags, []string{"R"}) {
		t.Errorf("__LINKEDIT = %+v (%v): section-less segments with file data must be listed", link, ok)
	}
	if res.Details.Slices[0].Segments[len(res.Details.Slices[0].Segments)-1].Name != "__LINKEDIT" {
		t.Errorf("segments = %+v", res.Details.Slices[0].Segments)
	}
}

func TestParse_FatBinary(t *testing.T) {
	amd64 := testfixtures.MachO(testfixtures.MachOOptions{Dylibs: []string{"/usr/lib/libx86.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_x86only", Ordinal: 1}}})
	noise := make([]byte, 2048)
	state := uint32(7)
	for i := range noise {
		state = state*1664525 + 1013904223
		noise[i] = byte(state >> 24)
	}
	arm64 := testfixtures.MachO(testfixtures.MachOOptions{
		CPU: testfixtures.MachOCPUARM64, CodeSignature: true, TextData: noise,
		Dylibs: []string{"/usr/lib/libarm.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_armonly", Ordinal: 1}, {Name: "___stack_chk_fail", Ordinal: 1}},
	})
	t.Run("arm64 is primary", func(t *testing.T) {
		res := parse(t, testfixtures.MachOFat(amd64, arm64), limits.Limits{})
		d := res.Details
		if !d.Fat || d.PrimarySlice != 1 || len(d.Slices) != 2 {
			t.Fatalf("details = %+v", d)
		}
		if d.Slices[0].CPU != "x86_64" || d.Slices[1].CPU != "arm64" || d.Slices[0].Offset == 0 || d.Slices[1].Offset <= d.Slices[0].Offset {
			t.Errorf("slices = %+v", d.Slices)
		}
		if d.Slices[1].Size != int64(len(arm64)) || d.Slices[0].Size != int64(len(amd64)) {
			t.Errorf("sizes = %d %d", d.Slices[0].Size, d.Slices[1].Size)
		}
		if len(res.Imports) != 1 || res.Imports[0].Library != "/usr/lib/libarm.dylib" || res.Imports[0].Count != 2 || !slices.Contains(res.Imports[0].Functions, "armonly") {
			t.Errorf("imports must describe the arm64 slice: %+v", res.Imports)
		}
		if got := hardeningOf(t, res, report.HardenCanary); got.Status != report.StatusEnabled {
			t.Errorf("canary = %+v", got)
		}
		if got := hardeningOf(t, res, report.HardenSigned); got.Status != report.StatusEnabled {
			t.Errorf("signed = %+v", got)
		}
		if !noteMentions(res, "describe the arm64 slice (index 1)") {
			t.Errorf("notes = %v", res.Notes)
		}
		// Section offsets are absolute in the file; the slice-relative offset plus the slice offset.
		text, _ := sectionByName(res, "__TEXT,__text")
		if text.Offset <= uint64(d.Slices[1].Offset) {
			t.Errorf("section offset %d must be absolute (slice at %d)", text.Offset, d.Slices[1].Offset)
		}
		// Entropy must be measured at that absolute location: the arm64 text is
		// noise while the x86_64 slice in front of it holds low-entropy code.
		if text.Entropy < 7 {
			t.Errorf("text entropy = %v, want the arm64 noise measured at its absolute offset", text.Entropy)
		}
	})
	t.Run("amd64 beats an unknown cpu", func(t *testing.T) {
		weird := testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM})
		res := parse(t, testfixtures.MachOFat(weird, amd64), limits.Limits{})
		if res.Details.PrimarySlice != 1 {
			t.Errorf("primary = %d, want the x86_64 slice", res.Details.PrimarySlice)
		}
	})
	t.Run("first parsable slice otherwise", func(t *testing.T) {
		res := parse(t, testfixtures.MachOFat(testfixtures.MachO(testfixtures.MachOOptions{CPU: testfixtures.MachOCPUARM}), testfixtures.MachO(testfixtures.MachOOptions{Bits: 32})), limits.Limits{})
		if res.Details.PrimarySlice != 0 || res.Details.Slices[0].CPU != "arm" {
			t.Errorf("details = %+v", res.Details)
		}
	})
	t.Run("a damaged slice is reported, not fatal", func(t *testing.T) {
		data := testfixtures.MachOFat(amd64, arm64)
		// Destroy the magic of the first slice.
		first := int(binary.BigEndian.Uint32(data[8+8:]))
		data[first] = 0
		res := parse(t, data, limits.Limits{})
		if res.Details.PrimarySlice != 1 || res.Details.Slices[0].Error == "" || res.Details.Slices[0].CPU != "x86_64" {
			t.Fatalf("slices = %+v", res.Details.Slices)
		}
		if len(res.Details.Slices[0].Segments) != 0 || res.Details.Slices[0].Type != "" {
			t.Errorf("a failed slice carries no parsed facts: %+v", res.Details.Slices[0])
		}
	})
	t.Run("truncated container", func(t *testing.T) {
		data := testfixtures.MachOFat(amd64, arm64)
		res := parse(t, data[:int(binary.BigEndian.Uint32(data[8+20+8:]))+200], limits.Limits{})
		if !noteMentions(res, "is truncated") {
			t.Errorf("notes = %v", res.Notes)
		}
	})
}

func TestParse_Errors(t *testing.T) {
	good := testfixtures.MachO(testfixtures.MachOOptions{})
	javaClass := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0x10, 0x0a, 0, 3}
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "only 0 bytes"},
		{"three bytes", []byte{0xcf, 0xfa, 0xed}, "only 3 bytes"},
		{"bad magic", append([]byte("hello, world"), make([]byte, 40)...), "bad magic number"},
		{"truncated header", good[:20], "truncated Mach-O header"},
		{"java class file", javaClass, "not a Mach-O"},
		{"fat with zero architectures", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0}, "implausible"},
		{"fat with too many architectures", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 1, 0}, "implausible"},
		{"fat header cut", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0}, "truncated universal header"},
		{"fat without a valid slice", append([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 3, 0, 0, 0x10, 0, 0, 0, 0, 20, 0, 0, 0, 12}, make([]byte, 64)...), "none of the 1 universal slices"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse(context.Background(), bytes.NewReader(tc.data), int64(len(tc.data)), limits.Limits{})
			if err == nil || res != nil {
				t.Fatalf("want an error, got %+v, %v", res, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestParse_MalformedLoadCommandsAreNotesNotCrashes(t *testing.T) {
	good := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_puts", Ordinal: 1}}, UUID: make([]byte, 16),
	})
	le := binary.LittleEndian
	// Offsets in the 64-bit header: ncmds @16, sizeofcmds @20. The first load
	// command (LC_SEGMENT_64 __PAGEZERO) starts at 32.
	tests := []struct {
		name   string
		mutate func([]byte)
		note   string
	}{
		{"more commands than fit", func(b []byte) { le.PutUint32(b[16:], 1<<30) }, "load command area holds at most"},
		{"command area larger than the file", func(b []byte) { le.PutUint32(b[20:], 1<<30) }, "probably truncated"},
		{"zero-sized command", func(b []byte) { le.PutUint32(b[32+4:], 0) }, "invalid size"},
		{"oversized command", func(b []byte) { le.PutUint32(b[32+4:], 1<<20) }, "invalid size"},
		{"segment claiming too many sections", func(b []byte) {
			// __PAGEZERO is 72 bytes, __TEXT starts at 32+72; nsects is at +64.
			le.PutUint32(b[32+72+8+16+32+8:], 1<<20)
		}, "declares"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := slices.Clone(good)
			tc.mutate(b)
			res, err := Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{})
			if err != nil {
				t.Fatalf("a valid header with bad commands must not be fatal: %v", err)
			}
			if !noteMentions(res, tc.note) {
				t.Errorf("notes %v do not mention %q", res.Notes, tc.note)
			}
			if len(res.Hardening) != 5 {
				t.Errorf("want five hardening entries, got %d", len(res.Hardening))
			}
		})
	}
}

func TestParse_BadSymbolTablesAreReported(t *testing.T) {
	good := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_a", Ordinal: 1}, {Name: "_b", Ordinal: 1}},
	})
	le := binary.LittleEndian
	// Locate LC_SYMTAB in the load commands.
	symtab := -1
	for pos, i := 32, 0; i < int(le.Uint32(good[16:])); i++ {
		if le.Uint32(good[pos:]) == lcSymtab {
			symtab = pos
		}
		pos += int(le.Uint32(good[pos+4:]))
	}
	if symtab < 0 {
		t.Fatal("fixture has no LC_SYMTAB")
	}
	tests := []struct {
		name   string
		mutate func([]byte)
		note   string
	}{
		{"symbol table beyond the file", func(b []byte) { le.PutUint32(b[symtab+8:], 1<<30) }, "beyond the end of the file"},
		{"more symbols than the file holds", func(b []byte) { le.PutUint32(b[symtab+12:], 1<<30) }, "symbol table is truncated"},
		{"string table beyond the file", func(b []byte) { le.PutUint32(b[symtab+16:], 1<<30) }, "string table is missing or outside the file"},
		{"empty string table", func(b []byte) { le.PutUint32(b[symtab+20:], 0) }, "string table is missing or outside the file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := slices.Clone(good)
			tc.mutate(b)
			res := parse(t, b, limits.Limits{})
			if !noteMentions(res, tc.note) {
				t.Errorf("notes %v do not mention %q", res.Notes, tc.note)
			}
			if got := hardeningOf(t, res, report.HardenCanary).Status; got == report.StatusEnabled {
				t.Errorf("canary = %s with an unreadable symbol table", got)
			}
		})
	}
}

func TestParse_OversizedStringTableIsCountedNotRead(t *testing.T) {
	var undefined []testfixtures.MachOSymbol
	for i := range 100 {
		undefined = append(undefined, testfixtures.MachOSymbol{Name: "_a_rather_long_symbol_name_" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	data := testfixtures.MachO(testfixtures.MachOOptions{Undefined: undefined})
	// The load commands (about 600 bytes) fit a 1 KiB budget; the string table (about 3 KiB) does not.
	res := parse(t, data, limits.Limits{MaxMeta: 1024})
	if !noteMentions(res, "counted but not read") || len(res.Imports) != 0 {
		t.Errorf("imports %+v notes %v", res.Imports, res.Notes)
	}
	if res.Details.Slices[0].SymbolCount != 100 {
		t.Errorf("symbolCount = %d, want the true 100", res.Details.Slices[0].SymbolCount)
	}
	if got := hardeningOf(t, res, report.HardenCanary).Status; got != report.StatusUnknown {
		t.Errorf("canary = %s, want unknown", got)
	}
	if full := parse(t, data, limits.Limits{}); full.Details.ImportCount != 100 {
		t.Errorf("default limits read %d imports, want 100", full.Details.ImportCount)
	}
}

func TestParse_LimitsCapListsButKeepTrueCounts(t *testing.T) {
	var undefined []testfixtures.MachOSymbol
	for i := range 20 {
		undefined = append(undefined, testfixtures.MachOSymbol{Name: "_f" + string(rune('a'+i)), Ordinal: 1})
	}
	data := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"a", "b", "c", "d"}, RPaths: []string{"r1", "r2", "r3", "r4"},
		Undefined: undefined, Defined: []string{"_e1", "_e2", "_e3", "_e4"},
	})
	res := parse(t, data, limits.Limits{MaxList: 3})
	recorded := 0
	for _, imp := range res.Imports {
		recorded += len(imp.Functions)
	}
	if recorded != 3 || res.Details.ImportCount != 20 {
		t.Errorf("recorded %d imports, count %d", recorded, res.Details.ImportCount)
	}
	if len(res.Exports) != 3 || res.Details.ExportCount != 4 {
		t.Errorf("exports %v count %d", res.Exports, res.Details.ExportCount)
	}
	s := res.Details.Slices[0]
	if len(s.Dylibs) != 3 || len(s.RPaths) != 3 || len(s.Segments) != 3 || len(res.Sections) != 3 {
		t.Errorf("dylibs %d rpaths %d segments %d sections %d, want 3 each", len(s.Dylibs), len(s.RPaths), len(s.Segments), len(res.Sections))
	}
}

func TestParse_ContextCancellationReturnsPartialResult(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{Dylibs: []string{"/usr/lib/libSystem.B.dylib"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if res == nil || len(res.Details.Slices) != 1 || res.Details.Slices[0].CPU != "x86_64" || len(res.Hardening) != 5 {
		t.Fatalf("a cancelled parse must still return what it has: %+v", res)
	}
}

func TestParse_SizeIsAHardBoundOnReads(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{})
	res, err := Parse(context.Background(), bytes.NewReader(data), 100, limits.Limits{})
	if err != nil {
		t.Fatalf("header and the first commands fit in 100 bytes: %v", err)
	}
	if !noteMentions(res, "probably truncated") {
		t.Errorf("notes = %v", res.Notes)
	}
	if _, err := Parse(context.Background(), bytes.NewReader(data), -3, limits.Limits{}); err == nil {
		t.Error("a negative size must behave like an empty file")
	}
}

func TestParse_NonPrintableNamesAreEscaped(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{
		Dylibs: []string{"/usr/lib/lib\x1b[31mred.dylib"}, RPaths: []string{"/tmp/\x07bell"},
		Undefined: []testfixtures.MachOSymbol{{Name: "_bad\x1bname", Ordinal: 1}},
		Segments:  []testfixtures.MachOSegment{{Name: "__T\x1bEXT", InitProt: 5, Sections: []testfixtures.MachOSection{{Name: "__te\x1bxt", Data: []byte{1}}}}},
	})
	res := parse(t, data, limits.Limits{})
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `\u001b`) || strings.Contains(string(raw), `\u0007`) {
		t.Errorf("control characters leaked: %s", raw)
	}
	if !slices.Equal(res.Details.Slices[0].Dylibs, []string{`/usr/lib/lib\x1b[31mred.dylib`}) {
		t.Errorf("dylibs = %q", res.Details.Slices[0].Dylibs)
	}
}

func TestDetailsJSONContract(t *testing.T) {
	data := testfixtures.MachO(testfixtures.MachOOptions{CodeSignature: true, UUID: make([]byte, 16), Main: true, BuildPlatform: 1})
	raw, err := json.Marshal(parse(t, data, limits.Limits{}).Details)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fat", "primarySlice", "slices", "importCount", "exportCount"} {
		if _, ok := m[k]; !ok {
			t.Errorf("details.macho is missing %q", k)
		}
	}
	slice := m["slices"].([]any)[0].(map[string]any)
	for _, k := range []string{"cpu", "type", "bits", "endian", "offset", "size", "flags", "dylibs", "rpaths", "installName", "uuid", "signed", "encrypted",
		"platform", "minOS", "sdk", "entryOffset", "segments", "loadCommands", "symbolCount"} {
		if _, ok := slice[k]; !ok {
			t.Errorf("slice is missing %q", k)
		}
	}
	for _, k := range []string{"flags", "dylibs", "rpaths", "segments"} {
		if _, ok := slice[k].([]any); !ok {
			t.Errorf("%s must encode as an array, got %T", k, slice[k])
		}
	}
	seg := slice["segments"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "vmAddr", "vmSize", "fileOffset", "fileSize", "flags"} {
		if _, ok := seg[k]; !ok {
			t.Errorf("segment is missing %q", k)
		}
	}
}

func TestResultSlicesAreNeverNil(t *testing.T) {
	res := parse(t, testfixtures.MachO(testfixtures.MachOOptions{}), limits.Limits{})
	if res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Hardening == nil || res.Notes == nil {
		t.Fatalf("nil slice in %+v", res)
	}
}

func TestEntropyBudgetStopsOverlappingRanges(t *testing.T) {
	data := bytes.Repeat([]byte{1, 2, 3, 4}, 100)
	p := &parser{ctx: context.Background(), file: bytes.NewReader(data), size: int64(len(data)), entropyBudget: 150}
	th := &thin{size: int64(len(data))}
	if h, _ := p.entropyOf(th, 0, 100); h != 2 {
		t.Fatalf("first measurement = %v, want 2", h)
	}
	if h, reason := p.entropyOf(th, 0, 100); h != 0 || reason != "" || p.skipped != 1 {
		t.Fatalf("second measurement = %v %q skipped=%d, want it skipped once the budget is spent", h, reason, p.skipped)
	}
}
