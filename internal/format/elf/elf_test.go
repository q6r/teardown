package elf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand/v2"
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

func sectionNamed(res *Result, name string) (report.Section, bool) {
	for _, s := range res.Sections {
		if s.Name == name {
			return s, true
		}
	}
	return report.Section{}, false
}

// noise returns deterministic high-entropy bytes.
func noise(n int) []byte {
	r := rand.New(rand.NewPCG(7, 11))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(r.UintN(256))
	}
	return out
}

func TestParse_ZeroValueFixture(t *testing.T) {
	res := parse(t, testfixtures.ELF(testfixtures.ELFOptions{}), limits.Limits{})
	d := res.Details
	if d.Class != "ELF64" || d.Endian != "little" || d.Type != "DYN" || d.Machine != "x86-64" || d.OSABI != "SYSV" {
		t.Fatalf("details = %+v", d)
	}
	if d.Interpreter != "/lib64/ld-linux-x86-64.so.2" || d.Linking != "dynamic" {
		t.Errorf("interpreter %q linking %q", d.Interpreter, d.Linking)
	}
	if !d.Stripped || d.HasDebugInfo || d.BuildID != "" || d.GoBuildID != "" {
		t.Errorf("stripped/debug/ids = %v %v %q %q", d.Stripped, d.HasDebugInfo, d.BuildID, d.GoBuildID)
	}
	if d.SegmentCount != 5 || len(d.Segments) != 5 || d.RWXSegments != 0 || d.SectionCount != 6 {
		t.Errorf("segments %d/%d rwx %d sections %d", d.SegmentCount, len(d.Segments), d.RWXSegments, d.SectionCount)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a valid fixture must not produce notes: %v", res.Notes)
	}
	var names []string
	for _, s := range res.Sections {
		names = append(names, s.Name)
	}
	if want := []string{".interp", ".dynsym", ".dynstr", ".text", ".dynamic", ".shstrtab"}; !slices.Equal(names, want) {
		t.Errorf("sections = %v, want %v", names, want)
	}
	if text, _ := sectionNamed(res, ".text"); !slices.Equal(text.Flags, []string{"R", "X"}) || text.Suspicious || text.RawSize != 16 || text.VirtualSize != 16 {
		t.Errorf(".text = %+v", text)
	}
	if dyn, _ := sectionNamed(res, ".dynamic"); !slices.Equal(dyn.Flags, []string{"R", "W"}) {
		t.Errorf(".dynamic = %+v", dyn)
	}
	if str, _ := sectionNamed(res, ".shstrtab"); len(str.Flags) != 0 || str.VirtualSize != 0 {
		t.Errorf("unmapped section carries flags or a virtual size: %+v", str)
	}
}

func TestParse_HardeningMatrix(t *testing.T) {
	const (
		en = report.StatusEnabled
		di = report.StatusDisabled
		na = report.StatusNA
		un = report.StatusUnknown
	)
	hardened := []testfixtures.ELFImport{
		{Name: "__stack_chk_fail", Library: "libc.so.6", Version: "GLIBC_2.4"},
		{Name: "__memcpy_chk", Library: "libc.so.6", Version: "GLIBC_2.3.4"},
		{Name: "__printf_chk", Library: "libc.so.6", Version: "GLIBC_2.3.4"},
	}
	tests := []struct {
		name                            string
		opts                            testfixtures.ELFOptions
		pie, nx, relro, canary, fortify string
		relroPrefix                     string
		linking                         string
	}{
		{"zero value", testfixtures.ELFOptions{}, en, en, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"fully hardened via BIND_NOW tag", testfixtures.ELFOptions{RELRO: true, BindNowTag: true, Imports: hardened}, en, en, en, en, en, "full RELRO", "dynamic"},
		{"full RELRO via DT_FLAGS", testfixtures.ELFOptions{RELRO: true, DynFlags: testfixtures.ELFDynFlagBindNow}, en, en, en, di, di, "full RELRO", "dynamic"},
		{"full RELRO via DT_FLAGS_1", testfixtures.ELFOptions{RELRO: true, DynFlags1: testfixtures.ELFDynFlag1Now}, en, en, en, di, di, "full RELRO", "dynamic"},
		{"partial RELRO", testfixtures.ELFOptions{RELRO: true}, en, en, en, di, di, "partial RELRO", "dynamic"},
		{"bind now without PT_GNU_RELRO is not RELRO", testfixtures.ELFOptions{BindNowTag: true}, en, en, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"fixed address executable", testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec}, di, en, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"executable stack", testfixtures.ELFOptions{Stack: testfixtures.ELFStackRWX}, en, di, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"dynamic image without PT_GNU_STACK", testfixtures.ELFOptions{Stack: testfixtures.ELFStackNone}, en, di, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"shared object", testfixtures.ELFOptions{NoInterp: true}, na, en, di, di, di, "no PT_GNU_RELRO", ""},
		{"shared object with dependencies", testfixtures.ELFOptions{NoInterp: true, Needed: []string{"libc.so.6"}}, na, en, di, di, di, "no PT_GNU_RELRO", "dynamic"},
		{"static-pie", testfixtures.ELFOptions{NoInterp: true, DynFlags1: testfixtures.ELFDynFlag1PIE, RELRO: true}, en, en, en, di, di, "partial RELRO", "static-pie"},
		{"static executable without symbols", testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true}, di, en, di, un, un, "no PT_GNU_RELRO", "static"},
		{"static executable without PT_GNU_STACK", testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true, Stack: testfixtures.ELFStackNone}, di, un, di, un, un, "no PT_GNU_RELRO", "static"},
		{"static executable with symbols", testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true, Symbols: []string{"main", "__stack_chk_fail", "__sprintf_chk"}}, di, en, di, en, en, "no PT_GNU_RELRO", "static"},
		{"static executable with plain symbols", testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true, Symbols: []string{"main"}}, di, en, di, di, di, "no PT_GNU_RELRO", "static"},
		{"relocatable object", testfixtures.ELFOptions{Type: testfixtures.ELFTypeRel, Symbols: []string{"main", "__stack_chk_fail"}}, na, na, na, en, di, "is not relocated", ""},
		{"32-bit big-endian", testfixtures.ELFOptions{Bits: 32, BigEndian: true, RELRO: true, DynFlags: testfixtures.ELFDynFlagBindNow, Imports: hardened}, en, en, en, en, en, "full RELRO", "dynamic"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, testfixtures.ELF(tc.opts), limits.Limits{})
			for id, want := range map[string]string{
				report.HardenPIE: tc.pie, report.HardenNX: tc.nx, report.HardenRELRO: tc.relro,
				report.HardenCanary: tc.canary, report.HardenFortify: tc.fortify,
			} {
				if got := hardeningOf(t, res, id); got.Status != want || got.Detail == "" || got.Label == "" {
					t.Errorf("%s = %+v, want status %s", id, got, want)
				}
			}
			if d := hardeningOf(t, res, report.HardenRELRO).Detail; !strings.HasPrefix(d, tc.relroPrefix) && !strings.Contains(d, tc.relroPrefix) {
				t.Errorf("RELRO detail %q does not mention %q", d, tc.relroPrefix)
			}
			if res.Details.Linking != tc.linking {
				t.Errorf("linking = %q, want %q", res.Details.Linking, tc.linking)
			}
			if len(res.Hardening) != 5 {
				t.Errorf("want exactly the five checksec entries, got %d", len(res.Hardening))
			}
		})
	}
}

func TestParse_GoBinaryIsNotPenalisedForCanaryOrFortify(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{
		Type: testfixtures.ELFTypeExec, Static: true, GoBuildID: "go/id/with/slashes",
		Symbols:  []string{"main.main", "runtime.main"},
		Sections: []testfixtures.ELFSection{{Name: ".gopclntab", Flags: testfixtures.ELFSectionFlagAlloc, Data: []byte("pclntab")}},
	})
	res := parse(t, data, limits.Limits{})
	if got := hardeningOf(t, res, report.HardenCanary).Status; got != report.StatusNA {
		t.Errorf("canary = %s, want n/a for a Go binary", got)
	}
	if got := hardeningOf(t, res, report.HardenFortify).Status; got != report.StatusNA {
		t.Errorf("fortify = %s, want n/a for a Go binary", got)
	}
	if res.Details.GoBuildID != "go/id/with/slashes" {
		t.Errorf("goBuildId = %q", res.Details.GoBuildID)
	}
}

func TestParse_DynamicFacts(t *testing.T) {
	for _, bits := range []int{64, 32} {
		for _, big := range []bool{false, true} {
			data := testfixtures.ELF(testfixtures.ELFOptions{
				Bits: bits, BigEndian: big, Machine: testfixtures.ELFMachineAArch64,
				Needed: []string{"libc.so.6", "libm.so.6"}, RPath: []string{"/opt/a", "", "$ORIGIN/lib"},
				RunPath: []string{"/opt/b"}, Soname: "libfixture.so.1", Interp: "/lib/ld-musl-aarch64.so.1",
				OSABI: 3, Entry: 0x1234,
			})
			res := parse(t, data, limits.Limits{})
			d := res.Details
			if !slices.Equal(d.Needed, []string{"libc.so.6", "libm.so.6"}) {
				t.Errorf("bits=%d big=%v needed = %v", bits, big, d.Needed)
			}
			if !slices.Equal(d.RPath, []string{"/opt/a", "", "$ORIGIN/lib"}) {
				t.Errorf("rpath = %q (empty elements must be kept)", d.RPath)
			}
			if !slices.Equal(d.RunPath, []string{"/opt/b"}) || d.Soname != "libfixture.so.1" || d.Interpreter != "/lib/ld-musl-aarch64.so.1" {
				t.Errorf("runpath/soname/interp = %v %q %q", d.RunPath, d.Soname, d.Interpreter)
			}
			if d.Machine != "AArch64" || d.OSABI != "LINUX" || d.Entry != "0x1234" {
				t.Errorf("machine/osabi/entry = %q %q %q", d.Machine, d.OSABI, d.Entry)
			}
			wantEndian, wantClass := "little", "ELF64"
			if big {
				wantEndian = "big"
			}
			if bits == 32 {
				wantClass = "ELF32"
			}
			if d.Endian != wantEndian || d.Class != wantClass {
				t.Errorf("class/endian = %s/%s, want %s/%s", d.Class, d.Endian, wantClass, wantEndian)
			}
		}
	}
}

func TestParse_ImportsAndExports(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{
		Imports: []testfixtures.ELFImport{
			{Name: "puts", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
			{Name: "malloc", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
			{Name: "sqrt", Library: "libm.so.6", Version: "GLIBC_2.29"},
			{Name: "free", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
			{Name: "orphan"},
			{Name: "__gmon_start__", Weak: true},
		},
		Exports: []string{"zeta", "alpha"},
		Symbols: []string{"main", "helper"},
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
		{"libc.so.6", 3, []string{"free", "malloc", "puts"}},
		{"libm.so.6", 1, []string{"sqrt"}},
		{report.UnspecifiedLibrary, 2, []string{"__gmon_start__", "orphan"}},
	}
	if len(got) != len(want) {
		t.Fatalf("imports = %+v", got)
	}
	for i := range want {
		if got[i].lib != want[i].lib || got[i].count != want[i].count || !slices.Equal(got[i].funcs, want[i].funcs) {
			t.Errorf("import %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !slices.Equal(res.Exports, []string{"alpha", "zeta"}) {
		t.Errorf("exports = %v", res.Exports)
	}
	d := res.Details
	if d.ImportCount != 6 || d.ExportCount != 2 {
		t.Errorf("import/export counts = %d/%d", d.ImportCount, d.ExportCount)
	}
	// .dynsym holds 6 imports + 2 exports; .symtab holds the FILE entry + 2 functions.
	if d.DynamicSymbolCount != 8 || d.SymbolCount != 3 || d.Stripped {
		t.Errorf("counts dyn=%d sym=%d stripped=%v", d.DynamicSymbolCount, d.SymbolCount, d.Stripped)
	}
}

func TestParse_SectionClassification(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{
		TextData: noise(4096),
		Sections: []testfixtures.ELFSection{
			{Name: ".rodata", Flags: testfixtures.ELFSectionFlagAlloc, Data: bytes.Repeat([]byte{0}, 512)},
			{Name: ".evil", Flags: testfixtures.ELFSectionFlagAlloc | testfixtures.ELFSectionFlagWrite | testfixtures.ELFSectionFlagExec, Data: []byte{0xcc, 0xcc}},
			{Name: ".text.hot", Flags: testfixtures.ELFSectionFlagAlloc | testfixtures.ELFSectionFlagExec, Data: []byte{0x90}},
			{Name: "oddname", Flags: testfixtures.ELFSectionFlagAlloc, Data: []byte("x")},
			{Name: "__libc_freeres_fn", Flags: testfixtures.ELFSectionFlagAlloc | testfixtures.ELFSectionFlagExec, Data: []byte{0xc3}},
			{Name: ".bss2", Type: testfixtures.ELFSectionNobits, Flags: testfixtures.ELFSectionFlagAlloc | testfixtures.ELFSectionFlagWrite, Data: make([]byte, 128)},
			{Name: ".comment", Data: []byte("GCC: (fixture)")},
		},
		DebugInfo: true,
	})
	res := parse(t, data, limits.Limits{})
	byName := map[string]report.Section{}
	for _, s := range res.Sections {
		byName[s.Name] = s
	}
	if s := byName[".text"]; s.Entropy < 7.5 || s.Suspicious {
		t.Errorf(".text = %+v (noise must be high entropy and, by itself, not structurally suspicious)", s)
	}
	if s := byName[".rodata"]; s.Entropy != 0 || s.Suspicious || !slices.Equal(s.Flags, []string{"R"}) {
		t.Errorf(".rodata = %+v", s)
	}
	evil := byName[".evil"]
	if !evil.Suspicious || !slices.Equal(evil.Flags, []string{"R", "W", "X"}) ||
		!slices.Contains(evil.Reasons, "writable and executable") ||
		!slices.Contains(evil.Reasons, "executable section with a name that is not a code section") {
		t.Errorf(".evil = %+v", evil)
	}
	if s := byName[".text.hot"]; s.Suspicious {
		t.Errorf(".text.hot is a code section name: %+v", s)
	}
	if s := byName["oddname"]; !s.Suspicious || !slices.Contains(s.Reasons, "section name does not start with a dot") {
		t.Errorf("oddname = %+v", s)
	}
	if s := byName["__libc_freeres_fn"]; slices.Contains(s.Reasons, "section name does not start with a dot") {
		t.Errorf("a double-underscore name is a linker/runtime convention, not odd: %+v", s)
	}
	if s := byName[".bss2"]; s.RawSize != 0 || s.VirtualSize != 128 || s.Entropy != 0 {
		t.Errorf(".bss2 (NOBITS) = %+v", s)
	}
	if s := byName[".comment"]; len(s.Flags) != 0 || s.VirtualSize != 0 || s.RawSize != 14 {
		t.Errorf(".comment = %+v", s)
	}
	if !res.Details.HasDebugInfo {
		t.Error("hasDebugInfo should be true when .debug_info exists")
	}
	if res.Details.RWXSegments != 0 {
		t.Errorf("an RWX section does not make an RWX segment: %d", res.Details.RWXSegments)
	}
}

func TestParse_RWXSegmentIsCounted(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{Segments: []testfixtures.ELFSegment{
		{Type: testfixtures.ELFSegmentLoad, Flags: testfixtures.ELFSegmentFlagR | testfixtures.ELFSegmentFlagW | testfixtures.ELFSegmentFlagX, Data: noise(64)},
	}})
	res := parse(t, data, limits.Limits{})
	if res.Details.RWXSegments != 1 {
		t.Fatalf("rwxSegments = %d", res.Details.RWXSegments)
	}
	last := res.Details.Segments[len(res.Details.Segments)-1]
	if last.Type != "PT_LOAD" || !slices.Equal(last.Flags, []string{"R", "W", "X"}) || !strings.HasPrefix(last.VAddr, "0x") {
		t.Errorf("segment = %+v", last)
	}
}

func TestParse_NotesBuildIDs(t *testing.T) {
	id := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for _, big := range []bool{false, true} {
		res := parse(t, testfixtures.ELF(testfixtures.ELFOptions{BigEndian: big, BuildID: id, GoBuildID: "abc123"}), limits.Limits{})
		if res.Details.BuildID != "deadbeef0102030405060708090a0b0c0d0e0f10" || res.Details.GoBuildID != "abc123" {
			t.Errorf("big=%v ids = %q %q", big, res.Details.BuildID, res.Details.GoBuildID)
		}
	}
}

func TestParse_WithoutSectionHeadersListsLoadSegments(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{
		NoSections: true, Needed: []string{"libc.so.6"}, RPath: []string{"/tmp/x"}, RELRO: true,
		Imports: []testfixtures.ELFImport{{Name: "puts"}}, TextData: noise(2048),
	})
	res := parse(t, data, limits.Limits{})
	if len(res.Sections) != 2 || res.Sections[0].Name != "LOAD[0]" || res.Sections[1].Name != "LOAD[1]" {
		t.Fatalf("sections = %+v", res.Sections)
	}
	if !slices.Equal(res.Sections[0].Flags, []string{"R", "X"}) || !slices.Equal(res.Sections[1].Flags, []string{"R", "W"}) {
		t.Errorf("segment flags = %v %v", res.Sections[0].Flags, res.Sections[1].Flags)
	}
	if res.Sections[0].Entropy < 3 {
		t.Errorf("LOAD[0] entropy = %v, want the noisy .text to show", res.Sections[0].Entropy)
	}
	if !noteMentions(res, "no usable section header table") {
		t.Errorf("notes = %v", res.Notes)
	}
	d := res.Details
	if !slices.Equal(d.Needed, []string{"libc.so.6"}) || !slices.Equal(d.RPath, []string{"/tmp/x"}) || d.Interpreter == "" {
		t.Errorf("the dynamic section must be read through PT_DYNAMIC: %+v", d)
	}
	if len(res.Imports) != 0 {
		t.Errorf("imports need the section table: %+v", res.Imports)
	}
	if got := hardeningOf(t, res, report.HardenRELRO); got.Status != report.StatusEnabled || !strings.HasPrefix(got.Detail, "partial RELRO") {
		t.Errorf("relro = %+v", got)
	}
	if got := hardeningOf(t, res, report.HardenCanary).Status; got != report.StatusUnknown {
		t.Errorf("canary without symbols = %s, want unknown", got)
	}
	if d.SectionCount != 0 || !d.Stripped {
		t.Errorf("sectionCount %d stripped %v", d.SectionCount, d.Stripped)
	}
}

func TestParse_RWXLoadSegmentWithoutSectionsIsSuspicious(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{NoSections: true, Segments: []testfixtures.ELFSegment{
		{Type: testfixtures.ELFSegmentLoad, Flags: 7, Data: []byte("x")},
	}})
	res := parse(t, data, limits.Limits{})
	last := res.Sections[len(res.Sections)-1]
	if !last.Suspicious || !slices.Contains(last.Reasons, "writable and executable") {
		t.Errorf("section = %+v", last)
	}
}

func noteMentions(res *Result, sub string) bool {
	return slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func le64(data []byte, off int) uint64 { return binary.LittleEndian.Uint64(data[off:]) }

func TestParse_TruncatedFilesStillYieldHeaderAndSegments(t *testing.T) {
	full := testfixtures.ELF(testfixtures.ELFOptions{
		Needed: []string{"libc.so.6"}, Imports: []testfixtures.ELFImport{{Name: "puts", Library: "libc.so.6", Version: "GLIBC_2.2.5"}},
		Symbols: []string{"main"}, TextData: noise(1024),
	})
	shoff := int(le64(full, 40))
	tests := []struct {
		name    string
		cut     int
		note    string
		wantSec func(*Result) bool
	}{
		{"section table missing entirely", shoff, "lies outside the file", func(r *Result) bool { return r.Sections[0].Name == "LOAD[0]" }},
		{"section table cut inside the first header", shoff + 10, "truncated", func(r *Result) bool { return r.Sections[0].Name == "LOAD[0]" }},
		{"section table cut after three headers", shoff + 3*64, "truncated", func(r *Result) bool { return len(r.Sections) == 2 }},
		{"cut in the middle of the code", 400, "", func(r *Result) bool { return len(r.Sections) >= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, full[:tc.cut], limits.Limits{})
			if res.Details.Class != "ELF64" || res.Details.Machine != "x86-64" || res.Details.SegmentCount == 0 {
				t.Fatalf("header and program headers must survive: %+v", res.Details)
			}
			if tc.note != "" && !noteMentions(res, tc.note) {
				t.Errorf("notes %v do not mention %q", res.Notes, tc.note)
			}
			if tc.name == "section table cut after three headers" {
				if !tc.wantSec(res) && len(res.Sections) > 3 {
					t.Errorf("sections = %d", len(res.Sections))
				}
				return
			}
			if len(res.Sections) == 0 {
				t.Fatal("expected sections or segments to be listed")
			}
		})
	}
}

func TestParse_HeaderErrors(t *testing.T) {
	good := testfixtures.ELF(testfixtures.ELFOptions{})
	mutate := func(off int, v byte) []byte {
		b := slices.Clone(good)
		b[off] = v
		return b
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "only 0 bytes"},
		{"too short for the identification", good[:10], "only 10 bytes"},
		{"bad magic", mutate(1, 'X'), "bad magic"},
		{"bad class", mutate(4, 7), "unsupported ELF class"},
		{"bad data encoding", mutate(5, 9), "unsupported ELF data encoding"},
		{"truncated header", good[:40], "truncated ELF header"},
		{"text file", []byte("#!/bin/sh\necho not an elf\n"), "bad magic"},
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

func TestParse_MalformedTablesAreNotesNotCrashes(t *testing.T) {
	good := testfixtures.ELF(testfixtures.ELFOptions{Needed: []string{"libc.so.6"}, Symbols: []string{"main"}})
	put16 := func(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	put64 := func(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	tests := []struct {
		name   string
		mutate func([]byte)
		note   string
	}{
		{"program header entries too small", func(b []byte) { put16(b, 54, 8) }, "program header entries are declared as 8 bytes"},
		{"program header table outside the file", func(b []byte) { put64(b, 32, 1<<40) }, "program header table at offset"},
		{"more program headers than the file holds", func(b []byte) { put16(b, 56, 65535) }, "program header table is truncated"},
		{"section header entries too small", func(b []byte) { put16(b, 58, 10) }, "section header entries are declared as 10 bytes"},
		{"section header table outside the file", func(b []byte) { put64(b, 40, 1<<40) }, "section header table at offset"},
		{"more sections than the file holds", func(b []byte) { put16(b, 60, 60000) }, "section header table is truncated"},
		{"section name table index out of range", func(b []byte) { put16(b, 62, 99) }, "section name string table index 99"},
		{"section count without a table", func(b []byte) { put64(b, 40, 0) }, "e_shoff is 0"},
		{"extended section numbering with no room", func(b []byte) { put16(b, 60, 0) }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := slices.Clone(good)
			tc.mutate(b)
			res, err := Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{})
			if err != nil {
				t.Fatalf("a valid header with bad tables must not be fatal: %v", err)
			}
			if tc.note != "" && !noteMentions(res, tc.note) {
				t.Errorf("notes %v do not mention %q", res.Notes, tc.note)
			}
			if len(res.Hardening) != 5 {
				t.Errorf("hardening must always list five entries, got %d", len(res.Hardening))
			}
		})
	}
}

func TestParse_UnmappedStringTableIsReported(t *testing.T) {
	b := testfixtures.ELF(testfixtures.ELFOptions{NoSections: true, Needed: []string{"libc.so.6"}})
	// Move the read-only PT_LOAD far away so DT_STRTAB maps nowhere.
	// Program headers: PT_INTERP, PT_LOAD(rx), PT_LOAD(rw), ... entry 1 starts at 64+56.
	binary.LittleEndian.PutUint64(b[64+56+16:], 0x7000_0000)
	res := parse(t, b, limits.Limits{})
	if !noteMentions(res, "is not mapped by any loadable segment") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if len(res.Details.Needed) != 0 {
		t.Errorf("needed = %v", res.Details.Needed)
	}
}

func TestParse_LimitsCapRecordedListsButKeepTrueCounts(t *testing.T) {
	var imports []testfixtures.ELFImport
	for i := range 20 {
		imports = append(imports, testfixtures.ELFImport{Name: "fn" + string(rune('a'+i))})
	}
	data := testfixtures.ELF(testfixtures.ELFOptions{Imports: imports, Exports: []string{"e1", "e2", "e3", "e4"}, Needed: []string{"a", "b", "c", "d"}})
	res := parse(t, data, limits.Limits{MaxList: 3})
	recorded := 0
	for _, imp := range res.Imports {
		recorded += len(imp.Functions)
		if imp.Count != 20 {
			t.Errorf("Count = %d, want the true 20", imp.Count)
		}
	}
	if recorded != 3 {
		t.Errorf("recorded %d functions, want the cap of 3", recorded)
	}
	if len(res.Exports) != 3 || res.Details.ExportCount != 4 || res.Details.ImportCount != 20 {
		t.Errorf("exports %v counts %d/%d", res.Exports, res.Details.ExportCount, res.Details.ImportCount)
	}
	if len(res.Sections) != 3 || res.Details.SectionCount != 6 {
		t.Errorf("sections %d (count %d)", len(res.Sections), res.Details.SectionCount)
	}
	if len(res.Details.Segments) != 3 || res.Details.SegmentCount != 5 {
		t.Errorf("segments %d (count %d)", len(res.Details.Segments), res.Details.SegmentCount)
	}
	if len(res.Details.Needed) != 3 {
		t.Errorf("needed = %v", res.Details.Needed)
	}
}

func TestParse_OversizedSymbolTableIsCountedNotDecoded(t *testing.T) {
	var imports []testfixtures.ELFImport
	for i := range 100 {
		imports = append(imports, testfixtures.ELFImport{Name: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	data := testfixtures.ELF(testfixtures.ELFOptions{Imports: imports})
	// .dynsym is 101*24 bytes; a 1 KiB metadata budget still fits the headers
	// but makes the symbol table "too large to decode".
	res := parse(t, data, limits.Limits{MaxMeta: 1024})
	if res.Details.DynamicSymbolCount != 100 {
		t.Errorf("counts must come from the section headers: %+v", res.Details)
	}
	if len(res.Imports) != 0 || !noteMentions(res, "counted but not decoded") {
		t.Errorf("imports %+v notes %v", res.Imports, res.Notes)
	}
	if got := hardeningOf(t, res, report.HardenCanary).Status; got != report.StatusUnknown {
		t.Errorf("canary = %s, want unknown when no table could be decoded", got)
	}
	// With the default budget the same file decodes fine.
	if full := parse(t, data, limits.Limits{}); full.Details.ImportCount != 100 {
		t.Errorf("default limits decode %d imports, want 100", full.Details.ImportCount)
	}
}

func TestParse_ContextCancellationReturnsPartialResult(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{Needed: []string{"libc.so.6"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil || res.Details.Class != "ELF64" || len(res.Hardening) != 5 {
		t.Fatalf("a cancelled parse must still return what it has: %+v", res)
	}
}

func TestParse_SizeIsAHardBoundOnReads(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{})
	// The reader holds the whole file but the caller says it is shorter: the
	// parser must behave as if the file really ended there.
	if _, err := Parse(context.Background(), bytes.NewReader(data), 40, limits.Limits{}); err == nil || !strings.Contains(err.Error(), "truncated ELF header") {
		t.Fatalf("a 40 byte view cuts the header: err = %v", err)
	}
	res, err := Parse(context.Background(), bytes.NewReader(data), 100, limits.Limits{})
	if err != nil {
		t.Fatalf("a 64-byte header fits in 100 bytes: %v", err)
	}
	if res.Details.SegmentCount != 0 || !noteMentions(res, "program header table is truncated") {
		t.Errorf("segments %d notes %v", res.Details.SegmentCount, res.Notes)
	}
	if _, err := Parse(context.Background(), bytes.NewReader(data), -5, limits.Limits{}); err == nil {
		t.Error("a negative size must be treated as an empty file")
	}
}

func TestParse_NonPrintableNamesAreEscaped(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{
		Needed: []string{"lib\x1b[31mred.so"}, Soname: "so\x07name",
		Sections: []testfixtures.ELFSection{{Name: ".e\x1bvil", Flags: testfixtures.ELFSectionFlagAlloc, Data: []byte{1}}},
		Imports:  []testfixtures.ELFImport{{Name: "bad\x1bname"}},
	})
	res := parse(t, data, limits.Limits{})
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte{0x1b}) || strings.Contains(string(raw), `\u001b`) {
		t.Errorf("escape characters must not reach the result: %s", raw)
	}
	if !slices.Equal(res.Details.Needed, []string{`lib\x1b[31mred.so`}) {
		t.Errorf("needed = %q", res.Details.Needed)
	}
}

func TestDetailsJSONContract(t *testing.T) {
	data := testfixtures.ELF(testfixtures.ELFOptions{GoBuildID: "x"})
	raw, err := json.Marshal(parse(t, data, limits.Limits{}).Details)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"class", "endian", "osAbi", "abiVersion", "type", "machine", "entry", "interpreter", "linking", "needed", "rpath", "runpath",
		"soname", "stripped", "hasDebugInfo", "buildId", "goBuildId", "segments", "segmentCount", "rwxSegments", "sectionCount",
		"symbolCount", "dynamicSymbolCount", "importCount", "exportCount",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("details.elf is missing the key %q", key)
		}
	}
	for _, key := range []string{"needed", "rpath", "runpath", "segments"} {
		if _, ok := m[key].([]any); !ok {
			t.Errorf("%s must encode as an array, got %T", key, m[key])
		}
	}
	seg := m["segments"].([]any)[0].(map[string]any)
	for _, key := range []string{"type", "flags", "offset", "vaddr", "fileSize", "memSize"} {
		if _, ok := seg[key]; !ok {
			t.Errorf("segment is missing %q", key)
		}
	}
}

func TestResultSlicesAreNeverNil(t *testing.T) {
	res := parse(t, testfixtures.ELF(testfixtures.ELFOptions{NoSections: true, Stack: testfixtures.ELFStackNone}), limits.Limits{})
	if res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Hardening == nil || res.Notes == nil {
		t.Fatalf("nil slice in %+v", res)
	}
}

func TestParse_EntropyBudgetStopsOverlappingSectionTables(t *testing.T) {
	var extra []testfixtures.ELFSection
	for i := range 12 {
		extra = append(extra, testfixtures.ELFSection{Name: ".x" + string(rune('a'+i)), Flags: testfixtures.ELFSectionFlagAlloc, Data: []byte{byte(i)}})
	}
	data := testfixtures.ELF(testfixtures.ELFOptions{TextData: noise(300_000), Sections: extra})
	shoff, shnum, shstrndx := int(le64(data, 40)), int(binary.LittleEndian.Uint16(data[60:])), int(binary.LittleEndian.Uint16(data[62:]))
	// Every section except the name table now claims the whole file.
	for i := 1; i < shnum; i++ {
		if i == shstrndx {
			continue
		}
		hdr := data[shoff+i*64:]
		binary.LittleEndian.PutUint64(hdr[24:], 0)
		binary.LittleEndian.PutUint64(hdr[32:], uint64(len(data)))
	}
	res := parse(t, data, limits.Limits{})
	if !noteMentions(res, "entropy was not computed") {
		t.Fatalf("notes = %v", res.Notes)
	}
	measured := 0
	for _, s := range res.Sections {
		if s.Entropy > 0 {
			measured++
		}
	}
	if measured == 0 || measured >= len(res.Sections)-1 {
		t.Errorf("%d of %d sections were measured; the budget should let some through and stop the rest", measured, len(res.Sections))
	}
	// An honest file of the same size is never throttled.
	honest := parse(t, testfixtures.ELF(testfixtures.ELFOptions{TextData: noise(300_000), Sections: extra}), limits.Limits{})
	if noteMentions(honest, "entropy was not computed") {
		t.Errorf("honest file throttled: %v", honest.Notes)
	}
}
