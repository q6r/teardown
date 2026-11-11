package sniff

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/report"
)

// idFamily is the family every type ID must be reported with.
var idFamily = map[string]string{
	report.TypePE: report.FamilyExecutable, report.TypeDOS: report.FamilyExecutable,
	report.TypeELF: report.FamilyExecutable, report.TypeMachO: report.FamilyExecutable,
	report.TypeMachOFat: report.FamilyExecutable, report.TypeWasm: report.FamilyExecutable,
	report.TypeClass: report.FamilyBytecode, report.TypeDex: report.FamilyBytecode,
	report.TypePyc: report.FamilyBytecode, report.TypeLua: report.FamilyBytecode,
	report.TypeZip: report.FamilyArchive, report.TypeGzip: report.FamilyArchive,
	report.TypeBzip2: report.FamilyArchive, report.TypeXz: report.FamilyArchive,
	report.TypeZstd: report.FamilyArchive, report.Type7z: report.FamilyArchive,
	report.TypeRar: report.FamilyArchive, report.TypeTar: report.FamilyArchive,
	report.TypeJar: report.FamilyPackage, report.TypeAPK: report.FamilyPackage,
	report.TypeAAB: report.FamilyPackage, report.TypeNupkg: report.FamilyPackage,
	report.TypeWheel: report.FamilyPackage, report.TypeVSIX: report.FamilyPackage,
	report.TypeAsar: report.FamilyPackage,
	report.TypeDocx: report.FamilyDocument, report.TypeXlsx: report.FamilyDocument,
	report.TypePptx: report.FamilyDocument, report.TypeODF: report.FamilyDocument,
	report.TypeEPUB: report.FamilyDocument, report.TypePDF: report.FamilyDocument,
	report.TypeRTF: report.FamilyDocument, report.TypeOLE: report.FamilyDocument,
	report.TypePNG: report.FamilyImage, report.TypeJPEG: report.FamilyImage,
	report.TypeGIF: report.FamilyImage, report.TypeWebP: report.FamilyImage,
	report.TypeSQLite: report.FamilyDatabase,
	report.TypeGGUF:   report.FamilyModel, report.TypeSafetensors: report.FamilyModel,
	report.TypeScript: report.FamilyScript,
	report.TypeText:   report.FamilyText,
	report.TypeData:   report.FamilyData,
}

// invariantProblem returns a description of the first violated contract rule of
// a detection result, or "" when it is well-formed.
func invariantProblem(got report.Type) string {
	switch {
	case got.ID == "" || got.Family == "" || got.Label == "" || got.MIME == "":
		return fmt.Sprintf("empty field in %+v", got)
	case got.Tags == nil:
		return "Tags must never be nil"
	case !slices.IsSorted(got.Tags):
		return fmt.Sprintf("Tags not sorted: %v", got.Tags)
	}
	for i, tag := range got.Tags {
		switch {
		case tag == "" || tag != strings.ToLower(tag):
			return fmt.Sprintf("bad tag %q in %v", tag, got.Tags)
		case i > 0 && tag == got.Tags[i-1]:
			return fmt.Sprintf("duplicate tag %q", tag)
		}
	}
	switch got.Confidence {
	case report.ConfidenceHigh, report.ConfidenceMedium, report.ConfidenceLow:
	default:
		return fmt.Sprintf("bad confidence %q", got.Confidence)
	}
	want, known := idFamily[got.ID]
	switch {
	case !known:
		return fmt.Sprintf("unknown type ID %q", got.ID)
	case got.Family != want:
		return fmt.Sprintf("type %q reported with family %q, want %q", got.ID, got.Family, want)
	}
	return ""
}

func detectBytes(b []byte) report.Type { return Detect(bytes.NewReader(b), int64(len(b))) }

func TestDetect(t *testing.T) {
	for _, f := range fixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			got := detectBytes(f.data)
			if p := invariantProblem(got); p != "" {
				t.Fatal(p)
			}
			if got.ID != f.id {
				t.Fatalf("ID = %q (%s), want %q", got.ID, got.Label, f.id)
			}
			if got.Family != f.family {
				t.Errorf("Family = %q, want %q", got.Family, f.family)
			}
			if got.Confidence != f.conf {
				t.Errorf("Confidence = %q, want %q (label %q)", got.Confidence, f.conf, got.Label)
			}
			if f.tags != nil && !slices.Equal(got.Tags, f.tags) {
				t.Errorf("Tags = %v, want %v", got.Tags, f.tags)
			}
			if f.label != "" && !strings.Contains(got.Label, f.label) {
				t.Errorf("Label = %q, want it to contain %q", got.Label, f.label)
			}
			if f.mime != "" && got.MIME != f.mime {
				t.Errorf("MIME = %q, want %q", got.MIME, f.mime)
			}
		})
	}
}

func TestDetectEmptyInput(t *testing.T) {
	for _, size := range []int64{0, -1, -1 << 40} {
		got := Detect(bytes.NewReader(nil), size)
		if p := invariantProblem(got); p != "" {
			t.Fatal(p)
		}
		if got.ID != report.TypeData || got.Label != "empty file" || !slices.Equal(got.Tags, []string{"empty"}) {
			t.Errorf("size %d: got %+v", size, got)
		}
	}
}

func TestDetectEveryTypeIDIsExercised(t *testing.T) {
	// Every ID the table can produce must appear in the fixtures, so a detector
	// that silently stops matching cannot go unnoticed.
	seen := map[string]bool{}
	for _, f := range fixtures(t) {
		seen[f.id] = true
	}
	for id := range idFamily {
		if !seen[id] {
			t.Errorf("no fixture produces type %q", id)
		}
	}
}

// part overlays bytes at an offset of a virtual file.
type part struct {
	off  int64
	data []byte
}

// virtualReader is a sparse file: zeros everywhere except the overlays. It counts
// what is read from it.
type virtualReader struct {
	size  int64
	parts []part
	read  int64
	calls int
}

func (v *virtualReader) ReadAt(p []byte, off int64) (int, error) {
	v.calls++
	v.read += int64(len(p))
	if off < 0 || off >= v.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), v.size-off))
	clear(p[:n])
	for _, pt := range v.parts {
		lo, hi := max(off, pt.off), min(off+int64(n), pt.off+int64(len(pt.data)))
		if lo < hi {
			copy(p[lo-off:hi-off], pt.data[lo-pt.off:hi-pt.off])
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestDetectDoesBoundedWorkOnHugeFiles(t *testing.T) {
	const size = int64(4) << 30
	cookie := []byte("MEI\x0c\x0b\x0a\x0b\x0e")
	farPE := buildPE(peSpec{})
	// e_lfanew pointing 1 KiB before the end of a 4 GiB file: the header probe
	// must seek there instead of reading the file.
	const farOffset = int64(4)<<30 - 1024
	le.PutUint32(farPE[0x3c:], uint32(farOffset))
	farHeader := buildPE(peSpec{})[0x80 : 0x80+4+20+240]

	tests := []struct {
		name     string
		parts    []part
		wantID   string
		wantTags []string
	}{
		{"zeros", nil, report.TypeData, nil},
		{"pe with a cookie in the last 64 KiB", []part{{0, buildPE(peSpec{})}, {size - 100, cookie}},
			report.TypePE, []string{"64-bit", "exe", "pyinstaller", "x86-64"}},
		{"pe with a cookie far from the end", []part{{0, buildPE(peSpec{})}, {size - 1<<20, cookie}},
			report.TypePE, []string{"64-bit", "exe", "x86-64"}},
		{"pe whose header is at the end of the file", []part{{0, farPE[:0x40]}, {farOffset, farHeader}},
			report.TypePE, []string{"64-bit", "exe", "x86-64"}},
		{"elf", []part{{0, buildELF(2, 1, 3, 62)}}, report.TypeELF, nil},
		{"mach-o", []part{{0, buildMachO(machoMagic64LE, 0x0100000c, 0, 2, 0, 0)}}, report.TypeMachO, nil},
		{"fat mach-o with slices past 3 GiB", nil, report.TypeData, nil}, // replaced below
	}
	fat := buildFat(be, fatMagic, false, fatSlice{0x0100000c, 0, buildMachO(machoMagic64LE, 0x0100000c, 0, 2, 0, 0)})
	be.PutUint32(fat[16:], uint32(3<<30)) // slice offset 3 GiB
	be.PutUint32(fat[20:], 32)
	tests[len(tests)-1].parts = []part{{0, fat[:28]}, {3 << 30, buildMachO(machoMagic64LE, 0x0100000c, 0, 2, 0, 0)}}
	tests[len(tests)-1].wantID = report.TypeMachOFat

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &virtualReader{size: size, parts: tc.parts}
			start := time.Now()
			got := Detect(v, size)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Detect took %v", d)
			}
			if p := invariantProblem(got); p != "" {
				t.Fatal(p)
			}
			if got.ID != tc.wantID {
				t.Fatalf("ID = %q (%s), want %q", got.ID, got.Label, tc.wantID)
			}
			if tc.wantTags != nil && !slices.Equal(got.Tags, tc.wantTags) {
				t.Errorf("Tags = %v, want %v", got.Tags, tc.wantTags)
			}
			if limit := int64(headSize + tailSize + 8<<10); v.read > limit || v.calls > 12 {
				t.Errorf("read %d bytes in %d calls, want at most %d bytes", v.read, v.calls, limit)
			}
		})
	}
}

func TestDetectSafetensorsLargeHeaders(t *testing.T) {
	// A header above 16 MiB is accepted on its framing alone; above 100 MiB it is rejected.
	const headerLen = 20 << 20
	size := int64(8 + headerLen + 64)
	tests := []struct {
		name   string
		last   byte
		length uint64
		want   string
	}{
		{"closing brace", '}', headerLen, report.TypeSafetensors},
		{"padding spaces", ' ', headerLen, report.TypeSafetensors},
		{"truncated header", 'x', headerLen, report.TypeData},
		{"implausible length", '}', 200 << 20, report.TypeData},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			head := append(le.AppendUint64(nil, tc.length), `{"w":`...)
			v := &virtualReader{size: size, parts: []part{{0, head}, {8 + headerLen - 1, []byte{tc.last}}}}
			got := Detect(v, size)
			if got.ID != tc.want {
				t.Fatalf("ID = %q (%s), want %q", got.ID, got.Label, tc.want)
			}
			if got.ID == report.TypeSafetensors && got.Confidence != report.ConfidenceMedium {
				t.Errorf("Confidence = %q, want medium for an undecoded header", got.Confidence)
			}
		})
	}
}

func TestDetectToleratesMisbehavingReaders(t *testing.T) {
	pe := buildPE(peSpec{})
	tests := []struct {
		name string
		r    io.ReaderAt
		size int64
		want string // "" = any well-formed result
	}{
		{"read error", errReader{errors.New("boom")}, 4096, report.TypeData},
		{"size larger than the data", bytes.NewReader(pe), int64(len(pe)) + 1<<40, report.TypePE},
		{"size smaller than the data", bytes.NewReader(pe), 100, ""},
		{"size of one byte", bytes.NewReader(pe), 1, report.TypeText},
		{"reader that returns nothing and no error", zeroReader{}, 1 << 20, report.TypeData},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.r, tc.size)
			if p := invariantProblem(got); p != "" {
				t.Fatal(p)
			}
			if tc.want != "" && got.ID != tc.want {
				t.Errorf("ID = %q (%s), want %q", got.ID, got.Label, tc.want)
			}
		})
	}
}

type errReader struct{ err error }

func (e errReader) ReadAt([]byte, int64) (int, error) { return 0, e.err }

// zeroReader claims success while reading nothing.
type zeroReader struct{}

func (zeroReader) ReadAt([]byte, int64) (int, error) { return 0, nil }

// TestNeverPanics feeds every fixture truncated at every length (all lengths up
// to 4 KiB, then every 97th) and with each of its first 512 bytes replaced by
// 0x00, 0xFF and 0x80. Detect must return a well-formed result, quickly.
func TestNeverPanics(t *testing.T) {
	const slow = time.Second
	check := func(name string, data []byte) {
		t.Helper()
		start := time.Now()
		got := detectBytes(data)
		if d := time.Since(start); d > slow {
			t.Fatalf("%s: Detect took %v", name, d)
		}
		if p := invariantProblem(got); p != "" {
			t.Fatalf("%s: %s", name, p)
		}
	}
	for _, f := range fixtures(t) {
		for n := 0; n <= len(f.data); {
			check(fmt.Sprintf("%s truncated to %d", f.name, n), f.data[:n])
			if n < 4096 {
				n++
			} else {
				n += 97
			}
		}
		mutated := slices.Clone(f.data)
		for i := range min(512, len(mutated)) {
			orig := mutated[i]
			for _, v := range []byte{0x00, 0xff, 0x80} {
				mutated[i] = v
				check(fmt.Sprintf("%s byte %d = %#x", f.name, i, v), mutated)
			}
			mutated[i] = orig
		}
	}
}

func TestZipClassificationLooksAtEveryMember(t *testing.T) {
	// Large APKs list their resources before classes.dex; a capped listing would
	// misreport them as plain ZIP files.
	entries := make([]zentry, 0, 12_000)
	entries = append(entries, zentry{name: "AndroidManifest.xml", data: "m"})
	for i := range 11_000 {
		entries = append(entries, zentry{name: fmt.Sprintf("res/layout/l%05d.xml", i)})
	}
	entries = append(entries, zentry{name: "classes.dex", data: "d"}, zentry{name: "resources.arsc", data: "r"})
	got := detectBytes(buildZip(t, entries...))
	if got.ID != report.TypeAPK || got.Confidence != report.ConfidenceHigh {
		t.Fatalf("got %s (%s, %s), want a high-confidence apk", got.ID, got.Label, got.Confidence)
	}
}

func TestPycTable(t *testing.T) {
	prev := pycRelease{}
	for _, r := range pycReleases {
		if r.lo > r.hi {
			t.Errorf("range %+v is inverted", r)
		}
		// Within each family (2.x and 3.x numbers) ranges ascend and never overlap.
		if (r.lo < 10000) == (prev.lo < 10000) && prev.version != "" && r.lo <= prev.hi {
			t.Errorf("range %+v overlaps %+v", r, prev)
		}
		prev = r
	}
	if last := pycReleases[len(pycReleases)-1]; last.hi >= pycNewerLo {
		t.Errorf("the table reaches %d, into the open-ended range starting at %d", last.hi, pycNewerLo)
	}
	tests := []struct {
		magic int
		want  string
		ok    bool
	}{
		{3495, "3.11", true}, {3394, "3.7", true}, {3413, "3.8", true}, {3425, "3.9", true}, {3439, "3.10", true},
		{3531, "3.12", true}, {3571, "3.13", true}, {3627, "3.14", true}, {62211, "2.7", true}, {3131, "3.0", true},
		{3999, "3.15+", true}, {4000, "", false}, {2999, "", false}, {0, "", false}, {20122, "", false},
	}
	for _, tc := range tests {
		got, ok := pycVersion(tc.magic)
		if got != tc.want || ok != tc.ok {
			t.Errorf("pycVersion(%d) = %q, %v; want %q, %v", tc.magic, got, ok, tc.want, tc.ok)
		}
	}
	for magic, want := range map[int]int{62211: 8, 3000: 8, 3189: 8, 3190: 12, 3389: 12, 3390: 16, 3627: 16} {
		if got := pycHeaderLen(magic); got != want {
			t.Errorf("pycHeaderLen(%d) = %d, want %d", magic, got, want)
		}
	}
}

func TestJavaRelease(t *testing.T) {
	tests := []struct {
		major uint16
		want  string
		ok    bool
	}{
		{44, "", false}, {45, "1.1", true}, {46, "1.2", true}, {47, "1.3", true}, {48, "1.4", true},
		{49, "5", true}, {50, "6", true}, {51, "7", true}, {52, "8", true}, {55, "11", true}, {61, "17", true},
		{65, "21", true}, {69, "25", true}, {70, "26", true}, {100, "56", true}, {101, "", false},
	}
	for _, tc := range tests {
		got, ok := javaRelease(tc.major)
		if got != tc.want || ok != tc.ok {
			t.Errorf("javaRelease(%d) = %q, %v; want %q, %v", tc.major, got, ok, tc.want, tc.ok)
		}
	}
}

func TestShebangInterpreter(t *testing.T) {
	tests := []struct {
		line, path, base string
	}{
		{"/bin/sh", "/bin/sh", "sh"},
		{"/bin/bash -e", "/bin/bash", "bash"},
		{"/usr/bin/env python3", "python3", "python3"},
		{"/usr/bin/env -S node --flag", "node", "node"},
		{"/usr/bin/env FOO=bar ruby", "ruby", "ruby"},
		{"/usr/bin/env", "/usr/bin/env", "env"},
		{`C:\Tools\Python\PYTHON.EXE`, `C:\Tools\Python\PYTHON.EXE`, "python.exe"},
	}
	for _, tc := range tests {
		path, base := shebangInterpreter(tc.line)
		if path != tc.path || base != tc.base {
			t.Errorf("shebangInterpreter(%q) = %q, %q; want %q, %q", tc.line, path, base, tc.path, tc.base)
		}
	}
}

func TestScriptLabelsAreSanitised(t *testing.T) {
	// The interpreter path comes from the file; control characters must not reach the label.
	got := detectBytes([]byte("#!/bin/sh\x1b[31m\nmore\n"))
	if strings.ContainsRune(got.Label, 0x1b) {
		t.Fatalf("label %q contains an escape character", got.Label)
	}
	if got.ID == report.TypeScript && got.Confidence == report.ConfidenceHigh {
		t.Errorf("a shebang line with control characters must not be trusted: %+v", got)
	}
}

func TestPEWithPrefixedGarbageIsNotReported(t *testing.T) {
	// MZ must be at offset 0: an executable embedded in other data is not an executable file.
	got := detectBytes(append([]byte("junk"), buildPE(peSpec{})...))
	if got.ID == report.TypePE {
		t.Fatalf("got %+v", got)
	}
}
