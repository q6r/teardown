package archive_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/format/archive"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
	"github.com/q6r/teardown/internal/zipscan"
)

func parse(t *testing.T, b []byte, kind string) *archive.Result {
	t.Helper()
	return parseLim(t, b, kind, limits.Limits{})
}

func parseLim(t *testing.T, b []byte, kind string, lim limits.Limits) *archive.Result {
	t.Helper()
	res, err := archive.Parse(context.Background(), bytes.NewReader(b), int64(len(b)), lim, kind)
	if err != nil {
		t.Fatalf("Parse(%s): %v", kind, err)
	}
	return res
}

func hasNote(res *archive.Result, substr string) bool {
	for _, n := range res.Notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

func hasLimitation(res *archive.Result, substr string) bool {
	for _, l := range res.Limitations {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func TestParseAlwaysStatesTheDeclaredSizeLimitation(t *testing.T) {
	res := parse(t, testfixtures.Zip(store("a", "1")), report.TypeZip)
	if !hasLimitation(res, "declares") || hasLimitation(res, "heuristically") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func store(name, data string) testfixtures.ZipEntry {
	return testfixtures.ZipEntry{Name: name, Data: []byte(data), Store: true}
}

func TestParseJAR(t *testing.T) {
	b := testfixtures.JAR(testfixtures.JAROptions{
		MainClass:  "com.example.Main",
		ClassPath:  strings.Repeat("lib/dep-1.0.jar ", 10),
		Attributes: map[string]string{"Multi-Release": "true", "Premain-Class": "com.example.Agent", "Bundle-SymbolicName": "demo"},
		Classes:    4,
		Signed:     true,
		Extra:      []testfixtures.ZipEntry{store("lib/inner.jar", "PK\x03\x04 nested"), store("run.sh", "#!/bin/sh\n")},
	})
	d := parse(t, b, report.TypeJar).Details

	if d.Kind != "jar" || d.EntryCount != 10 || len(d.Entries) != 10 || d.EntriesTruncated {
		t.Errorf("kind=%q entries=%d/%d truncated=%v", d.Kind, d.EntryCount, len(d.Entries), d.EntriesTruncated)
	}
	if d.ClassCount != 4 || !d.Signed {
		t.Errorf("classes=%d signed=%v", d.ClassCount, d.Signed)
	}
	wantManifest := map[string]string{
		"Manifest-Version": "1.0", "Created-By": "teardown testfixtures", "Main-Class": "com.example.Main",
		"Multi-Release": "true", "Premain-Class": "com.example.Agent", "Bundle-SymbolicName": "demo",
		"Class-Path": strings.Repeat("lib/dep-1.0.jar ", 10),
	}
	for k, v := range wantManifest {
		if d.Manifest[k] != v {
			t.Errorf("manifest[%s] = %q, want %q", k, d.Manifest[k], v)
		}
	}
	if !slices.Equal(d.Nested, []string{"lib/inner.jar"}) || d.NestedCount != 1 {
		t.Errorf("nested = %v (%d)", d.Nested, d.NestedCount)
	}
	if d.Android != nil || d.Office != nil {
		t.Errorf("a JAR must carry neither android nor office facts")
	}
	if d.Entries[0].Name != "META-INF/" || !d.Entries[0].Dir {
		t.Errorf("first entry = %+v", d.Entries[0])
	}
	if e := d.Entries[1]; e.Name != "META-INF/MANIFEST.MF" || e.Method != "stored" || e.Size == 0 || e.Size != e.CompressedSize {
		t.Errorf("manifest entry = %+v", e)
	}
}

func TestParseUnsignedJARHasNoSignature(t *testing.T) {
	d := parse(t, testfixtures.JAR(testfixtures.JAROptions{}), report.TypeJar).Details
	if d.Signed || len(d.Nested) != 0 || d.ClassCount != 1 {
		t.Fatalf("signed=%v nested=%v classes=%d", d.Signed, d.Nested, d.ClassCount)
	}
}

func TestParseAPK(t *testing.T) {
	perms := []string{"android.permission.INTERNET", "android.permission.CAMERA", "android.permission.INTERNET", "com.example.demo.permission.PRIVATE"}
	b := testfixtures.APK(testfixtures.APKOptions{
		Permissions: perms, ABIs: []string{"x86_64", "arm64-v8a"}, DexFiles: 2, V1Signed: true, SigningBlock: true,
	})
	res := parse(t, b, report.TypeAPK)
	a := res.Details.Android
	if a == nil {
		t.Fatal("android facts missing")
	}
	wantPerms := []string{"android.permission.CAMERA", "android.permission.INTERNET", "com.example.demo.permission.PRIVATE"}
	if !slices.Equal(a.Permissions, wantPerms) {
		t.Errorf("permissions = %v, want %v", a.Permissions, wantPerms)
	}
	if !a.ManifestPresent || !a.PermissionsHeuristic || !a.HasResourcesArsc || !a.SigningBlock {
		t.Errorf("flags = %+v", a)
	}
	if a.DexFiles != 2 {
		t.Errorf("dex files = %d", a.DexFiles)
	}
	if !slices.Equal(a.ABIs, []string{"arm64-v8a", "x86_64"}) {
		t.Errorf("abis = %v", a.ABIs)
	}
	if !slices.Equal(a.NativeLibs, []string{"lib/arm64-v8a/libdemo.so", "lib/x86_64/libdemo.so"}) {
		t.Errorf("native libs = %v", a.NativeLibs)
	}
	if !res.Details.Signed {
		t.Error("v1 signature files must set signed")
	}
	if !hasLimitation(res, "heuristically") || !hasLimitation(res, "presence checks only") {
		t.Errorf("limitations must state that permissions are heuristic and signatures unverified: %v", res.Limitations)
	}
	if hasNote(res, "heuristic") {
		t.Errorf("a limitation is not a warning: %v", res.Notes)
	}
	if res.Details.PrefixBytes != 0 {
		t.Errorf("a signing block is not a prefix: %d", res.Details.PrefixBytes)
	}
}

func TestParseAPKWithoutExtras(t *testing.T) {
	a := parse(t, testfixtures.APK(testfixtures.APKOptions{}), report.TypeAPK).Details.Android
	if a.SigningBlock || len(a.Permissions) != 0 || a.Permissions == nil || len(a.ABIs) != 0 || a.ABIs == nil || a.NativeLibs == nil {
		t.Fatalf("%+v (slices must be empty, not nil)", a)
	}
}

func TestParseAAB(t *testing.T) {
	perms := []string{"android.permission.READ_CONTACTS", "android.permission.INTERNET"}
	b := testfixtures.AAB(testfixtures.AABOptions{Permissions: perms, ABIs: []string{"arm64-v8a", "armeabi-v7a"}})
	res := parse(t, b, report.TypeAAB)
	a := res.Details.Android
	if a == nil || !a.ManifestPresent {
		t.Fatalf("android = %+v", a)
	}
	if !slices.Equal(a.Permissions, []string{"android.permission.INTERNET", "android.permission.READ_CONTACTS"}) {
		t.Errorf("permissions = %v", a.Permissions)
	}
	if !slices.Equal(a.ABIs, []string{"arm64-v8a", "armeabi-v7a"}) || len(a.NativeLibs) != 2 {
		t.Errorf("abis = %v libs = %v", a.ABIs, a.NativeLibs)
	}
	if a.DexFiles != 1 || !a.HasResourcesArsc || a.SigningBlock {
		t.Errorf("dex=%d resources=%v signing=%v", a.DexFiles, a.HasResourcesArsc, a.SigningBlock)
	}
	if !hasLimitation(res, "heuristically") {
		t.Errorf("limitations = %v", res.Limitations)
	}
	if hasNote(res, "no readable string pool") {
		t.Errorf("a protobuf manifest is expected to be scanned as raw bytes without complaint: %v", res.Notes)
	}
}

func TestParseNotesAnOversizedAndroidManifest(t *testing.T) {
	big := testfixtures.Zip(testfixtures.ZipEntry{Name: "AndroidManifest.xml", Data: bytes.Repeat([]byte{'x'}, 5000), Store: true})
	res := parseLim(t, big, report.TypeAPK, limits.Limits{MaxMeta: 1024})
	if !hasNote(res, "larger than the read limit") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if a := res.Details.Android; a == nil || !a.ManifestPresent || len(a.Permissions) != 0 {
		t.Fatalf("android = %+v", a)
	}
}

func TestParseAndroidFactsOnlyForAndroidKinds(t *testing.T) {
	b := testfixtures.APK(testfixtures.APKOptions{Permissions: []string{"android.permission.INTERNET"}})
	for _, kind := range []string{report.TypeZip, report.TypeJar, report.TypeDocx, ""} {
		if d := parse(t, b, kind).Details; d.Android != nil {
			t.Errorf("kind %q must not produce android facts", kind)
		}
	}
}

func TestParseZipSlip(t *testing.T) {
	res := parse(t, testfixtures.ZipSlip(), report.TypeZip)
	d := res.Details
	want := []string{
		"../../evil.sh", `..\..\Windows\Temp\evil.dll`, "/etc/cron.d/backdoor", `C:\Users\Public\evil.exe`,
		`\\attacker\share\evil.lnk`, "nested/../../escape.txt", `ok.txt\x00../../hidden`,
	}
	if !slices.Equal(d.UnsafeNames, want) || d.UnsafeCount != len(want) {
		t.Fatalf("unsafe = %q (%d)\nwant   %q", d.UnsafeNames, d.UnsafeCount, want)
	}
	if slices.Contains(d.UnsafeNames, "docs/readme.txt") {
		t.Error("the harmless entry must not be flagged")
	}
	for _, n := range d.UnsafeNames {
		if strings.ContainsRune(n, 0) {
			t.Errorf("unsafe name %q still contains a NUL", n)
		}
	}
}

func TestParseFindsZipSlipBeyondTheListedEntries(t *testing.T) {
	entries := make([]testfixtures.ZipEntry, 0, 400)
	for i := range 399 {
		entries = append(entries, store(fmt.Sprintf("ok/%03d.txt", i), "x"))
	}
	entries = append(entries, store("../../late-evil", "x"))
	res := parseLim(t, testfixtures.Zip(entries...), report.TypeZip, limits.Limits{MaxList: 64})
	d := res.Details
	if len(d.Entries) != 64 || !d.EntriesTruncated || d.EntryCount != 400 {
		t.Fatalf("entries=%d/%d truncated=%v", len(d.Entries), d.EntryCount, d.EntriesTruncated)
	}
	if !slices.Equal(d.UnsafeNames, []string{"../../late-evil"}) {
		t.Fatalf("a hostile name after the listing cap must still be found: %v", d.UnsafeNames)
	}
	if !hasNote(res, "limited to the first 64 of 400") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestParseCapsListsButKeepsTrueCounts(t *testing.T) {
	entries := make([]testfixtures.ZipEntry, 0, 300)
	for i := range 150 {
		entries = append(entries, store(fmt.Sprintf("../x%03d", i), "x"), store(fmt.Sprintf("n%03d.zip", i), "PK\x03\x04"))
	}
	d := parseLim(t, testfixtures.Zip(entries...), report.TypeZip, limits.Limits{MaxList: 64}).Details
	if len(d.UnsafeNames) != 64 || d.UnsafeCount != 150 {
		t.Errorf("unsafe %d listed of %d", len(d.UnsafeNames), d.UnsafeCount)
	}
	if len(d.Nested) != 64 || d.NestedCount != 150 {
		t.Errorf("nested %d listed of %d", len(d.Nested), d.NestedCount)
	}
}

func TestParseCompressionStatistics(t *testing.T) {
	d := parse(t, testfixtures.ZipHighRatio(8<<20), report.TypeZip).Details
	if d.MaxRatioEntry != "zeros.bin" || d.MaxRatio < 1000 {
		t.Fatalf("maxRatio=%v entry=%q", d.MaxRatio, d.MaxRatioEntry)
	}
	if d.Ratio < 1000 || d.TotalUncompressed != 8<<20 || d.TotalCompressed == 0 || d.TotalCompressed > 100<<10 {
		t.Fatalf("ratio=%v uncompressed=%d compressed=%d", d.Ratio, d.TotalUncompressed, d.TotalCompressed)
	}
	plain := parse(t, testfixtures.Zip(store("a", "abcdef")), report.TypeZip).Details
	if plain.Ratio != 1 || plain.MaxRatio != 1 {
		t.Errorf("stored data has ratio 1, got %v / %v", plain.Ratio, plain.MaxRatio)
	}
	empty := parse(t, testfixtures.Zip(), report.TypeZip).Details
	if empty.Ratio != 0 || empty.EntryCount != 0 || empty.Entries == nil {
		t.Errorf("empty archive: %+v", empty)
	}
}

// allocated returns how many bytes fn allocated, measured from the runtime's
// cumulative counter, which does not depend on how busy the machine is.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestParseDoesNotInflateBombs(t *testing.T) {
	t.Run("members that are never read", func(t *testing.T) {
		b := testfixtures.ZipHighRatio(32 << 20) // 32 MiB of zeros in about 32 KiB
		var res *archive.Result
		if alloc := allocated(func() { res = parse(t, b, report.TypeJar) }); alloc > 4<<20 {
			t.Fatalf("analysing the archive allocated %d bytes", alloc)
		}
		if res.Details.TotalUncompressed != 32<<20 {
			t.Fatalf("declared size = %d", res.Details.TotalUncompressed)
		}
	})
	t.Run("a manifest that is a bomb is read under the limit", func(t *testing.T) {
		// The read limit is 8 MiB. Inflating a 64 MiB entry would cost at least 64 MiB plus the
		// buffer growth, while reading up to the limit costs the same whatever size the entry
		// declares. The absolute cost depends on the build (the race detector doubles it), so the
		// test compares two sizes instead of trusting one figure.
		cost := func(size int) uint64 {
			b := testfixtures.Zip(testfixtures.ZipEntry{Name: "AndroidManifest.xml", Data: make([]byte, size)})
			var res *archive.Result
			alloc := allocated(func() { res = parse(t, b, report.TypeAPK) })
			if !hasNote(res, "larger than the read limit") {
				t.Fatalf("a %d MiB manifest: notes = %v", size>>20, res.Notes)
			}
			return alloc
		}
		small, large := cost(16<<20), cost(64<<20)
		if large > small+small/10+(1<<20) {
			t.Fatalf("a 64 MiB manifest allocated %d bytes but a 16 MiB one only %d: the read is not bounded by the limit", large, small)
		}
		if large > 100<<20 {
			t.Fatalf("analysing the archive allocated %d bytes", large)
		}
	})
}

func TestParseStructuralAnomalies(t *testing.T) {
	overlap := parse(t, testfixtures.ZipOverlapping(), report.TypeZip).Details
	if overlap.OverlappingEntries < 1 {
		t.Errorf("overlapping = %d", overlap.OverlappingEntries)
	}
	dup := parse(t, testfixtures.ZipDuplicateNames(), report.TypeZip).Details
	if dup.DuplicateNames != 1 || dup.OverlappingEntries != 0 {
		t.Errorf("duplicates = %d overlapping = %d", dup.DuplicateNames, dup.OverlappingEntries)
	}
	prefixed := parse(t, testfixtures.ZipWithPrefix(bytes.Repeat([]byte("MZ"), 100), store("a", "1")), report.TypeZip).Details
	if prefixed.PrefixBytes != 200 {
		t.Errorf("prefix = %d", prefixed.PrefixBytes)
	}
}

func TestParseEncryptedEntries(t *testing.T) {
	b := testfixtures.Zip(store("secret.bin", "data"), store("open.txt", "x"))
	first := bytes.Index(b, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint16(b[first+8:], binary.LittleEndian.Uint16(b[first+8:])|1)
	d := parse(t, b, report.TypeZip).Details
	if d.EncryptedEntries != 1 || !d.Entries[0].Encrypted || d.Entries[1].Encrypted {
		t.Fatalf("encrypted = %d entries = %+v", d.EncryptedEntries, d.Entries)
	}
}

func TestParseNestedByExtensionAndMagic(t *testing.T) {
	exe := "MZ\x90\x00\x03\x00\x00\x00 fake pe"
	b := testfixtures.Zip(
		store("setup.exe", "anything"),
		store("tools/helper.dll", "anything"),
		store("data/payload.bin", exe),         // disguised executable, no giveaway extension
		store("images/logo.png", exe),          // benign extension: not examined, documented
		store("misc/blob", "PK\x03\x04 inner"), // no extension
		testfixtures.ZipEntry{Name: "misc/packed.dat", Data: []byte("\x7fELF\x02\x01 more bytes")},
		store("notes/readme.txt", "just text"),
		store("lib/libfoo.so", "\x7fELF"), // native libraries are normal contents
		store("empty.dat", ""),
	)
	d := parse(t, b, report.TypeZip).Details
	want := []string{"setup.exe", "tools/helper.dll", "data/payload.bin", "misc/blob", "misc/packed.dat"}
	got := slices.Clone(d.Nested)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || d.NestedCount != len(want) {
		t.Fatalf("nested = %v (%d)\nwant     %v", got, d.NestedCount, want)
	}
}

func TestParseOfficeFacts(t *testing.T) {
	macro := testfixtures.Zip(
		store("[Content_Types].xml", "<Types/>"),
		store("word/document.xml", "<w:document/>"),
		store("word/vbaProject.bin", "\xd0\xcf\x11\xe0"),
		store("word/embeddings/oleObject1.bin", "x"),
		store("word/embeddings/oleObject2.bin", "x"),
		store("word/activeX/activeX1.xml", "<ax/>"),
	)
	o := parse(t, macro, report.TypeDocx).Details.Office
	if o == nil || !o.Macros || o.EmbeddedObjects != 2 || !o.ActiveX {
		t.Fatalf("office = %+v", o)
	}
	clean := testfixtures.Zip(store("[Content_Types].xml", "<Types/>"), store("xl/workbook.xml", "<wb/>"))
	if o := parse(t, clean, report.TypeXlsx).Details.Office; o == nil || o.Macros || o.EmbeddedObjects != 0 || o.ActiveX {
		t.Fatalf("clean workbook = %+v", o)
	}
	if parse(t, macro, report.TypeZip).Details.Office != nil {
		t.Error("office facts are only produced for OOXML kinds")
	}
}

func TestParseDamagedArchives(t *testing.T) {
	entries := []testfixtures.ZipEntry{store("a.txt", "alpha"), store("b.txt", "beta")}
	res := parse(t, testfixtures.ZipTruncatedEOCD(entries...), report.TypeZip)
	if !res.Details.Recovered || res.Details.EntryCount != 2 {
		t.Fatalf("recovered=%v count=%d", res.Details.Recovered, res.Details.EntryCount)
	}
	if !hasNote(res, "damaged or incomplete") || len(res.Notes) < 2 {
		t.Errorf("notes = %v", res.Notes)
	}
	intact := parse(t, testfixtures.Zip(entries...), report.TypeZip)
	if intact.Details.Recovered || len(intact.Notes) != 0 {
		t.Errorf("intact archive: recovered=%v notes=%v", intact.Details.Recovered, intact.Notes)
	}
}

func TestParseRejectsNonArchives(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty": {}, "text": []byte(strings.Repeat("hello world\n", 50)), "zeros": make([]byte, 1024), "tiny": []byte("PK"),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := archive.Parse(context.Background(), bytes.NewReader(in), int64(len(in)), limits.Limits{}, report.TypeZip)
			if res != nil || !errors.Is(err, zipscan.ErrNotZip) {
				t.Fatalf("got %+v, %v; want a nil result and ErrNotZip", res, err)
			}
			if !strings.Contains(err.Error(), "archive:") {
				t.Errorf("error lacks context: %v", err)
			}
		})
	}
}

func TestParseHonoursCancellation(t *testing.T) {
	b := testfixtures.ZipMany(5000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := archive.Parse(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{}, report.TypeZip)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if res == nil || res.Details.EntryCount >= 5000 {
		t.Fatalf("a cancelled parse must return a partial result, got %+v", res)
	}
}

func TestParseWithExplicitLimitsAndDefaults(t *testing.T) {
	b := testfixtures.ZipMany(100)
	zero := parse(t, b, report.TypeZip).Details
	tight := parseLim(t, b, report.TypeZip, limits.ForSize(int64(len(b)))).Details
	if len(zero.Entries) != 100 || zero.EntriesTruncated {
		t.Errorf("default limits: %d entries truncated=%v", len(zero.Entries), zero.EntriesTruncated)
	}
	if tight.EntryCount != 100 {
		t.Errorf("true count must survive any limit: %d", tight.EntryCount)
	}
}

func TestDetailsJSONShape(t *testing.T) {
	for kind, b := range map[string][]byte{
		report.TypeJar:  testfixtures.JAR(testfixtures.JAROptions{}),
		report.TypeAPK:  testfixtures.APK(testfixtures.APKOptions{Permissions: []string{"android.permission.INTERNET"}}),
		report.TypeDocx: testfixtures.Zip(store("word/document.xml", "<d/>")),
		report.TypeZip:  testfixtures.Zip(),
	} {
		t.Run(kind, func(t *testing.T) {
			raw, err := json.Marshal(parse(t, b, kind).Details)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("null")) {
				t.Fatalf("details contain null: %s", raw)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{
				"kind", "entryCount", "entries", "entriesTruncated", "totalCompressed", "totalUncompressed", "ratio", "maxRatio",
				"maxRatioEntry", "unsafeNames", "unsafeCount", "nested", "nestedCount", "encryptedEntries", "overlappingEntries",
				"duplicateNames", "comment", "prefixBytes", "recovered", "signed", "manifest", "classCount",
			} {
				if _, ok := m[key]; !ok {
					t.Errorf("details lack the key %q", key)
				}
			}
			_, hasAndroid := m["android"]
			_, hasOffice := m["office"]
			if hasAndroid != (kind == report.TypeAPK) || hasOffice != (kind == report.TypeDocx) {
				t.Errorf("android present = %v office present = %v for %s", hasAndroid, hasOffice, kind)
			}
		})
	}
}

// sweepInputs are the archives used by the robustness sweeps, with their kinds.
func sweepInputs() map[string]struct {
	data []byte
	kind string
} {
	type input = struct {
		data []byte
		kind string
	}
	return map[string]input{
		"jar":         {testfixtures.JAR(testfixtures.JAROptions{MainClass: "a.B", Signed: true}), report.TypeJar},
		"apk":         {testfixtures.APK(testfixtures.APKOptions{Permissions: []string{"android.permission.INTERNET"}, ABIs: []string{"x86"}, SigningBlock: true}), report.TypeAPK},
		"aab":         {testfixtures.AAB(testfixtures.AABOptions{Permissions: []string{"android.permission.CAMERA"}, ABIs: []string{"arm64-v8a"}}), report.TypeAAB},
		"slip":        {testfixtures.ZipSlip(), report.TypeZip},
		"overlapping": {testfixtures.ZipOverlapping(), report.TypeZip},
		"docx":        {testfixtures.Zip(store("[Content_Types].xml", "<T/>"), store("word/vbaProject.bin", "x")), report.TypeDocx},
		"truncated":   {testfixtures.ZipTruncatedEOCD(store("a", "1"), store("b", "2")), report.TypeZip},
	}
}

func TestParseNeverPanics(t *testing.T) {
	for name, in := range sweepInputs() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run := func(b []byte) {
				start := time.Now()
				res, err := archive.Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{}, in.kind)
				if err == nil && res == nil {
					t.Fatal("nil result without an error")
				}
				if time.Since(start) > time.Second {
					t.Fatalf("a %d byte input took %v", len(b), time.Since(start))
				}
			}
			for n := 0; n <= len(in.data); n++ {
				if n > 4096 && n%97 != 0 {
					continue
				}
				run(in.data[:n])
			}
			for i := 0; i < min(512, len(in.data)); i++ {
				for _, v := range []byte{0x00, 0xFF, 0x80} {
					mutated := bytes.Clone(in.data)
					mutated[i] = v
					run(mutated)
				}
			}
		})
	}
}
