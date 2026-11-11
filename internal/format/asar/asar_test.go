package asar_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/format/asar"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

func parse(t *testing.T, b []byte) *asar.Result {
	t.Helper()
	return parseLim(t, b, limits.Limits{})
}

func parseLim(t *testing.T, b []byte, lim limits.Limits) *asar.Result {
	t.Helper()
	res, err := asar.Parse(context.Background(), bytes.NewReader(b), int64(len(b)), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func hasNote(res *asar.Result, substr string) bool {
	for _, n := range res.Notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

func file(path, data string) testfixtures.AsarFile {
	return testfixtures.AsarFile{Path: path, Data: []byte(data)}
}

func TestParseElectronApp(t *testing.T) {
	b := testfixtures.AsarElectronApp()
	res := parse(t, b)
	d := res.Details

	wantFiles := []string{"bin/helper", "index.html", "main.js", "native/addon.node", "node_modules/left-pad/index.js", "package.json"}
	if !slices.Equal(d.Files, wantFiles) || d.FileCount != 6 || d.FilesTruncated {
		t.Errorf("files = %v (count %d, truncated %v)", d.Files, d.FileCount, d.FilesTruncated)
	}
	if d.DirectoryCount != 4 || d.UnpackedCount != 1 {
		t.Errorf("directories = %d unpacked = %d", d.DirectoryCount, d.UnpackedCount)
	}
	if d.DataOffset != 8+d.HeaderSize || d.HeaderSize == 0 || d.TotalSize == 0 {
		t.Errorf("header=%d dataOffset=%d total=%d", d.HeaderSize, d.DataOffset, d.TotalSize)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a valid archive must not produce notes: %v", res.Notes)
	}

	p := d.Package
	if p == nil {
		t.Fatal("package.json not found")
	}
	if p.Name != "demo-app" || p.Version != "1.2.3" || p.Main != "main.js" || p.Electron != "^28.1.0" || p.Description != "Fixture Electron application" {
		t.Errorf("package = %+v", p)
	}
	if !slices.Equal(p.Dependencies, []string{"electron-log", "left-pad"}) {
		t.Errorf("dependencies = %v", p.Dependencies)
	}

	wantHints := []asar.Hint{
		{ID: "node-integration", Evidence: "main.js: nodeIntegration: true"},
		{ID: "context-isolation-disabled", Evidence: "main.js: contextIsolation: false"},
		{ID: "web-security-disabled", Evidence: "main.js: webSecurity: false"},
		{ID: "remote-module-enabled", Evidence: "main.js: enableRemoteModule: true"},
		{ID: "insecure-content", Evidence: "main.js: allowRunningInsecureContent: true"},
		{ID: "no-sandbox", Evidence: "main.js: sandbox: false"},
		{ID: "child-process", Evidence: "main.js: require('child_process')"},
	}
	if !slices.Equal(d.Hints, wantHints) {
		t.Errorf("hints:\n got %+v\nwant %+v", d.Hints, wantHints)
	}
	for _, h := range d.Hints {
		if strings.Contains(h.Evidence, "node_modules") {
			t.Errorf("third-party code must not produce hints: %+v", h)
		}
	}
}

func TestParseStatesTheHintLimitation(t *testing.T) {
	res := parse(t, testfixtures.AsarElectronApp())
	if len(res.Limitations) != 1 || !strings.Contains(res.Limitations[0], "textual matches") || !strings.Contains(res.Limitations[0], "50 application scripts") {
		t.Fatalf("limitations = %q", res.Limitations)
	}
	if hasNote(res, "textual matches") {
		t.Fatalf("a limitation is not a warning: %v", res.Notes)
	}
}

func TestParseHintsInMinifiedAndPlainCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		want []asar.Hint
	}{
		{"minified booleans", `new BrowserWindow({webPreferences:{nodeIntegration:!0,contextIsolation:!1,webSecurity:!1}})`, []asar.Hint{
			{ID: "node-integration", Evidence: "main.js: nodeIntegration:!0"},
			{ID: "context-isolation-disabled", Evidence: "main.js: contextIsolation:!1"},
			{ID: "web-security-disabled", Evidence: "main.js: webSecurity:!1"},
		}},
		{"safe settings produce nothing", `webPreferences: { nodeIntegration: false, contextIsolation: true, webSecurity: true, sandbox: true }`, []asar.Hint{}},
		{"flexible whitespace", "nodeIntegration   :\n\ttrue", []asar.Hint{{ID: "node-integration", Evidence: "main.js: nodeIntegration   :\\x0a\\x09true"}}},
		{"no-sandbox switch", `app.commandLine.appendSwitch('--no-sandbox')`, []asar.Hint{{ID: "no-sandbox", Evidence: "main.js: --no-sandbox"}}},
		{"esm import of child_process", `import { exec } from "node:child_process"`, []asar.Hint{{ID: "child-process", Evidence: `main.js: from "node:child_process"`}}},
		{"word boundary: trueish is not true", `nodeIntegration: trueish`, []asar.Hint{}},
		{"flags are only matched as settings", `// we never set nodeIntegration to true`, []asar.Hint{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, testfixtures.Asar(file("main.js", tc.code)))
			if !slices.Equal(res.Details.Hints, tc.want) {
				t.Fatalf("hints:\n got %+v\nwant %+v", res.Details.Hints, tc.want)
			}
		})
	}
}

func TestParseHintsNeverEchoSurroundingCode(t *testing.T) {
	// The token is written in two pieces so that secret scanners do not mistake this fake for a leaked one.
	code := `const apiKey = "AKIAIOSFODNN7EXAMPLE"; const token = "ghp_` + `abcdefghijklmnopqrstuvwxyz0123456789";
new BrowserWindow({ webPreferences: { nodeIntegration: true } }); // password=hunter2`
	res := parse(t, testfixtures.Asar(file("main.js", code)))
	raw, err := json.Marshal(res.Details)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghij", "hunter2"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("details leak %q: %s", secret, raw)
		}
	}
	if len(res.Details.Hints) != 1 {
		t.Fatalf("hints = %+v", res.Details.Hints)
	}
}

func TestParseOnlyScansApplicationScripts(t *testing.T) {
	flag := "nodeIntegration: true"
	b := testfixtures.Asar(
		file("node_modules/pkg/index.js", flag),
		file("app/node_modules/deep/lib.js", flag),
		file("notes.txt", flag),
		file("src/main.mjs", flag),
		file("src/preload.cjs", "contextIsolation: false"),
		file("src/ENTRY.JS", "webSecurity: false"),
	)
	var got []string
	for _, h := range parse(t, b).Details.Hints {
		got = append(got, h.Evidence)
	}
	slices.Sort(got)
	want := []string{"src/ENTRY.JS: webSecurity: false", "src/main.mjs: nodeIntegration: true", "src/preload.cjs: contextIsolation: false"}
	if !slices.Equal(got, want) {
		t.Fatalf("evidence = %q\nwant       %q", got, want)
	}
}

func TestParseScriptScanLimits(t *testing.T) {
	t.Run("a flag beyond the scan window is not seen, and the note says so", func(t *testing.T) {
		big := strings.Repeat("// padding line\n", 40_000) + "nodeIntegration: true"
		res := parse(t, testfixtures.Asar(file("main.js", big)))
		if len(res.Details.Hints) != 0 || !hasNote(res, "searched only in their first 512 KiB") {
			t.Fatalf("hints = %+v notes = %v", res.Details.Hints, res.Notes)
		}
	})
	t.Run("only the first 50 scripts are scanned", func(t *testing.T) {
		files := make([]testfixtures.AsarFile, 0, 60)
		for i := range 60 {
			code := "// nothing"
			if i == 55 {
				code = "nodeIntegration: true"
			}
			files = append(files, file(fmt.Sprintf("s%02d.js", i), code))
		}
		if hints := parse(t, testfixtures.Asar(files...)).Details.Hints; len(hints) != 0 {
			t.Fatalf("hints = %+v", hints)
		}
	})
}

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		name     string
		files    []testfixtures.AsarFile
		want     *asar.Package
		wantNote string
	}{
		{"none", []testfixtures.AsarFile{file("main.js", "x")}, nil, ""},
		{"nested in app/", []testfixtures.AsarFile{file("app/package.json", `{"name":"inner","version":"2.0.0"}`)}, &asar.Package{Name: "inner", Version: "2.0.0", Dependencies: []string{}}, ""},
		{"nested in resources/app/", []testfixtures.AsarFile{file("resources/app/package.json", `{"name":"deep"}`)}, &asar.Package{Name: "deep", Dependencies: []string{}}, ""},
		{"root wins over nested", []testfixtures.AsarFile{file("app/package.json", `{"name":"inner"}`), file("package.json", `{"name":"outer"}`)}, &asar.Package{Name: "outer", Dependencies: []string{}}, ""},
		{"electron in dependencies", []testfixtures.AsarFile{file("package.json", `{"dependencies":{"electron":"30.0.0","a":"1"}}`)}, &asar.Package{Electron: "30.0.0", Dependencies: []string{"a", "electron"}}, ""},
		{"wrong field types are skipped", []testfixtures.AsarFile{file("package.json", `{"name":123,"version":"1.0.0","main":["x"]}`)}, &asar.Package{Version: "1.0.0", Dependencies: []string{}}, ""},
		{"control characters are escaped", []testfixtures.AsarFile{file("package.json", `{"name":"a\u001b[31mb"}`)}, &asar.Package{Name: `a\x1b[31mb`, Dependencies: []string{}}, ""},
		{"invalid json", []testfixtures.AsarFile{file("package.json", `{"name": `)}, nil, "is not valid JSON"},
		{"unpacked package.json cannot be read", []testfixtures.AsarFile{{Path: "package.json", Data: []byte(`{"name":"x"}`), Unpacked: true}}, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, testfixtures.Asar(tc.files...))
			got := res.Details.Package
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("package = %+v, want none", got)
			case tc.want != nil && got == nil:
				t.Fatalf("package missing, want %+v", tc.want)
			case tc.want != nil && (got.Name != tc.want.Name || got.Version != tc.want.Version || got.Main != tc.want.Main ||
				got.Electron != tc.want.Electron || !slices.Equal(got.Dependencies, tc.want.Dependencies)):
				t.Fatalf("package = %+v, want %+v", got, tc.want)
			}
			if tc.wantNote != "" && !hasNote(res, tc.wantNote) {
				t.Fatalf("notes = %v, want one containing %q", res.Notes, tc.wantNote)
			}
		})
	}
}

func TestParseListCapKeepsTrueCounts(t *testing.T) {
	files := make([]testfixtures.AsarFile, 300)
	for i := range files {
		files[i] = file(fmt.Sprintf("d%d/f%03d.txt", i%5, i), "x")
	}
	d := parseLim(t, testfixtures.Asar(files...), limits.Limits{MaxList: 64}).Details
	if len(d.Files) != 64 || !d.FilesTruncated || d.FileCount != 300 || d.DirectoryCount != 5 || d.TotalSize != 300 {
		t.Fatalf("listed=%d truncated=%v count=%d dirs=%d total=%d", len(d.Files), d.FilesTruncated, d.FileCount, d.DirectoryCount, d.TotalSize)
	}
}

func TestParseDamagedArchives(t *testing.T) {
	full := testfixtures.Asar(file("a.txt", strings.Repeat("a", 1000)), file("b.txt", strings.Repeat("b", 1000)))

	t.Run("truncated data", func(t *testing.T) {
		res := parse(t, full[:len(full)-1200])
		if !hasNote(res, "point outside the archive data") || res.Details.FileCount != 2 {
			t.Fatalf("notes = %v count = %d", res.Notes, res.Details.FileCount)
		}
	})
	t.Run("offsets outside the data", func(t *testing.T) {
		b := testfixtures.AsarRaw(`{"files":{"x":{"size":10,"offset":"999999"},"y":{"size":5,"offset":"-1"},"z":{"size":5,"offset":"abc"},"w":{"size":5}}}`, []byte("0123456789"))
		res := parse(t, b)
		if !hasNote(res, "4 file entries point outside") {
			t.Fatalf("notes = %v", res.Notes)
		}
	})
	t.Run("index cut short", func(t *testing.T) {
		b := testfixtures.AsarRaw(`{"files":{"a":{"size":1,"offset":"0"},"b":{"size":`, nil)
		res := parse(t, b)
		if !hasNote(res, "could not be fully parsed") || res.Details.FileCount != 1 {
			t.Fatalf("notes = %v count = %d", res.Notes, res.Details.FileCount)
		}
	})
	t.Run("inconsistent header sizes", func(t *testing.T) {
		b := bytes.Clone(full)
		binary.LittleEndian.PutUint32(b[8:], 7)
		res := parse(t, b)
		if !hasNote(res, "header sizes are inconsistent") || res.Details.FileCount != 2 {
			t.Fatalf("notes = %v count = %d", res.Notes, res.Details.FileCount)
		}
	})
	t.Run("header size too small for the index", func(t *testing.T) {
		b := bytes.Clone(full)
		binary.LittleEndian.PutUint32(b[4:], 8)
		res := parse(t, b)
		if !hasNote(res, "cannot hold the index") || res.Details.FileCount != 2 {
			t.Fatalf("notes = %v count = %d", res.Notes, res.Details.FileCount)
		}
	})
	t.Run("data start beyond the file", func(t *testing.T) {
		b := testfixtures.AsarRaw(`{"files":{}}`, nil)
		binary.LittleEndian.PutUint32(b[4:], 1000)
		res := parse(t, b)
		if !hasNote(res, "truncated") {
			t.Fatalf("notes = %v", res.Notes)
		}
	})
}

func TestParseHostileIndexes(t *testing.T) {
	// Each repetition adds two object levels, so 25 of them stay within the limit of 64.
	deep := strings.Repeat(`{"files":{"d":`, 25) + `{"size":1,"offset":"0"}` + strings.Repeat("}}", 25)
	tests := []struct {
		name     string
		header   string
		wantNote string
		files    int
	}{
		{"nesting beyond the limit", strings.Repeat(`{"files":{"d":`, 100) + `{}` + strings.Repeat("}}", 100), "nests deeper than 64", 0},
		{"arrays beyond the limit", strings.Repeat("[", 200) + strings.Repeat("]", 200), "nests deeper than 64", 0},
		{"deep but allowed", `{"files":{"a":` + deep + `}}`, "", 1},
		{"scalar nodes are ignored", `{"files":{"a":5,"b":"str","c":null,"d":true}}`, "", 0},
		{"array nodes are skipped", `{"files":{"a":[1,[2,3],{"x":1}],"b":{"size":1,"offset":"0"}}}`, "", 1},
		{"files that is not an object", `{"files":{"a":{"files":null},"b":{"size":1,"offset":"0"}}}`, "could not be fully parsed", 0},
		{"odd attribute types", `{"files":{"a":{"size":"big","offset":7,"unpacked":"yes"},"b":{"size":1.5,"offset":"0"}}}`, "2 file entries point outside", 2},
		{"unknown attributes are skipped", `{"files":{"a":{"size":1,"offset":"0","integrity":{"hash":[1,2,{"k":"v"}]},"extra":[[]]}}}`, "", 1},
		{"top-level extras are skipped", `{"meta":{"deep":[1,2,3]},"files":{"a":{"size":1,"offset":"0"}}}`, "", 1},
		{"not a json object", `[1,2,3]`, "could not be fully parsed", 0},
		{"garbage", `\x00\x01 not json at all`, "could not be fully parsed", 0},
		{"huge size number", `{"files":{"a":{"size":99999999999999999999999,"offset":"0"}}}`, "1 file entries point outside", 1},
		{"links", `{"files":{"l":{"link":"target"}}}`, "", 1},
		{"escaped names", `{"files":{"a\u001b[31m":{"size":1,"offset":"0"}}}`, "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parse(t, testfixtures.AsarRaw(tc.header, []byte("0123456789")))
			if res.Details.FileCount != tc.files {
				t.Errorf("files = %d, want %d (notes %v)", res.Details.FileCount, tc.files, res.Notes)
			}
			if tc.wantNote == "" && len(res.Notes) != 0 {
				t.Errorf("unexpected notes: %v", res.Notes)
			}
			if tc.wantNote != "" && !hasNote(res, tc.wantNote) {
				t.Errorf("notes = %v, want one containing %q", res.Notes, tc.wantNote)
			}
			for _, f := range res.Details.Files {
				if strings.ContainsRune(f, 0x1b) {
					t.Errorf("file name %q still contains ESC", f)
				}
			}
		})
	}
}

func TestParseRejectsNonArchives(t *testing.T) {
	valid := testfixtures.Asar(file("a", "1"))
	wrongMagic := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(wrongMagic, 5)
	hugeIndex := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(hugeIndex[12:], 0x7FFFFFFF)
	zeroIndex := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(zeroIndex[12:], 0)

	tests := map[string][]byte{
		"empty": {}, "tiny": []byte("asar"), "text": []byte(strings.Repeat("hello world\n", 50)),
		"wrong size pickle": wrongMagic, "index longer than the file": hugeIndex, "empty index": zeroIndex,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := asar.Parse(context.Background(), bytes.NewReader(in), int64(len(in)), limits.Limits{})
			if res != nil || err == nil || !strings.Contains(err.Error(), "asar:") {
				t.Fatalf("got %+v, %v; want a nil result and an asar error", res, err)
			}
		})
	}
	t.Run("index above the metadata limit", func(t *testing.T) {
		b := testfixtures.Asar(file("a", strings.Repeat("x", 100)))
		res, err := asar.Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{MaxMeta: 10})
		if res != nil || err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("got %+v, %v", res, err)
		}
	})
}

func TestParseHonoursCancellation(t *testing.T) {
	files := make([]testfixtures.AsarFile, 5000)
	for i := range files {
		files[i] = file(fmt.Sprintf("f%05d.js", i), "x")
	}
	b := testfixtures.Asar(files...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := asar.Parse(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{})
	if !errors.Is(err, context.Canceled) || res == nil || res.Details.FileCount >= 5000 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestParseHandlesManyFilesQuickly(t *testing.T) {
	files := make([]testfixtures.AsarFile, 20_000)
	for i := range files {
		files[i] = file(fmt.Sprintf("dir%d/file%05d.bin", i%50, i), "x")
	}
	b := testfixtures.Asar(files...)
	start := time.Now()
	res := parse(t, b)
	if res.Details.FileCount != 20_000 || res.Details.DirectoryCount != 50 {
		t.Fatalf("files=%d dirs=%d", res.Details.FileCount, res.Details.DirectoryCount)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("20000 entries took %v", elapsed)
	}
}

func TestParseHugeNamesStayCheap(t *testing.T) {
	// A 3 MiB directory name with 30000 children: copying the name into every
	// child's path would cost gigabytes, so paths are clipped.
	var sb strings.Builder
	sb.WriteString(`{"files":{"` + strings.Repeat("a", 3<<20) + `":{"files":{`)
	for i := range 30_000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"f%d":{"size":1,"offset":"0"}`, i)
	}
	sb.WriteString(`}}}}`)
	b := testfixtures.AsarRaw(sb.String(), []byte("x"))
	start := time.Now()
	res := parse(t, b)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("parsing took %v", elapsed)
	}
	d := res.Details
	if d.FileCount != 30_000 || d.DirectoryCount != 1 {
		t.Fatalf("files=%d dirs=%d notes=%v", d.FileCount, d.DirectoryCount, res.Notes)
	}
	for _, f := range d.Files {
		if len([]rune(f)) > 513 {
			t.Fatalf("listed path has %d runes", len([]rune(f)))
		}
	}
}

func TestDetailsJSONShape(t *testing.T) {
	for name, b := range map[string][]byte{
		"app":   testfixtures.AsarElectronApp(),
		"empty": testfixtures.Asar(),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(parse(t, b).Details)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"headerSize", "dataOffset", "fileCount", "directoryCount", "files", "filesTruncated", "unpackedCount", "totalSize", "package", "hints"} {
				if _, ok := m[key]; !ok {
					t.Errorf("details lack %q", key)
				}
			}
			for _, key := range []string{"files", "hints"} {
				if m[key] == nil {
					t.Errorf("%q must be an empty list, not null", key)
				}
			}
			if (m["package"] == nil) != (name == "empty") {
				t.Errorf("package = %v for %s", m["package"], name)
			}
		})
	}
}

func sweepInputs() map[string][]byte {
	return map[string][]byte{
		"app":     testfixtures.AsarElectronApp(),
		"plain":   testfixtures.Asar(file("a.txt", "alpha"), file("d/b.js", "nodeIntegration: true")),
		"hostile": testfixtures.AsarRaw(`{"files":{"a":[1,{"x":2}],"b":{"size":1e400,"offset":"0"},"c":{"files":null}}}`, []byte("data")),
		"hostile script": testfixtures.Asar(
			file("m.js", "nodeIntegration: true \x00\x1b[31m\xff\xfe sandbox:!1 \n\r\n\t"+strings.Repeat("x", 5000)),
			file("n.js", "contextIsolation\n  :\n\n false"),
		),
	}
}

func TestParseNeverPanics(t *testing.T) {
	for name, input := range sweepInputs() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run := func(b []byte) {
				start := time.Now()
				res, err := asar.Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{})
				if err == nil && res == nil {
					t.Fatal("nil result without an error")
				}
				if time.Since(start) > time.Second {
					t.Fatalf("a %d byte input took %v", len(b), time.Since(start))
				}
			}
			for n := 0; n <= len(input); n++ {
				if n > 4096 && n%97 != 0 {
					continue
				}
				run(input[:n])
			}
			for i := 0; i < min(512, len(input)); i++ {
				for _, v := range []byte{0x00, 0xFF, 0x80} {
					mutated := bytes.Clone(input)
					mutated[i] = v
					run(mutated)
				}
			}
		})
	}
}
