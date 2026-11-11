package asar_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/format/asar"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

func walkAll(t *testing.T, b []byte) []asar.File {
	t.Helper()
	var files []asar.File
	err := asar.Walk(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{}, func(f asar.File) bool {
		files = append(files, f)
		return true
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return files
}

func hitsOf(t *testing.T, b []byte) []asar.ScriptHit {
	t.Helper()
	hits, err := asar.Hits(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{})
	if err != nil {
		t.Fatalf("Hits: %v", err)
	}
	return hits
}

func TestWalkLocatesPackedFileContent(t *testing.T) {
	contents := map[string]string{
		"package.json":              `{"name":"x"}`,
		"src/main.js":               "console.log('main');\n",
		"src/deep/er/util.js":       "module.exports = 1;\r\n",
		"assets/empty.txt":          "",
		"node_modules/dep/index.js": "// third party\n",
		"assets/ünicode-中.txt":      "text",
	}
	var archive []testfixtures.AsarFile
	for _, p := range []string{"package.json", "src/main.js", "src/deep/er/util.js", "assets/empty.txt", "node_modules/dep/index.js", "assets/ünicode-中.txt"} {
		archive = append(archive, file(p, contents[p]))
	}
	archive = append(archive, testfixtures.AsarFile{Path: "native/addon.node", Data: []byte("ELF"), Unpacked: true})
	b := testfixtures.Asar(archive...)

	files := walkAll(t, b)
	if len(files) != len(contents) {
		t.Fatalf("visited %d files, want %d (unpacked files are not part of the archive): %+v", len(files), len(contents), files)
	}
	for _, f := range files {
		want, ok := contents[f.Path]
		if !ok {
			t.Errorf("unexpected file %q", f.Path)
			continue
		}
		if f.Size != int64(len(want)) || f.Offset < 0 || f.Offset+f.Size > int64(len(b)) {
			t.Errorf("%s: offset %d size %d do not fit a %d byte file holding %d bytes", f.Path, f.Offset, f.Size, len(b), len(want))
			continue
		}
		if got := string(b[f.Offset : f.Offset+f.Size]); got != want {
			t.Errorf("%s: content at the reported offset is %q, want %q", f.Path, got, want)
		}
	}
}

func TestWalkStopsWhenTheVisitorSaysSo(t *testing.T) {
	b := testfixtures.AsarElectronApp()
	calls := 0
	err := asar.Walk(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{}, func(asar.File) bool {
		calls++
		return false
	})
	if err != nil || calls != 1 {
		t.Fatalf("calls = %d, err = %v: stopping the walk is not a failure", calls, err)
	}
}

func TestWalkSkipsEntriesOutsideTheArchive(t *testing.T) {
	header := `{"files":{"ok":{"size":4,"offset":"0"},"far":{"size":4,"offset":"999"},"neg":{"size":4,"offset":"-1"},"big":{"size":99999,"offset":"0"},"odd":{"size":1,"offset":"x"},"ok2":{"size":2,"offset":"4"}}}`
	b := testfixtures.AsarRaw(header, []byte("abcdefgh"))
	var got []string
	for _, f := range walkAll(t, b) {
		got = append(got, fmt.Sprintf("%s=%s", f.Path, b[f.Offset:f.Offset+f.Size]))
	}
	if want := []string{"ok=abcd", "ok2=ef"}; !slices.Equal(got, want) {
		t.Fatalf("visited %q, want %q", got, want)
	}
}

func TestWalkErrors(t *testing.T) {
	notAsar := []byte(strings.Repeat("hello world\n", 20))
	err := asar.Walk(context.Background(), bytes.NewReader(notAsar), int64(len(notAsar)), limits.Limits{}, func(asar.File) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "asar:") {
		t.Errorf("a text file must be rejected with an asar error, got %v", err)
	}

	many := make([]testfixtures.AsarFile, 3000)
	for i := range many {
		many[i] = file(fmt.Sprintf("f%05d.js", i), "x")
	}
	b := testfixtures.Asar(many...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	visited := 0
	err = asar.Walk(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{}, func(asar.File) bool { visited++; return true })
	if !errors.Is(err, context.Canceled) || visited >= len(many) {
		t.Errorf("a cancelled context must end the walk with its error: visited %d, err %v", visited, err)
	}

	damaged := testfixtures.AsarRaw(`{"files":{"a":{"size":1,"offset":"0"},"b":[}`, []byte("xy"))
	var names []string
	err = asar.Walk(context.Background(), bytes.NewReader(damaged), int64(len(damaged)), limits.Limits{}, func(f asar.File) bool {
		names = append(names, f.Path)
		return true
	})
	if err == nil || !slices.Equal(names, []string{"a"}) {
		t.Errorf("a damaged index reports its damage after visiting what came before: names %v, err %v", names, err)
	}
}

// TestWalkMatchesParse: the files Walk visits are the files Parse counts, bar
// the ones that cannot be read.
func TestWalkMatchesParse(t *testing.T) {
	b := testfixtures.AsarElectronApp()
	res := parse(t, b)
	got := len(walkAll(t, b))
	if want := res.Details.FileCount - res.Details.UnpackedCount; got != want {
		t.Fatalf("Walk visited %d files, Parse counts %d packed files", got, want)
	}
}

func TestHitsLocateTheMatchesParseReports(t *testing.T) {
	b := testfixtures.AsarElectronApp()
	res := parse(t, b)
	hits := hitsOf(t, b)
	if len(hits) != len(res.Details.Hints) || len(hits) == 0 {
		t.Fatalf("%d hits for %d hints", len(hits), len(res.Details.Hints))
	}
	for i, h := range hits {
		hint := res.Details.Hints[i]
		if h.ID != hint.ID {
			t.Errorf("hit %d is %q, Parse lists %q at that place", i, h.ID, hint.ID)
		}
		if h.Script.Path != "main.js" || h.Start >= h.End || int64(h.End) > h.Script.Size {
			t.Errorf("hit %d: script %+v range [%d,%d)", i, h.Script, h.Start, h.End)
			continue
		}
		matched := string(b[h.Script.Offset+int64(h.Start) : h.Script.Offset+int64(h.End)])
		if want := h.Script.Path + ": " + matched; want != hint.Evidence {
			t.Errorf("hit %d covers %q, but Parse reports %q", i, matched, hint.Evidence)
		}
	}
}

func TestHitsInMinifiedAndMultiLineCode(t *testing.T) {
	code := "var a=1;\nnodeIntegration   :\n\ttrue; new B({webPreferences:{contextIsolation:!1,sandbox:!1}})\n"
	b := testfixtures.Asar(file("dist/app.js", code))
	var got []string
	for _, h := range hitsOf(t, b) {
		got = append(got, h.ID+"="+string(b[h.Script.Offset+int64(h.Start):h.Script.Offset+int64(h.End)]))
	}
	want := []string{
		"node-integration=nodeIntegration   :\n\ttrue",
		"context-isolation-disabled=contextIsolation:!1",
		"no-sandbox=sandbox:!1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("hits:\n got %q\nwant %q", got, want)
	}
}

func TestHitsFollowTheSameScopeAsParse(t *testing.T) {
	flag := "nodeIntegration: true"
	big := strings.Repeat("// padding line\n", 40_000) + flag
	b := testfixtures.Asar(
		file("node_modules/pkg/index.js", flag),
		file("notes.txt", flag),
		file("far.js", big),
		file("src/main.mjs", flag),
	)
	hits := hitsOf(t, b)
	if len(hits) != 1 || hits[0].Script.Path != "src/main.mjs" {
		t.Fatalf("hits = %+v: third-party code, non-scripts and matches beyond 512 KiB are outside the scan", hits)
	}
}

func TestHitsRejectNonArchivesAndHonourCancellation(t *testing.T) {
	if hits, err := asar.Hits(context.Background(), strings.NewReader("not an archive at all"), 21, limits.Limits{}); hits != nil || err == nil {
		t.Errorf("got %v, %v", hits, err)
	}
	b := testfixtures.AsarElectronApp()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := asar.Hits(ctx, bytes.NewReader(b), int64(len(b)), limits.Limits{}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestWalkAndHitsNeverPanic(t *testing.T) {
	for name, input := range sweepInputs() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run := func(b []byte) {
				r := bytes.NewReader(b)
				_ = asar.Walk(context.Background(), r, int64(len(b)), limits.Limits{}, func(f asar.File) bool {
					if f.Offset < 0 || f.Size < 0 || f.Offset+f.Size > int64(len(b)) {
						t.Fatalf("a located file lies outside the %d byte archive: %+v", len(b), f)
					}
					return true
				})
				hits, _ := asar.Hits(context.Background(), r, int64(len(b)), limits.Limits{})
				for _, h := range hits {
					if h.Start < 0 || h.End < h.Start || h.Script.Offset+int64(h.End) > int64(len(b)) {
						t.Fatalf("a hit lies outside the %d byte archive: %+v", len(b), h)
					}
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
