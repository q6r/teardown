package mcp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// confinementFixture lays out a root next to a sibling whose name starts with
// the root's name, and a secret file outside both.
type confinementFixture struct {
	base, root, evil string
	okData           []byte
	secret           []byte
}

func newConfinementFixture(t *testing.T) confinementFixture {
	t.Helper()
	base := t.TempDir()
	f := confinementFixture{
		base:   base,
		root:   filepath.Join(base, "root"),
		evil:   filepath.Join(base, "root-evil"),
		okData: []byte("INSIDE-FILE-CONTENT"),
		secret: []byte("OUTSIDE-SECRET-CONTENT"),
	}
	writeFile(t, f.root, "ok.bin", f.okData)
	writeFile(t, f.root, "sub/deep.bin", []byte("DEEP"))
	writeFile(t, f.root, "empty.bin", nil)
	if err := os.MkdirAll(filepath.Join(f.root, "sub", "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.evil, "secret.bin", f.secret)
	writeFile(t, base, "outside.bin", f.secret)
	return f
}

// readAll reads an opened file completely.
func readAll(t *testing.T, f *openedFile) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(f, 0, f.size))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openTestRoots(t *testing.T, dirs ...string) *rootSet {
	t.Helper()
	rs, err := openRoots(dirs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	return rs
}

func TestOpenAcceptsPathsInsideTheRoot(t *testing.T) {
	fx := newConfinementFixture(t)
	rs := openTestRoots(t, fx.root)
	tests := []struct {
		name, path string
		want       []byte
		wantName   string
	}{
		{"relative", "ok.bin", fx.okData, "ok.bin"},
		{"dot slash", "./ok.bin", fx.okData, "ok.bin"},
		{"nested", "sub/deep.bin", []byte("DEEP"), "deep.bin"},
		{"harmless dot dot", "sub/../ok.bin", fx.okData, "ok.bin"},
		{"doubled separators", "sub//deep.bin", []byte("DEEP"), "deep.bin"},
		{"absolute", filepath.Join(fx.root, "ok.bin"), fx.okData, "ok.bin"},
		{"absolute nested", filepath.Join(fx.root, "sub", "deep.bin"), []byte("DEEP"), "deep.bin"},
		{"absolute with dot dot that stays inside", filepath.Join(fx.root, "sub", "..", "ok.bin"), fx.okData, "ok.bin"},
		{"empty file", "empty.bin", nil, "empty.bin"},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct {
			name, path string
			want       []byte
			wantName   string
		}{
			{"backslashes", `sub\deep.bin`, []byte("DEEP"), "deep.bin"},
			{"forward slashes in an absolute path", filepath.ToSlash(filepath.Join(fx.root, "ok.bin")), fx.okData, "ok.bin"},
			{"different case", "OK.BIN", fx.okData, "ok.bin"},
			{"absolute in different case", strings.ToUpper(filepath.Join(fx.root, "ok.bin")), fx.okData, "ok.bin"},
		}...)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := rs.open(tc.path)
			if err != nil {
				t.Fatalf("open(%q): %v", tc.path, err)
			}
			defer f.Close()
			if got := readAll(t, f); !bytes.Equal(got, tc.want) {
				t.Errorf("content = %q, want %q", got, tc.want)
			}
			if f.size != int64(len(tc.want)) {
				t.Errorf("size = %d", f.size)
			}
			if tc.wantName != "" && !strings.EqualFold(f.name, tc.wantName) {
				t.Errorf("name = %q, want %q (base name only)", f.name, tc.wantName)
			}
		})
	}
}

func TestOpenRefusesEverythingOutsideTheRoot(t *testing.T) {
	fx := newConfinementFixture(t)
	rs := openTestRoots(t, fx.root)
	tests := []struct {
		name, path, wantMsg string
	}{
		{"parent", "..", "outside the allowed roots"},
		{"parent with slash", "../", "outside the allowed roots"},
		{"file in the parent", "../outside.bin", "outside the allowed roots"},
		{"sibling with the root's name as prefix", "../root-evil/secret.bin", "outside the allowed roots"},
		{"escape after descending", "sub/../../outside.bin", "outside the allowed roots"},
		{"deep escape", "sub/dir/../../../outside.bin", "outside the allowed roots"},
		{"absolute outside", filepath.Join(fx.base, "outside.bin"), "outside the allowed roots"},
		{"absolute sibling prefix", filepath.Join(fx.evil, "secret.bin"), "outside the allowed roots"},
		{"absolute that climbs out", filepath.Join(fx.root, "..", "root-evil", "secret.bin"), "outside the allowed roots"},
		{"absolute parent", fx.base, "outside the allowed roots"},
		{"filesystem root", string(filepath.Separator), map[bool]string{true: "ambiguous", false: "outside the allowed roots"}[runtime.GOOS == "windows"]},
		{"url-encoded dot dot is a literal name", "%2e%2e/outside.bin", "not found"},
		{"url-encoded separator is a literal name", "..%2foutside.bin", "not found"},
		{"empty", "", "path is empty"},
		{"blank", "  \t ", "path is empty"},
		{"nul byte", "ok.bin\x00.txt", "NUL byte"},
		{"newline", "ok.bin\n", "control characters"},
		{"escape character", "ok\x1b[31m.bin", "control characters"},
		{"too long", strings.Repeat("a", maxPathBytes+1), "longer than"},
		{"uri", "file:///etc/passwd", "URI"},
		{"directory", "sub", "a directory"},
		{"root directory itself", ".", "a directory"},
		{"nested directory", "sub/dir", "a directory"},
		{"missing", "nope.bin", "not found"},
		{"missing directory component", "nope/x.bin", "not found"},
		{"invalid utf-8", "ok\xff.bin", "UTF-8"},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct{ name, path, wantMsg string }{
			{"mixed separators climbing out", `sub\..\..\outside.bin`, "outside the allowed roots"},
			{"backslash parent", `..\outside.bin`, "outside the allowed roots"},
			{"drive-relative", "C:ok.bin", "ambiguous"},
			{"rooted without a drive", `\ok.bin`, "ambiguous"},
			{"device namespace", `\\.\NUL`, "device"},
			{"extended-length namespace", `\\?\` + filepath.Join(fx.root, "ok.bin"), "device"},
			{"unc path", `\\localhost\c$\Windows\notepad.exe`, "outside the allowed roots"},
			{"alternate data stream", "ok.bin:stream", "alternate data streams"},
			{"default data stream", "ok.bin::$DATA", "alternate data streams"},
			{"reserved NUL", "NUL", "reserved Windows device name"},
			{"reserved nul with extension", "nul.txt", "reserved Windows device name"},
			{"reserved in a subdirectory", `sub\CON`, "reserved Windows device name"},
			{"reserved with trailing dots", "COM1..", "reserved Windows device name"},
			{"reserved with trailing space", "LPT1 ", "reserved Windows device name"},
			{"reserved absolute", filepath.Join(fx.root, "aux"), "reserved Windows device name"},
			{"reserved console input", "CONIN$", "reserved Windows device name"},
		}...)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := rs.open(tc.path)
			if err == nil {
				got := readAll(t, f)
				f.Close()
				t.Fatalf("open(%q) succeeded and exposed %q", tc.path, got)
			}
			var ue *userError
			if !errors.As(err, &ue) {
				t.Fatalf("error %v must be a user error", err)
			}
			if !strings.Contains(ue.msg, tc.wantMsg) {
				t.Errorf("message %q does not mention %q", ue.msg, tc.wantMsg)
			}
			if bytes.Contains([]byte(ue.msg), fx.secret) {
				t.Errorf("message leaks the secret: %q", ue.msg)
			}
		})
	}
}

func TestOutsideErrorNamesTheRootsButNothingElse(t *testing.T) {
	fx := newConfinementFixture(t)
	rs := openTestRoots(t, fx.root)
	_, err := rs.open("../root-evil/secret.bin")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), rs.names()[0]) {
		t.Errorf("the message should tell the caller which roots are allowed: %q", err)
	}
	if strings.Contains(err.Error(), "secret.bin"+string(filepath.Separator)) || strings.Contains(err.Error(), fx.evil) {
		t.Errorf("the message must not resolve the outside location: %q", err)
	}
}

func TestSymlinksThatLeaveTheRootAreRefused(t *testing.T) {
	fx := newConfinementFixture(t)
	outsideDir := filepath.Join(fx.base, "zz-outside-target")
	writeFile(t, outsideDir, "payload.bin", fx.secret)
	links := map[string]string{
		"link-abs-file": filepath.Join(fx.base, "outside.bin"),
		"link-rel-file": filepath.Join("..", "outside.bin"),
		"link-dir":      outsideDir,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(fx.root, name)); err != nil {
			t.Skipf("this environment cannot create symbolic links (%v)", err)
		}
	}
	if err := os.Symlink("ok.bin", filepath.Join(fx.root, "link-inside")); err != nil {
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}
	rs := openTestRoots(t, fx.root)
	for _, p := range []string{"link-abs-file", "link-rel-file", "link-dir/payload.bin", filepath.Join(fx.root, "link-abs-file")} {
		f, err := rs.open(p)
		if err == nil {
			got := readAll(t, f)
			f.Close()
			t.Fatalf("open(%q) followed a link out of the root and read %q", p, got)
		}
		if !strings.Contains(err.Error(), "leaves the allowed roots") {
			t.Errorf("open(%q): message %q should explain the link problem", p, err)
		}
		if strings.Contains(err.Error(), "zz-outside-target") {
			t.Errorf("open(%q): the message reveals the link target: %q", p, err)
		}
	}
	// A link that stays inside the root is fine.
	f, err := rs.open("link-inside")
	if err != nil {
		t.Fatalf("a link inside the root must work: %v", err)
	}
	defer f.Close()
	if got := readAll(t, f); !bytes.Equal(got, fx.okData) {
		t.Errorf("content = %q", got)
	}
}

func TestFirstRootWinsAndEachRootIsReachable(t *testing.T) {
	base := t.TempDir()
	r1, r2 := filepath.Join(base, "one"), filepath.Join(base, "two")
	writeFile(t, r1, "shared.bin", []byte("from-one"))
	writeFile(t, r2, "shared.bin", []byte("from-two"))
	writeFile(t, r2, "only-two.bin", []byte("only-two"))
	rs := openTestRoots(t, r1, r2)
	tests := []struct{ path, want string }{
		{"shared.bin", "from-one"},
		{"only-two.bin", "only-two"},
		{filepath.Join(r2, "shared.bin"), "from-two"},
		{filepath.Join(r1, "shared.bin"), "from-one"},
	}
	for _, tc := range tests {
		f, err := rs.open(tc.path)
		if err != nil {
			t.Fatalf("open(%q): %v", tc.path, err)
		}
		if got := string(readAll(t, f)); got != tc.want {
			t.Errorf("open(%q) = %q, want %q", tc.path, got, tc.want)
		}
		f.Close()
	}
	if _, err := rs.open(filepath.Join(base, "three.bin")); err == nil || !strings.Contains(err.Error(), "outside the allowed roots") {
		t.Errorf("a path in neither root must be refused: %v", err)
	}
}

func TestOpenRoots(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := writeFile(t, base, "file.txt", []byte("x"))

	t.Run("duplicates collapse", func(t *testing.T) {
		rs := openTestRoots(t, dir, dir, filepath.Join(dir, "."), filepath.Join(dir, "..", "d"))
		if len(rs.entries) != 1 {
			t.Fatalf("roots = %v", rs.names())
		}
	})
	t.Run("relative roots are made absolute", func(t *testing.T) {
		t.Chdir(base)
		rs := openTestRoots(t, "d")
		if !filepath.IsAbs(rs.names()[0]) || filepath.Base(rs.names()[0]) != "d" {
			t.Fatalf("roots = %v", rs.names())
		}
	})
	t.Run("no roots means the working directory", func(t *testing.T) {
		t.Chdir(dir)
		writeFile(t, dir, "here.bin", []byte("here"))
		rs := openTestRoots(t)
		f, err := rs.open("here.bin")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	})
	t.Run("a file is not a root", func(t *testing.T) {
		if _, err := openRoots([]string{file}); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a missing directory is not a root", func(t *testing.T) {
		if _, err := openRoots([]string{filepath.Join(base, "missing")}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("a bad root closes the ones opened before it", func(t *testing.T) {
		if _, err := openRoots([]string{dir, filepath.Join(base, "missing")}); err == nil {
			t.Fatal("expected an error")
		}
		// The directory must be removable afterwards (an open handle would block it on Windows).
		if err := os.Remove(filepath.Join(base, "d")); err != nil && !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("a root handle leaked: %v", err)
		}
	})
	t.Run("a symlinked root works and is matched by both spellings", func(t *testing.T) {
		link := filepath.Join(base, "link-to-d")
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("this environment cannot create symbolic links (%v)", err)
		}
		writeFile(t, dir, "viaLink.bin", []byte("via"))
		rs := openTestRoots(t, link)
		for _, p := range []string{filepath.Join(link, "viaLink.bin"), filepath.Join(dir, "viaLink.bin"), "viaLink.bin"} {
			f, err := rs.open(p)
			if err != nil {
				t.Errorf("open(%q): %v", p, err)
				continue
			}
			f.Close()
		}
	})
}

// aliasResolver stands in for a file system where the directory alias is a
// symbolic link to target (like /var -> /private/var on macOS), for environments
// that may not create links. Everything else is resolved for real.
func aliasResolver(alias, target string) func(string) (string, error) {
	return func(p string) (string, error) {
		if rel, err := filepath.Rel(alias, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			p = filepath.Join(target, rel)
		}
		return filepath.EvalSymlinks(p)
	}
}

// TestOpenAcceptsAnotherSpellingOfTheSamePlace covers a request that names a
// place inside a root through an alias the root was not configured with: the
// macOS temporary directory is /var/... for some callers and /private/var/...
// for others, and Windows knows directories by short names too. The place must
// be accepted under either spelling, and nothing outside the root under any.
func TestOpenAcceptsAnotherSpellingOfTheSamePlace(t *testing.T) {
	fx := newConfinementFixture(t)
	alias := filepath.Join(fx.base, "alias") // not on disk: the resolver makes it a link to base
	rs, err := openRootsResolving([]string{fx.root}, aliasResolver(alias, fx.base))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	via := func(parts ...string) string { return filepath.Join(append([]string{alias}, parts...)...) }

	t.Run("places inside the root are found", func(t *testing.T) {
		tests := []struct {
			name, path string
			want       []byte
		}{
			{"file", via("root", "ok.bin"), fx.okData},
			{"nested", via("root", "sub", "deep.bin"), []byte("DEEP")},
			{"harmless dot dot", via("root", "sub", "..", "ok.bin"), fx.okData},
			{"empty file", via("root", "empty.bin"), nil},
		}
		for _, tc := range tests {
			f, err := rs.open(tc.path)
			if err != nil {
				t.Errorf("%s: open(%q): %v", tc.name, tc.path, err)
				continue
			}
			if got := readAll(t, f); !bytes.Equal(got, tc.want) {
				t.Errorf("%s: content = %q, want %q", tc.name, got, tc.want)
			}
			f.Close()
		}
	})

	t.Run("everything else stays refused", func(t *testing.T) {
		tests := []struct{ name, path, wantMsg string }{
			{"sibling with the root's name as prefix", via("root-evil", "secret.bin"), "outside the allowed roots"},
			{"file next to the root", via("outside.bin"), "outside the allowed roots"},
			{"climbing out of the root", via("root", "..", "outside.bin"), "outside the allowed roots"},
			{"climbing into the sibling", via("root", "..", "root-evil", "secret.bin"), "outside the allowed roots"},
			{"directory that does not exist", via("no-such-directory", "ok.bin"), "outside the allowed roots"},
			{"the parent of the root", via(), "outside the allowed roots"},
			{"the root itself", via("root"), "a directory"},
			{"a directory inside the root", via("root", "sub"), "a directory"},
			{"missing file", via("root", "nope.bin"), "not found"},
		}
		for _, tc := range tests {
			f, err := rs.open(tc.path)
			if err == nil {
				got := readAll(t, f)
				f.Close()
				t.Errorf("%s: open(%q) succeeded and exposed %q", tc.name, tc.path, got)
				continue
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("%s: message %q does not mention %q", tc.name, err, tc.wantMsg)
			}
			if strings.Contains(err.Error(), string(fx.secret)) || strings.Contains(err.Error(), fx.evil) {
				t.Errorf("%s: the message resolves or leaks the outside location: %q", tc.name, err)
			}
		}
	})
}

// TestOpenAcceptsPathsThroughASymlinkedParent is the same with a real link: a
// directory elsewhere that points at the root's parent. A link inside the root
// that leaves it must still be refused when the path arrives through the alias.
func TestOpenAcceptsPathsThroughASymlinkedParent(t *testing.T) {
	fx := newConfinementFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(fx.base, alias); err != nil {
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}
	outsideLink := filepath.Join(fx.root, "link-out")
	if err := os.Symlink(filepath.Join(fx.base, "outside.bin"), outsideLink); err != nil {
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}
	if err := os.Symlink("ok.bin", filepath.Join(fx.root, "link-in")); err != nil {
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}
	rs := openTestRoots(t, fx.root)

	for _, p := range []string{
		filepath.Join(alias, "root", "ok.bin"),
		filepath.Join(alias, "root", "sub", "deep.bin"),
		filepath.Join(alias, "root", "link-in"), // a link that stays inside is fine
	} {
		f, err := rs.open(p)
		if err != nil {
			t.Errorf("open(%q): %v", p, err)
			continue
		}
		f.Close()
	}

	for _, tc := range []struct{ path, wantMsg string }{
		{filepath.Join(alias, "root", "link-out"), "leaves the allowed roots"},
		{filepath.Join(alias, "root-evil", "secret.bin"), "outside the allowed roots"},
		{filepath.Join(alias, "outside.bin"), "outside the allowed roots"},
		{filepath.Join(alias, "root", "..", "outside.bin"), "outside the allowed roots"},
	} {
		f, err := rs.open(tc.path)
		if err == nil {
			got := readAll(t, f)
			f.Close()
			t.Errorf("open(%q) succeeded and exposed %q", tc.path, got)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("open(%q): message %q does not mention %q", tc.path, err, tc.wantMsg)
		}
	}
}

func TestReservedWindowsNames(t *testing.T) {
	reserved := []string{"NUL", "nul", "Nul.txt", "nul ", "nul.", "nul . ", "NUL.tar.gz", "CON", "con", "PRN", "AUX", "aux.c",
		"COM0", "COM1", "com9", "COM1.txt", "LPT1", "lpt9", "LPT5.log", "COM¹", "LPT²", "COM³", "CONIN$", "CONOUT$"}
	fine := []string{"", "ok.bin", "console", "nullable", "NULL", "COM10", "COM", "LPT", "aux1", "com1x", "CONSOLE.txt", "pre.nul", "my-con.txt", ".nul", "COMA"}
	for _, name := range reserved {
		if !isReservedWindowsName(name) {
			t.Errorf("%q must be reserved", name)
		}
	}
	for _, name := range fine {
		if isReservedWindowsName(name) {
			t.Errorf("%q must not be reserved", name)
		}
	}
	if got := reservedWindowsComponent(`a\b\NUL.txt\c`); got != "NUL.txt" {
		t.Errorf("reservedWindowsComponent = %q", got)
	}
	if got := reservedWindowsComponent(`a/b/c`); got != "" {
		t.Errorf("reservedWindowsComponent = %q", got)
	}
}

func TestWindowsPathProblem(t *testing.T) {
	problems := map[string]string{
		`\\.\PhysicalDrive0`: "device",
		`\\.\NUL`:            "device",
		`\\?\C:\x`:           "device",
		`C:file`:             "ambiguous",
		`C:`:                 "ambiguous",
		`\file`:              "ambiguous",
		`file:stream`:        "alternate data streams",
		`C:\x\file::$DATA`:   "alternate data streams",
		`D:\a:b`:             "alternate data streams",
	}
	for p, want := range problems {
		if got := windowsPathProblem(p); !strings.Contains(got, want) {
			t.Errorf("windowsPathProblem(%q) = %q, want mention of %q", p, got, want)
		}
	}
	for _, p := range []string{`C:\dir\file.bin`, `dir\file.bin`, `file.bin`, `..\x`, `\\server\share\file`, `z:\`} {
		if got := windowsPathProblem(p); got != "" {
			t.Errorf("windowsPathProblem(%q) = %q, want accepted", p, got)
		}
	}
}

func TestDescribeMode(t *testing.T) {
	tests := map[os.FileMode]string{
		os.ModeDir:                        "a directory",
		os.ModeSymlink:                    "a symbolic link",
		os.ModeDevice:                     "a device",
		os.ModeNamedPipe:                  "a named pipe",
		os.ModeSocket:                     "a socket",
		os.ModeIrregular:                  "not an ordinary file",
		os.ModeDevice | os.ModeCharDevice: "a device",
	}
	for mode, want := range tests {
		if got := describeMode(mode); !strings.Contains(got, want) {
			t.Errorf("describeMode(%v) = %q, want mention of %q", mode, got, want)
		}
	}
}

// TestRootEscapesThroughTheProtocol runs the hostile paths through the real
// tools: every one must come back as an isError result and none may expose the
// outside file (checked by its digests).
func TestRootEscapesThroughTheProtocol(t *testing.T) {
	fx := newConfinementFixture(t)
	c := startServer(t, Config{Roots: []string{fx.root}}, realAnalyzer())
	secretSHA, secretMD5 := hexSHA256(fx.secret), hexMD5(fx.secret)

	hostile := []string{
		"../outside.bin", "../root-evil/secret.bin", "sub/../../outside.bin",
		filepath.Join(fx.base, "outside.bin"), filepath.Join(fx.evil, "secret.bin"),
		filepath.Join(fx.root, "..", "outside.bin"), "%2e%2e/outside.bin", "....//outside.bin", "..;/outside.bin",
		"sub", ".", "", "ok.bin\x00../outside.bin",
	}
	if runtime.GOOS == "windows" {
		hostile = append(hostile, `..\outside.bin`, `sub\..\..\outside.bin`, `..\root-evil\secret.bin`, "NUL", `\\.\NUL`,
			filepath.ToSlash(filepath.Join(fx.base, "outside.bin")), "...\\outside.bin", "ok.bin::$DATA")
	}
	for i, p := range hostile {
		for _, tool := range []string{"hash_file", "analyze_file", "list_strings", "entropy_profile"} {
			res := c.callTool(1000+i*10, tool, map[string]any{"path": p})
			text := mustErrorText(t, res)
			if strings.Contains(text, secretSHA) || strings.Contains(text, secretMD5) || strings.Contains(text, string(fx.secret)) {
				t.Fatalf("%s(%q) exposed the outside file: %s", tool, p, text)
			}
		}
	}
	// diff_files checks both arguments.
	res := c.callTool(5000, "diff_files", map[string]any{"a": "ok.bin", "b": "../outside.bin"})
	if msg := mustErrorText(t, res); !strings.Contains(msg, `argument "b"`) {
		t.Errorf("message = %q", msg)
	}

	// The inside file still works, with its own digest and never the secret's.
	doc := mustJSON(t, c.callTool(6000, "hash_file", map[string]any{"path": "ok.bin"}))
	if got := doc["hashes"].(map[string]any)["sha256"]; got != hexSHA256(fx.okData) {
		t.Errorf("sha256 = %v", got)
	}
	// And the empty file analyses cleanly.
	doc = mustJSON(t, c.callTool(6001, "hash_file", map[string]any{"path": "empty.bin"}))
	if got := doc["hashes"].(map[string]any)["sha256"]; got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("sha256 of the empty file = %v", got)
	}
}
