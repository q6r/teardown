//go:build windows

package mcp

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestJunctionsThatLeaveTheRootAreRefused covers the Windows escape that needs
// no privilege: a directory junction inside the root pointing outside it.
func TestJunctionsThatLeaveTheRootAreRefused(t *testing.T) {
	fx := newConfinementFixture(t)
	target := filepath.Join(fx.base, "zz-outside-target")
	writeFile(t, target, "payload.bin", fx.secret)
	junction := filepath.Join(fx.root, "junc")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v: %s", err, out)
	}
	t.Cleanup(func() { os.Remove(junction) })

	rs := openTestRoots(t, fx.root)
	for _, p := range []string{`junc\payload.bin`, "junc/payload.bin", filepath.Join(fx.root, "junc", "payload.bin"), "junc"} {
		f, err := rs.open(p)
		if err == nil {
			got := readAll(t, f)
			f.Close()
			t.Fatalf("open(%q) went through the junction and read %q", p, got)
		}
		if bytes.Contains([]byte(err.Error()), fx.secret) || strings.Contains(err.Error(), "zz-outside-target") {
			t.Errorf("open(%q): message leaks the target: %q", p, err)
		}
	}

	// End to end: the junction cannot be used to read the outside file.
	c := startServer(t, Config{Roots: []string{fx.root}}, realAnalyzer())
	res := c.callTool(1, "hash_file", map[string]any{"path": `junc\payload.bin`})
	msg := mustErrorText(t, res)
	if strings.Contains(msg, hexSHA256(fx.secret)) {
		t.Fatalf("the junction exposed the outside file: %s", msg)
	}
}

// shortPath returns the 8.3 spelling of an existing path. Components without a
// short name stay as they are, and so does the whole path on a volume that has
// none, which the callers detect by comparing with the long spelling.
func shortPath(t *testing.T, long string) string {
	t.Helper()
	in, err := syscall.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 2048)
	n, err := syscall.GetShortPathName(in, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Skipf("cannot ask for the short name of %q: %v", long, err)
	}
	if int(n) > len(buf) {
		t.Skipf("the short name of %q does not fit %d characters", long, len(buf))
	}
	return syscall.UTF16ToString(buf[:n])
}

// TestOpenAcceptsShortNameSpellings is the failure the first CI run showed: the
// runner's temporary directory is spelled with the short name RUNNER~1 while the
// resolved root uses the long name runneradmin. Every directory with a long name
// is also known by an 8.3 name, and a request may use either, or a mix, for the
// root, for what is above it and for what is below it. Short spellings of places
// outside the root must stay refused.
func TestOpenAcceptsShortNameSpellings(t *testing.T) {
	base := t.TempDir()
	const (
		rootName = "a-root-with-a-long-name"
		evilName = "a-root-with-a-long-name-evil" // starts with the root's name: the classic prefix trap
		fileName = "a-file-with-a-long-name.bin"
		deepName = "a-subdirectory-with-a-long-name/a-nested-file-with-a-long-name.bin"
	)
	inside, deep := []byte("INSIDE-FILE-CONTENT"), []byte("DEEP-FILE-CONTENT")
	secret := []byte("OUTSIDE-SECRET-CONTENT")
	writeFile(t, filepath.Join(base, rootName), fileName, inside)
	writeFile(t, filepath.Join(base, rootName), deepName, deep)
	writeFile(t, filepath.Join(base, evilName), "a-secret-in-the-sibling.bin", secret)
	writeFile(t, base, "a-file-outside-the-root.bin", secret)

	longRoot, err := filepath.EvalSymlinks(filepath.Join(base, rootName)) // the long spelling, exactly as the roots are stored
	if err != nil {
		t.Fatal(err)
	}
	longFile := filepath.Join(longRoot, fileName)
	shortFile := shortPath(t, longFile)
	if strings.EqualFold(shortFile, longFile) {
		t.Skip("this volume has no 8.3 short names")
	}
	shortRoot, shortBase := shortPath(t, longRoot), shortPath(t, filepath.Dir(longRoot))
	shortDeep := shortPath(t, filepath.Join(longRoot, filepath.FromSlash(deepName)))
	shortSecret := shortPath(t, filepath.Join(filepath.Dir(longRoot), evilName, "a-secret-in-the-sibling.bin"))
	shortOutside := shortPath(t, filepath.Join(filepath.Dir(longRoot), "a-file-outside-the-root.bin"))
	t.Logf("short spellings: file %s, root %s, base %s", shortFile, shortRoot, shortBase)

	rs := openTestRoots(t, longRoot)
	accepted := []struct {
		name, path string
		want       []byte
	}{
		{"everything short", shortFile, inside},
		{"short root, long file", filepath.Join(shortRoot, fileName), inside},
		{"long root, short file", filepath.Join(longRoot, filepath.Base(shortFile)), inside},
		{"short parent, long names below", filepath.Join(shortBase, rootName, fileName), inside},
		{"upper case short file", strings.ToUpper(shortFile), inside},
		{"lower case short file", strings.ToLower(shortFile), inside},
		{"nested, everything short", shortDeep, deep},
		{"nested, short root only", filepath.Join(shortRoot, filepath.FromSlash(deepName)), deep},
		{"harmless dot dot", filepath.Join(shortRoot, "nowhere", "..", fileName), inside},
	}
	for _, tc := range accepted {
		f, err := rs.open(tc.path)
		if err != nil {
			t.Errorf("%s: open(%q): %v", tc.name, tc.path, err)
			continue
		}
		if got := readAll(t, f); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: open(%q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
		f.Close()
	}

	// A root that is itself given by its short name is the same root.
	short := openTestRoots(t, shortRoot)
	for _, p := range []string{shortFile, filepath.Join(longRoot, fileName), fileName} {
		f, err := short.open(p)
		if err != nil {
			t.Errorf("root given as %q: open(%q): %v", shortRoot, p, err)
			continue
		}
		f.Close()
	}

	refused := []struct{ name, path, wantMsg string }{
		{"short spelling of the sibling", shortSecret, "outside the allowed roots"},
		{"short spelling of a file next to the root", shortOutside, "outside the allowed roots"},
		{"short parent, climbing out", filepath.Join(shortRoot, "..", "a-file-outside-the-root.bin"), "outside the allowed roots"},
		{"short parent, climbing into the sibling", filepath.Join(shortRoot, "..", evilName, "a-secret-in-the-sibling.bin"), "outside the allowed roots"},
		{"short parent, long sibling", filepath.Join(shortBase, evilName, "a-secret-in-the-sibling.bin"), "outside the allowed roots"},
		{"short parent of the root", shortBase, "outside the allowed roots"},
		{"missing file under the short root", filepath.Join(shortRoot, "missing-file-with-a-long-name.bin"), "not found"},
	}
	for _, tc := range refused {
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
		if strings.Contains(err.Error(), string(secret)) {
			t.Errorf("%s: message leaks the secret: %q", tc.name, err)
		}
	}
}

// TestOpenNeverResolvesPathsOnOtherVolumes guards a property the short-name
// support must not break: a path outside every root is refused without being
// looked at. Resolving \\host\share\... would make this machine connect to a
// host the caller chose (and offer it the user's credentials), and device names
// such as CON or COM1 must never reach the file system.
func TestOpenNeverResolvesPathsOnOtherVolumes(t *testing.T) {
	fx := newConfinementFixture(t)
	var asked []string
	rs, err := openRootsResolving([]string{fx.root}, func(p string) (string, error) {
		asked = append(asked, p)
		return filepath.EvalSymlinks(p)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	asked = nil // the root itself was resolved above

	volume := filepath.VolumeName(fx.root)
	otherDrive := `Z:`
	if strings.EqualFold(volume, otherDrive) {
		otherDrive = `Y:`
	}
	for _, p := range []string{
		`\\attacker.invalid\share\dir\file.bin`,
		`\\attacker.invalid\c$\Windows\notepad.exe`,
		`\\localhost\c$\Windows\notepad.exe`,
		otherDrive + `\dir\file.bin`,
		filepath.Join(volume+`\`, "con", "file.bin"),
		filepath.Join(volume+`\`, "somewhere", "NUL.txt", "file.bin"),
		filepath.Join(volume+`\`, "somewhere", "COM1", "file.bin"),
	} {
		f, err := rs.open(p)
		if err == nil {
			f.Close()
			t.Errorf("open(%q) succeeded", p)
			continue
		}
		if !strings.Contains(err.Error(), "outside the allowed roots") {
			t.Errorf("open(%q): message %q should say the path is outside the roots", p, err)
		}
	}
	if len(asked) != 0 {
		t.Errorf("the resolver was asked about %q: paths that cannot be inside a root must not touch the file system", asked)
	}

	// On the root's own volume resolution does happen, so the guard above is not
	// just a resolver that never gets called.
	if f, err := rs.open(filepath.Join(filepath.Dir(fx.base), "no-such-directory", "file.bin")); err == nil {
		f.Close()
		t.Error("a missing directory outside the root was opened")
	}
	if len(asked) == 0 {
		t.Error("the resolver was not used for a path on the root's volume")
	}
}
