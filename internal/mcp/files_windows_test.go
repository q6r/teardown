//go:build windows

package mcp

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
