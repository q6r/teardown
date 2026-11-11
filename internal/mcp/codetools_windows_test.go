//go:build windows

package mcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodeToolsRefuseJunctionsThatLeaveTheRoot is the Windows escape that needs
// no privilege, run through the tools that read raw bytes: a directory junction
// inside the root pointing outside it must not give access to the file there.
func TestCodeToolsRefuseJunctionsThatLeaveTheRoot(t *testing.T) {
	fx := newConfinementFixture(t)
	target := filepath.Join(fx.base, "zz-outside-target")
	writeFile(t, target, "payload.bin", fx.secret)
	junction := filepath.Join(fx.root, "junc")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v: %s", err, out)
	}
	t.Cleanup(func() { os.Remove(junction) })

	c := startServer(t, Config{Roots: []string{fx.root}}, realAnalyzer())
	for _, p := range []string{`junc\payload.bin`, "junc/payload.bin", filepath.Join(fx.root, "junc", "payload.bin"), "junc"} {
		for tool, args := range map[string]map[string]any{
			"read_bytes":  {"path": p},
			"disassemble": {"path": p, "arch": "x86-64"},
			"find_calls":  {"path": p, "api": "ExitProcess"},
		} {
			msg := mustErrorText(t, c.callTool(1, tool, args))
			if strings.Contains(msg, string(fx.secret)) || strings.Contains(msg, hexOf(fx.secret)) || strings.Contains(msg, "zz-outside-target") {
				t.Errorf("%s(%q) went through the junction or leaks its target: %s", tool, p, msg)
			}
		}
	}
}
