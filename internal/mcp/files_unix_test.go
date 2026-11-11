//go:build unix

package mcp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReplacedRootStaysTheDirectoryThatWasOpened plays the attack the other
// spellings must not make easier: after the server started, the root is renamed
// away and a link with its old name leads to a directory holding a secret. The
// root is the directory that was opened, not whatever its name leads to later,
// so the secret must stay unreachable under every spelling.
func TestReplacedRootStaysTheDirectoryThatWasOpened(t *testing.T) {
	fx := newConfinementFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(fx.base, alias); err != nil {
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}
	rs := openTestRoots(t, fx.root)

	if err := os.Rename(fx.root, fx.root+"-moved"); err != nil {
		t.Skipf("this platform does not let an open directory be renamed (%v)", err)
	}
	if err := os.Symlink(fx.evil, fx.root); err != nil { // root -> the sibling that holds secret.bin
		t.Skipf("this environment cannot create symbolic links (%v)", err)
	}

	for _, tc := range []struct{ name, path, wantMsg string }{
		{"relative", "secret.bin", "not found"},
		{"absolute", filepath.Join(fx.root, "secret.bin"), "not found"},
		{"through an alias of the parent", filepath.Join(alias, "root", "secret.bin"), "outside the allowed roots"},
	} {
		f, err := rs.open(tc.path)
		if err == nil {
			got := readAll(t, f)
			f.Close()
			t.Errorf("%s: open(%q) followed the replaced root and read %q", tc.name, tc.path, got)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantMsg) {
			t.Errorf("%s: message %q does not mention %q", tc.name, err, tc.wantMsg)
		}
		if strings.Contains(err.Error(), string(fx.secret)) {
			t.Errorf("%s: the message leaks the secret: %q", tc.name, err)
		}
	}

	// What was opened is still what is served.
	f, err := rs.open("ok.bin")
	if err != nil {
		t.Fatalf("the opened root must keep working: %v", err)
	}
	defer f.Close()
	if got := readAll(t, f); !bytes.Equal(got, fx.okData) {
		t.Errorf("content = %q, want the original %q", got, fx.okData)
	}
}

// TestNamedPipesAreRejectedWithoutBlocking checks that a FIFO inside the root
// is refused by the pre-open Stat; opening a FIFO for reading would block until
// a writer shows up.
func TestNamedPipesAreRejectedWithoutBlocking(t *testing.T) {
	fx := newConfinementFixture(t)
	fifo := filepath.Join(fx.root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	rs := openTestRoots(t, fx.root)
	done := make(chan error, 1)
	go func() {
		f, err := rs.open("pipe")
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "named pipe") {
			t.Fatalf("a FIFO must be refused as a named pipe, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked: it must be rejected before the open")
	}
}
