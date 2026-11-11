//go:build unix

package mcp

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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
