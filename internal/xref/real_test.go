package xref

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
)

// TestScanTheTestBinary scans the Go test binary itself, a genuine PE32+ image
// on Windows: a few megabytes of compiler-generated code. It checks what must
// hold on real code (the scan finishes inside its budget, covers every
// executable byte, and every block it makes is valid) and logs what it found.
func TestScanTheTestBinary(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("the Go test binary is an x86-64 PE image only on windows/amd64")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Skipf("cannot open %s: %v", exe, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	ix, err := Scan(context.Background(), f, st.Size(), limits.ForSize(st.Size()), Options{})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if !ix.Complete() {
		t.Errorf("the sweep of a %d byte image was cut short: %v", st.Size(), ix.Notes())
	}
	sites, blocks, noLeadIn := 0, 0, 0
	for _, a := range ix.APIs() {
		sites += a.Sites
		for _, s := range ix.Sites(a.Name) {
			b := ix.Block(s, DefaultBefore, DefaultAfter)
			if err := b.Validate(); err != nil {
				t.Fatalf("%s at %#x: %v", a.Name, s.Addr, err)
			}
			blocks++
			if b.Limitations[len(b.Limitations)-1] == leadInLimit {
				noLeadIn++
			}
		}
	}
	t.Logf("%d bytes scanned in %v: %d of %d imports have %d sites; notes %v", st.Size(), elapsed, len(ix.APIs()), ix.Imports(), sites, ix.Notes())
	t.Logf("%d of %d blocks could not recover the instructions before the call", noLeadIn, blocks)
	if blocks > 0 && noLeadIn*4 > blocks {
		t.Errorf("%d of %d blocks lost their lead-in: on compiler output the search for a clean start point should rarely fail", noLeadIn, blocks)
	}
	if elapsed > 30*time.Second {
		t.Errorf("the scan took %v", elapsed)
	}
}
