package pe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// dirOffset returns the file offset of the data directory entry idx in a 64-bit fixture.
func dirOffset(idx int) int { return testfixtures.PEDataDirectoryOffset(64, idx) }

// dirRVA returns the RVA stored in data directory idx of a 64-bit fixture.
func dirRVA(b []byte, idx int) uint32 { return binary.LittleEndian.Uint32(b[dirOffset(idx):]) }

// fileOffset maps an RVA of a 64-bit fixture to a file offset through its section table.
func fileOffset(b []byte, rva uint32) int {
	n := int(binary.LittleEndian.Uint16(b[testfixtures.PEOffset+6:]))
	for i := range n {
		h := testfixtures.PESectionHeaderOffset(64, i)
		vsize, va, raw := binary.LittleEndian.Uint32(b[h+8:]), binary.LittleEndian.Uint32(b[h+12:]), binary.LittleEndian.Uint32(b[h+20:])
		if rva >= va && rva-va < max(vsize, 1) {
			return int(raw + rva - va)
		}
	}
	panic("fileOffset: RVA is not inside any section")
}

func clone(b []byte) []byte { return slices.Clone(b) }

func TestParseRejectsUnusableInput(t *testing.T) {
	good := testfixtures.PE(testfixtures.PEOptions{})
	notMZ := clone(good)
	notMZ[0], notMZ[1] = 'E', 'L'
	farLfanew := clone(good)
	put32(farLfanew, 0x3c, 0xffffff)
	tinyLfanew := clone(good)
	put32(tinyLfanew, 0x3c, 2)
	noSig := clone(good)
	noSig[testfixtures.PEOffset] = 'X'
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "smaller than a DOS header"},
		{"shorter than a DOS header", good[:63], "smaller than a DOS header"},
		{"not MZ", notMZ, "missing the MZ signature"},
		{"e_lfanew far outside the file", farLfanew, "e_lfanew"},
		{"e_lfanew inside the DOS header", tinyLfanew, "e_lfanew"},
		{"no PE signature", noSig, `no "PE\0\0" signature`},
		{"COFF header cut off", good[:testfixtures.PEOffset+10], "e_lfanew"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Parse(context.Background(), bytes.NewReader(tc.data), int64(len(tc.data)), limits.Limits{})
			if err == nil || res != nil {
				t.Fatalf("got (%v, %v), want (nil, error)", res, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestParseToleratesDamage(t *testing.T) {
	dll := testfixtures.PEOptions{DLL: true, Exports: []testfixtures.PEExport{{Name: "a"}, {Name: "b"}}}
	tests := []struct {
		name   string
		opts   testfixtures.PEOptions
		mutate func(b []byte) []byte
		note   string
		check  func(t *testing.T, res *Result, b []byte)
	}{
		{
			name:   "optional header cut off",
			mutate: func(b []byte) []byte { return b[:testfixtures.PEOptionalOffset+60] },
			note:   "optional header is truncated",
			check: func(t *testing.T, res *Result, _ []byte) {
				if res.Details.Bits != 64 {
					t.Errorf("bits = %d", res.Details.Bits)
				}
				for _, h := range res.Hardening {
					if h.Status != report.StatusUnknown {
						t.Errorf("%s = %s, want unknown when the flags cannot be read", h.ID, h.Status)
					}
				}
			},
		},
		{
			name: "unrecognised optional header magic",
			mutate: func(b []byte) []byte {
				put16(b, testfixtures.PEOptionalOffset, 0x107)
				return b
			},
			note: "unrecognised optional header magic 0x107",
			check: func(t *testing.T, res *Result, _ []byte) {
				if len(res.Sections) != 3 {
					t.Errorf("the section table is still readable: %d sections", len(res.Sections))
				}
				if len(res.Imports) != 0 {
					t.Errorf("imports need the data directories: %+v", res.Imports)
				}
			},
		},
		{
			name: "no optional header",
			mutate: func(b []byte) []byte {
				put16(b, testfixtures.PEOffset+20, 0)
				return b
			},
			note: "no optional header",
		},
		{
			name: "section count exceeds what fits",
			mutate: func(b []byte) []byte {
				put16(b, testfixtures.PEOffset+6, 500)
				return b
			},
			note: "declares 500 sections but only",
		},
		{
			name: "zero sections",
			mutate: func(b []byte) []byte {
				put16(b, testfixtures.PEOffset+6, 0)
				return b
			},
			note: "section table is empty",
		},
		{
			name: "import directory outside the file",
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(1), 0x90000)
				return b
			},
			note: "outside the file; imports were skipped",
			check: func(t *testing.T, res *Result, _ []byte) {
				if len(res.Imports) != 0 || res.ImpHash != "" {
					t.Errorf("imports %+v imphash %q", res.Imports, res.ImpHash)
				}
			},
		},
		{
			name: "import name outside the file",
			mutate: func(b []byte) []byte {
				// First descriptor -> OriginalFirstThunk -> first thunk entry.
				intRVA := binary.LittleEndian.Uint32(b[fileOffset(b, dirRVA(b, 1)):])
				put32(b, fileOffset(b, intRVA), 0x90000)
				return b
			},
			note: "an import name lies outside the file",
			check: func(t *testing.T, res *Result, _ []byte) {
				if len(res.Imports) != 1 || res.Imports[0].Count != 0 || res.ImpHash != "" {
					t.Errorf("imports %+v imphash %q", res.Imports, res.ImpHash)
				}
				if !hasNote(res, "import hash was not computed") {
					t.Errorf("notes = %v", res.Notes)
				}
			},
		},
		{
			name: "DLL name outside the file",
			mutate: func(b []byte) []byte {
				put32(b, fileOffset(b, dirRVA(b, 1))+12, 0x90000)
				return b
			},
			note: "DLL name (RVA 0x90000) outside the file",
		},
		{
			name: "export directory outside the file",
			opts: dll,
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(0), 0x90000)
				return b
			},
			note: "export directory (RVA 0x90000) lies outside the file",
		},
		{
			name: "absurd export counts",
			opts: dll,
			mutate: func(b []byte) []byte {
				d := fileOffset(b, dirRVA(b, 0))
				put32(b, d+20, 0xffffffff)
				put32(b, d+24, 0xffffffff)
				return b
			},
			note: "declares 4294967295 function entries",
			check: func(t *testing.T, res *Result, b []byte) {
				if uint64(res.Details.ExportCount) > uint64(len(b)) {
					t.Errorf("exportCount %d exceeds what the file can hold", res.Details.ExportCount)
				}
			},
		},
		{
			name: "export ordinal outside the address table",
			opts: dll,
			mutate: func(b []byte) []byte {
				d := fileOffset(b, dirRVA(b, 0))
				ords := fileOffset(b, binary.LittleEndian.Uint32(b[d+36:]))
				put16(b, ords, 0xffff)
				return b
			},
			note: "refer to an ordinal outside the export address table",
		},
		{
			name: "export name outside the file",
			opts: dll,
			mutate: func(b []byte) []byte {
				d := fileOffset(b, dirRVA(b, 0))
				names := fileOffset(b, binary.LittleEndian.Uint32(b[d+32:]))
				put32(b, names, 0x90000)
				return b
			},
			note: "export names lie outside the file",
		},
		{
			name: "certificate table outside the file",
			opts: testfixtures.PEOptions{Signed: true},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(4), uint32(len(b)+100))
				return b
			},
			note: "certificate table",
			check: func(t *testing.T, res *Result, _ []byte) {
				if res.Details.Signed {
					t.Error("a certificate table outside the file must not count as a signature")
				}
			},
		},
		{
			name: "too many data directories declared",
			mutate: func(b []byte) []byte {
				put32(b, testfixtures.PEOptionalOffset+108, 100)
				return b
			},
			note: "only the first 16 data directories are read",
		},
		{
			name:   "file cut in the middle of a section",
			mutate: func(b []byte) []byte { return b[:len(b)-300] },
			note:   "extend beyond the end of the file",
			check: func(t *testing.T, res *Result, _ []byte) {
				last := res.Sections[len(res.Sections)-1]
				if !last.Suspicious {
					t.Errorf("the cut section must be flagged: %+v", last)
				}
			},
		},
		{
			name: "entry point outside every section",
			mutate: func(b []byte) []byte {
				put32(b, testfixtures.PEOptionalOffset+16, 0x90000)
				return b
			},
			note: "entry point RVA 0x90000 does not lie inside any section",
		},
		{
			name: "section name refers to a missing string table entry",
			mutate: func(b []byte) []byte {
				copy(b[testfixtures.PESectionHeaderOffset(64, 0):], "/99999\x00\x00")
				return b
			},
			check: func(t *testing.T, res *Result, _ []byte) {
				if res.Sections[0].Name != "/99999" {
					t.Errorf("name = %q", res.Sections[0].Name)
				}
			},
		},
		{
			name: "debug directory outside the file",
			opts: testfixtures.PEOptions{PDBPath: "x.pdb"},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(6), 0x90000)
				return b
			},
			note: "debug directory",
		},
		{
			name: "CLR header outside the file",
			opts: testfixtures.PEOptions{DotNet: true},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(14), 0x90000)
				return b
			},
			note: "CLR runtime header",
			check: func(t *testing.T, res *Result, _ []byte) {
				if !res.Details.DotNet {
					t.Error("the CLR directory entry still marks the image as .NET")
				}
			},
		},
		{
			name: "CLR metadata root corrupted",
			opts: testfixtures.PEOptions{DotNet: true},
			mutate: func(b []byte) []byte {
				hdr := fileOffset(b, dirRVA(b, 14))
				md := fileOffset(b, binary.LittleEndian.Uint32(b[hdr+8:]))
				copy(b[md:], "XXXX")
				return b
			},
			note: "CLR metadata root",
		},
		{
			name: "TLS directory outside the file",
			opts: testfixtures.PEOptions{TLSCallbacks: 1},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(9), 0x90000)
				return b
			},
			note: "TLS directory",
		},
		{
			name: "TLS callback table outside the image",
			opts: testfixtures.PEOptions{TLSCallbacks: 1},
			mutate: func(b []byte) []byte {
				d := fileOffset(b, dirRVA(b, 9))
				binary.LittleEndian.PutUint64(b[d+24:], 0x10)
				return b
			},
			note: "TLS callback table address",
		},
		{
			name: "load configuration outside the file",
			opts: testfixtures.PEOptions{GuardCF: true},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(10), 0x90000)
				return b
			},
			note: "load configuration directory",
		},
		{
			name: "delay-load directory outside the file",
			opts: testfixtures.PEOptions{DelayImports: []testfixtures.PEImport{{Library: "x.dll", Functions: []string{"F"}}}},
			mutate: func(b []byte) []byte {
				put32(b, dirOffset(13), 0x90000)
				return b
			},
			note: "delay-load import directory",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mutate(testfixtures.PE(tc.opts))
			res, err := Parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{})
			if err != nil {
				t.Fatalf("a damaged but recognisable image must yield a partial result, got error %v", err)
			}
			if tc.note != "" && !hasNote(res, tc.note) {
				t.Errorf("notes %q do not mention %q", res.Notes, tc.note)
			}
			if res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Hardening == nil || res.Notes == nil {
				t.Error("every slice in the result must be non-nil")
			}
			if tc.check != nil {
				tc.check(t, res, b)
			}
		})
	}
}

func TestParseNotesAreBounded(t *testing.T) {
	// A corrupt image with many independent problems must not produce an unbounded note list.
	p := &parser{}
	for i := range 200 {
		p.notef("problem %d", i)
	}
	if len(p.notes) != maxNotes+1 || p.notes[len(p.notes)-1] != "further notes were suppressed" {
		t.Errorf("notes: %d entries, last %q", len(p.notes), p.notes[len(p.notes)-1])
	}
	p2 := &parser{}
	p2.notef("same")
	p2.notef("same")
	if len(p2.notes) != 1 {
		t.Errorf("identical notes must be recorded once: %v", p2.notes)
	}
}

// maxReadsPerParse bounds the reads Parse may issue against the file for the
// tiny fixtures used in the sweeps: a runaway loop shows up as a read explosion
// long before wall-clock time becomes a reliable signal on a loaded machine.
const maxReadsPerParse = 1000

func parseWithinABlink(t *testing.T, label string, data []byte) {
	t.Helper()
	src := &countingReaderAt{r: bytes.NewReader(data)}
	start := time.Now()
	res, err := Parse(context.Background(), src, int64(len(data)), limits.ForSize(int64(len(data))))
	if src.reads > maxReadsPerParse {
		t.Fatalf("%s: Parse issued %d reads against a %d byte file", label, src.reads, len(data))
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("%s: Parse took %v", label, took)
	}
	if err == nil && res == nil {
		t.Fatalf("%s: Parse returned neither a result nor an error", label)
	}
	if err != nil && res != nil {
		t.Fatalf("%s: a non-cancellation error must come without a result", label)
	}
}

func TestParseNeverPanics(t *testing.T) {
	for _, fx := range fixtureSet() {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			for n := 0; n <= len(fx.data); n++ {
				if n > 4096 && n%97 != 0 && n != len(fx.data) {
					continue
				}
				parseWithinABlink(t, "prefix", fx.data[:n])
			}
			scratch := make([]byte, len(fx.data))
			for i := range min(512, len(fx.data)) {
				for _, v := range []byte{0x00, 0xff, 0x80} {
					copy(scratch, fx.data)
					scratch[i] = v
					parseWithinABlink(t, "corrupt", scratch)
				}
			}
		})
	}
}

// TestParseDirectoryCorruptionSweep damages every 32-bit word of the data
// directory table and the first section headers: the fields the parser trusts most.
func TestParseDirectoryCorruptionSweep(t *testing.T) {
	for _, fx := range fixtureSet() {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			start := testfixtures.PEOptionalOffset
			end := min(len(fx.data), testfixtures.PESectionHeaderOffset(64, 3))
			scratch := make([]byte, len(fx.data))
			for off := start; off+4 <= end; off += 4 {
				for _, v := range []uint32{0, 0xffffffff, 0x7fffffff, 0x90000, 0x1} {
					copy(scratch, fx.data)
					put32(scratch, off, v)
					parseWithinABlink(t, "word", scratch)
				}
			}
		})
	}
}

func TestParseLyingSize(t *testing.T) {
	good := testfixtures.PE(testfixtures.PEOptions{DLL: true, Exports: []testfixtures.PEExport{{Name: "a"}}})
	// The caller claims a size far beyond the data: reads fail cleanly and quickly.
	start := time.Now()
	res, err := Parse(context.Background(), bytes.NewReader(good), 1<<40, limits.Limits{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	if len(res.Sections) != 3 {
		t.Errorf("sections = %d", len(res.Sections))
	}
	// And a size smaller than the data hides the tail.
	short, err := Parse(context.Background(), bytes.NewReader(good), 100, limits.Limits{})
	if err == nil || short != nil {
		t.Errorf("a 100 byte view of the file cannot be a PE: (%v, %v)", short, err)
	}
}

// sparseReader serves head bytes and then zeros, simulating a huge file.
type sparseReader struct {
	head []byte
	size int64
}

func (s sparseReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= s.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.size-off))
	for i := range n {
		if pos := off + int64(i); pos < int64(len(s.head)) {
			p[i] = s.head[pos]
		} else {
			p[i] = 0
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestParseHugeSectionIsBounded(t *testing.T) {
	head := testfixtures.PE(testfixtures.PEOptions{})
	third := testfixtures.PESectionHeaderOffset(64, 2)
	put32(head, third+16, 0x40000000) // .data claims 1 GiB of raw data
	src := sparseReader{head: head, size: 3 << 30}
	start := time.Now()
	res, err := Parse(context.Background(), src, src.size, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a huge section must be sampled, not read in full: took %v", took)
	}
	if res.Sections[2].Entropy != 0 {
		t.Errorf("entropy of zeros = %v", res.Sections[2].Entropy)
	}
	if res.Details.OverlaySize == 0 {
		t.Errorf("the bytes after the last section are overlay: %d", res.Details.OverlaySize)
	}
}

// cancelAfterReader cancels a context once n reads have been served.
type cancelAfterReader struct {
	r      io.ReaderAt
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfterReader) ReadAt(p []byte, off int64) (int, error) {
	c.n--
	if c.n == 0 {
		c.cancel()
	}
	return c.r.ReadAt(p, off)
}

func TestParseHonoursContext(t *testing.T) {
	data := testfixtures.PE(testfixtures.PEOptions{DLL: true, Exports: []testfixtures.PEExport{{Name: "a"}}})

	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{})
		if !errors.Is(err, context.Canceled) || res != nil {
			t.Fatalf("got (%v, %v), want (nil, context.Canceled)", res, err)
		}
	})
	t.Run("deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if _, err := Parse(ctx, bytes.NewReader(data), int64(len(data)), limits.Limits{}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled while working returns the partial result", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// Read 1 fills the header cache, read 2 measures .text; the next section check sees the cancellation.
		src := &cancelAfterReader{r: bytes.NewReader(data), n: 2, cancel: cancel}
		res, err := Parse(ctx, src, int64(len(data)), limits.Limits{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if res == nil || len(res.Sections) == 0 || len(res.Sections) >= 3 {
			t.Fatalf("want a partial result with 1-2 sections, got %+v", res)
		}
		if res.Sections == nil || res.Imports == nil || res.Hardening == nil || res.Notes == nil {
			t.Error("partial results must keep their slices non-nil")
		}
	})
}

func TestBlockReader(t *testing.T) {
	data := make([]byte, 3*cacheBlock+123)
	for i := range data {
		data[i] = byte(i * 7)
	}
	counting := &countingReaderAt{r: bytes.NewReader(data)}
	br := newBlockReader(counting, int64(len(data)), readBudget)
	tests := []struct {
		name   string
		off, n int
	}{
		{"start", 0, 16},
		{"same block", 100, 200},
		{"spans two blocks", cacheBlock - 8, 16},
		{"last partial block", 3 * cacheBlock, 100},
		{"tail", len(data) - 5, 5},
		{"spans three blocks", cacheBlock - 8, 2 * cacheBlock},
		{"read larger than two blocks bypasses the cache", 10, 2*cacheBlock + 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.n)
			n, err := br.ReadAt(p, int64(tc.off))
			if n != tc.n || (err != nil && !errors.Is(err, io.EOF)) {
				t.Fatalf("ReadAt = %d, %v", n, err)
			}
			if !bytes.Equal(p, data[tc.off:tc.off+tc.n]) {
				t.Fatal("wrong data")
			}
		})
	}
	counting.reads = 0
	for i := range 100 {
		p := make([]byte, 8)
		if _, err := br.ReadAt(p, int64(3*cacheBlock+i)); err != nil {
			t.Fatal(err)
		}
	}
	if counting.reads > 1 {
		t.Errorf("100 reads inside one block caused %d underlying reads", counting.reads)
	}
	if n, err := br.ReadAt(make([]byte, 4), int64(len(data))); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("read at EOF = %d, %v", n, err)
	}
	if n, err := br.ReadAt(make([]byte, 4), -1); n != 0 || err == nil {
		t.Errorf("negative offset = %d, %v", n, err)
	}
	if n, err := br.ReadAt(nil, 5); n != 0 || err != nil {
		t.Errorf("empty read = %d, %v", n, err)
	}
}

type countingReaderAt struct {
	r     io.ReaderAt
	reads int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	return c.r.ReadAt(p, off)
}

type failingReaderAt struct{ err error }

func (f failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, f.err }

func TestParseReportsIOErrors(t *testing.T) {
	boom := errors.New("disk on fire")
	_, err := Parse(context.Background(), failingReaderAt{boom}, 4096, limits.Limits{})
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err = %v, want the I/O error to surface", err)
	}
}

func TestBlockReaderBudget(t *testing.T) {
	data := make([]byte, 4*cacheBlock)
	br := newBlockReader(bytes.NewReader(data), int64(len(data)), 2*cacheBlock+1)
	buf := make([]byte, 8)
	// Refills are charged after the fact: while any budget is left a read is
	// allowed (the third one overshoots it), the fourth is refused.
	for _, off := range []int64{0, cacheBlock, 2 * cacheBlock} {
		if _, err := br.ReadAt(buf, off); err != nil {
			t.Fatalf("read at %d: %v", off, err)
		}
	}
	if _, err := br.ReadAt(buf, 3*cacheBlock); !errors.Is(err, errReadBudget) || !br.denied {
		t.Fatalf("read past the budget: err = %v, denied = %v", err, br.denied)
	}
	// Cached data stays readable.
	if _, err := br.ReadAt(buf, 2*cacheBlock+16); err != nil {
		t.Errorf("a cache hit costs nothing: %v", err)
	}

	zero := newBlockReader(bytes.NewReader(data), int64(len(data)), 0)
	if _, err := zero.ReadAt(buf, 0); !errors.Is(err, errReadBudget) {
		t.Errorf("empty budget: %v", err)
	}
	big := newBlockReader(bytes.NewReader(data), int64(len(data)), 10)
	if _, err := big.ReadAt(make([]byte, 3*cacheBlock), 0); err != nil {
		t.Errorf("the first big read is allowed: %v", err)
	}
	if _, err := big.ReadAt(make([]byte, 3*cacheBlock), 0); !errors.Is(err, errReadBudget) {
		t.Errorf("the second big read must be refused: %v", err)
	}
}

func TestParseWithExhaustedReadBudget(t *testing.T) {
	// A zero budget makes even the DOS header unreadable.
	b := testfixtures.PE(testfixtures.PEOptions{})
	if _, err := parse(context.Background(), bytes.NewReader(b), int64(len(b)), limits.Limits{}, 0); !errors.Is(err, errReadBudget) {
		t.Fatalf("err = %v, want errReadBudget", err)
	}

	// Export names scattered over a large section force one cache refill each.
	exports := make([]testfixtures.PEExport, 10)
	for i := range exports {
		exports[i] = testfixtures.PEExport{Name: "fn" + string(rune('a'+i))}
	}
	blob := bytes.Repeat([]byte{'x', 0}, 150<<10) // 300 KB
	img := testfixtures.PE(testfixtures.PEOptions{DLL: true, Exports: exports, Sections: []testfixtures.PESection{{Name: ".blob", Data: blob}}})
	blobVA := binary.LittleEndian.Uint32(img[testfixtures.PESectionHeaderOffset(64, 3)+12:])
	exp := fileOffset(img, dirRVA(img, 0))
	names := fileOffset(img, binary.LittleEndian.Uint32(img[exp+32:]))
	for i := range exports {
		put32(img, names+4*i, blobVA+uint32(i)*cacheBlock)
	}
	res, err := parse(context.Background(), bytes.NewReader(img), int64(len(img)), limits.Limits{}, 2*cacheBlock)
	if err != nil {
		t.Fatalf("a refused read is not a fatal error: %v", err)
	}
	if !hasNote(res, "budget for reading structure data was exhausted") {
		t.Errorf("notes = %v", res.Notes)
	}
	if len(res.Exports) >= len(exports) {
		t.Errorf("exports recorded despite the exhausted budget: %d", len(res.Exports))
	}
	full, err := Parse(context.Background(), bytes.NewReader(img), int64(len(img)), limits.Limits{})
	if err != nil || hasNote(full, "budget") {
		t.Fatalf("the normal budget must be enough: %v %v", err, full.Notes)
	}
}

func TestParseEntropyBudgetStopsOverlappingSections(t *testing.T) {
	var secs []testfixtures.PESection
	for i := range 8 {
		secs = append(secs, testfixtures.PESection{Name: ".s" + string(rune('0'+i)), Data: bytes.Repeat([]byte{byte(i), 0x55, 0xA3, 0x1F}, 16<<10)})
	}
	img := testfixtures.PE(testfixtures.PEOptions{Sections: secs})
	first := testfixtures.PESectionHeaderOffset(64, 3)
	ptr := binary.LittleEndian.Uint32(img[first+20:])
	// Every extra section claims the whole data area, 8x its real size.
	for i := range secs {
		h := testfixtures.PESectionHeaderOffset(64, 3+i)
		put32(img, h+20, ptr)
		put32(img, h+16, uint32(len(img))-ptr)
	}
	res := parseBytes(t, img)
	if !hasNote(res, "entropy budget") {
		t.Fatalf("notes = %v", res.Notes)
	}
	last := res.Sections[len(res.Sections)-1]
	if last.Entropy != 0 {
		t.Errorf("the last overlapping section was measured despite the exhausted budget: %v", last.Entropy)
	}
	if res.Sections[3].Entropy == 0 {
		t.Error("the first extra section must be measured")
	}
}
