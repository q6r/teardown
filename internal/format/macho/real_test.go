package macho

import (
	"bytes"
	"context"
	dmacho "debug/macho"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// TestRealGoBinaries parses genuine Go linker output for macOS and checks every
// fact against debug/macho, the reference implementation.
func TestRealGoBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles Go programs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, tg := range []struct{ goarch, cpu string }{{"arm64", "arm64"}, {"amd64", "x86_64"}} {
		t.Run(tg.goarch, func(t *testing.T) {
			path, err := testfixtures.GoBuildInfoCompile(ctx, t.TempDir(), "darwin", tg.goarch)
			if errors.Is(err, testfixtures.ErrNoGoCommand) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			res := parse(t, data, limits.Limits{})
			ref, err := dmacho.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("debug/macho: %v", err)
			}
			compareWithReference(t, res, ref, tg.cpu)

			if got := hardeningOf(t, res, report.HardenPIE); got.Status != report.StatusEnabled {
				t.Errorf("a Go executable is position independent on macOS: %+v", got)
			}
			if got := hardeningOf(t, res, report.HardenNX); got.Status != report.StatusEnabled {
				t.Errorf("nx = %+v", got)
			}
			if got := hardeningOf(t, res, report.HardenCanary); got.Status != report.StatusNA {
				t.Errorf("canary = %+v, want n/a for a Go binary", got)
			}
			hasSignature := slices.ContainsFunc(ref.Loads, func(l dmacho.Load) bool { return ref.ByteOrder.Uint32(l.Raw()) == lcCodeSignature })
			if got := hardeningOf(t, res, report.HardenSigned); (got.Status == report.StatusEnabled) != hasSignature {
				t.Errorf("signed = %+v but LC_CODE_SIGNATURE present = %v", got, hasSignature)
			}
			if tg.goarch == "arm64" && !hasSignature {
				t.Error("the Go linker ad-hoc signs darwin/arm64 binaries, so a signature is expected")
			}
			if len(res.Details.Slices[0].Platform) == 0 {
				t.Error("platform missing: the Go linker emits LC_BUILD_VERSION")
			}
		})
	}
}

func compareWithReference(t *testing.T, res *Result, ref *dmacho.File, wantCPU string) {
	t.Helper()
	s := res.Details.Slices[0]
	if s.CPU != wantCPU || s.Type != "executable" || s.Bits != 64 || s.Error != "" {
		t.Errorf("slice = cpu %q type %q bits %d err %q", s.CPU, s.Type, s.Bits, s.Error)
	}
	var wantFlags []string
	for _, f := range headerFlags {
		if ref.Flags&f.bit != 0 {
			wantFlags = append(wantFlags, f.name)
		}
	}
	if !slices.Equal(s.Flags, wantFlags) {
		t.Errorf("flags = %v, reference %v", s.Flags, wantFlags)
	}

	// Segments and sections must agree with the reference one by one.
	var refSegs []*dmacho.Segment
	for _, l := range ref.Loads {
		if seg, ok := l.(*dmacho.Segment); ok {
			refSegs = append(refSegs, seg)
		}
	}
	if len(s.Segments) != len(refSegs) {
		t.Fatalf("%d segments, reference has %d", len(s.Segments), len(refSegs))
	}
	for i, seg := range s.Segments {
		r := refSegs[i]
		if seg.Name != r.Name || seg.VMSize != r.Memsz || seg.FileOffset != r.Offset || seg.FileSize != r.Filesz || seg.SectionCount != int(r.Nsect) {
			t.Errorf("segment %d = %+v, reference %+v", i, seg, r.SegmentHeader)
		}
	}
	for _, rs := range ref.Sections {
		got, ok := sectionByName(res, rs.Seg+","+rs.Name)
		if !ok {
			t.Errorf("section %s,%s missing", rs.Seg, rs.Name)
			continue
		}
		if got.VirtualSize != rs.Size {
			t.Errorf("section %s,%s size %d, reference %d", rs.Seg, rs.Name, got.VirtualSize, rs.Size)
		}
		zerofill := slices.Contains([]uint32{0x1, 0xc, 0x12}, rs.Flags&0xff)
		// An empty section has no data in the file, so the parser leaves its offset at 0 while debug/macho
		// repeats the raw header value (the Go 1.24 linker emits an empty __gosymtab with a non-zero one).
		if !zerofill && rs.Size != 0 && rs.Offset != 0 && got.Offset != uint64(rs.Offset) {
			t.Errorf("section %s,%s offset %d, reference %d", rs.Seg, rs.Name, got.Offset, rs.Offset)
		}
	}

	// Dylibs: debug/macho reports LC_LOAD_DYLIB only, in command order.
	refLibs, err := ref.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	var ours []string
	for _, l := range s.Dylibs {
		if slices.Contains(refLibs, l) {
			ours = append(ours, l)
		}
	}
	if !slices.Equal(ours, refLibs) || len(refLibs) == 0 {
		t.Errorf("dylibs = %v, reference %v", s.Dylibs, refLibs)
	}

	// Imported symbols: same set, one leading underscore removed.
	refSyms, err := ref.ImportedSymbols()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, n := range refSyms {
		want = append(want, strings.TrimPrefix(n, "_"))
	}
	var got []string
	for _, imp := range res.Imports {
		got = append(got, imp.Functions...)
		if imp.Library != report.UnspecifiedLibrary && !slices.Contains(s.Dylibs, imp.Library) {
			t.Errorf("import library %q is not one of the dylibs", imp.Library)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	want = slices.Compact(want)
	if !slices.Equal(got, want) {
		t.Errorf("imports differ from the reference:\n got %v\nwant %v", got, want)
	}
	if ref.Symtab != nil && s.SymbolCount != len(ref.Symtab.Syms) {
		t.Errorf("symbolCount = %d, reference %d", s.SymbolCount, len(ref.Symtab.Syms))
	}
}
