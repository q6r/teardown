package elf

import (
	"bytes"
	"context"
	delf "debug/elf"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// TestRealGoBinaries parses genuine Go linker output for Linux and checks every
// fact against debug/elf, the reference implementation.
func TestRealGoBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles Go programs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, tg := range []struct {
		goarch  string
		machine string
	}{{"amd64", "x86-64"}, {"arm64", "AArch64"}} {
		t.Run(tg.goarch, func(t *testing.T) {
			path, err := testfixtures.GoBuildInfoCompile(ctx, t.TempDir(), "linux", tg.goarch)
			if errors.Is(err, testfixtures.GoBuildInfoErrNoGo) {
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
			ref, err := delf.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("debug/elf: %v", err)
			}
			compareWithReference(t, res, ref, tg.machine)

			d := res.Details
			if d.Linking != "static" || d.Type != "EXEC" || d.Interpreter != "" || len(d.Needed) != 0 {
				t.Errorf("a CGO-free Go executable is static: %+v", d)
			}
			if d.GoBuildID == "" {
				t.Error("the Go build ID note was not found")
			}
			if got := hardeningOf(t, res, report.HardenCanary).Status; got != report.StatusNA {
				t.Errorf("canary = %s, want n/a for a Go binary", got)
			}
			if got := hardeningOf(t, res, report.HardenFortify).Status; got != report.StatusNA {
				t.Errorf("fortify = %s, want n/a for a Go binary", got)
			}
			if got := hardeningOf(t, res, report.HardenPIE).Status; got != report.StatusDisabled {
				t.Errorf("pie = %s: Go builds fixed-address executables by default on linux/%s", got, tg.goarch)
			}
			if len(res.Imports) != 0 {
				t.Errorf("a static binary imports nothing: %+v", res.Imports)
			}
		})
	}
}

func compareWithReference(t *testing.T, res *Result, ref *delf.File, wantMachine string) {
	t.Helper()
	d := res.Details
	if d.Class != "ELF64" || d.Endian != "little" || d.Machine != wantMachine || d.OSABI == "" {
		t.Errorf("header facts = %+v", d)
	}
	if d.Type != "EXEC" && d.Type != "DYN" {
		t.Errorf("type = %q", d.Type)
	}

	// Sections: same names, sizes, offsets and mapped flags, in order.
	var refSections []*delf.Section
	for _, s := range ref.Sections {
		if s.Type != delf.SHT_NULL {
			refSections = append(refSections, s)
		}
	}
	if len(res.Sections) != len(refSections) || d.SectionCount != len(refSections) {
		t.Fatalf("%d sections (count %d), reference has %d", len(res.Sections), d.SectionCount, len(refSections))
	}
	for i, rs := range refSections {
		got := res.Sections[i]
		if got.Name != rs.Name || got.Offset != rs.Offset {
			t.Errorf("section %d = %q @%d, reference %q @%d", i, got.Name, got.Offset, rs.Name, rs.Offset)
		}
		wantRaw := rs.FileSize
		if rs.Type == delf.SHT_NOBITS {
			wantRaw = 0
		}
		if got.RawSize != wantRaw {
			t.Errorf("section %q raw size %d, reference %d", rs.Name, got.RawSize, wantRaw)
		}
		mapped := rs.Flags&delf.SHF_ALLOC != 0
		if mapped != (len(got.Flags) > 0) || (rs.Flags&delf.SHF_EXECINSTR != 0 && mapped) != got.Executable() || (rs.Flags&delf.SHF_WRITE != 0 && mapped) != got.Writable() {
			t.Errorf("section %q flags %v, reference %v", rs.Name, got.Flags, rs.Flags)
		}
	}
	if sec, ok := sectionNamed(res, ".text"); !ok || !slices.Equal(sec.Flags, []string{"R", "X"}) || sec.Entropy < 3 || sec.Entropy > 8 {
		t.Errorf(".text = %+v", sec)
	}

	// Segments: same types, flags and extents.
	if len(d.Segments) != len(ref.Progs) || d.SegmentCount != len(ref.Progs) {
		t.Fatalf("%d segments, reference has %d", len(d.Segments), len(ref.Progs))
	}
	for i, p := range ref.Progs {
		seg := d.Segments[i]
		if seg.Type != p.Type.String() || seg.Offset != p.Off || seg.FileSize != p.Filesz || seg.MemSize != p.Memsz {
			t.Errorf("segment %d = %+v, reference %+v", i, seg, p.ProgHeader)
		}
		if (p.Flags&delf.PF_X != 0) != slices.Contains(seg.Flags, "X") || (p.Flags&delf.PF_W != 0) != slices.Contains(seg.Flags, "W") {
			t.Errorf("segment %d flags %v, reference %v", i, seg.Flags, p.Flags)
		}
	}

	// Symbols and stripping.
	syms, symErr := ref.Symbols()
	if hasSymtab := !errors.Is(symErr, delf.ErrNoSymbols); hasSymtab == d.Stripped {
		t.Errorf("stripped = %v but the reference found a symbol table = %v", d.Stripped, hasSymtab)
	}
	if d.SymbolCount != len(syms) {
		t.Errorf("symbolCount = %d, reference %d", d.SymbolCount, len(syms))
	}
	dyn, _ := ref.DynamicSymbols()
	if d.DynamicSymbolCount != len(dyn) {
		t.Errorf("dynamicSymbolCount = %d, reference %d", d.DynamicSymbolCount, len(dyn))
	}

	// Hardening derived from the reference program headers.
	var stack *delf.Prog
	hasRelro := false
	for _, p := range ref.Progs {
		switch p.Type {
		case delf.PT_GNU_STACK:
			stack = p
		case delf.PT_GNU_RELRO:
			hasRelro = true
		}
	}
	wantNX := report.StatusUnknown
	switch {
	case stack != nil && stack.Flags&delf.PF_X == 0:
		wantNX = report.StatusEnabled
	case stack != nil:
		wantNX = report.StatusDisabled
	}
	if got := hardeningOf(t, res, report.HardenNX).Status; got != wantNX {
		t.Errorf("nx = %s, reference program headers say %s", got, wantNX)
	}
	if got := hardeningOf(t, res, report.HardenRELRO).Status; (got == report.StatusEnabled) != hasRelro {
		t.Errorf("relro = %s but PT_GNU_RELRO present = %v", got, hasRelro)
	}
	if len(res.Notes) != 0 {
		t.Errorf("a linker-produced file must parse without notes: %v", res.Notes)
	}
}
