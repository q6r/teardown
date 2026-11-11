package pe

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// checkInvariants asserts properties every successful parse must satisfy,
// whatever the input was.
func checkInvariants(t *testing.T, res *Result, size int64, lim limits.Limits) {
	t.Helper()
	if res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Hardening == nil || res.Notes == nil {
		t.Fatal("result slices must be non-nil")
	}
	if len(res.Sections) > lim.MaxList || len(res.Exports) > lim.MaxList || len(res.Imports) > lim.MaxList {
		t.Fatalf("lists exceed MaxList %d: %d sections, %d imports, %d exports", lim.MaxList, len(res.Sections), len(res.Imports), len(res.Exports))
	}
	if len(res.Notes) > maxNotes+1 {
		t.Fatalf("%d notes", len(res.Notes))
	}
	if len(res.Hardening) != 7 {
		t.Fatalf("hardening entries = %d, want 7", len(res.Hardening))
	}
	for _, h := range res.Hardening {
		switch h.Status {
		case report.StatusEnabled, report.StatusDisabled, report.StatusUnknown, report.StatusNA:
		default:
			t.Fatalf("hardening %s has status %q", h.ID, h.Status)
		}
		if h.Label == "" || h.Detail == "" {
			t.Fatalf("hardening %s lacks label or detail", h.ID)
		}
	}
	d := res.Details
	if d.Bits != 32 && d.Bits != 64 {
		t.Fatalf("bits = %d", d.Bits)
	}
	if d.OverlaySize < 0 || d.OverlaySize > size {
		t.Fatalf("overlay %d outside [0, %d]", d.OverlaySize, size)
	}
	if d.Characteristics == nil || d.DllCharacteristics == nil || d.PackerHints == nil || d.DelayImportLibraries == nil || d.DotNetFlags == nil {
		t.Fatal("details slices must be non-nil")
	}
	for _, s := range res.Sections {
		if !utf8.ValidString(s.Name) || s.Flags == nil || s.Entropy < 0 || s.Entropy > 8 {
			t.Fatalf("bad section %+v", s)
		}
		if s.Suspicious != (len(s.Reasons) > 0) {
			t.Fatalf("section %+v: Suspicious and Reasons disagree", s)
		}
	}
	for _, imp := range res.Imports {
		if !utf8.ValidString(imp.Library) || imp.Functions == nil || imp.Count < len(imp.Functions) {
			t.Fatalf("bad import %+v", imp)
		}
		for _, f := range imp.Functions {
			if !utf8.ValidString(f) {
				t.Fatalf("invalid UTF-8 function name %q", f)
			}
		}
	}
	for _, e := range res.Exports {
		if !utf8.ValidString(e) {
			t.Fatalf("invalid UTF-8 export %q", e)
		}
	}
	for _, n := range res.Notes {
		if !utf8.ValidString(n) {
			t.Fatalf("invalid UTF-8 note %q", n)
		}
	}
	if !utf8.ValidString(d.PDBPath) || !utf8.ValidString(d.DotNetVersion) || !utf8.ValidString(d.ExportName) {
		t.Fatal("details strings must be valid UTF-8")
	}
	checkLayout(t, res, size, lim)
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("result does not marshal: %v", err)
	}
}

// checkLayout asserts what the address layout must satisfy whatever the input
// was: slots only for recorded functions, sections that map to bytes of the file.
func checkLayout(t *testing.T, res *Result, size int64, lim limits.Limits) {
	t.Helper()
	l := res.Layout
	recorded := 0
	for _, imp := range res.Imports {
		recorded += len(imp.Functions)
	}
	if len(l.Slots) > recorded || len(l.Slots) > lim.MaxList*4 {
		t.Fatalf("%d slots for %d recorded functions (cap %d)", len(l.Slots), recorded, lim.MaxList*4)
	}
	for _, s := range l.Slots {
		if s.VA != l.ImageBase+uint64(s.RVA) || s.Function == "" || !utf8.ValidString(s.Library+s.Function) {
			t.Fatalf("bad slot %+v", s)
		}
	}
	if len(l.Sections) > lim.MaxList {
		t.Fatalf("%d layout sections", len(l.Sections))
	}
	for _, s := range l.Sections {
		if s.RawLen < 0 || s.RawLen > int64(s.RawSize) || s.Mapped() < 0 || s.Mapped() > s.RawLen || (s.RawLen > 0 && int64(s.RawOffset)+s.RawLen > size) {
			t.Fatalf("bad layout section %+v for a %d byte file", s, size)
		}
		// Overlapping sections resolve to the first that holds a byte, so only the
		// existence of the mapping is certain: an address that maps to an offset
		// maps to an offset inside the file.
		if s.Mapped() > 0 {
			_, va, ok := l.SectionAtOffset(int64(s.RawOffset))
			if !ok {
				t.Fatalf("the first byte of %+v maps nowhere", s)
			}
			if _, off, ok := l.SectionAtVA(va); !ok || off < 0 || off >= size {
				t.Fatalf("the address %#x of %+v maps to offset %d, %v", va, s, off, ok)
			}
		}
	}
}

// FuzzParse feeds arbitrary bytes to Parse directly (no recover): any panic or
// hang is a bug.
func FuzzParse(f *testing.F) {
	for _, fx := range fixtureSet() {
		f.Add(fx.data)
		f.Add(fx.data[:len(fx.data)/2])
		f.Add(fx.data[:testfixtures.PEOptionalOffset+120])
	}
	f.Add([]byte("MZ"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		lim := limits.ForSize(int64(len(data)))
		res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), lim)
		if err != nil {
			if res != nil {
				t.Fatalf("error %v returned together with a result", err)
			}
			return
		}
		checkInvariants(t, res, int64(len(data)), lim)
	})
}

func TestParseInvariantsOnFixtures(t *testing.T) {
	for _, fx := range fixtureSet() {
		t.Run(fx.name, func(t *testing.T) {
			lim := limits.ForSize(int64(len(fx.data)))
			res, err := Parse(context.Background(), bytes.NewReader(fx.data), int64(len(fx.data)), lim)
			if err != nil {
				t.Fatal(err)
			}
			checkInvariants(t, res, int64(len(fx.data)), lim)
		})
	}
}
