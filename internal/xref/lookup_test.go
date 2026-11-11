package xref

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/q6r/teardown/internal/disasm"
	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

func TestLookupReturnsTheCallSitesWithTheirCode(t *testing.T) {
	ix := scan(t, dropperFixture())

	f := ix.Lookup("VirtualAllocEx", DefaultBefore, DefaultAfter, DefaultSites)
	if !slices.Equal(f.Imports, []string{"KERNEL32.dll!VirtualAllocEx"}) || f.Total != 1 || len(f.Sites) != 1 {
		t.Fatalf("found = %+v", f)
	}
	s := f.Sites[0]
	if s.Kind != KindCall || s.Addr != 0x140001047 || s.Offset != 0x247 || s.Section != ".text" || s.API != "KERNEL32.dll!VirtualAllocEx" {
		t.Errorf("site = %+v", s.Site)
	}
	// The block is the one the findings show for the same site.
	if want := ix.Block(s.Site, DefaultBefore, DefaultAfter); !equalBlocks(s.Code, want) {
		t.Errorf("the code of the site differs from Block:\n%+v\n%+v", s.Code, want)
	}
	if err := s.Code.Validate(); err != nil {
		t.Errorf("the block is not valid: %v", err)
	}

	t.Run("the stub that only jumps through the slot is not a call site", func(t *testing.T) {
		f := ix.Lookup("CreateRemoteThread", DefaultBefore, DefaultAfter, DefaultSites)
		if f.Total != 1 || len(f.Sites) != 1 || f.Sites[0].Kind != KindCallThunk || f.Sites[0].Addr != 0x1400010a7 || f.Sites[0].Via != 0x1400010b8 {
			t.Fatalf("found = %+v", f)
		}
		if note := highlightNote(f.Sites[0].Code); note != "KERNEL32.dll!CreateRemoteThread (through the thunk at 0x1400010b8)" {
			t.Errorf("note = %q", note)
		}
	})
	t.Run("an import nothing calls", func(t *testing.T) {
		f := ix.Lookup("kernel32.dll!exitprocess", 8, 4, 10)
		if !slices.Equal(f.Imports, []string{"KERNEL32.dll!ExitProcess"}) || f.Total != 0 || len(f.Sites) != 0 {
			t.Errorf("found = %+v", f)
		}
	})
	t.Run("a name that matches no import", func(t *testing.T) {
		for _, name := range []string{"NoSuchFunction", "other.dll!VirtualAllocEx", "", "!", "#7", "kernel32.dll!"} {
			if f := ix.Lookup(name, 8, 4, 10); len(f.Imports) != 0 || f.Total != 0 || len(f.Sites) != 0 {
				t.Errorf("Lookup(%q) = %+v", name, f)
			}
		}
	})
	t.Run("the bounds", func(t *testing.T) {
		if f := ix.Lookup("VirtualAllocEx", 0, 0, 0); f.Total != 1 || len(f.Sites) != 0 {
			t.Errorf("a limit of zero returns no site but still counts: %+v", f)
		}
		if f := ix.Lookup("VirtualAllocEx", -5, -5, -1); f.Total != 1 || len(f.Sites) != 0 {
			t.Errorf("negative numbers are zero: %+v", f)
		}
		f := ix.Lookup("VirtualAllocEx", 0, 0, 5)
		if len(f.Sites) != 1 || len(f.Sites[0].Code.Lines) != 1 || !f.Sites[0].Code.Lines[0].Highlight {
			t.Errorf("no context shows the call alone: %+v", f.Sites)
		}
		f = ix.Lookup("VirtualAllocEx", 1<<30, 1<<30, 5)
		if n := len(f.Sites[0].Code.Lines); n > MaxBefore+MaxAfter+1 {
			t.Errorf("%d lines for a huge context, at most %d", n, MaxBefore+MaxAfter+1)
		}
		if err := f.Sites[0].Code.Validate(); err != nil {
			t.Errorf("a huge context still gives a valid block: %v", err)
		}
	})
}

func TestAPIsCountTheCallSites(t *testing.T) {
	ix := scan(t, dropperFixture())
	got := map[string]API{}
	for _, a := range ix.APIs() {
		got[a.Function] = a
	}
	// CreateRemoteThread has two sites (the call and the stub) but one call site.
	for fn, want := range map[string][2]int{"OpenProcess": {1, 1}, "VirtualAllocEx": {1, 1}, "WriteProcessMemory": {1, 1}, "CreateRemoteThread": {2, 1}} {
		if a := got[fn]; a.Sites != want[0] || a.Calls != want[1] {
			t.Errorf("%s: %d sites and %d calls, want %v", fn, a.Sites, a.Calls, want)
		}
	}
	if _, listed := got["ExitProcess"]; listed {
		t.Error("an import nothing calls is not listed")
	}
}

func TestKindIDsAreStable(t *testing.T) {
	want := map[Kind]string{KindCall: "call", KindCallThunk: "call-thunk", KindJumpThunk: "jump-thunk", KindJump: "jump", KindLoad: "load", KindThunk: "thunk", Kind(99): "unknown"}
	for k, id := range want {
		if k.ID() != id {
			t.Errorf("Kind(%d).ID() = %q, want %q", k, k.ID(), id)
		}
	}
}

func TestAnnotatorSaysWhatAnInstructionRefersTo(t *testing.T) {
	data := dropperFixture()
	res, err := pe.Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.ForSize(int64(len(data))))
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAnnotator(bytes.NewReader(data), int64(len(data)), res.Layout)
	if err != nil {
		t.Fatal(err)
	}
	if a.Arch() != "x86-64" {
		t.Errorf("arch = %q", a.Arch())
	}
	tests := []struct {
		name string
		in   disasm.Inst
		want string
	}{
		// The slots of the fixture are at 0x1400020d0 (OpenProcess) and 8 bytes on for each next one.
		{"a call through the slot of an import", disasm.Inst{HasRipRef: true, RipRef: 0x1400020d8}, "KERNEL32.dll!VirtualAllocEx"},
		{"a load of the last slot", disasm.Inst{HasRipRef: true, RipRef: 0x1400020f0}, "KERNEL32.dll!ExitProcess"},
		{"a reference into .data", disasm.Inst{HasRipRef: true, RipRef: 0x140003000}, "0x140003000 in .data"},
		{"a reference into no section", disasm.Inst{HasRipRef: true, RipRef: 0x150000000}, ""},
		// The stub that jumps through the slot of CreateRemoteThread is at .text+0xb8.
		{"a call to a thunk", disasm.Inst{HasTarget: true, Flow: disasm.FlowCall, Target: 0x1400010b8}, "KERNEL32.dll!CreateRemoteThread (through the thunk at 0x1400010b8)"},
		{"a jump to a thunk", disasm.Inst{HasTarget: true, Flow: disasm.FlowJump, Target: 0x1400010b8}, "KERNEL32.dll!CreateRemoteThread (through the thunk at 0x1400010b8)"},
		{"a call to ordinary code", disasm.Inst{HasTarget: true, Flow: disasm.FlowCall, Target: 0x140001010}, ""},
		{"a conditional jump to a thunk is not a call of it", disasm.Inst{HasTarget: true, Flow: disasm.FlowCondJump, Target: 0x1400010b8}, ""},
		{"a call into the middle of an instruction", disasm.Inst{HasTarget: true, Flow: disasm.FlowCall, Target: 0x1400010b9}, ""},
		{"a call outside every section", disasm.Inst{HasTarget: true, Flow: disasm.FlowCall, Target: 0x1}, ""},
		{"an instruction that refers to nothing", disasm.Inst{}, ""},
	}
	for _, tc := range tests {
		if got := a.Note(tc.in); got != tc.want {
			t.Errorf("%s: Note = %q, want %q", tc.name, got, tc.want)
		}
	}

	arm := res.Layout
	arm.Machine = 0xaa64
	if _, err := NewAnnotator(bytes.NewReader(data), int64(len(data)), arm); !errors.Is(err, ErrUnsupported) {
		t.Errorf("an ARM64 image has no annotator: %v", err)
	}
	// A target in the last bytes of a section, and a file cut in the middle of the stub, are safe.
	cut := data[:0x200+0xb8+3]
	short, err := NewAnnotator(bytes.NewReader(cut), int64(len(cut)), res.Layout)
	if err != nil {
		t.Fatal(err)
	}
	if got := short.Note(disasm.Inst{HasTarget: true, Flow: disasm.FlowCall, Target: 0x1400010b8}); got != "" {
		t.Errorf("a stub cut off by the end of the file is not a thunk: %q", got)
	}
}

// TestASmallerContextIsTheTailOfALargerOne: asking for fewer instructions before
// a call shows the last of the same instructions, never a different (misaligned)
// decoding of the bytes just before the call.
func TestASmallerContextIsTheTailOfALargerOne(t *testing.T) {
	ix := scan(t, testfixtures.SamplePE())
	compared := 0
	for _, api := range ix.APIs() {
		for _, s := range ix.Sites(api.Name) {
			full := ix.Block(s, DefaultBefore, 0)
			for before := 0; before < DefaultBefore; before++ {
				got := ix.Block(s, before, 0)
				want := full.Lines[max(0, len(full.Lines)-1-before):]
				if len(got.Lines) != len(want) {
					t.Fatalf("%s at %#x, %d before: %d lines, want %d", api.Name, s.Addr, before, len(got.Lines), len(want))
				}
				for i := range want {
					if got.Lines[i].Address != want[i].Address || got.Lines[i].Text != want[i].Text || got.Lines[i].Bytes != want[i].Bytes {
						t.Fatalf("%s at %#x, %d before: line %d is %+v, want %+v", api.Name, s.Addr, before, i, got.Lines[i], want[i])
					}
				}
				compared++
			}
		}
	}
	if compared < 50 {
		t.Errorf("only %d windows were compared", compared)
	}
}

// highlightNote returns the note of the highlighted line of a block.
func highlightNote(b report.CodeBlock) string {
	for _, l := range b.Lines {
		if l.Highlight {
			return l.Note
		}
	}
	return ""
}

func equalBlocks(a, b report.CodeBlock) bool { return reflect.DeepEqual(a, b) }
