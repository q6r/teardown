package xref

import (
	"fmt"
	"io"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/disasm"
	"github.com/q6r/teardown/internal/format/pe"
)

// Annotator says what an instruction of an x86 or x86-64 PE image refers to, in
// the words every view of the code uses: the import behind a slot of the import
// address table ("KERNEL32.dll!VirtualAllocEx"), the import behind a stub that
// only jumps through such a slot ("KERNEL32.dll!CreateProcessW (through the thunk
// at 0x140001180)"), or the section a data reference lands in ("0x140003000 in
// .data"). It does no scan: it looks at the one instruction it is given, and at
// the bytes of a branch target when it has to. The code blocks of the findings,
// the xrefs command, the find_calls tool and the disasm window all take their
// notes from it, so they agree.
//
// An Annotator reads the file again when it checks a branch target, so it is
// valid while the reader it was built from is. It holds no mutable state and can
// be used from several goroutines.
type Annotator struct {
	r      io.ReaderAt
	size   int64
	layout pe.Layout
	mode   disasm.Mode
	arch   string
	slotAt map[uint64]int // virtual address of an import slot -> index into layout.Slots
}

// NewAnnotator returns the annotator of the image of size bytes in r, whose
// layout comes from [pe.Parse] or [pe.LoadLayout] (with slots). It returns an
// error that wraps [ErrUnsupported] for an image that is not x86 or x86-64.
func NewAnnotator(r io.ReaderAt, size int64, layout pe.Layout) (*Annotator, error) {
	a := &Annotator{r: r, size: size, layout: layout, slotAt: make(map[uint64]int, len(layout.Slots))}
	switch layout.Machine {
	case machineX8664:
		a.mode, a.arch = disasm.Mode64, archX8664
	case machineX86:
		a.mode, a.arch = disasm.Mode32, archX86
	default:
		return nil, fmt.Errorf("%w: the machine type is %#04x", ErrUnsupported, layout.Machine)
	}
	for i, s := range layout.Slots {
		if _, dup := a.slotAt[s.VA]; !dup {
			a.slotAt[s.VA] = i
		}
	}
	return a, nil
}

// Arch names the instruction set the image is decoded as: "x86-64" or "x86".
func (a *Annotator) Arch() string { return a.arch }

// Note labels what the instruction refers to, or returns "" when there is
// nothing to say. The text is made of names taken from the file: callers that
// print it keep it bounded (see [report.MaxCodeLineChars]) and printable.
func (a *Annotator) Note(in disasm.Inst) string {
	ref, has := in.RipRef, in.HasRipRef
	if a.mode == disasm.Mode32 {
		ref, has = in.AbsRef, in.HasAbsRef
	}
	if has {
		if i, ok := a.slotAt[ref]; ok {
			return a.layout.Slots[i].Display()
		}
		if si, _, ok := a.layout.SectionAtVA(ref); ok {
			return fmt.Sprintf("0x%x in %s", ref, a.layout.Sections[si].Name)
		}
		return ""
	}
	if in.HasTarget && (in.Flow == disasm.FlowCall || in.Flow == disasm.FlowJump) {
		if i, ok := a.thunkAt(in.Target); ok {
			return viaThunk(a.layout.Slots[i].Display(), in.Target)
		}
	}
	return ""
}

// viaThunk words a reference to an import that goes through a stub:
// "KERNEL32.dll!CreateProcessW (through the thunk at 0x140001180)".
func viaThunk(api string, thunk uint64) string {
	return fmt.Sprintf("%s (through the thunk at 0x%x)", api, thunk)
}

// thunkAt reports whether the instruction at the virtual address va is a jump
// through an import slot, which is what a compiler emits as the body of an
// imported function's stub, and returns the index of the slot's entry in the
// layout.
func (a *Annotator) thunkAt(va uint64) (int, bool) {
	si, off, ok := a.layout.SectionAtVA(va)
	if !ok {
		return 0, false
	}
	sec := a.layout.Sections[si]
	n := min(int64(sec.RawOffset)+sec.Mapped()-off, disasm.MaxInstLen)
	buf, err := binio.ReadAt(a.r, a.size, off, n)
	if err != nil {
		return 0, false
	}
	in := disasm.Decode(a.mode, buf, va)
	if !in.Valid || in.Flow != disasm.FlowJump || !in.Indirect {
		return 0, false
	}
	ref, has := in.RipRef, in.HasRipRef
	if a.mode == disasm.Mode32 {
		ref, has = in.AbsRef, in.HasAbsRef
	}
	if !has {
		return 0, false
	}
	i, ok := a.slotAt[ref]
	return i, ok
}
