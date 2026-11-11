package xref

import (
	"context"
	"fmt"
	"math/bits"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/disasm"
	"github.com/q6r/teardown/internal/format/pe"
)

// branch is a direct call or jump remembered to find the ones aimed at an
// import thunk, which is only known once the whole image has been swept.
type branch struct {
	addr, target uint64
	call         bool
}

// sweeper carries the state of one sweep over the executable sections.
type sweeper struct {
	ix       *Index
	ctx      context.Context
	branches []branch
	maxInst  int // the instruction limit, for the note
	instLeft int
	ticks    int
	kept     int
	capped   bool  // some sites were counted but not kept
	stop     bool  // a budget ran out: no further section is swept
	err      error // the context's error
}

// sizeText writes a byte count the way a note reads best: "32 bytes", "3 KiB" or "16 MiB".
func sizeText(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// note records what limited the scan.
func (ix *Index) note(format string, args ...any) {
	if len(ix.notes) < 8 {
		ix.notes = append(ix.notes, fmt.Sprintf(format, args...))
	}
}

// sweep decodes the executable sections one chunk at a time and records the
// instructions that refer to an import slot, then matches the direct branches
// against the import thunks it saw.
func (ix *Index) sweep(ctx context.Context, o Options) error {
	if len(ix.entries) == 0 {
		ix.note("the image has no import slots to look for")
		return ctx.Err()
	}
	sw := &sweeper{ix: ix, ctx: ctx, maxInst: o.MaxInstructions, instLeft: o.MaxInstructions}
	budget := o.MaxBytes
	sawCode := false
	for si, sec := range ix.layout.Sections {
		if !sec.Executable() || sec.Mapped() <= 0 {
			continue
		}
		sawCode = true
		if budget <= 0 {
			ix.partial = true
			ix.note("the sweep stopped after %s of code: the later sections were not scanned", sizeText(o.MaxBytes))
			break
		}
		n := min(sec.Mapped(), o.MaxSectionBytes, budget)
		if n < sec.Mapped() {
			ix.partial = true
			ix.note("only the first %s of section %s were scanned", sizeText(n), sec.Name)
		}
		budget -= sw.section(si, sec, n)
		if sw.err != nil || sw.stop {
			ix.partial = true
			break
		}
	}
	ix.hasCode = sawCode
	if !sawCode {
		ix.note("the image has no executable section")
	}
	if sw.err != nil {
		ix.note("the scan was interrupted: %v", sw.err)
		return sw.err
	}
	sw.resolve()
	if sw.capped {
		ix.note("more call sites exist than are kept (the first %d per import)", maxSitesPerAPI)
	}
	return nil
}

// section sweeps the first n mapped bytes of one section and returns how many it covered.
func (sw *sweeper) section(si int, sec pe.Section, n int64) int64 {
	ix := sw.ix
	base, carry := bits.Add64(ix.layout.ImageBase, uint64(sec.RVA), 0)
	if carry != 0 {
		ix.note("section %s lies beyond the 64-bit address space and was skipped", sec.Name)
		return 0
	}
	var pos int64
	for pos < n {
		if err := sw.ctx.Err(); err != nil {
			sw.err = err
			break
		}
		want := min(int64(chunkSize), n-pos)
		off := int64(sec.RawOffset) + pos
		buf, err := binio.ReadAt(ix.r, ix.size, off, want)
		if err != nil {
			ix.partial = true
			ix.note("section %s could not be read at file offset %#x: %v", sec.Name, off, err)
			break
		}
		used := sw.decode(buf, base+uint64(pos), off, si, pos+want >= n)
		if used <= 0 {
			break
		}
		pos += int64(used)
		if sw.stop || sw.err != nil {
			break
		}
	}
	return pos
}

// decode sweeps one chunk and returns how many bytes it consumed. Unless the
// chunk is the last of its section it stops when fewer than the longest
// instruction's worth of bytes remain, so no instruction is cut by the chunk edge.
func (sw *sweeper) decode(buf []byte, va uint64, fileOff int64, si int, final bool) int {
	pos := 0
	for pos < len(buf) {
		if !final && len(buf)-pos < disasm.MaxInstLen {
			break
		}
		if sw.instLeft <= 0 {
			sw.stop = true
			sw.ix.note("the sweep stopped at its limit of %d instructions", sw.maxInst)
			break
		}
		if sw.ticks++; sw.ticks%pollEvery == 0 {
			if err := sw.ctx.Err(); err != nil {
				sw.err = err
				break
			}
		}
		in := disasm.Decode(sw.ix.mode, buf[pos:], va+uint64(pos))
		sw.instLeft--
		sw.classify(in, si, fileOff+int64(pos))
		pos += in.Len
	}
	return pos
}

// classify records the instruction when it refers to an import slot, and
// remembers it when it is a direct call or jump.
func (sw *sweeper) classify(in disasm.Inst, si int, off int64) {
	ref, has := in.RipRef, in.HasRipRef
	if sw.ix.mode == disasm.Mode32 {
		ref, has = in.AbsRef, in.HasAbsRef
	}
	if has {
		if ei, hit := sw.ix.slotAt[ref]; hit {
			kind := KindLoad
			switch {
			case in.Indirect && in.Flow == disasm.FlowCall:
				kind = KindCall
			case in.Indirect && in.Flow == disasm.FlowJump:
				kind = KindJump
				if len(sw.ix.thunks) < maxThunks {
					sw.ix.thunks[in.Addr] = ei
				}
			}
			sw.add(ei, Site{Kind: kind, Addr: in.Addr, Offset: off, Section: sw.ix.layout.Sections[si].Name})
			return
		}
	}
	if in.HasTarget && (in.Flow == disasm.FlowCall || in.Flow == disasm.FlowJump) && len(sw.branches) < maxBranches {
		sw.branches = append(sw.branches, branch{addr: in.Addr, target: in.Target, call: in.Flow == disasm.FlowCall})
	}
}

// add counts a site and keeps it while there is room.
func (sw *sweeper) add(ei int, s Site) {
	e := &sw.ix.entries[ei]
	e.total++
	if len(e.sites) >= maxSitesPerAPI || sw.kept >= maxSites {
		sw.capped = true
		return
	}
	s.API = e.slot.Display()
	e.sites = append(e.sites, s)
	sw.kept++
}

// resolve turns the direct branches that target an import thunk into sites and
// marks the thunks that something calls as such.
func (sw *sweeper) resolve() {
	ix := sw.ix
	called := map[uint64]bool{}
	for _, b := range sw.branches {
		ei, ok := ix.thunks[b.target]
		if !ok {
			continue
		}
		si, off, ok := ix.layout.SectionAtVA(b.addr)
		if !ok {
			continue
		}
		called[b.target] = true
		kind := KindJumpThunk
		if b.call {
			kind = KindCallThunk
		}
		sw.add(ei, Site{Kind: kind, Addr: b.addr, Offset: off, Section: ix.layout.Sections[si].Name, Via: b.target})
	}
	for va, ei := range ix.thunks {
		if !called[va] {
			continue
		}
		sites := ix.entries[ei].sites
		for i := range sites {
			if sites[i].Addr == va && sites[i].Kind == KindJump {
				sites[i].Kind = KindThunk
			}
		}
	}
}
