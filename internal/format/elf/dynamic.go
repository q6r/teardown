package elf

import (
	delf "debug/elf"
	"encoding/hex"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

// Dynamic tags and flag bits used by the hardening checks.
const (
	dtNull      = uint64(delf.DT_NULL)
	dtNeeded    = uint64(delf.DT_NEEDED)
	dtStrtab    = uint64(delf.DT_STRTAB)
	dtStrsz     = uint64(delf.DT_STRSZ)
	dtSoname    = uint64(delf.DT_SONAME)
	dtRpath     = uint64(delf.DT_RPATH)
	dtRunpath   = uint64(delf.DT_RUNPATH)
	dtBindNow   = uint64(delf.DT_BIND_NOW)
	dtFlags     = uint64(delf.DT_FLAGS)
	dtFlags1    = uint64(delf.DT_FLAGS_1)
	dfBindNow   = uint64(delf.DF_BIND_NOW)
	df1Now      = uint64(delf.DF_1_NOW)
	df1PIE      = uint64(delf.DF_1_PIE)
	noteBuildID = 3
	noteGoID    = 4
)

// dynamic is the information recovered from the PT_DYNAMIC segment. It is read
// through the program headers, exactly like the loader does, so it works for
// images whose section headers are stripped or truncated.
type dynamic struct {
	present bool
	needed  []string
	rpath   []string
	runpath []string
	soname  string
	flags   uint64
	flags1  uint64
	bindNow bool // DT_BIND_NOW tag present
}

func (d *dynamic) immediateBinding() bool {
	return d.bindNow || d.flags&dfBindNow != 0 || d.flags1&df1Now != 0
}

type dynString struct {
	tag uint64
	off uint64
}

func (p *parser) readDynamic() {
	var off, size uint64
	if pr, ok := p.findProg(ptDynamic); ok {
		off, size = pr.off, pr.filesz
	} else if s, ok := p.findSect(shtDynamic); ok {
		off, size = s.off, s.size
	} else {
		return
	}
	p.dyn.present = true
	entSize := uint64(8)
	if p.h.is64 {
		entSize = 16
	}
	want := min(size, maxDynEntries*entSize)
	raw, err := binio.ReadUpTo(p.r, p.size, int64(min(off, uint64(p.size))), int64(want))
	if err != nil {
		p.note("the dynamic section could not be read: %v", err)
		return
	}
	if uint64(len(raw)) < size && size <= maxDynEntries*entSize {
		p.note("the dynamic section is truncated: %d of %d bytes are present", len(raw), size)
	}
	c := binio.NewCursor(raw, p.h.order)
	var strtab, strsz uint64
	var strs []dynString
	for c.Remaining() >= int(entSize) {
		tag, val := readWord(c, p.h.is64), readWord(c, p.h.is64)
		if tag == dtNull {
			break
		}
		switch tag {
		case dtNeeded, dtSoname, dtRpath, dtRunpath:
			strs = append(strs, dynString{tag, val})
		case dtStrtab:
			strtab = val
		case dtStrsz:
			strsz = val
		case dtFlags:
			p.dyn.flags = val
		case dtFlags1:
			p.dyn.flags1 = val
		case dtBindNow:
			p.dyn.bindNow = true
		}
	}
	if len(strs) == 0 {
		return
	}
	base, ok := p.strtabOffset(strtab)
	if !ok {
		p.note("DT_STRTAB (%#x) is not mapped by any loadable segment or section; library names and search paths are unavailable", strtab)
		return
	}
	bad := 0
	for _, s := range strs {
		if strsz != 0 && s.off >= strsz {
			bad++
			continue
		}
		str, err := binio.CString(p.r, p.size, base+int64(s.off), maxInterp)
		if err != nil && str == "" {
			bad++
			continue
		}
		str = binio.Printable(str, maxName)
		switch s.tag {
		case dtNeeded:
			if len(p.dyn.needed) < p.lim.MaxList {
				p.dyn.needed = append(p.dyn.needed, str)
			}
		case dtSoname:
			p.dyn.soname = str
		case dtRpath:
			p.dyn.rpath = strings.Split(str, ":")
		case dtRunpath:
			p.dyn.runpath = strings.Split(str, ":")
		}
	}
	if bad > 0 {
		p.note("%d dynamic string references point outside the dynamic string table", bad)
	}
}

func readWord(c *binio.Cursor, is64 bool) uint64 {
	if is64 {
		return c.U64()
	}
	return uint64(c.U32())
}

// strtabOffset maps the virtual address of the dynamic string table to a file
// offset using the PT_LOAD segments, falling back to a section with that address.
func (p *parser) strtabOffset(vaddr uint64) (int64, bool) {
	for _, pr := range p.progs {
		if pr.typ == ptLoad && vaddr >= pr.vaddr && vaddr-pr.vaddr < pr.filesz {
			if off := pr.off + (vaddr - pr.vaddr); off < uint64(p.size) {
				return int64(off), true
			}
		}
	}
	for _, s := range p.sects {
		if s.typ == shtStrtab && s.addr == vaddr && s.off < uint64(p.size) {
			return int64(s.off), true
		}
	}
	return 0, false
}

func (p *parser) readInterpreter() {
	pr, ok := p.findProg(ptInterp)
	if !ok || pr.filesz == 0 || pr.off >= uint64(p.size) {
		return
	}
	s, _ := binio.CString(p.r, p.size, int64(pr.off), int(min(pr.filesz, maxInterp)))
	p.interp = binio.Printable(s, maxName)
}

// readNotes looks for the GNU and Go build identifiers in PT_NOTE segments and
// SHT_NOTE sections.
func (p *parser) readNotes() {
	type span struct{ off, size uint64 }
	var spans []span
	add := func(off, size uint64) {
		s := span{off, size}
		for _, e := range spans {
			if e == s {
				return
			}
		}
		if len(spans) < maxNoteRanges && size > 0 && off < uint64(p.size) {
			spans = append(spans, s)
		}
	}
	for _, pr := range p.progs {
		if pr.typ == ptNote {
			add(pr.off, pr.filesz)
		}
	}
	for _, s := range p.sects {
		if s.typ == shtNote {
			add(s.off, s.size)
		}
	}
	budget := uint64(maxNoteBytes)
	for _, s := range spans {
		if budget == 0 {
			return
		}
		raw, err := binio.ReadUpTo(p.r, p.size, int64(s.off), int64(min(s.size, budget)))
		if err != nil {
			continue
		}
		budget -= uint64(len(raw))
		p.parseNotes(raw)
	}
}

func (p *parser) parseNotes(raw []byte) {
	c := binio.NewCursor(raw, p.h.order)
	for c.Remaining() >= 12 {
		namesz, descsz, typ := c.U32(), c.U32(), c.U32()
		name := c.Bytes(int(min(uint64(namesz), uint64(c.Remaining()))))
		align := uint32(4)
		if p.h.is64 && typ == 5 && strings.HasPrefix(string(name), "GNU") {
			align = 8 // NT_GNU_PROPERTY_TYPE_0 notes are 8-byte aligned in ELF64
		}
		c.Skip(padding(namesz, 4))
		desc := c.Bytes(int(min(uint64(descsz), uint64(c.Remaining()))))
		c.Skip(padding(descsz, align))
		if c.Err() != nil {
			return
		}
		owner := strings.TrimRight(string(name), "\x00")
		switch {
		case owner == "GNU" && typ == noteBuildID && p.buildID == "":
			p.buildID = hex.EncodeToString(desc[:min(len(desc), 64)])
		case owner == "Go" && typ == noteGoID && p.goBuildID == "":
			p.goBuildID = binio.Printable(string(desc), maxName)
		}
	}
}

// padding returns how many bytes follow n to reach the next multiple of align.
func padding(n, align uint32) int {
	if r := n % align; r != 0 {
		return int(align - r)
	}
	return 0
}
