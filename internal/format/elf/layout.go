package elf

import (
	"bytes"
	delf "debug/elf"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/q6r/teardown/internal/binio"
)

// Constants the parser needs, taken from debug/elf so the values stay canonical.
const (
	ptLoad     = uint32(delf.PT_LOAD)
	ptDynamic  = uint32(delf.PT_DYNAMIC)
	ptInterp   = uint32(delf.PT_INTERP)
	ptNote     = uint32(delf.PT_NOTE)
	ptGNUStack = uint32(delf.PT_GNU_STACK)
	ptGNURelro = uint32(delf.PT_GNU_RELRO)

	pfX = uint32(delf.PF_X)
	pfW = uint32(delf.PF_W)
	pfR = uint32(delf.PF_R)

	shtNull    = uint32(delf.SHT_NULL)
	shtSymtab  = uint32(delf.SHT_SYMTAB)
	shtStrtab  = uint32(delf.SHT_STRTAB)
	shtDynamic = uint32(delf.SHT_DYNAMIC)
	shtNote    = uint32(delf.SHT_NOTE)
	shtNobits  = uint32(delf.SHT_NOBITS)
	shtDynsym  = uint32(delf.SHT_DYNSYM)

	shfWrite = uint64(delf.SHF_WRITE)
	shfAlloc = uint64(delf.SHF_ALLOC)
	shfExec  = uint64(delf.SHF_EXECINSTR)

	etRel  = uint16(delf.ET_REL)
	etExec = uint16(delf.ET_EXEC)
	etDyn  = uint16(delf.ET_DYN)

	shnXIndex = uint16(delf.SHN_XINDEX)
)

// Parser limits that are independent of the caller's [limits.Limits].
const (
	maxSections   = 1 << 16 // sections read from the header table
	maxDynEntries = 4096    // dynamic entries read
	maxNoteBytes  = 64 << 10
	maxNoteRanges = 32
	maxName       = 512
	maxInterp     = 4096
)

type header struct {
	is64       bool
	big        bool
	order      binary.ByteOrder
	osabi      uint8
	abiVersion uint8
	version    uint32
	typ        uint16
	machine    uint16
	entry      uint64
	phoff      uint64
	shoff      uint64
	phentsize  uint16
	phnum      uint16
	shentsize  uint16
	shnum      uint16
	shstrndx   uint16
}

type prog struct {
	typ, flags uint32
	off, vaddr uint64
	filesz     uint64
	memsz      uint64
}

type sect struct {
	index   int
	name    string
	nameIdx uint32
	typ     uint32
	flags   uint64
	addr    uint64
	off     uint64
	size    uint64
	link    uint32
	info    uint32
	entsize uint64
}

func (p *parser) readHeader() error {
	ident, err := binio.ReadUpTo(p.r, p.size, 0, 16)
	if err != nil {
		return fmt.Errorf("reading ELF identification: %w", err)
	}
	if len(ident) < 16 {
		return fmt.Errorf("not an ELF file: only %d bytes, an ELF identification header needs 16", len(ident))
	}
	if !bytes.Equal(ident[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return errors.New("not an ELF file: bad magic number (want 7f 45 4c 46)")
	}
	h := &p.h
	switch delf.Class(ident[4]) {
	case delf.ELFCLASS32:
	case delf.ELFCLASS64:
		h.is64 = true
	default:
		return fmt.Errorf("unsupported ELF class %d (want 1 = 32-bit or 2 = 64-bit)", ident[4])
	}
	switch delf.Data(ident[5]) {
	case delf.ELFDATA2LSB:
		h.order = binary.LittleEndian
	case delf.ELFDATA2MSB:
		h.order, h.big = binary.BigEndian, true
	default:
		return fmt.Errorf("unsupported ELF data encoding %d (want 1 = little endian or 2 = big endian)", ident[5])
	}
	h.osabi, h.abiVersion = ident[7], ident[8]

	hdrLen := int64(52)
	if h.is64 {
		hdrLen = 64
	}
	raw, err := binio.ReadAt(p.r, p.size, 0, hdrLen)
	if err != nil {
		return fmt.Errorf("truncated ELF header: need %d bytes, the file has %d", hdrLen, p.size)
	}
	c := binio.NewCursor(raw, h.order)
	c.Skip(16)
	h.typ = c.U16()
	h.machine = c.U16()
	h.version = c.U32()
	if h.is64 {
		h.entry, h.phoff, h.shoff = c.U64(), c.U64(), c.U64()
	} else {
		h.entry, h.phoff, h.shoff = uint64(c.U32()), uint64(c.U32()), uint64(c.U32())
	}
	c.Skip(4) // e_flags
	c.Skip(2) // e_ehsize
	h.phentsize, h.phnum = c.U16(), c.U16()
	h.shentsize, h.shnum, h.shstrndx = c.U16(), c.U16(), c.U16()
	if err := c.Err(); err != nil {
		return fmt.Errorf("truncated ELF header: %w", err)
	}
	if h.version != 1 || ident[6] != 1 {
		p.note("ELF version field is %d (identification byte %d), expected 1", h.version, ident[6])
	}
	return nil
}

func (p *parser) readProgs() {
	h := &p.h
	if h.phnum == 0 {
		return
	}
	minEnt := uint64(32)
	if h.is64 {
		minEnt = 56
	}
	ent := uint64(h.phentsize)
	if ent < minEnt {
		p.note("program header entries are declared as %d bytes but an ELF%d program header needs %d; program headers skipped", ent, bits(h.is64), minEnt)
		return
	}
	if h.phoff >= uint64(p.size) {
		p.note("program header table at offset %#x lies outside the file (%d bytes); the file is probably truncated", h.phoff, p.size)
		return
	}
	count := uint64(h.phnum)
	if avail := (uint64(p.size) - h.phoff) / ent; count > avail {
		p.note("program header table is truncated: %d of %d entries are present", avail, count)
		count = avail
	}
	if byMeta := uint64(p.lim.MaxMeta) / ent; count > byMeta {
		p.note("program header table is limited to %d entries (declared %d)", byMeta, count)
		count = byMeta
	}
	raw, err := binio.ReadAt(p.r, p.size, int64(h.phoff), int64(count*ent))
	if err != nil {
		p.note("program header table could not be read: %v", err)
		return
	}
	p.progs = make([]prog, 0, count)
	for i := range count {
		c := binio.NewCursor(raw[i*ent:(i+1)*ent], h.order)
		var pr prog
		if h.is64 {
			pr.typ, pr.flags = c.U32(), c.U32()
			pr.off, pr.vaddr = c.U64(), c.U64()
			c.Skip(8) // p_paddr
			pr.filesz, pr.memsz = c.U64(), c.U64()
		} else {
			pr.typ = c.U32()
			pr.off, pr.vaddr = uint64(c.U32()), uint64(c.U32())
			c.Skip(4) // p_paddr
			pr.filesz, pr.memsz = uint64(c.U32()), uint64(c.U32())
			pr.flags = c.U32()
		}
		p.progs = append(p.progs, pr)
	}
}

func bits(is64 bool) int {
	if is64 {
		return 64
	}
	return 32
}

// readSectionHeader decodes the section header at index i from the raw table.
func (p *parser) decodeSection(raw []byte, i int) sect {
	c := binio.NewCursor(raw, p.h.order)
	s := sect{index: i}
	s.nameIdx, s.typ = c.U32(), c.U32()
	if p.h.is64 {
		s.flags, s.addr, s.off, s.size = c.U64(), c.U64(), c.U64(), c.U64()
		s.link, s.info = c.U32(), c.U32()
		c.Skip(8) // sh_addralign
		s.entsize = c.U64()
	} else {
		s.flags, s.addr, s.off, s.size = uint64(c.U32()), uint64(c.U32()), uint64(c.U32()), uint64(c.U32())
		s.link, s.info = c.U32(), c.U32()
		c.Skip(4) // sh_addralign
		s.entsize = uint64(c.U32())
	}
	return s
}

func (p *parser) readSections() {
	h := &p.h
	if h.shoff == 0 {
		if h.shnum != 0 {
			p.note("the header declares %d sections but e_shoff is 0; the section table is ignored", h.shnum)
		}
		return
	}
	minEnt := uint64(40)
	if h.is64 {
		minEnt = 64
	}
	ent := uint64(h.shentsize)
	if ent < minEnt {
		p.note("section header entries are declared as %d bytes but an ELF%d section header needs %d; section headers skipped", ent, bits(h.is64), minEnt)
		p.sectionsIncomplete = true
		return
	}
	if h.shoff >= uint64(p.size) {
		p.note("section header table at offset %#x lies outside the file (%d bytes); the file is probably truncated", h.shoff, p.size)
		p.sectionsIncomplete = true
		return
	}
	count := uint64(h.shnum)
	strndx := uint32(h.shstrndx)
	if count == 0 || h.shstrndx == shnXIndex {
		first, err := binio.ReadAt(p.r, p.size, int64(h.shoff), int64(ent))
		if err != nil {
			p.note("the first section header (extended section numbering) is unreadable: %v", err)
			p.sectionsIncomplete = true
			return
		}
		s0 := p.decodeSection(first, 0)
		if count == 0 {
			count = s0.size
		}
		if h.shstrndx == shnXIndex {
			strndx = s0.link
		}
	}
	if count > maxSections {
		p.note("the file declares %d sections; only the first %d are read", count, maxSections)
		count = maxSections
		p.sectionsIncomplete = true
	}
	if avail := (uint64(p.size) - h.shoff) / ent; count > avail {
		p.note("section header table is truncated: %d of %d headers are present", avail, count)
		count = avail
		p.sectionsIncomplete = true
	}
	if byMeta := uint64(p.lim.MaxMeta) / ent; count > byMeta {
		p.note("section header table is limited to %d entries (declared %d)", byMeta, count)
		count = byMeta
		p.sectionsIncomplete = true
	}
	if count == 0 {
		return
	}
	raw, err := binio.ReadAt(p.r, p.size, int64(h.shoff), int64(count*ent))
	if err != nil {
		p.note("section header table could not be read: %v", err)
		p.sectionsIncomplete = true
		return
	}
	p.sects = make([]sect, 0, count)
	for i := range count {
		p.sects = append(p.sects, p.decodeSection(raw[i*ent:(i+1)*ent], int(i)))
	}
	p.shstrndx = int(strndx)
	p.resolveSectionNames()
}

func (p *parser) resolveSectionNames() {
	if p.shstrndx <= 0 || p.shstrndx >= len(p.sects) {
		if p.shstrndx != 0 {
			p.note("section name string table index %d is outside the %d sections; section names are unavailable", p.shstrndx, len(p.sects))
		}
		return
	}
	st := p.sects[p.shstrndx]
	want := min(st.size, uint64(p.lim.MaxMeta))
	tab, err := binio.ReadUpTo(p.r, p.size, int64(min(st.off, uint64(p.size))), int64(want))
	if err != nil {
		p.note("section name string table could not be read: %v", err)
		return
	}
	p.namesKnown = true
	if st.size > uint64(len(tab)) {
		p.note("section name string table is larger than the %d bytes available or allowed; names beyond that are unavailable", len(tab))
	}
	unresolved := 0
	for i := range p.sects {
		name, ok := cstring(tab, p.sects[i].nameIdx)
		if !ok && p.sects[i].typ != shtNull {
			unresolved++
		}
		p.sects[i].name = name
	}
	if unresolved > 0 {
		p.note("%d section names point outside the section name string table", unresolved)
	}
}

// cstring returns the NUL-terminated string at idx of a string table.
func cstring(tab []byte, idx uint32) (string, bool) {
	if uint64(idx) >= uint64(len(tab)) {
		return "", false
	}
	rest := tab[idx:]
	if len(rest) > 4096 {
		rest = rest[:4096]
	}
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		rest = rest[:i]
	}
	return binio.Printable(string(rest), maxName), true
}

func (p *parser) findProg(typ uint32) (prog, bool) {
	for _, pr := range p.progs {
		if pr.typ == typ {
			return pr, true
		}
	}
	return prog{}, false
}

func (p *parser) findSect(typ uint32) (sect, bool) {
	for _, s := range p.sects {
		if s.typ == typ {
			return s, true
		}
	}
	return sect{}, false
}

func (p *parser) hasSection(name string) bool {
	for _, s := range p.sects {
		if s.name == name {
			return true
		}
	}
	return false
}
