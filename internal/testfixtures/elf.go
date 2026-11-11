package testfixtures

import (
	"encoding/binary"
	"slices"
	"strings"
)

// ELF object types accepted by [ELFOptions].Type.
const (
	ELFTypeRel  uint16 = 1
	ELFTypeExec uint16 = 2
	ELFTypeDyn  uint16 = 3
)

// Machine numbers accepted by [ELFOptions].Machine.
const (
	ELFMachine386     uint16 = 3
	ELFMachineARM     uint16 = 40
	ELFMachineAMD64   uint16 = 62
	ELFMachineAArch64 uint16 = 183
	ELFMachineRISCV   uint16 = 243
)

// Program header types and flags for [ELFSegment].
const (
	ELFSegmentLoad     uint32 = 1
	ELFSegmentDynamic  uint32 = 2
	ELFSegmentInterp   uint32 = 3
	ELFSegmentNote     uint32 = 4
	ELFSegmentGNUStack uint32 = 0x6474e551
	ELFSegmentGNURelro uint32 = 0x6474e552

	ELFSegmentFlagX uint32 = 1
	ELFSegmentFlagW uint32 = 2
	ELFSegmentFlagR uint32 = 4
)

// Section types and flags for [ELFSection].
const (
	ELFSectionProgbits uint32 = 1
	ELFSectionNote     uint32 = 7
	ELFSectionNobits   uint32 = 8

	ELFSectionFlagWrite uint64 = 1
	ELFSectionFlagAlloc uint64 = 2
	ELFSectionFlagExec  uint64 = 4
)

// Dynamic section flag values for [ELFOptions].DynFlags and DynFlags1.
const (
	ELFDynFlagBindNow uint64 = 0x8        // DT_FLAGS: DF_BIND_NOW
	ELFDynFlag1Now    uint64 = 0x1        // DT_FLAGS_1: DF_1_NOW
	ELFDynFlag1PIE    uint64 = 0x08000000 // DT_FLAGS_1: DF_1_PIE
)

// ELFStack selects how the PT_GNU_STACK header of a fixture is emitted.
type ELFStack int

// ELFStack values; the zero value is a non-executable stack.
const (
	ELFStackRW   ELFStack = iota // PT_GNU_STACK with R+W (default)
	ELFStackRWX                  // PT_GNU_STACK with R+W+X (executable stack)
	ELFStackNone                 // no PT_GNU_STACK header at all
)

// ELFImport is one undefined dynamic symbol.
type ELFImport struct {
	Name string
	// Library and Version together create a GNU symbol version requirement
	// (for example "libc.so.6" and "GLIBC_2.2.5"); leave either empty for an
	// unversioned import.
	Library string
	Version string
	// Weak makes the symbol STB_WEAK instead of STB_GLOBAL.
	Weak bool
}

// ELFSection is an extra section appended to the fixture.
type ELFSection struct {
	Name string
	// Type defaults to SHT_PROGBITS.
	Type  uint32
	Flags uint64
	Data  []byte
	// Align defaults to 16.
	Align uint64
}

// ELFSegment is an extra program header together with the bytes it maps.
type ELFSegment struct {
	Type  uint32
	Flags uint32
	Data  []byte
}

// ELFOptions configures [ELF]. The zero value describes a minimal dynamically
// linked 64-bit little-endian x86-64 PIE: ET_DYN with PT_INTERP, two PT_LOAD
// segments (R+X and R+W), PT_DYNAMIC, a non-executable PT_GNU_STACK, no RELRO,
// no DT_NEEDED entries, no .symtab (so it counts as stripped) and the sections
// .interp .text .dynsym .dynstr .dynamic .shstrtab.
type ELFOptions struct {
	// Bits is 32 or 64 (default 64).
	Bits      int
	BigEndian bool
	// Type is the e_type (default ELFTypeDyn). ELFTypeRel produces an object
	// file without program headers.
	Type    uint16
	Machine uint16 // default ELFMachineAMD64
	OSABI   uint8
	// Entry overrides e_entry (default: the address of .text).
	Entry uint64

	// Static omits .interp, .dynamic, .dynsym, .dynstr and the matching headers.
	Static bool
	// Interp is the PT_INTERP path (default "/lib64/ld-linux-x86-64.so.2").
	Interp string
	// NoInterp omits PT_INTERP while keeping the dynamic section (a shared object).
	NoInterp bool

	Needed  []string // DT_NEEDED
	RPath   []string // DT_RPATH (joined with ':')
	RunPath []string // DT_RUNPATH (joined with ':')
	Soname  string   // DT_SONAME
	// DynFlags and DynFlags1 are emitted as DT_FLAGS / DT_FLAGS_1 when non-zero.
	DynFlags  uint64
	DynFlags1 uint64
	// BindNowTag emits a DT_BIND_NOW entry.
	BindNowTag bool
	// RELRO adds a PT_GNU_RELRO header over the dynamic section.
	RELRO bool
	Stack ELFStack

	Imports []ELFImport // undefined dynamic symbols
	Exports []string    // defined global functions in .dynsym
	Symbols []string    // global functions in .symtab (none => no .symtab)

	// TextData is the content of .text (default: sixteen bytes of NOPs and a RET).
	TextData []byte
	// BuildID adds a .note.gnu.build-id note; GoBuildID adds .note.go.buildid.
	BuildID   []byte
	GoBuildID string
	// DebugInfo adds a .debug_info section.
	DebugInfo bool

	// Sections are extra sections: ALLOC+WRITE ones land in the writable
	// segment, ALLOC ones in the read-only one, the rest stay unmapped.
	Sections []ELFSection
	// Segments are extra program headers with their own file data.
	Segments []ELFSegment
	// NoSections drops the section header table (like sstrip or UPX do).
	NoSections bool
}

// ELF builds a tiny, valid, deterministic ELF file. The result is accepted by
// debug/elf and is meant to exercise parsers, not to run.
func ELF(opts ELFOptions) []byte {
	b := &elfBuilder{opts: opts}
	b.setup()
	return b.build()
}

const (
	elfSHTSymtab  uint32 = 2
	elfSHTStrtab  uint32 = 3
	elfSHTDynamic uint32 = 6
	elfSHTDynsym  uint32 = 11
	elfSHTVerneed uint32 = 0x6ffffffe
	elfSHTVersym  uint32 = 0x6fffffff

	elfDTNull      uint64 = 0
	elfDTNeeded    uint64 = 1
	elfDTStrtab    uint64 = 5
	elfDTSymtab    uint64 = 6
	elfDTStrsz     uint64 = 10
	elfDTSyment    uint64 = 11
	elfDTSoname    uint64 = 14
	elfDTRpath     uint64 = 15
	elfDTBindNow   uint64 = 24
	elfDTRunpath   uint64 = 29
	elfDTFlags     uint64 = 30
	elfDTFlags1    uint64 = 0x6ffffffb
	elfDTVersym    uint64 = 0x6ffffff0
	elfDTVerneed   uint64 = 0x6ffffffe
	elfDTVerneednm uint64 = 0x6fffffff

	elfSTBGlobal uint8 = 1
	elfSTBWeak   uint8 = 2
	elfSTTFile   uint8 = 4
	elfSTTFunc   uint8 = 2
)

type elfEnc struct {
	order binary.AppendByteOrder
	is64  bool
}

func (e elfEnc) u16(b []byte, v uint16) []byte { return e.order.AppendUint16(b, v) }
func (e elfEnc) u32(b []byte, v uint32) []byte { return e.order.AppendUint32(b, v) }

// word appends a native-width (4 or 8 byte) value.
func (e elfEnc) word(b []byte, v uint64) []byte {
	if e.is64 {
		return e.order.AppendUint64(b, v)
	}
	return e.order.AppendUint32(b, uint32(v))
}

type elfStrtab struct {
	buf []byte
	idx map[string]uint32
}

func elfNewStrtab() *elfStrtab {
	return &elfStrtab{buf: []byte{0}, idx: map[string]uint32{"": 0}}
}

func (t *elfStrtab) add(s string) uint32 {
	if off, ok := t.idx[s]; ok {
		return off
	}
	off := uint32(len(t.buf))
	t.buf = append(append(t.buf, s...), 0)
	t.idx[s] = off
	return off
}

// elfLayout carries the final section indices and addresses to the generators.
// During the sizing pass it is empty and every lookup yields zero.
type elfLayout struct {
	idx  map[string]uint16
	addr map[string]uint64
}

func (l *elfLayout) index(name string) uint32 { return uint32(l.idx[name]) }
func (l *elfLayout) at(name string) uint64    { return l.addr[name] }

type elfPart struct {
	name    string
	typ     uint32
	flags   uint64
	align   uint64
	entsize uint64
	info    uint32
	link    string // name of the linked section
	gen     func(l *elfLayout) []byte

	size uint64
	off  uint64
	addr uint64
	data []byte
}

type elfPhdr struct {
	typ, flags uint32
	// cover names the section to map, or one of the pseudo names
	// "load-rx", "load-rw" and "notes"; "" maps nothing (PT_GNU_STACK).
	cover     string
	off, addr uint64
	filesz    uint64
	align     uint64
}

type elfNeed struct {
	lib      string
	versions []string
	others   []uint16
}

type elfSym struct {
	name    string
	bind    uint8
	defined bool // defined in .text, otherwise SHN_UNDEF
	version uint16
}

type elfBuilder struct {
	opts    ELFOptions
	enc     elfEnc
	is64    bool
	typ     uint16
	machine uint16
	base    uint64
	rel     bool
	static  bool

	parts   []*elfPart
	phdrs   []*elfPhdr
	dynstr  *elfStrtab
	needs   []elfNeed
	dynsyms []elfSym
}

func (b *elfBuilder) setup() {
	o := b.opts
	b.is64 = o.Bits != 32
	var order binary.AppendByteOrder = binary.LittleEndian
	if o.BigEndian {
		order = binary.BigEndian
	}
	b.enc = elfEnc{order: order, is64: b.is64}
	b.typ = o.Type
	if b.typ == 0 {
		b.typ = ELFTypeDyn
	}
	b.rel = b.typ == ELFTypeRel
	b.machine = o.Machine
	if b.machine == 0 {
		b.machine = ELFMachineAMD64
	}
	if b.typ == ELFTypeExec {
		b.base = 0x400000
		if !b.is64 {
			b.base = 0x08048000
		}
	}
	b.static = o.Static || b.rel
	b.dynstr = elfNewStrtab()
	if !b.static {
		b.collectNeeds()
		b.buildDynsyms()
		b.internDynamicStrings()
	}
	b.composeParts()
	b.composePhdrs()
}

// collectNeeds groups the versioned imports by library and numbers the versions
// from 2 upwards in the order the GNU toolchain would.
func (b *elfBuilder) collectNeeds() {
	for _, imp := range b.opts.Imports {
		if imp.Library == "" || imp.Version == "" {
			continue
		}
		i := slices.IndexFunc(b.needs, func(n elfNeed) bool { return n.lib == imp.Library })
		if i < 0 {
			b.needs = append(b.needs, elfNeed{lib: imp.Library})
			i = len(b.needs) - 1
		}
		if !slices.Contains(b.needs[i].versions, imp.Version) {
			b.needs[i].versions = append(b.needs[i].versions, imp.Version)
		}
	}
	next := uint16(2)
	for i := range b.needs {
		for range b.needs[i].versions {
			b.needs[i].others = append(b.needs[i].others, next)
			next++
		}
	}
}

func (b *elfBuilder) versionIndex(imp ELFImport) uint16 {
	for _, n := range b.needs {
		if n.lib != imp.Library {
			continue
		}
		if j := slices.Index(n.versions, imp.Version); j >= 0 {
			return n.others[j]
		}
	}
	return 1
}

func (b *elfBuilder) buildDynsyms() {
	for _, imp := range b.opts.Imports {
		bind := elfSTBGlobal
		if imp.Weak {
			bind = elfSTBWeak
		}
		b.dynsyms = append(b.dynsyms, elfSym{name: imp.Name, bind: bind, version: b.versionIndex(imp)})
	}
	for _, name := range b.opts.Exports {
		b.dynsyms = append(b.dynsyms, elfSym{name: name, bind: elfSTBGlobal, defined: true, version: 1})
	}
}

// internDynamicStrings fills .dynstr up front so that its size never changes
// between the sizing pass and the final pass.
func (b *elfBuilder) internDynamicStrings() {
	o := b.opts
	for _, s := range o.Needed {
		b.dynstr.add(s)
	}
	b.dynstr.add(o.Soname)
	b.dynstr.add(strings.Join(o.RPath, ":"))
	b.dynstr.add(strings.Join(o.RunPath, ":"))
	for _, s := range b.dynsyms {
		b.dynstr.add(s.name)
	}
	for _, n := range b.needs {
		b.dynstr.add(n.lib)
		for _, v := range n.versions {
			b.dynstr.add(v)
		}
	}
}

func (b *elfBuilder) add(p *elfPart) { b.parts = append(b.parts, p) }

func (b *elfBuilder) composeParts() {
	o := b.opts
	symSize, dynSize := uint64(24), uint64(16)
	if !b.is64 {
		symSize, dynSize = 16, 8
	}

	// Read-only and executable group.
	if !b.static && !o.NoInterp {
		interp := o.Interp
		if interp == "" {
			interp = "/lib64/ld-linux-x86-64.so.2"
		}
		b.add(&elfPart{name: ".interp", typ: ELFSectionProgbits, flags: ELFSectionFlagAlloc, align: 1,
			gen: func(*elfLayout) []byte { return append([]byte(interp), 0) }})
	}
	if len(o.BuildID) > 0 {
		b.add(&elfPart{name: ".note.gnu.build-id", typ: ELFSectionNote, flags: ELFSectionFlagAlloc, align: 4,
			gen: func(*elfLayout) []byte { return b.note("GNU\x00", 3, o.BuildID) }})
	}
	if o.GoBuildID != "" {
		b.add(&elfPart{name: ".note.go.buildid", typ: ELFSectionNote, flags: ELFSectionFlagAlloc, align: 4,
			gen: func(*elfLayout) []byte { return b.note("Go\x00\x00", 4, []byte(o.GoBuildID)) }})
	}
	if !b.static {
		b.add(&elfPart{name: ".dynsym", typ: elfSHTDynsym, flags: ELFSectionFlagAlloc, align: 8, entsize: symSize, info: 1, link: ".dynstr",
			gen: b.encodeDynsym})
		b.add(&elfPart{name: ".dynstr", typ: elfSHTStrtab, flags: ELFSectionFlagAlloc, align: 1,
			gen: func(*elfLayout) []byte { return b.dynstr.buf }})
		if len(b.needs) > 0 {
			b.add(&elfPart{name: ".gnu.version", typ: elfSHTVersym, flags: ELFSectionFlagAlloc, align: 2, entsize: 2, link: ".dynsym",
				gen: func(*elfLayout) []byte { return b.encodeVersym() }})
			b.add(&elfPart{name: ".gnu.version_r", typ: elfSHTVerneed, flags: ELFSectionFlagAlloc, align: 8, info: uint32(len(b.needs)), link: ".dynstr",
				gen: func(*elfLayout) []byte { return b.encodeVerneed() }})
		}
	}
	text := o.TextData
	if text == nil {
		text = append(slicesRepeatByte(0x90, 15), 0xc3)
	}
	b.add(&elfPart{name: ".text", typ: ELFSectionProgbits, flags: ELFSectionFlagAlloc | ELFSectionFlagExec, align: 16,
		gen: func(*elfLayout) []byte { return text }})
	for _, s := range o.Sections {
		if s.Flags&ELFSectionFlagAlloc != 0 && s.Flags&ELFSectionFlagWrite == 0 {
			b.add(elfUserPart(s))
		}
	}

	// Writable group.
	if !b.static {
		b.add(&elfPart{name: ".dynamic", typ: elfSHTDynamic, flags: ELFSectionFlagAlloc | ELFSectionFlagWrite, align: 8, entsize: dynSize, link: ".dynstr",
			gen: b.encodeDynamic})
	}
	for _, s := range o.Sections {
		if s.Flags&ELFSectionFlagAlloc != 0 && s.Flags&ELFSectionFlagWrite != 0 {
			b.add(elfUserPart(s))
		}
	}

	// Data of extra segments, then the unmapped sections.
	for i, seg := range o.Segments {
		data := seg.Data
		b.add(&elfPart{name: elfSegmentName(i), typ: ELFSectionProgbits, align: 16, gen: func(*elfLayout) []byte { return data }})
	}
	for _, s := range o.Sections {
		if s.Flags&ELFSectionFlagAlloc == 0 {
			b.add(elfUserPart(s))
		}
	}
	if o.DebugInfo {
		b.add(&elfPart{name: ".debug_info", typ: ELFSectionProgbits, align: 1,
			gen: func(*elfLayout) []byte { return []byte("fixture debug info") }})
	}
	if len(o.Symbols) > 0 {
		b.add(&elfPart{name: ".symtab", typ: elfSHTSymtab, align: 8, entsize: symSize, info: 2, link: ".strtab",
			gen: b.encodeSymtab})
		b.add(&elfPart{name: ".strtab", typ: elfSHTStrtab, align: 1,
			gen: func(*elfLayout) []byte { return b.symbolStrings().buf }})
	}
	if !o.NoSections {
		b.add(&elfPart{name: ".shstrtab", typ: elfSHTStrtab, align: 1,
			gen: func(*elfLayout) []byte { return b.sectionNames().buf }})
	}
}

func slicesRepeatByte(v byte, n int) []byte { return slices.Repeat([]byte{v}, n) }

func elfSegmentName(i int) string { return ".segdata" + string(rune('0'+i%10)) }

func elfUserPart(s ELFSection) *elfPart {
	typ, align := s.Type, s.Align
	if typ == 0 {
		typ = ELFSectionProgbits
	}
	if align == 0 {
		align = 16
	}
	data := s.Data
	return &elfPart{name: s.Name, typ: typ, flags: s.Flags, align: align, gen: func(*elfLayout) []byte { return data }}
}

func (b *elfBuilder) composePhdrs() {
	o := b.opts
	if b.rel {
		return
	}
	has := func(name string) bool {
		return slices.ContainsFunc(b.parts, func(p *elfPart) bool { return p.name == name })
	}
	if !b.static && !o.NoInterp {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentInterp, flags: ELFSegmentFlagR, cover: ".interp", align: 1})
	}
	b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentLoad, flags: ELFSegmentFlagR | ELFSegmentFlagX, cover: "load-rx", align: 0x1000})
	if slices.ContainsFunc(b.parts, func(p *elfPart) bool {
		return p.flags&ELFSectionFlagAlloc != 0 && p.flags&ELFSectionFlagWrite != 0
	}) {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentLoad, flags: ELFSegmentFlagR | ELFSegmentFlagW, cover: "load-rw", align: 0x1000})
	}
	if !b.static {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentDynamic, flags: ELFSegmentFlagR | ELFSegmentFlagW, cover: ".dynamic", align: 8})
	}
	if has(".note.gnu.build-id") || has(".note.go.buildid") {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentNote, flags: ELFSegmentFlagR, cover: "notes", align: 4})
	}
	if o.RELRO && !b.static {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentGNURelro, flags: ELFSegmentFlagR, cover: ".dynamic", align: 1})
	}
	switch o.Stack {
	case ELFStackRW:
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentGNUStack, flags: ELFSegmentFlagR | ELFSegmentFlagW, align: 16})
	case ELFStackRWX:
		b.phdrs = append(b.phdrs, &elfPhdr{typ: ELFSegmentGNUStack, flags: ELFSegmentFlagR | ELFSegmentFlagW | ELFSegmentFlagX, align: 16})
	case ELFStackNone:
	}
	for i, seg := range o.Segments {
		b.phdrs = append(b.phdrs, &elfPhdr{typ: seg.Type, flags: seg.Flags, cover: elfSegmentName(i), align: 16})
	}
}

func (b *elfBuilder) note(name string, typ uint32, desc []byte) []byte {
	var out []byte
	out = b.enc.u32(out, uint32(len(name)))
	out = b.enc.u32(out, uint32(len(desc)))
	out = b.enc.u32(out, typ)
	out = append(out, name...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	out = append(out, desc...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func (b *elfBuilder) symbolStrings() *elfStrtab {
	t := elfNewStrtab()
	t.add("fixture.c")
	for _, s := range b.opts.Symbols {
		t.add(s)
	}
	return t
}

func (b *elfBuilder) sectionNames() *elfStrtab {
	t := elfNewStrtab()
	for _, p := range b.parts {
		t.add(p.name)
	}
	t.add(".shstrtab")
	return t
}

func (b *elfBuilder) encodeSym(out []byte, name uint32, info uint8, shndx uint16, value, size uint64) []byte {
	e := b.enc
	out = e.u32(out, name)
	if e.is64 {
		out = append(out, info, 0)
		out = e.u16(out, shndx)
		out = e.word(out, value)
		return e.word(out, size)
	}
	out = e.word(out, value)
	out = e.word(out, size)
	out = append(out, info, 0)
	return e.u16(out, shndx)
}

func (b *elfBuilder) encodeDynsym(l *elfLayout) []byte {
	out := b.encodeSym(nil, 0, 0, 0, 0, 0)
	for _, s := range b.dynsyms {
		var shndx uint16
		var value uint64
		if s.defined {
			shndx, value = uint16(l.index(".text")), l.at(".text")
		}
		out = b.encodeSym(out, b.dynstr.add(s.name), s.bind<<4|elfSTTFunc, shndx, value, 4)
	}
	return out
}

func (b *elfBuilder) encodeSymtab(l *elfLayout) []byte {
	st := b.symbolStrings()
	out := b.encodeSym(nil, 0, 0, 0, 0, 0)
	out = b.encodeSym(out, st.add("fixture.c"), elfSTTFile, 0xfff1, 0, 0)
	for _, name := range b.opts.Symbols {
		out = b.encodeSym(out, st.add(name), elfSTBGlobal<<4|elfSTTFunc, uint16(l.index(".text")), l.at(".text"), 4)
	}
	return out
}

func (b *elfBuilder) encodeVersym() []byte {
	out := b.enc.u16(nil, 0)
	for _, s := range b.dynsyms {
		out = b.enc.u16(out, s.version)
	}
	return out
}

func (b *elfBuilder) encodeVerneed() []byte {
	e := b.enc
	var out []byte
	for i, n := range b.needs {
		next := uint32(0)
		if i < len(b.needs)-1 {
			next = uint32(16 + 16*len(n.versions))
		}
		out = e.u16(out, 1)
		out = e.u16(out, uint16(len(n.versions)))
		out = e.u32(out, b.dynstr.add(n.lib))
		out = e.u32(out, 16)
		out = e.u32(out, next)
		for j, v := range n.versions {
			auxNext := uint32(16)
			if j == len(n.versions)-1 {
				auxNext = 0
			}
			out = e.u32(out, elfHash(v))
			out = e.u16(out, 0)
			out = e.u16(out, n.others[j])
			out = e.u32(out, b.dynstr.add(v))
			out = e.u32(out, auxNext)
		}
	}
	return out
}

// elfHash is the SysV ELF symbol hash used by version auxiliary entries.
func elfHash(name string) uint32 {
	var h uint32
	for i := range len(name) {
		h = h<<4 + uint32(name[i])
		if g := h & 0xf0000000; g != 0 {
			h ^= g >> 24
		}
		h &^= 0xf0000000
	}
	return h
}

func (b *elfBuilder) encodeDynamic(l *elfLayout) []byte {
	o := b.opts
	e := b.enc
	var out []byte
	put := func(tag, val uint64) {
		out = e.word(out, tag)
		out = e.word(out, val)
	}
	for _, s := range o.Needed {
		put(elfDTNeeded, uint64(b.dynstr.add(s)))
	}
	if o.Soname != "" {
		put(elfDTSoname, uint64(b.dynstr.add(o.Soname)))
	}
	if len(o.RPath) > 0 {
		put(elfDTRpath, uint64(b.dynstr.add(strings.Join(o.RPath, ":"))))
	}
	if len(o.RunPath) > 0 {
		put(elfDTRunpath, uint64(b.dynstr.add(strings.Join(o.RunPath, ":"))))
	}
	put(elfDTStrtab, l.at(".dynstr"))
	put(elfDTSymtab, l.at(".dynsym"))
	put(elfDTStrsz, uint64(len(b.dynstr.buf)))
	if e.is64 {
		put(elfDTSyment, 24)
	} else {
		put(elfDTSyment, 16)
	}
	if len(b.needs) > 0 {
		put(elfDTVerneed, l.at(".gnu.version_r"))
		put(elfDTVerneednm, uint64(len(b.needs)))
		put(elfDTVersym, l.at(".gnu.version"))
	}
	if o.DynFlags != 0 {
		put(elfDTFlags, o.DynFlags)
	}
	if o.DynFlags1 != 0 {
		put(elfDTFlags1, o.DynFlags1)
	}
	if o.BindNowTag {
		put(elfDTBindNow, 0)
	}
	put(elfDTNull, 0)
	return out
}

func elfAlignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}

func (b *elfBuilder) sizes() (ehdr, phent, shent uint64) {
	if b.is64 {
		return 64, 56, 64
	}
	return 52, 32, 40
}

func (b *elfBuilder) build() []byte {
	ehdrSize, phentSize, shentSize := b.sizes()

	// Pass 1: sizes, offsets and addresses.
	empty := &elfLayout{idx: map[string]uint16{}, addr: map[string]uint64{}}
	cursor := ehdrSize + uint64(len(b.phdrs))*phentSize
	for _, p := range b.parts {
		p.size = uint64(len(p.gen(empty)))
		cursor = elfAlignUp(cursor, p.align)
		p.off = cursor
		if p.flags&ELFSectionFlagAlloc != 0 && !b.rel {
			p.addr = b.base + cursor
		}
		if p.typ != ELFSectionNobits {
			cursor += p.size
		}
	}
	shoff := elfAlignUp(cursor, 8)

	// Pass 2: real contents now that indices and addresses are known.
	l := &elfLayout{idx: map[string]uint16{}, addr: map[string]uint64{}}
	for i, p := range b.parts {
		l.idx[p.name] = uint16(i + 1)
		l.addr[p.name] = p.addr
	}
	for _, p := range b.parts {
		p.data = p.gen(l)
	}
	b.fillPhdrs(ehdrSize, phentSize)

	var shnum, shstrndx uint16
	shOffset := uint64(0)
	if !b.opts.NoSections {
		shOffset = shoff
		shnum = uint16(len(b.parts) + 1)
		shstrndx = l.idx[".shstrtab"]
	}
	entry := b.opts.Entry
	if entry == 0 {
		entry = l.at(".text")
	}
	phoff := uint64(0)
	if len(b.phdrs) > 0 {
		phoff = ehdrSize
	}
	out := make([]byte, 0, shoff+uint64(len(b.parts)+1)*shentSize)
	out = b.writeEhdr(out, entry, phoff, shOffset, uint16(len(b.phdrs)), shnum, shstrndx)
	for _, ph := range b.phdrs {
		out = b.writePhdr(out, ph)
	}
	for _, p := range b.parts {
		out = append(out, make([]byte, p.off-uint64(len(out)))...)
		if p.typ != ELFSectionNobits {
			out = append(out, p.data...)
		}
	}
	if b.opts.NoSections {
		return out
	}
	out = append(out, make([]byte, shoff-uint64(len(out)))...)
	out = append(out, make([]byte, shentSize)...) // SHT_NULL
	names := b.sectionNames()
	for _, p := range b.parts {
		out = b.writeShdr(out, names.add(p.name), p, l)
	}
	return out
}

func (b *elfBuilder) fillPhdrs(ehdrSize, phentSize uint64) {
	byName := map[string]*elfPart{}
	for _, p := range b.parts {
		byName[p.name] = p
	}
	rxEnd := ehdrSize + uint64(len(b.phdrs))*phentSize
	var rwStart, rwEnd, noteStart, noteEnd uint64
	for _, p := range b.parts {
		end := p.off + p.size
		if p.typ == ELFSectionNobits {
			end = p.off
		}
		if p.typ == ELFSectionNote {
			if noteStart == 0 {
				noteStart = p.off
			}
			noteEnd = end
		}
		if p.flags&ELFSectionFlagAlloc == 0 {
			continue
		}
		if p.flags&ELFSectionFlagWrite != 0 {
			if rwStart == 0 {
				rwStart = p.off
			}
			rwEnd = max(rwEnd, end)
		} else {
			rxEnd = max(rxEnd, end)
		}
	}
	for _, ph := range b.phdrs {
		switch ph.cover {
		case "load-rx":
			ph.off, ph.addr, ph.filesz = 0, b.base, rxEnd
		case "load-rw":
			ph.off, ph.addr, ph.filesz = rwStart, b.base+rwStart, rwEnd-rwStart
		case "notes":
			ph.off, ph.addr, ph.filesz = noteStart, b.base+noteStart, noteEnd-noteStart
		case "":
			// PT_GNU_STACK maps nothing.
		default:
			p := byName[ph.cover]
			ph.off, ph.addr, ph.filesz = p.off, b.base+p.off, p.size
		}
	}
}

func (b *elfBuilder) writeEhdr(out []byte, entry, phoff, shoff uint64, phnum, shnum, shstrndx uint16) []byte {
	e := b.enc
	ehdrSize, phentSize, shentSize := b.sizes()
	class, data := byte(2), byte(1)
	if !b.is64 {
		class = 1
	}
	if b.opts.BigEndian {
		data = 2
	}
	out = append(out, 0x7f, 'E', 'L', 'F', class, data, 1, b.opts.OSABI, 0, 0, 0, 0, 0, 0, 0, 0)
	out = e.u16(out, b.typ)
	out = e.u16(out, b.machine)
	out = e.u32(out, 1)
	out = e.word(out, entry)
	out = e.word(out, phoff)
	out = e.word(out, shoff)
	out = e.u32(out, 0)
	out = e.u16(out, uint16(ehdrSize))
	out = e.u16(out, uint16(phentSize))
	out = e.u16(out, phnum)
	out = e.u16(out, uint16(shentSize))
	out = e.u16(out, shnum)
	return e.u16(out, shstrndx)
}

func (b *elfBuilder) writePhdr(out []byte, ph *elfPhdr) []byte {
	e := b.enc
	if e.is64 {
		out = e.u32(out, ph.typ)
		out = e.u32(out, ph.flags)
		out = e.word(out, ph.off)
		out = e.word(out, ph.addr)
		out = e.word(out, ph.addr)
		out = e.word(out, ph.filesz)
		out = e.word(out, ph.filesz)
		return e.word(out, ph.align)
	}
	out = e.u32(out, ph.typ)
	out = e.word(out, ph.off)
	out = e.word(out, ph.addr)
	out = e.word(out, ph.addr)
	out = e.word(out, ph.filesz)
	out = e.word(out, ph.filesz)
	out = e.u32(out, ph.flags)
	return e.word(out, ph.align)
}

func (b *elfBuilder) writeShdr(out []byte, name uint32, p *elfPart, l *elfLayout) []byte {
	e := b.enc
	out = e.u32(out, name)
	out = e.u32(out, p.typ)
	out = e.word(out, p.flags)
	out = e.word(out, p.addr)
	out = e.word(out, p.off)
	out = e.word(out, p.size)
	out = e.u32(out, l.index(p.link))
	out = e.u32(out, p.info)
	out = e.word(out, p.align)
	return e.word(out, p.entsize)
}
