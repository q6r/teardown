package testfixtures

import (
	"encoding/binary"
	"slices"
)

// CPU types for [MachOOptions].CPU.
const (
	MachOCPUX86   uint32 = 7
	MachOCPUAMD64 uint32 = 0x01000007
	MachOCPUARM   uint32 = 12
	MachOCPUARM64 uint32 = 0x0100000c
)

// File types for [MachOOptions].Type.
const (
	MachOTypeObject  uint32 = 1
	MachOTypeExecute uint32 = 2
	MachOTypeDylib   uint32 = 6
	MachOTypeBundle  uint32 = 8
)

// Header flags for [MachOOptions].AddFlags and DropFlags.
const (
	MachOFlagNoUndefs           uint32 = 0x1
	MachOFlagDyldLink           uint32 = 0x4
	MachOFlagTwoLevel           uint32 = 0x80
	MachOFlagAllowStackExecute  uint32 = 0x20000
	MachOFlagPIE                uint32 = 0x200000
	MachOFlagNoHeapExecute      uint32 = 0x1000000
	machoFlagSubsectionsViaSyms uint32 = 0x2000
)

// Virtual memory protections for [MachOSegment].InitProt and MaxProt.
const (
	MachOProtRead    uint32 = 1
	MachOProtWrite   uint32 = 2
	MachOProtExecute uint32 = 4
)

// MachOSection is one section of a [MachOSegment].
type MachOSection struct {
	Name string
	Data []byte
	// Zerofill makes the section occupy memory but no file space (like __bss);
	// Data then only provides its size.
	Zerofill bool
}

// MachOSegment is one segment with its sections.
type MachOSegment struct {
	Name     string
	InitProt uint32
	MaxProt  uint32 // defaults to InitProt
	Sections []MachOSection
}

// MachOSymbol is one undefined external symbol.
type MachOSymbol struct {
	// Name is the symbol exactly as the symbol table stores it, so C symbols
	// carry a leading underscore ("_printf").
	Name string
	// Ordinal is the 1-based index of the dylib that provides the symbol (two-level
	// namespace); 0 leaves it unspecified.
	Ordinal int
}

// MachOOptions configures [MachO]. The zero value describes a 64-bit
// little-endian x86-64 position independent executable with __PAGEZERO, a
// read-execute __TEXT segment holding a __text section, a read-write __DATA
// segment holding a __data section, and no symbols, dylibs or signature.
type MachOOptions struct {
	// Bits is 32 or 64 (default 64).
	Bits      int
	BigEndian bool
	// CPU defaults to x86_64 (or x86 for 32-bit images); SubCPU is written as is.
	CPU    uint32
	SubCPU uint32
	// Type defaults to MachOTypeExecute.
	Type uint32
	// AddFlags and DropFlags adjust the default header flags: NoUndefs, DyldLink
	// and TwoLevel for every type, plus PIE for executables.
	AddFlags  uint32
	DropFlags uint32

	Dylibs         []string // LC_LOAD_DYLIB
	WeakDylibs     []string // LC_LOAD_WEAK_DYLIB
	ReexportDylibs []string // LC_REEXPORT_DYLIB
	RPaths         []string // LC_RPATH
	InstallName    string   // LC_ID_DYLIB
	UUID           []byte   // 16 bytes => LC_UUID

	// Segments replace the default __TEXT and __DATA segments.
	Segments []MachOSegment
	// TextData is the content of __TEXT,__text (default: NOPs and a RET).
	TextData []byte

	// CodeSignature adds LC_CODE_SIGNATURE with a minimal signature blob.
	CodeSignature bool
	// EncryptionInfo adds LC_ENCRYPTION_INFO(_64) with the given CryptID.
	EncryptionInfo bool
	CryptID        uint32

	Undefined []MachOSymbol // undefined external symbols
	Defined   []string      // defined external symbols (in __text)
	// NoSymtab omits LC_SYMTAB (and LC_DYSYMTAB) even if symbols are given.
	NoSymtab bool

	// BuildPlatform non-zero adds LC_BUILD_VERSION; otherwise VersionMin non-zero
	// adds LC_VERSION_MIN_MACOSX. Versions are packed as 0xMMMMmmpp.
	BuildPlatform uint32
	MinOS         uint32
	SDK           uint32
	VersionMin    uint32
	// Main adds LC_MAIN pointing at __text.
	Main bool
}

type machoSect struct {
	name     string
	segName  string
	data     []byte
	zerofill bool
	offset   uint64
	addr     uint64
}

type machoSeg struct {
	name               string
	initprot, maxprot  uint32
	sects              []*machoSect
	fileoff, filesize  uint64
	vmaddr, vmsize     uint64
	pagezero, linkedit bool
}

type machoBuilder struct {
	opts   MachOOptions
	is64   bool
	order  binary.AppendByteOrder
	cpu    uint32
	typ    uint32
	flags  uint32
	base   uint64
	segs   []*machoSeg
	dylibs []machoDylib

	// __LINKEDIT contents
	nlist      []byte
	strtab     []byte
	symoff     uint64
	stroff     uint64
	sigoff     uint64
	sigsize    uint64
	haveSymtab bool
}

type machoDylib struct {
	cmd  uint32
	name string
}

// Load command numbers used by the builder.
const (
	machoLCSegment       uint32 = 0x1
	machoLCSymtab        uint32 = 0x2
	machoLCDysymtab      uint32 = 0xb
	machoLCLoadDylib     uint32 = 0xc
	machoLCIDDylib       uint32 = 0xd
	machoLCUUID          uint32 = 0x1b
	machoLCCodeSignature uint32 = 0x1d
	machoLCSegment64     uint32 = 0x19
	machoLCEncryption    uint32 = 0x21
	machoLCVersionMinMac uint32 = 0x24
	machoLCEncryption64  uint32 = 0x2c
	machoLCBuildVersion  uint32 = 0x32
	machoLCRPath         uint32 = 0x8000001c
	machoLCLoadWeak      uint32 = 0x80000018
	machoLCReexport      uint32 = 0x8000001f
	machoLCMain          uint32 = 0x80000028
)

// MachO builds a tiny, valid, deterministic thin Mach-O image accepted by
// debug/macho. It is meant to exercise parsers, not to run.
func MachO(opts MachOOptions) []byte {
	b := &machoBuilder{opts: opts}
	b.setup()
	return b.build()
}

func (b *machoBuilder) setup() {
	o := b.opts
	b.is64 = o.Bits != 32
	b.order = binary.LittleEndian
	if o.BigEndian {
		b.order = binary.BigEndian
	}
	b.cpu = o.CPU
	if b.cpu == 0 {
		b.cpu = MachOCPUAMD64
		if !b.is64 {
			b.cpu = MachOCPUX86
		}
	}
	b.typ = o.Type
	if b.typ == 0 {
		b.typ = MachOTypeExecute
	}
	switch b.typ {
	case MachOTypeObject:
		b.flags = machoFlagSubsectionsViaSyms
	case MachOTypeExecute:
		b.flags = MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel | MachOFlagPIE
	default:
		b.flags = MachOFlagNoUndefs | MachOFlagDyldLink | MachOFlagTwoLevel
	}
	b.flags = (b.flags | o.AddFlags) &^ o.DropFlags

	for _, n := range o.Dylibs {
		b.dylibs = append(b.dylibs, machoDylib{machoLCLoadDylib, n})
	}
	for _, n := range o.WeakDylibs {
		b.dylibs = append(b.dylibs, machoDylib{machoLCLoadWeak, n})
	}
	for _, n := range o.ReexportDylibs {
		b.dylibs = append(b.dylibs, machoDylib{machoLCReexport, n})
	}

	if b.typ == MachOTypeExecute {
		pz := uint64(0x100000000)
		b.base = pz
		if !b.is64 {
			pz, b.base = 0x1000, 0x1000
		}
		b.segs = append(b.segs, &machoSeg{name: "__PAGEZERO", vmsize: pz, pagezero: true})
	}
	text := o.TextData
	if text == nil {
		text = append(slices.Repeat([]byte{0x90}, 15), 0xc3)
	}
	segs := o.Segments
	if segs == nil {
		segs = []MachOSegment{
			{Name: "__TEXT", InitProt: MachOProtRead | MachOProtExecute, Sections: []MachOSection{{Name: "__text", Data: text}}},
			{Name: "__DATA", InitProt: MachOProtRead | MachOProtWrite, Sections: []MachOSection{{Name: "__data", Data: []byte("data\x00\x00\x00\x00")}}},
		}
	}
	for _, s := range segs {
		seg := &machoSeg{name: s.Name, initprot: s.InitProt, maxprot: s.MaxProt}
		if seg.maxprot == 0 {
			seg.maxprot = seg.initprot
		}
		for _, sec := range s.Sections {
			seg.sects = append(seg.sects, &machoSect{name: sec.Name, segName: s.Name, data: sec.Data, zerofill: sec.Zerofill})
		}
		b.segs = append(b.segs, seg)
	}
	b.haveSymtab = !o.NoSymtab && (len(o.Undefined) > 0 || len(o.Defined) > 0)
	if b.haveSymtab || o.CodeSignature {
		b.segs = append(b.segs, &machoSeg{name: "__LINKEDIT", initprot: MachOProtRead, maxprot: MachOProtRead, linkedit: true})
	}
}

func (b *machoBuilder) word(out []byte, v uint64) []byte {
	if b.is64 {
		return b.order.AppendUint64(out, v)
	}
	return b.order.AppendUint32(out, uint32(v))
}

func machoName16(s string) []byte {
	out := make([]byte, 16)
	copy(out, s)
	return out
}

func machoAlignUp(v, a uint64) uint64 { return (v + a - 1) / a * a }

// commands encodes every load command; offsets are those currently stored in
// the builder (zero during the sizing pass, which only needs lengths).
func (b *machoBuilder) commands() ([]byte, uint32) {
	o := b.opts
	var out []byte
	var count uint32
	cmdAlign := 4
	if b.is64 {
		cmdAlign = 8
	}
	emit := func(cmd uint32, body []byte) {
		size := 8 + len(body)
		for size%cmdAlign != 0 {
			size++
		}
		out = b.order.AppendUint32(out, cmd)
		out = b.order.AppendUint32(out, uint32(size))
		out = append(out, body...)
		out = append(out, make([]byte, size-8-len(body))...)
		count++
	}
	for _, s := range b.segs {
		var body []byte
		body = append(body, machoName16(s.name)...)
		body = b.word(body, s.vmaddr)
		body = b.word(body, s.vmsize)
		body = b.word(body, s.fileoff)
		body = b.word(body, s.filesize)
		body = b.order.AppendUint32(body, s.maxprot)
		body = b.order.AppendUint32(body, s.initprot)
		body = b.order.AppendUint32(body, uint32(len(s.sects)))
		body = b.order.AppendUint32(body, 0)
		for _, sec := range s.sects {
			body = append(body, machoName16(sec.name)...)
			body = append(body, machoName16(sec.segName)...)
			body = b.word(body, sec.addr)
			body = b.word(body, uint64(len(sec.data)))
			body = b.order.AppendUint32(body, uint32(sec.offset))
			body = b.order.AppendUint32(body, 4) // align 2^4
			body = b.order.AppendUint32(body, 0) // reloff
			body = b.order.AppendUint32(body, 0) // nreloc
			flags := uint32(0)
			switch {
			case sec.zerofill:
				flags = 0x1 // S_ZEROFILL
			case s.initprot&MachOProtExecute != 0:
				flags = 0x80000400 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
			}
			body = b.order.AppendUint32(body, flags)
			body = b.order.AppendUint32(body, 0) // reserved1
			body = b.order.AppendUint32(body, 0) // reserved2
			if b.is64 {
				body = b.order.AppendUint32(body, 0) // reserved3
			}
		}
		cmd := machoLCSegment
		if b.is64 {
			cmd = machoLCSegment64
		}
		emit(cmd, body)
	}
	if b.haveSymtab {
		var body []byte
		body = b.order.AppendUint32(body, uint32(b.symoff))
		body = b.order.AppendUint32(body, uint32(len(b.nlist)/b.nlistSize()))
		body = b.order.AppendUint32(body, uint32(b.stroff))
		body = b.order.AppendUint32(body, uint32(len(b.strtab)))
		emit(machoLCSymtab, body)

		nDef, nUndef := uint32(len(o.Defined)), uint32(len(o.Undefined))
		var dy []byte
		for _, v := range []uint32{0, 0, 0, nDef, nDef, nUndef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} {
			dy = b.order.AppendUint32(dy, v)
		}
		emit(machoLCDysymtab, dy)
	}
	if len(o.UUID) == 16 {
		emit(machoLCUUID, o.UUID)
	}
	switch {
	case o.BuildPlatform != 0:
		var body []byte
		for _, v := range []uint32{o.BuildPlatform, o.MinOS, o.SDK, 0} {
			body = b.order.AppendUint32(body, v)
		}
		emit(machoLCBuildVersion, body)
	case o.VersionMin != 0:
		var body []byte
		body = b.order.AppendUint32(body, o.VersionMin)
		body = b.order.AppendUint32(body, o.SDK)
		emit(machoLCVersionMinMac, body)
	}
	if o.Main {
		var body []byte
		body = b.order.AppendUint64(body, b.textOffset())
		body = b.order.AppendUint64(body, 0)
		emit(machoLCMain, body)
	}
	for _, d := range b.dylibs {
		emit(d.cmd, b.dylibBody(d.name))
	}
	if o.InstallName != "" {
		emit(machoLCIDDylib, b.dylibBody(o.InstallName))
	}
	for _, p := range o.RPaths {
		emit(machoLCRPath, append(b.order.AppendUint32(nil, 12), append([]byte(p), 0)...))
	}
	if o.CodeSignature {
		var body []byte
		body = b.order.AppendUint32(body, uint32(b.sigoff))
		body = b.order.AppendUint32(body, uint32(b.sigsize))
		emit(machoLCCodeSignature, body)
	}
	if o.EncryptionInfo {
		var body []byte
		body = b.order.AppendUint32(body, 0x1000) // cryptoff
		body = b.order.AppendUint32(body, 0x1000) // cryptsize
		body = b.order.AppendUint32(body, o.CryptID)
		cmd := machoLCEncryption
		if b.is64 {
			body = b.order.AppendUint32(body, 0) // pad
			cmd = machoLCEncryption64
		}
		emit(cmd, body)
	}
	return out, count
}

func (b *machoBuilder) dylibBody(name string) []byte {
	var body []byte
	body = b.order.AppendUint32(body, 24) // name offset
	body = b.order.AppendUint32(body, 2)  // timestamp
	body = b.order.AppendUint32(body, 0x010000)
	body = b.order.AppendUint32(body, 0x010000)
	return append(body, append([]byte(name), 0)...)
}

func (b *machoBuilder) nlistSize() int {
	if b.is64 {
		return 16
	}
	return 12
}

// textOffset is the file offset of __text (used by LC_MAIN).
func (b *machoBuilder) textOffset() uint64 {
	for _, s := range b.segs {
		for _, sec := range s.sects {
			if sec.name == "__text" {
				return sec.offset
			}
		}
	}
	return 0
}

func (b *machoBuilder) textAddr() uint64 {
	for _, s := range b.segs {
		for _, sec := range s.sects {
			if sec.name == "__text" {
				return sec.addr
			}
		}
	}
	return 0
}

func (b *machoBuilder) headerSize() uint64 {
	if b.is64 {
		return 32
	}
	return 28
}

func (b *machoBuilder) build() []byte {
	o := b.opts
	// Sizing pass: lengths only.
	b.encodeSymbols()
	sizing, _ := b.commands()
	contentStart := machoAlignUp(b.headerSize()+uint64(len(sizing)), 16)

	// Lay out the segments in file order.
	cursor := contentStart
	first := true
	for _, s := range b.segs {
		switch {
		case s.pagezero:
			continue
		case s.linkedit:
			s.fileoff = machoAlignUp(cursor, 16)
			b.symoff = s.fileoff
			b.stroff = b.symoff + uint64(len(b.nlist))
			end := b.stroff + uint64(len(b.strtab))
			if !b.haveSymtab {
				b.symoff, b.stroff, end = 0, 0, s.fileoff
			}
			if o.CodeSignature {
				b.sigoff = machoAlignUp(end, 16)
				b.sigsize = 16
				end = b.sigoff + b.sigsize
			}
			s.filesize = end - s.fileoff
			s.vmaddr = b.base + s.fileoff
			s.vmsize = machoAlignUp(max(s.filesize, 1), 0x1000)
			cursor = end
			continue
		}
		start := machoAlignUp(cursor, 16)
		pos := start
		if first {
			start, pos = 0, contentStart
			first = false
		}
		s.fileoff = start
		s.vmaddr = b.base + start
		var zero uint64
		for _, sec := range s.sects {
			pos = machoAlignUp(pos, 16)
			if sec.zerofill {
				sec.offset = 0
				sec.addr = s.vmaddr + (pos - start) + zero
				zero += uint64(len(sec.data))
				continue
			}
			sec.offset = pos
			sec.addr = s.vmaddr + (pos - start)
			pos += uint64(len(sec.data))
		}
		s.filesize = pos - start
		s.vmsize = machoAlignUp(max(s.filesize+zero, 1), 0x1000)
		cursor = pos
	}
	b.encodeSymbols() // symbol values depend on the section addresses

	cmds, ncmds := b.commands()
	magic := uint32(0xfeedface)
	if b.is64 {
		magic = 0xfeedfacf
	}
	out := b.order.AppendUint32(nil, magic)
	out = b.order.AppendUint32(out, b.cpu)
	out = b.order.AppendUint32(out, o.SubCPU)
	out = b.order.AppendUint32(out, b.typ)
	out = b.order.AppendUint32(out, ncmds)
	out = b.order.AppendUint32(out, uint32(len(cmds)))
	out = b.order.AppendUint32(out, b.flags)
	if b.is64 {
		out = b.order.AppendUint32(out, 0)
	}
	out = append(out, cmds...)
	for _, s := range b.segs {
		for _, sec := range s.sects {
			if sec.zerofill {
				continue
			}
			out = append(out, make([]byte, sec.offset-uint64(len(out)))...)
			out = append(out, sec.data...)
		}
	}
	if b.haveSymtab {
		out = append(out, make([]byte, b.symoff-uint64(len(out)))...)
		out = append(out, b.nlist...)
		out = append(out, b.strtab...)
	}
	if o.CodeSignature {
		out = append(out, make([]byte, b.sigoff-uint64(len(out)))...)
		// A minimal embedded-signature SuperBlob: magic, length, zero blobs.
		out = binary.BigEndian.AppendUint32(out, 0xfade0cc0)
		out = binary.BigEndian.AppendUint32(out, 12)
		out = binary.BigEndian.AppendUint32(out, 0)
		out = append(out, 0)
	}
	return out
}

// encodeSymbols builds the nlist table and string table.
func (b *machoBuilder) encodeSymbols() {
	b.nlist, b.strtab = nil, []byte{0}
	if !b.haveSymtab {
		return
	}
	add := func(name string) uint32 {
		off := uint32(len(b.strtab))
		b.strtab = append(append(b.strtab, name...), 0)
		return off
	}
	entry := func(strx uint32, typ, sect uint8, desc uint16, value uint64) {
		b.nlist = b.order.AppendUint32(b.nlist, strx)
		b.nlist = append(b.nlist, typ, sect)
		b.nlist = b.order.AppendUint16(b.nlist, desc)
		b.nlist = b.word(b.nlist, value)
	}
	for _, name := range b.opts.Defined {
		entry(add(name), 0x0f, 1, 0, b.textAddr()) // N_EXT | N_SECT, section 1
	}
	for _, sym := range b.opts.Undefined {
		entry(add(sym.Name), 0x01, 0, uint16(sym.Ordinal)<<8, 0) // N_EXT | N_UNDF
	}
}

// MachOFat wraps thin Mach-O images (as returned by [MachO]) in a big-endian
// universal ("fat") container with 4 KiB alignment.
func MachOFat(thin ...[]byte) []byte {
	const align = 12
	header := 8 + 20*uint64(len(thin))
	out := binary.BigEndian.AppendUint32(nil, 0xcafebabe)
	out = binary.BigEndian.AppendUint32(out, uint32(len(thin)))
	offset := machoAlignUp(header, 1<<align)
	offsets := make([]uint64, len(thin))
	for i, s := range thin {
		offsets[i] = offset
		var cpu, sub uint32
		if len(s) >= 12 {
			order := binary.ByteOrder(binary.LittleEndian)
			if s[0] == 0xfe { // big-endian magic bytes fe ed fa ce/cf
				order = binary.BigEndian
			}
			cpu, sub = order.Uint32(s[4:]), order.Uint32(s[8:])
		}
		out = binary.BigEndian.AppendUint32(out, cpu)
		out = binary.BigEndian.AppendUint32(out, sub)
		out = binary.BigEndian.AppendUint32(out, uint32(offset))
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = binary.BigEndian.AppendUint32(out, align)
		offset = machoAlignUp(offset+uint64(len(s)), 1<<align)
	}
	for i, s := range thin {
		out = append(out, make([]byte, offsets[i]-uint64(len(out)))...)
		out = append(out, s...)
	}
	return out
}
