package pe

import "math/bits"

// scnCntCode is IMAGE_SCN_CNT_CODE: the section contains executable code.
const scnCntCode = 0x00000020

// Layout says where the bytes of an image live and which import address table
// slot belongs to each imported function. It is what a code scan needs to turn
// a virtual address into a file offset (and back) and to recognise a
// reference to an import. It is built from the same bounded walk as the import
// lists, so it never holds more than the report lists do.
type Layout struct {
	// Machine is the COFF machine type: 0x8664 for x86-64, 0x14c for x86.
	Machine uint16
	// Bits is 32 for PE32 and 64 for PE32+.
	Bits int
	// ImageBase is the preferred load address.
	ImageBase uint64
	// HasOptional is true when the image has an optional header. Without one (an
	// object file) the sections have no addresses and ImageBase is zero.
	HasOptional bool
	// Entry is the virtual address of the entry point, valid when HasEntry is set:
	// the image has an optional header that names one.
	Entry    uint64
	HasEntry bool
	// Sections is the section table in file order (at most as many entries as the
	// report lists).
	Sections []Section
	// Slots lists the import address table slots of the recorded imported
	// functions, library by library, in table order: regular imports first, then
	// delay-load imports. A function whose slot could not be located is absent.
	Slots []ImportSlot
}

// Section is one entry of the section table.
type Section struct {
	// Name is the section name.
	Name string
	// RVA is the relative virtual address of the first byte.
	RVA uint32
	// VirtualSize and RawSize are the sizes the section table declares.
	VirtualSize uint32
	RawSize     uint32
	// RawOffset is the file offset of the raw data.
	RawOffset uint32
	// RawLen is the number of raw bytes that exist in the file: RawSize cut short
	// by the end of the file.
	RawLen int64
	// Characteristics are the IMAGE_SCN_* flags.
	Characteristics uint32
}

// Executable reports whether the section holds code: it is marked executable or
// as containing code.
func (s Section) Executable() bool { return s.Characteristics&(scnMemExecute|scnCntCode) != 0 }

// Mapped returns the number of bytes of the section that the loader maps from
// the file and that exist in it: the raw bytes, cut at the virtual size when the
// section declares one (the rest of the raw data is file padding).
func (s Section) Mapped() int64 {
	if s.VirtualSize != 0 {
		return min(s.RawLen, int64(s.VirtualSize))
	}
	return s.RawLen
}

// ImportSlot is one entry of an import address table: the pointer-sized cell
// the loader fills with the address of an imported function and through which
// compiled code calls it.
type ImportSlot struct {
	// RVA is the relative virtual address of the slot and VA its virtual address
	// at the preferred image base.
	RVA uint32
	VA  uint64
	// Library is the library name as Result.Imports lists it (delay-load
	// libraries carry the " (delay-load)" suffix) and Function the name as listed
	// there; an import by ordinal reads "#N".
	Library  string
	Function string
	// Delay is true for a delay-load import.
	Delay bool
}

// Display returns "Library!Function", the form the rules and the code views use.
func (s ImportSlot) Display() string { return s.Library + "!" + s.Function }

// SectionAtVA returns the index of the section whose mapped bytes hold the
// virtual address, and the file offset the address maps to. The first section
// that holds it wins, as in the parser's own address translation.
func (l *Layout) SectionAtVA(va uint64) (idx int, off int64, ok bool) {
	if va < l.ImageBase {
		return 0, 0, false
	}
	rel := va - l.ImageBase
	if rel > uint64(^uint32(0)) {
		return 0, 0, false
	}
	rva := uint32(rel) // checked above
	for i := range l.Sections {
		s := &l.Sections[i]
		if rva < s.RVA {
			continue
		}
		if d := int64(rva - s.RVA); d < s.Mapped() {
			return i, int64(s.RawOffset) + d, true
		}
	}
	return 0, 0, false
}

// SectionAtOffset returns the index of the section whose mapped bytes hold the
// file offset, and the virtual address the offset maps to.
func (l *Layout) SectionAtOffset(off int64) (idx int, va uint64, ok bool) {
	for i := range l.Sections {
		s := &l.Sections[i]
		d := off - int64(s.RawOffset)
		if d < 0 || d >= s.Mapped() {
			continue
		}
		sum, carry := bits.Add64(l.ImageBase, uint64(s.RVA), 0)
		if carry != 0 {
			return 0, 0, false
		}
		return i, sum + uint64(d), true // d is not negative
	}
	return 0, 0, false
}

// SlotAt returns the import slot whose virtual address is va.
func (l *Layout) SlotAt(va uint64) (ImportSlot, bool) {
	for _, s := range l.Slots {
		if s.VA == va {
			return s, true
		}
	}
	return ImportSlot{}, false
}

// layout builds the Layout of the parsed image.
func (p *parser) layout() Layout {
	l := Layout{
		Machine:     p.h.machine,
		Bits:        p.bits(),
		ImageBase:   p.h.imageBase,
		HasOptional: p.h.hasOpt,
		Entry:       p.h.imageBase + uint64(p.h.entry),
		HasEntry:    p.h.hasOpt && p.h.entry != 0,
		Sections:    make([]Section, 0, len(p.secs)),
		Slots:       append([]ImportSlot{}, p.slots...),
	}
	for _, s := range p.secs {
		l.Sections = append(l.Sections, Section{
			Name: s.name, RVA: s.virtualAddr, VirtualSize: s.virtualSize, RawSize: s.rawSize,
			RawOffset: s.rawPtr, RawLen: s.rawLen(p.size), Characteristics: s.chars,
		})
	}
	return l
}

// recordSlot remembers the import slot of function index idx of a library whose
// address table starts at iatRVA. It records nothing when the table is absent or
// the slot would lie beyond the 32-bit address space.
func (p *parser) recordSlot(iatRVA uint32, idx uint64, lib, fn string, delay bool) {
	if iatRVA == 0 {
		return
	}
	width := uint64(4)
	if p.h.pe64 {
		width = 8
	}
	rva, ok := rvaAdd(iatRVA, idx*width)
	if !ok {
		return
	}
	p.slots = append(p.slots, ImportSlot{
		RVA: rva, VA: p.h.imageBase + uint64(rva), Library: lib, Function: fn, Delay: delay,
	})
}
