package codeview

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/limits"
)

// Formats of an [Image].
const (
	FormatPE    = "pe"
	FormatELF   = "elf"
	FormatMachO = "macho"
)

// Bounds on what [Detect] reads, so that a crafted header cannot make it read
// or allocate much.
const (
	maxPESections    = 256
	maxELFSegments   = 128
	maxMachOCommands = 4096
	maxMachOBytes    = 256 << 10
	maxFatSlices     = 20
)

// Image says what the headers of a file tell about how its bytes map into
// memory and which instruction set they are for. The zero value stands for a
// file that is none of PE, ELF or Mach-O.
type Image struct {
	// Format is [FormatPE], [FormatELF] or [FormatMachO]; empty for any other file.
	Format string
	// Arch is the instruction set the header declares: [ArchX86], [ArchX8664] or
	// another name such as "ARM64" (which this package does not decode).
	Arch string
	// Entry is the virtual address of the entry point, valid when HasEntry is set.
	Entry    uint64
	HasEntry bool
	// Segments are the parts of the file that hold data and have an address, in
	// header order.
	Segments []Segment

	// layout is the address map of a PE image. A PE is mapped by the layout its
	// parser builds (the one the findings use), never by a second reading of its
	// headers: Segments only lists what the layout maps.
	layout *pe.Layout
}

// Segment is one section (PE, Mach-O) or loadable segment (ELF) that has data
// in the file.
type Segment struct {
	// Name is the section name, or "LOAD n (rwx)" for an ELF segment.
	Name string
	// Addr is the virtual address of the first byte.
	Addr uint64
	// Offset is the file offset of the first byte.
	Offset int64
	// Length is the number of bytes of the segment that exist in the file.
	Length int64
	// Exec is true when the header marks the segment as holding code.
	Exec bool
}

// AtAddress finds the segment that holds the virtual address and the file
// offset the address maps to. The first segment that holds it wins, as in the
// loader-tolerant readers elsewhere in the module.
func (im Image) AtAddress(addr uint64) (Segment, int64, bool) {
	if im.layout != nil {
		i, off, ok := im.layout.SectionAtVA(addr)
		if !ok {
			return Segment{}, 0, false
		}
		seg, _ := peSegment(im.layout, i) // the layout found the section, so it has bytes
		return seg, off, true
	}
	for _, s := range im.Segments {
		// Length is never negative (see addSegment), so the conversion is exact.
		if addr >= s.Addr && addr-s.Addr < uint64(s.Length) {
			return s, s.Offset + int64(addr-s.Addr), true
		}
	}
	return Segment{}, 0, false
}

// AtOffset finds the segment that holds the file offset and the virtual address
// the offset maps to.
func (im Image) AtOffset(off int64) (Segment, uint64, bool) {
	if im.layout != nil {
		i, addr, ok := im.layout.SectionAtOffset(off)
		if !ok {
			return Segment{}, 0, false
		}
		seg, _ := peSegment(im.layout, i)
		return seg, addr, true
	}
	for _, s := range im.Segments {
		if off >= s.Offset && off-s.Offset < s.Length {
			// addSegment checked that Addr+Length does not overflow.
			return s, s.Addr + uint64(off-s.Offset), true
		}
	}
	return Segment{}, 0, false
}

// Kind names the format for display: "PE", "ELF", "Mach-O" or "raw bytes".
func (im Image) Kind() string {
	switch im.Format {
	case FormatPE:
		return "PE"
	case FormatELF:
		return "ELF"
	case FormatMachO:
		return "Mach-O"
	}
	return "raw bytes"
}

// Label describes the image for a message: "PE x86-64" or "a file that is not
// a PE, ELF or Mach-O image".
func (im Image) Label() string {
	if im.Format == "" {
		return "a file that is not a PE, ELF or Mach-O image"
	}
	return im.Kind() + " " + im.Arch
}

// addSegment records a segment, dropping one that is empty, lies outside the
// file or whose addresses would wrap around.
func (im *Image) addSegment(s Segment, fileSize int64) {
	if s.Length <= 0 || s.Offset < 0 || s.Offset > fileSize || s.Length > fileSize-s.Offset {
		return
	}
	if _, carry := bits.Add64(s.Addr, uint64(s.Length), 0); carry != 0 { // Length > 0 was checked
		return
	}
	im.Segments = append(im.Segments, s)
}

// Detect reads the headers of the file and returns what it can say about the
// image. It never fails: a file whose headers are missing, damaged or cut off
// gives the zero Image, or an Image that knows the architecture but has no
// segments. It reads the headers and, for a PE, its import tables: never more
// than the structures themselves, whatever the size of the file.
func Detect(r io.ReaderAt, size int64) Image { return detect(r, size, true) }

// detect is Detect; withSlots says whether a PE's import tables are read too,
// which only the notes of a disassembly need.
func detect(r io.ReaderAt, size int64, withSlots bool) Image {
	head, err := binio.ReadUpTo(r, size, 0, 4)
	if err != nil || len(head) < 4 {
		return Image{}
	}
	var (
		im Image
		ok bool
	)
	switch {
	case head[0] == 'M' && head[1] == 'Z':
		im, ok = parsePE(r, size, withSlots)
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		im, ok = parseELF(r, size)
	default:
		im, ok = parseMachO(r, size)
	}
	if !ok {
		return Image{}
	}
	return im
}

// parsePE maps a PE image through the layout the PE parser builds, the one map
// of a PE that the findings use as well: its section table, its entry point and,
// when withSlots is set, the import address table slots.
func parsePE(r io.ReaderAt, size int64, withSlots bool) (Image, bool) {
	// LoadLayout fails only when not even the COFF header is usable, and with a
	// background context it cannot be interrupted.
	l, _ := pe.LoadLayout(context.Background(), r, size, limits.ForSize(size), withSlots)
	if l == nil {
		return Image{}, false
	}
	im := Image{Format: FormatPE, Arch: peArch(l.Machine)}
	if !l.HasOptional {
		return im, true // an object file, or an optional header nobody can read: the machine type is all it says
	}
	im.layout = l
	im.Entry, im.HasEntry = l.Entry, l.HasEntry
	for i := range l.Sections {
		if seg, ok := peSegment(l, i); ok {
			im.Segments = append(im.Segments, seg)
		}
	}
	return im, true
}

// peSegment describes section i of the layout as a segment. It reports false for
// a section that has no bytes in the file (like .bss) or whose addresses would
// wrap around.
func peSegment(l *pe.Layout, i int) (Segment, bool) {
	s := l.Sections[i]
	length := s.Mapped()
	if length <= 0 {
		return Segment{}, false
	}
	addr, carry := bits.Add64(l.ImageBase, uint64(s.RVA), 0)
	if _, end := bits.Add64(addr, uint64(length), 0); carry != 0 || end != 0 { // length > 0 was checked
		return Segment{}, false
	}
	return Segment{Name: s.Name, Addr: addr, Offset: int64(s.RawOffset), Length: length, Exec: s.Executable()}, true
}

// peArch names the machine type of a PE image.
func peArch(machine uint16) string {
	switch machine {
	case 0x14c:
		return ArchX86
	case 0x8664:
		return ArchX8664
	}
	if name := pe.MachineName(machine); !strings.HasPrefix(name, "0x") {
		return name
	}
	return fmt.Sprintf("machine 0x%04x", machine)
}

// parseELF reads the ELF header and the PT_LOAD program headers.
func parseELF(r io.ReaderAt, size int64) (Image, bool) {
	ident, err := binio.ReadAt(r, size, 0, 16)
	if err != nil {
		return Image{}, false
	}
	var order binary.ByteOrder
	switch ident[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return Image{}, false
	}
	var is64 bool
	hdrLen := int64(52)
	switch ident[4] {
	case 1:
	case 2:
		is64, hdrLen = true, 64
	default:
		return Image{}, false
	}
	h, err := binio.ReadAt(r, size, 0, hdrLen)
	if err != nil {
		return Image{}, false
	}
	im := Image{Format: FormatELF, Arch: elfArch(order.Uint16(h[18:]))}
	var phoff uint64
	var phentsize, phnum uint16
	if is64 {
		im.Entry, phoff = order.Uint64(h[24:]), order.Uint64(h[32:])
		phentsize, phnum = order.Uint16(h[54:]), order.Uint16(h[56:])
	} else {
		im.Entry, phoff = uint64(order.Uint32(h[24:])), uint64(order.Uint32(h[28:]))
		phentsize, phnum = order.Uint16(h[42:]), order.Uint16(h[44:])
	}
	im.HasEntry = im.Entry != 0

	minEnt := int64(32)
	if is64 {
		minEnt = 56
	}
	if phnum == 0 || int64(phentsize) < minEnt || phoff >= uint64(size) { // size >= 16 here, so the conversion is exact
		return im, true
	}
	ent := int64(phentsize)
	n := min(int64(phnum), maxELFSegments, (size-int64(phoff))/ent)
	table, err := binio.ReadUpTo(r, size, int64(phoff), n*ent)
	if err != nil {
		return im, true
	}
	loads := 0
	for i := int64(0); (i+1)*ent <= int64(len(table)); i++ {
		p := table[i*ent : (i+1)*ent]
		var kind, flags uint32
		var off, vaddr, filesz uint64
		if is64 {
			kind, flags = order.Uint32(p), order.Uint32(p[4:])
			off, vaddr, filesz = order.Uint64(p[8:]), order.Uint64(p[16:]), order.Uint64(p[32:])
		} else {
			kind, flags = order.Uint32(p), order.Uint32(p[24:])
			off, vaddr, filesz = uint64(order.Uint32(p[4:])), uint64(order.Uint32(p[8:])), uint64(order.Uint32(p[16:]))
		}
		if kind != 1 { // PT_LOAD
			continue
		}
		name := fmt.Sprintf("LOAD %d (%s)", loads, elfPerms(flags))
		loads++
		if off >= uint64(size) {
			continue
		}
		im.addSegment(Segment{
			Name:   name,
			Addr:   vaddr,
			Offset: int64(off), // off < size
			Length: int64(min(filesz, uint64(size)-off)),
			Exec:   flags&1 != 0,
		}, size)
	}
	return im, true
}

// elfPerms renders the p_flags of a program header as "r-x".
func elfPerms(flags uint32) string {
	perm := []byte("---")
	if flags&4 != 0 {
		perm[0] = 'r'
	}
	if flags&2 != 0 {
		perm[1] = 'w'
	}
	if flags&1 != 0 {
		perm[2] = 'x'
	}
	return string(perm)
}

// elfArch names the e_machine of an ELF file.
func elfArch(machine uint16) string {
	switch machine {
	case 3:
		return ArchX86
	case 62:
		return ArchX8664
	}
	names := map[uint16]string{
		2: "SPARC", 4: "68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM", 42: "SuperH",
		43: "SPARC64", 183: "ARM64", 243: "RISC-V", 258: "LoongArch",
	}
	if name, ok := names[machine]; ok {
		return name
	}
	return fmt.Sprintf("machine %d", machine)
}

// parseMachO reads a thin Mach-O image or, in a universal file, the slice for
// x86-64 (else x86, else the first one).
func parseMachO(r io.ReaderAt, size int64) (Image, bool) {
	head, err := binio.ReadUpTo(r, size, 0, 8)
	if err != nil || len(head) < 8 {
		return Image{}, false
	}
	if binary.BigEndian.Uint32(head) == 0xcafebabe {
		return parseFat(r, size, int64(binary.BigEndian.Uint32(head[4:])))
	}
	return parseThin(r, size, 0, size)
}

// parseFat picks a slice of a universal binary. A count above maxFatSlices is
// how a Java class file (same magic number) shows itself.
func parseFat(r io.ReaderAt, size, count int64) (Image, bool) {
	if count < 1 || count > maxFatSlices {
		return Image{}, false
	}
	raw, err := binio.ReadAt(r, size, 8, count*20)
	if err != nil {
		return Image{}, false
	}
	be := binary.BigEndian
	type slice struct{ cpu, off, length int64 }
	var found []slice
	for i := int64(0); i < count; i++ {
		e := raw[i*20 : (i+1)*20]
		s := slice{cpu: int64(be.Uint32(e)), off: int64(be.Uint32(e[8:])), length: int64(be.Uint32(e[12:]))}
		if s.length > 0 && s.off <= size && s.length <= size-s.off {
			found = append(found, s)
		}
	}
	if len(found) == 0 {
		return Image{}, false
	}
	pick := found[0]
	for _, want := range []int64{0x01000007, 7} { // x86-64, then x86
		matched := false
		for _, s := range found {
			if s.cpu == want {
				pick, matched = s, true
				break
			}
		}
		if matched {
			break
		}
	}
	return parseThin(r, size, pick.off, pick.length)
}

// parseThin reads the Mach-O image that occupies [base, base+length) of the file.
func parseThin(r io.ReaderAt, fileSize, base, length int64) (Image, bool) {
	sr := io.NewSectionReader(r, base, length)
	head, err := binio.ReadUpTo(sr, length, 0, 32)
	if err != nil || len(head) < 28 {
		return Image{}, false
	}
	var order binary.ByteOrder
	var is64 bool
	switch binary.LittleEndian.Uint32(head) {
	case 0xfeedface:
		order = binary.LittleEndian
	case 0xfeedfacf:
		order, is64 = binary.LittleEndian, true
	case 0xcefaedfe:
		order = binary.BigEndian
	case 0xcffaedfe:
		order, is64 = binary.BigEndian, true
	default:
		return Image{}, false
	}
	hdrLen := int64(28)
	if is64 {
		hdrLen = 32
		if len(head) < 32 {
			return Image{}, false
		}
	}
	im := Image{Format: FormatMachO, Arch: machoArch(order.Uint32(head[4:]))}
	ncmds, cmdsSize := int64(order.Uint32(head[16:])), int64(order.Uint32(head[20:]))
	cmds, err := binio.ReadUpTo(sr, length, hdrLen, min(cmdsSize, maxMachOBytes))
	if err != nil {
		return im, true
	}
	var entryOff uint64
	haveMain := false
	pos := int64(0)
	for i := int64(0); i < min(ncmds, maxMachOCommands) && pos+8 <= int64(len(cmds)); i++ {
		cmd, size := order.Uint32(cmds[pos:]), int64(order.Uint32(cmds[pos+4:]))
		if size < 8 || size > int64(len(cmds))-pos {
			break
		}
		body := cmds[pos : pos+size]
		pos += size
		switch cmd {
		case 0x1, 0x19: // LC_SEGMENT, LC_SEGMENT_64
			machoSections(&im, body, order, cmd == 0x19, base, length, fileSize)
		case 0x80000028: // LC_MAIN
			if len(body) >= 16 {
				entryOff, haveMain = order.Uint64(body[8:]), true
			}
		}
	}
	if haveMain && entryOff < uint64(length) {
		if _, addr, ok := im.AtOffset(base + int64(entryOff)); ok { // entryOff < length
			im.Entry, im.HasEntry = addr, true
		}
	}
	return im, true
}

// machoSections adds the file-backed sections of one segment command.
func machoSections(im *Image, body []byte, order binary.ByteOrder, is64 bool, base, length, fileSize int64) {
	headLen, secLen := 56, 68
	if is64 {
		headLen, secLen = 72, 80
	}
	if len(body) < headLen {
		return
	}
	count := min(int(order.Uint32(body[headLen-8:])), (len(body)-headLen)/secLen, maxPESections)
	for i := range count {
		s := body[headLen+i*secLen : headLen+(i+1)*secLen]
		var addr, size uint64
		var off uint32
		var flags uint32
		if is64 {
			addr, size, off, flags = order.Uint64(s[32:]), order.Uint64(s[40:]), order.Uint32(s[48:]), order.Uint32(s[64:])
		} else {
			addr, size, off, flags = uint64(order.Uint32(s[32:])), uint64(order.Uint32(s[36:])), order.Uint32(s[40:]), order.Uint32(s[56:])
		}
		switch flags & 0xff {
		case 0x1, 0xc, 0x12: // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL: no data in the file
			continue
		}
		if int64(off) >= length {
			continue
		}
		im.addSegment(Segment{
			Name:   binio.FixedString(s[16:32]) + "," + binio.FixedString(s[:16]),
			Addr:   addr,
			Offset: base + int64(off),
			Length: int64(min(size, uint64(length-int64(off)))), // off < length, so the difference is positive
			Exec:   flags&(0x80000000|0x400) != 0,               // S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS
		}, fileSize)
	}
}

// machoArch names the cpu type of a Mach-O image.
func machoArch(cpu uint32) string {
	switch cpu {
	case 7:
		return ArchX86
	case 0x01000007:
		return ArchX8664
	}
	names := map[uint32]string{
		12: "ARM", 0x0100000c: "ARM64", 0x0200000c: "ARM64_32", 18: "PowerPC", 0x01000012: "PowerPC64",
	}
	if name, ok := names[cpu]; ok {
		return name
	}
	return fmt.Sprintf("cpu 0x%x", cpu)
}
