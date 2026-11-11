package testfixtures

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
)

// Section characteristic presets for [PESection].Characteristics.
const (
	// PESectionCode is a readable, executable code section.
	PESectionCode uint32 = 0x60000020
	// PESectionRData is a readable, initialised data section.
	PESectionRData uint32 = 0x40000040
	// PESectionData is a readable, writable, initialised data section.
	PESectionData uint32 = 0xC0000040
	// PESectionRWX is a readable, writable, executable code section.
	PESectionRWX uint32 = 0xE0000020
	// PESectionBSS is a readable, writable, uninitialised data section.
	PESectionBSS uint32 = 0xC0000080
)

// DllCharacteristics bits for [PEOptions].DllCharsSet and DllCharsClear.
const (
	PEDllHighEntropyVA  uint16 = 0x0020
	PEDllDynamicBase    uint16 = 0x0040
	PEDllForceIntegrity uint16 = 0x0080
	PEDllNXCompat       uint16 = 0x0100
	PEDllNoSEH          uint16 = 0x0400
	PEDllGuardCF        uint16 = 0x4000
)

// COFF characteristics bits for [PEOptions].CharsSet and CharsClear.
const (
	PECharRelocsStripped    uint16 = 0x0001
	PECharLargeAddressAware uint16 = 0x0020
)

// Fixed layout of every PE fixture.
const (
	// PEOffset is the file offset of the "PE\0\0" signature (the DOS header and
	// stub occupy the first 0x80 bytes).
	PEOffset = 0x80
	// PEOptionalOffset is the file offset of the optional header.
	PEOptionalOffset = PEOffset + 24

	peTextVA     = 0x1000
	peRDataVA    = 0x2000
	peTextSize   = 0x200
	peFileAlign  = 0x200
	peSectAlign  = 0x1000
	peSecHdrSize = 40
)

// PEImport is one library imported by a fixture.
type PEImport struct {
	// Library is the DLL name, for example "kernel32.dll".
	Library string
	// Functions are the imported names; an entry such as "#23" imports by ordinal.
	Functions []string
}

// PEExport is one named export of a fixture DLL.
type PEExport struct {
	Name string
	// Forwarder, when set, turns the export into a forwarder such as
	// "NTDLL.RtlAllocateHeap".
	Forwarder string
}

// PESection is an extra section appended after .text, .rdata and .data.
type PESection struct {
	// Name is the section name. Names longer than 8 bytes are stored in the COFF
	// string table and referenced as "/N", like real linkers do for DWARF data.
	Name string
	// Data is the raw content (ignored when NoRaw is set).
	Data []byte
	// Characteristics are the IMAGE_SCN_* flags; 0 means [PESectionData].
	Characteristics uint32
	// VirtualSize is the in-memory size; 0 means len(Data) (or 0x1000 with NoRaw).
	VirtualSize uint32
	// NoRaw gives the section no file data (SizeOfRawData = 0), like .bss or UPX0.
	NoRaw bool
}

// PEOptions configures [PE]. The zero value yields a minimal, valid 64-bit
// console executable with .text, .rdata and .data sections that imports
// ExitProcess from kernel32.dll.
type PEOptions struct {
	// Bits selects PE32 (32) or PE32+ (anything else, default 64).
	Bits int
	// DLL builds a library (IMAGE_FILE_DLL, windows-gui subsystem).
	DLL bool
	// Driver builds a kernel-mode driver (IMAGE_FILE_SYSTEM, native subsystem,
	// imports ntoskrnl.exe by default).
	Driver bool
	// Machine overrides the machine type (default x86-64 or x86 by Bits).
	Machine uint16
	// Subsystem overrides the subsystem (default 3 console, 2 for DLLs, 1 for drivers).
	Subsystem uint16
	// Timestamp is IMAGE_FILE_HEADER.TimeDateStamp.
	Timestamp uint32
	// ImageBase overrides the preferred load address.
	ImageBase uint64
	// CharsSet and CharsClear adjust the default COFF characteristics.
	CharsSet, CharsClear uint16
	// DllCharsSet and DllCharsClear adjust the default DllCharacteristics
	// (DYNAMIC_BASE, NX_COMPAT, TERMINAL_SERVER_AWARE and, for PE32+, HIGH_ENTROPY_VA).
	DllCharsSet, DllCharsClear uint16

	// Imports replaces the default import list; NoImports removes the import table.
	Imports   []PEImport
	NoImports bool
	// DelayImports adds a delay-load import table.
	DelayImports []PEImport
	// Exports and ExportOrdinalOnly build an export table (named exports, then
	// that many exports without a name).
	Exports           []PEExport
	ExportOrdinalOnly int
	// ExportDLLName is the name stored in the export directory (default "fixture.dll").
	ExportDLLName string

	// PDBPath adds a CodeView (RSDS) debug directory entry with this path.
	PDBPath string
	// Signed appends an Authenticode-style WIN_CERTIFICATE (not a real signature)
	// and points the security directory at it.
	Signed bool
	// Overlay is appended after the last section (before the certificate).
	Overlay []byte
	// DotNet adds a CLR runtime header with DotNetVersion (default "v4.0.30319")
	// in the metadata root and imports mscoree.dll by default.
	DotNet        bool
	DotNetVersion string
	// TLSCallbacks adds a TLS directory with that many callbacks.
	TLSCallbacks int
	// SafeSEH adds a load configuration with a SafeSEH handler table (PE32 only).
	SafeSEH bool
	// GuardCF adds a load configuration with control-flow-guard flags and sets
	// IMAGE_DLLCHARACTERISTICS_GUARD_CF.
	GuardCF bool
	// SecurityCookie adds a load configuration with a non-zero /GS cookie address.
	SecurityCookie bool
	// Sections are extra sections placed after .data.
	Sections []PESection
	// Calls adds a small x86-64 stub to .text that calls the listed imports the way
	// compilers do: a stack frame, the arguments set up with mov, xor and lea,
	// then a call through the import address table slot (or through a thunk). The
	// stub starts at offset 0x10, behind the entry point's "xor eax, eax; ret", so
	// the image does nothing when started: the stub is dead code that is only meant
	// to be read. It works on a 64-bit image only.
	Calls []PECall
}

// PEDataDirectoryOffset returns the file offset of data directory entry index
// (0 = export, 1 = import, 4 = security, ...) in a fixture with the given bit width.
func PEDataDirectoryOffset(bits, index int) int {
	base := PEOptionalOffset + 112
	if bits == 32 {
		base = PEOptionalOffset + 96
	}
	return base + 8*index
}

// PESectionHeaderOffset returns the file offset of section header i in a
// fixture with the given bit width.
func PESectionHeaderOffset(bits, i int) int {
	opt := 240
	if bits == 32 {
		opt = 224
	}
	return PEOptionalOffset + opt + peSecHdrSize*i
}

type peConfig struct {
	o         PEOptions
	pe64      bool
	machine   uint16
	subsystem uint16
	chars     uint16
	dllChars  uint16
	imageBase uint64
	imports   []PEImport
}

func peResolve(o PEOptions) peConfig {
	c := peConfig{o: o, pe64: o.Bits != 32}
	c.machine = o.Machine
	if c.machine == 0 {
		c.machine = 0x14c
		if c.pe64 {
			c.machine = 0x8664
		}
	}
	c.subsystem = o.Subsystem
	if c.subsystem == 0 {
		switch {
		case o.Driver:
			c.subsystem = 1
		case o.DLL:
			c.subsystem = 2
		default:
			c.subsystem = 3
		}
	}
	chars := uint16(0x0022)
	if !c.pe64 {
		chars = 0x0122
	}
	if o.DLL {
		chars |= 0x2000
	}
	if o.Driver {
		chars |= 0x1000
	}
	c.chars = (chars | o.CharsSet) &^ o.CharsClear
	dll := uint16(0x8140)
	if c.pe64 {
		dll |= 0x0020
	}
	if o.GuardCF {
		dll |= PEDllGuardCF
	}
	c.dllChars = (dll | o.DllCharsSet) &^ o.DllCharsClear
	c.imageBase = o.ImageBase
	if c.imageBase == 0 {
		switch {
		case c.pe64 && o.DLL:
			c.imageBase = 0x180000000
		case c.pe64:
			c.imageBase = 0x140000000
		case o.DLL:
			c.imageBase = 0x10000000
		default:
			c.imageBase = 0x400000
		}
	}
	switch {
	case o.NoImports:
	case len(o.Imports) > 0:
		c.imports = o.Imports
	case o.DotNet && o.DLL:
		c.imports = []PEImport{{Library: "mscoree.dll", Functions: []string{"_CorDllMain"}}}
	case o.DotNet:
		c.imports = []PEImport{{Library: "mscoree.dll", Functions: []string{"_CorExeMain"}}}
	case o.Driver:
		c.imports = []PEImport{{Library: "ntoskrnl.exe", Functions: []string{"IoCreateDevice", "DbgPrint"}}}
	default:
		c.imports = []PEImport{{Library: "kernel32.dll", Functions: []string{"ExitProcess"}}}
	}
	return c
}

type peDir struct{ rva, size uint32 }

// peBlob accumulates the .rdata section, which hosts every directory structure.
type peBlob struct {
	base  uint32 // RVA of the blob
	raw   uint32 // file offset of the blob
	buf   []byte
	dirs  [16]peDir
	slots []peSlot // the address table slots of the regular imports
}

func (b *peBlob) here() uint32 { return b.base + uint32(len(b.buf)) }

func (b *peBlob) hereRaw() uint32 { return b.raw + uint32(len(b.buf)) }

func (b *peBlob) pad(align int) {
	for len(b.buf)%align != 0 {
		b.buf = append(b.buf, 0)
	}
}

func (b *peBlob) reserve(n int) int {
	off := len(b.buf)
	b.buf = append(b.buf, make([]byte, n)...)
	return off
}

func (b *peBlob) u16(v uint16) { b.buf = binary.LittleEndian.AppendUint16(b.buf, v) }

func (b *peBlob) u32(v uint32) { b.buf = binary.LittleEndian.AppendUint32(b.buf, v) }

func (b *peBlob) u64(v uint64) { b.buf = binary.LittleEndian.AppendUint64(b.buf, v) }

func (b *peBlob) str(s string) { b.buf = append(append(b.buf, s...), 0) }

func (b *peBlob) set16(off int, v uint16) { binary.LittleEndian.PutUint16(b.buf[off:], v) }

func (b *peBlob) set32(off int, v uint32) { binary.LittleEndian.PutUint32(b.buf[off:], v) }

func (b *peBlob) set64(off int, v uint64) { binary.LittleEndian.PutUint64(b.buf[off:], v) }

func peOrdinal(fn string) (uint16, bool) {
	if !strings.HasPrefix(fn, "#") {
		return 0, false
	}
	n, err := strconv.ParseUint(fn[1:], 10, 16)
	return uint16(n), err == nil
}

// library writes the hint/name entries, the DLL name, the import name table
// (INT) and the import address table (IAT) of one library.
func (b *peBlob) library(lib PEImport, pe64 bool) (nameRVA, intRVA, iatRVA uint32) {
	entries := make([]uint64, 0, len(lib.Functions))
	for _, fn := range lib.Functions {
		if ord, ok := peOrdinal(fn); ok {
			if pe64 {
				entries = append(entries, 1<<63|uint64(ord))
			} else {
				entries = append(entries, 1<<31|uint64(ord))
			}
			continue
		}
		b.pad(2)
		entries = append(entries, uint64(b.here()))
		b.u16(0)
		b.str(fn)
	}
	nameRVA = b.here()
	b.str(lib.Library)
	b.pad(8)
	intRVA = b.here()
	b.thunks(entries, pe64)
	iatRVA = b.here()
	b.thunks(entries, pe64)
	return nameRVA, intRVA, iatRVA
}

func (b *peBlob) thunks(entries []uint64, pe64 bool) {
	for _, e := range entries {
		if pe64 {
			b.u64(e)
		} else {
			b.u32(uint32(e))
		}
	}
	if pe64 {
		b.u64(0)
	} else {
		b.u32(0)
	}
}

func (b *peBlob) importTable(libs []PEImport, pe64 bool) peDir {
	size := (len(libs) + 1) * 20
	desc := b.reserve(size)
	width := uint32(4)
	if pe64 {
		width = 8
	}
	for i, lib := range libs {
		nameRVA, intRVA, iatRVA := b.library(lib, pe64)
		b.set32(desc+i*20, intRVA)
		b.set32(desc+i*20+12, nameRVA)
		b.set32(desc+i*20+16, iatRVA)
		for j, fn := range lib.Functions {
			b.slots = append(b.slots, peSlot{library: lib.Library, function: fn, rva: iatRVA + uint32(j)*width})
		}
	}
	return peDir{b.base + uint32(desc), uint32(size)}
}

func (b *peBlob) delayTable(libs []PEImport, pe64 bool, handleRVA uint32) peDir {
	size := (len(libs) + 1) * 32
	desc := b.reserve(size)
	for i, lib := range libs {
		nameRVA, intRVA, iatRVA := b.library(lib, pe64)
		o := desc + i*32
		b.set32(o, 1) // Attributes: RVA based
		b.set32(o+4, nameRVA)
		b.set32(o+8, handleRVA)
		b.set32(o+12, iatRVA)
		b.set32(o+16, intRVA)
	}
	return peDir{b.base + uint32(desc), uint32(size)}
}

func (b *peBlob) exportTable(o PEOptions) peDir {
	named := append([]PEExport(nil), o.Exports...)
	sort.SliceStable(named, func(i, j int) bool { return named[i].Name < named[j].Name })
	nFuncs := len(named) + o.ExportOrdinalOnly
	dll := o.ExportDLLName
	if dll == "" {
		dll = "fixture.dll"
	}
	start := len(b.buf)
	hdr := b.reserve(40)
	funcs := b.reserve(4 * nFuncs)
	names := b.reserve(4 * len(named))
	ords := b.reserve(2 * len(named))
	dllRVA := b.here()
	b.str(dll)
	for i, e := range named {
		b.set32(names+4*i, b.here())
		b.str(e.Name)
		b.set16(ords+2*i, uint16(i))
		if e.Forwarder != "" {
			b.set32(funcs+4*i, b.here())
			b.str(e.Forwarder)
		} else {
			b.set32(funcs+4*i, peTextVA+uint32(i%0x100))
		}
	}
	for j := range o.ExportOrdinalOnly {
		b.set32(funcs+4*(len(named)+j), peTextVA+0x80+uint32(j%0x80))
	}
	b.set32(hdr+4, o.Timestamp)
	b.set32(hdr+12, dllRVA)
	b.set32(hdr+16, 1) // ordinal base
	b.set32(hdr+20, uint32(nFuncs))
	b.set32(hdr+24, uint32(len(named)))
	b.set32(hdr+28, b.base+uint32(funcs))
	b.set32(hdr+32, b.base+uint32(names))
	b.set32(hdr+36, b.base+uint32(ords))
	return peDir{b.base + uint32(start), uint32(len(b.buf) - start)}
}

func (b *peBlob) debugTable(o PEOptions) peDir {
	b.pad(4)
	dir := b.reserve(28)
	b.pad(4)
	dataRVA, dataRaw := b.here(), b.hereRaw()
	data := len(b.buf)
	b.buf = append(b.buf, "RSDS"...)
	for i := range 16 {
		b.buf = append(b.buf, byte(0xA0+i))
	}
	b.u32(1)
	b.str(o.PDBPath)
	size := uint32(len(b.buf) - data)
	b.set32(dir+4, o.Timestamp)
	b.set32(dir+12, 2) // IMAGE_DEBUG_TYPE_CODEVIEW
	b.set32(dir+16, size)
	b.set32(dir+20, dataRVA)
	b.set32(dir+24, dataRaw)
	return peDir{b.base + uint32(dir), 28}
}

func (b *peBlob) loadConfig(c peConfig, scratchRVA uint32) peDir {
	b.pad(8)
	size, flagsOff, cookieOff := 0x5C, 88, 60
	if c.pe64 {
		size, flagsOff, cookieOff = 0x94, 144, 88
	}
	off := b.reserve(size)
	b.set32(off, uint32(size))
	if c.o.SecurityCookie {
		va := c.imageBase + uint64(scratchRVA)
		if c.pe64 {
			b.set64(off+cookieOff, va)
		} else {
			b.set32(off+cookieOff, uint32(va))
		}
	}
	if c.o.GuardCF {
		b.set32(off+flagsOff, 0x100|0x400)
	}
	if c.o.SafeSEH && !c.pe64 {
		b.pad(4)
		table := b.here()
		b.u32(peTextVA)
		b.set32(off+64, uint32(c.imageBase)+table)
		b.set32(off+68, 1)
	}
	return peDir{b.base + uint32(off), uint32(size)}
}

func (b *peBlob) tlsTable(c peConfig, scratchRVA uint32) peDir {
	b.pad(8)
	callbacks := b.here()
	for i := range c.o.TLSCallbacks {
		if c.pe64 {
			b.u64(c.imageBase + peTextVA + uint64(i))
		} else {
			b.u32(uint32(c.imageBase) + peTextVA + uint32(i))
		}
	}
	if c.pe64 {
		b.u64(0)
	} else {
		b.u32(0)
	}
	b.pad(8)
	start := b.here()
	if c.pe64 {
		b.u64(c.imageBase + uint64(scratchRVA))
		b.u64(c.imageBase + uint64(scratchRVA) + 8)
		b.u64(c.imageBase + uint64(scratchRVA) + 8)
		b.u64(c.imageBase + uint64(callbacks))
		b.u32(0)
		b.u32(0)
		return peDir{start, 40}
	}
	b.u32(uint32(c.imageBase) + scratchRVA)
	b.u32(uint32(c.imageBase) + scratchRVA + 8)
	b.u32(uint32(c.imageBase) + scratchRVA + 8)
	b.u32(uint32(c.imageBase) + callbacks)
	b.u32(0)
	b.u32(0)
	return peDir{start, 24}
}

func (b *peBlob) clrTable(version string) peDir {
	b.pad(4)
	md := b.here()
	b.buf = append(b.buf, "BSJB"...)
	b.u16(1)
	b.u16(1)
	b.u32(0)
	padded := (len(version) + 1 + 3) &^ 3
	b.u32(uint32(padded))
	b.str(version)
	for i := len(version) + 1; i < padded; i++ {
		b.buf = append(b.buf, 0)
	}
	b.u16(0) // flags
	b.u16(0) // stream count
	mdSize := b.here() - md
	b.pad(4)
	hdr := b.here()
	b.u32(72)
	b.u16(2)
	b.u16(5)
	b.u32(md)
	b.u32(mdSize)
	b.u32(1) // COMIMAGE_FLAGS_ILONLY
	b.u32(0)
	b.buf = append(b.buf, make([]byte, 48)...)
	return peDir{hdr, 72}
}

func (b *peBlob) build(c peConfig) {
	scratch := b.reserve(16)
	scratchRVA := b.base + uint32(scratch)
	if len(c.imports) > 0 {
		b.dirs[1] = b.importTable(c.imports, c.pe64)
	}
	if len(c.o.DelayImports) > 0 {
		b.dirs[13] = b.delayTable(c.o.DelayImports, c.pe64, scratchRVA)
	}
	if len(c.o.Exports) > 0 || c.o.ExportOrdinalOnly > 0 {
		b.dirs[0] = b.exportTable(c.o)
	}
	if c.o.PDBPath != "" {
		b.dirs[6] = b.debugTable(c.o)
	}
	if c.o.SafeSEH || c.o.GuardCF || c.o.SecurityCookie {
		b.dirs[10] = b.loadConfig(c, scratchRVA)
	}
	if c.o.TLSCallbacks > 0 {
		b.dirs[9] = b.tlsTable(c, scratchRVA)
	}
	if c.o.DotNet {
		version := c.o.DotNetVersion
		if version == "" {
			version = "v4.0.30319"
		}
		b.dirs[14] = b.clrTable(version)
	}
}

type peSec struct {
	name                string
	data                []byte
	vsize, chars        uint32
	noRaw               bool
	va, rawPtr, rawSize uint32
	strOff              uint32
	long                bool
}

func peAlign(v, a int) int { return (v + a - 1) / a * a }

func peCode() []byte {
	code := make([]byte, peTextSize)
	for i := range code {
		code[i] = 0xCC
	}
	copy(code, []byte{0x31, 0xC0, 0xC3})
	return code
}

func peDOS() []byte {
	h := make([]byte, PEOffset)
	copy(h, []byte{
		0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
		0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	binary.LittleEndian.PutUint32(h[0x3C:], PEOffset)
	stub := append([]byte{0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21},
		"This program cannot be run in DOS mode.\r\r\n$"...)
	copy(h[0x40:], stub)
	return h
}

func peCertificate() []byte {
	body := []byte("teardown fixture: not a real PKCS#7 signature")
	total := peAlign(8+len(body), 8)
	out := make([]byte, total)
	binary.LittleEndian.PutUint32(out, uint32(total))
	binary.LittleEndian.PutUint16(out[4:], 0x0200)
	binary.LittleEndian.PutUint16(out[6:], 0x0002)
	copy(out[8:], body)
	return out
}

// PE builds a deterministic, minimal but valid Portable Executable image.
//
// Layout: DOS header and stub (0x80 bytes), PE signature at [PEOffset], COFF
// header, optional header (PE32 or PE32+ with 16 data directories), section
// table, then .text (VA 0x1000), .rdata (VA 0x2000, hosting every directory
// structure), .data and the extra sections, followed by the optional COFF
// symbol/string table (only when a section name needs it), the overlay and the
// certificate. File alignment is 0x200 and section alignment 0x1000.
func PE(o PEOptions) []byte {
	c := peResolve(o)
	nSec := 3 + len(o.Sections)
	optSize := 224
	if c.pe64 {
		optSize = 240
	}
	sizeOfHeaders := peAlign(PEOffset+24+optSize+nSec*peSecHdrSize, peFileAlign)

	text := peCode()
	var stub *peStub
	if len(o.Calls) > 0 {
		if !c.pe64 {
			panic("testfixtures: PEOptions.Calls emits x86-64 code and needs a 64-bit image")
		}
		stub = peAssemble(o.Calls)
		text = stub.code
	}
	blob := &peBlob{base: peRDataVA, raw: uint32(sizeOfHeaders + len(text))}
	blob.build(c)

	data := make([]byte, 32)
	copy(data, "teardown-fixture")
	secs := []peSec{
		{name: ".text", data: text, chars: PESectionCode},
		{name: ".rdata", data: blob.buf, chars: PESectionRData},
		{name: ".data", data: data, chars: PESectionData},
	}
	for _, s := range o.Sections {
		ps := peSec{name: s.Name, data: s.Data, chars: s.Characteristics, vsize: s.VirtualSize, noRaw: s.NoRaw}
		if ps.chars == 0 {
			ps.chars = PESectionData
		}
		if ps.noRaw {
			ps.data = nil
		}
		secs = append(secs, ps)
	}

	// Long names go to the COFF string table (offsets start after its 4-byte size).
	strTab := []byte{0, 0, 0, 0}
	for i := range secs {
		if len(secs[i].name) > 8 {
			secs[i].long = true
			secs[i].strOff = uint32(len(strTab))
			strTab = append(append(strTab, secs[i].name...), 0)
		}
	}
	binary.LittleEndian.PutUint32(strTab, uint32(len(strTab)))

	rawPtr, va := uint32(sizeOfHeaders), uint32(peTextVA)
	for i := range secs {
		s := &secs[i]
		if s.vsize == 0 {
			s.vsize = uint32(len(s.data))
			if s.noRaw {
				s.vsize = 0x1000
			}
		}
		s.va = va
		va += uint32(peAlign(int(max(s.vsize, 1)), peSectAlign))
		if !s.noRaw {
			s.rawPtr = rawPtr
			s.rawSize = uint32(peAlign(len(s.data), peFileAlign))
			rawPtr += s.rawSize
		}
	}
	sizeOfImage := va
	if stub != nil {
		stub.patch(peTextVA, secs[2].va, peSlotLookup(blob.slots)) // the code is secs[0].data: patched in place
	}
	end := int(rawPtr)

	var symPtr, nSyms uint32
	hasStrTab := false
	for _, s := range secs {
		hasStrTab = hasStrTab || s.long
	}
	if hasStrTab {
		symPtr, nSyms = uint32(end), 1
		end += 18 + len(strTab)
	}
	overlayAt := end
	end += len(o.Overlay)
	var cert []byte
	certAt := 0
	if o.Signed {
		certAt = peAlign(end, 8)
		cert = peCertificate()
		end = certAt + len(cert)
	}

	out := make([]byte, end)
	copy(out, peDOS())
	w := out[PEOffset:]
	copy(w, "PE\x00\x00")
	binary.LittleEndian.PutUint16(w[4:], c.machine)
	binary.LittleEndian.PutUint16(w[6:], uint16(nSec))
	binary.LittleEndian.PutUint32(w[8:], o.Timestamp)
	binary.LittleEndian.PutUint32(w[12:], symPtr)
	binary.LittleEndian.PutUint32(w[16:], nSyms)
	binary.LittleEndian.PutUint16(w[20:], uint16(optSize))
	binary.LittleEndian.PutUint16(w[22:], c.chars)

	opt := out[PEOptionalOffset:]
	le := binary.LittleEndian
	if c.pe64 {
		le.PutUint16(opt, 0x20b)
	} else {
		le.PutUint16(opt, 0x10b)
	}
	opt[2], opt[3] = 14, 29
	le.PutUint32(opt[4:], uint32(len(text)))
	le.PutUint32(opt[8:], uint32(peAlign(len(blob.buf), peFileAlign)+32))
	le.PutUint32(opt[16:], peTextVA)
	le.PutUint32(opt[20:], peTextVA)
	dirOff := 96
	if c.pe64 {
		le.PutUint64(opt[24:], c.imageBase)
		dirOff = 112
	} else {
		le.PutUint32(opt[24:], secs[2].va)
		le.PutUint32(opt[28:], uint32(c.imageBase))
	}
	le.PutUint32(opt[32:], peSectAlign)
	le.PutUint32(opt[36:], peFileAlign)
	le.PutUint16(opt[40:], 6)
	le.PutUint16(opt[48:], 6)
	le.PutUint32(opt[56:], sizeOfImage)
	le.PutUint32(opt[60:], uint32(sizeOfHeaders))
	le.PutUint16(opt[68:], c.subsystem)
	le.PutUint16(opt[70:], c.dllChars)
	if c.pe64 {
		le.PutUint64(opt[72:], 0x100000)
		le.PutUint64(opt[80:], 0x1000)
		le.PutUint64(opt[88:], 0x100000)
		le.PutUint64(opt[96:], 0x1000)
		le.PutUint32(opt[108:], 16)
	} else {
		le.PutUint32(opt[72:], 0x100000)
		le.PutUint32(opt[76:], 0x1000)
		le.PutUint32(opt[80:], 0x100000)
		le.PutUint32(opt[84:], 0x1000)
		le.PutUint32(opt[92:], 16)
	}
	dirs := blob.dirs
	if o.Signed {
		dirs[4] = peDir{uint32(certAt), uint32(len(cert))}
	}
	for i, d := range dirs {
		le.PutUint32(opt[dirOff+8*i:], d.rva)
		le.PutUint32(opt[dirOff+8*i+4:], d.size)
	}

	bits := 32
	if c.pe64 {
		bits = 64
	}
	for i, s := range secs {
		h := out[PESectionHeaderOffset(bits, i):]
		name := s.name
		if s.long {
			name = "/" + strconv.Itoa(int(s.strOff))
		}
		copy(h[:8], name)
		le.PutUint32(h[8:], s.vsize)
		le.PutUint32(h[12:], s.va)
		le.PutUint32(h[16:], s.rawSize)
		le.PutUint32(h[20:], s.rawPtr)
		le.PutUint32(h[36:], s.chars)
		if s.rawSize > 0 {
			copy(out[s.rawPtr:], s.data)
		}
	}
	if hasStrTab {
		copy(out[symPtr:], "x")
		le.PutUint16(out[symPtr+12:], 1)
		out[symPtr+16] = 2
		copy(out[int(symPtr)+18:], strTab)
	}
	copy(out[overlayAt:], o.Overlay)
	copy(out[certAt:], cert)
	return out
}
