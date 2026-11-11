package pe

import (
	"encoding/binary"
	"fmt"

	"github.com/q6r/teardown/internal/binio"
)

const (
	dosHeaderSize     = 64
	coffHeaderSize    = 20
	sectionHeaderSize = 40

	magicPE32     = 0x10b
	magicPE32Plus = 0x20b
)

// Data directory indices.
const (
	dirExport      = 0
	dirImport      = 1
	dirSecurity    = 4
	dirDebug       = 6
	dirTLS         = 9
	dirLoadConfig  = 10
	dirDelayImport = 13
	dirCLR         = 14
	numDirs        = 16
)

type dataDir struct{ rva, size uint32 }

// header holds the COFF and optional header fields the parser needs.
type header struct {
	machine   uint16
	nSections uint16
	timestamp uint32
	symPtr    uint32
	nSyms     uint32
	optSize   uint16
	chars     uint16

	// Optional header; hasOpt is false when it is missing or unrecognised and
	// hasFlags is true only when the header reaches DllCharacteristics.
	hasOpt        bool
	hasFlags      bool
	pe64          bool
	linkerMajor   uint8
	linkerMinor   uint8
	entry         uint32
	imageBase     uint64
	osMajor       uint16
	osMinor       uint16
	subMajor      uint16
	subMinor      uint16
	sizeOfImage   uint32
	sizeOfHeaders uint32
	checksum      uint32
	subsystem     uint16
	dllChars      uint16
	dirs          [numDirs]dataDir
}

// readHeaders parses the DOS header, the PE signature, the COFF header and the
// optional header. It fails only when no usable COFF header exists.
func (p *parser) readHeaders() error {
	if p.size < dosHeaderSize {
		return fmt.Errorf("not a PE file: %d bytes is smaller than a DOS header (%d bytes)", p.size, dosHeaderSize)
	}
	dos, err := binio.ReadAt(p.r, p.size, 0, dosHeaderSize)
	if err != nil {
		return fmt.Errorf("reading the DOS header: %w", err)
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return fmt.Errorf("not a PE file: missing the MZ signature (the file starts with %#02x %#02x)", dos[0], dos[1])
	}
	lfanew := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if lfanew < 4 || lfanew+4+coffHeaderSize > p.size {
		return fmt.Errorf("not a usable PE file: e_lfanew %#x points outside the %d byte file", lfanew, p.size)
	}
	b, err := binio.ReadAt(p.r, p.size, lfanew, 4+coffHeaderSize)
	if err != nil {
		return fmt.Errorf("reading the COFF header: %w", err)
	}
	if string(b[:4]) != "PE\x00\x00" {
		return fmt.Errorf("not a PE image: no \"PE\\0\\0\" signature at offset %#x (DOS-only executable?)", lfanew)
	}
	p.peOff = lfanew

	c := binio.NewCursor(b[4:], binary.LittleEndian)
	h := &p.h
	h.machine = c.U16()
	h.nSections = c.U16()
	h.timestamp = c.U32()
	h.symPtr = c.U32()
	h.nSyms = c.U32()
	h.optSize = c.U16()
	h.chars = c.U16()

	optOff := lfanew + 4 + coffHeaderSize
	opt, err := binio.ReadUpTo(p.r, p.size, optOff, int64(h.optSize))
	if err != nil {
		return fmt.Errorf("reading the optional header: %w", err)
	}
	if len(opt) < int(h.optSize) {
		p.notef("the optional header is cut off by the end of the file (%d of %d bytes present)", len(opt), h.optSize)
	}
	p.parseOptional(opt)
	return nil
}

// parseOptional decodes the optional header. Missing trailing fields stay zero.
func (p *parser) parseOptional(b []byte) {
	h := &p.h
	if len(b) < 2 {
		if h.optSize == 0 {
			p.notef("the image has no optional header; data directories and hardening flags are unavailable")
		}
		return
	}
	c := binio.NewCursor(b, binary.LittleEndian)
	magic := c.U16()
	switch magic {
	case magicPE32:
	case magicPE32Plus:
		h.pe64 = true
	default:
		p.notef("unrecognised optional header magic %#x; data directories were not read", magic)
		return
	}
	h.hasOpt = true
	h.linkerMajor, h.linkerMinor = c.U8(), c.U8()
	c.Skip(12) // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
	h.entry = c.U32()
	c.Skip(4) // BaseOfCode
	if h.pe64 {
		h.imageBase = c.U64()
	} else {
		c.Skip(4) // BaseOfData
		h.imageBase = uint64(c.U32())
	}
	c.Skip(8) // SectionAlignment, FileAlignment
	h.osMajor, h.osMinor = c.U16(), c.U16()
	c.Skip(4) // MajorImageVersion, MinorImageVersion
	h.subMajor, h.subMinor = c.U16(), c.U16()
	c.Skip(4) // Win32VersionValue
	h.sizeOfImage = c.U32()
	h.sizeOfHeaders = c.U32()
	h.checksum = c.U32()
	h.subsystem = c.U16()
	h.dllChars = c.U16()
	h.hasFlags = c.Err() == nil
	if h.pe64 {
		c.Skip(32) // stack and heap reserve/commit
	} else {
		c.Skip(16)
	}
	c.Skip(4) // LoaderFlags
	declared := c.U32()
	if c.Err() != nil {
		p.notef("the optional header is truncated (SizeOfOptionalHeader is %d); later fields are missing", h.optSize)
		return
	}
	n := int(min(declared, numDirs))
	if declared > numDirs {
		p.notef("NumberOfRvaAndSizes is %d; only the first %d data directories are read", declared, numDirs)
	}
	read := 0
	for read < n && c.Remaining() >= 8 {
		h.dirs[read] = dataDir{rva: c.U32(), size: c.U32()}
		read++
	}
	if read < n {
		p.notef("the optional header has room for only %d of its %d data directories", read, n)
	}
}
