package pe

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

const (
	debugEntrySize    = 28
	maxDebugEntries   = 64
	maxCodeViewBytes  = 24 + 1024
	debugTypeCodeView = 2
	debugTypeRepro    = 16
	maxTLSCallbacks   = 256
	clrHeaderSize     = 72
)

// parseDebug reads the debug directory for the CodeView PDB reference (the
// path leaks the build machine's directory layout) and the reproducible-build marker.
func (p *parser) parseDebug() {
	d := p.h.dirs[dirDebug]
	if d.rva == 0 || d.size == 0 {
		return
	}
	n := min(uint64(d.size)/debugEntrySize, maxDebugEntries)
	for i := range n {
		if p.done() {
			return
		}
		var b []byte
		at, ok := rvaAdd(d.rva, i*debugEntrySize)
		if ok {
			b, ok = p.readRVA(at, debugEntrySize)
		}
		if !ok {
			p.notef("the debug directory (RVA %#x) lies outside the file", d.rva)
			return
		}
		c := binio.NewCursor(b, binary.LittleEndian)
		c.Skip(12) // Characteristics, TimeDateStamp, MajorVersion, MinorVersion
		typ := c.U32()
		dataSize, dataRVA, dataPtr := c.U32(), c.U32(), c.U32()
		switch typ {
		case debugTypeCodeView:
			if p.det.PDBPath == "" {
				p.readCodeView(dataSize, dataRVA, dataPtr)
			}
		case debugTypeRepro:
			p.det.Reproducible = true
		}
	}
}

// readCodeView decodes an RSDS (PDB 7.0) or NB10 (PDB 2.0) record.
func (p *parser) readCodeView(size, rva, ptr uint32) {
	want := int(min(size, maxCodeViewBytes))
	var data []byte
	if ptr != 0 {
		data, _ = binio.ReadUpTo(p.r, p.size, int64(ptr), int64(want))
	}
	if len(data) < 16 && rva != 0 {
		data = p.readRVAUpTo(rva, want)
	}
	switch {
	case len(data) >= 24 && string(data[:4]) == "RSDS":
		p.det.PDBGUID = formatGUID(data[4:20])
		p.det.PDBAge = binary.LittleEndian.Uint32(data[20:])
		p.det.PDBPath = cutString(data[24:])
	case len(data) >= 16 && string(data[:4]) == "NB10":
		p.det.PDBAge = binary.LittleEndian.Uint32(data[12:])
		p.det.PDBPath = cutString(data[16:])
	}
}

// cutString returns the printable text before the first NUL.
func cutString(b []byte) string {
	if i := slices.Index(b, 0); i >= 0 {
		b = b[:i]
	}
	return binio.Printable(string(b), 512)
}

// formatGUID renders a 16-byte little-endian GUID in the registry format.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%s-%s",
		binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]),
		strings.ToUpper(hex.EncodeToString(b[8:10])), strings.ToUpper(hex.EncodeToString(b[10:16])))
}

// parseSecurity records the presence of an Authenticode certificate table. The
// directory's "virtual address" is a file offset. Only presence is reported:
// the signature is never validated.
func (p *parser) parseSecurity() {
	d := p.h.dirs[dirSecurity]
	if d.rva == 0 && d.size == 0 {
		return
	}
	off := int64(d.rva)
	if d.size < 8 || off+int64(d.size) > p.size {
		p.notef("the certificate table (offset %#x, size %d) lies outside the file or is too small; the image is not reported as signed", d.rva, d.size)
		return
	}
	p.det.Signed = true
	p.det.SignatureSize = int(min(d.size, math.MaxInt32))
	p.certOff, p.certSize = off, int64(d.size)
	hdr, err := binio.ReadAt(p.r, p.size, off, 8)
	if err != nil {
		return
	}
	switch typ := binary.LittleEndian.Uint16(hdr[6:]); typ {
	case 1:
		p.det.SignatureType = "x509"
	case 2:
		p.det.SignatureType = "pkcs7-signed-data"
	case 3:
		p.det.SignatureType = "reserved"
	case 4:
		p.det.SignatureType = "ts-stack-signed"
	default:
		p.det.SignatureType = fmt.Sprintf("0x%04x", typ)
	}
}

// parseCLR detects a managed (.NET) image from the CLR runtime header and
// reads the metadata version string.
func (p *parser) parseCLR() {
	d := p.h.dirs[dirCLR]
	if d.rva == 0 || d.size == 0 {
		return
	}
	p.det.DotNet = true
	hdr, ok := p.readRVA(d.rva, clrHeaderSize)
	if !ok {
		p.notef("the CLR runtime header (RVA %#x) lies outside the file", d.rva)
		return
	}
	c := binio.NewCursor(hdr, binary.LittleEndian)
	c.Skip(8) // cb, MajorRuntimeVersion, MinorRuntimeVersion
	mdRVA := c.U32()
	c.Skip(4) // metadata size
	flags := c.U32()
	p.det.DotNetFlags = flagNames(flags, clrFlagNames)
	p.clrILOnly = flags&0x1 != 0

	root, ok := p.readRVA(mdRVA, 16)
	if !ok || string(root[:4]) != "BSJB" {
		p.notef("the CLR metadata root (RVA %#x) is missing or invalid", mdRVA)
		return
	}
	n := int(min(binary.LittleEndian.Uint32(root[12:]), 255))
	if at, ok := rvaAdd(mdRVA, 16); ok && n > 0 {
		p.det.DotNetVersion = cutString(p.readRVAUpTo(at, n))
	}
}

// parseTLS counts the TLS callbacks; they run before the entry point, which
// makes them a popular anti-debugging hook.
func (p *parser) parseTLS() {
	d := p.h.dirs[dirTLS]
	if d.rva == 0 {
		return
	}
	width := 4
	if p.h.pe64 {
		width = 8
	}
	b, ok := p.readRVA(d.rva, 4*width)
	if !ok {
		p.notef("the TLS directory (RVA %#x) lies outside the file", d.rva)
		return
	}
	var callbacks uint64
	if width == 8 {
		callbacks = binary.LittleEndian.Uint64(b[24:])
	} else {
		callbacks = uint64(binary.LittleEndian.Uint32(b[12:]))
	}
	if callbacks == 0 {
		return
	}
	rva, ok := p.fromVA(callbacks)
	if !ok {
		p.notef("the TLS callback table address %#x is not inside the image", callbacks)
		return
	}
	count := 0
	p.scanArray(rva, width, maxTLSCallbacks, func(_ uint64, v uint64) bool {
		if v == 0 {
			return false
		}
		count++
		return true
	})
	p.det.TLSCallbacks = count
}

// loadConfig holds the load configuration facts hardening depends on.
type loadConfig struct {
	safeSEH    bool
	guardFlags uint32
}

// parseLoadConfig reads the stack cookie, SafeSEH handler table and CFG flags.
// Fields beyond the structure's own Size field are treated as absent.
func (p *parser) parseLoadConfig() {
	d := p.h.dirs[dirLoadConfig]
	if d.rva == 0 {
		return
	}
	head, ok := p.readRVA(d.rva, 4)
	if !ok {
		p.notef("the load configuration directory (RVA %#x) lies outside the file", d.rva)
		return
	}
	b := p.readRVAUpTo(d.rva, int(min(binary.LittleEndian.Uint32(head), 512)))
	u32 := func(off int) uint32 {
		if off+4 > len(b) {
			return 0
		}
		return binary.LittleEndian.Uint32(b[off:])
	}
	u64 := func(off int) uint64 {
		if off+8 > len(b) {
			return 0
		}
		return binary.LittleEndian.Uint64(b[off:])
	}
	if p.h.pe64 {
		p.det.SecurityCookie = u64(88) != 0
		p.lc.guardFlags = u32(144)
		return
	}
	p.det.SecurityCookie = u32(60) != 0
	p.lc.safeSEH = u32(64) != 0 && u32(68) != 0
	p.lc.guardFlags = u32(88)
}

// overlaySize returns the bytes after the last section's raw data, leaving out
// the Authenticode certificate table and the COFF symbol and string tables,
// which are part of the file but not appended data.
func (p *parser) overlaySize() int64 {
	var start int64
	for _, s := range p.secs {
		if s.rawSize > 0 {
			start = max(start, min(int64(s.rawPtr)+int64(s.rawSize), p.size))
		}
	}
	if start == 0 {
		start = min(max(int64(p.h.sizeOfHeaders), p.tableEnd), p.size)
	}
	if start >= p.size {
		return 0
	}
	type span struct{ from, to int64 }
	var skip []span
	if p.certSize > 0 {
		skip = append(skip, span{p.certOff, p.certOff + p.certSize})
	}
	if p.h.symPtr != 0 {
		symEnd := int64(p.h.symPtr) + int64(p.h.nSyms)*18
		end := symEnd
		if b, err := binio.ReadAt(p.r, p.size, symEnd, 4); err == nil {
			end += max(int64(binary.LittleEndian.Uint32(b)), 4)
		}
		skip = append(skip, span{int64(p.h.symPtr), end})
	}
	slices.SortFunc(skip, func(a, b span) int { return cmp.Compare(a.from, b.from) })
	overlay := p.size - start
	var covered int64
	for _, s := range skip {
		from, to := max(s.from, start, covered), min(s.to, p.size)
		if to > from {
			overlay -= to - from
			covered = to
		}
	}
	return max(overlay, 0)
}
