package pe

import (
	"encoding/binary"
	"strconv"

	"github.com/q6r/teardown/internal/binio"
)

const (
	exportDirectorySize = 40
	// maxExportEntries bounds each export table walk; ordinals are 16-bit, so no
	// valid image comes close.
	maxExportEntries = 1 << 17
)

// parseExports reads the export directory: named exports in name-table order,
// then exports that have only an ordinal ("#N"). A function whose address lies
// inside the export directory is a forwarder and is listed as "name -> target".
func (p *parser) parseExports() {
	d := p.h.dirs[dirExport]
	if d.rva == 0 {
		return
	}
	hdr, ok := p.readRVA(d.rva, exportDirectorySize)
	if !ok {
		p.notef("the export directory (RVA %#x) lies outside the file; exports were skipped", d.rva)
		return
	}
	c := binio.NewCursor(hdr, binary.LittleEndian)
	c.Skip(12) // Characteristics, TimeDateStamp, MajorVersion, MinorVersion
	nameRVA := c.U32()
	base := uint64(c.U32())
	declaredFuncs, declaredNames := uint64(c.U32()), uint64(c.U32())
	funcsRVA, namesRVA, ordsRVA := c.U32(), c.U32(), c.U32()

	if nameRVA != 0 {
		if s, ok := p.cstringRVA(nameRVA); ok {
			p.det.ExportName = binio.Printable(s, displayNameLen)
		}
	}
	nFuncs := p.clampCount(declaredFuncs, 4, "function")
	nNames := p.clampCount(declaredNames, 4, "name")

	add := func(s string) {
		if len(p.exports) < p.lim.MaxList {
			p.exports = append(p.exports, s)
		} else {
			p.exportsTruncated = true
		}
	}
	withForwarder := func(entry string, funcRVA uint32) string {
		if funcRVA < d.rva || uint64(funcRVA) >= uint64(d.rva)+uint64(d.size) {
			return entry
		}
		target, ok := p.cstringRVA(funcRVA)
		if !ok {
			return entry
		}
		return entry + " -> " + binio.Printable(target, displayNameLen)
	}

	ords := make([]uint16, 0, min(nNames, 4096))
	p.scanArray(ordsRVA, 2, nNames, func(_ uint64, v uint64) bool {
		ords = append(ords, uint16(v))
		return true
	})
	if uint64(len(ords)) < nNames && p.err == nil {
		p.notef("the export ordinal table is cut off: %d of %d entries could be read", len(ords), nNames)
	}

	named := make([]uint64, nFuncs/64+1)
	badOrdinals, badNames := 0, 0
	p.scanArray(namesRVA, 4, uint64(len(ords)), func(i uint64, v uint64) bool {
		idx := uint64(ords[i])
		if idx >= nFuncs {
			badOrdinals++
			return true
		}
		named[idx/64] |= 1 << (idx % 64)
		name, ok := p.cstringRVA(uint32(v))
		if !ok {
			badNames++
			return true
		}
		entry := binio.Printable(name, displayNameLen)
		if at, ok := rvaAdd(funcsRVA, idx*4); ok {
			if funcRVA, ok := p.u32AtRVA(at); ok {
				entry = withForwarder(entry, funcRVA)
			}
		}
		add(entry)
		return true
	})
	if badOrdinals > 0 {
		p.notef("%d export names refer to an ordinal outside the export address table", badOrdinals)
	}
	if badNames > 0 {
		p.notef("%d export names lie outside the file", badNames)
	}

	var count int
	seen := p.scanArray(funcsRVA, 4, nFuncs, func(i uint64, v uint64) bool {
		if v == 0 {
			return true
		}
		count++
		if named[i/64]&(1<<(i%64)) == 0 {
			add(withForwarder("#"+strconv.FormatUint(base+i, 10), uint32(v)))
		}
		return true
	})
	if seen < nFuncs && p.err == nil {
		p.notef("the export address table is cut off: %d of %d entries could be read", seen, nFuncs)
	}
	p.det.ExportCount = count
	if p.exportsTruncated {
		p.notef("only the first %d exports are recorded; exportCount is exact", p.lim.MaxList)
	}
}

// clampCount limits a table length read from the file to what the file could
// hold and to the absolute walk limit.
func (p *parser) clampCount(declared uint64, width int, what string) uint64 {
	limit := min(uint64(p.size)/uint64(width), maxExportEntries)
	if declared > limit {
		p.notef("the export directory declares %d %s entries; only the first %d are read", declared, what, limit)
		return limit
	}
	return declared
}
