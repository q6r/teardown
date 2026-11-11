package pe

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/entropy"
	"github.com/q6r/teardown/internal/report"
)

// Section characteristic bits (IMAGE_SCN_MEM_*).
const (
	scnMemExecute = 0x20000000
	scnMemRead    = 0x40000000
	scnMemWrite   = 0x80000000
)

// sectionScanLimit bounds the sections consulted for overlap checks and RVA
// translation; the Windows loader accepts at most 96 sections.
const sectionScanLimit = 256

type section struct {
	name        string
	virtualSize uint32
	virtualAddr uint32
	rawSize     uint32
	rawPtr      uint32
	chars       uint32
}

// extent is the number of bytes the section can be addressed by in memory.
func (s section) extent() uint64 { return uint64(max(s.virtualSize, s.rawSize)) }

// rawLen is how many bytes of the section's raw data exist in a file of the given size.
func (s section) rawLen(size int64) int64 {
	ptr := int64(s.rawPtr)
	if s.rawSize == 0 || ptr >= size {
		return 0
	}
	return min(int64(s.rawSize), size-ptr)
}

// readSections reads the section table and builds the RVA map.
func (p *parser) readSections() {
	h := &p.h
	n := int64(h.nSections)
	tableOff := p.peOff + 4 + coffHeaderSize + int64(h.optSize)
	p.tableEnd = tableOff
	if n == 0 {
		p.notef("the section table is empty")
		p.buildMaps()
		return
	}
	fit := int64(0)
	if tableOff < p.size {
		fit = (p.size - tableOff) / sectionHeaderSize
	}
	if n > fit {
		p.notef("the COFF header declares %d sections but only %d fit in the file", n, fit)
		n = fit
	}
	if limit := int64(p.lim.MaxList); n > limit {
		p.notef("the image has %d sections; only the first %d are read", n, limit)
		n = limit
	}
	n = min(n, p.lim.MaxMeta/sectionHeaderSize)
	if n > 0 {
		buf, err := binio.ReadAt(p.r, p.size, tableOff, n*sectionHeaderSize)
		if err != nil {
			p.notef("the section table could not be read: %v", err)
		} else {
			p.tableEnd = tableOff + n*sectionHeaderSize
			p.secs = make([]section, 0, n)
			for i := range int(n) {
				raw := buf[i*sectionHeaderSize : (i+1)*sectionHeaderSize]
				p.secs = append(p.secs, section{
					name:        p.decodeName(raw[:8]),
					virtualSize: binary.LittleEndian.Uint32(raw[8:]),
					virtualAddr: binary.LittleEndian.Uint32(raw[12:]),
					rawSize:     binary.LittleEndian.Uint32(raw[16:]),
					rawPtr:      binary.LittleEndian.Uint32(raw[20:]),
					chars:       binary.LittleEndian.Uint32(raw[36:]),
				})
			}
		}
	}
	p.buildMaps()
}

// buildMaps prepares RVA translation from the parsed sections.
func (p *parser) buildMaps() {
	m := &p.maps
	m.secs = make([]secMap, 0, min(len(p.secs), sectionScanLimit))
	minVA := uint32(0)
	for _, s := range p.secs[:min(len(p.secs), sectionScanLimit)] {
		m.secs = append(m.secs, secMap{rva: s.virtualAddr, span: s.extent(), ptr: int64(s.rawPtr), raw: s.rawLen(p.size)})
		if s.virtualAddr != 0 && (minVA == 0 || s.virtualAddr < minVA) {
			minVA = s.virtualAddr
		}
	}
	if len(p.secs) == 0 {
		m.headerEnd = p.size
		return
	}
	end := int64(p.h.sizeOfHeaders)
	if end == 0 {
		end = p.tableEnd
	}
	if minVA != 0 {
		end = min(end, int64(minVA))
	}
	m.headerEnd = min(end, p.size)
}

// decodeName returns the section name; "/N" names are resolved through the COFF
// string table (linkers use them for names longer than eight bytes).
func (p *parser) decodeName(raw []byte) string {
	if raw[0] == '/' {
		var off uint32
		digits := 0
		for _, c := range raw[1:] {
			if c < '0' || c > '9' {
				break
			}
			off = off*10 + uint32(c-'0')
			digits++
		}
		if digits > 0 && !slices.ContainsFunc(raw[1+digits:], func(c byte) bool { return c != 0 }) {
			if s, ok := p.coffString(off); ok {
				return binio.Printable(s, displayNameLen)
			}
		}
	}
	return binio.FixedString(raw)
}

// coffString reads a string from the COFF string table, which follows the symbol table.
func (p *parser) coffString(off uint32) (string, bool) {
	if p.h.symPtr == 0 || off < 4 {
		return "", false
	}
	pos := int64(p.h.symPtr) + int64(p.h.nSyms)*18 + int64(off)
	if pos >= p.size {
		return "", false
	}
	s, _ := binio.CString(p.r, p.size, pos, 256)
	return s, s != ""
}

func sectionFlags(chars uint32) []string {
	flags := []string{}
	if chars&scnMemRead != 0 {
		flags = append(flags, report.FlagR)
	}
	if chars&scnMemWrite != 0 {
		flags = append(flags, report.FlagW)
	}
	if chars&scnMemExecute != 0 {
		flags = append(flags, report.FlagX)
	}
	return flags
}

// buildSections converts the section table into report sections: entropy plus
// structural suspicion. Entropy-based suspicion is left to the rules engine.
func (p *parser) buildSections() {
	p.res.Sections = make([]report.Section, 0, len(p.secs))
	overV := overlaps(p.secs, func(s section) uint64 { return uint64(s.virtualAddr) }, section.extent)
	overR := overlaps(p.secs, func(s section) uint64 { return uint64(s.rawPtr) }, func(s section) uint64 { return uint64(s.rawSize) })
	beyond := 0
	for i, s := range p.secs {
		if p.stopped() {
			return
		}
		var reasons []string
		add := func(format string, args ...any) { reasons = append(reasons, fmt.Sprintf(format, args...)) }
		exec, write := s.chars&scnMemExecute != 0, s.chars&scnMemWrite != 0
		if exec && write {
			add("writable and executable (RWX)")
		}
		if packer := packerForSection(s.name); packer != "" {
			add("section name is typical of %s", packer)
			p.addHint(packer)
		} else if !knownSection(s.name) {
			add("unusual section name %q", s.name)
		}
		if exec && s.rawSize == 0 && s.virtualSize > 0 && !strings.EqualFold(s.name, ".textbss") {
			add("executable section has no raw data (code created at run time?)")
		}
		if exec && s.virtualSize > 64<<10 && uint64(s.virtualSize) > 16*uint64(s.rawSize) {
			add("virtual size %d is more than 16x its raw size %d (room for unpacked code?)", s.virtualSize, s.rawSize)
		}
		if hdr := p.headerBytes(); hdr > 0 {
			if s.extent() > 0 && s.virtualAddr != 0 && int64(s.virtualAddr) < hdr {
				add("virtual range overlaps the PE headers (first %#x bytes)", hdr)
			}
			if s.rawSize > 0 && s.rawPtr != 0 && int64(s.rawPtr) < hdr {
				add("raw data overlaps the PE headers (first %#x bytes)", hdr)
			}
		}
		if j, ok := overV[i]; ok {
			add("virtual range overlaps section %q", p.secs[j].name)
		}
		if j, ok := overR[i]; ok {
			add("raw data overlaps section %q", p.secs[j].name)
		}
		if s.rawSize > 0 && int64(s.rawPtr)+int64(s.rawSize) > p.size {
			add("raw data extends beyond the end of the file (truncated?)")
			beyond++
		}
		ent := p.sectionEntropy(s)
		p.res.Sections = append(p.res.Sections, report.Section{
			Name:        s.name,
			VirtualSize: uint64(s.virtualSize),
			RawSize:     uint64(s.rawSize),
			Offset:      uint64(s.rawPtr),
			Entropy:     ent,
			Flags:       sectionFlags(s.chars),
			Suspicious:  len(reasons) > 0,
			Reasons:     reasons,
		})
	}
	if beyond > 0 {
		p.notef("%d section(s) extend beyond the end of the file; the image looks truncated", beyond)
	}
}

// sectionEntropy measures a section's raw data. The bytes sampled across all
// sections are limited to the file size (plus a little slack): honest images
// have disjoint sections, while a crafted one whose thousands of sections all
// point at the same huge region would otherwise multiply the I/O.
func (p *parser) sectionEntropy(s section) float64 {
	n := s.rawLen(p.size)
	if n == 0 {
		return 0
	}
	cost := min(n, entropy.MaxSample)
	if cost > p.entropyLeft {
		p.notef("the entropy budget (the file size) is exhausted; the entropy of overlapping sections was not measured")
		return 0
	}
	p.entropyLeft -= cost
	ent, err := entropy.Range(p.raw, int64(s.rawPtr), n)
	if err != nil {
		p.notef("section %q: entropy could not be computed: %v", s.name, err)
	}
	return ent
}

// headerBytes is the size of the header area sections must not intrude on.
func (p *parser) headerBytes() int64 {
	if p.h.sizeOfHeaders != 0 {
		return int64(p.h.sizeOfHeaders)
	}
	return p.tableEnd
}

// overlaps returns, for every section that overlaps an earlier-starting one in
// the given dimension, the index of the section it overlaps.
func overlaps(secs []section, start, extent func(section) uint64) map[int]int {
	n := min(len(secs), sectionScanLimit)
	order := make([]int, 0, n)
	for i := range n {
		if extent(secs[i]) > 0 {
			order = append(order, i)
		}
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(start(secs[a]), start(secs[b])) })
	out := map[int]int{}
	var maxEnd uint64
	maxIdx := -1
	for _, i := range order {
		s := start(secs[i])
		if maxIdx >= 0 && s < maxEnd {
			out[i] = maxIdx
		}
		if end := s + extent(secs[i]); end > maxEnd {
			maxEnd, maxIdx = end, i
		}
	}
	return out
}

// knownSection reports whether the name is one linkers and toolchains commonly emit.
func knownSection(name string) bool {
	n := strings.ToLower(name)
	if i := strings.IndexByte(n, '$'); i > 0 {
		n = n[:i]
	}
	switch n {
	case ".text", ".code", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc", ".pdata", ".xdata",
		".tls", ".bss", ".didat", ".crt", ".gfids", ".giats", ".gehcont", ".00cfg", ".retplne", ".voltbl",
		".textbss", ".sdata", ".srdata", ".rodata", ".drectve", ".sxdata", ".debug", ".detourc", ".detourd",
		".orpc", ".mrdata", ".fptable", ".cormeta", ".shared", ".symtab", ".strtab", ".eh_fram", ".ctors",
		".dtors", ".jcr", ".bind", ".wixburn", ".ndata", ".stab", ".stabstr", ".text1", ".data1",
		".gxfg", ".apiset", ".buildid", "fothk", "_rdata", "cpadinfo", "loadcfg", "minatl", "malloc_h",
		"code", "data", "bss", "init", "text":
		return true
	}
	return strings.HasPrefix(n, ".debug_") || strings.HasPrefix(n, ".zdebug_") || strings.HasPrefix(n, "page") ||
		strings.HasPrefix(n, ".tls") || strings.HasPrefix(n, ".rsrc")
}

// packerForSection returns the packer or protector whose sections carry this
// name, or "". It is a hint, never proof.
func packerForSection(name string) string {
	switch strings.ToLower(name) {
	case "upx0", "upx1", "upx2":
		return "UPX"
	case ".aspack", ".adata":
		return "ASPack"
	case ".themida":
		return "Themida/WinLicense"
	case ".vmp0", ".vmp1", ".vmp2":
		return "VMProtect"
	case ".petite":
		return "Petite"
	case ".nsp0", ".nsp1", ".nsp2":
		return "NsPack"
	case ".mpress1", ".mpress2":
		return "MPRESS"
	case ".enigma1", ".enigma2":
		return "Enigma Protector"
	case "pec1", "pec2", "pec2mo", "pec2to", "pecompact2":
		return "PECompact"
	case ".upack", ".bydwing":
		return "Upack"
	case ".rlpack":
		return "RLPack"
	case ".yp":
		return "Yoda's Protector"
	case "fsg!":
		return "FSG"
	case ".perplex":
		return "Perplex PE-Protector"
	case ".packed":
		return "an unnamed packer (.packed)"
	}
	return ""
}

// addHint records a packer hint once.
func (p *parser) addHint(name string) {
	if !slices.Contains(p.det.PackerHints, name) {
		p.det.PackerHints = append(p.det.PackerHints, name)
	}
}
