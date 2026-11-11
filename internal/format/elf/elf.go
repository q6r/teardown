// Package elf analyses ELF images (Linux, BSD, Android, firmware): header
// facts, sections with entropy, program headers, DT_NEEDED/RPATH/RUNPATH,
// symbol tables and a built-in checksec (PIE, NX, RELRO, stack canary,
// FORTIFY_SOURCE).
//
// The header, program headers, section headers, dynamic section and notes are
// read by a small bounds-checked decoder so that truncated or corrupted files
// still produce a partial result. Symbol tables, which need GNU symbol-version
// decoding, are read with debug/elf when the section table is intact and the
// tables are small enough to hold in memory. Nothing is ever executed.
package elf

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/entropy"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

const unspecified = report.UnspecifiedLibrary

// Result is everything the parser could recover from an image.
type Result struct {
	// Sections lists the section headers (index order, the null section
	// omitted). When the image has no usable section header table the PT_LOAD
	// segments are listed instead, named LOAD[n].
	Sections []report.Section
	// Imports groups undefined dynamic symbols by the library named in the GNU
	// symbol version requirements; symbols without one fall under
	// [report.UnspecifiedLibrary].
	Imports []report.Import
	// Exports lists defined global and weak dynamic symbols, sorted.
	Exports []string
	// Hardening holds the pie, nx, relro, canary and fortify entries.
	Hardening []report.Hardening
	Details   Details
	// Notes explains anything that was skipped or looked malformed.
	Notes []string
}

// Segment is one program header.
type Segment struct {
	// Type is the PT_* name, for example "PT_LOAD" or "PT_GNU_STACK".
	Type  string   `json:"type"`
	Flags []string `json:"flags"`
	// Offset, FileSize and MemSize are in bytes; VAddr is a hexadecimal string.
	Offset   uint64 `json:"offset"`
	VAddr    string `json:"vaddr"`
	FileSize uint64 `json:"fileSize"`
	MemSize  uint64 `json:"memSize"`
}

// Details holds the ELF-specific facts stored under details["elf"].
type Details struct {
	// Class is "ELF32" or "ELF64"; Endian is "little" or "big".
	Class  string `json:"class"`
	Endian string `json:"endian"`
	// OSABI is the EI_OSABI name ("SYSV", "LINUX", "FREEBSD", ...).
	OSABI      string `json:"osAbi"`
	ABIVersion int    `json:"abiVersion"`
	// Type is "EXEC", "DYN", "REL" or "CORE"; Machine is a name such as "x86-64".
	Type    string `json:"type"`
	Machine string `json:"machine"`
	// Entry is the entry point as a hexadecimal string.
	Entry       string `json:"entry"`
	Interpreter string `json:"interpreter"`
	// Linking is "dynamic" (PT_INTERP or DT_NEEDED entries), "static-pie"
	// (dynamic section with DF_1_PIE but no interpreter or libraries), "static"
	// (neither PT_INTERP nor PT_DYNAMIC) or "" for relocatable objects and
	// libraries without dependencies.
	Linking string `json:"linking"`
	// Needed lists DT_NEEDED libraries. RPath and RunPath split DT_RPATH and
	// DT_RUNPATH on ':'; empty elements are kept because they mean "the current
	// directory".
	Needed  []string `json:"needed"`
	RPath   []string `json:"rpath"`
	RunPath []string `json:"runpath"`
	Soname  string   `json:"soname"`
	// Stripped is true when there is no .symtab. HasDebugInfo is true when a
	// .debug_info, .zdebug_info or .gnu_debuglink section exists.
	Stripped     bool   `json:"stripped"`
	HasDebugInfo bool   `json:"hasDebugInfo"`
	BuildID      string `json:"buildId"`
	GoBuildID    string `json:"goBuildId,omitempty"`
	// Segments lists the program headers (capped); SegmentCount is the true number.
	Segments     []Segment `json:"segments"`
	SegmentCount int       `json:"segmentCount"`
	// RWXSegments counts PT_LOAD segments that are both writable and executable.
	RWXSegments  int `json:"rwxSegments"`
	SectionCount int `json:"sectionCount"`
	// SymbolCount and DynamicSymbolCount are the .symtab and .dynsym entry
	// counts (excluding the null symbol), taken from the section headers.
	SymbolCount        int `json:"symbolCount"`
	DynamicSymbolCount int `json:"dynamicSymbolCount"`
	// ImportCount and ExportCount are the true number of distinct imported and
	// exported dynamic symbols that were decoded.
	ImportCount int `json:"importCount"`
	ExportCount int `json:"exportCount"`
}

type parser struct {
	ctx  context.Context
	r    *io.SectionReader
	size int64
	lim  limits.Limits

	h        header
	progs    []prog
	sects    []sect
	shstrndx int
	// sectionsIncomplete is set when the section header table was cut short,
	// oversized or inconsistent, so debug/elf cannot be trusted with it.
	sectionsIncomplete bool
	namesKnown         bool

	dyn       dynamic
	interp    string
	buildID   string
	goBuildID string
	syms      symbolScan

	notes     []string
	secs      []report.Section
	truncated int
	// entropyBudget is how many bytes entropy measurements may still read. Real
	// sections do not overlap, so twice the file size plus a megabyte is generous;
	// a crafted section table whose entries all claim the whole file runs out of it.
	entropyBudget int64
	skipped       int
}

// note records a parse problem (deduplicated, capped).
func (p *parser) note(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if len(p.notes) < 50 && !slices.Contains(p.notes, msg) {
		p.notes = append(p.notes, msg)
	}
}

// Parse analyses the ELF image of the given size readable through r. It never
// panics and never executes the image. When the header is unusable it returns
// (nil, err); otherwise it returns whatever could be recovered together with
// Notes, and, on cancellation, the partial result with ctx.Err().
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	size = max(size, 0)
	p := &parser{ctx: ctx, r: io.NewSectionReader(r, 0, size), size: size, lim: lim.Normalize(), entropyBudget: 2*size + 1<<20}
	if err := p.readHeader(); err != nil {
		return nil, err
	}
	phases := []func(){
		p.readProgs, p.readSections, p.readDynamic, p.readInterpreter,
		p.readNotes, p.scanSymbols, p.measureSections,
	}
	for _, phase := range phases {
		if err := ctx.Err(); err != nil {
			return p.result(), err
		}
		phase()
	}
	if err := ctx.Err(); err != nil {
		return p.result(), err
	}
	return p.result(), nil
}

// measureSections builds the report sections (entropy included). Without a
// section header table the loadable segments stand in for sections.
func (p *parser) measureSections() {
	if len(p.sects) == 0 {
		p.measureSegments()
		return
	}
	for _, s := range p.sects {
		if s.typ == shtNull {
			continue
		}
		if len(p.secs) >= p.lim.MaxList {
			break
		}
		if len(p.secs)%32 == 0 && p.ctx.Err() != nil {
			return
		}
		sec := report.Section{
			Name:        s.name,
			RawSize:     s.size,
			Offset:      s.off,
			Flags:       sectionFlags(s.flags),
			VirtualSize: 0,
		}
		if s.flags&shfAlloc != 0 {
			sec.VirtualSize = s.size
		}
		reasons := p.sectionReasons(s)
		if s.typ == shtNobits {
			sec.RawSize = 0
		} else {
			var extra string
			sec.Entropy, extra = p.entropyOf(s.off, s.size)
			if extra != "" {
				reasons = append(reasons, extra)
			}
		}
		sec.Reasons, sec.Suspicious = reasons, len(reasons) > 0
		p.secs = append(p.secs, sec)
	}
	if p.truncated > 0 {
		p.note("%d section(s) extend past the end of the file; their entropy covers only the bytes that exist", p.truncated)
	}
}

func (p *parser) measureSegments() {
	if len(p.progs) > 0 {
		p.note("the image has no usable section header table; its loadable segments are listed instead of sections")
	}
	n := 0
	for _, pr := range p.progs {
		if pr.typ != ptLoad {
			continue
		}
		if len(p.secs) >= p.lim.MaxList || p.ctx.Err() != nil {
			break
		}
		sec := report.Section{
			Name:        fmt.Sprintf("LOAD[%d]", n),
			VirtualSize: pr.memsz,
			RawSize:     pr.filesz,
			Offset:      pr.off,
			Flags:       permFlags(pr.flags),
		}
		var reasons []string
		if pr.flags&pfW != 0 && pr.flags&pfX != 0 {
			reasons = append(reasons, "writable and executable")
		}
		var extra string
		sec.Entropy, extra = p.entropyOf(pr.off, pr.filesz)
		if extra != "" {
			reasons = append(reasons, extra)
		}
		sec.Reasons, sec.Suspicious = reasons, len(reasons) > 0
		p.secs = append(p.secs, sec)
		n++
	}
	if p.truncated > 0 {
		p.note("%d segment(s) extend past the end of the file; their entropy covers only the bytes that exist", p.truncated)
	}
}

// entropyOf measures the part of [off, off+n) that exists in the file. The
// second result is a Reason when the range is not fully inside the file.
func (p *parser) entropyOf(off, n uint64) (float64, string) {
	if n == 0 {
		return 0, ""
	}
	if off >= uint64(p.size) {
		p.truncated++
		return 0, "data lies outside the file"
	}
	avail := uint64(p.size) - off
	reason := ""
	if n > avail {
		n = avail
		reason = "data extends past the end of the file"
		p.truncated++
	}
	cost := min(int64(n), entropy.MaxSample)
	if cost > p.entropyBudget {
		p.skipped++
		return 0, reason
	}
	p.entropyBudget -= cost
	h, err := entropy.Range(p.r, int64(off), int64(n))
	if err != nil {
		p.note("entropy of the range at offset %#x could not be computed: %v", off, err)
		return 0, reason
	}
	return h, reason
}

func (p *parser) result() *Result {
	if p.skipped > 0 {
		p.note("entropy was not computed for %d range(s): the section data overlaps far more than the file size allows", p.skipped)
	}
	imports, importCount := p.importList()
	exports := p.exportList()
	res := &Result{
		Sections:  p.secs,
		Imports:   imports,
		Exports:   exports,
		Hardening: p.hardening(),
		Details:   p.details(importCount),
		Notes:     p.notes,
	}
	if res.Sections == nil {
		res.Sections = []report.Section{}
	}
	if res.Notes == nil {
		res.Notes = []string{}
	}
	return res
}

func (p *parser) importList() ([]report.Import, int) {
	out := []report.Import{}
	total := 0
	libs := make([]string, 0, len(p.syms.imports))
	for lib := range p.syms.imports {
		libs = append(libs, lib)
	}
	// Named libraries first (alphabetical), the unattributed group last.
	slices.SortFunc(libs, func(a, b string) int {
		switch {
		case a == unspecified && b != unspecified:
			return 1
		case b == unspecified && a != unspecified:
			return -1
		}
		return strings.Compare(a, b)
	})
	budget := p.lim.MaxList
	for _, lib := range libs {
		names := make([]string, 0, len(p.syms.imports[lib]))
		for n := range p.syms.imports[lib] {
			names = append(names, n)
		}
		slices.Sort(names)
		total += len(names)
		keep := names[:min(len(names), budget)]
		budget -= len(keep)
		out = append(out, report.Import{Library: lib, Count: len(names), Functions: keep})
	}
	return out, total
}

func (p *parser) exportList() []string {
	out := make([]string, 0, len(p.syms.exports))
	for n := range p.syms.exports {
		out = append(out, n)
	}
	slices.Sort(out)
	return out[:min(len(out), p.lim.MaxList)]
}

func (p *parser) details(importCount int) Details {
	h := p.h
	d := Details{
		Class:       "ELF32",
		Endian:      "little",
		OSABI:       osABIName(h.osabi),
		ABIVersion:  int(h.abiVersion),
		Type:        typeName(h.typ),
		Machine:     machineName(h.machine),
		Entry:       fmt.Sprintf("0x%x", h.entry),
		Interpreter: p.interp,
		Linking:     p.linking(),
		Needed:      nonNil(p.dyn.needed),
		RPath:       nonNil(p.dyn.rpath),
		RunPath:     nonNil(p.dyn.runpath),
		Soname:      p.dyn.soname,
		BuildID:     p.buildID,
		GoBuildID:   p.goBuildID,
		Segments:    []Segment{},

		SegmentCount:       len(p.progs),
		SectionCount:       max(len(p.sects)-1, 0),
		SymbolCount:        p.syms.symCount,
		DynamicSymbolCount: p.syms.dynCount,
		ImportCount:        importCount,
		ExportCount:        len(p.syms.exports),
	}
	if h.is64 {
		d.Class = "ELF64"
	}
	if h.big {
		d.Endian = "big"
	}
	_, hasSymtab := p.findSect(shtSymtab)
	d.Stripped = !hasSymtab
	for _, s := range p.sects {
		if strings.HasPrefix(s.name, ".debug_info") || strings.HasPrefix(s.name, ".zdebug_info") || s.name == ".gnu_debuglink" {
			d.HasDebugInfo = true
		}
	}
	for i, pr := range p.progs {
		if pr.typ == ptLoad && pr.flags&pfW != 0 && pr.flags&pfX != 0 {
			d.RWXSegments++
		}
		if i < p.lim.MaxList {
			d.Segments = append(d.Segments, Segment{
				Type: segmentTypeName(pr.typ), Flags: permFlags(pr.flags), Offset: pr.off,
				VAddr: fmt.Sprintf("0x%x", pr.vaddr), FileSize: pr.filesz, MemSize: pr.memsz,
			})
		}
	}
	return d
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
