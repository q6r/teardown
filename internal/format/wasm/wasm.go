// Package wasm lists the sections, imports and exports of a WebAssembly binary
// module and extracts a few well-known custom sections (producers,
// target_features, name). It never validates, instantiates or executes the
// module: function bodies and data are not even read, only measured.
package wasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/entropy"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

const (
	headerLen    = 8
	maxNameRunes = 256
	maxNotes     = 40
	maxProducers = 64
	// nameProbe is how many bytes are read to decode the name of a custom section.
	nameProbe = 5 + 4*maxNameRunes

	// componentVersion is the version and layer words of a component-model
	// preamble ("\0asm" 0x0d 0x00 0x01 0x00) read as one little-endian integer.
	componentVersion = 0x0001000d
)

// Section kinds reported in Details.Kind.
const (
	kindModule    = "module"
	kindComponent = "component"
)

// Core section ids.
const (
	idCustom    = 0
	idType      = 1
	idImport    = 2
	idFunction  = 3
	idTable     = 4
	idMemory    = 5
	idGlobal    = 6
	idExport    = 7
	idStart     = 8
	idElement   = 9
	idCode      = 10
	idData      = 11
	idDataCount = 12
	idTag       = 13
)

// Import and export kinds.
const (
	kindFunc   = 0
	kindTable  = 1
	kindMemory = 2
	kindGlobal = 3
	kindTag    = 4
)

var magic = []byte("\x00asm")

// Result is what Parse learned about a WebAssembly binary.
type Result struct {
	// Sections lists the sections in file order, named after the standard
	// section ("type", "import", ..., "code", "data") or "custom:<name>". Offset
	// and RawSize describe the section payload. Only the code section carries the
	// X flag.
	Sections []report.Section
	// Imports groups imported items by module; each entry of Functions reads
	// "<kind> <field>", for example "func puts" or "memory memory".
	Imports []report.Import
	// Exports lists exported items as "<kind> <name>".
	Exports []string
	// Details holds the facts stored under report.details["wasm"].
	Details Details
	// Notes lists the non-fatal problems met while parsing.
	Notes []string
}

// Details are the WebAssembly facts stored in the report under details["wasm"].
type Details struct {
	// Kind is "module" or "component".
	Kind string `json:"kind"`
	// Version is the binary format version: 1 for modules, 13 for components.
	Version uint32 `json:"version"`
	// Layer is the component-model layer (1) and is only set for components.
	Layer int `json:"layer,omitempty"`
	// SectionCount is the number of sections walked.
	SectionCount int `json:"sectionCount"`
	// TypeCount is the number of function types declared.
	TypeCount int `json:"typeCount"`
	// FunctionCount is the number of functions the module defines (the size of
	// the function section); imported functions are counted by ImportCount.
	FunctionCount int `json:"functionCount"`
	// ImportCount and ExportCount are the true numbers of imports and exports
	// decoded, even when the lists in Result are capped.
	ImportCount int `json:"importCount"`
	ExportCount int `json:"exportCount"`
	// Memories lists imported and defined memories.
	Memories []Memory `json:"memories"`
	// Tables and Globals count imported plus defined tables and globals.
	Tables  int `json:"tables"`
	Globals int `json:"globals"`
	// Start is the index of the start function, or -1 when there is none.
	Start int64 `json:"start"`
	// DataSegments and ElementSegments are the sizes of the data and element sections.
	DataSegments    int `json:"dataSegments"`
	ElementSegments int `json:"elementSegments"`
	// CustomSections lists the names of the custom sections.
	CustomSections []string `json:"customSections"`
	// HasNameSection is true when the module carries a "name" custom section
	// (function and local names, usually removed from release builds).
	HasNameSection bool `json:"hasNameSection"`
	// Producers is the content of the "producers" custom section: which
	// languages, tools and SDKs built the module.
	Producers []Producer `json:"producers"`
	// Features is the content of the "target_features" custom section, each
	// feature prefixed with + (used), - (disallowed) or = (required).
	Features []string `json:"features"`
}

// Memory is the limits of a linear memory, in 64 KiB pages.
type Memory struct {
	Min uint64 `json:"min"`
	// Max is null when the memory has no declared maximum.
	Max      *uint64 `json:"max"`
	Shared   bool    `json:"shared"`
	Memory64 bool    `json:"memory64"`
}

// Producer is one entry of the "producers" custom section.
type Producer struct {
	// Field is "language", "processed-by" or "sdk".
	Field   string `json:"field"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Parse decodes the section structure of the WebAssembly binary in r (size
// bytes). It returns (nil, err) only when the 8-byte header is missing or wrong;
// any later problem yields a partial Result and a Note. When ctx ends the
// partial Result is returned together with the context error.
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	hdr, err := binio.ReadAt(r, size, 0, headerLen)
	if err != nil {
		return nil, errors.New("not a WebAssembly binary: the file is shorter than the 8-byte header")
	}
	if !bytes.Equal(hdr[:4], magic) {
		return nil, errors.New(`not a WebAssembly binary: the file does not start with "\0asm"`)
	}
	p := &parser{
		ctx: ctx, r: r, size: size, lim: lim.Normalize(),
		res: &Result{
			Sections: []report.Section{},
			Imports:  []report.Import{},
			Exports:  []string{},
			Details: Details{
				Memories: []Memory{}, Start: -1, CustomSections: []string{},
				Producers: []Producer{}, Features: []string{},
			},
			Notes: []string{},
		},
		imports: map[string]int{},
	}
	p.header(binary.LittleEndian.Uint32(hdr[4:]))
	err = p.run()
	p.finish()
	return p.res, err
}

// parser carries the state of one Parse call.
type parser struct {
	ctx  context.Context
	r    io.ReaderAt
	size int64
	lim  limits.Limits
	res  *Result

	component bool
	lastRank  int
	imports   map[string]int // module name -> index in res.Imports

	functions, bodies     int
	hasFunctions, hasCode bool
	declaredData          int
	hasDataCount, hasData bool
	modulesDropped        bool
	omitted               int // notes dropped after the cap
}

func (p *parser) note(format string, args ...any) {
	if len(p.res.Notes) >= maxNotes {
		p.omitted++
		return
	}
	p.res.Notes = append(p.res.Notes, fmt.Sprintf(format, args...))
}

func (p *parser) header(version uint32) {
	d := &p.res.Details
	switch version {
	case 1:
		d.Kind, d.Version = kindModule, 1
	case componentVersion:
		p.component = true
		d.Kind, d.Version, d.Layer = kindComponent, 13, 1
		p.note("WebAssembly component: only the section framing is decoded, not the contents")
	default:
		d.Kind, d.Version = kindModule, version
		p.note("unsupported binary version %d; the sections are decoded as a version 1 module", version)
	}
}

// run walks the sections.
func (p *parser) run() error {
	off := int64(headerLen)
	for walked := 0; off < p.size; walked++ {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if walked >= p.lim.MaxList {
			p.note("stopped after %d sections; the file has more", walked)
			return nil
		}
		head, err := binio.ReadUpTo(p.r, p.size, off, 6) // id plus a LEB128 size of at most 5 bytes
		if err != nil {
			return fmt.Errorf("reading the section header at offset %d: %w", off, err)
		}
		if len(head) < 2 {
			p.note("truncated section header at offset %d", off)
			return nil
		}
		id := head[0]
		length, n, err := leb32(head[1:])
		if err != nil {
			p.note("section %d at offset %d has a malformed size: %v", id, off, err)
			return nil
		}
		payload := off + 1 + int64(n)
		avail := p.size - payload
		want := int64(length)
		cut := want > avail
		if cut {
			p.note("%s section at offset %d declares %d bytes but only %d remain; the file looks truncated",
				p.sectionName(id), off, want, avail)
			want = avail
		}
		p.section(id, payload, want)
		if cut {
			return nil
		}
		off = payload + want
	}
	return nil
}

func (p *parser) sectionName(id byte) string {
	if p.component {
		return componentSectionName(id)
	}
	return coreSectionName(id)
}

func coreSectionName(id byte) string {
	switch id {
	case idCustom:
		return "custom"
	case idType:
		return "type"
	case idImport:
		return "import"
	case idFunction:
		return "function"
	case idTable:
		return "table"
	case idMemory:
		return "memory"
	case idGlobal:
		return "global"
	case idExport:
		return "export"
	case idStart:
		return "start"
	case idElement:
		return "element"
	case idCode:
		return "code"
	case idData:
		return "data"
	case idDataCount:
		return "datacount"
	case idTag:
		return "tag"
	}
	return fmt.Sprintf("unknown(%d)", id)
}

func componentSectionName(id byte) string {
	names := [...]string{"custom", "core:module", "core:instance", "core:type", "component", "instance",
		"alias", "type", "canon", "start", "import", "export", "value"}
	if int(id) < len(names) {
		return names[id]
	}
	return fmt.Sprintf("unknown(%d)", id)
}

// sectionRank is the position a standard section must have in a module (0 for
// custom and unknown ids, which may appear anywhere).
func sectionRank(id byte) int {
	switch id {
	case idType:
		return 1
	case idImport:
		return 2
	case idFunction:
		return 3
	case idTable:
		return 4
	case idMemory:
		return 5
	case idTag:
		return 6
	case idGlobal:
		return 7
	case idExport:
		return 8
	case idStart:
		return 9
	case idElement:
		return 10
	case idDataCount:
		return 11
	case idCode:
		return 12
	case idData:
		return 13
	}
	return 0
}

// section records one section and decodes what is worth knowing about it.
func (p *parser) section(id byte, off, length int64) {
	det := &p.res.Details
	det.SectionCount++
	name := p.sectionName(id)
	custom := ""
	if id == idCustom {
		custom = p.customName(off, length)
		name = "custom:" + custom
	}
	if len(p.res.Sections) < p.lim.MaxList {
		p.res.Sections = append(p.res.Sections, p.describe(name, id, off, length))
	}
	switch {
	case id == idCustom:
		p.customSection(custom, off, length)
	case !p.component:
		p.coreSection(id, off, length)
	}
}

func (p *parser) describe(name string, id byte, off, length int64) report.Section {
	ent, err := entropy.Range(p.r, off, length)
	if err != nil {
		p.note("could not measure the entropy of the %s section: %v", name, err)
	}
	flags := []string{}
	if !p.component && id == idCode {
		flags = append(flags, report.FlagX)
	}
	return report.Section{Name: name, RawSize: uint64(length), Offset: uint64(off), Entropy: ent, Flags: flags}
}

// coreSection decodes the contents of the standard sections that matter.
func (p *parser) coreSection(id byte, off, length int64) {
	det := &p.res.Details
	if rank := sectionRank(id); rank > 0 {
		if rank <= p.lastRank {
			p.note("%s section at offset %d is out of order or repeated", coreSectionName(id), off)
		}
		p.lastRank = max(p.lastRank, rank)
	}
	switch id {
	case idType:
		det.TypeCount = p.count("type", off, length)
	case idImport:
		p.decodeImports(off, length)
	case idFunction:
		p.functions, p.hasFunctions = p.count("function", off, length), true
		det.FunctionCount = p.functions
	case idTable:
		det.Tables += p.count("table", off, length)
	case idMemory:
		p.decodeMemories(off, length)
	case idGlobal:
		det.Globals += p.count("global", off, length)
	case idExport:
		p.decodeExports(off, length)
	case idStart:
		p.decodeStart(off, length)
	case idElement:
		det.ElementSegments = p.count("element", off, length)
	case idCode:
		p.bodies, p.hasCode = p.count("code", off, length), true
	case idData:
		det.DataSegments, p.hasData = p.count("data", off, length), true
	case idDataCount:
		p.declaredData, p.hasDataCount = p.number("datacount", off, length), true
	case idTag:
		// Exception-handling tags carry no facts worth recording.
	default:
		p.note("unknown section id %d at offset %d", id, off)
	}
}

// payload reads a section's content for decoding, at most MaxMeta bytes.
func (p *parser) payload(what string, off, length int64) ([]byte, bool) {
	n := min(length, p.lim.MaxMeta)
	b, err := binio.ReadAt(p.r, p.size, off, n)
	if err != nil {
		p.note("could not read the %s section: %v", what, err)
		return nil, false
	}
	if n < length {
		p.note("the %s section is %d bytes; only its first %d were decoded (metadata limit)", what, length, n)
	}
	return b, true
}

// number reads the unsigned 32-bit integer at the start of a section.
func (p *parser) number(what string, off, length int64) int {
	head, err := binio.ReadUpTo(p.r, p.size, off, min(length, 5))
	if err != nil {
		p.note("could not read the %s section: %v", what, err)
		return 0
	}
	v, _, err := leb32(head)
	if err != nil {
		p.note("the %s section does not start with a valid integer: %v", what, err)
		return 0
	}
	return int(v)
}

// count reads the entry count at the start of a vector section. A count larger
// than the section's byte length cannot be right (every entry takes at least a
// byte) and is ignored.
func (p *parser) count(what string, off, length int64) int {
	n := p.number(what, off, length)
	if int64(n) > length {
		p.note("the %s section declares %d entries in %d bytes; the count is ignored", what, n, length)
		return 0
	}
	return n
}

func kindName(kind byte) string {
	switch kind {
	case kindFunc:
		return "func"
	case kindTable:
		return "table"
	case kindMemory:
		return "memory"
	case kindGlobal:
		return "global"
	case kindTag:
		return "tag"
	}
	return fmt.Sprintf("unknown(%d)", kind)
}

func (p *parser) addMemory(lo, hi uint64, hasMax, shared, is64 bool) {
	if len(p.res.Details.Memories) >= p.lim.MaxList {
		return
	}
	m := Memory{Min: lo, Shared: shared, Memory64: is64}
	if hasMax {
		m.Max = &hi
	}
	p.res.Details.Memories = append(p.res.Details.Memories, m)
}

func (p *parser) decodeMemories(off, length int64) {
	data, ok := p.payload("memory", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	n := d.u32()
	for i := uint32(0); i < n && d.err == nil; i++ {
		lo, hi, hasMax, shared, is64 := d.limits()
		if d.err == nil {
			p.addMemory(lo, hi, hasMax, shared, is64)
		}
	}
	if d.err != nil {
		p.note("the memory section is malformed: %v", d.err)
	}
}

func (p *parser) decodeImports(off, length int64) {
	data, ok := p.payload("import", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	n := d.u32()
	for i := uint32(0); i < n && d.err == nil; i++ {
		if i&0x3ff == 0x3ff && p.ctx.Err() != nil {
			return
		}
		module := d.name(maxNameRunes)
		field := d.name(maxNameRunes)
		kind := d.byte()
		if d.err != nil {
			break
		}
		p.importDescriptor(d, kind)
		if d.err != nil {
			break
		}
		p.addImport(module, kindName(kind)+" "+field)
	}
	if d.err != nil {
		p.note("the import section is malformed after %d imports: %v", p.res.Details.ImportCount, d.err)
	}
}

// importDescriptor decodes the type that follows an import's names. Memories,
// tables and globals are counted; an unknown kind makes the section undecodable.
func (p *parser) importDescriptor(d *reader, kind byte) {
	det := &p.res.Details
	switch kind {
	case kindFunc:
		d.u32()
	case kindTable:
		d.valType()
		d.limits()
		det.Tables++
	case kindMemory:
		lo, hi, hasMax, shared, is64 := d.limits()
		if d.err == nil {
			p.addMemory(lo, hi, hasMax, shared, is64)
		}
	case kindGlobal:
		d.valType()
		d.byte()
		det.Globals++
	case kindTag:
		d.byte()
		d.u32()
	default:
		d.fail(fmt.Errorf("%w: import kind %d", errFormat, kind))
	}
}

func (p *parser) addImport(module, entry string) {
	p.res.Details.ImportCount++
	idx, known := p.imports[module]
	if !known {
		if len(p.res.Imports) >= p.lim.MaxList {
			p.modulesDropped = true
			return
		}
		idx = len(p.res.Imports)
		p.imports[module] = idx
		p.res.Imports = append(p.res.Imports, report.Import{Library: module, Functions: []string{}})
	}
	imp := &p.res.Imports[idx]
	imp.Count++
	if len(imp.Functions) < p.lim.MaxList {
		imp.Functions = append(imp.Functions, entry)
	}
}

func (p *parser) decodeExports(off, length int64) {
	data, ok := p.payload("export", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	n := d.u32()
	for i := uint32(0); i < n && d.err == nil; i++ {
		if i&0x3ff == 0x3ff && p.ctx.Err() != nil {
			return
		}
		name := d.name(maxNameRunes)
		kind := d.byte()
		d.u32() // the index of the exported item
		if d.err != nil {
			break
		}
		p.res.Details.ExportCount++
		if len(p.res.Exports) < p.lim.MaxList {
			p.res.Exports = append(p.res.Exports, kindName(kind)+" "+name)
		}
	}
	if d.err != nil {
		p.note("the export section is malformed after %d exports: %v", p.res.Details.ExportCount, d.err)
	}
}

func (p *parser) decodeStart(off, length int64) {
	data, ok := p.payload("start", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	if idx := d.u32(); d.err == nil {
		p.res.Details.Start = int64(idx)
		return
	}
	p.note("the start section is malformed: %v", d.err)
}

// customName reads the name that opens a custom section.
func (p *parser) customName(off, length int64) string {
	head, err := binio.ReadUpTo(p.r, p.size, off, min(length, nameProbe))
	if err != nil {
		return "?"
	}
	d := &reader{b: head}
	name := d.name(maxNameRunes)
	if d.err != nil {
		return "?"
	}
	return name
}

func (p *parser) customSection(name string, off, length int64) {
	det := &p.res.Details
	if len(det.CustomSections) < p.lim.MaxList {
		det.CustomSections = append(det.CustomSections, name)
	}
	switch name {
	case "name":
		det.HasNameSection = true
	case "producers":
		p.decodeProducers(off, length)
	case "target_features":
		p.decodeFeatures(off, length)
	}
}

func (p *parser) decodeProducers(off, length int64) {
	data, ok := p.payload("producers", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	d.name(maxNameRunes) // the section name
	limit := min(maxProducers, p.lim.MaxList)
	fields := d.u32()
	for i := uint32(0); i < fields && d.err == nil; i++ {
		field := d.name(maxNameRunes)
		values := d.u32()
		for j := uint32(0); j < values && d.err == nil; j++ {
			name, version := d.name(maxNameRunes), d.name(maxNameRunes)
			if d.err == nil && len(p.res.Details.Producers) < limit {
				p.res.Details.Producers = append(p.res.Details.Producers, Producer{Field: field, Name: name, Version: version})
			}
		}
	}
	if d.err != nil {
		p.note("the producers section is malformed: %v", d.err)
	}
}

func (p *parser) decodeFeatures(off, length int64) {
	data, ok := p.payload("target_features", off, length)
	if !ok {
		return
	}
	d := &reader{b: data}
	d.name(maxNameRunes) // the section name
	n := d.u32()
	for i := uint32(0); i < n && d.err == nil; i++ {
		prefix := d.byte()
		name := d.name(maxNameRunes)
		if d.err != nil {
			break
		}
		if prefix != '+' && prefix != '-' && prefix != '=' {
			prefix = '?'
		}
		if len(p.res.Details.Features) < p.lim.MaxList {
			p.res.Details.Features = append(p.res.Details.Features, string(rune(prefix))+name)
		}
	}
	if d.err != nil {
		p.note("the target_features section is malformed: %v", d.err)
	}
}

// finish cross-checks the sections against each other and flushes bookkeeping notes.
func (p *parser) finish() {
	switch {
	case p.hasFunctions && p.hasCode && p.functions != p.bodies:
		p.note("the function section declares %d functions but the code section has %d bodies", p.functions, p.bodies)
	case p.hasFunctions && !p.hasCode && p.functions > 0:
		p.note("the module declares %d functions but has no code section", p.functions)
	case p.hasCode && !p.hasFunctions && p.bodies > 0:
		p.note("the module has %d function bodies but no function section", p.bodies)
	}
	if p.hasDataCount && p.hasData && p.declaredData != p.res.Details.DataSegments {
		p.note("the datacount section declares %d segments but the data section has %d", p.declaredData, p.res.Details.DataSegments)
	}
	if p.modulesDropped {
		p.note("imports come from more than %d modules; the list of modules is capped", p.lim.MaxList)
	}
	if p.omitted > 0 {
		p.res.Notes = append(p.res.Notes, fmt.Sprintf("%d further notes omitted", p.omitted))
	}
}
