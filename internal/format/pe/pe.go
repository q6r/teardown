// Package pe parses Windows Portable Executable images (EXE, DLL and driver
// files) for static triage. It reads the headers, the section table and the
// data directories that matter for triage (imports, delay-load imports,
// exports, debug, security, TLS, load configuration and the CLR header)
// without ever executing the file.
//
// The parser is hand-written on top of package binio rather than debug/pe so
// that a damaged image still yields a partial result: every unreadable
// structure becomes an entry in [Result.Notes] instead of an error, and every
// count read from the file is validated against the file size before it is used
// to allocate or loop. Parse never panics and polls its context.
//
// Besides the report facts, Parse returns a [Layout]: the address map of the
// image and the import address table slot of every recorded imported function,
// which package xref uses to find the code that calls the imports.
package pe

import (
	"context"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

// Result is the outcome of [Parse]. All slices are non-nil.
type Result struct {
	// Sections is the section table with per-section entropy and structural
	// suspicion (see report.Section).
	Sections []report.Section
	// Imports lists the imported libraries in table order. Delay-load imports
	// follow the regular ones and carry the library suffix " (delay-load)".
	// Library names keep the case used in the file; an import by ordinal is "#N".
	Imports []report.Import
	// Exports lists exported symbols: named exports in name-table order, then
	// exports that only have an ordinal ("#N"). Forwarders read "name -> target".
	Exports []string
	// Hardening has one entry per mitigation (aslr, high-entropy-va, dep, cfg,
	// seh, force-integrity, signed).
	Hardening []report.Hardening
	// ImpHash is the pefile-compatible import hash, "" when the image has no
	// regular imports or the import table could not be read completely. It
	// ignores delay-load imports. The ordinal-name tables behind it are partial
	// (see ordinals.go).
	ImpHash string
	// Details are the PE-specific facts reported under details["pe"].
	Details Details
	// Notes lists non-fatal problems met while parsing (truncated tables,
	// addresses outside the file, caps reached).
	Notes []string
	// Layout maps addresses to file offsets and names the import address table
	// slot of every recorded imported function. It is for code analysis and is
	// not part of the report.
	Layout Layout `json:"-"`
}

// Details holds the PE facts reported under details["pe"] in the report. Every
// field is always present in the JSON form; slices are never null.
type Details struct {
	// Kind is "exe", "dll" or "driver" (IMAGE_FILE_SYSTEM, or a native-subsystem
	// image that imports kernel modules such as ntoskrnl.exe).
	Kind string `json:"kind"`
	// Machine is the target architecture, e.g. "x86", "x86-64", "ARM64"; an
	// unknown machine type appears as "0x%04x".
	Machine string `json:"machine"`
	// Bits is 32 (PE32) or 64 (PE32+).
	Bits int `json:"bits"`
	// Subsystem is e.g. "windows-gui", "windows-cui", "native" or "efi-application".
	Subsystem string `json:"subsystem"`
	// Timestamp is the link time (TimeDateStamp) as RFC 3339 UTC, "" when zero.
	// Reproducible builds store a hash here, so see Reproducible before trusting it.
	Timestamp string `json:"timestamp"`
	// TimestampRaw is the unmodified TimeDateStamp.
	TimestampRaw uint32 `json:"timestampRaw"`
	// EntryPoint is AddressOfEntryPoint as a "0x" hex RVA.
	EntryPoint string `json:"entryPoint"`
	// EntrySection names the section that contains the entry point, "" when none does.
	EntrySection string `json:"entrySection"`
	// ImageBase is the preferred load address as "0x" hex.
	ImageBase string `json:"imageBase"`
	// LinkerVersion is "major.minor" of the linker that produced the image.
	LinkerVersion string `json:"linkerVersion"`
	// OSVersion and SubsystemVersion are the minimum "major.minor" versions.
	OSVersion        string `json:"osVersion"`
	SubsystemVersion string `json:"subsystemVersion"`
	// SizeOfImage is the in-memory size of the image.
	SizeOfImage uint32 `json:"sizeOfImage"`
	// Checksum is the stored (unverified) checksum as "0x" hex.
	Checksum string `json:"checksum"`
	// Characteristics and DllCharacteristics list the set flag names without the
	// IMAGE_FILE_ / IMAGE_DLLCHARACTERISTICS_ prefix.
	Characteristics    []string `json:"characteristics"`
	DllCharacteristics []string `json:"dllCharacteristics"`
	// Signed is true when an Authenticode certificate table lies inside the
	// file. The signature is never validated, and false does not mean untrusted:
	// Windows system files are usually catalog-signed and carry no embedded table.
	Signed bool `json:"signed"`
	// SignatureSize is the size of the certificate table in bytes (0 when unsigned).
	SignatureSize int `json:"signatureSize"`
	// SignatureType is the WIN_CERTIFICATE type: "pkcs7-signed-data" (Authenticode),
	// "x509", "reserved", "ts-stack-signed" or "0x%04x"; "" when unsigned.
	SignatureType string `json:"signatureType"`
	// OverlaySize counts the bytes after the last section's raw data, excluding
	// the certificate table and the COFF symbol and string tables.
	OverlaySize int64 `json:"overlaySize"`
	// PDBPath is the CodeView debug path ("" when absent). It usually reveals
	// the build machine's directory layout.
	PDBPath string `json:"pdbPath"`
	// PDBGUID and PDBAge identify the matching PDB (RSDS/NB10 records).
	PDBGUID string `json:"pdbGuid"`
	PDBAge  uint32 `json:"pdbAge"`
	// Reproducible is true when a reproducible-build debug entry exists (then
	// Timestamp is not a date).
	Reproducible bool `json:"reproducible"`
	// DotNet is true when the image has a CLR runtime header.
	DotNet bool `json:"dotNet"`
	// DotNetVersion is the metadata version string, e.g. "v4.0.30319".
	DotNetVersion string `json:"dotNetVersion"`
	// DotNetFlags lists COMIMAGE_FLAGS_* names without the prefix (ILONLY, ...).
	DotNetFlags []string `json:"dotNetFlags"`
	// TLSCallbacks counts TLS callbacks, which run before the entry point.
	TLSCallbacks int `json:"tlsCallbacks"`
	// SecurityCookie is true when the load configuration has a /GS stack cookie.
	SecurityCookie bool `json:"securityCookie"`
	// PackerHints names packers or protectors suggested by section names (UPX,
	// ASPack, ...). A hint is not proof.
	PackerHints []string `json:"packerHints"`
	// DelayImportLibraries lists the delay-loaded DLL names.
	DelayImportLibraries []string `json:"delayImportLibraries"`
	// ImportCount is the true number of imported functions (regular and
	// delay-load), even when the report lists are capped.
	ImportCount int `json:"importCount"`
	// ExportCount is the true number of exported functions (non-empty entries
	// of the export address table), even when the export list is capped.
	ExportCount int `json:"exportCount"`
	// ExportName is the DLL name recorded in the export directory.
	ExportName string `json:"exportName"`
}

const (
	maxNotes = 32
)

// parser carries the state of one Parse call.
type parser struct {
	ctx         context.Context
	raw         io.ReaderAt // uncached, for bulk reads (entropy)
	r           io.ReaderAt // cached and budgeted, for the many small reads
	cache       *blockReader
	size        int64
	lim         limits.Limits
	err         error // sticky context error
	ticks       uint32
	notes       []string
	entropyLeft int64

	peOff    int64
	h        header
	secs     []section
	tableEnd int64
	maps     rvaMap

	imports            []report.Import
	delayImports       []report.Import
	slots              []ImportSlot
	exports            []string
	importTotal        int
	recordedFuncs      int
	thunkBudget        int
	hasher             *impHasher
	impMD5             hash.Hash
	hashOK             bool
	importsTruncated   bool
	functionsTruncated bool
	exportsTruncated   bool

	certOff, certSize int64
	lc                loadConfig
	clrILOnly         bool

	det Details
	res Result
}

// Parse analyses the PE image in r, which holds size bytes. It returns
// (nil, err) only when not even the COFF header is usable; otherwise it returns
// everything it could read, with Notes describing what it could not. When ctx
// is cancelled mid-way it returns the partial result together with ctx.Err().
// Parse never executes the image and never panics on malformed input.
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	return parse(ctx, r, size, lim, readBudget)
}

// parse is Parse with an explicit budget for structure reads (tests shrink it).
func parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits, budget int64) (*Result, error) {
	p, err := newParser(ctx, r, size, lim, budget)
	if err != nil {
		return nil, err
	}
	p.run()
	return p.finish(), p.err
}

// newParser returns a parser positioned after the headers, or an error when not
// even the COFF header is usable.
func newParser(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits, budget int64) (*parser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cache := newBlockReader(r, size, budget)
	p := &parser{
		ctx: ctx, raw: r, r: cache, cache: cache, size: size, lim: lim.Normalize(),
		thunkBudget: maxThunksTotal, entropyLeft: size + 1<<20,
		det: Details{
			PackerHints: []string{}, DelayImportLibraries: []string{}, DotNetFlags: []string{},
		},
		res: Result{Sections: []report.Section{}},
	}
	if err := p.readHeaders(); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadLayout reads only what mapping an image needs: the headers, the section
// table and, when withSlots is set, the import tables for the address table slot
// of every imported function. Unlike [Parse] it measures no entropy and builds no
// report facts, so it stays cheap for a large file, and the [Layout] it returns
// is the one Parse returns for the same bytes and limits. It returns (nil, err)
// when not even the COFF header is usable and, when ctx ends first, the partial
// layout together with ctx's error. It never executes the image.
func LoadLayout(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits, withSlots bool) (*Layout, error) {
	p, err := newParser(ctx, r, size, lim, readBudget)
	if err != nil {
		return nil, err
	}
	p.readSections()
	if withSlots && p.h.hasOpt && !p.stopped() {
		p.parseImports()
		if !p.stopped() {
			p.parseDelayImports()
		}
	}
	l := p.layout()
	return &l, p.err
}

// run executes the parsing steps in order, stopping early when cancelled.
func (p *parser) run() {
	p.readSections()
	p.buildSections()
	if !p.h.hasOpt {
		return
	}
	for _, step := range []func(){
		p.parseImports, p.parseDelayImports, p.parseExports, p.parseDebug,
		p.parseSecurity, p.parseTLS, p.parseLoadConfig, p.parseCLR,
	} {
		if p.stopped() {
			return
		}
		step()
	}
}

// stopped reports whether the context is done, remembering the error.
func (p *parser) stopped() bool {
	if p.err == nil {
		p.err = p.ctx.Err()
	}
	return p.err != nil
}

// done is a cheap per-iteration check that consults the context every 64 calls.
func (p *parser) done() bool {
	p.ticks++
	if p.ticks&63 == 0 {
		return p.stopped()
	}
	return p.err != nil
}

// notef records a note once; after maxNotes entries further notes are summarised.
func (p *parser) notef(format string, args ...any) {
	if len(p.notes) > maxNotes {
		return
	}
	if len(p.notes) == maxNotes {
		p.notes = append(p.notes, "further notes were suppressed")
		return
	}
	s := fmt.Sprintf(format, args...)
	if !slices.Contains(p.notes, s) {
		p.notes = append(p.notes, s)
	}
}

// entrySection returns the name of the section containing the entry point.
func (p *parser) entrySection() string {
	rva := p.h.entry
	if rva == 0 {
		return ""
	}
	for _, s := range p.secs {
		if rva >= s.virtualAddr && uint64(rva-s.virtualAddr) < s.extent() {
			return s.name
		}
	}
	return ""
}

// kind classifies the image as exe, dll or driver.
func (p *parser) kind() string {
	switch {
	case p.h.chars&charSystem != 0:
		return "driver"
	case p.h.subsystem == subsystemNative && p.importsKernelModule():
		return "driver"
	case p.h.chars&charDLL != 0:
		return "dll"
	}
	return "exe"
}

// importsKernelModule reports whether any import library is a kernel-mode module.
func (p *parser) importsKernelModule() bool {
	for _, lib := range p.imports {
		switch l := strings.ToLower(lib.Library); {
		case strings.HasSuffix(l, ".sys"):
			return true
		case l == "ntoskrnl.exe", l == "ntkrnlpa.exe", l == "ntkrnlmp.exe", l == "ntkrpamp.exe",
			l == "hal.dll", l == "halmacpi.dll":
			return true
		}
	}
	return false
}

// bits is 64 for a PE32+ image (or, when the optional header is too damaged to
// say, a 64-bit machine) and 32 otherwise.
func (p *parser) bits() int {
	h := &p.h
	if (h.hasOpt && h.pe64) || (!h.hasOpt && machineIs64(h.machine)) {
		return 64
	}
	return 32
}

// finish derives the report facts from the parsed structures.
func (p *parser) finish() *Result {
	h, d := &p.h, &p.det
	d.Kind = p.kind()
	d.Machine = machineName(h.machine)
	d.Bits = p.bits()
	d.Subsystem = subsystemName(h.subsystem)
	d.TimestampRaw = h.timestamp
	if h.timestamp != 0 {
		d.Timestamp = time.Unix(int64(h.timestamp), 0).UTC().Format(time.RFC3339)
	}
	d.EntryPoint = fmt.Sprintf("0x%x", h.entry)
	d.EntrySection = p.entrySection()
	if h.hasOpt && h.entry != 0 && d.EntrySection == "" && int64(h.entry) >= p.maps.headerEnd {
		p.notef("the entry point RVA %#x does not lie inside any section", h.entry)
	}
	d.ImageBase = fmt.Sprintf("0x%x", h.imageBase)
	d.LinkerVersion = fmt.Sprintf("%d.%d", h.linkerMajor, h.linkerMinor)
	d.OSVersion = fmt.Sprintf("%d.%d", h.osMajor, h.osMinor)
	d.SubsystemVersion = fmt.Sprintf("%d.%d", h.subMajor, h.subMinor)
	d.SizeOfImage = h.sizeOfImage
	d.Checksum = fmt.Sprintf("0x%x", h.checksum)
	d.Characteristics = flagNames(uint32(h.chars), coffCharacteristics)
	d.DllCharacteristics = flagNames(uint32(h.dllChars), dllCharacteristicNames)
	d.OverlaySize = p.overlaySize()
	d.ImportCount = p.importTotal
	slices.Sort(d.PackerHints)
	if p.functionsTruncated {
		p.notef("imported function lists are capped (%d per library, %d in total); importCount is exact", p.lim.MaxList, p.lim.MaxList*4)
	}
	if p.cache.denied {
		p.notef("the budget for reading structure data was exhausted; the result is incomplete (crafted image?)")
	}

	res := &p.res
	res.Imports = append(append([]report.Import{}, p.imports...), p.delayImports...)
	res.Exports = append([]string{}, p.exports...)
	res.Hardening = p.buildHardening()
	res.Details = *d
	res.Layout = p.layout()
	res.Notes = append([]string{}, p.notes...)
	return res
}
