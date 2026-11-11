// Package macho analyses Mach-O images (macOS, iOS and other Apple platforms),
// thin or universal ("fat"): header facts, segments and sections with entropy,
// dylibs, rpaths, imported and exported symbols, UUID, build platform, and a
// hardening summary (PIE, non-executable stack, stack canary, code signature,
// App Store encryption).
//
// Load commands are decoded by a small bounds-checked walker rather than
// debug/macho, because debug/macho is all-or-nothing on damaged files and does
// not expose rpaths, the UUID, the code signature, encryption info or the build
// version. debug/macho remains the reference the tests compare against.
// Only the presence of the code signature is reported: signatures are not
// verified and the hardened-runtime flags inside them are not decoded.
// Nothing is ever executed.
package macho

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/entropy"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

const unspecified = report.UnspecifiedLibrary

// maxArches bounds the number of slices read from a universal header (real
// binaries have a handful).
const maxArches = 64

// Result is everything the parser could recover from an image.
type Result struct {
	// Sections lists "SEGMENT,section" entries of the primary slice (and
	// section-less segments that hold file data, such as __LINKEDIT), with entropy.
	Sections []report.Section
	// Imports groups the primary slice's undefined external symbols by the dylib
	// named by their library ordinal (two-level namespace); the rest fall under
	// [report.UnspecifiedLibrary]. Names have one leading underscore removed.
	Imports []report.Import
	// Exports lists the primary slice's defined external symbols, sorted.
	Exports []string
	// Hardening holds the pie, nx, canary, signed and encrypted entries.
	Hardening []report.Hardening
	Details   Details
	// Notes explains anything that was skipped or looked malformed.
	Notes []string
}

// Details holds the Mach-O facts stored under details["macho"].
type Details struct {
	// Fat is true for universal binaries.
	Fat bool `json:"fat"`
	// PrimarySlice indexes Slices: the slice that Result.Sections, Imports,
	// Exports and Hardening describe (first arm64, else first x86_64, else the
	// first slice that could be parsed).
	PrimarySlice int     `json:"primarySlice"`
	Slices       []Slice `json:"slices"`
	// ImportCount and ExportCount are the true numbers of undefined and defined
	// external symbols of the primary slice.
	ImportCount int `json:"importCount"`
	ExportCount int `json:"exportCount"`
}

// Slice describes one architecture of the file.
type Slice struct {
	// CPU is "x86_64", "arm64", "arm64e", "x86", "arm", ...
	CPU string `json:"cpu"`
	// Type is "executable", "dylib", "bundle", "object", "kext", ...
	Type   string `json:"type"`
	Bits   int    `json:"bits"`
	Endian string `json:"endian"`
	// Offset and Size locate the slice inside the file (0 and the file size for
	// thin files). Segment and section offsets below are relative to the slice.
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
	// Flags names the mach_header flag bits that are set (PIE, TWOLEVEL, ...).
	Flags  []string `json:"flags"`
	Dylibs []string `json:"dylibs"`
	RPaths []string `json:"rpaths"`
	// InstallName is the LC_ID_DYLIB name of a dylib.
	InstallName string `json:"installName"`
	UUID        string `json:"uuid"`
	// Signed is true when an LC_CODE_SIGNATURE command exists (presence only).
	Signed bool `json:"signed"`
	// Encrypted is true when LC_ENCRYPTION_INFO has a non-zero cryptid.
	Encrypted bool `json:"encrypted"`
	// Platform, MinOS and SDK come from LC_BUILD_VERSION or LC_VERSION_MIN_*.
	Platform string `json:"platform"`
	MinOS    string `json:"minOS"`
	SDK      string `json:"sdk"`
	// EntryOffset is the LC_MAIN entry point offset as a hexadecimal string.
	EntryOffset  string    `json:"entryOffset,omitempty"`
	Segments     []Segment `json:"segments"`
	LoadCommands int       `json:"loadCommands"`
	SymbolCount  int       `json:"symbolCount"`
	// Error is set when the slice could not be parsed at all.
	Error string `json:"error,omitempty"`
}

// Segment is one LC_SEGMENT(_64) command.
type Segment struct {
	Name string `json:"name"`
	// VMAddr is a hexadecimal string; sizes and offsets are in bytes.
	VMAddr     string `json:"vmAddr"`
	VMSize     uint64 `json:"vmSize"`
	FileOffset uint64 `json:"fileOffset"`
	FileSize   uint64 `json:"fileSize"`
	// Flags are the initial protections: R, W and X.
	Flags        []string `json:"flags"`
	SectionCount int      `json:"sectionCount"`
}

type parser struct {
	ctx   context.Context
	file  io.ReaderAt
	size  int64
	lim   limits.Limits
	notes []string

	truncated int
	// entropyBudget is how many bytes entropy measurements may still read. Real
	// sections do not overlap, so twice the file size plus a megabyte is generous;
	// a crafted load command table whose sections all claim the whole file runs
	// out of it.
	entropyBudget int64
	skipped       int
}

func (p *parser) note(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if len(p.notes) < 50 && !slices.Contains(p.notes, msg) {
		p.notes = append(p.notes, msg)
	}
}

// Parse analyses the Mach-O image (thin or universal) of the given size
// readable through r. It never panics and never executes the image. When the
// header is unusable it returns (nil, err); otherwise it returns whatever could
// be recovered together with Notes, and, on cancellation, the partial result
// with ctx.Err().
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	size = max(size, 0)
	file := io.NewSectionReader(r, 0, size)
	p := &parser{ctx: ctx, file: file, size: size, lim: lim.Normalize(), entropyBudget: 2*size + 1<<20}
	head, err := binio.ReadUpTo(file, size, 0, 8)
	if err != nil {
		return nil, fmt.Errorf("reading the Mach-O header: %w", err)
	}
	if len(head) < 4 {
		return nil, fmt.Errorf("%w: only %d bytes, a Mach-O header needs at least 28", errNotMachO, len(head))
	}
	switch binary.BigEndian.Uint32(head) {
	case 0xcafebabe:
		return p.parseFat(false)
	case 0xcafebabf:
		return p.parseFat(true)
	}
	t, err := parseThin(ctx, file, 0, size, p.lim)
	if err != nil {
		return nil, err
	}
	return p.assemble([]*thin{t}, []string{""}, 0, false)
}

type fatArch struct {
	cpu, sub     uint32
	offset, size uint64
}

func (p *parser) parseFat(is64 bool) (*Result, error) {
	head, err := binio.ReadUpTo(p.file, p.size, 0, 8)
	if err != nil || len(head) < 8 {
		return nil, fmt.Errorf("truncated universal header: need 8 bytes, have %d", len(head))
	}
	n := uint64(binary.BigEndian.Uint32(head[4:]))
	if n == 0 || n > maxArches {
		return nil, fmt.Errorf("%w: implausible universal binary with %d architectures (a Java class file shares this magic number)", errNotMachO, n)
	}
	entSize := uint64(20)
	if is64 {
		entSize = 32
	}
	if fit := (uint64(p.size) - 8) / entSize; n > fit {
		p.note("the universal header declares %d architectures but only %d fit in the file", n, fit)
		n = fit
	}
	raw, err := binio.ReadAt(p.file, p.size, 8, int64(n*entSize))
	if err != nil {
		return nil, fmt.Errorf("reading the universal header: %w", err)
	}
	c := binio.NewCursor(raw, binary.BigEndian)
	arches := make([]fatArch, 0, n)
	for range n {
		a := fatArch{cpu: c.U32(), sub: c.U32()}
		if is64 {
			a.offset, a.size = c.U64(), c.U64()
			c.Skip(8) // align, reserved
		} else {
			a.offset, a.size = uint64(c.U32()), uint64(c.U32())
			c.Skip(4) // align
		}
		arches = append(arches, a)
	}

	var thins []*thin
	var errs []string
	valid := 0
	for i, a := range arches {
		if err := p.ctx.Err(); err != nil {
			return nil, err
		}
		var t *thin
		var msg string
		switch {
		case a.offset >= uint64(p.size):
			msg = fmt.Sprintf("slice offset %#x lies outside the file (%d bytes)", a.offset, p.size)
		default:
			sz := a.size
			if avail := uint64(p.size) - a.offset; sz > avail {
				p.note("slice %d (%s) is truncated: %d of %d bytes are present", i, cpuName(a.cpu, a.sub), avail, sz)
				sz = avail
			}
			t, err = parseThin(p.ctx, p.file, int64(a.offset), int64(sz), p.lim)
			if err != nil {
				msg = err.Error()
				t = nil
			}
		}
		if t == nil {
			t = &thin{base: int64(min(a.offset, uint64(p.size))), size: int64(a.size), cpu: a.cpu, subcpu: a.sub}
		} else {
			valid++
		}
		thins = append(thins, t)
		errs = append(errs, msg)
	}
	if valid == 0 {
		return nil, fmt.Errorf("%w: none of the %d universal slices holds a valid Mach-O image", errNotMachO, len(arches))
	}
	primary := choosePrimary(thins, errs)
	return p.assemble(thins, errs, primary, true)
}

// choosePrimary picks the slice described by the top-level result: the first
// arm64, else the first x86_64, else the first slice that parsed.
func choosePrimary(thins []*thin, errs []string) int {
	for _, want := range []uint32{cpuARM64, cpuAMD64} {
		for i, t := range thins {
			if errs[i] == "" && t.cpu == want {
				return i
			}
		}
	}
	for i := range thins {
		if errs[i] == "" {
			return i
		}
	}
	return 0
}

func (p *parser) assemble(thins []*thin, errs []string, primary int, fat bool) (*Result, error) {
	res := &Result{
		Sections: []report.Section{}, Imports: []report.Import{}, Exports: []string{},
		Hardening: []report.Hardening{},
		Details:   Details{Fat: fat, PrimarySlice: primary, Slices: make([]Slice, 0, len(thins))},
	}
	t := thins[primary]
	usable := errs[primary] == ""
	var si symbolInfo
	if usable && p.ctx.Err() == nil {
		si = t.scanSymbols(p.ctx, io.NewSectionReader(p.file, t.base, t.size), p.lim)
	}
	for i, th := range thins {
		res.Details.Slices = append(res.Details.Slices, p.sliceDetails(th, errs[i]))
		for _, n := range th.notes {
			if fat {
				n = fmt.Sprintf("slice %d (%s): %s", i, cpuName(th.cpu, th.subcpu), n)
			}
			p.note("%s", n)
		}
	}
	if fat && usable {
		p.note("universal binary with %d slices; sections, imports and hardening describe the %s slice (index %d)", len(thins), cpuName(t.cpu, t.subcpu), primary)
	}
	res.Imports, res.Details.ImportCount = importList(si, p.lim.MaxList)
	res.Exports = exportList(si, p.lim.MaxList)
	res.Details.ExportCount = si.exportCount
	if usable {
		res.Hardening = p.hardening(t, si)
		if p.ctx.Err() == nil {
			res.Sections = p.sections(t)
		}
	}
	res.Notes = p.notes
	if res.Notes == nil {
		res.Notes = []string{}
	}
	return res, p.ctx.Err()
}

func (p *parser) sliceDetails(t *thin, errMsg string) Slice {
	s := Slice{
		CPU: cpuName(t.cpu, t.subcpu), Type: typeName(t.typ), Bits: 32, Endian: "little",
		Offset: t.base, Size: t.size,
		Flags: flagNames(t.flags), Dylibs: nonNil(t.dylibs), RPaths: nonNil(t.rpaths),
		InstallName: t.installName, UUID: t.uuid, Signed: t.signed, Encrypted: t.hasEncCmd && t.cryptID != 0,
		Platform: t.platform, MinOS: t.minOS, SDK: t.sdk,
		Segments: []Segment{}, LoadCommands: t.loadCommands, Error: errMsg,
	}
	if t.is64 {
		s.Bits = 64
	}
	if t.big {
		s.Endian = "big"
	}
	if t.haveSymtab {
		s.SymbolCount = int(t.nsyms)
	}
	if t.entryOffset != nil {
		s.EntryOffset = fmt.Sprintf("0x%x", *t.entryOffset)
	}
	if errMsg != "" {
		s.Type, s.Bits, s.Endian = "", 0, ""
	}
	for i, seg := range t.segments {
		if i >= p.lim.MaxList {
			break
		}
		s.Segments = append(s.Segments, Segment{
			Name: seg.name, VMAddr: fmt.Sprintf("0x%x", seg.vmaddr), VMSize: seg.vmsize,
			FileOffset: seg.fileoff, FileSize: seg.filesize, Flags: protFlags(seg.initprot), SectionCount: int(seg.nsects),
		})
	}
	return s
}

// sections builds the report sections of the primary slice.
func (p *parser) sections(t *thin) []report.Section {
	out := []report.Section{}
	for _, seg := range t.segments {
		if len(out) >= p.lim.MaxList || p.ctx.Err() != nil {
			break
		}
		flags := protFlags(seg.initprot)
		rwx := seg.initprot&2 != 0 && seg.initprot&4 != 0
		if len(seg.sections) == 0 {
			if seg.filesize == 0 {
				continue // __PAGEZERO and other pure address-space reservations
			}
			out = append(out, p.sectionEntry(t, seg.name, flags, rwx, seg.vmsize, seg.filesize, seg.fileoff, false))
			continue
		}
		for _, sec := range seg.sections {
			if len(out) >= p.lim.MaxList {
				break
			}
			raw, off := sec.size, uint64(sec.offset)
			if sec.zerofill || sec.offset == 0 {
				raw, off = 0, 0
			}
			out = append(out, p.sectionEntry(t, sec.name, flags, rwx, sec.size, raw, off, sec.zerofill))
		}
	}
	if p.truncated > 0 {
		p.note("%d section(s) extend past the end of the file; their entropy covers only the bytes that exist", p.truncated)
	}
	if p.skipped > 0 {
		p.note("entropy was not computed for %d range(s): the section data overlaps far more than the file size allows", p.skipped)
	}
	return out
}

func (p *parser) sectionEntry(t *thin, name string, flags []string, rwx bool, vsize, raw, off uint64, zerofill bool) report.Section {
	sec := report.Section{Name: name, VirtualSize: vsize, RawSize: raw, Flags: flags}
	var reasons []string
	if rwx {
		reasons = append(reasons, "writable and executable segment")
	}
	if raw > 0 && !zerofill {
		sec.Offset = uint64(t.base) + off
		var extra string
		sec.Entropy, extra = p.entropyOf(t, off, raw)
		if extra != "" {
			reasons = append(reasons, extra)
		}
	}
	sec.Reasons, sec.Suspicious = reasons, len(reasons) > 0
	return sec
}

// entropyOf measures the part of [off, off+n) (relative to the slice) that
// exists inside the slice.
func (p *parser) entropyOf(t *thin, off, n uint64) (float64, string) {
	if off >= uint64(t.size) {
		p.truncated++
		return 0, "data lies outside the file"
	}
	reason := ""
	if avail := uint64(t.size) - off; n > avail {
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
	h, err := entropy.Range(p.file, t.base+int64(off), int64(n))
	if err != nil {
		p.note("entropy of the range at offset %#x could not be computed: %v", uint64(t.base)+off, err)
		return 0, reason
	}
	return h, reason
}

func importList(si symbolInfo, maxList int) ([]report.Import, int) {
	out := []report.Import{}
	libs := make([]string, 0, len(si.imports))
	for lib := range si.imports {
		libs = append(libs, lib)
	}
	slices.SortFunc(libs, func(a, b string) int {
		switch {
		case a == unspecified && b != unspecified:
			return 1
		case b == unspecified && a != unspecified:
			return -1
		}
		return strings.Compare(a, b)
	})
	budget := maxList
	for _, lib := range libs {
		names := make([]string, 0, len(si.imports[lib]))
		for n := range si.imports[lib] {
			names = append(names, n)
		}
		slices.Sort(names)
		keep := names[:min(len(names), budget)]
		budget -= len(keep)
		out = append(out, report.Import{Library: lib, Count: len(names), Functions: keep})
	}
	return out, si.importCount
}

func exportList(si symbolInfo, maxList int) []string {
	out := make([]string, 0, len(si.exports))
	for n := range si.exports {
		out = append(out, n)
	}
	slices.Sort(out)
	return out[:min(len(out), maxList)]
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
