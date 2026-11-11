// Package xref finds the code that calls the imports of a Windows executable
// and shows it: for each imported function, the places in the executable
// sections that call it through the import address table, with the
// instructions around each call so a reader sees how the arguments are set up.
//
// # What it finds
//
// It sweeps the executable sections of an x86-64 (or 32-bit x86) PE image with
// the decoder of package disasm and records, for every import slot:
//
//   - "call [IAT]": call qword ptr [rip+disp] (call dword ptr [abs] in 32-bit
//     code), the way compilers call an import;
//   - "call thunk" and "jmp thunk": call rel32 or jmp rel32 to an import thunk,
//     a stub that is itself a jmp through the slot (one level);
//   - "jmp [IAT]": a jump through the slot, which is a tail call or a thunk
//     nobody calls directly;
//   - "load [IAT]": any other instruction that reads the slot, such as the
//     mov rax, [slot] that precedes an indirect call;
//   - "thunk": the jmp through the slot that other code calls.
//
// Index.Sites lists them for one function (by "Library!Function" or by a bare
// name, matched like the rules match API names, see package apiname) and
// Index.Block turns one into a code block of the report: the call line
// highlighted, the instructions before it and after it. Index.Lookup is the whole
// question "who calls this import" in one call, which the xrefs command and the
// find_calls tool ask. Every note on a line comes from an [Annotator], which the
// disasm command and the disassemble tool use on their own for PE images, so the
// same instruction reads the same everywhere.
//
// # What it does not do
//
// Linear sweep only: data inside a code section can be read as instructions and
// one wrong byte can shift what follows, so every block says so. The
// instructions before a call are not decoded backwards blindly: the block tries
// start points a little earlier, keeps the first one that decodes cleanly and
// reaches the call on an instruction boundary, and says when none did. Imports
// resolved at run time (GetProcAddress, delay-load helpers) and code hidden by a
// packer are invisible, ARM64 and other instruction sets are not decoded, and
// nothing is executed or emulated. Every scan is bounded: bytes swept, branches
// remembered and sites kept have caps, and an index that hit one says so (see
// [Index.Notes]).
//
// An [Index] reads the file again to build blocks, so it is valid while the
// reader it was built from is.
package xref

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/apiname"
	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/limits"
)

// ErrUnsupported is wrapped by the error [Find] and [Scan] return for an image
// whose code this package does not decode (anything but x86 and x86-64).
var ErrUnsupported = errors.New("call-site search supports x86 and x86-64 PE images only")

// COFF machine types of the images that are decoded.
const (
	machineX86   = 0x14c
	machineX8664 = 0x8664
)

// Architectures as they appear in [report.CodeBlock].Arch.
const (
	archX86   = "x86"
	archX8664 = "x86-64"
)

// Default bounds of one scan (see [Options]).
const (
	// DefaultMaxBytes is the most code bytes swept in one image.
	DefaultMaxBytes = 32 << 20
	// DefaultMaxSectionBytes is the most code bytes swept in one section.
	DefaultMaxSectionBytes = 16 << 20
	// DefaultMaxInstructions is the most instructions decoded in one image.
	DefaultMaxInstructions = 8 << 20

	// maxSitesPerAPI is how many sites are kept for one import slot; the true
	// number is counted beyond it.
	maxSitesPerAPI = 256
	// maxSites is how many sites are kept in the whole index.
	maxSites = 20000
	// maxBranches is how many direct calls and jumps are remembered to find the
	// ones that target an import thunk.
	maxBranches = 1 << 19
	// maxThunks is how many "jmp [slot]" instructions are remembered as thunks.
	maxThunks = 1 << 16
	// chunkSize is how many bytes are read and decoded at a time.
	chunkSize = 128 << 10
	// pollEvery is how many instructions are decoded between checks of the context.
	pollEvery = 2048
)

// Options bounds a scan. The zero value uses the defaults.
type Options struct {
	// MaxBytes caps the code bytes swept in the whole image (default [DefaultMaxBytes]).
	MaxBytes int64
	// MaxSectionBytes caps the code bytes swept in one section (default [DefaultMaxSectionBytes]).
	MaxSectionBytes int64
	// MaxInstructions caps the instructions decoded (default [DefaultMaxInstructions]).
	MaxInstructions int
}

func (o Options) withDefaults() Options {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxSectionBytes <= 0 {
		o.MaxSectionBytes = DefaultMaxSectionBytes
	}
	if o.MaxInstructions <= 0 {
		o.MaxInstructions = DefaultMaxInstructions
	}
	return o
}

// Kind says how a site refers to an import.
type Kind uint8

// The kinds of site, in the order that [Index.Sites] ranks them: calls first.
const (
	// KindCall is a call through the import address table slot.
	KindCall Kind = iota
	// KindCallThunk is a call to an import thunk.
	KindCallThunk
	// KindJumpThunk is a jump to an import thunk (a tail call).
	KindJumpThunk
	// KindJump is a jump through the slot that no other code jumps or calls to: a
	// tail call, or a thunk nothing calls directly.
	KindJump
	// KindLoad is any other instruction that reads the slot.
	KindLoad
	// KindThunk is the jump through the slot that makes up an import thunk that
	// other code calls.
	KindThunk
)

// String returns the name used in listings: "call [IAT]", "call thunk", ...
func (k Kind) String() string {
	switch k {
	case KindCall:
		return "call [IAT]"
	case KindCallThunk:
		return "call thunk"
	case KindJumpThunk:
		return "jmp thunk"
	case KindJump:
		return "jmp [IAT]"
	case KindLoad:
		return "load [IAT]"
	case KindThunk:
		return "thunk"
	}
	return "unknown"
}

// Site is one place in the code that refers to an import.
type Site struct {
	// API is the import as the report lists it: "KERNEL32.dll!VirtualAllocEx".
	API string
	// Kind says how the instruction refers to the import.
	Kind Kind
	// Addr is the virtual address of the instruction and Offset its file offset.
	Addr   uint64
	Offset int64
	// Section is the name of the section that holds it.
	Section string
	// Via is the address of the import thunk a [KindCallThunk] or [KindJumpThunk]
	// site goes through, and zero for the other kinds.
	Via uint64
}

// ID is the stable name of the kind in machine-readable output: "call",
// "call-thunk", "jump-thunk", "jump", "load" or "thunk".
func (k Kind) ID() string {
	switch k {
	case KindCall:
		return "call"
	case KindCallThunk:
		return "call-thunk"
	case KindJumpThunk:
		return "jump-thunk"
	case KindJump:
		return "jump"
	case KindLoad:
		return "load"
	case KindThunk:
		return "thunk"
	}
	return "unknown"
}

// API is an import that has at least one site.
type API struct {
	// Name is "Library!Function", Library and Function its parts.
	Name, Library, Function string
	// Sites is the number of sites found, which can exceed what [Index.Sites] returns.
	Sites int
	// Calls is the number of places that call or use the import, which is what the
	// findings count: Sites without the stub that only jumps through the slot, and
	// without the loads of the slot when the import is also called.
	Calls int
}

// entry is one import slot and what was found about it.
type entry struct {
	slot  pe.ImportSlot
	sites []Site
	total int
}

// Index is the result of a scan: the sites of every import of an image. It is
// also an [Annotator], so the notes of its code blocks are the ones every other
// view of the code prints.
type Index struct {
	*Annotator

	entries []entry
	byName  map[string][]int // lower-case "library!function" -> entries
	byKey   map[string][]int // canonical function name (and its A/W stem) -> entries
	thunks  map[uint64]int   // address of a "jmp [slot]" -> entry
	notes   []string
	partial bool // the sweep did not cover every executable byte
	hasCode bool // the image has an executable section with bytes in the file
}

// Find scans the image of size bytes in r for calls to the imports named by
// layout, which comes from [pe.Parse]. It returns the index, or an error that
// wraps [ErrUnsupported] for an image that is not x86 or x86-64. When ctx ends
// first it returns the partial index together with the context's error.
func Find(ctx context.Context, r io.ReaderAt, size int64, layout pe.Layout, opts Options) (*Index, error) {
	ann, err := NewAnnotator(r, size, layout)
	if err != nil {
		return nil, err
	}
	ix := &Index{Annotator: ann, byName: map[string][]int{}, byKey: map[string][]int{}, thunks: map[uint64]int{}}
	ix.entries = make([]entry, len(layout.Slots))
	for i, s := range layout.Slots {
		ix.entries[i].slot = s
		name := strings.ToLower(s.Display())
		ix.byName[name] = append(ix.byName[name], i)
		for _, key := range apiname.Keys(s.Function) {
			ix.byKey[key] = append(ix.byKey[key], i)
		}
	}
	err = ix.sweep(ctx, opts.withDefaults())
	ix.rank()
	return ix, err
}

// Scan parses the PE headers of the image in r itself and then behaves like
// [Find]. Use Find when the headers were already parsed.
func Scan(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits, opts Options) (*Index, error) {
	res, err := pe.Parse(ctx, r, size, lim)
	if res == nil {
		return nil, fmt.Errorf("reading the PE headers: %w", err)
	}
	ix, ferr := Find(ctx, r, size, res.Layout, opts)
	if ferr == nil {
		ferr = err // a cancelled parse still returned a result
	}
	return ix, ferr
}

// Notes lists what limited the scan: a cap that was reached, a section that
// could not be read, an image without executable sections. It is empty for a
// scan that covered everything.
func (ix *Index) Notes() []string { return slices.Clone(ix.notes) }

// Complete reports whether the sweep covered every executable byte of the image.
// A missing call site proves nothing when it did not.
func (ix *Index) Complete() bool { return !ix.partial }

// HasCode reports whether the image has an executable section with bytes in the
// file, which is what the scan reads. It is false when the image has no import
// slots to look for, because the scan then reads nothing.
func (ix *Index) HasCode() bool { return ix.hasCode }

// Imports returns the number of imported functions the scan knew the slot of.
func (ix *Index) Imports() int { return len(ix.entries) }

// APIs lists every import that has at least one site, in import-table order.
func (ix *Index) APIs() []API {
	var out []API
	for _, e := range ix.entries {
		if e.total > 0 {
			calls := len(relevant(e.sites)) + max(0, e.total-len(e.sites))
			out = append(out, API{Name: e.slot.Display(), Library: e.slot.Library, Function: e.slot.Function, Sites: e.total, Calls: calls})
		}
	}
	return out
}

// match returns the entries that api names: the import "Library!Function" (case
// does not matter), or a bare function name matched as the rules match API names
// ("CreateProcess" finds CreateProcessA and CreateProcessW, "zwopenfile" finds
// NtOpenFile).
func (ix *Index) match(api string) []int {
	if idx, ok := ix.byName[strings.ToLower(api)]; ok {
		return idx
	}
	if strings.Contains(api, "!") {
		return nil
	}
	return ix.byKey[apiname.Canonical(api)]
}

// Sites returns the sites that refer to api, best first: calls, then calls and
// jumps through thunks, jumps, loads and finally the thunks themselves, each
// group by ascending address. At most 256 sites are kept per import; [Index.Count]
// has the true number.
func (ix *Index) Sites(api string) []Site {
	var out []Site
	matched := ix.match(api)
	for _, i := range matched {
		out = append(out, ix.entries[i].sites...)
	}
	if len(matched) > 1 {
		sortSites(out) // sites of different imports merge into one ranking
	}
	return out
}

// Count returns the number of sites that refer to api, including those beyond
// the ones [Index.Sites] keeps.
func (ix *Index) Count(api string) int {
	n := 0
	for _, i := range ix.match(api) {
		n += ix.entries[i].total
	}
	return n
}

// sortSites orders sites by kind and then by address.
func sortSites(s []Site) {
	slices.SortStableFunc(s, func(a, b Site) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		switch {
		case a.Addr < b.Addr:
			return -1
		case a.Addr > b.Addr:
			return 1
		}
		return 0
	})
}

// rank sorts the sites of every entry for [Index.Sites].
func (ix *Index) rank() {
	for i := range ix.entries {
		sortSites(ix.entries[i].sites)
	}
}
