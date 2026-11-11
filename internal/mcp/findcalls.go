package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/codeview"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/xref"
)

const (
	// maxAPIChars bounds the name of the import a caller asks about.
	maxAPIChars = 256
	// maxNamedImports is how many called imports an error message names.
	maxNamedImports = 8
)

// callsResult is the payload of find_calls.
type callsResult struct {
	File report.File `json:"file"`
	// API is the name as the caller wrote it; Imports are the imports it matched.
	API     string   `json:"api"`
	Imports []string `json:"imports"`
	Arch    string   `json:"arch"`
	// Total is the number of call sites the scan found, Sites the first of them.
	Total int        `json:"total"`
	Sites []callSite `json:"sites"`
	// ScanComplete is false when the scan of the code was cut short by its size
	// limits: a call that is not listed may then simply not have been reached.
	ScanComplete bool     `json:"scanComplete"`
	ScanNotes    []string `json:"scanNotes,omitempty"`
}

// callSite is one place that calls an import, with the code around it.
type callSite struct {
	API string `json:"api"`
	// Kind is one of call, call-thunk, jump-thunk, jump or load (see package xref).
	Kind    string      `json:"kind"`
	Address report.Addr `json:"address"`
	Offset  int64       `json:"offset"`
	Section string      `json:"section"`
	// Via is the address of the import thunk a call-thunk or jump-thunk goes through.
	Via  report.Addr      `json:"via,omitempty"`
	Code report.CodeBlock `json:"code"`
}

// callSteps is the order in which a result gives up detail while the text
// exceeds the output cap: lines around each call first, then whole call sites.
func callSteps() []trimStep {
	var steps []trimStep
	for _, n := range []int{48, 32, 24, 16, 12, 8, 4, 2, 1} {
		steps = append(steps, capSiteLines(n))
	}
	for _, n := range []int{50, 25, 10, 5, 2, 1} {
		steps = append(steps, capArrayAt(n, "sites"))
	}
	return steps
}

// callsFinisher decorates a find_calls result after trimming: whether it is
// incomplete, and why. returned is the number of sites the lookup produced and
// total the number the scan found.
func callsFinisher(returned, total int) func(*node, []trimNote) {
	return func(root *node, notes []trimNote) {
		kept := returned
		if arr := root.at("sites"); arr != nil {
			kept = len(arr.kids)
		}
		root.setKey("truncated", boolNode(len(notes) > 0 || total > returned))
		root.delKey("trimmed")
		root.delKey("note")
		var say []string
		if total > returned {
			say = append(say, fmt.Sprintf("%d call sites were found and the first %d are returned: raise \"max\" (up to %d) for more.", total, returned, xref.MaxSites))
		}
		if len(notes) > 0 {
			root.setKey("trimmed", notesNode(notes))
			say = append(say, fmt.Sprintf("The result was shortened to fit the server's output cap (see \"trimmed\"; %d sites remain): ask for fewer sites with \"max\" or a smaller window with \"before\" and \"after\".", kept))
		}
		if len(say) > 0 {
			root.setKey("note", stringNode(strings.Join(say, " ")))
		}
	}
}

// findCalls implements the find_calls tool.
func (s *server) findCalls(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path   *string `json:"path"`
		API    *string `json:"api"`
		Before *int    `json:"before"`
		After  *int    `json:"after"`
		Max    *int    `json:"max"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	api, err := requireString(a.API, "api")
	if err != nil {
		return nil, err
	}
	if api = strings.TrimSpace(api); api == "" {
		return nil, userErrorf("argument %q must name an imported function, for example %q or %q", "api", "VirtualAllocEx", "KERNEL32.dll!VirtualAllocEx")
	}
	if n := utf8.RuneCountInString(api); n > maxAPIChars {
		return nil, userErrorf("argument %q is %d characters long, at most %d", "api", n, maxAPIChars)
	}
	before, err := intArg(a.Before, "before", xref.DefaultBefore, 0, xref.MaxBefore)
	if err != nil {
		return nil, err
	}
	after, err := intArg(a.After, "after", xref.DefaultAfter, 0, xref.MaxAfter)
	if err != nil {
		return nil, err
	}
	limit, err := intArg(a.Max, "max", xref.DefaultSites, 1, xref.MaxSites)
	if err != nil {
		return nil, err
	}

	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if im := codeview.Detect(f.File, f.size); im.Format != codeview.FormatPE {
		return nil, unsupportedImage(im)
	}
	ix, err := xref.Scan(ctx, f.File, f.size, limits.ForSize(f.size), xref.Options{})
	switch {
	case errors.Is(err, xref.ErrUnsupported):
		return nil, unsupportedImage(codeview.Detect(f.File, f.size))
	case ix == nil || err != nil:
		return nil, fmt.Errorf("scanning the code for calls: %w", err)
	case ix.Imports() == 0:
		return nil, userErrorf("the image has no imports this tool can resolve (the import table is missing, empty or unreadable), so there are no calls to look for")
	case !ix.HasCode():
		return nil, userErrorf("the image has no executable section with bytes in the file, so there is no code to search")
	}

	found := ix.Lookup(api, before, after, limit)
	if len(found.Imports) == 0 {
		return nil, noSuchImport(api, ix)
	}
	res := callsResult{
		File: report.File{Name: f.name, Size: f.size}, API: binio.Printable(api, maxAPIChars),
		Imports: found.Imports, Arch: ix.Arch(), Total: found.Total, Sites: make([]callSite, len(found.Sites)),
		ScanComplete: ix.Complete(), ScanNotes: ix.Notes(),
	}
	for i, site := range found.Sites {
		res.Sites[i] = callSite{
			API: site.API, Kind: site.Kind.ID(), Address: report.Addr(site.Addr), Offset: site.Offset, Section: site.Section,
			Via: report.Addr(site.Via), Code: site.Code,
		}
	}
	tree, err := treeOf(res)
	if err != nil {
		return nil, err
	}
	return &toolOutput{tree: tree, spec: fitSpec{onCap: callSteps(), finish: callsFinisher(len(res.Sites), res.Total)}}, nil
}

// unsupportedImage explains that the file is not an image find_calls can search.
func unsupportedImage(im codeview.Image) error {
	what := "this file is not a PE image"
	if im.Format != "" {
		what = "this file is " + im.Label()
	}
	return userErrorf("%s: find_calls finds the calls to the imports of PE images for x86 and x86-64 only (ELF, Mach-O, other instruction sets and other file types are not supported)", what)
}

// noSuchImport explains a name that matches no import, and names the imports
// that are called so a misspelling is easy to fix.
func noSuchImport(api string, ix *xref.Index) error {
	msg := fmt.Sprintf(`no import of this file matches "%s"`, binio.Printable(api, 80))
	called := ix.APIs()
	if len(called) == 0 {
		return userErrorf("%s; none of its imports has a call site in the executable sections", msg)
	}
	var names []string
	for _, c := range called[:min(len(called), maxNamedImports)] {
		names = append(names, binio.Printable(c.Name, 120))
	}
	more := ""
	if len(called) > len(names) {
		more = fmt.Sprintf(" and %d more", len(called)-len(names))
	}
	return userErrorf("%s; imports with call sites include %s%s (analyze_file lists every import)", msg, strings.Join(names, ", "), more)
}
