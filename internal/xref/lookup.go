package xref

import (
	"slices"

	"github.com/q6r/teardown/internal/report"
)

// Bounds of a lookup, for the commands and tools that expose one.
const (
	// MaxBefore and MaxAfter are the most instructions a lookup shows before and
	// after a call (see [Index.Block]).
	MaxBefore = maxBefore
	MaxAfter  = maxAfter
	// MaxSites is the most call sites a lookup returns.
	MaxSites = 100
	// DefaultSites is how many call sites a lookup returns when it is not told.
	DefaultSites = 10
)

// Found is the answer to the question "who calls this import": which imports the
// name matched, how many places call them and the best of those places, each with
// the code around it.
type Found struct {
	// Imports lists the imports the name matched as "Library!Function", in the
	// order of the import table. It is empty when the name matches none of them.
	Imports []string
	// Total is the number of call sites the scan found for them. It can exceed
	// len(Sites): a lookup returns a bounded number, and the index itself keeps a
	// bounded number per import.
	Total int
	// Sites are the call sites, calls first and each group by ascending address,
	// each with its code block.
	Sites []FoundSite
}

// FoundSite is one call site and the code around it.
type FoundSite struct {
	Site
	// Code is the instruction window around the site, see [Index.Block].
	Code report.CodeBlock
}

// Lookup finds the places that call or use the import api (written
// "Library!Function", or as a bare function name matched like the rules match
// API names, see [Index.Sites]) and returns at most limit of them, each with the
// code around it: before instructions before the call and after after it, both
// bounded by [MaxBefore] and [MaxAfter]. The stub that only jumps through an
// import slot is not a call site of its own and is left out, and so are the plain
// loads of a slot that is also called: these are the places the findings of the
// report show. It is the one query behind the xrefs command and the find_calls
// tool.
func (ix *Index) Lookup(api string, before, after, limit int) Found {
	var f Found
	for _, i := range ix.match(api) {
		name := ix.entries[i].slot.Display()
		if !slices.Contains(f.Imports, name) {
			f.Imports = append(f.Imports, name)
		}
	}
	all := ix.Sites(api)
	keep := relevant(all)
	f.Total = len(keep) + max(0, ix.Count(api)-len(all)) // the sites beyond the cap are counted too
	for _, s := range keep[:min(max(limit, 0), len(keep))] {
		f.Sites = append(f.Sites, FoundSite{Site: s, Code: ix.Block(s, before, after)})
	}
	return f
}
