package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Bounds on the code the import rules attach to a finding.
const (
	// callSitesPerAPI is the most call sites shown for one imported function.
	callSitesPerAPI = 6
	// maxMissingNames is how many functions without a call site a limitation names.
	maxMissingNames = 3
)

// CodeSource supplies the code behind the imported functions of the analysed
// file: where it calls them, with the instructions around each call. The import
// rules ask it for the functions that triggered a finding. It is implemented by
// the call-site index of package xref; the rules only see this interface, so
// they stay pure functions of the report and of whatever the source says.
type CodeSource interface {
	// CallBlocks returns up to limit code blocks, best first, for the places that
	// call the imported function api (written "Library!Function", as the report
	// lists it), and the number of such places the scan found. It returns no
	// blocks and zero for a function nothing calls.
	CallBlocks(api string, limit int) (blocks []report.CodeBlock, sites int)
	// Complete reports whether the scan covered all the code of the file: when it
	// did not, a function with no call site may simply not have been reached.
	Complete() bool
}

// withCode returns f as the single finding of a rule after attaching the code
// of the functions in groups (see [input.attachCode]).
func (in *input) withCode(f report.Finding, groups ...[]string) []report.Finding {
	in.attachCode(&f, groups...)
	return []report.Finding{f}
}

// attachCode shows the code behind a finding made from imported functions. The
// groups list the functions that triggered it, the most relevant group first
// (for process injection: the functions that allocate, write and run, then the
// one that opens the process), each as "Library!Function". The blocks are taken
// from the groups in rounds, so that one call of every function comes before a
// second call of any of them, and cut at six calls per function and at
// [report.MaxCodeBlocks] blocks. An evidence line states how many call sites
// there are and where. A function with no call site is named in the
// limitations, and a finding whose functions all lack one says so instead of
// showing nothing. Without a [CodeSource] nothing is attached.
func (in *input) attachCode(f *report.Finding, groups ...[]string) {
	if in.code == nil {
		return
	}
	type found struct {
		blocks []report.CodeBlock
		sites  int
	}
	var (
		apis    []string
		hits    []found
		missing []string
		total   int
	)
	for _, g := range groups {
		for _, api := range g {
			if slices.Contains(apis, api) {
				continue
			}
			apis = append(apis, api)
			blocks, sites := in.code.CallBlocks(api, callSitesPerAPI)
			if len(blocks) == 0 {
				missing = append(missing, api)
				continue
			}
			hits = append(hits, found{blocks: blocks, sites: sites})
			total += sites
		}
	}

	var shown []report.CodeBlock
	for round := 0; len(shown) < report.MaxCodeBlocks; round++ {
		progressed := false
		for _, h := range hits {
			if round < len(h.blocks) && len(shown) < report.MaxCodeBlocks {
				shown = append(shown, h.blocks[round])
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}

	if len(shown) == 0 {
		f.Limitations = append(f.Limitations, noCallLimitation(in.code.Complete()))
		return
	}
	f.Code = append(f.Code, shown...)
	f.Evidence = append(f.Evidence, codeEvidence(total, len(shown), shown))
	if len(missing) > 0 {
		f.Limitations = append(f.Limitations, fmt.Sprintf("No call was found for %s, so no code is shown for %s.",
			strings.Join(sample(missing, maxMissingNames), ", "), pronoun(len(missing))))
	}
}

// codeEvidence is the evidence line that points at the code blocks.
func codeEvidence(total, shown int, blocks []report.CodeBlock) string {
	var sections []string
	for _, b := range blocks {
		if b.Section != "" && !slices.Contains(sections, b.Section) {
			sections = append(sections, b.Section)
		}
	}
	where := ""
	if len(sections) > 0 {
		where = " in " + strings.Join(sample(sections, 3), ", ")
	}
	sites := fmt.Sprintf("%d call sites", total)
	if total == 1 {
		sites = "1 call site"
	}
	if total > shown {
		return fmt.Sprintf("code: %s%s, the first %d are shown (see the code blocks)", sites, where, shown)
	}
	return fmt.Sprintf("code: %s%s (see the code blocks)", sites, where)
}

// noCallLimitation explains a finding that has no code although the scan ran.
func noCallLimitation(complete bool) string {
	s := "No call to these functions was found in the executable sections, so no code is shown: they may be called through pointers or resolved at run time, or the code that uses them may be packed or lie where this scan does not look."
	if !complete {
		s += " The scan of the code was cut short at its size limits."
	}
	return s
}

// pronoun refers to one function or to several.
func pronoun(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
