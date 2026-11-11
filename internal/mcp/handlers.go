package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/diff"
	"github.com/q6r/teardown/internal/report"
)

// Views of analyze_file.
const (
	detailSummary = "summary"
	detailFull    = "full"
)

// Limits of the summary view of analyze_file.
const (
	summaryStrings   = 40
	summaryFunctions = 25
	summaryList      = 50
	summaryExports   = 50
	// The code behind each finding: the first blocks, and the lines around the
	// flagged one in each block. These are the bounds of the terminal output too.
	summaryCodeBlocks = 3
	summaryCodeLines  = 24
)

// listMaxStrings is how many string items list_strings asks the analysis to keep.
const listMaxStrings = 20000

// Defaults and bounds of list_strings paging.
const (
	defaultPageSize = 100
	maxPageSize     = 1000
)

func (s *server) analysisOptions(name string, minString, maxStrings int) analyze.Options {
	return analyze.Options{Name: name, MinString: minString, MaxStrings: maxStrings, Timeout: s.cfg.Timeout}
}

// analyzeFile implements the analyze_file tool.
func (s *server) analyzeFile(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path       *string `json:"path"`
		MinString  *int    `json:"minString"`
		MaxStrings *int    `json:"maxStrings"`
		Detail     *string `json:"detail"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	minString, err := intArg(a.MinString, "minString", analyze.DefaultMinString, 3, 256)
	if err != nil {
		return nil, err
	}
	maxStrings, err := intArg(a.MaxStrings, "maxStrings", analyze.DefaultMaxStrings, 1, 10000)
	if err != nil {
		return nil, err
	}
	detail := detailSummary
	if a.Detail != nil {
		detail = *a.Detail
		if detail != detailSummary && detail != detailFull {
			return nil, userErrorf("argument %q must be %q or %q (got %q)", "detail", detailSummary, detailFull, detail)
		}
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rep, err := s.an.reader(ctx, f.File, f.size, s.analysisOptions(f.name, minString, maxStrings))
	if err != nil {
		return nil, err
	}
	tree, err := treeOf(rep)
	if err != nil {
		return nil, err
	}
	spec := fitSpec{onCap: analyzeLadder(), finish: reportFinisher(detail)}
	if detail == detailSummary {
		spec.always = summarySteps()
	}
	return &toolOutput{tree: tree, spec: spec}, nil
}

// summarySteps are the limits of the summary view.
func summarySteps() []trimStep {
	return []trimStep{
		capStringsTop(summaryStrings),
		capEachField(summaryFunctions, "functions", "imports"),
		capDetailLists(summaryList),
		capArrayAt(summaryExports, "exports"),
		capEachField(summaryCodeBlocks, "code", "findings"),
		capCodeLines(summaryCodeLines),
	}
}

// analyzeLadder is the order in which analyze_file gives up detail while the
// text exceeds the output cap: strings first, then import function lists, then
// the lists inside details (archive entries and the like), then sections, then
// the remaining lists, then the code behind the findings (lines of each block,
// then whole blocks), finally evidence and entropy windows.
func analyzeLadder() []trimStep {
	var steps []trimStep
	for _, n := range []int{1000, 500, 250, 100, 40, 20, 10, 0} {
		steps = append(steps, capStringsTop(n))
	}
	for _, n := range []int{200, 100, 50, 25, 10, 5, 0} {
		steps = append(steps, capEachField(n, "functions", "imports"))
	}
	for _, n := range []int{200, 100, 50, 20, 10, 5, 0} {
		steps = append(steps, capDetailLists(n))
	}
	for _, n := range []int{64, 32, 16, 8, 0} {
		steps = append(steps, capArrayAt(n, "sections"))
	}
	for _, n := range []int{50, 10, 0} {
		steps = append(steps, capArrayAt(n, "exports"))
	}
	for _, n := range []int{32, 16, 4, 0} {
		steps = append(steps, capArrayAt(n, "imports"))
	}
	for _, n := range []int{16, 8, 4} {
		steps = append(steps, capCodeLines(n))
	}
	for _, n := range []int{2, 1, 0} {
		steps = append(steps, capEachField(n, "code", "findings"))
	}
	for _, n := range []int{5, 2, 0} {
		steps = append(steps, capEachField(n, "evidence", "findings"))
	}
	for _, n := range []int{128, 32, 0} {
		steps = append(steps, capArrayAt(n, "entropy", "windows"))
	}
	return steps
}

// reportFinisher decorates an analyze_file result with the view, whether lists
// were trimmed, what was trimmed and how to get more.
func reportFinisher(detail string) func(*node, []trimNote) {
	return func(root *node, notes []trimNote) {
		root.setKey("detail", stringNode(detail))
		root.setKey("truncated", boolNode(len(notes) > 0))
		root.delKey("trimmed")
		root.delKey("note")
		if len(notes) == 0 {
			return
		}
		root.setKey("trimmed", notesNode(notes))
		note := "Some lists were shortened to fit the server's output cap (see \"trimmed\": kept of total). Use list_strings to page through all strings."
		if detail == detailSummary {
			note = "Long lists were shortened (see \"trimmed\": kept of total). Use list_strings to page through all strings, or call analyze_file with detail=\"full\" for fuller lists (still limited by the server's output cap)."
		}
		if slices.ContainsFunc(notes, func(n trimNote) bool { return strings.HasPrefix(n.Path, "findings[].code") }) {
			note += " Code blocks were shortened too: find_calls, disassemble and read_bytes read any part of the file."
		}
		root.setKey("note", stringNode(note))
	}
}

// listStrings implements the list_strings tool.
func (s *server) listStrings(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path      *string `json:"path"`
		Category  *string `json:"category"`
		Query     *string `json:"query"`
		MinLength *int    `json:"minLength"`
		Limit     *int    `json:"limit"`
		Offset    *int    `json:"offset"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	cats, err := parseCategories(a.Category)
	if err != nil {
		return nil, err
	}
	minLength, err := intArg(a.MinLength, "minLength", analyze.DefaultMinString, 3, 256)
	if err != nil {
		return nil, err
	}
	limit, err := intArg(a.Limit, "limit", defaultPageSize, 1, maxPageSize)
	if err != nil {
		return nil, err
	}
	offset, err := intArg(a.Offset, "offset", 0, 0, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	query := ""
	if a.Query != nil {
		query = *a.Query
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	found, err := s.an.strings(ctx, f.File, f.size, s.analysisOptions(f.name, minLength, listMaxStrings))
	if err != nil {
		return nil, err
	}
	matches := filterStrings(found.Items, cats, query)
	total := len(matches)
	page := []report.StringItem{}
	if offset < total {
		page = slices.Clone(matches[offset:min(total, offset+limit)])
	}
	res := listResult{
		File:          report.File{Name: f.name, Size: f.size},
		MinLength:     found.MinLength,
		StringsFound:  found.Total,
		ScanTruncated: found.Truncated,
		ByCategory:    found.ByCategory,
		Category:      cats,
		Query:         query,
		Total:         total,
		Offset:        offset,
		Limit:         limit,
		Items:         page,
	}
	if res.ByCategory == nil {
		res.ByCategory = map[string]int{}
	}
	tree, err := treeOf(res)
	if err != nil {
		return nil, err
	}
	spec := fitSpec{
		onCap: itemLadder(),
		finish: func(root *node, notes []trimNote) {
			returned := len(root.at("items").kids)
			root.setKey("returned", intNode(returned))
			root.delKey("nextOffset")
			if offset+returned < total {
				root.setKey("nextOffset", intNode(offset+returned))
			}
			root.setKey("truncated", boolNode(len(notes) > 0))
			root.delKey("trimmed")
			root.delKey("note")
			if len(notes) > 0 {
				root.setKey("trimmed", notesNode(notes))
				root.setKey("note", stringNode("The page was shortened to fit the server's output cap; continue from \"nextOffset\"."))
			}
		},
	}
	return &toolOutput{tree: tree, spec: spec}, nil
}

// listResult is the payload of list_strings.
type listResult struct {
	File          report.File         `json:"file"`
	MinLength     int                 `json:"minLength"`
	StringsFound  int                 `json:"stringsFound"`
	ScanTruncated bool                `json:"scanTruncated"`
	ByCategory    map[string]int      `json:"byCategory"`
	Category      []string            `json:"category,omitempty"`
	Query         string              `json:"query,omitempty"`
	Total         int                 `json:"total"`
	Offset        int                 `json:"offset"`
	Limit         int                 `json:"limit"`
	Items         []report.StringItem `json:"items"`
}

// itemLadder shortens a page of items step by step.
func itemLadder() []trimStep {
	var steps []trimStep
	for _, n := range []int{500, 250, 100, 50, 25, 10, 5, 2, 1, 0} {
		steps = append(steps, capArrayAt(n, "items"))
	}
	return steps
}

// parseCategories validates a comma-separated category filter.
func parseCategories(v *string) ([]string, error) {
	if v == nil || strings.TrimSpace(*v) == "" {
		return nil, nil
	}
	valid := report.StringCategories()
	var out []string
	for _, c := range strings.Split(*v, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !slices.Contains(valid, c) {
			return nil, userErrorf("unknown category %q; valid categories are %s", c, strings.Join(valid, ", "))
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// filterStrings keeps the items in the given categories (all when cats is empty)
// whose value contains query, ignoring case.
func filterStrings(items []report.StringItem, cats []string, query string) []report.StringItem {
	query = strings.ToLower(query)
	var out []report.StringItem
	for _, it := range items {
		if len(cats) > 0 && !slices.Contains(cats, it.Category) {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(it.Value), query) {
			continue
		}
		out = append(out, it)
	}
	return out
}

// hashFile implements the hash_file tool.
func (s *server) hashFile(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path *string `json:"path"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sum, err := s.an.quick(ctx, f.File, f.size, s.analysisOptions(f.name, 0, 0))
	if err != nil {
		return nil, err
	}
	tree, err := treeOf(struct {
		File   report.File   `json:"file"`
		Type   report.Type   `json:"type"`
		Hashes report.Hashes `json:"hashes"`
	}{sum.File, sum.Type, sum.Hashes})
	if err != nil {
		return nil, err
	}
	return &toolOutput{tree: tree}, nil
}

// entropyScale explains the numbers in an entropy_profile result.
const entropyScale = "bits per byte: 0 = constant data, 8 = uniformly random; compressed, encrypted or packed data is typically above 7.2, code and text well below"

// entropyProfile implements the entropy_profile tool.
func (s *server) entropyProfile(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path *string `json:"path"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rep, err := s.an.reader(ctx, f.File, f.size, s.analysisOptions(f.name, 0, 1))
	if err != nil {
		return nil, err
	}
	type sectionEntropy struct {
		Name    string  `json:"name"`
		Entropy float64 `json:"entropy"`
		RawSize uint64  `json:"rawSize"`
	}
	res := struct {
		File       report.File      `json:"file"`
		Type       typeRef          `json:"type"`
		Scale      string           `json:"scale"`
		Overall    float64          `json:"overall"`
		WindowSize int64            `json:"windowSize"`
		Windows    []float64        `json:"windows"`
		Sections   []sectionEntropy `json:"sections"`
	}{
		File: rep.File, Type: typeRef{ID: rep.Type.ID, Label: rep.Type.Label}, Scale: entropyScale,
		Overall: rep.Entropy.Overall, WindowSize: rep.Entropy.WindowSize, Windows: rep.Entropy.Windows,
		Sections: []sectionEntropy{},
	}
	if res.Windows == nil {
		res.Windows = []float64{}
	}
	for _, sec := range rep.Sections {
		res.Sections = append(res.Sections, sectionEntropy{Name: sec.Name, Entropy: sec.Entropy, RawSize: sec.RawSize})
	}
	tree, err := treeOf(res)
	if err != nil {
		return nil, err
	}
	var steps []trimStep
	for _, n := range []int{256, 128, 64, 32, 0} {
		steps = append(steps, capArrayAt(n, "windows"))
	}
	for _, n := range []int{64, 16, 4, 0} {
		steps = append(steps, capArrayAt(n, "sections"))
	}
	return &toolOutput{tree: tree, spec: fitSpec{onCap: steps, finish: genericFinisher("The profile was shortened to fit the server's output cap (see \"trimmed\").")}}, nil
}

// typeRef is the short form of a detected type.
type typeRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// genericFinisher marks a result as trimmed and explains it with note.
func genericFinisher(note string) func(*node, []trimNote) {
	return func(root *node, notes []trimNote) {
		root.setKey("truncated", boolNode(len(notes) > 0))
		root.delKey("trimmed")
		root.delKey("note")
		if len(notes) > 0 {
			root.setKey("trimmed", notesNode(notes))
			root.setKey("note", stringNode(note))
		}
	}
}

// identity is the short description of one side of a diff.
type identity struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Type      string `json:"type"`
	TypeLabel string `json:"typeLabel"`
}

func identityOf(r *report.Report) identity {
	return identity{Name: r.File.Name, Size: r.File.Size, SHA256: r.Hashes.SHA256, Type: r.Type.ID, TypeLabel: r.Type.Label}
}

// diffFiles implements the diff_files tool.
func (s *server) diffFiles(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		A *string `json:"a"`
		B *string `json:"b"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	pathA, err := requireString(a.A, "a")
	if err != nil {
		return nil, err
	}
	pathB, err := requireString(a.B, "b")
	if err != nil {
		return nil, err
	}
	fa, err := s.roots.open(pathA)
	if err != nil {
		return nil, prefixed("a", err)
	}
	defer fa.Close()
	fb, err := s.roots.open(pathB)
	if err != nil {
		return nil, prefixed("b", err)
	}
	defer fb.Close()

	repA, repB, err := s.analyzePair(ctx, fa, fb)
	if err != nil {
		return nil, err
	}
	tree, err := treeOf(struct {
		A    identity     `json:"a"`
		B    identity     `json:"b"`
		Diff *diff.Result `json:"diff"`
	}{identityOf(repA), identityOf(repB), diff.Compare(repA, repB)})
	if err != nil {
		return nil, err
	}
	return &toolOutput{tree: tree, spec: fitSpec{finish: genericFinisher("The diff was shortened to fit the server's output cap (see \"trimmed\").")}}, nil
}

// prefixed names the argument a user error belongs to.
func prefixed(arg string, err error) error {
	var ue *userError
	if errors.As(err, &ue) {
		return userErrorf("argument %q: %s", arg, ue.msg)
	}
	return err
}

// analyzePair analyses two files concurrently; the first failure cancels the other.
func (s *server) analyzePair(ctx context.Context, fa, fb *openedFile) (*report.Report, *report.Report, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		rep *report.Report
		err error
	}
	second := make(chan outcome, 1)
	go func() {
		rep, err := s.an.reader(ctx, fb.File, fb.size, s.analysisOptions(fb.name, 0, 0))
		if err != nil {
			cancel()
		}
		second <- outcome{rep, err}
	}()
	repA, errA := s.an.reader(ctx, fa.File, fa.size, s.analysisOptions(fa.name, 0, 0))
	if errA != nil {
		cancel()
	}
	ob := <-second
	switch {
	case errA != nil && ob.err != nil && errors.Is(errA, context.Canceled):
		return nil, nil, fmt.Errorf("file b: %w", ob.err)
	case errA != nil:
		return nil, nil, fmt.Errorf("file a: %w", errA)
	case ob.err != nil:
		return nil, nil, fmt.Errorf("file b: %w", ob.err)
	}
	return repA, ob.rep, nil
}
