// Package diff compares two teardown reports and describes what changed:
// identity, type, sections, imports, exports, strings, hardening and findings.
//
// The comparison works on the report contract only, so it applies equally to
// freshly produced reports and to ones loaded back from JSON.
package diff

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Schema identifies the JSON shape of [Result].
const Schema = "teardown.diff/v1"

// maxListed caps every added/removed list; the *Count fields carry the true totals.
const maxListed = 200

// Result is the structured difference between two reports (a = before, b = after).
type Result struct {
	Schema string `json:"schema"`
	A      Side   `json:"a"`
	B      Side   `json:"b"`
	// Identical is true when both files have the same SHA-256.
	Identical bool         `json:"identical"`
	Type      *TypeChange  `json:"type,omitempty"`
	Sections  SectionsDiff `json:"sections"`
	Imports   ListDiff     `json:"imports"`
	Exports   ListDiff     `json:"exports"`
	Strings   StringsDiff  `json:"strings"`
	Hardening []StatusDiff `json:"hardening"`
	Findings  FindingsDiff `json:"findings"`
	Risk      RiskDiff     `json:"risk"`
	// Summary lists the notable changes as short human-readable bullets (ASCII only).
	Summary []string `json:"summary"`
	// Limitations qualifies the comparison.
	Limitations []string `json:"limitations"`
}

// Side identifies one input of the comparison.
type Side struct {
	Name      string  `json:"name"`
	Size      int64   `json:"size"`
	SHA256    string  `json:"sha256"`
	Imphash   string  `json:"imphash"`
	Type      string  `json:"type"`
	TypeLabel string  `json:"typeLabel"`
	Entropy   float64 `json:"entropy"`
	Risk      int     `json:"risk"`
}

// Change is a value that differs between the two reports.
type Change[T any] struct {
	From T `json:"from"`
	To   T `json:"to"`
}

// TypeChange describes a different detected type or different tags.
type TypeChange struct {
	ID          *Change[string] `json:"id,omitempty"`
	Label       *Change[string] `json:"label,omitempty"`
	TagsAdded   []string        `json:"tagsAdded"`
	TagsRemoved []string        `json:"tagsRemoved"`
}

// SectionsDiff lists section-level changes, matched by name.
type SectionsDiff struct {
	Added   []string        `json:"added"`
	Removed []string        `json:"removed"`
	Changed []SectionChange `json:"changed"`
}

// SectionChange is a section present on both sides whose properties differ.
type SectionChange struct {
	Name        string            `json:"name"`
	RawSize     *Change[uint64]   `json:"rawSize,omitempty"`
	VirtualSize *Change[uint64]   `json:"virtualSize,omitempty"`
	Entropy     *Change[float64]  `json:"entropy,omitempty"`
	Flags       *Change[[]string] `json:"flags,omitempty"`
}

// ListDiff lists items added and removed. Items are capped; the counts are exact.
type ListDiff struct {
	Added        []string `json:"added"`
	Removed      []string `json:"removed"`
	AddedCount   int      `json:"addedCount"`
	RemovedCount int      `json:"removedCount"`
}

// StringsDiff lists strings that appear on only one side. Only the strings kept
// in each report (see strings.truncated) are compared.
type StringsDiff struct {
	Added        []StringRef            `json:"added"`
	Removed      []StringRef            `json:"removed"`
	AddedCount   int                    `json:"addedCount"`
	RemovedCount int                    `json:"removedCount"`
	ByCategory   map[string]Change[int] `json:"byCategory"`
}

// StringRef is a string with its category. Secrets stay redacted.
type StringRef struct {
	Value    string `json:"value"`
	Category string `json:"category"`
}

// StatusDiff is a hardening feature whose status changed.
type StatusDiff struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// FindingsDiff compares findings by ID.
type FindingsDiff struct {
	Added     []FindingRef `json:"added"`
	Removed   []FindingRef `json:"removed"`
	Changed   []FindingRef `json:"changed"`
	Unchanged int          `json:"unchanged"`
}

// FindingRef identifies a finding in a diff. For changed findings From holds the
// previous severity.
type FindingRef struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity report.Severity `json:"severity"`
	From     report.Severity `json:"from,omitempty"`
}

// RiskDiff compares the risk scores.
type RiskDiff struct {
	From      int    `json:"from"`
	To        int    `json:"to"`
	Delta     int    `json:"delta"`
	LabelFrom string `json:"labelFrom"`
	LabelTo   string `json:"labelTo"`
}

// Compare diffs two reports. It never mutates its arguments; nil arguments are
// treated as empty reports.
func Compare(a, b *report.Report) *Result {
	if a == nil {
		a = report.New("", 0, "")
	}
	if b == nil {
		b = report.New("", 0, "")
	}
	res := &Result{
		Schema:    Schema,
		A:         side(a),
		B:         side(b),
		Identical: a.Hashes.SHA256 != "" && a.Hashes.SHA256 == b.Hashes.SHA256,
		Sections:  diffSections(a.Sections, b.Sections),
		Imports:   diffList(flattenImports(a.Imports), flattenImports(b.Imports)),
		Exports:   diffList(a.Exports, b.Exports),
		Strings:   diffStrings(a.Strings, b.Strings),
		Hardening: diffHardening(a.Hardening, b.Hardening),
		Findings:  diffFindings(a.Findings, b.Findings),
		Risk: RiskDiff{
			From: a.Risk.Score, To: b.Risk.Score, Delta: b.Risk.Score - a.Risk.Score,
			LabelFrom: a.Risk.Label, LabelTo: b.Risk.Label,
		},
		Limitations: []string{
			"Compares what each report recorded: lists capped by the analyzer (strings, imports, exports, entries) are compared as recorded.",
			"A difference in sections, imports or strings does not say which build is better or safer; read the findings and the evidence.",
		},
	}
	res.Type = diffType(a.Type, b.Type)
	res.Summary = summarize(res)
	return res
}

func side(r *report.Report) Side {
	return Side{
		Name: r.File.Name, Size: r.File.Size, SHA256: r.Hashes.SHA256, Imphash: r.Hashes.Imphash,
		Type: r.Type.ID, TypeLabel: r.Type.Label, Entropy: r.Entropy.Overall, Risk: r.Risk.Score,
	}
}

func diffType(a, b report.Type) *TypeChange {
	tc := &TypeChange{TagsAdded: []string{}, TagsRemoved: []string{}}
	if a.ID != b.ID {
		tc.ID = &Change[string]{From: a.ID, To: b.ID}
	}
	if a.Label != b.Label {
		tc.Label = &Change[string]{From: a.Label, To: b.Label}
	}
	for _, t := range b.Tags {
		if !slices.Contains(a.Tags, t) {
			tc.TagsAdded = append(tc.TagsAdded, t)
		}
	}
	for _, t := range a.Tags {
		if !slices.Contains(b.Tags, t) {
			tc.TagsRemoved = append(tc.TagsRemoved, t)
		}
	}
	slices.Sort(tc.TagsAdded)
	slices.Sort(tc.TagsRemoved)
	if tc.ID == nil && tc.Label == nil && len(tc.TagsAdded) == 0 && len(tc.TagsRemoved) == 0 {
		return nil
	}
	return tc
}

func diffSections(a, b []report.Section) SectionsDiff {
	d := SectionsDiff{Added: []string{}, Removed: []string{}, Changed: []SectionChange{}}
	byName := func(ss []report.Section) map[string]report.Section {
		m := make(map[string]report.Section, len(ss))
		for _, s := range ss {
			if _, dup := m[s.Name]; !dup {
				m[s.Name] = s
			}
		}
		return m
	}
	am, bm := byName(a), byName(b)
	for _, name := range sortedKeys(bm) {
		bs := bm[name]
		as, ok := am[name]
		if !ok {
			d.Added = append(d.Added, name)
			continue
		}
		ch := SectionChange{Name: name}
		changed := false
		if as.RawSize != bs.RawSize {
			ch.RawSize, changed = &Change[uint64]{as.RawSize, bs.RawSize}, true
		}
		if as.VirtualSize != bs.VirtualSize {
			ch.VirtualSize, changed = &Change[uint64]{as.VirtualSize, bs.VirtualSize}, true
		}
		if as.Entropy != bs.Entropy {
			ch.Entropy, changed = &Change[float64]{as.Entropy, bs.Entropy}, true
		}
		if !slices.Equal(as.Flags, bs.Flags) {
			ch.Flags, changed = &Change[[]string]{as.Flags, bs.Flags}, true
		}
		if changed {
			d.Changed = append(d.Changed, ch)
		}
	}
	for _, name := range sortedKeys(am) {
		if _, ok := bm[name]; !ok {
			d.Removed = append(d.Removed, name)
		}
	}
	return d
}

// flattenImports turns the per-library lists into "library!function" entries
// (library names are compared case-insensitively, as the Windows loader does).
func flattenImports(imps []report.Import) []string {
	var out []string
	for _, lib := range imps {
		name := strings.ToLower(lib.Library)
		if len(lib.Functions) == 0 {
			out = append(out, name+"!")
			continue
		}
		for _, fn := range lib.Functions {
			out = append(out, name+"!"+fn)
		}
	}
	return out
}

func diffList(a, b []string) ListDiff {
	d := ListDiff{Added: []string{}, Removed: []string{}}
	as, bs := toSet(a), toSet(b)
	for _, v := range sortedKeys(bs) {
		if _, ok := as[v]; !ok {
			d.AddedCount++
			if len(d.Added) < maxListed {
				d.Added = append(d.Added, v)
			}
		}
	}
	for _, v := range sortedKeys(as) {
		if _, ok := bs[v]; !ok {
			d.RemovedCount++
			if len(d.Removed) < maxListed {
				d.Removed = append(d.Removed, v)
			}
		}
	}
	return d
}

func diffStrings(a, b report.Strings) StringsDiff {
	d := StringsDiff{Added: []StringRef{}, Removed: []StringRef{}, ByCategory: map[string]Change[int]{}}
	index := func(s report.Strings) map[string]string {
		m := make(map[string]string, len(s.Items))
		for _, it := range s.Items {
			if _, dup := m[it.Value]; !dup {
				m[it.Value] = it.Category
			}
		}
		return m
	}
	am, bm := index(a), index(b)
	for _, v := range sortedKeys(bm) {
		if _, ok := am[v]; !ok {
			d.AddedCount++
			if len(d.Added) < maxListed {
				d.Added = append(d.Added, StringRef{Value: v, Category: bm[v]})
			}
		}
	}
	for _, v := range sortedKeys(am) {
		if _, ok := bm[v]; !ok {
			d.RemovedCount++
			if len(d.Removed) < maxListed {
				d.Removed = append(d.Removed, StringRef{Value: v, Category: am[v]})
			}
		}
	}
	cats := map[string]bool{}
	for c := range a.ByCategory {
		cats[c] = true
	}
	for c := range b.ByCategory {
		cats[c] = true
	}
	for c := range cats {
		if a.ByCategory[c] != b.ByCategory[c] {
			d.ByCategory[c] = Change[int]{From: a.ByCategory[c], To: b.ByCategory[c]}
		}
	}
	return d
}

func diffHardening(a, b []report.Hardening) []StatusDiff {
	out := []StatusDiff{}
	am := map[string]report.Hardening{}
	for _, h := range a {
		am[h.ID] = h
	}
	seen := map[string]bool{}
	for _, hb := range b {
		seen[hb.ID] = true
		ha, ok := am[hb.ID]
		from := "absent"
		if ok {
			from = ha.Status
		}
		if from != hb.Status {
			out = append(out, StatusDiff{ID: hb.ID, Label: hb.Label, From: from, To: hb.Status})
		}
	}
	for _, ha := range a {
		if !seen[ha.ID] {
			out = append(out, StatusDiff{ID: ha.ID, Label: ha.Label, From: ha.Status, To: "absent"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func diffFindings(a, b []report.Finding) FindingsDiff {
	d := FindingsDiff{Added: []FindingRef{}, Removed: []FindingRef{}, Changed: []FindingRef{}}
	am := make(map[string]report.Finding, len(a))
	for _, f := range a {
		am[f.ID] = f
	}
	bm := make(map[string]report.Finding, len(b))
	for _, f := range b {
		bm[f.ID] = f
	}
	for _, id := range sortedKeys(bm) {
		fb := bm[id]
		fa, ok := am[id]
		switch {
		case !ok:
			d.Added = append(d.Added, FindingRef{ID: id, Title: fb.Title, Severity: fb.Severity})
		case fa.Severity != fb.Severity:
			d.Changed = append(d.Changed, FindingRef{ID: id, Title: fb.Title, Severity: fb.Severity, From: fa.Severity})
		default:
			d.Unchanged++
		}
	}
	for _, id := range sortedKeys(am) {
		if _, ok := bm[id]; !ok {
			fa := am[id]
			d.Removed = append(d.Removed, FindingRef{ID: id, Title: fa.Title, Severity: fa.Severity})
		}
	}
	rank := func(fs []FindingRef) {
		slices.SortStableFunc(fs, func(x, y FindingRef) int {
			if c := cmp.Compare(y.Severity.Rank(), x.Severity.Rank()); c != 0 {
				return c
			}
			return strings.Compare(x.ID, y.ID)
		})
	}
	rank(d.Added)
	rank(d.Removed)
	rank(d.Changed)
	return d
}

func summarize(r *Result) []string {
	s := []string{}
	if r.Identical {
		return append(s, "files are identical (same SHA-256)")
	}
	if r.A.SHA256 != "" || r.B.SHA256 != "" {
		s = append(s, "SHA-256 differs")
	}
	if r.A.Size != r.B.Size {
		s = append(s, fmt.Sprintf("size %d -> %d bytes (%+d)", r.A.Size, r.B.Size, r.B.Size-r.A.Size))
	}
	if r.Type != nil {
		if r.Type.ID != nil {
			s = append(s, fmt.Sprintf("type %s -> %s", r.Type.ID.From, r.Type.ID.To))
		} else if r.Type.Label != nil {
			s = append(s, fmt.Sprintf("type label %q -> %q", r.Type.Label.From, r.Type.Label.To))
		}
		if len(r.Type.TagsAdded) > 0 {
			s = append(s, "tags added: "+strings.Join(r.Type.TagsAdded, ", "))
		}
		if len(r.Type.TagsRemoved) > 0 {
			s = append(s, "tags removed: "+strings.Join(r.Type.TagsRemoved, ", "))
		}
	}
	if r.A.Imphash != r.B.Imphash && (r.A.Imphash != "" || r.B.Imphash != "") {
		s = append(s, "import hash changed: the import table differs")
	}
	if n := len(r.Sections.Added); n > 0 {
		s = append(s, fmt.Sprintf("%d section(s) added: %s", n, strings.Join(headTail(r.Sections.Added, 5), ", ")))
	}
	if n := len(r.Sections.Removed); n > 0 {
		s = append(s, fmt.Sprintf("%d section(s) removed: %s", n, strings.Join(headTail(r.Sections.Removed, 5), ", ")))
	}
	for _, c := range r.Sections.Changed {
		if c.Entropy != nil && (c.Entropy.To-c.Entropy.From >= 0.5 || c.Entropy.From-c.Entropy.To >= 0.5) {
			s = append(s, fmt.Sprintf("section %s entropy %.2f -> %.2f", c.Name, c.Entropy.From, c.Entropy.To))
		}
		if c.Flags != nil {
			s = append(s, fmt.Sprintf("section %s flags %s -> %s", c.Name, strings.Join(c.Flags.From, ""), strings.Join(c.Flags.To, "")))
		}
	}
	if r.Imports.AddedCount > 0 || r.Imports.RemovedCount > 0 {
		s = append(s, fmt.Sprintf("imports: +%d -%d functions", r.Imports.AddedCount, r.Imports.RemovedCount))
	}
	if r.Exports.AddedCount > 0 || r.Exports.RemovedCount > 0 {
		s = append(s, fmt.Sprintf("exports: +%d -%d", r.Exports.AddedCount, r.Exports.RemovedCount))
	}
	if r.Strings.AddedCount > 0 || r.Strings.RemovedCount > 0 {
		s = append(s, fmt.Sprintf("strings: +%d new, -%d gone", r.Strings.AddedCount, r.Strings.RemovedCount))
	}
	for _, h := range r.Hardening {
		s = append(s, fmt.Sprintf("hardening %s: %s -> %s", h.ID, h.From, h.To))
	}
	for _, f := range r.Findings.Added {
		s = append(s, fmt.Sprintf("new finding %s (%s)", f.ID, f.Severity))
	}
	for _, f := range r.Findings.Removed {
		s = append(s, fmt.Sprintf("finding gone %s (%s)", f.ID, f.Severity))
	}
	for _, f := range r.Findings.Changed {
		s = append(s, fmt.Sprintf("finding %s severity %s -> %s", f.ID, f.From, f.Severity))
	}
	if r.Risk.Delta != 0 {
		s = append(s, fmt.Sprintf("risk %d (%s) -> %d (%s), %+d", r.Risk.From, r.Risk.LabelFrom, r.Risk.To, r.Risk.LabelTo, r.Risk.Delta))
	}
	if len(s) == 1 && s[0] == "SHA-256 differs" {
		s = append(s, "no structural difference was recorded in sections, imports, strings, hardening or findings")
	}
	return s
}

func headTail(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(slices.Clone(items[:n]), fmt.Sprintf("(+%d more)", len(items)-n))
}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, v := range items {
		m[v] = struct{}{}
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
