package mcp

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// errTooLarge is returned when a result cannot be made to fit the output cap.
var errTooLarge = errors.New("result does not fit the output cap")

// trimNote records one list that was shortened.
type trimNote struct {
	Path  string `json:"path"`
	Kept  int    `json:"kept"`
	Total int    `json:"total"`
}

// trimStep shortens parts of a result tree and reports what it cut; it returns
// nothing when there was nothing left to cut.
type trimStep func(root *node) []trimNote

// fitSpec describes how a tool result is brought under the output cap.
type fitSpec struct {
	// always run before the first measurement (the "summary" view).
	always []trimStep
	// onCap run one at a time, in order, while the text is still too large.
	onCap []trimStep
	// finish sets derived keys (truncated, trimmed, note, paging) on the tree. It
	// runs before every measurement because those keys take space themselves.
	finish func(root *node, notes []trimNote)
}

// maxLargestRounds bounds the generic fallback that halves the largest array.
const maxLargestRounds = 256

// fit applies the spec to tree until the pretty-printed text is at most limit
// bytes. It returns the text, the compact form of the final tree, and the notes
// describing every list that was shortened. Nothing in the tree is protected
// from the generic fallback except the notes themselves, so a result that is
// still too large after every step yields errTooLarge.
func fit(tree *node, spec fitSpec, limit int) (text string, compact []byte, notes []trimNote, err error) {
	apply := func(st trimStep) bool {
		got := st(tree)
		for _, n := range got {
			notes = mergeNote(notes, n)
		}
		return len(got) > 0
	}
	measure := func() bool {
		if spec.finish != nil {
			spec.finish(tree, notes)
		}
		text = tree.pretty()
		return len(text) <= limit
	}
	for _, st := range spec.always {
		apply(st)
	}
	if measure() {
		return text, tree.compact(), notes, nil
	}
	for _, st := range spec.onCap {
		if apply(st) && measure() {
			return text, tree.compact(), notes, nil
		}
	}
	for range maxLargestRounds {
		if !apply(capLargest()) {
			break
		}
		if measure() {
			return text, tree.compact(), notes, nil
		}
	}
	return "", nil, notes, errTooLarge
}

// mergeNote adds n, or lowers the kept count of an existing note for the same
// path while preserving the original total.
func mergeNote(notes []trimNote, n trimNote) []trimNote {
	for i := range notes {
		if notes[i].Path == n.Path {
			notes[i].Kept = n.Kept
			return notes
		}
	}
	return append(notes, n)
}

// cut shortens an array node to at most n elements.
func cut(arr *node, n int) (kept, total int, changed bool) {
	total = len(arr.kids)
	if total <= n {
		return total, total, false
	}
	arr.kids = arr.kids[:n]
	return n, total, true
}

// capArrayAt keeps at most n elements of the array found at path.
func capArrayAt(n int, path ...string) trimStep {
	label := strings.Join(path, ".")
	return func(root *node) []trimNote {
		arr := root.at(path...)
		if arr == nil || arr.kind != kindArray {
			return nil
		}
		kept, total, changed := cut(arr, n)
		if !changed {
			return nil
		}
		return []trimNote{{Path: label, Kept: kept, Total: total}}
	}
}

// capEachField keeps at most n elements of the array member field of every
// object in the array at listPath (for example imports[].functions).
func capEachField(n int, field string, listPath ...string) trimStep {
	label := strings.Join(listPath, ".") + "[]." + field
	return func(root *node) []trimNote {
		list := root.at(listPath...)
		if list == nil || list.kind != kindArray {
			return nil
		}
		var kept, total int
		changed := false
		for _, el := range list.kids {
			arr := el.child(field)
			if arr == nil || arr.kind != kindArray {
				continue
			}
			k, t, c := cut(arr, n)
			kept += k
			total += t
			changed = changed || c
		}
		if !changed {
			return nil
		}
		return []trimNote{{Path: label, Kept: kept, Total: total}}
	}
}

// maxDetailNotes bounds the notes produced by capDetailLists.
const maxDetailNotes = 24

// capDetailLists keeps at most n elements of every array anywhere inside the
// details member (archive entries, file lists, dependencies, ...).
func capDetailLists(n int) trimStep {
	return func(root *node) []trimNote {
		d := root.child("details")
		if d == nil {
			return nil
		}
		var notes []trimNote
		var walk func(v *node, path string)
		walk = func(v *node, path string) {
			switch v.kind {
			case kindObject:
				for i, k := range v.keys {
					walk(v.kids[i], path+"."+k)
				}
			case kindArray:
				if kept, total, changed := cut(v, n); changed {
					notes = append(notes, trimNote{Path: path, Kept: kept, Total: total})
				}
				for _, el := range v.kids {
					walk(el, path+"[]")
				}
			}
		}
		walk(d, "details")
		if len(notes) > maxDetailNotes {
			rest := notes[maxDetailNotes-1:]
			agg := trimNote{Path: "details (other lists)"}
			for _, r := range rest {
				agg.Kept += r.Kept
				agg.Total += r.Total
			}
			notes = append(notes[:maxDetailNotes-1], agg)
		}
		return notes
	}
}

// capStringsTop keeps the n most interesting items of strings.items: secrets
// first, then the categories in report.StringCategories order, with file order
// preserved inside the result.
func capStringsTop(n int) trimStep {
	rank := map[string]int{}
	for i, c := range report.StringCategories() {
		rank[c] = i
	}
	return func(root *node) []trimNote {
		items := root.at("strings", "items")
		if items == nil || items.kind != kindArray || len(items.kids) <= n {
			return nil
		}
		total := len(items.kids)
		idx := make([]int, total)
		for i := range idx {
			idx[i] = i
		}
		prio := func(i int) int {
			cat, _ := items.kids[i].child("category").stringValue()
			if r, ok := rank[cat]; ok {
				return r
			}
			return len(rank)
		}
		sort.SliceStable(idx, func(a, b int) bool { return prio(idx[a]) < prio(idx[b]) })
		keep := idx[:n]
		slices.Sort(keep)
		kept := make([]*node, 0, n)
		for _, i := range keep {
			kept = append(kept, items.kids[i])
		}
		items.kids = kept
		return []trimNote{{Path: "strings.items", Kept: n, Total: total}}
	}
}

// capLargest halves the array with the most descendants. It is the generic
// fallback for results whose shape the tool does not know (diffs).
func capLargest() trimStep {
	return func(root *node) []trimNote {
		var best *node
		bestPath, bestWeight := "", 0
		var walk func(v *node, path string)
		walk = func(v *node, path string) {
			switch v.kind {
			case kindObject:
				for i, k := range v.keys {
					if path == "" && k == "trimmed" {
						continue
					}
					walk(v.kids[i], join(path, k))
				}
			case kindArray:
				if w := v.weight(); len(v.kids) > 0 && w > bestWeight {
					best, bestPath, bestWeight = v, path, w
				}
				for _, el := range v.kids {
					walk(el, path+"[]")
				}
			}
		}
		walk(root, "")
		if best == nil {
			return nil
		}
		total := len(best.kids)
		best.kids = best.kids[:total/2]
		return []trimNote{{Path: bestPath, Kept: len(best.kids), Total: total}}
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// notesNode converts notes to a tree for the "trimmed" member.
func notesNode(notes []trimNote) *node {
	arr := &node{kind: kindArray}
	for _, n := range notes {
		obj := &node{kind: kindObject}
		obj.setKey("path", stringNode(n.Path))
		obj.setKey("kept", intNode(n.Kept))
		obj.setKey("total", intNode(n.Total))
		arr.kids = append(arr.kids, obj)
	}
	return arr
}
