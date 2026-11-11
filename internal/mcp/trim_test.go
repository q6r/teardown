package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

func mustTree(t *testing.T, v any) *node {
	t.Helper()
	n, err := treeOf(v)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCapArrayAndCapEachField(t *testing.T) {
	n := mustTree(t, map[string]any{
		"items": []int{1, 2, 3, 4, 5},
		"libs": []map[string]any{
			{"name": "a", "functions": []string{"1", "2", "3", "4"}},
			{"name": "b", "functions": []string{"1"}},
			{"name": "c"},
		},
	})
	notes := capArrayAt(2, "items")(n)
	if len(notes) != 1 || notes[0] != (trimNote{Path: "items", Kept: 2, Total: 5}) {
		t.Fatalf("notes = %+v", notes)
	}
	if got := capArrayAt(2, "items")(n); got != nil {
		t.Errorf("a second application must be a no-op, got %+v", got)
	}
	if got := capArrayAt(2, "missing", "path")(n); got != nil {
		t.Errorf("a missing path must be a no-op, got %+v", got)
	}
	notes = capEachField(2, "functions", "libs")(n)
	if len(notes) != 1 || notes[0] != (trimNote{Path: "libs[].functions", Kept: 3, Total: 5}) {
		t.Fatalf("each-field notes = %+v", notes)
	}
	if got := string(n.at("libs").kids[0].child("functions").compact()); got != `["1","2"]` {
		t.Errorf("functions = %s", got)
	}
}

func TestCapDetailListsWalksNestedLists(t *testing.T) {
	n := mustTree(t, map[string]any{
		"sections": []int{1, 2, 3, 4, 5, 6},
		"details": map[string]any{
			"archive": map[string]any{"entries": []int{1, 2, 3, 4, 5, 6}, "kind": "zip", "nested": []string{"a", "b"}},
			"go":      map[string]any{"deps": []map[string]any{{"p": []int{1, 2, 3}}, {"p": []int{4}}}},
		},
	})
	notes := capDetailLists(2)(n)
	got := map[string]trimNote{}
	for _, nt := range notes {
		got[nt.Path] = nt
	}
	if got["details.archive.entries"] != (trimNote{Path: "details.archive.entries", Kept: 2, Total: 6}) {
		t.Errorf("entries note = %+v", got["details.archive.entries"])
	}
	if got["details.go.deps[].p"].Total != 3 || got["details.go.deps[].p"].Kept != 2 {
		t.Errorf("nested list note = %+v (all notes %+v)", got["details.go.deps[].p"], notes)
	}
	if n.at("sections").kids == nil || len(n.at("sections").kids) != 6 {
		t.Error("lists outside details must not be touched")
	}
	if len(n.at("details", "archive", "nested").kids) != 2 {
		t.Error("short lists must stay")
	}
	if capDetailLists(2)(mustTree(t, map[string]any{"x": 1})) != nil {
		t.Error("no details member is a no-op")
	}
}

func TestCapDetailListsBoundsTheNumberOfNotes(t *testing.T) {
	details := map[string]any{}
	for i := range 60 {
		details[fmt.Sprintf("list%02d", i)] = []int{1, 2, 3, 4}
	}
	notes := capDetailLists(1)(mustTree(t, map[string]any{"details": details}))
	if len(notes) != maxDetailNotes {
		t.Fatalf("notes = %d, want the bound %d", len(notes), maxDetailNotes)
	}
	last := notes[len(notes)-1]
	if !strings.Contains(last.Path, "other lists") || last.Total != (60-(maxDetailNotes-1))*4 {
		t.Errorf("aggregate note = %+v", last)
	}
}

func TestCapStringsTopPrefersInterestingCategoriesAndKeepsFileOrder(t *testing.T) {
	var items []report.StringItem
	cats := []string{report.CatPlain, report.CatPlain, report.CatURL, report.CatPlain, report.CatSecret, report.CatAPI, report.CatPlain, report.CatIP, report.CatHex}
	for i, c := range cats {
		items = append(items, report.StringItem{Value: fmt.Sprintf("v%d", i), Offset: int64(i * 10), Category: c, Encoding: "ascii"})
	}
	n := mustTree(t, map[string]any{"strings": map[string]any{"items": items}})
	notes := capStringsTop(4)(n)
	if len(notes) != 1 || notes[0] != (trimNote{Path: "strings.items", Kept: 4, Total: 9}) {
		t.Fatalf("notes = %+v", notes)
	}
	var kept []string
	for _, k := range n.at("strings", "items").kids {
		v, _ := k.child("value").stringValue()
		kept = append(kept, v)
	}
	// secret (v4), url (v2), ip (v7) and api (v5) outrank hex and plain; file order is restored.
	if want := []string{"v2", "v4", "v5", "v7"}; !slices.Equal(kept, want) {
		t.Errorf("kept = %v, want %v", kept, want)
	}
	if capStringsTop(4)(n) != nil || capStringsTop(100)(n) != nil {
		t.Error("nothing more to cut")
	}
	capStringsTop(0)(n)
	if len(n.at("strings", "items").kids) != 0 {
		t.Error("capStringsTop(0) must empty the list")
	}
}

func TestCapLargestHalvesTheHeaviestArray(t *testing.T) {
	n := mustTree(t, map[string]any{
		"small": []int{1, 2},
		"big":   []int{1, 2, 3, 4, 5, 6, 7, 8},
		"nest":  map[string]any{"rows": []map[string]any{{"x": []int{1, 2, 3}}}},
		"trimmed": []map[string]any{
			{"path": "a", "kept": 1, "total": 2}, {"path": "b", "kept": 1, "total": 2}, {"path": "c", "kept": 1, "total": 2},
			{"path": "d", "kept": 1, "total": 2}, {"path": "e", "kept": 1, "total": 2}, {"path": "f", "kept": 1, "total": 2},
			{"path": "g", "kept": 1, "total": 2}, {"path": "h", "kept": 1, "total": 2}, {"path": "i", "kept": 1, "total": 2},
		},
	})
	notes := capLargest()(n)
	if len(notes) != 1 || notes[0] != (trimNote{Path: "big", Kept: 4, Total: 8}) {
		t.Fatalf("notes = %+v (the trimmed member must never be chosen)", notes)
	}
	// Repeated application terminates and eventually finds nothing to cut.
	for range 100 {
		if capLargest()(n) == nil {
			break
		}
	}
	if capLargest()(n) != nil {
		t.Fatal("capLargest must terminate")
	}
	if len(n.at("trimmed").kids) != 9 {
		t.Error("the trimmed notes must survive")
	}
}

func TestMergeNoteKeepsTheOriginalTotal(t *testing.T) {
	var notes []trimNote
	notes = mergeNote(notes, trimNote{Path: "x", Kept: 100, Total: 5000})
	notes = mergeNote(notes, trimNote{Path: "y", Kept: 3, Total: 9})
	notes = mergeNote(notes, trimNote{Path: "x", Kept: 10, Total: 100})
	want := []trimNote{{Path: "x", Kept: 10, Total: 5000}, {Path: "y", Kept: 3, Total: 9}}
	if !slices.Equal(notes, want) {
		t.Fatalf("notes = %+v, want %+v", notes, want)
	}
}

// ladderOrder is the order in which analyze_file gives up detail.
var ladderOrder = []string{
	"strings.items", "imports[].functions", "details.archive.entries", "sections",
	"exports", "imports", "findings[].evidence", "entropy.windows",
}

func TestFitHonoursTheCapAndTheLadderOrder(t *testing.T) {
	base, err := json.Marshal(bigReport(1200))
	if err != nil {
		t.Fatal(err)
	}
	var lastWeight int
	for _, limit := range []int{1 << 20, 256 << 10, 64 << 10, 16 << 10, 4 << 10, 1 << 10} {
		tree, err := parseTree(base)
		if err != nil {
			t.Fatal(err)
		}
		spec := fitSpec{onCap: analyzeLadder(), finish: reportFinisher(detailFull)}
		text, compact, notes, err := fit(tree, spec, limit)
		if errors.Is(err, errTooLarge) {
			if limit > 4<<10 {
				t.Errorf("cap %d: the report must be trimmable to this size", limit)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(text) > limit {
			t.Errorf("cap %d: text is %d bytes", limit, len(text))
		}
		if !json.Valid([]byte(text)) || !json.Valid(compact) {
			t.Errorf("cap %d: output is not valid JSON", limit)
		}
		checkLadderOrder(t, limit, notes)
		// A smaller cap never keeps more data than a larger one.
		w := tree.weight()
		if lastWeight != 0 && w > lastWeight {
			t.Errorf("cap %d keeps more nodes (%d) than a larger cap (%d)", limit, w, lastWeight)
		}
		lastWeight = w
	}
}

func checkLadderOrder(t *testing.T, limit int, notes []trimNote) {
	t.Helper()
	kept := map[string]int{}
	for _, n := range notes {
		kept[n.Path] = n.Kept
	}
	for i, path := range ladderOrder {
		if _, trimmed := kept[path]; !trimmed {
			continue
		}
		for _, earlier := range ladderOrder[:i] {
			if k, ok := kept[earlier]; !ok || k != 0 {
				t.Errorf("cap %d: %s was cut while %s still holds data (kept %d, present %v)", limit, path, earlier, k, ok)
			}
		}
	}
}

func TestFitFallsBackToTheLargestArrayForUnknownShapes(t *testing.T) {
	huge := make([]string, 3000)
	for i := range huge {
		huge[i] = fmt.Sprintf("item-%04d-%s", i, strings.Repeat("z", 40))
	}
	tree := mustTree(t, map[string]any{"name": "x", "mystery": map[string]any{"rows": huge}})
	spec := fitSpec{finish: genericFinisher("shortened")}
	text, _, notes, err := fit(tree, spec, 4<<10)
	if err != nil {
		t.Fatal(err)
	}
	if len(text) > 4<<10 || len(notes) == 0 || notes[0].Path != "mystery.rows" || notes[0].Total != 3000 {
		t.Fatalf("len=%d notes=%+v", len(text), notes)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(text), &doc); err != nil || doc["truncated"] != true || doc["note"] != "shortened" {
		t.Errorf("decoration missing: %v %v", err, doc)
	}
}

func TestFitReportsAResultItCannotShrink(t *testing.T) {
	tree := mustTree(t, map[string]any{"blob": strings.Repeat("x", 50_000)})
	if _, _, _, err := fit(tree, fitSpec{}, 4<<10); !errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v, want errTooLarge", err)
	}
}

func TestFitDoesNotTrimWhenTheResultFits(t *testing.T) {
	tree := mustTree(t, map[string]any{"items": []int{1, 2, 3}})
	text, _, notes, err := fit(tree, fitSpec{onCap: itemLadder(), finish: genericFinisher("n")}, 1<<10)
	if err != nil || len(notes) != 0 {
		t.Fatalf("err=%v notes=%+v", err, notes)
	}
	if !strings.Contains(text, `"truncated": false`) || strings.Contains(text, "trimmed") {
		t.Errorf("text = %s", text)
	}
}
