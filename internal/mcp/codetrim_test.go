package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// codeFinding is a finding with the given number of disassembly blocks of the
// given number of lines each; the line at index mark is flagged in every block.
func codeFinding(id string, blocks, lines, mark int) report.Finding {
	f := report.Finding{
		ID: id, Title: "A finding with code", Severity: report.SeverityHigh, Category: report.CategoryImports,
		Confidence: report.ConfidenceMedium, Evidence: []string{"evidence"}, Limitations: []string{"it can be wrong"},
	}
	for b := range blocks {
		base := report.Addr(0x140001000 + b*0x1000)
		blk := report.CodeBlock{
			Kind: report.CodeKindDisasm, Title: fmt.Sprintf("%s block %d", id, b), Section: ".text", Offset: 0x400 + int64(b)*0x1000,
			Address: base, Arch: "x86-64", Limitations: []string{"Linear sweep: data can be shown as code."},
		}
		for i := range lines {
			blk.Lines = append(blk.Lines, report.CodeLine{
				Address: base + report.Addr(i*4), Offset: blk.Offset + int64(i*4), Bytes: "0f 1f 40 00",
				Text: fmt.Sprintf("nop dword ptr [rax+0x%x]", i), Highlight: i == mark,
			})
		}
		f.Code = append(f.Code, blk)
	}
	return f
}

// codeBlocksOf returns the code blocks of finding i of an analyze_file result.
func codeBlocksOf(t *testing.T, doc map[string]any, i int) []map[string]any {
	t.Helper()
	finding := doc["findings"].([]any)[i].(map[string]any)
	raw, _ := finding["code"].([]any)
	blocks := make([]map[string]any, len(raw))
	for j, b := range raw {
		blocks[j] = b.(map[string]any)
	}
	return blocks
}

func trimNotes(doc map[string]any) map[string]map[string]any {
	notes := map[string]map[string]any{}
	items, _ := doc["trimmed"].([]any)
	for _, n := range items {
		m := n.(map[string]any)
		notes[m["path"].(string)] = m
	}
	return notes
}

func TestAnalyzeFileSummaryBoundsTheCodeBehindFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "x.bin", sampleBytes(100, 1))
	rep := bigReport(3)
	rep.Findings = []report.Finding{codeFinding("a.first", 6, 40, 30), codeFinding("a.second", 2, 5, 2)}
	rep.Normalize()
	c := startServer(t, Config{Roots: []string{root}}, stubAnalyzer(rep))

	doc := mustJSON(t, c.callTool(1, "analyze_file", map[string]any{"path": "x.bin"}))
	first := codeBlocksOf(t, doc, 0)
	if len(first) != summaryCodeBlocks {
		t.Fatalf("the summary keeps %d blocks of a finding, got %d", summaryCodeBlocks, len(first))
	}
	for i, b := range first {
		lines := b["lines"].([]any)
		if len(lines) != summaryCodeLines {
			t.Fatalf("block %d has %d lines, want %d", i, len(lines), summaryCodeLines)
		}
		// The window around line 30 of 40 is lines 16 to 39, and it keeps the flagged line.
		if text := lines[0].(map[string]any)["text"]; text != "nop dword ptr [rax+0x10]" {
			t.Errorf("block %d starts at %v", i, text)
		}
		flagged := 0
		for _, l := range lines {
			if l.(map[string]any)["highlight"] == true {
				flagged++
			}
		}
		if flagged != 1 {
			t.Errorf("block %d keeps %d flagged lines, want 1", i, flagged)
		}
		// The block begins where its first kept line does, and says it was cut.
		base := uint64(0x140001000 + i*0x1000)
		if b["truncated"] != true || b["address"] != fmt.Sprintf("0x%x", base+64) || b["offset"] != float64(0x400+i*0x1000+64) {
			t.Errorf("block %d header = address %v offset %v truncated %v", i, b["address"], b["offset"], b["truncated"])
		}
		if lims, _ := b["limitations"].([]any); len(lims) != 1 {
			t.Errorf("block %d lost its limitations", i)
		}
	}
	second := codeBlocksOf(t, doc, 1)
	if len(second) != 2 || len(second[0]["lines"].([]any)) != 5 || second[0]["truncated"] != nil {
		t.Errorf("small blocks must be left alone: %v", second)
	}

	notes := trimNotes(doc)
	if n := notes["findings[].code"]; n == nil || n["kept"] != float64(5) || n["total"] != float64(8) {
		t.Errorf("block note = %v", n)
	}
	if n := notes["findings[].code[].lines"]; n == nil || n["kept"] != float64(3*24+10) || n["total"] != float64(3*40+10) {
		t.Errorf("line note = %v", n)
	}
	if doc["truncated"] != true || !strings.Contains(doc["note"].(string), "disassemble and read_bytes") {
		t.Errorf("truncated %v note %v", doc["truncated"], doc["note"])
	}
	if n := len(doc["findings"].([]any)); n != 2 {
		t.Errorf("the summary must keep every finding, got %d", n)
	}
}

func TestAnalyzeFileFullDetailKeepsTheCodeUnlessTheCapForcesOtherwise(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "x.bin", sampleBytes(100, 1))
	rep := report.New("x.bin", 100, "test")
	rep.Findings = []report.Finding{codeFinding("a.first", 6, 40, 30), codeFinding("a.second", 2, 5, 2)}
	rep.Normalize()

	t.Run("a roomy cap", func(t *testing.T) {
		c := startServer(t, Config{Roots: []string{root}, MaxOutput: 4 << 20}, stubAnalyzer(rep))
		doc := mustJSON(t, c.callTool(1, "analyze_file", map[string]any{"path": "x.bin", "detail": "full"}))
		blocks := codeBlocksOf(t, doc, 0)
		if len(blocks) != 6 || len(blocks[0]["lines"].([]any)) != 40 || blocks[0]["truncated"] != nil || doc["truncated"] != false {
			t.Errorf("%d blocks, truncated %v", len(blocks), doc["truncated"])
		}
	})
	t.Run("a tight cap cuts lines around the flagged one, then blocks", func(t *testing.T) {
		for _, limit := range []int{40 << 10, 16 << 10, 6 << 10, 3 << 10} {
			c := startServer(t, Config{Roots: []string{root}, MaxOutput: limit}, stubAnalyzer(rep))
			res := c.callTool(1, "analyze_file", map[string]any{"path": "x.bin", "detail": "full"})
			if res.IsError {
				t.Fatalf("cap %d: %s", limit, res.text())
			}
			if len(res.text()) > limit {
				t.Fatalf("cap %d: text is %d bytes", limit, len(res.text()))
			}
			doc := mustJSON(t, res)
			if doc["truncated"] != true || len(doc["findings"].([]any)) != 2 {
				t.Fatalf("cap %d: truncated %v, findings %d", limit, doc["truncated"], len(doc["findings"].([]any)))
			}
			for f := range 2 {
				for _, b := range codeBlocksOf(t, doc, f) {
					lines := b["lines"].([]any)
					if len(lines) == 0 {
						t.Fatalf("cap %d: a block was emptied", limit)
					}
					if f == 0 && len(lines) < 40 && b["truncated"] != true {
						t.Errorf("cap %d: a cut block must say so", limit)
					}
					if f == 0 {
						flagged := false
						for _, l := range lines {
							flagged = flagged || l.(map[string]any)["highlight"] == true
						}
						if !flagged {
							t.Errorf("cap %d: the flagged line was cut out of a block of %d lines", limit, len(lines))
						}
					}
				}
			}
			if notes := trimNotes(doc); notes["findings[].code[].lines"] == nil && notes["findings[].code"] == nil {
				t.Errorf("cap %d: the cut code is not reported in %v", limit, doc["trimmed"])
			}
		}
	})
}

func treeFrom(t *testing.T, doc string) *node {
	t.Helper()
	n, err := parseTree([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCapCodeLines(t *testing.T) {
	lines := func(n, mark int) string {
		var parts []string
		for i := range n {
			parts = append(parts, fmt.Sprintf(`{"offset":%d,"address":"0x%x","text":"i%d","highlight":%v}`, 100+i, 0x1000+i, i, i == mark))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	doc := `{"findings":[` +
		`{"code":[{"offset":100,"address":"0x1000","lines":` + lines(10, 7) + `},{"offset":0,"lines":` + lines(3, 0) + `}]},` +
		`{"code":[{"offset":100,"lines":` + lines(10, -1) + `}]},` +
		`{"id":"no code here"}]}`
	root := treeFrom(t, doc)
	notes := capCodeLines(4)(root)
	if len(notes) != 1 || notes[0].Path != "findings[].code[].lines" || notes[0].Kept != 4+3+4 || notes[0].Total != 10+3+10 {
		t.Fatalf("notes = %+v", notes)
	}
	text := func(block *node, i int) string {
		s, _ := block.child("lines").kids[i].child("text").stringValue()
		return s
	}
	first := root.at("findings").kids[0].child("code").kids[0]
	// Line 7 of 10 in a window of 4 starts at min(7-2, 10-4) = 5 and keeps the flagged line.
	if got := len(first.child("lines").kids); got != 4 || text(first, 0) != "i5" || text(first, 3) != "i8" {
		t.Errorf("window = %d lines from %s", got, text(first, 0))
	}
	if string(first.child("offset").raw) != "105" || string(first.child("address").raw) != `"0x1005"` || string(first.child("truncated").raw) != "true" {
		t.Errorf("block header = offset %s address %s truncated %v", first.child("offset").raw, first.child("address").raw, first.child("truncated"))
	}
	// A block of three lines is left alone.
	if small := root.at("findings").kids[0].child("code").kids[1]; len(small.child("lines").kids) != 3 || small.child("truncated") != nil {
		t.Error("a block within the limit must not change")
	}
	// Without a flagged line the window is the top of the block.
	plain := root.at("findings").kids[1].child("code").kids[0]
	if text(plain, 0) != "i0" || text(plain, 3) != "i3" || string(plain.child("address").raw) != `"0x1000"` || string(plain.child("offset").raw) != "100" {
		t.Errorf("plain window starts at %s", text(plain, 0))
	}
	// A block whose lines carry no address (a hex window) has none after the cut either.
	hex := treeFrom(t, `{"findings":[{"code":[{"kind":"hex","offset":0,"address":"0x9","lines":[{"offset":0,"text":"a"},{"offset":16,"text":"b"},{"offset":32,"text":"c"}]}]}]}`)
	if got := capCodeLines(2)(hex); len(got) != 1 || got[0].Kept != 2 || got[0].Total != 3 {
		t.Fatalf("hex notes = %+v", got)
	}
	if block := hex.at("findings").kids[0].child("code").kids[0]; block.child("address") != nil || string(block.child("offset").raw) != "0" {
		t.Errorf("hex block = %s", block.compact())
	}
	if again := capCodeLines(4)(root); again != nil {
		t.Errorf("a second pass has nothing left to cut: %+v", again)
	}
	for _, bad := range []string{`{}`, `{"findings":5}`, `{"findings":[{"code":5}]}`, `{"findings":[{"code":[{"lines":5}]}]}`, `{"findings":[{"code":[5]}]}`} {
		if got := capCodeLines(1)(treeFrom(t, bad)); got != nil {
			t.Errorf("%s: notes = %+v", bad, got)
		}
	}
}

func TestWindowStart(t *testing.T) {
	mk := func(n, mark int) []*node {
		out := make([]*node, n)
		for i := range out {
			out[i] = &node{kind: kindObject}
			out[i].setKey("highlight", boolNode(i == mark))
		}
		return out
	}
	tests := []struct {
		n, mark, window, want int
	}{
		{40, 30, 24, 16}, // the flagged line near the end: the window ends with the block
		{40, 20, 24, 8},  // in the middle: centred
		{40, 3, 24, 0},   // near the top: starts at the top
		{40, -1, 24, 0},  // nothing flagged: the top
		{10, 5, 10, 0},   // the window is the whole block
		{10, 9, 4, 6},
	}
	for _, tc := range tests {
		if got := windowStart(mk(tc.n, tc.mark), tc.window); got != tc.want {
			t.Errorf("windowStart(%d lines, flagged %d, window %d) = %d, want %d", tc.n, tc.mark, tc.window, got, tc.want)
		}
	}
}
