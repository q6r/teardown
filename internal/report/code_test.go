package report

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAddrJSONRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		in   Addr
		want string
	}{
		{0, `"0x0"`},
		{0x1a40, `"0x1a40"`},
		{0x140001042, `"0x140001042"`},
		{Addr(math.MaxUint64), `"0xffffffffffffffff"`},
		{1 << 53, `"0x20000000000000"`}, // above the 53 bits a JavaScript number holds exactly
	} {
		raw, err := json.Marshal(tc.in)
		if err != nil || string(raw) != tc.want {
			t.Fatalf("Marshal(%#x) = %s, %v; want %s", uint64(tc.in), raw, err, tc.want)
		}
		var back Addr
		if err := json.Unmarshal(raw, &back); err != nil || back != tc.in {
			t.Errorf("Unmarshal(%s) = %#x, %v; want %#x", raw, uint64(back), err, uint64(tc.in))
		}
	}
	var upper Addr
	if err := json.Unmarshal([]byte(`"0X1F"`), &upper); err != nil || upper != 0x1f {
		t.Errorf("an upper-case prefix and digits are accepted: %v, %#x", err, uint64(upper))
	}
}

func TestAddrRejectsGarbageAndKeepsItsValue(t *testing.T) {
	for _, in := range []string{
		`"140001042"`, `"0x"`, `""`, `"0xg"`, `"0x1_0"`, `" 0x10"`, `"0x10 "`, `"-0x1"`, `"0x-1"`, `"0x+1"`,
		`"0x0x1"`, `"0x10000000000000000"`, `"0x00000000000000001"`, `"1e3"`, `"0b11"`, `"0o7"`,
		`"0x1\u0000"`, `"0x` + string(rune(0x661)) + `"`, // a NUL, then an Arabic-Indic digit
		`5368713282`, `1.5`, `true`, `[]`, `{}`, `["0x1"]`,
	} {
		back := Addr(7)
		if err := json.Unmarshal([]byte(in), &back); err == nil {
			t.Errorf("Unmarshal(%s) succeeded with %#x", in, uint64(back))
		} else if back != 7 {
			t.Errorf("Unmarshal(%s) failed but changed the value to %#x", in, uint64(back))
		}
	}
	if err := (*Addr)(new(Addr)).UnmarshalText([]byte(strings.Repeat("z", 5000))); err == nil || len(err.Error()) > 200 {
		t.Errorf("the error for a huge value must stay short, got %v", err)
	}
	var null Addr = 9
	if err := json.Unmarshal([]byte(`null`), &null); err != nil || null != 9 {
		t.Errorf("null is a no-op like for every text-coded value: %v, %d", err, null)
	}
}

func FuzzAddrText(f *testing.F) {
	for _, s := range []string{"0x0", "0x140001042", "0xFFFFFFFFFFFFFFFF", "0x", "", "0x1_0", "-1", "0x\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var a Addr
		if err := a.UnmarshalText([]byte(s)); err != nil {
			return
		}
		text, err := a.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var again Addr
		if err := again.UnmarshalText(text); err != nil || again != a {
			t.Fatalf("%q -> %#x -> %q -> %#x (%v)", s, uint64(a), text, uint64(again), err)
		}
	})
}

// sampleBlock is a valid block used as the starting point of the validation cases.
func sampleBlock() CodeBlock {
	return CodeBlock{
		Kind: CodeKindDisasm, Title: "Call site of KERNEL32.dll!VirtualAllocEx", Section: ".text", Offset: 0x442, Address: 0x140001042, Arch: "x86-64",
		Lines: []CodeLine{
			{Address: 0x14000103a, Offset: 0x43a, Bytes: "48 89 c1", Text: "mov rcx, rax"},
			{Address: 0x140001042, Offset: 0x442, Bytes: "ff 15 b7 1f 00 00", Text: "call qword ptr [rip+0x1fb7]", Note: "KERNEL32.dll!VirtualAllocEx", Highlight: true},
		},
		Limitations: []string{"x86 family only; a linear sweep can decode data as code."},
	}
}

func TestCodeJSONKeysAreStable(t *testing.T) {
	b := sampleBlock()
	b.File, b.Truncated = "app/main.js", true
	b.Lines[0].Line = 3
	raw, err := json.Marshal(Finding{ID: "x.y", Code: []CodeBlock{b}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	block := m["code"].([]any)[0].(map[string]any)
	line := block["lines"].([]any)[0].(map[string]any)
	for name, tc := range map[string]struct {
		obj  map[string]any
		keys []string
	}{
		"block": {block, []string{"kind", "title", "file", "section", "offset", "address", "arch", "lines", "truncated", "limitations"}},
		"line":  {line, []string{"address", "offset", "bytes", "text", "line"}},
	} {
		got := make([]string, 0, len(tc.obj))
		for k := range tc.obj {
			got = append(got, k)
		}
		slices.Sort(got)
		want := slices.Clone(tc.keys)
		slices.Sort(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s keys:\n got %v\nwant %v", name, got, want)
		}
	}
	if block["address"] != "0x140001042" || line["address"] != "0x14000103a" {
		t.Errorf("addresses must be strings: %v %v", block["address"], line["address"])
	}
	hit := block["lines"].([]any)[1].(map[string]any)
	if hit["highlight"] != true || hit["note"] != "KERNEL32.dll!VirtualAllocEx" {
		t.Errorf("highlight and note are missing from %v", hit)
	}
}

func TestFindingWithoutCodeEncodesAsBefore(t *testing.T) {
	raw, err := json.Marshal(Finding{ID: "a.b", Title: "t", Severity: SeverityLow, Category: CategoryFile, Confidence: ConfidenceHigh, Evidence: []string{"e"}, Limitations: []string{"l"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"a.b","title":"t","severity":"low","category":"file","confidence":"high","evidence":["e"],"limitations":["l"]}`
	if string(raw) != want {
		t.Fatalf("a finding without code changed its encoding:\n got %s\nwant %s", raw, want)
	}
}

// TestReportsWithoutCodeStillDecodeAndReencodeIdentically: the golden sample of
// the contract predates code blocks, so decoding and encoding it again must
// reproduce it byte for byte.
func TestReportsWithoutCodeStillDecodeAndReencodeIdentically(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("a report without code blocks must decode: %v", err)
	}
	again, err := json.MarshalIndent(&rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(again)+"\n" != string(raw) {
		t.Fatal("decoding and encoding the sample report changed it")
	}
}

func TestReportWithCodeRoundTrips(t *testing.T) {
	rep := New("dropper.exe", 1, "dev")
	hex := CodeBlock{Kind: CodeKindHex, Offset: 0x1a40, Lines: []CodeLine{{Offset: 0x1a40, Bytes: "68 74 74 70", Text: "http", Highlight: true}}, Limitations: []string{"bytes only"}}
	src := CodeBlock{Kind: CodeKindSource, File: "app/main.js", Offset: 12, Lines: []CodeLine{{Offset: 12, Line: 7, Text: "eval(payload)"}}, Limitations: []string{"text only"}}
	rep.Findings = []Finding{{ID: "x.y", Code: []CodeBlock{sampleBlock(), hex, src}}}
	rep.Normalize()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Findings, back.Findings) {
		t.Fatalf("code blocks did not survive a round trip:\n got %+v\nwant %+v", back.Findings, rep.Findings)
	}
	for _, b := range back.Findings[0].Code {
		if err := b.Validate(); err != nil {
			t.Errorf("%s block: %v", b.Kind, err)
		}
	}
}

func TestNormalizeKeepsCodeSlicesOutOfNull(t *testing.T) {
	rep := New("x", 0, "dev")
	rep.Findings = []Finding{{ID: "a", Code: []CodeBlock{{Kind: CodeKindHex}}}}
	rep.Normalize()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "null") {
		t.Fatalf("a code block encoded a null: %s", raw)
	}
	if !strings.Contains(string(raw), `"lines":[]`) || !strings.Contains(string(raw), `"limitations":[]`) {
		t.Fatalf("lines and limitations must be empty lists: %s", raw)
	}
}

func TestValidateCodeBlock(t *testing.T) {
	long := strings.Repeat("a", MaxCodeLineChars+1)
	tooMany := make([]CodeLine, MaxCodeLines+1)
	for i := range tooMany {
		tooMany[i] = CodeLine{Text: "nop"}
	}
	cases := []struct {
		name   string
		mutate func(*CodeBlock)
		want   string // substring of the error; "" means valid
	}{
		{"valid", func(*CodeBlock) {}, ""},
		{"all kinds are known (hex)", func(b *CodeBlock) { b.Kind = CodeKindHex }, ""},
		{"all kinds are known (source)", func(b *CodeBlock) {
			b.Kind = CodeKindSource
			for i := range b.Lines {
				b.Lines[i].Line = i + 1
			}
		}, ""},
		{"unknown kind", func(b *CodeBlock) { b.Kind = "decompiled" }, "unknown code block kind"},
		{"empty kind", func(b *CodeBlock) { b.Kind = "" }, "unknown code block kind"},
		{"negative offset", func(b *CodeBlock) { b.Offset = -1 }, "negative offset"},
		{"negative line offset", func(b *CodeBlock) { b.Lines[0].Offset = -5 }, "line 0: negative offset"},
		{"no lines", func(b *CodeBlock) { b.Lines = nil }, "at least one line"},
		{"too many lines", func(b *CodeBlock) { b.Lines = tooMany }, "at most 64"},
		{"exactly the line cap", func(b *CodeBlock) { b.Lines = tooMany[:MaxCodeLines] }, ""},
		{"long text", func(b *CodeBlock) { b.Lines[1].Text = long }, "line 1: text has 201 characters"},
		{"long note", func(b *CodeBlock) { b.Lines[1].Note = long }, "note has 201 characters"},
		{"long title", func(b *CodeBlock) { b.Title = strings.Repeat("t", MaxCodeLabelChars+1) }, "title has"},
		{"control in text", func(b *CodeBlock) { b.Lines[0].Text = "mov\x1b[31m" }, "control character U+001B"},
		{"tab in text", func(b *CodeBlock) { b.Lines[0].Text = "a\tb" }, "control character U+0009"},
		{"C1 control in note", func(b *CodeBlock) { b.Lines[0].Note = "x\u009by" }, "control character U+009B"},
		{"newline in title", func(b *CodeBlock) { b.Title = "a\nb" }, "control character U+000A"},
		{"invalid UTF-8", func(b *CodeBlock) { b.Lines[0].Text = "a\xffb" }, "not valid UTF-8"},
		{"line separator is text, not a control", func(b *CodeBlock) { b.Lines[0].Text = "a" + string(rune(0x2028)) + "b" }, ""},
		{"bad bytes: not hex", func(b *CodeBlock) { b.Lines[0].Bytes = "zz 00" }, "bytes"},
		{"bad bytes: one digit", func(b *CodeBlock) { b.Lines[0].Bytes = "4 89" }, "bytes"},
		{"bad bytes: double space", func(b *CodeBlock) { b.Lines[0].Bytes = "48  89" }, "bytes"},
		{"bad bytes: trailing space", func(b *CodeBlock) { b.Lines[0].Bytes = "48 " }, "bytes"},
		{"bad bytes: 17 pairs", func(b *CodeBlock) { b.Lines[0].Bytes = strings.TrimSpace(strings.Repeat("00 ", 17)) }, "bytes"},
		{"16 pairs of bytes", func(b *CodeBlock) { b.Lines[0].Bytes = strings.TrimSpace(strings.Repeat("aB ", 16)) }, ""},
		{"source line without a number", func(b *CodeBlock) { b.Kind = CodeKindSource }, "numbered from 1"},
		{"negative line number", func(b *CodeBlock) { b.Lines[0].Line = -1 }, "numbered from 1"},
		{"no limitations", func(b *CodeBlock) { b.Limitations = nil }, "always states its limitations"},
		{"blank limitation", func(b *CodeBlock) { b.Limitations = []string{"  "} }, "blank"},
		{"too many limitations", func(b *CodeBlock) { b.Limitations = slices.Repeat([]string{"x"}, MaxCodeLimitations+1) }, "at most 8"},
		{"long limitation", func(b *CodeBlock) { b.Limitations = []string{strings.Repeat("x", MaxCodeLimitationChars+1)} }, "limitation 0"},
	}
	for _, tc := range cases {
		b := sampleBlock()
		tc.mutate(&b)
		err := b.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want one containing %q", tc.name, err, tc.want)
		}
	}
}

func TestFindingValidateCode(t *testing.T) {
	f := Finding{ID: "imports.process-injection"}
	if err := f.ValidateCode(); err != nil {
		t.Fatalf("a finding without code is valid: %v", err)
	}
	f.Code = slices.Repeat([]CodeBlock{sampleBlock()}, MaxCodeBlocks)
	if err := f.ValidateCode(); err != nil {
		t.Fatalf("%d blocks are allowed: %v", MaxCodeBlocks, err)
	}
	f.Code[3].Kind = "nope"
	if err := f.ValidateCode(); err == nil || !strings.Contains(err.Error(), "imports.process-injection") || !strings.Contains(err.Error(), "code block 3") {
		t.Errorf("the error must say which block is wrong: %v", err)
	}
	f.Code = slices.Repeat([]CodeBlock{sampleBlock()}, MaxCodeBlocks+1)
	if err := f.ValidateCode(); err == nil || !strings.Contains(err.Error(), "13 code blocks") {
		t.Errorf("too many blocks: %v", err)
	}
}

func TestClippedBlockKeepsTheFlaggedLineAndSaysItWasCut(t *testing.T) {
	b := sampleBlock()
	b.Lines = nil
	for i := range 300 {
		b.Lines = append(b.Lines, CodeLine{Address: Addr(0x140001000 + i*4), Offset: int64(0x400 + i*4), Bytes: "90", Text: "nop", Highlight: i == 200})
	}
	b.Offset, b.Address = 0x400, 0x140001000
	got := b.Clipped()
	if len(got.Lines) != MaxCodeLines || !got.Truncated {
		t.Fatalf("got %d lines, truncated %v", len(got.Lines), got.Truncated)
	}
	if !slices.ContainsFunc(got.Lines, func(l CodeLine) bool { return l.Highlight }) {
		t.Error("the flagged line fell out of the window")
	}
	if got.Offset != got.Lines[0].Offset || got.Address != got.Lines[0].Address || got.Address == b.Address {
		t.Errorf("the block must start where its first kept line starts: %#x %#x", got.Offset, uint64(got.Address))
	}
	if err := got.Validate(); err != nil {
		t.Errorf("a clipped block must be valid: %v", err)
	}
	if len(b.Lines) != 300 || b.Truncated {
		t.Error("Clipped must not change its receiver")
	}

	b.Lines[200].Highlight = false // no flagged line: the first lines are kept
	if got := b.Clipped(); got.Lines[0].Offset != 0x400 || len(got.Lines) != MaxCodeLines {
		t.Errorf("without a flagged line the window starts at the top: %+v", got.Lines[0])
	}
	b.Lines[299].Highlight = true // a flagged line at the very end: the window ends there
	if got := b.Clipped(); !got.Lines[len(got.Lines)-1].Highlight {
		t.Error("a flagged last line must end the window")
	}
}

func TestClippedBlockBoundsTextAndFillsInTheLimits(t *testing.T) {
	b := sampleBlock()
	b.Title = strings.Repeat("é", MaxCodeLabelChars+50)
	b.Lines[0].Text = strings.Repeat("日", 5000)
	b.Lines[0].Bytes = strings.TrimSpace(strings.Repeat("ab ", 40))
	b.Lines[1].Bytes = "not hex"
	b.Limitations = []string{"", "  ", strings.Repeat("x", 1000)}
	got := b.Clipped()
	if utf8.RuneCountInString(got.Title) != MaxCodeLabelChars || !strings.HasSuffix(got.Title, "…") {
		t.Errorf("title not clipped to %d characters with an ellipsis: %d", MaxCodeLabelChars, utf8.RuneCountInString(got.Title))
	}
	if utf8.RuneCountInString(got.Lines[0].Text) != MaxCodeLineChars {
		t.Errorf("text has %d characters", utf8.RuneCountInString(got.Lines[0].Text))
	}
	if got.Lines[0].Bytes != strings.TrimSpace(strings.Repeat("ab ", 16)) || got.Lines[1].Bytes != "" {
		t.Errorf("bytes must be cut to the longest valid prefix: %q, %q", got.Lines[0].Bytes, got.Lines[1].Bytes)
	}
	if len(got.Limitations) != 1 || utf8.RuneCountInString(got.Limitations[0]) != MaxCodeLimitationChars {
		t.Errorf("blank limitations are dropped and long ones clipped: %q", got.Limitations)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the clipped block must validate: %v", err)
	}

	b.Limitations = nil
	if got := b.Clipped(); !slices.Equal(got.Limitations, []string{NoLimitsStated}) {
		t.Errorf("a block without limitations gets the stated default: %q", got.Limitations)
	}
	b.Offset, b.Lines[0].Offset, b.Lines[0].Line = -9, -9, -9
	if got := b.Clipped(); got.Offset != 0 || got.Lines[0].Offset != 0 || got.Lines[0].Line != 0 {
		t.Errorf("negative numbers are raised to zero: %+v", got)
	}
}

func TestClippedCodeCapsTheNumberOfBlocksAndSaysSo(t *testing.T) {
	f := Finding{ID: "x", Code: slices.Repeat([]CodeBlock{sampleBlock()}, 5000)}
	got, omitted := f.ClippedCode()
	if len(got) != MaxCodeBlocks || omitted != 4988 {
		t.Fatalf("%d blocks kept and %d omitted, want %d and 4988", len(got), omitted, MaxCodeBlocks)
	}
	last := got[len(got)-1].Limitations
	if !strings.Contains(last[len(last)-1], "4988 more code blocks") {
		t.Errorf("the last kept block must say how many were left out: %q", last)
	}
	if len(got[0].Limitations) != 1 || len(f.Code) != 5000 || len(f.Code[11].Limitations) != 1 {
		t.Error("only the last kept block is annotated, and the finding itself is not changed")
	}
	f.Code = nil
	if none, n := f.ClippedCode(); none != nil || n != 0 {
		t.Error("no code, no blocks")
	}
	f.Code = []CodeBlock{{Kind: CodeKindHex}, sampleBlock()}
	if kept, n := f.ClippedCode(); len(kept) != 1 || n != 0 || kept[0].Kind != CodeKindDisasm {
		t.Errorf("a block without lines shows nothing and is dropped: %d kept, %d omitted", len(kept), n)
	}
	full := sampleBlock()
	full.Limitations = slices.Repeat([]string{"x"}, MaxCodeLimitations)
	f.Code = slices.Repeat([]CodeBlock{full}, MaxCodeBlocks+2)
	got, _ = f.ClippedCode()
	if err := got[len(got)-1].Validate(); err != nil {
		t.Errorf("the annotated block must still validate when it already had every limitation: %v", err)
	}
}

func TestWithoutCode(t *testing.T) {
	rep := New("x", 1, "dev")
	rep.Findings = []Finding{{ID: "a", Code: []CodeBlock{sampleBlock()}}, {ID: "b"}}
	bare := rep.WithoutCode()
	if len(rep.Findings[0].Code) != 1 {
		t.Fatal("the original report must keep its code")
	}
	for _, f := range bare.Findings {
		if f.Code != nil {
			t.Errorf("finding %s still has code", f.ID)
		}
	}
	raw, err := json.Marshal(bare)
	if err != nil || strings.Contains(string(raw), `"code"`) {
		t.Errorf("the copy must encode without a code key: %v %s", err, raw)
	}
	empty := &Report{}
	if got := empty.WithoutCode(); got.Findings != nil {
		t.Error("a report without findings keeps nil findings")
	}
}

func FuzzClippedBlock(f *testing.F) {
	f.Add("disasm", "title", "mov rax, rbx", "48 89 d8", "note", 3, true)
	f.Add("hex", strings.Repeat("é", 300), strings.Repeat("x", 500), "zz", "", 200, false)
	f.Add("", "", "", "", "", 0, false)
	f.Fuzz(func(t *testing.T, kind, title, text, bytes, note string, n int, hit bool) {
		n = min(max(n, 0), 400)
		b := CodeBlock{Kind: kind, Title: title, Offset: int64(n), Limitations: []string{text}}
		for i := range n {
			b.Lines = append(b.Lines, CodeLine{Offset: int64(i), Bytes: bytes, Text: text, Note: note, Highlight: hit && i == n/2})
		}
		got := b.Clipped()
		if len(got.Lines) > MaxCodeLines || len(got.Limitations) == 0 || len(got.Limitations) > MaxCodeLimitations {
			t.Fatalf("caps not applied: %d lines, %d limitations", len(got.Lines), len(got.Limitations))
		}
		for _, l := range got.Lines {
			if utf8.RuneCountInString(l.Text) > MaxCodeLineChars || !validHexBytes(l.Bytes) {
				t.Fatalf("line not clipped: %d chars, bytes %q", utf8.RuneCountInString(l.Text), l.Bytes)
			}
		}
	})
}
