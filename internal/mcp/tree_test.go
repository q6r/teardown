package mcp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Separator characters are built from numeric code points so no invisible
// character ever appears in the source.
var (
	lineSep = string(rune(0x2028))
	paraSep = string(rune(0x2029))
)

// decodeExact decodes JSON keeping numbers exact, for semantic comparison.
func decodeExact(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, data)
	}
	return v
}

func TestTreeRoundTripIsSemanticallyIdentical(t *testing.T) {
	tricky, err := json.Marshal(map[string]string{
		"s":                 "tab\there\nnew \"quoted\" back\\slash \x00 nul \x1f \x7f " + lineSep + " " + paraSep + " é 日本 😀 <tag> & more",
		"unicode key é":     "v",
		"":                  "empty key",
		"html <b>&amp;</b>": "<script>alert(1)</script>",
	})
	if err != nil {
		t.Fatal(err)
	}
	docs := []string{
		`{}`, `[]`, `null`, `true`, `"x"`, `0`, `-0`, `1.5e300`,
		`{"a":1,"b":[1,2,3],"c":{"d":"x","e":[]},"f":["short","list"],"g":[{"h":1},{"h":2}],"i":{}}`,
		`{"big":18446744073709551615,"neg":-9223372036854775808,"frac":0.1000000000000000055511151231257827,"exp":1E+2}`,
		string(tricky),
		`[[[[[[1]]]]]]`,
	}
	for _, doc := range docs {
		n, err := parseTree([]byte(doc))
		if err != nil {
			t.Fatalf("parseTree(%s): %v", doc, err)
		}
		want := decodeExact(t, []byte(doc))
		for name, out := range map[string][]byte{"compact": n.compact(), "pretty": []byte(n.pretty())} {
			if got := decodeExact(t, out); !reflect.DeepEqual(got, want) {
				t.Errorf("%s of %s changed the value:\n%s", name, doc, out)
			}
		}
	}
}

func TestTreeKeepsDuplicateKeysInOrder(t *testing.T) {
	n, err := parseTree([]byte(`{"dup":1,"other":0,"dup":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(n.compact()); got != `{"dup":1,"other":0,"dup":2}` {
		t.Errorf("compact = %s", got)
	}
}

func TestTreePrettyFormat(t *testing.T) {
	n, err := parseTree([]byte(`{"a":1,"b":[1,2,3],"c":{"d":"x","e":[]},"f":["short","list"],"g":[{"h":1},{"h":2}],"i":{},"url":"http://x/?a=1&b=<2>"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "a": 1,
  "b": [1, 2, 3],
  "c": {
    "d": "x",
    "e": []
  },
  "f": ["short", "list"],
  "g": [
    {
      "h": 1
    },
    {
      "h": 2
    }
  ],
  "i": {},
  "url": "http://x/?a=1&b=<2>"
}`
	if got := n.pretty(); got != want {
		t.Errorf("pretty output differs:\n%s\nwant:\n%s", got, want)
	}
}

func TestTreePrettyKeepsLongStringListsReadable(t *testing.T) {
	long := `["` + strings.Repeat("a", 60) + `","` + strings.Repeat("b", 60) + `"]`
	n, err := parseTree([]byte(`{"names":` + long + `,"windows":[` + strings.TrimSuffix(strings.Repeat("7.123,", 400), ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	out := n.pretty()
	if !strings.Contains(out, "\"names\": [\n    \""+strings.Repeat("a", 60)+"\",\n    \""+strings.Repeat("b", 60)+"\"\n  ]") {
		t.Errorf("long string lists must be one element per line:\n%s", out)
	}
	if !strings.Contains(out, `"windows": [7.123, 7.123,`) {
		t.Errorf("number lists must stay on one line:\n%.200s", out)
	}
}

func TestTreeRejectsBadInput(t *testing.T) {
	deep := strings.Repeat("[", maxTreeDepth+5) + strings.Repeat("]", maxTreeDepth+5)
	tests := []struct {
		name, doc string
	}{
		{"empty", ``},
		{"truncated object", `{"a":`},
		{"truncated array", `[1,2`},
		{"trailing garbage", `{} {}`},
		{"trailing comma", `[1,]`},
		{"bare word", `nope`},
		{"unquoted key", `{a:1}`},
		{"too deep", deep},
	}
	for _, tc := range tests {
		if n, err := parseTree([]byte(tc.doc)); err == nil {
			t.Errorf("%s: parseTree accepted %q as %v", tc.name, tc.doc, n)
		}
	}
	ok := strings.Repeat("[", maxTreeDepth) + strings.Repeat("]", maxTreeDepth)
	if _, err := parseTree([]byte(ok)); err != nil {
		t.Errorf("nesting at the limit must parse: %v", err)
	}
}

func TestAppendQuoted(t *testing.T) {
	bs := "\\"
	tests := []struct {
		in, want string
	}{
		{"plain", `"plain"`},
		{`say "hi"`, `"say ` + bs + `"hi` + bs + `""`},
		{`back\slash`, `"back` + bs + bs + `slash"`},
		{"line\nbreak\rand\ttab", `"line` + bs + `nbreak` + bs + `rand` + bs + `ttab"`},
		{"nul\x00and\x1f", `"nul` + bs + `u0000and` + bs + `u001f"`},
		{"del\x7f", `"del` + bs + `u007f"`},
		{"ls" + lineSep + "ps" + paraSep, `"ls` + bs + `u2028ps` + bs + `u2029"`},
		{"<a href='x'>&</a>", `"<a href='x'>&</a>"`},
		{"é日本😀", `"é日本😀"`},
		{"bad\xffutf8", `"bad` + string(utf8.RuneError) + `utf8"`},
		{"", `""`},
	}
	for _, tc := range tests {
		got := string(appendQuoted(nil, tc.in))
		if got != tc.want {
			t.Errorf("appendQuoted(%q) = %s, want %s", tc.in, got, tc.want)
		}
		var back string
		if err := json.Unmarshal([]byte(got), &back); err != nil {
			t.Errorf("appendQuoted(%q) is not valid JSON: %v", tc.in, err)
		}
	}
	if out := appendQuoted(nil, "x"+lineSep+paraSep); bytes.ContainsAny(out, lineSep+paraSep) {
		t.Errorf("the separators must be escaped, got %q", out)
	}
}

func TestTreeMutationHelpers(t *testing.T) {
	n, err := parseTree([]byte(`{"a":1,"b":{"c":[1,2]},"d":"s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n.at("b", "c").kind != kindArray || n.at("b", "zzz") != nil || n.at("a", "x") != nil {
		t.Error("at navigates objects only")
	}
	n.setKey("a", intNode(2))
	n.setKey("e", boolNode(true))
	n.delKey("b")
	n.delKey("missing")
	if got := string(n.compact()); got != `{"a":2,"d":"s","e":true}` {
		t.Errorf("after mutation: %s", got)
	}
	if v, ok := n.child("d").stringValue(); !ok || v != "s" {
		t.Error("stringValue failed")
	}
	if _, ok := n.child("a").stringValue(); ok {
		t.Error("a number is not a string value")
	}
	if n.weight() != 4 {
		t.Errorf("weight = %d", n.weight())
	}
	if (*node)(nil).child("x") != nil {
		t.Error("child on a nil node must be nil")
	}
}
