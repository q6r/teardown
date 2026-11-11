package analyze

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/strs"
)

// Fake credentials, assembled from pieces so that secret scanners do not mistake
// this file for a leak. Every one of them matches a pattern of the scanner.
var (
	fakeAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGitHub = "ghp_" + strings.Repeat("Zy9x", 9)
	fakeSlack  = "xoxb-" + "123456789012-" + "abcdefABCDEF1234"
	fakePEM    = "-----BEGIN RSA PRIVATE" + " KEY-----"
)

func TestMaskSecretsHidesEveryByteOfEverySecret(t *testing.T) {
	utf16 := func(s string) []byte {
		var out []byte
		for i := 0; i < len(s); i++ {
			out = append(out, s[i], 0)
		}
		return out
	}
	tests := []struct {
		name   string
		in     []byte
		secret string // what must be gone, as it appears in in
	}{
		{"alone", []byte(fakeAWS), fakeAWS},
		{"in an assignment", []byte("aws_access_key_id=" + fakeAWS + ";\n"), fakeAWS},
		{"glued to text", []byte("x" + fakeGitHub + "y"), fakeGitHub},
		{"slack between NULs", []byte("\x00\x00" + fakeSlack + "\x00\x00"), fakeSlack},
		{"utf-16 at an even offset", append([]byte("ab"), utf16(fakeAWS)...), string(utf16(fakeAWS))},
		{"utf-16 at an odd offset", append([]byte("abc"), utf16(fakeGitHub)...), string(utf16(fakeGitHub))},
		{"two secrets", []byte(fakeAWS + "\x00" + fakeGitHub), fakeAWS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, hidden, _ := maskSecrets(tc.in)
			if len(out) != len(tc.in) {
				t.Fatalf("length changed: %d -> %d", len(tc.in), len(out))
			}
			if bytes.Contains(out, []byte(tc.secret)) {
				t.Fatalf("the secret survived: %q", out)
			}
			start := bytes.Index(tc.in, []byte(tc.secret))
			for i := start; i < start+len(tc.secret); i++ {
				if out[i] != maskByte {
					t.Fatalf("byte %d of the secret is %#x, want %#x: %q", i-start, out[i], maskByte, out)
				}
			}
			if !maskedAt(hidden, int64(start), int64(start+1)) {
				t.Fatalf("the hidden ranges %v do not cover the secret at %d", hidden, start)
			}
		})
	}
}

func TestMaskSecretsLeavesOrdinaryBytesAlone(t *testing.T) {
	in := []byte("GET /index.html HTTP/1.1\r\nHost: example.test\x00\x01\x02 plain AKIA text and 0123456789")
	out, hidden, pem := maskSecrets(in)
	if !bytes.Equal(out, in) || len(hidden) != 0 || pem {
		t.Fatalf("nothing is secret here, got %q (%v, %v)", out, hidden, pem)
	}
}

func TestMaskSecretsHidesTheBodyOfAPrivateKey(t *testing.T) {
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
	in := []byte("before\n" + fakePEM + "\n" + body + "\n" + body + "\n-----END RSA PRIVATE KEY-----\nafter")
	out, _, pem := maskSecrets(in)
	if !pem {
		t.Fatal("a private-key header must be reported")
	}
	if bytes.Contains(out, []byte(body[:12])) || bytes.Contains(out, []byte("PRIVATE")) {
		t.Fatalf("key material or the header survived: %q", out)
	}
	if !bytes.HasPrefix(out, []byte("before\n")) {
		t.Fatalf("what precedes the header must stay: %q", out)
	}
}

func TestRenderLineRedactsAndSanitises(t *testing.T) {
	// A key written on one line puts its material right behind the header: all of it goes.
	onePEM := fakePEM + `\nMIIEvQIBADANBg\n-----END"`
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "const a = 1;", "const a = 1;"},
		{"crlf", "const a = 1;\r", "const a = 1;"},
		{"tab stops", "a\tb\t\tc", "a   b       c"},
		{"escape sequence", "\x1b[31mred\x1b[0m", `\x1b[31mred\x1b[0m`},
		{"invalid utf-8", "caf\xe9", `caf\xe9`},
		{"nul and bell", "a\x00b\x07c", `a\x00b\x07c`},
		{"bidi override", "a" + string(rune(0x202e)) + "b", "a[U+202E]b"},
		{"line separator", "a" + string(rune(0x2028)) + "b", "a[U+2028]b"},
		{"zero width and bom", "a" + string(rune(0x200b)) + string(rune(0xfeff)) + "b", "a[U+200B][U+FEFF]b"},
		{"c1 control", "a" + string(rune(0x85)) + "b", `a\x85b`},
		{"aws key", "const k = '" + fakeAWS + "';", "const k = 'AKIA…(20 chars)';"},
		{"private key on one line", `k = "` + onePEM, `k = "` + strs.Redact(onePEM)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := renderLine([]byte(tc.in), 0, false)
			if got.text != tc.want {
				t.Fatalf("renderLine(%q) = %q, want %q", tc.in, got.text, tc.want)
			}
		})
	}
	if got := renderLine([]byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAAS"), 0, true); !strings.Contains(got.text, "hidden") || strings.Contains(got.text, "MIIE") || !got.redacted {
		t.Fatalf("a line in a key body must be replaced by a note: %+v", got)
	}
}

func TestRenderLineClipsAroundTheMatch(t *testing.T) {
	line := strings.Repeat("x", 1000) + "nodeIntegration:!0" + strings.Repeat("y", 1000)
	hit := strings.Index(line, "nodeIntegration")
	got := renderLine([]byte(line), hit, false)
	if !got.clipped || utf8.RuneCountInString(got.text) != report.MaxCodeLineChars {
		t.Fatalf("want a clipped line of %d characters, got %d (clipped %v)", report.MaxCodeLineChars, utf8.RuneCountInString(got.text), got.clipped)
	}
	if !strings.Contains(got.text, "nodeIntegration:!0") || !strings.HasPrefix(got.text, "…") || !strings.HasSuffix(got.text, "…") {
		t.Fatalf("the match must be inside the window and both cut sides marked: %q", got.text)
	}
	// A line without a match is cut at its end.
	head := renderLine([]byte(strings.Repeat("z", 500)), 0, false)
	if !head.clipped || strings.HasPrefix(head.text, "…") || !strings.HasSuffix(head.text, "…") || utf8.RuneCountInString(head.text) != report.MaxCodeLineChars {
		t.Fatalf("head clip = %q", head.text)
	}
	// A secret is hidden before the line is cut, so cutting cannot leave part of it.
	long := strings.Repeat("a", 150) + fakeGitHub + strings.Repeat("b", 150)
	if got := renderLine([]byte(long), 150, false); strings.Contains(got.text, "ghp_Zy9x") || !got.redacted {
		t.Fatalf("a secret must be redacted before clipping: %q", got.text)
	}
}

func TestSanitizeTextOutputAlwaysPassesTheModelChecks(t *testing.T) {
	inputs := []string{"", "plain", "\x00\x01\x02", "\xff\xfe", "tab\there", string(rune(0x202e)) + "rtl", "é́", strings.Repeat("\x1b", 300)}
	for _, in := range inputs {
		out := sanitizeText(in)
		b := report.CodeBlock{Kind: report.CodeKindSource, Lines: []report.CodeLine{{Line: 1, Text: clipRunes(out, report.MaxCodeLineChars)}}, Limitations: []string{"x"}}
		if err := b.Validate(); err != nil {
			t.Errorf("sanitizeText(%q) = %q: %v", in, out, err)
		}
	}
}

func TestLooksLikeText(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		partial bool
		want    bool
	}{
		{"empty", nil, false, false},
		{"ascii", []byte("const a = 1;\n"), false, true},
		{"utf-8", []byte("café 中文\n"), false, true},
		{"crlf and tabs", []byte("a\r\n\tb\r\n"), false, true},
		{"ansi colours", []byte("\x1b[31merror\x1b[0m\n"), false, true},
		{"nul byte", []byte("MZ\x00\x00 binary"), false, false},
		{"utf-16", []byte("\xff\xfea\x00b\x00"), false, false},
		{"many control characters", []byte("\x01\x02\x03\x04\x05abcdef"), false, false},
		{"latin-1 text", []byte("caf\xe9 au lait, tr\xe8s bien, \xe0 la carte, tout est correct\n"), false, true},
		{"mostly high bytes", bytes.Repeat([]byte{0xe9}, 40), false, false},
		{"cut inside a character", []byte("abc \xe4\xb8"), true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeText(tc.in, tc.partial); got != tc.want {
				t.Fatalf("looksLikeText(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestGroupSpans(t *testing.T) {
	tests := []struct {
		name      string
		in        []span
		maxSpan   int64
		maxGroups int
		want      []spanGroup
	}{
		{"overlapping spans merge", []span{{10, 30}, {20, 40}}, 100, 3, []spanGroup{{span{10, 40}, []int{0, 1}}}},
		{"touching spans merge", []span{{10, 20}, {20, 30}}, 100, 3, []spanGroup{{span{10, 30}, []int{0, 1}}}},
		{"far spans stay apart and come out in order", []span{{100, 110}, {10, 20}}, 100, 3, []spanGroup{{span{10, 20}, []int{1}}, {span{100, 110}, []int{0}}}},
		{"a merge that would be too big opens a new window", []span{{0, 60}, {50, 120}}, 100, 3, []spanGroup{{span{0, 60}, []int{0}}, {span{50, 120}, []int{1}}}},
		{"the cap drops the least telling spans", []span{{0, 10}, {100, 110}, {200, 210}}, 50, 2, []spanGroup{{span{0, 10}, []int{0}}, {span{100, 110}, []int{1}}}},
		{"nothing", nil, 100, 3, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := groupSpans(tc.in, tc.maxSpan, tc.maxGroups)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i].win != tc.want[i].win || !slices.Equal(got[i].members, tc.want[i].members) {
					t.Fatalf("group %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestLineHelpers(t *testing.T) {
	data := []byte("one\ntwo\r\nthree\n\nfive")
	for pos, want := range map[int64]int64{0: 1, 3: 1, 4: 2, 8: 2, 9: 3, 15: 4, 16: 5, 19: 5, 100: 5, -5: 1} {
		if got := lineNumber(data, pos); got != want {
			t.Errorf("lineNumber(%d) = %d, want %d", pos, got, want)
		}
	}
	for line, want := range map[int64]int{1: 0, 2: 4, 3: 9, 4: 15, 5: 16, 6: len(data), 99: len(data)} {
		if got := lineStartPos(data, line); got != want {
			t.Errorf("lineStartPos(%d) = %d, want %d", line, got, want)
		}
	}
}

func TestKeyBodiesAndLabels(t *testing.T) {
	data := []byte("a\n" + fakePEM + "\nBODY1\nBODY2\n-----END RSA PRIVATE KEY-----\nb\n-----BEGIN CERTIFICATE-----\nCERT\n")
	bodies := keyBodies(data)
	if len(bodies) != 1 {
		t.Fatalf("bodies = %v: only the private key has hidden lines", bodies)
	}
	if got := string(data[bodies[0].lo:bodies[0].hi]); got != "BODY1\nBODY2\n" {
		t.Fatalf("hidden bytes = %q", got)
	}
	if got := joinLabels([]string{"a", "b", "a", "c", "d", "e"}); got != "a, b, c and 2 more" {
		t.Errorf("joinLabels = %q", got)
	}
	if got := describeStrings([]string{"URL", "URL"}); got != "2 URLs" {
		t.Errorf("describeStrings = %q", got)
	}
	if got := describeStrings([]string{"IP address", "IP address", "URL"}); got != "3 strings (IP address, URL)" {
		t.Errorf("describeStrings = %q", got)
	}
	if got := pluralLabel("IP address"); got != "IP addresses" {
		t.Errorf("pluralLabel = %q", got)
	}
}
