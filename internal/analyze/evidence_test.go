package analyze_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

func fixedNow() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }

func analyse(t testing.TB, name string, data []byte) *report.Report {
	t.Helper()
	rep, err := analyze.Reader(context.Background(), bytes.NewReader(data), int64(len(data)), analyze.Options{Name: name, Now: fixedNow, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("analyze %s: %v", name, err)
	}
	return rep
}

func findingByID(t testing.TB, rep *report.Report, id string) report.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.ID == id {
			return f
		}
	}
	ids := make([]string, len(rep.Findings))
	for i, f := range rep.Findings {
		ids[i] = f.ID
	}
	t.Fatalf("no finding %q among %v", id, ids)
	return report.Finding{}
}

// assertCodeIsValid checks every block of every finding against the model's own
// rules and the caps, whatever produced it.
func assertCodeIsValid(t testing.TB, rep *report.Report) {
	t.Helper()
	for _, f := range rep.Findings {
		if err := f.ValidateCode(); err != nil {
			t.Fatalf("%v", err)
		}
		hex, src := 0, 0
		for _, b := range f.Code {
			switch b.Kind {
			case report.CodeKindHex:
				hex++
			case report.CodeKindSource:
				src++
			}
			if len(b.Lines) > report.MaxCodeLines || len(b.Limitations) == 0 {
				t.Fatalf("%s: block %q breaks the caps: %d lines, %d limitations", f.ID, b.Title, len(b.Lines), len(b.Limitations))
			}
		}
		if hex > 3 || src > 6 || len(f.Code) > report.MaxCodeBlocks {
			t.Fatalf("%s: %d hex, %d source, %d blocks in all", f.ID, hex, src, len(f.Code))
		}
	}
}

func peWithBlob(blob []byte) []byte {
	return testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{{Name: ".cfg", Data: blob, Characteristics: testfixtures.PESectionRData}}})
}

func asciiColumn(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = '.'
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		}
	}
	return string(out)
}

func spacedHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, " ")
}

func TestHexWindowAroundAStringIsExact(t *testing.T) {
	url := "https://update.example.test/gate.php"
	blob := slices.Concat(make([]byte, 200), []byte(url), []byte{0}, make([]byte, 200))
	data := peWithBlob(blob)
	off := int64(bytes.Index(data, []byte(url)))
	urlEnd := off + int64(len(url))

	f := findingByID(t, analyse(t, "a.exe", data), "indicators.network")
	if len(f.Code) != 1 {
		t.Fatalf("want one block, got %d", len(f.Code))
	}
	b := f.Code[0]
	lo := (off - 64) &^ 15
	hi := (urlEnd + 64 + 15) &^ 15
	if b.Kind != report.CodeKindHex || b.Offset != lo || len(b.Lines) != int((hi-lo)/16) {
		t.Fatalf("block starts at %#x with %d lines (kind %s), want %#x and %d", b.Offset, len(b.Lines), b.Kind, lo, (hi-lo)/16)
	}
	for i, l := range b.Lines {
		at := lo + int64(i)*16
		chunk := data[at : at+16]
		wantHit := at < urlEnd && at+16 > off
		if l.Offset != at || l.Bytes != spacedHex(chunk) || l.Text != asciiColumn(chunk) || l.Highlight != wantHit {
			t.Errorf("line %d = %+v\nwant offset %#x bytes %q text %q highlight %v", i, l, at, spacedHex(chunk), asciiColumn(chunk), wantHit)
		}
	}
	if want := fmt.Sprintf("Bytes around the URL at file offset 0x%x", off); b.Title != want {
		t.Errorf("title = %q, want %q", b.Title, want)
	}
	if b.Section != ".cfg" || b.File != "" || b.Truncated || len(b.Limitations) != 1 {
		t.Errorf("section %q file %q truncated %v limitations %v", b.Section, b.File, b.Truncated, b.Limitations)
	}
}

// TestHexWindowAtTheStartOfTheFile: a string near offset 0 cannot have a window
// that starts before the file, and the first row is then the first 16 bytes.
func TestHexWindowIsClampedToTheFile(t *testing.T) {
	url := "https://start.example.test/x"
	data := slices.Concat([]byte(url), make([]byte, 30))
	rep := analyse(t, "tiny.bin", data)
	b := findingByID(t, rep, "indicators.network").Code[0]
	if b.Offset != 0 || b.Lines[0].Offset != 0 || len(b.Lines) != 4 {
		t.Fatalf("offset %d, %d lines: %+v", b.Offset, len(b.Lines), b.Lines)
	}
	last := b.Lines[len(b.Lines)-1]
	if rest := len(data) - 48; last.Offset != 48 || len(strings.Fields(last.Bytes)) != rest || len(last.Text) != rest { // the file ends inside the last row
		t.Fatalf("last row = %+v, want %d bytes at 48", last, len(data)-48)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

// TestSecretsNeverAppearInAnyOutputOrWindow plants fake credentials of every
// kind, as ASCII and as UTF-16LE, next to a URL and a command line, and checks
// that neither the text, nor the bytes (in hex, whole or in part), nor the key
// material after a private-key header appears anywhere in the JSON, the terminal
// output (with every block and limitation), the Markdown or the HTML.
func TestSecretsNeverAppearInAnyOutputOrWindow(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("Zy9x", 9)
	ghWide := "ghp_" + strings.Repeat("Qw3r", 9)
	slack := "xoxb-" + "123456789012-" + "abcdefABCDEF1234"
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "c2lnbmF0dXJlLXNpZ25hdHVyZS1ieXRlcw"
	pemHeader := "-----BEGIN RSA PRIVATE" + " KEY-----"
	pemBody1 := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Zr5gTz1q"
	pemBody2 := "kT8vYw0aPzLmB3nQxR9sUeHfJdC2iVoKtNyXlGhAbWpZq4uEjM6rSc1DgIv"
	url := "https://c2.example.test/gate.php"
	cmd := "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

	blob := slices.Concat(make([]byte, 64),
		[]byte("token="+awsKey+";\x00"), []byte(url+"\x00"), []byte("auth: "+ghToken+"\x00"), []byte(slack+"\x00"),
		[]byte("\x00"), utf16le(ghWide), []byte("\x00\x00\x00"), []byte(jwt+"\x00"), []byte(cmd+"\x00"),
		[]byte("\n"+pemHeader+"\n"+pemBody1+"\n"+pemBody2+"\n-----END RSA PRIVATE KEY-----\n"), make([]byte, 64))
	data := peWithBlob(blob)
	rep := analyse(t, "plant.exe", data)
	assertCodeIsValid(t, rep)

	var outputs = map[string]string{}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	outputs["json"] = string(raw)
	for name, o := range map[string]render.Options{"text": {CodeAll: true, Verbose: true}, "text ascii": {CodeAll: true, Verbose: true, ASCII: true}, "text default": {}} {
		var sb strings.Builder
		if err := render.Text(&sb, rep, o); err != nil {
			t.Fatal(err)
		}
		outputs[name] = sb.String()
	}
	var md, page strings.Builder
	if err := render.Markdown(&md, rep); err != nil {
		t.Fatal(err)
	}
	if err := render.HTML(&page, rep); err != nil {
		t.Fatal(err)
	}
	outputs["markdown"], outputs["html"] = md.String(), page.String()
	var codeOnly []report.CodeBlock
	for _, f := range rep.Findings {
		codeOnly = append(codeOnly, f.Code...)
	}
	codeRaw, err := json.Marshal(codeOnly)
	if err != nil {
		t.Fatal(err)
	}

	// The lines behind a private-key header are not a pattern the scanner knows, so they
	// are listed as plain strings in the strings section of the report; what this pass
	// adds (the code blocks) must still never show them.
	type secret struct {
		name     string
		raw      []byte
		codeOnly bool
	}
	secrets := []secret{
		{"aws key", []byte(awsKey), false}, {"github token", []byte(ghToken), false}, {"slack token", []byte(slack), false}, {"jwt", []byte(jwt), false},
		{"pem header", []byte(pemHeader), false}, {"pem body 1", []byte(pemBody1), true}, {"pem body 2", []byte(pemBody2), true},
		{"utf-16 github token", utf16le(ghWide), false}, {"utf-16 github token as text", []byte(ghWide), false},
	}
	for _, s := range secrets {
		forms := map[string]string{
			"plaintext":          string(s.raw),
			"hex":                hex.EncodeToString(s.raw),
			"spaced hex":         spacedHex(s.raw),
			"first bytes (hex)":  spacedHex(s.raw[:min(8, len(s.raw))]),
			"last bytes (hex)":   spacedHex(s.raw[max(0, len(s.raw)-8):]),
			"middle bytes (hex)": spacedHex(s.raw[len(s.raw)/2-4 : len(s.raw)/2+4]),
		}
		scope := outputs
		if s.codeOnly {
			scope = map[string]string{"code blocks": string(codeRaw)}
		}
		for outName, out := range scope {
			for form, needle := range forms {
				if strings.Contains(out, needle) {
					t.Errorf("%s: the %s appears in the %s output", s.name, form, outName)
				}
			}
			// The first characters may stay in the redacted form that every output carries,
			// but nothing longer than that may.
			if len(s.raw) >= 12 && strings.Contains(out, string(s.raw[:12])) {
				t.Errorf("%s: twelve characters of the %s appear in the %s output", s.name, s.name, outName)
			}
		}
	}

	// The windows of secret findings exist, are marked as masked, and show the mask byte
	// at every position of every secret in the file.
	for _, id := range []string{"secrets.aws-access-key-id", "secrets.github-token", "secrets.slack-token", "secrets.jwt", "secrets.pem-private-key"} {
		f := findingByID(t, rep, id)
		if len(f.Code) == 0 || !strings.Contains(f.Code[0].Title, " masked)") {
			t.Fatalf("%s: want a masked window, got %+v", id, f.Code)
		}
		if !slices.ContainsFunc(f.Code[0].Limitations, func(l string) bool { return strings.Contains(l, "replaced by 2a") }) {
			t.Errorf("%s: the block must say that values are masked: %v", id, f.Code[0].Limitations)
		}
	}
	covered := map[int64]report.CodeLine{}
	for _, f := range rep.Findings {
		for _, b := range f.Code {
			for _, l := range b.Lines {
				for i := int64(0); i < int64(len(strings.Fields(l.Bytes))); i++ {
					covered[l.Offset+i] = l
				}
			}
		}
	}
	for _, s := range secrets[:4] {
		start := int64(bytes.Index(data, s.raw))
		for i := range int64(len(s.raw)) {
			l, ok := covered[start+i]
			if !ok {
				continue // not every byte of every secret lies in a window of some finding
			}
			col := start + i - l.Offset
			if got := strings.Fields(l.Bytes)[col]; got != "2a" || l.Text[col] != '*' {
				t.Fatalf("%s: byte %d at %#x shows %s / %q, want 2a / '*'", s.name, i, start+i, got, l.Text[col])
			}
		}
	}
	if len(covered) == 0 {
		t.Fatal("no window was built at all")
	}

	// Non-secret strings stay readable next to the masked ones.
	net := findingByID(t, rep, "indicators.network")
	if len(net.Code) == 0 || !slices.ContainsFunc(net.Code[0].Lines, func(l report.CodeLine) bool { return strings.Contains(l.Text, "gate.php") }) {
		t.Errorf("the URL must stay readable in its window: %+v", net.Code)
	}
}

// TestSecretWindowsDoNotRevealTheRestOfAKey: the bytes after a private-key
// header are masked up to the end of the region read, so a short window right
// after the header shows no key material even though it matches no pattern.
func TestWindowAfterAPrivateKeyHeaderShowsNoKeyMaterial(t *testing.T) {
	pemHeader := "-----BEGIN RSA PRIVATE" + " KEY-----"
	body := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", 3)
	blob := slices.Concat(make([]byte, 80), []byte("\n"+pemHeader+"\n"+body+"\n-----END RSA PRIVATE KEY-----\n"), []byte("https://after.example.test/x\x00"), make([]byte, 40))
	data := peWithBlob(blob)
	rep := analyse(t, "key.exe", data)
	assertCodeIsValid(t, rep)
	for _, f := range rep.Findings {
		for _, b := range f.Code {
			for _, l := range b.Lines {
				if strings.Contains(l.Text, "QUJDREVG") || strings.Contains(l.Bytes, spacedHex([]byte("QUJDREVG"))) {
					t.Fatalf("%s: key material in %+v", f.ID, l)
				}
			}
		}
	}
}

func jsLines(n int, flagAt map[int]string) string {
	var sb strings.Builder
	for i := 1; i <= n; i++ {
		if text, ok := flagAt[i]; ok {
			sb.WriteString(text)
		} else {
			fmt.Fprintf(&sb, "// filler line %d", i)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

type excerpt struct {
	file       string
	first      int
	last       int
	highlights []int
}

func assertExcerpt(t *testing.T, data []byte, b report.CodeBlock, want excerpt) {
	t.Helper()
	if b.Kind != report.CodeKindSource || b.File != want.file {
		t.Fatalf("block kind %q file %q, want a source block of %q", b.Kind, b.File, want.file)
	}
	if len(b.Lines) != want.last-want.first+1 || b.Lines[0].Line != want.first || b.Lines[len(b.Lines)-1].Line != want.last {
		t.Fatalf("%s: lines %d..%d (%d lines), want %d..%d", want.file, b.Lines[0].Line, b.Lines[len(b.Lines)-1].Line, len(b.Lines), want.first, want.last)
	}
	var hits []int
	for i, l := range b.Lines {
		if l.Line != want.first+i {
			t.Errorf("%s: line %d is numbered %d", want.file, i, l.Line)
		}
		if l.Highlight {
			hits = append(hits, l.Line)
		}
		// A line that was not clipped is found as it is shown at its offset in the file.
		if !strings.Contains(l.Text, "…") && !bytes.HasPrefix(data[l.Offset:], []byte(l.Text)) {
			t.Errorf("%s: line %d is not at offset %#x: %q", want.file, l.Line, l.Offset, l.Text)
		}
	}
	if !slices.Equal(hits, want.highlights) {
		t.Errorf("%s: highlighted lines %v, want %v", want.file, hits, want.highlights)
	}
	if b.Offset != b.Lines[0].Offset {
		t.Errorf("%s: block offset %#x, first line at %#x", want.file, b.Offset, b.Lines[0].Offset)
	}
}

func TestAsarScriptFindingShowsTheLinesBehindIt(t *testing.T) {
	mainJS := jsLines(20, map[int]string{10: "  webPreferences: { nodeIntegration: true },"})
	winJS := strings.ReplaceAll(jsLines(8, map[int]string{2: "  new BrowserWindow({ webPreferences: { webSecurity: false } });"}), "\n", "\r\n")
	lastJS := strings.TrimSuffix(jsLines(6, map[int]string{6: "  const cp = require('child_process');"}), "\n")
	minJS := strings.Repeat("a=1;", 400) + "x={webPreferences:{contextIsolation:!1}};" + strings.Repeat("b=2;", 400)
	data := testfixtures.Asar(
		testfixtures.AsarFile{Path: "package.json", Data: []byte(`{"name":"demo","version":"1.0.0","main":"src/main.js"}`)},
		testfixtures.AsarFile{Path: "src/main.js", Data: []byte(mainJS)},
		testfixtures.AsarFile{Path: "src/win.js", Data: []byte(winJS)},
		testfixtures.AsarFile{Path: "src/last.js", Data: []byte(lastJS)},
		testfixtures.AsarFile{Path: "src/min.js", Data: []byte(minJS)},
		testfixtures.AsarFile{Path: "node_modules/dep/index.js", Data: []byte("nodeIntegration: true\n")},
	)
	rep := analyse(t, "app.asar", data)
	assertCodeIsValid(t, rep)
	f := findingByID(t, rep, "application.electron-risky-settings")
	byFile := map[string]report.CodeBlock{}
	for _, b := range f.Code {
		byFile[b.File] = b
	}
	if len(f.Code) != 4 || byFile["node_modules/dep/index.js"].Kind != "" {
		t.Fatalf("want one block for each of the four application scripts and none for third-party code, got %d: %v", len(f.Code), slices.Collect(func(yield func(string) bool) {
			for _, b := range f.Code {
				if !yield(b.File) {
					return
				}
			}
		}))
	}

	assertExcerpt(t, data, byFile["src/main.js"], excerpt{file: "src/main.js", first: 7, last: 13, highlights: []int{10}})
	assertExcerpt(t, data, byFile["src/win.js"], excerpt{file: "src/win.js", first: 1, last: 5, highlights: []int{2}})
	assertExcerpt(t, data, byFile["src/last.js"], excerpt{file: "src/last.js", first: 3, last: 6, highlights: []int{6}})

	win := byFile["src/win.js"]
	for _, l := range win.Lines {
		if strings.Contains(l.Text, "\r") {
			t.Errorf("a CRLF line keeps its carriage return: %q", l.Text)
		}
	}
	if win.Lines[1].Text != "  new BrowserWindow({ webPreferences: { webSecurity: false } });" {
		t.Errorf("CRLF line text = %q", win.Lines[1].Text)
	}
	if last := byFile["src/last.js"].Lines[3]; last.Text != "  const cp = require('child_process');" {
		t.Errorf("the last line of a file without a final newline = %q", last.Text)
	}

	min := byFile["src/min.js"]
	if len(min.Lines) != 1 || !min.Truncated || !min.Lines[0].Highlight || min.Lines[0].Line != 1 {
		t.Fatalf("a minified single line: %+v", min)
	}
	text := min.Lines[0].Text
	if utf8.RuneCountInString(text) != report.MaxCodeLineChars || !strings.Contains(text, "contextIsolation:!1") || !strings.HasPrefix(text, "…") || !strings.HasSuffix(text, "…") {
		t.Errorf("the line must be cut around the match and say so: %q", text)
	}
	if !slices.ContainsFunc(min.Limitations, func(l string) bool { return strings.Contains(l, "cut around the match") }) {
		t.Errorf("a clipped block must say so: %v", min.Limitations)
	}
	if want := "Source lines for context-isolation-disabled"; min.Title != want {
		t.Errorf("title = %q, want %q", min.Title, want)
	}
	for _, b := range f.Code {
		if !slices.ContainsFunc(b.Limitations, func(l string) bool { return strings.Contains(l, "nothing was extracted") }) {
			t.Errorf("%s: limitations = %v", b.File, b.Limitations)
		}
	}
}

func TestAsarHintsInOneFileShareOneBlock(t *testing.T) {
	data := testfixtures.AsarElectronApp()
	rep := analyse(t, "app.asar", data)
	assertCodeIsValid(t, rep)
	f := findingByID(t, rep, "application.electron-risky-settings")
	if len(f.Code) != 1 {
		t.Fatalf("seven hints in one script must share one block, got %d", len(f.Code))
	}
	b := f.Code[0]
	var hits []string
	for _, l := range b.Lines {
		if l.Highlight {
			hits = append(hits, strings.TrimSpace(l.Text))
		}
	}
	want := []string{"const cp = require('child_process');", "nodeIntegration: true,", "contextIsolation: false,", "webSecurity: false,", "enableRemoteModule: true,", "allowRunningInsecureContent: true,", "sandbox: false,"}
	if !slices.Equal(hits, want) {
		t.Fatalf("highlighted lines:\n got %q\nwant %q", hits, want)
	}
	if b.Lines[0].Line != 1 || b.File != "main.js" || !strings.HasSuffix(b.Title, "and 4 more") {
		t.Errorf("first line %d, file %q, title %q", b.Lines[0].Line, b.File, b.Title)
	}
}

func TestStoredScriptInAZipShowsItsLines(t *testing.T) {
	script := strings.Join([]string{
		"#!/bin/sh", "# updater", "set -e", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
		`echo "done"`, "https://update.example.test/gate.php", "exit 0",
	}, "\n")
	blobEntry := slices.Concat(make([]byte, 100), []byte("https://beacon.example.test/in-a-binary-entry"), make([]byte, 100))
	data := testfixtures.Zip(
		testfixtures.ZipEntry{Name: "bin/update.sh", Data: []byte(script), Store: true},
		testfixtures.ZipEntry{Name: "bin/tool.dat", Data: blobEntry, Store: true},
		testfixtures.ZipEntry{Name: "docs/readme.txt", Data: bytes.Repeat([]byte("plain words "), 100)},
	)
	rep := analyse(t, "bundle.zip", data)
	assertCodeIsValid(t, rep)

	cmd := findingByID(t, rep, "indicators.suspicious-commands")
	if len(cmd.Code) != 1 {
		t.Fatalf("commands: %d blocks", len(cmd.Code))
	}
	assertExcerpt(t, data, cmd.Code[0], excerpt{file: "bin/update.sh", first: 1, last: 7, highlights: []int{4}})
	if want := "Source lines around the command line at line 4"; cmd.Code[0].Title != want {
		t.Errorf("title = %q, want %q", cmd.Code[0].Title, want)
	}

	net := findingByID(t, rep, "indicators.network")
	byFile := map[string]report.CodeBlock{}
	for _, b := range net.Code {
		byFile[b.File] = b
	}
	assertExcerpt(t, data, byFile["bin/update.sh"], excerpt{file: "bin/update.sh", first: 3, last: 7, highlights: []int{6}})
	hexBlock, ok := byFile["bin/tool.dat"]
	if !ok || hexBlock.Kind != report.CodeKindHex || hexBlock.Section != "" || !slices.ContainsFunc(hexBlock.Lines, func(l report.CodeLine) bool { return l.Highlight }) {
		t.Fatalf("a stored entry that is not text gets a hex window labelled with its name: %+v", hexBlock)
	}
	for _, l := range hexBlock.Lines {
		if l.Offset < int64(bytes.Index(data, blobEntry)) || l.Offset+int64(len(strings.Fields(l.Bytes))) > int64(bytes.Index(data, blobEntry)+len(blobEntry)) {
			t.Errorf("the window of an entry stays inside the entry: %+v", l)
		}
	}
}

func TestStandaloneScriptShowsItsLines(t *testing.T) {
	script := "#!/bin/sh\n# updater\nset -e\npowershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\necho \"done\"\nhttps://update.example.test/gate.php\nexit 0"
	data := []byte(script)
	rep := analyse(t, "update.sh", data)
	assertCodeIsValid(t, rep)
	if rep.Type.Family != report.FamilyScript {
		t.Fatalf("type = %+v", rep.Type)
	}
	assertExcerpt(t, data, findingByID(t, rep, "indicators.suspicious-commands").Code[0], excerpt{first: 1, last: 7, highlights: []int{4}})
	assertExcerpt(t, data, findingByID(t, rep, "indicators.network").Code[0], excerpt{first: 3, last: 7, highlights: []int{6}})
}

func TestSecretsInScriptsAreRedactedInTheShownLines(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("Zy9x", 9)
	pemHeader := "-----BEGIN RSA PRIVATE" + " KEY-----"
	script := strings.Join([]string{
		"#!/bin/sh", "export AWS_KEY=" + awsKey, "export TOKEN='" + ghToken + "' # deploy",
		`KEY="` + pemHeader + `\nZZZZsingleLineKeyMaterial0123456789\n-----END RSA PRIVATE KEY-----"`,
		pemHeader, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", "-----END RSA PRIVATE KEY-----", "echo ok",
	}, "\n")
	data := []byte(script)
	rep := analyse(t, "deploy.sh", data)
	assertCodeIsValid(t, rep)
	raw, _ := json.Marshal(rep)
	for _, secret := range []string{awsKey, ghToken, "ZZZZsingleLine"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("the report contains %q:\n%s", secret, raw)
		}
	}
	// The lines of a multi-line key are listed as strings by the scanner, but the excerpts hide them.
	for _, f := range rep.Findings {
		code, _ := json.Marshal(f.Code)
		if bytes.Contains(code, []byte("MIIEvQ")) {
			t.Fatalf("%s: key material in the excerpts: %s", f.ID, code)
		}
	}
	f := findingByID(t, rep, "secrets.aws-access-key-id")
	var shown []string
	for _, l := range f.Code[0].Lines {
		shown = append(shown, l.Text)
	}
	if !slices.Contains(shown, "export AWS_KEY=AKIA…(20 chars)") || f.Code[0].Kind != report.CodeKindSource {
		t.Fatalf("the shown lines = %q", shown)
	}
	if !slices.ContainsFunc(f.Code[0].Limitations, func(l string) bool { return strings.Contains(l, "redacted") }) {
		t.Errorf("limitations = %v", f.Code[0].Limitations)
	}
}

func TestCapsAreEnforced(t *testing.T) {
	t.Run("hex blocks per finding", func(t *testing.T) {
		var blob []byte
		for i := range 12 {
			blob = append(blob, make([]byte, 600)...)
			blob = append(blob, fmt.Sprintf("https://host%02d.example.test/path\x00", i)...)
		}
		rep := analyse(t, "many.exe", peWithBlob(blob))
		assertCodeIsValid(t, rep)
		f := findingByID(t, rep, "indicators.network")
		if len(f.Code) != 3 {
			t.Fatalf("a finding gets at most 3 hex blocks (and 12 strings far apart need more), got %d", len(f.Code))
		}
		for _, b := range f.Code {
			if len(b.Lines) > 64 {
				t.Errorf("%d lines in a block", len(b.Lines))
			}
		}
	})
	t.Run("a long run of strings is bounded to 64 rows", func(t *testing.T) {
		var blob []byte
		for i := range 40 {
			blob = append(blob, fmt.Sprintf("https://host%02d.example.test/%s\x00", i, strings.Repeat("p", 20))...)
		}
		rep := analyse(t, "dense.exe", peWithBlob(blob))
		assertCodeIsValid(t, rep)
		for _, b := range findingByID(t, rep, "indicators.network").Code {
			if len(b.Lines) > 64 {
				t.Errorf("%d lines in a block", len(b.Lines))
			}
		}
	})
	t.Run("source blocks per finding", func(t *testing.T) {
		var files []testfixtures.AsarFile
		for i := range 20 {
			files = append(files, testfixtures.AsarFile{Path: fmt.Sprintf("src/s%02d.js", i), Data: []byte("x = 1;\nnodeIntegration: true\n")})
		}
		rep := analyse(t, "many.asar", testfixtures.Asar(files...))
		assertCodeIsValid(t, rep)
		f := findingByID(t, rep, "application.electron-risky-settings")
		if len(f.Code) != 6 {
			t.Fatalf("a finding gets at most 6 source blocks, got %d", len(f.Code))
		}
	})
	t.Run("a very long line", func(t *testing.T) {
		long := "console.log('" + strings.Repeat("x", 5000) + "'); nodeIntegration: true // " + strings.Repeat("y", 5000)
		rep := analyse(t, "long.asar", testfixtures.Asar(testfixtures.AsarFile{Path: "main.js", Data: []byte(long)}))
		assertCodeIsValid(t, rep)
		b := findingByID(t, rep, "application.electron-risky-settings").Code[0]
		if utf8.RuneCountInString(b.Lines[0].Text) > report.MaxCodeLineChars || !b.Truncated || !strings.Contains(b.Lines[0].Text, "nodeIntegration: true") {
			t.Errorf("line = %q truncated %v", b.Lines[0].Text, b.Truncated)
		}
	})
}

func TestSourceBlocksKeepTheirLineNumbersFarIntoAFile(t *testing.T) {
	// 5000 lines in, so the numbering depends on counting every newline before the match.
	body := strings.Repeat("var padding = 0;\n", 5000) + "app.commandLine.appendSwitch('--no-sandbox');\n" + strings.Repeat("// tail\n", 10)
	data := testfixtures.Asar(testfixtures.AsarFile{Path: "boot.js", Data: []byte(body)})
	b := findingByID(t, analyse(t, "big.asar", data), "application.electron-risky-settings").Code[0]
	if b.Lines[0].Line != 4998 || len(b.Lines) != 7 || !b.Lines[3].Highlight || b.Lines[3].Line != 5001 || !strings.Contains(b.Lines[3].Text, "--no-sandbox") {
		t.Fatalf("lines = %+v", b.Lines)
	}
}

// hostileScripts are entries meant to break whatever shows them.
func hostileScripts() map[string]string {
	return map[string]string{
		"control characters": "x = 1;\x00\x01\x02\x07\x1b[31m\x7f nodeIntegration: true \x1b]0;title\x07\ny = 2;\n",
		"bidi and invisible": "// " + string(rune(0x202e)) + "elif" + string(rune(0x2066)) + string(rune(0x200b)) + string(rune(0xfeff)) + "\nnodeIntegration: true // " + string(rune(0x2028)) + string(rune(0x2029)) + "\n",
		"invalid utf-8":      "caf\xe9 \xff\xfe nodeIntegration: true \xc3\x28\n",
		"nul bytes":          "MZ\x00\x00\x00\x00nodeIntegration: true\x00\x00\x00\x00binary masquerading as a script\n",
		"huge line":          strings.Repeat("a", 3<<20) + "nodeIntegration: true" + strings.Repeat("b", 1<<20),
		"many newlines":      "nodeIntegration: true" + strings.Repeat("\n", 2<<20),
		"carriage returns":   "line one\rnodeIntegration: true\rline three\r\n",
		"tabs":               "\t\t\t\tnodeIntegration: true\t\t\t\n",
		"utf-16":             string(utf16le("nodeIntegration: true\nsecond line\n")),
		"unterminated pem":   "-----BEGIN RSA PRIVATE" + " KEY-----\n" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\n", 50) + "nodeIntegration: true\n",
	}
}

func TestHostileScriptsCannotBreakTheEvidence(t *testing.T) {
	for name, content := range hostileScripts() {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			rep := analyse(t, "h.asar", testfixtures.Asar(testfixtures.AsarFile{Path: "dir/h.js", Data: []byte(content)}))
			if time.Since(start) > 15*time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
			assertCodeIsValid(t, rep)
			for _, f := range rep.Findings {
				if f.ID == "parser.error" || f.ID == "analysis.incomplete" {
					t.Fatalf("hostile content must not break the analysis: %+v", f)
				}
				for _, b := range f.Code {
					for _, l := range b.Lines {
						for _, r := range l.Text + l.Note + b.Title + b.File {
							if r < 0x20 || (r >= 0x7f && r < 0xa0) || r == 0x202e || r == 0x2066 || r == 0x200b || r == 0xfeff || r == 0x2028 || r == 0x2029 {
								t.Fatalf("%s: %U in %q", f.ID, r, l.Text)
							}
						}
					}
				}
			}
			// The scanner lists the lines of a key as strings; the code blocks must not show them.
			for _, f := range rep.Findings {
				if code, _ := json.Marshal(f.Code); bytes.Contains(code, []byte("QUJDREVG")) {
					t.Fatalf("%s: key material in the code blocks: %s", f.ID, code)
				}
			}
		})
	}
}

// TestEvidenceNeverPanicsOnDamagedContainers cuts and corrupts archives and
// executables that carry strings and scripts: whatever the damage, the pass
// must not panic (a panic would show up as a parser.error finding) and every
// block it makes must be valid.
func TestEvidenceNeverPanicsOnDamagedContainers(t *testing.T) {
	script := "#!/bin/sh\npowershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\nhttps://update.example.test/gate.php\n"
	inputs := map[string][]byte{
		"asar": testfixtures.Asar(
			testfixtures.AsarFile{Path: "package.json", Data: []byte(`{"name":"d","main":"m.js"}`)},
			testfixtures.AsarFile{Path: "m.js", Data: []byte("nodeIntegration: true\nhttps://update.example.test/gate.php\n" + "AKIA" + "IOSFODNN7EXAMPLE\n")},
		),
		"zip": testfixtures.Zip(testfixtures.ZipEntry{Name: "a.sh", Data: []byte(script), Store: true}, testfixtures.ZipEntry{Name: "b.bin", Data: []byte("https://b.example.test/x\x00\x00\x00"), Store: true}),
		"pe":  peWithBlob([]byte("https://c.example.test/x\x00" + "AKIA" + "IOSFODNN7EXAMPLE\x00powershell -nop -w hidden -enc AAAA\x00")),
		"sh":  []byte(script),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			check := func(b []byte) {
				rep := analyse(t, "d.bin", b)
				assertCodeIsValid(t, rep)
				for _, f := range rep.Findings {
					if f.ID == "parser.error" && strings.Contains(strings.Join(f.Evidence, " "), "internal error") {
						t.Fatalf("a stage panicked on %d bytes: %+v", len(b), f)
					}
				}
			}
			for n := 0; n <= len(input); n += max(1, len(input)/200) {
				check(input[:n])
			}
			for i := 0; i < len(input); i += max(1, len(input)/120) {
				for _, v := range []byte{0x00, 0xFF, 0x20, '\n'} {
					m := bytes.Clone(input)
					m[i] = v
					check(m)
				}
			}
		})
	}
}

func FuzzEvidence(f *testing.F) {
	script := []byte("#!/bin/sh\npowershell -nop -w hidden -enc SQBFAFgA\nhttps://update.example.test/gate.php\nAKIA" + "IOSFODNN7EXAMPLE\n")
	for _, s := range [][]byte{
		script, testfixtures.AsarElectronApp(), testfixtures.Zip(testfixtures.ZipEntry{Name: "a.sh", Data: script, Store: true}),
		peWithBlob(script), testfixtures.Asar(testfixtures.AsarFile{Path: "x.js", Data: script}),
	} {
		f.Add(s)
		f.Add(s[:len(s)/2])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<18 {
			t.Skip("keep fuzz inputs small")
		}
		rep := analyse(t, "fuzz.bin", data)
		assertCodeIsValid(t, rep)
		for _, fd := range rep.Findings {
			if fd.ID == "parser.error" && strings.Contains(strings.Join(fd.Evidence, " "), "internal error") {
				t.Fatalf("a stage panicked: %+v", fd)
			}
		}
	})
}
