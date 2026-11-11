package sniff

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

const (
	// textSample is how much of the file the text heuristic looks at.
	textSample = 8 << 10
	// maxShebang bounds the length of a "#!" line.
	maxShebang = 512
)

// scriptLang describes a scripting language recognised from a shebang.
type scriptLang struct {
	name string // shown in the label, e.g. "Python"
	mime string
}

// interpreterLang maps an interpreter (the base name without a version suffix)
// to the key of its language in languages.
var interpreterLang = map[string]string{
	"sh": "shell", "bash": "shell", "dash": "shell", "zsh": "shell", "ash": "shell", "ksh": "shell",
	"mksh": "shell", "csh": "shell", "tcsh": "shell", "fish": "shell", "busybox": "shell",
	"python": "python", "pypy": "python",
	"node": "node", "nodejs": "node",
	"deno": "deno", "bun": "bun",
	"perl": "perl", "ruby": "ruby", "php": "php",
	"pwsh": "powershell", "powershell": "powershell",
	"lua": "lua", "luajit": "lua",
	"awk": "awk", "gawk": "awk", "mawk": "awk", "nawk": "awk",
	"osascript": "applescript", "tclsh": "tcl", "wish": "tcl", "expect": "expect",
	"groovy": "groovy", "rscript": "r", "julia": "julia", "escript": "erlang", "sed": "sed",
}

var languages = map[string]scriptLang{
	"shell":       {"Shell", "text/x-shellscript"},
	"python":      {"Python", "text/x-python"},
	"node":        {"Node.js", "text/javascript"},
	"deno":        {"Deno", "text/javascript"},
	"bun":         {"Bun", "text/javascript"},
	"perl":        {"Perl", "text/x-perl"},
	"ruby":        {"Ruby", "text/x-ruby"},
	"php":         {"PHP", "text/x-php"},
	"powershell":  {"PowerShell", "application/x-powershell"},
	"lua":         {"Lua", "text/x-lua"},
	"awk":         {"AWK", "text/x-awk"},
	"applescript": {"AppleScript", "text/plain"},
	"tcl":         {"Tcl", "text/x-tcl"},
	"expect":      {"Expect", "text/plain"},
	"groovy":      {"Groovy", "text/x-groovy"},
	"r":           {"R", "text/x-r"},
	"julia":       {"Julia", "text/x-julia"},
	"erlang":      {"Erlang", "text/plain"},
	"sed":         {"sed", "text/plain"},
}

// detectScript recognises scripts that start with a "#!" interpreter line.
func detectScript(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 3 || h[0] != '#' || h[1] != '!' {
		return report.Type{}, false
	}
	window := h[2:min(len(h), 2+maxShebang)]
	end := bytes.IndexByte(window, '\n')
	if end < 0 {
		if int64(len(h)) < p.size || len(window) >= maxShebang {
			return report.Type{}, false // no end of line where one must be
		}
		end = len(window)
	}
	line := strings.TrimSpace(string(window[:end]))
	if line == "" || !isPrintableASCII(line) {
		return report.Type{}, false
	}

	interpreter, base := shebangInterpreter(line)
	key, known := interpreterLang[strings.TrimRight(base, "0123456789.")]
	if !known {
		key, known = interpreterLang[base]
	}
	lang, tag := scriptLang{name: "", mime: "text/plain"}, base
	label := "Script (" + binio.Printable(interpreter, 80) + ")"
	if known {
		lang, tag = languages[key], key
		label = lang.name + " script (" + binio.Printable(interpreter, 80) + ")"
	}
	if !isSafeTag(tag) {
		tag = "script"
	}
	// A script is text; a "#!" line in front of binary data (self-extracting
	// archives, for example) is still a script but less certain.
	_, isText := classifyText(h[:min(len(h), textSample)], int64(len(h)) < p.size)
	return newType(report.TypeScript, report.FamilyScript, label, lang.mime, confidenceIf(isText), tag), true
}

// shebangInterpreter extracts the interpreter path and its base name (lower
// case) from the text after "#!", looking through "env" and its options.
func shebangInterpreter(line string) (path, base string) {
	fields := strings.Fields(line)
	path = fields[0]
	base = baseName(path)
	if base == "env" {
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			path, base = f, baseName(f)
			break
		}
	}
	return path, strings.ToLower(base)
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// isSafeTag reports whether s can be used verbatim as a tag.
func isSafeTag(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}

// detectText recognises plain text in the first 8 KiB.
func detectText(p *probe) (report.Type, bool) {
	sample := p.head[:min(len(p.head), textSample)]
	enc, ok := classifyText(sample, int64(len(sample)) < p.size)
	if !ok {
		return report.Type{}, false
	}
	label := map[string]string{
		"ascii": "ASCII text", "utf-8": "UTF-8 text", "utf-16le": "UTF-16LE text",
		"utf-16be": "UTF-16BE text", "8-bit": "8-bit text (unknown encoding)",
	}[enc]
	return newType(report.TypeText, report.FamilyText, label, "text/plain", report.ConfidenceLow, enc), true
}

// classifyText decides whether sample looks like text and names its encoding:
// "ascii", "utf-8", "utf-16le", "utf-16be" or "8-bit". prefix tells it that the
// sample is only the beginning of a longer file, so a multi-byte character may
// be cut at the end.
func classifyText(sample []byte, prefix bool) (string, bool) {
	if len(sample) == 0 {
		return "", false
	}
	switch {
	case bytes.HasPrefix(sample, []byte{0xef, 0xbb, 0xbf}):
		rest := sample[3:]
		if _, ok := classifyUTF8(rest, prefix); !ok && len(rest) > 0 {
			return "", false
		}
		return "utf-8", true
	case bytes.HasPrefix(sample, []byte{0xff, 0xfe}) && !bytes.HasPrefix(sample, []byte{0xff, 0xfe, 0, 0}):
		return "utf-16le", looksLikeUTF16(sample[2:], binary.LittleEndian)
	case bytes.HasPrefix(sample, []byte{0xfe, 0xff}):
		return "utf-16be", looksLikeUTF16(sample[2:], binary.BigEndian)
	}
	return classifyUTF8(sample, prefix)
}

// classifyUTF8 handles BOM-less 8-bit text: ASCII, UTF-8 or a legacy 8-bit encoding.
func classifyUTF8(s []byte, prefix bool) (string, bool) {
	if len(s) == 0 || bytes.IndexByte(s, 0) >= 0 {
		return "", false
	}
	bad := 0
	for _, c := range s {
		if (c < 0x20 && !isTextControl(c)) || c == 0x7f {
			bad++
		}
	}
	if bad > len(s)/100 {
		return "", false
	}
	trimmed := s
	if prefix {
		// A prefix may end in the middle of a multi-byte character.
		for i := 0; i < utf8.UTFMax-1 && len(trimmed) > 0 && !utf8.Valid(trimmed); i++ {
			trimmed = trimmed[:len(trimmed)-1]
		}
	}
	if utf8.Valid(trimmed) {
		for _, c := range trimmed {
			if c >= 0x80 {
				return "utf-8", true
			}
		}
		return "ascii", true
	}
	// Not UTF-8: accept legacy 8-bit text only when nearly everything is plain ASCII.
	ascii := 0
	for _, c := range s {
		if (c >= 0x20 && c <= 0x7e) || isTextControl(c) {
			ascii++
		}
	}
	if ascii*10 >= len(s)*9 {
		return "8-bit", true
	}
	return "", false
}

// isTextControl reports whether c is a control character found in ordinary
// text: tab, newline, carriage return, vertical tab, form feed, backspace, escape.
func isTextControl(c byte) bool {
	switch c {
	case '\t', '\n', '\r', '\v', '\f', '\b', 0x1b:
		return true
	}
	return false
}

// looksLikeUTF16 checks that the code units after a byte-order mark are
// plausible text: no NULs, no stray control characters, paired surrogates.
func looksLikeUTF16(b []byte, order binary.ByteOrder) bool {
	units := len(b) / 2
	bad := 0
	for i := 0; i < units; i++ {
		u := order.Uint16(b[2*i:])
		switch {
		case u == 0 || (u < 0x20 && !isTextControl(byte(u))):
			bad++
		case u >= 0xd800 && u < 0xdc00:
			if i+1 < units {
				if next := order.Uint16(b[2*(i+1):]); next >= 0xdc00 && next < 0xe000 {
					i++
					continue
				}
			}
			bad++
		case u >= 0xdc00 && u < 0xe000:
			bad++
		}
	}
	return bad <= units/100
}
