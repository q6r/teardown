package analyze

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/strs"
)

const (
	// maxSourceRead is the most bytes read from one entry to show its lines.
	// Line numbers count from the start of the entry, so a match further in than
	// this is shown as a hex window instead.
	maxSourceRead = 4 << 20
	// sourceContext is how many lines are shown before and after the matching ones.
	sourceContext = 3
	// maxMarkLines is how many lines of one match are highlighted: a pattern that
	// allows white space between its words can match across many lines.
	maxMarkLines = 8
	// tabWidth is the width of a tab stop when a line is shown.
	tabWidth = 4
)

var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
	newline  = []byte{'\n'}
)

// mark is a range of the file that a source excerpt points at: the text a hint
// pattern matched, or a string the scanner found.
type mark struct {
	start, end int64 // file offsets, end exclusive
	label      string
	hint       bool // a hint pattern matched this text, as opposed to a string of the scanner
	rank       int  // position among the things the finding is about
}

// memberText is the text of an entry as far as it was read.
type memberText struct {
	data    []byte
	partial bool   // the entry is longer than data
	ok      bool   // data looks like text
	bodies  []span // byte ranges of data that hold private-key material
}

// memberText reads an entry (once per cache) and decides whether it is text.
func (e *evidence) memberText(cache map[member]*memberText, m member) *memberText {
	if mt, ok := cache[m]; ok {
		return mt
	}
	mt := &memberText{}
	cache[m] = mt
	n := min(m.size, maxSourceRead, e.lim.MaxMeta)
	if n <= 0 || m.offset < 0 {
		return mt
	}
	data, err := binio.ReadAt(e.r, e.size, m.offset, n)
	if err != nil {
		return mt
	}
	mt.data, mt.partial = data, m.size > n
	if mt.ok = looksLikeText(data, mt.partial); mt.ok {
		mt.bodies = keyBodies(data)
	}
	return mt
}

// looksLikeText reports whether data is text a person could read: no NUL bytes,
// at most one byte in a hundred a control character outside the ones text uses,
// and either valid UTF-8 or almost entirely ASCII. UTF-16 text has NULs and is
// therefore shown as a hex window instead.
func looksLikeText(data []byte, partial bool) bool {
	if len(data) == 0 || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	sample := data
	if partial {
		// A prefix may end in the middle of a multi-byte character.
		for i := 0; i < utf8.UTFMax-1 && len(sample) > 0 && !utf8.Valid(sample); i++ {
			sample = sample[:len(sample)-1]
		}
	}
	bad, plain := 0, 0
	for _, c := range sample {
		switch {
		case c == 0x7f || (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' && c != 0x1b):
			bad++
		case c < 0x80:
			plain++
		}
	}
	if bad*100 > len(sample) {
		return false
	}
	return utf8.Valid(sample) || plain*10 >= len(sample)*9
}

// keyBodies returns the byte ranges of data that hold the body of a PEM private
// key: from the line after a private-key header up to the "-----END" marker (or
// the end of data). The key material is not matched by any pattern, so the lines
// that hold it are hidden by position.
func keyBodies(data []byte) []span {
	var out []span
	for pos := 0; pos < len(data); {
		i := bytes.Index(data[pos:], pemBegin)
		if i < 0 {
			break
		}
		i += pos
		lineStart := bytes.LastIndexByte(data[:i], '\n') + 1
		lineEnd := len(data)
		if j := bytes.IndexByte(data[i:], '\n'); j >= 0 {
			lineEnd = i + j
		}
		isKey := slices.ContainsFunc(strs.FindSecrets(string(data[lineStart:lineEnd])), func(s strs.SecretSpan) bool { return s.Kind == pemKind })
		if !isKey {
			pos = lineEnd + 1
			continue
		}
		bodyStart := min(lineEnd+1, len(data))
		bodyEnd := len(data)
		if j := bytes.Index(data[bodyStart:], pemEnd); j >= 0 {
			bodyEnd = bodyStart + j
		}
		out = append(out, span{lo: int64(bodyStart), hi: int64(bodyEnd)})
		pos = max(bodyEnd, lineEnd+1)
	}
	return out
}

// inBody reports whether the line that starts at pos lies in a hidden key body.
func inBody(bodies []span, pos int) bool {
	return slices.ContainsFunc(bodies, func(s span) bool { return int64(pos) >= s.lo && int64(pos) < s.hi })
}

// lineNumber returns the 1-based number of the line that holds byte pos of data.
func lineNumber(data []byte, pos int64) int64 {
	pos = min(max(pos, 0), int64(len(data)))
	return 1 + int64(bytes.Count(data[:pos], newline))
}

// lineStartPos returns the index of the first byte of the 1-based line.
func lineStartPos(data []byte, line int64) int {
	pos := 0
	for n := int64(1); n < line; n++ {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			return len(data)
		}
		pos += i + 1
	}
	return pos
}

// sourceBlocks builds the source excerpts for marks inside one text entry: the
// lines that hold a mark, highlighted, with three lines of context on each side.
// Excerpts that overlap are merged (at most 64 lines each) and at most budget are
// made. The lines come from the file as stored; nothing is extracted or run.
func (e *evidence) sourceBlocks(m member, mt *memberText, marks []mark, budget int) []blockAt {
	if budget <= 0 || len(marks) == 0 {
		return nil
	}
	data := mt.data
	spans := make([]span, len(marks))
	for i, k := range marks {
		lo := min(max(k.start-m.offset, 0), int64(len(data)))
		hi := min(max(k.end-m.offset, lo+1), int64(len(data)))
		first := lineNumber(data, lo)
		last := min(lineNumber(data, max(hi-1, lo)), first+maxMarkLines-1)
		spans[i] = span{lo: max(1, first-sourceContext), hi: last + sourceContext + 1}
	}
	var out []blockAt
	for _, g := range groupSpans(spans, report.MaxCodeLines, budget) {
		if e.ctx.Err() != nil {
			break
		}
		group := make([]mark, len(g.members))
		rank := marks[g.members[0]].rank
		for i, idx := range g.members {
			group[i] = marks[idx]
			rank = min(rank, marks[idx].rank)
		}
		if b, ok := sourceBlock(m, mt, g.win, group); ok {
			out = append(out, blockAt{rank: rank, block: b})
		}
	}
	return out
}

// sourceBlock lays out the lines of win (line numbers, end exclusive) of an entry.
func sourceBlock(m member, mt *memberText, win span, marks []mark) (report.CodeBlock, bool) {
	data := mt.data
	b := report.CodeBlock{Kind: report.CodeKindSource, File: labelText(m.name)}
	pos := lineStartPos(data, win.lo)
	clipped, redacted, reachedEnd := false, false, false
	firstHit := int64(0)
	for ln := win.lo; ln < win.hi && pos < len(data); ln++ {
		end := len(data)
		if i := bytes.IndexByte(data[pos:], '\n'); i >= 0 {
			end = pos + i
		}
		hit, hitLo := false, 0
		for _, k := range marks {
			ks, ke := k.start-m.offset, k.end-m.offset
			if ks < int64(end) && ke > int64(pos) {
				if !hit {
					hitLo = int(max(ks, int64(pos))) - pos
				}
				hit = true
			}
		}
		if hit && firstHit == 0 {
			firstHit = ln
		}
		r := renderLine(data[pos:end], hitLo, inBody(mt.bodies, pos))
		b.Lines = append(b.Lines, report.CodeLine{Offset: m.offset + int64(pos), Line: int(ln), Text: r.text, Highlight: hit})
		clipped, redacted = clipped || r.clipped, redacted || r.redacted
		if end == len(data) {
			reachedEnd = true
			break
		}
		pos = end + 1
	}
	if len(b.Lines) == 0 {
		return b, false
	}
	b.Offset = b.Lines[0].Offset
	b.Truncated = clipped || (reachedEnd && mt.partial)
	b.Title = sourceTitle(marks, max(firstHit, int64(b.Lines[0].Line)))
	b.Limitations = sourceLimitations(marks, clipped, redacted, reachedEnd && mt.partial)
	return b, true
}

// sourceTitle names an excerpt after what it points at.
func sourceTitle(marks []mark, line int64) string {
	labels := make([]string, len(marks))
	hints := true
	for i, k := range marks {
		labels[i] = k.label
		hints = hints && k.hint
	}
	switch {
	case hints:
		return clipRunes("Source lines for " + joinLabels(labels))
	case len(marks) == 1:
		return clipRunes(fmt.Sprintf("Source lines around the %s at line %d", labels[0], line))
	}
	return clipRunes(fmt.Sprintf("Source lines around %s, from line %d", describeStrings(labels), line))
}

// sourceLimitations states what an excerpt cannot show.
func sourceLimitations(marks []mark, clipped, redacted, partial bool) []string {
	out := []string{"Plain text lines read from the file as stored: nothing was extracted to disk, run or evaluated, and a text match does not prove what the code does."}
	if slices.ContainsFunc(marks, func(k mark) bool { return k.hint }) {
		out = append(out, "The setting names are matched as text: the code can be dead, commented out, guarded by a condition or overridden before a window opens.")
	} else {
		out = append(out, "A string in a script does not show that it is used: it can be dead code, a comment or a documentation example.")
	}
	if clipped {
		out = append(out, fmt.Sprintf("Lines longer than %d characters (minified code) are cut around the match with an ellipsis; the whole line is in the file.", report.MaxCodeLineChars))
	}
	if redacted {
		out = append(out, "Credential-like values are redacted as everywhere else in the report (the first characters and the length are kept) and the key material after a private-key header is hidden.")
	}
	if partial {
		out = append(out, fmt.Sprintf("Only the first %d MiB of this entry were read, so lines further on are not shown.", maxSourceRead>>20))
	}
	return out
}

// renderedLine is one line ready to be shown.
type renderedLine struct {
	text     string
	clipped  bool // the line was cut to the length cap
	redacted bool // a secret or key material was hidden in it
}

// renderLine turns the bytes of one line into text that is safe to show: secrets
// are redacted (the whole line first, so that a secret is never cut in the middle
// before it is looked for; a private-key header takes the rest of its line with
// it), control characters, invalid UTF-8 and invisible format characters are
// spelled out, tabs are expanded and a line longer than the cap is cut around
// hitLo, the byte at which the matching text starts. A line in the body of a
// private key is replaced by a note.
func renderLine(raw []byte, hitLo int, keyBody bool) renderedLine {
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	if keyBody {
		return renderedLine{text: fmt.Sprintf("(%d characters of private key material hidden)", utf8.RuneCount(raw)), redacted: true}
	}
	s := string(raw)
	hitLo = min(hitLo, len(s))
	shown, prefix, redacted := s, s[:hitLo], false
	if len(strs.FindSecrets(s)) > 0 {
		redacted = true
		shown, _ = strs.RedactSecrets(s)
		prefix, _ = strs.RedactSecrets(s[:hitLo])
	}
	text := sanitizeText(shown)
	if utf8.RuneCountInString(text) <= report.MaxCodeLineChars {
		return renderedLine{text: text, redacted: redacted}
	}
	center := utf8.RuneCountInString(sanitizeText(prefix))
	return renderedLine{text: clipAround(text, center, report.MaxCodeLineChars), clipped: true, redacted: redacted}
}

// sanitizeText makes text from the analysed file harmless to store and show:
// invalid UTF-8 bytes and control characters (C0, DEL and C1, which include the
// terminal escape introducers) become \xNN escapes, invisible format characters
// (bidirectional controls, zero-width characters, the byte order mark) and the
// line and paragraph separators become [U+XXXX], and tabs are expanded to tab
// stops. The renderers escape again; this keeps blocks valid in the JSON too.
func sanitizeText(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	col := 0
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && w == 1:
			col += writeText(&sb, fmt.Sprintf("\\x%02x", s[i]))
		case r == '\t':
			col += writeText(&sb, strings.Repeat(" ", tabWidth-col%tabWidth))
		case unicode.IsControl(r):
			col += writeText(&sb, fmt.Sprintf("\\x%02x", r))
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			col += writeText(&sb, fmt.Sprintf("[U+%04X]", r))
		default:
			sb.WriteRune(r)
			col++
		}
		i += w
	}
	return sb.String()
}

// writeText writes s and returns its width in characters.
func writeText(sb *strings.Builder, s string) int {
	sb.WriteString(s)
	return utf8.RuneCountInString(s)
}

// clipAround cuts text to limit characters, keeping the window that starts a
// little before center (a character index), and marks each side that was cut
// with an ellipsis in place of its edge character.
func clipAround(text string, center, limit int) string {
	r := []rune(text)
	if len(r) <= limit {
		return text
	}
	start := min(max(center-limit/3, 0), len(r)-limit)
	out := slices.Clone(r[start : start+limit])
	if start > 0 {
		out[0] = '…'
	}
	if start+limit < len(r) {
		out[len(out)-1] = '…'
	}
	return string(out)
}

// clipRunes shortens s to at most report.MaxCodeLabelChars characters, ending with an ellipsis.
func clipRunes(s string) string {
	const n = report.MaxCodeLabelChars
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// labelText makes a name from the file (an entry path, a section name) safe to
// use as a label and short enough for one.
func labelText(s string) string {
	return clipRunes(sanitizeText(s))
}
