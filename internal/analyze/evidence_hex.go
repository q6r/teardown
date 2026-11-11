package analyze

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/strs"
)

const (
	// hexMargin is how many bytes a window shows before and after a string.
	hexMargin = 64
	// hexMaxSpan is the most bytes one hex block holds: the line cap of the model.
	hexMaxSpan = report.MaxCodeLines * hexdump.BytesPerRow
	// secretMargin is how far beyond a window the file is searched for secrets
	// that reach into it: the longest run the scanner keeps, as UTF-16 text.
	secretMargin = 2 * strs.MaxStringLen
	// secretMinLen is the length of the shortest secret the scanner recognises.
	secretMinLen = 20
	// maskByte replaces every byte of a secret in a window, in the hex column
	// (as 2a) and in the ASCII column (as an asterisk).
	maskByte = '*'
	// pemKind is the kind of the private-key header secret.
	pemKind = "pem-private-key"
)

// hexWindow returns the byte range a hex window shows around a string: a margin
// on both sides, rounded out to whole rows and held inside the entry that holds
// the string (or the file).
func (e *evidence) hexWindow(p *pick) span {
	lo, hi := int64(0), e.size
	if p.mem != nil {
		lo, hi = p.mem.offset, min(p.mem.offset+p.mem.size, e.size)
	}
	const row = hexdump.BytesPerRow
	first := max(lo, (p.start-hexMargin)&^(row-1))
	last := min(hi, (p.start+p.extent()+hexMargin+row-1)&^(row-1))
	return span{lo: first, hi: last}
}

// hexBlocks builds the hex blocks for strings that are not shown as source:
// windows that overlap are merged into one block (at most 64 rows), and at most
// [maxHexBlocks] blocks are made. rank gives the position of a string in its
// finding's list.
func (e *evidence) hexBlocks(picks []*pick, rank func(*pick) int) []blockAt {
	spans := make([]span, 0, len(picks))
	shown := make([]*pick, 0, len(picks))
	for _, p := range picks {
		if w := e.hexWindow(p); w.hi > w.lo {
			spans = append(spans, w)
			shown = append(shown, p)
		}
	}
	var out []blockAt
	for _, g := range groupSpans(spans, hexMaxSpan, maxHexBlocks) {
		if e.ctx.Err() != nil {
			break
		}
		group := make([]*pick, len(g.members))
		first := rank(shown[g.members[0]])
		for i, m := range g.members {
			group[i] = shown[m]
			first = min(first, rank(shown[m]))
		}
		if b, ok := e.hexBlock(g.win, group); ok {
			out = append(out, blockAt{rank: first, block: b})
		}
	}
	return out
}

// hexBlock reads the window win of the file and lays it out as rows of 16 bytes.
//
// Redaction decision. Secrets stay redacted in every output, and a window of raw
// bytes is an output. The window could simply be left out for a secret, but the
// place a credential sits and what surrounds it (the name of the variable, the
// quotes, the neighbouring strings) is what a developer needs to find and fix
// it. So the window is shown with every byte of every credential-like value
// replaced by an asterisk (2a in the hex column, "*" in the ASCII column): no
// byte of the value can be recovered from either column, and the width of the
// masked run is all that is left of it (the finding already states the length).
// The masking is applied to every window, not only to those of secret findings,
// because a credential can sit right next to a URL or a command line. It looks for
// secrets in a larger region than the window, so one that starts before the
// first row, or ends after the last, is hidden too, and it finds them as ASCII
// and as UTF-16LE text with the scanner's own patterns. After a private-key
// header the key material follows, and nothing in it matches a pattern, so every
// printable byte from the header to the end of the region is masked as well.
func (e *evidence) hexBlock(win span, picks []*pick) (report.CodeBlock, bool) {
	regionLo := max(0, win.lo-secretMargin)
	regionHi := min(e.size, win.hi+secretMargin)
	buf, err := binio.ReadAt(e.r, e.size, regionLo, regionHi-regionLo)
	if err != nil {
		return report.CodeBlock{}, false
	}
	masked, hidden, pem := maskSecrets(buf)
	rows, _, err := hexdump.Window(masked, win.lo-regionLo, int(win.hi-win.lo))
	if err != nil {
		return report.CodeBlock{}, false
	}

	truncated := false
	for _, p := range picks {
		truncated = truncated || p.end-p.start > maxMarkBytes
	}
	lines := make([]report.CodeLine, len(rows))
	for i, row := range rows {
		off := regionLo + row.Offset
		hit := false
		for _, p := range picks {
			hit = hit || (off < p.start+p.extent() && off+int64(row.Len) > p.start)
		}
		lines[i] = report.CodeLine{Offset: off, Bytes: row.Hex, Text: row.ASCII, Highlight: hit}
	}

	b := report.CodeBlock{
		Kind: report.CodeKindHex, Title: hexTitle(picks), Offset: lines[0].Offset, Lines: lines, Truncated: truncated,
	}
	first := slices.MinFunc(picks, func(a, b *pick) int { return cmp.Compare(a.start, b.start) })
	if first.mem != nil {
		b.File = labelText(first.mem.name)
	} else {
		b.Section = e.sectionAt(first.start)
	}
	// The hidden ranges are relative to the region that was read.
	b.Limitations = hexLimitations(maskedAt(hidden, win.lo-regionLo, win.hi-regionLo), pem)
	return b, true
}

// hexTitle names a block after the strings it highlights.
func hexTitle(picks []*pick) string {
	if len(picks) == 1 {
		t := fmt.Sprintf("Bytes around the %s at file offset %s", picks[0].label, offsetText(picks[0].start))
		if picks[0].item.Category == report.CatSecret {
			t += " (value masked)"
		}
		return clipRunes(t, report.MaxCodeLabelChars)
	}
	labels := make([]string, len(picks))
	lowest := picks[0].start
	secret := false
	for i, p := range picks {
		labels[i] = p.label
		lowest = min(lowest, p.start)
		secret = secret || p.item.Category == report.CatSecret
	}
	t := fmt.Sprintf("Bytes around %s, the first at file offset %s", describeStrings(labels), offsetText(lowest))
	if secret {
		t += " (values masked)"
	}
	return clipRunes(t, report.MaxCodeLabelChars)
}

// hexLimitations states what a hex window cannot show.
func hexLimitations(masked, pem bool) []string {
	out := []string{"A raw window over the file: the bytes are shown as stored, 16 to a row, and nothing says that any code uses them."}
	if masked {
		out = append(out, "The bytes of credential-like values are replaced by 2a (an asterisk) in the hex and ASCII columns, so the values cannot be recovered from this view.")
	}
	if pem {
		out = append(out, "After a private-key header every printable byte up to the end of the region read is masked, because the key material follows the header.")
	}
	return out
}

// sectionAt names the section of the executable whose raw data holds a file offset.
func (e *evidence) sectionAt(off int64) string {
	if off < 0 {
		return ""
	}
	for _, s := range e.rep.Sections {
		// off is not negative, so the conversion keeps its value.
		if s.RawSize > 0 && uint64(off) >= s.Offset && uint64(off)-s.Offset < s.RawSize { //nolint:gosec // off >= 0 checked above
			return labelText(s.Name)
		}
	}
	return ""
}

// maskedAt reports whether any hidden range overlaps the bytes [lo, hi).
func maskedAt(hidden []span, lo, hi int64) bool {
	return slices.ContainsFunc(hidden, func(s span) bool { return s.lo < hi && s.hi > lo })
}

// maskSecrets returns a copy of buf in which every byte of every credential-like
// value is replaced by [maskByte], the ranges it hid, and whether a private-key
// header was met (everything printable after it is hidden too). Secrets are
// found with the scanner's patterns in printable ASCII runs and in UTF-16LE runs
// at either alignment, so that the hidden values are the ones the report
// redacts, and then some: the patterns are deliberately generous.
func maskSecrets(buf []byte) (out []byte, hidden []span, pem bool) {
	out = bytes.Clone(buf)
	hide := func(lo, hi int) {
		for i := lo; i < hi; i++ {
			out[i] = maskByte
		}
		hidden = append(hidden, span{lo: int64(lo), hi: int64(hi)})
	}
	hideRest := func(from int) {
		for i := from; i < len(buf); i++ {
			if isStringByte(buf[i]) {
				out[i] = maskByte
			}
		}
		hidden = append(hidden, span{lo: int64(from), hi: int64(len(buf))})
		pem = true
	}

	for i := 0; i < len(buf); {
		if !isStringByte(buf[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(buf) && isStringByte(buf[j]) {
			j++
		}
		if j-i >= secretMinLen {
			for _, sp := range strs.FindSecrets(string(buf[i:j])) {
				hide(i+sp.Start, i+sp.End)
				if sp.Kind == pemKind {
					hideRest(i + sp.End)
				}
			}
		}
		i = j
	}

	for align := range 2 {
		for i := align; i+1 < len(buf); {
			if !isStringByte(buf[i]) || buf[i+1] != 0 {
				i += 2
				continue
			}
			var chars []byte
			j := i
			for j+1 < len(buf) && isStringByte(buf[j]) && buf[j+1] == 0 {
				chars = append(chars, buf[j])
				j += 2
			}
			if len(chars) >= secretMinLen {
				for _, sp := range strs.FindSecrets(string(chars)) {
					hide(i+2*sp.Start, i+2*sp.End)
					if sp.Kind == pemKind {
						hideRest(i + 2*sp.End)
					}
				}
			}
			i = j
		}
	}
	return out, hidden, pem
}
