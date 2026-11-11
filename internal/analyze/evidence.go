package analyze

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/format/archive"
	"github.com/q6r/teardown/internal/format/asar"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/rules"
	"github.com/q6r/teardown/internal/strs"
)

// Caps on the evidence this pass adds to one finding. They sit inside the caps of
// the report model (12 blocks of 64 lines of 200 characters), which every
// producer and every renderer applies again.
const (
	// maxHexBlocks is the most hex blocks added to one finding.
	maxHexBlocks = 3
	// maxSourceBlocks is the most source blocks added to one finding.
	maxSourceBlocks = 6
	// maxCandidates is how many of a finding's strings are considered, most telling first.
	maxCandidates = 8
	// maxMarkBytes is how much of one string a hex window highlights and sizes itself on.
	maxMarkBytes = 256
)

// electronFinding is the finding about Electron settings found as text in bundled scripts.
const electronFinding = "application.electron-risky-settings"

// evidence enriches the findings of one report with the code behind them.
type evidence struct {
	ctx  context.Context
	rep  *report.Report
	r    io.ReaderAt
	size int64
	lim  limits.Limits
}

// addEvidence adds code blocks to the findings it knows how to explain, after the
// rules have run: a hex window around each string behind a string-derived
// finding (a source excerpt instead when the string sits in a text entry of an
// ASAR or ZIP container, or in a text file) and the source lines behind the
// Electron settings found in bundled scripts. It only reads the file through
// bounded reads, never extracts or runs anything, and every secret it could show
// is hidden (see [maskSecrets] and [redactLine]). It returns the context's error
// when the analysis deadline ends first; findings already enriched keep their blocks.
func addEvidence(ctx context.Context, rep *report.Report, r io.ReaderAt, size int64, lim limits.Limits) error {
	e := &evidence{ctx: ctx, rep: rep, r: r, size: size, lim: lim.Normalize()}
	plans := e.plan()
	e.locate(plans)
	for _, pl := range plans {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.stringBlocks(pl)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.electronBlocks()
	scrubCode(rep)
	return ctx.Err()
}

// pick is one string behind a finding, located in the file.
type pick struct {
	item  report.StringItem
	start int64 // file offset of the first byte of the string
	end   int64 // file offset after its last byte, as long as the file shows it
	label string
	mem   *member // the container entry that holds the string, nil when none
}

// extent is the number of bytes of the string that a window highlights.
func (p *pick) extent() int64 { return min(p.end-p.start, maxMarkBytes) }

// plan lists, for every finding derived from strings, the strings to show.
func (e *evidence) plan() []*findingPlan {
	var plans []*findingPlan
	for i := range e.rep.Findings {
		f := &e.rep.Findings[i]
		if len(f.Code) >= report.MaxCodeBlocks {
			continue
		}
		items := rules.StringEvidence(e.rep, f.ID)
		if len(items) == 0 {
			continue
		}
		pl := &findingPlan{finding: f}
		for _, it := range items {
			if len(pl.picks) == maxCandidates {
				break
			}
			if p, ok := e.measure(it); ok {
				pl.picks = append(pl.picks, p)
			}
		}
		if len(pl.picks) > 0 {
			plans = append(plans, pl)
		}
	}
	return plans
}

// findingPlan is the strings to show for one finding, most telling first.
type findingPlan struct {
	finding *report.Finding
	picks   []*pick
}

// isStringByte is the scanner's idea of a printable byte: space to tilde, and tab.
func isStringByte(b byte) bool { return (b >= 0x20 && b <= 0x7e) || b == '\t' }

// measure finds how many bytes the string of item occupies in the file by
// reading the run of printable bytes (or of printable code units for UTF-16LE)
// that starts at its offset. It returns false when the file holds no string there.
func (e *evidence) measure(it report.StringItem) (*pick, bool) {
	unit := int64(1)
	if it.Encoding == "utf16le" {
		unit = 2
	}
	if it.Offset < 0 || it.Offset >= e.size {
		return nil, false
	}
	data, err := binio.ReadUpTo(e.r, e.size, it.Offset, strs.MaxStringLen*unit)
	if err != nil {
		return nil, false
	}
	n := 0
	if unit == 1 {
		for n < len(data) && isStringByte(data[n]) {
			n++
		}
	} else {
		for 2*n+1 < len(data) && isStringByte(data[2*n]) && data[2*n+1] == 0 {
			n++
		}
		n *= 2
	}
	if n == 0 {
		return nil, false
	}
	return &pick{item: it, start: it.Offset, end: it.Offset + int64(n), label: stringLabel(it)}, true
}

// stringLabel names a kind of string for a block title.
func stringLabel(it report.StringItem) string {
	switch it.Category {
	case report.CatURL:
		return "URL"
	case report.CatIP:
		return "IP address"
	case report.CatDomain:
		return "domain"
	case report.CatEmail:
		return "e-mail address"
	case report.CatCommand:
		return "command line"
	case report.CatRegistry:
		return "registry path"
	case report.CatSecret:
		switch it.Kind {
		case "aws-access-key-id":
			return "AWS access key ID"
		case "github-token":
			return "GitHub token"
		case "slack-token":
			return "Slack token"
		case "pem-private-key":
			return "PEM private key header"
		case "jwt":
			return "JSON Web Token"
		}
		return "credential-like string"
	}
	return "string"
}

// member is the part of the file that holds one entry of a container, or the
// whole of a text file.
type member struct {
	name   string // path inside the container, "" for the file itself
	offset int64  // file offset of the first byte of the content
	size   int64  // content length in bytes
}

// locate finds the container entry (or the file itself, for a text file) that
// holds each string of the plans and records it in the picks.
func (e *evidence) locate(plans []*findingPlan) {
	var offsets []int64
	for _, pl := range plans {
		for _, p := range pl.picks {
			offsets = append(offsets, p.start)
		}
	}
	if len(offsets) == 0 {
		return
	}
	slices.Sort(offsets)
	offsets = slices.Compact(offsets)

	var found map[int64]*member
	switch id := e.rep.Type.ID; {
	case id == report.TypeAsar:
		found = e.locateAsar(offsets)
	case isZipFamily(id):
		found = e.locateZip(offsets)
	case e.rep.Type.Family == report.FamilyText || e.rep.Type.Family == report.FamilyScript:
		whole := &member{size: e.size}
		found = make(map[int64]*member, len(offsets))
		for _, off := range offsets {
			found[off] = whole
		}
	}
	for _, pl := range plans {
		for _, p := range pl.picks {
			if m := found[p.start]; m != nil {
				p.mem = m
				p.end = min(p.end, m.offset+m.size) // a string never runs on into the next entry
			}
		}
	}
}

// isZipFamily reports whether the type is a ZIP archive or a format built on one.
func isZipFamily(id string) bool {
	switch id {
	case report.TypeZip, report.TypeJar, report.TypeAPK, report.TypeAAB, report.TypeDocx, report.TypeXlsx,
		report.TypePptx, report.TypeODF, report.TypeEPUB, report.TypeNupkg, report.TypeWheel, report.TypeVSIX:
		return true
	}
	return false
}

// locateAsar streams the ASAR index once and returns the packed file that holds
// each offset. A damaged index only means that fewer offsets are located: the
// parse stage has already reported the damage.
func (e *evidence) locateAsar(sorted []int64) map[int64]*member {
	out := make(map[int64]*member, len(sorted))
	_ = asar.Walk(e.ctx, e.r, e.size, e.lim, func(f asar.File) bool {
		i := sort.Search(len(sorted), func(i int) bool { return sorted[i] >= f.Offset })
		for ; i < len(sorted) && sorted[i] < f.Offset+f.Size; i++ {
			if out[sorted[i]] == nil {
				out[sorted[i]] = &member{name: f.Path, offset: f.Offset, size: f.Size}
			}
		}
		return len(out) < len(sorted)
	})
	return out
}

// locateZip returns the stored member of the ZIP archive that holds each offset.
// Compressed members are not located: the file holds their compressed bytes.
func (e *evidence) locateZip(sorted []int64) map[int64]*member {
	out := make(map[int64]*member, len(sorted))
	members, _ := archive.Locate(e.ctx, e.r, e.size, sorted) // a damaged directory only means fewer members
	for i, m := range members {
		if m != nil {
			out[sorted[i]] = &member{name: m.Name, offset: m.Offset, size: m.Size}
		}
	}
	return out
}

// blockAt is a finished block together with the rank of the first string it
// shows, so that blocks of one finding come out in the order of their strings.
type blockAt struct {
	rank  int
	block report.CodeBlock
}

// stringBlocks adds the blocks of one finding: source excerpts for strings in
// text entries, hex windows for the rest.
func (e *evidence) stringBlocks(pl *findingPlan) {
	f := pl.finding
	room := report.MaxCodeBlocks - len(f.Code)
	if room <= 0 {
		return
	}
	texts := map[member]*memberText{}
	var hexPicks []*pick
	srcPicks := map[member][]*pick{}
	var srcOrder []member
	for _, p := range pl.picks {
		if p.mem != nil {
			if mt := e.memberText(texts, *p.mem); mt.ok && p.end <= p.mem.offset+int64(len(mt.data)) {
				if _, seen := srcPicks[*p.mem]; !seen {
					srcOrder = append(srcOrder, *p.mem)
				}
				srcPicks[*p.mem] = append(srcPicks[*p.mem], p)
				continue
			}
		}
		hexPicks = append(hexPicks, p)
	}

	rank := func(p *pick) int { return slices.Index(pl.picks, p) }
	var blocks []blockAt
	budget := maxSourceBlocks
	for _, m := range srcOrder {
		marks := make([]mark, 0, len(srcPicks[m]))
		for _, p := range srcPicks[m] {
			marks = append(marks, mark{start: p.start, end: p.end, label: p.label, rank: rank(p)})
		}
		got := e.sourceBlocks(m, texts[m], marks, budget)
		budget -= len(got)
		blocks = append(blocks, got...)
	}
	blocks = append(blocks, e.hexBlocks(hexPicks, rank)...)
	slices.SortStableFunc(blocks, func(a, b blockAt) int { return cmp.Compare(a.rank, b.rank) })
	for _, b := range blocks[:min(len(blocks), room)] {
		f.Code = append(f.Code, b.block)
	}
}

// electronBlocks adds the source lines behind the Electron settings that were
// found as text in the bundled scripts.
func (e *evidence) electronBlocks() {
	var f *report.Finding
	for i := range e.rep.Findings {
		if e.rep.Findings[i].ID == electronFinding && len(e.rep.Findings[i].Code) < report.MaxCodeBlocks {
			f = &e.rep.Findings[i]
			break
		}
	}
	if f == nil {
		return
	}
	// A damaged index only means fewer hits: the parse stage already said so.
	hits, _ := asar.Hits(e.ctx, e.r, e.size, e.lim)
	var order []member
	marks := map[member][]mark{}
	for i, h := range hits {
		m := member{name: h.Script.Path, offset: h.Script.Offset, size: h.Script.Size}
		if _, seen := marks[m]; !seen {
			order = append(order, m)
		}
		marks[m] = append(marks[m], mark{start: m.offset + int64(h.Start), end: m.offset + int64(h.End), label: h.ID, hint: true, rank: i})
	}
	texts := map[member]*memberText{}
	budget := min(maxSourceBlocks, report.MaxCodeBlocks-len(f.Code))
	var blocks []blockAt
	for _, m := range order {
		if budget <= 0 || e.ctx.Err() != nil {
			break
		}
		mt := e.memberText(texts, m)
		if !mt.ok {
			continue
		}
		ms := slices.DeleteFunc(slices.Clone(marks[m]), func(k mark) bool { return k.end > m.offset+int64(len(mt.data)) })
		got := e.sourceBlocks(m, mt, ms, budget)
		budget -= len(got)
		blocks = append(blocks, got...)
	}
	for _, b := range blocks {
		f.Code = append(f.Code, b.block)
	}
}

// span is a half-open range of positions: bytes for a hex window, line numbers
// for a source excerpt.
type span struct{ lo, hi int64 }

// spanGroup is a set of spans merged into one window.
type spanGroup struct {
	win     span
	members []int // indices of the merged spans
}

// groupSpans merges spans, given most telling first, into at most maxGroups
// windows of at most maxSpan positions: a span joins the first window it
// overlaps or touches while the merged window stays within maxSpan, otherwise it
// opens a window of its own if there is room and is left out if there is none.
// The windows come back in position order.
func groupSpans(spans []span, maxSpan int64, maxGroups int) []spanGroup {
	var groups []spanGroup
	for i, s := range spans {
		joined := false
		for g := range groups {
			w := groups[g].win
			merged := span{lo: min(w.lo, s.lo), hi: max(w.hi, s.hi)}
			if s.lo <= w.hi && s.hi >= w.lo && merged.hi-merged.lo <= maxSpan {
				groups[g].win = merged
				groups[g].members = append(groups[g].members, i)
				joined = true
				break
			}
		}
		if !joined && len(groups) < maxGroups {
			groups = append(groups, spanGroup{win: s, members: []int{i}})
		}
	}
	slices.SortStableFunc(groups, func(a, b spanGroup) int { return cmp.Compare(a.win.lo, b.win.lo) })
	return groups
}

// maxTitleLabels is how many distinct labels a title spells out.
const maxTitleLabels = 3

// joinLabels lists the distinct labels in order, for example "URL, IP address".
// Beyond three it says how many more there are.
func joinLabels(labels []string) string {
	var seen []string
	for _, l := range labels {
		if !slices.Contains(seen, l) {
			seen = append(seen, l)
		}
	}
	if len(seen) > maxTitleLabels {
		return fmt.Sprintf("%s and %d more", strings.Join(seen[:maxTitleLabels], ", "), len(seen)-maxTitleLabels)
	}
	return strings.Join(seen, ", ")
}

// pluralLabel returns the plural of a label of [stringLabel] ("URL" becomes "URLs").
func pluralLabel(label string) string {
	if strings.HasSuffix(label, "s") {
		return label + "es"
	}
	return label + "s"
}

// describeStrings names a group of strings for a title: "3 URLs" when they
// share a label, "3 strings (URL, IP address)" when they do not.
func describeStrings(labels []string) string {
	same := true
	for _, l := range labels {
		same = same && l == labels[0]
	}
	if same {
		return fmt.Sprintf("%d %s", len(labels), pluralLabel(labels[0]))
	}
	return fmt.Sprintf("%d strings (%s)", len(labels), joinLabels(labels))
}

// scrubCode is the last line of defence for the promise that secrets are
// redacted in every output, applied to the code blocks as scrubSecrets is to the
// rest of the report: any secret-looking substring in a title, a file name or the
// text of a line is replaced by its redacted form. The producers hide secrets
// where they sit (masked bytes in a hex window, redacted source lines); this
// catches whatever reaches a block by another route.
func scrubCode(rep *report.Report) {
	for i := range rep.Findings {
		code := rep.Findings[i].Code
		for j := range code {
			b := &code[j]
			b.Title, _ = strs.RedactSecrets(b.Title)
			b.File, _ = strs.RedactSecrets(b.File)
			for k := range b.Lines {
				l := &b.Lines[k]
				l.Text, _ = strs.RedactSecrets(l.Text)
				l.Note, _ = strs.RedactSecrets(l.Note)
			}
		}
	}
}

// offsetText formats a file offset for a title.
func offsetText(off int64) string { return fmt.Sprintf("0x%x", off) }
