package render

import (
	"fmt"
	"html"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// What the terminal output of a finding shows of its code unless [Options.CodeAll] is set.
const (
	// DefaultCodeBlocks is the number of code blocks shown per finding.
	DefaultCodeBlocks = 3
	// DefaultCodeLines is the number of lines shown per block.
	DefaultCodeLines = 24
)

// codeLimits returns how many blocks of a finding and how many lines of a block the terminal output shows.
func (o Options) codeLimits() (blocks, lines int) {
	if o.CodeAll {
		return report.MaxCodeBlocks, report.MaxCodeLines
	}
	return DefaultCodeBlocks, DefaultCodeLines
}

// codeRow is one line of a code block as plain, already escaped text.
type codeRow struct {
	hit                     bool
	addr, bytes, text, note string
}

// codeTable is the visible part of one block laid out in aligned columns. The
// plain-text outputs (terminal, Markdown, the no-script summary of the HTML
// page) all print it, so they agree on what a block looks like.
type codeTable struct {
	kind          string
	rows          []codeRow
	addrW, bytesW int
	// first is the index of the first row within the block's lines and total
	// the number of lines the block has.
	first, total int
}

// newCodeTable lays out at most limit lines of b (every line when limit <= 0),
// a window around the flagged line when the block is longer.
func newCodeTable(b report.CodeBlock, limit int) codeTable {
	t := codeTable{kind: b.Kind, total: len(b.Lines)}
	lines := b.Lines
	if limit > 0 && len(lines) > limit {
		t.first = b.WindowStart(limit)
		lines = lines[t.first : t.first+limit]
	}
	for _, l := range lines {
		r := codeRow{hit: l.Highlight, bytes: visible(l.Bytes), text: visible(l.Text), note: visible(l.Note)}
		switch b.Kind {
		case report.CodeKindHex:
			r.addr = fmt.Sprintf("%08x", l.Offset)
		case report.CodeKindSource:
			r.addr = strconv.Itoa(l.Line)
		default:
			r.addr = fmt.Sprintf("0x%x", l.Offset)
			if l.Address != 0 {
				r.addr = l.Address.String()
			}
		}
		t.addrW = max(t.addrW, runeLen(r.addr))
		t.bytesW = max(t.bytesW, runeLen(r.bytes))
		t.rows = append(t.rows, r)
	}
	return t
}

// cut reports how many lines of the block lie before and after the laid-out rows.
func (t codeTable) cut() (before, after int) {
	return t.first, t.total - t.first - len(t.rows)
}

// format returns one string per row, without indentation. A flagged row starts
// with "> ", so the mark survives without colour; p only adds emphasis. Lines are
// never cut to a width: the model already bounds them, and cutting would hide
// the note that names the API.
func (t codeTable) format(p palette) []string {
	out := make([]string, 0, len(t.rows))
	for _, r := range t.rows {
		mark := "  "
		if r.hit {
			mark = p.wrap("1;33", ">") + " "
		}
		var line string
		switch t.kind {
		case report.CodeKindSource:
			line = mark + p.dim(padLeft(r.addr, t.addrW)+" |") + " " + r.text
		case report.CodeKindHex:
			line = mark + p.dim(padRight(r.addr, t.addrW)+"  "+padRight(r.bytes, t.bytesW)) + "  " + p.dim("|"+r.text+"|")
		default:
			line = mark + p.dim(padRight(r.addr, t.addrW))
			if t.bytesW > 0 {
				line += "  " + p.dim(padRight(r.bytes, t.bytesW))
			}
			text := r.text
			if r.hit {
				text = p.bold(text)
			}
			line += "  " + text
			if r.note != "" {
				line += "  " + p.dim("; "+r.note)
			}
		}
		out = append(out, strings.TrimRight(line, " "))
	}
	return out
}

// codeTitle is the heading of a block: its title, or its kind when it has none.
func codeTitle(b report.CodeBlock) string {
	if b.Title != "" {
		return visible(b.Title)
	}
	switch b.Kind {
	case report.CodeKindDisasm:
		return "disassembly"
	case report.CodeKindHex:
		return "hex dump"
	case report.CodeKindSource:
		return "source lines"
	default:
		return "code"
	}
}

// codeMeta lists where a block comes from: file, section, address or file
// offset, instruction set. The parts are joined with sep.
func codeMeta(b report.CodeBlock, sep string) string {
	var parts []string
	if b.File != "" {
		parts = append(parts, visible(b.File))
	}
	if b.Section != "" {
		parts = append(parts, visible(b.Section))
	}
	switch {
	case b.Kind == report.CodeKindDisasm && b.Address != 0:
		parts = append(parts, b.Address.String())
	case b.Kind != report.CodeKindSource:
		parts = append(parts, fmt.Sprintf("file offset 0x%x", b.Offset))
	}
	if b.Arch != "" {
		parts = append(parts, visible(b.Arch))
	}
	return strings.Join(parts, sep)
}

// code prints the code blocks of one finding under its evidence: a heading per
// block, the aligned lines with the flagged one marked ">", a note when a block
// was cut, and the limitations of what is shown once. Without Options.CodeAll it
// shows the first DefaultCodeBlocks blocks of DefaultCodeLines lines each.
func (t *textView) code(f *report.Finding) {
	if t.o.HideCode || len(f.Code) == 0 {
		return
	}
	blocks, omitted := f.ClippedCode()
	if len(blocks) == 0 {
		return
	}
	maxBlocks, maxLines := t.o.codeLimits()
	shown := blocks[:min(len(blocks), maxBlocks)]
	sep := " · "
	if t.o.ASCII {
		sep = " | "
	}
	t.line("      %s %s", t.p.dim("code:"), plural(len(blocks)+omitted, "block"))
	for _, b := range shown {
		title := t.p.bold(codeTitle(b))
		if meta := codeMeta(b, sep); meta != "" {
			title += "  " + t.p.dim("("+meta+")")
		}
		t.line("        %s", title)
		table := newCodeTable(b, maxLines)
		for _, row := range table.format(t.p) {
			t.line("          %s", row)
		}
		before, after := table.cut()
		if before+after > 0 {
			t.line("          %s", t.p.dim(fmt.Sprintf("(lines %d-%d of %d: --code-all shows the whole block, --json has it all)", table.first+1, table.first+len(table.rows), table.total)))
		}
		if b.Truncated {
			t.line("          %s", t.p.dim("(the block is a bounded window: the code goes on after its last line)"))
		}
	}
	if hidden := len(blocks) + omitted - len(shown); hidden > 0 {
		hint := "see --code-all or --json"
		if t.o.CodeAll {
			hint = "see --json"
		}
		t.line("        %s", t.p.dim(fmt.Sprintf("(+%s, %s)", plural(hidden, "more code block"), hint)))
	}
	limits := distinctLimitations(shown)
	if !t.o.Verbose && len(limits) > 1 {
		limits = limits[:1]
	}
	for _, l := range limits {
		for i, w := range wrapText(visible(l), t.o.width()-26) {
			label := strings.Repeat(" ", len("limits: "))
			if i == 0 {
				label = "limits: "
			}
			t.line("        %s%s", t.p.dim(label), t.p.dim(w))
		}
	}
}

// CodeRows lays out the lines of a code block as the terminal report prints the
// code behind a finding: the address (the file offset of a hex row, the number of
// a source line), the bytes, the text and the note in aligned columns, with "> "
// in front of the flagged line and two spaces in front of the others. Text taken
// from the file is made printable, so nothing in a block can inject a control
// sequence, and a block longer than [report.MaxCodeLines] is cut to that cap
// around its flagged line. The rows carry no indentation and no heading.
func CodeRows(b report.CodeBlock, o Options) []string {
	return newCodeTable(b.Clipped(), 0).format(palette{on: o.Color})
}

// CodeLimits returns the limitations of the blocks, each said once, as lines
// wrapped to the width of the terminal output: the first line of a limitation
// starts with "limits: " and the lines that follow are aligned under it.
func CodeLimits(blocks []report.CodeBlock, o Options) []string {
	clipped := make([]report.CodeBlock, len(blocks))
	for i := range blocks {
		clipped[i] = blocks[i].Clipped()
	}
	const label = "limits: "
	p := palette{on: o.Color}
	var out []string
	for _, l := range distinctLimitations(clipped) {
		for i, w := range wrapText(visible(l), o.width()-len(label)-2) {
			prefix := strings.Repeat(" ", len(label))
			if i == 0 {
				prefix = label
			}
			out = append(out, p.dim(prefix+w))
		}
	}
	return out
}

// sourceLanguages maps the extension of a script to the language tag of its
// fenced block. The tag is chosen here, never taken from the file, so a hostile
// name cannot put anything into the fence line.
var sourceLanguages = map[string]string{
	".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "ts", ".json": "json", ".py": "python", ".sh": "sh",
	".ps1": "powershell", ".html": "html", ".css": "css", ".xml": "xml", ".lua": "lua", ".rb": "ruby",
}

// fenceLanguage is the info string of a block's fence in Markdown.
func fenceLanguage(b report.CodeBlock) string {
	switch b.Kind {
	case report.CodeKindDisasm:
		return "asm"
	case report.CodeKindSource:
		if lang, ok := sourceLanguages[strings.ToLower(path.Ext(b.File))]; ok {
			return lang
		}
	}
	return "text"
}

// markdownCode renders the code blocks of one finding: a heading and a fenced
// block each, then the limitations of what is shown. Lines can contain
// backticks, so every fence is longer than any run of them inside its block.
func markdownCode(f *report.Finding) string {
	blocks, _ := f.ClippedCode()
	if len(blocks) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Code:\n\n")
	for _, b := range blocks {
		fmt.Fprintf(&sb, "#### Code: %s\n\n", mdText(codeTitle(b)))
		if meta := codeMeta(b, " · "); meta != "" {
			fmt.Fprintf(&sb, "%s\n\n", mdText(meta))
		}
		rows := newCodeTable(b, 0).format(palette{})
		fence := strings.Repeat("`", max(3, longestBackticks(rows)+1))
		fmt.Fprintf(&sb, "%s%s\n%s\n%s\n\n", fence, fenceLanguage(b), strings.Join(rows, "\n"), fence)
		if b.Truncated {
			sb.WriteString("The block is a bounded window: the code goes on after its last line.\n\n")
		}
	}
	sb.WriteString("Limitations of the code shown:\n\n")
	for _, l := range distinctLimitations(blocks) {
		fmt.Fprintf(&sb, "- %s\n", mdText(visible(l)))
	}
	sb.WriteString("\n")
	return sb.String()
}

// longestBackticks returns the length of the longest run of backticks in lines.
func longestBackticks(lines []string) int {
	longest, run := 0, 0
	for _, l := range lines {
		run = 0
		for _, r := range l {
			if r == '`' {
				run++
				longest = max(longest, run)
			} else {
				run = 0
			}
		}
	}
	return longest
}

// withClippedCode returns rep with the code of every finding held to the caps of
// the model, or rep itself when no finding has any.
func withClippedCode(rep *report.Report) *report.Report {
	if !slices.ContainsFunc(rep.Findings, func(f report.Finding) bool { return len(f.Code) > 0 }) {
		return rep
	}
	cp := *rep
	cp.Findings = slices.Clone(rep.Findings)
	for i := range cp.Findings {
		cp.Findings[i].Code, _ = cp.Findings[i].ClippedCode()
	}
	return &cp
}

// writeCode writes the code of one finding into the no-script summary of the
// HTML page: the first blocks, each as a preformatted listing.
func writeCode(sb *strings.Builder, f *report.Finding) {
	blocks, omitted := f.ClippedCode()
	if len(blocks) == 0 {
		return
	}
	shown := blocks[:min(len(blocks), DefaultCodeBlocks)]
	sb.WriteString("<h4>Code</h4>\n")
	for _, b := range shown {
		title := codeTitle(b)
		if meta := codeMeta(b, " | "); meta != "" {
			title += " (" + meta + ")"
		}
		listing := strings.Join(newCodeTable(b, DefaultCodeLines).format(palette{}), "\n")
		fmt.Fprintf(sb, "<p>%s</p>\n<pre>%s</pre>\n", html.EscapeString(title), html.EscapeString(listing))
	}
	if hidden := len(blocks) + omitted - len(shown); hidden > 0 {
		verb := "are"
		if hidden == 1 {
			verb = "is"
		}
		fmt.Fprintf(sb, "<p>%s %s in the interactive report.</p>\n", plural(hidden, "more code block"), verb)
	}
	writeList(sb, "Limitations of the code shown", distinctLimitations(shown))
}

// distinctLimitations returns the limitations of the blocks without repeats, in order.
func distinctLimitations(blocks []report.CodeBlock) []string {
	var out []string
	seen := map[string]bool{}
	for _, b := range blocks {
		for _, l := range b.Limitations {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// plural returns "1 block" or "3 blocks".
func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}
