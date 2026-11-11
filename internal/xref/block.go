package xref

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/disasm"
	"github.com/q6r/teardown/internal/report"
)

// The context of a block, in instructions.
const (
	// DefaultBefore is the number of instructions shown before a call.
	DefaultBefore = 8
	// DefaultAfter is the number of instructions shown after a call.
	DefaultAfter = 4

	maxBefore = 40
	maxAfter  = 20
	// bytesPerInstruction is how far back, per instruction asked for, the search
	// for a clean start point goes. Typical instructions are three to seven bytes
	// long: this leaves room for the long ones and for a few bytes of slack.
	bytesPerInstruction = 12
)

// leadInLimit is said by a block whose earlier instructions could not be recovered.
const leadInLimit = "The instructions before this call could not be recovered reliably (no start point before it decodes cleanly and reaches it), so the block starts at the call."

// limitations are the limits every block states about itself, the most important first.
func (ix *Index) limitations() []string {
	return []string{
		fmt.Sprintf("%s code decoded as a linear sweep (ARM64 and other instruction sets are not supported): data inside a code section can be read as instructions, and one wrong byte shifts what follows.", ix.arch),
		"Only calls through the import table and import thunks are found: functions resolved at run time are invisible, and packed or protected code hides its real calls.",
		"A view of the code, not a decompiler, an emulator or a verdict: nothing was executed, and the code shows what is called, not why.",
	}
}

// title names a block after the import and the section.
func (ix *Index) title(s Site) string {
	var what string
	switch s.Kind {
	case KindCall:
		what = "call to " + s.API
	case KindCallThunk:
		what = "call to " + s.API + " through a thunk"
	case KindJumpThunk:
		what = "jump to " + s.API + " through a thunk"
	case KindJump:
		what = "jump to " + s.API
	case KindLoad:
		what = "reference to " + s.API
	default:
		what = "import thunk for " + s.API
	}
	if s.Section != "" {
		what += " in " + s.Section
	}
	return clip(what, report.MaxCodeLabelChars)
}

// clip shortens s to at most n characters, ending with an ellipsis.
func clip(s string, n int) string { //nolint:unparam // the label and line limits are separate constants that happen to be equal
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Block returns the code around a site as a code block of the report: the
// instruction that refers to the import (highlighted), up to before
// instructions that lead to it and up to after instructions that follow it
// (see [DefaultBefore] and [DefaultAfter]; both are bounded).
//
// The lead-in is not decoded backwards blindly. The block tries start points
// ever closer to the site, from about twelve bytes per instruction wanted
// before it (and at least as far back as for [DefaultBefore]), and keeps the
// first one whose instructions all decode and reach the site exactly on an
// instruction boundary; when none does the block starts at the site and says so.
// A site the index cannot read gives a block with the one line the index knows.
func (ix *Index) Block(s Site, before, after int) report.CodeBlock {
	before, after = min(max(before, 0), maxBefore), min(max(after, 0), maxAfter)
	b := report.CodeBlock{
		Kind: report.CodeKindDisasm, Title: ix.title(s), Section: s.Section, Arch: ix.arch,
		Limitations: ix.limitations(),
	}
	fallback := func(why string) report.CodeBlock {
		b.Offset, b.Address = s.Offset, report.Addr(s.Addr)
		b.Lines = []report.CodeLine{{Address: report.Addr(s.Addr), Offset: s.Offset, Text: s.Kind.String(), Note: clip(s.API, report.MaxCodeLineChars), Highlight: true}}
		b.Limitations = append(b.Limitations, why)
		return b
	}

	si, off, ok := ix.layout.SectionAtVA(s.Addr)
	if !ok {
		return fallback("The code at this address could not be located in the file.")
	}
	sec := ix.layout.Sections[si]
	secStart, secEnd := int64(sec.RawOffset), int64(sec.RawOffset)+sec.Mapped()
	// The search for a start point looks as far back as it does for the default
	// context even when fewer instructions are wanted: a start that is a few bytes
	// off takes several instructions to fall in step, and a window of one or two
	// instructions would show the tail of that misaligned run.
	back := int64(0)
	if before > 0 {
		back = min(off-secStart, int64(max(before, DefaultBefore))*bytesPerInstruction)
	}
	fwd := min(secEnd-off, int64(after+1)*disasm.MaxInstLen)
	buf, err := binio.ReadAt(ix.r, ix.size, off-back, back+fwd)
	if err != nil {
		return fallback("The code around this address could not be read.")
	}

	lead, ok := ix.leadIn(buf, int(back), s.Addr-uint64(back), before) // back <= the window read
	if !ok {
		b.Limitations = append(b.Limitations, leadInLimit)
	}
	insts := make([]disasm.Inst, 0, len(lead)+after+1)
	insts = append(insts, lead...)
	insts = append(insts, disasm.DecodeAll(ix.mode, buf[back:], s.Addr, after+1)...)

	b.Lines = make([]report.CodeLine, 0, len(insts))
	for _, in := range insts {
		line := report.CodeLine{
			Address: report.Addr(in.Addr),
			Offset:  off + int64(in.Addr-s.Addr), // negative for the instructions before the site
			Bytes:   hexBytes(in.Bytes),
			Text:    clip(in.Text, report.MaxCodeLineChars),
			Note:    clip(ix.Note(in), report.MaxCodeLineChars),
		}
		if in.Addr == s.Addr {
			line.Highlight = true
			line.Note = clip(siteNote(s), report.MaxCodeLineChars)
		}
		b.Lines = append(b.Lines, line)
	}
	b.Offset, b.Address = b.Lines[0].Offset, b.Lines[0].Address
	return b
}

// siteNote is the note on the highlighted line: the import, and the thunk a
// call goes through. It is the note the [Annotator] gives the same instruction
// anywhere else.
func siteNote(s Site) string {
	if s.Via != 0 {
		return viaThunk(s.API, s.Via)
	}
	return s.API
}

// leadIn decodes the instructions that end exactly where the site starts:
// buf[:end] is the window before the site (it starts at address base), and the
// bytes after it let an instruction that crosses the end be recognised as a
// misaligned start. It returns the last want instructions of the first start
// point that decodes without an undecodable byte and lands on the site, and
// false when none does. A window with nothing before the site is a success.
func (ix *Index) leadIn(buf []byte, end int, base uint64, want int) ([]disasm.Inst, bool) {
	if end == 0 || want == 0 {
		return nil, true
	}
	for start := range end {
		run := make([]disasm.Inst, 0, end-start)
		pos := start
		for pos < end {
			in := disasm.Decode(ix.mode, buf[pos:], base+uint64(pos))
			if !in.Valid {
				break
			}
			run = append(run, in)
			pos += in.Len
		}
		if pos == end {
			return run[max(0, len(run)-want):], true
		}
	}
	return nil, false
}

// hexBytes renders bytes as hex pairs separated by single spaces.
func hexBytes(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(digits[v>>4])
		sb.WriteByte(digits[v&15])
	}
	return sb.String()
}

// CallBlocks returns up to limit blocks for the places that call or refer to
// the import api (see [Index.Sites] for how api is matched), best first and with
// the default context, together with the number of such places the scan found.
// An import thunk that nothing calls is not counted, and loads of the slot are
// left out when the import is called somewhere. It is what the rules attach to
// a finding.
func (ix *Index) CallBlocks(api string, limit int) (blocks []report.CodeBlock, sites int) {
	all := ix.Sites(api)
	keep := relevant(all)
	sites = len(keep) + max(0, ix.Count(api)-len(all)) // the sites beyond the cap are counted too
	for _, s := range keep[:min(max(limit, 0), len(keep))] {
		blocks = append(blocks, ix.Block(s, DefaultBefore, DefaultAfter))
	}
	return blocks, sites
}

// relevant keeps the sites that are places where an import is called or used:
// everything but the stub that only jumps through the slot (it is not a use of
// its own: the code that calls the stub is) and, when the import is also called
// or jumped to, the plain loads of its slot.
func relevant(all []Site) []Site {
	callLike := false
	for _, s := range all {
		callLike = callLike || s.Kind == KindCall || s.Kind == KindCallThunk || s.Kind == KindJumpThunk || s.Kind == KindJump
	}
	var keep []Site
	for _, s := range all {
		if s.Kind == KindThunk || (s.Kind == KindLoad && callLike) {
			continue
		}
		keep = append(keep, s)
	}
	return keep
}
