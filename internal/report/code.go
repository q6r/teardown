package report

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kinds of code block (CodeBlock.Kind).
const (
	// CodeKindDisasm is a window of disassembled instructions.
	CodeKindDisasm = "disasm"
	// CodeKindHex is a hex and ASCII window over raw bytes.
	CodeKindHex = "hex"
	// CodeKindSource is a run of source lines with their line numbers.
	CodeKindSource = "source"
)

// Caps on code evidence. A producer applies them when it builds the blocks and
// every renderer applies them again (see [Finding.ClippedCode]), so a report
// that came from somewhere else cannot make an output grow without bound.
const (
	// MaxCodeBlocks is the most code blocks one finding carries.
	MaxCodeBlocks = 12
	// MaxCodeLines is the most lines one block carries.
	MaxCodeLines = 64
	// MaxCodeLineChars is the most characters in the text or the note of one line.
	MaxCodeLineChars = 200
	// MaxCodeLabelChars is the most characters in a block's title, file, section or arch.
	MaxCodeLabelChars = 200
	// MaxCodeLimitations is the most limitations one block carries.
	MaxCodeLimitations = 8
	// MaxCodeLimitationChars is the most characters in one limitation.
	MaxCodeLimitationChars = 400

	// maxCodeBytesChars is the width of one hex dump row: 16 bytes as "xx xx ... xx".
	maxCodeBytesChars = 3*16 - 1
)

// NoLimitsStated is the limitation a renderer shows for a block whose producer
// stated none, so that no block is ever shown without its limits.
const NoLimitsStated = "The producer of this block stated no limits: treat it as a partial, unverified view of the file."

// Addr is a virtual address. It is written to JSON as a string such as
// "0x140001042", because a JavaScript number cannot hold every 64-bit value, and
// it is read back from that form only: a JSON number, a decimal string, a string
// without the 0x prefix, an empty digit run or more than 16 digits is an error.
type Addr uint64

// String returns the address as 0x followed by lower-case hexadecimal digits.
func (a Addr) String() string { return "0x" + strconv.FormatUint(uint64(a), 16) }

// MarshalText implements [encoding.TextMarshaler]; encoding/json writes the result as a JSON string.
func (a Addr) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements [encoding.TextUnmarshaler]. A value it rejects leaves
// *a unchanged.
func (a *Addr) UnmarshalText(text []byte) error {
	s := string(text)
	digits, ok := strings.CutPrefix(s, "0x")
	if !ok {
		digits, ok = strings.CutPrefix(s, "0X")
	}
	if !ok || digits == "" || len(digits) > 16 {
		return fmt.Errorf("invalid address %q: want 0x followed by 1 to 16 hexadecimal digits", clipChars(s, 40))
	}
	v, err := strconv.ParseUint(digits, 16, 64) // base 16 refuses signs and underscores
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", clipChars(s, 40), err)
	}
	*a = Addr(v)
	return nil
}

// CodeBlock is one piece of code that backs a finding: a window of
// instructions around a call site, a hex window or a few source lines. Every
// block states its limits: a linear sweep can decode data as code, only the x86
// family is understood and nothing here is a decompilation.
type CodeBlock struct {
	// Kind is one of the CodeKind* constants.
	Kind  string `json:"kind"`
	Title string `json:"title,omitempty"`
	// File is the path inside a container (zip, asar) when the block comes from one.
	File string `json:"file,omitempty"`
	// Section names the section of a binary the block lies in.
	Section string `json:"section,omitempty"`
	// Offset is the file offset of the first line.
	Offset int64 `json:"offset"`
	// Address is the virtual address of the first line (disassembly).
	Address Addr `json:"address,omitempty"`
	// Arch is the instruction set of a disassembly: "x86-64" or "x86".
	Arch  string     `json:"arch,omitempty"`
	Lines []CodeLine `json:"lines"`
	// Truncated is true when the block was cut and the code goes on beyond its last line.
	Truncated bool `json:"truncated,omitempty"`
	// Limitations says what the block cannot show; it is never empty.
	Limitations []string `json:"limitations"`
}

// CodeLine is one line of a [CodeBlock].
type CodeLine struct {
	// Address is the virtual address of the line (disassembly).
	Address Addr `json:"address,omitempty"`
	// Offset is the file offset of the line.
	Offset int64 `json:"offset"`
	// Bytes holds the encoded bytes as hex pairs separated by spaces, "ff 15 b7 1f 00 00".
	Bytes string `json:"bytes,omitempty"`
	// Text is the instruction, the ASCII column of a hex row or the source line.
	Text string `json:"text"`
	// Note explains the line, for example "KERNEL32.dll!VirtualAllocEx".
	Note string `json:"note,omitempty"`
	// Highlight marks the line the finding is about.
	Highlight bool `json:"highlight,omitempty"`
	// Line is the 1-based source line number (kind "source").
	Line int `json:"line,omitempty"`
}

// Validate checks b against the rules every producer follows: a known kind, a
// non-negative offset, at least one and at most [MaxCodeLines] lines, line text
// and labels of bounded length without control characters, well-formed hex
// bytes, source lines that carry their number, and at least one limitation.
func (b *CodeBlock) Validate() error {
	switch b.Kind {
	case CodeKindDisasm, CodeKindHex, CodeKindSource:
	default:
		return fmt.Errorf("unknown code block kind %q", clipChars(b.Kind, 24))
	}
	if b.Offset < 0 {
		return fmt.Errorf("negative offset %d", b.Offset)
	}
	for _, f := range [...]struct{ name, value string }{{"title", b.Title}, {"file", b.File}, {"section", b.Section}, {"arch", b.Arch}} {
		if err := checkText(f.name, f.value, MaxCodeLabelChars); err != nil {
			return err
		}
	}
	if len(b.Lines) == 0 {
		return errors.New("a code block needs at least one line")
	}
	if len(b.Lines) > MaxCodeLines {
		return fmt.Errorf("%d lines, at most %d", len(b.Lines), MaxCodeLines)
	}
	for i := range b.Lines {
		if err := b.Lines[i].validate(b.Kind); err != nil {
			return fmt.Errorf("line %d: %w", i, err)
		}
	}
	if len(b.Limitations) == 0 {
		return errors.New("a code block always states its limitations")
	}
	if len(b.Limitations) > MaxCodeLimitations {
		return fmt.Errorf("%d limitations, at most %d", len(b.Limitations), MaxCodeLimitations)
	}
	for i, l := range b.Limitations {
		if strings.TrimSpace(l) == "" {
			return fmt.Errorf("limitation %d is blank", i)
		}
		if err := checkText("limitation", l, MaxCodeLimitationChars); err != nil {
			return fmt.Errorf("limitation %d: %w", i, err)
		}
	}
	return nil
}

func (l *CodeLine) validate(kind string) error {
	if l.Offset < 0 {
		return fmt.Errorf("negative offset %d", l.Offset)
	}
	if l.Line < 0 || (kind == CodeKindSource && l.Line == 0) {
		return fmt.Errorf("line number %d: a source line is numbered from 1", l.Line)
	}
	if err := checkText("text", l.Text, MaxCodeLineChars); err != nil {
		return err
	}
	if err := checkText("note", l.Note, MaxCodeLineChars); err != nil {
		return err
	}
	if !validHexBytes(l.Bytes) {
		return fmt.Errorf("bytes %q: want at most 16 hex pairs separated by single spaces", clipChars(l.Bytes, 60))
	}
	return nil
}

// ValidateCode checks every code block of the finding and the number of blocks.
func (f *Finding) ValidateCode() error {
	if len(f.Code) > MaxCodeBlocks {
		return fmt.Errorf("finding %q has %d code blocks, at most %d", f.ID, len(f.Code), MaxCodeBlocks)
	}
	for i := range f.Code {
		if err := f.Code[i].Validate(); err != nil {
			return fmt.Errorf("finding %q: code block %d: %w", f.ID, i, err)
		}
	}
	return nil
}

// checkText reports a value that is too long, is not valid UTF-8 or contains a
// control character (C0, DEL or C1). Tabs count: a producer expands them.
func checkText(name, s string, maxChars int) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if n := utf8.RuneCountInString(s); n > maxChars {
		return fmt.Errorf("%s has %d characters, at most %d", name, n, maxChars)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains the control character U+%04X", name, r)
		}
	}
	return nil
}

// validHexBytes reports whether s is empty or at most 16 two-digit hex groups
// separated by single spaces.
func validHexBytes(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > maxCodeBytesChars || (len(s)+1)%3 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i%3 == 2 {
			if s[i] != ' ' {
				return false
			}
			continue
		}
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// ClippedCode returns the finding's code blocks reduced to the caps, without
// changing the finding: blocks without lines are dropped, at most
// [MaxCodeBlocks] blocks are kept and each is cut by [CodeBlock.Clipped].
// omitted counts the blocks left out because of the cap; the last block that is
// kept says so in its limitations. It never fails and returns no blocks when
// there is no code.
func (f *Finding) ClippedCode() (blocks []CodeBlock, omitted int) {
	for i := range f.Code {
		if len(f.Code[i].Lines) == 0 {
			continue
		}
		if len(blocks) == MaxCodeBlocks {
			omitted++
			continue
		}
		blocks = append(blocks, f.Code[i].Clipped())
	}
	if omitted > 0 {
		last := &blocks[len(blocks)-1]
		if len(last.Limitations) >= MaxCodeLimitations {
			last.Limitations = last.Limitations[:MaxCodeLimitations-1]
		}
		last.Limitations = append(last.Limitations, fmt.Sprintf("%d more code blocks of this finding were left out of this view.", omitted))
	}
	return blocks, omitted
}

// Clipped returns a copy of b that satisfies the size rules of [CodeBlock.Validate]:
// at most [MaxCodeLines] lines (a long block keeps the window around its first
// highlighted line, is marked Truncated and starts at the first kept line), text
// and labels cut to their caps with an ellipsis, malformed hex bytes shortened
// to their longest valid prefix, bounded limitations, and [NoLimitsStated] when
// there were none. It does not rewrite characters: renderers escape those.
func (b CodeBlock) Clipped() CodeBlock {
	out := b
	out.Title = clipChars(b.Title, MaxCodeLabelChars)
	out.File = clipChars(b.File, MaxCodeLabelChars)
	out.Section = clipChars(b.Section, MaxCodeLabelChars)
	out.Arch = clipChars(b.Arch, MaxCodeLabelChars)
	if out.Offset < 0 {
		out.Offset = 0
	}

	lines := b.Lines
	windowed := false
	if len(lines) > MaxCodeLines {
		start := b.WindowStart(MaxCodeLines)
		lines = lines[start : start+MaxCodeLines]
		out.Truncated, windowed = true, true
	}
	out.Lines = make([]CodeLine, len(lines))
	for i, l := range lines {
		l.Text = clipChars(l.Text, MaxCodeLineChars)
		l.Note = clipChars(l.Note, MaxCodeLineChars)
		l.Bytes = hexPrefix(l.Bytes)
		l.Offset = max(l.Offset, 0)
		l.Line = max(l.Line, 0)
		out.Lines[i] = l
	}
	if windowed {
		out.Offset, out.Address = out.Lines[0].Offset, out.Lines[0].Address
	}

	out.Limitations = make([]string, 0, min(len(b.Limitations), MaxCodeLimitations))
	for _, l := range b.Limitations {
		if strings.TrimSpace(l) != "" && len(out.Limitations) < MaxCodeLimitations {
			out.Limitations = append(out.Limitations, clipChars(l, MaxCodeLimitationChars))
		}
	}
	if len(out.Limitations) == 0 {
		out.Limitations = []string{NoLimitsStated}
	}
	return out
}

// WindowStart returns the index of the first line of a window of n lines over
// the block: the window keeps the first highlighted line (the top of the block
// when no line is highlighted) as near its middle as the bounds allow. It is
// how a view that shows fewer lines than the block holds keeps the flagged line
// in sight. A block of n lines or fewer starts at 0.
func (b CodeBlock) WindowStart(n int) int {
	if n <= 0 || len(b.Lines) <= n {
		return 0
	}
	first := 0
	for i, l := range b.Lines {
		if l.Highlight {
			first = i
			break
		}
	}
	return max(0, min(first-n/2, len(b.Lines)-n))
}

// hexPrefix returns the longest prefix of s that is a valid byte run (at most 16 pairs).
func hexPrefix(s string) string {
	for end := min(len(s), maxCodeBytesChars); end > 0; end-- {
		if validHexBytes(s[:end]) {
			return s[:end]
		}
	}
	return ""
}

// clipChars shortens s to at most n characters, ending with an ellipsis.
func clipChars(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// WithoutCode returns a shallow copy of the report in which no finding carries
// code blocks. It is how a front end honours a request to leave code out of any
// output (JSON, Markdown, HTML, SARIF or the terminal): render the copy.
func (r *Report) WithoutCode() *Report {
	cp := *r
	cp.Findings = make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Code = nil
		cp.Findings[i] = f
	}
	if r.Findings == nil {
		cp.Findings = nil
	}
	return &cp
}
