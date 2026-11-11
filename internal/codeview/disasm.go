package codeview

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/disasm"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/xref"
)

// How a window found its first instruction ([Disassembly].Start).
const (
	StartAddress = "address"
	StartOffset  = "offset"
	StartEntry   = "entry point"
	StartFile    = "start of file"
)

// maxRanges is how many mapped ranges an error message lists.
const maxRanges = 6

// Request says where to start decoding and how much to decode. At most one of
// HasAddr and HasOffset is set; with neither the window starts at the entry
// point of the image, or at the first byte of a file that has none.
type Request struct {
	// Addr is a virtual address, valid when HasAddr is set. It is looked up in
	// the section table (PE, Mach-O) or the program headers (ELF).
	Addr    uint64
	HasAddr bool
	// Offset is a file offset, valid when HasOffset is set.
	Offset    int64
	HasOffset bool
	// Count is the number of instructions to decode: [DefaultInstructions] when
	// it is not positive, at most [MaxInstructions].
	Count int
	// Arch forces the instruction set ([ArchX86] or [ArchX8664]); empty takes it
	// from the header of the file.
	Arch string
}

// Disassembly is a window of decoded instructions.
type Disassembly struct {
	// Block is the window as a code block: Address and the line addresses are
	// set when the start lies in an addressable part of an image, and are left
	// empty (every address is then a file offset) otherwise.
	Block report.CodeBlock
	// Image is what the headers of the file say.
	Image Image
	// Start says how the first instruction was chosen: one of the Start constants.
	Start string
	// More is true when decodable bytes follow the last instruction.
	More bool
	// NextAddr is the address of the byte after the window, valid when HasNextAddr
	// is set; NextOffset is its file offset.
	NextAddr    uint64
	HasNextAddr bool
	NextOffset  int64
}

// Disassemble decodes the instructions at the start the request names. It reads
// at most Count*15 bytes, never past the end of the section (or segment) that
// holds the start, and never executes anything.
//
// A request it cannot serve is a [RequestError]: an address that no section
// holds, an offset outside the file, a file for an instruction set other than
// x86 or x86-64 (unless the request names one), a start given twice.
func Disassemble(src Source, req Request) (*Disassembly, error) {
	if req.HasAddr && req.HasOffset {
		return nil, requestErrorf("give either an address or a file offset, not both")
	}
	if src.Size <= 0 {
		return nil, requestErrorf("the file is empty: there is nothing to disassemble")
	}
	count := req.Count
	if count <= 0 {
		count = DefaultInstructions
	}
	count = min(count, MaxInstructions)

	im := Detect(src.R, src.Size)
	arch, forced, err := chooseArch(im, req.Arch)
	if err != nil {
		return nil, err
	}
	mode := disasm.Mode64
	if arch == ArchX86 {
		mode = disasm.Mode32
	}

	var (
		seg    Segment
		mapped bool
		off    int64
		addr   uint64
		start  string
	)
	switch {
	case req.HasAddr:
		start = StartAddress
		s, o, ok := im.AtAddress(req.Addr)
		if !ok {
			return nil, addressError(im, req.Addr)
		}
		seg, mapped, off, addr = s, true, o, req.Addr
	case req.HasOffset:
		start = StartOffset
		if req.Offset < 0 || req.Offset >= src.Size {
			return nil, requestErrorf("file offset %d is outside the file (%s)", req.Offset, sizeText(src.Size))
		}
		off = req.Offset
		if s, a, ok := im.AtOffset(off); ok {
			seg, mapped, addr = s, true, a
		}
	case im.HasEntry:
		start = StartEntry
		s, o, ok := im.AtAddress(im.Entry)
		if !ok {
			return nil, requestErrorf("the entry point 0x%x is not inside any section or segment that holds data (a packed or damaged file?): give an address or a file offset", im.Entry)
		}
		seg, mapped, off, addr = s, true, o, im.Entry
	default:
		start = StartFile
	}
	if !mapped {
		addr = uint64(off) // off is not negative, so the conversion is exact
	}

	avail := src.Size - off
	if mapped {
		avail = seg.Offset + seg.Length - off
	}
	buf, err := binio.ReadAt(src.R, src.Size, off, min(avail, int64(count)*disasm.MaxInstLen))
	if err != nil {
		return nil, fmt.Errorf("reading the code at file offset %d: %w", off, err)
	}
	insts := disasm.DecodeAll(mode, buf, addr, count)

	// A PE image names what its instructions refer to, with the words the findings
	// use: the import behind a slot or a thunk, the section behind a data reference.
	// The notes need the addresses of the image and the instruction set it declares.
	var notes *xref.Annotator
	if mapped && !forced && im.layout != nil {
		notes, _ = xref.NewAnnotator(src.R, src.Size, *im.layout) // fails only for another instruction set, which chooseArch refused
	}

	lines := make([]report.CodeLine, len(insts))
	pos := off
	for i, in := range insts {
		lines[i] = report.CodeLine{Offset: pos, Bytes: hexBytes(in.Bytes), Text: in.Text}
		if mapped {
			lines[i].Address = report.Addr(in.Addr)
		}
		if notes != nil {
			lines[i].Note = clipNote(notes.Note(in))
		}
		pos += int64(in.Len)
	}
	consumed := pos - off

	d := &Disassembly{Image: im, Start: start, More: consumed < avail, NextOffset: pos}
	d.NextAddr, d.HasNextAddr = addr+uint64(consumed), mapped // consumed is not negative

	where := fmt.Sprintf("file offset 0x%x", off)
	if mapped {
		where = fmt.Sprintf("0x%x", addr)
	}
	d.Block = report.CodeBlock{
		Kind:        report.CodeKindDisasm,
		Title:       fmt.Sprintf("%s: disassembly at %s", printable(src.Name, maxNameChars), where),
		Section:     seg.Name,
		Offset:      off,
		Arch:        arch,
		Lines:       lines,
		Truncated:   d.More,
		Limitations: limitations(im, arch, forced, seg, mapped),
	}
	if mapped {
		d.Block.Address = report.Addr(addr)
	}
	return d, nil
}

// chooseArch picks the instruction set to decode with. forced is true when the
// request overrides what the header of the file declares.
func chooseArch(im Image, requested string) (arch string, forced bool, err error) {
	switch requested {
	case ArchX86, ArchX8664:
		return requested, im.Arch != "" && im.Arch != requested, nil
	case "":
	default:
		return "", false, requestErrorf("unknown architecture %q: use %s or %s", printable(requested, 40), ArchX86, ArchX8664)
	}
	switch im.Arch {
	case ArchX86, ArchX8664:
		return im.Arch, false, nil
	case "":
		return "", false, requestErrorf("cannot tell the instruction set of this file (it is not a PE, ELF or Mach-O image): name it, %s or %s", ArchX86, ArchX8664)
	}
	return "", false, requestErrorf("this file is %s: only x86 and x86-64 code can be disassembled, other instruction sets are not supported", im.Label())
}

// addressError explains an address that no segment holds and lists where the
// addresses of the file are.
func addressError(im Image, addr uint64) error {
	if len(im.Segments) == 0 {
		return requestErrorf("this file has no address map this tool can read (it is %s): give a file offset instead", im.Label())
	}
	var ranges []string
	for i, s := range im.Segments {
		if i == maxRanges {
			ranges = append(ranges, "...")
			break
		}
		ranges = append(ranges, fmt.Sprintf("%s 0x%x-0x%x", s.Name, s.Addr, s.Addr+uint64(s.Length)-1)) // Length > 0
	}
	return requestErrorf("address 0x%x is not inside any section or segment that holds data in this file; mapped ranges: %s", addr, strings.Join(ranges, ", "))
}

// limitations lists what the reader of a disassembly must keep in mind.
func limitations(im Image, arch string, forced bool, seg Segment, mapped bool) []string {
	out := []string{limitSweep, limitScope}
	if mapped && !seg.Exec {
		out = append(out, fmt.Sprintf("The section %s is not marked as holding code: these bytes are probably data.", seg.Name))
	}
	if forced {
		out = append(out, fmt.Sprintf("The header of the file says %s; the instruction set was set to %s by the request.", im.Arch, arch))
	}
	if !mapped {
		out = append(out, "No address map applies here: the addresses shown are file offsets.")
	}
	return out
}

// clipNote shortens a note to the length a code line may carry, ending with an
// ellipsis. A note is made of names taken from the file, which are already printable.
func clipNote(s string) string {
	if utf8.RuneCountInString(s) <= report.MaxCodeLineChars {
		return s
	}
	return string([]rune(s)[:report.MaxCodeLineChars-1]) + "…"
}

// hexBytes renders bytes as hex pairs separated by single spaces.
func hexBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, digits[v>>4], digits[v&15])
	}
	return string(out)
}
