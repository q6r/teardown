// Package codeview reads bounded windows of raw code out of a file. It is the
// engine behind the hexdump and disasm commands and the read_bytes and
// disassemble MCP tools: a hex and ASCII dump at a file offset, or the x86 or
// x86-64 instructions at a virtual address or a file offset.
//
// A window comes back as a [report.CodeBlock], the same shape the findings use
// for the code behind them, and every block states its limits: the decoding is
// a linear sweep, only the x86 family is understood and nothing is a
// decompilation. The package reads only the bytes of the window and the few
// header fields it needs to map a virtual address of a PE, ELF or Mach-O image
// to a file offset (see [Detect]); a PE is mapped by the layout the PE parser
// builds, the same one the findings use, and its disassembly names the imports
// that calls and jumps go through with the notes of package xref. Nothing is
// executed, emulated or resolved, and every size and count is bounded.
package codeview

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
)

// Instruction sets the decoder understands, as they appear in
// [report.CodeBlock].Arch and in the arch arguments of the commands and tools.
const (
	ArchX86   = "x86"
	ArchX8664 = "x86-64"
)

// Bounds of a window.
const (
	// DefaultInstructions is the number of instructions decoded when a request
	// names none.
	DefaultInstructions = 24
	// MaxInstructions is the most instructions one window holds.
	MaxInstructions = 256
)

// Limits every block states about itself.
const (
	limitSweep = "Linear sweep: the bytes are decoded one after another, so data can be shown as code and the sweep can lose sync."
	limitScope = "x86 and x86-64 only; bytes that are not understood are shown as db. Not a decompiler: nothing is executed, emulated or resolved."
	limitHex   = "Raw bytes as stored in the file: they show what is there, not what it means. Packed or encrypted data looks like noise."
	// maxNameChars bounds the file name used in titles.
	maxNameChars = 80
)

// Source is the file a window is read from.
type Source struct {
	// R reads the file; only the bytes of the window are ever requested.
	R io.ReaderAt
	// Size is the length of the file in bytes.
	Size int64
	// Name is the name shown in titles. It is made printable before use.
	Name string
}

// RequestError reports a request that cannot be served as asked: an offset or
// an address outside the file, an architecture that is not x86, a start given
// twice. Its message is written for the person or the agent who made the
// request and never repeats bytes of the file. Other errors come from reading
// the file.
type RequestError struct{ msg string }

// Error returns the message written for the caller.
func (e *RequestError) Error() string { return e.msg }

func requestErrorf(format string, a ...any) error {
	return &RequestError{msg: fmt.Sprintf(format, a...)}
}

// IsRequestError reports whether err is, or wraps, a [RequestError].
func IsRequestError(err error) bool {
	var re *RequestError
	return errors.As(err, &re)
}

// ParseNumber parses an address or an offset written as decimal digits or as
// 0x followed by hexadecimal digits. Signs, underscores, octal and binary forms
// are refused so that a leading zero never changes the base.
func ParseNumber(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	digits, base := t, 10
	if rest, ok := strings.CutPrefix(t, "0x"); ok {
		digits, base = rest, 16
	} else if rest, ok := strings.CutPrefix(t, "0X"); ok {
		digits, base = rest, 16
	}
	if digits == "" {
		return 0, fmt.Errorf("%q is not a number: write decimal digits or 0x and hexadecimal digits", printable(s, 40))
	}
	v, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("%q is too large: the largest value is 0xffffffffffffffff", printable(s, 40))
		}
		return 0, fmt.Errorf("%q is not a number: write decimal digits or 0x and hexadecimal digits", printable(s, 40))
	}
	return v, nil
}

// HexWindow is a hex and ASCII window of a file.
type HexWindow struct {
	// Block holds one line per row of 16 bytes: Offset is the file offset of the
	// row, Bytes the hex column and Text the ASCII column.
	Block report.CodeBlock
	// Rows are the same rows with absolute file offsets, ready for [hexdump.Format].
	Rows []hexdump.Row
	// Length is the number of bytes shown.
	Length int
	// Next is the file offset of the first byte after the window.
	Next int64
	// More is true when bytes of the file follow the window.
	More bool
}

// Hex returns the window of n bytes (hexdump.DefaultWindow when n <= 0, at most
// hexdump.MaxWindow) that starts at the file offset. The window is cut short by
// the end of the file. An offset outside the file, and any offset into an empty
// file, is a [RequestError].
func Hex(src Source, offset int64, n int) (*HexWindow, error) {
	if offset < 0 || offset >= src.Size {
		return nil, requestErrorf("file offset %d is outside the file (%s)", offset, sizeText(src.Size))
	}
	if n <= 0 {
		n = hexdump.DefaultWindow
	}
	got := min(int64(n), hexdump.MaxWindow, src.Size-offset)
	data, err := binio.ReadAt(src.R, src.Size, offset, got)
	if err != nil {
		return nil, fmt.Errorf("reading %d bytes at file offset %d: %w", got, offset, err)
	}
	rows, _, err := hexdump.Window(data, 0, int(got)) // got <= MaxWindow, so it fits an int
	if err != nil {
		return nil, fmt.Errorf("laying out the window: %w", err)
	}
	lines := make([]report.CodeLine, len(rows))
	for i := range rows {
		rows[i].Offset += offset
		lines[i] = report.CodeLine{Offset: rows[i].Offset, Bytes: rows[i].Hex, Text: rows[i].ASCII}
	}
	next := offset + got
	more := next < src.Size

	block := report.CodeBlock{
		Kind:        report.CodeKindHex,
		Title:       fmt.Sprintf("%s: bytes at file offset 0x%x", printable(src.Name, maxNameChars), offset),
		Offset:      offset,
		Lines:       lines,
		Truncated:   more,
		Limitations: []string{limitHex},
	}
	if seg, _, ok := detect(src.R, src.Size, false).AtOffset(offset); ok {
		block.Section = seg.Name
	}
	return &HexWindow{Block: block, Rows: rows, Length: int(got), Next: next, More: more}, nil
}

// sizeText describes a file size for an error message.
func sizeText(size int64) string {
	switch size {
	case 0:
		return "the file is empty"
	case 1:
		return "the file has 1 byte"
	}
	return fmt.Sprintf("the file has %d bytes", size)
}

// printable makes a name from the file or from the caller safe to show: control
// characters and invalid UTF-8 become \xNN escapes and the result is cut to max
// characters.
func printable(s string, max int) string { return binio.Printable(s, max) }
