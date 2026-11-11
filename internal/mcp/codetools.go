package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/codeview"
	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
)

// source lends the opened file to the code view engine.
func (f *openedFile) source() codeview.Source {
	return codeview.Source{R: f.File, Size: f.size, Name: f.name}
}

// codeResult is the payload of read_bytes and disassemble: the window as a code
// block, the file it came from and where to continue.
type codeResult struct {
	File report.File `json:"file"`
	// Start says how a disassembly chose its first instruction.
	Start string `json:"start,omitempty"`
	// Length is the number of bytes a read_bytes window holds.
	Length int              `json:"length,omitempty"`
	Code   report.CodeBlock `json:"code"`
	// Next is where the following window starts, present when the data goes on.
	Next *codePosition `json:"next,omitempty"`
}

// codePosition is a place in a file: the offset and, when the file is an image
// that maps it, the virtual address.
type codePosition struct {
	Offset  int64       `json:"offset"`
	Address report.Addr `json:"address,omitempty"`
}

// codeSteps is the order in which a window gives up lines while the text
// exceeds the output cap.
func codeSteps() []trimStep {
	var steps []trimStep
	for _, n := range []int{200, 128, 64, 32, 16, 8, 4, 2, 1} {
		steps = append(steps, capArrayAt(n, "code", "lines"))
	}
	return steps
}

// codeFinisher decorates a window result after trimming: the number of bytes
// shown, where to continue, and which lists were cut. lines are the lines the
// window had before any trimming; more says whether data followed the last of
// them; mapped says whether the lines carry virtual addresses; withLength asks
// for the "length" member (read_bytes).
func codeFinisher(lines []report.CodeLine, more, mapped, withLength bool, note string) func(*node, []trimNote) {
	return func(root *node, notes []trimNote) {
		root.delKey("next")
		if kept := root.at("code", "lines"); kept != nil && len(kept.kids) > 0 && len(lines) > 0 {
			n := min(len(kept.kids), len(lines))
			last := lines[n-1]
			size := int64(byteCount(last.Bytes))
			end := last.Offset + size
			if withLength {
				root.setKey("length", int64Node(end-lines[0].Offset))
			}
			if n < len(lines) || more {
				next := &node{kind: kindObject}
				next.setKey("offset", int64Node(end))
				if mapped {
					// The address of the byte after the last line: lines of a mapped window carry one.
					next.setKey("address", stringNode((last.Address + report.Addr(size)).String()))
				}
				root.setKey("next", next)
				if code := root.child("code"); code != nil {
					code.setKey("truncated", boolNode(true))
				}
			}
		}
		root.setKey("truncated", boolNode(len(notes) > 0))
		root.delKey("trimmed")
		root.delKey("note")
		if len(notes) > 0 {
			root.setKey("trimmed", notesNode(notes))
			root.setKey("note", stringNode(note))
		}
	}
}

// byteCount is the number of bytes a hex column such as "ff 15 b7" holds.
func byteCount(hexColumn string) int {
	if hexColumn == "" {
		return 0
	}
	return (len(hexColumn) + 1) / 3
}

// codeError turns an error of the code view engine into a tool error: a request
// it cannot serve is written for the caller, anything else is a read failure.
func codeError(err error) error {
	if codeview.IsRequestError(err) {
		return userErrorf("%s", err.Error())
	}
	return fmt.Errorf("reading the file: %w", err)
}

// readBytes implements the read_bytes tool.
func (s *server) readBytes(_ context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path   *string `json:"path"`
		Offset *int64  `json:"offset"`
		Length *int    `json:"length"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	offset, err := int64Arg(a.Offset, "offset", 0, 0, math.MaxInt64)
	if err != nil {
		return nil, err
	}
	length, err := intArg(a.Length, "length", hexdump.DefaultWindow, 1, hexdump.MaxWindow)
	if err != nil {
		return nil, err
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	win, err := codeview.Hex(f.source(), offset, length)
	if err != nil {
		return nil, codeError(err)
	}
	res := codeResult{File: report.File{Name: f.name, Size: f.size}, Length: win.Length, Code: win.Block}
	tree, err := treeOf(res)
	if err != nil {
		return nil, err
	}
	finish := codeFinisher(win.Block.Lines, win.More, false, true, "The window was shortened to fit the server's output cap; continue from \"next\".")
	return &toolOutput{tree: tree, spec: fitSpec{onCap: codeSteps(), finish: finish}}, nil
}

// disassemble implements the disassemble tool.
func (s *server) disassemble(_ context.Context, raw json.RawMessage) (*toolOutput, error) {
	var a struct {
		Path    *string `json:"path"`
		Address *string `json:"address"`
		Offset  *int64  `json:"offset"`
		Count   *int    `json:"count"`
		Arch    *string `json:"arch"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	path, err := requireString(a.Path, "path")
	if err != nil {
		return nil, err
	}
	count, err := intArg(a.Count, "count", codeview.DefaultInstructions, 1, codeview.MaxInstructions)
	if err != nil {
		return nil, err
	}
	req := codeview.Request{Count: count}
	if a.Arch != nil {
		if *a.Arch != codeview.ArchX86 && *a.Arch != codeview.ArchX8664 {
			return nil, userErrorf("argument %q must be %q or %q (got %q)", "arch", codeview.ArchX86, codeview.ArchX8664, binio.Printable(*a.Arch, 40))
		}
		req.Arch = *a.Arch
	}
	if a.Address != nil && a.Offset != nil {
		return nil, userErrorf("give either argument %q or argument %q, not both", "address", "offset")
	}
	if a.Address != nil {
		addr, perr := codeview.ParseNumber(*a.Address)
		if perr != nil {
			return nil, userErrorf("argument %q: %s", "address", perr)
		}
		req.Addr, req.HasAddr = addr, true
	}
	if a.Offset != nil {
		off, oerr := int64Arg(a.Offset, "offset", 0, 0, math.MaxInt64)
		if oerr != nil {
			return nil, oerr
		}
		req.Offset, req.HasOffset = off, true
	}
	f, err := s.roots.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d, err := codeview.Disassemble(f.source(), req)
	if err != nil {
		return nil, codeError(err)
	}
	res := codeResult{File: report.File{Name: f.name, Size: f.size}, Start: d.Start, Code: d.Block}
	if d.More {
		res.Next = &codePosition{Offset: d.NextOffset}
		if d.HasNextAddr {
			res.Next.Address = report.Addr(d.NextAddr)
		}
	}
	tree, err := treeOf(res)
	if err != nil {
		return nil, err
	}
	finish := codeFinisher(d.Block.Lines, d.More, d.HasNextAddr, false, "The listing was shortened to fit the server's output cap; continue from \"next\".")
	return &toolOutput{tree: tree, spec: fitSpec{onCap: codeSteps(), finish: finish}}, nil
}
