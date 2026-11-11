package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/codeview"
	"github.com/q6r/teardown/internal/hexdump"
	"github.com/q6r/teardown/internal/report"
)

func hexdumpCommand() command {
	return command{
		name:    "hexdump",
		summary: "Show a hex and ASCII window of the raw bytes of a file",
		args:    "<file>",
		long: `Prints a bounded window of the bytes of a file, 16 bytes a row: the file offset,
the hex digits and the printable ASCII characters. The window starts at --at (a
file offset, decimal or 0x hex) and holds --length bytes (at most 4096). Stdout
carries only the rows; a line on stderr says where the window ended and how to
continue. The file is read, never executed.`,
		examples: []string{
			"teardown hexdump app.exe",
			"teardown hexdump app.exe --at 0x400 -n 256",
			"teardown hexdump app.exe --at 0x1a40 --json        # the window as a JSON code block",
		},
		register: func(f *flagSet) runner {
			var o struct {
				at     string
				length int
				json   bool
			}
			f.Group("Window")
			f.String(&o.at, "at", "", "OFFSET", "0", "File offset to start at, decimal or 0x hex")
			f.Int(&o.length, "length", "n", "LEN", hexdump.DefaultWindow, fmt.Sprintf("Bytes to show, 1 to %d", hexdump.MaxWindow))
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print the window as a JSON code block (kind hex) instead of rows")

			return func(_ context.Context, env Env, pos []string) int {
				if len(pos) != 1 {
					return usageError(env, "hexdump", "expected exactly one file, got %d", len(pos))
				}
				if o.length < 1 || o.length > hexdump.MaxWindow {
					return usageError(env, "hexdump", "--length must be between 1 and %d", hexdump.MaxWindow)
				}
				at, err := parseOffset(o.at)
				if err != nil {
					return usageError(env, "hexdump", "--at: %v", err)
				}
				file, size, err := openRegular(pos[0])
				if err != nil {
					return failure(env, "hexdump", err)
				}
				defer file.Close()
				w, err := codeview.Hex(codeview.Source{R: file, Size: size, Name: filepath.Base(pos[0])}, at, o.length)
				if err != nil {
					return failure(env, "hexdump", err)
				}
				if o.json {
					if err := writeJSON(env.Stdout, w.Block); err != nil {
						return failure(env, "hexdump", fmt.Errorf("writing output: %w", err))
					}
					return exitOK
				}
				if _, err := io.WriteString(env.Stdout, hexdump.Format(w.Rows)); err != nil {
					return failure(env, "hexdump", fmt.Errorf("writing output: %w", err))
				}
				// The summary goes to stderr so stdout stays pipeable.
				end := "end of file"
				if w.More {
					end = fmt.Sprintf("continue with --at 0x%x", w.Next)
				}
				fmt.Fprintf(env.Stderr, "%d bytes shown (file offsets 0x%x to 0x%x of %d); %s\n", w.Length, at, w.Next-1, size, end)
				return exitOK
			}
		},
	}
}

func disasmCommand() command {
	return command{
		name:    "disasm",
		summary: "Disassemble x86 and x86-64 code at an address or a file offset",
		args:    "<file>",
		long: `Decodes a window of instructions in Intel syntax, starting at a virtual address
(--at, mapped through the section table of a PE or Mach-O image or the program
headers of an ELF image) or at a file offset (--offset). Without either it starts
at the entry point, or at the first byte of a file that has none. The instruction
set comes from the file header; name it with --arch for raw bytes or to override
the header. Other instruction sets (ARM64 included) are not supported.

In a PE image, a call or jump through the import table ends with a note that
names the import (; KERNEL32.dll!VirtualAllocEx), the same note the findings and
xrefs show, and a reference to data names the section it lands in.

It is a linear sweep: data can be shown as code and the sweep can lose sync. It
is not a decompiler, and the file is read, never executed. The header lines of
the listing start with ";" and say what the window is.`,
		examples: []string{
			"teardown disasm app.exe                              # from the entry point",
			"teardown disasm app.exe --at 0x140001030 -n 40",
			"teardown disasm app.exe --offset 0x430",
			"teardown disasm shellcode.bin --arch x86-64          # raw bytes from the start",
			"teardown disasm app.exe --at 0x140001030 --json      # the window as a JSON code block",
		},
		register: func(f *flagSet) runner {
			var o struct {
				at, offset, arch string
				count            int
				json             bool
			}
			f.Group("Position")
			f.String(&o.at, "at", "", "ADDR", "", "Virtual address to start at, decimal or 0x hex (an address of the image, as the report shows it)")
			f.String(&o.offset, "offset", "", "OFFSET", "", "File offset to start at, decimal or 0x hex")
			f.Int(&o.count, "count", "n", "N", codeview.DefaultInstructions, fmt.Sprintf("Instructions to decode, 1 to %d", codeview.MaxInstructions))
			f.Group("Architecture")
			f.String(&o.arch, "arch", "", "ARCH", "", "Instruction set: x86 or x86-64 (default: from the file header)", codeview.ArchX86, codeview.ArchX8664)
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print the window as a JSON code block (kind disasm) instead of a listing")

			return func(_ context.Context, env Env, pos []string) int {
				if len(pos) != 1 {
					return usageError(env, "disasm", "expected exactly one file, got %d", len(pos))
				}
				if o.count < 1 || o.count > codeview.MaxInstructions {
					return usageError(env, "disasm", "--count must be between 1 and %d", codeview.MaxInstructions)
				}
				if o.arch != "" && o.arch != codeview.ArchX86 && o.arch != codeview.ArchX8664 {
					return usageError(env, "disasm", "--arch must be %s or %s, not %q", codeview.ArchX86, codeview.ArchX8664, o.arch)
				}
				req := codeview.Request{Count: o.count, Arch: o.arch}
				if f.Given("at") && f.Given("offset") {
					return usageError(env, "disasm", "choose one of --at and --offset")
				}
				if f.Given("at") {
					addr, err := codeview.ParseNumber(o.at)
					if err != nil {
						return usageError(env, "disasm", "--at: %v", err)
					}
					req.Addr, req.HasAddr = addr, true
				}
				if f.Given("offset") {
					off, err := parseOffset(o.offset)
					if err != nil {
						return usageError(env, "disasm", "--offset: %v", err)
					}
					req.Offset, req.HasOffset = off, true
				}
				file, size, err := openRegular(pos[0])
				if err != nil {
					return failure(env, "disasm", err)
				}
				defer file.Close()
				d, err := codeview.Disassemble(codeview.Source{R: file, Size: size, Name: filepath.Base(pos[0])}, req)
				if err != nil {
					return failure(env, "disasm", err)
				}
				var werr error
				if o.json {
					werr = writeJSON(env.Stdout, d.Block)
				} else {
					werr = writeListing(env.Stdout, filepath.Base(pos[0]), d)
				}
				if werr != nil {
					return failure(env, "disasm", fmt.Errorf("writing output: %w", werr))
				}
				return exitOK
			}
		},
	}
}

// parseOffset parses a file offset: decimal or 0x hexadecimal, at most the
// largest int64.
func parseOffset(s string) (int64, error) {
	v, err := codeview.ParseNumber(s)
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("%q is not a file offset: the largest is %d", binio.Printable(s, 40), int64(math.MaxInt64))
	}
	return int64(v), nil // v <= MaxInt64
}

// openRegular opens path for reading. Like the analysis it takes regular files
// only, and it never echoes a file name without making it printable.
func openRegular(path string) (*os.File, int64, error) {
	shown := binio.Printable(path, 200)
	f, err := os.Open(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the file name is shown below, made printable
		}
		return nil, 0, fmt.Errorf("cannot open %s: %w", shown, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("cannot read the metadata of %s: %w", shown, err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("%s is not a regular file", shown)
	}
	return f, st.Size(), nil
}

// writeListing prints a disassembly as an assembly-style listing: header lines
// that start with ";" (what the window is, then its limits), one row per
// instruction with the address, the bytes and the text, and a pointer to the
// next window when more code follows.
func writeListing(w io.Writer, name string, d *codeview.Disassembly) error {
	b := d.Block
	var sb strings.Builder
	where := fmt.Sprintf("file offset 0x%x", b.Offset)
	if d.HasNextAddr { // set exactly when the addresses are those of an image
		where = fmt.Sprintf("0x%x (file offset 0x%x)", uint64(b.Address), b.Offset)
	}
	if d.Start == codeview.StartEntry {
		where = "the entry point " + where
	}
	section := ""
	if b.Section != "" {
		section = ", section " + b.Section
	}
	count := fmt.Sprintf("%d instructions", len(b.Lines))
	if len(b.Lines) == 1 {
		count = "1 instruction"
	}
	fmt.Fprintf(&sb, "; %s: %s, %s%s, %s from %s\n", binio.Printable(name, 200), d.Image.Kind(), b.Arch, section, count, where)
	for _, l := range b.Limitations {
		fmt.Fprintf(&sb, "; %s\n", l)
	}

	addrs := make([]string, len(b.Lines))
	addrW, bytesW := 0, 0
	for i, l := range b.Lines {
		a := uint64(l.Offset) // offsets are never negative
		if d.HasNextAddr {
			a = uint64(l.Address)
		}
		addrs[i] = fmt.Sprintf("0x%x", a)
		addrW, bytesW = max(addrW, len(addrs[i])), max(bytesW, len(l.Bytes))
	}
	for i, l := range b.Lines {
		fmt.Fprintf(&sb, "%-*s  %-*s  %s", addrW, addrs[i], bytesW, l.Bytes, l.Text)
		if l.Note != "" {
			// What a call, a jump or a data reference points at, as the findings word it.
			fmt.Fprintf(&sb, "  ; %s", binio.Printable(l.Note, report.MaxCodeLineChars))
		}
		sb.WriteByte('\n')
	}
	if d.More {
		if d.HasNextAddr {
			fmt.Fprintf(&sb, "; more code follows: continue with --at 0x%x\n", d.NextAddr)
		} else {
			fmt.Fprintf(&sb, "; more code follows: continue with --offset 0x%x\n", d.NextOffset)
		}
	}
	_, err := io.WriteString(w, sb.String())
	return err
}
