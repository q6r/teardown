package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/codeview"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/xref"
)

const (
	// maxAPIChars bounds the name of the import a user asks about.
	maxAPIChars = 256
	// maxNamedImports is how many called imports an error message names.
	maxNamedImports = 8
)

func xrefsCommand() command {
	return command{
		name:    "xrefs",
		summary: "Show who calls an import: its call sites in a PE image, with the code around each",
		args:    "<file> <api>",
		long: `Finds the places in the executable sections of a PE image (x86 or x86-64) that
call an imported function and shows the instructions around each call, so the way
its arguments are set up is visible. The name is matched as the findings match
API names: with or without the library ("KERNEL32.dll!VirtualAllocEx" or
"VirtualAllocEx"), in any case, with the ANSI and wide spellings together
("CreateProcess" finds CreateProcessA and CreateProcessW). With --list it prints
the imports that have at least one call site instead, with their counts.

It is a linear sweep of the code with a small built-in decoder: data in a code
section can be read as instructions, imports resolved at run time are invisible
and packed code hides its calls. It is not a decompiler, and the file is read,
never executed. ELF, Mach-O and other instruction sets are not supported.`,
		examples: []string{
			"teardown xrefs app.exe VirtualAllocEx",
			"teardown xrefs app.exe kernel32.dll!WriteProcessMemory --before 12 --after 6",
			"teardown xrefs app.exe CreateProcess --max 3",
			"teardown xrefs app.exe --list                    # the imports that are called, with counts",
			"teardown xrefs app.exe VirtualAllocEx --json     # the windows as JSON code blocks",
		},
		register: func(f *flagSet) runner {
			var o struct {
				before, after, max int
				list, json         bool
				color              string
			}
			f.Group("Selection")
			f.Int(&o.before, "before", "", "N", xref.DefaultBefore, fmt.Sprintf("Instructions to show before each call, 0 to %d", xref.MaxBefore))
			f.Int(&o.after, "after", "", "N", xref.DefaultAfter, fmt.Sprintf("Instructions to show after each call, 0 to %d", xref.MaxAfter))
			f.Int(&o.max, "max", "", "N", xref.DefaultSites, fmt.Sprintf("Call sites to show, 1 to %d", xref.MaxSites))
			f.Bool(&o.list, "list", "", "List the imports that have call sites, with counts, instead of the sites of one")
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print JSON: the code blocks of the call sites (or, with --list, the imports and their counts)")
			f.String(&o.color, "color", "", "WHEN", "auto", "Colour: auto, always or never (NO_COLOR is honoured)", "auto", "always", "never")

			return func(ctx context.Context, env Env, pos []string) int {
				switch {
				case o.list && len(pos) != 1:
					return usageError(env, "xrefs", "--list takes exactly one file, got %d arguments", len(pos))
				case !o.list && len(pos) != 2:
					return usageError(env, "xrefs", "expected a file and the name of an import (or --list), got %d arguments", len(pos))
				case o.before < 0 || o.before > xref.MaxBefore:
					return usageError(env, "xrefs", "--before must be between 0 and %d", xref.MaxBefore)
				case o.after < 0 || o.after > xref.MaxAfter:
					return usageError(env, "xrefs", "--after must be between 0 and %d", xref.MaxAfter)
				case o.max < 1 || o.max > xref.MaxSites:
					return usageError(env, "xrefs", "--max must be between 1 and %d", xref.MaxSites)
				case o.color != "auto" && o.color != "always" && o.color != "never":
					return usageError(env, "xrefs", "--color must be auto, always or never, not %q", o.color)
				}
				api := ""
				if !o.list {
					api = strings.TrimSpace(pos[1])
					if api == "" {
						return usageError(env, "xrefs", "the name of the import is empty")
					}
					if utf8.RuneCountInString(api) > maxAPIChars {
						return usageError(env, "xrefs", "the name of the import is longer than %d characters", maxAPIChars)
					}
				}

				file, size, err := openRegular(pos[0])
				if err != nil {
					return failure(env, "xrefs", err)
				}
				defer file.Close()
				if im := codeview.Detect(file, size); im.Format != codeview.FormatPE {
					return failure(env, "xrefs", unsupportedImage(im))
				}
				ix, err := xref.Scan(ctx, file, size, limits.ForSize(size), xref.Options{})
				switch {
				case errors.Is(err, xref.ErrUnsupported):
					return failure(env, "xrefs", unsupportedImage(codeview.Detect(file, size)))
				case ix == nil:
					return failure(env, "xrefs", err)
				case err != nil && ctx.Err() != nil:
					return failure(env, "xrefs", errors.New("interrupted"))
				case ix.Imports() == 0:
					return failure(env, "xrefs", errors.New("the image has no imports this tool can resolve (the import table is missing, empty or unreadable), so there are no calls to look for"))
				case !ix.HasCode():
					return failure(env, "xrefs", errors.New("the image has no executable section with bytes in the file, so there is no code to search"))
				}
				for _, n := range ix.Notes() {
					fmt.Fprintf(env.Stderr, "teardown xrefs: note: %s\n", binio.Printable(n, 300))
				}

				ro := render.Options{Color: colorEnabled(o.color, env, env.Stdout), Width: terminalWidth(env)}
				name := filepath.Base(pos[0])
				var werr error
				switch {
				case o.list:
					werr = writeCalledImports(env.Stdout, name, ix, o.json, ro)
				default:
					found := ix.Lookup(api, o.before, o.after, o.max)
					if len(found.Imports) == 0 {
						return failure(env, "xrefs", noSuchImport(api, ix))
					}
					werr = writeFound(env.Stdout, name, ix, found, o.json, ro)
				}
				if werr != nil {
					return failure(env, "xrefs", fmt.Errorf("writing output: %w", werr))
				}
				return exitOK
			}
		},
	}
}

// unsupportedImage explains that the file is not an image xrefs can search.
func unsupportedImage(im codeview.Image) error {
	what := "this file is not a PE image"
	if im.Format != "" {
		what = "this file is " + im.Label()
	}
	return fmt.Errorf("%s: xrefs finds the calls to the imports of PE images for x86 and x86-64 only (ELF, Mach-O, other instruction sets and other file types are not supported)", what)
}

// noSuchImport explains a name that matches no import, and names the imports
// that are called so a misspelling is easy to fix.
func noSuchImport(api string, ix *xref.Index) error {
	msg := `no import of this file matches "` + binio.Printable(api, 80) + `"`
	called := ix.APIs()
	if len(called) == 0 {
		return errors.New(msg + "; none of its imports has a call site in the executable sections")
	}
	var names []string
	for _, a := range called[:min(len(called), maxNamedImports)] {
		names = append(names, binio.Printable(a.Name, 120))
	}
	more := ""
	if len(called) > len(names) {
		more = fmt.Sprintf(" and %d more", len(called)-len(names))
	}
	return fmt.Errorf("%s; imports with call sites include %s%s (teardown xrefs <file> --list shows them all)", msg, strings.Join(names, ", "), more)
}

// calledImport is the JSON form of one entry of --list.
type calledImport struct {
	API       string `json:"api"`
	Library   string `json:"library"`
	Function  string `json:"function"`
	CallSites int    `json:"callSites"`
}

// writeCalledImports prints the imports that have call sites: one per line with
// the number of call sites, or as JSON.
func writeCalledImports(w io.Writer, name string, ix *xref.Index, asJSON bool, ro render.Options) error {
	called := ix.APIs()
	if asJSON {
		out := make([]calledImport, len(called))
		for i, a := range called {
			out[i] = calledImport{API: a.Name, Library: a.Library, Function: a.Function, CallSites: a.Calls}
		}
		return writeJSON(w, out)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", styled(ro.Color, "1", binio.Printable(name, 200)))
	if len(called) == 0 {
		fmt.Fprintf(&sb, "none of the %d imports has a call site in the executable sections (PE %s, linear sweep)\n", ix.Imports(), ix.Arch())
		_, err := io.WriteString(w, sb.String())
		return err
	}
	fmt.Fprintf(&sb, "%d of %d imports have call sites (PE %s, linear sweep of the executable sections)\n\n",
		len(called), ix.Imports(), ix.Arch())
	width := 0
	for _, a := range called {
		width = max(width, utf8.RuneCountInString(binio.Printable(a.Name, 200)))
	}
	for _, a := range called {
		shown := binio.Printable(a.Name, 200)
		fmt.Fprintf(&sb, "  %s%s  %s\n", shown, strings.Repeat(" ", width-utf8.RuneCountInString(shown)), styled(ro.Color, "2", pluralize(a.Calls, "call site")))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// writeFound prints the call sites of the imports a name matched: as JSON, the
// code block of each site; otherwise a heading per site and the same aligned
// rows the report shows under a finding.
func writeFound(w io.Writer, name string, ix *xref.Index, f xref.Found, asJSON bool, ro render.Options) error {
	blocks := make([]report.CodeBlock, len(f.Sites))
	for i, s := range f.Sites {
		blocks[i] = s.Code
	}
	if asJSON {
		return writeJSON(w, blocks)
	}

	shownNames := make([]string, len(f.Imports))
	for i, n := range f.Imports {
		shownNames[i] = binio.Printable(n, 200)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %s\n", styled(ro.Color, "1", binio.Printable(name, 200)), strings.Join(shownNames, ", "))
	if f.Total == 0 {
		sb.WriteString("imported, but no call to it was found in the executable sections: it may be called through a pointer, resolved at run time or hidden by a packer")
		if !ix.Complete() {
			sb.WriteString(", and the scan of the code was cut short at its size limits")
		}
		sb.WriteString("\n")
		_, err := io.WriteString(w, sb.String())
		return err
	}
	shown := ""
	if f.Total > len(f.Sites) {
		shown = fmt.Sprintf(", the first %d shown", len(f.Sites))
	}
	fmt.Fprintf(&sb, "%s%s (PE %s, linear sweep of the executable sections)\n", pluralize(f.Total, "call site"), shown, ix.Arch())

	for i, s := range f.Sites {
		heading := fmt.Sprintf("#%d  %s  0x%x", i+1, s.Kind, s.Addr)
		if len(f.Imports) > 1 {
			heading += "  " + binio.Printable(s.API, 200)
		}
		where := fmt.Sprintf("file offset 0x%x, section %s", s.Offset, binio.Printable(s.Section, 80))
		if s.Via != 0 {
			where += fmt.Sprintf(", through the thunk at 0x%x", s.Via)
		}
		fmt.Fprintf(&sb, "\n  %s  %s\n", styled(ro.Color, "1", heading), styled(ro.Color, "2", "("+where+")"))
		for _, row := range render.CodeRows(s.Code, ro) {
			fmt.Fprintf(&sb, "    %s\n", row)
		}
	}
	if f.Total > len(f.Sites) {
		fmt.Fprintf(&sb, "\n  %s\n", styled(ro.Color, "2", fmt.Sprintf("(%d of %d call sites: --max N shows more, up to %d)", len(f.Sites), f.Total, xref.MaxSites)))
	}
	sb.WriteString("\n")
	for _, l := range render.CodeLimits(blocks, ro) {
		fmt.Fprintf(&sb, "  %s\n", l)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// styled wraps s in an ANSI style when colour is on.
func styled(on bool, code, s string) string {
	if !on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// pluralize returns "1 call site" or "3 call sites".
func pluralize(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}
