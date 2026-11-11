package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/diff"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
)

func stringsCommand() command {
	return command{
		name:    "strings",
		summary: "List the strings in a file, classified (urls, ips, paths, commands, secrets, ...)",
		args:    "<file>",
		long: `Extracts ASCII and UTF-16LE strings in one streaming pass and classifies them.
Secrets (AWS access key IDs, GitHub and Slack tokens, PEM private key headers,
JWTs) are never printed in full: only the first four characters and the length
are kept. Classified strings are kept first when the --max cap is reached.`,
		examples: []string{
			"teardown strings app.exe",
			"teardown strings app.exe --category url,ip,domain",
			"teardown strings firmware.bin --min 8 --json",
			"teardown strings app.exe --category secret",
		},
		register: func(f *flagSet) runner {
			var o struct {
				category, out, color string
				min, max             int
				json                 bool
			}
			f.Group("Selection")
			f.String(&o.category, "category", "c", "LIST", "", "Only these categories, comma separated: "+strings.Join(report.StringCategories(), ", "), report.StringCategories()...)
			f.Int(&o.min, "min", "n", "N", analyze.DefaultMinString, "Minimum string length")
			f.Int(&o.max, "max", "", "N", 20000, "Maximum strings to extract")
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print JSON instead of one string per line")
			f.Path(&o.out, "output", "o", "FILE", "Write the output to FILE instead of stdout")
			f.String(&o.color, "color", "", "WHEN", "auto", "Colour: auto, always or never (NO_COLOR is honoured)", "auto", "always", "never")

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) != 1 {
					return usageError(env, "strings", "expected exactly one file, got %d", len(pos))
				}
				switch {
				case o.min < 1 || o.min > 4096:
					return usageError(env, "strings", "--min must be between 1 and 4096")
				case o.max < 1 || o.max > 1_000_000:
					return usageError(env, "strings", "--max must be between 1 and 1000000")
				case o.color != "auto" && o.color != "always" && o.color != "never":
					return usageError(env, "strings", "--color must be auto, always or never, not %q", o.color)
				}
				wanted := splitList(o.category)
				for _, c := range wanted {
					if !slices.Contains(report.StringCategories(), c) {
						return usageError(env, "strings", "unknown category %q (valid: %s)", c, strings.Join(report.StringCategories(), ", "))
					}
				}
				res, err := analyze.StringsFile(ctx, pos[0], analyze.Options{MinString: o.min, MaxStrings: o.max, Now: env.Now})
				if err != nil {
					return failure(env, "strings", err)
				}
				items := res.Strings.Items
				if len(wanted) > 0 {
					items = slices.DeleteFunc(slices.Clone(items), func(it report.StringItem) bool { return !slices.Contains(wanted, it.Category) })
				}
				dest, err := openDestination(env, o.out, pos[0])
				if err != nil {
					return failure(env, "strings", err)
				}
				var werr error
				if o.json {
					out := struct {
						File       report.File         `json:"file"`
						Total      int                 `json:"total"`
						MinLength  int                 `json:"minLength"`
						Truncated  bool                `json:"truncated"`
						ByCategory map[string]int      `json:"byCategory"`
						Matched    int                 `json:"matched"`
						Items      []report.StringItem `json:"items"`
					}{res.File, res.Strings.Total, res.Strings.MinLength, res.Strings.Truncated, res.Strings.ByCategory, len(items), items}
					if out.Items == nil {
						out.Items = []report.StringItem{}
					}
					werr = writeJSON(dest.w, out)
				} else {
					ro := render.Options{Color: colorEnabled(o.color, env, dest.w)}
					werr = render.Strings(dest.w, report.Strings{Items: items}, ro)
					if werr == nil {
						// The summary goes to stderr so stdout stays pipeable.
						werr = render.StringsFooter(env.Stderr, len(items), res.Strings, render.Options{Color: colorEnabled(o.color, env, env.Stderr)})
					}
				}
				if cerr := dest.close(); werr == nil {
					werr = cerr
				}
				if werr != nil {
					return failure(env, "strings", fmt.Errorf("writing output: %w", werr))
				}
				return exitOK
			}
		},
	}
}

func hashCommand() command {
	return command{
		name:    "hash",
		summary: "MD5, SHA-1 and SHA-256 of files, plus the PE import hash and entropy",
		args:    "<file>...",
		long: `Computes the digests and the entropy in a single pass over each file. For PE
files the import hash (imphash) is added. With --json a single file prints one
object and several files print an array of objects.`,
		examples: []string{
			"teardown hash setup.exe",
			"teardown hash a.dll b.dll --json",
		},
		register: func(f *flagSet) runner {
			var o struct {
				json, ascii bool
				color       string
			}
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print JSON")
			f.String(&o.color, "color", "", "WHEN", "auto", "Colour: auto, always or never (NO_COLOR is honoured)", "auto", "always", "never")
			f.Bool(&o.ascii, "ascii", "", "Use ASCII instead of unicode bars")

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) == 0 {
					return usageError(env, "hash", "expected at least one file")
				}
				if o.color != "auto" && o.color != "always" && o.color != "never" {
					return usageError(env, "hash", "--color must be auto, always or never, not %q", o.color)
				}
				var sums []*analyze.Summary
				failed := false
				for _, path := range pos {
					sum, err := analyze.QuickFile(ctx, path, analyze.Options{Now: env.Now})
					if err != nil {
						fmt.Fprintf(env.Stderr, "teardown hash: %v\n", err)
						failed = true
						if errors.Is(ctx.Err(), context.Canceled) {
							break
						}
						continue
					}
					sums = append(sums, sum)
				}
				var werr error
				switch {
				case o.json && len(pos) == 1 && len(sums) == 1:
					werr = writeJSON(env.Stdout, sums[0])
				case o.json:
					if sums == nil {
						sums = []*analyze.Summary{}
					}
					werr = writeJSON(env.Stdout, sums)
				default:
					ro := renderOptions(env, env.Stdout, o.color, o.ascii, false, 0)
					for _, s := range sums {
						if werr = render.Hash(env.Stdout, s, ro); werr != nil {
							break
						}
					}
				}
				if werr != nil {
					return failure(env, "hash", fmt.Errorf("writing output: %w", werr))
				}
				if failed {
					return exitError
				}
				return exitOK
			}
		},
	}
}

func diffCommand() command {
	return command{
		name:    "diff",
		summary: "Compare two files: hashes, type, sections, imports, strings, hardening and findings",
		args:    "<a> <b>",
		long: `Analyses both files and reports what changed from a to b: new and removed
sections, imports and strings, hardening changes, findings that appeared or
disappeared, and the change in risk score. Useful for comparing builds, or a
sample against its packed or patched variant.`,
		examples: []string{
			"teardown diff old.exe new.exe",
			"teardown diff v1/app v2/app --json -o diff.json",
		},
		register: func(f *flagSet) runner {
			var o struct {
				json, ascii bool
				out, color  string
			}
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print the comparison as JSON (schema teardown.diff/v1)")
			f.Path(&o.out, "output", "o", "FILE", "Write the output to FILE instead of stdout")
			f.String(&o.color, "color", "", "WHEN", "auto", "Colour: auto, always or never (NO_COLOR is honoured)", "auto", "always", "never")
			f.Bool(&o.ascii, "ascii", "", "Use ASCII instead of unicode symbols")

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) != 2 {
					return usageError(env, "diff", "expected exactly two files, got %d", len(pos))
				}
				if o.color != "auto" && o.color != "always" && o.color != "never" {
					return usageError(env, "diff", "--color must be auto, always or never, not %q", o.color)
				}
				reps := make([]*report.Report, 2)
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for i, path := range pos {
					wg.Add(1)
					go func() {
						defer wg.Done()
						reps[i], errs[i] = analyze.File(ctx, path, analyze.Options{Now: env.Now})
					}()
				}
				wg.Wait()
				if err := errors.Join(errs...); err != nil {
					return failure(env, "diff", err)
				}
				res := diff.Compare(reps[0], reps[1])
				dest, err := openDestination(env, o.out, pos...)
				if err != nil {
					return failure(env, "diff", err)
				}
				var werr error
				if o.json {
					werr = writeJSON(dest.w, res)
				} else {
					werr = render.Diff(dest.w, res, renderOptions(env, dest.w, o.color, o.ascii, false, 0))
				}
				if cerr := dest.close(); werr == nil {
					werr = cerr
				}
				if werr != nil {
					return failure(env, "diff", fmt.Errorf("writing output: %w", werr))
				}
				return exitOK
			}
		},
	}
}
