package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func analyzeCommand() command {
	return command{
		name:    "analyze",
		summary: "Analyse one file: type, hashes, entropy, structure, strings, findings and risk",
		args:    "<file>",
		long: `Static triage: the file is parsed, never executed. The report lists what was
found (type, hashes, entropy, sections, imports, hardening, strings) and a set of
findings, each with its evidence and the reasons it may be wrong. The risk score
is a deterministic triage aid, not a verdict.`,
		examples: []string{
			"teardown analyze setup.exe",
			"teardown analyze setup.exe -v                     # risk arithmetic, all evidence, all limitations",
			"teardown analyze setup.exe --code-all             # every block of code behind each finding, in full",
			"teardown analyze setup.exe --no-code              # findings without the code behind them",
			"teardown analyze app.apk --json -o report.json    # machine-readable report",
			"teardown analyze app.apk --sarif -o app.sarif     # findings for GitHub code scanning and other SARIF tools",
			"teardown analyze lib.so --html report.html        # self-contained HTML report",
			"teardown analyze build/app --fail-on high         # CI gate: exit status 3 on high or critical findings",
		},
		register: func(f *flagSet) runner {
			var o struct {
				json, md, sarif, ascii, verbose bool
				noCode, codeAll                 bool
				html, out, color, failOn        string
				minString, maxStrings           int
				width                           int
				timeout                         time.Duration
			}
			f.Group("Output")
			f.Bool(&o.json, "json", "", "Print the full report as JSON (schema teardown.report/v1)")
			f.Bool(&o.md, "md", "", "Print the report as Markdown")
			f.Bool(&o.sarif, "sarif", "", "Print the findings as SARIF 2.1.0 for code-scanning dashboards")
			f.Path(&o.html, "html", "", "FILE", "Write a self-contained HTML report to FILE")
			f.Path(&o.out, "output", "o", "FILE", "Write the output to FILE instead of stdout (not with --html)")
			f.String(&o.color, "color", "", "WHEN", "auto", "Colour: auto, always or never (NO_COLOR is honoured)", "auto", "always", "never")
			f.Bool(&o.ascii, "ascii", "", "Use ASCII instead of unicode bars and symbols")
			f.Bool(&o.verbose, "verbose", "v", "Show the risk arithmetic, all evidence and all limitations")
			f.Int(&o.width, "width", "", "N", 0, "Line width of the terminal output (default: $COLUMNS or 100)")
			f.Bool(&o.noCode, "no-code", "", "Leave the code behind the findings (instructions, bytes, source lines) out of the output")
			f.Bool(&o.codeAll, "code-all", "", "Show every code block of each finding in full in the terminal output (--json and --html already carry them all)")
			f.Group("Analysis")
			f.Int(&o.minString, "min-string", "", "N", analyze.DefaultMinString, "Minimum string length")
			f.Int(&o.maxStrings, "max-strings", "", "N", analyze.DefaultMaxStrings, "Maximum string items kept in the report")
			f.Duration(&o.timeout, "timeout", "DURATION", analyze.DefaultTimeout, "Give up after this long")
			f.Group("CI gating")
			f.String(&o.failOn, "fail-on", "", "SEVERITY", "", "Exit with status 3 when a finding of at least this severity exists: "+strings.Join(severityNames, ", "), severityNames...)

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) != 1 {
					return usageError(env, "analyze", "expected exactly one file, got %d", len(pos))
				}
				modes := 0
				for _, on := range []bool{o.json, o.md, o.sarif, o.html != ""} {
					if on {
						modes++
					}
				}
				switch {
				case modes > 1:
					return usageError(env, "analyze", "choose one of --json, --md, --sarif or --html")
				case o.html != "" && o.out != "":
					return usageError(env, "analyze", "--output does not apply to --html; pass the file name to --html")
				case o.color != "auto" && o.color != "always" && o.color != "never":
					return usageError(env, "analyze", "--color must be auto, always or never, not %q", o.color)
				case o.minString < 1 || o.minString > 4096:
					return usageError(env, "analyze", "--min-string must be between 1 and 4096")
				case o.maxStrings < 1 || o.maxStrings > 1_000_000:
					return usageError(env, "analyze", "--max-strings must be between 1 and 1000000")
				case o.timeout <= 0:
					return usageError(env, "analyze", "--timeout must be positive")
				case o.width < 0:
					return usageError(env, "analyze", "--width must not be negative")
				case o.noCode && o.codeAll:
					return usageError(env, "analyze", "choose one of --no-code or --code-all")
				}
				var threshold report.Severity
				if o.failOn != "" {
					s, err := report.ParseSeverity(o.failOn)
					if err != nil {
						return usageError(env, "analyze", "--fail-on: %v", err)
					}
					threshold = s
				}

				rep, err := env.Analyze(ctx, pos[0], analyze.Options{
					MinString: o.minString, MaxStrings: o.maxStrings, Timeout: o.timeout, Now: env.Now,
				})
				if err != nil {
					if errors.Is(ctx.Err(), context.Canceled) {
						return failure(env, "analyze", errors.New("interrupted"))
					}
					return failure(env, "analyze", err)
				}

				// The terminal renderer honours --no-code itself; every other output is
				// given a copy of the report without the code blocks.
				shown := rep
				if o.noCode && (o.json || o.md || o.sarif || o.html != "") {
					shown = rep.WithoutCode()
				}

				if o.html != "" {
					if code := writeHTML(env, o.html, pos[0], shown); code != exitOK {
						return code
					}
				} else {
					dest, err := openDestination(env, o.out, pos[0])
					if err != nil {
						return failure(env, "analyze", err)
					}
					var werr error
					switch {
					case o.json:
						werr = writeJSON(dest.w, shown)
					case o.md:
						werr = render.Markdown(dest.w, shown)
					case o.sarif:
						werr = render.SARIF(dest.w, shown)
					default:
						ro := renderOptions(env, dest.w, o.color, o.ascii, o.verbose, o.width)
						ro.HideCode, ro.CodeAll = o.noCode, o.codeAll
						werr = render.Text(dest.w, rep, ro)
					}
					if cerr := dest.close(); werr == nil {
						werr = cerr
					}
					if werr != nil {
						return failure(env, "analyze", fmt.Errorf("writing output: %w", werr))
					}
				}

				if threshold != "" && rep.Meets(threshold) {
					var ids []string
					for _, fd := range rep.Findings {
						if fd.Severity.AtLeast(threshold) {
							ids = append(ids, fd.ID+" ("+string(fd.Severity)+")")
						}
					}
					fmt.Fprintf(env.Stderr, "teardown analyze: --fail-on %s: %d finding(s) at or above %s: %s\n", threshold, len(ids), threshold, strings.Join(ids, ", "))
					return exitFailOn
				}
				return exitOK
			}
		},
	}
}

func writeHTML(env Env, path, input string, rep *report.Report) int {
	dest, err := openDestination(env, path, input)
	if err != nil {
		return failure(env, "analyze", err)
	}
	werr := render.HTML(dest.w, rep)
	if cerr := dest.close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return failure(env, "analyze", fmt.Errorf("writing %s: %w", path, werr))
	}
	fmt.Fprintf(env.Stdout, "wrote %s (risk %d/100 %s, %d findings)\n", path, rep.Risk.Score, rep.Risk.Label, len(rep.Findings))
	return exitOK
}
