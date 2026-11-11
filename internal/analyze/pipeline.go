package analyze

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/q6r/teardown/internal/hashing"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/rules"
	"github.com/q6r/teardown/internal/sniff"
	"github.com/q6r/teardown/internal/strs"
	"github.com/q6r/teardown/internal/version"
)

// Reader analyses size bytes readable through r.
func Reader(ctx context.Context, r io.ReaderAt, size int64, opts Options) (*report.Report, error) {
	opts = opts.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	start := opts.Now()

	rep := report.New(opts.Name, size, version.String())
	rep.GeneratedAt = start.UTC().Truncate(time.Millisecond) // the rules judge timestamps against this clock
	stages := &stages{ctx: ctx, rep: rep, timeout: opts.Timeout}

	// 1. Content type: magic bytes plus light structure checks.
	rep.Type = dataType()
	stages.run("sniff", func() error {
		rep.Type = sniff.Detect(r, size)
		return nil
	})

	// 2. One streaming pass feeds the digests, the entropy profile and the string scanner.
	scanner := strs.NewScanner(strs.Options{MinLength: opts.MinString, MaxItems: opts.MaxStrings})
	pass, err := hashing.Stream(ctx, io.NewSectionReader(r, 0, size), size, scanner)
	if err != nil {
		return nil, timeoutError(opts.Name, opts.Timeout, err)
	}
	rep.Hashes = pass.Hashes
	rep.Entropy = pass.Entropy
	rep.Strings = scanner.Result()

	// 3. Format-specific parsing (each parser is isolated, bounded and cancellable).
	lim := limits.ForSize(size)
	parseFormat(stages, r, size, lim)

	// 4. Findings and risk, then a last pass that redacts secrets anywhere they could have leaked.
	res := rules.Evaluate(rep)
	rep.Findings, rep.Risk = res.Findings, res.Risk
	scrubSecrets(rep)
	addLimitations(rep)

	rep.DurationMs = max(opts.Now().Sub(start).Milliseconds(), 0)
	rep.Normalize()
	return rep, nil
}

// Quick computes the [Summary] of a file: type, digests (including the PE
// import hash) and entropy, without the rules engine or the string scan.
func Quick(ctx context.Context, r io.ReaderAt, size int64, opts Options) (*Summary, error) {
	opts = opts.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	rep := report.New(opts.Name, size, version.String())
	stages := &stages{ctx: ctx, rep: rep, timeout: opts.Timeout}
	rep.Type = dataType()
	stages.run("sniff", func() error {
		rep.Type = sniff.Detect(r, size)
		return nil
	})
	pass, err := hashing.Stream(ctx, io.NewSectionReader(r, 0, size), size)
	if err != nil {
		return nil, timeoutError(opts.Name, opts.Timeout, err)
	}
	rep.Hashes, rep.Entropy = pass.Hashes, pass.Entropy
	if rep.Type.ID == report.TypePE {
		stages.run("pe", func() error {
			_, err := parsePE(ctx, rep, r, size, limits.ForSize(size))
			return err
		})
	}
	return &Summary{File: rep.File, Type: rep.Type, Hashes: rep.Hashes, Entropy: rep.Entropy}, nil
}

// Strings extracts and classifies the strings of a file without hashing it or
// running any parser.
func Strings(ctx context.Context, r io.ReaderAt, size int64, opts Options) (report.Strings, error) {
	opts = opts.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	s, err := strs.Extract(ctx, io.NewSectionReader(r, 0, size), strs.Options{MinLength: opts.MinString, MaxItems: opts.MaxStrings})
	if err != nil {
		return report.Strings{}, timeoutError(opts.Name, opts.Timeout, err)
	}
	return s, nil
}

// dataType is the fallback type used when sniffing fails.
func dataType() report.Type {
	return report.Type{
		ID: report.TypeData, Family: report.FamilyData, Label: "data", MIME: "application/octet-stream",
		Confidence: report.ConfidenceLow, Tags: []string{},
	}
}

// stages runs the parsing steps of one analysis, turning errors, panics and
// deadline overruns into findings instead of failures.
type stages struct {
	ctx     context.Context
	rep     *report.Report
	timeout time.Duration
}

// run executes fn behind a recover and records its failure as a finding.
func (s *stages) run(name string, fn func() error) {
	err := guard(fn)
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		s.rep.Findings = append(s.rep.Findings, incompleteFinding(name, s.timeout))
	case errors.Is(err, context.Canceled):
		// The caller gave up; the stages that follow will notice the same cancellation.
	default:
		s.rep.Findings = append(s.rep.Findings, parserErrorFinding(name, err))
	}
}

// notes records a parser's non-fatal observations as one info finding.
func (s *stages) notes(name string, notes []string) {
	if len(notes) == 0 {
		return
	}
	s.rep.Findings = append(s.rep.Findings, parserWarningFinding(name, notes))
}

func incompleteFinding(stage string, timeout time.Duration) report.Finding {
	return report.Finding{
		ID: "analysis.incomplete", Title: fmt.Sprintf("The analysis deadline (%s) was reached during %s parsing", timeout, stage),
		Severity: report.SeverityLow, Category: report.CategoryParser, Confidence: report.ConfidenceHigh,
		Evidence: []string{fmt.Sprintf("%s stage stopped at the %s deadline", stage, timeout)},
		Limitations: []string{
			"Everything reported before the deadline is valid, but sections, imports or other lists for this format may be incomplete.",
			"A very large, deeply nested or deliberately malformed file can exhaust the budget; raise the timeout to analyse it fully.",
		},
	}
}

func parserErrorFinding(stage string, err error) report.Finding {
	title := fmt.Sprintf("The %s parser could not fully read this file", stage)
	var pe *panicError
	limits := []string{
		"Results for this format are incomplete or missing; the finding says the parser failed, not that the file is malicious.",
		"Truncated downloads, corrupted files and deliberately malformed samples all look like this.",
	}
	evidence := []string{safeMessage(err)}
	if errors.As(err, &pe) {
		title = fmt.Sprintf("The %s parser crashed on this file", stage)
		limits = append(limits, "A crash is a bug in teardown: please report it with a minimal sample.")
		evidence = append(evidence, "location: "+pe.location)
	}
	return report.Finding{
		ID: "parser.error", Title: title, Severity: report.SeverityLow, Category: report.CategoryParser,
		Confidence: report.ConfidenceHigh, Evidence: evidence, Limitations: limits,
	}
}

func parserWarningFinding(stage string, notes []string) report.Finding {
	ev := make([]string, 0, len(notes))
	for _, n := range notes {
		ev = append(ev, stage+": "+n)
	}
	if len(ev) > 12 {
		ev = append(ev[:12], fmt.Sprintf("(+%d more)", len(notes)-12))
	}
	return report.Finding{
		ID: "parser.warning", Title: fmt.Sprintf("The %s parser recovered from unexpected structures", stage),
		Severity: report.SeverityInfo, Category: report.CategoryParser, Confidence: report.ConfidenceHigh,
		Evidence: ev,
		Limitations: []string{
			"The parser skipped or truncated the parts listed as evidence, so lists in this report (sections, imports, entries) may be incomplete.",
		},
	}
}
