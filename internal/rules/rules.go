// Package rules is the findings engine. It interprets the facts collected in a
// [report.Report] (sections, imports, hardening, strings, format details) and
// returns findings, each with its evidence and the reasons it may be wrong,
// plus a deterministic risk score.
//
// Rules are pure functions of the report. They read format-specific details
// through their JSON form (the documented report contract), so the engine does
// not depend on the parser packages and behaves identically on a report that
// was loaded back from disk. Nothing here is a verdict: every finding is a lead
// for a human, and the score is a prioritisation aid.
package rules

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Result is the outcome of evaluating a report.
type Result struct {
	// Findings are sorted by severity (highest first), then by ID. They include
	// any findings that were already present on the report.
	Findings []report.Finding
	// Risk is the score computed from Findings.
	Risk report.Risk
}

// Info documents one family of findings for the generated rule catalogue.
type Info struct {
	// IDs lists the finding identifiers the rule can emit.
	IDs      []string
	Category string
	// Severity describes the severity (range) the rule emits.
	Severity string
	// Summary is one sentence on what the rule looks for and how.
	Summary string
}

type rule struct {
	info Info
	run  func(*input) []report.Finding
}

// input is the read-only view of a report that rules work on.
type input struct {
	rep *report.Report
	imp importIndex
}

func newInput(rep *report.Report) *input {
	return &input{rep: rep, imp: indexImports(rep.Imports)}
}

// detail decodes rep.Details[key] into T through its JSON form.
func detail[T any](rep *report.Report, key string) (T, bool) {
	var zero T
	raw, ok := rep.Details[key]
	if !ok || raw == nil {
		return zero, false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return zero, false
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return zero, false
	}
	return out, true
}

// Evaluate runs every rule against rep without modifying it and returns the
// merged, sorted findings together with the risk score.
func Evaluate(rep *report.Report) Result {
	in := newInput(rep)
	findings := slices.Clone(rep.Findings)
	for _, r := range registry() {
		findings = append(findings, r.run(in)...)
	}
	for i := range findings {
		if findings[i].Evidence == nil {
			findings[i].Evidence = []string{}
		}
	}
	sortFindings(findings)
	return Result{Findings: findings, Risk: Score(findings)}
}

// Catalog describes every rule family, in evaluation order.
func Catalog() []Info {
	rs := registry()
	out := make([]Info, len(rs))
	for i, r := range rs {
		out[i] = r.info
	}
	return out
}

func sortFindings(fs []report.Finding) {
	slices.SortStableFunc(fs, func(a, b report.Finding) int {
		if c := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// registry lists the rules in evaluation order.
func registry() []rule {
	var rs []rule
	rs = append(rs, packingRules()...)
	rs = append(rs, structureRules()...)
	rs = append(rs, hardeningRules()...)
	rs = append(rs, importRules()...)
	rs = append(rs, stringRules()...)
	rs = append(rs, archiveRules()...)
	rs = append(rs, appRules()...)
	rs = append(rs, fileRules()...)
	return rs
}

// sample returns at most n items followed by a "(+k more)" marker.
func sample(items []string, n int) []string {
	if len(items) <= n {
		return slices.Clone(items)
	}
	out := slices.Clone(items[:n])
	return append(out, fmt.Sprintf("(+%d more)", len(items)-n))
}

// humanBytes formats a byte count with binary units.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func isExecutable(rep *report.Report) bool { return rep.Type.Family == report.FamilyExecutable }
