package rules

import (
	"fmt"
	"math"

	"github.com/q6r/teardown/internal/report"
)

// The risk score is deterministic and fully explained by Risk.Basis:
//
//  1. every finding earns points = round(severity points x confidence factor);
//  2. the points of one category are capped (see categoryCap) so that a pile of
//     weak signals in one area cannot outweigh independent evidence elsewhere;
//  3. the capped category totals are summed and limited to 100;
//  4. the label is low (< 20), medium (< 45), high (< 70) or critical.
//
// It is a triage aid for ordering a queue, not a verdict.
var (
	severityPoints = map[report.Severity]int{
		report.SeverityInfo:     0,
		report.SeverityLow:      4,
		report.SeverityMedium:   10,
		report.SeverityHigh:     20,
		report.SeverityCritical: 40,
	}
	confidenceFactor = map[report.Confidence]float64{
		report.ConfidenceHigh:   1.0,
		report.ConfidenceMedium: 0.7,
		report.ConfidenceLow:    0.4,
	}
	categoryCap = map[string]int{
		report.CategoryHardening: 15,
		report.CategorySignature: 6,
		report.CategoryPrivacy:   6,
		report.CategoryParser:    5,
		report.CategoryBuild:     0,
		report.CategoryIndicator: 20,
		report.CategoryStructure: 30,
		report.CategoryPacking:   30,
		report.CategoryApp:       30,
		report.CategoryFile:      30,
	}
)

const (
	defaultCategoryCap = 40
	maxScore           = 100
	mediumFrom         = 20
	highFrom           = 45
	criticalFrom       = 70
)

// Points returns the points a single finding earns before category capping.
func Points(f report.Finding) int {
	return int(math.Round(float64(severityPoints[f.Severity]) * confidenceFactor[f.Confidence]))
}

// Label maps a score to low, medium, high or critical.
func Label(score int) string {
	switch {
	case score >= criticalFrom:
		return report.RiskCritical
	case score >= highFrom:
		return report.RiskHigh
	case score >= mediumFrom:
		return report.RiskMedium
	default:
		return report.RiskLow
	}
}

// Score computes the risk of a set of findings and explains the arithmetic.
// The findings should already be sorted (see [Evaluate]) so the basis reads
// from most to least severe.
func Score(findings []report.Finding) report.Risk {
	basis := []string{
		"points per finding = severity (info 0, low 4, medium 10, high 20, critical 40) x confidence (low 0.4, medium 0.7, high 1.0), rounded",
	}
	perCategory := map[string]int{}
	var order []string
	for _, f := range findings {
		pts := Points(f)
		if pts == 0 {
			continue
		}
		if _, seen := perCategory[f.Category]; !seen {
			order = append(order, f.Category)
		}
		perCategory[f.Category] += pts
		basis = append(basis, fmt.Sprintf("+%d  %s (%s severity, %s confidence)", pts, f.ID, f.Severity, f.Confidence))
	}
	total := 0
	for _, cat := range order {
		sum := perCategory[cat]
		limit, ok := categoryCap[cat]
		if !ok {
			limit = defaultCategoryCap
		}
		if sum > limit {
			basis = append(basis, fmt.Sprintf("category %q capped at %d (was %d)", cat, limit, sum))
			sum = limit
		}
		total += sum
	}
	score := min(total, maxScore)
	if total > maxScore {
		basis = append(basis, fmt.Sprintf("total %d limited to %d", total, maxScore))
	}
	label := Label(score)
	basis = append(basis, fmt.Sprintf("score %d => %s (low < %d <= medium < %d <= high < %d <= critical)", score, label, mediumFrom, highFrom, criticalFrom))
	if len(order) == 0 {
		basis = append(basis, "no finding carries points, so nothing raised the score")
	}
	return report.Risk{Score: score, Label: label, Basis: basis}
}
