package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// categoryOrder is the order of sections in the generated catalogue.
var categoryOrder = []struct{ id, title string }{
	{report.CategoryPacking, "Packing and packaging"},
	{report.CategoryStructure, "File structure"},
	{report.CategoryHardening, "Hardening"},
	{report.CategorySignature, "Signatures"},
	{report.CategoryImports, "Imports"},
	{report.CategorySecrets, "Secrets"},
	{report.CategoryIndicator, "Indicators in strings"},
	{report.CategoryArchive, "Archives"},
	{report.CategoryApp, "Applications"},
	{report.CategoryBuild, "Build metadata"},
	{report.CategoryPrivacy, "Privacy"},
	{report.CategoryFile, "File name and type"},
}

// markdown renders the rule catalogue as docs/rules.md.
func markdown() string {
	var sb strings.Builder
	sb.WriteString("# Finding catalogue\n\n")
	sb.WriteString("<!-- Generated from internal/rules by `go test ./internal/rules -run TestCatalogDoc -update`. Do not edit by hand. -->\n\n")
	sb.WriteString("Every finding is `{id, title, severity, category, confidence, evidence[], limitations[]}`. A finding without evidence or without limitations is a bug (a test enforces both). ")
	sb.WriteString("Findings are leads for a human, not verdicts: each one states how it can be wrong.\n\n")
	sb.WriteString("Use the `id` to gate CI (`teardown analyze --fail-on high`) or to filter dashboards. IDs are stable; new ones may be added in later releases.\n\n")

	sb.WriteString("## Risk score\n\n")
	sb.WriteString("The score is deterministic and explained line by line in `risk.basis`:\n\n")
	sb.WriteString("1. Every finding earns `severity points x confidence factor`, rounded: ")
	fmt.Fprintf(&sb, "info %d, low %d, medium %d, high %d, critical %d points; confidence low x%.1f, medium x%.1f, high x%.1f.\n",
		severityPoints[report.SeverityInfo], severityPoints[report.SeverityLow], severityPoints[report.SeverityMedium],
		severityPoints[report.SeverityHigh], severityPoints[report.SeverityCritical],
		confidenceFactor[report.ConfidenceLow], confidenceFactor[report.ConfidenceMedium], confidenceFactor[report.ConfidenceHigh])
	sb.WriteString("2. The points of one category are capped so a pile of weak signals in one area cannot outweigh independent evidence elsewhere: ")
	caps := make([]string, 0, len(categoryCap))
	for _, c := range categoryOrder {
		if limit, ok := categoryCap[c.id]; ok {
			caps = append(caps, fmt.Sprintf("%s %d", c.id, limit))
		}
	}
	sb.WriteString(strings.Join(caps, ", "))
	fmt.Fprintf(&sb, " (other categories %d).\n", defaultCategoryCap)
	fmt.Fprintf(&sb, "3. The capped category totals are summed and limited to %d.\n", maxScore)
	fmt.Fprintf(&sb, "4. Label: low below %d, medium below %d, high below %d, critical from %d.\n\n", mediumFrom, highFrom, criticalFrom, criticalFrom)
	sb.WriteString("The score orders a review queue; it says nothing about intent.\n\n")

	sb.WriteString("## Thresholds\n\n")
	fmt.Fprintf(&sb, "- High-entropy section: entropy >= %.1f bits per byte on at least %d raw bytes (executable sections raise severity and confidence).\n", HighEntropySection, minEntropyBytes)
	fmt.Fprintf(&sb, "- High-entropy file without parsed sections: overall entropy >= %.1f.\n", HighEntropyFile)
	fmt.Fprintf(&sb, "- Zip bomb: declared total >= %s with ratio >= %.0f:1, or a per-entry ratio >= %.0f:1 with at least %s declared, or any overlapping entries.\n",
		humanBytes(bombTotalBytes), bombTotalRatio, bombEntryRatio, humanBytes(bombEntryBytes))
	fmt.Fprintf(&sb, "- PE overlay: at least %s.\n\n", humanBytes(overlayMinBytes))

	byCategory := map[string][]Info{}
	for _, info := range Catalog() {
		byCategory[info.Category] = append(byCategory[info.Category], info)
	}
	for _, c := range categoryOrder {
		infos := byCategory[c.id]
		if len(infos) == 0 {
			continue
		}
		sb.WriteString("## " + c.title + "\n\n")
		sb.WriteString("| Finding | Severity | What it looks for |\n|---|---|---|\n")
		for _, info := range infos {
			ids := slices.Clone(info.IDs)
			for i := range ids {
				ids[i] = "`" + ids[i] + "`"
			}
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", strings.Join(ids, "<br>"), info.Severity, info.Summary)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Added by the analyzer\n\n")
	sb.WriteString("| Finding | Severity | When |\n|---|---|---|\n")
	sb.WriteString("| `parser.error` | low | A format parser failed or panicked; results for that format are incomplete. |\n")
	sb.WriteString("| `parser.warning` | info | A parser recovered from malformed structures and lists what it skipped. |\n")
	sb.WriteString("| `analysis.incomplete` | low | The analysis deadline was reached before every stage finished. |\n")
	return sb.String()
}
