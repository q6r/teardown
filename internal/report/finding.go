package report

import (
	"fmt"
	"strings"
)

// Severity ranks how much attention a finding deserves.
type Severity string

// Severities in ascending order.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var allSeverities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Severities returns every severity in ascending order.
func Severities() []Severity { return append([]Severity(nil), allSeverities...) }

// Rank returns 0 (info) .. 4 (critical), or -1 for an unknown value.
func (s Severity) Rank() int {
	for i, v := range allSeverities {
		if v == s {
			return i
		}
	}
	return -1
}

// AtLeast reports whether s is at least as severe as other. Unknown values
// never satisfy the comparison.
func (s Severity) AtLeast(other Severity) bool {
	return s.Rank() >= 0 && other.Rank() >= 0 && s.Rank() >= other.Rank()
}

// ParseSeverity parses a severity name case-insensitively.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if s.Rank() < 0 {
		return "", fmt.Errorf("unknown severity %q (want one of: info, low, medium, high, critical)", v)
	}
	return s, nil
}

// Confidence states how sure the engine is that the evidence supports the title.
type Confidence string

// Confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Finding is one conclusion together with the evidence behind it and the
// reasons it may be wrong. A finding without limitations is a bug.
type Finding struct {
	// ID is a stable, dotted identifier such as "hardening.no-aslr".
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Category   string     `json:"category"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence"`
	// Limitations explains how this finding can be a false positive or incomplete.
	Limitations []string `json:"limitations"`
}

// Finding categories.
const (
	CategoryPacking   = "packing"
	CategoryStructure = "structure"
	CategoryHardening = "hardening"
	CategoryImports   = "imports"
	CategorySecrets   = "secrets"
	CategoryArchive   = "archive"
	CategorySignature = "signature"
	CategoryPrivacy   = "privacy"
	CategoryBuild     = "build"
	CategoryIndicator = "indicators"
	CategoryApp       = "application"
	CategoryParser    = "parser"
	CategoryFile      = "file"
)
