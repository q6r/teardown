package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

func evidenceScenario() *report.Report {
	r := base("blob.bin", report.TypePE, report.FamilyExecutable, 1<<20)
	r.Strings = report.Strings{Items: []report.StringItem{
		{Value: "AKIA…(20 chars)", Offset: 0x100, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
		{Value: "AKIA…(20 chars)", Offset: 0x180, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
		{Value: "ghp_…(40 chars)", Offset: 0x200, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "github-token"},
		{Value: "mysT…(18 chars)", Offset: 0x600, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "mystery"},
		{Value: "ops@example.net", Offset: 0x6f0, Encoding: "ascii", Category: report.CatEmail},
		{Value: "https://c2.example.net/gate.php", Offset: 0x700, Encoding: "ascii", Category: report.CatURL},
		{Value: "203.0.113.7", Offset: 0x710, Encoding: "ascii", Category: report.CatIP},
		{Value: "192.168.1.10", Offset: 0x720, Encoding: "ascii", Category: report.CatIP},
		{Value: "https://c2.example.net/gate.php", Offset: 0x730, Encoding: "utf16le", Category: report.CatURL},
		{Value: "evil.example.net", Offset: 0x740, Encoding: "ascii", Category: report.CatDomain},
		{Value: "cmd.exe /c dir", Offset: 0x780, Encoding: "ascii", Category: report.CatCommand},
		{Value: "powershell -nop -w hidden -enc SQBFAFgA", Offset: 0x800, Encoding: "ascii", Category: report.CatCommand},
		{Value: `HKLM\Software\Vendor\Settings`, Offset: 0x880, Encoding: "ascii", Category: report.CatRegistry},
		{Value: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, Offset: 0x900, Encoding: "ascii", Category: report.CatRegistry},
	}}
	return r
}

func offsetsOf(items []report.StringItem) []int64 {
	out := make([]int64, len(items))
	for i, it := range items {
		out[i] = it.Offset
	}
	return out
}

func TestStringEvidenceFollowsTheRules(t *testing.T) {
	r := evidenceScenario()
	tests := []struct {
		id   string
		want []int64
	}{
		// URLs first, then public addresses only, then domains, then e-mail; the repeated URL appears once.
		{"indicators.network", []int64{0x700, 0x710, 0x740, 0x6f0}},
		// The command with a hidden-execution pattern comes before the plain one.
		{"indicators.suspicious-commands", []int64{0x800, 0x780}},
		{"indicators.persistence-registry", []int64{0x900}},
		// Secrets are never merged, even when their redacted forms are identical.
		{"secrets.aws-access-key-id", []int64{0x100, 0x180}},
		{"secrets.github-token", []int64{0x200}},
		{"secrets.unclassified", []int64{0x600}},
		{"secrets.slack-token", nil},
		{"imports.process-injection", nil},
		{"hardening.no-aslr", nil},
		{"", nil},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			got := offsetsOf(StringEvidence(r, tc.id))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("offsets = %#x, want %#x", got, tc.want)
			}
		})
	}
}

// TestStringEvidenceCoversTheStringsOfEveryStringFinding keeps the helper and the
// rules in step: whenever a string rule emits a finding, the helper finds
// strings for it, and when it does not, it finds none.
func TestStringEvidenceCoversTheStringsOfEveryStringFinding(t *testing.T) {
	r := evidenceScenario()
	res := Evaluate(r)
	seen := map[string]bool{}
	for _, f := range res.Findings {
		seen[f.ID] = true
		got := StringEvidence(r, f.ID)
		isString := f.Category == report.CategorySecrets || f.Category == report.CategoryIndicator
		if isString && len(got) == 0 {
			t.Errorf("%s is derived from strings but StringEvidence found none", f.ID)
		}
		if !isString && got != nil {
			t.Errorf("%s is not derived from strings but StringEvidence returned %d items", f.ID, len(got))
		}
	}
	for _, id := range []string{"indicators.network", "indicators.suspicious-commands", "indicators.persistence-registry", "secrets.aws-access-key-id"} {
		if !seen[id] {
			t.Errorf("the scenario no longer triggers %s", id)
		}
	}

	// Without public addresses, domains, URLs or e-mail the network finding is absent and so is its evidence.
	quiet := base("quiet.bin", report.TypePE, report.FamilyExecutable, 1<<10)
	quiet.Strings.Items = []report.StringItem{{Value: "192.168.1.10", Offset: 8, Encoding: "ascii", Category: report.CatIP}}
	if got := StringEvidence(quiet, "indicators.network"); len(got) != 0 {
		t.Errorf("a private address is not network evidence: %+v", got)
	}
	for _, f := range Evaluate(quiet).Findings {
		if f.ID == "indicators.network" {
			t.Errorf("the rule emitted a finding the helper cannot explain")
		}
	}
}

func TestStringEvidenceIgnoresRunOnStrings(t *testing.T) {
	r := base("go.exe", report.TypePE, report.FamilyExecutable, 1<<10)
	runOn := "https://example.com/" + strings.Repeat("a", maxIndicatorLen)
	r.Strings.Items = []report.StringItem{{Value: runOn, Offset: 4, Encoding: "ascii", Category: report.CatURL}}
	if got := StringEvidence(r, "indicators.network"); len(got) != 0 {
		t.Fatalf("strings longer than %d characters are not indicators: %+v", maxIndicatorLen, got)
	}
}
