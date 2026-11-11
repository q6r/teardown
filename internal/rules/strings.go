package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

type secretSpec struct {
	title string
	sev   report.Severity
}

// secretSpecs holds the display data for the secret kinds the string scanner emits.
var secretSpecs = map[string]secretSpec{
	"aws-access-key-id": {"AWS access key ID embedded in the file", report.SeverityHigh},
	"github-token":      {"GitHub token embedded in the file", report.SeverityHigh},
	"slack-token":       {"Slack token embedded in the file", report.SeverityHigh},
	"pem-private-key":   {"PEM private key header embedded in the file", report.SeverityHigh},
	"jwt":               {"JSON Web Token embedded in the file", report.SeverityMedium},
}

func stringRules() []rule {
	ids := []string{"secrets.unclassified"}
	for kind := range secretSpecs {
		ids = append(ids, "secrets."+kind)
	}
	slices.Sort(ids)
	return []rule{
		{info: Info{IDs: ids, Category: report.CategorySecrets, Severity: "medium-high",
			Summary: "Strings that match credential formats (AWS access key IDs, GitHub and Slack tokens, PEM private key headers, JWTs). Values are redacted everywhere."},
			run: ruleSecrets},
		{info: Info{IDs: []string{"indicators.network"}, Category: report.CategoryIndicator, Severity: "info-low",
			Summary: "Hard-coded URLs, public IP addresses, domains and e-mail addresses."},
			run: ruleNetworkIndicators},
		{info: Info{IDs: []string{"indicators.suspicious-commands"}, Category: report.CategoryIndicator, Severity: "low-medium",
			Summary: "Embedded shell, PowerShell and living-off-the-land command lines."},
			run: ruleCommands},
		{info: Info{IDs: []string{"indicators.persistence-registry"}, Category: report.CategoryIndicator, Severity: "low",
			Summary: "Registry paths used for autostart, logon hooks and image hijacking."},
			run: rulePersistence},
	}
}

// clip shortens s to at most n runes for use as evidence.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func itemsOf(rep *report.Report, category string) []report.StringItem {
	var out []report.StringItem
	for _, it := range rep.Strings.Items {
		if it.Category == category {
			out = append(out, it)
		}
	}
	return out
}

// maxIndicatorLen bounds the strings that count as indicators. Concatenated
// string tables (typical of Go and Rust binaries) form run-on strings that
// contain URLs, commands and addresses by accident.
const maxIndicatorLen = 400

// indicatorItems returns the strings of a category that are short enough to be
// a single indicator.
func indicatorItems(rep *report.Report, category string) []report.StringItem {
	var out []report.StringItem
	for _, it := range itemsOf(rep, category) {
		if len(it.Value) <= maxIndicatorLen {
			out = append(out, it)
		}
	}
	return out
}

func ruleSecrets(in *input) []report.Finding {
	byKind := map[string][]report.StringItem{}
	for _, it := range itemsOf(in.rep, report.CatSecret) {
		byKind[it.Kind] = append(byKind[it.Kind], it)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)

	var out []report.Finding
	for _, kind := range kinds {
		items := byKind[kind]
		id, spec := "secrets.unclassified", secretSpec{"Credential-like string embedded in the file", report.SeverityMedium}
		if s, ok := secretSpecs[kind]; ok {
			id, spec = "secrets."+kind, s
		}
		evidence := make([]string, 0, len(items))
		for _, it := range items {
			evidence = append(evidence, fmt.Sprintf("offset 0x%x (%s): %s", it.Offset, it.Encoding, clip(it.Value, 100)))
		}
		limits := []string{
			"Pattern match only: the credential was not validated and may be a placeholder, documentation example, test fixture or an already revoked key.",
			"Values are redacted in every output: only the first four characters and the length are kept.",
		}
		if in.rep.Strings.Truncated {
			limits = append(limits, "The string list is truncated, so further secrets may exist beyond the ones listed.")
		}
		out = append(out, report.Finding{
			ID: id, Title: spec.title, Severity: spec.sev, Category: report.CategorySecrets,
			Confidence: report.ConfidenceMedium, Evidence: sample(evidence, 8), Limitations: limits,
		})
	}
	return out
}

func uniqueValues(items []report.StringItem) []string {
	vals := make([]string, 0, len(items))
	for _, it := range items {
		if v := strings.TrimSpace(it.Value); v != "" {
			vals = append(vals, v)
		}
	}
	return sortedUnique(vals)
}

func isPublicIP(s string) bool {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return false
	}
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

func ruleNetworkIndicators(in *input) []report.Finding {
	rep := in.rep
	urls := uniqueValues(indicatorItems(rep, report.CatURL))
	public := uniqueValues(publicIPItems(rep))
	domains := uniqueValues(indicatorItems(rep, report.CatDomain))
	emails := uniqueValues(indicatorItems(rep, report.CatEmail))
	if len(urls)+len(public)+len(domains)+len(emails) == 0 {
		return nil
	}
	var evidence []string
	add := func(label string, total int, vals []string) {
		if total == 0 && len(vals) == 0 {
			return
		}
		if total < len(vals) {
			total = len(vals)
		}
		evidence = append(evidence, fmt.Sprintf("%s: %d found, e.g. %s", label, total, strings.Join(clipAll(sample(vals, 4), 80), ", ")))
	}
	add("URLs", rep.Strings.ByCategory[report.CatURL], urls)
	add("public IP addresses", len(public), public)
	add("domains", rep.Strings.ByCategory[report.CatDomain], domains)
	add("e-mail addresses", rep.Strings.ByCategory[report.CatEmail], emails)

	sev, conf := report.SeverityInfo, report.ConfidenceMedium
	if len(public) > 0 {
		sev, conf = report.SeverityLow, report.ConfidenceLow
	}
	return []report.Finding{{
		ID: "indicators.network", Title: "Hard-coded network indicators", Severity: sev,
		Category: report.CategoryIndicator, Confidence: conf, Evidence: evidence,
		Limitations: []string{
			"A string in a binary may be dead code, a library default, a documentation or licence link, an XML namespace or a decoy; presence does not show that the program contacts it.",
			"Dotted-quad strings can be version numbers rather than IP addresses.",
			"Strings longer than 400 characters are ignored here: concatenated string tables (Go, Rust) produce accidental matches.",
			"Only the strings kept in the report were examined (see strings.truncated).",
		},
	}}
}

func clipAll(in []string, n int) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = clip(s, n)
	}
	return out
}

// strongCommandMarkers are fragments of command lines that are rarely benign.
var strongCommandMarkers = []string{
	"-enc ", "-encodedcommand", "downloadstring", "downloadfile", "invoke-expression", "iex ", "frombase64string",
	"-urlcache", "bitsadmin", "mshta", "scrobj.dll", "/dev/tcp/", "bash -i", "nc -e", "ncat -e", "| sh", "| bash",
	"-windowstyle hidden", "-w hidden", "-nop",
}

func ruleCommands(in *input) []report.Finding {
	items := indicatorItems(in.rep, report.CatCommand)
	if len(items) == 0 {
		return nil
	}
	cmds := uniqueValues(items)
	strong := 0
	for _, c := range cmds {
		if isStrongCommand(c) {
			strong++
		}
	}
	sev, conf := report.SeverityLow, report.ConfidenceLow
	title := "Embedded command lines"
	if strong > 0 {
		sev, conf = report.SeverityMedium, report.ConfidenceMedium
		title = "Embedded command lines with download, encoding or hidden-execution patterns"
	}
	return []report.Finding{{
		ID: "indicators.suspicious-commands", Title: title, Severity: sev, Category: report.CategoryIndicator, Confidence: conf,
		Evidence: clipAll(sample(cmds, 8), 120),
		Limitations: []string{
			"Command lines in a binary may belong to installers, update scripts, help text or documentation rather than code that runs; they are not executed here.",
			"Only the strings kept in the report were examined (see strings.truncated).",
		},
	}}
}

var persistenceMarkers = []string{
	`\currentversion\run`, `\currentversion\runonce`, `\winlogon`, "image file execution options",
	"appinit_dlls", `\currentcontrolset\services\`, `\policies\explorer\run`,
}

func rulePersistence(in *input) []report.Finding {
	hits := uniqueValues(persistenceItems(in.rep))
	if len(hits) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "indicators.persistence-registry", Title: "Registry paths associated with autostart or hijacking", Severity: report.SeverityLow,
		Category: report.CategoryIndicator, Confidence: report.ConfidenceLow, Evidence: clipAll(sample(hits, 8), 120),
		Limitations: []string{
			"Installers, updaters and system utilities legitimately reference the same keys; the strings do not show the program writes them.",
		},
	}}
}

// StringEvidence returns the strings of rep that back the finding with the given
// ID: the ones the rule behind the finding reads, the most telling first (URLs
// before public IP addresses, domains and e-mail addresses; command lines with
// download, encoding or hidden-execution patterns before the others) and every
// distinct value once, at the offset where it first appears. Secrets are listed
// in file order and never merged, because two different secrets can have the
// same redacted form. The items carry the values the scanner stored, which are
// already redacted for secrets.
//
// It returns nil for a finding that is not derived from strings. It lets a
// caller that has the file bytes (the rules themselves only see the report)
// show what the finding is about without repeating how the rules choose.
func StringEvidence(rep *report.Report, findingID string) []report.StringItem {
	switch findingID {
	case "indicators.network":
		return firstOfEach(networkItems(rep))
	case "indicators.suspicious-commands":
		return firstOfEach(commandItems(rep))
	case "indicators.persistence-registry":
		return firstOfEach(persistenceItems(rep))
	}
	if kind, ok := strings.CutPrefix(findingID, "secrets."); ok {
		return secretItems(rep, kind)
	}
	return nil
}

// networkItems lists the strings behind indicators.network, most telling first.
func networkItems(rep *report.Report) []report.StringItem {
	var out []report.StringItem
	out = append(out, indicatorItems(rep, report.CatURL)...)
	out = append(out, publicIPItems(rep)...)
	out = append(out, indicatorItems(rep, report.CatDomain)...)
	out = append(out, indicatorItems(rep, report.CatEmail)...)
	return out
}

// publicIPItems returns the IP address strings that are public addresses.
func publicIPItems(rep *report.Report) []report.StringItem {
	var out []report.StringItem
	for _, it := range indicatorItems(rep, report.CatIP) {
		if isPublicIP(strings.TrimSpace(it.Value)) {
			out = append(out, it)
		}
	}
	return out
}

// isStrongCommand reports whether a command line carries a download, encoding or
// hidden-execution pattern.
func isStrongCommand(cmd string) bool {
	l := strings.ToLower(cmd)
	for _, m := range strongCommandMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// commandItems lists the command-line strings, those with strong patterns first.
func commandItems(rep *report.Report) []report.StringItem {
	var strong, rest []report.StringItem
	for _, it := range indicatorItems(rep, report.CatCommand) {
		if isStrongCommand(it.Value) {
			strong = append(strong, it)
		} else {
			rest = append(rest, it)
		}
	}
	return append(strong, rest...)
}

// persistenceItems returns the registry strings that name an autostart or
// hijacking location.
func persistenceItems(rep *report.Report) []report.StringItem {
	var out []report.StringItem
	for _, it := range indicatorItems(rep, report.CatRegistry) {
		l := strings.ToLower(it.Value)
		for _, m := range persistenceMarkers {
			if strings.Contains(l, m) {
				out = append(out, it)
				break
			}
		}
	}
	return out
}

// secretItems returns the secret strings of one finding: the kind named after
// "secrets." or, for "unclassified", every kind that has no finding of its own.
func secretItems(rep *report.Report, kind string) []report.StringItem {
	var out []report.StringItem
	for _, it := range itemsOf(rep, report.CatSecret) {
		_, known := secretSpecs[it.Kind]
		if it.Kind == kind || (kind == "unclassified" && !known) {
			out = append(out, it)
		}
	}
	return out
}

// firstOfEach keeps the first string of every distinct value (compared without
// surrounding white space) and drops blank ones, as uniqueValues does for the
// evidence lines of a finding.
func firstOfEach(items []report.StringItem) []report.StringItem {
	seen := make(map[string]bool, len(items))
	out := make([]report.StringItem, 0, len(items))
	for _, it := range items {
		v := strings.TrimSpace(it.Value)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, it)
	}
	return out
}
