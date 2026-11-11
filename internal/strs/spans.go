package strs

import (
	"cmp"
	"slices"
)

// SecretSpan is the byte range [Start, End) of one secret-looking substring of a
// string, together with the kind of secret it looks like.
type SecretSpan struct {
	Start, End int
	// Kind is one of "aws-access-key-id", "github-token", "slack-token",
	// "pem-private-key" or "jwt" (the values of report.StringItem.Kind).
	Kind string
}

// FindSecrets locates the secret-looking substrings of s: the places
// [RedactSecrets] replaces, found with the same patterns. It exists for callers
// that must hide a secret where it sits (a hex window over the file, a line of a
// script) instead of rewriting a string.
//
// The spans are sorted and never overlap: overlapping matches are merged into
// one span that keeps the kind of the earliest. A string for which RedactSecrets
// reports a kind always yields at least one span, and a string for which it
// reports none yields no span. Like RedactSecrets it keeps the over-redaction
// bias: a secret glued to other text is still found.
func FindSecrets(s string) []SecretSpan {
	if len(s) < minSecretLen {
		return nil
	}
	var spans []SecretSpan
	for _, r := range secretRules {
		if !r.gate(s) {
			continue
		}
		for _, loc := range r.re.FindAllStringIndex(s, -1) {
			spans = append(spans, SecretSpan{Start: loc[0], End: loc[1], Kind: r.kind})
		}
	}
	if len(spans) == 0 {
		return nil
	}
	slices.SortStableFunc(spans, func(a, b SecretSpan) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End))
	})
	merged := spans[:1]
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp.Start < last.End {
			last.End = max(last.End, sp.End)
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}
