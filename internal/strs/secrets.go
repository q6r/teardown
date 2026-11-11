package strs

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// minSecretLen is the length of the shortest recognised secret (an AWS key id).
const minSecretLen = 20

// redactKeepRunes is how many leading characters Redact keeps.
const redactKeepRunes = 4

// maxRedactRounds bounds the fixpoint loop of RedactSecrets.
const maxRedactRounds = 4

// Secret kinds reported in StringItem.Kind.
const (
	kindAWS    = "aws-access-key-id"
	kindGitHub = "github-token"
	kindSlack  = "slack-token"
	kindPEM    = "pem-private-key"
	kindJWT    = "jwt"
)

// secretRule recognises one kind of secret. gate is a cheap pre-check that
// rejects almost every string before the regular expression runs.
type secretRule struct {
	kind string
	gate func(string) bool
	re   *regexp.Regexp
}

// secretRules lists the recognised secrets, longest and most specific first.
// The patterns have no word-boundary anchors on purpose: a secret glued to
// other text (key=AKIA..., "token":"ghp_...") must still be redacted, so over-
// redaction is the accepted failure mode. For the same reason a private-key
// header takes the rest of its string with it: a key written on one line (with
// escaped newlines, in a script or a configuration file) puts the key material
// right behind the header, where no pattern of its own could recognise it.
var secretRules = []secretRule{
	{
		kind: kindJWT,
		gate: func(s string) bool { return strings.Contains(s, "eyJ") },
		re:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	},
	{
		kind: kindGitHub,
		gate: hasGitHubAnchor,
		re:   regexp.MustCompile(`github_pat_[A-Za-z0-9_]{70,}|gh[pousr]_[A-Za-z0-9]{36,}`),
	},
	{
		kind: kindSlack,
		gate: func(s string) bool { return strings.Contains(s, "xox") || strings.Contains(s, "xapp-") },
		re:   regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,}`),
	},
	{
		kind: kindPEM,
		gate: func(s string) bool { return strings.Contains(s, "-----BEGIN") },
		re:   regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*`),
	},
	{
		kind: kindAWS,
		gate: hasAWSAnchor,
		re:   regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}`),
	},
}

// hasGitHubAnchor reports whether s contains "gh[pousr]_" or "github_pat_".
func hasGitHubAnchor(s string) bool {
	if strings.Contains(s, "github_pat_") {
		return true
	}
	for off := 0; off < len(s); {
		j := strings.Index(s[off:], "gh")
		if j < 0 {
			return false
		}
		j += off
		if j+3 < len(s) && s[j+3] == '_' && strings.IndexByte("pousr", s[j+2]) >= 0 {
			return true
		}
		off = j + 1
	}
	return false
}

// hasAWSAnchor reports whether s contains one of the AWS key-id prefixes.
func hasAWSAnchor(s string) bool {
	for off := 0; off < len(s); {
		j := strings.IndexByte(s[off:], 'A')
		if j < 0 {
			return false
		}
		j += off
		if j+4 <= len(s) {
			switch s[j : j+4] {
			case "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA":
				return true
			}
			if s[j+1] == '3' && s[j+2] == 'T' {
				return true
			}
		}
		off = j + 1
	}
	return false
}

// Redact hides a secret: it keeps the first four characters (fewer for very
// short input, never more than a quarter of it) and the length, for example
// "AKIA…(20 chars)".
func Redact(secret string) string {
	n := utf8.RuneCountInString(secret)
	keep := min(redactKeepRunes, n/4)
	end := 0
	for i := 0; i < keep && end < len(secret); i++ {
		_, w := utf8.DecodeRuneInString(secret[end:])
		end += w
	}
	return secret[:end] + "…(" + strconv.Itoa(n) + " chars)"
}

// RedactSecrets replaces every secret-looking substring of s (AWS access key
// ids, GitHub and Slack tokens, PEM private-key headers, JWTs) with its
// [Redact]ed form and returns the sorted, de-duplicated kinds that were found
// ("aws-access-key-id", "github-token", "jwt", "pem-private-key",
// "slack-token"). It returns s unchanged and no kinds when nothing matched.
// The result never matches again, so the call is idempotent.
func RedactSecrets(s string) (redacted string, kinds []string) {
	if len(s) < minSecretLen {
		return s, nil
	}
	for range maxRedactRounds {
		changed := false
		for _, r := range secretRules {
			if !r.gate(s) || !r.re.MatchString(s) {
				continue
			}
			s = r.re.ReplaceAllStringFunc(s, Redact)
			if !slices.Contains(kinds, r.kind) {
				kinds = append(kinds, r.kind)
			}
			changed = true
		}
		if !changed {
			break
		}
	}
	slices.Sort(kinds)
	return s, kinds
}
