package strs

import (
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Category indexes, in classification priority order: the first matcher that
// accepts a string decides its category.
const (
	cSecret = iota
	cURL
	cEmail
	cIP
	cRegistry
	cCommand
	cUserAgent
	cPath
	cDomain
	cAPI
	cBase64
	cHex
	cPlain
	numCategories
)

// categoryNames maps a category index to its report.Cat* identifier.
var categoryNames = [numCategories]string{
	cSecret:    report.CatSecret,
	cURL:       report.CatURL,
	cEmail:     report.CatEmail,
	cIP:        report.CatIP,
	cRegistry:  report.CatRegistry,
	cCommand:   report.CatCommand,
	cUserAgent: report.CatUserAgent,
	cPath:      report.CatPath,
	cDomain:    report.CatDomain,
	cAPI:       report.CatAPI,
	cBase64:    report.CatBase64,
	cHex:       report.CatHex,
	cPlain:     report.CatPlain,
}

// Byte-class features OR-ed together in a single pass over a string; the
// matchers consult them to reject most strings without further work.
const (
	fSpace     uint32 = 1 << iota // ' ' or tab
	fColon                        // ':'
	fSlash                        // '/'
	fBackslash                    // '\'
	fAt                           // '@'
	fDot                          // '.'
	fDigit                        // 0-9
	fUpper                        // A-Z
	fLower                        // a-z
	fNotHex                       // a byte outside [0-9A-Fa-f]
	fNotB64                       // a byte outside [A-Za-z0-9+/=_-]
	fNotIdent                     // a byte outside [A-Za-z0-9_]
	fNotDomain                    // a byte outside [A-Za-z0-9.-]
	fNotAPI                       // a byte outside [A-Za-z0-9_+-]
)

// featureTable holds the features of every byte value. It is built once and
// never modified.
var featureTable = buildFeatureTable()

func buildFeatureTable() (t [256]uint32) {
	for i := range t {
		c := byte(i)
		var f uint32
		isDigit := c >= '0' && c <= '9'
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		switch {
		case c == ' ' || c == '\t':
			f |= fSpace
		case c == ':':
			f |= fColon
		case c == '/':
			f |= fSlash
		case c == '\\':
			f |= fBackslash
		case c == '@':
			f |= fAt
		case c == '.':
			f |= fDot
		case isDigit:
			f |= fDigit
		case isUpper:
			f |= fUpper
		case isLower:
			f |= fLower
		}
		isHex := isDigit || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			f |= fNotHex
		}
		if !(isDigit || isUpper || isLower || c == '+' || c == '/' || c == '=' || c == '_' || c == '-') {
			f |= fNotB64
		}
		if !(isDigit || isUpper || isLower || c == '_') {
			f |= fNotIdent
		}
		if !(isDigit || isUpper || isLower || c == '.' || c == '-') {
			f |= fNotDomain
		}
		if !(isDigit || isUpper || isLower || c == '_' || c == '+' || c == '-') {
			f |= fNotAPI
		}
		t[i] = f
	}
	return t
}

// features returns the union of the byte-class features of s.
func features(s string) uint32 {
	var f uint32
	for i := 0; i < len(s); i++ {
		f |= featureTable[s[i]]
	}
	return f
}

// classification is the outcome of classifying one string.
type classification struct {
	cat  int
	kind string
	// redacted is the string with its secrets replaced; set only for secrets.
	redacted string
}

// Classify returns the category (one of the report.Cat* constants) and an
// optional refinement kind for s. The first matching category wins, in this
// order: secret, url, email, ip, registry, command, useragent, path, domain,
// api, base64, hex; everything else is plain. See the matcher files for what
// each category accepts. Classify never panics, whatever s contains.
//
// The kind refines the category: the key type for secrets, the scheme for URLs,
// "ipv4" or "ipv6" for addresses, the hive for registry keys, the shell family
// for commands, "browser" or "tool" for user agents, "windows", "unc" or
// "unix" for paths, the top-level domain for domains and the API group (for
// example "crypto" or "process") for API names.
func Classify(s string) (category, kind string) {
	c := classify(s)
	return categoryNames[c.cat], c.kind
}

func classify(s string) classification {
	f := features(s)

	if len(s) >= minSecretLen {
		if redacted, kinds := RedactSecrets(s); len(kinds) > 0 {
			return classification{cat: cSecret, kind: kinds[0], redacted: redacted}
		}
	}
	if f&fColon != 0 && f&fSlash != 0 {
		if scheme, ok := urlScheme(s); ok {
			return classification{cat: cURL, kind: scheme}
		}
	}
	if f&fAt != 0 && f&fDot != 0 && hasEmail(s) {
		return classification{cat: cEmail}
	}
	if kind := ipKind(s, f); kind != "" {
		return classification{cat: cIP, kind: kind}
	}
	if f&fBackslash != 0 || (f&fUpper != 0 && strings.Contains(s, "HKEY_")) {
		if hive, ok := registryHive(s); ok {
			return classification{cat: cRegistry, kind: hive}
		}
	}
	if f&fSpace != 0 && len(s) >= 6 {
		if kind, ok := commandKind(s); ok {
			return classification{cat: cCommand, kind: kind}
		}
	}
	if f&(fSlash|fColon) != 0 {
		if kind, ok := userAgentKind(s); ok {
			return classification{cat: cUserAgent, kind: kind}
		}
	}
	if f&(fSlash|fBackslash) != 0 {
		if kind, ok := pathKind(s); ok {
			return classification{cat: cPath, kind: kind}
		}
	}
	if f&fDot != 0 && f&fNotDomain == 0 {
		if tld, ok := domainTLD(s, f); ok {
			return classification{cat: cDomain, kind: tld}
		}
	}
	if f&fNotAPI == 0 {
		if group, ok := apiGroup(s); ok {
			return classification{cat: cAPI, kind: group}
		}
	}
	if f&fNotB64 == 0 && len(s) >= minBase64Len && isBase64Blob(s, f) {
		return classification{cat: cBase64}
	}
	if f&fNotHex == 0 && len(s) >= minHexLen && isHexBlob(s, f) {
		return classification{cat: cHex}
	}
	return classification{cat: cPlain}
}
