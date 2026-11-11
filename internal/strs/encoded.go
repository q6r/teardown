package strs

import (
	"encoding/base64"
	"strings"
)

// Minimum lengths of encoded blobs.
const (
	minBase64Len = 40
	minHexLen    = 32
	// hexAlwaysLen is the length from which a hex run is accepted even when it
	// lacks either digits or letters.
	hexAlwaysLen = 64
)

// isHexBlob reports whether s (all hex digits, per f) looks like a hex-encoded
// blob: an even length of at least 32 characters that mixes digits with letters
// (typical of digests and keys), or any even run of 64 or more.
func isHexBlob(s string, f uint32) bool {
	if len(s)%2 != 0 {
		return false
	}
	mixed := f&fDigit != 0 && f&(fUpper|fLower) != 0
	return mixed || len(s) >= hexAlwaysLen
}

// isBase64Blob reports whether s (all base64 or base64url characters, per f)
// looks like a base64-encoded blob rather than an identifier: it is not pure
// hex, mixes digits with upper- and lower-case letters, has valid padding and a
// valid length, uses only one of the two alphabets, has few separators and
// decodes with zero trailing bits.
func isBase64Blob(s string, f uint32) bool {
	if f&fNotHex == 0 {
		return false
	}
	if f&fDigit == 0 || f&fUpper == 0 || f&fLower == 0 {
		return false
	}
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 || strings.IndexByte(body, '=') >= 0 {
		return false
	}
	if len(s) != len(body) && len(s)%4 != 0 {
		return false
	}
	if len(body)%4 == 1 {
		return false
	}
	std := strings.ContainsAny(body, "+/")
	url := strings.ContainsAny(body, "-_")
	if std && url {
		return false
	}
	if url && strings.Count(body, "_")+strings.Count(body, "-") > len(body)/12 {
		return false
	}
	enc := base64.RawStdEncoding
	if url {
		enc = base64.RawURLEncoding
	}
	_, err := enc.Strict().DecodeString(body)
	return err == nil
}
