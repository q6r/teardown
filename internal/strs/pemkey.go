package strs

import (
	"bytes"
	"regexp"
)

// maxPEMLines bounds how many lines after a private-key header are taken to be
// the key. A key is written 64 or 76 characters to a line: an 8192-bit RSA key
// has about a hundred lines, so this leaves room for any real key and stops the
// reading of a header that has no end marker.
const maxPEMLines = 256

// pemHeaderEnd matches a private-key header that ends its line, which is how a
// key written over several lines starts. A header with more text behind it on
// the same line is a key written on one line, which the secret rules already
// take whole.
var pemHeaderEnd = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[ \t]*$`)

// pemEnd is the marker that closes a PEM block.
var pemEnd = []byte("-----END ")

// pemState follows a multi-line private key across the lines that come after its
// header. The scanner sees a file one printable run (one line) at a time, so the
// base64 lines of the key would otherwise be listed as strings of their own, in
// the clear, next to a redacted header: the key must not leave the scanner in
// full, however many lines it spans.
type pemState struct {
	open bool
	enc  encoding
	// end is the stream offset just after the last line taken into the key; the
	// next line has to start within one line break of it.
	end   int64
	lines int
}

// openKey starts following a key whose header ended at stream offset end.
func (s *Scanner) openKey(enc encoding, end int64) {
	s.pem = pemState{open: true, enc: enc, end: end}
}

// keyBody reports whether the run is a line of the private key whose header came
// just before, in which case it is part of the secret and the scanner drops it.
// A key ends at its END marker, at the first line that is not base64 (or one of
// the two headers an encrypted key carries), at a gap in the stream or after
// [maxPEMLines] lines. Those lines are then ordinary strings again.
func (s *Scanner) keyBody(off int64, enc encoding, raw []byte) bool {
	// The two encodings are tracked side by side, and a wide string is full of
	// one-character ASCII runs between its characters: only a run of the key's own
	// encoding says anything about the key.
	if !s.pem.open || enc != s.pem.enc {
		return false
	}
	unit := int64(1)
	if enc == encUTF16 {
		unit = 2
	}
	gap := off - s.pem.end
	line := bytes.Trim(raw, " \t")
	if gap < 1 || gap > 2*unit || s.pem.lines >= maxPEMLines || bytes.Contains(line, pemEnd) || !pemBodyLine(line) {
		s.pem = pemState{}
		return false
	}
	s.pem.end = off + int64(len(raw))*unit
	s.pem.lines++
	return true
}

// pemBodyLine reports whether a line is base64 or one of the headers of an
// encrypted key.
func pemBodyLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	if bytes.HasPrefix(line, []byte("Proc-Type:")) || bytes.HasPrefix(line, []byte("DEK-Info:")) {
		return true
	}
	for _, c := range line {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '/' && c != '=' {
			return false
		}
	}
	return true
}
