package server

import (
	"mime"
	"mime/multipart"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// fallbackName is the display name used when a client supplies nothing usable.
	fallbackName = "upload.bin"
	// maxNameBytes caps the display name length.
	maxNameBytes = 255
	// maxExtBytes is the longest extension preserved when a long name is cut.
	maxExtBytes = 16
)

// sanitizeName turns a client-supplied file name into a safe display name. The
// result is never used as a path: it only labels the report. It is always
// non-empty valid UTF-8 of at most 255 bytes, contains no path separators, no
// control or format characters (which includes bidirectional overrides), and
// keeps a short file extension when a long name has to be cut. It is idempotent:
// sanitizeName(sanitizeName(x)) equals sanitizeName(x).
func sanitizeName(raw string) string {
	s := strings.ToValidUTF8(raw, "")
	s = strings.ReplaceAll(s, `\`, "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.Join(strings.Fields(cleanRunes(s)), " ")
	for len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) { // drive-relative remnants such as "C:file.exe"
		s = strings.TrimSpace(s[2:])
	}
	// Cut first and judge what is left afterwards. Cutting a long name can leave
	// nothing but dots and spaces (the fuzzer found ". . . 0." cut to ". . . .."),
	// and the fallback must apply in this call, not only when the result is
	// sanitized a second time.
	s = truncateName(s, maxNameBytes)
	if strings.Trim(s, ". ") == "" {
		return fallbackName
	}
	return s
}

// cleanRunes turns every kind of whitespace into a plain space and drops control
// and format characters.
func cleanRunes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// truncateName shortens s to at most limit bytes on a rune boundary, keeping a
// short trailing extension so that "…aaaa.exe" is still recognisable.
func truncateName(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	ext := path.Ext(s)
	if len(ext) > maxExtBytes || ext == s {
		ext = ""
	}
	stem := cutRunes(s[:len(s)-len(ext)], limit-len(ext))
	return strings.TrimSpace(stem) + ext
}

// cutRunes returns the longest prefix of s that is at most limit bytes long and
// does not split a rune.
func cutRunes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// partFilename returns the raw filename parameter of a multipart part. The
// standard library's Part.FileName applies filepath.Base, which is platform
// dependent; sanitizeName needs the raw value to treat both separators alike.
func partFilename(p *multipart.Part) string {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	return params["filename"]
}
