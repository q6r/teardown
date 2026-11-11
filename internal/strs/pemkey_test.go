package strs

import (
	"encoding/base64"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/q6r/teardown/internal/report"
)

// fakeKeyBody returns the base64 body lines of a made-up private key: random
// bytes from a fixed seed, 48 bytes (64 characters) per line, so no line is a
// real key and every line is distinct.
func fakeKeyBody(lines int) []string {
	rng := rand.New(rand.NewPCG(7, 11))
	out := make([]string, lines)
	for i := range out {
		raw := make([]byte, 48)
		for j := range raw {
			raw[j] = byte(rng.UintN(256))
		}
		out[i] = base64.StdEncoding.EncodeToString(raw)
	}
	return out
}

// pemFile lays out a file around a multi-line private key: text before, the key
// with the given line break, and text after.
func pemFile(header string, body []string, footer, lineBreak string) string {
	return "preamble-before-the-key" + lineBreak + header + lineBreak + strings.Join(body, lineBreak) + lineBreak + footer + lineBreak + "https://after.example.test/path" + lineBreak
}

const (
	testPEMHeader = "-----BEGIN RSA PRIVATE KEY-----"
	testPEMFooter = "-----END RSA PRIVATE KEY-----"
)

// leaks returns the first body line, or a fragment of one, that appears in any
// item of the result.
func leaks(res report.Strings, body []string) string {
	for _, it := range res.Items {
		for _, line := range body {
			for _, frag := range []string{line, line[:16], line[len(line)-16:]} {
				if strings.Contains(it.Value, frag) {
					return frag
				}
			}
		}
	}
	return ""
}

func scanMin(t *testing.T, data []byte, minLength int) report.Strings {
	t.Helper()
	s := NewScanner(Options{MinLength: minLength})
	if _, err := s.Write(data); err != nil {
		t.Fatal(err)
	}
	return s.Result()
}

func valuesOf(res report.Strings) []string {
	out := make([]string, len(res.Items))
	for i, it := range res.Items {
		out[i] = it.Value
	}
	return out
}

func TestMultiLinePrivateKeyBodyIsPartOfTheSecret(t *testing.T) {
	body := fakeKeyBody(25)
	for _, lineBreak := range []string{"\n", "\r\n"} {
		name := map[string]string{"\n": "LF", "\r\n": "CRLF"}[lineBreak]
		t.Run(name, func(t *testing.T) {
			res := scanMin(t, []byte(pemFile(testPEMHeader, body, testPEMFooter, lineBreak)), 0)
			if frag := leaks(res, body); frag != "" {
				t.Fatalf("a line of the key is listed as a string: %q in %q", frag, valuesOf(res))
			}
			// The header is the one secret, redacted as before.
			var secrets []report.StringItem
			for _, it := range res.Items {
				if it.Category == report.CatSecret {
					secrets = append(secrets, it)
				}
			}
			if len(secrets) != 1 || secrets[0].Kind != kindPEM || !secrets[0].Redacted || secrets[0].Value != "----…(31 chars)" {
				t.Fatalf("secrets = %+v", secrets)
			}
			// What comes before and after the key is still found.
			vals := valuesOf(res)
			for _, want := range []string{"preamble-before-the-key", "https://after.example.test/path"} {
				if !slices.Contains(vals, want) {
					t.Errorf("the string %q around the key was lost: %q", want, vals)
				}
			}
			if res.ByCategory[report.CatSecret] != 1 || res.ByCategory[report.CatBase64] != 0 {
				t.Errorf("by category = %v: the key is one secret, and no body line is a string of its own", res.ByCategory)
			}
		})
	}
}

func TestPrivateKeyBodyIsHiddenWhateverTheFormat(t *testing.T) {
	body := fakeKeyBody(10)
	tests := []struct {
		name string
		data string
	}{
		{"other key types", pemFile("-----BEGIN PRIVATE KEY-----", body, "-----END PRIVATE KEY-----", "\n")},
		{"openssh", pemFile("-----BEGIN OPENSSH PRIVATE KEY-----", body, "-----END OPENSSH PRIVATE KEY-----", "\n")},
		{"pgp block", pemFile("-----BEGIN PGP PRIVATE KEY BLOCK-----", body, "-----END PGP PRIVATE KEY BLOCK-----", "\n")},
		{"encrypted with headers", pemFile(testPEMHeader+"\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n", body, testPEMFooter, "\n")},
		{"indented in a script", "var k = `" + testPEMHeader + "\n    " + strings.Join(body, "\n    ") + "\n    " + testPEMFooter + "`;\n"},
		{"the footer is missing", pemFile(testPEMHeader, body, "", "\n")},
		{"a blank line inside", "x\n" + testPEMHeader + "\n" + strings.Join(body[:5], "\n") + "\n\n" + strings.Join(body[5:], "\n") + "\n" + testPEMFooter + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, min := range []int{3, 5} {
				res := scanMin(t, []byte(tc.data), min)
				if frag := leaks(res, body); frag != "" {
					t.Fatalf("minimum length %d: a line of the key is listed: %q in %q", min, frag, valuesOf(res))
				}
			}
		})
	}
}

func TestPrivateKeyBodyInUTF16(t *testing.T) {
	body := fakeKeyBody(8)
	for _, lineBreak := range []string{"\n", "\r\n"} {
		text := pemFile(testPEMHeader, body, testPEMFooter, lineBreak)
		var raw []byte
		for _, u := range utf16.Encode([]rune(text)) {
			raw = append(raw, byte(u), byte(u>>8))
		}
		res := scanMin(t, raw, 0)
		if frag := leaks(res, body); frag != "" {
			t.Fatalf("a UTF-16 line of the key is listed: %q in %q", frag, valuesOf(res))
		}
		found := false
		for _, it := range res.Items {
			found = found || (it.Category == report.CatSecret && it.Encoding == "utf16le")
		}
		if !found {
			t.Errorf("the UTF-16 header is still reported: %+v", res.Items)
		}
	}
}

func TestPrivateKeyHidingIsBoundedAndLeavesOtherStringsAlone(t *testing.T) {
	t.Run("at most a bounded number of lines follow a header", func(t *testing.T) {
		body := fakeKeyBody(maxPEMLines + 40)
		res := scanMin(t, []byte(pemFile(testPEMHeader, body, "", "\n")), 0)
		listed := 0
		for _, line := range body {
			if slices.Contains(valuesOf(res), line) {
				listed++
			}
		}
		if listed != 40 {
			t.Errorf("%d lines beyond the bound are listed, want 40 (the bound is %d lines)", listed, maxPEMLines)
		}
	})
	t.Run("a line that is not base64 ends the key", func(t *testing.T) {
		data := testPEMHeader + "\n" + fakeKeyBody(1)[0] + "\nthis is ordinary text, not key material\n" + fakeKeyBody(2)[1] + "\n"
		vals := valuesOf(scanMin(t, []byte(data), 0))
		if !slices.Contains(vals, "this is ordinary text, not key material") || !slices.Contains(vals, fakeKeyBody(2)[1]) {
			t.Errorf("strings after the key stay visible: %q", vals)
		}
	})
	t.Run("a header followed by a gap is not followed", func(t *testing.T) {
		data := testPEMHeader + "\n\x00\x00\x00\x00\x00" + fakeKeyBody(1)[0] + "\n"
		vals := valuesOf(scanMin(t, []byte(data), 0))
		if !slices.Contains(vals, fakeKeyBody(1)[0]) {
			t.Errorf("bytes far from the header are not part of the key: %q", vals)
		}
	})
	t.Run("a header with its key on the same line takes no following line", func(t *testing.T) {
		data := testPEMHeader + fakeKeyBody(1)[0] + "\n" + fakeKeyBody(2)[1] + "\n"
		vals := valuesOf(scanMin(t, []byte(data), 0))
		if !slices.Contains(vals, fakeKeyBody(2)[1]) {
			t.Errorf("the next line is ordinary: %q", vals)
		}
	})
	t.Run("two keys in a row", func(t *testing.T) {
		a, b := fakeKeyBody(6), fakeKeyBody(12)[6:]
		data := pemFile(testPEMHeader, a, testPEMFooter, "\n") + pemFile(testPEMHeader, b, testPEMFooter, "\n")
		res := scanMin(t, []byte(data), 0)
		if frag := leaks(res, append(slices.Clone(a), b...)); frag != "" {
			t.Errorf("a line of a key is listed: %q", frag)
		}
		if res.ByCategory[report.CatSecret] != 2 {
			t.Errorf("by category = %v", res.ByCategory)
		}
	})
}

func TestPrivateKeyHidingDoesNotDependOnTheChunking(t *testing.T) {
	data := []byte(pemFile(testPEMHeader, fakeKeyBody(30), testPEMFooter, "\r\n"))
	whole := scanMin(t, data, 0)
	for _, size := range []int{1, 3, 7, 64, 1000} {
		s := NewScanner(Options{})
		for i := 0; i < len(data); i += size {
			if _, err := s.Write(data[i:min(i+size, len(data))]); err != nil {
				t.Fatal(err)
			}
		}
		got := s.Result()
		if !slices.Equal(valuesOf(got), valuesOf(whole)) || got.Total != whole.Total {
			t.Fatalf("chunks of %d bytes: %q (total %d), whole: %q (total %d)", size, valuesOf(got), got.Total, valuesOf(whole), whole.Total)
		}
	}
}
