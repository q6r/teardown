package server

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestSanitizeName(t *testing.T) {
	manyAccents := strings.Repeat("é", 200) // 400 bytes
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "report.pdf", "report.pdf"},
		{"unix traversal", "../../etc/passwd", "passwd"},
		{"windows traversal", `..\..\boot.ini`, "boot.ini"},
		{"windows path", `C:\Users\x\a.exe`, "a.exe"},
		{"mixed separators", `a/b\c/d.txt`, "d.txt"},
		{"drive relative", "C:evil.exe", "evil.exe"},
		{"repeated drive remnants", "a:b:c.exe", "c.exe"},
		{"drive only", "C:", fallbackName},
		{"trailing slash", "dir/", fallbackName},
		{"root", "/", fallbackName},
		{"empty", "", fallbackName},
		{"dot", ".", fallbackName},
		{"dotdot", "..", fallbackName},
		{"dots and spaces", " . . ", fallbackName},
		{"dotfile kept", ".bashrc", ".bashrc"},
		{"NUL removed", "a\x00b", "ab"},
		{"tab and newline become spaces", "a\tb\nc", "a b c"},
		{"unicode line separator", "a\u2028b", "a b"},
		{"no-break space", "a\u00a0b", "a b"},
		{"escape sequence loses its introducer", "\x1b[31mred", "[31mred"},
		{"invalid UTF-8 dropped", "a\xffb", "ab"},
		{"bidi override removed", "photo\u202Efdp.exe", "photofdp.exe"},
		{"zero-width characters removed", "a\u200bb\u200dc", "abc"},
		{"only format characters", "\u200b\u200c\u202e", fallbackName},
		{"combining marks kept", "e\u0301.txt", "e\u0301.txt"},
		{"emoji kept", "🙂.png", "🙂.png"},
		{"spaces collapse and trim", "  a   b  ", "a b"},
		{"colon inside is kept", "file.txt:stream", "file.txt:stream"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeName(tc.in); got != tc.want {
				t.Fatalf("sanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("long names are cut but keep a short extension", func(t *testing.T) {
		got := sanitizeName(strings.Repeat("x", 400) + ".tar.gz")
		if len(got) != maxNameBytes || !strings.HasSuffix(got, ".gz") {
			t.Errorf("got %d bytes ending %q", len(got), got[len(got)-6:])
		}
	})
	t.Run("long names with a long extension are simply cut", func(t *testing.T) {
		got := sanitizeName(strings.Repeat("x", 300) + ".a-very-long-extension")
		if len(got) > maxNameBytes || got == "" {
			t.Errorf("got %d bytes", len(got))
		}
	})
	t.Run("multi-byte names are cut on a rune boundary", func(t *testing.T) {
		got := sanitizeName(manyAccents + ".dat")
		if len(got) > maxNameBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, ".dat") {
			t.Errorf("got %d bytes, valid=%v", len(got), utf8.ValidString(got))
		}
		bare := sanitizeName(manyAccents)
		if len(bare) > maxNameBytes || !utf8.ValidString(bare) {
			t.Errorf("bare multi-byte name: %d bytes, valid=%v", len(bare), utf8.ValidString(bare))
		}
	})
	t.Run("exactly at the limit is untouched", func(t *testing.T) {
		name := strings.Repeat("y", maxNameBytes)
		if got := sanitizeName(name); got != name {
			t.Errorf("a %d-byte name changed to %d bytes", maxNameBytes, len(got))
		}
	})
}

func TestCutRunes(t *testing.T) {
	tests := []struct {
		in    string
		limit int
		want  string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"éé", 3, "é"},  // 4 bytes: the second é does not fit
		{"日本語", 4, "日"}, // 9 bytes
		{"日本語", 0, ""},
		{"🙂🙂", 5, "🙂"},
	}
	for _, tc := range tests {
		if got := cutRunes(tc.in, tc.limit); got != tc.want {
			t.Errorf("cutRunes(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
	}
}

// checkSanitized asserts the guarantees documented on sanitizeName.
func checkSanitized(t *testing.T, in, got string) {
	t.Helper()
	switch {
	case got == "":
		t.Errorf("sanitizeName(%q) is empty", in)
	case !utf8.ValidString(got):
		t.Errorf("sanitizeName(%q) = %q is not valid UTF-8", in, got)
	case len(got) > maxNameBytes:
		t.Errorf("sanitizeName(%q) is %d bytes", in, len(got))
	case strings.ContainsAny(got, `/\`):
		t.Errorf("sanitizeName(%q) = %q contains a path separator", in, got)
	case got != strings.TrimSpace(got):
		t.Errorf("sanitizeName(%q) = %q has leading or trailing space", in, got)
	}
	for _, r := range got {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("sanitizeName(%q) = %q contains control or format rune %U", in, got, r)
		}
	}
	if again := sanitizeName(got); again != got {
		t.Errorf("sanitizeName is not idempotent: %q -> %q -> %q", in, got, again)
	}
}

func FuzzSanitizeName(f *testing.F) {
	for _, seed := range []string{
		"", "a", "report.pdf", "../../etc/passwd", `..\..\windows\system32`, `C:\Windows\x.exe`, "C:evil.exe", "a:b:c",
		".", "..", "...", " ", "\x00", "a\x00b", "\x1b[2J", "a\u202eb", "\xff\xfe", "dir/", "/", `\`,
		strings.Repeat("a", 300), strings.Repeat("é", 300) + ".exe", strings.Repeat("x", 254) + "é.exe",
		"e\u0301", "🙂", "a\u2028b", "\u200b", "file.txt:stream", ".bashrc", strings.Repeat(".", 300),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		checkSanitized(t, in, sanitizeName(in))
	})
}
