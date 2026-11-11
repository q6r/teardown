package strs

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// classifySeeds are representative inputs for the classifier fuzz target.
func classifySeeds() []string {
	seeds := []string{
		"http://example.com/path", "Failed to fetch https://example.com/x: timeout", "admin@example.com",
		"192.168.1.1", "10.0.0.5:8080", "::1", "[::1]:8080", "fe80::1%eth0", "12:34:56",
		`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SYSTEM\CurrentControlSet`,
		`cmd.exe /c whoami`, `powershell -nop -w hidden -enc SQBFAFgA`, `/bin/sh -c "echo hi"`,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "curl/7.68.0",
		`C:\Windows\System32\drivers\etc\hosts`, `\\server\share\file`, "/usr/lib/libc.so.6", "~/.ssh/id_rsa",
		"example.com", "evil.onion", "Microsoft.NET", "CreateRemoteThread", "CreateFileW", "BCryptEncrypt",
		"SGVsbG8sIHdvcmxkISBUaGlzIGlzIGEgYmFzZTY0IGVuY29kZWQgc3RyaW5nLg==",
		"d41d8cd98f00b204e9800998ecf8427e", "plain text", "", "\x00\xff", "é€😀",
		"eyJ.eyJ.eyJ", "ghp_", "AKIA", "xox", "-----BEGIN ", "github_pat_",
	}
	return append(seeds, testSecrets()...)
}

func FuzzClassify(f *testing.F) {
	for _, s := range classifySeeds() {
		f.Add(s)
	}
	f.Add(testPEM)
	f.Add("prefix" + testAWSKey + "suffix" + testGitHubPAT)
	valid := map[string]bool{}
	for _, c := range report.StringCategories() {
		valid[c] = true
	}
	f.Fuzz(func(t *testing.T, s string) {
		cat, kind := Classify(s)
		if !valid[cat] {
			t.Fatalf("Classify returned unknown category %q", cat)
		}
		redacted, kinds := RedactSecrets(s)
		if (cat == report.CatSecret) != (len(kinds) > 0) {
			t.Fatalf("category %q but secret kinds %v for %q", cat, kinds, s)
		}
		if cat == report.CatSecret {
			if kind != kinds[0] {
				t.Fatalf("secret kind %q, want %q", kind, kinds[0])
			}
			again, kinds2 := RedactSecrets(redacted)
			if again != redacted || len(kinds2) != 0 {
				t.Fatalf("RedactSecrets is not idempotent: %q -> %q (%v)", redacted, again, kinds2)
			}
		} else if redacted != s {
			t.Fatalf("RedactSecrets changed a non-secret string: %q -> %q", s, redacted)
		}
		if r := Redact(s); !strings.Contains(r, "…(") {
			t.Fatalf("Redact lost its marker: %q", r)
		}
	})
}

func FuzzScanner(f *testing.F) {
	seeds := [][]byte{
		sampleStream(1, 80),
		sampleStream(2, 40),
		[]byte(testAWSKey),
		utf16le(testAWSKey),
		[]byte("\x00\x00hello world\x00ab\x00tab\tinside\n\x80\xffxyz12345"),
		join([]byte{1}, utf16le("Hello"), []byte{0, 0, 0}, utf16le("World!")),
		join([]byte("abc\x00"), utf16le("defgh"), []byte{0, 0}),
		[]byte(strings.Repeat("word ", 1000)),
		{},
	}
	for _, s := range seeds {
		f.Add(s, uint8(7))
		f.Add(s, uint8(0))
	}
	secrets := append(testSecrets(), testPEM)
	opts := Options{MaxItems: 8, MinLength: 3}
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		whole := scan(data, opts, 0)
		if chunked := scan(data, opts, int(chunk)+1); !reflect.DeepEqual(whole, chunked) {
			t.Fatalf("result depends on chunking (chunk %d): total %d vs %d", int(chunk)+1, whole.Total, chunked.Total)
		}

		sum := 0
		for _, n := range whole.ByCategory {
			sum += n
		}
		if sum != whole.Total || len(whole.Items) > opts.MaxItems {
			t.Fatalf("inconsistent result: total %d, category sum %d, items %d", whole.Total, sum, len(whole.Items))
		}
		if !slices.IsSortedFunc(whole.Items, func(a, b report.StringItem) int { return int(a.Offset - b.Offset) }) {
			t.Fatal("items are not sorted by offset")
		}
		if _, err := json.Marshal(whole); err != nil {
			t.Fatal(err)
		}
		for _, it := range whole.Items {
			// Values are checked directly: JSON escapes such as > end in
			// letters and can spell a secret prefix by accident.
			for _, s := range secrets {
				if strings.Contains(it.Value, s) {
					t.Fatalf("raw secret %q… leaked into an item", s[:6])
				}
			}
			if it.Offset < 0 || it.Offset >= int64(max(len(data), 1)) {
				t.Fatalf("offset %d outside a stream of %d bytes", it.Offset, len(data))
			}
			if _, kinds := RedactSecrets(it.Value); len(kinds) > 0 {
				t.Fatalf("stored value still contains a secret: %q", it.Value)
			}
			if it.Category != report.CatSecret {
				if cat, kind := Classify(it.Value); cat != it.Category || kind != it.Kind {
					t.Fatalf("stored category (%q, %q) disagrees with Classify (%q, %q) for %q", it.Category, it.Kind, cat, kind, it.Value)
				}
			}
		}
	})
}
