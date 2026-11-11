package analyze_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/render"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/testfixtures"
)

// fakeKeyLines returns the body of a made-up private key: random bytes from a
// fixed seed, 48 bytes (64 base64 characters) to a line. No line is a real key.
func fakeKeyLines(n int) []string {
	rng := rand.New(rand.NewPCG(3, 5))
	out := make([]string, n)
	for i := range out {
		raw := make([]byte, 48)
		for j := range raw {
			raw[j] = byte(rng.UintN(256))
		}
		out[i] = base64.StdEncoding.EncodeToString(raw)
	}
	return out
}

// TestMultiLinePrivateKeyNeverLeavesThroughAnyOutput plants a fake private key
// written over many lines in three kinds of file (a text file, a PE image and a
// UTF-16 file) and looks for every line of it, and for the bytes of every line as
// hex, in the report as JSON, text, Markdown, HTML and SARIF.
func TestMultiLinePrivateKeyNeverLeavesThroughAnyOutput(t *testing.T) {
	body := fakeKeyLines(30)
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----\n"
	text := "# deploy notes\nsee https://deploy.example.test/docs for the setup\n" + key + "contact ops@example.test\n"

	var wide []byte
	for _, u := range text {
		wide = append(wide, byte(u), 0)
	}
	pe := testfixtures.PE(testfixtures.PEOptions{Overlay: []byte("pad\x00" + key + "\x00after the key\x00")})

	files := map[string][]byte{"notes.txt": []byte(text), "keys.exe": pe, "wide.txt": wide}
	fixed := func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			rep, err := analyze.Reader(context.Background(), bytes.NewReader(data), int64(len(data)), analyze.Options{Name: name, Now: fixed})
			if err != nil {
				t.Fatal(err)
			}
			secrets := 0
			for _, it := range rep.Strings.Items {
				if it.Category == report.CatSecret {
					secrets++
				}
			}
			if secrets == 0 {
				t.Fatal("the private key header was not reported: the test would prove nothing")
			}

			outputs := map[string]string{}
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			outputs["json"] = string(raw)
			var sb strings.Builder
			for label, render := range map[string]func(*strings.Builder) error{
				"text": func(w *strings.Builder) error {
					return render.Text(w, rep, render.Options{Width: 120, Verbose: true, CodeAll: true})
				},
				"markdown": func(w *strings.Builder) error { return render.Markdown(w, rep) },
				"html":     func(w *strings.Builder) error { return render.HTML(w, rep) },
				"sarif":    func(w *strings.Builder) error { return render.SARIF(w, rep) },
			} {
				sb.Reset()
				if err := render(&sb); err != nil {
					t.Fatal(err)
				}
				outputs[label] = sb.String()
			}
			outputs["json without code"] = mustJSON(t, rep.WithoutCode())

			for label, out := range outputs {
				for i, line := range body {
					for _, frag := range []string{line, line[:16], line[len(line)-16:]} {
						if strings.Contains(out, frag) {
							t.Fatalf("%s output: line %d of the key appears as %q", label, i, frag)
						}
					}
					// The bytes of the line as the hex column of a window prints them.
					hexRun := hexOf([]byte(line[:8]))
					if strings.Contains(out, hexRun) {
						t.Fatalf("%s output: line %d of the key appears as hex %q", label, i, hexRun)
					}
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func hexOf(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, " ")
}
