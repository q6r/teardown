package archive

import (
	"iter"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

const (
	// maxManifestKeys bounds the attributes recorded from a manifest.
	maxManifestKeys = 64
	maxManifestKey  = 64
	maxManifestVal  = 512
)

// parseManifest reads the main section of a JAR manifest (META-INF/MANIFEST.MF):
// "Name: value" lines, where a line starting with a single space continues the
// previous one, ending at the first blank line. Per-entry sections are ignored.
// Keys keep their written case; the result is capped in size.
func parseManifest(data []byte) map[string]string {
	attrs := map[string]string{}
	var key string
	var val strings.Builder
	flush := func() {
		if key == "" || len(attrs) >= maxManifestKeys {
			return
		}
		attrs[binio.Printable(key, maxManifestKey)] = binio.Printable(val.String(), maxManifestVal)
	}
	for line := range manifestLines(string(data)) {
		if line == "" {
			break
		}
		if line[0] == ' ' {
			if key != "" && val.Len() < 4*maxManifestVal {
				val.WriteString(line[1:])
			}
			continue
		}
		flush()
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			key = ""
			continue
		}
		key = name
		val.Reset()
		val.WriteString(strings.TrimPrefix(value, " "))
	}
	flush()
	return attrs
}

// manifestLines splits on CRLF, LF or a lone CR, the three line terminators the
// manifest specification allows.
func manifestLines(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for len(s) > 0 {
			i := strings.IndexAny(s, "\r\n")
			if i < 0 {
				yield(s)
				return
			}
			line := s[:i]
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				s = s[i+2:]
			} else {
				s = s[i+1:]
			}
			if !yield(line) {
				return
			}
		}
	}
}
