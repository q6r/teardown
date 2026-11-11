package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Markdown writes a GitHub-flavoured Markdown report. Text that comes from the
// analysed file is escaped or placed in code spans.
func Markdown(w io.Writer, rep *report.Report) error {
	var sb strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&sb, format+"\n", a...) }

	line("# teardown report: %s", code(rep.File.Name))
	line("")
	line("> %s", mdText(report.StaticOnly))
	line("")
	line("| | |")
	line("|---|---|")
	line("| Type | %s (%s confidence) |", cell(rep.Type.Label), rep.Type.Confidence)
	if len(rep.Type.Tags) > 0 {
		tags := make([]string, len(rep.Type.Tags))
		for i, t := range rep.Type.Tags {
			tags[i] = code(t)
		}
		line("| Tags | %s |", strings.Join(tags, " "))
	}
	line("| Size | %s (%s bytes) |", humanBytes(rep.File.Size), groupInt(int(rep.File.Size)))
	line("| Risk | **%d/100 %s** |", rep.Risk.Score, rep.Risk.Label)
	line("| Entropy | %.2f of 8.00 bits per byte |", rep.Entropy.Overall)
	line("| Generated | %s by teardown %s in %d ms |", rep.GeneratedAt.UTC().Format("2006-01-02 15:04:05Z"), cell(rep.Tool.Version), rep.DurationMs)
	line("")

	line("## Findings (%d)", len(rep.Findings))
	line("")
	if len(rep.Findings) == 0 {
		line("No findings.")
		line("")
	}
	for _, f := range rep.Findings {
		line("### [%s] %s: %s", strings.ToUpper(string(f.Severity)), code(f.ID), mdText(f.Title))
		line("")
		line("Confidence: **%s** · category: %s", f.Confidence, mdText(f.Category))
		line("")
		if len(f.Evidence) > 0 {
			line("Evidence:")
			line("")
			for _, e := range f.Evidence {
				line("- %s", mdText(e))
			}
			line("")
		}
		if len(f.Limitations) > 0 {
			line("Limitations:")
			line("")
			for _, l := range f.Limitations {
				line("- %s", mdText(l))
			}
			line("")
		}
	}

	line("## Risk basis")
	line("")
	for _, b := range rep.Risk.Basis {
		line("- %s", mdText(b))
	}
	line("")

	line("## Hashes")
	line("")
	line("| Algorithm | Digest |")
	line("|---|---|")
	line("| MD5 | `%s` |", rep.Hashes.MD5)
	line("| SHA-1 | `%s` |", rep.Hashes.SHA1)
	line("| SHA-256 | `%s` |", rep.Hashes.SHA256)
	if rep.Hashes.Imphash != "" {
		line("| Imphash | `%s` |", rep.Hashes.Imphash)
	}
	line("")

	if len(rep.Hardening) > 0 {
		line("## Hardening")
		line("")
		line("| Feature | Status | Detail |")
		line("|---|---|---|")
		for _, h := range rep.Hardening {
			line("| %s | %s | %s |", cell(h.Label), h.Status, cell(h.Detail))
		}
		line("")
	}

	if len(rep.Sections) > 0 {
		line("## Sections")
		line("")
		line("| Name | Virtual | Raw | Entropy | Flags | Notes |")
		line("|---|---:|---:|---:|---|---|")
		for _, s := range rep.Sections {
			note := ""
			if s.Suspicious {
				note = strings.Join(s.Reasons, "; ")
				if note == "" {
					note = "suspicious"
				}
			}
			line("| %s | %s | %s | %.2f | %s | %s |", cell(s.Name), humanBytes(int64(s.VirtualSize)), humanBytes(int64(s.RawSize)), s.Entropy, flagCell(s), cell(note))
		}
		line("")
	}

	if len(rep.Imports) > 0 {
		line("## Imports")
		line("")
		line("| Library | Functions |")
		line("|---|---:|")
		libs := append([]report.Import(nil), rep.Imports...)
		sort.SliceStable(libs, func(i, j int) bool { return libs[i].Count > libs[j].Count })
		for _, im := range libs {
			line("| %s | %d |", cell(im.Library), im.Count)
		}
		line("")
	}
	if len(rep.Exports) > 0 {
		line("## Exports")
		line("")
		shown := rep.Exports
		if len(shown) > 50 {
			shown = shown[:50]
		}
		for _, e := range shown {
			line("- %s", code(e))
		}
		if len(shown) < len(rep.Exports) {
			line("- (+%d more, see the JSON report)", len(rep.Exports)-len(shown))
		}
		line("")
	}

	line("## Strings")
	line("")
	line("%s strings found (minimum length %d)%s.", groupInt(rep.Strings.Total), rep.Strings.MinLength, truncNote(rep.Strings.Truncated))
	line("")
	var cats []string
	for _, c := range report.StringCategories() {
		if n := rep.Strings.ByCategory[c]; n > 0 {
			cats = append(cats, fmt.Sprintf("%s %s", c, groupInt(n)))
		}
	}
	if len(cats) > 0 {
		line("By category: %s.", strings.Join(cats, ", "))
		line("")
	}
	shown := 0
	for _, c := range report.StringCategories() {
		if c == report.CatPlain || c == report.CatBase64 || c == report.CatHex {
			continue
		}
		for _, it := range rep.Strings.Items {
			if it.Category == c && shown < 40 {
				shown++
				line("- `%s` %s %s", it.Category, fmt.Sprintf("0x%x", it.Offset), code(clip(it.Value, 160)))
			}
		}
	}
	if shown > 0 {
		line("")
	}

	if len(rep.Details) > 0 {
		line("## Format details")
		line("")
		keys := make([]string, 0, len(rep.Details))
		for k := range rep.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pairs := scalarFacts(rep.Details[k], factOrder[k])
			if len(pairs) == 0 {
				continue
			}
			line("**%s**", mdText(k))
			line("")
			for _, kv := range pairs {
				line("- %s: %s", mdText(kv[0]), code(clip(kv[1], 160)))
			}
			line("")
		}
	}

	line("## Limitations")
	line("")
	for _, l := range rep.Limitations {
		line("- %s", mdText(l))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// code wraps s in a Markdown code span, choosing a fence longer than any run of
// backticks inside s.
func code(s string) string {
	s = safe(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

var mdReplacer = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "|", `\|`, "&", `&amp;`,
)

// mdText escapes Markdown and HTML metacharacters in untrusted text.
func mdText(s string) string { return mdReplacer.Replace(safe(s)) }

// cell is mdText for table cells.
func cell(s string) string { return mdText(s) }
