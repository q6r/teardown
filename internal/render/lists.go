package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/diff"
	"github.com/q6r/teardown/internal/report"
)

// Strings writes extracted strings one per line: offset, encoding, category, value.
func Strings(w io.Writer, s report.Strings, o Options) error {
	p := palette{on: o.Color}
	var sb strings.Builder
	for _, it := range s.Items {
		enc := "a"
		if it.Encoding == "utf16le" {
			enc = "u"
		}
		fmt.Fprintf(&sb, "%s %s %s %s\n", p.dim(fmt.Sprintf("0x%08x", it.Offset)), enc, p.cyan(padRight(it.Category, 9)), safe(it.Value))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// StringsFooter writes the one-line summary printed after a strings listing.
func StringsFooter(w io.Writer, shown int, s report.Strings, o Options) error {
	p := palette{on: o.Color}
	note := ""
	if s.Truncated {
		note = ", list truncated: raise --max-strings or narrow with --category"
	}
	_, err := fmt.Fprintf(w, "%s\n", p.dim(fmt.Sprintf("%d of %s strings shown (minimum length %d%s)", shown, groupInt(s.Total), s.MinLength, note)))
	return err
}

// Hash writes the digests, type and entropy of a quick summary.
func Hash(w io.Writer, s *analyze.Summary, o Options) error {
	p := palette{on: o.Color}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  %s\n", p.bold(safe(s.File.Name)), p.dim(fmt.Sprintf("%s · %s", humanBytes(s.File.Size), safe(s.Type.Label))))
	fmt.Fprintf(&sb, "  md5      %s\n  sha1     %s\n  sha256   %s\n", s.Hashes.MD5, s.Hashes.SHA1, s.Hashes.SHA256)
	if s.Hashes.Imphash != "" {
		fmt.Fprintf(&sb, "  imphash  %s\n", s.Hashes.Imphash)
	}
	fmt.Fprintf(&sb, "  entropy  %s %.2f\n", bar(s.Entropy.Overall/8, 24, o.ASCII), s.Entropy.Overall)
	_, err := io.WriteString(w, sb.String())
	return err
}

// Diff writes the human-readable comparison of two reports.
func Diff(w io.Writer, d *diff.Result, o Options) error {
	p := palette{on: o.Color}
	var sb strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&sb, format+"\n", a...) }
	describe := func(tag string, s diff.Side) {
		line("%s  %s  %s", p.bold(tag), p.bold(safe(s.Name)), p.dim(fmt.Sprintf("%s · %s · risk %d", humanBytes(s.Size), safe(s.TypeLabel), s.Risk)))
		line("   %s", p.dim("sha256 "+s.SHA256))
	}
	line("%s", p.bold("teardown diff"))
	line("")
	describe("a", d.A)
	describe("b", d.B)
	line("")
	line("%s", p.bold("── Summary"))
	for _, s := range d.Summary {
		line("  · %s", safe(s))
	}
	section := func(title, sign string, items []string, color func(string) string) {
		if len(items) == 0 {
			return
		}
		line("")
		line("%s", p.bold("── "+title))
		for _, it := range items {
			line("  %s %s", color(sign), safe(it))
		}
	}
	section("Sections added", "+", d.Sections.Added, p.green)
	section("Sections removed", "-", d.Sections.Removed, p.red)
	var added, removed []string
	for _, f := range d.Findings.Added {
		added = append(added, fmt.Sprintf("[%s] %s  %s", strings.ToUpper(string(f.Severity)), f.ID, f.Title))
	}
	for _, f := range d.Findings.Removed {
		removed = append(removed, fmt.Sprintf("[%s] %s  %s", strings.ToUpper(string(f.Severity)), f.ID, f.Title))
	}
	section("Findings added", "+", added, p.green)
	section("Findings removed", "-", removed, p.red)
	section("Imports added", "+", capList(d.Imports.Added, d.Imports.AddedCount, 25), p.green)
	section("Imports removed", "-", capList(d.Imports.Removed, d.Imports.RemovedCount, 25), p.red)
	var newStrings []string
	for _, s := range d.Strings.Added {
		newStrings = append(newStrings, fmt.Sprintf("%-9s %s", s.Category, clip(s.Value, 100)))
	}
	section("New strings", "+", capList(newStrings, d.Strings.AddedCount, 25), p.green)
	line("")
	for _, l := range d.Limitations {
		line("%s", p.dim("· "+l))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// capList shows at most n items of list and a marker for the rest of total.
func capList(list []string, total, n int) []string {
	if len(list) > n {
		list = list[:n]
	}
	out := append([]string(nil), list...)
	if total > len(out) {
		out = append(out, fmt.Sprintf("(+%d more, see --json)", total-len(out)))
	}
	return out
}
