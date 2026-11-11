// Package render turns reports into human-oriented output: coloured terminal
// text with unicode bars, Markdown, and a self-contained HTML page.
//
// Every string that originates from an analysed file is sanitised before it is
// written, so a hostile file cannot inject terminal escape sequences, Markdown
// or HTML into the output.
package render

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

// Options controls terminal rendering.
type Options struct {
	// Color enables ANSI colours.
	Color bool
	// ASCII replaces unicode bars and symbols with plain ASCII.
	ASCII bool
	// Width is the target line width (default 100, minimum 60).
	Width int
	// Verbose shows the risk basis, every limitation and more evidence.
	Verbose bool
}

func (o Options) width() int {
	switch {
	case o.Width <= 0:
		return 100
	case o.Width < 60:
		return 60
	default:
		return o.Width
	}
}

// palette wraps text in ANSI styles when colours are enabled.
type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p palette) bold(s string) string   { return p.wrap("1", s) }
func (p palette) dim(s string) string    { return p.wrap("2", s) }
func (p palette) red(s string) string    { return p.wrap("31", s) }
func (p palette) green(s string) string  { return p.wrap("32", s) }
func (p palette) yellow(s string) string { return p.wrap("33", s) }
func (p palette) blue(s string) string   { return p.wrap("34", s) }
func (p palette) cyan(s string) string   { return p.wrap("36", s) }

func (p palette) severity(s report.Severity, text string) string {
	switch s {
	case report.SeverityCritical:
		return p.wrap("1;35", text)
	case report.SeverityHigh:
		return p.wrap("1;31", text)
	case report.SeverityMedium:
		return p.wrap("33", text)
	case report.SeverityLow:
		return p.wrap("36", text)
	default:
		return p.wrap("2", text)
	}
}

func (p palette) risk(label, text string) string {
	switch label {
	case report.RiskCritical:
		return p.wrap("1;35", text)
	case report.RiskHigh:
		return p.wrap("1;31", text)
	case report.RiskMedium:
		return p.wrap("33", text)
	default:
		return p.wrap("32", text)
	}
}

func (p palette) status(status, text string) string {
	switch status {
	case report.StatusEnabled:
		return p.green(text)
	case report.StatusDisabled:
		return p.red(text)
	case report.StatusUnknown:
		return p.yellow(text)
	default:
		return p.dim(text)
	}
}

// safe makes text from an analysed file harmless to print.
func safe(s string) string { return binio.Printable(s, 0) }

// clip shortens s to at most n runes, ending with an ellipsis.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:max(n-1, 0)]) + "…"
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func padRight(s string, w int) string {
	if n := runeLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func padLeft(s string, w int) string {
	if n := runeLen(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// bar draws a horizontal bar of the given cell width filled to frac (0..1).
func bar(frac float64, width int, ascii bool) string {
	full, empty := "█", "░"
	if ascii {
		full, empty = "#", "."
	}
	frac = math.Min(math.Max(frac, 0), 1)
	n := int(math.Round(frac * float64(width)))
	return strings.Repeat(full, n) + strings.Repeat(empty, width-n)
}

// spark draws a sparkline of at most width cells, averaging buckets of values
// that are scaled against the 0..8 bits-per-byte entropy range.
func spark(values []float64, width int, ascii bool) string {
	if len(values) == 0 || width <= 0 {
		return ""
	}
	levels := []rune("▁▂▃▄▅▆▇█")
	if ascii {
		levels = []rune("_.-=+*#@")
	}
	cells := min(width, len(values))
	var sb strings.Builder
	for i := range cells {
		lo, hi := i*len(values)/cells, (i+1)*len(values)/cells
		if hi <= lo {
			hi = lo + 1
		}
		var sum float64
		for _, v := range values[lo:hi] {
			sum += v
		}
		avg := sum / float64(hi-lo)
		idx := int(math.Round(avg / 8 * float64(len(levels)-1)))
		sb.WriteRune(levels[min(max(idx, 0), len(levels)-1)])
	}
	return sb.String()
}

// humanBytes formats a byte count with binary units.
func humanBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// groupInt formats n with thousands separators.
func groupInt(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []byte
	for i := range len(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// wrapText breaks text into lines of at most width runes (a single word longer
// than width stays on its own line). Callers add their own prefixes.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if runeLen(cur)+1+runeLen(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(lines, cur)
}
