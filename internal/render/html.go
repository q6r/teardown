package render

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/web"
)

// The embedded dashboard files that make up an exported page, in document order.
// The scripts share one global scope, so aurora.js comes first and the bootstrap last.
var (
	pageStyles  = []string{"aurora.css", "report-view.css"}
	pageScripts = []string{"aurora.js", "aurora-charts.js", "report-view.js", "report-boot.js"}
)

// HTML writes the report as a single self-contained HTML page that opens from
// disk, offline: the Aurora UI kit, the same shell and report view that the web
// dashboard uses (the report sections are #fragment links in its sub bar), and
// the report itself as an inert JSON island (script id "report-data").
//
// The page is safe to open and to share:
//
//   - The JSON comes from [json.Marshal], which escapes <, >, & and the line and
//     paragraph separators U+2028 and U+2029, so no file name or string can close
//     the script element or open a comment inside it. [escapeInvisible] extends
//     that to every invisible format character, such as a right-to-left override.
//   - Text from the analysed file reaches the DOM only through textContent; the
//     view never builds markup from data.
//   - A Content-Security-Policy meta tag allows only this page's own inline style
//     and script (by SHA-256 hash) and data: images, so even a bug could not make
//     a network request.
//   - Without scripting the page falls back to a plain readable summary inside
//     <noscript>.
func HTML(w io.Writer, rep *report.Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	island := escapeInvisible(data)
	styles, err := inlineAssets(pageStyles)
	if err != nil {
		return err
	}
	scripts, err := inlineAssets(pageScripts)
	if err != nil {
		return err
	}
	style := "\n" + strings.Join(styles, "\n") + "\n"
	script := "\n" + strings.Join(scripts, "\n") + "\n"

	var sb strings.Builder
	sb.WriteString("<!doctype html>\n<html lang=\"en\" data-theme=\"auto\">\n<head>\n<meta charset=\"utf-8\">\n")
	sb.WriteString("<meta http-equiv=\"Content-Security-Policy\" content=\"" + contentSecurityPolicy(style, script) + "\">\n")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	sb.WriteString("<meta name=\"color-scheme\" content=\"dark light\">\n")
	fmt.Fprintf(&sb, "<meta name=\"generator\" content=\"teardown %s\">\n", html.EscapeString(visible(rep.Tool.Version)))
	fmt.Fprintf(&sb, "<title>teardown: %s</title>\n", html.EscapeString(visible(rep.File.Name)))
	// The body holds no markup of its own: report-boot.js builds the Aurora shell
	// (rail, top bar, sub bar, status bar) and the report page from the JSON island.
	sb.WriteString("<style>" + style + "</style>\n</head>\n<body class=\"a-body\">\n")
	writeFallback(&sb, rep)
	fmt.Fprintf(&sb, "<script type=\"application/json\" id=\"report-data\">%s</script>\n", island)
	sb.WriteString("<script>" + script + "</script>\n</body>\n</html>\n")
	_, err = io.WriteString(w, sb.String())
	return err
}

// escapeInvisible rewrites the invisible format characters in a JSON document
// (bidirectional controls, zero-width characters, the byte order mark, tag
// characters) as JSON unicode escapes. [json.Marshal] already escapes <, >, &,
// U+2028 and U+2029; this extends that to everything that could hide or reorder
// text when someone reads the page source in an editor. The result decodes to the
// same value, and these characters can only occur inside JSON strings.
func escapeInvisible(doc []byte) []byte {
	out := make([]byte, 0, len(doc))
	for i := 0; i < len(doc); {
		r, size := utf8.DecodeRune(doc[i:])
		if size > 1 && unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			for _, unit := range utf16.Encode([]rune{r}) {
				out = fmt.Appendf(out, "\\u%04x", unit)
			}
		} else {
			out = append(out, doc[i:i+size]...)
		}
		i += size
	}
	return out
}

// inlineAssets reads embedded dashboard files and refuses any that could not be
// placed inside a style or script element.
func inlineAssets(names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, name := range names {
		raw, err := fs.ReadFile(web.FS(), name)
		if err != nil {
			return nil, fmt.Errorf("read dashboard asset %s: %w", name, err)
		}
		text := string(raw)
		lower := strings.ToLower(text)
		for _, hazard := range []string{"</script", "</style", "<!--"} {
			if strings.Contains(lower, hazard) {
				return nil, fmt.Errorf("dashboard asset %s contains %q and cannot be inlined", name, hazard)
			}
		}
		out = append(out, text)
	}
	return out, nil
}

// contentSecurityPolicy allows exactly the page's own inline style and script
// (matched by hash) and data: images. Everything else, including every kind of
// network access, is denied.
func contentSecurityPolicy(style, script string) string {
	return "default-src 'none'; script-src " + cspHash(script) + "; style-src " + cspHash(style) +
		"; img-src data:; base-uri 'none'; form-action 'none'"
}

func cspHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// visible makes text from the analysed file harmless to show: control characters
// become escapes (see [safe]) and invisible format characters, among them the
// bidirectional overrides and the line and paragraph separators, are spelled
// out as [U+XXXX] so they cannot reorder or hide what a reader sees.
func visible(s string) string {
	var sb strings.Builder
	for _, r := range safe(s) {
		if unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			fmt.Fprintf(&sb, "[U+%04X]", r)
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// writeFallback writes the readable summary shown when scripting is disabled.
func writeFallback(sb *strings.Builder, rep *report.Report) {
	e := func(s string) string { return html.EscapeString(visible(s)) }
	sb.WriteString("<noscript>\n<div class=\"a-container td-fallback\">\n")
	fmt.Fprintf(sb, "<h1>%s</h1>\n", e(rep.File.Name))
	fmt.Fprintf(sb, "<p>%s (%s confidence), %s. Risk <strong>%d/100 %s</strong>.</p>\n",
		e(rep.Type.Label), e(string(rep.Type.Confidence)), humanBytes(rep.File.Size), rep.Risk.Score, e(rep.Risk.Label))
	fmt.Fprintf(sb, "<p><em>%s</em></p>\n", e(report.StaticOnly))
	sb.WriteString("<p>Turn on JavaScript to see the interactive report: charts, tables, imports and strings.</p>\n")
	fmt.Fprintf(sb, "<h2>Findings (%d)</h2>\n", len(rep.Findings))
	if len(rep.Findings) == 0 {
		sb.WriteString("<p>No findings.</p>\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(sb, "<h3><span class=\"td-sev\">%s</span> <code>%s</code> %s</h3>\n<p>Confidence: %s</p>\n",
			e(string(f.Severity)), e(f.ID), e(f.Title), e(string(f.Confidence)))
		writeList(sb, "Evidence", f.Evidence)
		writeList(sb, "Limitations", f.Limitations)
	}
	sb.WriteString("<h2>Hashes</h2>\n<table>\n")
	for _, kv := range [][2]string{{"MD5", rep.Hashes.MD5}, {"SHA-1", rep.Hashes.SHA1}, {"SHA-256", rep.Hashes.SHA256}, {"Imphash", rep.Hashes.Imphash}} {
		if kv[1] != "" {
			fmt.Fprintf(sb, "<tr><th>%s</th><td><code>%s</code></td></tr>\n", kv[0], e(kv[1]))
		}
	}
	sb.WriteString("</table>\n")
	writeList(sb, "Limitations of this report", rep.Limitations)
	sb.WriteString("</div>\n</noscript>\n")
}

func writeList(sb *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(sb, "<h4>%s</h4>\n<ul>\n", html.EscapeString(title))
	for _, it := range items {
		fmt.Fprintf(sb, "<li>%s</li>\n", html.EscapeString(visible(it)))
	}
	sb.WriteString("</ul>\n")
}
