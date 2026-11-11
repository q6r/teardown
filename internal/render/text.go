package render

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Text writes the human-readable analysis of rep to w.
func Text(w io.Writer, rep *report.Report, o Options) error {
	t := &textView{p: palette{on: o.Color}, o: o, rep: rep}
	t.header()
	t.risk()
	t.hashes()
	t.entropy()
	t.facts()
	t.hardening()
	t.sections()
	t.imports()
	t.strings()
	t.findings()
	t.limitations()
	_, err := io.WriteString(w, t.sb.String())
	return err
}

type textView struct {
	sb  strings.Builder
	p   palette
	o   Options
	rep *report.Report
}

func (t *textView) line(format string, a ...any) {
	fmt.Fprintf(&t.sb, format, a...)
	t.sb.WriteByte('\n')
}

func (t *textView) heading(title string, extra string) {
	t.sb.WriteByte('\n')
	rule := "──"
	if t.o.ASCII {
		rule = "--"
	}
	if extra != "" {
		t.line("%s", t.p.bold(rule+" "+title)+"  "+t.p.dim(extra))
		return
	}
	t.line("%s", t.p.bold(rule+" "+title))
}

func (t *textView) header() {
	r := t.rep
	t.line("%s  %s", t.p.bold("teardown"), t.p.dim(safe(r.Tool.Version)+" · static triage, the file was never executed"))
	t.sb.WriteByte('\n')
	t.line("%s", t.p.bold(safe(r.File.Name)))
	label := safe(r.Type.Label)
	if len(r.Type.Tags) > 0 {
		tags := make([]string, len(r.Type.Tags))
		for i, tag := range r.Type.Tags {
			tags[i] = safe(tag)
		}
		label += "  " + t.p.dim("["+strings.Join(tags, ", ")+"]")
	}
	t.line("%s", label)
	t.line("%s", t.p.dim(fmt.Sprintf("%s (%s bytes) · type confidence %s · analysed in %d ms",
		humanBytes(r.File.Size), groupInt(int(r.File.Size)), r.Type.Confidence, r.DurationMs)))
}

func (t *textView) risk() {
	r := t.rep.Risk
	t.sb.WriteByte('\n')
	meter := bar(float64(r.Score)/100, 24, t.o.ASCII)
	t.line("%s  %s  %s  %s", t.p.bold("RISK"), t.p.risk(r.Label, meter),
		t.p.risk(r.Label, fmt.Sprintf("%d/100", r.Score)), t.p.risk(r.Label, strings.ToUpper(r.Label)))
	t.line("%s", t.p.dim("a triage aid for ordering a review queue, not a verdict"))
	if t.o.Verbose {
		for _, b := range r.Basis {
			for i, l := range wrapText(safe(b), t.o.width()-6) {
				prefix := "  · "
				if i > 0 {
					prefix = "    "
				}
				t.line("%s", t.p.dim(prefix+l))
			}
		}
	}
}

func (t *textView) hashes() {
	h := t.rep.Hashes
	t.heading("Hashes", "")
	t.line("  md5      %s", h.MD5)
	t.line("  sha1     %s", h.SHA1)
	t.line("  sha256   %s", h.SHA256)
	if h.Imphash != "" {
		t.line("  imphash  %s", h.Imphash)
	}
}

func (t *textView) entropy() {
	e := t.rep.Entropy
	t.heading("Entropy", fmt.Sprintf("%.2f of 8.00 bits per byte", e.Overall))
	t.line("  %s  %.2f", bar(e.Overall/8, 32, t.o.ASCII), e.Overall)
	if len(e.Windows) > 0 {
		t.line("  %s", t.p.cyan(spark(e.Windows, min(t.o.width()-4, 96), t.o.ASCII)))
		t.line("  %s", t.p.dim(fmt.Sprintf("%d windows of %s; high bars suggest compressed or encrypted data", len(e.Windows), humanBytes(e.WindowSize))))
	}
}

// factOrder lists the details keys shown first, per format.
var factOrder = map[string][]string{
	"pe":      {"kind", "machine", "bits", "subsystem", "timestamp", "entryPoint", "entrySection", "imageBase", "signed", "overlaySize", "pdbPath", "dotNet", "dotNetVersion", "packerHints"},
	"elf":     {"class", "endian", "osAbi", "type", "machine", "entry", "interpreter", "needed", "rpath", "runpath", "soname", "stripped", "buildId"},
	"macho":   {"fat", "primarySlice"},
	"go":      {"goVersion", "path", "goos", "goarch", "cgo", "compiler", "buildMode"},
	"archive": {"kind", "entryCount", "totalCompressed", "totalUncompressed", "ratio", "signed", "encryptedEntries", "classCount"},
	"asar":    {"headerSize", "fileCount", "totalSize"},
	"wasm":    {"version", "functionCount", "importCount", "exportCount"},
	"gguf":    {"version", "architecture", "name", "tensorCount", "kvCount", "contextLength", "parameterCount"},
}

// facts prints the headline scalar facts of every details block.
func (t *textView) facts() {
	keys := make([]string, 0, len(t.rep.Details))
	for k := range t.rep.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	first := true
	for _, k := range keys {
		pairs := scalarFacts(t.rep.Details[k], factOrder[k])
		if len(pairs) == 0 {
			continue
		}
		if first {
			t.heading("Format details", "")
			first = false
		}
		t.line("  %s", t.p.bold(safe(k)))
		for _, kv := range pairs {
			t.line("    %s %s", t.p.dim(padRight(safe(kv[0]), 18)), clip(safe(kv[1]), t.o.width()-26))
		}
	}
}

// scalarFacts extracts printable key/value pairs from a details block: the
// preferred keys first (in order), then up to a few other scalars.
func scalarFacts(v any, preferred []string) [][2]string {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	render := func(x any) (string, bool) {
		switch val := x.(type) {
		case string:
			return val, val != ""
		case bool:
			return fmt.Sprint(val), true
		case float64:
			if val == float64(int64(val)) {
				return fmt.Sprint(int64(val)), true
			}
			return fmt.Sprintf("%.2f", val), true
		case []any:
			parts := make([]string, 0, len(val))
			for _, e := range val {
				if s, ok := e.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) == 0 {
				return "", false
			}
			if len(parts) > 6 {
				parts = append(parts[:6], fmt.Sprintf("(+%d more)", len(parts)-6))
			}
			return strings.Join(parts, ", "), true
		default:
			return "", false
		}
	}
	var out [][2]string
	used := map[string]bool{}
	for _, k := range preferred {
		if s, ok := render(m[k]); ok {
			out = append(out, [2]string{k, s})
			used[k] = true
		}
	}
	if len(preferred) == 0 {
		rest := make([]string, 0, len(m))
		for k := range m {
			if !used[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest)
		for _, k := range rest {
			if _, isList := m[k].([]any); isList {
				continue
			}
			if s, ok := render(m[k]); ok && len(out) < 8 {
				out = append(out, [2]string{k, s})
			}
		}
	}
	return out
}

func (t *textView) hardening() {
	hs := t.rep.Hardening
	if len(hs) == 0 {
		return
	}
	t.heading("Hardening", "")
	glyph := map[string]string{report.StatusEnabled: "✔", report.StatusDisabled: "✘", report.StatusUnknown: "?", report.StatusNA: "–"}
	if t.o.ASCII {
		glyph = map[string]string{report.StatusEnabled: "+", report.StatusDisabled: "x", report.StatusUnknown: "?", report.StatusNA: "-"}
	}
	width := 0
	for _, h := range hs {
		width = max(width, runeLen(safe(h.Label)))
	}
	for _, h := range hs {
		g := glyph[h.Status]
		if g == "" {
			g = "?"
		}
		t.line("  %s %s  %s  %s", t.p.status(h.Status, g), padRight(safe(h.Label), width),
			t.p.status(h.Status, padRight(h.Status, 8)), t.p.dim(clip(safe(h.Detail), max(t.o.width()-width-18, 20))))
	}
}

func (t *textView) sections() {
	ss := t.rep.Sections
	if len(ss) == 0 {
		return
	}
	t.heading(fmt.Sprintf("Sections (%d)", len(ss)), "")
	nameW := 8
	for _, s := range ss {
		nameW = max(nameW, min(runeLen(safe(s.Name)), 24))
	}
	t.line("  %s %s %s  %s  %s", t.p.dim(padRight("name", nameW)), t.p.dim(padLeft("virtual", 10)),
		t.p.dim(padLeft("raw", 10)), t.p.dim(padRight("entropy", 16)), t.p.dim("flags"))
	for _, s := range ss {
		flags := flagCell(s)
		if s.Writable() && s.Executable() {
			flags = t.p.red(flags)
		}
		ent := padRight(fmt.Sprintf("%s %.2f", bar(s.Entropy/8, 8, t.o.ASCII), s.Entropy), 16)
		if s.Entropy >= 7.2 && s.RawSize >= 1024 {
			ent = t.p.yellow(ent)
		}
		note := ""
		if s.Suspicious {
			note = "  " + t.p.yellow(clip(safe(strings.Join(s.Reasons, "; ")), max(t.o.width()-nameW-50, 12)))
			if len(s.Reasons) == 0 {
				note = "  " + t.p.yellow("suspicious")
			}
		}
		t.line("  %s %s %s  %s  %s%s", padRight(clip(safe(s.Name), nameW), nameW), padLeft(humanBytes(int64(s.VirtualSize)), 10),
			padLeft(humanBytes(int64(s.RawSize)), 10), ent, flags, note)
	}
}

func flagCell(s report.Section) string {
	out := []byte("---")
	for _, f := range s.Flags {
		switch f {
		case report.FlagR:
			out[0] = 'R'
		case report.FlagW:
			out[1] = 'W'
		case report.FlagX:
			out[2] = 'X'
		}
	}
	return string(out)
}

func (t *textView) imports() {
	r := t.rep
	if len(r.Imports) == 0 && len(r.Exports) == 0 {
		return
	}
	total := 0
	for _, im := range r.Imports {
		total += im.Count
	}
	if len(r.Imports) > 0 {
		t.heading(fmt.Sprintf("Imports (%d libraries, %s functions)", len(r.Imports), groupInt(total)), "")
		libs := slices.Clone(r.Imports)
		sort.SliceStable(libs, func(i, j int) bool { return libs[i].Count > libs[j].Count })
		limit := 10
		if t.o.Verbose {
			limit = len(libs)
		}
		for _, im := range libs[:min(limit, len(libs))] {
			t.line("  %s %s", padRight(clip(safe(im.Library), 36), 36), padLeft(groupInt(im.Count), 6))
			if t.o.Verbose {
				for _, l := range wrapText(safe(strings.Join(im.Functions, ", ")), t.o.width()-8) {
					t.line("      %s", t.p.dim(l))
				}
			}
		}
		if len(libs) > limit {
			t.line("  %s", t.p.dim(fmt.Sprintf("(+%d more libraries, see --json or -v)", len(libs)-limit)))
		}
	}
	if len(r.Exports) > 0 {
		t.heading(fmt.Sprintf("Exports (%s)", groupInt(len(r.Exports))), "")
		shown := r.Exports
		if !t.o.Verbose && len(shown) > 12 {
			shown = shown[:12]
		}
		for _, l := range wrapText(safe(strings.Join(shown, ", ")), t.o.width()-4) {
			t.line("  %s", l)
		}
		if len(shown) < len(r.Exports) {
			t.line("  %s", t.p.dim(fmt.Sprintf("(+%d more)", len(r.Exports)-len(shown))))
		}
	}
}

func (t *textView) strings() {
	s := t.rep.Strings
	t.heading("Strings", fmt.Sprintf("%s found, min length %d%s", groupInt(s.Total), s.MinLength, truncNote(s.Truncated)))
	var cats []string
	for _, c := range report.StringCategories() {
		if n := s.ByCategory[c]; n > 0 && c != report.CatPlain {
			cats = append(cats, fmt.Sprintf("%s %s", c, groupInt(n)))
		}
	}
	if len(cats) > 0 {
		t.line("  %s", strings.Join(cats, " · "))
	}
	limit := 14
	if t.o.Verbose {
		limit = 60
	}
	shown := 0
	for _, c := range report.StringCategories() {
		if c == report.CatPlain || c == report.CatBase64 || c == report.CatHex {
			continue
		}
		for _, it := range s.Items {
			if it.Category != c || shown >= limit {
				continue
			}
			shown++
			t.line("  %s %s %s", t.p.cyan(padRight(it.Category, 9)), t.p.dim(padLeft(fmt.Sprintf("0x%x", it.Offset), 10)),
				clip(safe(it.Value), t.o.width()-24))
		}
	}
	if shown == 0 {
		t.line("  %s", t.p.dim("no classified strings; use `teardown strings` to list everything"))
	}
}

func truncNote(truncated bool) string {
	if truncated {
		return " (list truncated)"
	}
	return ""
}

func (t *textView) findings() {
	fs := t.rep.Findings
	t.heading(fmt.Sprintf("Findings (%d)", len(fs)), "")
	if len(fs) == 0 {
		t.line("  %s", t.p.green("no findings"))
		return
	}
	for _, f := range fs {
		tag := strings.ToUpper(string(f.Severity))
		t.line("  %s %s  %s", t.p.severity(f.Severity, padRight("["+tag+"]", 10)), t.p.bold(safe(f.ID)), t.p.dim("confidence "+string(f.Confidence)))
		for _, l := range wrapText(safe(f.Title), t.o.width()-6) {
			t.line("      %s", l)
		}
		limit := 3
		if t.o.Verbose {
			limit = len(f.Evidence)
		}
		for i, e := range f.Evidence {
			if i >= limit {
				t.line("      %s", t.p.dim(fmt.Sprintf("(+%d more evidence lines, see -v)", len(f.Evidence)-limit)))
				break
			}
			t.line("      %s %s", t.p.dim("evidence:"), clip(safe(e), t.o.width()-20))
		}
		lims := f.Limitations
		if !t.o.Verbose && len(lims) > 1 {
			lims = lims[:1]
		}
		for _, l := range lims {
			for i, w := range wrapText(safe(l), t.o.width()-20) {
				if i == 0 {
					t.line("      %s %s", t.p.dim("limitation:"), t.p.dim(w))
				} else {
					t.line("      %s%s", strings.Repeat(" ", len("limitation: ")), t.p.dim(w))
				}
			}
		}
	}
}

func (t *textView) limitations() {
	ls := t.rep.Limitations
	if len(ls) == 0 {
		return
	}
	t.heading("Limitations", "")
	for _, l := range ls {
		for i, w := range wrapText(safe(l), t.o.width()-6) {
			prefix := "  · "
			if i > 0 {
				prefix = "    "
			}
			t.line("%s", t.p.dim(prefix+w))
		}
	}
}
