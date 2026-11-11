package web

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

var refPattern = regexp.MustCompile(`(?:href|src)="([^"]*)"`)

// requiredAssets are the files the dashboard and the exported report need.
var requiredAssets = []string{
	"index.html", "favicon.svg",
	"aurora.css", "aurora.js", "aurora-charts.js", // the bundled Aurora UI kit
	"report-view.css", "report-view.js", "report-boot.js", // shared report view and the export bootstrap
	"app.css", "app.js", // the dashboard
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(FS(), name)
	if err != nil {
		t.Fatalf("%s is not embedded: %v", name, err)
	}
	return string(b)
}

// TestEmbeddedAssetsAreComplete is the CI "dashboard asset check": every required
// file is embedded and every file index.html references locally is embedded too,
// otherwise the dashboard would break only after release.
func TestEmbeddedAssetsAreComplete(t *testing.T) {
	fsys := FS()
	for _, name := range requiredAssets {
		if info, err := fs.Stat(fsys, name); err != nil || info.Size() == 0 {
			t.Errorf("%s must be embedded and not empty (err %v)", name, err)
		}
	}
	index := read(t, "index.html")
	refs := refPattern.FindAllStringSubmatch(index, -1)
	if len(refs) < 5 {
		t.Fatalf("index.html references only %d files; the stylesheets and scripts are missing", len(refs))
	}
	for _, m := range refs {
		ref := m[1]
		switch {
		case ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "/api/"):
			continue // fragments and API routes are served by the HTTP layer
		case strings.Contains(ref, "://") || strings.HasPrefix(ref, "//"):
			t.Errorf("index.html makes an external request to %q: dashboards must work offline", ref)
			continue
		}
		file := strings.TrimPrefix(path.Clean("/"+ref), "/")
		if _, err := fs.Stat(fsys, file); err != nil {
			t.Errorf("index.html references %q but it is not embedded: %v", ref, err)
		}
	}
}

// TestIndexWorksUnderTheStrictCSP: the server sends "default-src 'self'", which
// forbids inline script, inline style and inline event handlers.
func TestIndexWorksUnderTheStrictCSP(t *testing.T) {
	index := read(t, "index.html")
	for name, pattern := range map[string]string{
		"an inline <style> element": `(?i)<style\b`,
		"a style attribute":         `(?i)\sstyle\s*=`,
		"an inline event handler":   `(?i)\son[a-z]+\s*=`,
		"a javascript: URL":         `(?i)javascript:`,
	} {
		if regexp.MustCompile(pattern).MatchString(index) {
			t.Errorf("index.html contains %s, which the Content-Security-Policy blocks", name)
		}
	}
	for _, m := range regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(index, -1) {
		if !strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) != "" {
			t.Errorf("index.html has an inline script (%q): the Content-Security-Policy blocks it", m[0])
		}
	}
}

// TestNoExternalRequestsInAssets scans every embedded text asset for absolute
// URLs. W3C namespace identifiers (SVG, XHTML) are allowed: they are never fetched.
func TestNoExternalRequestsInAssets(t *testing.T) {
	url := regexp.MustCompile(`https?://[^\s"'<>)]+`)
	err := fs.WalkDir(FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(FS(), name)
		if err != nil {
			return err
		}
		for _, u := range url.FindAllString(string(raw), -1) {
			if strings.HasPrefix(u, "http://www.w3.org/") || strings.HasPrefix(u, "https://www.w3.org/") {
				continue
			}
			t.Errorf("%s contains the absolute URL %q; the dashboard must not depend on the network", name, u)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDashboardScriptsBuildNoMarkupFromData is the XSS guard: file names, strings
// and findings come from analysed files and are hostile by assumption, so the
// project's own scripts may only create text and elements, never parse markup.
func TestDashboardScriptsBuildNoMarkupFromData(t *testing.T) {
	sinks := regexp.MustCompile(`(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc|document\.write(?:ln)?|DOMParser|createContextualFragment)\b|\beval\s*\(|new\s+Function\b|setTimeout\s*\(\s*['"` + "`" + `]|setAttribute\s*\(\s*['"]on`)
	for _, name := range []string{"app.js", "report-view.js", "report-boot.js"} {
		if m := sinks.FindString(read(t, name)); m != "" {
			t.Errorf("%s uses %q: build text with Aurora.el (textContent), never markup", name, m)
		}
	}
}

// TestAssetsCanBeInlinedIntoASingleFile: the export puts these files inside
// <style> and <script> elements, so none may contain the terminators.
func TestAssetsCanBeInlinedIntoASingleFile(t *testing.T) {
	for _, name := range []string{"aurora.js", "aurora-charts.js", "report-view.js", "report-boot.js"} {
		src := strings.ToLower(read(t, name))
		for _, bad := range []string{"</script", "<!--"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q and cannot be inlined in a <script> element", name, bad)
			}
		}
	}
	for _, name := range []string{"aurora.css", "report-view.css"} {
		if strings.Contains(strings.ToLower(read(t, name)), "</style") {
			t.Errorf("%s contains a style terminator and cannot be inlined", name)
		}
	}
}

// TestProjectStylesUseOnlyTokens: the project's own CSS uses the tokens of the
// Aurora UI kit (custom properties), no raw colours, no font files and no remote images.
func TestProjectStylesUseOnlyTokens(t *testing.T) {
	hexColour := regexp.MustCompile(`#[0-9a-fA-F]{3,8}[^0-9a-zA-Z_-]`)
	for _, name := range []string{"app.css", "report-view.css"} {
		css := read(t, name)
		if m := hexColour.FindString(css); m != "" {
			t.Errorf("%s contains the raw colour %q: use a token such as var(--accent)", name, m[:len(m)-1])
		}
		for _, bad := range []string{"@font-face", "@import", "url("} {
			if strings.Contains(css, bad) {
				t.Errorf("%s contains %q: the dashboard has no web fonts, imports or images of its own", name, bad)
			}
		}
	}
}

// TestProjectScriptsUseNoRawColours: colours come from the tokens in aurora.css, so a
// theme switch recolours everything; a script may not write a colour of its own, nor set
// a style attribute (the Content-Security-Policy would drop it).
func TestProjectScriptsUseNoRawColours(t *testing.T) {
	hexColour := regexp.MustCompile(`#[0-9a-fA-F]{3,8}[^0-9a-zA-Z_-]`)
	styleAttr := regexp.MustCompile(`setAttribute\(\s*['"]style`)
	for _, name := range []string{"app.js", "report-view.js", "report-boot.js"} {
		js := read(t, name)
		if m := hexColour.FindString(js); m != "" {
			t.Errorf("%s contains the raw colour %q: use a token such as var(--accent) in the CSS", name, m[:len(m)-1])
		}
		if styleAttr.MatchString(js) {
			t.Errorf("%s sets a style attribute: use a class in the project CSS", name)
		}
	}
}

// TestPagesAreBuiltByTheAuroraShell: index.html is an almost empty page (a <noscript>
// note and the scripts) and both the dashboard and the exported report get their layout
// (rail, top bar, sub bar, status bar) from Aurora.shell, so the two cannot drift apart.
func TestPagesAreBuiltByTheAuroraShell(t *testing.T) {
	index := read(t, "index.html")
	for _, skeleton := range []string{"<header", "<main", "<nav", "<footer", "a-topbar", "a-brand", "a-nav", "a-main"} {
		if strings.Contains(index, skeleton) {
			t.Errorf("index.html contains %q: the page skeleton is built by Aurora.shell, the page only loads the scripts", skeleton)
		}
	}
	prev := -1
	for _, script := range []string{"aurora.js", "aurora-charts.js", "report-view.js", "app.js"} {
		at := strings.Index(index, `src="`+script+`"`)
		if at < 0 || at < prev {
			t.Errorf("index.html must load %s after the scripts it needs (aurora.js, aurora-charts.js, report-view.js, then app.js)", script)
		}
		prev = at
	}
	for _, name := range []string{"app.js", "report-boot.js"} {
		if !strings.Contains(read(t, name), "A.shell(") {
			t.Errorf("%s does not build its layout with Aurora.shell", name)
		}
	}
	if !strings.Contains(read(t, "report-boot.js"), "anchors: true") {
		t.Error("report-boot.js must dock the report sections as #fragment links: the exported file has no router and must work from file://")
	}
	if strings.Contains(read(t, "app.js"), "anchors: true") {
		t.Error("app.js must not use #fragment links for the report sections: the dashboard routes on the hash")
	}
}

// TestProjectFilesUseCurrentKitNames: the classes and tokens below are gone from the
// bundled kit (or are only kept as aliases); a project file that used them would render
// unstyled or ignore the theme.
func TestProjectFilesUseCurrentKitNames(t *testing.T) {
	removed := []string{"a-brand", "a-nav__item", "a-aurora", "--grad-brand", "--grad-btn", "--blob-opacity", "--grid-line", "--surface-glass", "--accent-1", "--accent-2", "--accent-3", "--border"}
	for _, name := range []string{"app.js", "report-view.js", "report-boot.js", "app.css", "report-view.css"} {
		src := read(t, name)
		for _, old := range removed {
			if strings.Contains(src, old) {
				t.Errorf("%s uses %q, which the kit no longer has: use the current tokens and classes of aurora.css", name, old)
			}
		}
	}
}
