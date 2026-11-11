package asar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/q6r/teardown/internal/binio"
)

const (
	// maxScriptScan is how much of one script is searched for hints.
	maxScriptScan = 512 << 10
	// maxPackageJSON is the largest package.json that is read.
	maxPackageJSON = 1 << 20
	// maxHints bounds the hints recorded.
	maxHints = 100
	// maxSnippet bounds the matched text quoted in a hint.
	maxSnippet = 80
)

// hintPatterns pair a hint id with the text that triggers it. Minified code
// writes true and false as !0 and !1, so both spellings are matched. Only the
// matched flag text is ever quoted, never surrounding code.
var hintPatterns = []struct {
	id string
	re *regexp.Regexp
}{
	{"node-integration", regexp.MustCompile(`nodeIntegration\s*:\s*(?:true|!0)\b`)},
	{"context-isolation-disabled", regexp.MustCompile(`contextIsolation\s*:\s*(?:false|!1)\b`)},
	{"web-security-disabled", regexp.MustCompile(`webSecurity\s*:\s*(?:false|!1)\b`)},
	{"remote-module-enabled", regexp.MustCompile(`enableRemoteModule\s*:\s*(?:true|!0)\b`)},
	{"insecure-content", regexp.MustCompile(`allowRunningInsecureContent\s*:\s*(?:true|!0)\b`)},
	{"no-sandbox", regexp.MustCompile(`--no-sandbox|\bsandbox\s*:\s*(?:false|!1)\b`)},
	{"child-process", regexp.MustCompile(`require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]`)},
}

// inspect reads the application's package.json and scans its scripts for
// hints. It returns notes about anything that could not be read.
func (w *walker) inspect(ctx context.Context) []string {
	var notes []string
	for _, p := range []string{"package.json", "app/package.json", "resources/app/package.json"} {
		ref, ok := w.pkg[p]
		if !ok {
			continue
		}
		pkg, note := w.readPackage(ref)
		if note != "" {
			notes = append(notes, note)
		}
		if pkg != nil {
			w.d.Package = pkg
			break
		}
	}

	cut := 0
	for _, ref := range w.scripts {
		if ctx.Err() != nil || len(w.d.Hints) >= maxHints {
			break
		}
		n := min(ref.size, maxScriptScan)
		if ref.size > n {
			cut++
		}
		data, err := binio.ReadAt(w.r, w.size, w.d.DataOffset+ref.off, n)
		if err != nil {
			continue
		}
		for _, p := range hintPatterns {
			if loc := p.re.FindIndex(data); loc != nil && len(w.d.Hints) < maxHints {
				w.d.Hints = append(w.d.Hints, Hint{
					ID:       p.id,
					Evidence: binio.Printable(ref.path, 160) + ": " + binio.Printable(string(data[loc[0]:loc[1]]), maxSnippet),
				})
			}
		}
	}
	if cut > 0 {
		notes = append(notes, fmt.Sprintf("%d scripts are larger than %d KiB and were searched only in their first %d KiB", cut, maxScriptScan>>10, maxScriptScan>>10))
	}
	return notes
}

// readPackage reads and decodes a package.json member.
func (w *walker) readPackage(ref fileRef) (*Package, string) {
	if ref.size > maxPackageJSON {
		return nil, fmt.Sprintf("%s is larger than %d KiB and was not read", ref.path, maxPackageJSON>>10)
	}
	data, err := binio.ReadAt(w.r, w.size, w.d.DataOffset+ref.off, ref.size)
	if err != nil {
		return nil, fmt.Sprintf("%s could not be read: %v", ref.path, err)
	}
	if jsonDepth(data, maxDepth) > maxDepth {
		return nil, fmt.Sprintf("%s nests deeper than %d levels and was not parsed", ref.path, maxDepth)
	}
	var raw struct {
		Name            string                     `json:"name"`
		Version         string                     `json:"version"`
		Main            string                     `json:"main"`
		Description     string                     `json:"description"`
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	// A field of the wrong type is skipped by the decoder; only broken JSON fails.
	if err := json.Unmarshal(data, &raw); err != nil {
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) {
			return nil, fmt.Sprintf("%s is not valid JSON: %v", ref.path, err)
		}
	}
	pkg := &Package{
		Name:         binio.Printable(raw.Name, 256),
		Version:      binio.Printable(raw.Version, 64),
		Main:         binio.Printable(raw.Main, 256),
		Description:  binio.Printable(raw.Description, 512),
		Dependencies: make([]string, 0, len(raw.Dependencies)),
	}
	for _, deps := range []map[string]json.RawMessage{raw.Dependencies, raw.DevDependencies} {
		if v, ok := deps["electron"]; ok && pkg.Electron == "" {
			var version string
			if json.Unmarshal(v, &version) == nil {
				pkg.Electron = binio.Printable(version, 64)
			}
		}
	}
	for name := range raw.Dependencies {
		pkg.Dependencies = append(pkg.Dependencies, binio.Printable(name, 214))
	}
	slices.Sort(pkg.Dependencies)
	if len(pkg.Dependencies) > w.lim.MaxList {
		pkg.Dependencies = pkg.Dependencies[:w.lim.MaxList]
	}
	return pkg, ""
}
