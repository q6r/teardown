package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

type asarFacts struct {
	Package *struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Main     string `json:"main"`
		Electron string `json:"electron"`
	} `json:"package"`
	Hints []struct {
		ID       string `json:"id"`
		Evidence string `json:"evidence"`
	} `json:"hints"`
}

type goFacts struct {
	GoVersion string `json:"goVersion"`
	Path      string `json:"path"`
	VCS       *struct {
		System   string `json:"system"`
		Revision string `json:"revision"`
		Time     string `json:"time"`
		Modified bool   `json:"modified"`
	} `json:"vcs"`
}

type pdbFacts struct {
	PDBPath string `json:"pdbPath"`
}

func appRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"application.electron-app"}, Category: report.CategoryApp, Severity: "info",
			Summary: "An Electron ASAR archive: package name, version, main script and Electron version."},
			run: ruleElectronApp},
		{info: Info{IDs: []string{"application.electron-risky-settings"}, Category: report.CategoryApp, Severity: "low",
			Summary: "Textual hints in bundled JavaScript for Electron settings such as nodeIntegration: true or contextIsolation: false (evidence only)."},
			run: ruleElectronHints},
		{info: Info{IDs: []string{"build.go-vcs"}, Category: report.CategoryBuild, Severity: "info",
			Summary: "A Go binary that embeds version-control revision, time and dirty-tree state."},
			run: ruleGoVCS},
		{info: Info{IDs: []string{"privacy.pdb-path"}, Category: report.CategoryPrivacy, Severity: "low",
			Summary: "A PDB debug path embedded in a PE, which can leak the build machine's directory layout and user name."},
			run: rulePDB},
	}
}

func ruleElectronApp(in *input) []report.Finding {
	a, ok := detail[asarFacts](in.rep, "asar")
	if !ok || a.Package == nil {
		return nil
	}
	p := a.Package
	evidence := []string{fmt.Sprintf("package: %s %s", clip(p.Name, 80), clip(p.Version, 40))}
	if p.Main != "" {
		evidence = append(evidence, "main script: "+clip(p.Main, 80))
	}
	if p.Electron != "" {
		evidence = append(evidence, "electron dependency: "+clip(p.Electron, 40))
	}
	return []report.Finding{{
		ID: "application.electron-app", Title: "Electron application package", Severity: report.SeverityInfo,
		Category: report.CategoryApp, Confidence: report.ConfidenceHigh, Evidence: evidence,
		Limitations: []string{
			"Read from package.json inside the ASAR archive; the packaged application's JavaScript is not executed or deeply analysed.",
		},
	}}
}

func ruleElectronHints(in *input) []report.Finding {
	a, ok := detail[asarFacts](in.rep, "asar")
	if !ok || len(a.Hints) == 0 {
		return nil
	}
	evidence := make([]string, 0, len(a.Hints))
	for _, h := range a.Hints {
		evidence = append(evidence, fmt.Sprintf("%s: %s", h.ID, clip(h.Evidence, 140)))
	}
	return []report.Finding{{
		ID: "application.electron-risky-settings", Title: "Bundled JavaScript mentions settings that widen the attack surface",
		Severity: report.SeverityLow, Category: report.CategoryApp, Confidence: report.ConfidenceLow, Evidence: sample(evidence, 10),
		Limitations: []string{
			"These are text matches in bundled JavaScript, reported as evidence and not as a verdict: the setting may be in dead code, in a window that loads only local content, or in a dependency.",
			"The effective configuration depends on run-time code paths that are not analysed here.",
		},
	}}
}

func ruleGoVCS(in *input) []report.Finding {
	g, ok := detail[goFacts](in.rep, "go")
	if !ok || g.VCS == nil || (g.VCS.Revision == "" && g.VCS.Time == "") {
		return nil
	}
	evidence := []string{fmt.Sprintf("%s revision %s", orDash(g.VCS.System), orDash(g.VCS.Revision))}
	if g.VCS.Time != "" {
		evidence = append(evidence, "commit time "+g.VCS.Time)
	}
	if g.VCS.Modified {
		evidence = append(evidence, "built from a modified (dirty) working tree")
	}
	if g.GoVersion != "" {
		evidence = append(evidence, "toolchain "+g.GoVersion)
	}
	return []report.Finding{{
		ID: "build.go-vcs", Title: "Go build embeds version-control information", Severity: report.SeverityInfo,
		Category: report.CategoryBuild, Confidence: report.ConfidenceHigh, Evidence: evidence,
		Limitations: []string{
			"Useful for provenance, and it also reveals which source revision and when it was built; -buildvcs=false removes it.",
			"The revision identifies a commit, not the integrity of what was built from it.",
		},
	}}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func rulePDB(in *input) []report.Finding {
	p, ok := detail[pdbFacts](in.rep, "pe")
	if !ok || p.PDBPath == "" {
		return nil
	}
	return []report.Finding{{
		ID: "privacy.pdb-path", Title: "Debug (PDB) path is embedded in the binary", Severity: report.SeverityLow,
		Category: report.CategoryPrivacy, Confidence: report.ConfidenceHigh, Evidence: []string{clip(p.PDBPath, 200)},
		Limitations: []string{
			"A PDB path can reveal the build machine's directory layout, user name or project names; it is also a useful attribution and clustering hint.",
			"The path is metadata written by the linker and can be edited or stripped without changing behaviour.",
		},
	}}
}

// documentExts are extensions that promise inert content.
var documentExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".txt": true, ".rtf": true, ".csv": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".bmp": true, ".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".wav": true, ".log": true,
	".ini": true, ".json": true, ".xml": true, ".html": true, ".htm": true, ".md": true,
}

// launchExts are extensions that run code when opened.
var launchExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".bat": true, ".cmd": true, ".pif": true, ".js": true,
	".jse": true, ".vbs": true, ".vbe": true, ".wsf": true, ".ps1": true, ".lnk": true, ".hta": true,
	".jar": true, ".msi": true,
}

func fileRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"file.type-mismatch"}, Category: report.CategoryFile, Severity: "medium",
			Summary: "A file name with a document, image or media extension whose content is an executable or package."},
			run: ruleTypeMismatch},
		{info: Info{IDs: []string{"file.double-extension"}, Category: report.CategoryFile, Severity: "medium",
			Summary: "A name such as invoice.pdf.exe that hides a launchable extension behind a document one."},
			run: ruleDoubleExtension},
	}
}

func ruleTypeMismatch(in *input) []report.Finding {
	rep := in.rep
	ext := strings.ToLower(filepath.Ext(rep.File.Name))
	if !documentExts[ext] || (rep.Type.Family != report.FamilyExecutable && rep.Type.Family != report.FamilyPackage) {
		return nil
	}
	return []report.Finding{{
		ID: "file.type-mismatch", Title: fmt.Sprintf("Extension %s does not match the content", ext), Severity: report.SeverityMedium,
		Category: report.CategoryFile, Confidence: report.ConfidenceHigh,
		Evidence: []string{fmt.Sprintf("file name %q promises inert content but the bytes are: %s", clip(rep.File.Name, 80), rep.Type.Label)},
		Limitations: []string{
			"The name is chosen by whoever supplied the file and may have been altered in transit; the detection is based on magic bytes and structure, not on execution.",
			"Polyglot files and mislabelled downloads exist innocently, though a document name on an executable is a classic masquerading technique.",
		},
	}}
}

func ruleDoubleExtension(in *input) []report.Finding {
	name := strings.ToLower(in.rep.File.Name)
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return nil
	}
	last, prev := "."+parts[len(parts)-1], "."+parts[len(parts)-2]
	if !launchExts[last] || !documentExts[prev] {
		return nil
	}
	return []report.Finding{{
		ID: "file.double-extension", Title: "Name hides a launchable extension behind a document extension", Severity: report.SeverityMedium,
		Category: report.CategoryFile, Confidence: report.ConfidenceMedium,
		Evidence: []string{fmt.Sprintf("file name %q ends in %s%s", clip(in.rep.File.Name, 80), prev, last)},
		Limitations: []string{
			"A social-engineering indicator about the name only; it says nothing about what the content does and the name may be unrelated to the original.",
		},
	}}
}
