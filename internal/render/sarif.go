package render

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

const (
	sarifSchema      = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifInformation = "https://github.com/q6r/teardown"
	maxSARIFEvidence = 5
)

// SARIF writes the findings of rep as a SARIF 2.1.0 log, the format that code
// scanning dashboards read. Each distinct finding ID becomes a rule, each
// finding a result attached to the analysed file (by base name, because that is
// all a report records), and the evidence and limitations travel in the result's
// properties. Severity maps to the SARIF level: critical and high are errors,
// medium is a warning, low and info are notes.
func SARIF(w io.Writer, rep *report.Report) error {
	driver := sarifDriver{Name: report.ToolName, Version: rep.Tool.Version, InformationURI: sarifInformation, Rules: []sarifRule{}}
	ruleIndex := map[string]int{}
	results := make([]sarifResult, 0, len(rep.Findings))
	uri := (&url.URL{Path: safe(rep.File.Name)}).EscapedPath()
	for _, f := range rep.Findings {
		level := sarifLevel(f.Severity)
		idx, seen := ruleIndex[f.ID]
		if !seen {
			idx = len(driver.Rules)
			ruleIndex[f.ID] = idx
			driver.Rules = append(driver.Rules, sarifRule{
				ID:               f.ID,
				ShortDescription: sarifText{Text: safe(f.Title)},
				Help:             sarifText{Text: "How this can be wrong: " + joinSafe(f.Limitations, " ")},
				DefaultConfig:    sarifConfig{Level: level},
				Properties:       map[string]any{"category": f.Category, "tags": []string{f.Category, "static-analysis"}},
			})
		}
		text := safe(f.Title)
		if shown := f.Evidence[:min(len(f.Evidence), maxSARIFEvidence)]; len(shown) > 0 {
			text += ". Evidence: " + joinSafe(shown, "; ")
		}
		results = append(results, sarifResult{
			RuleID: f.ID, RuleIndex: idx, Level: level, Message: sarifText{Text: text},
			Locations:  []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifactLocation{URI: uri, Index: 0}}}},
			Properties: map[string]any{"severity": f.Severity, "confidence": f.Confidence, "category": f.Category, "evidence": f.Evidence, "limitations": f.Limitations},
		})
	}
	doc := sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{{
		Tool:      sarifTool{Driver: driver},
		Artifacts: []sarifArtifact{{Location: sarifArtifactLocation{URI: uri}, Length: rep.File.Size, Hashes: map[string]string{"sha-256": rep.Hashes.SHA256, "sha-1": rep.Hashes.SHA1, "md5": rep.Hashes.MD5}}},
		Results:   results,
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode SARIF: %w", err)
	}
	return nil
}

func sarifLevel(s report.Severity) string {
	switch s {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// joinSafe joins untrusted lines after making each harmless to print.
func joinSafe(items []string, sep string) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = safe(it)
	}
	return strings.Join(parts, sep)
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Artifacts []sarifArtifact `json:"artifacts"`
	Results   []sarifResult   `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Help             sarifText      `json:"help"`
	DefaultConfig    sarifConfig    `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
	Length   int64                 `json:"length"`
	Hashes   map[string]string     `json:"hashes"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}
