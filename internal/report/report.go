// Package report defines the teardown.report/v1 data contract that is shared by
// the analyzer, the CLI, the HTTP API, the MCP server and the dashboard.
//
// The contract is additive-only: later releases may add keys, but existing keys
// never change type or meaning. Every JSON key is camelCase. Slices are never
// null in the encoded form (see [Report.Normalize]) so consumers can iterate
// without nil checks.
//
// This package is a leaf: it imports nothing from the rest of the module.
package report

import (
	"slices"
	"time"
)

// Schema is the value of [Report.Schema].
const Schema = "teardown.report/v1"

// ToolName is the value of [Tool.Name].
const ToolName = "teardown"

// StaticOnly is the limitation that every report carries.
const StaticOnly = "Static analysis only; the file was never executed."

// Report is the complete result of analysing one file.
type Report struct {
	Schema      string         `json:"schema"`
	Tool        Tool           `json:"tool"`
	GeneratedAt time.Time      `json:"generatedAt"`
	DurationMs  int64          `json:"durationMs"`
	File        File           `json:"file"`
	Type        Type           `json:"type"`
	Hashes      Hashes         `json:"hashes"`
	Entropy     Entropy        `json:"entropy"`
	Sections    []Section      `json:"sections"`
	Imports     []Import       `json:"imports"`
	Exports     []string       `json:"exports"`
	Strings     Strings        `json:"strings"`
	Hardening   []Hardening    `json:"hardening"`
	Details     map[string]any `json:"details"`
	Findings    []Finding      `json:"findings"`
	Risk        Risk           `json:"risk"`
	Limitations []string       `json:"limitations"`
}

// Tool identifies the program that produced a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// File describes the analysed input. Only the base name is recorded, never a
// directory, so reports are safe to share.
type File struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Type is the detected content type (see package sniff for the identifiers).
type Type struct {
	// ID is a short stable token such as "pe", "elf" or "apk" (see the Type* constants).
	ID string `json:"id"`
	// Family groups IDs: executable, bytecode, archive, package, document, image,
	// database, model, script, text or data (see the Family* constants).
	Family string `json:"family"`
	// Label is a human readable description, e.g. "PE32+ executable (x86-64, console)".
	Label string `json:"label"`
	// MIME is the closest media type, "application/octet-stream" when unknown.
	MIME       string     `json:"mime"`
	Confidence Confidence `json:"confidence"`
	// Tags carry extra facts such as "dll", "dotnet", "upx", "pyinstaller", "java-21".
	Tags []string `json:"tags"`
}

// Hashes holds the digests computed in the single streaming pass.
type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	// Imphash is the PE import hash, or "" when the file has no PE import table.
	Imphash string `json:"imphash"`
}

// Entropy is the Shannon entropy (bits per byte, 0..8) of the whole file plus a
// windowed profile of at most 512 windows.
type Entropy struct {
	Overall float64 `json:"overall"`
	// WindowSize is the size in bytes of every window except possibly the last.
	WindowSize int64     `json:"windowSize"`
	Windows    []float64 `json:"windows"`
}

// Section is a section or segment of an executable, or a top-level part of
// another container (for example a WebAssembly section).
type Section struct {
	Name        string  `json:"name"`
	VirtualSize uint64  `json:"virtualSize"`
	RawSize     uint64  `json:"rawSize"`
	Offset      uint64  `json:"offset"`
	Entropy     float64 `json:"entropy"`
	// Flags is a subset of "R", "W", "X" in that order.
	Flags      []string `json:"flags"`
	Suspicious bool     `json:"suspicious"`
	// Reasons explains Suspicious (omitted when empty).
	Reasons []string `json:"reasons,omitempty"`
}

// Executable reports whether the X flag is set.
func (s Section) Executable() bool { return slices.Contains(s.Flags, FlagX) }

// Writable reports whether the W flag is set.
func (s Section) Writable() bool { return slices.Contains(s.Flags, FlagW) }

// Section permission flags.
const (
	FlagR = "R"
	FlagW = "W"
	FlagX = "X"
)

// Import is one imported library and the functions taken from it.
type Import struct {
	Library string `json:"library"`
	// Count is the true number of imported functions even when Functions was capped.
	Count     int      `json:"count"`
	Functions []string `json:"functions"`
}

// UnspecifiedLibrary is the Import.Library used for imported symbols that the
// format does not attribute to a particular library (ELF without symbol
// versioning, Mach-O two-level namespace off, ...).
const UnspecifiedLibrary = "(unspecified)"

// Strings summarises string extraction.
type Strings struct {
	// Total is the number of strings found (>= len(Items)).
	Total     int `json:"total"`
	MinLength int `json:"minLength"`
	// Truncated is true when Items does not contain every string found.
	Truncated  bool           `json:"truncated"`
	ByCategory map[string]int `json:"byCategory"`
	Items      []StringItem   `json:"items"`
}

// StringItem is one extracted string.
type StringItem struct {
	// Value is the string; for secrets it is the redacted form.
	Value  string `json:"value"`
	Offset int64  `json:"offset"`
	// Encoding is "ascii" or "utf16le".
	Encoding string `json:"encoding"`
	// Category is one of the Cat* constants.
	Category string `json:"category"`
	// Redacted is true when Value hides the real string (secrets only).
	Redacted bool `json:"redacted"`
	// Kind refines Category when known, e.g. "aws-access-key-id", "github-token",
	// "slack-token", "pem-private-key" or "jwt" for secrets (omitted when empty).
	Kind string `json:"kind,omitempty"`
}

// Hardening is one exploit-mitigation or integrity feature.
type Hardening struct {
	// ID is one of the Harden* constants.
	ID    string `json:"id"`
	Label string `json:"label"`
	// Status is one of the Status* constants.
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Hardening statuses.
const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"
	StatusUnknown  = "unknown"
	StatusNA       = "n/a"
)

// Risk is the deterministic triage score. It is a prioritisation aid, not a verdict.
type Risk struct {
	// Score is 0..100.
	Score int `json:"score"`
	// Label is low, medium, high or critical.
	Label string `json:"label"`
	// Basis lists, line by line, how Score was computed.
	Basis []string `json:"basis"`
}

// Risk labels.
const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

// New returns an empty report for a file, with the schema, tool name and the
// mandatory limitation already set and every slice allocated.
func New(name string, size int64, version string) *Report {
	r := &Report{
		Schema: Schema,
		Tool:   Tool{Name: ToolName, Version: version},
		File:   File{Name: name, Size: size},
	}
	r.Limitations = []string{StaticOnly}
	r.Normalize()
	return r
}

// Normalize replaces nil slices and maps with empty ones so the JSON form never
// contains null for a collection.
func (r *Report) Normalize() {
	if r.Type.Tags == nil {
		r.Type.Tags = []string{}
	}
	if r.Entropy.Windows == nil {
		r.Entropy.Windows = []float64{}
	}
	if r.Sections == nil {
		r.Sections = []Section{}
	}
	for i := range r.Sections {
		if r.Sections[i].Flags == nil {
			r.Sections[i].Flags = []string{}
		}
	}
	if r.Imports == nil {
		r.Imports = []Import{}
	}
	for i := range r.Imports {
		if r.Imports[i].Functions == nil {
			r.Imports[i].Functions = []string{}
		}
	}
	if r.Exports == nil {
		r.Exports = []string{}
	}
	if r.Strings.ByCategory == nil {
		r.Strings.ByCategory = map[string]int{}
	}
	if r.Strings.Items == nil {
		r.Strings.Items = []StringItem{}
	}
	if r.Hardening == nil {
		r.Hardening = []Hardening{}
	}
	if r.Details == nil {
		r.Details = map[string]any{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	for i := range r.Findings {
		if r.Findings[i].Evidence == nil {
			r.Findings[i].Evidence = []string{}
		}
		if r.Findings[i].Limitations == nil {
			r.Findings[i].Limitations = []string{}
		}
		for j := range r.Findings[i].Code {
			b := &r.Findings[i].Code[j]
			if b.Lines == nil {
				b.Lines = []CodeLine{}
			}
			if b.Limitations == nil {
				b.Limitations = []string{}
			}
		}
	}
	if r.Risk.Basis == nil {
		r.Risk.Basis = []string{}
	}
	if r.Limitations == nil {
		r.Limitations = []string{}
	}
}

// AddLimitation appends a report-level limitation unless it is already present.
func (r *Report) AddLimitation(s string) {
	if !slices.Contains(r.Limitations, s) {
		r.Limitations = append(r.Limitations, s)
	}
}

// HardeningByID returns the hardening entry with the given ID.
func (r *Report) HardeningByID(id string) (Hardening, bool) {
	for _, h := range r.Hardening {
		if h.ID == id {
			return h, true
		}
	}
	return Hardening{}, false
}

// HasTag reports whether the detected type carries the tag.
func (r *Report) HasTag(tag string) bool { return slices.Contains(r.Type.Tags, tag) }

// MaxSeverity returns the highest severity among the findings and false when
// there are none.
func (r *Report) MaxSeverity() (Severity, bool) {
	best, found := SeverityInfo, false
	for _, f := range r.Findings {
		if !found || f.Severity.Rank() > best.Rank() {
			best, found = f.Severity, true
		}
	}
	return best, found
}

// Meets reports whether any finding has at least the given severity. It is the
// predicate behind the CLI's --fail-on gate.
func (r *Report) Meets(threshold Severity) bool {
	for _, f := range r.Findings {
		if f.Severity.AtLeast(threshold) {
			return true
		}
	}
	return false
}

// CountBySeverity returns how many findings exist per severity.
func (r *Report) CountBySeverity() map[Severity]int {
	out := make(map[Severity]int, len(allSeverities))
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}
