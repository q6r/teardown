package rules

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/q6r/teardown/internal/report"
)

const (
	overlayMinBytes = 4096
	// firstPETimestamp is the earliest plausible PE link time (Windows NT 3.1 era).
	firstPETimestamp = "1992-01-01T00:00:00Z"
)

func structureRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"structure.rwx-section"}, Category: report.CategoryStructure, Severity: "medium",
			Summary: "Sections that are both writable and executable."},
			run: ruleRWXSections},
		{info: Info{IDs: []string{"structure.rwx-segment"}, Category: report.CategoryStructure, Severity: "medium",
			Summary: "ELF program headers that map memory writable and executable."},
			run: ruleRWXSegments},
		{info: Info{IDs: []string{"structure.suspicious-section"}, Category: report.CategoryStructure, Severity: "low",
			Summary: "Sections the format parser flagged for a structural reason other than RWX (odd name, empty executable section, huge virtual size)."},
			run: ruleSuspiciousSections},
		{info: Info{IDs: []string{"structure.entry-point-anomaly"}, Category: report.CategoryStructure, Severity: "low-medium",
			Summary: "PE entry point outside every section, in a non-executable section, or in the last section."},
			run: ruleEntryPoint},
		{info: Info{IDs: []string{"structure.overlay"}, Category: report.CategoryStructure, Severity: "info-low",
			Summary: "Data appended after the end of the PE image (overlay) of at least 4 KiB."},
			run: ruleOverlay},
		{info: Info{IDs: []string{"structure.timestamp-anomaly"}, Category: report.CategoryStructure, Severity: "info",
			Summary: "PE link timestamp in the future or before the format existed."},
			run: ruleTimestamp},
		{info: Info{IDs: []string{"structure.insecure-rpath"}, Category: report.CategoryStructure, Severity: "low",
			Summary: "ELF RPATH/RUNPATH entries that are relative or point into world-writable locations."},
			run: ruleRPath},
	}
}

func ruleRWXSections(in *input) []report.Finding {
	var evidence []string
	for _, s := range in.rep.Sections {
		if s.Writable() && s.Executable() {
			evidence = append(evidence, fmt.Sprintf("%s: flags %s, raw size %s", s.Name, flagString(s), humanBytes(s.RawSize)))
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "structure.rwx-section", Title: "Section is both writable and executable", Severity: report.SeverityMedium,
		Category: report.CategoryStructure, Confidence: report.ConfidenceHigh, Evidence: sample(evidence, 8),
		Limitations: []string{
			"Describes the file layout, not run-time behaviour. Packers, self-extractors, JIT-style loaders and some legacy toolchains legitimately use RWX sections.",
			"The section flags come from the header and may not match the protection the loader finally applies.",
		},
	}}
}

type elfSegmentFacts struct {
	Segments []struct {
		Type  string   `json:"type"`
		Flags []string `json:"flags"`
		VAddr string   `json:"vaddr"` // "0x..." hex string
	} `json:"segments"`
	RPath   []string `json:"rpath"`
	RunPath []string `json:"runpath"`
}

func ruleRWXSegments(in *input) []report.Finding {
	elf, ok := detail[elfSegmentFacts](in.rep, "elf")
	if !ok {
		return nil
	}
	var evidence []string
	for _, s := range elf.Segments {
		if slices.Contains(s.Flags, report.FlagW) && slices.Contains(s.Flags, report.FlagX) {
			evidence = append(evidence, fmt.Sprintf("%s segment at %s mapped RWX", s.Type, orDash(s.VAddr)))
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "structure.rwx-segment", Title: "Program header maps memory writable and executable", Severity: report.SeverityMedium,
		Category: report.CategoryStructure, Confidence: report.ConfidenceHigh, Evidence: sample(evidence, 8),
		Limitations: []string{
			"An executable stack (GNU_STACK with X) or an RWX load segment is typical of old toolchains, assembly programs and shellcode loaders alike.",
			"Describes the file layout, not what the program does at run time.",
		},
	}}
}

func ruleSuspiciousSections(in *input) []report.Finding {
	var evidence []string
	for _, s := range in.rep.Sections {
		if !s.Suspicious {
			continue
		}
		if s.Writable() && s.Executable() && len(s.Reasons) <= 1 {
			continue // already reported by structure.rwx-section
		}
		reason := "flagged by the parser"
		if len(s.Reasons) > 0 {
			reason = strings.Join(s.Reasons, "; ")
		}
		evidence = append(evidence, fmt.Sprintf("%s: %s", s.Name, reason))
	}
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "structure.suspicious-section", Title: "Sections with unusual structure", Severity: report.SeverityLow,
		Category: report.CategoryStructure, Confidence: report.ConfidenceMedium, Evidence: sample(evidence, 8),
		Limitations: []string{
			"Odd section names and sizes are produced by many legitimate toolchains (Go, Delphi, custom linkers, resource packers) as well as by packers.",
		},
	}}
}

type peEntryFacts struct {
	EntryPoint   string `json:"entryPoint"`
	EntrySection string `json:"entrySection"`
}

func ruleEntryPoint(in *input) []report.Finding {
	pe, ok := detail[peEntryFacts](in.rep, "pe")
	if !ok || pe.EntryPoint == "" || pe.EntryPoint == "0x0" {
		return nil
	}
	sections := in.rep.Sections
	var evidence []string
	sev, conf := report.SeverityLow, report.ConfidenceLow
	switch pe.EntrySection {
	case "":
		evidence = append(evidence, fmt.Sprintf("entry point %s lies outside every section", pe.EntryPoint))
		sev, conf = report.SeverityMedium, report.ConfidenceMedium
	default:
		idx := slices.IndexFunc(sections, func(s report.Section) bool { return s.Name == pe.EntrySection })
		switch {
		case idx >= 0 && !sections[idx].Executable():
			evidence = append(evidence, fmt.Sprintf("entry point %s lies in non-executable section %s", pe.EntryPoint, pe.EntrySection))
			sev, conf = report.SeverityMedium, report.ConfidenceMedium
		case idx >= 0 && idx == len(sections)-1 && len(sections) >= 3:
			evidence = append(evidence, fmt.Sprintf("entry point %s lies in the last section (%s) of %d", pe.EntryPoint, pe.EntrySection, len(sections)))
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "structure.entry-point-anomaly", Title: "Entry point is not in the usual place", Severity: sev,
		Category: report.CategoryStructure, Confidence: conf, Evidence: evidence,
		Limitations: []string{
			"Packers and protectors move the entry point into their stub, but so do some installers, managed-code launchers and unusual linkers.",
		},
	}}
}

type peOverlayFacts struct {
	OverlaySize  int64  `json:"overlaySize"`
	Timestamp    string `json:"timestamp"`
	Reproducible bool   `json:"reproducible"`
}

func ruleOverlay(in *input) []report.Finding {
	pe, ok := detail[peOverlayFacts](in.rep, "pe")
	if !ok || pe.OverlaySize < overlayMinBytes || in.rep.File.Size <= 0 {
		return nil
	}
	pct := 100 * float64(pe.OverlaySize) / float64(in.rep.File.Size)
	sev := report.SeverityInfo
	if pct >= 50 {
		sev = report.SeverityLow
	}
	return []report.Finding{{
		ID: "structure.overlay", Title: "Data is appended after the PE image", Severity: sev,
		Category: report.CategoryStructure, Confidence: report.ConfidenceLow,
		Evidence: []string{fmt.Sprintf("overlay of %s (%.0f%% of the file)", humanBytes(uint64(pe.OverlaySize)), pct)},
		Limitations: []string{
			"Installers, self-extractors, Python/Electron/Go bundlers and signed binaries append data on purpose; malware droppers hide payloads the same way. The overlay is not analysed here.",
			"The Authenticode certificate table is excluded from the overlay size when it sits at the end of the file.",
		},
	}}
}

func ruleTimestamp(in *input) []report.Finding {
	pe, ok := detail[peOverlayFacts](in.rep, "pe")
	if !ok || pe.Timestamp == "" || pe.Reproducible {
		return nil // a reproducible-build marker means the field is a hash, not a time
	}
	ts, err := time.Parse(time.RFC3339, pe.Timestamp)
	if err != nil {
		return nil
	}
	floor, _ := time.Parse(time.RFC3339, firstPETimestamp)
	var evidence string
	switch {
	case !in.rep.GeneratedAt.IsZero() && ts.After(in.rep.GeneratedAt.Add(24*time.Hour)):
		evidence = fmt.Sprintf("link timestamp %s is later than the analysis time", pe.Timestamp)
	case ts.Before(floor):
		evidence = fmt.Sprintf("link timestamp %s predates the PE format", pe.Timestamp)
	default:
		return nil
	}
	return []report.Finding{{
		ID: "structure.timestamp-anomaly", Title: "PE link timestamp is implausible", Severity: report.SeverityInfo,
		Category: report.CategoryStructure, Confidence: report.ConfidenceMedium, Evidence: []string{evidence},
		Limitations: []string{
			"The timestamp is a forgeable header field; reproducible-build toolchains replace it with a constant or a hash on purpose.",
		},
	}}
}

func ruleRPath(in *input) []report.Finding {
	elf, ok := detail[elfSegmentFacts](in.rep, "elf")
	if !ok {
		return nil
	}
	var evidence []string
	check := func(kind string, entries []string) {
		for _, e := range entries {
			switch {
			case e == "" || e == ".":
				evidence = append(evidence, fmt.Sprintf("%s contains the current directory", kind))
			case strings.HasPrefix(e, "/tmp") || strings.HasPrefix(e, "/var/tmp") || strings.HasPrefix(e, "/dev/shm") || strings.HasPrefix(e, "/home/"):
				evidence = append(evidence, fmt.Sprintf("%s entry %q is in a user-writable location", kind, e))
			case !strings.HasPrefix(e, "/") && !strings.HasPrefix(e, "$ORIGIN") && !strings.HasPrefix(e, "${ORIGIN}"):
				evidence = append(evidence, fmt.Sprintf("%s entry %q is relative", kind, e))
			}
		}
	}
	check("RPATH", elf.RPath)
	check("RUNPATH", elf.RunPath)
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "structure.insecure-rpath", Title: "Library search path points somewhere an attacker may control", Severity: report.SeverityLow,
		Category: report.CategoryStructure, Confidence: report.ConfidenceMedium, Evidence: sample(sortedUnique(evidence), 8),
		Limitations: []string{
			"Relative and user-writable search paths enable library planting only if an attacker can write there at run time; development builds often carry them by accident.",
		},
	}}
}
