package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Entropy thresholds (bits per byte). Random or well-compressed data sits near 8;
// compiled code and text are typically between 4.5 and 6.8.
const (
	// HighEntropySection is the entropy from which a section is reported.
	HighEntropySection = 7.2
	// HighEntropyFile is the overall entropy from which an executable without a
	// parsed section table is reported.
	HighEntropyFile = 7.5
	// minEntropyBytes ignores tiny sections whose entropy is statistically meaningless.
	minEntropyBytes = 1024
)

const entropyLimitation = "Compressed or encrypted resources, embedded images, archives and fonts are legitimately high-entropy; high entropy suggests packing or encryption but does not prove either."

func packingRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"packing.high-entropy-section"}, Category: report.CategoryPacking, Severity: "low-medium",
			Summary: fmt.Sprintf("Executable sections of at least 1 KiB whose entropy is >= %.1f bits per byte.", HighEntropySection)},
			run: ruleHighEntropySections},
		{info: Info{IDs: []string{"packing.high-entropy-file"}, Category: report.CategoryPacking, Severity: "low",
			Summary: fmt.Sprintf("An executable with no parsed sections whose overall entropy is >= %.1f.", HighEntropyFile)},
			run: ruleHighEntropyFile},
		{info: Info{IDs: []string{"packing.upx"}, Category: report.CategoryPacking, Severity: "medium",
			Summary: "UPX packer markers (UPX0/UPX1 sections or the UPX! signature)."},
			run: ruleUPX},
		{info: Info{IDs: []string{"packing.known-packer"}, Category: report.CategoryPacking, Severity: "medium",
			Summary: "PE section names used by known packers and protectors (ASPack, Themida, VMProtect, MPRESS, ...)."},
			run: rulePackerSections},
		{info: Info{IDs: []string{"packaging.pyinstaller"}, Category: report.CategoryPacking, Severity: "info",
			Summary: "PyInstaller bundle cookie: a Python application packaged as a native executable."},
			run: rulePyInstaller},
	}
}

func ruleHighEntropySections(in *input) []report.Finding {
	if !isExecutable(in.rep) {
		return nil
	}
	var evidence []string
	execHit := false
	for _, s := range in.rep.Sections {
		if s.Entropy < HighEntropySection || s.RawSize < minEntropyBytes {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s: entropy %.2f, raw size %s, flags %s", s.Name, s.Entropy, humanBytes(s.RawSize), flagString(s)))
		if s.Executable() {
			execHit = true
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	sev, conf := report.SeverityLow, report.ConfidenceLow
	title := "Non-code section with very high entropy"
	if execHit {
		sev, conf = report.SeverityMedium, report.ConfidenceMedium
		title = "Executable section with very high entropy (possible packing or encryption)"
	}
	return []report.Finding{{
		ID: "packing.high-entropy-section", Title: title, Severity: sev, Category: report.CategoryPacking, Confidence: conf,
		Evidence:    sample(evidence, 8),
		Limitations: []string{entropyLimitation, "Entropy is computed over the raw bytes of each section; very large sections are sampled."},
	}}
}

func ruleHighEntropyFile(in *input) []report.Finding {
	rep := in.rep
	if !isExecutable(rep) || len(rep.Sections) > 0 || rep.Entropy.Overall < HighEntropyFile || rep.File.Size < minEntropyBytes {
		return nil
	}
	return []report.Finding{{
		ID: "packing.high-entropy-file", Title: "Executable with very high overall entropy and no parsed sections",
		Severity: report.SeverityLow, Category: report.CategoryPacking, Confidence: report.ConfidenceLow,
		Evidence:    []string{fmt.Sprintf("overall entropy %.2f over %s", rep.Entropy.Overall, humanBytes(uint64(rep.File.Size)))},
		Limitations: []string{entropyLimitation, "The section table could not be used, so the entropy cannot be attributed to code or data."},
	}}
}

func ruleUPX(in *input) []report.Finding {
	if !in.rep.HasTag("upx") {
		return nil
	}
	return []report.Finding{{
		ID: "packing.upx", Title: "File is packed with UPX", Severity: report.SeverityMedium,
		Category: report.CategoryPacking, Confidence: report.ConfidenceHigh,
		Evidence: []string{"UPX markers detected (section names UPX0/UPX1 or the UPX! signature)"},
		Limitations: []string{
			"UPX is a legitimate open-source packer that benign software also uses to shrink binaries.",
			"Packing hides the original code and imports from static triage: unpack the file first (for example with upx -d) and analyse the result for a meaningful picture.",
		},
	}}
}

func rulePackerSections(in *input) []report.Finding {
	pe, ok := detail[struct {
		PackerHints []string `json:"packerHints"`
	}](in.rep, "pe")
	if !ok {
		return nil
	}
	var hints []string
	for _, h := range pe.PackerHints {
		if !strings.HasPrefix(strings.ToLower(h), "upx") {
			hints = append(hints, h)
		}
	}
	if len(hints) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "packing.known-packer", Title: "Section names match a known packer or protector", Severity: report.SeverityMedium,
		Category: report.CategoryPacking, Confidence: report.ConfidenceMedium, Evidence: sample(hints, 8),
		Limitations: []string{
			"Section names are chosen by the linker or packer and are trivial to fake or rename.",
			"Commercial protectors are also used on legitimate software (licensing, anti-tamper).",
		},
	}}
}

func rulePyInstaller(in *input) []report.Finding {
	if !in.rep.HasTag("pyinstaller") {
		return nil
	}
	return []report.Finding{{
		ID: "packaging.pyinstaller", Title: "Python application bundled with PyInstaller", Severity: report.SeverityInfo,
		Category: report.CategoryPacking, Confidence: report.ConfidenceHigh,
		Evidence: []string{"PyInstaller archive cookie found near the end of the file"},
		Limitations: []string{
			"The bundled Python bytecode is not extracted or analysed here: the native imports and strings describe the bootloader, not the application.",
			"PyInstaller is widely used for legitimate tools as well as malware.",
		},
	}}
}

func flagString(s report.Section) string {
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

// sortedUnique returns a sorted copy without duplicates.
func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
