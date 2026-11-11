package rules

import (
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

type hardeningSpec struct {
	id    string
	title string
	sev   report.Severity
	note  string
}

const hardeningLimitation = "Describes how hard the file is to exploit, not whether it is malicious: older toolchains, statically linked and embedded software often lack these mitigations."

// hardeningSpecs maps a hardening ID to the finding raised when it is disabled.
var hardeningSpecs = map[string]hardeningSpec{
	report.HardenASLR: {"hardening.no-aslr", "ASLR is disabled (image has a fixed base address)", report.SeverityMedium,
		"The dynamic-base flag is necessary but not sufficient: ASLR is only effective when relocation data is present."},
	report.HardenDEP: {"hardening.no-dep", "DEP/NX is not enabled", report.SeverityMedium,
		"Mitigation flags are read from the header; the OS may apply system-wide policy regardless."},
	report.HardenPIE: {"hardening.no-pie", "Executable is not position independent (no PIE)", report.SeverityMedium,
		"A fixed load address defeats ASLR for the main image; shared libraries are unaffected."},
	report.HardenNX: {"hardening.no-nx", "Stack is executable (no NX)", report.SeverityMedium,
		"Derived from the GNU_STACK program header; a missing header is treated as an executable stack by older loaders."},
	report.HardenRELRO: {"hardening.no-relro", "No RELRO: the GOT stays writable", report.SeverityLow,
		"Partial RELRO still protects the data sections; full RELRO additionally needs immediate binding."},
	report.HardenCanary: {"hardening.no-canary", "No stack-smashing protection detected", report.SeverityLow,
		"Detection relies on __stack_chk_fail appearing in the symbols or imports; stripped static binaries can hide it, and code with no stack buffers needs none."},
	report.HardenSEH: {"hardening.no-seh-protection", "Structured exception handling is not hardened", report.SeverityLow,
		"Only relevant to 32-bit images; SafeSEH tables and /SAFESEH cannot be checked for every linker's output."},
	report.HardenCFG: {"hardening.no-cfg", "Control Flow Guard is not enabled", report.SeverityInfo,
		"CFG is only worthwhile for code built with it; many third-party and non-MSVC toolchains do not offer it."},
	report.HardenHighEntropyVA: {"hardening.no-high-entropy-va", "64-bit ASLR entropy is not enabled", report.SeverityInfo,
		"High-entropy ASLR only matters for 64-bit images."},
	report.HardenFortify: {"hardening.no-fortify", "No _FORTIFY_SOURCE checked calls found", report.SeverityInfo,
		"No *_chk imports may simply mean the program has nothing to fortify, or that it is statically linked."},
}

func hardeningRules() []rule {
	ids := make([]string, 0, len(hardeningSpecs)+2)
	for _, spec := range hardeningSpecs {
		ids = append(ids, spec.id)
	}
	slices.Sort(ids)
	ids = append(ids, "hardening.partial-relro")
	return []rule{
		{info: Info{IDs: ids, Category: report.CategoryHardening, Severity: "info-medium",
			Summary: "A mitigation the format parser reported as disabled (ASLR, DEP, PIE, NX, RELRO, stack canary, SafeSEH, CFG, ...); partial RELRO is reported at info level."},
			run: ruleHardening},
		{info: Info{IDs: []string{"signature.unsigned"}, Category: report.CategorySignature, Severity: "low",
			Summary: "No Authenticode signature (PE), code signature (Mach-O) or APK signature was found."},
			run: ruleUnsigned},
	}
}

func ruleHardening(in *input) []report.Finding {
	var out []report.Finding
	for _, h := range in.rep.Hardening {
		if h.ID == report.HardenRELRO && h.Status == report.StatusEnabled && strings.Contains(strings.ToLower(h.Detail), "partial") {
			out = append(out, report.Finding{
				ID: "hardening.partial-relro", Title: "Only partial RELRO: the GOT remains writable", Severity: report.SeverityInfo,
				Category: report.CategoryHardening, Confidence: report.ConfidenceHigh,
				Evidence:    []string{h.Label + ": " + h.Detail},
				Limitations: []string{hardeningLimitation, "Full RELRO needs both PT_GNU_RELRO and immediate binding (-z now)."},
			})
			continue
		}
		spec, ok := hardeningSpecs[h.ID]
		if !ok || h.Status != report.StatusDisabled {
			continue
		}
		out = append(out, report.Finding{
			ID: spec.id, Title: spec.title, Severity: spec.sev, Category: report.CategoryHardening,
			Confidence:  report.ConfidenceHigh,
			Evidence:    []string{h.Label + ": " + h.Detail},
			Limitations: []string{hardeningLimitation, spec.note},
		})
	}
	return out
}

func ruleUnsigned(in *input) []report.Finding {
	rep := in.rep
	if h, ok := rep.HardeningByID(report.HardenSigned); ok && h.Status == report.StatusDisabled {
		var limits []string
		if rep.Type.ID == report.TypePE {
			limits = append(limits, "Windows system files and driver packages are often signed through security catalogs (.cat) instead of an embedded signature, which this check cannot see.")
		}
		limits = append(limits, "Only the presence of a signature is checked; a present signature is not verified here and an absent one is normal for open-source and internal tools.")
		return []report.Finding{{
			ID: "signature.unsigned", Title: "No embedded code signature present", Severity: report.SeverityLow,
			Category: report.CategorySignature, Confidence: report.ConfidenceHigh,
			Evidence:    []string{h.Label + ": " + h.Detail},
			Limitations: limits,
		}}
	}
	if rep.Type.ID == report.TypeAPK {
		a, ok := detail[archiveFacts](rep, "archive")
		if ok && !a.Signed && (a.Android == nil || !a.Android.SigningBlock) {
			return []report.Finding{{
				ID: "signature.unsigned", Title: "No APK signature found", Severity: report.SeverityLow,
				Category: report.CategorySignature, Confidence: report.ConfidenceMedium,
				Evidence: []string{"no META-INF signature files and no APK Signing Block before the central directory"},
				Limitations: []string{
					"Android refuses to install unsigned packages, so this is usually a build artefact; signatures are not verified here.",
				},
			}}
		}
	}
	return nil
}
