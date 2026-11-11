package pe

import "github.com/q6r/teardown/internal/report"

// Labels of the hardening entries (the IDs come from package report).
const (
	labelASLR           = "ASLR (DYNAMIC_BASE)"
	labelHighEntropyVA  = "High-entropy ASLR (HIGH_ENTROPY_VA)"
	labelDEP            = "DEP (NX_COMPAT)"
	labelCFG            = "Control Flow Guard (GUARD_CF)"
	labelSEH            = "Safe exception handling (SafeSEH / NO_SEH)"
	labelForceIntegrity = "Forced signature integrity (FORCE_INTEGRITY)"
	labelSigned         = "Authenticode signature present (not verified)"
)

// buildHardening evaluates the exploit-mitigation flags. Every entry carries a
// one-sentence detail naming the flag it is based on.
func (p *parser) buildHardening() []report.Hardening {
	h := &p.h
	entry := func(id, label, status, detail string) report.Hardening {
		return report.Hardening{ID: id, Label: label, Status: status, Detail: detail}
	}
	if !h.hasFlags {
		const why = "the optional header is missing or cut off before DllCharacteristics, so the flags are unknown"
		return []report.Hardening{
			entry(report.HardenASLR, labelASLR, report.StatusUnknown, why),
			entry(report.HardenHighEntropyVA, labelHighEntropyVA, report.StatusUnknown, why),
			entry(report.HardenDEP, labelDEP, report.StatusUnknown, why),
			entry(report.HardenCFG, labelCFG, report.StatusUnknown, why),
			entry(report.HardenSEH, labelSEH, report.StatusUnknown, why),
			entry(report.HardenForceIntegrity, labelForceIntegrity, report.StatusUnknown, why),
			entry(report.HardenSigned, labelSigned, report.StatusUnknown, why),
		}
	}
	set := func(f uint16) bool { return h.dllChars&f != 0 }
	managed := p.det.DotNet && p.clrILOnly

	var aslr, heva, dep, cfg, seh, force, signed report.Hardening
	switch {
	case !set(dllDynamicBase):
		aslr = entry(report.HardenASLR, labelASLR, report.StatusDisabled,
			"DYNAMIC_BASE is not set; the image always loads at its preferred base address")
	case h.chars&charRelocsStripped != 0:
		aslr = entry(report.HardenASLR, labelASLR, report.StatusDisabled,
			"DYNAMIC_BASE is set but relocations are stripped (RELOCS_STRIPPED), so the image cannot be rebased and ASLR is ineffective")
	default:
		aslr = entry(report.HardenASLR, labelASLR, report.StatusEnabled,
			"DYNAMIC_BASE is set; the image can be rebased at load time")
	}

	switch {
	case !h.pe64:
		heva = entry(report.HardenHighEntropyVA, labelHighEntropyVA, report.StatusNA,
			"high-entropy ASLR applies to 64-bit images only")
	case set(dllHighEntropyVA) && !set(dllDynamicBase):
		heva = entry(report.HardenHighEntropyVA, labelHighEntropyVA, report.StatusEnabled,
			"HIGH_ENTROPY_VA is set but has no effect without DYNAMIC_BASE")
	case set(dllHighEntropyVA):
		heva = entry(report.HardenHighEntropyVA, labelHighEntropyVA, report.StatusEnabled,
			"HIGH_ENTROPY_VA is set; 64-bit ASLR may use the full address space")
	default:
		heva = entry(report.HardenHighEntropyVA, labelHighEntropyVA, report.StatusDisabled,
			"HIGH_ENTROPY_VA is not set; 64-bit ASLR uses less entropy for this image")
	}

	switch {
	case set(dllNXCompat):
		dep = entry(report.HardenDEP, labelDEP, report.StatusEnabled, "NX_COMPAT is set; the image opts in to data execution prevention")
	case h.pe64:
		dep = entry(report.HardenDEP, labelDEP, report.StatusDisabled,
			"NX_COMPAT is not set (64-bit Windows enforces DEP for 64-bit processes regardless)")
	default:
		dep = entry(report.HardenDEP, labelDEP, report.StatusDisabled, "NX_COMPAT is not set; the image does not opt in to data execution prevention")
	}

	switch {
	case managed:
		cfg = entry(report.HardenCFG, labelCFG, report.StatusNA, "managed (IL-only) code is not compiled with Control Flow Guard")
	case set(dllGuardCF) && p.lc.guardFlags&0x400 != 0:
		cfg = entry(report.HardenCFG, labelCFG, report.StatusEnabled, "GUARD_CF is set and the load configuration has a CF function table")
	case set(dllGuardCF):
		cfg = entry(report.HardenCFG, labelCFG, report.StatusEnabled, "GUARD_CF is set")
	default:
		cfg = entry(report.HardenCFG, labelCFG, report.StatusDisabled, "GUARD_CF is not set")
	}

	switch {
	case h.machine != machineI386:
		seh = entry(report.HardenSEH, labelSEH, report.StatusNA, "SafeSEH and NO_SEH apply to x86 images only")
	case managed:
		seh = entry(report.HardenSEH, labelSEH, report.StatusNA, "managed (IL-only) code does not use native exception handlers")
	case set(dllNoSEH):
		seh = entry(report.HardenSEH, labelSEH, report.StatusEnabled, "NO_SEH is set; the image uses no structured exception handlers")
	case p.lc.safeSEH:
		seh = entry(report.HardenSEH, labelSEH, report.StatusEnabled, "the load configuration has a SafeSEH handler table")
	default:
		seh = entry(report.HardenSEH, labelSEH, report.StatusDisabled, "NO_SEH is not set and there is no SafeSEH handler table")
	}

	if set(dllForceIntegrity) {
		force = entry(report.HardenForceIntegrity, labelForceIntegrity, report.StatusEnabled,
			"FORCE_INTEGRITY is set; the loader checks the signature at load time")
	} else {
		force = entry(report.HardenForceIntegrity, labelForceIntegrity, report.StatusDisabled, "FORCE_INTEGRITY is not set")
	}

	if p.det.Signed {
		signed = entry(report.HardenSigned, labelSigned, report.StatusEnabled,
			"an Authenticode certificate table is present; the signature and its chain were not validated")
	} else {
		signed = entry(report.HardenSigned, labelSigned, report.StatusDisabled, "no Authenticode certificate table")
	}
	return []report.Hardening{aslr, heva, dep, cfg, seh, force, signed}
}
