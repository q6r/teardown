package macho

import (
	"fmt"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// isGo reports whether the image carries Go runtime sections, for which stack
// canaries are not applicable.
func (t *thin) isGo() bool {
	for _, seg := range t.segments {
		for _, sec := range seg.sections {
			if strings.HasSuffix(sec.name, ",__gopclntab") || strings.HasSuffix(sec.name, ",__go_buildinfo") {
				return true
			}
		}
	}
	return false
}

// hardening summarises the exploit-mitigation and integrity features of the
// primary slice: pie, nx, canary, signed and encrypted.
func (p *parser) hardening(t *thin, si symbolInfo) []report.Hardening {
	return []report.Hardening{checkPIE(t), checkNX(t), checkCanary(t, si), checkSigned(t), checkEncrypted(t)}
}

func checkPIE(t *thin) report.Hardening {
	h := report.Hardening{ID: report.HardenPIE, Label: "PIE (MH_PIE)"}
	switch {
	case t.typ != typeExecute:
		h.Status, h.Detail = report.StatusNA, fmt.Sprintf("only executables are position independent executables (this is a %s)", typeName(t.typ))
	case t.flags&flagPIE != 0:
		h.Status, h.Detail = report.StatusEnabled, "MH_PIE is set: the image can be loaded at a random base address"
	default:
		h.Status, h.Detail = report.StatusDisabled, "MH_PIE is not set: the executable has a fixed load address"
	}
	return h
}

func checkNX(t *thin) report.Hardening {
	h := report.Hardening{ID: report.HardenNX, Label: "Non-executable stack (MH_ALLOW_STACK_EXECUTION)"}
	switch {
	case t.typ == typeObject:
		h.Status, h.Detail = report.StatusNA, "object files carry no stack policy"
	case t.flags&flagAllowStackExe != 0:
		h.Status, h.Detail = report.StatusDisabled, "MH_ALLOW_STACK_EXECUTION is set: the stack may be executable"
	default:
		h.Status, h.Detail = report.StatusEnabled, "MH_ALLOW_STACK_EXECUTION is not set: the stack is not executable"
		if t.flags&flagNoHeapExe != 0 {
			h.Detail += " (MH_NO_HEAP_EXECUTION is also set)"
		}
	}
	return h
}

func checkCanary(t *thin, si symbolInfo) report.Hardening {
	h := report.Hardening{ID: report.HardenCanary, Label: "Stack canary (-fstack-protector)"}
	switch {
	case si.canary:
		h.Status, h.Detail = report.StatusEnabled, "references ___stack_chk_fail or ___stack_chk_guard"
	case t.isGo():
		h.Status, h.Detail = report.StatusNA, "Go binary: the Go compiler does not emit stack canaries"
	case si.decoded:
		h.Status, h.Detail = report.StatusDisabled, fmt.Sprintf("no ___stack_chk_fail among %d symbols", t.nsyms)
	default:
		h.Status, h.Detail = report.StatusUnknown, "no readable symbol table: stack canary use cannot be determined"
	}
	return h
}

func checkSigned(t *thin) report.Hardening {
	h := report.Hardening{ID: report.HardenSigned, Label: "Code signature (LC_CODE_SIGNATURE)"}
	switch {
	case t.typ == typeObject:
		h.Status, h.Detail = report.StatusNA, "object files are not signed"
	case t.signed:
		h.Status, h.Detail = report.StatusEnabled, "LC_CODE_SIGNATURE present (presence only: the signature is not verified and hardened-runtime flags are not decoded)"
	default:
		h.Status, h.Detail = report.StatusDisabled, "no LC_CODE_SIGNATURE load command"
	}
	return h
}

func checkEncrypted(t *thin) report.Hardening {
	h := report.Hardening{ID: report.HardenEncrypted, Label: "Encrypted image (LC_ENCRYPTION_INFO)"}
	switch {
	case !t.hasEncCmd:
		h.Status, h.Detail = report.StatusNA, "no LC_ENCRYPTION_INFO load command"
	case t.cryptID != 0:
		h.Status, h.Detail = report.StatusEnabled, fmt.Sprintf("LC_ENCRYPTION_INFO with cryptid %d: the image is encrypted (App Store DRM), so its code cannot be analysed statically", t.cryptID)
	default:
		h.Status, h.Detail = report.StatusDisabled, "LC_ENCRYPTION_INFO is present with cryptid 0: the image is not encrypted"
	}
	return h
}
