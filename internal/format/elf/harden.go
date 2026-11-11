package elf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// linking classifies how an image finds its libraries:
//
//	"dynamic"    PT_INTERP present, or a dynamic section with DT_NEEDED entries
//	"static-pie" no PT_INTERP, a dynamic section and DF_1_PIE, no DT_NEEDED
//	"static"     an executable or shared-object image with neither PT_INTERP nor PT_DYNAMIC
//	""           anything else (relocatable objects, libraries without dependencies, ...)
func (p *parser) linking() string {
	switch {
	case p.h.typ != etExec && p.h.typ != etDyn:
		return ""
	case p.interp != "" || len(p.dyn.needed) > 0 || p.hasProg(ptInterp):
		return "dynamic"
	case p.dyn.present && p.dyn.flags1&df1PIE != 0:
		return "static-pie"
	case !p.dyn.present && len(p.progs) > 0:
		return "static"
	}
	return ""
}

func (p *parser) hasProg(typ uint32) bool {
	_, ok := p.findProg(typ)
	return ok
}

// isGo reports whether the image looks like a Go binary, for which stack
// canaries and FORTIFY are not applicable.
func (p *parser) isGo() bool {
	return p.goBuildID != "" || p.hasSection(".go.buildinfo") || p.hasSection(".gopclntab")
}

// hardening is the built-in checksec: PIE, NX, RELRO, stack canary, FORTIFY.
// Detail texts of RELRO start with "full RELRO" or "partial RELRO" so callers
// can tell the two enabled variants apart.
func (p *parser) hardening() []report.Hardening {
	return []report.Hardening{p.checkPIE(), p.checkNX(), p.checkRELRO(), p.checkCanary(), p.checkFortify()}
}

func (p *parser) isImage() bool { return p.h.typ == etExec || p.h.typ == etDyn }

func (p *parser) checkPIE() report.Hardening {
	h := report.Hardening{ID: report.HardenPIE, Label: "PIE (position independent executable)"}
	switch {
	case p.h.typ == etExec:
		h.Status, h.Detail = report.StatusDisabled, "ET_EXEC: the image is linked at a fixed address, so ASLR cannot relocate it"
	case p.h.typ == etDyn && (p.hasProg(ptInterp) || p.dyn.flags1&df1PIE != 0):
		h.Status, h.Detail = report.StatusEnabled, "ET_DYN executable: the image can be loaded at a random base address"
	case p.h.typ == etDyn:
		h.Status, h.Detail = report.StatusNA, "ET_DYN without PT_INTERP or DF_1_PIE: treated as a shared library (a static-pie linked without DF_1_PIE looks the same)"
	default:
		h.Status, h.Detail = report.StatusNA, fmt.Sprintf("object type %s has no load address to randomise", typeName(p.h.typ))
	}
	return h
}

func (p *parser) checkNX() report.Hardening {
	h := report.Hardening{ID: report.HardenNX, Label: "NX stack (PT_GNU_STACK)"}
	switch {
	case !p.isImage():
		h.Status, h.Detail = report.StatusNA, fmt.Sprintf("object type %s carries no PT_GNU_STACK header", typeName(p.h.typ))
	case len(p.progs) == 0:
		h.Status, h.Detail = report.StatusUnknown, "program headers are missing or unreadable"
	default:
		if st, ok := p.findProg(ptGNUStack); ok {
			if st.flags&pfX != 0 {
				h.Status, h.Detail = report.StatusDisabled, "PT_GNU_STACK requests an executable stack (flags "+strings.Join(permFlags(st.flags), "")+")"
			} else {
				h.Status, h.Detail = report.StatusEnabled, "PT_GNU_STACK without the X flag: the stack is not executable"
			}
		} else if p.linking() == "dynamic" {
			h.Status, h.Detail = report.StatusDisabled, "no PT_GNU_STACK header: the dynamic loader falls back to an executable stack on most targets"
		} else {
			h.Status, h.Detail = report.StatusUnknown, "no PT_GNU_STACK header; the default stack permissions of a statically linked image depend on the target"
		}
	}
	return h
}

func (p *parser) checkRELRO() report.Hardening {
	h := report.Hardening{ID: report.HardenRELRO, Label: "RELRO (relocation read-only)"}
	switch {
	case !p.isImage():
		h.Status, h.Detail = report.StatusNA, fmt.Sprintf("object type %s is not relocated at load time", typeName(p.h.typ))
	case len(p.progs) == 0:
		h.Status, h.Detail = report.StatusUnknown, "program headers are missing or unreadable"
	case !p.hasProg(ptGNURelro):
		h.Status, h.Detail = report.StatusDisabled, "no PT_GNU_RELRO header: relocation tables and the GOT stay writable"
	case !p.dyn.present:
		h.Status, h.Detail = report.StatusEnabled, "partial RELRO: PT_GNU_RELRO present (static image, no dynamic relocations to bind)"
	case p.dyn.immediateBinding():
		h.Status, h.Detail = report.StatusEnabled, "full RELRO: PT_GNU_RELRO with immediate binding (BIND_NOW), the GOT is read-only after start-up"
	default:
		h.Status, h.Detail = report.StatusEnabled, "partial RELRO: PT_GNU_RELRO without BIND_NOW, lazy binding keeps the PLT part of the GOT writable"
	}
	return h
}

func (p *parser) checkCanary() report.Hardening {
	h := report.Hardening{ID: report.HardenCanary, Label: "Stack canary (-fstack-protector)"}
	switch {
	case p.syms.canary:
		h.Status, h.Detail = report.StatusEnabled, "references __stack_chk_fail or __stack_chk_guard"
	case p.isGo():
		h.Status, h.Detail = report.StatusNA, "Go binary: the Go compiler does not emit stack canaries"
	case p.syms.readable():
		h.Status, h.Detail = report.StatusDisabled, fmt.Sprintf("no __stack_chk_fail or __stack_chk_guard among %d symbols", p.symbolsSeen())
	default:
		h.Status, h.Detail = report.StatusUnknown, "no readable symbol table (stripped, static or truncated): stack canary use cannot be determined"
	}
	return h
}

func (p *parser) checkFortify() report.Hardening {
	h := report.Hardening{ID: report.HardenFortify, Label: "FORTIFY_SOURCE"}
	switch {
	case len(p.syms.fortify) > 0:
		names := make([]string, 0, len(p.syms.fortify))
		for n := range p.syms.fortify {
			names = append(names, n)
		}
		slices.Sort(names)
		h.Status = report.StatusEnabled
		h.Detail = fmt.Sprintf("references %d fortified function(s), e.g. %s", len(names), strings.Join(names[:min(3, len(names))], ", "))
	case p.isGo():
		h.Status, h.Detail = report.StatusNA, "Go binary: FORTIFY_SOURCE applies to C code only"
	case p.syms.readable():
		h.Status, h.Detail = report.StatusDisabled, "no __*_chk functions referenced; this can simply mean there was nothing to fortify"
	default:
		h.Status, h.Detail = report.StatusUnknown, "no readable symbol table: FORTIFY_SOURCE use cannot be determined"
	}
	return h
}

// symbolsSeen is the number of symbols behind a "not found" verdict.
func (p *parser) symbolsSeen() int {
	n := 0
	if p.syms.dynDecoded {
		n += p.syms.dynCount
	}
	if p.syms.symDecoded {
		n += p.syms.symCount
	}
	return n
}

// codeSectionPrefixes are the names under which executable code is expected.
var codeSectionPrefixes = []string{".text", ".init", ".fini", ".plt", ".iplt", ".stub", ".MIPS.stubs", ".ltext", ".exit"}

func isCodeSectionName(name string) bool {
	for _, p := range codeSectionPrefixes {
		if name == p || strings.HasPrefix(name, p+".") {
			return true
		}
	}
	return false
}

// sectionFlags renders SHF_* bits as R/W/X. Sections that are not mapped into
// memory carry no flags.
func sectionFlags(flags uint64) []string {
	out := make([]string, 0, 3)
	if flags&shfAlloc == 0 {
		return out
	}
	out = append(out, report.FlagR)
	if flags&shfWrite != 0 {
		out = append(out, report.FlagW)
	}
	if flags&shfExec != 0 {
		out = append(out, report.FlagX)
	}
	return out
}

// sectionReasons lists structural oddities of a section. Entropy is judged by
// the rules engine, not here.
func (p *parser) sectionReasons(s sect) []string {
	var reasons []string
	if s.flags&shfAlloc != 0 && s.flags&shfWrite != 0 && s.flags&shfExec != 0 {
		reasons = append(reasons, "writable and executable")
	}
	if s.flags&shfAlloc != 0 && s.flags&shfExec != 0 && !isCodeSectionName(s.name) {
		reasons = append(reasons, "executable section with a name that is not a code section")
	}
	if p.namesKnown {
		switch {
		case s.name == "":
			reasons = append(reasons, "section has no name")
		case !strings.HasPrefix(s.name, ".") && !strings.HasPrefix(s.name, "__"):
			reasons = append(reasons, "section name does not start with a dot")
		}
	}
	return reasons
}
