package sniff

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/q6r/teardown/internal/report"
)

var wasmMagic = []byte("\x00asm")

// detectWasm recognises WebAssembly binary modules and components.
func detectWasm(p *probe) (report.Type, bool) {
	h := p.head
	if !bytes.HasPrefix(h, wasmMagic) {
		return report.Type{}, false
	}
	const mime = "application/wasm"
	if len(h) < 8 {
		return newType(report.TypeWasm, report.FamilyExecutable, "WebAssembly binary (truncated header)", mime,
			report.ConfidenceMedium), true
	}
	switch version := binary.LittleEndian.Uint32(h[4:]); version {
	case 1:
		return newType(report.TypeWasm, report.FamilyExecutable, "WebAssembly module (version 1)", mime,
			report.ConfidenceHigh), true
	case 0x0001000d:
		// Component model preamble: version 0x0d, layer 1.
		return newType(report.TypeWasm, report.FamilyExecutable, "WebAssembly component", mime,
			report.ConfidenceHigh, "component"), true
	default:
		return newType(report.TypeWasm, report.FamilyExecutable, fmt.Sprintf("WebAssembly binary (version %#x)", version), mime,
			report.ConfidenceMedium), true
	}
}
