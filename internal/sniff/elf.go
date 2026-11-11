package sniff

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/q6r/teardown/internal/report"
)

// ELF object file types (e_type).
const (
	elfRelocatable = 1
	elfExecutable  = 2
	elfSharedObj   = 3
	elfCore        = 4
)

var elfMagic = []byte("\x7fELF")

// detectELF recognises ELF files from the identification bytes and the header
// fields that follow them.
func detectELF(p *probe) (report.Type, bool) {
	h := p.head
	if !bytes.HasPrefix(h, elfMagic) {
		return report.Type{}, false
	}
	bits, class := 0, byte(0)
	var order binary.ByteOrder
	endian, endianTag := "", ""
	if len(h) > 5 {
		class = h[4]
		switch h[5] {
		case 1:
			order, endian, endianTag = binary.LittleEndian, "LSB", "little-endian"
		case 2:
			order, endian, endianTag = binary.BigEndian, "MSB", "big-endian"
		}
	}
	switch class {
	case 1:
		bits = 32
	case 2:
		bits = 64
	}
	if bits == 0 || order == nil || len(h) < 20 {
		return newType(report.TypeELF, report.FamilyExecutable, "ELF file (truncated or unrecognised header)",
			"application/x-executable", report.ConfidenceMedium, upxTag(h)), true
	}

	etype := order.Uint16(h[16:])
	machine, archTag := elfMachine(order.Uint16(h[18:]))
	kind, kindTag, mime := "file", "", "application/x-executable"
	switch etype {
	case elfRelocatable:
		kind, kindTag, mime = "relocatable", "relocatable", "application/x-object"
	case elfExecutable:
		kind, kindTag, mime = "executable", "executable", "application/x-executable"
	case elfSharedObj:
		kind, kindTag, mime = "shared object", "shared-object", "application/x-sharedlib"
	case elfCore:
		kind, kindTag, mime = "core file", "core", "application/x-coredump"
	}
	bitsTag := tag32Bit
	if bits == 64 {
		bitsTag = tag64Bit
	}
	tags := []string{kindTag, bitsTag, endianTag, archTag, upxTag(h)}
	if bytes.Contains(p.tailBytes(), pyInstallerCookie) {
		tags = append(tags, tagPyInstaller)
	}
	conf := report.ConfidenceMedium
	if kindTag != "" && h[6] == 1 {
		conf = report.ConfidenceHigh
	}
	label := fmt.Sprintf("ELF %d-bit %s %s (%s)", bits, endian, kind, machine)
	return newType(report.TypeELF, report.FamilyExecutable, label, mime, conf, tags...), true
}

// upxTag returns "upx" when the UPX marker appears in the first 4 KiB.
func upxTag(h []byte) string {
	if bytes.Contains(h[:min(len(h), 4096)], []byte("UPX!")) {
		return tagUPX
	}
	return ""
}

// elfMachine names an e_machine value and gives its tag.
func elfMachine(m uint16) (name, tag string) {
	switch m {
	case 2:
		return "SPARC", "sparc"
	case 3:
		return "x86", "x86"
	case 4:
		return "m68k", "m68k"
	case 8:
		return "MIPS", "mips"
	case 15:
		return "PA-RISC", "pa-risc"
	case 20:
		return "PowerPC", "powerpc"
	case 21:
		return "PowerPC64", "powerpc64"
	case 22:
		return "S/390", "s390"
	case 40:
		return "ARM", "arm"
	case 41:
		return "Alpha", "alpha"
	case 42:
		return "SuperH", "superh"
	case 43:
		return "SPARC V9", "sparc"
	case 50:
		return "IA-64", "ia-64"
	case 62:
		return "x86-64", "x86-64"
	case 83:
		return "AVR", "avr"
	case 92:
		return "OpenRISC", "openrisc"
	case 94:
		return "Xtensa", "xtensa"
	case 105:
		return "MSP430", "msp430"
	case 164:
		return "Hexagon", "hexagon"
	case 183:
		return "AArch64", "aarch64"
	case 189:
		return "MicroBlaze", "microblaze"
	case 190:
		return "CUDA", "cuda"
	case 224:
		return "AMD GPU", "amdgpu"
	case 243:
		return "RISC-V", "riscv"
	case 247:
		return "BPF", "bpf"
	case 258:
		return "LoongArch", "loongarch"
	}
	return fmt.Sprintf("machine %d", m), ""
}
