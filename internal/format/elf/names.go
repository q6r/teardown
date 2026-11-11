package elf

import (
	delf "debug/elf"
	"fmt"
	"strings"
)

var machineNames = map[uint16]string{
	2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 14: "PA-RISC", 15: "PA-RISC", 20: "PowerPC", 21: "PowerPC64", 22: "S390",
	40: "ARM", 42: "SuperH", 43: "SPARC V9", 50: "IA-64", 62: "x86-64", 94: "Xtensa", 164: "Hexagon",
	183: "AArch64", 224: "AMDGPU", 243: "RISC-V", 247: "eBPF", 258: "LoongArch",
}

func machineName(m uint16) string {
	if n, ok := machineNames[m]; ok {
		return n
	}
	return fmt.Sprintf("unknown (%d)", m)
}

func typeName(t uint16) string {
	switch delf.Type(t) {
	case delf.ET_NONE:
		return "NONE"
	case delf.ET_REL:
		return "REL"
	case delf.ET_EXEC:
		return "EXEC"
	case delf.ET_DYN:
		return "DYN"
	case delf.ET_CORE:
		return "CORE"
	}
	return fmt.Sprintf("0x%x", t)
}

func osABIName(a uint8) string {
	if delf.OSABI(a) == delf.ELFOSABI_NONE {
		return "SYSV"
	}
	s := delf.OSABI(a).String()
	if strings.HasPrefix(s, "ELFOSABI_") {
		return strings.TrimPrefix(s, "ELFOSABI_")
	}
	return fmt.Sprintf("0x%x", a)
}

func segmentTypeName(t uint32) string {
	if s := delf.ProgType(t).String(); strings.HasPrefix(s, "PT_") {
		return s
	}
	return fmt.Sprintf("PT_0x%x", t)
}

// permFlags renders segment permission bits as the R, W, X flag list.
func permFlags(f uint32) []string {
	out := make([]string, 0, 3)
	if f&pfR != 0 {
		out = append(out, "R")
	}
	if f&pfW != 0 {
		out = append(out, "W")
	}
	if f&pfX != 0 {
		out = append(out, "X")
	}
	return out
}
