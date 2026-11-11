package sniff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

const (
	mimePE  = "application/vnd.microsoft.portable-executable"
	mimeDOS = "application/x-dosexec"

	dosHeaderLen  = 0x40
	peMaxSections = 96 // the format limit; more is corruption
	peSectionLen  = 40
	peOptReadMax  = 240 // a PE32+ optional header with 16 data directories

	peFlagDLL       = 0x2000
	peMagic32       = 0x10b
	peMagic64       = 0x20b
	subsystemNative = 1
)

// pyInstallerCookie is the magic of the PyInstaller CArchive trailer.
var pyInstallerCookie = []byte("MEI\x0c\x0b\x0a\x0b\x0e")

// newHeader is what could be read of the header that e_lfanew of an "MZ" file
// points to.
type newHeader struct {
	sig           string // "PE", "NE", "LE", "LX", or "" when there is none
	haveCOFF      bool
	machine       uint16
	chars         uint16
	optMagic      uint16 // 0 when the optional header is missing or truncated
	haveSubsystem bool
	subsystem     uint16
	clr           bool // data directory 14 (CLR runtime header) is populated
	sections      []string
}

// detectMZ recognises PE images and, failing that, other MZ-based executables.
func detectMZ(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 2 || h[0] != 'M' || h[1] != 'Z' {
		return report.Type{}, false
	}
	nh := probeNewHeader(p)
	switch nh.sig {
	case "PE":
		return peType(p, nh), true
	case "NE":
		return newType(report.TypeDOS, report.FamilyExecutable, "NE executable (16-bit Windows or OS/2)",
			mimeDOS, report.ConfidenceMedium, "mz", "ne"), true
	case "LE", "LX":
		return newType(report.TypeDOS, report.FamilyExecutable, "LE/LX executable (VxD or OS/2)",
			mimeDOS, report.ConfidenceMedium, "mz", strings.ToLower(nh.sig)), true
	}
	if !plausibleDOSHeader(h) {
		return report.Type{}, false
	}
	return newType(report.TypeDOS, report.FamilyExecutable, "DOS MZ executable (no valid PE header)",
		mimeDOS, report.ConfidenceMedium, "mz"), true
}

// plausibleDOSHeader keeps text that merely starts with "MZ" from being called a
// DOS executable: the bytes-in-last-page and page-count fields must make sense.
func plausibleDOSHeader(h []byte) bool {
	if len(h) < 0x1c {
		return false
	}
	return binary.LittleEndian.Uint16(h[2:]) <= 512 && binary.LittleEndian.Uint16(h[4:]) >= 1
}

// probeNewHeader reads the header at e_lfanew. It never fails; fields that
// could not be read stay zero.
func probeNewHeader(p *probe) newHeader {
	var nh newHeader
	h := p.head
	if len(h) < dosHeaderLen {
		return nh
	}
	lfanew := int64(binary.LittleEndian.Uint32(h[0x3c:]))
	if lfanew < 4 || lfanew > p.size-4 {
		return nh
	}
	win, err := binio.ReadUpTo(p.r, p.size, lfanew, 4+20+peOptReadMax)
	if err != nil || len(win) < 4 {
		return nh
	}
	switch {
	case bytes.HasPrefix(win, []byte("PE\x00\x00")):
		nh.sig = "PE"
	case bytes.HasPrefix(win, []byte("NE")):
		nh.sig = "NE"
		return nh
	case bytes.HasPrefix(win, []byte("LE")):
		nh.sig = "LE"
		return nh
	case bytes.HasPrefix(win, []byte("LX")):
		nh.sig = "LX"
		return nh
	default:
		return nh
	}

	coff := win[4:]
	if len(coff) < 20 {
		return nh
	}
	nh.haveCOFF = true
	nh.machine = binary.LittleEndian.Uint16(coff[0:])
	sections := int(binary.LittleEndian.Uint16(coff[2:]))
	optSize := int(binary.LittleEndian.Uint16(coff[16:]))
	nh.chars = binary.LittleEndian.Uint16(coff[18:])

	opt := coff[20:]
	if len(opt) > optSize {
		opt = opt[:optSize]
	}
	if len(opt) >= 2 {
		nh.optMagic = binary.LittleEndian.Uint16(opt)
	}
	if len(opt) >= 70 {
		nh.haveSubsystem = true
		nh.subsystem = binary.LittleEndian.Uint16(opt[68:])
	}
	dirs := 0 // offset of the data directory array inside the optional header
	switch nh.optMagic {
	case peMagic32:
		dirs = 96
	case peMagic64:
		dirs = 112
	}
	const clrIndex = 14
	if dirs > 0 && len(opt) >= dirs+(clrIndex+1)*8 && binary.LittleEndian.Uint32(opt[dirs-4:]) > clrIndex {
		entry := dirs + clrIndex*8
		nh.clr = binary.LittleEndian.Uint32(opt[entry:]) != 0 && binary.LittleEndian.Uint32(opt[entry+4:]) != 0
	}

	if n := min(sections, peMaxSections); n > 0 {
		table, err := binio.ReadUpTo(p.r, p.size, lfanew+24+int64(optSize), int64(n)*peSectionLen)
		if err == nil {
			for i := 0; i+peSectionLen <= len(table); i += peSectionLen {
				nh.sections = append(nh.sections, binio.FixedString(table[i:i+8]))
			}
		}
	}
	return nh
}

// peType builds the report.Type of a PE image.
func peType(p *probe, nh newHeader) report.Type {
	format, bits := "PE", ""
	switch nh.optMagic {
	case peMagic32:
		format, bits = "PE32", tag32Bit
	case peMagic64:
		format, bits = "PE32+", tag64Bit
	}
	arch, archTag := "", ""
	if nh.haveCOFF {
		arch, archTag = peMachine(nh.machine)
	}

	dll := nh.haveCOFF && nh.chars&peFlagDLL != 0
	native := nh.haveSubsystem && nh.subsystem == subsystemNative
	efiKind, efi := peEFIKind(nh)

	tags := []string{bits, archTag}
	var what, where string // "executable for Windows", etc.
	switch {
	case efi:
		tags = append(tags, "efi", map[bool]string{true: "driver", false: "exe"}[strings.Contains(efiKind, "driver")])
		what, where = efiKind, ""
	case native && !dll:
		tags = append(tags, "driver", "native")
		what, where = "native driver", " for Windows"
	case dll:
		tags = append(tags, "dll")
		if native {
			tags = append(tags, "native")
		}
		what, where = "DLL", " for Windows"
	default:
		tags = append(tags, "exe")
		what, where = "executable", " for Windows"
	}

	parts := []string{arch}
	if !dll && !efi && !native && nh.haveSubsystem {
		parts = append(parts, peSubsystemLabel(nh.subsystem))
	}
	if nh.clr {
		tags = append(tags, "dotnet")
		parts = append(parts, ".NET")
	}
	if slices.ContainsFunc(nh.sections, isUPXSection) {
		tags = append(tags, tagUPX)
	}
	if bytes.Contains(p.tailBytes(), pyInstallerCookie) {
		tags = append(tags, tagPyInstaller)
	}

	label := format + " " + what + where
	if detail := joinNonEmpty(parts, ", "); detail != "" {
		label += " (" + detail + ")"
	}
	conf := report.ConfidenceMedium
	if nh.haveCOFF && bits != "" {
		conf = report.ConfidenceHigh
	}
	return newType(report.TypePE, report.FamilyExecutable, label, mimePE, conf, tags...)
}

func isUPXSection(name string) bool {
	return name == "UPX0" || name == "UPX1" || name == "UPX2"
}

func joinNonEmpty(parts []string, sep string) string {
	kept := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, sep)
}

// peMachine names an IMAGE_FILE_MACHINE value and gives its tag.
func peMachine(m uint16) (name, tag string) {
	switch m {
	case 0x014c:
		return "x86", "x86"
	case 0x8664:
		return "x86-64", "x86-64"
	case 0x01c0:
		return "ARM", "arm"
	case 0x01c4:
		return "ARM Thumb-2", "arm"
	case 0xaa64:
		return "ARM64", "arm64"
	case 0xa641:
		return "ARM64EC", "arm64ec"
	case 0x0200:
		return "IA-64", "ia-64"
	case 0x5032, 0x5064, 0x5128:
		return fmt.Sprintf("RISC-V %d", map[uint16]int{0x5032: 32, 0x5064: 64, 0x5128: 128}[m]), "riscv"
	case 0x6232, 0x6264:
		return "LoongArch", "loongarch"
	case 0x0ebc:
		return "EFI byte code", "ebc"
	case 0x0166, 0x0266, 0x0366, 0x0466:
		return "MIPS", "mips"
	case 0x01f0, 0x01f1:
		return "PowerPC", "powerpc"
	case 0x01a2, 0x01a6, 0x01a8:
		return "SuperH", "superh"
	}
	return fmt.Sprintf("machine 0x%04x", m), ""
}

// peSubsystemLabel describes an IMAGE_SUBSYSTEM value for executables.
func peSubsystemLabel(s uint16) string {
	switch s {
	case 2:
		return "GUI"
	case 3:
		return "console"
	case 5:
		return "OS/2 console"
	case 7:
		return "POSIX console"
	case 9:
		return "Windows CE GUI"
	case 14:
		return "Xbox"
	case 16:
		return "boot application"
	}
	return ""
}

// peEFIKind names the EFI subsystems (10..13).
func peEFIKind(nh newHeader) (string, bool) {
	if !nh.haveSubsystem {
		return "", false
	}
	switch nh.subsystem {
	case 10:
		return "EFI application", true
	case 11:
		return "EFI boot service driver", true
	case 12:
		return "EFI runtime driver", true
	case 13:
		return "EFI ROM image", true
	}
	return "", false
}
