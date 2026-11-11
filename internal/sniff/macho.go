package sniff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

const mimeMachO = "application/x-mach-binary"

// Mach-O and fat magic numbers, read as big-endian from the first four bytes.
const (
	machoMagic32BE = 0xfeedface
	machoMagic64BE = 0xfeedfacf
	machoMagic32LE = 0xcefaedfe
	machoMagic64LE = 0xcffaedfe

	fatMagic       = 0xcafebabe // also the magic of Java class files
	fatMagic64     = 0xcafebabf
	fatMagicSwap   = 0xbebafeca
	fatMagic64Swap = 0xbfbafeca

	// maxFatArchs bounds the arch count of a plausible universal binary; every
	// valid Java class file has a major version of at least 45, so the two
	// formats cannot be confused below this limit.
	maxFatArchs = 30

	javaMinMajor = 45
)

func isMachOMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(b) {
	case machoMagic32BE, machoMagic64BE, machoMagic32LE, machoMagic64LE:
		return true
	}
	return false
}

// detectMachO recognises thin Mach-O files.
func detectMachO(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 4 {
		return report.Type{}, false
	}
	var order binary.ByteOrder
	bits := 0
	switch binary.BigEndian.Uint32(h) {
	case machoMagic32BE:
		order, bits = binary.BigEndian, 32
	case machoMagic64BE:
		order, bits = binary.BigEndian, 64
	case machoMagic32LE:
		order, bits = binary.LittleEndian, 32
	case machoMagic64LE:
		order, bits = binary.LittleEndian, 64
	default:
		return report.Type{}, false
	}
	bitsTag, headerLen := tag32Bit, 28
	if bits == 64 {
		bitsTag, headerLen = tag64Bit, 32
	}
	if len(h) < headerLen {
		return newType(report.TypeMachO, report.FamilyExecutable,
			fmt.Sprintf("Mach-O %d-bit file (truncated header)", bits), mimeMachO, report.ConfidenceMedium,
			bitsTag, upxTag(h)), true
	}
	arch, archTag := machoCPU(order.Uint32(h[4:]), order.Uint32(h[8:]))
	kind, kindTag := machoFileType(order.Uint32(h[12:]))
	ncmds, sizeofcmds := order.Uint32(h[16:]), order.Uint32(h[20:])
	// Every load command is at least 8 bytes and the commands must fit in the file.
	ok := kindTag != "" && int64(sizeofcmds) <= p.size && uint64(ncmds) <= uint64(sizeofcmds)/8

	tags := []string{kindTag, bitsTag, archTag, upxTag(h)}
	if bytes.Contains(p.tailBytes(), pyInstallerCookie) {
		tags = append(tags, tagPyInstaller)
	}
	label := fmt.Sprintf("Mach-O %d-bit %s (%s)", bits, kind, arch)
	return newType(report.TypeMachO, report.FamilyExecutable, label, mimeMachO, confidenceIf(ok), tags...), true
}

// detectCafe resolves the magic number shared by universal ("fat") Mach-O
// binaries and Java class files.
func detectCafe(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 8 {
		return report.Type{}, false
	}
	switch binary.BigEndian.Uint32(h) {
	case fatMagic:
		if n := binary.BigEndian.Uint32(h[4:]); n >= 1 && n <= maxFatArchs {
			return fatType(p, binary.BigEndian, false, int(n)), true
		}
		return classType(h)
	case fatMagic64:
		if n := binary.BigEndian.Uint32(h[4:]); n >= 1 && n <= maxFatArchs {
			return fatType(p, binary.BigEndian, true, int(n)), true
		}
	case fatMagicSwap:
		if n := binary.LittleEndian.Uint32(h[4:]); n >= 1 && n <= maxFatArchs {
			return fatType(p, binary.LittleEndian, false, int(n)), true
		}
	case fatMagic64Swap:
		if n := binary.LittleEndian.Uint32(h[4:]); n >= 1 && n <= maxFatArchs {
			return fatType(p, binary.LittleEndian, true, int(n)), true
		}
	}
	return report.Type{}, false
}

// fatType describes a universal binary with n architecture entries.
func fatType(p *probe, order binary.ByteOrder, wide bool, n int) report.Type {
	entryLen := 20
	if wide {
		entryLen = 32
	}
	h := p.head
	tableEnd := uint64(8 + n*entryLen)
	archs := make([]string, 0, n)
	tags := []string{"universal"}
	trustworthy := true
	for i := range n {
		off := 8 + i*entryLen
		if off+entryLen > len(h) {
			trustworthy = false
			break
		}
		name, tag := machoCPU(order.Uint32(h[off:]), order.Uint32(h[off+4:]))
		archs = append(archs, name)
		tags = append(tags, tag)

		var sliceOff, sliceSize uint64
		if wide {
			sliceOff, sliceSize = order.Uint64(h[off+8:]), order.Uint64(h[off+16:])
		} else {
			sliceOff, sliceSize = uint64(order.Uint32(h[off+8:])), uint64(order.Uint32(h[off+12:]))
		}
		// Every slice must sit after the table, inside the file, and start with a Mach-O magic.
		if sliceOff < tableEnd || sliceOff > uint64(p.size) || sliceSize > uint64(p.size)-sliceOff {
			trustworthy = false
			continue
		}
		if magic, err := binio.ReadAt(p.r, p.size, int64(sliceOff), 4); err != nil || !isMachOMagic(magic) {
			trustworthy = false
		}
	}
	label := "Mach-O universal binary"
	if len(archs) > 0 {
		label += " (" + joinNonEmpty(archs, ", ") + ")"
	}
	return newType(report.TypeMachOFat, report.FamilyExecutable, label, mimeMachO, confidenceIf(trustworthy), tags...)
}

// classType describes a Java class file whose 0xCAFEBABE magic was not a fat header.
func classType(h []byte) (report.Type, bool) {
	minor, major := binary.BigEndian.Uint16(h[4:]), binary.BigEndian.Uint16(h[6:])
	if major < javaMinMajor {
		return report.Type{}, false
	}
	release, known := javaRelease(major)
	label := fmt.Sprintf("Java class file (major %d)", major)
	tags := []string{}
	if known {
		label = fmt.Sprintf("Java class file (major %d, Java %s)", major, release)
		tags = append(tags, "java-"+release)
	}
	if minor == 0xffff {
		label += ", preview features"
		tags = append(tags, "preview")
	}
	// The constant pool count that follows the version is at least 1.
	ok := known && len(h) >= 10 && binary.BigEndian.Uint16(h[8:]) >= 1
	return newType(report.TypeClass, report.FamilyBytecode, label, "application/java-vm", confidenceIf(ok), tags...), true
}

// javaRelease maps a class file major version to the Java release name.
func javaRelease(major uint16) (string, bool) {
	switch {
	case major >= 45 && major <= 48:
		return [...]string{"1.1", "1.2", "1.3", "1.4"}[major-45], true
	case major >= 49 && major <= 100:
		return strconv.Itoa(int(major) - 44), true
	}
	return "", false
}

// machoCPU names a Mach-O cputype/cpusubtype pair and gives its tag.
func machoCPU(cpu, sub uint32) (name, tag string) {
	const (
		abi64    = 0x01000000
		abi6432  = 0x02000000
		abiMask  = 0xff000000
		arm64e   = 2
		subMask  = 0x00ffffff
		cpuX86   = 7
		cpuARM   = 12
		cpuPPC   = 18
		cpuARM64 = cpuARM | abi64
	)
	switch cpu &^ abiMask {
	case cpuX86:
		if cpu&abi64 != 0 {
			return "x86_64", "x86_64"
		}
		return "x86", "x86"
	case cpuARM:
		switch {
		case cpu&abi6432 != 0:
			return "arm64_32", "arm64_32"
		case cpu&abi64 != 0 && sub&subMask == arm64e:
			return "arm64e", "arm64e"
		case cpu&abi64 != 0:
			return "arm64", "arm64"
		}
		return "arm", "arm"
	case cpuPPC:
		if cpu&abi64 != 0 {
			return "ppc64", "ppc64"
		}
		return "ppc", "ppc"
	}
	return fmt.Sprintf("cpu 0x%x", cpu), ""
}

// machoFileType names a Mach-O filetype and gives its tag ("" when unknown).
func machoFileType(t uint32) (name, tag string) {
	switch t {
	case 1:
		return "object file", "object"
	case 2:
		return "executable", "executable"
	case 3:
		return "fixed VM library", "fvmlib"
	case 4:
		return "core file", "core"
	case 5:
		return "preloaded executable", "preload"
	case 6:
		return "dynamic library", "dylib"
	case 7:
		return "dynamic linker", "dylinker"
	case 8:
		return "bundle", "bundle"
	case 9:
		return "dylib stub", "stub"
	case 10:
		return "debug symbols", "dsym"
	case 11:
		return "kernel extension", "kext"
	case 12:
		return "fileset", "fileset"
	}
	return "file", ""
}
