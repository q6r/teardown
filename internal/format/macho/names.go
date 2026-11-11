package macho

import "fmt"

// Mach-O CPU types.
const (
	cpuX86     = 7
	cpuAMD64   = 0x01000007
	cpuARM     = 12
	cpuARM64   = 0x0100000c
	cpuARM6432 = 0x0200000c
	cpuPPC     = 18
	cpuPPC64   = 0x01000012
)

// File types.
const (
	typeObject  = 1
	typeExecute = 2
	typeDylib   = 6
	typeBundle  = 8
)

// Header flags.
const (
	flagTwoLevel      = 0x80
	flagAllowStackExe = 0x20000
	flagPIE           = 0x200000
	flagNoHeapExe     = 0x1000000
)

var cpuNames = map[uint32]string{
	cpuX86: "x86", cpuAMD64: "x86_64", cpuARM: "arm", cpuARM64: "arm64", cpuARM6432: "arm64_32", cpuPPC: "ppc", cpuPPC64: "ppc64",
}

// cpuName names a CPU type; arm64 with sub-type 2 is the pointer-authenticated arm64e.
func cpuName(cpu, sub uint32) string {
	name, ok := cpuNames[cpu]
	if !ok {
		return fmt.Sprintf("unknown (0x%x)", cpu)
	}
	if cpu == cpuARM64 && sub&0xff == 2 {
		return "arm64e"
	}
	return name
}

var typeNames = map[uint32]string{
	1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib",
	7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym", 11: "kext", 12: "fileset",
}

func typeName(t uint32) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown (%d)", t)
}

// headerFlags lists the mach_header flag bits in ascending order.
var headerFlags = []struct {
	bit  uint32
	name string
}{
	{0x1, "NOUNDEFS"}, {0x2, "INCRLINK"}, {0x4, "DYLDLINK"}, {0x8, "BINDATLOAD"}, {0x10, "PREBOUND"},
	{0x20, "SPLIT_SEGS"}, {0x40, "LAZY_INIT"}, {0x80, "TWOLEVEL"}, {0x100, "FORCE_FLAT"}, {0x200, "NOMULTIDEFS"},
	{0x400, "NOFIXPREBINDING"}, {0x800, "PREBINDABLE"}, {0x1000, "ALLMODSBOUND"}, {0x2000, "SUBSECTIONS_VIA_SYMBOLS"},
	{0x4000, "CANONICAL"}, {0x8000, "WEAK_DEFINES"}, {0x10000, "BINDS_TO_WEAK"}, {0x20000, "ALLOW_STACK_EXECUTION"},
	{0x40000, "ROOT_SAFE"}, {0x80000, "SETUID_SAFE"}, {0x100000, "NO_REEXPORTED_DYLIBS"}, {0x200000, "PIE"},
	{0x400000, "DEAD_STRIPPABLE_DYLIB"}, {0x800000, "HAS_TLV_DESCRIPTORS"}, {0x1000000, "NO_HEAP_EXECUTION"},
	{0x2000000, "APP_EXTENSION_SAFE"}, {0x4000000, "NLIST_OUTOFSYNC_WITH_DYLDINFO"}, {0x8000000, "SIM_SUPPORT"},
	{0x80000000, "DYLIB_IN_CACHE"},
}

func flagNames(flags uint32) []string {
	out := []string{}
	for _, f := range headerFlags {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

var platformNames = map[uint32]string{
	1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst", 7: "ios-simulator",
	8: "tvos-simulator", 9: "watchos-simulator", 10: "driverkit", 11: "visionos", 12: "visionos-simulator",
}

func platformName(p uint32) string {
	if n, ok := platformNames[p]; ok {
		return n
	}
	return fmt.Sprintf("unknown (%d)", p)
}

// versionString renders a packed xxxx.yy.zz version, omitting a zero patch level.
func versionString(v uint32) string {
	if v&0xff == 0 {
		return fmt.Sprintf("%d.%d", v>>16, v>>8&0xff)
	}
	return fmt.Sprintf("%d.%d.%d", v>>16, v>>8&0xff, v&0xff)
}

// protFlags renders VM protection bits as the R, W, X flag list.
func protFlags(p uint32) []string {
	out := make([]string, 0, 3)
	if p&1 != 0 {
		out = append(out, "R")
	}
	if p&2 != 0 {
		out = append(out, "W")
	}
	if p&4 != 0 {
		out = append(out, "X")
	}
	return out
}
