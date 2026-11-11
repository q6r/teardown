package pe

import "fmt"

type flagName struct {
	mask uint32
	name string
}

var coffCharacteristics = []flagName{
	{0x0001, "RELOCS_STRIPPED"}, {0x0002, "EXECUTABLE_IMAGE"}, {0x0004, "LINE_NUMS_STRIPPED"},
	{0x0008, "LOCAL_SYMS_STRIPPED"}, {0x0010, "AGGRESSIVE_WS_TRIM"}, {0x0020, "LARGE_ADDRESS_AWARE"},
	{0x0080, "BYTES_REVERSED_LO"}, {0x0100, "32BIT_MACHINE"}, {0x0200, "DEBUG_STRIPPED"},
	{0x0400, "REMOVABLE_RUN_FROM_SWAP"}, {0x0800, "NET_RUN_FROM_SWAP"}, {0x1000, "SYSTEM"},
	{0x2000, "DLL"}, {0x4000, "UP_SYSTEM_ONLY"}, {0x8000, "BYTES_REVERSED_HI"},
}

var dllCharacteristicNames = []flagName{
	{0x0020, "HIGH_ENTROPY_VA"}, {0x0040, "DYNAMIC_BASE"}, {0x0080, "FORCE_INTEGRITY"},
	{0x0100, "NX_COMPAT"}, {0x0200, "NO_ISOLATION"}, {0x0400, "NO_SEH"}, {0x0800, "NO_BIND"},
	{0x1000, "APPCONTAINER"}, {0x2000, "WDM_DRIVER"}, {0x4000, "GUARD_CF"}, {0x8000, "TERMINAL_SERVER_AWARE"},
}

var clrFlagNames = []flagName{
	{0x1, "ILONLY"}, {0x2, "32BITREQUIRED"}, {0x4, "IL_LIBRARY"}, {0x8, "STRONGNAMESIGNED"},
	{0x10, "NATIVE_ENTRYPOINT"}, {0x10000, "TRACKDEBUGDATA"}, {0x20000, "32BITPREFERRED"},
}

// flagNames lists the names of the bits set in v, in table order. The result is
// never nil so it encodes as an empty JSON array.
func flagNames(v uint32, table []flagName) []string {
	out := []string{}
	for _, f := range table {
		if v&f.mask != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// IMAGE_FILE_HEADER.Characteristics bits the parser acts on.
const (
	charRelocsStripped = 0x0001
	charSystem         = 0x1000
	charDLL            = 0x2000
)

// IMAGE_OPTIONAL_HEADER.DllCharacteristics bits the parser acts on.
const (
	dllHighEntropyVA  = 0x0020
	dllDynamicBase    = 0x0040
	dllForceIntegrity = 0x0080
	dllNXCompat       = 0x0100
	dllNoSEH          = 0x0400
	dllGuardCF        = 0x4000
)

const subsystemNative = 1

const (
	machineI386  = 0x14c
	machineAMD64 = 0x8664
)

// MachineName names a COFF machine type: "x86", "x86-64", "ARM64" and so on,
// or the four hexadecimal digits of one it does not know ("0x1234").
func MachineName(m uint16) string { return machineName(m) }

func machineName(m uint16) string {
	switch m {
	case machineI386:
		return "x86"
	case machineAMD64:
		return "x86-64"
	case 0x1c0:
		return "ARM"
	case 0x1c2:
		return "Thumb"
	case 0x1c4:
		return "ARMNT"
	case 0xaa64:
		return "ARM64"
	case 0xa641:
		return "ARM64EC"
	case 0xa64e:
		return "ARM64X"
	case 0x200:
		return "IA-64"
	case 0xebc:
		return "EBC"
	case 0x166:
		return "MIPS"
	case 0x266:
		return "MIPS16"
	case 0x366:
		return "MIPSFPU"
	case 0x1f0:
		return "PowerPC"
	case 0x1f1:
		return "PowerPC-FP"
	case 0x1a2:
		return "SH3"
	case 0x1a6:
		return "SH4"
	case 0x5032:
		return "RISC-V32"
	case 0x5064:
		return "RISC-V64"
	case 0x5128:
		return "RISC-V128"
	case 0x6232:
		return "LoongArch32"
	case 0x6264:
		return "LoongArch64"
	default:
		return fmt.Sprintf("0x%04x", m)
	}
}

// machineIs64 reports whether the architecture is a 64-bit one; it is only used
// when the optional header is too damaged to say.
func machineIs64(m uint16) bool {
	switch m {
	case machineAMD64, 0xaa64, 0xa641, 0xa64e, 0x200, 0x5064, 0x5128, 0x6264:
		return true
	}
	return false
}

func subsystemName(s uint16) string {
	switch s {
	case 0:
		return "unknown"
	case subsystemNative:
		return "native"
	case 2:
		return "windows-gui"
	case 3:
		return "windows-cui"
	case 5:
		return "os2-cui"
	case 7:
		return "posix-cui"
	case 8:
		return "native-windows"
	case 9:
		return "windows-ce-gui"
	case 10:
		return "efi-application"
	case 11:
		return "efi-boot-service-driver"
	case 12:
		return "efi-runtime-driver"
	case 13:
		return "efi-rom"
	case 14:
		return "xbox"
	case 16:
		return "windows-boot-application"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}
