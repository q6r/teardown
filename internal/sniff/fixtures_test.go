package sniff

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

// fixture is one sample file with the result Detect must produce for it. The
// same table drives the unit test, the robustness sweeps and the fuzz seeds.
type fixture struct {
	name   string
	data   []byte
	id     string
	family string
	conf   report.Confidence
	tags   []string // exact, sorted
	label  string   // substring of the label; empty skips the check
	mime   string   // exact; empty skips the check
}

// peSpec describes a synthetic PE image.
type peSpec struct {
	pe32      bool
	machine   uint16
	dll       bool
	subsystem uint16
	clr       bool
	sections  []string
	trailer   []byte
	cut       int // truncate the image to this many bytes when > 0
}

// buildPE assembles a minimal PE header (DOS header, PE signature, COFF header,
// optional header with 16 data directories, section table) padded to 1 KiB.
func buildPE(s peSpec) []byte {
	const lfanew = 0x80
	optSize, magic, dirs := 240, uint16(0x20b), 112
	machine, chars := s.machine, uint16(0x0022)
	if s.pe32 {
		optSize, magic, dirs, chars = 224, 0x10b, 96, 0x0102
		if machine == 0 {
			machine = 0x14c
		}
	} else if machine == 0 {
		machine = 0x8664
	}
	if s.dll {
		chars |= 0x2000
	}
	subsystem := s.subsystem
	if subsystem == 0 {
		subsystem = 3
	}

	b := make([]byte, lfanew+4+20+optSize+peSectionLen*len(s.sections))
	copy(b, "MZ")
	le.PutUint16(b[2:], 0x90)
	le.PutUint16(b[4:], 3)
	le.PutUint32(b[0x3c:], lfanew)
	copy(b[lfanew:], "PE\x00\x00")
	coff := b[lfanew+4:]
	le.PutUint16(coff[0:], machine)
	le.PutUint16(coff[2:], uint16(len(s.sections)))
	le.PutUint16(coff[16:], uint16(optSize))
	le.PutUint16(coff[18:], chars)
	opt := coff[20:]
	le.PutUint16(opt, magic)
	le.PutUint16(opt[68:], subsystem)
	le.PutUint32(opt[dirs-4:], 16)
	if s.clr {
		le.PutUint32(opt[dirs+14*8:], 0x2000)
		le.PutUint32(opt[dirs+14*8+4:], 0x48)
	}
	for i, name := range s.sections {
		copy(opt[optSize+i*peSectionLen:], name)
	}
	b = append(b, make([]byte, max(0, 0x400-len(b)))...)
	b = append(b, s.trailer...)
	if s.cut > 0 {
		b = b[:min(s.cut, len(b))]
	}
	return b
}

// buildDOSWithSignature returns an MZ file whose e_lfanew points at sig.
func buildDOSWithSignature(sig string) []byte {
	b := make([]byte, 0x100)
	copy(b, "MZ")
	le.PutUint16(b[2:], 0x90)
	le.PutUint16(b[4:], 3)
	le.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], sig)
	return b
}

func buildELF(class, data byte, etype, machine uint16) []byte {
	b := make([]byte, 64)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = class, data, 1
	var order binary.ByteOrder = le
	if data == 2 {
		order = be
	}
	order.PutUint16(b[16:], etype)
	order.PutUint16(b[18:], machine)
	return b
}

// buildMachO writes a thin Mach-O header; magic is given as read big-endian from
// the first four bytes, which also decides the byte order of the other fields.
func buildMachO(magic, cpu, sub, ftype, ncmds, sizeofcmds uint32) []byte {
	var order binary.ByteOrder = be
	if magic == machoMagic32LE || magic == machoMagic64LE {
		order = le
	}
	b := make([]byte, 32+int(sizeofcmds))
	be.PutUint32(b, magic)
	order.PutUint32(b[4:], cpu)
	order.PutUint32(b[8:], sub)
	order.PutUint32(b[12:], ftype)
	order.PutUint32(b[16:], ncmds)
	order.PutUint32(b[20:], sizeofcmds)
	return b
}

type fatSlice struct {
	cpu, sub uint32
	body     []byte
}

// buildFat assembles a universal binary with 16-byte aligned slices.
func buildFat(order binary.ByteOrder, magic uint32, wide bool, slices ...fatSlice) []byte {
	entryLen := 20
	if wide {
		entryLen = 32
	}
	b := make([]byte, 8+entryLen*len(slices))
	be.PutUint32(b, magic)
	order.PutUint32(b[4:], uint32(len(slices)))
	for i, s := range slices {
		for len(b)%16 != 0 {
			b = append(b, 0)
		}
		off := len(b)
		b = append(b, s.body...)
		e := b[8+i*entryLen:]
		order.PutUint32(e[0:], s.cpu)
		order.PutUint32(e[4:], s.sub)
		if wide {
			order.PutUint64(e[8:], uint64(off))
			order.PutUint64(e[16:], uint64(len(s.body)))
			order.PutUint32(e[24:], 4)
		} else {
			order.PutUint32(e[8:], uint32(off))
			order.PutUint32(e[12:], uint32(len(s.body)))
			order.PutUint32(e[16:], 4)
		}
	}
	return b
}

func buildClass(major, minor, constantPool uint16) []byte {
	b := make([]byte, 16)
	be.PutUint32(b, 0xcafebabe)
	be.PutUint16(b[4:], minor)
	be.PutUint16(b[6:], major)
	be.PutUint16(b[8:], constantPool)
	return b
}

func buildPyc(magic uint16, headerLen int, code byte) []byte {
	b := make([]byte, headerLen+8)
	le.PutUint16(b, magic)
	b[2], b[3] = '\r', '\n'
	b[headerLen] = code
	return b
}

func sampleDex() []byte {
	b := make([]byte, 112)
	copy(b, "dex\n035\x00")
	le.PutUint32(b[36:], 0x70)
	le.PutUint32(b[40:], 0x12345678)
	return b
}

func samplePNG() []byte {
	b := []byte("\x89PNG\r\n\x1a\n")
	b = be.AppendUint32(b, 13)
	b = append(b, "IHDR"...)
	b = be.AppendUint32(b, 16)
	b = be.AppendUint32(b, 8)
	return append(b, make([]byte, 16)...)
}

func buildTar(magic string) []byte {
	b := make([]byte, 1024)
	copy(b, "a.txt")
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], "00000000003\x00")
	copy(b[136:], "00000000000\x00")
	b[156] = '0'
	copy(b[257:], magic)
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	sum := 0
	for _, c := range b[:512] {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func sampleSQLite() []byte {
	b := make([]byte, 100)
	copy(b, "SQLite format 3\x00")
	be.PutUint16(b[16:], 4096)
	b[18], b[19] = 1, 1
	return b
}

func sampleGGUF(version uint32) []byte {
	b := []byte("GGUF")
	b = le.AppendUint32(b, version)
	b = le.AppendUint64(b, 0)
	return le.AppendUint64(b, 0)
}

func buildSafetensors(header string, data []byte) []byte {
	b := le.AppendUint64(nil, uint64(len(header)))
	b = append(b, header...)
	return append(b, data...)
}

// buildAsar frames an ASAR header pickle around the JSON index.
func buildAsar(index, data string) []byte {
	pad := (4 - len(index)%4) % 4
	payload := 4 + len(index) + pad
	b := le.AppendUint32(nil, 4)
	b = le.AppendUint32(b, uint32(payload+4))
	b = le.AppendUint32(b, uint32(payload))
	b = le.AppendUint32(b, uint32(len(index)))
	b = append(b, index...)
	b = append(b, make([]byte, pad)...)
	return append(b, data...)
}

func buildPDF(junk int) []byte {
	return append(bytes.Repeat([]byte{' '}, junk), "%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\nstartxref\n0\n%%EOF\n"...)
}

func sampleOLE() []byte {
	b := make([]byte, 64)
	copy(b, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
	b[28], b[29] = 0xfe, 0xff
	return b
}

// zentry is one member of a test archive.
type zentry struct {
	name  string
	data  string
	store bool
}

func buildZip(tb testing.TB, entries ...zentry) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		method := zip.Deflate
		if e.store {
			method = zip.Store
		}
		fw, err := w.CreateHeader(&zip.FileHeader{Name: e.name, Method: method})
		if err != nil {
			tb.Fatal(err)
		}
		if _, err := fw.Write([]byte(e.data)); err != nil {
			tb.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// fixtures returns the sample files and the exact result expected for each.
func fixtures(tb testing.TB) []fixture {
	tb.Helper()
	const (
		high   = report.ConfidenceHigh
		medium = report.ConfidenceMedium
		low    = report.ConfidenceLow
	)
	cookie := []byte("MEI\x0c\x0b\x0a\x0b\x0e")
	exec, doc, arch, pkg, bytecode, image := report.FamilyExecutable, report.FamilyDocument, report.FamilyArchive,
		report.FamilyPackage, report.FamilyBytecode, report.FamilyImage
	upxELF := append(buildELF(2, 1, 2, 62), make([]byte, 64)...)
	copy(upxELF[100:], "UPX!")
	fatBody := func(cpu uint32) []byte { return buildMachO(machoMagic64LE, cpu, 0, 2, 0, 0) }
	badFat := buildFat(be, fatMagic, false, fatSlice{cpu: 0x0100000c, body: fatBody(0x0100000c)})
	be.PutUint32(badFat[16:], 0x7fffff00) // slice offset far outside the file
	tarGNU := buildTar("ustar  \x00")
	badGzip := []byte("\x1f\x8b\x08\xe0rest of the file")
	cutASAR := buildAsar(`{"files":{"a":{"size":3,"offset":"0"}}}`, "abc")[:40] // the header pickle runs past the end
	latin1 := []byte("Ol\xe1, mundo, como vai voc\xea hoje?\n")
	utf16le := []byte{0xff, 0xfe, 'H', 0, 'i', 0, '\n', 0}
	utf16be := []byte{0xfe, 0xff, 0, 'H', 0, 'i', 0, '\n'}

	jarEntries := []zentry{{name: "META-INF/MANIFEST.MF", data: "Manifest-Version: 1.0\n"}, {name: "p/A.class", data: "x"}}
	return []fixture{
		// Portable Executable
		{"pe64 console exe", buildPE(peSpec{}), report.TypePE, exec, high,
			[]string{"64-bit", "exe", "x86-64"}, "PE32+ executable for Windows (x86-64, console)", mimePE},
		{"pe32 gui exe", buildPE(peSpec{pe32: true, subsystem: 2}), report.TypePE, exec, high,
			[]string{"32-bit", "exe", "x86"}, "PE32 executable for Windows (x86, GUI)", mimePE},
		{"pe64 dll", buildPE(peSpec{dll: true}), report.TypePE, exec, high,
			[]string{"64-bit", "dll", "x86-64"}, "PE32+ DLL for Windows (x86-64)", mimePE},
		{"pe64 native driver", buildPE(peSpec{subsystem: 1}), report.TypePE, exec, high,
			[]string{"64-bit", "driver", "native", "x86-64"}, "PE32+ native driver for Windows (x86-64)", mimePE},
		{"pe64 native dll", buildPE(peSpec{subsystem: 1, dll: true}), report.TypePE, exec, high,
			[]string{"64-bit", "dll", "native", "x86-64"}, "PE32+ DLL for Windows", mimePE},
		{"pe32 dotnet exe", buildPE(peSpec{pe32: true, clr: true}), report.TypePE, exec, high,
			[]string{"32-bit", "dotnet", "exe", "x86"}, "PE32 executable for Windows (x86, console, .NET)", mimePE},
		{"pe64 upx sections", buildPE(peSpec{sections: []string{"UPX0", "UPX1", ".rsrc"}}), report.TypePE, exec, high,
			[]string{"64-bit", "exe", "upx", "x86-64"}, "", mimePE},
		{"pe64 pyinstaller cookie", buildPE(peSpec{trailer: cookie}), report.TypePE, exec, high,
			[]string{"64-bit", "exe", "pyinstaller", "x86-64"}, "", mimePE},
		{"pe arm64", buildPE(peSpec{machine: 0xaa64}), report.TypePE, exec, high,
			[]string{"64-bit", "arm64", "exe"}, "(ARM64, console)", mimePE},
		{"pe efi application", buildPE(peSpec{subsystem: 10}), report.TypePE, exec, high,
			[]string{"64-bit", "efi", "exe", "x86-64"}, "PE32+ EFI application (x86-64)", mimePE},
		{"pe efi runtime driver", buildPE(peSpec{subsystem: 12}), report.TypePE, exec, high,
			[]string{"64-bit", "driver", "efi", "x86-64"}, "EFI runtime driver", mimePE},
		{"pe cut inside coff header", buildPE(peSpec{cut: 0x80 + 4 + 10}), report.TypePE, exec, medium,
			[]string{"exe"}, "PE executable for Windows", mimePE},
		{"pe cut inside optional header", buildPE(peSpec{cut: 0x80 + 4 + 20 + 10}), report.TypePE, exec, high,
			[]string{"64-bit", "exe", "x86-64"}, "PE32+ executable for Windows (x86-64)", mimePE},
		{"ne executable", buildDOSWithSignature("NE"), report.TypeDOS, exec, medium,
			[]string{"mz", "ne"}, "NE executable", mimeDOS},
		{"lx executable", buildDOSWithSignature("LX"), report.TypeDOS, exec, medium,
			[]string{"lx", "mz"}, "LE/LX executable", mimeDOS},
		{"dos executable", buildDOSWithSignature("XX"), report.TypeDOS, exec, medium,
			[]string{"mz"}, "no valid PE header", mimeDOS},
		{"text that starts with MZ", []byte("MZ is a two-letter abbreviation used in this note.\n"),
			report.TypeText, report.FamilyText, low, []string{"ascii"}, "ASCII text", "text/plain"},

		// ELF
		{"elf64 shared object", buildELF(2, 1, 3, 62), report.TypeELF, exec, high,
			[]string{"64-bit", "little-endian", "shared-object", "x86-64"}, "ELF 64-bit LSB shared object (x86-64)", "application/x-sharedlib"},
		{"elf32 big-endian executable", buildELF(1, 2, 2, 8), report.TypeELF, exec, high,
			[]string{"32-bit", "big-endian", "executable", "mips"}, "ELF 32-bit MSB executable (MIPS)", "application/x-executable"},
		{"elf64 relocatable", buildELF(2, 1, 1, 183), report.TypeELF, exec, high,
			[]string{"64-bit", "aarch64", "little-endian", "relocatable"}, "relocatable (AArch64)", "application/x-object"},
		{"elf64 core", buildELF(2, 1, 4, 62), report.TypeELF, exec, high,
			[]string{"64-bit", "core", "little-endian", "x86-64"}, "core file", "application/x-coredump"},
		{"elf64 upx marker", upxELF, report.TypeELF, exec, high,
			[]string{"64-bit", "executable", "little-endian", "upx", "x86-64"}, "", ""},
		{"elf unknown type", buildELF(2, 1, 0, 62), report.TypeELF, exec, medium,
			[]string{"64-bit", "little-endian", "x86-64"}, "ELF 64-bit LSB file", ""},
		{"elf magic only", []byte("\x7fELF"), report.TypeELF, exec, medium, []string{}, "truncated or unrecognised", ""},
		{"elf bad class", buildELF(7, 1, 2, 62), report.TypeELF, exec, medium, []string{}, "unrecognised", ""},

		// Mach-O
		{"macho64 arm64 executable", buildMachO(machoMagic64LE, 0x0100000c, 0, 2, 0, 0), report.TypeMachO, exec, high,
			[]string{"64-bit", "arm64", "executable"}, "Mach-O 64-bit executable (arm64)", mimeMachO},
		{"macho32 big-endian ppc dylib", buildMachO(machoMagic32BE, 18, 0, 6, 0, 0), report.TypeMachO, exec, high,
			[]string{"32-bit", "dylib", "ppc"}, "Mach-O 32-bit dynamic library (ppc)", mimeMachO},
		{"macho64 x86_64 dylib", buildMachO(machoMagic64LE, 0x01000007, 3, 6, 1, 8), report.TypeMachO, exec, high,
			[]string{"64-bit", "dylib", "x86_64"}, "(x86_64)", mimeMachO},
		{"macho64 arm64e bundle", buildMachO(machoMagic64LE, 0x0100000c, 2, 8, 0, 0), report.TypeMachO, exec, high,
			[]string{"64-bit", "arm64e", "bundle"}, "(arm64e)", mimeMachO},
		{"macho bad filetype", buildMachO(machoMagic64LE, 0x0100000c, 0, 99, 0, 0), report.TypeMachO, exec, medium,
			[]string{"64-bit", "arm64"}, "Mach-O 64-bit file (arm64)", mimeMachO},
		{"macho truncated header", buildMachO(machoMagic64LE, 0x0100000c, 0, 2, 0, 0)[:8], report.TypeMachO, exec, medium,
			[]string{"64-bit"}, "truncated header", mimeMachO},
		{"macho fat arm64+x86_64", buildFat(be, fatMagic, false,
			fatSlice{0x0100000c, 0, fatBody(0x0100000c)}, fatSlice{0x01000007, 3, fatBody(0x01000007)}),
			report.TypeMachOFat, exec, high, []string{"arm64", "universal", "x86_64"},
			"Mach-O universal binary (arm64, x86_64)", mimeMachO},
		{"macho fat64", buildFat(be, fatMagic64, true, fatSlice{0x0100000c, 0, fatBody(0x0100000c)}),
			report.TypeMachOFat, exec, high, []string{"arm64", "universal"}, "universal binary (arm64)", mimeMachO},
		{"macho fat byte-swapped", buildFat(le, fatMagicSwap, false, fatSlice{0x01000007, 3, fatBody(0x01000007)}),
			report.TypeMachOFat, exec, high, []string{"universal", "x86_64"}, "(x86_64)", mimeMachO},
		{"macho fat implausible slice", badFat, report.TypeMachOFat, exec, medium,
			[]string{"arm64", "universal"}, "universal binary", mimeMachO},
		{"cafebabe with zero count", append([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x00"), make([]byte, 8)...),
			report.TypeData, report.FamilyData, low, []string{}, "data", mimeOctet},

		// Java class files
		{"class java 21", buildClass(65, 0, 16), report.TypeClass, bytecode, high,
			[]string{"java-21"}, "Java class file (major 65, Java 21)", "application/java-vm"},
		{"class java 8", buildClass(52, 0, 16), report.TypeClass, bytecode, high, []string{"java-8"}, "Java 8", ""},
		{"class java 1.1", buildClass(45, 3, 16), report.TypeClass, bytecode, high, []string{"java-1.1"}, "Java 1.1", ""},
		{"class java 1.4", buildClass(48, 0, 16), report.TypeClass, bytecode, high, []string{"java-1.4"}, "Java 1.4", ""},
		{"class java 5", buildClass(49, 0, 16), report.TypeClass, bytecode, high, []string{"java-5"}, "Java 5", ""},
		{"class preview features", buildClass(65, 0xffff, 16), report.TypeClass, bytecode, high,
			[]string{"java-21", "preview"}, "preview features", ""},
		{"class unknown release", buildClass(200, 0, 16), report.TypeClass, bytecode, medium, []string{}, "major 200", ""},
		{"class empty constant pool", buildClass(52, 0, 0), report.TypeClass, bytecode, medium, []string{"java-8"}, "", ""},

		// WebAssembly
		{"wasm module", []byte("\x00asm\x01\x00\x00\x00"), report.TypeWasm, exec, high, []string{}, "WebAssembly module", "application/wasm"},
		{"wasm component", []byte("\x00asm\x0d\x00\x01\x00"), report.TypeWasm, exec, high, []string{"component"}, "component", ""},
		{"wasm unknown version", []byte("\x00asm\x07\x00\x00\x00"), report.TypeWasm, exec, medium, []string{}, "version 0x7", ""},
		{"wasm magic only", []byte("\x00asm"), report.TypeWasm, exec, medium, []string{}, "truncated", ""},

		// Python and Lua bytecode, Dalvik
		{"pyc 3.11", buildPyc(3495, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.11"},
			"Python 3.11 bytecode (magic 3495)", "application/x-python-code"},
		{"pyc 3.8", buildPyc(3413, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.8"}, "Python 3.8", ""},
		{"pyc 3.12", buildPyc(3531, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.12"}, "", ""},
		{"pyc 3.13", buildPyc(3571, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.13"}, "", ""},
		{"pyc 3.14", buildPyc(3627, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.14"}, "", ""},
		{"pyc newer than the table", buildPyc(3700, 16, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.15+"}, "", ""},
		{"pyc 3.6 has a 12-byte header", buildPyc(3379, 12, 0xe3), report.TypePyc, bytecode, high, []string{"python-3.6"}, "", ""},
		{"pyc 3.0 has an 8-byte header", buildPyc(3131, 8, 'c'), report.TypePyc, bytecode, high, []string{"python-3.0"}, "", ""},
		{"pyc 2.7", buildPyc(62211, 8, 'c'), report.TypePyc, bytecode, high, []string{"python-2.7"}, "Python 2.7", ""},
		{"pyc 1.5", buildPyc(20121, 8, 'c'), report.TypePyc, bytecode, high, []string{"python-1.5"}, "", ""},
		{"pyc magic only", []byte{0xa7, 0x0d, 0x0d, 0x0a}, report.TypePyc, bytecode, medium, []string{"python-3.11"}, "", ""},
		{"pyc without a code object", buildPyc(3495, 16, 0), report.TypeData, report.FamilyData, low, []string{}, "", ""},
		{"pyc unknown magic number", buildPyc(1000, 16, 0xe3), report.TypeData, report.FamilyData, low, []string{}, "", ""},
		{"pyc with invalid flags", func() []byte { b := buildPyc(3495, 16, 0xe3); le.PutUint32(b[4:], 0xffffffff); return b }(),
			report.TypeData, report.FamilyData, low, []string{}, "", ""},
		{"lua 5.4", []byte("\x1bLua\x54\x00\x19\x93\r\n\x1a\n"), report.TypeLua, bytecode, high, []string{"lua-5.4"}, "Lua 5.4 bytecode", ""},
		{"lua unknown version", []byte("\x1bLua\x99\x00"), report.TypeLua, bytecode, medium, []string{"lua"}, "", ""},
		{"luajit", []byte("\x1bLJ\x02\x00"), report.TypeLua, bytecode, high, []string{"luajit"}, "LuaJIT bytecode (version 2)", ""},
		{"dex", sampleDex(), report.TypeDex, bytecode, high, []string{"android", "dex-035"}, "DEX 035", "application/vnd.android.dex"},
		{"dex magic only", []byte("dex\n039\x00"), report.TypeDex, bytecode, medium, []string{"android", "dex-039"}, "", ""},

		// Images
		{"png", samplePNG(), report.TypePNG, image, high, []string{}, "PNG image (16x8)", "image/png"},
		{"png signature only", []byte("\x89PNG\r\n\x1a\n"), report.TypePNG, image, medium, []string{}, "PNG image", ""},
		{"jpeg jfif", []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"), report.TypeJPEG, image, high, []string{}, "JPEG image (JFIF)", "image/jpeg"},
		{"jpeg exif", []byte("\xff\xd8\xff\xe1\x00\x10Exif\x00\x00"), report.TypeJPEG, image, high, []string{}, "(Exif)", ""},
		{"jpeg bad marker", []byte("\xff\xd8\xff\x00\x00"), report.TypeJPEG, image, medium, []string{}, "", ""},
		{"gif", append([]byte("GIF89a"), 0x40, 0x01, 0xc8, 0x00, 0, 0), report.TypeGIF, image, high, []string{}, "GIF image (89a, 320x200)", "image/gif"},
		{"webp", []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00"), report.TypeWebP, image, high, []string{}, "WebP image", "image/webp"},
		{"riff that is not webp", []byte("RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00"), report.TypeData, report.FamilyData, low,
			[]string{}, "", ""},

		// Compression and archives
		{"gzip", []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03rest"), report.TypeGzip, arch, high, []string{}, "gzip", "application/gzip"},
		{"gzip reserved flags", badGzip, report.TypeGzip, arch, medium, []string{}, "", ""},
		{"bzip2", []byte("BZh91AY&SY\x00\x00"), report.TypeBzip2, arch, high, []string{}, "bzip2", "application/x-bzip2"},
		{"bzip2 magic only", []byte("BZh9xxxxxxxx"), report.TypeBzip2, arch, medium, []string{}, "", ""},
		{"xz", []byte("\xfd7zXZ\x00\x00\x04\xe6\xd6"), report.TypeXz, arch, high, []string{}, "xz", "application/x-xz"},
		{"zstd", []byte("\x28\xb5\x2f\xfd\x00\x58\x00\x00"), report.TypeZstd, arch, high, []string{}, "Zstandard", "application/zstd"},
		{"7z", []byte("7z\xbc\xaf\x27\x1c\x00\x04\x00\x00"), report.Type7z, arch, high, []string{}, "7-Zip", "application/x-7z-compressed"},
		{"rar4", []byte("Rar!\x1a\x07\x00\xcf\x90s"), report.TypeRar, arch, high, []string{"rar4"}, "version 4", "application/vnd.rar"},
		{"rar5", []byte("Rar!\x1a\x07\x01\x00\x33\x92"), report.TypeRar, arch, high, []string{"rar5"}, "version 5", ""},
		{"tar posix", buildTar("ustar\x0000"), report.TypeTar, arch, high, []string{"posix"}, "POSIX ustar", "application/x-tar"},
		{"tar gnu", tarGNU, report.TypeTar, arch, high, []string{"gnu"}, "GNU", ""},
		{"tar bad checksum", func() []byte { b := buildTar("ustar\x0000"); b[0] = 'b'; return b }(), report.TypeTar, arch, medium,
			[]string{"posix"}, "", ""},

		// Documents and databases
		{"pdf", buildPDF(0), report.TypePDF, doc, high, []string{}, "PDF document (version 1.7)", "application/pdf"},
		{"pdf after junk", buildPDF(100), report.TypePDF, doc, medium, []string{}, "version 1.7", ""},
		{"text that mentions pdf", []byte("The header %PDF-1.7 starts every PDF file.\n"), report.TypeText, report.FamilyText, low,
			[]string{"ascii"}, "", ""},
		{"rtf", []byte(`{\rtf1\ansi\deff0 hello}`), report.TypeRTF, doc, high, []string{}, "Rich Text Format", "application/rtf"},
		{"ole compound document", sampleOLE(), report.TypeOLE, doc, high, []string{}, "OLE2", ""},
		{"sqlite", sampleSQLite(), report.TypeSQLite, report.FamilyDatabase, high, []string{}, "SQLite 3", "application/vnd.sqlite3"},
		{"sqlite bad page size", func() []byte { b := sampleSQLite(); be.PutUint16(b[16:], 1000); return b }(),
			report.TypeSQLite, report.FamilyDatabase, medium, []string{}, "", ""},

		// Model files
		{"gguf v3", sampleGGUF(3), report.TypeGGUF, report.FamilyModel, high, []string{"gguf-v3"}, "GGUF model (version 3)", mimeOctet},
		{"gguf unknown version", sampleGGUF(9), report.TypeData, report.FamilyData, low, []string{}, "", ""},
		{"safetensors", buildSafetensors(`{"__metadata__":{"format":"pt"},"w":{"dtype":"F16","shape":[2,2],"data_offsets":[0,8]}}`+"   ",
			make([]byte, 8)), report.TypeSafetensors, report.FamilyModel, high, []string{}, "Safetensors model (1 tensors)", ""},
		{"safetensors metadata only", buildSafetensors(`{"__metadata__":{"format":"pt"}}`, nil),
			report.TypeSafetensors, report.FamilyModel, medium, []string{}, "", ""},
		{"safetensors with a malformed tensor", buildSafetensors(`{"w":{"dtype":"F16"}}`, make([]byte, 8)),
			report.TypeData, report.FamilyData, low, []string{}, "", ""},
		{"safetensors with invalid json", buildSafetensors(`{"w":{"dtype":"F16",`, make([]byte, 8)),
			report.TypeData, report.FamilyData, low, []string{}, "", ""},

		// Electron
		{"asar", buildAsar(`{"files":{"a.txt":{"size":3,"offset":"0"}}}`, "abc"), report.TypeAsar, pkg, high,
			[]string{"electron"}, "Electron ASAR", mimeOctet},
		{"asar cut inside the header", cutASAR, report.TypeAsar, pkg, medium, []string{"electron"}, "", ""},
		{"asar with inconsistent sizes", func() []byte {
			b := buildAsar(`{"files":{}}`, "")
			le.PutUint32(b[8:], le.Uint32(b[8:])+8)
			return b
		}(), report.TypeData, report.FamilyData, low, []string{}, "", ""},

		// Scripts and text
		{"shell script", []byte("#!/bin/sh\necho hi\n"), report.TypeScript, report.FamilyScript, high, []string{"shell"},
			"Shell script (/bin/sh)", "text/x-shellscript"},
		{"python script via env", []byte("#!/usr/bin/env python3\nprint(1)\n"), report.TypeScript, report.FamilyScript, high,
			[]string{"python"}, "Python script (python3)", "text/x-python"},
		{"node script via env -S", []byte("#!/usr/bin/env -S node --harmony\nconsole.log(1)\n"), report.TypeScript, report.FamilyScript, high,
			[]string{"node"}, "Node.js script (node)", ""},
		{"perl script with options", []byte("#!/usr/bin/perl -w\nprint 1;\n"), report.TypeScript, report.FamilyScript, high,
			[]string{"perl"}, "Perl script", ""},
		{"powershell script", []byte("#!/usr/bin/pwsh\nWrite-Host hi\n"), report.TypeScript, report.FamilyScript, high,
			[]string{"powershell"}, "PowerShell script", ""},
		{"unknown interpreter", []byte("#!/opt/custom/run-me\nstuff\n"), report.TypeScript, report.FamilyScript, high,
			[]string{"run-me"}, "Script (/opt/custom/run-me)", "text/plain"},
		{"script with binary payload", append([]byte("#!/bin/sh\nexit\n"), 0, 1, 2, 3, 0, 0, 0, 0), report.TypeScript,
			report.FamilyScript, medium, []string{"shell"}, "", ""},
		{"shebang with no interpreter", []byte("#!\nhello\n"), report.TypeText, report.FamilyText, low, []string{"ascii"}, "", ""},
		{"ascii text", []byte("Hello, world.\nSecond line.\n"), report.TypeText, report.FamilyText, low, []string{"ascii"},
			"ASCII text", "text/plain"},
		{"utf-8 text", []byte("Olá, mundo — café\n"), report.TypeText, report.FamilyText, low, []string{"utf-8"}, "UTF-8 text", ""},
		{"utf-8 text with bom", append([]byte{0xef, 0xbb, 0xbf}, "hello\n"...), report.TypeText, report.FamilyText, low,
			[]string{"utf-8"}, "", ""},
		{"utf-16le text with bom", utf16le, report.TypeText, report.FamilyText, low, []string{"utf-16le"}, "UTF-16LE", ""},
		{"utf-16be text with bom", utf16be, report.TypeText, report.FamilyText, low, []string{"utf-16be"}, "UTF-16BE", ""},
		{"latin-1 text", latin1, report.TypeText, report.FamilyText, low, []string{"8-bit"}, "8-bit text", ""},
		{"single character", []byte("A"), report.TypeText, report.FamilyText, low, []string{"ascii"}, "", ""},
		{"binary bytes", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), report.TypeData, report.FamilyData, low, []string{}, "data", mimeOctet},
		{"zero bytes", make([]byte, 128), report.TypeData, report.FamilyData, low, []string{}, "data", mimeOctet},

		// ZIP family
		{"zip plain", buildZip(tb, zentry{name: "a.txt", data: "hello"}, zentry{name: "d/b.txt", data: "world"}),
			report.TypeZip, arch, high, []string{}, "ZIP archive", mimeZip},
		{"zip empty", append([]byte("PK\x05\x06"), make([]byte, 18)...), report.TypeZip, arch, high, []string{"empty"}, "empty", mimeZip},
		{"zip opc package", buildZip(tb, zentry{name: "[Content_Types].xml", data: "<x/>"}), report.TypeZip, arch, high,
			[]string{"opc"}, "Open Packaging", ""},
		{"jar", buildZip(tb, jarEntries...), report.TypeJar, pkg, high, []string{"java"}, "Java archive (JAR)", "application/java-archive"},
		{"jar with backslash names", buildZip(tb, zentry{name: `META-INF\MANIFEST.MF`, data: "Manifest-Version: 1.0\n"}),
			report.TypeJar, pkg, high, []string{"java"}, "", ""},
		{"jar without manifest", buildZip(tb, zentry{name: "p/A.class", data: "x"}), report.TypeJar, pkg, medium,
			[]string{"java"}, "no manifest", ""},
		{"war", buildZip(tb, append(jarEntries, zentry{name: "WEB-INF/web.xml", data: "<x/>"})...), report.TypeJar, pkg, high,
			[]string{"java", "war"}, "WAR", ""},
		{"ear", buildZip(tb, append(jarEntries, zentry{name: "META-INF/application.xml", data: "<x/>"})...), report.TypeJar, pkg, high,
			[]string{"ear", "java"}, "EAR", ""},
		{"apk", buildZip(tb, zentry{name: "AndroidManifest.xml", data: "x"}, zentry{name: "classes.dex", data: "d"},
			zentry{name: "resources.arsc", data: "r"}, zentry{name: "META-INF/MANIFEST.MF", data: "m"}),
			report.TypeAPK, pkg, high, []string{"android"}, "Android package (APK)", "application/vnd.android.package-archive"},
		{"aab", buildZip(tb, zentry{name: "BundleConfig.pb", data: "x"}, zentry{name: "base/manifest/AndroidManifest.xml", data: "x"},
			zentry{name: "META-INF/MANIFEST.MF", data: "m"}),
			report.TypeAAB, pkg, high, []string{"android"}, "Android App Bundle", ""},
		{"aar", buildZip(tb, zentry{name: "AndroidManifest.xml", data: "x"}, zentry{name: "classes.jar", data: "j"}, zentry{name: "R.txt", data: "r"}),
			report.TypeZip, arch, high, []string{"aar", "android"}, "AAR", ""},
		{"docx", buildZip(tb, zentry{name: "[Content_Types].xml", data: "x"}, zentry{name: "word/document.xml", data: "x"}),
			report.TypeDocx, doc, high, []string{"office"}, "DOCX", mimeOffice + "wordprocessingml.document"},
		{"xlsx", buildZip(tb, zentry{name: "[Content_Types].xml", data: "x"}, zentry{name: "xl/workbook.xml", data: "x"}),
			report.TypeXlsx, doc, high, []string{"office"}, "XLSX", mimeOffice + "spreadsheetml.sheet"},
		{"pptx", buildZip(tb, zentry{name: "[Content_Types].xml", data: "x"}, zentry{name: "ppt/presentation.xml", data: "x"}),
			report.TypePptx, doc, high, []string{"office"}, "PPTX", mimeOffice + "presentationml.presentation"},
		{"odt", buildZip(tb, zentry{name: "mimetype", data: "application/vnd.oasis.opendocument.text", store: true}, zentry{name: "content.xml", data: "x"}),
			report.TypeODF, doc, high, []string{"office", "text"}, "OpenDocument text document (ODT)", "application/vnd.oasis.opendocument.text"},
		{"ods template", buildZip(tb, zentry{name: "mimetype", data: "application/vnd.oasis.opendocument.spreadsheet-template", store: true}),
			report.TypeODF, doc, high, []string{"office", "spreadsheet", "template"}, "spreadsheet (ODS) template", ""},
		{"odf with mimetype not first", buildZip(tb, zentry{name: "content.xml", data: "x"},
			zentry{name: "mimetype", data: "application/vnd.oasis.opendocument.graphics", store: true}),
			report.TypeODF, doc, medium, []string{"graphics", "office"}, "drawing (ODG)", ""},
		{"odf with a hostile mimetype", buildZip(tb, zentry{name: "mimetype", data: "application/vnd.oasis.opendocument.<script>", store: true}),
			report.TypeZip, arch, high, []string{}, "", ""},
		{"epub", buildZip(tb, zentry{name: "mimetype", data: "application/epub+zip", store: true}, zentry{name: "META-INF/container.xml", data: "x"}),
			report.TypeEPUB, doc, high, []string{}, "EPUB", "application/epub+zip"},
		{"nupkg", buildZip(tb, zentry{name: "Demo.nuspec", data: "x"}, zentry{name: "[Content_Types].xml", data: "x"},
			zentry{name: "lib/net8.0/Demo.dll", data: "x"}), report.TypeNupkg, pkg, high, []string{"dotnet"}, "NuGet", ""},
		{"wheel", buildZip(tb, zentry{name: "demo/__init__.py", data: "x"}, zentry{name: "demo-1.0.dist-info/WHEEL", data: "Wheel-Version: 1.0\n"}),
			report.TypeWheel, pkg, high, []string{"python"}, "Python wheel", "application/x-wheel+zip"},
		{"vsix for vscode", buildZip(tb, zentry{name: "extension.vsixmanifest", data: "x"}, zentry{name: "extension/package.json", data: "{}"},
			zentry{name: "[Content_Types].xml", data: "x"}), report.TypeVSIX, pkg, high, []string{"vscode"}, "Visual Studio Code", ""},
		{"vsix for visual studio", buildZip(tb, zentry{name: "extension.vsixmanifest", data: "x"}, zentry{name: "[Content_Types].xml", data: "x"}),
			report.TypeVSIX, pkg, high, []string{"visualstudio"}, "Visual Studio extension", ""},
		{"zip with trailing garbage cut off", func() []byte {
			b := buildZip(tb, zentry{name: "a.txt", data: strings.Repeat("hello ", 50)}, zentry{name: "b.txt", data: "world"})
			return b[:len(b)/2]
		}(), report.TypeZip, arch, medium, nil, "", mimeZip},
	}
}
