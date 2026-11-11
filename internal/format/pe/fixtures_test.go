package pe

import (
	"bytes"

	"github.com/q6r/teardown/internal/testfixtures"
)

type namedFixture struct {
	name string
	data []byte
}

// fixtureSet returns a spread of valid images that exercises every directory
// the parser reads; the robustness sweeps and the fuzz seeds use it.
func fixtureSet() []namedFixture {
	exports := make([]testfixtures.PEExport, 0, 40)
	for i := range 40 {
		exports = append(exports, testfixtures.PEExport{Name: "export_" + string(rune('a'+i%26)) + string(rune('0'+i/26))})
	}
	exports = append(exports, testfixtures.PEExport{Name: "forwarded", Forwarder: "NTDLL.RtlAllocateHeap"})
	return []namedFixture{
		{"default64", testfixtures.PE(testfixtures.PEOptions{})},
		{"pe32", testfixtures.PE(testfixtures.PEOptions{Bits: 32})},
		{"dll-exports", testfixtures.PE(testfixtures.PEOptions{DLL: true, Exports: exports, ExportOrdinalOnly: 3, Timestamp: 1700000000})},
		{"driver", testfixtures.PE(testfixtures.PEOptions{Driver: true})},
		{"delay-imports", testfixtures.PE(testfixtures.PEOptions{
			Imports: []testfixtures.PEImport{
				{Library: "KERNEL32.dll", Functions: []string{"ExitProcess", "GetStdHandle"}},
				{Library: "WS2_32.dll", Functions: []string{"#23", "WSAStartup"}},
			},
			DelayImports: []testfixtures.PEImport{{Library: "shell32.dll", Functions: []string{"ShellExecuteW", "#42"}}},
		})},
		{"pdb-signed-overlay", testfixtures.PE(testfixtures.PEOptions{
			PDBPath: `C:\build\app.pdb`, Signed: true, Overlay: bytes.Repeat([]byte{0x41}, 100),
		})},
		{"dotnet", testfixtures.PE(testfixtures.PEOptions{DotNet: true})},
		{"x86-hardening", testfixtures.PE(testfixtures.PEOptions{
			Bits: 32, TLSCallbacks: 2, SafeSEH: true, GuardCF: true, SecurityCookie: true,
		})},
		{"x64-hardening", testfixtures.PE(testfixtures.PEOptions{TLSCallbacks: 1, GuardCF: true, SecurityCookie: true})},
		{"packed", testfixtures.PE(testfixtures.PEOptions{Sections: []testfixtures.PESection{
			{Name: "UPX0", NoRaw: true, VirtualSize: 0x20000, Characteristics: testfixtures.PESectionRWX},
			{Name: "UPX1", Data: bytes.Repeat([]byte{0x5a}, 600), Characteristics: testfixtures.PESectionRWX},
			{Name: ".debug_abbrev", Data: []byte("abc"), Characteristics: testfixtures.PESectionRData},
		}})},
		{"no-imports", testfixtures.PE(testfixtures.PEOptions{NoImports: true})},
	}
}
