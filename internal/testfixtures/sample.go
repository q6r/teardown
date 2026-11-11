package testfixtures

import (
	"bytes"
	"strings"
)

// buildHome is the home directory of the fictional developer whose machine
// "built" the sample. It is assembled from two literals so that path scanners
// do not mistake this fixture for a leaked real user path.
const buildHome = `C:\` + `Users\dev`

// SamplePE returns a harmless PE32+ that looks like a small dropper to a static
// scanner: suspicious import clusters, a packed-looking executable section, an
// RWX section, no ASLR, no signature, a PDB path, an overlay and a configuration
// blob full of network indicators and (fake, pattern-valid) credentials. It is
// the file behind testdata/sample-report.json and the examples. Nothing in it
// is executable code.
func SamplePE() []byte {
	return PE(PEOptions{
		Timestamp:     1_700_000_000,
		PDBPath:       buildHome + `\src\loader\x64\Release\loader.pdb`,
		CharsSet:      PECharRelocsStripped,
		DllCharsClear: 0x0040, // DYNAMIC_BASE
		Overlay:       bytes.Repeat([]byte("overlay-"), 800),
		Imports: []PEImport{
			{Library: "KERNEL32.dll", Functions: []string{
				"ExitProcess", "GetProcAddress", "LoadLibraryA", "VirtualAllocEx", "WriteProcessMemory",
				"CreateRemoteThread", "OpenProcess", "IsDebuggerPresent", "CreateProcessW",
			}},
			{Library: "USER32.dll", Functions: []string{"SetWindowsHookExA", "GetAsyncKeyState", "GetForegroundWindow"}},
			{Library: "WS2_32.dll", Functions: []string{"WSAStartup", "socket", "connect", "send", "recv"}},
			{Library: "ADVAPI32.dll", Functions: []string{"CryptAcquireContextA", "CryptEncrypt", "RegSetValueExA"}},
			{Library: "URLMON.dll", Functions: []string{"URLDownloadToFileA"}},
		},
		Sections: []PESection{
			{Name: ".config", Data: sampleConfigBlob(), Characteristics: PESectionRData},
			{Name: ".packed", Data: samplePseudoRandom(8192), Characteristics: PESectionCode},
			{Name: ".rwx", Data: make([]byte, 512), Characteristics: PESectionRWX},
		},
	})
}

// sampleConfigBlob is the NUL-separated string table of SamplePE.
func sampleConfigBlob() []byte {
	// Both credentials are assembled at run time: fake, pattern-valid values
	// (the AWS one is the key from the AWS documentation).
	githubToken := "ghp_" + strings.Repeat("a1b2c3", 6)
	awsExampleKey := "AKIA" + "IOSFODNN7EXAMPLE"
	items := []string{
		"https://update.example.test/gate.php",
		"http://198.51.100.23:8080/beacon",
		"203.0.113.7",
		"ops@example.test",
		"cmd.exe /c whoami /all",
		"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		buildHome + `\AppData\Roaming\svc\update.exe`,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		awsExampleKey,
		githubToken,
		"this is a harmless configuration sample",
	}
	return []byte(strings.Join(items, "\x00") + "\x00")
}

// samplePseudoRandom returns n deterministic, high-entropy bytes (xorshift32).
func samplePseudoRandom(n int) []byte {
	out := make([]byte, n)
	x := uint32(2463534242)
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x >> 8)
	}
	return out
}
