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
// scanner: suspicious import clusters whose code really calls them (see
// [samplePECalls]), a packed-looking executable section, an RWX section, no
// ASLR, no signature, a PDB path, an overlay and a configuration blob full of
// network indicators and (fake, pattern-valid) credentials. It is the file
// behind testdata/sample-report.json and the examples. It does nothing when
// started: the entry point returns at once, and the code that calls the imports
// lies behind it as dead code that is only meant to be read.
func SamplePE() []byte {
	return PE(PEOptions{
		Calls:         samplePECalls(),
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

// samplePECalls is the code of SamplePE, in the order a small dropper would run
// it: an anti-debugging check, a keyboard hook, a socket, a download, run-time
// resolution of a function, then the process-injection chain (open the process,
// allocate in it, write the payload, start a remote thread), a process launch
// through a thunk and the exit. The arguments are the constants a dropper would
// use; the pointers refer to .data.
func samplePECalls() []PECall {
	zero := PEArg{Kind: PEArgZero}
	imm := func(v uint32) PEArg { return PEArg{Kind: PEArgImm, Value: v} }
	data := func(off uint32) PEArg { return PEArg{Kind: PEArgData, Value: off} }
	result := func(call uint32) PEArg { return PEArg{Kind: PEArgResult, Value: call} }
	const (
		socketCall = 4  // the call whose result connect uses
		loadCall   = 7  // LoadLibraryA
		openCall   = 8  // OpenProcess
		allocCall  = 9  // VirtualAllocEx
		callCount  = 15 // the calls below
	)
	calls := []PECall{
		{Function: "IsDebuggerPresent", Discard: true},
		{Function: "SetWindowsHookExA", Discard: true, Args: []PEArg{imm(13), data(0), zero, zero}},
		{Function: "GetAsyncKeyState", Discard: true, Args: []PEArg{imm(0x41)}},
		{Function: "WSAStartup", Discard: true, Args: []PEArg{imm(0x202), data(0x10)}},
		{Function: "socket", Args: []PEArg{imm(2), imm(1), imm(6)}},
		{Function: "connect", Discard: true, Args: []PEArg{result(socketCall), data(0x10), imm(16)}},
		{Function: "URLDownloadToFileA", Discard: true, Args: []PEArg{zero, data(0), data(0x10), zero, zero}},
		{Function: "LoadLibraryA", Args: []PEArg{data(0)}},
		{Function: "OpenProcess", Args: []PEArg{imm(0x1fffff), zero, imm(0x1a4)}},
		{Function: "VirtualAllocEx", Args: []PEArg{result(openCall), zero, imm(0x1000), imm(0x3000), imm(0x40)}},
		{Function: "WriteProcessMemory", Discard: true, Args: []PEArg{result(openCall), result(allocCall), data(0), imm(0x200), zero}},
		{Function: "CreateRemoteThread", Discard: true, Args: []PEArg{result(openCall), zero, zero, result(allocCall), zero, zero, zero}},
		{Function: "GetProcAddress", Discard: true, Args: []PEArg{result(loadCall), data(0x10)}},
		{Function: "CreateProcessW", Thunk: true, Discard: true, Args: []PEArg{zero, data(0x10), zero, zero}},
		{Function: "ExitProcess", Discard: true, Args: []PEArg{zero}},
	}
	if len(calls) != callCount {
		panic("testfixtures: the sample's call numbers are out of date")
	}
	return calls
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
