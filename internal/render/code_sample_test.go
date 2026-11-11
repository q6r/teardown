package render

import (
	"strings"
	"time"

	"github.com/q6r/teardown/internal/report"
)

// textBase is the distance between a virtual address and a file offset in the
// .text section of the sample: the section starts at address 0x140001000 and at
// file offset 0x400.
const textBase = 0x140000c00

// insn is one instruction of a hand-written listing. The encodings were written
// from the architecture manual, not produced by a decoder.
type insn struct {
	va    uint64
	bytes string
	text  string
	note  string
	hit   bool
}

func asmLimits() []string {
	return []string{
		"x86 and x86-64 only: other instruction sets are not decoded.",
		"A linear sweep: data inside a code section can be read as instructions, and one wrong byte shifts everything after it.",
		"A view of the code, not a decompilation. Nothing was executed.",
	}
}

// callSite builds the disassembly block for a window of instructions around a call.
func callSite(api string, rows []insn) report.CodeBlock {
	b := report.CodeBlock{Kind: report.CodeKindDisasm, Title: "Call site of " + api, Section: ".text", Arch: "x86-64", Limitations: asmLimits()}
	for _, r := range rows {
		b.Lines = append(b.Lines, report.CodeLine{Address: report.Addr(r.va), Offset: int64(r.va - textBase), Bytes: r.bytes, Text: r.text, Note: r.note, Highlight: r.hit})
	}
	b.Offset, b.Address = b.Lines[0].Offset, b.Lines[0].Address
	return b
}

// hexRows builds the lines of a hex block from sixteen-byte rows, the way the hexdump package lays them out.
func hexRows(first int64, rows [][2]string, flagged int) []report.CodeLine {
	lines := make([]report.CodeLine, len(rows))
	for i, r := range rows {
		lines[i] = report.CodeLine{Offset: first + int64(i)*16, Bytes: r[0], Text: r[1], Highlight: i == flagged}
	}
	return lines
}

func srcLines(first int, firstOffset int64, flagged int, texts ...string) []report.CodeLine {
	lines := make([]report.CodeLine, len(texts))
	off := firstOffset
	for i, t := range texts {
		lines[i] = report.CodeLine{Offset: off, Line: first + i, Text: t, Highlight: i == flagged}
		off += int64(len(t)) + 1
	}
	return lines
}

// codeSampleReport is a hand-written report whose findings carry every kind of
// code block: four call sites of a process-injection chain (disassembly), the
// bytes around a URL (hex) and the lines of a script (source), next to
// findings without code. Its text, Markdown, JSON and page outputs are pinned
// by the golden files in testdata.
func codeSampleReport() *report.Report {
	r := report.New("dropper.exe", 38400, "0.2.0")
	r.GeneratedAt = time.Date(2026, 11, 15, 9, 30, 0, 0, time.UTC)
	r.DurationMs = 18
	r.Type = report.Type{ID: report.TypePE, Family: report.FamilyExecutable, Label: "PE32+ executable for Windows (x86-64, console)", MIME: "application/vnd.microsoft.portable-executable", Confidence: report.ConfidenceHigh, Tags: []string{"64-bit", "exe", "x86-64"}}
	r.Hashes = report.Hashes{MD5: "5f0e3a7c9b21d84e6a1f0c3d7b92e4a8", SHA1: "9c1185a5c5e9fc54612808977ee8f548b2258d31", SHA256: "3f2a9c7e41d0b85a6e13c97f2b40d8a15c6e9f0b7d3a2e8c14b95f60a7d1c3e2", Imphash: "8b1e5c4d2a7f9063e1b8d4c5a2f70e93"}
	r.Entropy = report.Entropy{Overall: 5.82, WindowSize: 2048, Windows: []float64{1.2, 5.9, 6.1, 5.4, 4.8, 2.1, 0.4, 3.3, 5.7, 6.0, 5.2, 1.1, 0.2, 0.1, 2.9, 4.4, 5.1, 3.8}}
	r.Sections = []report.Section{
		{Name: ".text", VirtualSize: 0xc40, RawSize: 0x1000, Offset: 0x400, Entropy: 5.9, Flags: []string{"R", "X"}},
		{Name: ".rdata", VirtualSize: 0x9a4, RawSize: 0xa00, Offset: 0x1400, Entropy: 4.6, Flags: []string{"R"}},
		{Name: ".data", VirtualSize: 0x2f0, RawSize: 0x200, Offset: 0x1e00, Entropy: 1.8, Flags: []string{"R", "W"}},
	}
	r.Imports = []report.Import{
		{Library: "KERNEL32.dll", Count: 7, Functions: []string{"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "GetProcAddress", "LoadLibraryA", "ExitProcess"}},
		{Library: "WS2_32.dll", Count: 4, Functions: []string{"WSAStartup", "socket", "connect", "send"}},
	}
	r.Strings = report.Strings{Total: 212, MinLength: 5, ByCategory: map[string]int{report.CatURL: 1, report.CatPlain: 211}, Items: []report.StringItem{
		{Value: "http://203.0.113.7/gate.php", Offset: 0x1a58, Encoding: "ascii", Category: report.CatURL},
	}}
	r.Hardening = []report.Hardening{
		{ID: report.HardenASLR, Label: "ASLR", Status: report.StatusEnabled, Detail: "DYNAMIC_BASE is set"},
		{ID: report.HardenCFG, Label: "Control Flow Guard", Status: report.StatusDisabled, Detail: "GUARD_CF is not set"},
	}
	r.Details["pe"] = map[string]any{"machine": "x86-64", "bits": 64, "subsystem": "console", "entryPoint": "0x140001000", "entrySection": ".text"}

	injection := report.Finding{
		ID: "imports.process-injection", Title: "Imports cover the full process-injection chain (allocate, write, execute)",
		Severity: report.SeverityHigh, Category: report.CategoryImports, Confidence: report.ConfidenceMedium,
		Evidence: []string{
			"allocate or map memory in another process: KERNEL32.dll!VirtualAllocEx",
			"write to another process: KERNEL32.dll!WriteProcessMemory",
			"start or hijack a thread there: KERNEL32.dll!CreateRemoteThread",
		},
		Limitations: []string{
			"API presence alone proves nothing: legitimate software (debuggers, installers, security and remote-support tools) imports the same functions.",
			"Functions resolved at run time (GetProcAddress, dlsym) or hidden by a packer are not in the import table, so a missing cluster proves nothing either.",
		},
		Code: []report.CodeBlock{
			callSite("KERNEL32.dll!VirtualAllocEx", []insn{
				{0x14000101c, "48 8b 4d f8", "mov rcx, qword ptr [rbp-0x8]", "", false},
				{0x140001020, "31 d2", "xor edx, edx", "", false},
				{0x140001022, "41 b8 00 10 00 00", "mov r8d, 0x1000", "", false},
				{0x140001028, "41 b9 00 30 00 00", "mov r9d, 0x3000", "", false},
				{0x14000102e, "c7 44 24 20 40 00 00 00", "mov dword ptr [rsp+0x20], 0x40", "", false},
				{0x140001036, "ff 15 c4 1f 00 00", "call qword ptr [rip+0x1fc4]", "KERNEL32.dll!VirtualAllocEx", true},
				{0x14000103c, "48 89 45 f0", "mov qword ptr [rbp-0x10], rax", "", false},
				{0x140001040, "48 83 7d f0 00", "cmp qword ptr [rbp-0x10], 0", "", false},
				{0x140001045, "74 3b", "je 0x140001082", "", false},
			}),
			callSite("KERNEL32.dll!WriteProcessMemory", []insn{
				{0x140001047, "48 8b 4d f8", "mov rcx, qword ptr [rbp-0x8]", "", false},
				{0x14000104b, "48 8b 55 f0", "mov rdx, qword ptr [rbp-0x10]", "", false},
				{0x14000104f, "4c 8d 05 aa 2f 00 00", "lea r8, [rip+0x2faa]", "0x140004000 in .data", false},
				{0x140001056, "41 b9 00 02 00 00", "mov r9d, 0x200", "", false},
				{0x14000105c, "48 c7 44 24 20 00 00 00 00", "mov qword ptr [rsp+0x20], 0x0", "", false},
				{0x140001065, "ff 15 9d 1f 00 00", "call qword ptr [rip+0x1f9d]", "KERNEL32.dll!WriteProcessMemory", true},
				{0x14000106b, "85 c0", "test eax, eax", "", false},
				{0x14000106d, "74 15", "je 0x140001084", "", false},
			}),
			callSite("KERNEL32.dll!CreateRemoteThread", []insn{
				{0x14000106f, "48 8b 4d f8", "mov rcx, qword ptr [rbp-0x8]", "", false},
				{0x140001073, "31 d2", "xor edx, edx", "", false},
				{0x140001075, "45 31 c0", "xor r8d, r8d", "", false},
				{0x140001078, "4c 8b 4d f0", "mov r9, qword ptr [rbp-0x10]", "", false},
				{0x14000107c, "48 c7 44 24 20 00 00 00 00", "mov qword ptr [rsp+0x20], 0x0", "", false},
				{0x140001085, "ff 15 85 1f 00 00", "call qword ptr [rip+0x1f85]", "KERNEL32.dll!CreateRemoteThread", true},
				{0x14000108b, "48 85 c0", "test rax, rax", "", false},
				{0x14000108e, "74 0a", "je 0x14000109a", "", false},
			}),
			callSite("KERNEL32.dll!OpenProcess", []insn{
				{0x140001000, "b9 ff ff 1f 00", "mov ecx, 0x1fffff", "", false},
				{0x140001005, "31 d2", "xor edx, edx", "", false},
				{0x140001007, "44 8b 45 fc", "mov r8d, dword ptr [rbp-0x4]", "", false},
				{0x14000100b, "ff 15 07 20 00 00", "call qword ptr [rip+0x2007]", "KERNEL32.dll!OpenProcess", true},
				{0x140001011, "48 89 45 f8", "mov qword ptr [rbp-0x8], rax", "", false},
				{0x140001015, "48 83 7d f8 00", "cmp qword ptr [rbp-0x8], 0", "", false},
				{0x14000101a, "74 6c", "je 0x140001088", "", false},
			}),
		},
	}

	network := report.Finding{
		ID: "indicators.network", Title: "Hard-coded network indicators", Severity: report.SeverityMedium, Category: report.CategoryIndicator, Confidence: report.ConfidenceMedium,
		Evidence:    []string{"url: http://203.0.113.7/gate.php"},
		Limitations: []string{"A string in the file does not mean the program contacts it: it can be dead data, a placeholder or a documentation address."},
		Code: []report.CodeBlock{{
			Kind: report.CodeKindHex, Title: "Bytes around the URL at file offset 0x1a58", Section: ".rdata", Offset: 0x1a40,
			Lines: hexRows(0x1a40, [][2]string{
				{"00 00 00 00 00 00 00 00 55 73 65 72 2d 41 67 65", "........User-Age"},
				{"6e 74 3a 20 00 00 00 00 68 74 74 70 3a 2f 2f 32", "nt: ....http://2"},
				{"30 33 2e 30 2e 31 31 33 2e 37 2f 67 61 74 65 2e", "03.0.113.7/gate."},
				{"70 68 70 00 00 00 00 00 50 4f 53 54 00 00 00 00", "php.....POST...."},
				{"43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70", "Content-Type: ap"},
			}, 1),
			Limitations: []string{"A raw window over the file: the bytes are shown as they are and nothing says that any code uses them."},
		}},
	}

	script := report.Finding{
		ID: "application.electron-risky-settings", Title: "Bundled JavaScript mentions settings that widen the attack surface", Severity: report.SeverityMedium, Category: report.CategoryApp, Confidence: report.ConfidenceLow,
		Evidence:    []string{"nodeIntegration: true (app/main.js)", "contextIsolation: false (app/main.js)"},
		Limitations: []string{"The settings are read from text; other code can change them before a window opens."},
		Code: []report.CodeBlock{{
			Kind: report.CodeKindSource, Title: "Window settings in the main process", File: "app/main.js", Offset: 0x2f10,
			Lines: srcLines(15, 0x2f10, 3,
				"const { app, BrowserWindow } = require('electron');",
				"",
				"function createWindow() {",
				"  const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });",
				"  win.loadURL('https://example.com/app');",
				"  return win;",
				"}",
			),
			Limitations: []string{"Plain text lines taken from the packaged script: nothing was run or evaluated."},
		}},
	}

	noCFG := report.Finding{
		ID: "hardening.no-cfg", Title: "Control Flow Guard is not enabled", Severity: report.SeverityInfo, Category: report.CategoryHardening, Confidence: report.ConfidenceHigh,
		Evidence:    []string{"GUARD_CF is not set in the DLL characteristics"},
		Limitations: []string{"A missing mitigation describes how hard the file is to exploit, not whether it is malicious."},
	}

	r.Findings = []report.Finding{injection, network, script, noCFG}
	r.Risk = report.Risk{Score: 58, Label: report.RiskHigh, Basis: []string{"+30  imports.process-injection (high, medium confidence)", "+14  indicators.network (medium)", "+14  application.electron-risky-settings (medium, low confidence)"}}
	r.Normalize()
	return r
}

// codeSection returns the lines of out that belong to the first "code:" section
// of the terminal output, for tests that look at the layout.
func codeSection(out string) []string {
	var lines []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "      code:"):
			in = true
		case in && !strings.HasPrefix(l, "        "):
			return lines
		}
		if in {
			lines = append(lines, l)
		}
	}
	return lines
}
