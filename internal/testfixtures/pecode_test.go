package testfixtures

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// hexBytes decodes "48 83 ec 28" into bytes; the expected values below were
// written by hand from the instruction set reference, not produced by a decoder.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// textOf returns the raw bytes of the first section of a fixture.
func textOf(t *testing.T, data []byte) []byte {
	t.Helper()
	h := data[PESectionHeaderOffset(64, 0):]
	if name := string(bytes.TrimRight(h[:8], "\x00")); name != ".text" {
		t.Fatalf("first section is %q", name)
	}
	size, ptr := binary.LittleEndian.Uint32(h[16:]), binary.LittleEndian.Uint32(h[20:])
	return data[ptr : ptr+size]
}

func TestPECallsEncodeThePrologueCallsAndEpilogue(t *testing.T) {
	data := PE(PEOptions{
		Imports: []PEImport{{Library: "KERNEL32.dll", Functions: []string{"OpenProcess", "VirtualAllocEx"}}},
		Calls: []PECall{
			{Function: "OpenProcess", Args: []PEArg{{PEArgImm, 0x1fffff}, {Kind: PEArgZero}, {PEArgImm, 0x1a4}}},
			{Function: "KERNEL32.dll!VirtualAllocEx", Thunk: true, Args: []PEArg{
				{PEArgResult, 0}, {Kind: PEArgZero}, {PEArgImm, 0x1000}, {PEArgImm, 0x3000}, {PEArgImm, 0x40},
			}},
		},
	})
	// By hand. The import address table of this image starts at RVA 0x2080: OpenProcess
	// is the slot at 0x2080 and VirtualAllocEx the one at 0x2088. .text is at RVA 0x1000.
	// The entry point is "xor eax, eax; ret" and the stub starts at 0x10. Five arguments
	// make the outgoing area 0x28 bytes and two locals bring the frame to 0x38 (8 modulo
	// 16, as the return address makes rsp on entry).
	//
	//	0x00  xor eax, eax; ret        then int3 padding up to 0x10
	//	0x10  sub rsp, 0x38
	//	0x14  mov ecx, 0x1fffff        0x19  xor edx, edx          0x1b  mov r8d, 0x1a4
	//	0x21  call [rip+0x1059]        slot 0x2080 - next 0x1027
	//	0x27  mov [rsp+0x28], rax      the result of call 0
	//	0x2c  mov rcx, [rsp+0x28]      0x31  xor edx, edx
	//	0x33  mov r8d, 0x1000          0x39  mov r9d, 0x3000       0x3f  mov dword ptr [rsp+0x20], 0x40
	//	0x47  call rel32 +0xc          thunk 0x58 - next 0x4c
	//	0x4c  mov [rsp+0x30], rax
	//	0x51  xor eax, eax             0x53  add rsp, 0x38         0x57  ret
	//	0x58  jmp [rip+0x102a]         slot 0x2088 - next 0x105e
	want := hexBytes(t, `31 c0 c3  cc cc cc cc cc cc cc cc cc cc cc cc cc
		48 83 ec 38
		b9 ff ff 1f 00  31 d2  41 b8 a4 01 00 00
		ff 15 59 10 00 00
		48 89 44 24 28
		48 8b 4c 24 28  31 d2  41 b8 00 10 00 00  41 b9 00 30 00 00  c7 44 24 20 40 00 00 00
		e8 0c 00 00 00
		48 89 44 24 30
		31 c0  48 83 c4 38  c3
		ff 25 2a 10 00 00`)
	text := textOf(t, data)
	if len(text) != 0x200 {
		t.Fatalf(".text is %#x bytes, want the usual 0x200", len(text))
	}
	if !bytes.Equal(text[:len(want)], want) {
		t.Fatalf(".text starts with\n%x\nwant\n%x", text[:len(want)], want)
	}
	if rest := text[len(want):]; len(bytes.Trim(rest, "\xcc")) != 0 {
		t.Errorf("the rest of .text must be int3 padding: %x", rest)
	}
}

func TestPECallsDataArgumentAndSlotDisplacement(t *testing.T) {
	data := PE(PEOptions{Calls: []PECall{{Function: "ExitProcess", Args: []PEArg{{PEArgData, 8}}}}})
	// ExitProcess is the slot at RVA 0x2068 (see the layout in the parser tests) and .data
	// is at RVA 0x3000. The stub starts at 0x10, so lea rcx ends at 0x101b: 0x3008 - 0x101b =
	// 0x1fed. The call ends at 0x1021: 0x2068 - 0x1021 = 0x1047.
	want := hexBytes(t, `31 c0 c3  cc cc cc cc cc cc cc cc cc cc cc cc cc
		48 83 ec 28
		48 8d 0d ed 1f 00 00
		ff 15 47 10 00 00
		48 89 44 24 20
		31 c0  48 83 c4 28  c3`)
	if text := textOf(t, data); !bytes.Equal(text[:len(want)], want) {
		t.Fatalf(".text starts with\n%x\nwant\n%x", text[:len(want)], want)
	}
}

func TestPEDiscardedResultsAreNotStored(t *testing.T) {
	data := PE(PEOptions{Calls: []PECall{{Function: "ExitProcess", Discard: true, Args: []PEArg{{Kind: PEArgZero}}}}})
	// Nothing is kept, so the frame is the 0x20 bytes of shadow space padded to 0x28; the call ends at
	// 0x101c and the slot is at 0x2068: 0x2068 - 0x101c = 0x104c. There is no store after the call.
	want := hexBytes(t, "31 c0 c3  cc cc cc cc cc cc cc cc cc cc cc cc cc  48 83 ec 28  31 c9  ff 15 4c 10 00 00  31 c0  48 83 c4 28  c3")
	if text := textOf(t, data); !bytes.Equal(text[:len(want)], want) {
		t.Fatalf(".text starts with\n%x\nwant\n%x", text[:len(want)], want)
	}
}

func TestPEArgumentEncodings(t *testing.T) {
	tests := []struct {
		name string
		arg  PEArg
		pos  int
		want string
	}{
		{"zero rcx", PEArg{Kind: PEArgZero}, 0, "31 c9"},
		{"zero rdx", PEArg{Kind: PEArgZero}, 1, "31 d2"},
		{"zero r8", PEArg{Kind: PEArgZero}, 2, "45 31 c0"},
		{"zero r9", PEArg{Kind: PEArgZero}, 3, "45 31 c9"},
		{"zero stack 5th", PEArg{Kind: PEArgZero}, 4, "48 c7 44 24 20 00 00 00 00"},
		{"zero stack 6th", PEArg{Kind: PEArgZero}, 5, "48 c7 44 24 28 00 00 00 00"},
		{"imm rcx", PEArg{PEArgImm, 0x11223344}, 0, "b9 44 33 22 11"},
		{"imm rdx", PEArg{PEArgImm, 0x11223344}, 1, "ba 44 33 22 11"},
		{"imm r8", PEArg{PEArgImm, 0x11223344}, 2, "41 b8 44 33 22 11"},
		{"imm r9", PEArg{PEArgImm, 0x11223344}, 3, "41 b9 44 33 22 11"},
		{"imm stack 5th", PEArg{PEArgImm, 0x11223344}, 4, "c7 44 24 20 44 33 22 11"},
		{"imm stack 7th", PEArg{PEArgImm, 0x11223344}, 6, "c7 44 24 30 44 33 22 11"},
		{"data rcx", PEArg{PEArgData, 0}, 0, "48 8d 0d 00 00 00 00"},
		{"data rdx", PEArg{PEArgData, 0}, 1, "48 8d 15 00 00 00 00"},
		{"data r8", PEArg{PEArgData, 0}, 2, "4c 8d 05 00 00 00 00"},
		{"data r9", PEArg{PEArgData, 0}, 3, "4c 8d 0d 00 00 00 00"},
		{"result rcx", PEArg{PEArgResult, 0}, 0, "48 8b 4c 24 28"},
		{"result rdx", PEArg{PEArgResult, 0}, 1, "48 8b 54 24 28"},
		{"result r8", PEArg{PEArgResult, 0}, 2, "4c 8b 44 24 28"},
		{"result r9", PEArg{PEArgResult, 0}, 3, "4c 8b 4c 24 28"},
	}
	local := func(i int) (byte, bool) { return byte(0x28 + 8*i), true }
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &peStub{}
			s.setArg(tc.pos, tc.arg, 1, local)
			if want := hexBytes(t, tc.want); !bytes.Equal(s.code, want) {
				t.Errorf("encoded %x, want %x", s.code, want)
			}
		})
	}
}

func TestPECallsRejectWhatTheStubCannotDo(t *testing.T) {
	imports := []PEImport{{Library: "k.dll", Functions: []string{"A"}}}
	tests := map[string]PEOptions{
		"unknown import":      {Imports: imports, Calls: []PECall{{Function: "B"}}},
		"32-bit image":        {Imports: imports, Bits: 32, Calls: []PECall{{Function: "A"}}},
		"too many calls":      {Imports: imports, Calls: make([]PECall, peMaxCalls+1)},
		"too many arguments":  {Imports: imports, Calls: []PECall{{Function: "A", Args: make([]PEArg, peMaxArgs+1)}}},
		"result not ready":    {Imports: imports, Calls: []PECall{{Function: "A", Args: []PEArg{{PEArgResult, 0}}}}},
		"data on the stack":   {Imports: imports, Calls: []PECall{{Function: "A", Args: []PEArg{{}, {}, {}, {}, {PEArgData, 0}}}}},
		"unknown kind":        {Imports: imports, Calls: []PECall{{Function: "A", Args: []PEArg{{Kind: 99}}}}},
		"library mismatch":    {Imports: imports, Calls: []PECall{{Function: "other.dll!A"}}},
		"result of the later": {Imports: imports, Calls: []PECall{{Function: "A"}, {Function: "A", Args: []PEArg{{PEArgResult, 1}}}}},
		"discarded result":    {Imports: imports, Calls: []PECall{{Function: "A", Discard: true}, {Function: "A", Args: []PEArg{{PEArgResult, 0}}}}},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected a panic: a fixture that cannot be built must say so")
				}
			}()
			PE(opts)
		})
	}
}

func TestPEWithoutCallsKeepsTheDefaultCode(t *testing.T) {
	text := textOf(t, PE(PEOptions{}))
	if len(text) != 0x200 || !bytes.Equal(text[:3], []byte{0x31, 0xc0, 0xc3}) || len(bytes.Trim(text[3:], "\xcc")) != 0 {
		t.Fatalf("default .text = %x", text)
	}
}
