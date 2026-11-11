package testfixtures

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// PEArgKind says how one argument of a [PECall] is set up before the call.
type PEArgKind uint8

// The ways to set up an argument. The first four arguments travel in rcx, rdx,
// r8 and r9; the others are stored above the 32-byte shadow space at the top of
// the stack frame, as the Windows x64 calling convention says.
const (
	// PEArgZero passes zero: "xor ecx, ecx" for a register, a zeroed stack slot otherwise.
	PEArgZero PEArgKind = iota
	// PEArgImm passes the constant Value: "mov ecx, imm32" or "mov dword ptr [rsp+disp], imm32".
	PEArgImm
	// PEArgData passes the address of byte Value of the .data section: "lea rcx, [rip+disp32]". Registers only.
	PEArgData
	// PEArgResult passes the result of the call numbered Value (from 0), which the stub
	// saved in its frame: "mov rcx, qword ptr [rsp+disp8]". Registers only.
	PEArgResult
)

// PEArg is one argument of a [PECall].
type PEArg struct {
	Kind  PEArgKind
	Value uint32
}

// PECall is one call made by the code stub of a fixture (see [PEOptions].Calls).
type PECall struct {
	// Function is the imported function to call, "Name" or "Library!Name" (the
	// library compared without regard to case). It must be one of the fixture's
	// regular imports.
	Function string
	// Args set up the arguments in order; at most eight.
	Args []PEArg
	// Thunk makes the call go through an import thunk: "call rel32" to a stub
	// "jmp qword ptr [rip+disp32]" placed after the function, the way some linkers
	// emit imports, instead of "call qword ptr [rip+disp32]" through the slot.
	Thunk bool
	// Discard drops the result: the stub stores the result of a call in its frame
	// (so that [PEArgResult] can pass it on) unless Discard is set, the way a
	// compiler stores only what later code uses.
	Discard bool
}

// Limits of the stub: its frame must fit a signed 8-bit displacement and its
// code the one page that .text owns in the fixture layout.
const (
	peMaxArgs  = 8
	peMaxCalls = 16
	peMaxText  = 0x1000
	// peStubOffset is where the stub starts in .text, behind the entry point's "xor eax, eax; ret".
	peStubOffset = 0x10
)

type peFixKind uint8

const (
	peFixSlot peFixKind = iota // displacement to an import address table slot
	peFixData                  // displacement to a byte of .data
)

// peFix is a 32-bit RIP-relative field whose value is known once the sections
// have their addresses.
type peFix struct {
	at, end int // offsets in the code of the field and of the end of its instruction
	kind    peFixKind
	fn      string // peFixSlot: the function, as given in PECall.Function
	data    uint32 // peFixData: the offset in .data
}

// peStub is the code of a fixture and the fields still to patch.
type peStub struct {
	code  []byte
	fixes []peFix
}

func (s *peStub) emit(b ...byte) { s.code = append(s.code, b...) }

func (s *peStub) u32(v uint32) { s.code = binary.LittleEndian.AppendUint32(s.code, v) }

// field writes a placeholder for a 32-bit RIP-relative field and records it.
func (s *peStub) field(f peFix) {
	f.at, f.end = len(s.code), len(s.code)+4
	s.u32(0)
	s.fixes = append(s.fixes, f)
}

// Encodings written from the Intel Software Developer's Manual (vol. 2, the
// opcode map and the ModRM tables), one entry per Windows x64 argument register
// (rcx, rdx, r8, r9).
var (
	// xor r32, r32 (31 /r with the register in both fields).
	peXorReg = [4][]byte{{0x31, 0xC9}, {0x31, 0xD2}, {0x45, 0x31, 0xC0}, {0x45, 0x31, 0xC9}}
	// mov r32, imm32 (B8+rd id; REX.B 0x41 selects r8 and r9).
	peMovImmReg = [4][]byte{{0xB9}, {0xBA}, {0x41, 0xB8}, {0x41, 0xB9}}
	// lea r64, [rip+disp32] (REX.W 8D /r, ModRM mod 00 rm 101).
	peLeaReg = [4][]byte{{0x48, 0x8D, 0x0D}, {0x48, 0x8D, 0x15}, {0x4C, 0x8D, 0x05}, {0x4C, 0x8D, 0x0D}}
	// mov r64, qword ptr [rsp+disp8] (REX.W 8B /r, ModRM mod 01 rm 100, SIB 24); disp8 follows.
	peLoadReg = [4][]byte{{0x48, 0x8B, 0x4C, 0x24}, {0x48, 0x8B, 0x54, 0x24}, {0x4C, 0x8B, 0x44, 0x24}, {0x4C, 0x8B, 0x4C, 0x24}}
)

// peAssemble writes the stub: a frame, each call with its argument set-up and
// the result saved in a local, an epilogue and the import thunks. Displacements
// that need the section addresses are left as fixes.
func peAssemble(calls []PECall) *peStub {
	if len(calls) > peMaxCalls {
		panic(fmt.Sprintf("testfixtures: %d calls, at most %d", len(calls), peMaxCalls))
	}
	maxArgs := 4
	for _, c := range calls {
		if len(c.Args) > peMaxArgs {
			panic(fmt.Sprintf("testfixtures: %d arguments, at most %d", len(c.Args), peMaxArgs))
		}
		maxArgs = max(maxArgs, len(c.Args))
	}
	outgoing := 0x20 + 8*(maxArgs-4) // shadow space and the stack arguments
	slots := make([]int, len(calls)) // the local that keeps the result of each call, -1 when discarded
	kept := 0
	for i, c := range calls {
		slots[i] = -1
		if !c.Discard {
			slots[i] = kept
			kept++
		}
	}
	frame := outgoing + 8*kept // plus one local per kept result
	for frame%16 != 8 {        // the return address makes rsp 8 (mod 16) on entry
		frame += 8
	}
	if frame > 0x7f {
		panic("testfixtures: the stub frame does not fit a signed 8-bit displacement")
	}
	local := func(i int) (byte, bool) { // fits: outgoing + 8*kept <= frame <= 0x7f
		if slots[i] < 0 {
			return 0, false
		}
		return byte(outgoing + 8*slots[i]), true
	}

	s := &peStub{}
	// The entry point is still "xor eax, eax; ret": the image does nothing when
	// started, and the stub behind it is dead code that is only meant to be read.
	s.emit(0x31, 0xC0, 0xC3)
	for len(s.code) < peStubOffset {
		s.emit(0xCC)
	}
	s.emit(0x48, 0x83, 0xEC, byte(frame)) // sub rsp, frame
	type thunkCall struct{ at, end, thunk int }
	var thunkCalls []thunkCall
	var thunks []string
	for i, c := range calls {
		for n, a := range c.Args {
			s.setArg(n, a, i, local)
		}
		if c.Thunk {
			j := indexOf(thunks, c.Function)
			if j < 0 {
				thunks = append(thunks, c.Function)
				j = len(thunks) - 1
			}
			s.emit(0xE8) // call rel32
			thunkCalls = append(thunkCalls, thunkCall{at: len(s.code), end: len(s.code) + 4, thunk: j})
			s.u32(0)
		} else {
			s.emit(0xFF, 0x15) // call qword ptr [rip+disp32]
			s.field(peFix{kind: peFixSlot, fn: c.Function})
		}
		if disp, ok := local(i); ok {
			s.emit(0x48, 0x89, 0x44, 0x24, disp) // mov qword ptr [rsp+local], rax
		}
	}
	s.emit(0x31, 0xC0)                    // xor eax, eax
	s.emit(0x48, 0x83, 0xC4, byte(frame)) // add rsp, frame
	s.emit(0xC3)                          // ret

	offsets := make([]int, len(thunks))
	for j, fn := range thunks {
		for len(s.code)%8 != 0 {
			s.emit(0xCC) // int3 padding, as linkers align thunks
		}
		offsets[j] = len(s.code)
		s.emit(0xFF, 0x25) // jmp qword ptr [rip+disp32]
		s.field(peFix{kind: peFixSlot, fn: fn})
	}
	for _, tc := range thunkCalls {
		binary.LittleEndian.PutUint32(s.code[tc.at:], uint32(int32(offsets[tc.thunk]-tc.end))) // a small signed distance
	}
	for len(s.code)%peFileAlign != 0 || len(s.code) < peTextSize {
		s.emit(0xCC)
	}
	if len(s.code) > peMaxText {
		panic(fmt.Sprintf("testfixtures: the stub is %d bytes, at most %d", len(s.code), peMaxText))
	}
	return s
}

// setArg writes the instruction that sets argument n of call number call.
func (s *peStub) setArg(n int, a PEArg, call int, local func(int) (byte, bool)) {
	if n < 4 {
		switch a.Kind {
		case PEArgZero:
			s.emit(peXorReg[n]...)
		case PEArgImm:
			s.emit(peMovImmReg[n]...)
			s.u32(a.Value)
		case PEArgData:
			s.emit(peLeaReg[n]...)
			s.field(peFix{kind: peFixData, data: a.Value})
		case PEArgResult:
			if int(a.Value) >= call {
				panic(fmt.Sprintf("testfixtures: call %d uses the result of call %d, which has not run yet", call, a.Value))
			}
			disp, ok := local(int(a.Value))
			if !ok {
				panic(fmt.Sprintf("testfixtures: call %d uses the result of call %d, which is discarded", call, a.Value))
			}
			s.emit(peLoadReg[n]...)
			s.emit(disp)
		default:
			panic(fmt.Sprintf("testfixtures: unknown argument kind %d", a.Kind))
		}
		return
	}
	disp := byte(0x20 + 8*(n-4)) // the stack arguments sit above the shadow space
	switch a.Kind {
	case PEArgZero:
		s.emit(0x48, 0xC7, 0x44, 0x24, disp, 0, 0, 0, 0) // mov qword ptr [rsp+disp8], 0
	case PEArgImm:
		s.emit(0xC7, 0x44, 0x24, disp) // mov dword ptr [rsp+disp8], imm32
		s.u32(a.Value)
	default:
		panic(fmt.Sprintf("testfixtures: argument %d lives on the stack: only zero and constants are supported there", n))
	}
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// patch fills the RIP-relative fields once the fixture layout is known: textRVA
// and dataRVA are the section addresses and slot returns the address of an import
// address table slot.
func (s *peStub) patch(textRVA, dataRVA uint32, slot func(fn string) (uint32, bool)) {
	for _, f := range s.fixes {
		var target uint32
		switch f.kind {
		case peFixSlot:
			rva, ok := slot(f.fn)
			if !ok {
				panic(fmt.Sprintf("testfixtures: the fixture does not import %q", f.fn))
			}
			target = rva
		case peFixData:
			target = dataRVA + f.data
		}
		next := textRVA + uint32(f.end) // the displacement counts from the end of the instruction
		binary.LittleEndian.PutUint32(s.code[f.at:], target-next)
	}
}

// peSlot is the import address table slot of one imported function.
type peSlot struct {
	library, function string
	rva               uint32
}

// peSlotLookup returns the function that finds the slot of "Name" or
// "Library!Name" among slots.
func peSlotLookup(slots []peSlot) func(string) (uint32, bool) {
	return func(name string) (uint32, bool) {
		lib, fn, qualified := strings.Cut(name, "!")
		if !qualified {
			lib, fn = "", name
		}
		for _, s := range slots {
			if s.function == fn && (lib == "" || strings.EqualFold(s.library, lib)) {
				return s.rva, true
			}
		}
		return 0, false
	}
}
