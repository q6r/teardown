// Package disasm is a small x86 and x86-64 instruction decoder with Intel-syntax
// output, built to show the code around a call site. It is not a full
// disassembler: linear sweep only, no decompilation, no emulation, and it never
// executes anything.
//
// # Coverage
//
// Both [Mode64] and [Mode32] are supported. The decoder understands the legacy
// prefixes, REX, ModRM and SIB addressing (including RIP-relative operands in
// 64-bit mode and absolute 32-bit operands), the whole one-byte opcode map, the
// x87 escape opcodes, the two-byte (0F) map including the common SSE and SSE2
// instructions and the SSE3 to SSE4.2, AES-NI, PCLMULQDQ, SHA and BMI integer
// extensions of the three-byte maps (0F 38 and 0F 3A).
//
// VEX (C4 and C5) and EVEX (62) encodings always get the correct length. VEX
// instructions whose legacy SSE counterpart is modelled, the common AVX2 moves,
// compares and shuffles, the FMA family and a few BMI forms get a mnemonic and
// operands. Every other VEX or EVEX instruction is reported with Valid true and
// a generic mnemonic: "vex" or "evex" with the operand text
// "<map>.<pp>.<opcode>" (for example "0f38.66.2c"), which names the encoding
// without claiming to know the operation.
//
// # What it does not do
//
// Bytes that are not understood become a one-byte "db 0xNN" with Valid false and
// decoding resynchronises on the next byte; a linear sweep over data therefore
// produces plausible-looking but meaningless instructions, and a sweep can lose
// synchronisation after one of them. Not covered: 3DNow!, XOP, AVX-512 operand
// decoding, the VMX, SGX and TSX families beyond a few fixed forms, APX, and any
// non-x86 architecture. Branch targets are reported as encoded; nothing is
// resolved or emulated.
//
// # Guarantees
//
// Decode never panics, never reads past the slice it is given, and never looks at
// more than 15 bytes. The output text is plain ASCII. DecodeAll is bounded by
// [MaxInstructions].
//
// # Reading the result
//
// Use [Inst.Flow], [Inst.Indirect], [Inst.HasTarget], [Inst.HasRipRef] and
// [Inst.HasAbsRef] to find calls and references, not the mnemonic text: prefixes
// that stay unconsumed are part of the mnemonic ("lock cmpxchg", "rep movs",
// "bnd jmp", "repz ret"). HasAbsRef marks a memory operand with an absolute
// address and no base or index register, in both modes (the 64-bit form is a SIB
// byte with no base and no index); it is not set when an fs or gs override makes
// the number a segment offset rather than an address.
package disasm

// Mode selects the processor mode the code is decoded for.
type Mode uint8

// Processor modes.
const (
	Mode64 Mode = 64
	Mode32 Mode = 32
)

// Flow tells how an instruction changes control flow.
type Flow uint8

// Control-flow classes.
const (
	FlowNone     Flow = iota // falls through
	FlowCall                 // call, direct or indirect
	FlowJump                 // jmp, direct or indirect
	FlowCondJump             // jcc, loop, jcxz
	FlowRet                  // ret, retf, iret
	FlowTrap                 // int3, int n, ud2, hlt
)

// String returns a short lower-case name for the flow class.
func (f Flow) String() string {
	switch f {
	case FlowNone:
		return "none"
	case FlowCall:
		return "call"
	case FlowJump:
		return "jump"
	case FlowCondJump:
		return "condjump"
	case FlowRet:
		return "ret"
	case FlowTrap:
		return "trap"
	}
	return "unknown"
}

// Limits of the decoder.
const (
	// MaxInstLen is the longest instruction the processor accepts.
	MaxInstLen = 15
	// MaxInstructions caps the instructions returned by one call to [DecodeAll],
	// whatever max the caller passes. Use [Decode] in a loop for longer sweeps.
	MaxInstructions = 1 << 16
)

// Inst is one decoded instruction.
type Inst struct {
	Addr     uint64 // virtual address of the first byte, as passed in
	Len      int    // encoded length, 1..15, never 0 for non-empty input
	Bytes    []byte // the encoded bytes, a sub-slice of the input
	Mnemonic string // lower case; "db" when the bytes are not understood
	Operands string // Intel-syntax operands, empty when there are none
	Text     string // Mnemonic, a space, Operands (no trailing space), e.g. "call qword ptr [rip+0x1fb7]"
	Flow     Flow
	Valid    bool // false for the "db" fallback (Len is then 1)

	HasTarget bool   // direct rel8/rel32 call, jmp or jcc
	Target    uint64 // absolute virtual address of that target

	Indirect bool // call or jmp through a register or a memory operand

	HasRipRef bool   // x86-64 RIP-relative memory operand
	RipRef    uint64 // the absolute virtual address it refers to (Addr + Len + disp)

	HasAbsRef bool   // memory operand with an absolute 32-bit address and no base or index register (32-bit "call dword ptr [abs]")
	AbsRef    uint64 // that address
}

// Decode decodes one instruction at the start of code. It never panics and never reads past code.
// For empty input it returns the zero Inst. For bytes it does not understand it returns a one-byte "db 0xNN" with Valid false.
//
// Any mode other than [Mode32] is treated as [Mode64]. Prefix bytes are part of the
// instruction they precede: they are included in Len and Bytes, and lock, rep and
// bnd prefixes appear in front of the mnemonic ("lock cmpxchg", "rep stos").
func Decode(mode Mode, code []byte, addr uint64) Inst {
	if len(code) == 0 {
		return Inst{}
	}
	d := decoder{mode: mode, code: code, addr: addr, limit: min(len(code), MaxInstLen)}
	if d.mode != Mode32 {
		d.mode = Mode64
	}
	if in, ok := d.decode(); ok && in.Len >= 1 && in.Len <= d.limit {
		in.Bytes = code[:in.Len:in.Len]
		return in
	}
	return invalidInst(code, addr)
}

// DecodeAll decodes consecutive instructions (linear sweep) until code is consumed or max instructions were produced (max <= 0 means a hard internal cap).
// An undecodable byte becomes "db 0xNN" and decoding resynchronises on the next byte.
//
// The result never holds more than [MaxInstructions] instructions.
func DecodeAll(mode Mode, code []byte, addr uint64, max int) []Inst {
	if max <= 0 || max > MaxInstructions {
		max = MaxInstructions
	}
	// Every instruction takes at least one byte, so len(code) bounds the count.
	out := make([]Inst, 0, min(max, len(code), 64))
	for off := 0; off < len(code) && len(out) < max; {
		in := Decode(mode, code[off:], addr+uint64(off))
		out = append(out, in)
		off += in.Len
	}
	return out
}

// invalidInst is the "db 0xNN" fallback for the first byte of code (len(code) >= 1).
func invalidInst(code []byte, addr uint64) Inst {
	const digits = "0123456789abcdef"
	b := code[0]
	ops := "0x" + string([]byte{digits[b>>4], digits[b&15]})
	return Inst{
		Addr:     addr,
		Len:      1,
		Bytes:    code[:1:1],
		Mnemonic: "db",
		Operands: ops,
		Text:     "db " + ops,
	}
}
