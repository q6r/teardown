package disasm

import (
	"fmt"
	"strings"
)

// The opcode maps are written as short specification strings that read like the
// opcode tables of the architecture manuals and are turned into entry values once,
// when the package is initialised. A specification is
//
//	variants := variant { "|" variant }      up to four: none, 66, F3, F2 (mandatory prefix)
//	variant  := leaf | leaf ";" leaf         memory form ";" register form (mod == 3)
//	leaf     := "@group" flags | mnemonic [operands] flags
//
// An empty variant or leaf is an invalid encoding. The mnemonic may be three names
// separated by "/" that are chosen by operand size (16/32/64), or by address size
// with the asz flag. Operands are comma separated names from operandTable.
// Flags are the lower-case words of flagNames.
//
// A mistake in a table is a programming error, found by the first test run: the
// parser panics at initialisation. Nothing here depends on the bytes being decoded.

// opSize describes the width of an operand.
type opSize uint8

const (
	szNone opSize = iota
	sz8           // byte
	sz16          // word
	sz32          // dword
	sz64          // qword
	szV           // operand size: 16, 32 or 64 bits
	szY           // 32 bits, or 64 with REX.W
	szZ           // 16 or 32 bits, never 64
	szN           // native width: 64 in 64-bit mode, 32 in 32-bit mode
	sz80          // tbyte
	sz128         // xmmword
	szX           // vector length: xmm, ymm or zmm
	szFar         // far pointer m16:16, m16:32 or m16:64
	szDW          // a 32-bit register or a word in memory
	szDB          // a 32-bit register or a byte in memory
	szVW          // a register of operand size or a word in memory
	szS           // scalar float: dword, or qword with VEX.W
)

// opClass is the kind of an operand, named after the manual's operand letters.
type opClass uint8

const (
	_           opClass = iota // the zero value is not an operand
	cE                         // ModRM r/m: register or memory
	cG                         // ModRM reg: general register
	cR                         // ModRM r/m: general register only
	cM                         // ModRM r/m: memory only
	cSeg                       // ModRM reg: segment register
	cCR                        // ModRM reg: control register
	cDR                        // ModRM reg: debug register
	cImm                       // immediate of the encoded width
	cImmS                      // 8-bit immediate sign-extended to the operand size
	cOne                       // the constant 1
	cRel                       // relative branch displacement
	cMoffs                     // absolute memory offset
	cFarPtr                    // seg:offset immediate
	cZ                         // register in the low bits of the opcode
	cFixed                     // fixed general register
	cFixSeg                    // fixed segment register
	cStrX                      // string source [rsi]
	cStrY                      // string destination [rdi]
	cMMReg                     // MMX register from ModRM reg
	cMMRM                      // MMX register or memory from ModRM r/m
	cMMRegOnly                 // MMX register from ModRM r/m, mod == 3
	cVecReg                    // vector register from ModRM reg
	cVecRM                     // vector register or memory from ModRM r/m
	cVecRegOnly                // vector register from ModRM r/m, mod == 3
	cVecVVVV                   // vector register from VEX.vvvv
	cVecIS4                    // vector register from the top four bits of an 8-bit immediate
	cGprVVVV                   // general register from VEX.vvvv
	cXmm0                      // the register xmm0
)

// opd is one operand of an instruction form.
type opd struct {
	c opClass
	s opSize
	n uint8 // register number for cFixed and cFixSeg
}

// usesModRM reports whether an operand of this class is encoded in a ModRM byte.
func (c opClass) usesModRM() bool {
	switch c {
	case cE, cG, cR, cM, cSeg, cCR, cDR, cMMReg, cMMRM, cMMRegOnly, cVecReg, cVecRM, cVecRegOnly:
		return true
	}
	return false
}

// flag is a property of an instruction form.
type flag uint16

const (
	fD64      flag = 1 << iota // operand size defaults to 64 bits in 64-bit mode (push, pop, call, ret)
	fF64                       // operand size is 64 bits in 64-bit mode, whatever the prefixes
	fInv64                     // not valid in 64-bit mode
	fRep                       // string instruction: F3 is "rep", F2 is "repne"
	fRepCC                     // comparing string instruction: F3 is "repe", F2 is "repne"
	fBranch                    // F2 is the "bnd" prefix
	fNDS                       // the VEX form has a second source in VEX.vvvv
	fNDD                       // the VEX form has its destination in VEX.vvvv
	fKeep66                    // the 66 prefix selecting this variant is also an operand-size prefix
	fWQ                        // the mnemonic ends in q instead of d when REX.W is set
	fForceReg                  // the ModRM mod field is ignored: the operand is a register
	fMnv                       // the mnemonic depends on the operand size
	fAsz                       // the mnemonic depends on the address size
)

var flagNames = map[string]flag{
	"d64": fD64, "f64": fF64, "inv64": fInv64, "rep": fRep, "repcc": fRepCC, "br": fBranch,
	"nds": fNDS, "ndd": fNDD, "keep66": fKeep66, "wq": fWQ, "forcereg": fForceReg, "asz": fAsz,
}

// entry is one node of an opcode map: either a leaf describing an instruction
// form, or an indirection selected by the mandatory prefix (pfx), the ModRM reg
// field (grp) or the ModRM mod field (mod).
type entry struct {
	mn    string
	mnv   [3]string // mnemonics by operand size 16/32/64 (or address size) when flags has fMnv
	ops   [4]opd
	n     uint8 // number of operands
	flags flag
	flow  Flow
	modrm bool // a ModRM byte follows the opcode

	pfx *[4]entry // by mandatory prefix: none, 66, F3, F2
	grp *[8]entry // by ModRM reg
	mod *[2]entry // by ModRM mod: memory, register
}

// parser turns specification strings into entries.
type parser struct {
	groups map[string][8]string
}

func (p *parser) fail(spec, why string) {
	panic(fmt.Sprintf("disasm: bad table specification %q: %s", spec, why))
}

// parse handles the whole variants grammar.
func (p *parser) parse(spec string) entry {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return entry{}
	}
	if !strings.Contains(spec, "|") {
		return p.parseVariant(spec)
	}
	parts := strings.Split(spec, "|")
	if len(parts) > 4 {
		p.fail(spec, "more than four prefix variants")
	}
	var arr [4]entry
	for i, s := range parts {
		arr[i] = p.parseVariant(s)
	}
	return entry{pfx: &arr}
}

func (p *parser) parseVariant(spec string) entry {
	spec = strings.TrimSpace(spec)
	if before, after, ok := strings.Cut(spec, ";"); ok {
		return entry{mod: &[2]entry{p.parseLeaf(before), p.parseLeaf(after)}}
	}
	return p.parseLeaf(spec)
}

func (p *parser) parseLeaf(spec string) entry {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return entry{}
	}
	if name, ok := strings.CutPrefix(fields[0], "@"); ok {
		g, found := p.groups[name]
		if !found {
			p.fail(spec, "unknown group")
		}
		var arr [8]entry
		for i, s := range g {
			arr[i] = p.parse(s)
		}
		return entry{grp: &arr, flags: p.flags(spec, fields[1:])}
	}

	var e entry
	e.mn = fields[0]
	if strings.Contains(e.mn, "/") {
		parts := strings.Split(e.mn, "/")
		if len(parts) != 3 {
			p.fail(spec, "a mnemonic with variants needs three names")
		}
		copy(e.mnv[:], parts)
		e.mn = parts[1]
		e.flags |= fMnv
	}
	rest := fields[1:]
	if len(rest) > 0 && rest[0][0] >= 'A' && rest[0][0] <= 'Z' {
		names := strings.Split(rest[0], ",")
		if len(names) > len(e.ops) {
			p.fail(spec, "too many operands")
		}
		for _, nm := range names {
			o, ok := operandTable[nm]
			if !ok {
				p.fail(spec, "unknown operand "+nm)
			}
			e.ops[e.n] = o
			e.n++
			if o.c.usesModRM() {
				e.modrm = true
			}
		}
		rest = rest[1:]
	}
	e.flags |= p.flags(spec, rest)
	if e.flags&fAsz != 0 {
		e.flags |= fMnv
	}
	e.flow = flowOf(e.mn)
	return e
}

func (p *parser) flags(spec string, words []string) flag {
	var f flag
	for _, w := range words {
		v, ok := flagNames[w]
		if !ok {
			p.fail(spec, "unknown flag "+w)
		}
		f |= v
	}
	return f
}

// condNames are the sixteen condition-code suffixes in encoding order.
var condNames = [16]string{"o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"}

// flowOf classifies a mnemonic by its effect on control flow.
func flowOf(mn string) Flow {
	switch mn {
	case "call":
		return FlowCall
	case "jmp":
		return FlowJump
	case "ret", "retf", "iretw", "iretd", "iretq", "sysret", "sysretq", "sysexit":
		return FlowRet
	case "int3", "int", "into", "int1", "ud0", "ud1", "ud2", "hlt":
		return FlowTrap
	case "loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz", "xbegin":
		return FlowCondJump
	}
	if len(mn) >= 2 && mn[0] == 'j' {
		for _, c := range condNames {
			if mn[1:] == c {
				return FlowCondJump
			}
		}
	}
	return FlowNone
}

// operandTable maps the operand names used in the specifications to their meaning.
var operandTable = map[string]opd{
	// ModRM r/m, register or memory
	"Eb": {cE, sz8, 0}, "Ew": {cE, sz16, 0}, "Ed": {cE, sz32, 0},
	"Ev": {cE, szV, 0}, "Ey": {cE, szY, 0}, "Edw": {cE, szDW, 0}, "Edb": {cE, szDB, 0}, "Evw": {cE, szVW, 0},
	// ModRM reg
	"Gb": {cG, sz8, 0}, "Gw": {cG, sz16, 0}, "Gd": {cG, sz32, 0},
	"Gv": {cG, szV, 0}, "Gy": {cG, szY, 0},
	// ModRM r/m, register only
	"Rv": {cR, szV, 0}, "Ry": {cR, szY, 0}, "Rr": {cR, szN, 0},
	// ModRM r/m, memory only
	"M": {cM, szNone, 0}, "Mb": {cM, sz8, 0}, "Md": {cM, sz32, 0}, "Mq": {cM, sz64, 0},
	"Mv": {cM, szV, 0}, "My": {cM, szY, 0}, "Mo": {cM, sz128, 0}, "Mx": {cM, szX, 0},
	"Mp": {cM, szFar, 0},
	// special registers
	"Sw": {cSeg, szNone, 0}, "Cd": {cCR, szNone, 0}, "Dd": {cDR, szNone, 0},
	// immediates and relative targets
	"Ib": {cImm, sz8, 0}, "Iw": {cImm, sz16, 0}, "Iz": {cImm, szZ, 0}, "Iv": {cImm, szV, 0},
	"Ibs": {cImmS, sz8, 0}, "One": {cOne, szNone, 0},
	"Jb": {cRel, sz8, 0}, "Jz": {cRel, szZ, 0},
	"Ob": {cMoffs, sz8, 0}, "Ov": {cMoffs, szV, 0}, "Ap": {cFarPtr, szZ, 0},
	// registers in the opcode and fixed registers
	"Zb": {cZ, sz8, 0}, "Zv": {cZ, szV, 0},
	"AL": {cFixed, sz8, 0}, "CL": {cFixed, sz8, 1}, "DX": {cFixed, sz16, 2},
	"Acc": {cFixed, szV, 0}, "AccD": {cFixed, szZ, 0},
	"ES": {cFixSeg, szNone, 0}, "CS": {cFixSeg, szNone, 1}, "SS": {cFixSeg, szNone, 2},
	"DS": {cFixSeg, szNone, 3}, "FS": {cFixSeg, szNone, 4}, "GS": {cFixSeg, szNone, 5},
	// string operands
	"Xb": {cStrX, sz8, 0}, "Xv": {cStrX, szV, 0}, "Xz": {cStrX, szZ, 0},
	"Yb": {cStrY, sz8, 0}, "Yv": {cStrY, szV, 0}, "Yz": {cStrY, szZ, 0},
	// MMX
	"Pq": {cMMReg, sz64, 0}, "Qq": {cMMRM, sz64, 0}, "Qd": {cMMRM, sz32, 0}, "Nq": {cMMRegOnly, sz64, 0},
	// SSE and AVX
	"Vx": {cVecReg, szX, 0}, "Wx": {cVecRM, szX, 0}, "Ux": {cVecRegOnly, szX, 0}, "Hx": {cVecVVVV, szX, 0},
	"Wq": {cVecRM, sz64, 0}, "Wd": {cVecRM, sz32, 0}, "Ww": {cVecRM, sz16, 0}, "Wb": {cVecRM, sz8, 0},
	"Ws": {cVecRM, szS, 0}, "Wo": {cVecRM, sz128, 0}, "Lx": {cVecIS4, szX, 0},
	"X0": {cXmm0, szNone, 0},
	// VEX.vvvv general register (BMI)
	"By": {cGprVVVV, szY, 0},
}

// tables holds every opcode map. It is built once and read-only afterwards.
type tables struct {
	one    [256]entry // one-byte map
	movsxd entry      // opcode 63 in 64-bit mode
	xchg90 entry      // opcode 90 with REX.B
	pause  entry      // F3 90
	x87    entry      // stands in for the x87 instructions, which are decoded by hand
	two    [256]entry // two-byte map (0F xx)
	t38    [256]entry // 0F 38 xx
	t3a    [256]entry // 0F 3A xx
	fixed  map[uint32]*entry

	vex1     [256]entry // VEX map 1 (0F), derived from two plus the AVX-only forms
	vex2     [256]entry // VEX map 2 (0F 38)
	vex3     [256]entry // VEX map 3 (0F 3A)
	vzeroall entry      // VEX.256 0F 77
}

// tbl is the decoder's instruction database.
var tbl = buildTables()

func buildTables() *tables {
	p := &parser{groups: groupSpecs()}
	t := &tables{fixed: make(map[uint32]*entry)}

	fill := func(dst *[256]entry, specs *[256]string) {
		for i, s := range specs {
			dst[i] = p.parse(s)
		}
	}
	one := oneByteSpecs()
	fill(&t.one, &one)
	t.movsxd = p.parse("movsxd Gv,Ed")
	t.xchg90 = p.parse("xchg Zv,Acc")
	t.pause = p.parse("pause")

	two := twoByteSpecs()
	fill(&t.two, &two)
	t38 := threeByte38Specs()
	fill(&t.t38, &t38)
	t3a := threeByte3ASpecs()
	fill(&t.t3a, &t3a)

	for key, spec := range fixedSpecs() {
		e := p.parse(spec)
		t.fixed[key] = &e
	}

	buildVEX(p, t)
	return t
}
