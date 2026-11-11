package disasm

// x87Mem is the memory form of the x87 escape opcodes D8 to DF, by opcode and ModRM reg.
// An empty mnemonic is an undefined encoding.
var x87Mem = [8][8]struct {
	mn string
	s  opSize
}{
	{ // D8: single-precision operand
		{"fadd", sz32}, {"fmul", sz32}, {"fcom", sz32}, {"fcomp", sz32}, {"fsub", sz32}, {"fsubr", sz32}, {"fdiv", sz32}, {"fdivr", sz32},
	},
	{ // D9
		{"fld", sz32}, {}, {"fst", sz32}, {"fstp", sz32}, {"fldenv", szNone}, {"fldcw", sz16}, {"fnstenv", szNone}, {"fnstcw", sz16},
	},
	{ // DA: 32-bit integer operand
		{"fiadd", sz32}, {"fimul", sz32}, {"ficom", sz32}, {"ficomp", sz32}, {"fisub", sz32}, {"fisubr", sz32}, {"fidiv", sz32}, {"fidivr", sz32},
	},
	{ // DB
		{"fild", sz32}, {"fisttp", sz32}, {"fist", sz32}, {"fistp", sz32}, {}, {"fld", sz80}, {}, {"fstp", sz80},
	},
	{ // DC: double-precision operand
		{"fadd", sz64}, {"fmul", sz64}, {"fcom", sz64}, {"fcomp", sz64}, {"fsub", sz64}, {"fsubr", sz64}, {"fdiv", sz64}, {"fdivr", sz64},
	},
	{ // DD
		{"fld", sz64}, {"fisttp", sz64}, {"fst", sz64}, {"fstp", sz64}, {"frstor", szNone}, {}, {"fnsave", szNone}, {"fnstsw", sz16},
	},
	{ // DE: 16-bit integer operand
		{"fiadd", sz16}, {"fimul", sz16}, {"ficom", sz16}, {"ficomp", sz16}, {"fisub", sz16}, {"fisubr", sz16}, {"fidiv", sz16}, {"fidivr", sz16},
	},
	{ // DF
		{"fild", sz16}, {"fisttp", sz16}, {"fist", sz16}, {"fistp", sz16}, {"fbld", sz80}, {"fild", sz64}, {"fbstp", sz80}, {"fistp", sz64},
	},
}

// x87Arith are the arithmetic operations of D8, by ModRM reg.
var x87Arith = [8]string{"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"}

// x87D9 are the register-less forms of D9 E0 to FF, by ModRM reg (4 to 7) and r/m.
var x87D9 = [4][8]string{
	{"fchs", "fabs", "", "", "ftst", "fxam", "", ""},
	{"fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", ""},
	{"f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp"},
	{"fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos"},
}

// decodeX87 decodes the escape opcodes D8 to DF.
func (d *decoder) decodeX87(op byte) (Inst, bool) {
	d.readModRM(false)
	if d.bad {
		return Inst{}, false
	}
	d.e = &tbl.x87
	ops := d.scratch[:0]
	var mn string
	if d.mod != 3 {
		f := x87Mem[op-0xD8][d.reg]
		if f.mn == "" {
			return Inst{}, false
		}
		mn = f.mn
		ops = d.appendMem(ops, f.s)
	} else {
		var text string
		mn, text = x87Reg(op, d.reg, d.rm)
		if mn == "" {
			return Inst{}, false
		}
		ops = append(ops, text...)
	}
	if d.bad {
		return Inst{}, false
	}
	return d.build(mn, ops, &tbl.x87), true
}

// x87Reg returns the mnemonic and operands of the register form (mod == 3) of an x87 opcode.
func x87Reg(op, reg, rm byte) (mn, ops string) {
	sti := "st(" + string('0'+rm) + ")"
	switch op {
	case 0xD8:
		if reg == 2 || reg == 3 {
			return x87Arith[reg], sti
		}
		return x87Arith[reg], "st, " + sti
	case 0xD9:
		switch {
		case reg == 0:
			return "fld", sti
		case reg == 1:
			return "fxch", sti
		case reg == 2 && rm == 0:
			return "fnop", ""
		case reg >= 4:
			return x87D9[reg-4][rm], ""
		}
	case 0xDA:
		if reg < 4 {
			return [4]string{"fcmovb", "fcmove", "fcmovbe", "fcmovu"}[reg], "st, " + sti
		}
		if reg == 5 && rm == 1 {
			return "fucompp", ""
		}
	case 0xDB:
		switch {
		case reg < 4:
			return [4]string{"fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu"}[reg], "st, " + sti
		case reg == 4 && rm == 2:
			return "fnclex", ""
		case reg == 4 && rm == 3:
			return "fninit", ""
		case reg == 5:
			return "fucomi", "st, " + sti
		case reg == 6:
			return "fcomi", "st, " + sti
		}
	case 0xDC:
		if names := [8]string{"fadd", "fmul", "", "", "fsubr", "fsub", "fdivr", "fdiv"}; names[reg] != "" {
			return names[reg], sti + ", st"
		}
	case 0xDD:
		if names := [8]string{"ffree", "", "fst", "fstp", "fucom", "fucomp", "", ""}; names[reg] != "" {
			return names[reg], sti
		}
	case 0xDE:
		switch {
		case reg == 3 && rm == 1:
			return "fcompp", ""
		case reg != 2 && reg != 3:
			return [8]string{"faddp", "fmulp", "", "", "fsubrp", "fsubp", "fdivrp", "fdivp"}[reg], sti + ", st"
		}
	case 0xDF:
		switch {
		case reg == 4 && rm == 0:
			return "fnstsw", "ax"
		case reg == 5:
			return "fucomip", "st, " + sti
		case reg == 6:
			return "fcomip", "st, " + sti
		}
	}
	return "", ""
}
