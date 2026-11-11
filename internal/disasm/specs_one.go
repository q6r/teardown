package disasm

// groupSpecs returns the opcode groups: eight forms selected by the ModRM reg field.
func groupSpecs() map[string][8]string {
	arith := [8]string{"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"}
	shift := [8]string{"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"}
	with := func(names [8]string, ops string) [8]string {
		var g [8]string
		for i, n := range names {
			g[i] = n + " " + ops
		}
		return g
	}
	return map[string][8]string{
		"g1b":  with(arith, "Eb,Ib"),
		"g1v":  with(arith, "Ev,Iz"),
		"g1s":  with(arith, "Ev,Ibs"),
		"g2b":  with(shift, "Eb,Ib"),
		"g2v":  with(shift, "Ev,Ib"),
		"g2b1": with(shift, "Eb,One"),
		"g2v1": with(shift, "Ev,One"),
		"g2bc": with(shift, "Eb,CL"),
		"g2vc": with(shift, "Ev,CL"),
		"g3b":  {"test Eb,Ib", "test Eb,Ib", "not Eb", "neg Eb", "mul Eb", "imul Eb", "div Eb", "idiv Eb"},
		"g3v":  {"test Ev,Iz", "test Ev,Iz", "not Ev", "neg Ev", "mul Ev", "imul Ev", "div Ev", "idiv Ev"},
		"g4":   {"inc Eb", "dec Eb"},
		"g5":   {"inc Ev", "dec Ev", "call Ev f64 br", "call Mp", "jmp Ev f64 br", "jmp Mp", "push Ev d64"},
		"g1a":  {"pop Ev d64"},
		"g11b": {"mov Eb,Ib", 7: ";xabort Ib"},
		"g11v": {"mov Ev,Iz", 7: ";xbegin Jz"},
		"gbmi": {1: "blsr By,Ey", 2: "blsmsk By,Ey", 3: "blsi By,Ey"},

		// two-byte map groups
		"g6":  {"sldt Evw", "str Evw", "lldt Ew", "ltr Ew", "verr Ew", "verw Ew"},
		"g7m": {"sgdt M", "sidt M", "lgdt M", "lidt M", "smsw Evw", "", "lmsw Ew", "invlpg M"},
		"g7r": {4: "smsw Evw", 6: "lmsw Ew"},
		"g8":  {4: "bt Ev,Ib", 5: "bts Ev,Ib", 6: "btr Ev,Ib", 7: "btc Ev,Ib"},
		"g9m": {1: "cmpxchg8b/cmpxchg8b/cmpxchg16b M", 3: "xrstors/xrstors/xrstors64 M", 4: "xsavec/xsavec/xsavec64 M", 5: "xsaves/xsaves/xsaves64 M"},
		"g9r": {6: "rdrand Rv", 7: "rdseed Rv"},
		"g12": {2: "psrlw Nq,Ib|psrlw Ux,Ib ndd", 4: "psraw Nq,Ib|psraw Ux,Ib ndd", 6: "psllw Nq,Ib|psllw Ux,Ib ndd"},
		"g13": {2: "psrld Nq,Ib|psrld Ux,Ib ndd", 4: "psrad Nq,Ib|psrad Ux,Ib ndd", 6: "pslld Nq,Ib|pslld Ux,Ib ndd"},
		"g14": {2: "psrlq Nq,Ib|psrlq Ux,Ib ndd", 3: "|psrldq Ux,Ib ndd", 6: "psllq Nq,Ib|psllq Ux,Ib ndd", 7: "|pslldq Ux,Ib ndd"},
		"g15m": {
			"fxsave/fxsave/fxsave64 M", "fxrstor/fxrstor/fxrstor64 M", "ldmxcsr Md", "stmxcsr Md",
			"xsave/xsave/xsave64 M", "xrstor/xrstor/xrstor64 M", "xsaveopt/xsaveopt/xsaveopt64 M|clwb M", "clflush Mb|clflushopt Mb",
		},
		"g15r": {"||rdfsbase Ry", "||rdgsbase Ry", "||wrfsbase Ry", "||wrgsbase Ry", "", "lfence", "mfence", "sfence"},
		"g16": {
			"prefetchnta M;nop Ev", "prefetcht0 M;nop Ev", "prefetcht1 M;nop Ev", "prefetcht2 M;nop Ev",
			"nop Ev", "nop Ev", "nop Ev", "nop Ev",
		},
		"gpf": {"prefetch M", "prefetchw M", "prefetchwt1 M", "prefetch M", "prefetch M", "prefetch M", "prefetch M", "prefetch M"},
	}
}

// fixedSpecs returns the instructions that are a fixed byte sequence after 0F and
// whose ModRM byte has mod == 3. The key is rep prefix << 24, 0F << 16, the second
// opcode byte << 8 and the ModRM byte.
func fixedSpecs() map[uint32]string {
	return map[uint32]string{
		0x0F01C1: "vmcall", 0x0F01C2: "vmlaunch", 0x0F01C3: "vmresume", 0x0F01C4: "vmxoff",
		0x0F01C8: "monitor", 0x0F01C9: "mwait", 0x0F01CA: "clac", 0x0F01CB: "stac",
		0x0F01D0: "xgetbv", 0x0F01D1: "xsetbv", 0x0F01D4: "vmfunc", 0x0F01D5: "xend", 0x0F01D6: "xtest",
		0x0F01EE: "rdpkru", 0x0F01EF: "wrpkru", 0x0F01F8: "swapgs", 0x0F01F9: "rdtscp",
		0xF30F1EFA: "endbr64", 0xF30F1EFB: "endbr32",
	}
}

// oneByteSpecs describes the one-byte opcode map. Entries that differ between
// the modes are written for 32-bit mode with the inv64 flag; the decoder handles
// the 64-bit meaning of 62, 63, 90, C4 and C5 itself.
func oneByteSpecs() [256]string {
	var s [256]string

	arith := [8]string{"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"}
	for i, m := range arith {
		b := i * 8
		s[b+0] = m + " Eb,Gb"
		s[b+1] = m + " Ev,Gv"
		s[b+2] = m + " Gb,Eb"
		s[b+3] = m + " Gv,Ev"
		s[b+4] = m + " AL,Ib"
		s[b+5] = m + " Acc,Iz"
	}
	s[0x06], s[0x07] = "push ES inv64", "pop ES inv64"
	s[0x0E] = "push CS inv64"
	s[0x16], s[0x17] = "push SS inv64", "pop SS inv64"
	s[0x1E], s[0x1F] = "push DS inv64", "pop DS inv64"
	s[0x27], s[0x2F] = "daa inv64", "das inv64"
	s[0x37], s[0x3F] = "aaa inv64", "aas inv64"

	for i := 0; i < 8; i++ {
		s[0x40+i] = "inc Zv inv64"
		s[0x48+i] = "dec Zv inv64"
		s[0x50+i] = "push Zv d64"
		s[0x58+i] = "pop Zv d64"
	}
	for i := 1; i < 8; i++ {
		s[0x90+i] = "xchg Zv,Acc"
	}
	s[0x60], s[0x61] = "pushaw/pushad/ inv64", "popaw/popad/ inv64"
	s[0x62] = "bound Gv,M inv64"
	s[0x63] = "arpl Ew,Gw inv64"
	s[0x68] = "push Iz d64"
	s[0x69] = "imul Gv,Ev,Iz"
	s[0x6A] = "push Ibs d64"
	s[0x6B] = "imul Gv,Ev,Ibs"
	s[0x6C], s[0x6D] = "ins Yb,DX rep", "ins Yz,DX rep"
	s[0x6E], s[0x6F] = "outs DX,Xb rep", "outs DX,Xz rep"
	for i, c := range condNames {
		s[0x70+i] = "j" + c + " Jb br"
	}
	s[0x80], s[0x81], s[0x82], s[0x83] = "@g1b", "@g1v", "@g1b inv64", "@g1s"
	s[0x84], s[0x85] = "test Eb,Gb", "test Ev,Gv"
	s[0x86], s[0x87] = "xchg Eb,Gb", "xchg Ev,Gv"
	s[0x88], s[0x89], s[0x8A], s[0x8B] = "mov Eb,Gb", "mov Ev,Gv", "mov Gb,Eb", "mov Gv,Ev"
	s[0x8C], s[0x8D], s[0x8E], s[0x8F] = "mov Evw,Sw", "lea Gv,M", "mov Sw,Evw", "@g1a"
	s[0x90] = "nop"
	s[0x98], s[0x99] = "cbw/cwde/cdqe", "cwd/cdq/cqo"
	s[0x9A] = "call Ap inv64"
	s[0x9B] = "fwait"
	s[0x9C], s[0x9D] = "pushfw/pushfd/pushf d64", "popfw/popfd/popf d64"
	s[0x9E], s[0x9F] = "sahf", "lahf"
	s[0xA0], s[0xA1] = "mov/mov/movabs AL,Ob asz", "mov/mov/movabs Acc,Ov asz"
	s[0xA2], s[0xA3] = "mov/mov/movabs Ob,AL asz", "mov/mov/movabs Ov,Acc asz"
	s[0xA4], s[0xA5] = "movs Yb,Xb rep", "movs Yv,Xv rep"
	s[0xA6], s[0xA7] = "cmps Xb,Yb repcc", "cmps Xv,Yv repcc"
	s[0xA8], s[0xA9] = "test AL,Ib", "test Acc,Iz"
	s[0xAA], s[0xAB] = "stos Yb,AL rep", "stos Yv,Acc rep"
	s[0xAC], s[0xAD] = "lods AL,Xb rep", "lods Acc,Xv rep"
	s[0xAE], s[0xAF] = "scas AL,Yb repcc", "scas Acc,Yv repcc"
	for i := 0; i < 8; i++ {
		s[0xB0+i] = "mov Zb,Ib"
		s[0xB8+i] = "mov/mov/movabs Zv,Iv"
	}
	s[0xC0], s[0xC1] = "@g2b", "@g2v"
	s[0xC2], s[0xC3] = "ret Iw d64 br", "ret d64 br"
	s[0xC4], s[0xC5] = "les Gv,Mp inv64", "lds Gv,Mp inv64"
	s[0xC6], s[0xC7] = "@g11b", "@g11v"
	s[0xC8], s[0xC9] = "enter Iw,Ib d64", "leave d64"
	s[0xCA], s[0xCB] = "retf Iw", "retf"
	s[0xCC], s[0xCD], s[0xCE], s[0xCF] = "int3", "int Ib", "into inv64", "iretw/iretd/iretq"
	s[0xD0], s[0xD1], s[0xD2], s[0xD3] = "@g2b1", "@g2v1", "@g2bc", "@g2vc"
	s[0xD4], s[0xD5], s[0xD6], s[0xD7] = "aam Ib inv64", "aad Ib inv64", "salc inv64", "xlatb"
	s[0xE0], s[0xE1], s[0xE2], s[0xE3] = "loopne Jb", "loope Jb", "loop Jb", "jcxz/jecxz/jrcxz Jb asz"
	s[0xE4], s[0xE5], s[0xE6], s[0xE7] = "in AL,Ib", "in AccD,Ib", "out Ib,AL", "out Ib,AccD"
	s[0xE8], s[0xE9], s[0xEA], s[0xEB] = "call Jz d64 br", "jmp Jz d64 br", "jmp Ap inv64", "jmp Jb br"
	s[0xEC], s[0xED], s[0xEE], s[0xEF] = "in AL,DX", "in AccD,DX", "out DX,AL", "out DX,AccD"
	s[0xF1], s[0xF4], s[0xF5] = "int1", "hlt", "cmc"
	s[0xF6], s[0xF7] = "@g3b", "@g3v"
	s[0xF8], s[0xF9], s[0xFA], s[0xFB], s[0xFC], s[0xFD] = "clc", "stc", "cli", "sti", "cld", "std"
	s[0xFE], s[0xFF] = "@g4", "@g5"
	return s
}
