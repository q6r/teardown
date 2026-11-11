package disasm

// mmxSSE builds the specification of an integer instruction that exists as an MMX
// form (no prefix) and as an SSE2 form (66 prefix): name mm, mm/m64 and name xmm, xmm/m128.
func mmxSSE(name string) string {
	return name + " Pq,Qq|" + name + " Vx,Wx nds"
}

// mmxSSEHalf is like mmxSSE for the low unpack instructions, whose MMX form reads only 32 bits of memory.
func mmxSSEHalf(name string) string {
	return name + " Pq,Qd|" + name + " Vx,Wx nds"
}

// sse66 builds the specification of an instruction that only exists with the 66 prefix.
func sse66(name, ops string) string {
	return "|" + name + " " + ops
}

// fpFour builds the four forms of a floating-point arithmetic instruction:
// packed single, packed double, scalar single and scalar double.
func fpFour(base string) string {
	return base + "ps Vx,Wx nds|" + base + "pd Vx,Wx nds|" + base + "ss Vx,Wd nds|" + base + "sd Vx,Wq nds"
}

// twoByteSpecs describes the two-byte opcode map (the bytes after 0F).
func twoByteSpecs() [256]string {
	var s [256]string

	s[0x00] = "@g6"
	s[0x01] = "@g7m;@g7r"
	s[0x02], s[0x03] = "lar Gv,Ew", "lsl Gv,Ew"
	s[0x05], s[0x06], s[0x07] = "syscall", "clts", "sysret/sysret/sysretq"
	s[0x08], s[0x09], s[0x0B] = "invd", "wbinvd", "ud2"
	s[0x0D], s[0x0E] = "@gpf", "femms"

	// SSE moves and conversions
	s[0x10] = "movups Vx,Wx|movupd Vx,Wx|movss Vx,Wd;movss Vx,Wd nds|movsd Vx,Wq;movsd Vx,Wq nds"
	s[0x11] = "movups Wx,Vx|movupd Wx,Vx|movss Wd,Vx;movss Wd,Vx nds|movsd Wq,Vx;movsd Wq,Vx nds"
	s[0x12] = "movlps Vx,Mq nds;movhlps Vx,Ux nds|movlpd Vx,Mq nds|movsldup Vx,Wx|movddup Vx,Wq"
	s[0x13] = "movlps Mq,Vx|movlpd Mq,Vx"
	s[0x14] = "unpcklps Vx,Wx nds|unpcklpd Vx,Wx nds"
	s[0x15] = "unpckhps Vx,Wx nds|unpckhpd Vx,Wx nds"
	s[0x16] = "movhps Vx,Mq nds;movlhps Vx,Ux nds|movhpd Vx,Mq nds|movshdup Vx,Wx"
	s[0x17] = "movhps Mq,Vx|movhpd Mq,Vx"
	s[0x18] = "@g16"
	for op := 0x19; op <= 0x1F; op++ {
		s[op] = "nop Ev"
	}
	s[0x20], s[0x21] = "mov Rr,Cd forcereg", "mov Rr,Dd forcereg"
	s[0x22], s[0x23] = "mov Cd,Rr forcereg", "mov Dd,Rr forcereg"
	s[0x28] = "movaps Vx,Wx|movapd Vx,Wx"
	s[0x29] = "movaps Wx,Vx|movapd Wx,Vx"
	s[0x2A] = "cvtpi2ps Vx,Qq|cvtpi2pd Vx,Qq|cvtsi2ss Vx,Ey nds|cvtsi2sd Vx,Ey nds"
	s[0x2B] = "movntps Mx,Vx|movntpd Mx,Vx"
	s[0x2C] = "cvttps2pi Pq,Wq|cvttpd2pi Pq,Wx|cvttss2si Gy,Wd|cvttsd2si Gy,Wq"
	s[0x2D] = "cvtps2pi Pq,Wq|cvtpd2pi Pq,Wx|cvtss2si Gy,Wd|cvtsd2si Gy,Wq"
	s[0x2E] = "ucomiss Vx,Wd|ucomisd Vx,Wq"
	s[0x2F] = "comiss Vx,Wd|comisd Vx,Wq"

	s[0x30], s[0x31], s[0x32], s[0x33] = "wrmsr", "rdtsc", "rdmsr", "rdpmc"
	s[0x34], s[0x35], s[0x37] = "sysenter", "sysexit", "getsec"

	for i, c := range condNames {
		s[0x40+i] = "cmov" + c + " Gv,Ev"
		s[0x80+i] = "j" + c + " Jz br"
		s[0x90+i] = "set" + c + " Eb"
	}

	// SSE arithmetic
	s[0x50] = "movmskps Gd,Ux|movmskpd Gd,Ux"
	s[0x51] = "sqrtps Vx,Wx|sqrtpd Vx,Wx|sqrtss Vx,Wd nds|sqrtsd Vx,Wq nds"
	s[0x52] = "rsqrtps Vx,Wx||rsqrtss Vx,Wd nds"
	s[0x53] = "rcpps Vx,Wx||rcpss Vx,Wd nds"
	s[0x54] = "andps Vx,Wx nds|andpd Vx,Wx nds"
	s[0x55] = "andnps Vx,Wx nds|andnpd Vx,Wx nds"
	s[0x56] = "orps Vx,Wx nds|orpd Vx,Wx nds"
	s[0x57] = "xorps Vx,Wx nds|xorpd Vx,Wx nds"
	s[0x58], s[0x59] = fpFour("add"), fpFour("mul")
	s[0x5A] = "cvtps2pd Vx,Wq|cvtpd2ps Vx,Wx|cvtss2sd Vx,Wd nds|cvtsd2ss Vx,Wq nds"
	s[0x5B] = "cvtdq2ps Vx,Wx|cvtps2dq Vx,Wx|cvttps2dq Vx,Wx"
	s[0x5C], s[0x5D], s[0x5E], s[0x5F] = fpFour("sub"), fpFour("min"), fpFour("div"), fpFour("max")

	// MMX and SSE2 integer instructions
	s[0x60], s[0x61], s[0x62] = mmxSSEHalf("punpcklbw"), mmxSSEHalf("punpcklwd"), mmxSSEHalf("punpckldq")
	s[0x6C], s[0x6D] = sse66("punpcklqdq", "Vx,Wx nds"), sse66("punpckhqdq", "Vx,Wx nds")
	s[0x6E] = "movd Pq,Ey wq|movd Vx,Ey wq"
	s[0x6F] = "movq Pq,Qq|movdqa Vx,Wx|movdqu Vx,Wx"
	s[0x70] = "pshufw Pq,Qq,Ib|pshufd Vx,Wx,Ib|pshufhw Vx,Wx,Ib|pshuflw Vx,Wx,Ib"
	s[0x71], s[0x72], s[0x73] = "@g12", "@g13", "@g14"
	s[0x77] = "emms"
	s[0x7C] = "|haddpd Vx,Wx nds||haddps Vx,Wx nds"
	s[0x7D] = "|hsubpd Vx,Wx nds||hsubps Vx,Wx nds"
	s[0x7E] = "movd Ey,Pq wq|movd Ey,Vx wq|movq Vx,Wq"
	s[0x7F] = "movq Qq,Pq|movdqa Wx,Vx|movdqu Wx,Vx"
	mmxNames := map[int]string{
		0x63: "packsswb", 0x64: "pcmpgtb", 0x65: "pcmpgtw", 0x66: "pcmpgtd", 0x67: "packuswb",
		0x68: "punpckhbw", 0x69: "punpckhwd", 0x6A: "punpckhdq", 0x6B: "packssdw",
		0x74: "pcmpeqb", 0x75: "pcmpeqw", 0x76: "pcmpeqd",
		0xD1: "psrlw", 0xD2: "psrld", 0xD3: "psrlq", 0xD4: "paddq", 0xD5: "pmullw",
		0xD8: "psubusb", 0xD9: "psubusw", 0xDA: "pminub", 0xDB: "pand", 0xDC: "paddusb", 0xDD: "paddusw", 0xDE: "pmaxub", 0xDF: "pandn",
		0xE0: "pavgb", 0xE1: "psraw", 0xE2: "psrad", 0xE3: "pavgw", 0xE4: "pmulhuw", 0xE5: "pmulhw",
		0xE8: "psubsb", 0xE9: "psubsw", 0xEA: "pminsw", 0xEB: "por", 0xEC: "paddsb", 0xED: "paddsw", 0xEE: "pmaxsw", 0xEF: "pxor",
		0xF1: "psllw", 0xF2: "pslld", 0xF3: "psllq", 0xF4: "pmuludq", 0xF5: "pmaddwd", 0xF6: "psadbw",
		0xF8: "psubb", 0xF9: "psubw", 0xFA: "psubd", 0xFB: "psubq", 0xFC: "paddb", 0xFD: "paddw", 0xFE: "paddd",
	}
	for op, name := range mmxNames {
		s[op] = mmxSSE(name)
	}

	// stack segment registers, system and bit instructions
	s[0xA0], s[0xA1], s[0xA2], s[0xA3] = "push FS d64", "pop FS d64", "cpuid", "bt Ev,Gv"
	s[0xA4], s[0xA5] = "shld Ev,Gv,Ib", "shld Ev,Gv,CL"
	s[0xA8], s[0xA9], s[0xAA], s[0xAB] = "push GS d64", "pop GS d64", "rsm", "bts Ev,Gv"
	s[0xAC], s[0xAD] = "shrd Ev,Gv,Ib", "shrd Ev,Gv,CL"
	s[0xAE], s[0xAF] = "@g15m;@g15r", "imul Gv,Ev"
	s[0xB0], s[0xB1], s[0xB2], s[0xB3] = "cmpxchg Eb,Gb", "cmpxchg Ev,Gv", "lss Gv,Mp", "btr Ev,Gv"
	s[0xB4], s[0xB5], s[0xB6], s[0xB7] = "lfs Gv,Mp", "lgs Gv,Mp", "movzx Gv,Eb", "movzx Gv,Ew"
	s[0xB8], s[0xB9], s[0xBA], s[0xBB] = "||popcnt Gv,Ev", "ud1 Gv,Ev", "@g8", "btc Ev,Gv"
	s[0xBC] = "bsf Gv,Ev|bsf Gv,Ev keep66|tzcnt Gv,Ev"
	s[0xBD] = "bsr Gv,Ev|bsr Gv,Ev keep66|lzcnt Gv,Ev"
	s[0xBE], s[0xBF] = "movsx Gv,Eb", "movsx Gv,Ew"
	s[0xC0], s[0xC1] = "xadd Eb,Gb", "xadd Ev,Gv"
	s[0xC2] = "cmpps Vx,Wx,Ib nds|cmppd Vx,Wx,Ib nds|cmpss Vx,Wd,Ib nds|cmpsd Vx,Wq,Ib nds"
	s[0xC3] = "movnti My,Gy"
	s[0xC4] = "pinsrw Pq,Edw,Ib|pinsrw Vx,Edw,Ib nds"
	s[0xC5] = "pextrw Gd,Nq,Ib|pextrw Gd,Ux,Ib"
	s[0xC6] = "shufps Vx,Wx,Ib nds|shufpd Vx,Wx,Ib nds"
	s[0xC7] = "@g9m;@g9r"
	for i := 0; i < 8; i++ {
		s[0xC8+i] = "bswap Zv"
	}
	s[0xD0] = "|addsubpd Vx,Wx nds||addsubps Vx,Wx nds"
	s[0xD6] = "|movq Wq,Vx|movq2dq Vx,Nq|movdq2q Pq,Ux"
	s[0xD7] = "pmovmskb Gd,Nq|pmovmskb Gd,Ux"
	s[0xE6] = "|cvttpd2dq Vx,Wx|cvtdq2pd Vx,Wq|cvtpd2dq Vx,Wx"
	s[0xE7] = "movntq Mq,Pq|movntdq Mx,Vx"
	s[0xF0] = "|||lddqu Vx,Mx"
	s[0xF7] = "maskmovq Pq,Nq|maskmovdqu Vx,Ux"
	s[0xFF] = "ud0 Gv,Ev"
	return s
}

// threeByte38Specs describes the 0F 38 opcode map.
func threeByte38Specs() [256]string {
	var s [256]string

	names := map[int]string{
		0x00: "pshufb", 0x01: "phaddw", 0x02: "phaddd", 0x03: "phaddsw", 0x04: "pmaddubsw",
		0x05: "phsubw", 0x06: "phsubd", 0x07: "phsubsw", 0x08: "psignb", 0x09: "psignw", 0x0A: "psignd", 0x0B: "pmulhrsw",
	}
	for op, name := range names {
		s[op] = mmxSSE(name)
	}
	for i, name := range [3]string{"pabsb", "pabsw", "pabsd"} {
		s[0x1C+i] = name + " Pq,Qq|" + name + " Vx,Wx"
	}
	s[0x10] = sse66("pblendvb", "Vx,Wx,X0")
	s[0x14] = sse66("blendvps", "Vx,Wx,X0")
	s[0x15] = sse66("blendvpd", "Vx,Wx,X0")
	s[0x17] = sse66("ptest", "Vx,Wx")

	// zero and sign extensions: the memory operand shrinks with the element ratio
	ext := [6]struct{ from, to, mem string }{
		{"bw", "", "Wq"}, {"bd", "", "Wd"}, {"bq", "", "Ww"}, {"wd", "", "Wq"}, {"wq", "", "Wd"}, {"dq", "", "Wq"},
	}
	for i, e := range ext {
		s[0x20+i] = sse66("pmovsx"+e.from, "Vx,"+e.mem)
		s[0x30+i] = sse66("pmovzx"+e.from, "Vx,"+e.mem)
	}
	s[0x28] = sse66("pmuldq", "Vx,Wx nds")
	s[0x29] = sse66("pcmpeqq", "Vx,Wx nds")
	s[0x2A] = sse66("movntdqa", "Vx,Mx")
	s[0x2B] = sse66("packusdw", "Vx,Wx nds")
	s[0x37] = sse66("pcmpgtq", "Vx,Wx nds")
	more := map[int]string{
		0x38: "pminsb", 0x39: "pminsd", 0x3A: "pminuw", 0x3B: "pminud",
		0x3C: "pmaxsb", 0x3D: "pmaxsd", 0x3E: "pmaxuw", 0x3F: "pmaxud", 0x40: "pmulld",
	}
	for op, name := range more {
		s[op] = sse66(name, "Vx,Wx nds")
	}
	s[0x41] = sse66("phminposuw", "Vx,Wx")
	s[0x80], s[0x81], s[0x82] = sse66("invept", "Gy,Mo"), sse66("invvpid", "Gy,Mo"), sse66("invpcid", "Gy,Mo")

	// SHA extensions
	s[0xC8], s[0xC9], s[0xCA] = "sha1nexte Vx,Wx", "sha1msg1 Vx,Wx", "sha1msg2 Vx,Wx"
	s[0xCB], s[0xCC], s[0xCD] = "sha256rnds2 Vx,Wx,X0", "sha256msg1 Vx,Wx", "sha256msg2 Vx,Wx"
	s[0xCF] = sse66("gf2p8mulb", "Vx,Wx nds")

	// AES
	s[0xDB] = sse66("aesimc", "Vx,Wx")
	for i, name := range [4]string{"aesenc", "aesenclast", "aesdec", "aesdeclast"} {
		s[0xDC+i] = sse66(name, "Vx,Wx nds")
	}

	// movbe, crc32, adcx, adox
	s[0xF0] = "movbe Gv,Mv|movbe Gv,Mv keep66||crc32 Gy,Eb"
	s[0xF1] = "movbe Mv,Gv|movbe Mv,Gv keep66||crc32 Gy,Ev"
	s[0xF6] = "|adcx Gy,Ey|adox Gy,Ey"
	return s
}

// threeByte3ASpecs describes the 0F 3A opcode map. Every instruction has an
// 8-bit immediate.
func threeByte3ASpecs() [256]string {
	var s [256]string

	s[0x08] = sse66("roundps", "Vx,Wx,Ib")
	s[0x09] = sse66("roundpd", "Vx,Wx,Ib")
	s[0x0A] = sse66("roundss", "Vx,Wd,Ib nds")
	s[0x0B] = sse66("roundsd", "Vx,Wq,Ib nds")
	s[0x0C] = sse66("blendps", "Vx,Wx,Ib nds")
	s[0x0D] = sse66("blendpd", "Vx,Wx,Ib nds")
	s[0x0E] = sse66("pblendw", "Vx,Wx,Ib nds")
	s[0x0F] = "palignr Pq,Qq,Ib|palignr Vx,Wx,Ib nds"
	s[0x14] = sse66("pextrb", "Edb,Vx,Ib")
	s[0x15] = sse66("pextrw", "Edw,Vx,Ib")
	s[0x16] = sse66("pextrd", "Ey,Vx,Ib wq")
	s[0x17] = sse66("extractps", "Ed,Vx,Ib")
	s[0x20] = sse66("pinsrb", "Vx,Edb,Ib nds")
	s[0x21] = sse66("insertps", "Vx,Wd,Ib nds")
	s[0x22] = sse66("pinsrd", "Vx,Ey,Ib wq nds")
	s[0x40] = sse66("dpps", "Vx,Wx,Ib nds")
	s[0x41] = sse66("dppd", "Vx,Wx,Ib nds")
	s[0x42] = sse66("mpsadbw", "Vx,Wx,Ib nds")
	s[0x44] = sse66("pclmulqdq", "Vx,Wx,Ib nds")
	s[0x60] = sse66("pcmpestrm", "Vx,Wx,Ib")
	s[0x61] = sse66("pcmpestri", "Vx,Wx,Ib")
	s[0x62] = sse66("pcmpistrm", "Vx,Wx,Ib")
	s[0x63] = sse66("pcmpistri", "Vx,Wx,Ib")
	s[0xCC] = "sha1rnds4 Vx,Wx,Ib"
	s[0xCE] = sse66("gf2p8affineqb", "Vx,Wx,Ib nds")
	s[0xCF] = sse66("gf2p8affineinvqb", "Vx,Wx,Ib nds")
	s[0xDF] = sse66("aeskeygenassist", "Vx,Wx,Ib")
	return s
}
