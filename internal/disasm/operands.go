package disasm

import "strconv"

// regBits returns the width in bits of a register operand of size s.
func (d *decoder) regBits(s opSize) int {
	switch s {
	case sz8:
		return 8
	case sz16:
		return 16
	case sz32, szDW, szDB, szS:
		return 32
	case sz64:
		return 64
	case szV, szVW:
		return d.osz()
	case szY:
		if d.rex&8 != 0 {
			return 64
		}
		return 32
	case szZ:
		if d.osz() == 16 {
			return 16
		}
		return 32
	case szN:
		if d.mode == Mode64 {
			return 64
		}
		return 32
	}
	return 0
}

// sizeKeyword returns the "xxx ptr " text that introduces a memory operand of size s.
func (d *decoder) sizeKeyword(s opSize) string {
	switch s {
	case szNone:
		return ""
	case sz8, szDB:
		return "byte ptr "
	case sz16, szDW, szVW:
		return "word ptr "
	case sz80:
		return "tbyte ptr "
	case sz128:
		return "xmmword ptr "
	case szX:
		switch d.vl {
		case 1:
			return "ymmword ptr "
		case 2:
			return "zmmword ptr "
		}
		return "xmmword ptr "
	case szFar:
		switch d.osz() {
		case 16:
			return "dword ptr "
		case 64:
			return "tbyte ptr "
		}
		return "fword ptr "
	case szS:
		if d.rex&8 != 0 {
			return "qword ptr "
		}
		return "dword ptr "
	}
	switch d.regBits(s) {
	case 16:
		return "word ptr "
	case 32:
		return "dword ptr "
	case 64:
		return "qword ptr "
	}
	return ""
}

// appendReg appends the name of general register n (0..15) with the width of size s.
func (d *decoder) appendReg(buf []byte, n int, s opSize) []byte {
	n &= 15
	switch d.regBits(s) {
	case 8:
		if d.rex != 0 {
			return append(buf, regs8Rex[n]...)
		}
		return append(buf, regs8[n&7]...)
	case 16:
		return append(buf, regs16[n]...)
	case 32:
		return append(buf, regs32[n]...)
	}
	return append(buf, regs64[n]...)
}

// appendNumbered appends a register name made of a prefix and a number (xmm3, cr0).
func appendNumbered(buf []byte, prefix string, n int) []byte {
	buf = append(buf, prefix...)
	return strconv.AppendInt(buf, int64(n), 10)
}

// appendVec appends the name of vector register n; operands of size szX follow the vector length.
func (d *decoder) appendVec(buf []byte, n int, s opSize) []byte {
	prefix := "xmm"
	if s == szX {
		switch d.vl {
		case 1:
			prefix = "ymm"
		case 2:
			prefix = "zmm"
		}
	}
	return appendNumbered(buf, prefix, n)
}

// mask returns the all-ones value of the given width in bits.
func mask(bits int) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	return 1<<uint(bits) - 1
}

// immediate reads an immediate operand of size s.
func (d *decoder) immediate(s opSize) uint64 {
	switch s {
	case sz8:
		return d.imm(1)
	case sz16:
		return d.imm(2)
	case szZ:
		size := d.osz()
		if size == 16 {
			return d.imm(2)
		}
		v := d.imm(4)
		if size == 64 {
			return uint64(int64(int32(uint32(v))))
		}
		return v
	case szV:
		switch d.osz() {
		case 16:
			return d.imm(2)
		case 64:
			return d.imm(8)
		}
		return d.imm(4)
	}
	return 0
}

// relative reads a relative branch displacement and prints the absolute target.
func (d *decoder) relative(buf []byte, s opSize) []byte {
	var rel int64
	switch {
	case s == sz8:
		rel = int64(int8(d.u8()))
	case d.mode == Mode64 || d.osz() != 16:
		rel = int64(int32(uint32(d.imm(4))))
	default:
		rel = int64(int16(uint16(d.imm(2))))
	}
	target := d.addr + uint64(d.pos) + uint64(rel)
	if d.mode == Mode32 {
		target &= 0xFFFFFFFF
		if d.osz() == 16 {
			target &= 0xFFFF
		}
	}
	d.hasTgt, d.target = true, target
	return appendHex(buf, target)
}

// appendString appends a string-instruction operand: [rsi] or [rdi] with a size keyword.
func (d *decoder) appendString(buf []byte, o opd) []byte {
	buf = append(buf, d.sizeKeyword(o.s)...)
	reg := 6 // rsi
	if o.c == cStrY {
		reg = 7 // rdi
	} else if d.seg != "" {
		buf = append(buf, d.seg...)
		buf = append(buf, ':')
	}
	buf = append(buf, '[')
	switch d.addrBits() {
	case 64:
		buf = append(buf, regs64[reg]...)
	case 32:
		buf = append(buf, regs32[reg]...)
	default:
		buf = append(buf, regs16[reg]...)
	}
	return append(buf, ']')
}

// operand decodes one operand and appends its Intel-syntax text. Operands that
// cannot be decoded in the current encoding set d.bad.
func (d *decoder) operand(buf []byte, o opd) []byte {
	switch o.c {
	case cE:
		if d.mod == 3 {
			return d.appendReg(buf, int(d.rm)+d.rexB(), o.s)
		}
		return d.appendMem(buf, o.s)
	case cG:
		return d.appendReg(buf, int(d.reg)+d.rexR(), o.s)
	case cR:
		if d.mod != 3 {
			d.bad = true
			return buf
		}
		return d.appendReg(buf, int(d.rm)+d.rexB(), o.s)
	case cM:
		if d.mod == 3 {
			d.bad = true
			return buf
		}
		return d.appendMem(buf, o.s)
	case cSeg:
		if d.reg > 5 {
			d.bad = true
			return buf
		}
		return append(buf, segRegs[d.reg]...)
	case cCR:
		return appendNumbered(buf, "cr", int(d.reg)+d.rexR())
	case cDR:
		return appendNumbered(buf, "dr", int(d.reg)+d.rexR())
	case cImm:
		return appendHex(buf, d.immediate(o.s))
	case cImmS:
		v := uint64(int64(int8(d.u8())))
		return appendHex(buf, v&mask(d.osz()))
	case cOne:
		return append(buf, '1')
	case cRel:
		return d.relative(buf, o.s)
	case cMoffs:
		v := d.imm(d.addrBits() / 8)
		buf = append(buf, d.sizeKeyword(o.s)...)
		seg := d.seg
		if seg == "" {
			seg = "ds"
		}
		if seg != "fs" && seg != "gs" {
			d.hasAbs, d.absRef = true, v
		}
		buf = append(buf, seg...)
		buf = append(buf, ':')
		return appendHex(buf, v)
	case cFarPtr:
		n := 4
		if d.osz() == 16 {
			n = 2
		}
		off := d.imm(n)
		sel := d.imm(2)
		buf = appendHex(buf, sel)
		buf = append(buf, ':')
		return appendHex(buf, off)
	case cZ:
		return d.appendReg(buf, int(d.op&7)+d.rexB(), o.s)
	case cFixed:
		return d.appendReg(buf, int(o.n), o.s)
	case cFixSeg:
		return append(buf, segRegs[o.n]...)
	case cStrX, cStrY:
		return d.appendString(buf, o)
	case cMMReg:
		return appendNumbered(buf, "mm", int(d.reg))
	case cMMRM:
		if d.mod == 3 {
			return appendNumbered(buf, "mm", int(d.rm))
		}
		return d.appendMem(buf, o.s)
	case cMMRegOnly:
		if d.mod != 3 {
			d.bad = true
			return buf
		}
		return appendNumbered(buf, "mm", int(d.rm))
	case cVecReg:
		return d.appendVec(buf, int(d.reg)+d.rexR(), o.s)
	case cVecRM:
		if d.mod == 3 {
			return d.appendVec(buf, int(d.rm)+d.rexB(), o.s)
		}
		return d.appendMem(buf, o.s)
	case cVecRegOnly:
		if d.mod != 3 {
			d.bad = true
			return buf
		}
		return d.appendVec(buf, int(d.rm)+d.rexB(), o.s)
	case cVecVVVV:
		return d.appendVec(buf, int(d.vvvv), o.s)
	case cVecIS4:
		return d.appendVec(buf, int(d.u8()>>4), o.s)
	case cGprVVVV:
		return d.appendReg(buf, int(d.vvvv), o.s)
	case cXmm0:
		return append(buf, "xmm0"...)
	}
	d.bad = true
	return buf
}
