package disasm

import "strconv"

// memRef is a decoded ModRM memory operand.
type memRef struct {
	base  int   // base register number (0..15), or -1
	index int   // index register number (0..15), or -1
	scale int   // 1, 2, 4 or 8; meaningful only with an index
	disp  int64 // sign-extended displacement
	// hasDisp tells that a displacement was encoded (and is printed even when zero).
	hasDisp bool
	rip     bool // RIP-relative (64-bit mode, mod 00, r/m 101)
	bits    int  // address size: 16, 32 or 64
	rm16    int  // r/m field, for 16-bit addressing
}

// Register names, indexed by register number.
var (
	regs64 = [16]string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	regs32 = [16]string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
	regs16 = [16]string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"}
	// regs8Rex are the byte registers when a REX prefix is present (spl, bpl, sil, dil instead of ah, ch, dh, bh).
	regs8Rex = [16]string{"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"}
	regs8    = [8]string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
	segRegs  = [6]string{"es", "cs", "ss", "ds", "fs", "gs"}
	// rm16Names are the base and index registers of the 16-bit addressing forms.
	rm16Names = [8]string{"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"}
)

// readModRM reads the ModRM byte and, unless the operand is a register, the SIB
// byte and the displacement. force makes the mod field read as 3 (mov to and from
// control and debug registers ignore it).
func (d *decoder) readModRM(force bool) {
	if d.haveModRM {
		return
	}
	b := d.u8()
	if d.bad {
		return
	}
	d.haveModRM = true
	d.mod, d.reg, d.rm = b>>6, b>>3&7, b&7
	if force {
		d.mod = 3
	}
	if d.mod != 3 {
		d.readMem()
	}
}

// readMem decodes the SIB byte and displacement that follow a ModRM byte whose mod is not 3.
func (d *decoder) readMem() {
	m := &d.mem
	m.base, m.index, m.scale = -1, -1, 1
	m.bits = d.addrBits()
	if m.bits == 16 {
		d.readMem16()
		return
	}

	noBase := false
	switch {
	case d.rm == 4:
		sib := d.u8()
		if idx := int(sib>>3&7) | d.rexX(); idx != 4 {
			m.index = idx
			m.scale = 1 << (sib >> 6)
		}
		if sib&7 == 5 && d.mod == 0 {
			noBase = true
		} else {
			m.base = int(sib&7) | d.rexB()
		}
	case d.rm == 5 && d.mod == 0:
		noBase = true
		m.rip = d.mode == Mode64
	default:
		m.base = int(d.rm) | d.rexB()
	}

	switch {
	case d.mod == 1:
		m.disp, m.hasDisp = int64(int8(d.u8())), true
	case d.mod == 2 || noBase:
		m.disp, m.hasDisp = int64(int32(uint32(d.imm(4)))), true
	}

	switch {
	case m.rip:
		d.hasRip = true
		d.ripDisp = m.disp
	case m.base < 0 && m.index < 0 && d.seg != "fs" && d.seg != "gs":
		d.hasAbs = true
		d.absRef = m.absolute()
	}
}

// absolute returns the address of a memory operand that has no base or index
// register: the displacement, as wide as the address size.
func (m *memRef) absolute() uint64 {
	if m.bits == 32 {
		return uint64(uint32(m.disp))
	}
	return uint64(m.disp)
}

// readMem16 decodes the 16-bit addressing forms (32-bit mode with the 67 prefix).
func (d *decoder) readMem16() {
	m := &d.mem
	m.rm16 = int(d.rm)
	switch {
	case d.mod == 0 && d.rm == 6:
		m.disp, m.hasDisp = int64(int16(uint16(d.imm(2)))), true
		m.rm16 = -1 // a bare 16-bit displacement
	case d.mod == 1:
		m.disp, m.hasDisp = int64(int8(d.u8())), true
	case d.mod == 2:
		m.disp, m.hasDisp = int64(int16(uint16(d.imm(2)))), true
	}
}

// appendSigned appends a displacement as +0x.. or -0x...
func appendSigned(buf []byte, v int64) []byte {
	if v < 0 {
		buf = append(buf, '-', '0', 'x')
		return strconv.AppendUint(buf, uint64(-v), 16)
	}
	buf = append(buf, '+', '0', 'x')
	return strconv.AppendUint(buf, uint64(v), 16)
}

// appendHex appends v as 0x followed by lower-case hexadecimal digits.
func appendHex(buf []byte, v uint64) []byte {
	buf = append(buf, '0', 'x')
	return strconv.AppendUint(buf, v, 16)
}

// appendMem appends the memory operand: the size keyword, the segment override and the bracketed address.
func (d *decoder) appendMem(buf []byte, s opSize) []byte {
	buf = append(buf, d.sizeKeyword(s)...)
	if d.seg != "" {
		buf = append(buf, d.seg...)
		buf = append(buf, ':')
	}
	buf = append(buf, '[')
	m := &d.mem
	switch {
	case m.bits == 16:
		if m.rm16 < 0 {
			buf = appendHex(buf, uint64(uint16(m.disp)))
		} else {
			buf = append(buf, rm16Names[m.rm16]...)
			if m.hasDisp {
				buf = appendSigned(buf, m.disp)
			}
		}
	case m.rip:
		if m.bits == 32 {
			buf = append(buf, "eip"...)
		} else {
			buf = append(buf, "rip"...)
		}
		buf = appendSigned(buf, m.disp)
	case m.base < 0 && m.index < 0:
		buf = appendHex(buf, m.absolute())
	default:
		names := &regs64
		if m.bits == 32 {
			names = &regs32
		}
		if m.base >= 0 {
			buf = append(buf, names[m.base]...)
		}
		if m.index >= 0 {
			if m.base >= 0 {
				buf = append(buf, '+')
			}
			buf = append(buf, names[m.index]...)
			buf = append(buf, '*')
			buf = strconv.AppendInt(buf, int64(m.scale), 10)
		}
		if m.hasDisp {
			buf = appendSigned(buf, m.disp)
		}
	}
	return append(buf, ']')
}
