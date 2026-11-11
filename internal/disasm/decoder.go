package disasm

import "strings"

// decoder holds the state of one Decode call. Every read goes through u8, which
// stops at the 15-byte limit or at the end of the input and records the failure in
// bad, so no path can read out of bounds; the callers check bad before using
// anything they decoded.
type decoder struct {
	mode  Mode
	code  []byte
	addr  uint64
	limit int // min(len(code), MaxInstLen)
	pos   int // next byte to read
	bad   bool

	// prefixes
	opsize16 bool   // 66 seen
	addr67   bool   // 67 seen
	lock     bool   // F0 seen
	rep      byte   // F3 or F2 (the last one seen); 0 once consumed as a mandatory prefix
	seg      string // segment override name, or ""
	rex      byte   // REX byte (0x40..0x4F) or the equivalent bits synthesised from VEX; 0 when absent

	// VEX and EVEX
	vexed bool  // the instruction is VEX or EVEX encoded
	pp    uint8 // implied mandatory prefix: 0 none, 1 66, 2 F3, 3 F2
	vl    uint8 // vector length: 0 128 bits, 1 256 bits, 2 512 bits
	vvvv  uint8 // the extra register operand

	consumed66 bool // 66 was used as a mandatory prefix
	notrack    bool // a DS prefix on an indirect call or jump: the CET notrack prefix
	op         byte // the last opcode byte read; its low three bits name the register of cZ operands

	// ModRM
	haveModRM bool
	mod       uint8
	reg       uint8
	rm        uint8
	mem       memRef

	e *entry // the instruction form being decoded

	// facts collected while decoding the operands
	hasRip  bool
	ripDisp int64
	hasAbs  bool
	absRef  uint64
	hasTgt  bool
	target  uint64

	scratch [128]byte // operand text is built here
}

// u8 reads the next byte; at the end of the input it records the failure and returns 0.
func (d *decoder) u8() byte {
	if d.pos >= d.limit {
		d.bad = true
		return 0
	}
	b := d.code[d.pos]
	d.pos++
	return b
}

// imm reads an n-byte little-endian unsigned value (n <= 8).
func (d *decoder) imm(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(d.u8()) << (8 * uint(i))
	}
	return v
}

// prefixes consumes the legacy prefixes and the REX prefix.
func (d *decoder) prefixes() {
	for d.pos < d.limit {
		b := d.code[d.pos]
		switch b {
		case 0x66:
			d.opsize16 = true
		case 0x67:
			d.addr67 = true
		case 0xF0:
			d.lock = true
		case 0xF2, 0xF3:
			d.rep = b
		case 0x26:
			d.seg = "es"
		case 0x2E:
			d.seg = "cs"
		case 0x36:
			d.seg = "ss"
		case 0x3E:
			d.seg = "ds"
		case 0x64:
			d.seg = "fs"
		case 0x65:
			d.seg = "gs"
		default:
			if d.mode == Mode64 && b&0xF0 == 0x40 {
				d.rex = b
				d.pos++
				continue
			}
			return
		}
		// A REX prefix only counts directly before the opcode.
		d.rex = 0
		d.pos++
	}
}

// osz returns the operand size in bits of the current instruction form.
func (d *decoder) osz() int {
	if d.mode == Mode64 {
		switch {
		case d.e != nil && d.e.flags&fF64 != 0:
			return 64
		case d.e != nil && d.e.flags&fD64 != 0:
			if d.opsize16 {
				return 16
			}
			return 64
		case d.rex&8 != 0:
			return 64
		}
	}
	if d.opsize16 {
		return 16
	}
	if d.rex&8 != 0 && d.vexed {
		return 64
	}
	return 32
}

// addrBits returns the address size in bits.
func (d *decoder) addrBits() int {
	switch {
	case d.mode == Mode64 && d.addr67:
		return 32
	case d.mode == Mode64:
		return 64
	case d.addr67:
		return 16
	}
	return 32
}

// rexR, rexX and rexB are the REX register-extension bits as register-number increments.
func (d *decoder) rexR() int { return int(d.rex>>2&1) << 3 }
func (d *decoder) rexX() int { return int(d.rex>>1&1) << 3 }
func (d *decoder) rexB() int { return int(d.rex&1) << 3 }

// decode decodes one instruction. A false result means the bytes are not an
// instruction this decoder knows.
func (d *decoder) decode() (Inst, bool) {
	d.prefixes()
	if d.pos >= d.limit {
		return Inst{}, false
	}
	op := d.u8()
	d.op = op

	var e *entry
	switch {
	case op == 0x0F:
		e = d.escape()
	case (op == 0xC4 || op == 0xC5) && d.vexPrefixed():
		return d.decodeVEX(op)
	case op == 0x62 && d.vexPrefixed():
		return d.decodeEVEX()
	case op >= 0xD8 && op <= 0xDF:
		return d.decodeX87(op)
	case op == 0x63 && d.mode == Mode64:
		e = &tbl.movsxd
	case op == 0x90 && d.rex&1 != 0:
		e = &tbl.xchg90
	case op == 0x90 && d.rep == 0xF3:
		d.rep = 0
		e = &tbl.pause
	default:
		e = d.resolve(&tbl.one[op])
	}
	if e == nil || d.bad {
		return Inst{}, false
	}
	return d.finish(e)
}

// vexPrefixed reports whether the byte just read starts a VEX or EVEX prefix.
// In 64-bit mode it always does; in 32-bit mode the byte after it must have its
// two top bits set, otherwise it is les, lds or bound.
func (d *decoder) vexPrefixed() bool {
	if d.mode == Mode64 {
		return true
	}
	return d.pos < d.limit && d.code[d.pos]&0xC0 == 0xC0
}

// escape decodes after a 0F byte: the two-byte map and the two three-byte maps.
func (d *decoder) escape() *entry {
	op := d.u8()
	if d.bad {
		return nil
	}
	d.op = op
	switch op {
	case 0x38:
		op3 := d.u8()
		if d.bad {
			return nil
		}
		return d.resolve(&tbl.t38[op3])
	case 0x3A:
		op3 := d.u8()
		if d.bad {
			return nil
		}
		return d.resolve(&tbl.t3a[op3])
	case 0x01, 0x1E:
		if e := d.fixedForm(op); e != nil {
			return e
		}
	}
	return d.resolve(&tbl.two[op])
}

// fixedForm recognises the instructions that are a fixed byte sequence after 0F
// (xgetbv, swapgs, endbr64, ...) and consumes their ModRM byte.
func (d *decoder) fixedForm(op byte) *entry {
	if d.pos >= d.limit {
		return nil
	}
	m := d.code[d.pos]
	if m>>6 != 3 {
		return nil
	}
	key := uint32(0x0F)<<16 | uint32(op)<<8 | uint32(m)
	if d.rep != 0 {
		if e, ok := tbl.fixed[uint32(d.rep)<<24|key]; ok {
			d.pos++
			d.rep = 0
			return e
		}
	}
	if e, ok := tbl.fixed[key]; ok {
		d.pos++
		return e
	}
	return nil
}

// prefixIndex selects the mandatory-prefix variant: 0 none, 1 66, 2 F3, 3 F2.
func (d *decoder) prefixIndex() int {
	switch {
	case d.vexed:
		return int(d.pp)
	case d.rep == 0xF3:
		return 2
	case d.rep == 0xF2:
		return 3
	case d.opsize16:
		return 1
	}
	return 0
}

// resolve follows the prefix, group and mod indirections of an entry down to the
// instruction form. It returns nil when the encoding is invalid.
func (d *decoder) resolve(e *entry) *entry {
	for range 6 {
		if e.flags&fInv64 != 0 && d.mode == Mode64 {
			return nil
		}
		switch {
		case e.pfx != nil:
			idx := d.prefixIndex()
			e = &e.pfx[idx]
			if !d.vexed {
				switch idx {
				case 1:
					d.opsize16 = false
					d.consumed66 = true
				case 2, 3:
					d.rep = 0
				}
			}
		case e.grp != nil:
			d.readModRM(false)
			if d.bad {
				return nil
			}
			e = &e.grp[d.reg]
		case e.mod != nil:
			d.readModRM(false)
			if d.bad {
				return nil
			}
			if d.mod == 3 {
				e = &e.mod[1]
			} else {
				e = &e.mod[0]
			}
		default:
			if e.mn == "" {
				return nil
			}
			if e.flags&fKeep66 != 0 && d.consumed66 {
				d.opsize16 = true
			}
			return e
		}
	}
	return nil
}

// finish decodes the operands of a resolved instruction form and assembles the result.
func (d *decoder) finish(e *entry) (Inst, bool) {
	if e.flags&fInv64 != 0 && d.mode == Mode64 {
		return Inst{}, false
	}
	d.e = e
	if e.modrm && !d.haveModRM {
		d.readModRM(e.flags&fForceReg != 0)
	}
	// A DS prefix on an indirect call or jump is the CET "notrack" prefix, not a segment override.
	if (e.flow == FlowCall || e.flow == FlowJump) && d.seg == "ds" && e.n > 0 && (e.ops[0].c == cE || e.ops[0].c == cM || e.ops[0].c == cR) {
		d.notrack, d.seg = true, ""
	}
	mn := d.mnemonic(e)
	ops := d.scratch[:0]
	for i := 0; i < int(e.n); i++ {
		if i > 0 {
			ops = append(ops, ',', ' ')
		}
		ops = d.operand(ops, e.ops[i])
	}
	if d.bad {
		return Inst{}, false
	}
	return d.build(mn, ops, e), true
}

// mnemonic picks the mnemonic of a form that depends on the operand or address size.
func (d *decoder) mnemonic(e *entry) string {
	mn := e.mn
	if e.flags&fMnv != 0 {
		size := d.osz()
		if e.flags&fAsz != 0 {
			size = d.addrBits()
		}
		switch size {
		case 16:
			mn = e.mnv[0]
		case 64:
			mn = e.mnv[2]
		default:
			mn = e.mnv[1]
		}
		if mn == "" {
			d.bad = true
		}
	}
	if e.flags&fWQ != 0 && d.rex&8 != 0 && strings.HasSuffix(mn, "d") {
		mn = mn[:len(mn)-1] + "q"
	}
	return mn
}

// prefixText returns the text of the prefixes that stayed unconsumed: lock, notrack, rep and bnd.
func (d *decoder) prefixText(e *entry) string {
	var p string
	if d.lock {
		p = "lock "
	}
	if d.notrack {
		p += "notrack "
	}
	switch {
	case d.rep == 0:
	case e.flags&fRep != 0:
		if d.rep == 0xF3 {
			p += "rep "
		} else {
			p += "repne "
		}
	case e.flags&fRepCC != 0:
		if d.rep == 0xF3 {
			p += "repe "
		} else {
			p += "repne "
		}
	case e.flags&fBranch != 0 && d.rep == 0xF2:
		p += "bnd "
	case d.rep == 0xF3:
		p += "repz "
	default:
		p += "repnz "
	}
	return p
}

// build assembles the Inst once the whole instruction has been consumed.
func (d *decoder) build(mn string, ops []byte, e *entry) Inst {
	pre := d.prefixText(e)
	var sb strings.Builder
	sb.Grow(len(pre) + len(mn) + 1 + len(ops))
	sb.WriteString(pre)
	sb.WriteString(mn)
	mnEnd := sb.Len()
	if len(ops) > 0 {
		sb.WriteByte(' ')
		sb.Write(ops)
	}
	text := sb.String()

	in := Inst{
		Addr:     d.addr,
		Len:      d.pos,
		Mnemonic: text[:mnEnd],
		Text:     text,
		Flow:     e.flow,
		Valid:    true,
	}
	if len(ops) > 0 {
		in.Operands = text[mnEnd+1:]
	}
	if e.flow == FlowCall || e.flow == FlowJump {
		for _, o := range e.ops[:e.n] {
			if o.c == cE || o.c == cM || o.c == cR {
				in.Indirect = true
			}
		}
	}
	if d.hasTgt {
		in.HasTarget = true
		in.Target = d.target
	}
	if d.hasRip {
		in.HasRipRef = true
		ref := d.addr + uint64(d.pos) + uint64(d.ripDisp)
		if d.mem.bits == 32 {
			ref = uint64(uint32(ref))
		}
		in.RipRef = ref
	}
	if d.hasAbs {
		in.HasAbsRef = true
		in.AbsRef = d.absRef
	}
	return in
}
