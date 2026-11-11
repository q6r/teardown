package disasm

import "strings"

// vexMapNames and vexPPNames label the opcode map and the implied prefix of a
// VEX or EVEX instruction that is only reported generically.
var (
	vexMapNames = [4]string{"", "0f", "0f38", "0f3a"}
	vexPPNames  = [4]string{"np", "66", "f3", "f2"}
)

// vexable reports whether a legacy form can be turned into a VEX form: it has a vector operand to widen,
// needs no MMX register and has a VEX encoding.
func vexable(e *entry) bool {
	hasVec := false
	for _, o := range e.ops[:e.n] {
		switch o.c {
		case cVecReg, cVecRM, cVecRegOnly:
			hasVec = true
		case cMMReg, cMMRM, cMMRegOnly, cXmm0:
			return false
		}
	}
	return hasVec && !strings.HasPrefix(e.mn, "sha")
}

// vexize derives the VEX form of a legacy SSE entry: a "v" in front of the
// mnemonic and, for the non-destructive forms, the extra VEX.vvvv operand.
func vexize(e *entry) entry {
	switch {
	case e.pfx != nil:
		var arr [4]entry
		for i := range arr {
			arr[i] = vexize(&e.pfx[i])
		}
		return entry{pfx: &arr}
	case e.mod != nil:
		var arr [2]entry
		for i := range arr {
			arr[i] = vexize(&e.mod[i])
		}
		return entry{mod: &arr}
	case e.grp != nil:
		var arr [8]entry
		for i := range arr {
			arr[i] = vexize(&e.grp[i])
		}
		return entry{grp: &arr}
	}
	if e.mn == "" || !vexable(e) {
		return entry{}
	}
	v := *e
	v.mn = "v" + e.mn
	v.flags &^= fRep | fRepCC | fBranch | fNDS | fNDD
	v.ops, v.n = [4]opd{}, 0
	h := operandTable["Hx"]
	add := func(o opd) {
		v.ops[v.n] = o
		v.n++
	}
	if e.flags&fNDD != 0 {
		add(h)
	}
	for i, o := range e.ops[:e.n] {
		add(o)
		if i == 0 && e.flags&fNDS != 0 {
			add(h)
		}
	}
	return v
}

// vexOnly38Specs describes the VEX-only instructions of map 0F 38: the AVX2
// broadcasts and permutes, the FMA family and the BMI instructions.
func vexOnly38Specs() map[int]string {
	m := map[int]string{
		0x0C: sse66("vpermilps", "Vx,Hx,Wx"), 0x0D: sse66("vpermilpd", "Vx,Hx,Wx"),
		0x0E: sse66("vtestps", "Vx,Wx"), 0x0F: sse66("vtestpd", "Vx,Wx"),
		0x13: sse66("vcvtph2ps", "Vx,Wq"),
		0x16: sse66("vpermps", "Vx,Hx,Wx"),
		0x18: sse66("vbroadcastss", "Vx,Wd"), 0x19: sse66("vbroadcastsd", "Vx,Wq"), 0x1A: sse66("vbroadcastf128", "Vx,Mo"),
		0x2C: sse66("vmaskmovps", "Vx,Hx,Mx"), 0x2D: sse66("vmaskmovpd", "Vx,Hx,Mx"),
		0x2E: sse66("vmaskmovps", "Mx,Hx,Vx"), 0x2F: sse66("vmaskmovpd", "Mx,Hx,Vx"),
		0x36: sse66("vpermd", "Vx,Hx,Wx"),
		0x45: sse66("vpsrlvd", "Vx,Hx,Wx wq"), 0x46: sse66("vpsravd", "Vx,Hx,Wx"), 0x47: sse66("vpsllvd", "Vx,Hx,Wx wq"),
		0x58: sse66("vpbroadcastd", "Vx,Wd"), 0x59: sse66("vpbroadcastq", "Vx,Wq"), 0x5A: sse66("vbroadcasti128", "Vx,Mo"),
		0x78: sse66("vpbroadcastb", "Vx,Wb"), 0x79: sse66("vpbroadcastw", "Vx,Ww"),
		0x8C: sse66("vpmaskmovd", "Vx,Hx,Mx wq"), 0x8E: sse66("vpmaskmovd", "Mx,Hx,Vx wq"),

		// BMI1 and BMI2 (general registers, VEX encoded)
		0xF2: "andn Gy,By,Ey|",
		0xF3: "@gbmi|",
		0xF5: "bzhi Gy,Ey,By||pext Gy,By,Ey|pdep Gy,By,Ey",
		0xF6: "|||mulx Gy,By,Ey",
		0xF7: "bextr Gy,Ey,By|shlx Gy,Ey,By|sarx Gy,Ey,By|shrx Gy,Ey,By",
	}

	// FMA: the high nibble selects the operand order, the low nibble the operation.
	orders := [3]string{"132", "213", "231"}
	forms := [10]struct {
		name   string
		scalar bool
	}{
		{"fmaddsub", false}, {"fmsubadd", false}, {"fmadd", false}, {"fmadd", true}, {"fmsub", false},
		{"fmsub", true}, {"fnmadd", false}, {"fnmadd", true}, {"fnmsub", false}, {"fnmsub", true},
	}
	for hi, order := range orders {
		for lo, f := range forms {
			op := 0x90 + hi*0x10 + 6 + lo
			base := "v" + f.name + order
			if f.scalar {
				m[op] = sse66(base+"ss/"+base+"ss/"+base+"sd", "Vx,Hx,Ws")
			} else {
				m[op] = sse66(base+"ps/"+base+"ps/"+base+"pd", "Vx,Hx,Wx")
			}
		}
	}
	return m
}

// vexOnly3ASpecs describes the VEX-only instructions of map 0F 3A.
func vexOnly3ASpecs() map[int]string {
	return map[int]string{
		0x00: sse66("vpermq", "Vx,Wx,Ib"), 0x01: sse66("vpermpd", "Vx,Wx,Ib"), 0x02: sse66("vpblendd", "Vx,Hx,Wx,Ib"),
		0x04: sse66("vpermilps", "Vx,Wx,Ib"), 0x05: sse66("vpermilpd", "Vx,Wx,Ib"), 0x06: sse66("vperm2f128", "Vx,Hx,Wx,Ib"),
		0x18: sse66("vinsertf128", "Vx,Hx,Wo,Ib"), 0x19: sse66("vextractf128", "Wo,Vx,Ib"),
		0x38: sse66("vinserti128", "Vx,Hx,Wo,Ib"), 0x39: sse66("vextracti128", "Wo,Vx,Ib"),
		0x46: sse66("vperm2i128", "Vx,Hx,Wx,Ib"),
		0x4A: sse66("vblendvps", "Vx,Hx,Wx,Lx"), 0x4B: sse66("vblendvpd", "Vx,Hx,Wx,Lx"), 0x4C: sse66("vpblendvb", "Vx,Hx,Wx,Lx"),
		0xF0: "|||rorx Gy,Ey,Ib",
	}
}

// buildVEX fills the VEX opcode maps: the legacy SSE forms widened, plus the VEX-only forms.
func buildVEX(p *parser, t *tables) {
	derive := func(dst, src *[256]entry) {
		for i := range src {
			dst[i] = vexize(&src[i])
		}
	}
	derive(&t.vex1, &t.two)
	derive(&t.vex2, &t.t38)
	derive(&t.vex3, &t.t3a)
	t.vex1[0x77] = p.parse("vzeroupper")
	t.vzeroall = p.parse("vzeroall")
	for op, spec := range vexOnly38Specs() {
		t.vex2[op] = p.parse(spec)
	}
	for op, spec := range vexOnly3ASpecs() {
		t.vex3[op] = p.parse(spec)
	}
}

// vexShape returns whether a VEX or EVEX instruction of the given map and opcode
// has a ModRM byte and how many immediate bytes follow it. This is all the
// length of an instruction the decoder does not model depends on.
func vexShape(mapID, op byte) (modrm bool, imm int) {
	switch mapID {
	case 1:
		switch op {
		case 0x77:
			return false, 0
		case 0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6:
			return true, 1
		}
	case 3:
		return true, 1
	}
	return true, 0
}

// decodeVEX decodes a VEX-encoded instruction; first is the C4 or C5 byte just read.
func (d *decoder) decodeVEX(first byte) (Inst, bool) {
	if d.opsize16 || d.rep != 0 || d.lock || d.rex != 0 {
		return Inst{}, false // these prefixes before VEX are undefined
	}
	b1 := d.u8()
	b2, mapID, w, x, b := b1, byte(1), byte(0), byte(0), byte(0)
	r := ^b1 >> 7 & 1
	if first == 0xC4 {
		b2 = d.u8()
		x, b = ^b1>>6&1, ^b1>>5&1
		mapID = b1 & 0x1F
		w = b2 >> 7
	}
	vvvv := ^b2 >> 3 & 15
	if d.mode == Mode32 {
		r, x, b, vvvv = 0, 0, 0, vvvv&7
	}
	op := d.u8()
	if d.bad {
		return Inst{}, false
	}
	d.vexed = true
	d.pp, d.vl, d.vvvv = b2&3, b2>>2&1, vvvv
	d.rex = 0x40 | w<<3 | r<<2 | x<<1 | b
	d.op = op

	var table *[256]entry
	switch mapID {
	case 1:
		table = &tbl.vex1
	case 2:
		table = &tbl.vex2
	case 3:
		table = &tbl.vex3
	default:
		return Inst{}, false
	}
	e := &table[op]
	if mapID == 1 && op == 0x77 && d.vl == 1 {
		e = &tbl.vzeroall
	}
	if leaf := d.resolve(e); leaf != nil {
		return d.finish(leaf)
	}
	return d.generic("vex", mapID, op)
}

// decodeEVEX decodes an EVEX-encoded instruction (the 62 byte was just read).
// Only the length is modelled.
func (d *decoder) decodeEVEX() (Inst, bool) {
	if d.opsize16 || d.rep != 0 || d.lock || d.rex != 0 {
		return Inst{}, false
	}
	p0, p1, p2 := d.u8(), d.u8(), d.u8()
	op := d.u8()
	mapID := p0 & 7
	if d.bad || p0&0x08 != 0 || p1&0x04 == 0 || mapID < 1 || mapID > 3 {
		return Inst{}, false
	}
	d.vexed = true
	d.pp, d.vl = p1&3, p2>>5&3
	d.rex = 0x40 | (p1>>7)<<3 | (^p0>>7&1)<<2 | (^p0>>6&1)<<1 | (^p0 >> 5 & 1)
	d.op = op
	return d.generic("evex", mapID, op)
}

// generic finishes a VEX or EVEX instruction that is not modelled: it consumes the
// ModRM operand and the immediate and names the encoding.
func (d *decoder) generic(kind string, mapID, op byte) (Inst, bool) {
	modrm, imm := vexShape(mapID, op)
	if modrm {
		d.readModRM(false)
	}
	d.imm(imm)
	if d.bad {
		return Inst{}, false
	}
	const digits = "0123456789abcdef"
	d.e = &tbl.x87
	ops := append(d.scratch[:0], vexMapNames[mapID]...)
	ops = append(ops, '.')
	ops = append(ops, vexPPNames[d.pp]...)
	ops = append(ops, '.', digits[op>>4], digits[op&15])
	return d.build(kind, ops, &tbl.x87), true
}
