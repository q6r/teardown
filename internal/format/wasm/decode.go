package wasm

import (
	"errors"

	"github.com/q6r/teardown/internal/binio"
)

var (
	errTruncated = errors.New("unexpected end of data")
	errLEB       = errors.New("malformed LEB128 integer")
	errFormat    = errors.New("unsupported or malformed encoding")
)

// leb32 decodes an unsigned LEB128 integer of at most 32 bits (five bytes) from
// the start of b and returns the value and the number of bytes used.
func leb32(b []byte) (v uint32, n int, err error) {
	var shift uint
	for n < 5 {
		if n >= len(b) {
			return 0, 0, errTruncated
		}
		c := b[n]
		n++
		if n == 5 && c > 0x0f { // only four payload bits remain and no continuation
			return 0, 0, errLEB
		}
		v |= uint32(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, n, nil
		}
		shift += 7
	}
	return 0, 0, errLEB
}

// leb64 decodes an unsigned LEB128 integer of at most 64 bits (ten bytes).
func leb64(b []byte) (v uint64, n int, err error) {
	var shift uint
	for n < 10 {
		if n >= len(b) {
			return 0, 0, errTruncated
		}
		c := b[n]
		n++
		if n == 10 && c > 0x01 { // only one payload bit remains and no continuation
			return 0, 0, errLEB
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, n, nil
		}
		shift += 7
	}
	return 0, 0, errLEB
}

// reader decodes WebAssembly primitives from a byte slice with a sticky error:
// once a read fails every later read returns a zero value and err stays set.
type reader struct {
	b   []byte
	i   int
	err error
}

func (d *reader) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *reader) byte() byte {
	if d.err != nil {
		return 0
	}
	if d.i >= len(d.b) {
		d.fail(errTruncated)
		return 0
	}
	c := d.b[d.i]
	d.i++
	return c
}

func (d *reader) u32() uint32 {
	if d.err != nil {
		return 0
	}
	v, n, err := leb32(d.b[d.i:])
	if err != nil {
		d.fail(err)
		return 0
	}
	d.i += n
	return v
}

func (d *reader) u64() uint64 {
	if d.err != nil {
		return 0
	}
	v, n, err := leb64(d.b[d.i:])
	if err != nil {
		d.fail(err)
		return 0
	}
	d.i += n
	return v
}

// skipLEB consumes one LEB128 integer of at most five bytes, whatever its
// signedness (used for heap types, which are signed).
func (d *reader) skipLEB() {
	for n := 0; n < 5; n++ {
		if c := d.byte(); d.err != nil || c&0x80 == 0 {
			return
		}
	}
	d.fail(errLEB)
}

// name reads a length-prefixed UTF-8 name. The text is made printable and cut to
// maxRunes runes, but the reader always advances past the whole name.
func (d *reader) name(maxRunes int) string {
	n := d.u32()
	if d.err != nil {
		return ""
	}
	if uint64(n) > uint64(len(d.b)-d.i) {
		d.fail(errTruncated)
		return ""
	}
	raw := d.b[d.i : d.i+int(n)]
	d.i += int(n)
	return binio.Printable(string(raw[:min(len(raw), 4*maxRunes)]), maxRunes)
}

// valType skips a value or reference type. Numeric, vector and packed types are
// one byte; the abstract reference shorthands are one byte too; the "(ref ht)"
// forms are a prefix byte followed by a heap type.
func (d *reader) valType() {
	switch c := d.byte(); {
	case d.err != nil:
	case c >= 0x77 && c <= 0x7f, // i8/i16 storage types, v128, f64, f32, i64, i32
		c >= 0x68 && c <= 0x74: // abstract heap type shorthands and funcref/externref
	case c == 0x63 || c == 0x64:
		d.skipLEB()
	default:
		d.fail(errFormat)
	}
}

// limits decodes the limits of a memory or table: a flag byte (bit 0 maximum
// present, bit 1 shared, bit 2 64-bit indices, bit 3 custom page size), the
// minimum and the optional maximum.
func (d *reader) limits() (lo, hi uint64, hasMax, shared, memory64 bool) {
	flags := d.byte()
	if d.err != nil {
		return
	}
	if flags&^0x0f != 0 {
		d.fail(errFormat)
		return
	}
	hasMax, shared, memory64 = flags&1 != 0, flags&2 != 0, flags&4 != 0
	next := func() uint64 { return uint64(d.u32()) }
	if memory64 {
		next = d.u64
	}
	lo = next()
	if hasMax {
		hi = next()
	}
	if flags&0x08 != 0 {
		d.u32() // the custom page size proposal appends a log2 page size
	}
	return lo, hi, hasMax, shared, memory64
}
