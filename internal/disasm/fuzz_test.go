package disasm

import (
	"bytes"
	"fmt"
	"testing"
)

// fuzzSeeds is the seed corpus: a sample of every family the decoder covers,
// in 64-bit and 32-bit flavours, plus boundary shapes.
var fuzzSeeds = []string{
	"90", "c3", "cc", "55", "48 89 e5", "48 83 ec 28", "48 8b 4c 24 08", "48 8d 0d b7 1f 00 00",
	"ff 15 b7 1f 00 00", "ff 25 b7 1f 00 00", "e8 00 00 00 00", "e9 fb ff ff ff", "74 05", "0f 84 10 00 00 00",
	"31 c0", "b8 01 00 00 00", "48 b8 88 77 66 55 44 33 22 11", "c7 45 fc 00 00 00 00", "8b 04 85 00 10 40 00",
	"64 48 8b 04 25 28 00 00 00", "f3 48 a5", "f2 ae", "f0 0f b1 0a", "66 2e 0f 1f 84 00 00 00 00 00",
	"0f 05", "0f a2", "0f 0b", "f3 0f 1e fa", "0f 01 d0", "0f ae f0", "0f c7 08", "48 0f c7 08",
	"f2 0f 10 45 f8", "66 0f ef c0", "f3 0f 6f 00", "66 0f 3a 63 c1 0c", "66 0f 38 dc c1", "f2 0f 38 f1 c1",
	"c5 f8 77", "c5 fd 6f 00", "c5 fd 74 c1", "c4 e2 7d 78 c0", "c4 e3 7d 39 c1 01", "c4 e2 f9 b9 c1", "c4 e2 78 f2 c1",
	"62 f1 7c 48 10 00", "62 f3 7d 48 3e c1 00",
	"d9 ee", "dd d8", "db 2d 00 20 40 00", "d8 c1", "de c1",
	"06", "60", "9a 00 10 00 00 23 00", "67 8b 06 34 12", "c4 00", "62 00", "63 c8", "ff 18",
	"66", "f3", "0f", "0f 38", "c5", "62", "48", "ff 15", "e8 00 00",
	"66 66 66 66 66 66 66 66 66 66 66 66 66 66 90", "66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 90",
	"2e 2e 2e 2e 2e 2e 2e 2e 2e 2e b8 01 00 00 00",
}

// checkDecode asserts every promise Decode makes about its result.
func checkDecode(t *testing.T, mode Mode, code []byte, addr uint64, in Inst) {
	t.Helper()
	if len(code) == 0 {
		if in.Len != 0 || in.Text != "" || in.Valid || in.Bytes != nil {
			t.Fatalf("empty input gave %+v", in)
		}
		return
	}
	limit := min(len(code), MaxInstLen)
	if in.Len < 1 || in.Len > limit {
		t.Fatalf("Len = %d for % x (limit %d)", in.Len, code, limit)
	}
	if !bytes.Equal(in.Bytes, code[:in.Len]) || len(in.Bytes) != in.Len || cap(in.Bytes) != in.Len {
		t.Fatalf("Bytes = % x (len %d cap %d) for Len %d of % x", in.Bytes, len(in.Bytes), cap(in.Bytes), in.Len, code)
	}
	if in.Addr != addr {
		t.Fatalf("Addr = %#x, want %#x", in.Addr, addr)
	}
	want := in.Mnemonic
	if in.Operands != "" {
		want += " " + in.Operands
	}
	if in.Text != want || in.Mnemonic == "" {
		t.Fatalf("Text %q is not Mnemonic %q + Operands %q", in.Text, in.Mnemonic, in.Operands)
	}
	for i := 0; i < len(in.Text); i++ {
		if c := in.Text[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("Text %q holds the byte %#x", in.Text, c)
		}
	}
	if in.Text[len(in.Text)-1] == ' ' || in.Text[0] == ' ' {
		t.Fatalf("Text %q has stray spaces", in.Text)
	}
	if in.Valid != (in.Mnemonic != "db") {
		t.Fatalf("Valid = %v for %q", in.Valid, in.Text)
	}
	if !in.Valid {
		if in.Len != 1 || in.Text != fmt.Sprintf("db 0x%02x", code[0]) || in.Flow != FlowNone {
			t.Fatalf("bad fallback %+v for % x", in, code)
		}
		return
	}
	if in.HasTarget && in.Flow != FlowCall && in.Flow != FlowJump && in.Flow != FlowCondJump {
		t.Fatalf("%q has a target but Flow %v", in.Text, in.Flow)
	}
	if in.Indirect && in.Flow != FlowCall && in.Flow != FlowJump {
		t.Fatalf("%q is indirect but Flow %v", in.Text, in.Flow)
	}
	if in.HasTarget && in.Indirect {
		t.Fatalf("%q is both direct and indirect", in.Text)
	}
	if in.HasRipRef && mode != Mode64 {
		t.Fatalf("%q has a RIP reference in 32-bit mode", in.Text)
	}
	if mode == Mode32 && (in.Target>>32 != 0 || in.AbsRef>>32 != 0) {
		t.Fatalf("%q has a 32-bit mode reference above 4 GiB: %#x %#x", in.Text, in.Target, in.AbsRef)
	}
	// an instruction decodes the same from its own bytes: nothing depends on what follows it
	again := Decode(mode, in.Bytes, addr)
	if again.Text != in.Text || again.Len != in.Len || again.Valid != in.Valid {
		t.Fatalf("Decode(% x) = %q (len %d) alone but %q (len %d) in context", in.Bytes, again.Text, again.Len, in.Text, in.Len)
	}
}

func modeFor(is32 bool) Mode {
	if is32 {
		return Mode32
	}
	return Mode64
}

// FuzzDecode feeds arbitrary bytes to Decode: no panic, no out-of-range read, and
// the structural promises of Inst hold for every input.
func FuzzDecode(f *testing.F) {
	for _, s := range fuzzSeeds {
		code := mustHex(f, s)
		f.Add(code, false, uint64(0x140001000))
		f.Add(code, true, uint64(0x401000))
	}
	f.Fuzz(func(t *testing.T, code []byte, is32 bool, addr uint64) {
		mode := modeFor(is32)
		checkDecode(t, mode, code, addr, Decode(mode, code, addr))
	})
}

// FuzzDecodeAll checks the linear sweep: it consumes exactly the input, the
// addresses are contiguous and every instruction equals a stand-alone decode.
func FuzzDecodeAll(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(mustHex(f, s), false, uint64(0x140001000), 0)
		f.Add(mustHex(f, s), true, uint64(0x401000), 3)
	}
	var all []byte
	for _, s := range fuzzSeeds {
		all = append(all, mustHex(f, s)...)
	}
	f.Add(all, false, uint64(0), 0)
	f.Add(all, true, uint64(1<<63), 100)
	f.Fuzz(func(t *testing.T, code []byte, is32 bool, addr uint64, maxN int) {
		mode := modeFor(is32)
		insts := DecodeAll(mode, code, addr, maxN)
		limit := MaxInstructions
		if maxN > 0 && maxN < limit {
			limit = maxN
		}
		if len(insts) > limit || len(insts) > len(code) {
			t.Fatalf("%d instructions for %d bytes and max %d", len(insts), len(code), maxN)
		}
		off := 0
		for i, in := range insts {
			if in.Addr != addr+uint64(off) {
				t.Fatalf("instruction %d at %#x, want %#x", i, in.Addr, addr+uint64(off))
			}
			solo := Decode(mode, code[off:], in.Addr)
			if solo.Text != in.Text || solo.Len != in.Len {
				t.Fatalf("instruction %d: sweep %q len %d, stand-alone %q len %d", i, in.Text, in.Len, solo.Text, solo.Len)
			}
			checkDecode(t, mode, code[off:], in.Addr, in)
			off += in.Len
		}
		if len(insts) < limit && off != len(code) {
			t.Fatalf("sweep stopped at %d of %d bytes after %d instructions (limit %d)", off, len(code), len(insts), limit)
		}
		if off > len(code) {
			t.Fatalf("sweep consumed %d bytes of %d", off, len(code))
		}
	})
}

// TestFuzzSeedsDecode runs the seed corpus as an ordinary test, so the
// properties are checked in every normal run, in both modes, at every length cut.
func TestFuzzSeedsDecode(t *testing.T) {
	for _, s := range fuzzSeeds {
		code := mustHex(t, s)
		for _, mode := range []Mode{Mode64, Mode32} {
			for n := 0; n <= len(code); n++ {
				checkDecode(t, mode, code[:n], 0x140001000, Decode(mode, code[:n], 0x140001000))
			}
		}
	}
}

// TestDecodeNeverPanicsOnAllShortInputs decodes every one- and two-byte input and a
// sample of three-byte inputs, padded with a repeating tail, in both modes.
func TestDecodeNeverPanicsOnAllShortInputs(t *testing.T) {
	tails := [][]byte{{}, {0x00}, {0xc0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}, bytes.Repeat([]byte{0xff}, 14)}
	for _, mode := range []Mode{Mode64, Mode32} {
		for a := 0; a < 256; a++ {
			for b := 0; b < 256; b++ {
				for _, tail := range tails {
					code := append([]byte{byte(a), byte(b)}, tail...)
					checkDecode(t, mode, code, 0x1000, Decode(mode, code, 0x1000))
				}
			}
		}
		// every three-byte opcode shape behind the 0F escapes
		for _, esc := range [][]byte{{0x0f, 0x38}, {0x0f, 0x3a}, {0xc4, 0xe2}, {0xc4, 0xe3}, {0xc4, 0xe1}, {0xc5}, {0x62, 0xf1}, {0x62, 0xf2}} {
			for c := 0; c < 256; c++ {
				for _, tail := range tails {
					code := append(append([]byte{}, esc...), byte(c))
					code = append(code, tail...)
					checkDecode(t, mode, code, 0x1000, Decode(mode, code, 0x1000))
				}
			}
		}
	}
}
