package pe

import (
	"errors"
	"math"

	"github.com/q6r/teardown/internal/binio"
)

// secMap maps one section's virtual range onto its raw data.
type secMap struct {
	rva  uint32
	span uint64 // bytes the section may be addressed by: max(VirtualSize, SizeOfRawData)
	ptr  int64  // file offset of the raw data
	raw  int64  // bytes of raw data that actually exist in the file
}

// rvaMap translates relative virtual addresses to file offsets. It is
// deliberately tolerant: overlapping sections resolve to the first one that has
// data, and the headers are identity-mapped.
type rvaMap struct {
	secs      []secMap
	headerEnd int64
}

// translate returns the file offset of rva and how many contiguous bytes of
// file data follow it.
func (m *rvaMap) translate(rva uint32) (off, avail int64, ok bool) {
	for _, s := range m.secs {
		if rva < s.rva || uint64(rva-s.rva) >= s.span {
			continue
		}
		d := int64(rva - s.rva)
		if d >= s.raw {
			continue // zero-filled tail: nothing in the file
		}
		return s.ptr + d, s.raw - d, true
	}
	if int64(rva) < m.headerEnd {
		return int64(rva), m.headerEnd - int64(rva), true
	}
	return 0, 0, false
}

// rvaAdd adds delta to rva and reports whether the sum still fits in 32 bits.
func rvaAdd(rva uint32, delta uint64) (uint32, bool) {
	v := uint64(rva) + delta
	return uint32(v), v <= math.MaxUint32
}

// readRVA reads exactly n bytes at rva; they must lie in one mapped region.
func (p *parser) readRVA(rva uint32, n int) ([]byte, bool) {
	off, avail, ok := p.maps.translate(rva)
	if !ok || int64(n) > avail {
		return nil, false
	}
	b, err := binio.ReadAt(p.r, p.size, off, int64(n))
	return b, err == nil
}

// readRVAUpTo reads up to n bytes at rva, clamped to the mapped region. It
// returns nil when rva is not mapped.
func (p *parser) readRVAUpTo(rva uint32, n int) []byte {
	off, avail, ok := p.maps.translate(rva)
	if !ok {
		return nil
	}
	b, err := binio.ReadAt(p.r, p.size, off, min(int64(n), avail))
	if err != nil {
		return nil
	}
	return b
}

// cstringRVA reads a NUL-terminated name of at most maxNameLen bytes at rva. A
// string cut off by the end of the mapped data is returned as far as it goes.
func (p *parser) cstringRVA(rva uint32) (string, bool) {
	off, avail, ok := p.maps.translate(rva)
	if !ok {
		return "", false
	}
	return cstringResult(binio.CString(p.r, p.size, off, int(min(maxNameLen, avail))))
}

// cstringResult accepts a string cut off by the end of the data but rejects a
// read that failed for any other reason (I/O error, exhausted read budget).
func cstringResult(s string, err error) (string, bool) {
	if err != nil && !errors.Is(err, binio.ErrTruncated) {
		return "", false
	}
	return s, true
}

// u32AtRVA reads one little-endian uint32 at rva.
func (p *parser) u32AtRVA(rva uint32) (uint32, bool) {
	b, ok := p.readRVA(rva, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

// scanArray delivers up to count consecutive little-endian values of the given
// width (2, 4 or 8 bytes) starting at rva to fn, in order, until fn returns
// false, the mapped data ends or the context is cancelled. It returns how many
// values were delivered, including the one on which fn returned false.
func (p *parser) scanArray(rva uint32, width int, count uint64, fn func(i uint64, v uint64) bool) uint64 {
	const chunk = 512
	var delivered uint64
	for delivered < count {
		if p.stopped() {
			return delivered
		}
		cur, ok := rvaAdd(rva, delivered*uint64(width))
		if !ok {
			return delivered
		}
		n := int(min(count-delivered, chunk))
		b := p.readRVAUpTo(cur, n*width)
		whole := len(b) / width
		if whole == 0 {
			return delivered
		}
		for j := range whole {
			var v uint64
			switch width {
			case 2:
				v = uint64(b[j*2]) | uint64(b[j*2+1])<<8
			case 4:
				v = uint64(uint32(b[j*4]) | uint32(b[j*4+1])<<8 | uint32(b[j*4+2])<<16 | uint32(b[j*4+3])<<24)
			default:
				for k := 7; k >= 0; k-- {
					v = v<<8 | uint64(b[j*8+k])
				}
			}
			delivered++
			if !fn(delivered-1, v) {
				return delivered
			}
		}
	}
	return delivered
}
