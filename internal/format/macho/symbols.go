package macho

import (
	"context"
	"io"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
)

// symbolInfo is what the symbol table revealed about an image.
type symbolInfo struct {
	// decoded is true when the symbol table was read (even if it held no matches).
	decoded bool
	// imports maps a dylib install name (or the unspecified marker) to the
	// undefined external symbols resolved from it; leading underscores are removed.
	imports map[string]map[string]struct{}
	exports map[string]struct{}
	// importCount and exportCount are true totals; the maps stop growing at maxStored.
	importCount, exportCount int
	canary                   bool
}

// scanSymbols reads the nlist table of the slice and classifies undefined and
// defined external symbols. sr is positioned at the start of the slice.
func (t *thin) scanSymbols(ctx context.Context, sr io.ReaderAt, lim limits.Limits) symbolInfo {
	si := symbolInfo{imports: map[string]map[string]struct{}{}, exports: map[string]struct{}{}}
	if !t.haveSymtab || t.nsyms == 0 {
		return si
	}
	entSize := uint64(12)
	if t.is64 {
		entSize = 16
	}
	size := uint64(t.size)
	if uint64(t.symoff) > size {
		t.note("the symbol table starts at offset %#x, beyond the end of the file; symbols were not read", t.symoff)
		return si
	}
	count := uint64(t.nsyms)
	if fit := (size - uint64(t.symoff)) / entSize; count > fit {
		t.note("the symbol table is truncated: %d of %d entries are present", fit, count)
		count = fit
	}
	if count > maxSymbols {
		t.note("the symbol table has %d entries; only the first %d are scanned", count, maxSymbols)
		count = maxSymbols
	}
	if uint64(t.stroff) > size || t.strsize == 0 {
		t.note("the string table is missing or outside the file; symbol names were not read")
		return si
	}
	strLen := min(uint64(t.strsize), size-uint64(t.stroff))
	if strLen < uint64(t.strsize) {
		t.note("the string table is truncated: %d of %d bytes are present", strLen, t.strsize)
	}
	if strLen > uint64(lim.MaxMeta) {
		t.note("the string table is %d bytes, above the %d byte limit; symbols were counted but not read", strLen, lim.MaxMeta)
		return si
	}
	strtab, err := binio.ReadAt(sr, t.size, int64(t.stroff), int64(strLen))
	if err != nil {
		t.note("the string table could not be read: %v", err)
		return si
	}
	si.decoded = true

	twoLevel := t.flags&flagTwoLevel != 0
	for done := uint64(0); done < count; {
		if ctx.Err() != nil {
			return si
		}
		n := min(count-done, nlistChunk)
		raw, err := binio.ReadAt(sr, t.size, int64(uint64(t.symoff)+done*entSize), int64(n*entSize))
		if err != nil {
			t.note("the symbol table could not be read past entry %d: %v", done, err)
			return si
		}
		for i := uint64(0); i < n; i++ {
			e := raw[i*entSize:]
			strx, ntype, nsect := t.order.Uint32(e), e[4], e[5]
			desc := t.order.Uint16(e[6:])
			if ntype&0xe0 != 0 || ntype&0x01 == 0 { // N_STAB debug entry, or not external
				continue
			}
			name := symbolName(strtab, strx)
			if name == "" {
				continue
			}
			switch ntype & 0x0e {
			case 0x00: // N_UNDF
				if nsect != 0 {
					continue
				}
				if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
					si.canary = true
				}
				lib := unspecified
				if twoLevel {
					if ord := int(desc >> 8); ord >= 1 && ord <= len(t.dylibs) {
						lib = t.dylibs[ord-1]
					}
				}
				si.addImport(lib, name)
			case 0x0e: // N_SECT
				si.addExport(name)
			}
		}
		done += n
	}
	return si
}

func (si *symbolInfo) addImport(lib, name string) {
	si.importCount++
	set := si.imports[lib]
	if set == nil {
		set = map[string]struct{}{}
		si.imports[lib] = set
	}
	if len(set) < maxStored {
		set[name] = struct{}{}
	}
}

func (si *symbolInfo) addExport(name string) {
	si.exportCount++
	if len(si.exports) < maxStored {
		si.exports[name] = struct{}{}
	}
}

// symbolName returns the symbol at a string table offset with one leading
// underscore (the C name mangling prefix) removed.
func symbolName(strtab []byte, off uint32) string {
	if uint64(off) >= uint64(len(strtab)) {
		return ""
	}
	rest := strtab[off:]
	if len(rest) > 4096 {
		rest = rest[:4096]
	}
	if i := indexNUL(rest); i >= 0 {
		rest = rest[:i]
	}
	return binio.Printable(strings.TrimPrefix(string(rest), "_"), maxName)
}
