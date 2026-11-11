package pe

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

// Absolute walk limits. Recorded lists are additionally capped by limits.Limits.
const (
	importDescriptorSize = 20
	delayDescriptorSize  = 32
	maxDescriptors       = 4096
	maxThunksPerLib      = 1 << 16
	maxThunksTotal       = 1 << 18
	maxNameLen           = 512
	displayNameLen       = 256
	delayLibSuffix       = " (delay-load)"
)

type thunk struct {
	byOrdinal bool
	ordinal   uint16
	nameRVA   uint32
}

// forEachThunk walks an import thunk array (INT or IAT) up to its zero
// terminator. visit returns false to stop early. visited counts the entries
// handed to visit; clean is true only when the terminator was reached.
func (p *parser) forEachThunk(rva uint32, visit func(thunk) bool) (visited int, clean bool) {
	width := 4
	if p.h.pe64 {
		width = 8
	}
	p.scanArray(rva, width, maxThunksPerLib, func(_ uint64, v uint64) bool {
		if v == 0 {
			clean = true
			return false
		}
		visited++
		t := thunk{ordinal: uint16(v), nameRVA: uint32(v & 0x7fffffff)}
		if width == 8 {
			t.byOrdinal = v>>63 != 0
		} else {
			t.byOrdinal = v>>31&1 != 0
		}
		return visit(t)
	})
	return visited, clean
}

// hintName reads the name of an IMAGE_IMPORT_BY_NAME entry (a 2-byte hint, then the name).
func (p *parser) hintName(rva uint32) (string, bool) {
	off, avail, ok := p.maps.translate(rva)
	if !ok || avail < 3 {
		return "", false
	}
	return cstringResult(binio.CString(p.r, p.size, off+2, int(min(avail-2, maxNameLen))))
}

// fromVA converts an absolute virtual address to an RVA.
func (p *parser) fromVA(v uint64) (uint32, bool) {
	if v < p.h.imageBase || v-p.h.imageBase > math.MaxUint32 {
		return 0, false
	}
	return uint32(v - p.h.imageBase), true
}

// parseImports walks the import directory, recording libraries and functions
// and streaming the import hash.
func (p *parser) parseImports() {
	d := p.h.dirs[dirImport]
	if d.rva == 0 {
		return
	}
	// The import hash is defined as an MD5 (pefile compatible), not a security control.
	p.impMD5 = md5.New()
	p.hasher = newImpHasher(p.impMD5)
	p.hashOK = true
	for i := uint64(0); ; i++ {
		if i >= maxDescriptors {
			p.notef("the import directory has more than %d descriptors; the rest were ignored", maxDescriptors)
			p.hashOK = false
			break
		}
		if p.done() {
			p.hashOK = false
			break
		}
		var b []byte
		at, ok := rvaAdd(d.rva, i*importDescriptorSize)
		if ok {
			b, ok = p.readRVA(at, importDescriptorSize)
		}
		if !ok {
			p.hashOK = false
			if i == 0 {
				p.notef("the import directory (RVA %#x) lies outside the file; imports were skipped", d.rva)
			} else {
				p.notef("the import directory is not terminated: descriptor %d lies outside the file", i)
			}
			break
		}
		c := binio.NewCursor(b, binary.LittleEndian)
		originalFirstThunk := c.U32()
		c.Skip(8) // TimeDateStamp, ForwarderChain
		nameRVA := c.U32()
		firstThunk := c.U32()
		if originalFirstThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}
		libRaw, ok := p.cstringRVA(nameRVA)
		if !ok {
			p.notef("import descriptor %d has a DLL name (RVA %#x) outside the file; the remaining imports were ignored", i, nameRVA)
			p.hashOK = false
			break
		}
		thunks := originalFirstThunk
		if thunks == 0 {
			thunks = firstThunk
		}
		lib := p.walkLibrary(libRaw, thunks, firstThunk, false, false)
		if len(p.imports) < p.lim.MaxList {
			p.imports = append(p.imports, lib)
		} else {
			p.importsTruncated = true
		}
	}
	if p.importsTruncated {
		p.notef("only the first %d import libraries are recorded", p.lim.MaxList)
	}
	if p.hashOK && p.hasher != nil && p.hasher.wrote {
		p.res.ImpHash = hex.EncodeToString(p.impMD5.Sum(nil))
	} else if p.hasher != nil && !p.hashOK {
		p.notef("the import hash was not computed because the import table could not be read completely")
	}
}

// parseDelayImports walks the delay-load import directory. Delay-load imports
// are listed but do not contribute to the import hash.
func (p *parser) parseDelayImports() {
	d := p.h.dirs[dirDelayImport]
	if d.rva == 0 {
		return
	}
	for i := uint64(0); ; i++ {
		if i >= maxDescriptors {
			p.notef("the delay-load import directory has more than %d descriptors; the rest were ignored", maxDescriptors)
			return
		}
		if p.done() {
			return
		}
		var b []byte
		at, ok := rvaAdd(d.rva, i*delayDescriptorSize)
		if ok {
			b, ok = p.readRVA(at, delayDescriptorSize)
		}
		if !ok {
			if i == 0 {
				p.notef("the delay-load import directory (RVA %#x) lies outside the file; it was skipped", d.rva)
			} else {
				p.notef("the delay-load import directory is not terminated: descriptor %d lies outside the file", i)
			}
			return
		}
		c := binio.NewCursor(b, binary.LittleEndian)
		attrs := c.U32()
		nameField := c.U32()
		c.Skip(4) // ModuleHandleRVA
		iatField := c.U32()
		intField := c.U32()
		if attrs == 0 && nameField == 0 && iatField == 0 && intField == 0 {
			return
		}
		vaBased := attrs&1 == 0
		thunkField := intField
		if thunkField == 0 {
			thunkField = iatField
		}
		nameRVA, ok1 := p.delayRVA(nameField, vaBased)
		thunkRVA, ok2 := p.delayRVA(thunkField, vaBased)
		iatRVA := uint32(0) // an address table that cannot be located only means no slots
		if iatField != 0 {
			iatRVA, _ = p.delayRVA(iatField, vaBased)
		}
		libRaw, ok3 := "", false
		if ok1 {
			libRaw, ok3 = p.cstringRVA(nameRVA)
		}
		if !ok1 || !ok2 || !ok3 {
			p.notef("delay-load descriptor %d points outside the file; the remaining delay-load imports were ignored", i)
			return
		}
		lib := p.walkLibrary(libRaw, thunkRVA, iatRVA, true, vaBased)
		if len(p.delayImports) < p.lim.MaxList {
			p.delayImports = append(p.delayImports, lib)
			p.det.DelayImportLibraries = append(p.det.DelayImportLibraries, binio.Printable(libRaw, displayNameLen))
		}
	}
}

// delayRVA converts a delay-load descriptor field to an RVA; old-style
// descriptors (attribute bit 0 clear) store absolute virtual addresses.
func (p *parser) delayRVA(v uint32, vaBased bool) (uint32, bool) {
	if !vaBased {
		return v, true
	}
	return p.fromVA(uint64(v))
}

// walkLibrary reads the thunks of one imported library; thunkRVA is the array
// that holds the names (the import name table, or the address table when the
// image has no name table) and iatRVA the import address table, which has the
// same layout and whose entries are the slots code calls through. Regular (not
// delay-load) imports also feed the import hash.
func (p *parser) walkLibrary(libRaw string, thunkRVA, iatRVA uint32, delay, vaBased bool) report.Import {
	lib := report.Import{Library: binio.Printable(libRaw, displayNameLen), Functions: []string{}}
	if delay {
		lib.Library += delayLibSuffix
	}
	if thunkRVA == 0 {
		return lib
	}
	unresolved := false
	index := uint64(0) // position of the thunk in the array, which names are skipped from
	visited, clean := p.forEachThunk(thunkRVA, func(t thunk) bool {
		if p.done() || p.thunkBudget <= 0 {
			return false
		}
		p.thunkBudget--
		slot := index
		index++
		var name string
		if t.byOrdinal {
			name = "#" + strconv.Itoa(int(t.ordinal))
			if !delay {
				p.hasher.addOrdinal(libRaw, t.ordinal)
			}
		} else {
			rva, ok := t.nameRVA, true
			if vaBased {
				rva, ok = p.fromVA(uint64(t.nameRVA))
			}
			var raw string
			if ok {
				raw, ok = p.hintName(rva)
			}
			if !ok {
				unresolved = true
				return false
			}
			if raw == "" {
				return true
			}
			name = binio.Printable(raw, displayNameLen)
			if !delay {
				p.hasher.add(libRaw, raw)
			}
		}
		lib.Count++
		p.importTotal++
		if len(lib.Functions) < p.lim.MaxList && p.recordedFuncs < p.lim.MaxList*4 {
			lib.Functions = append(lib.Functions, name)
			p.recordedFuncs++
			p.recordSlot(iatRVA, slot, lib.Library, name, delay)
		}
		return true
	})
	switch {
	case unresolved:
		p.notef("library %s: an import name lies outside the file; %d functions were read before it", lib.Library, lib.Count)
		if !delay {
			p.hashOK = false
		}
	case !clean && p.err == nil:
		if p.thunkBudget <= 0 {
			p.notef("the import walk limit of %d functions was reached; the import list is incomplete", maxThunksTotal)
		} else {
			p.notef("library %s: the import thunk array is not terminated or exceeds %d entries (%d read)", lib.Library, maxThunksPerLib, visited)
		}
		if !delay {
			p.hashOK = false
		}
	}
	if lib.Count > len(lib.Functions) {
		p.functionsTruncated = true
	}
	return lib
}
