package elf

import (
	delf "debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

// maxSymtabBytes bounds the size of a symbol table that is decoded in memory.
// debug/elf expands every 24-byte entry into a larger Go value, so the limit
// keeps the worst case in the tens of megabytes.
const maxSymtabBytes = 8 << 20

// symbolScan is what the symbol tables revealed.
type symbolScan struct {
	// dynCount and symCount come from the section headers (entries minus the
	// null symbol) and are known even when the table is too large to decode.
	dynCount, symCount     int
	dynDecoded, symDecoded bool

	imports map[string]map[string]struct{} // library -> function names
	exports map[string]struct{}
	canary  bool
	fortify map[string]struct{}
}

func (s *symbolScan) readable() bool { return s.dynDecoded || s.symDecoded }

// symbolEntries returns the number of entries of a symbol table section minus
// the mandatory null entry.
func (p *parser) symbolEntries(s sect) int {
	ent := s.entsize
	if ent == 0 {
		ent = 16
		if p.h.is64 {
			ent = 24
		}
	}
	if n := s.size / ent; n > 0 {
		return int(min(n-1, 1<<31-1))
	}
	return 0
}

// scanSymbols decodes the symbol tables with debug/elf when the section table
// is complete and the tables are small enough to hold in memory.
func (p *parser) scanSymbols() {
	s := &p.syms
	dyn, hasDyn := p.findSect(shtDynsym)
	sym, hasSym := p.findSect(shtSymtab)
	if hasDyn {
		s.dynCount = p.symbolEntries(dyn)
	}
	if hasSym {
		s.symCount = p.symbolEntries(sym)
	}
	if !hasDyn && !hasSym {
		return
	}
	if p.sectionsIncomplete {
		p.note("symbol tables were not read because the section header table is incomplete")
		return
	}
	readDyn := hasDyn && p.symbolTableUsable(".dynsym", dyn)
	readSym := hasSym && p.symbolTableUsable(".symtab", sym)
	if !readDyn && !readSym {
		return
	}
	if !p.nameTableUsable() {
		return
	}
	f, err := safeNewFile(p.r)
	if err != nil {
		p.note("debug/elf could not decode the section table (%v); symbol tables were not read", err)
		return
	}
	s.imports = map[string]map[string]struct{}{}
	s.exports = map[string]struct{}{}
	s.fortify = map[string]struct{}{}
	if readDyn {
		p.decodeDynamicSymbols(f)
	}
	if readSym && p.ctx.Err() == nil {
		p.decodeSymtab(f)
	}
}

// symbolTableUsable checks that a symbol table and its string table lie inside
// the file and are small enough to decode.
func (p *parser) symbolTableUsable(name string, s sect) bool {
	switch {
	case s.size > maxSymtabBytes || s.size > uint64(p.lim.MaxMeta):
		p.note("%s is %d bytes, above the %d byte limit; its symbols were counted but not decoded", name, s.size, min(maxSymtabBytes, p.lim.MaxMeta))
		return false
	case s.off > uint64(p.size) || s.size > uint64(p.size)-s.off:
		p.note("%s extends past the end of the file; its symbols were not read", name)
		return false
	case int(s.link) >= len(p.sects):
		p.note("%s links to section %d which does not exist; its symbols were not read", name, s.link)
		return false
	}
	str := p.sects[s.link]
	if str.size > uint64(p.lim.MaxMeta) || str.off > uint64(p.size) || str.size > uint64(p.size)-str.off {
		p.note("the string table of %s is missing, truncated or larger than %d bytes; its symbols were not read", name, p.lim.MaxMeta)
		return false
	}
	return true
}

// nameTableUsable guards debug/elf's eager load of the section name table.
func (p *parser) nameTableUsable() bool {
	if p.shstrndx <= 0 || p.shstrndx >= len(p.sects) {
		return true
	}
	st := p.sects[p.shstrndx]
	if st.size > uint64(p.lim.MaxMeta) || st.off > uint64(p.size) || st.size > uint64(p.size)-st.off {
		p.note("the section name string table is truncated or larger than %d bytes; symbol tables were not read", p.lim.MaxMeta)
		return false
	}
	return true
}

func safeNewFile(r io.ReaderAt) (f *delf.File, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			f, err = nil, fmt.Errorf("debug/elf panicked: %v", rec)
		}
	}()
	return delf.NewFile(r)
}

func safeSymbols(f *delf.File, dynamic bool) (syms []delf.Symbol, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			syms, err = nil, fmt.Errorf("debug/elf panicked: %v", rec)
		}
	}()
	if dynamic {
		return f.DynamicSymbols()
	}
	return f.Symbols()
}

func (p *parser) decodeDynamicSymbols(f *delf.File) {
	s := &p.syms
	syms, err := safeSymbols(f, true)
	if err != nil {
		if !errors.Is(err, delf.ErrNoSymbols) {
			p.note("the dynamic symbol table could not be decoded: %v", err)
		}
		return
	}
	s.dynDecoded = true
	for i, sy := range syms {
		if i%4096 == 0 && p.ctx.Err() != nil {
			return
		}
		name := cleanSymbol(sy.Name)
		if name == "" {
			continue
		}
		s.observe(name)
		bind, typ := delf.ST_BIND(sy.Info), delf.ST_TYPE(sy.Info)
		if bind != delf.STB_GLOBAL && bind != delf.STB_WEAK {
			continue
		}
		if sy.Section == delf.SHN_UNDEF {
			lib := binio.Printable(sy.Library, maxName)
			if !sy.HasVersion || lib == "" {
				lib = unspecified
			}
			if s.imports[lib] == nil {
				s.imports[lib] = map[string]struct{}{}
			}
			s.imports[lib][name] = struct{}{}
		} else if typ != delf.STT_SECTION && typ != delf.STT_FILE {
			s.exports[name] = struct{}{}
		}
	}
}

func (p *parser) decodeSymtab(f *delf.File) {
	s := &p.syms
	syms, err := safeSymbols(f, false)
	if err != nil {
		if !errors.Is(err, delf.ErrNoSymbols) {
			p.note("the symbol table could not be decoded: %v", err)
		}
		return
	}
	s.symDecoded = true
	for i, sy := range syms {
		if i%4096 == 0 && p.ctx.Err() != nil {
			return
		}
		if name := cleanSymbol(sy.Name); name != "" {
			s.observe(name)
		}
	}
}

// observe records stack-protector and FORTIFY_SOURCE evidence.
func (s *symbolScan) observe(name string) {
	switch name {
	case "__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local", "__stack_smash_handler":
		s.canary = true
		return
	}
	if strings.HasPrefix(name, "__") && strings.HasSuffix(name, "_chk") && len(s.fortify) < 64 {
		s.fortify[name] = struct{}{}
	}
}

// cleanSymbol strips a trailing @VERSION (or @@VERSION) and makes the name safe to print.
func cleanSymbol(name string) string {
	if i := strings.IndexByte(name, '@'); i > 0 {
		name = name[:i]
	}
	return binio.Printable(name, maxName)
}
