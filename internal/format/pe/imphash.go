package pe

import (
	"io"
	"strconv"
	"strings"
)

// impHasher builds the text that pefile's get_imphash() hashes: the
// lower-cased "library.function" pair of every import, joined with commas. The
// library name loses its extension only when it is .dll, .ocx or .sys, and an
// import by ordinal is named through the lookup tables for ws2_32, wsock32 and
// oleaut32 (see ordinals.go, which is partial) or, failing that, "ord<N>".
type impHasher struct {
	w     io.Writer
	wrote bool
}

// newImpHasher returns a hasher that streams its text to w, normally an MD5.
func newImpHasher(w io.Writer) *impHasher { return &impHasher{w: w} }

// add appends the entry for an import by name.
func (h *impHasher) add(lib, fn string) { h.put(impLibrary(lib), strings.ToLower(fn)) }

// addOrdinal appends the entry for an import by ordinal.
func (h *impHasher) addOrdinal(lib string, ord uint16) {
	h.put(impLibrary(lib), ordinalName(strings.ToLower(lib), ord))
}

func (h *impHasher) put(lib, fn string) {
	var sb strings.Builder
	if h.wrote {
		sb.WriteByte(',')
	}
	sb.WriteString(lib)
	sb.WriteByte('.')
	sb.WriteString(fn)
	// hash.Hash and bytes.Buffer writers never return an error.
	_, _ = io.WriteString(h.w, sb.String())
	h.wrote = true
}

// impLibrary lower-cases a DLL name and strips a .dll, .ocx or .sys extension.
func impLibrary(lib string) string {
	l := strings.ToLower(lib)
	if i := strings.LastIndexByte(l, '.'); i >= 0 {
		switch l[i+1:] {
		case "dll", "ocx", "sys":
			return l[:i]
		}
	}
	return l
}

// ordinalName names an import by ordinal like pefile's ordlookup module: the
// table entry when there is one, otherwise "ord<N>". libLower must be the
// lower-cased DLL name including its extension.
func ordinalName(libLower string, ord uint16) string {
	var table map[uint16]string
	switch libLower {
	case "ws2_32.dll":
		table = ws232Ordinals
	case "wsock32.dll":
		table = wsock32Ordinals
	case "oleaut32.dll":
		table = oleaut32Ordinals
	}
	if name, ok := table[ord]; ok {
		return strings.ToLower(name)
	}
	return "ord" + strconv.Itoa(int(ord))
}
