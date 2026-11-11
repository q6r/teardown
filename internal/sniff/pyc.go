package sniff

import (
	"encoding/binary"
	"fmt"

	"github.com/q6r/teardown/internal/report"
)

// pycRelease is a range of Python bytecode magic numbers.
//
// The ranges come from the magic-number history in CPython's importlib: every
// development snapshot of a release has its own number, and the numbers of one
// release form one contiguous block. A match therefore means "written by that
// release or one of its pre-releases". Numbers above the newest block are
// reported as newer than the table knows.
type pycRelease struct {
	lo, hi  int
	version string
}

var pycReleases = [...]pycRelease{
	{20121, 20121, "1.5"},
	{50428, 50428, "1.6"},
	{50823, 50823, "2.0"},
	{60202, 60202, "2.1"},
	{60717, 60717, "2.2"},
	{62011, 62021, "2.3"},
	{62041, 62061, "2.4"},
	{62071, 62131, "2.5"},
	{62151, 62161, "2.6"},
	{62171, 62211, "2.7"},
	{3000, 3139, "3.0"},
	{3140, 3159, "3.1"},
	{3160, 3189, "3.2"},
	{3190, 3249, "3.3"},
	{3250, 3319, "3.4"},
	{3320, 3359, "3.5"},
	{3360, 3389, "3.6"},
	{3390, 3399, "3.7"},
	{3400, 3419, "3.8"},
	{3420, 3429, "3.9"},
	{3430, 3449, "3.10"},
	{3450, 3499, "3.11"},
	{3500, 3549, "3.12"},
	{3550, 3599, "3.13"},
	{3600, 3649, "3.14"},
}

// pycNewer is the range reported for magic numbers beyond the table.
const (
	pycNewerLo = 3650
	pycNewerHi = 3999
)

// pycVersion maps a magic number to a Python release name.
func pycVersion(magic int) (version string, known bool) {
	for _, r := range &pycReleases {
		if magic >= r.lo && magic <= r.hi {
			return r.version, true
		}
	}
	if magic >= pycNewerLo && magic <= pycNewerHi {
		return "3.15+", true
	}
	return "", false
}

// pycHeaderLen is the length of the .pyc header before the marshalled code
// object: magic and mtime (8), plus source size (12) from 3.3, plus flags (16)
// from 3.7 (PEP 552).
func pycHeaderLen(magic int) int {
	switch {
	case magic >= 3390 && magic < 20000:
		return 16
	case magic >= 3190 && magic < 3390:
		return 12
	}
	return 8
}

// detectPyc recognises compiled Python files: a two-byte magic number, "\r\n",
// and, when the file is long enough to check, a marshalled code object.
func detectPyc(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 4 || h[2] != '\r' || h[3] != '\n' {
		return report.Type{}, false
	}
	magic := int(binary.LittleEndian.Uint16(h))
	version, known := pycVersion(magic)
	if !known {
		return report.Type{}, false
	}
	hdr := pycHeaderLen(magic)
	if hdr == 16 && len(h) >= 8 && binary.LittleEndian.Uint32(h[4:])&^3 != 0 {
		return report.Type{}, false // PEP 552 flags use only the two low bits
	}
	conf := report.ConfidenceMedium
	if len(h) > hdr {
		// The first marshalled object is a code object: type 'c', optionally with FLAG_REF.
		if b := h[hdr]; b != 'c' && b != 'c'|0x80 {
			return report.Type{}, false
		}
		conf = report.ConfidenceHigh
	}
	return newType(report.TypePyc, report.FamilyBytecode, fmt.Sprintf("Python %s bytecode (magic %d)", version, magic),
		"application/x-python-code", conf, "python-"+version), true
}
