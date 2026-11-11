// Package sniff identifies what kind of file a byte source is, from magic bytes
// and light structure checks.
//
// Detection is table driven and deliberately shallow: it never parses a format
// completely, never executes anything and never fails. Content that matches no
// signature is reported as "text" or "data". The amount of work is bounded for
// any input size: the first and the last 64 KiB, a handful of small structure
// probes, and for ZIP-based formats one pass over the central directory.
package sniff

import (
	"io"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Sizes of the windows Detect reads from the start and the end of a file.
const (
	headSize = 64 << 10
	tailSize = 64 << 10
)

const mimeOctet = "application/octet-stream"

// Tags shared by several detectors.
const (
	tagEmpty       = "empty"
	tagUPX         = "upx"
	tagPyInstaller = "pyinstaller"
	tag32Bit       = "32-bit"
	tag64Bit       = "64-bit"
)

// Detect identifies the content of the size bytes readable through r.
//
// The returned report.Type always has a non-empty ID, family, label and MIME
// type, and a non-nil, sorted, duplicate-free Tags slice. Confidence is high when
// a magic number and the structure behind it agree, medium when only the magic
// number matched (for example a truncated file) and low for the text and data
// fallbacks. A read error or a short read simply means less evidence: Detect
// never returns an error and never panics, whatever r returns.
func Detect(r io.ReaderAt, size int64) report.Type {
	if size <= 0 {
		return newType(report.TypeData, report.FamilyData, "empty file", mimeOctet,
			report.ConfidenceHigh, tagEmpty)
	}
	head := readWindow(r, 0, min(size, headSize))
	if len(head) == 0 {
		return unknownType()
	}
	p := &probe{r: r, size: size, head: head}
	for _, detect := range detectors {
		if t, ok := detect(p); ok {
			return t
		}
	}
	return unknownType()
}

// detector inspects a probe and reports whether it recognises the content.
type detector func(p *probe) (report.Type, bool)

// detectors run in order and the first match wins: cheap, specific signatures
// come first, the text heuristic comes last.
var detectors = [...]detector{
	detectMZ,
	detectELF,
	detectMachO,
	detectCafe,
	detectWasm,
	detectPK,
	detectSimple,
	detectPDF,
	detectPyc,
	detectASAR,
	detectTar,
	detectSafetensors,
	detectScript,
	detectText,
}

// probe is the evidence available to detectors: the head of the file is always
// loaded, the tail and other regions are read on demand.
type probe struct {
	r    io.ReaderAt
	size int64
	head []byte

	tail       []byte
	tailLoaded bool
}

// tailBytes returns the last tailSize bytes of the file (the head when the whole
// file fits in it).
func (p *probe) tailBytes() []byte {
	if p.size <= int64(len(p.head)) {
		return p.head
	}
	if !p.tailLoaded {
		p.tailLoaded = true
		n := min(p.size, tailSize)
		p.tail = readWindow(p.r, p.size-n, n)
	}
	return p.tail
}

// readWindow reads up to n bytes at off. A short read or an I/O error yields
// whatever bytes arrived: sniffing degrades to less evidence instead of failing.
func readWindow(r io.ReaderAt, off, n int64) []byte {
	if n <= 0 || off < 0 {
		return nil
	}
	buf := make([]byte, n)
	got, _ := r.ReadAt(buf, off)
	return buf[:max(got, 0)]
}

// newType assembles a report.Type with normalised tags: lower-case, sorted,
// unique and never nil.
func newType(id, family, label, mime string, conf report.Confidence, tags ...string) report.Type {
	clean := make([]string, 0, len(tags))
	for _, t := range tags {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			clean = append(clean, t)
		}
	}
	slices.Sort(clean)
	return report.Type{
		ID:         id,
		Family:     family,
		Label:      label,
		MIME:       mime,
		Confidence: conf,
		Tags:       slices.Compact(clean),
	}
}

func unknownType() report.Type {
	return newType(report.TypeData, report.FamilyData, "data", mimeOctet, report.ConfidenceLow)
}
