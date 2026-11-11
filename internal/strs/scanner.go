package strs

import (
	"cmp"
	"encoding/binary"
	"maps"
	"slices"

	"github.com/q6r/teardown/internal/report"
)

// Encodings reported in StringItem.Encoding.
const (
	encodingASCII = "ascii"
	encodingUTF16 = "utf16le"
)

type encoding uint8

const (
	encASCII encoding = iota
	encUTF16
)

func (e encoding) String() string {
	if e == encUTF16 {
		return encodingUTF16
	}
	return encodingASCII
}

// printable marks the bytes that may be part of a string: 0x20..0x7E and TAB.
var printable = buildPrintable()

func buildPrintable() (t [256]bool) {
	for c := 0x20; c <= 0x7e; c++ {
		t[c] = true
	}
	t['\t'] = true
	return t
}

// splitWindow is how far back from the length cap a split looks for a
// delimiter so that a token is not cut in the middle when it can be avoided.
const splitWindow = 128

// item is one retained string.
type item struct {
	off      int64
	enc      encoding
	cat      int
	kind     string
	value    string
	redacted bool
}

// Scanner extracts and classifies strings from a byte stream.
//
// It implements [io.Writer] and never fails; feed it the stream in chunks of
// any size, then call [Scanner.Result]. The outcome does not depend on how the
// stream was chunked. A Scanner is not safe for concurrent use.
//
// Runs shorter than the minimum length are ignored, as are noise runs (a single
// repeated byte, or fewer than three distinct bytes in a run shorter than 16).
// A UTF-16LE run never starts directly after a printable byte: that byte is
// almost always the last character of an ASCII string whose NUL terminator
// would otherwise be mistaken for the high byte of a code unit and glue the
// character to the front of a wide string that follows.
// A run longer than [MaxStringLen] is split into several strings, preferring a
// cut just after a delimiter such as a space or a quote, and the result is then
// marked truncated because those strings are fragments. After [MaxTotal]
// strings the scanner stops and the result is marked truncated.
//
// Retention is bounded: at most MaxItems classified and MaxItems plain strings
// are held. When classified strings exceed MaxItems the ones in the
// categories that come first in the priority order (secrets, URLs, ...) win and
// within a category the earliest in the stream win.
type Scanner struct {
	opts     Options
	maxTotal int

	// pos is the stream offset of the next byte; prevPrintable tells whether the
	// byte before it was printable.
	pos           int64
	prevPrintable bool

	// ASCII run in progress.
	aOn    bool
	aStart int64
	aBuf   []byte

	// UTF-16LE run in progress: uBuf holds the decoded characters, uLow the
	// low byte waiting for its 0x00 high byte when uPending is set.
	uStart   int64
	uBuf     []byte
	uLow     byte
	uPending bool

	total       int
	counts      [numCategories]int
	cls         [cPlain][]item
	nClassified int
	plain       []item

	capped    bool
	split     bool
	done      bool
	finalized bool
	result    report.Strings
}

// NewScanner returns a scanner for the options.
func NewScanner(opts Options) *Scanner {
	return newScanner(opts, MaxTotal)
}

func newScanner(opts Options, maxTotal int) *Scanner {
	return &Scanner{
		opts:     opts.normalize(),
		maxTotal: maxTotal,
		aBuf:     make([]byte, 0, MaxStringLen),
		uBuf:     make([]byte, 0, MaxStringLen),
	}
}

// Write consumes the next chunk of the stream. It always reports len(p) bytes
// written and a nil error. Writing after [Scanner.Result] has no effect.
func (s *Scanner) Write(p []byte) (int, error) {
	n := len(p)
	if s.done || s.finalized || n == 0 {
		return n, nil
	}
	base := s.pos
	s.pos += int64(n)
	for i := 0; i < n && !s.done; {
		switch {
		case s.aOn:
			// Inside an ASCII run whose previous byte was printable and with the
			// UTF-16 tracker idle, a printable byte can neither start nor extend a
			// UTF-16 run, so the rest of the printable stretch is appended in bulk.
			if s.prevPrintable && !s.uPending && len(s.uBuf) == 0 && printable[p[i]] {
				j := i + 1
				for j < n && printable[p[j]] {
					j++
				}
				s.appendASCII(p[i:j])
				i = j
				continue
			}
		case !s.uPending && len(s.uBuf) == 0:
			// Both trackers are idle: only a printable byte can start a run.
			start := i
			i = skipUnprintable(p, i)
			if i > start {
				s.prevPrintable = false
			}
			if i == n {
				continue
			}
		}
		b, off := p[i], base+int64(i)
		s.stepASCII(b, off)
		s.stepUTF16(b, off)
		s.prevPrintable = printable[b]
		if s.done {
			break
		}
		i++
	}
	return n, nil
}

// skipUnprintable returns the index of the first printable byte of p at or
// after i, or len(p). Runs of zero bytes, the commonest filler in executables,
// are skipped eight at a time.
func skipUnprintable(p []byte, i int) int {
	for i+8 <= len(p) && binary.LittleEndian.Uint64(p[i:i+8]) == 0 {
		i += 8
	}
	for i < len(p) && !printable[p[i]] {
		i++
	}
	return i
}

// appendASCII extends the ASCII run with a stretch of printable bytes,
// splitting it whenever it reaches [MaxStringLen].
func (s *Scanner) appendASCII(chunk []byte) {
	for len(chunk) > 0 {
		room := MaxStringLen - len(s.aBuf)
		if len(chunk) < room {
			s.aBuf = append(s.aBuf, chunk...)
			return
		}
		s.aBuf = append(s.aBuf, chunk[:room]...)
		chunk = chunk[room:]
		s.aBuf, s.aStart = s.splitRun(s.aBuf, s.aStart, 1, encASCII)
	}
}

func (s *Scanner) stepASCII(b byte, off int64) {
	if printable[b] {
		if !s.aOn {
			s.aOn, s.aStart = true, off
		}
		s.aBuf = append(s.aBuf, b)
		if len(s.aBuf) >= MaxStringLen {
			s.aBuf, s.aStart = s.splitRun(s.aBuf, s.aStart, 1, encASCII)
		}
		return
	}
	if s.aOn {
		s.endASCII()
	}
}

func (s *Scanner) endASCII() {
	s.emit(s.aStart, encASCII, s.aBuf)
	s.aOn = false
	s.aBuf = s.aBuf[:0]
}

func (s *Scanner) stepUTF16(b byte, off int64) {
	if s.uPending {
		if b == 0 {
			s.uBuf = append(s.uBuf, s.uLow)
			s.uPending = false
			if len(s.uBuf) >= MaxStringLen {
				s.uBuf, s.uStart = s.splitRun(s.uBuf, s.uStart, 2, encUTF16)
			}
			return
		}
		// The pending byte was not the low half of a code unit: the run so far
		// ends, and this byte is looked at afresh below.
		s.uPending = false
		s.endUTF16()
	}
	if printable[b] {
		if len(s.uBuf) == 0 {
			if s.prevPrintable {
				return
			}
			s.uStart = off
		}
		s.uLow, s.uPending = b, true
		return
	}
	if len(s.uBuf) > 0 {
		s.endUTF16()
	}
}

func (s *Scanner) endUTF16() {
	if len(s.uBuf) > 0 {
		s.emit(s.uStart, encUTF16, s.uBuf)
		s.uBuf = s.uBuf[:0]
	}
}

// splitRun emits the leading part of a full run buffer and returns the
// remainder together with its stream offset. unit is the number of stream bytes
// per buffered character.
func (s *Scanner) splitRun(buf []byte, start, unit int64, enc encoding) ([]byte, int64) {
	s.split = true
	cut := len(buf)
	for i := len(buf) - 1; i > 0 && i >= len(buf)-splitWindow; i-- {
		if isSplitDelimiter(buf[i]) {
			cut = i + 1
			break
		}
	}
	s.emit(start, enc, buf[:cut])
	rest := copy(buf, buf[cut:])
	return buf[:rest], start + int64(cut)*unit
}

func isSplitDelimiter(c byte) bool {
	switch c {
	case ' ', '\t', '"', '\'', ',', ';', '&', '|', '<', '>', '(', ')', '[', ']', '{', '}':
		return true
	}
	return false
}

// isNoise reports whether a run is not worth keeping: a single repeated byte,
// or, when shorter than 16 bytes, one with fewer than three distinct bytes.
func isNoise(b []byte) bool {
	first := b[0]
	same := true
	for _, c := range b[1:] {
		if c != first {
			same = false
			break
		}
	}
	if same {
		return true
	}
	if len(b) >= 16 {
		return false
	}
	distinct := 0
	for i, c := range b {
		seen := false
		for _, d := range b[:i] {
			if d == c {
				seen = true
				break
			}
		}
		if !seen {
			distinct++
			if distinct >= 3 {
				return false
			}
		}
	}
	return true
}

// emit classifies a finished run and files it.
func (s *Scanner) emit(off int64, enc encoding, raw []byte) {
	if s.done || len(raw) < s.opts.MinLength || isNoise(raw) {
		return
	}
	if s.total >= s.maxTotal {
		s.capped, s.done = true, true
		return
	}
	s.total++
	str := string(raw)
	c := classify(str)
	s.counts[c.cat]++
	it := item{off: off, enc: enc, cat: c.cat, kind: c.kind, value: str}
	if c.cat == cSecret {
		it.value, it.redacted = c.redacted, true
	}
	if c.cat == cPlain {
		if len(s.plain) < s.opts.MaxItems {
			s.plain = append(s.plain, it)
		}
		return
	}
	s.keepClassified(it)
}

// keepClassified retains a classified item, evicting the latest item of the
// lowest-priority category when the bucket is full and that category ranks
// below the new item's.
func (s *Scanner) keepClassified(it item) {
	if s.nClassified < s.opts.MaxItems {
		s.cls[it.cat] = append(s.cls[it.cat], it)
		s.nClassified++
		return
	}
	for c := cPlain - 1; c > it.cat; c-- {
		if n := len(s.cls[c]); n > 0 {
			s.cls[c][n-1] = item{}
			s.cls[c] = s.cls[c][:n-1]
			s.cls[it.cat] = append(s.cls[it.cat], it)
			return
		}
	}
}

// Result flushes pending runs and returns the extracted strings. Calling it
// again returns the same data; the Scanner ignores writes afterwards.
func (s *Scanner) Result() report.Strings {
	if !s.finalized {
		if s.aOn {
			s.endASCII()
		}
		s.uPending = false
		s.endUTF16()
		s.finalized = true
		s.result = s.build()
	}
	out := s.result
	out.Items = slices.Clone(out.Items)
	out.ByCategory = maps.Clone(out.ByCategory)
	return out
}

func (s *Scanner) build() report.Strings {
	items := make([]item, 0, s.nClassified+len(s.plain))
	for c := range cPlain {
		items = append(items, s.cls[c]...)
	}
	room := min(len(s.plain), max(s.opts.MaxItems-len(items), 0))
	items = append(items, s.plain[:room]...)
	slices.SortStableFunc(items, func(a, b item) int {
		return cmp.Or(cmp.Compare(a.off, b.off), cmp.Compare(a.enc, b.enc))
	})

	out := make([]report.StringItem, len(items))
	for i, it := range items {
		out[i] = report.StringItem{
			Value:    it.value,
			Offset:   it.off,
			Encoding: it.enc.String(),
			Category: categoryNames[it.cat],
			Redacted: it.redacted,
			Kind:     it.kind,
		}
	}
	byCategory := make(map[string]int, numCategories)
	for c, n := range s.counts {
		if n > 0 {
			byCategory[categoryNames[c]] = n
		}
	}
	return report.Strings{
		Total:      s.total,
		MinLength:  s.opts.MinLength,
		Truncated:  s.capped || s.split || len(items) < s.total,
		ByCategory: byCategory,
		Items:      out,
	}
}
