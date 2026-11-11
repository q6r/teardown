// Package limits carries the resource bounds that every format parser honours.
//
// The limits cap what a parser records and how much metadata it may hold in
// memory; they are deliberately independent of how much of the file a parser may
// read, which is always bounded by the file size itself.
package limits

// Limits bounds parser output and buffering. The zero value is valid: every zero
// field is replaced by its default (see [Limits.Normalize]).
type Limits struct {
	// MaxList caps the number of items recorded in any single list (imports,
	// exports, archive entries, symbols, ...). Parsers must still report true counts.
	MaxList int
	// MaxMeta caps the bytes of metadata (JSON headers, string tables, manifests,
	// decompressed entries) a parser may hold in memory at once.
	MaxMeta int64
	// MaxDepth caps nesting when a parser descends into containers.
	MaxDepth int
}

// Absolute ceilings used by [Default].
const (
	defaultMaxList  = 5000
	defaultMaxMeta  = 16 << 20 // 16 MiB
	defaultMaxDepth = 3

	minList = 64
)

// Default returns the limits used for large files.
func Default() Limits {
	return Limits{MaxList: defaultMaxList, MaxMeta: defaultMaxMeta, MaxDepth: defaultMaxDepth}
}

// ForSize scales the defaults down for small inputs: a 2 KiB file cannot
// sensibly hold thousands of imports, so a parser given such a file records
// proportionally less and rejects implausible counts early.
func ForSize(size int64) Limits {
	l := Default()
	if size < 0 {
		size = 0
	}
	if byLen := size / 16; byLen < int64(l.MaxList) {
		l.MaxList = int(max(byLen, minList))
	}
	if size < l.MaxMeta {
		l.MaxMeta = max(size, 4096)
	}
	return l
}

// Normalize returns l with zero or negative fields replaced by the defaults.
func (l Limits) Normalize() Limits {
	d := Default()
	if l.MaxList <= 0 {
		l.MaxList = d.MaxList
	}
	if l.MaxMeta <= 0 {
		l.MaxMeta = d.MaxMeta
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}
