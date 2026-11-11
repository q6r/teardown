// Package zipscan reads the structure of ZIP archives without trusting them.
//
// Unlike archive/zip it never loads the whole directory into memory: the
// central directory is streamed record by record, only a capped number of
// entries is retained, and aggregate statistics (totals, compression ratio,
// duplicate and overlapping entries) are computed on the fly for every record.
// It copes with prefixed (self-extracting) archives, ZIP64, and damaged or
// missing end-of-central-directory records (entries are then recovered from the
// local headers), and it never inflates more than a caller-given number of
// bytes.
package zipscan

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/q6r/teardown/internal/binio"
)

// Errors returned by this package; test with [errors.Is].
var (
	// ErrNotZip means the input has neither an end-of-central-directory record
	// nor a local file header at its start.
	ErrNotZip = errors.New("zipscan: not a ZIP archive")
	// ErrUnsupported means the entry uses a compression method other than
	// stored (0) or DEFLATE (8).
	ErrUnsupported = errors.New("zipscan: unsupported compression method")
	// ErrTooLarge means the entry would inflate beyond the caller's limit.
	ErrTooLarge = errors.New("zipscan: entry exceeds the size limit")
	// ErrEncrypted means the entry is encrypted and cannot be read.
	ErrEncrypted = errors.New("zipscan: entry is encrypted")
	// ErrCorrupt means the entry's local header is missing or inconsistent.
	ErrCorrupt = errors.New("zipscan: corrupt entry")
)

// Record signatures and fixed sizes of the ZIP format.
const (
	sigLocal   = 0x04034b50
	sigCentral = 0x02014b50
	sigEnd     = 0x06054b50
	sigEnd64   = 0x06064b50
	sigLoc64   = 0x07064b50
	sigDesc    = 0x08074b50

	localHeaderLen   = 30
	centralHeaderLen = 46
	endLen           = 22
	end64Len         = 56
	loc64Len         = 20

	// maxEndSearch is how far from the end of the file the end record is
	// searched: the largest comment (65535 bytes) plus the record itself.
	maxEndSearch = 65535 + endLen

	// MaxRecords is the hard cap on central-directory records walked in one scan.
	MaxRecords = 1_000_000
	// maxLocalRecords bounds recovery from local headers, which buffers entries.
	maxLocalRecords = 100_000

	maxRawName      = 2048
	maxNameRunes    = 512
	maxCommentRunes = 1024
)

// Entry is one archive member as described by its central-directory record, or
// by its local header when the directory had to be recovered.
type Entry struct {
	// Name is the member name made safe for reports and terminals: control
	// characters and invalid UTF-8 are escaped and very long names are cut.
	Name string
	// RawName is the name exactly as stored, cut at 2 KiB. It exists for
	// path-safety checks only and must never be printed.
	RawName string
	// Method is the compression method (0 stored, 8 DEFLATE, 99 AES-encrypted).
	Method uint16
	// Flags are the general-purpose bit flags.
	Flags uint16
	// CRC32 is the checksum declared by the archive.
	CRC32 uint32
	// CompressedSize and UncompressedSize are the declared sizes (ZIP64 aware).
	CompressedSize, UncompressedSize uint64
	// LocalOffset is the absolute file offset of the local header; it is
	// negative or beyond the file when the archive is damaged.
	LocalOffset int64
	// Encrypted is true for traditional, strong and AES encryption.
	Encrypted bool
	// IsDir is true for names ending in a slash.
	IsDir bool
}

// Directory is the result of scanning an archive.
type Directory struct {
	// Entries holds the first max records (see [Scan]).
	Entries []Entry
	// Count is the number of records walked (at most [MaxRecords]).
	Count int
	// Truncated is true when Entries does not hold every record walked, or the
	// walk stopped at [MaxRecords].
	Truncated bool
	// Comment is the archive comment, made printable.
	Comment string
	// PrefixBytes is the number of bytes before the first local header, for
	// example a self-extractor stub.
	PrefixBytes int64
	// TotalCompressed and TotalUncompressed sum the declared sizes of every
	// record walked, saturating instead of overflowing.
	TotalCompressed, TotalUncompressed uint64
	// CDOffset is the absolute offset of the central directory. An APK signing
	// block, when present, ends here.
	CDOffset int64
	// Zip64 is true when the ZIP64 end records were used.
	Zip64 bool

	// MaxRatio is the highest uncompressed/compressed ratio of any record with
	// both sizes non-zero, and MaxRatioEntry names that record.
	MaxRatio      float64
	MaxRatioEntry string
	// Overlapping counts records whose local data starts inside the span of an
	// earlier record, the signature of overlapping-entry zip bombs.
	Overlapping int
	// Duplicates counts records whose name repeats an earlier record's name.
	Duplicates int
	// BadOffsets counts records whose local header offset lies outside the file.
	BadOffsets int
	// Recovered is true when the central directory could not be located through
	// the end record and the entries were found by other means.
	Recovered bool
	// Warnings describes inconsistencies met while scanning.
	Warnings []string
}

// Find returns the first retained entry with exactly the given name.
func (d *Directory) Find(name string) (Entry, bool) {
	for _, e := range d.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Scan reads the directory of the archive in r (size bytes), retaining at most
// maxEntries entries; a value of zero or less retains none but still produces
// every count and total. When the context ends or reading fails after some
// progress, the partial Directory is returned together with the error.
func Scan(ctx context.Context, r io.ReaderAt, size int64, maxEntries int) (*Directory, error) {
	return Walk(ctx, r, size, maxEntries, nil)
}

// Walk is [Scan] that additionally calls visit for every record walked, not
// only for the retained ones, so callers can derive facts about all entries
// (path safety, file kinds) in constant memory.
func Walk(ctx context.Context, r io.ReaderAt, size int64, maxEntries int, visit func(Entry)) (*Directory, error) {
	if size < endLen {
		return nil, fmt.Errorf("%w: %d bytes is smaller than the smallest archive", ErrNotZip, size)
	}
	c := newCollector(size, maxEntries, visit)
	rec, found, err := locateEnd(r, size)
	if err != nil {
		return nil, err
	}
	if found {
		err = c.walkCentral(ctx, r, rec)
		c.checkPrefix(r)
	} else {
		err = c.walkLocal(ctx, r)
		if errors.Is(err, ErrNotZip) {
			return nil, err
		}
	}
	return c.finish(), err
}

// span is the byte range an entry occupies according to its directory record.
type span struct{ start, end int64 }

// collector accumulates records from either walker.
type collector struct {
	size       int64
	maxEntries int
	visit      func(Entry)
	d          Directory
	base       int64
	spans      []span
	hashes     []uint64
	minOff     int64
	capped     bool
}

func newCollector(size int64, maxEntries int, visit func(Entry)) *collector {
	c := &collector{size: size, maxEntries: max(maxEntries, 0), visit: visit, minOff: math.MaxInt64}
	c.d.Entries = make([]Entry, 0, min(c.maxEntries, 256))
	return c
}

func (c *collector) warnf(format string, args ...any) {
	c.d.Warnings = append(c.d.Warnings, fmt.Sprintf(format, args...))
}

// add records one entry; nameLen is the full stored name length and nameHash a
// hash of the full name, both used for the structural statistics.
func (c *collector) add(e Entry, nameLen int, nameHash uint64) {
	c.d.Count++
	if len(c.d.Entries) < c.maxEntries {
		c.d.Entries = append(c.d.Entries, e)
	}
	c.d.TotalCompressed = satAdd(c.d.TotalCompressed, e.CompressedSize)
	c.d.TotalUncompressed = satAdd(c.d.TotalUncompressed, e.UncompressedSize)
	if e.CompressedSize > 0 && e.UncompressedSize > 0 {
		if ratio := float64(e.UncompressedSize) / float64(e.CompressedSize); ratio > c.d.MaxRatio {
			c.d.MaxRatio, c.d.MaxRatioEntry = ratio, e.Name
		}
	}
	if e.LocalOffset < 0 || e.LocalOffset > c.size-localHeaderLen {
		c.d.BadOffsets++
	} else {
		c.minOff = min(c.minOff, e.LocalOffset)
		extent := int64(min(e.CompressedSize, 1<<40))
		c.spans = append(c.spans, span{e.LocalOffset, e.LocalOffset + localHeaderLen + int64(nameLen) + extent})
	}
	c.hashes = append(c.hashes, nameHash)
	if c.visit != nil {
		c.visit(e)
	}
}

// checkPrefix warns when the data before the first local header starts with a
// local header of its own: then two archives are concatenated or one is nested
// inside the other, and different tools may read different ones.
func (c *collector) checkPrefix(r io.ReaderAt) {
	if c.minOff == math.MaxInt64 || c.minOff < localHeaderLen {
		return
	}
	if b, err := binio.ReadAt(r, c.size, 0, 4); err == nil && le32(b) == sigLocal {
		c.warnf("another ZIP archive precedes this one (the data before offset %d starts with a local header): archives are concatenated or nested, and tools may read a different one", c.minOff)
	}
}

// finish derives the aggregate statistics and returns the directory.
func (c *collector) finish() *Directory {
	d := &c.d
	d.Truncated = c.capped || d.Count > len(d.Entries)
	if c.minOff != math.MaxInt64 {
		d.PrefixBytes = max(c.minOff, 0)
	}
	slices.SortFunc(c.spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	maxEnd := int64(math.MinInt64)
	for _, s := range c.spans {
		if s.start < maxEnd {
			d.Overlapping++
		}
		maxEnd = max(maxEnd, s.end)
	}
	slices.Sort(c.hashes)
	total := len(c.hashes)
	unique := len(slices.Compact(c.hashes))
	d.Duplicates = total - unique
	return d
}

// makeEntry builds an Entry from the raw record fields.
func makeEntry(name []byte, flags, method uint16, crc uint32, comp, uncomp uint64, offset int64) Entry {
	raw := name
	if len(raw) > maxRawName {
		raw = raw[:maxRawName]
	}
	return Entry{
		Name:             binio.Printable(string(raw), maxNameRunes),
		RawName:          string(raw),
		Method:           method,
		Flags:            flags,
		CRC32:            crc,
		CompressedSize:   comp,
		UncompressedSize: uncomp,
		LocalOffset:      offset,
		Encrypted:        flags&0x41 != 0 || method == 99,
		IsDir:            len(name) > 0 && name[len(name)-1] == '/',
	}
}

func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxUint64
}

// fnv64a hashes a name for duplicate detection.
func fnv64a(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
