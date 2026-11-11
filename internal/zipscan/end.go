package zipscan

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/q6r/teardown/internal/binio"
)

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// endRecord is the located and resolved end of the central directory.
type endRecord struct {
	count    uint64
	cdSize   uint64
	cdOffset uint64
	comment  string
	zip64    bool
	// endOff is the offset of the record that follows the central directory:
	// the ZIP64 end record when there is one, otherwise the end record.
	endOff int64
	// cdStart is the absolute offset of the first central-directory record and
	// base the amount to add to the offsets stored in the records.
	cdStart  int64
	base     int64
	warnings []string
}

// locateEnd searches the tail of the file for an end-of-central-directory
// record whose directory actually exists. A fake signature inside the archive
// comment is skipped when its directory does not resolve, and an empty
// directory never wins over one that has entries, so a planted decoy cannot
// hide the real contents. Several valid records are reported as a warning
// because archive tools may then disagree about what the archive holds.
func locateEnd(r io.ReaderAt, size int64) (endRecord, bool, error) {
	tail := min(size, maxEndSearch)
	buf, err := binio.ReadAt(r, size, size-tail, tail)
	if err != nil {
		return endRecord{}, false, err
	}
	var (
		best  endRecord
		found bool
		valid int
	)
	for i := len(buf) - endLen; i >= 0; i-- {
		if le32(buf[i:]) != sigEnd {
			continue
		}
		rec, ok := parseEnd(r, size, size-tail+int64(i), buf[i:])
		if !ok {
			continue
		}
		valid++
		if !found || (best.isEmpty() && !rec.isEmpty()) {
			best, found = rec, true
		}
	}
	if valid > 1 {
		best.warnings = append(best.warnings,
			fmt.Sprintf("%d end-of-central-directory records found; archive tools may disagree about the contents", valid))
	}
	return best, found, nil
}

// isEmpty reports whether the record describes an archive without entries.
func (e endRecord) isEmpty() bool { return e.count == 0 && e.cdSize == 0 }

// parseEnd decodes the end record at off (b starts at it and holds at least
// endLen bytes) and resolves the directory it describes.
func parseEnd(r io.ReaderAt, size, off int64, b []byte) (endRecord, bool) {
	rec := endRecord{
		count:    uint64(le16(b[10:])),
		cdSize:   uint64(le32(b[12:])),
		cdOffset: uint64(le32(b[16:])),
		endOff:   off,
	}
	if le16(b[4:]) != 0 || le16(b[6:]) != 0 {
		rec.warnings = append(rec.warnings, "multi-volume archive: entries stored on other volumes cannot be read")
	}
	commentLen := int(le16(b[20:]))
	comment := b[endLen:]
	switch {
	case len(comment) > commentLen:
		comment = comment[:commentLen]
	case len(comment) < commentLen:
		rec.warnings = append(rec.warnings, "archive comment is cut off")
	}
	rec.comment = binio.Printable(string(comment), maxCommentRunes)
	if rec.count == 0xFFFF || rec.cdSize == 0xFFFFFFFF || rec.cdOffset == 0xFFFFFFFF {
		readEnd64(r, size, off, &rec)
	}
	return rec, rec.resolve(r, size)
}

// readEnd64 looks for the ZIP64 locator right before the end record and, when
// it leads to a valid ZIP64 end record, replaces the sentinel values.
func readEnd64(r io.ReaderAt, size, endOff int64, rec *endRecord) {
	locOff := endOff - loc64Len
	loc, err := binio.ReadAt(r, size, locOff, loc64Len)
	if err != nil || le32(loc) != sigLoc64 {
		return
	}
	// The record normally sits right before the locator; the stored offset is
	// relative to the start of the archive, which differs when data is prepended.
	for _, cand := range []int64{int64(min(le64(loc[8:]), math.MaxInt64)), locOff - end64Len} {
		b, err := binio.ReadAt(r, size, cand, end64Len)
		if err != nil || le32(b) != sigEnd64 {
			continue
		}
		rec.count, rec.cdSize, rec.cdOffset = le64(b[32:]), le64(b[40:]), le64(b[48:])
		rec.endOff, rec.zip64 = cand, true
		return
	}
}

// resolve finds where the central directory really starts, following the same
// idea as archive/zip: the directory ends where the end record begins, so any
// difference to the stored offset is data prepended to the archive.
func (e *endRecord) resolve(r io.ReaderAt, size int64) bool {
	if e.cdOffset > math.MaxInt64 || e.cdSize > uint64(e.endOff) {
		return false
	}
	derived := e.endOff - int64(e.cdSize)
	if e.count == 0 && e.cdSize == 0 {
		e.cdStart, e.base = derived, derived-int64(e.cdOffset)
		return true
	}
	if hasCentralSignature(r, size, derived) {
		e.cdStart, e.base = derived, derived-int64(e.cdOffset)
		return true
	}
	if hasCentralSignature(r, size, int64(e.cdOffset)) {
		e.cdStart, e.base = int64(e.cdOffset), 0
		return true
	}
	return false
}

func hasCentralSignature(r io.ReaderAt, size, off int64) bool {
	b, err := binio.ReadAt(r, size, off, 4)
	return err == nil && le32(b) == sigCentral
}
