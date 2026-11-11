package zipscan

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/q6r/teardown/internal/binio"
)

// Read returns the uncompressed content of an entry, which must be stored or
// DEFLATE-compressed and not encrypted. It never inflates more than maxBytes:
// a larger entry yields the first maxBytes bytes together with [ErrTooLarge].
// When the archive is cut off inside the entry, the bytes recovered so far are
// returned with an error wrapping [binio.ErrTruncated]. The declared CRC is not
// verified, so damaged content is still returned for triage.
func Read(r io.ReaderAt, size int64, e Entry, maxBytes int64) ([]byte, error) {
	maxBytes = clampLimit(maxBytes)
	content, err := open(r, size, e)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Grow(int(min(e.UncompressedSize, uint64(maxBytes), 1<<20)))
	n, err := io.Copy(&buf, io.LimitReader(content, maxBytes+1))
	if n > maxBytes {
		return buf.Bytes()[:maxBytes], ErrTooLarge
	}
	return buf.Bytes(), contentErr(err, e)
}

// Peek returns up to n bytes from the start of an entry's uncompressed
// content. Unlike [Read] it never reports [ErrTooLarge]: it exists to look at
// magic numbers without paying for the rest of the entry.
func Peek(r io.ReaderAt, size int64, e Entry, n int) ([]byte, error) {
	content, err := open(r, size, e)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, max(n, 0))
	got, err := io.ReadFull(content, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	return buf[:got], contentErr(err, e)
}

func clampLimit(maxBytes int64) int64 {
	return min(max(maxBytes, 0), math.MaxInt64-1)
}

// contentErr turns a short read of the compressed stream into a truncation
// error and leaves other errors untouched.
func contentErr(err error, e Entry) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return fmt.Errorf("%w: entry %q ends early", binio.ErrTruncated, e.Name)
	default:
		return fmt.Errorf("%w: entry %q: %v", ErrCorrupt, e.Name, err)
	}
}

// open validates the local header of e and returns a reader of its
// uncompressed content.
func open(r io.ReaderAt, size int64, e Entry) (io.Reader, error) {
	if e.Encrypted {
		return nil, fmt.Errorf("%w: %q", ErrEncrypted, e.Name)
	}
	if e.Method != 0 && e.Method != 8 {
		return nil, fmt.Errorf("%w: method %d of %q", ErrUnsupported, e.Method, e.Name)
	}
	hdr, err := binio.ReadAt(r, size, e.LocalOffset, localHeaderLen)
	if err != nil {
		return nil, fmt.Errorf("%w: local header of %q lies outside the file", binio.ErrTruncated, e.Name)
	}
	if le32(hdr) != sigLocal {
		return nil, fmt.Errorf("%w: no local header for %q at offset %d", ErrCorrupt, e.Name, e.LocalOffset)
	}
	dataOff := e.LocalOffset + localHeaderLen + int64(le16(hdr[26:])) + int64(le16(hdr[28:]))
	if dataOff > size {
		return nil, fmt.Errorf("%w: data of %q lies outside the file", binio.ErrTruncated, e.Name)
	}
	stored := int64(min(e.CompressedSize, math.MaxInt64))
	section := io.NewSectionReader(r, dataOff, min(stored, size-dataOff))
	if e.Method == 0 {
		if stored > size-dataOff {
			return earlyEOF{section}, nil
		}
		return section, nil
	}
	return flate.NewReader(section), nil
}

// earlyEOF reports io.ErrUnexpectedEOF instead of io.EOF, for stored data that
// the file is too short to hold in full.
type earlyEOF struct{ io.Reader }

func (e earlyEOF) Read(p []byte) (int, error) {
	n, err := e.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
