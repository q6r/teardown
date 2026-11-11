// Package binio provides bounds-checked helpers for reading binary structures
// from untrusted files. Nothing here panics or over-allocates on malformed
// input: every request that lies outside the source fails with [ErrTruncated]
// before any buffer is allocated.
package binio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrTruncated is returned when a read lies (partly) outside the data.
var ErrTruncated = errors.New("binio: truncated data")

// ReadAt reads exactly n bytes at offset off from r, a source of length size.
// The allocation is bounded by size because the range is validated first.
func ReadAt(r io.ReaderAt, size, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > size || n > size-off {
		return nil, ErrTruncated
	}
	buf := make([]byte, n)
	if n == 0 {
		return buf, nil
	}
	got, err := r.ReadAt(buf, off)
	if got == len(buf) {
		return buf, nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return nil, ErrTruncated
	}
	return nil, err
}

// ReadUpTo is like ReadAt but clamps the request to the data that exists: it
// returns an empty slice when off is outside the source.
func ReadUpTo(r io.ReaderAt, size, off, n int64) ([]byte, error) {
	if off < 0 || off >= size || n <= 0 {
		return []byte{}, nil
	}
	return ReadAt(r, size, off, min(n, size-off))
}

// CString reads a NUL-terminated string starting at off. It returns at most max
// bytes; when the terminator is not found within max bytes the capped string is
// returned without error. When the data ends before a terminator the partial
// string is returned together with [ErrTruncated].
func CString(r io.ReaderAt, size, off int64, max int) (string, error) {
	if off < 0 || off >= size || max <= 0 {
		return "", ErrTruncated
	}
	var sb strings.Builder
	const chunk = 128
	for sb.Len() < max {
		want := min(int64(chunk), int64(max-sb.Len()), size-off)
		if want <= 0 {
			return sb.String(), ErrTruncated
		}
		buf, err := ReadAt(r, size, off, want)
		if err != nil {
			return sb.String(), err
		}
		if i := indexByte(buf, 0); i >= 0 {
			sb.Write(buf[:i])
			return sb.String(), nil
		}
		sb.Write(buf)
		off += want
		if off >= size {
			return sb.String(), ErrTruncated
		}
	}
	return sb.String(), nil
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// Cursor reads fixed-width integers from a byte slice with a sticky error:
// after the first out-of-range read every further read returns zero and
// [Cursor.Err] reports [ErrTruncated]. This keeps header parsers linear.
type Cursor struct {
	b     []byte
	pos   int
	order binary.ByteOrder
	err   error
}

// NewCursor returns a cursor over b that decodes integers with the given byte order.
func NewCursor(b []byte, order binary.ByteOrder) *Cursor {
	return &Cursor{b: b, order: order}
}

// Err returns the first error encountered, if any.
func (c *Cursor) Err() error { return c.err }

// Pos returns the current offset into the slice.
func (c *Cursor) Pos() int { return c.pos }

// Remaining returns the number of unread bytes.
func (c *Cursor) Remaining() int { return len(c.b) - c.pos }

// Seek moves to an absolute offset; an offset outside the slice sets the error.
func (c *Cursor) Seek(pos int) {
	if c.err != nil {
		return
	}
	if pos < 0 || pos > len(c.b) {
		c.err = ErrTruncated
		return
	}
	c.pos = pos
}

// Skip advances by n bytes.
func (c *Cursor) Skip(n int) { c.take(n) }

func (c *Cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.b)-c.pos {
		c.err = ErrTruncated
		return nil
	}
	out := c.b[c.pos : c.pos+n : c.pos+n]
	c.pos += n
	return out
}

// U8 reads one byte.
func (c *Cursor) U8() uint8 {
	if b := c.take(1); b != nil {
		return b[0]
	}
	return 0
}

// U16 reads a 16-bit integer.
func (c *Cursor) U16() uint16 {
	if b := c.take(2); b != nil {
		return c.order.Uint16(b)
	}
	return 0
}

// U32 reads a 32-bit integer.
func (c *Cursor) U32() uint32 {
	if b := c.take(4); b != nil {
		return c.order.Uint32(b)
	}
	return 0
}

// U64 reads a 64-bit integer.
func (c *Cursor) U64() uint64 {
	if b := c.take(8); b != nil {
		return c.order.Uint64(b)
	}
	return 0
}

// Bytes returns the next n bytes as a sub-slice (not a copy).
func (c *Cursor) Bytes(n int) []byte { return c.take(n) }

// CString reads a NUL-terminated string from the remaining bytes. A missing
// terminator sets the sticky error and returns what was available.
func (c *Cursor) CString() string {
	if c.err != nil {
		return ""
	}
	rest := c.b[c.pos:]
	i := indexByte(rest, 0)
	if i < 0 {
		c.pos = len(c.b)
		c.err = ErrTruncated
		return Printable(string(rest), 0)
	}
	c.pos += i + 1
	return Printable(string(rest[:i]), 0)
}

// Printable makes an untrusted string safe to store in a report and to show on a
// terminal: invalid UTF-8 bytes and control characters (C0, DEL and C1, which
// include terminal escape introducers) become \xNN escapes. When max > 0 the
// result is cut to at most max runes and ends with an ellipsis.
func Printable(s string, max int) string {
	var sb strings.Builder
	sb.Grow(len(s))
	runes := 0
	for i := 0; i < len(s); {
		if max > 0 && runes >= max {
			sb.WriteString("…")
			break
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && w == 1:
			fmt.Fprintf(&sb, "\\x%02x", s[i])
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			fmt.Fprintf(&sb, "\\x%02x", r)
		default:
			sb.WriteString(s[i : i+w])
		}
		i += w
		runes++
	}
	return sb.String()
}

// FixedString converts a fixed-width, NUL-padded field (for example an 8-byte PE
// section name) into a printable string.
func FixedString(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return Printable(string(b), 0)
}
