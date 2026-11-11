// Package hexdump renders bounded hex and ASCII windows over a byte slice.
//
// A window is at most [MaxWindow] bytes long and is split in rows of
// [BytesPerRow] bytes. Offsets are file offsets (int64), every request is
// validated against the data, and nothing here can read outside the slice it is
// given.
package hexdump

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Window geometry.
const (
	// BytesPerRow is the number of bytes shown in a full row.
	BytesPerRow = 16
	// DefaultWindow is the window size used when the caller asks for n <= 0.
	DefaultWindow = 128
	// MaxWindow is the hard cap on the bytes returned by one call to [Window].
	MaxWindow = 4096
)

// ErrOffset is returned (wrapped) by [Window] when the offset is negative or
// does not point at a byte of the data.
var ErrOffset = errors.New("hexdump: offset outside the data")

// hexDigits are the lower-case digits used for the Hex column.
const hexDigits = "0123456789abcdef"

// offsetWidth is the zero-padded width of the offset column written by [Format].
const offsetWidth = 10

// hexColumnWidth is the width of a full Hex column: two digits per byte and a
// single space between bytes.
const hexColumnWidth = BytesPerRow*3 - 1

// Row is one line of a hex dump.
type Row struct {
	Offset int64  // file offset of the first byte of the row
	Hex    string // "48 8b 4c 24 08 ..." (two lower-case hex digits per byte, single spaces)
	ASCII  string // printable ASCII, '.' for everything else
	Len    int    // bytes in this row (1..16)
}

// Window returns the rows covering n bytes of data starting at offset, clamped
// to the data and to [MaxWindow] (n <= 0 means [DefaultWindow]).
//
// truncated is true when fewer bytes than requested were returned because of
// the clamp, which includes reaching the end of the data. An offset that is
// negative or not inside data (including any offset into empty data) is an
// error wrapping [ErrOffset].
func Window(data []byte, offset int64, n int) (rows []Row, truncated bool, err error) {
	if offset < 0 || offset >= int64(len(data)) {
		return nil, false, fmt.Errorf("%w: offset %d, data length %d", ErrOffset, offset, len(data))
	}
	want := n
	if want <= 0 {
		want = DefaultWindow
	}
	start := int(offset) // offset < len(data), so it fits an int
	got := min(want, MaxWindow, len(data)-start)

	rows = make([]Row, 0, (got+BytesPerRow-1)/BytesPerRow)
	for i := 0; i < got; i += BytesPerRow {
		end := min(i+BytesPerRow, got)
		rows = append(rows, newRow(offset+int64(i), data[start+i:start+end]))
	}
	return rows, got < want, nil
}

// newRow builds one row from at most BytesPerRow bytes.
func newRow(offset int64, chunk []byte) Row {
	hex := make([]byte, 0, len(chunk)*3)
	ascii := make([]byte, len(chunk))
	for i, b := range chunk {
		if i > 0 {
			hex = append(hex, ' ')
		}
		hex = append(hex, hexDigits[b>>4], hexDigits[b&15])
		ascii[i] = printable(b)
	}
	return Row{Offset: offset, Hex: string(hex), ASCII: string(ascii), Len: len(chunk)}
}

// printable maps a byte to itself when it is printable ASCII and to '.' otherwise.
func printable(b byte) byte {
	if b >= 0x20 && b < 0x7f {
		return b
	}
	return '.'
}

// Format renders rows as classic text, one row per line:
//
//	0000001a40  48 8b 4c 24 08 48 89 c8 c3 90 90 90 90 90 90 90  |H.L$.H..........|
//
// The Hex column is padded to the width of a full row so the ASCII column
// lines up. Every line, including the last, ends with a newline. Format never
// emits control characters, whatever the rows contain.
func Format(rows []Row) string {
	var sb strings.Builder
	sb.Grow(len(rows) * (offsetWidth + hexColumnWidth + BytesPerRow + 8))
	for _, r := range rows {
		off := strconv.FormatInt(r.Offset, 16)
		for pad := offsetWidth - len(off); pad > 0; pad-- {
			sb.WriteByte('0')
		}
		sb.WriteString(off)
		sb.WriteString("  ")
		hex := sanitizeHex(r.Hex)
		sb.WriteString(hex)
		for pad := hexColumnWidth - len(hex); pad > 0; pad-- {
			sb.WriteByte(' ')
		}
		sb.WriteString("  |")
		for i := 0; i < len(r.ASCII); i++ {
			sb.WriteByte(printable(r.ASCII[i]))
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// sanitizeHex keeps only the characters a Hex column may contain, so rows built
// by hand cannot smuggle control characters into the output.
func sanitizeHex(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != ' ' && (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == ' ' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			out = append(out, c)
		}
	}
	return string(out)
}
