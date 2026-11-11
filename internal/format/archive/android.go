package archive

import (
	"encoding/binary"
	"errors"
	"regexp"
	"slices"
	"unicode/utf16"

	"github.com/q6r/teardown/internal/binio"
)

// Chunk types and flags of Android's binary XML (AXML) container.
const (
	axmlTypeXML        = 0x0003
	axmlTypeStringPool = 0x0001
	axmlFlagUTF8       = 0x0100

	// maxPoolStrings bounds how many pool strings are decoded.
	maxPoolStrings = 100_000
	// maxPoolString bounds the length of one decoded string.
	maxPoolString = 512
	// maxPermissions bounds the permissions collected from one manifest.
	maxPermissions = 1024
)

var (
	errNotAXML = errors.New("not binary Android XML")

	// permissionRE is the shape of a permission name taken from a string pool.
	permissionRE = regexp.MustCompile(`^(?:[A-Za-z0-9_.]+\.permission\.[A-Z0-9_.]+|android\.permission\.[A-Za-z0-9_.]+|com\.android\.vending\.[A-Z_]+)$`)
	// rawPermissionRE finds permission-shaped strings in unstructured bytes.
	rawPermissionRE = regexp.MustCompile(`(?:[A-Za-z0-9_]+\.)+permission\.[A-Za-z0-9_.]+|com\.android\.vending\.[A-Z_]+`)
)

// manifestPermissions recovers permission names from an Android manifest and
// reports whether the structured path was used. A binary XML manifest (APK) is
// read only as far as its string pool; anything else, such as the protocol
// buffer manifest of an AAB or a damaged pool, is scanned as raw bytes. The
// result is sorted and de-duplicated. It is a heuristic: see [Android].
func manifestPermissions(data []byte) (perms []string, structured bool) {
	if pool, err := axmlStrings(data); err == nil {
		for _, s := range pool {
			if permissionRE.MatchString(s) {
				perms = append(perms, s)
			}
		}
		return dedupe(perms), true
	}
	return dedupe(scanPermissions(data)), false
}

func dedupe(in []string) []string {
	slices.Sort(in)
	in = slices.Compact(in)
	if len(in) > maxPermissions {
		in = in[:maxPermissions]
	}
	return in
}

// axmlStrings decodes the first string pool of a binary XML document. Every
// offset and count is validated against the chunk before use.
func axmlStrings(data []byte) ([]string, error) {
	if len(data) < 8 || le16(data) != axmlTypeXML {
		return nil, errNotAXML
	}
	for pos := int(le16(data[2:])); pos+8 <= len(data); {
		typ, headerSize, chunkSize := le16(data[pos:]), int(le16(data[pos+2:])), int(le32(data[pos+4:]))
		if chunkSize < 8 || chunkSize > len(data)-pos {
			return nil, binio.ErrTruncated
		}
		if typ == axmlTypeStringPool {
			return decodePool(data[pos:pos+chunkSize], headerSize)
		}
		pos += chunkSize
	}
	return nil, errors.New("no string pool")
}

// decodePool decodes a string pool chunk (chunk starts at the chunk header).
func decodePool(chunk []byte, headerSize int) ([]string, error) {
	if headerSize < 28 || headerSize > len(chunk) {
		return nil, binio.ErrTruncated
	}
	count, flags := int(le32(chunk[8:])), le32(chunk[16:])
	stringsStart := int(le32(chunk[20:]))
	if count < 0 || count > maxPoolStrings || count > (len(chunk)-headerSize)/4 {
		return nil, binio.ErrTruncated
	}
	if stringsStart < headerSize+4*count || stringsStart > len(chunk) {
		return nil, binio.ErrTruncated
	}
	isUTF8 := flags&axmlFlagUTF8 != 0
	out := make([]string, 0, count)
	for i := range count {
		off := int(le32(chunk[headerSize+4*i:]))
		if off < 0 || off >= len(chunk)-stringsStart {
			out = append(out, "")
			continue
		}
		data := chunk[stringsStart+off:]
		if isUTF8 {
			out = append(out, poolString8(data))
		} else {
			out = append(out, poolString16(data))
		}
	}
	return out, nil
}

// poolString16 decodes a length-prefixed UTF-16LE string.
func poolString16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := int(le16(b))
	b = b[2:]
	if n&0x8000 != 0 {
		if len(b) < 2 {
			return ""
		}
		n = (n&0x7FFF)<<16 | int(le16(b))
		b = b[2:]
	}
	n = min(n, len(b)/2, maxPoolString)
	units := make([]uint16, n)
	for i := range n {
		units[i] = le16(b[2*i:])
	}
	return binio.Printable(string(utf16.Decode(units)), maxPoolString)
}

// poolString8 decodes a string prefixed by its length in characters and in bytes.
func poolString8(b []byte) string {
	skip := func() (int, bool) {
		if len(b) == 0 {
			return 0, false
		}
		n := int(b[0])
		b = b[1:]
		if n&0x80 != 0 {
			if len(b) == 0 {
				return 0, false
			}
			n = (n&0x7F)<<8 | int(b[0])
			b = b[1:]
		}
		return n, true
	}
	if _, ok := skip(); !ok { // length in characters
		return ""
	}
	n, ok := skip() // length in bytes
	if !ok {
		return ""
	}
	n = min(n, len(b), maxPoolString)
	return binio.Printable(string(b[:n]), maxPoolString)
}

// scanPermissions finds permission-shaped strings in raw bytes. In a protocol
// buffer a string is preceded by its length, which can itself be a letter and
// stick to the match, and followed by the next field's tag byte, so matches are
// trimmed to the length the preceding byte declares when that is consistent.
func scanPermissions(data []byte) []string {
	var out []string
	for _, loc := range rawPermissionRE.FindAllIndex(data, maxPermissions) {
		start, m := loc[0], data[loc[0]:loc[1]]
		switch {
		case len(m) > 1 && int(m[0]) == len(m)-1:
			m = m[1:] // the length byte was absorbed as a leading letter
		case start > 0 && int(data[start-1]) > 0 && int(data[start-1]) < len(m):
			m = m[:data[start-1]] // trailing tag byte absorbed
		}
		if s := string(m); permissionRE.MatchString(s) {
			out = append(out, binio.Printable(s, maxPoolString))
		}
	}
	return out
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
