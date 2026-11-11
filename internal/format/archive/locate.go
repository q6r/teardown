package archive

import (
	"context"
	"io"

	"github.com/q6r/teardown/internal/zipscan"
)

const (
	// maxLocateOffsets bounds how many offsets one call to [Locate] looks for.
	maxLocateOffsets = 256
	// maxLocalPrefix is the most bytes a local header takes before the data of its
	// member: the fixed part and the longest possible name and extra field.
	maxLocalPrefix = 30 + 2*65535
)

// Member is a stored (uncompressed, unencrypted) archive member located in the
// archive file, so that its content can be read straight from the file.
type Member struct {
	// Name is the member name, made printable.
	Name string
	// Offset is the file offset of the first byte of the content.
	Offset int64
	// Size is the length of the content in bytes, held to the end of the file.
	Size int64
}

// Locate finds, for each given file offset, the stored member whose content
// holds that offset. The result has one element per offset, in the order given:
// nil when no stored member holds it (the offset lies in a header, in compressed
// data, in the central directory or outside the file). Only the first 256 offsets
// are looked up.
//
// Compressed members are never reported: the file holds their compressed bytes,
// not their text, and nothing is inflated here. When members overlap (a trick of
// zip bombs) the first one in directory order wins. Nothing is extracted.
//
// It returns an error when r is not a ZIP archive, or ctx's error when the
// context ends. A damaged directory is not an error: the members that could be
// read are searched.
func Locate(ctx context.Context, r io.ReaderAt, size int64, offsets []int64) ([]*Member, error) {
	found := make([]*Member, len(offsets))
	probes := offsets[:min(len(offsets), maxLocateOffsets)]
	if len(probes) == 0 {
		return found, nil
	}
	dir, err := zipscan.Walk(ctx, r, size, 0, func(e zipscan.Entry) {
		if e.IsDir || e.Encrypted || e.Method != 0 || e.LocalOffset < 0 {
			return
		}
		// A stored member cannot be longer than the file; size >= 0 here, so the conversion is exact.
		length := int64(min(e.CompressedSize, uint64(max(size, 0))))
		var dataOff int64
		resolved, usable := false, false
		for i, off := range probes {
			if found[i] != nil || off < e.LocalOffset || off-e.LocalOffset >= maxLocalPrefix+length {
				continue
			}
			if !resolved {
				var derr error
				dataOff, derr = zipscan.DataOffset(r, size, e)
				resolved, usable = true, derr == nil
			}
			if !usable {
				return
			}
			if end := dataOff + min(length, size-dataOff); off >= dataOff && off < end {
				found[i] = &Member{Name: e.Name, Offset: dataOff, Size: end - dataOff}
			}
		}
	})
	if dir == nil {
		return found, err
	}
	if ctx.Err() != nil {
		return found, ctx.Err()
	}
	return found, nil
}
