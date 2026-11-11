package zipscan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
)

// walkCentral streams the central directory described by rec. It stops quietly
// at the first record that is not a central-directory header (normally the end
// record) and reports truncation or short counts as warnings.
func (c *collector) walkCentral(ctx context.Context, r io.ReaderAt, rec endRecord) error {
	c.d.Comment, c.d.CDOffset, c.d.Zip64, c.base = rec.comment, rec.cdStart, rec.zip64, rec.base
	c.d.Warnings = append(c.d.Warnings, rec.warnings...)
	declared := rec.count

	br := bufio.NewReaderSize(io.NewSectionReader(r, rec.cdStart, c.size-rec.cdStart), 64<<10)
	var (
		hdr   [centralHeaderLen]byte
		name  []byte
		extra []byte
	)
	for {
		if c.d.Count >= MaxRecords {
			c.capped = true
			c.warnf("stopped after %d central-directory records", MaxRecords)
			return nil
		}
		if c.d.Count&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		n, err := io.ReadFull(br, hdr[:])
		if n >= 4 && le32(hdr[:]) != sigCentral {
			break
		}
		if err != nil {
			if n > 0 {
				c.warnf("central directory is cut off in the record after entry %d", c.d.Count)
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return err
			}
			break
		}

		flags, method := le16(hdr[8:]), le16(hdr[10:])
		crc := le32(hdr[16:])
		comp, uncomp := uint64(le32(hdr[20:])), uint64(le32(hdr[24:]))
		nameLen, extraLen, commentLen := int(le16(hdr[28:])), int(le16(hdr[30:])), int(le16(hdr[32:]))
		offset := uint64(le32(hdr[42:]))

		name = fit(name, nameLen)
		extra = fit(extra, extraLen)
		if _, err := io.ReadFull(br, name); err != nil {
			c.warnf("central directory is cut off inside the name of entry %d", c.d.Count+1)
			return readErr(err)
		}
		// A cut inside the extra field or comment still leaves a usable entry:
		// the name and the fixed fields are complete.
		gotExtra, cutErr := io.ReadFull(br, extra)
		extra = extra[:gotExtra]
		if cutErr == nil {
			_, cutErr = br.Discard(commentLen)
		}

		if comp == 0xFFFFFFFF || uncomp == 0xFFFFFFFF || offset == 0xFFFFFFFF {
			uncomp, comp, offset = zip64Fields(extra, uncomp, comp, offset)
		}
		local := int64(-1)
		if offset <= math.MaxInt64-uint64(max(c.base, 0)) {
			local = int64(offset) + c.base
		}
		c.add(makeEntry(name, flags, method, crc, comp, uncomp, local), nameLen, fnv64a(name))
		if cutErr != nil {
			c.warnf("central directory is cut off inside entry %d", c.d.Count)
			return readErr(cutErr)
		}
	}
	if int64(c.d.Count) < int64(min(declared, math.MaxInt32)) && declared != 0xFFFF {
		c.warnf("the end record declares %d entries but only %d could be read", declared, c.d.Count)
	}
	return nil
}

// readErr maps the end-of-data conditions that were already reported as
// warnings to a clean stop, and passes real I/O errors through.
func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return err
}

// fit returns b resized to n bytes, reallocating only when it is too small.
func fit(b []byte, n int) []byte {
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

// zip64Fields replaces the sentinel values of a record with those of its ZIP64
// extended-information extra field. The field lists, in this order and only for
// the values that were 0xFFFFFFFF: uncompressed size, compressed size, local
// header offset.
func zip64Fields(extra []byte, uncomp, comp, offset uint64) (uncompOut, compOut, offsetOut uint64) {
	for len(extra) >= 4 {
		id, n := le16(extra), int(le16(extra[2:]))
		extra = extra[4:]
		n = min(n, len(extra))
		data := extra[:n]
		extra = extra[n:]
		if id != 0x0001 {
			continue
		}
		take := func(current uint64) uint64 {
			if len(data) < 8 {
				return current
			}
			v := le64(data)
			data = data[8:]
			return v
		}
		if uncomp == 0xFFFFFFFF {
			uncomp = take(uncomp)
		}
		if comp == 0xFFFFFFFF {
			comp = take(comp)
		}
		if offset == 0xFFFFFFFF {
			offset = take(offset)
		}
		break
	}
	return uncomp, comp, offset
}
