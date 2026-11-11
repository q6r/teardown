package zipscan

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/q6r/teardown/internal/binio"
)

// localRecord is an entry recovered from a local header, buffered until it is
// known whether a central directory turns up.
type localRecord struct {
	entry   Entry
	nameLen int
	hash    uint64
}

// walkLocal recovers entries from an archive without a usable end record, for
// example a download that was cut short. It follows the local headers from the
// start of the file; entries written with a data descriptor are skipped by
// locating the descriptor. If the walk reaches the central directory, that
// directory is used instead because it is complete and carries the real sizes.
func (c *collector) walkLocal(ctx context.Context, r io.ReaderAt) error {
	var records []localRecord
	off := int64(0)
	for {
		if len(records) >= maxLocalRecords {
			c.warnf("stopped recovering after %d local headers", maxLocalRecords)
			break
		}
		if len(records)&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		hdr, err := binio.ReadAt(r, c.size, off, localHeaderLen)
		if err != nil {
			if off < c.size {
				c.warnf("archive ends inside a local header at offset %d", off)
			}
			break
		}
		sig := le32(hdr)
		if sig == sigCentral {
			c.d.Recovered = true
			c.warnf("end-of-central-directory record is missing or damaged; the central directory was found by scanning")
			return c.walkCentral(ctx, r, endRecord{cdStart: off, endOff: c.size})
		}
		if sig != sigLocal {
			if off == 0 {
				return ErrNotZip
			}
			c.warnf("unexpected data at offset %d; the rest of the archive was not read", off)
			break
		}

		flags, method := le16(hdr[6:]), le16(hdr[8:])
		crc := le32(hdr[14:])
		comp, uncomp := uint64(le32(hdr[18:])), uint64(le32(hdr[22:]))
		nameLen, extraLen := int64(le16(hdr[26:])), int64(le16(hdr[28:]))
		fields, err := binio.ReadAt(r, c.size, off+localHeaderLen, nameLen+extraLen)
		if err != nil {
			c.warnf("archive ends inside the header of the entry at offset %d", off)
			break
		}
		name, extra := fields[:nameLen], fields[nameLen:]
		if comp == 0xFFFFFFFF || uncomp == 0xFFFFFFFF {
			uncomp, comp, _ = zip64Fields(extra, uncomp, comp, 0)
		}
		dataOff := off + localHeaderLen + nameLen + extraLen

		next := int64(-1)
		if flags&8 != 0 && comp == 0 && uncomp == 0 {
			d, found, err := c.findDescriptor(ctx, r, dataOff)
			if err != nil {
				return err
			}
			if !found {
				c.warnf("the entry at offset %d uses a data descriptor that could not be located", off)
				records = append(records, localRecord{makeEntry(name, flags, method, crc, comp, uncomp, off), int(nameLen), fnv64a(name)})
				break
			}
			crc, comp, uncomp, next = d.crc, d.comp, d.uncomp, d.end
		} else if comp <= uint64(c.size-dataOff) {
			next = dataOff + int64(comp)
		}
		records = append(records, localRecord{makeEntry(name, flags, method, crc, comp, uncomp, off), int(nameLen), fnv64a(name)})
		if next < 0 {
			c.warnf("archive is cut off inside the data of the entry at offset %d", off)
			break
		}
		if flags&8 != 0 {
			if b, err := binio.ReadAt(r, c.size, next, 4); err == nil && le32(b) == sigDesc {
				next += 16
			}
		}
		off = next
	}

	c.d.Recovered = true
	c.warnf("central directory is missing; %d entries were recovered from local headers", len(records))
	for _, lr := range records {
		c.add(lr.entry, lr.nameLen, lr.hash)
	}
	return nil
}

// descriptor is a located data descriptor.
type descriptor struct {
	crc          uint32
	comp, uncomp uint64
	end          int64
}

var descSignature = []byte{'P', 'K', 7, 8}

// findDescriptor searches forward from dataOff for the data descriptor that
// terminates an entry whose sizes are unknown. A candidate is accepted only if
// the compressed size it declares equals the distance travelled, which rules
// out signatures that merely occur inside the data (for instance in a stored,
// nested archive). Both 32-bit and ZIP64 descriptors are understood.
func (c *collector) findDescriptor(ctx context.Context, r io.ReaderAt, dataOff int64) (descriptor, bool, error) {
	const chunk = 256 << 10
	buf := make([]byte, chunk)
	for pos := dataOff; pos < c.size; {
		if err := ctx.Err(); err != nil {
			return descriptor{}, false, err
		}
		n, err := r.ReadAt(buf[:min(int64(chunk), c.size-pos)], pos)
		if err != nil && !errors.Is(err, io.EOF) {
			return descriptor{}, false, err
		}
		window := buf[:n]
		for from := 0; ; {
			i := bytes.Index(window[from:], descSignature)
			if i < 0 {
				break
			}
			at := pos + int64(from+i)
			candidate := window[from+i:]
			if len(candidate) < 24 { // near the end of the window: fetch the bytes that follow
				if b, err := binio.ReadUpTo(r, c.size, at, 24); err == nil {
					candidate = b
				}
			}
			if d, ok := descriptorFrom(candidate, at, at-dataOff); ok {
				return d, true, nil
			}
			from += i + 1
		}
		if n < 4 || pos+int64(n) >= c.size {
			break
		}
		pos += int64(n) - 3 // keep a signature that straddles the chunk boundary reachable
	}
	return descriptor{}, false, nil
}

// descriptorFrom validates the candidate descriptor at the start of b (which
// sits at file offset off) against the distance travelled since the start of
// the entry data. Working on bytes already in memory keeps a file full of
// signature look-alikes from costing a read per candidate.
func descriptorFrom(b []byte, off, distance int64) (descriptor, bool) {
	if len(b) < 16 {
		return descriptor{}, false
	}
	if int64(le32(b[8:])) == distance {
		return descriptor{crc: le32(b[4:]), comp: uint64(le32(b[8:])), uncomp: uint64(le32(b[12:])), end: off + 16}, true
	}
	if len(b) >= 24 && le64(b[8:]) == uint64(distance) {
		return descriptor{crc: le32(b[4:]), comp: le64(b[8:]), uncomp: le64(b[16:]), end: off + 24}, true
	}
	return descriptor{}, false
}
