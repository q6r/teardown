package testfixtures

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// ZipEntry describes one member of a fixture archive.
type ZipEntry struct {
	// Name is stored verbatim, so it may deliberately be unsafe ("../x").
	Name string
	// Data is the uncompressed content.
	Data []byte
	// Store keeps the data uncompressed, which makes the archive byte-stable
	// across Go releases. The default is DEFLATE.
	Store bool
}

// zipModTime is the modification time written for every fixture entry.
func zipModTime() time.Time { return time.Date(2026, time.January, 2, 3, 4, 6, 0, time.UTC) }

// Zip builds a ZIP archive from the entries, in order, with fixed timestamps.
// Like most streaming writers (Java, Go) it marks entries with a data
// descriptor, so local headers carry zero sizes and the central directory holds
// the real ones. It panics only on programmer error (an impossible write).
func Zip(entries ...ZipEntry) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.Name, Method: zip.Deflate, Modified: zipModTime()}
		if e.Store {
			hdr.Method = zip.Store
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			panic(fmt.Sprintf("testfixtures: zip entry %q: %v", e.Name, err))
		}
		if _, err := w.Write(e.Data); err != nil {
			panic(fmt.Sprintf("testfixtures: zip entry %q: %v", e.Name, err))
		}
	}
	if err := zw.Close(); err != nil {
		panic(fmt.Sprintf("testfixtures: zip close: %v", err))
	}
	return buf.Bytes()
}

// ZipSlip returns an archive with one harmless entry and several path-traversal
// ("zip-slip") entries: relative parents with both separators, absolute POSIX
// and Windows paths, a UNC path, a name that normalises outside the root and a
// name containing a NUL byte.
func ZipSlip() []byte {
	store := func(name, data string) ZipEntry { return ZipEntry{Name: name, Data: []byte(data), Store: true} }
	return Zip(
		store("docs/readme.txt", "hello"),
		store("../../evil.sh", "#!/bin/sh\n"),
		store(`..\..\Windows\Temp\evil.dll`, "MZ"),
		store("/etc/cron.d/backdoor", "* * * * * root true\n"),
		store(`C:\`+`Users\Public\evil.exe`, "MZ"), // split so path scanners ignore this fixture
		store(`\\attacker\share\evil.lnk`, "L"),
		store("nested/../../escape.txt", "x"),
		store("ok.txt\x00../../hidden", "x"),
	)
}

// ZipHighRatio returns an archive with one DEFLATE entry holding n zero bytes,
// whose compression ratio is far above anything legitimate content reaches.
func ZipHighRatio(n int) []byte {
	return Zip(ZipEntry{Name: "zeros.bin", Data: make([]byte, n)})
}

// ZipWithPrefix prepends prefix (a self-extractor stub, say) to an archive
// built from entries without adjusting any offset, exactly like
// "cat stub archive.zip".
func ZipWithPrefix(prefix []byte, entries ...ZipEntry) []byte {
	return append(bytes.Clone(prefix), Zip(entries...)...)
}

// ZipTruncatedEOCD returns an archive whose end-of-central-directory record is
// cut in half, as left by an interrupted download. The central directory
// itself is intact.
func ZipTruncatedEOCD(entries ...ZipEntry) []byte {
	b := Zip(entries...)
	return b[:len(b)-10]
}

// ZipOverlapping returns an archive whose last central-directory record points
// at the same local header as the first one, the signature of overlapping-entry
// zip bombs. It always contains exactly three entries.
func ZipOverlapping() []byte {
	data := bytes.Repeat([]byte{'a'}, 200)
	b := Zip(
		ZipEntry{Name: "a.bin", Data: data, Store: true},
		ZipEntry{Name: "b.bin", Data: data, Store: true},
		ZipEntry{Name: "c.bin", Data: data, Store: true},
	)
	records := zipCentralRecords(b)
	first := binary.LittleEndian.Uint32(b[records[0]+42:])
	binary.LittleEndian.PutUint32(b[records[len(records)-1]+42:], first)
	return b
}

// ZipDuplicateNames returns an archive in which two entries share a name.
func ZipDuplicateNames() []byte {
	return Zip(
		ZipEntry{Name: "same.txt", Data: []byte("first"), Store: true},
		ZipEntry{Name: "same.txt", Data: []byte("second"), Store: true},
		ZipEntry{Name: "other.txt", Data: []byte("third"), Store: true},
	)
}

// ZipMany returns an archive with n empty stored entries. With n >= 65535 the
// standard library writes ZIP64 end records, which makes this the cheap way to
// obtain a genuine ZIP64 archive.
func ZipMany(n int) []byte {
	entries := make([]ZipEntry, n)
	for i := range entries {
		entries[i] = ZipEntry{Name: fmt.Sprintf("f%06d", i), Store: true}
	}
	return Zip(entries...)
}

// Zip64 returns a small archive whose end records are in ZIP64 form (end
// record, locator and a standard end record full of sentinels). The ZIP64 end
// record declares the given number of entries, which may be a lie: pass a huge
// value to test that readers do not trust it.
func Zip64(declared uint64, entries ...ZipEntry) []byte {
	b := Zip(entries...)
	eocd := len(b) - 22
	cdSize := uint64(binary.LittleEndian.Uint32(b[eocd+12:]))
	cdOffset := uint64(binary.LittleEndian.Uint32(b[eocd+16:]))

	out := bytes.Clone(b[:eocd])
	record := make([]byte, 56)
	copy(record, "PK\x06\x06")
	binary.LittleEndian.PutUint64(record[4:], 44)
	binary.LittleEndian.PutUint16(record[12:], 45)
	binary.LittleEndian.PutUint16(record[14:], 45)
	binary.LittleEndian.PutUint64(record[24:], declared)
	binary.LittleEndian.PutUint64(record[32:], declared)
	binary.LittleEndian.PutUint64(record[40:], cdSize)
	binary.LittleEndian.PutUint64(record[48:], cdOffset)
	locator := make([]byte, 20)
	copy(locator, "PK\x06\x07")
	binary.LittleEndian.PutUint64(locator[8:], uint64(len(out)))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	end := make([]byte, 22)
	copy(end, "PK\x05\x06")
	binary.LittleEndian.PutUint16(end[10:], 0xFFFF)
	binary.LittleEndian.PutUint16(end[8:], 0xFFFF)
	binary.LittleEndian.PutUint32(end[12:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(end[16:], 0xFFFFFFFF)

	out = append(out, record...)
	out = append(out, locator...)
	return append(out, end...)
}

// zipCentralRecords returns the offset of every central-directory record of an
// archive written by Zip (which never writes an archive comment).
func zipCentralRecords(b []byte) []int {
	eocd := len(b) - 22
	count := int(binary.LittleEndian.Uint16(b[eocd+10:]))
	pos := int(binary.LittleEndian.Uint32(b[eocd+16:]))
	records := make([]int, 0, count)
	for range count {
		records = append(records, pos)
		nameLen := int(binary.LittleEndian.Uint16(b[pos+28:]))
		extraLen := int(binary.LittleEndian.Uint16(b[pos+30:]))
		commentLen := int(binary.LittleEndian.Uint16(b[pos+32:]))
		pos += 46 + nameLen + extraLen + commentLen
	}
	return records
}
