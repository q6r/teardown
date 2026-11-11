package sniff

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/q6r/teardown/internal/report"
)

// rule is one row of the simple-signature table: a cheap predicate over the head
// of the file and a builder that refines the answer once the predicate holds.
type rule struct {
	match func(h []byte) bool
	build func(h []byte) report.Type
}

func prefix(magic string) func([]byte) bool {
	return func(h []byte) bool { return bytes.HasPrefix(h, []byte(magic)) }
}

// simpleRules lists the formats that are recognised from a fixed magic number
// (optionally with one extra field) at the start of the file.
var simpleRules = [...]rule{
	{prefix("\x89PNG\r\n\x1a\n"), buildPNG},
	{prefix("\xff\xd8\xff"), buildJPEG},
	{prefix("GIF87a"), buildGIF},
	{prefix("GIF89a"), buildGIF},
	{isWebP, buildWebP},
	{prefix(`{\rtf`), buildRTF},
	{prefix("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), buildOLE},
	{prefix("SQLite format 3\x00"), buildSQLite},
	{prefix("\x1f\x8b\x08"), buildGzip},
	{isBzip2, buildBzip2},
	{prefix("\xfd7zXZ\x00"), buildXz},
	{prefix("\x28\xb5\x2f\xfd"), buildZstd},
	{prefix("7z\xbc\xaf\x27\x1c"), build7z},
	{prefix("Rar!\x1a\x07\x00"), buildRar4},
	{prefix("Rar!\x1a\x07\x01\x00"), buildRar5},
	{isDex, buildDex},
	{prefix("\x1bLua"), buildLua},
	{prefix("\x1bLJ"), buildLuaJIT},
	{isGGUF, buildGGUF},
}

func detectSimple(p *probe) (report.Type, bool) {
	for _, r := range simpleRules {
		if r.match(p.head) {
			return r.build(p.head), true
		}
	}
	return report.Type{}, false
}

func confidenceIf(ok bool) report.Confidence {
	if ok {
		return report.ConfidenceHigh
	}
	return report.ConfidenceMedium
}

func buildPNG(h []byte) report.Type {
	label := "PNG image"
	ok := len(h) >= 24 && string(h[12:16]) == "IHDR" && binary.BigEndian.Uint32(h[8:]) == 13
	if ok {
		label = fmt.Sprintf("PNG image (%dx%d)", binary.BigEndian.Uint32(h[16:]), binary.BigEndian.Uint32(h[20:]))
	}
	return newType(report.TypePNG, report.FamilyImage, label, "image/png", confidenceIf(ok))
}

func buildJPEG(h []byte) report.Type {
	// The byte after FF D8 FF is the first marker; markers are 0xC0..0xFE.
	ok := len(h) >= 4 && h[3] >= 0xc0 && h[3] != 0xff
	label := "JPEG image"
	switch head := h[:min(len(h), 32)]; {
	case bytes.Contains(head, []byte("JFIF\x00")):
		label = "JPEG image (JFIF)"
	case bytes.Contains(head, []byte("Exif\x00\x00")):
		label = "JPEG image (Exif)"
	}
	return newType(report.TypeJPEG, report.FamilyImage, label, "image/jpeg", confidenceIf(ok))
}

func buildGIF(h []byte) report.Type {
	label := "GIF image"
	ok := len(h) >= 10
	if ok {
		label = fmt.Sprintf("GIF image (%s, %dx%d)", h[3:6], binary.LittleEndian.Uint16(h[6:]), binary.LittleEndian.Uint16(h[8:]))
	}
	return newType(report.TypeGIF, report.FamilyImage, label, "image/gif", confidenceIf(ok))
}

func isWebP(h []byte) bool {
	return len(h) >= 12 && string(h[:4]) == "RIFF" && string(h[8:12]) == "WEBP"
}

func buildWebP(h []byte) report.Type {
	ok := false
	if len(h) >= 16 {
		switch string(h[12:16]) {
		case "VP8 ", "VP8L", "VP8X":
			ok = true
		}
	}
	return newType(report.TypeWebP, report.FamilyImage, "WebP image", "image/webp", confidenceIf(ok))
}

func buildRTF(h []byte) report.Type {
	ok := len(h) >= 6 && h[5] >= '1' && h[5] <= '9'
	return newType(report.TypeRTF, report.FamilyDocument, "Rich Text Format (RTF) document", "application/rtf", confidenceIf(ok))
}

func buildOLE(h []byte) report.Type {
	// Offset 28 holds the byte-order mark 0xFFFE (little-endian).
	ok := len(h) >= 30 && h[28] == 0xfe && h[29] == 0xff
	return newType(report.TypeOLE, report.FamilyDocument, "OLE2 compound document (legacy Office, MSI)",
		"application/x-ole-storage", confidenceIf(ok))
}

func buildSQLite(h []byte) report.Type {
	ok := false
	if len(h) >= 20 {
		page := int(binary.BigEndian.Uint16(h[16:]))
		pow2 := page >= 512 && page <= 32768 && page&(page-1) == 0
		ok = (pow2 || page == 1) && h[18] <= 2 && h[19] <= 2
	}
	return newType(report.TypeSQLite, report.FamilyDatabase, "SQLite 3 database", "application/vnd.sqlite3", confidenceIf(ok))
}

func buildGzip(h []byte) report.Type {
	// The top three flag bits are reserved and must be zero.
	ok := len(h) >= 4 && h[3]&0xe0 == 0
	return newType(report.TypeGzip, report.FamilyArchive, "gzip compressed data", "application/gzip", confidenceIf(ok))
}

func isBzip2(h []byte) bool {
	return len(h) >= 4 && string(h[:3]) == "BZh" && h[3] >= '1' && h[3] <= '9'
}

func buildBzip2(h []byte) report.Type {
	ok := false
	if len(h) >= 10 {
		block := string(h[4:10])
		// Either the first block header (pi) or the end-of-stream marker (sqrt(pi)).
		ok = block == "\x31\x41\x59\x26\x53\x59" || block == "\x17\x72\x45\x38\x50\x90"
	}
	return newType(report.TypeBzip2, report.FamilyArchive, "bzip2 compressed data", "application/x-bzip2", confidenceIf(ok))
}

func buildXz(h []byte) report.Type {
	// Stream flags: a zero byte followed by a check type 0..15.
	ok := len(h) >= 8 && h[6] == 0 && h[7] <= 0x0f
	return newType(report.TypeXz, report.FamilyArchive, "xz compressed data", "application/x-xz", confidenceIf(ok))
}

func buildZstd(h []byte) report.Type {
	// The frame header descriptor's bit 3 is reserved and must be zero.
	ok := len(h) >= 5 && h[4]&0x08 == 0
	return newType(report.TypeZstd, report.FamilyArchive, "Zstandard compressed data", "application/zstd", confidenceIf(ok))
}

func build7z(h []byte) report.Type {
	ok := len(h) >= 8 && h[6] == 0
	return newType(report.Type7z, report.FamilyArchive, "7-Zip archive", "application/x-7z-compressed", confidenceIf(ok))
}

func buildRar4(h []byte) report.Type {
	return newType(report.TypeRar, report.FamilyArchive, "RAR archive (version 4)", "application/vnd.rar",
		report.ConfidenceHigh, "rar4")
}

func buildRar5(h []byte) report.Type {
	return newType(report.TypeRar, report.FamilyArchive, "RAR archive (version 5)", "application/vnd.rar",
		report.ConfidenceHigh, "rar5")
}

func isDex(h []byte) bool {
	return len(h) >= 8 && string(h[:4]) == "dex\n" && isDigits(h[4:7]) && h[7] == 0
}

func isDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(b) > 0
}

func buildDex(h []byte) report.Type {
	version := string(h[4:7])
	// header_size is 0x70 and endian_tag 0x12345678 in every real DEX file.
	ok := len(h) >= 44 && binary.LittleEndian.Uint32(h[36:]) == 0x70 && binary.LittleEndian.Uint32(h[40:]) == 0x12345678
	return newType(report.TypeDex, report.FamilyBytecode, "Dalvik executable (DEX "+version+")",
		"application/vnd.android.dex", confidenceIf(ok), "android", "dex-"+version)
}

func buildLua(h []byte) report.Type {
	if len(h) >= 5 && h[4] >= 0x50 && h[4] <= 0x54 {
		version := fmt.Sprintf("%d.%d", h[4]>>4, h[4]&0x0f)
		return newType(report.TypeLua, report.FamilyBytecode, "Lua "+version+" bytecode",
			"application/x-lua-bytecode", report.ConfidenceHigh, "lua-"+version)
	}
	return newType(report.TypeLua, report.FamilyBytecode, "Lua bytecode (unrecognised version)",
		"application/x-lua-bytecode", report.ConfidenceMedium, "lua")
}

func buildLuaJIT(h []byte) report.Type {
	conf := report.ConfidenceMedium
	label := "LuaJIT bytecode"
	if len(h) >= 4 && (h[3] == 1 || h[3] == 2) {
		conf = report.ConfidenceHigh
		label = fmt.Sprintf("LuaJIT bytecode (version %d)", h[3])
	}
	return newType(report.TypeLua, report.FamilyBytecode, label, "application/x-lua-bytecode", conf, "luajit")
}

func isGGUF(h []byte) bool {
	if len(h) < 8 || string(h[:4]) != "GGUF" {
		return false
	}
	v := binary.LittleEndian.Uint32(h[4:])
	return v >= 1 && v <= 3
}

func buildGGUF(h []byte) report.Type {
	v := binary.LittleEndian.Uint32(h[4:])
	return newType(report.TypeGGUF, report.FamilyModel, fmt.Sprintf("GGUF model (version %d)", v), mimeOctet,
		report.ConfidenceHigh, fmt.Sprintf("gguf-v%d", v))
}

// detectPDF recognises "%PDF-" at the start of the file or, as Acrobat does,
// within the first KiB. A header that is not at offset 0 is only believed when
// the trailer marker "%%EOF" is present near the end, so a text file that merely
// mentions "%PDF-" is not mistaken for a PDF.
func detectPDF(p *probe) (report.Type, bool) {
	window := p.head[:min(len(p.head), 1024+8)]
	i := bytes.Index(window, []byte("%PDF-"))
	if i < 0 {
		return report.Type{}, false
	}
	version := pdfVersion(p.head[i+5:])
	if i > 0 {
		tail := p.tailBytes()
		tail = tail[max(0, len(tail)-2048):]
		if version == "" || !bytes.Contains(tail, []byte("%%EOF")) {
			return report.Type{}, false
		}
	}
	label := "PDF document"
	if version != "" {
		label = "PDF document (version " + version + ")"
	}
	conf := report.ConfidenceMedium
	if i == 0 && version != "" {
		conf = report.ConfidenceHigh
	}
	return newType(report.TypePDF, report.FamilyDocument, label, "application/pdf", conf), true
}

func pdfVersion(b []byte) string {
	if len(b) >= 3 && b[0] >= '1' && b[0] <= '9' && b[1] == '.' && b[2] >= '0' && b[2] <= '9' {
		return string(b[:3])
	}
	return ""
}

// detectTar recognises POSIX and GNU tar archives by the "ustar" magic at offset
// 257, and confirms them with the header checksum.
func detectTar(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 265 || string(h[257:262]) != "ustar" {
		return report.Type{}, false
	}
	label, tag := "tar archive", ""
	switch {
	case h[262] == 0 && h[263] == '0' && h[264] == '0':
		label, tag = "tar archive (POSIX ustar)", "posix"
	case h[262] == ' ' && h[263] == ' ' && h[264] == 0:
		label, tag = "tar archive (GNU)", "gnu"
	}
	ok := len(h) >= 512 && tarChecksumOK(h[:512])
	return newType(report.TypeTar, report.FamilyArchive, label, "application/x-tar", confidenceIf(ok), tag), true
}

// tarChecksumOK verifies the checksum field (offset 148, 8 bytes of octal) of a
// 512-byte tar header block: the sum of all bytes with the field read as spaces.
func tarChecksumOK(block []byte) bool {
	var want uint64
	digits := 0
	for _, c := range bytes.TrimLeft(block[148:156], " ") {
		if c == 0 || c == ' ' {
			break
		}
		if c < '0' || c > '7' {
			return false
		}
		want = want<<3 | uint64(c-'0')
		digits++
	}
	if digits == 0 {
		return false
	}
	var sum uint64
	for i, c := range block {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += uint64(c)
	}
	return sum == want
}
