package testfixtures

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf16"
)

// JAROptions configures [JAR].
type JAROptions struct {
	// MainClass sets the Main-Class attribute (omitted when empty).
	MainClass string
	// CreatedBy sets Created-By (default "teardown testfixtures").
	CreatedBy string
	// ClassPath sets Class-Path; long values are wrapped like real manifests.
	ClassPath string
	// Attributes are extra main-section attributes, written sorted by name.
	Attributes map[string]string
	// Classes is the number of stub .class entries; 0 means one, a negative
	// value means none.
	Classes int
	// Signed adds META-INF/CERT.SF and META-INF/CERT.RSA.
	Signed bool
	// Extra entries are appended unchanged.
	Extra []ZipEntry
}

// JAR builds a JAR: a META-INF/MANIFEST.MF with CRLF line endings and the
// 72-byte continuation lines real tools write, stub class files, and optional
// signature files. Entries are stored, so the bytes are stable across Go
// releases.
func JAR(opts JAROptions) []byte {
	var m strings.Builder
	m.WriteString("Manifest-Version: 1.0\r\n")
	createdBy := opts.CreatedBy
	if createdBy == "" {
		createdBy = "teardown testfixtures"
	}
	m.WriteString(jarWrap("Created-By: " + createdBy))
	if opts.MainClass != "" {
		m.WriteString(jarWrap("Main-Class: " + opts.MainClass))
	}
	if opts.ClassPath != "" {
		m.WriteString(jarWrap("Class-Path: " + opts.ClassPath))
	}
	keys := make([]string, 0, len(opts.Attributes))
	for k := range opts.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m.WriteString(jarWrap(k + ": " + opts.Attributes[k]))
	}
	m.WriteString("\r\nName: com/example/Main.class\r\nSHA-256-Digest: AAAA\r\n\r\n")

	entries := []ZipEntry{
		{Name: "META-INF/", Store: true},
		{Name: "META-INF/MANIFEST.MF", Data: []byte(m.String()), Store: true},
	}
	classes := opts.Classes
	if classes == 0 {
		classes = 1
	}
	for i := range max(classes, 0) {
		name := "com/example/Main.class"
		if i > 0 {
			name = fmt.Sprintf("com/example/Helper%d.class", i)
		}
		entries = append(entries, ZipEntry{Name: name, Data: jarClassStub(), Store: true})
	}
	if opts.Signed {
		entries = append(entries,
			ZipEntry{Name: "META-INF/CERT.SF", Data: []byte("Signature-Version: 1.0\r\n\r\n"), Store: true},
			ZipEntry{Name: "META-INF/CERT.RSA", Data: []byte{0x30, 0x82, 0x01, 0x00}, Store: true},
		)
	}
	entries = append(entries, opts.Extra...)
	return Zip(entries...)
}

// jarWrap writes one manifest attribute, wrapping it at 72 bytes with the
// leading-space continuation lines the specification prescribes.
func jarWrap(line string) string {
	var b strings.Builder
	first := true
	for len(line) > 0 {
		limit := 72
		if !first {
			b.WriteByte(' ')
			limit = 71
		}
		n := min(limit, len(line))
		b.WriteString(line[:n])
		b.WriteString("\r\n")
		line = line[n:]
		first = false
	}
	return b.String()
}

// jarClassStub is the header of a Java 8 class file followed by padding.
func jarClassStub() []byte {
	return append([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52}, make([]byte, 24)...)
}

// APKOptions configures [APK].
type APKOptions struct {
	// Package is the application id (default "com.example.demo").
	Package string
	// Permissions are written as <uses-permission> elements.
	Permissions []string
	// ABIs get one lib/<abi>/libdemo.so each.
	ABIs []string
	// DexFiles is the number of classes*.dex files; 0 means one, a negative
	// value means none.
	DexFiles int
	// V1Signed adds META-INF/CERT.SF and META-INF/CERT.RSA.
	V1Signed bool
	// SigningBlock inserts an APK Signing Block (v2 scheme id) before the
	// central directory.
	SigningBlock bool
}

// APK builds a minimal but structurally real Android package: a binary
// AndroidManifest.xml (UTF-16 string pool, namespace and element chunks, no
// resource map), dex files starting with the "dex\n035" magic, a resources.arsc
// header and one stub native library per ABI.
func APK(opts APKOptions) []byte {
	pkg := opts.Package
	if pkg == "" {
		pkg = "com.example.demo"
	}
	entries := []ZipEntry{{Name: "AndroidManifest.xml", Data: apkAXML(pkg, opts.Permissions), Store: true}}
	dex := opts.DexFiles
	if dex == 0 {
		dex = 1
	}
	for i := range max(dex, 0) {
		name := "classes.dex"
		if i > 0 {
			name = fmt.Sprintf("classes%d.dex", i+1)
		}
		entries = append(entries, ZipEntry{Name: name, Data: apkDexStub(), Store: true})
	}
	entries = append(entries, ZipEntry{Name: "resources.arsc", Data: []byte{0x02, 0, 0x0C, 0, 0x0C, 0, 0, 0, 0, 0, 0, 0}, Store: true})
	for _, abi := range opts.ABIs {
		entries = append(entries, ZipEntry{Name: "lib/" + abi + "/libdemo.so", Data: apkSOStub(), Store: true})
	}
	if opts.V1Signed {
		entries = append(entries,
			ZipEntry{Name: "META-INF/CERT.SF", Data: []byte("Signature-Version: 1.0\r\n\r\n"), Store: true},
			ZipEntry{Name: "META-INF/CERT.RSA", Data: []byte{0x30, 0x82, 0x01, 0x00}, Store: true},
		)
	}
	b := Zip(entries...)
	if opts.SigningBlock {
		b = apkInsertSigningBlock(b)
	}
	return b
}

func apkDexStub() []byte { return append([]byte("dex\n035\x00"), make([]byte, 104)...) }

func apkSOStub() []byte { return append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 57)...) }

// apkInsertSigningBlock inserts an APK Signing Block between the last entry
// and the central directory and fixes the directory offset in the end record.
func apkInsertSigningBlock(zipBytes []byte) []byte {
	le := binary.LittleEndian
	eocd := len(zipBytes) - 22
	cdOffset := int(le.Uint32(zipBytes[eocd+16:]))

	value := make([]byte, 8)
	pair := le.AppendUint64(nil, uint64(4+len(value)))
	pair = le.AppendUint32(pair, 0x7109871a) // the v2 signature scheme block id
	pair = append(pair, value...)

	sizeOfBlock := uint64(len(pair) + 8 + len("APK Sig Block 42"))
	block := le.AppendUint64(nil, sizeOfBlock)
	block = append(block, pair...)
	block = le.AppendUint64(block, sizeOfBlock)
	block = append(block, "APK Sig Block 42"...)

	out := make([]byte, 0, len(zipBytes)+len(block))
	out = append(out, zipBytes[:cdOffset]...)
	out = append(out, block...)
	out = append(out, zipBytes[cdOffset:]...)
	le.PutUint32(out[len(out)-22+16:], uint32(cdOffset+len(block)))
	return out
}

// apkAXML encodes <manifest package="..."><uses-permission android:name="..."/>...</manifest>
// as Android binary XML.
func apkAXML(pkg string, permissions []string) []byte {
	const (
		idxAndroid    = 0
		idxURI        = 1
		idxManifest   = 2
		idxPackage    = 3
		idxUsesPerm   = 4
		idxName       = 5
		idxPackageVal = 6
		firstPerm     = 7
		none          = 0xFFFFFFFF
	)
	pool := []string{
		"android", "http://schemas.android.com/apk/res/android", "manifest", "package", "uses-permission", "name", pkg,
	}
	pool = append(pool, permissions...)

	le := binary.LittleEndian
	// chunk writes the 8-byte chunk header (type, header size, total size) and
	// the body, which for node chunks starts with the rest of the header.
	chunk := func(typ uint16, header uint16, body []byte) []byte {
		b := le.AppendUint16(nil, typ)
		b = le.AppendUint16(b, header)
		b = le.AppendUint32(b, uint32(8+len(body)))
		return append(b, body...)
	}
	node := func(typ uint16, line uint32, rest ...uint32) []byte {
		body := le.AppendUint32(nil, line)
		body = le.AppendUint32(body, none)
		for _, v := range rest {
			body = le.AppendUint32(body, v)
		}
		return chunk(typ, 16, body)
	}
	startElement := func(name uint32, attrs ...[3]uint32) []byte {
		body := le.AppendUint32(nil, 2)
		body = le.AppendUint32(body, none)
		body = le.AppendUint32(body, none) // element namespace
		body = le.AppendUint32(body, name)
		body = le.AppendUint16(body, 20) // attribute start
		body = le.AppendUint16(body, 20) // attribute size
		body = le.AppendUint16(body, uint16(len(attrs)))
		body = append(body, make([]byte, 6)...) // id, class and style indexes
		for _, a := range attrs {               // namespace, name, value
			body = le.AppendUint32(body, a[0])
			body = le.AppendUint32(body, a[1])
			body = le.AppendUint32(body, a[2]) // raw value
			body = le.AppendUint16(body, 8)    // typed value size
			body = append(body, 0, 0x03)       // reserved, TYPE_STRING
			body = le.AppendUint32(body, a[2])
		}
		return chunk(0x0102, 16, body)
	}

	var xml []byte
	xml = append(xml, node(0x0100, 1, idxAndroid, idxURI)...)
	xml = append(xml, startElement(idxManifest, [3]uint32{none, idxPackage, idxPackageVal})...)
	for i := range permissions {
		xml = append(xml, startElement(idxUsesPerm, [3]uint32{idxURI, idxName, uint32(firstPerm + i)})...)
		xml = append(xml, node(0x0103, 3, none, idxUsesPerm)...)
	}
	xml = append(xml, node(0x0103, 4, none, idxManifest)...)
	xml = append(xml, node(0x0101, 5, idxAndroid, idxURI)...)

	file := append(apkStringPool(pool), xml...)
	return chunk(0x0003, 8, file)
}

// apkStringPool encodes strings as a UTF-16 string pool chunk.
func apkStringPool(strs []string) []byte {
	le := binary.LittleEndian
	var data []byte
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(len(data))
		units := utf16.Encode([]rune(s))
		data = le.AppendUint16(data, uint16(len(units)))
		for _, u := range units {
			data = le.AppendUint16(data, u)
		}
		data = le.AppendUint16(data, 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	const header = 28
	stringsStart := header + 4*len(strs)
	b := le.AppendUint16(nil, 0x0001)
	b = le.AppendUint16(b, header)
	b = le.AppendUint32(b, uint32(stringsStart+len(data)))
	b = le.AppendUint32(b, uint32(len(strs)))
	b = le.AppendUint32(b, 0) // style count
	b = le.AppendUint32(b, 0) // flags: UTF-16
	b = le.AppendUint32(b, uint32(stringsStart))
	b = le.AppendUint32(b, 0) // styles start
	for _, o := range offsets {
		b = le.AppendUint32(b, o)
	}
	return append(b, data...)
}

// AABOptions configures [AAB].
type AABOptions struct {
	// Package is the application id (default "com.example.demo").
	Package string
	// Permissions are written as <uses-permission> elements.
	Permissions []string
	// ABIs get one base/lib/<abi>/libdemo.so each.
	ABIs []string
}

// AAB builds a minimal Android App Bundle: BundleConfig.pb, a base module with a
// protocol-buffer manifest (the aapt2 XmlNode encoding), a dex file, resources.pb
// and one stub native library per ABI.
func AAB(opts AABOptions) []byte {
	pkg := opts.Package
	if pkg == "" {
		pkg = "com.example.demo"
	}
	entries := []ZipEntry{
		{Name: "BundleConfig.pb", Data: aabField(1, aabField(1, []byte("1.15.6"))), Store: true},
		{Name: "base/manifest/AndroidManifest.xml", Data: aabManifest(pkg, opts.Permissions), Store: true},
		{Name: "base/dex/classes.dex", Data: apkDexStub(), Store: true},
		{Name: "base/resources.pb", Data: aabField(1, aabField(1, []byte("res"))), Store: true},
	}
	for _, abi := range opts.ABIs {
		entries = append(entries, ZipEntry{Name: "base/lib/" + abi + "/libdemo.so", Data: apkSOStub(), Store: true})
	}
	entries = append(entries, ZipEntry{Name: "META-INF/MANIFEST.MF", Data: []byte("Manifest-Version: 1.0\r\nCreated-By: bundletool\r\n\r\n"), Store: true})
	return Zip(entries...)
}

// aabVarint encodes v as a protocol-buffer varint.
func aabVarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// aabField encodes a length-delimited field.
func aabField(num int, payload []byte) []byte {
	b := aabVarint(uint64(num)<<3 | 2)
	b = append(b, aabVarint(uint64(len(payload)))...)
	return append(b, payload...)
}

// aabNumber encodes a varint field.
func aabNumber(num int, v uint64) []byte {
	return append(aabVarint(uint64(num)<<3), aabVarint(v)...)
}

func aabString(num int, s string) []byte { return aabField(num, []byte(s)) }

// aabManifest encodes the manifest as aapt2's XmlNode message.
func aabManifest(pkg string, permissions []string) []byte {
	const androidURI = "http://schemas.android.com/apk/res/android"
	var element []byte
	element = append(element, aabField(1, slices.Concat(aabString(1, "android"), aabString(2, androidURI)))...)
	element = append(element, aabString(3, "manifest")...)
	element = append(element, aabField(4, slices.Concat(aabString(2, "package"), aabString(3, pkg)))...)
	for _, p := range permissions {
		attr := slices.Concat(aabString(1, androidURI), aabString(2, "name"), aabString(3, p), aabNumber(5, 0x01010003))
		child := slices.Concat(aabString(3, "uses-permission"), aabField(4, attr))
		element = append(element, aabField(5, aabField(1, child))...)
	}
	return aabField(1, element)
}
