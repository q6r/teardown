package testfixtures

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

func zipNames(t *testing.T, b []byte) []string {
	t.Helper()
	zr := zipOpen(t, b)
	names := make([]string, len(zr.File))
	for i, f := range zr.File {
		names[i] = f.Name
	}
	return names
}

func zipFile(t *testing.T, b []byte, name string) []byte {
	t.Helper()
	for _, f := range zipOpen(t, b).File {
		if f.Name == name {
			return zipReadAll(t, f)
		}
	}
	t.Fatalf("entry %q not found", name)
	return nil
}

func TestJAR_ManifestAndEntries(t *testing.T) {
	longPath := strings.Repeat("lib/some-library-1.0.0.jar ", 8)
	b := JAR(JAROptions{
		MainClass:  "com.example.Main",
		ClassPath:  longPath,
		Attributes: map[string]string{"Multi-Release": "true", "Implementation-Title": "demo"},
		Classes:    3,
		Signed:     true,
		Extra:      []ZipEntry{{Name: "lib/inner.jar", Data: Zip(), Store: true}},
	})
	manifest := string(zipFile(t, b, "META-INF/MANIFEST.MF"))
	if !strings.HasPrefix(manifest, "Manifest-Version: 1.0\r\nCreated-By: teardown testfixtures\r\nMain-Class: com.example.Main\r\nClass-Path: ") {
		t.Fatalf("manifest head: %q", manifest)
	}
	for _, line := range strings.Split(strings.TrimSuffix(manifest, "\r\n"), "\r\n") {
		if len(line) > 72 {
			t.Errorf("manifest line exceeds 72 bytes: %q", line)
		}
	}
	if !strings.Contains(manifest, "\r\n ") {
		t.Error("the long Class-Path must be wrapped onto continuation lines")
	}
	if unwrapped := strings.ReplaceAll(manifest, "\r\n ", ""); !strings.Contains(unwrapped, "Class-Path: "+longPath) {
		t.Error("unwrapping the continuation lines must restore the Class-Path value")
	}
	if !strings.Contains(manifest, "Implementation-Title: demo") || !strings.Contains(manifest, "Multi-Release: true") {
		t.Errorf("extra attributes missing: %q", manifest)
	}
	got := zipNames(t, b)
	want := []string{
		"META-INF/", "META-INF/MANIFEST.MF", "com/example/Main.class", "com/example/Helper1.class", "com/example/Helper2.class",
		"META-INF/CERT.SF", "META-INF/CERT.RSA", "lib/inner.jar",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("entries = %v\nwant     %v", got, want)
	}
	if class := zipFile(t, b, "com/example/Main.class"); !bytes.HasPrefix(class, []byte{0xCA, 0xFE, 0xBA, 0xBE}) {
		t.Errorf("class stub magic: %x", class[:4])
	}
}

func TestJAR_Defaults(t *testing.T) {
	names := zipNames(t, JAR(JAROptions{}))
	if len(names) != 3 || names[2] != "com/example/Main.class" {
		t.Errorf("default JAR entries = %v", names)
	}
	if none := zipNames(t, JAR(JAROptions{Classes: -1})); len(none) != 2 {
		t.Errorf("Classes -1 must produce no class files: %v", none)
	}
	if !bytes.Equal(JAR(JAROptions{MainClass: "A"}), JAR(JAROptions{MainClass: "A"})) {
		t.Error("JAR must be deterministic")
	}
}

// apkChunk is one chunk of an Android binary XML document.
type apkChunk struct {
	typ    uint16
	header uint16
	body   []byte // everything after the 8-byte chunk header
}

// apkReadChunks splits data into consecutive chunks, failing the test on any
// size inconsistency.
func apkReadChunks(t *testing.T, data []byte) []apkChunk {
	t.Helper()
	var chunks []apkChunk
	for len(data) > 0 {
		if len(data) < 8 {
			t.Fatalf("%d stray bytes after the last chunk", len(data))
		}
		size := int(binary.LittleEndian.Uint32(data[4:]))
		if size < 8 || size > len(data) {
			t.Fatalf("chunk size %d with %d bytes left", size, len(data))
		}
		chunks = append(chunks, apkChunk{binary.LittleEndian.Uint16(data), binary.LittleEndian.Uint16(data[2:]), data[8:size]})
		data = data[size:]
	}
	return chunks
}

// apkPoolStrings decodes a UTF-16 string pool chunk independently of any parser
// in the module.
func apkPoolStrings(t *testing.T, c apkChunk) []string {
	t.Helper()
	le := binary.LittleEndian
	// body starts at chunk offset 8: stringCount, styleCount, flags, stringsStart, stylesStart
	count := int(le.Uint32(c.body))
	flags := le.Uint32(c.body[8:])
	start := int(le.Uint32(c.body[12:])) - 8
	if flags != 0 {
		t.Fatalf("pool flags = %#x, fixtures use UTF-16", flags)
	}
	out := make([]string, count)
	for i := range count {
		off := start + int(le.Uint32(c.body[int(c.header)-8+4*i:]))
		n := int(le.Uint16(c.body[off:]))
		units := make([]uint16, n)
		for j := range n {
			units[j] = le.Uint16(c.body[off+2+2*j:])
		}
		if le.Uint16(c.body[off+2+2*n:]) != 0 {
			t.Fatalf("string %d is not NUL terminated", i)
		}
		out[i] = string(utf16.Decode(units))
	}
	return out
}

func TestAPK_ManifestIsStructurallyValidAXML(t *testing.T) {
	perms := []string{"android.permission.INTERNET", "android.permission.CAMERA", "com.example.demo.permission.PRIVATE"}
	b := APK(APKOptions{Permissions: perms})
	manifest := zipFile(t, b, "AndroidManifest.xml")

	outer := apkReadChunks(t, manifest)
	if len(outer) != 1 || outer[0].typ != 0x0003 || outer[0].header != 8 {
		t.Fatalf("outer chunk = %+v", outer)
	}
	chunks := apkReadChunks(t, outer[0].body)
	if chunks[0].typ != 0x0001 || chunks[0].header != 28 {
		t.Fatalf("first chunk must be the string pool: %+v", chunks[0])
	}
	pool := apkPoolStrings(t, chunks[0])
	wantPool := append([]string{"android", "http://schemas.android.com/apk/res/android", "manifest", "package", "uses-permission", "name", "com.example.demo"}, perms...)
	if !slices.Equal(pool, wantPool) {
		t.Fatalf("pool = %q\nwant   %q", pool, wantPool)
	}

	var types []uint16
	var permValues []string
	for _, c := range chunks[1:] {
		types = append(types, c.typ)
		if c.typ != 0x0102 {
			continue
		}
		// body: line, comment, ns, name, attrStart, attrSize, attrCount, id, class, style, attributes...
		le := binary.LittleEndian
		name := pool[le.Uint32(c.body[12:])]
		count := int(le.Uint16(c.body[20:]))
		if le.Uint16(c.body[16:]) != 20 || le.Uint16(c.body[18:]) != 20 {
			t.Fatalf("attribute geometry of <%s> is wrong", name)
		}
		if len(c.body) != 28+20*count {
			t.Fatalf("<%s> body = %d bytes for %d attributes", name, len(c.body), count)
		}
		if name == "uses-permission" {
			attr := c.body[28:]
			if pool[le.Uint32(attr[4:])] != "name" || attr[15] != 0x03 {
				t.Fatalf("uses-permission attribute malformed: %x", attr)
			}
			permValues = append(permValues, pool[le.Uint32(attr[16:])])
		}
	}
	wantTypes := []uint16{0x0100, 0x0102, 0x0102, 0x0103, 0x0102, 0x0103, 0x0102, 0x0103, 0x0103, 0x0101}
	if !slices.Equal(types, wantTypes) {
		t.Fatalf("node sequence = %#x\nwant           %#x", types, wantTypes)
	}
	if !slices.Equal(permValues, perms) {
		t.Fatalf("permissions in XML = %v", permValues)
	}
}

func TestAPK_Layout(t *testing.T) {
	b := APK(APKOptions{ABIs: []string{"arm64-v8a", "x86_64"}, DexFiles: 3, V1Signed: true, Permissions: []string{"android.permission.INTERNET"}})
	want := []string{
		"AndroidManifest.xml", "classes.dex", "classes2.dex", "classes3.dex", "resources.arsc",
		"lib/arm64-v8a/libdemo.so", "lib/x86_64/libdemo.so", "META-INF/CERT.SF", "META-INF/CERT.RSA",
	}
	if got := zipNames(t, b); !slices.Equal(got, want) {
		t.Fatalf("entries = %v\nwant     %v", got, want)
	}
	if dex := zipFile(t, b, "classes2.dex"); !bytes.HasPrefix(dex, []byte("dex\n035\x00")) {
		t.Errorf("dex magic: %q", dex[:8])
	}
	if so := zipFile(t, b, "lib/x86_64/libdemo.so"); !bytes.HasPrefix(so, []byte("\x7fELF")) {
		t.Errorf("so magic: %q", so[:4])
	}
	if names := zipNames(t, APK(APKOptions{DexFiles: -1})); slices.Contains(names, "classes.dex") {
		t.Errorf("DexFiles -1 must omit dex files: %v", names)
	}
	if !bytes.Equal(b, APK(APKOptions{ABIs: []string{"arm64-v8a", "x86_64"}, DexFiles: 3, V1Signed: true, Permissions: []string{"android.permission.INTERNET"}})) {
		t.Error("APK must be deterministic")
	}
}

func TestAPK_SigningBlockSitsBeforeTheCentralDirectory(t *testing.T) {
	b := APK(APKOptions{SigningBlock: true})
	zr := zipOpen(t, b) // the standard library must still read the shifted directory
	if len(zr.File) < 2 {
		t.Fatalf("entries = %d", len(zr.File))
	}
	eocd := len(b) - 22
	cd := int(binary.LittleEndian.Uint32(b[eocd+16:]))
	if got := string(b[cd-16 : cd]); got != "APK Sig Block 42" {
		t.Fatalf("bytes before the central directory = %q", got)
	}
	// The block starts with its size and ends with the same size before the magic.
	sizeOfBlock := binary.LittleEndian.Uint64(b[cd-16-8:])
	start := cd - int(sizeOfBlock) - 8 // the size field itself is not counted in sizeOfBlock
	if binary.LittleEndian.Uint64(b[start:]) != sizeOfBlock {
		t.Fatalf("leading block size does not match the trailing one")
	}
	if plain := APK(APKOptions{}); bytes.Contains(plain, []byte("APK Sig Block 42")) {
		t.Error("a plain APK must not carry a signing block")
	}
}

// aabStrings collects every string of a protocol buffer message, descending
// into fields that parse as messages themselves. It is a deliberately small,
// independent reader used only to validate the fixture.
func aabStrings(b []byte, depth int) []string {
	var out []string
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return out
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return out
			}
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || int(l) > len(b)-n {
				return out
			}
			payload := b[n : n+int(l)]
			b = b[n+int(l):]
			if nested := aabStrings(payload, depth+1); depth < 8 && len(nested) > 0 && len(payload) > 0 && payload[0] < 0x80 && aabLooksLikeMessage(payload) {
				out = append(out, nested...)
			} else {
				out = append(out, string(payload))
			}
		default:
			return out
		}
	}
	return out
}

// aabLooksLikeMessage tells a nested message from a plain string: a message
// parses completely as tag/length pairs.
func aabLooksLikeMessage(b []byte) bool {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 || tag&7 > 5 {
			return false
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || int(l) > len(b)-n {
				return false
			}
			b = b[n+int(l):]
		default:
			return false
		}
	}
	return true
}

func TestAAB_Layout(t *testing.T) {
	perms := []string{"android.permission.INTERNET", "android.permission.READ_CONTACTS"}
	b := AAB(AABOptions{Permissions: perms, ABIs: []string{"arm64-v8a"}})
	want := []string{
		"BundleConfig.pb", "base/manifest/AndroidManifest.xml", "base/dex/classes.dex", "base/resources.pb",
		"base/lib/arm64-v8a/libdemo.so", "META-INF/MANIFEST.MF",
	}
	if got := zipNames(t, b); !slices.Equal(got, want) {
		t.Fatalf("entries = %v\nwant     %v", got, want)
	}
	manifest := zipFile(t, b, "base/manifest/AndroidManifest.xml")
	strs := aabStrings(manifest, 0)
	for _, p := range append([]string{"manifest", "uses-permission", "package", "com.example.demo", "name"}, perms...) {
		if !slices.Contains(strs, p) {
			t.Errorf("protobuf manifest lacks the string %q (found %q)", p, strs)
		}
	}
	for _, p := range perms {
		if !bytes.Contains(manifest, []byte(p)) {
			t.Errorf("permission %q must appear as raw bytes", p)
		}
	}
	if !bytes.Equal(b, AAB(AABOptions{Permissions: perms, ABIs: []string{"arm64-v8a"}})) {
		t.Error("AAB must be deterministic")
	}
}
