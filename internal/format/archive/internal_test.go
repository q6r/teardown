package archive

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/testfixtures"
	"github.com/q6r/teardown/internal/zipscan"
)

func TestUnsafePath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"plain", "docs/readme.txt", false},
		{"nested directory", "a/b/c/d.bin", false},
		{"dot segment is fine", "./a/b", false},
		{"dots inside a name are fine", "a/b..c/d...e", false},
		{"three dots", "a/.../b", false},
		{"parent segment", "../evil", true},
		{"deep parent", "a/b/../../../evil", true},
		{"parent in the middle even if it stays inside", "a/../b", true},
		{"backslash parent", `..\evil`, true},
		{"backslash parent in the middle", `a\..\..\evil`, true},
		{"trailing parent", "a/..", true},
		{"absolute posix", "/etc/passwd", true},
		{"absolute with backslash", `\Windows\System32\x.dll`, true},
		{"unc", `\\server\share\x`, true},
		{"drive letter", `C:\Windows\x.exe`, true},
		{"lowercase drive letter with slash", "d:/tmp/x", true},
		{"drive relative", "c:evil", true},
		{"colon later is fine", "ab:c/d", false},
		{"nul byte", "ok.txt\x00../../x", true},
		{"empty", "", false},
		{"single letter then colon in a directory", "x/c:/y", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unsafePath(tc.raw); got != tc.want {
				t.Fatalf("unsafePath(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseManifest(t *testing.T) {
	long := strings.Repeat("x", 3000)
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"simple", "Manifest-Version: 1.0\r\nMain-Class: a.B\r\n\r\n", map[string]string{"Manifest-Version": "1.0", "Main-Class": "a.B"}},
		{"lf only", "Manifest-Version: 1.0\nMain-Class: a.B\n", map[string]string{"Manifest-Version": "1.0", "Main-Class": "a.B"}},
		{"cr only", "Manifest-Version: 1.0\rMain-Class: a.B\r", map[string]string{"Manifest-Version": "1.0", "Main-Class": "a.B"}},
		{"continuation lines", "Class-Path: one.jar\r\n two.jar\r\n  three.jar\r\nX: y\r\n", map[string]string{"Class-Path": "one.jartwo.jar three.jar", "X": "y"}},
		{"stops at the first blank line", "A: 1\r\n\r\nName: x\r\nB: 2\r\n", map[string]string{"A": "1"}},
		{"value may contain colons", "Url: http://example.com:8080/x\r\n", map[string]string{"Url": "http://example.com:8080/x"}},
		{"no space after the colon", "A:1\r\n", map[string]string{"A": "1"}},
		{"line without a colon is skipped", "garbage\r\nA: 1\r\n", map[string]string{"A": "1"}},
		{"empty value", "A:\r\nB: 2\r\n", map[string]string{"A": "", "B": "2"}},
		{"last duplicate wins", "A: 1\r\nA: 2\r\n", map[string]string{"A": "2"}},
		{"continuation without attribute is ignored", " orphan\r\nA: 1\r\n", map[string]string{"A": "1"}},
		{"control characters are escaped", "A: x\x1b[31my\r\n", map[string]string{"A": `x\x1b[31my`}},
		{"empty input", "", map[string]string{}},
		{"only blank lines", "\r\n\r\n", map[string]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseManifest([]byte(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
	t.Run("long values are cut", func(t *testing.T) {
		got := parseManifest([]byte("A: " + long + "\r\n"))
		if n := len([]rune(got["A"])); n > maxManifestVal+1 {
			t.Fatalf("value has %d runes", n)
		}
	})
	t.Run("attribute count is capped", func(t *testing.T) {
		var sb strings.Builder
		for i := range 500 {
			sb.WriteString("Key")
			sb.WriteString(strings.Repeat("a", i%7))
			sb.WriteString(strings.Repeat("b", i/7))
			sb.WriteString(": v\r\n")
		}
		if got := parseManifest([]byte(sb.String())); len(got) > maxManifestKeys {
			t.Fatalf("%d attributes recorded, cap is %d", len(got), maxManifestKeys)
		}
	})
}

// utf8Pool builds a binary XML document holding only a UTF-8 string pool.
func utf8Pool(strs ...string) []byte {
	le := binary.LittleEndian
	var data []byte
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(len(data))
		for range 2 { // character count, then byte count
			if len(s) >= 0x80 {
				data = append(data, byte(0x80|len(s)>>8), byte(len(s)))
			} else {
				data = append(data, byte(len(s)))
			}
		}
		data = append(append(data, s...), 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	start := 28 + 4*len(strs)
	pool := le.AppendUint16(nil, 1)
	pool = le.AppendUint16(pool, 28)
	pool = le.AppendUint32(pool, uint32(start+len(data)))
	pool = le.AppendUint32(pool, uint32(len(strs)))
	pool = le.AppendUint32(pool, 0)
	pool = le.AppendUint32(pool, 0x100)
	pool = le.AppendUint32(pool, uint32(start))
	pool = le.AppendUint32(pool, 0)
	for _, o := range offsets {
		pool = le.AppendUint32(pool, o)
	}
	pool = append(pool, data...)
	doc := le.AppendUint16(nil, 3)
	doc = le.AppendUint16(doc, 8)
	doc = le.AppendUint32(doc, uint32(8+len(pool)))
	return append(doc, pool...)
}

func TestAXMLStrings(t *testing.T) {
	perms := []string{"android.permission.INTERNET", "com.example.permission.X"}
	fixture := testfixtures.APK(testfixtures.APKOptions{Permissions: perms})
	manifest := readEntry(t, fixture, "AndroidManifest.xml")

	t.Run("utf-16 pool from the fixture", func(t *testing.T) {
		got, err := axmlStrings(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 7+len(perms) || got[2] != "manifest" || got[7] != perms[0] || got[8] != perms[1] {
			t.Fatalf("pool = %q", got)
		}
	})
	t.Run("utf-8 pool including a long string", func(t *testing.T) {
		long := strings.Repeat("a", 200)
		got, err := axmlStrings(utf8Pool("android.permission.CAMERA", long, "naïve"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0] != "android.permission.CAMERA" || got[1] != long || got[2] != "naïve" {
			t.Fatalf("pool = %q", got)
		}
	})
	t.Run("not xml", func(t *testing.T) {
		for _, in := range [][]byte{nil, {1, 2, 3}, []byte("<?xml version='1.0'?><manifest/>"), make([]byte, 64)} {
			if _, err := axmlStrings(in); err == nil {
				t.Errorf("axmlStrings(%q) must fail", in)
			}
		}
	})
	t.Run("corrupt pools fail cleanly", func(t *testing.T) {
		mutations := map[string]func([]byte){
			"huge string count":    func(b []byte) { binary.LittleEndian.PutUint32(b[8+8:], 0x7FFFFFFF) },
			"strings start past":   func(b []byte) { binary.LittleEndian.PutUint32(b[8+20:], 0xFFFFFF) },
			"strings start before": func(b []byte) { binary.LittleEndian.PutUint32(b[8+20:], 4) },
			"chunk size too large": func(b []byte) { binary.LittleEndian.PutUint32(b[8+4:], 0x7FFFFFFF) },
			"chunk size tiny":      func(b []byte) { binary.LittleEndian.PutUint32(b[8+4:], 3) },
			"header size tiny":     func(b []byte) { binary.LittleEndian.PutUint16(b[8+2:], 4) },
		}
		for name, mutate := range mutations {
			b := bytes.Clone(manifest)
			mutate(b)
			if _, err := axmlStrings(b); err == nil {
				t.Errorf("%s: expected an error", name)
			}
		}
	})
	t.Run("wild string offsets give empty strings, not panics", func(t *testing.T) {
		b := bytes.Clone(manifest)
		binary.LittleEndian.PutUint32(b[8+28:], 0xFFFFFFF0) // first offset
		got, err := axmlStrings(b)
		if err != nil || got[0] != "" {
			t.Fatalf("got %q, %v", got[:1], err)
		}
	})
	t.Run("extended utf-16 length prefix", func(t *testing.T) {
		// 0x8000 flags a two-unit length: (first&0x7FFF)<<16 | second.
		b := []byte{0x00, 0x80, 0x03, 0x00, 'a', 0, 'b', 0, 'c', 0}
		if got := poolString16(b); got != "abc" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("lengths beyond the data are clamped", func(t *testing.T) {
		if got := poolString16([]byte{0xFF, 0x7F, 'a', 0}); got != "a" {
			t.Errorf("utf-16: %q", got)
		}
		if got := poolString8([]byte{0x01, 0xFF, 0xFF, 'a'}); got != "a" {
			t.Errorf("utf-8: %q", got)
		}
		if poolString16([]byte{1}) != "" || poolString8(nil) != "" || poolString8([]byte{3}) != "" {
			t.Error("short input must give empty strings")
		}
	})
}

func readEntry(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	d, err := zipscan.Scan(t.Context(), bytes.NewReader(archive), int64(len(archive)), 100)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := d.Find(name)
	if !ok {
		t.Fatalf("entry %q not found", name)
	}
	data, err := zipscan.Read(bytes.NewReader(archive), int64(len(archive)), e, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManifestPermissions(t *testing.T) {
	perms := []string{"android.permission.CAMERA", "android.permission.INTERNET", "com.example.demo.permission.PRIVATE"}
	apk := readEntry(t, testfixtures.APK(testfixtures.APKOptions{Permissions: append(perms, perms[0])}), "AndroidManifest.xml")
	aab := readEntry(t, testfixtures.AAB(testfixtures.AABOptions{Permissions: perms}), "base/manifest/AndroidManifest.xml")

	tests := []struct {
		name           string
		data           []byte
		want           []string
		wantStructured bool
	}{
		{"binary xml, duplicates removed and sorted", apk, perms, true},
		{"protocol buffer manifest is scanned as raw bytes", aab, perms, false},
		{"utf-8 pool", utf8Pool("android.permission.VIBRATE", "not a permission", "manifest", "com.android.vending.BILLING", "foo.permission.lower"), []string{"android.permission.VIBRATE", "com.android.vending.BILLING"}, true},
		{"nothing", []byte("nothing to see"), nil, false},
		{"empty", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, structured := manifestPermissions(tc.data)
			if !slices.Equal(got, tc.want) || structured != tc.wantStructured {
				t.Fatalf("got %q (structured %v), want %q (%v)", got, structured, tc.want, tc.wantStructured)
			}
		})
	}
}

func TestScanPermissionsTrimsProtocolBufferFraming(t *testing.T) {
	perm := "android.permission.INTERNET" // 27 bytes
	long := "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"
	lower := strings.Repeat("a", 1) + "ndroid.permission." + strings.Repeat("X", 82) // 100 bytes, length byte is the letter 'd'
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"length byte is a control character", append([]byte{0x0A, byte(len(perm))}, perm...), []string{perm}},
		{"length byte is a letter (70 = 'F')", append([]byte{0x0A, byte(len(long))}, long...), []string{long}},
		{"next field tag is an uppercase letter", slices.Concat([]byte{0x0A, byte(len(perm))}, []byte(perm), []byte{'B', 0x01}), []string{perm}},
		{"long lowercase length byte", slices.Concat([]byte{0x12, byte(len(lower))}, []byte(lower)), []string{lower}},
		{"two in a row", slices.Concat([]byte{0x0A, byte(len(perm))}, []byte(perm), []byte{0x0A, byte(len(perm))}, []byte(perm)), []string{perm, perm}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanPermissions(tc.data); !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPermissionRegexp(t *testing.T) {
	good := []string{
		"android.permission.INTERNET", "android.permission.BIND_ACCESSIBILITY_SERVICE",
		"com.google.android.c2dm.permission.RECEIVE", "com.example.app.permission.MAPS_RECEIVE",
		"com.android.vending.BILLING", "android.permission.some_lowercase",
	}
	bad := []string{"", "permission.INTERNET", "android.permission.", "android.permission", "some string", "android.permission.INTERNET extra", "com.example.permissionless.X"}
	for _, s := range good {
		if !permissionRE.MatchString(s) {
			t.Errorf("%q must match", s)
		}
	}
	for _, s := range bad {
		if permissionRE.MatchString(s) {
			t.Errorf("%q must not match", s)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	for name, want := range map[string]bool{
		"classes.dex": true, "classes2.dex": true, "classes12.dex": true,
		"classes.dexx": false, "classes-x.dex": false, "class.dex": false, "classesA.dex": false, "x.dex": false,
	} {
		if got := isClassesDex(name); got != want {
			t.Errorf("isClassesDex(%q) = %v", name, got)
		}
	}
	abiTests := []struct {
		raw    string
		bundle bool
		abi    string
		ok     bool
	}{
		{"lib/arm64-v8a/libx.so", false, "arm64-v8a", true},
		{"LIB/x86/libx.so", false, "x86", true},
		{`lib\armeabi-v7a\libx.so`, false, "armeabi-v7a", true},
		{"lib/libx.so", false, "", false},
		{"base/lib/arm64-v8a/libx.so", true, "arm64-v8a", true},
		{"base/lib/libx.so", true, "", false},
		{"lib/arm64-v8a/libx.so", true, "", false},
		{"assets/lib/x86/libx.so", false, "", false},
		{"lib//libx.so", false, "", false},
	}
	for _, tc := range abiTests {
		abi, ok := nativeABI(tc.raw, tc.bundle)
		if abi != tc.abi || ok != tc.ok {
			t.Errorf("nativeABI(%q, %v) = %q, %v", tc.raw, tc.bundle, abi, ok)
		}
	}
	if !looksLikeContainer([]byte("PK\x03\x04rest")) || !looksLikeContainer([]byte("MZ")) || !looksLikeContainer([]byte{0x7F, 'E', 'L', 'F', 2}) {
		t.Error("container magics not recognised")
	}
	if looksLikeContainer([]byte("hello")) || looksLikeContainer(nil) || looksLikeContainer([]byte("P")) {
		t.Error("false positive on non-container bytes")
	}
	for in, want := range map[uint16]string{0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 95: "xz", 98: "ppmd", 99: "aes", 77: "method-77"} {
		if got := methodName(in); got != want {
			t.Errorf("methodName(%d) = %q", in, got)
		}
	}
	if round3(1.23456) != 1.235 || round3(0) != 0 {
		t.Error("round3 is wrong")
	}
}
