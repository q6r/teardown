package testfixtures

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// asarNode mirrors the index layout for the independent reader below.
type asarNode struct {
	Files      map[string]*asarNode `json:"files"`
	Size       int                  `json:"size"`
	Offset     string               `json:"offset"`
	Unpacked   bool                 `json:"unpacked"`
	Executable bool                 `json:"executable"`
	Integrity  *struct {
		Algorithm string   `json:"algorithm"`
		Hash      string   `json:"hash"`
		BlockSize int      `json:"blockSize"`
		Blocks    []string `json:"blocks"`
	} `json:"integrity"`
}

// asarRead is a minimal reader written from the format description, used only
// to prove that the fixture is a well-formed ASAR file. It returns the files by
// path (nil data for unpacked ones) after checking framing, offsets and hashes.
func asarRead(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	le := binary.LittleEndian
	if len(b) < 16 || le.Uint32(b) != 4 {
		t.Fatalf("size pickle is wrong: % x", b[:min(16, len(b))])
	}
	headerSize := int(le.Uint32(b[4:]))
	payload := int(le.Uint32(b[8:]))
	jsonLen := int(le.Uint32(b[12:]))
	if payload != headerSize-4 {
		t.Fatalf("payload size %d does not match header size %d", payload, headerSize)
	}
	if payload != 4+(jsonLen+3)&^3 {
		t.Fatalf("payload %d is not the aligned string length plus 4 (json %d)", payload, jsonLen)
	}
	base := 8 + headerSize
	if base > len(b) {
		t.Fatalf("data starts at %d beyond the %d byte file", base, len(b))
	}
	var root asarNode
	if err := json.Unmarshal(b[16:16+jsonLen], &root); err != nil {
		t.Fatalf("index is not JSON: %v", err)
	}
	for _, pad := range b[16+jsonLen : base] {
		if pad != 0 {
			t.Fatal("padding must be zero")
		}
	}
	files := map[string][]byte{}
	var walk func(prefix string, n *asarNode)
	walk = func(prefix string, n *asarNode) {
		for name, child := range n.Files {
			path := prefix + name
			if child.Files != nil {
				walk(path+"/", child)
				continue
			}
			if child.Unpacked {
				if child.Offset != "" {
					t.Errorf("%s: unpacked files have no offset", path)
				}
				files[path] = nil
				continue
			}
			off, err := strconv.Atoi(child.Offset)
			if err != nil || off < 0 || base+off+child.Size > len(b) {
				t.Errorf("%s: offset %q size %d is out of range", path, child.Offset, child.Size)
				continue
			}
			content := b[base+off : base+off+child.Size]
			sum := sha256.Sum256(content)
			if child.Integrity == nil || child.Integrity.Hash != hex.EncodeToString(sum[:]) || child.Integrity.Algorithm != "SHA256" {
				t.Errorf("%s: integrity block is wrong: %+v", path, child.Integrity)
			}
			files[path] = content
		}
	}
	walk("", &root)
	return files
}

func TestAsar_RoundTrip(t *testing.T) {
	files := asarRead(t, Asar(
		AsarFile{Path: "a.txt", Data: []byte("alpha")},
		AsarFile{Path: "dir/b.txt", Data: []byte("beta beta")},
		AsarFile{Path: "dir/sub/c.bin", Data: []byte{0, 1, 2, 3}},
		AsarFile{Path: "empty", Data: nil},
		AsarFile{Path: "lib/native.node", Data: []byte("elf"), Unpacked: true},
	))
	want := map[string]string{"a.txt": "alpha", "dir/b.txt": "beta beta", "dir/sub/c.bin": "\x00\x01\x02\x03", "empty": ""}
	for path, content := range want {
		if got, ok := files[path]; !ok || string(got) != content {
			t.Errorf("%s = %q (present %v), want %q", path, got, ok, content)
		}
	}
	if got, ok := files["lib/native.node"]; !ok || got != nil {
		t.Errorf("unpacked file: %q present=%v", got, ok)
	}
	if len(files) != 5 {
		t.Errorf("files = %d", len(files))
	}
}

func TestAsar_FramingAndAlignment(t *testing.T) {
	// Index lengths of every residue modulo 4 must produce a valid, aligned header.
	for pad := range 5 {
		name := "f" + strings.Repeat("x", pad)
		b := Asar(AsarFile{Path: name, Data: []byte("data")})
		files := asarRead(t, b)
		if string(files[name]) != "data" {
			t.Errorf("pad %d: content = %q", pad, files[name])
		}
		if (8+int(binary.LittleEndian.Uint32(b[4:])))%4 != 0 {
			t.Errorf("pad %d: data does not start on a 4-byte boundary", pad)
		}
	}
}

func TestAsar_Deterministic(t *testing.T) {
	if !bytes.Equal(AsarElectronApp(), AsarElectronApp()) {
		t.Fatal("AsarElectronApp must be deterministic")
	}
}

func TestAsar_ElectronApp(t *testing.T) {
	b := AsarElectronApp()
	files := asarRead(t, b)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"bin/helper", "index.html", "main.js", "native/addon.node", "node_modules/left-pad/index.js", "package.json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v", names)
	}
	var pkg struct {
		Name    string
		Main    string
		DevDeps map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(files["package.json"], &pkg); err != nil || pkg.Name != "demo-app" || pkg.Main != "main.js" || pkg.DevDeps["electron"] != "^28.1.0" {
		t.Fatalf("package.json = %+v, %v", pkg, err)
	}
	for _, flag := range []string{"nodeIntegration: true", "contextIsolation: false", "webSecurity: false", "enableRemoteModule: true", "allowRunningInsecureContent: true", "sandbox: false", "--no-sandbox", "require('child_process')"} {
		if !bytes.Contains(files["main.js"], []byte(flag)) {
			t.Errorf("main.js lacks %q", flag)
		}
	}
	if !bytes.Contains(files["node_modules/left-pad/index.js"], []byte("nodeIntegration: true")) {
		t.Error("the third-party module must mention the flag so analysers can prove they skip it")
	}
	if files["native/addon.node"] != nil {
		t.Error("the native addon must be unpacked")
	}
}

func TestAsar_RawFramesAnyHeader(t *testing.T) {
	b := AsarRaw(`{"files":{}}`, []byte("tail"))
	if got := binary.LittleEndian.Uint32(b[12:]); got != 12 {
		t.Fatalf("json length field = %d", got)
	}
	if !bytes.HasSuffix(b, []byte("tail")) || !bytes.Contains(b, []byte(`{"files":{}}`)) {
		t.Fatalf("raw framing lost data: %q", b)
	}
	if empty := AsarRaw("", nil); binary.LittleEndian.Uint32(empty[12:]) != 0 || len(empty) != 16 {
		t.Fatalf("empty header: % x", empty)
	}
}
