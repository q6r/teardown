package testfixtures

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AsarFile is one file of a fixture ASAR archive.
type AsarFile struct {
	// Path is slash-separated and relative to the archive root.
	Path string
	// Data is the file content.
	Data []byte
	// Unpacked marks a file kept outside the archive (in app.asar.unpacked):
	// the index records its size and the flag but no offset, and the content is
	// not embedded.
	Unpacked bool
	// Executable sets the executable flag.
	Executable bool
}

// Asar builds an Electron ASAR archive: a Chromium pickle holding the JSON
// index, followed by the packed file contents. The index follows the layout of
// the asar tool: directories are {"files": {...}}, packed files carry a size, a
// decimal-string offset and a SHA-256 integrity block, unpacked files carry
// "unpacked": true instead of an offset.
func Asar(files ...AsarFile) []byte {
	root := map[string]any{"files": map[string]any{}}
	var data []byte
	for _, f := range files {
		parts := strings.Split(f.Path, "/")
		dir := root
		for _, name := range parts[:len(parts)-1] {
			children := dir["files"].(map[string]any)
			next, ok := children[name].(map[string]any)
			if !ok {
				next = map[string]any{"files": map[string]any{}}
				children[name] = next
			}
			dir = next
		}
		node := map[string]any{"size": len(f.Data)}
		if f.Unpacked {
			node["unpacked"] = true
		} else {
			sum := sha256.Sum256(f.Data)
			hash := hex.EncodeToString(sum[:])
			node["offset"] = strconv.Itoa(len(data))
			node["integrity"] = map[string]any{"algorithm": "SHA256", "hash": hash, "blockSize": 4194304, "blocks": []string{hash}}
			data = append(data, f.Data...)
		}
		if f.Executable {
			node["executable"] = true
		}
		dir["files"].(map[string]any)[parts[len(parts)-1]] = node
	}
	index, err := json.Marshal(root)
	if err != nil {
		panic(fmt.Sprintf("testfixtures: asar index: %v", err))
	}
	return AsarRaw(string(index), data)
}

// AsarRaw frames an arbitrary header string and data as an ASAR file without
// looking at the header, so tests can build hostile or malformed indexes.
func AsarRaw(header string, data []byte) []byte {
	padded := (len(header) + 3) &^ 3
	payload := 4 + padded // the string length field plus the padded string
	headerSize := 4 + payload
	out := make([]byte, 0, 8+headerSize+len(data))
	out = binary.LittleEndian.AppendUint32(out, 4)
	out = binary.LittleEndian.AppendUint32(out, uint32(headerSize))
	out = binary.LittleEndian.AppendUint32(out, uint32(payload))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(header)))
	out = append(out, header...)
	out = append(out, make([]byte, padded-len(header))...)
	return append(out, data...)
}

// AsarElectronApp returns the archive of a small Electron application: a
// package.json naming electron as a dev dependency, a main process script that
// contains the risky BrowserWindow settings as plain text, an HTML page, a
// third-party module that also mentions them (which analysers should skip), an
// unpacked native addon and a stored executable.
func AsarElectronApp() []byte {
	pkg := `{"name":"demo-app","version":"1.2.3","main":"main.js","description":"Fixture Electron application",` +
		`"dependencies":{"electron-log":"^5.0.0","left-pad":"^1.3.0"},"devDependencies":{"electron":"^28.1.0"}}`
	main := `const { app, BrowserWindow } = require('electron');
const cp = require('child_process');

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      enableRemoteModule: true,
      allowRunningInsecureContent: true,
      sandbox: false,
    },
  });
  win.loadFile('index.html');
}

app.commandLine.appendSwitch('--no-sandbox');
app.whenReady().then(createWindow);
`
	return Asar(
		AsarFile{Path: "package.json", Data: []byte(pkg)},
		AsarFile{Path: "main.js", Data: []byte(main)},
		AsarFile{Path: "index.html", Data: []byte("<!doctype html><title>demo</title>")},
		AsarFile{Path: "node_modules/left-pad/index.js", Data: []byte("// docs: new BrowserWindow({ webPreferences: { nodeIntegration: true } })\nmodule.exports = function leftPad() {};\n")},
		AsarFile{Path: "native/addon.node", Data: []byte("\x7fELF"), Unpacked: true},
		AsarFile{Path: "bin/helper", Data: []byte("#!/bin/sh\n"), Executable: true},
	)
}
