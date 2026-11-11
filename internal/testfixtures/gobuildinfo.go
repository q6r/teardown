package testfixtures

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// GoBuildInfoModule is one module in the embedded build information.
type GoBuildInfoModule struct {
	Path    string
	Version string
	Sum     string
	// Replace, when set, is emitted as the "=>" line following the module.
	Replace *GoBuildInfoModule
}

// GoBuildInfoSetting is one "build" line (key=value) of the build information.
type GoBuildInfoSetting struct {
	Key   string
	Value string
}

// GoBuildInfoOptions describes the Go build information that [GoBuildInfo]
// embeds. Every zero field has a documented default.
type GoBuildInfoOptions struct {
	// GoVersion defaults to "go1.26.5".
	GoVersion string
	// Path is the main package path (default "example.com/hello").
	Path string
	// Main is the main module (default Path at "(devel)").
	Main GoBuildInfoModule
	// Deps are the dependency modules.
	Deps []GoBuildInfoModule
	// Settings default to -buildmode=exe, -compiler=gc, CGO_ENABLED=0,
	// GOARCH=amd64 and GOOS=linux.
	Settings []GoBuildInfoSetting
	// OmitModInfo drops the module information (a binary built without modules).
	OmitModInfo bool
}

// GoBuildInfoBlob returns the inline-format (Go 1.18+) build information blob:
// the "\xff Go buildinf:" header followed by the length-prefixed version and
// module strings, framed with the sentinels cmd/go uses, and 16 bytes of zero
// padding.
func GoBuildInfoBlob(o GoBuildInfoOptions) []byte {
	version := o.GoVersion
	if version == "" {
		version = "go1.26.5"
	}
	path := o.Path
	if path == "" {
		path = "example.com/hello"
	}
	main := o.Main
	if main.Path == "" {
		main = GoBuildInfoModule{Path: path, Version: "(devel)"}
	}
	settings := o.Settings
	if settings == nil {
		settings = []GoBuildInfoSetting{
			{"-buildmode", "exe"}, {"-compiler", "gc"}, {"CGO_ENABLED", "0"}, {"GOARCH", "amd64"}, {"GOOS", "linux"},
		}
	}

	var mod strings.Builder
	mod.WriteString("path\t" + path + "\n")
	gobuildinfoModule(&mod, "mod", main)
	for _, d := range o.Deps {
		gobuildinfoModule(&mod, "dep", d)
	}
	for _, s := range settings {
		key, value := s.Key, s.Value
		if strings.ContainsAny(key, "= \t\r\n\"`") || key == "" {
			key = strconv.Quote(key)
		}
		if strings.ContainsAny(value, " \t\r\n\"`") {
			value = strconv.Quote(value)
		}
		mod.WriteString("build\t" + key + "=" + value + "\n")
	}
	modinfo := ""
	if !o.OmitModInfo {
		modinfo = gobuildinfoInfoStart + mod.String() + gobuildinfoInfoEnd
	}

	var blob bytes.Buffer
	blob.WriteString("\xff Go buildinf:")
	blob.WriteByte(8)    // pointer size (unused in the inline format)
	blob.WriteByte(0x02) // flags: inline strings, little endian
	blob.Write(make([]byte, 16))
	blob.Write(binary.AppendUvarint(nil, uint64(len(version))))
	blob.WriteString(version)
	blob.Write(binary.AppendUvarint(nil, uint64(len(modinfo))))
	blob.WriteString(modinfo)
	// debug/buildinfo reads ten bytes (a maximal varint) ahead of every string,
	// so the strings must not sit at the very end of their section.
	blob.Write(make([]byte, 16))
	return blob.Bytes()
}

// The sentinels cmd/go wraps module information in (modload.infoStart/infoEnd).
const (
	gobuildinfoInfoStart = "\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6"
	gobuildinfoInfoEnd   = "\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2"
)

func gobuildinfoModule(sb *strings.Builder, word string, m GoBuildInfoModule) {
	sb.WriteString(word + "\t" + m.Path + "\t" + m.Version)
	if m.Replace == nil {
		sb.WriteString("\t" + m.Sum + "\n")
		return
	}
	sb.WriteString("\n=>\t" + m.Replace.Path + "\t" + m.Replace.Version + "\t" + m.Replace.Sum + "\n")
}

// GoBuildInfo returns a tiny static ELF executable whose .go.buildinfo section
// carries [GoBuildInfoBlob], so debug/buildinfo.Read accepts it.
func GoBuildInfo(o GoBuildInfoOptions) []byte {
	return ELF(ELFOptions{
		Type: ELFTypeExec, Static: true,
		Sections: []ELFSection{{
			Name: ".go.buildinfo", Flags: ELFSectionFlagAlloc | ELFSectionFlagWrite, Data: GoBuildInfoBlob(o), Align: 16,
		}},
	})
}

// ErrNoGoCommand is returned by [GoBuildInfoCompile] when no go command is on PATH.
var ErrNoGoCommand = errors.New("go command not found on PATH")

// GoBuildInfoCompile builds a minimal program (standard library only, cgo
// disabled) for the given target with the local Go toolchain and returns the
// path of the binary inside dir. It exists so parser tests can be checked
// against genuine linker output; callers should skip when it fails with
// [ErrNoGoCommand]. Extra arguments are passed to "go build".
func GoBuildInfoCompile(ctx context.Context, dir, goos, goarch string, extra ...string) (string, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return "", ErrNoGoCommand
	}
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o750); err != nil {
		return "", err
	}
	files := map[string]string{
		"go.mod":  "module example.com/hello\n\ngo 1.24\n",
		"main.go": "package main\n\nimport \"os\"\n\nfunc main() { os.Stdout.WriteString(\"hello\\n\") }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o600); err != nil {
			return "", err
		}
	}
	out := filepath.Join(dir, fmt.Sprintf("hello-%s-%s", goos, goarch))
	args := append([]string{"build", "-o", out}, extra...)
	cmd := exec.CommandContext(ctx, goBin, append(args, ".")...)
	cmd.Dir = src
	cmd.Env = append(os.Environ(),
		"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0",
		"GOFLAGS=", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local",
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build for %s/%s failed: %w\n%s", goos, goarch, err, combined)
	}
	return out, nil
}
