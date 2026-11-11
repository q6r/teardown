// Package goinfo reads the build information the Go linker embeds in every Go
// executable (ELF, PE and Mach-O): toolchain version, main package and module,
// dependencies with their versions, build settings, and VCS stamping.
//
// It wraps debug/buildinfo. The file is only read, never executed, and a binary
// without build information (or any input that is not a Go executable) simply
// yields "not found".
package goinfo

import (
	"debug/buildinfo"
	"io"
	"runtime/debug"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

// Limits on what is copied out of the build information.
const (
	maxDeps     = 2000 // dependency modules recorded
	maxSettings = 256  // build settings recorded
	maxValue    = 2048 // characters kept of any single value
	maxVersion  = 128  // characters kept of module paths, versions and the Go version
)

// Info is the Go build information, stored under details["go"] of a report.
type Info struct {
	// GoVersion is the toolchain that built the binary, e.g. "go1.26.5".
	GoVersion string `json:"goVersion"`
	// Path is the main package path.
	Path string `json:"path"`
	// Main is the main module.
	Main Module `json:"main"`
	// Deps lists the dependency modules (at most 2000); DepCount is the true number.
	Deps     []Module `json:"deps"`
	DepCount int      `json:"depCount"`
	// Settings holds every build setting ("-buildmode", "CGO_ENABLED", "GOOS",
	// "vcs.revision", ...). Values are cut at 2048 characters. Flag values such as
	// -ldflags can contain secrets passed with -X; callers must redact them.
	Settings map[string]string `json:"settings"`
	// VCS is the version-control stamp, or nil when the binary carries none.
	VCS *VCS `json:"vcs"`
	// GOOS, GOARCH, CGO, Compiler, BuildMode and TrimPath are the usual settings,
	// extracted for convenience.
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	CGO       bool   `json:"cgo"`
	Compiler  string `json:"compiler"`
	BuildMode string `json:"buildMode"`
	TrimPath  bool   `json:"trimpath"`
	// Flags holds the ldflags, gcflags, asmflags and tags settings that are
	// present, keyed without the leading dash.
	Flags map[string]string `json:"flags"`
}

// Module is a Go module as recorded in the build information.
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
	// Replace is "path version" of the replacement module, or "".
	Replace string `json:"replace"`
}

// VCS is the version-control information the go command stamps into a binary
// built inside a repository.
type VCS struct {
	System   string `json:"system"`
	Revision string `json:"revision"`
	Time     string `json:"time"`
	Modified bool   `json:"modified"`
}

// Read extracts the Go build information from r. The boolean is false when the
// file has none: it is not a Go executable, or the information is malformed.
// Read never panics, whatever r contains.
func Read(r io.ReaderAt) (info *Info, ok bool) {
	defer func() {
		if recover() != nil {
			info, ok = nil, false
		}
	}()
	bi, err := buildinfo.Read(r)
	if err != nil || bi == nil {
		return nil, false
	}
	return fromBuildInfo(bi), true
}

func fromBuildInfo(bi *debug.BuildInfo) *Info {
	info := &Info{
		GoVersion: binio.Printable(bi.GoVersion, maxVersion),
		Path:      binio.Printable(bi.Path, maxVersion),
		Main:      module(&bi.Main),
		Deps:      []Module{},
		DepCount:  len(bi.Deps),
		Settings:  map[string]string{},
		Flags:     map[string]string{},
	}
	for i, d := range bi.Deps {
		if i == maxDeps {
			break
		}
		if d != nil {
			info.Deps = append(info.Deps, module(d))
		}
	}
	for i, s := range bi.Settings {
		if i == maxSettings {
			break
		}
		info.Settings[binio.Printable(s.Key, maxVersion)] = binio.Printable(s.Value, maxValue)
	}
	st := info.Settings
	info.GOOS, info.GOARCH = st["GOOS"], st["GOARCH"]
	info.CGO = st["CGO_ENABLED"] == "1"
	info.Compiler, info.BuildMode = st["-compiler"], st["-buildmode"]
	info.TrimPath = st["-trimpath"] == "true"
	for _, k := range []string{"-ldflags", "-gcflags", "-asmflags", "-tags"} {
		if v, ok := st[k]; ok {
			info.Flags[strings.TrimPrefix(k, "-")] = v
		}
	}
	if _, hasSystem := st["vcs"]; hasSystem || st["vcs.revision"] != "" {
		info.VCS = &VCS{System: st["vcs"], Revision: st["vcs.revision"], Time: st["vcs.time"], Modified: st["vcs.modified"] == "true"}
	}
	return info
}

func module(m *debug.Module) Module {
	out := Module{
		Path:    binio.Printable(m.Path, maxVersion),
		Version: binio.Printable(m.Version, maxVersion),
		Sum:     binio.Printable(m.Sum, maxVersion),
	}
	if m.Replace != nil {
		out.Replace = strings.TrimSpace(binio.Printable(m.Replace.Path, maxVersion) + " " + binio.Printable(m.Replace.Version, maxVersion))
	}
	return out
}
