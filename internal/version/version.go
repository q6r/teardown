// Package version exposes the build version of the teardown binary.
package version

import (
	"runtime"
	"runtime/debug"
)

// These are set at link time by GoReleaser and the Makefile:
//
//	-X github.com/q6r/teardown/internal/version.version=v0.1.0
//	-X github.com/q6r/teardown/internal/version.commit=abc1234
//	-X github.com/q6r/teardown/internal/version.date=2026-11-10T12:00:00Z
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Info describes the running build.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Get returns the build information. When the binary was built without link-time
// values (for example via "go install"), the module version recorded by the Go
// toolchain is used instead.
func Get() Info {
	info := Info{Version: version, Commit: commit, Date: date, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		if info.Commit == "" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					info.Commit = s.Value
				}
			}
		}
	}
	return info
}

// String returns just the version, e.g. "v0.1.0" or "dev".
func String() string { return Get().Version }
