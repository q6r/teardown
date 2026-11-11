package goinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/testfixtures"
)

func read(t *testing.T, data []byte) *Info {
	t.Helper()
	info, ok := Read(bytes.NewReader(data))
	if !ok || info == nil {
		t.Fatal("Read found no Go build information")
	}
	return info
}

func TestRead_DefaultFixture(t *testing.T) {
	info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{}))
	if info.GoVersion != "go1.26.5" || info.Path != "example.com/hello" || info.Main.Path != "example.com/hello" || info.Main.Version != "(devel)" {
		t.Errorf("info = %+v", info)
	}
	if info.GOOS != "linux" || info.GOARCH != "amd64" || info.CGO || info.Compiler != "gc" || info.BuildMode != "exe" || info.TrimPath {
		t.Errorf("conveniences = %+v", info)
	}
	if info.VCS != nil {
		t.Errorf("vcs = %+v, want nil without stamping", info.VCS)
	}
	if info.Deps == nil || info.Flags == nil || info.Settings == nil || len(info.Deps) != 0 || info.DepCount != 0 {
		t.Errorf("collections must be non-nil and empty: %+v", info)
	}
	if len(info.Settings) != 5 {
		t.Errorf("settings = %v", info.Settings)
	}
}

func TestRead_FullFixture(t *testing.T) {
	info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{
		GoVersion: "go1.24.1",
		Path:      "github.com/q6r/tool/cmd/tool",
		Main:      testfixtures.GoBuildInfoModule{Path: "github.com/q6r/tool", Version: "v1.4.0", Sum: "h1:main"},
		Deps: []testfixtures.GoBuildInfoModule{
			{Path: "golang.org/x/text", Version: "v0.14.0", Sum: "h1:text"},
			{Path: "example.com/fork", Version: "v1.0.0", Replace: &testfixtures.GoBuildInfoModule{Path: "../fork", Version: "(devel)"}},
			{Path: "example.com/localdir", Version: "v2.0.0", Replace: &testfixtures.GoBuildInfoModule{Path: "/src/localdir"}},
		},
		Settings: []testfixtures.GoBuildInfoSetting{
			{Key: "-buildmode", Value: "pie"}, {Key: "-compiler", Value: "gc"}, {Key: "-trimpath", Value: "true"},
			{Key: "-ldflags", Value: "-s -w -X main.version=1.4.0"}, {Key: "-gcflags", Value: "all=-N -l"}, {Key: "-tags", Value: "netgo,osusergo"},
			{Key: "CGO_ENABLED", Value: "1"}, {Key: "GOOS", Value: "darwin"}, {Key: "GOARCH", Value: "arm64"},
			{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}, {Key: "vcs.modified", Value: "true"},
		},
	}))
	if info.GoVersion != "go1.24.1" || info.Main != (Module{Path: "github.com/q6r/tool", Version: "v1.4.0", Sum: "h1:main"}) {
		t.Errorf("version/main = %q %+v", info.GoVersion, info.Main)
	}
	wantDeps := []Module{
		{Path: "golang.org/x/text", Version: "v0.14.0", Sum: "h1:text"},
		{Path: "example.com/fork", Version: "v1.0.0", Replace: "../fork (devel)"},
		{Path: "example.com/localdir", Version: "v2.0.0", Replace: "/src/localdir"},
	}
	if len(info.Deps) != 3 || info.DepCount != 3 {
		t.Fatalf("deps = %+v", info.Deps)
	}
	for i, want := range wantDeps {
		if info.Deps[i] != want {
			t.Errorf("dep %d = %+v, want %+v", i, info.Deps[i], want)
		}
	}
	if info.GOOS != "darwin" || info.GOARCH != "arm64" || !info.CGO || info.BuildMode != "pie" || !info.TrimPath {
		t.Errorf("conveniences = %+v", info)
	}
	wantFlags := map[string]string{"ldflags": "-s -w -X main.version=1.4.0", "gcflags": "all=-N -l", "tags": "netgo,osusergo"}
	if len(info.Flags) != 3 {
		t.Errorf("flags = %v", info.Flags)
	}
	for k, v := range wantFlags {
		if info.Flags[k] != v {
			t.Errorf("flag %s = %q, want %q", k, info.Flags[k], v)
		}
	}
	if info.VCS == nil || *info.VCS != (VCS{System: "git", Revision: "0123456789abcdef0123456789abcdef01234567", Time: "2026-01-02T03:04:05Z", Modified: true}) {
		t.Errorf("vcs = %+v", info.VCS)
	}
	if info.Settings["-ldflags"] != "-s -w -X main.version=1.4.0" {
		t.Errorf("settings must keep every build line: %v", info.Settings)
	}
}

func TestRead_VCSVariants(t *testing.T) {
	tests := []struct {
		name     string
		settings []testfixtures.GoBuildInfoSetting
		want     *VCS
	}{
		{"none", []testfixtures.GoBuildInfoSetting{{Key: "GOOS", Value: "linux"}}, nil},
		{"clean checkout", []testfixtures.GoBuildInfoSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "false"}}, &VCS{System: "git", Revision: "abc"}},
		{"revision only", []testfixtures.GoBuildInfoSetting{{Key: "vcs.revision", Value: "abc"}}, &VCS{Revision: "abc"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{Settings: tc.settings}))
			switch {
			case tc.want == nil && info.VCS != nil, tc.want != nil && (info.VCS == nil || *info.VCS != *tc.want):
				t.Errorf("vcs = %+v, want %+v", info.VCS, tc.want)
			}
		})
	}
}

func TestRead_WithoutModuleInformation(t *testing.T) {
	info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{OmitModInfo: true}))
	if info.GoVersion == "" || info.Path != "" || len(info.Settings) != 0 || info.GOOS != "" {
		t.Errorf("info = %+v", info)
	}
}

func TestRead_LimitsAndSanitisation(t *testing.T) {
	var deps []testfixtures.GoBuildInfoModule
	for i := range maxDeps + 500 {
		deps = append(deps, testfixtures.GoBuildInfoModule{Path: fmt.Sprintf("example.com/m%d", i), Version: "v1.0.0"})
	}
	var settings []testfixtures.GoBuildInfoSetting
	for i := range maxSettings + 50 {
		settings = append(settings, testfixtures.GoBuildInfoSetting{Key: fmt.Sprintf("k%03d", i), Value: "v"})
	}
	settings = append(settings, testfixtures.GoBuildInfoSetting{Key: "-ldflags", Value: strings.Repeat("x", 5000)})
	info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{Deps: deps, Settings: settings}))
	if len(info.Deps) != maxDeps || info.DepCount != maxDeps+500 {
		t.Errorf("deps %d (count %d), want %d capped from %d", len(info.Deps), info.DepCount, maxDeps, maxDeps+500)
	}
	if len(info.Settings) != maxSettings {
		t.Errorf("settings = %d, want the cap of %d", len(info.Settings), maxSettings)
	}

	long := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{
		Settings: []testfixtures.GoBuildInfoSetting{{Key: "-ldflags", Value: strings.Repeat("y", 5000)}},
	}))
	if v := long.Flags["ldflags"]; len([]rune(v)) != maxValue+1 || !strings.HasSuffix(v, "…") {
		t.Errorf("ldflags length %d, want %d characters plus an ellipsis", len([]rune(v)), maxValue)
	}

	dirty := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{
		Path: "ex\x1b[31mample.com/x", Main: testfixtures.GoBuildInfoModule{Path: "m\x07", Version: "v1"},
	}))
	raw, err := json.Marshal(dirty)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `\u001b`) || strings.Contains(string(raw), `\u0007`) {
		t.Errorf("control characters leaked into the output: %s", raw)
	}
	if dirty.Path != `ex\x1b[31mample.com/x` {
		t.Errorf("path = %q", dirty.Path)
	}
}

func TestRead_RejectsEverythingThatIsNotAGoBinary(t *testing.T) {
	good := testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{})
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", []byte("\x7fELF")},
		{"text", []byte("hello, world\n")},
		{"plain ELF without build info", testfixtures.ELF(testfixtures.ELFOptions{})},
		{"static ELF without build info", testfixtures.ELF(testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true})},
		{"truncated Go ELF", good[:len(good)/2]},
		{"zeros", make([]byte, 4096)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if info, ok := Read(bytes.NewReader(tc.data)); ok || info != nil {
				t.Fatalf("Read = %+v, %v; want not found", info, ok)
			}
		})
	}
}

func TestRead_CorruptedBlobsNeverPanic(t *testing.T) {
	good := testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{Deps: []testfixtures.GoBuildInfoModule{{Path: "a/b", Version: "v1"}}})
	start := time.Now()
	for n := 0; n <= len(good); n++ {
		Read(bytes.NewReader(good[:n]))
	}
	buf := make([]byte, len(good))
	for i := range good {
		for _, v := range []byte{0x00, 0xff, 0x80, 0x0a} {
			copy(buf, good)
			buf[i] = v
			Read(bytes.NewReader(buf))
		}
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("sweeps took %v", d)
	}
}

func TestInfoJSONContract(t *testing.T) {
	info := read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{
		Deps:     []testfixtures.GoBuildInfoModule{{Path: "a/b", Version: "v1", Sum: "h1:x"}},
		Settings: []testfixtures.GoBuildInfoSetting{{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: "abc"}},
	}))
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"goVersion", "path", "main", "deps", "depCount", "settings", "vcs", "goos", "goarch", "cgo", "compiler", "buildMode", "trimpath", "flags"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	for _, k := range []string{"path", "version", "sum", "replace"} {
		if _, ok := m["main"].(map[string]any)[k]; !ok {
			t.Errorf("main is missing %q", k)
		}
		if _, ok := m["deps"].([]any)[0].(map[string]any)[k]; !ok {
			t.Errorf("deps[0] is missing %q", k)
		}
	}
	for _, k := range []string{"system", "revision", "time", "modified"} {
		if _, ok := m["vcs"].(map[string]any)[k]; !ok {
			t.Errorf("vcs is missing %q", k)
		}
	}
	// Without stamping the key stays but is null.
	plain, _ := json.Marshal(read(t, testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{})))
	var pm map[string]any
	_ = json.Unmarshal(plain, &pm)
	if v, present := pm["vcs"]; !present || v != nil {
		t.Errorf("vcs without stamping = %v (present %v), want null", v, present)
	}
}

// TestRead_RealBinaries checks genuine linker output for every platform whose
// binary format debug/buildinfo supports here.
func TestRead_RealBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles Go programs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	targets := [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}, {"windows", "amd64"}}
	for _, tg := range targets {
		goos, goarch := tg[0], tg[1]
		t.Run(goos+"-"+goarch, func(t *testing.T) {
			path, err := testfixtures.GoBuildInfoCompile(ctx, t.TempDir(), goos, goarch)
			if errors.Is(err, testfixtures.ErrNoGoCommand) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			data := readFile(t, path)
			info := read(t, data)
			if !strings.HasPrefix(info.GoVersion, "go1.") {
				t.Errorf("goVersion = %q", info.GoVersion)
			}
			if info.GOOS != goos || info.GOARCH != goarch || info.CGO || info.Compiler != "gc" || info.BuildMode != "exe" {
				t.Errorf("settings = %+v", info)
			}
			if info.Path != "example.com/hello" || info.Main.Path != "example.com/hello" {
				t.Errorf("path/main = %q %+v", info.Path, info.Main)
			}
			if len(info.Settings) < 4 {
				t.Errorf("settings = %v", info.Settings)
			}
		})
	}
}
