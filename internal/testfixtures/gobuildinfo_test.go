package testfixtures

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"testing"
	"time"
)

func TestGoBuildInfo_DefaultsAreReadByDebugBuildinfo(t *testing.T) {
	data := GoBuildInfo(GoBuildInfoOptions{})
	if _, err := elf.NewFile(bytes.NewReader(data)); err != nil {
		t.Fatalf("debug/elf rejected the carrier: %v", err)
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("buildinfo.Read: %v", err)
	}
	if bi.GoVersion != "go1.26.5" || bi.Path != "example.com/hello" || bi.Main.Path != "example.com/hello" || bi.Main.Version != "(devel)" {
		t.Errorf("build info = %+v", bi)
	}
	got := map[string]string{}
	for _, s := range bi.Settings {
		got[s.Key] = s.Value
	}
	for k, v := range map[string]string{"-buildmode": "exe", "-compiler": "gc", "CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": "linux"} {
		if got[k] != v {
			t.Errorf("setting %s = %q, want %q", k, got[k], v)
		}
	}
	if len(bi.Deps) != 0 {
		t.Errorf("deps = %v", bi.Deps)
	}
}

func TestGoBuildInfo_ModulesSettingsAndReplacements(t *testing.T) {
	data := GoBuildInfo(GoBuildInfoOptions{
		GoVersion: "go1.22.3",
		Path:      "github.com/q6r/tool/cmd/tool",
		Main:      GoBuildInfoModule{Path: "github.com/q6r/tool", Version: "v1.4.0", Sum: "h1:main"},
		Deps: []GoBuildInfoModule{
			{Path: "golang.org/x/text", Version: "v0.14.0", Sum: "h1:text"},
			{Path: "example.com/fork", Version: "v1.0.0", Replace: &GoBuildInfoModule{Path: "../fork", Version: "(devel)", Sum: ""}},
		},
		Settings: []GoBuildInfoSetting{
			{"-ldflags", "-s -w -X main.version=1.4.0"}, {"CGO_ENABLED", "1"}, {"GOOS", "darwin"}, {"GOARCH", "arm64"},
			{"vcs", "git"}, {"vcs.revision", "0123456789abcdef0123456789abcdef01234567"}, {"vcs.time", "2026-01-02T03:04:05Z"}, {"vcs.modified", "true"},
		},
	})
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if bi.GoVersion != "go1.22.3" || bi.Main.Version != "v1.4.0" || bi.Main.Sum != "h1:main" {
		t.Errorf("build info = %+v", bi)
	}
	if len(bi.Deps) != 2 || bi.Deps[0].Path != "golang.org/x/text" || bi.Deps[0].Version != "v0.14.0" {
		t.Fatalf("deps = %+v", bi.Deps)
	}
	if r := bi.Deps[1].Replace; r == nil || r.Path != "../fork" || r.Version != "(devel)" {
		t.Errorf("replacement = %+v", bi.Deps[1].Replace)
	}
	got := map[string]string{}
	for _, s := range bi.Settings {
		got[s.Key] = s.Value
	}
	if got["-ldflags"] != "-s -w -X main.version=1.4.0" || got["vcs.modified"] != "true" || got["vcs.revision"] != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("settings = %v", got)
	}
}

func TestGoBuildInfo_WithoutModuleInformation(t *testing.T) {
	bi, err := buildinfo.Read(bytes.NewReader(GoBuildInfo(GoBuildInfoOptions{OmitModInfo: true})))
	if err != nil {
		t.Fatal(err)
	}
	if bi.GoVersion == "" || bi.Path != "" || len(bi.Settings) != 0 {
		t.Errorf("build info = %+v", bi)
	}
}

func TestGoBuildInfo_BlobIsFramedLikeCmdGo(t *testing.T) {
	blob := GoBuildInfoBlob(GoBuildInfoOptions{})
	if !bytes.HasPrefix(blob, []byte("\xff Go buildinf:")) || blob[14] != 8 || blob[15]&0x2 == 0 {
		t.Fatalf("header = % x", blob[:32])
	}
	if !bytes.Contains(blob, []byte(gobuildinfoInfoStart)) || !bytes.HasSuffix(bytes.TrimRight(blob, "\x00"), []byte(gobuildinfoInfoEnd)) {
		t.Error("module information must be wrapped in the cmd/go sentinels")
	}
	if !bytes.Equal(blob, GoBuildInfoBlob(GoBuildInfoOptions{})) {
		t.Error("blob must be deterministic")
	}
}

func TestGoBuildInfo_CompileProducesARealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a Go program")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	path, err := GoBuildInfoCompile(ctx, t.TempDir(), "linux", "amd64")
	if errors.Is(err, ErrNoGoCommand) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bi.Path != "example.com/hello" || bi.Main.Path != "example.com/hello" {
		t.Errorf("build info = %+v", bi)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC {
		t.Errorf("machine %v type %v", f.Machine, f.Type)
	}
}
