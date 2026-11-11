package sniff

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// TestDetectGoDistributionSamples checks Detect against real files that ship in
// the Go source tree: compiler and linker output for many platforms plus archives
// and images written by independent tools. Files that are not installed are skipped.
func TestDetectGoDistributionSamples(t *testing.T) {
	src := filepath.Join(runtime.GOROOT(), "src")
	samples := []struct {
		path   string
		base64 bool
		id     string
		tags   []string // must all be present
	}{
		{"debug/elf/testdata/gcc-amd64-linux-exec", false, report.TypeELF, []string{"executable", "x86-64", "64-bit", "little-endian"}},
		{"debug/elf/testdata/gcc-386-freebsd-exec", false, report.TypeELF, []string{"executable", "x86", "32-bit"}},
		{"debug/elf/testdata/gcc-riscv64-linux-exec", false, report.TypeELF, []string{"executable", "riscv"}},
		{"debug/elf/testdata/go-relocation-test-gcc492-mips64.obj", false, report.TypeELF, []string{"big-endian", "mips", "64-bit"}},
		{"debug/elf/testdata/go-relocation-test-gcc482-aarch64.obj", false, report.TypeELF, []string{"aarch64", "relocatable"}},
		{"debug/elf/testdata/libtiffxx.so_", false, report.TypeELF, []string{"shared-object"}},
		{"debug/macho/testdata/gcc-amd64-darwin-exec.base64", true, report.TypeMachO, []string{"executable", "x86_64", "64-bit"}},
		{"debug/macho/testdata/gcc-386-darwin-exec.base64", true, report.TypeMachO, []string{"executable", "x86", "32-bit"}},
		{"debug/macho/testdata/clang-amd64-darwin.obj.base64", true, report.TypeMachO, []string{"object"}},
		{"debug/macho/testdata/fat-gcc-386-amd64-darwin-exec.base64", true, report.TypeMachOFat, []string{"universal", "x86", "x86_64"}},
		{"debug/pe/testdata/gcc-386-mingw-exec", false, report.TypePE, []string{"exe", "x86", "32-bit"}},
		{"debug/pe/testdata/gcc-amd64-mingw-exec", false, report.TypePE, []string{"exe", "x86-64", "64-bit"}},
		{"archive/zip/testdata/test.zip", false, report.TypeZip, nil},
		{"archive/zip/testdata/zip64.zip", false, report.TypeZip, nil},
		{"archive/zip/testdata/utf8-winrar.zip", false, report.TypeZip, nil},
		{"archive/zip/testdata/gophercolor16x16.png", false, report.TypePNG, nil},
		{"archive/tar/testdata/gnu.tar", false, report.TypeTar, []string{"gnu"}},
		{"archive/tar/testdata/pax.tar", false, report.TypeTar, []string{"posix"}},
		{"image/testdata/video-001.png", false, report.TypePNG, nil},
		{"image/testdata/video-001.jpeg", false, report.TypeJPEG, nil},
		{"image/testdata/video-001.gif", false, report.TypeGIF, nil},
		{"compress/bzip2/testdata/e.txt.bz2", false, report.TypeBzip2, nil},
		{"debug/elf/testdata/hello-world-core.gz", false, report.TypeGzip, nil},
		{"compress/testdata/gettysburg.txt", false, report.TypeText, []string{"ascii"}},
	}
	checked := 0
	for _, s := range samples {
		t.Run(s.path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(s.path)))
			if errors.Is(err, fs.ErrNotExist) {
				t.Skip("sample not installed")
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.base64 {
				if data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err != nil {
					t.Fatal(err)
				}
			}
			got := detectBytes(data)
			if p := invariantProblem(got); p != "" {
				t.Fatal(p)
			}
			if got.ID != s.id {
				t.Fatalf("ID = %q (%s), want %q", got.ID, got.Label, s.id)
			}
			for _, tag := range s.tags {
				if !slices.Contains(got.Tags, tag) {
					t.Errorf("tags %v lack %q", got.Tags, tag)
				}
			}
			checked++
		})
	}
	if checked == 0 {
		t.Skip("no Go distribution samples are installed")
	}
}

// TestDetectTestBinary classifies the executable the tests run from: whatever the
// platform, a Go test binary is a genuine native executable.
func TestDetectTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Skip(err)
	}
	want := map[string]string{"windows": report.TypePE, "linux": report.TypeELF, "darwin": report.TypeMachO}[runtime.GOOS]
	if want == "" {
		t.Skipf("no expectation for %s", runtime.GOOS)
	}
	got := detectBytes(data)
	if got.ID != want || got.Confidence != report.ConfidenceHigh || got.Family != report.FamilyExecutable {
		t.Fatalf("test binary detected as %s (%s, %s), want %s", got.ID, got.Label, got.Confidence, want)
	}
}
