package goinfo

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/q6r/teardown/internal/testfixtures"
)

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// FuzzRead feeds arbitrary bytes to Read; it must never panic (Read recovers
// internally, so the fuzzer additionally checks the result for consistency).
func FuzzRead(f *testing.F) {
	good := testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{
		Deps:     []testfixtures.GoBuildInfoModule{{Path: "a/b", Version: "v1", Sum: "h1:x", Replace: &testfixtures.GoBuildInfoModule{Path: "../b"}}},
		Settings: []testfixtures.GoBuildInfoSetting{{Key: "-ldflags", Value: "-s -w"}, {Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: "abc"}, {Key: "GOOS", Value: "linux"}},
	})
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add(testfixtures.GoBuildInfo(testfixtures.GoBuildInfoOptions{OmitModInfo: true}))
	f.Add(testfixtures.ELF(testfixtures.ELFOptions{}))
	f.Add([]byte("\xff Go buildinf:\x08\x02"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		info, ok := Read(bytes.NewReader(data))
		if ok != (info != nil) {
			t.Fatalf("ok=%v but info=%v", ok, info)
		}
		if ok {
			if info.Deps == nil || info.Settings == nil || info.Flags == nil {
				t.Fatalf("nil collection in %+v", info)
			}
			if _, err := json.Marshal(info); err != nil {
				t.Fatalf("does not encode: %v", err)
			}
		}
	})
}
