package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/testfixtures"
)

// codeELF is an ELF image whose .text holds codeFunc.
func codeELF() []byte { return testfixtures.ELF(testfixtures.ELFOptions{TextData: codeFunc}) }

// FuzzCodeToolArguments feeds arbitrary argument documents to read_bytes and
// disassemble. Neither may panic, whatever fails must fail as a message for the
// caller, and whatever succeeds must be valid JSON that fits the output cap and
// never contains the file outside the root.
func FuzzCodeToolArguments(f *testing.F) {
	root, secret := fuzzRoot(f)
	fx := buildCodePE(0)
	for name, data := range map[string][]byte{
		"code.exe": fx.file, "blob.bin": patternBytes(5000), "empty.bin": nil,
		"code.elf": codeELF(), "dropper.bin": testfixtures.SamplePE(),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o644); err != nil {
			f.Fatal(err)
		}
	}
	for _, seed := range []string{
		`{"path":"blob.bin"}`,
		`{"path":"blob.bin","offset":4999,"length":4096}`,
		`{"path":"blob.bin","offset":-1}`,
		`{"path":"code.exe","address":"0x140004000","count":9}`,
		`{"path":"code.exe","address":"0x140004000","offset":5}`,
		`{"path":"code.exe","offset":2560,"count":256,"arch":"x86"}`,
		`{"path":"code.exe","count":1,"arch":"x86-64"}`,
		`{"path":"code.elf"}`,
		`{"path":"empty.bin","arch":"x86"}`,
		`{"path":"../outside.bin","offset":0}`,
		`{"path":"a.bin","address":"18446744073709551615","arch":"x86-64"}`,
		`{"path":"a.bin","offset":9223372036854775807,"count":1}`,
		`{"path":"a.bin","offset":1e30}`, `{"path":["a.bin"]}`, `{"path":"a.bin","count":"9"}`,
		`{"path":"a.bin","address":null,"offset":null,"arch":null}`,
		`{"path":"dropper.bin","api":"VirtualAllocEx"}`, `{"path":"dropper.bin","api":"createprocess","before":0,"after":0,"max":1}`,
		`{"path":"dropper.bin","api":"KERNEL32.dll!WriteProcessMemory","before":40,"after":20,"max":100}`,
		`{"path":"code.exe","api":"ExitProcess"}`, `{"path":"code.exe","api":"kernel32.dll!ExitProcess","before":40,"after":20,"max":100}`,
		`{"path":"code.exe","api":"x","before":-1}`, `{"path":"code.exe","api":"x","max":0}`, `{"path":"code.exe","api":"   "}`,
		`{"path":"code.exe","api":["x"]}`, `{"path":"code.exe","api":null,"before":null,"after":null,"max":null}`,
		`{"path":"code.elf","api":"x"}`, `{"path":"empty.bin","api":"x"}`, `{"path":"../outside.bin","api":"x"}`,
		`null`, `{}`, `[]`, `"text"`, `{"path":`, ``, strings.Repeat("{", 300),
	} {
		f.Add([]byte(seed))
	}
	s, err := newServer(io.Discard, Config{Roots: []string{root}, Stderr: io.Discard, Timeout: 5 * time.Second, MaxOutput: 8 << 10}, realAnalyzer())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(s.roots.Close)
	tools := map[string]func(context.Context, json.RawMessage) (*toolOutput, error){
		"read_bytes": s.readBytes, "disassemble": s.disassemble, "find_calls": s.findCalls,
	}
	f.Fuzz(func(t *testing.T, args []byte) {
		for name, run := range tools {
			out, err := run(context.Background(), args)
			if err != nil {
				var ue *userError
				if !errors.As(err, &ue) {
					t.Fatalf("%s(%q): a failure must be a message for the caller, got %v", name, args, err)
				}
				continue
			}
			text, compact, _, err := fit(out.tree, out.spec, s.cfg.MaxOutput)
			if err != nil {
				if !errors.Is(err, errTooLarge) {
					t.Fatalf("%s(%q): %v", name, args, err)
				}
				continue
			}
			if len(text) > s.cfg.MaxOutput || !json.Valid([]byte(text)) || !json.Valid(compact) {
				t.Fatalf("%s(%q): the result is invalid or over the cap (%d bytes)", name, args, len(text))
			}
			// A window shows bytes as hex and as ASCII rows of 16, so look for both forms of its start.
			if bytes.Contains([]byte(text), secret) || strings.Contains(text, "FUZZ-OUT") || strings.Contains(text, hexOf(secret[:8])) {
				t.Fatalf("%s(%q): the outside file leaked", name, args)
			}
		}
	})
}
