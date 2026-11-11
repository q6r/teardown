package strs

import (
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

func benchInputs(b *testing.B) map[string][]byte {
	b.Helper()
	rng := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 8<<20)
	for i := range random {
		random[i] = byte(rng.Uint32())
	}
	text := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. https://example.com/a/b 10.1.2.3 C:\\Windows\\x.dll CreateFileW\n", 80_000))
	inputs := map[string][]byte{"random": random, "text": text}
	if exe, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(exe); err == nil {
			inputs["executable"] = data
		}
	}
	return inputs
}

// BenchmarkScanner reports the scanning throughput (MB/s) on random bytes, on
// text-heavy data and on a real executable (the test binary itself).
func BenchmarkScanner(b *testing.B) {
	for name, data := range benchInputs(b) {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				s := NewScanner(Options{})
				feed(s, data, 256<<10)
				s.Result()
			}
		})
	}
}

func BenchmarkClassify(b *testing.B) {
	for _, in := range []string{
		"This program cannot be run in DOS mode.", "kernel32.dll", "CreateFileW", "https://example.com/a/b?c=d",
		`C:\Windows\System32\cmd.exe`, testJWT, "AWAVAUATUSH", "d41d8cd98f00b204e9800998ecf8427e",
	} {
		b.Run(in[:min(len(in), 20)], func(b *testing.B) {
			for b.Loop() {
				Classify(in)
			}
		})
	}
}
