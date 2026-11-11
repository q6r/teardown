package elf

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/testfixtures"
)

// corpus returns the fixtures every robustness test sweeps. It covers both
// classes, both byte orders, static and dynamic images, relocatable objects
// and images without section headers.
func corpus() map[string][]byte {
	imports := []testfixtures.ELFImport{
		{Name: "puts", Library: "libc.so.6", Version: "GLIBC_2.2.5"},
		{Name: "__stack_chk_fail", Library: "libc.so.6", Version: "GLIBC_2.4"},
		{Name: "sqrt", Library: "libm.so.6", Version: "GLIBC_2.29"},
		{Name: "plain"},
	}
	rich := testfixtures.ELFOptions{
		Needed: []string{"libc.so.6", "libm.so.6"}, RPath: []string{"/opt/a", "$ORIGIN"}, RunPath: []string{"/opt/b"},
		Soname: "libx.so", Imports: imports, Exports: []string{"api"}, Symbols: []string{"main"},
		BuildID: bytes.Repeat([]byte{7}, 20), GoBuildID: "gid", RELRO: true, BindNowTag: true, DebugInfo: true,
		Sections: []testfixtures.ELFSection{{Name: ".data", Flags: testfixtures.ELFSectionFlagAlloc | testfixtures.ELFSectionFlagWrite, Data: []byte("data")}},
		Segments: []testfixtures.ELFSegment{{Type: testfixtures.ELFSegmentLoad, Flags: 7, Data: []byte("rwx")}},
	}
	rich32 := rich
	rich32.Bits = 32
	rich32.BigEndian = true
	return map[string][]byte{
		"zero":         testfixtures.ELF(testfixtures.ELFOptions{}),
		"rich64":       testfixtures.ELF(rich),
		"rich32be":     testfixtures.ELF(rich32),
		"static":       testfixtures.ELF(testfixtures.ELFOptions{Type: testfixtures.ELFTypeExec, Static: true, Symbols: []string{"main", "__stack_chk_fail"}}),
		"relocatable":  testfixtures.ELF(testfixtures.ELFOptions{Type: testfixtures.ELFTypeRel, Symbols: []string{"f"}}),
		"no sections":  testfixtures.ELF(testfixtures.ELFOptions{NoSections: true, Needed: []string{"libc.so.6"}, Imports: imports}),
		"shared lib":   testfixtures.ELF(testfixtures.ELFOptions{NoInterp: true, Soname: "libz.so.1", Exports: []string{"a", "b"}}),
		"arm32 static": testfixtures.ELF(testfixtures.ELFOptions{Bits: 32, Machine: testfixtures.ELFMachineARM, Static: true, Type: testfixtures.ELFTypeExec}),
	}
}

// parseChecked runs Parse the way the analyzer does and checks the invariants
// every outcome must satisfy.
func parseChecked(t *testing.T, label string, data []byte) {
	t.Helper()
	start := time.Now()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%s: parsing %d bytes took %v", label, len(data), d)
	}
	if err != nil {
		if res != nil {
			t.Fatalf("%s: an error must come with a nil result when the header is unusable", label)
		}
		return
	}
	if res == nil {
		t.Fatalf("%s: nil result without an error", label)
	}
	if len(res.Hardening) != 5 || res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Notes == nil {
		t.Fatalf("%s: incomplete result %+v", label, res)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("%s: result does not encode: %v", label, err)
	}
}

func TestParseNeverPanics(t *testing.T) {
	for name, data := range corpus() {
		t.Run(name, func(t *testing.T) {
			// Every prefix up to 4 KiB, then every 97th.
			for n := 0; n <= len(data); {
				parseChecked(t, "prefix", data[:n])
				if n < 4096 {
					n++
				} else {
					n += 97
				}
			}
			// Corrupt each byte of the header and program headers, and of the
			// trailing section header table, in turn.
			regions := [][2]int{{0, min(512, len(data))}}
			if shoff := int(le64(data, 40)); shoff > 0 && shoff < len(data) {
				regions = append(regions, [2]int{shoff, len(data)})
			}
			buf := make([]byte, len(data))
			for _, reg := range regions {
				for i := reg[0]; i < reg[1]; i++ {
					for _, v := range []byte{0x00, 0xff, 0x80} {
						copy(buf, data)
						buf[i] = v
						parseChecked(t, "corrupt", buf)
					}
				}
			}
		})
	}
}

func TestParseSurvivesRandomMutations(t *testing.T) {
	names := make([]string, 0)
	c := corpus()
	for name := range c {
		names = append(names, name)
	}
	slices.Sort(names)
	rng := rand.New(rand.NewPCG(42, 1337))
	buf := make([]byte, 0, 4096)
	for i := range 4000 {
		src := c[names[i%len(names)]]
		buf = append(buf[:0], src...)
		for range 1 + rng.IntN(6) {
			buf[rng.IntN(len(buf))] = byte(rng.UintN(256))
		}
		if rng.IntN(4) == 0 {
			buf = buf[:rng.IntN(len(buf)+1)]
		}
		parseChecked(t, "mutation", buf)
	}
}

func TestParseHandlesHostileCounts(t *testing.T) {
	// A header that claims the maximum of everything on a tiny file must be
	// answered quickly and without large allocations.
	hostile := testfixtures.ELF(testfixtures.ELFOptions{})
	for _, off := range []int{56, 60, 62} { // phnum, shnum, shstrndx
		hostile[off], hostile[off+1] = 0xff, 0xff
	}
	hostile[54], hostile[55] = 0xff, 0xff // phentsize
	hostile[58], hostile[59] = 0xff, 0xff // shentsize
	parseChecked(t, "hostile counts", hostile)
}
