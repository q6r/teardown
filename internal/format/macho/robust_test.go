package macho

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

// corpus returns the fixtures every robustness test sweeps: thin and universal
// images, both classes and byte orders, dylibs, objects and signed binaries.
func corpus() map[string][]byte {
	rich := testfixtures.MachOOptions{
		CPU: testfixtures.MachOCPUARM64, SubCPU: 2,
		Dylibs: []string{"/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"}, WeakDylibs: []string{"/usr/lib/libweak.dylib"},
		ReexportDylibs: []string{"/usr/lib/libre.dylib"}, RPaths: []string{"@executable_path/../Frameworks"},
		UUID: bytes.Repeat([]byte{9}, 16), CodeSignature: true, EncryptionInfo: true, CryptID: 1,
		BuildPlatform: 1, MinOS: 0x000e0000, SDK: 0x000e0200, Main: true,
		Defined:   []string{"_main", "_helper"},
		Undefined: []testfixtures.MachOSymbol{{Name: "_puts", Ordinal: 1}, {Name: "___stack_chk_fail", Ordinal: 1}, {Name: "_weak", Ordinal: 3}},
		Segments: []testfixtures.MachOSegment{
			{Name: "__TEXT", InitProt: 5, Sections: []testfixtures.MachOSection{{Name: "__text", Data: bytes.Repeat([]byte{0x1f, 0x20}, 64)}, {Name: "__cstring", Data: []byte("hello\x00")}}},
			{Name: "__EVIL", InitProt: 7, Sections: []testfixtures.MachOSection{{Name: "__rwx", Data: []byte{0xcc}}}},
			{Name: "__DATA", InitProt: 3, Sections: []testfixtures.MachOSection{{Name: "__bss", Data: make([]byte, 64), Zerofill: true}}},
		},
	}
	rich32 := rich
	rich32.Bits, rich32.BigEndian, rich32.CPU = 32, true, 0
	amd64 := testfixtures.MachO(testfixtures.MachOOptions{Defined: []string{"_main"}, Undefined: []testfixtures.MachOSymbol{{Name: "_x", Ordinal: 1}}, Dylibs: []string{"/usr/lib/libSystem.B.dylib"}})
	arm64 := testfixtures.MachO(rich)
	return map[string][]byte{
		"zero":    testfixtures.MachO(testfixtures.MachOOptions{}),
		"rich64":  arm64,
		"rich32":  testfixtures.MachO(rich32),
		"dylib":   testfixtures.MachO(testfixtures.MachOOptions{Type: testfixtures.MachOTypeDylib, InstallName: "@rpath/libx.dylib", Defined: []string{"_api"}}),
		"object":  testfixtures.MachO(testfixtures.MachOOptions{Type: testfixtures.MachOTypeObject, Undefined: []testfixtures.MachOSymbol{{Name: "_ext"}}}),
		"nosym":   testfixtures.MachO(testfixtures.MachOOptions{NoSymtab: true, Undefined: []testfixtures.MachOSymbol{{Name: "_x"}}, CodeSignature: true}),
		"fat":     testfixtures.MachOFat(amd64, arm64),
		"fat-one": testfixtures.MachOFat(amd64),
	}
}

func parseChecked(t *testing.T, label string, data []byte) {
	t.Helper()
	start := time.Now()
	res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{})
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%s: parsing %d bytes took %v", label, len(data), d)
	}
	if err != nil {
		if res != nil {
			t.Fatalf("%s: an error must come with a nil result", label)
		}
		return
	}
	if res == nil {
		t.Fatalf("%s: nil result without an error", label)
	}
	if len(res.Hardening) != 5 || res.Sections == nil || res.Imports == nil || res.Exports == nil || res.Notes == nil || len(res.Details.Slices) == 0 {
		t.Fatalf("%s: incomplete result %+v", label, res)
	}
	if res.Details.PrimarySlice < 0 || res.Details.PrimarySlice >= len(res.Details.Slices) {
		t.Fatalf("%s: primary slice %d out of range", label, res.Details.PrimarySlice)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("%s: result does not encode: %v", label, err)
	}
}

func TestParseNeverPanics(t *testing.T) {
	for name, data := range corpus() {
		t.Run(name, func(t *testing.T) {
			for n := 0; n <= len(data); {
				parseChecked(t, "prefix", data[:n])
				if n < 4096 {
					n++
				} else {
					n += 97
				}
			}
			// Corrupt every byte of the leading headers (the fat header, the thin
			// header and the load commands) and of the trailing symbol data.
			regions := [][2]int{{0, min(512, len(data))}}
			if res, err := Parse(context.Background(), bytes.NewReader(data), int64(len(data)), limits.Limits{}); err == nil {
				for _, s := range res.Details.Slices {
					for _, seg := range s.Segments {
						if seg.Name == "__LINKEDIT" {
							start := int(s.Offset) + int(seg.FileOffset)
							regions = append(regions, [2]int{start, min(start+160, len(data))})
						}
					}
					if s.Offset > 0 { // the first 512 bytes already cover a thin image's headers
						regions = append(regions, [2]int{int(s.Offset), min(int(s.Offset)+400, len(data))})
					}
				}
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
	c := corpus()
	names := make([]string, 0, len(c))
	for name := range c {
		names = append(names, name)
	}
	slices.Sort(names)
	rng := rand.New(rand.NewPCG(99, 2025))
	buf := make([]byte, 0, 16384)
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
	// Maximal counts and sizes in every header field of a tiny file.
	good := testfixtures.MachO(testfixtures.MachOOptions{Dylibs: []string{"/usr/lib/libSystem.B.dylib"}, Undefined: []testfixtures.MachOSymbol{{Name: "_a", Ordinal: 1}}})
	for _, off := range []int{16, 20} { // ncmds, sizeofcmds
		hostile := slices.Clone(good)
		for i := range 4 {
			hostile[off+i] = 0xff
		}
		parseChecked(t, "hostile header counts", hostile)
	}
	fat := testfixtures.MachOFat(good)
	hostile := slices.Clone(fat)
	for i := range 4 { // nfat_arch
		hostile[4+i] = 0xff
	}
	parseChecked(t, "hostile fat count", hostile)
	hostile = slices.Clone(fat)
	for i := range 4 { // offset and size of the only slice
		hostile[8+8+i], hostile[8+12+i] = 0xff, 0xff
	}
	parseChecked(t, "hostile fat slice", hostile)
}
