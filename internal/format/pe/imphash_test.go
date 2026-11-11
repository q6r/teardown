package pe

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"slices"
	"testing"
)

func TestImpHasherText(t *testing.T) {
	type imp struct {
		lib, fn string
		ord     uint16
	}
	tests := []struct {
		name string
		in   []imp
		want string
	}{
		{"one import", []imp{{lib: "KERNEL32.dll", fn: "ExitProcess"}}, "kernel32.exitprocess"},
		{
			"order is kept and everything is lower-cased",
			[]imp{{lib: "KERNEL32.dll", fn: "ExitProcess"}, {lib: "USER32.DLL", fn: "MessageBoxA"}},
			"kernel32.exitprocess,user32.messageboxa",
		},
		{
			"only .dll .ocx and .sys lose their extension",
			[]imp{
				{lib: "A.DLL", fn: "X"}, {lib: "b.ocx", fn: "X"}, {lib: "C.SYS", fn: "X"},
				{lib: "d.exe", fn: "X"}, {lib: "e.drv", fn: "X"}, {lib: "plain", fn: "X"},
			},
			"a.x,b.x,c.x,d.exe.x,e.drv.x,plain.x",
		},
		{"only the last extension is considered", []imp{{lib: "foo.bar.dll", fn: "X"}}, "foo.bar.x"},
		{
			"ordinals of known libraries are named",
			[]imp{
				{lib: "WS2_32.dll", ord: 23}, {lib: "wsock32.dll", ord: 10}, {lib: "OLEAUT32.dll", ord: 6},
				{lib: "ws2_32.dll", ord: 115},
			},
			"ws2_32.socket,wsock32.inet_addr,oleaut32.sysfreestring,ws2_32.wsastartup",
		},
		{
			"unknown ordinals become ord<N>",
			[]imp{{lib: "ws2_32.dll", ord: 999}, {lib: "MSVBVM60.dll", ord: 100}, {lib: "oleaut32.dll", ord: 500}},
			"ws2_32.ord999,msvbvm60.ord100,oleaut32.ord500",
		},
		{
			"the ordinal tables are keyed by the full lower-cased DLL name",
			[]imp{{lib: "WS2_32", ord: 23}},
			"ws2_32.ord23",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := newImpHasher(&buf)
			for _, i := range tc.in {
				if i.fn != "" {
					h.add(i.lib, i.fn)
				} else {
					h.addOrdinal(i.lib, i.ord)
				}
			}
			if buf.String() != tc.want {
				t.Fatalf("text = %q, want %q", buf.String(), tc.want)
			}
		})
	}
}

func TestImpHasherDigests(t *testing.T) {
	var buf bytes.Buffer
	h := newImpHasher(&buf)
	h.add("ws2_32.dll", "socket")
	h.add("WS2_32.dll", "WSAStartup")
	h.addOrdinal("ws2_32.dll", 999)
	h.addOrdinal("msvbvm60.dll", 100)
	h.add("OLEAUT32.dll", "SysFreeString")
	h.addOrdinal("oleaut32.dll", 500)
	sum := md5.Sum(buf.Bytes()) // the import hash is an MD5 by definition
	// Digest computed independently with md5sum over the same text.
	const want = "0bc444eb761f1aeff7bef90c61b643b1"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("md5(%q) = %s, want %s", buf.String(), got, want)
	}
}

func TestOrdinalTablesAreSane(t *testing.T) {
	tables := map[string]map[uint16]string{"ws2_32": ws232Ordinals, "wsock32": wsock32Ordinals, "oleaut32": oleaut32Ordinals}
	for name, table := range tables {
		seen := map[string]uint16{}
		for ord, fn := range table {
			if ord == 0 || fn == "" {
				t.Errorf("%s: bad entry %d=%q", name, ord, fn)
			}
			if prev, dup := seen[fn]; dup {
				t.Errorf("%s: %q appears at ordinals %d and %d", name, fn, prev, ord)
			}
			seen[fn] = ord
		}
	}
	// The two Winsock tables share their numbering except for the three entries
	// whose order differs between the DLLs.
	var differing []uint16
	for ord, fn := range ws232Ordinals {
		if wsock32Ordinals[ord] != fn {
			differing = append(differing, ord)
		}
	}
	slices.Sort(differing)
	if !slices.Equal(differing, []uint16{10, 11, 12}) {
		t.Errorf("ws2_32 and wsock32 differ at %v, want [10 11 12]", differing)
	}
}
