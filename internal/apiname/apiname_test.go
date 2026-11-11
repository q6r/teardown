package apiname

import (
	"slices"
	"testing"
)

func TestCanonical(t *testing.T) {
	tests := []struct{ in, want string }{
		{"VirtualAllocEx", "virtualallocex"},
		{"CreateProcessW", "createprocessw"},
		{"ZwQueryInformationProcess", "ntqueryinformationprocess"},
		{"NtQueryInformationProcess", "ntqueryinformationprocess"},
		{"__imp_CreateFileA", "createfilea"},
		{"_socket@12", "socket"},
		{"@fastcall@8", ""},
		{"getaddrinfo@GLIBC_2.2.5", "getaddrinfo"},
		{"#23", "#23"},
		{"", ""},
		{"Zw", "nt"},
		{"zwtest", "nttest"},
		{"CRYPT32", "crypt32"},
	}
	for _, tc := range tests {
		if got := Canonical(tc.in); got != tc.want {
			t.Errorf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStemAndKeys(t *testing.T) {
	tests := []struct {
		in   string
		stem string
		ok   bool
		keys []string
	}{
		{"CreateProcessW", "createprocess", true, []string{"createprocessw", "createprocess"}},
		{"CreateProcessA", "createprocess", true, []string{"createprocessa", "createprocess"}},
		{"VirtualAllocEx", "virtualallocex", false, []string{"virtualallocex"}},
		{"wa", "wa", false, []string{"wa"}},
		{"Opa", "op", true, []string{"opa", "op"}},
		{"", "", false, []string{""}},
	}
	for _, tc := range tests {
		c := Canonical(tc.in)
		if stem, ok := Stem(c); stem != tc.stem || ok != tc.ok {
			t.Errorf("Stem(%q) = %q, %v, want %q, %v", c, stem, ok, tc.stem, tc.ok)
		}
		if got := Keys(tc.in); !slices.Equal(got, tc.keys) {
			t.Errorf("Keys(%q) = %v, want %v", tc.in, got, tc.keys)
		}
	}
}

// FuzzCanonical checks that no input panics and that folding twice changes nothing.
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{"", "ZwOpenFile", "__imp__x@4", "a@b@c", "#12", "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c := Canonical(s)
		if again := Canonical(c); again != c {
			t.Fatalf("Canonical is not stable: %q -> %q -> %q", s, c, again)
		}
		if keys := Keys(s); len(keys) == 0 || keys[0] != c {
			t.Fatalf("Keys(%q) = %v, want the canonical form %q first", s, keys, c)
		}
	})
}
