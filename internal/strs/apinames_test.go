package strs

import (
	"slices"
	"testing"
)

func TestAPITableIsSortedUniqueAndMatchable(t *testing.T) {
	owner := map[string]string{}
	for _, g := range apiGroups {
		if len(g.names) == 0 {
			t.Errorf("group %q is empty", g.group)
		}
		if !slices.IsSorted(g.names) {
			for i := 1; i < len(g.names); i++ {
				if g.names[i-1] >= g.names[i] {
					t.Errorf("group %q is not sorted at %q, %q", g.group, g.names[i-1], g.names[i])
					break
				}
			}
		}
		for _, name := range g.names {
			if prev, dup := owner[name]; dup {
				t.Errorf("%q is listed in both %q and %q", name, prev, g.group)
			}
			owner[name] = g.group
			if len(name) < minAPILen || len(name) > maxAPILen {
				t.Errorf("%q has a length outside [%d, %d] and could never match", name, minAPILen, maxAPILen)
			}
			if features(name)&fNotAPI != 0 {
				t.Errorf("%q contains characters the api matcher never accepts", name)
			}
		}
	}
	if len(owner) < 500 {
		t.Errorf("table has only %d names; it has shrunk unexpectedly", len(owner))
	}
}

func TestEveryListedNameResolvesToItsGroup(t *testing.T) {
	for _, g := range apiGroups {
		for _, name := range g.names {
			if got, ok := apiGroup(name); !ok || got != g.group {
				t.Errorf("apiGroup(%q) = %q, %v; want %q", name, got, ok, g.group)
			}
		}
	}
}

func TestAPIGroupLookupRules(t *testing.T) {
	tests := []struct {
		in    string
		group string
		ok    bool
	}{
		{"CreateProcessW", groupProcess, true},
		{"CreateProcessAsUserA", groupProcess, true},
		{"StartServiceCtrlDispatcherW", groupService, true},
		{"_execve", groupExec, true},
		{"BCryptGenRandom", groupCrypto, true},
		{"CryptAcquireContextW", groupCrypto, true},
		{"NCryptOpenStorageProvider", groupCrypto, true},
		{"SSL_CTX_new", groupCrypto, true},
		{"mbedtls_aes_setkey_enc", groupCrypto, true},
		{"TLS_AES_128_GCM_SHA256", groupCrypto, true},
		{"WinHttpOpen", groupNetwork, true},
		{"InternetOpenUrlA", groupNetwork, true},
		{"createprocess", "", false}, // case matters
		{"CreateProces", "", false},  // truncated
		{"Cryptography", "", false},  // prefix needs an upper-case letter next
		{"WSAstartup", "", false},    // prefix needs an upper-case letter next
		{"ab", "", false},            // too short
		{"A_name_that_is_far_too_long_to_be_any_api_function_in_any_library_ever", "", false},
		{"EVP_", "", false}, // prefix alone
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := apiGroup(tc.in)
			if got != tc.group || ok != tc.ok {
				t.Fatalf("apiGroup(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.group, tc.ok)
			}
		})
	}
}
