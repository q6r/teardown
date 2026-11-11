package strs

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
)

func TestFindSecretsLocatesEachKind(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []SecretSpan
	}{
		{"aws key alone", testAWSKey, []SecretSpan{{0, 20, kindAWS}}},
		{"aws key in an assignment", "key=" + testAWSKey + ";", []SecretSpan{{4, 24, kindAWS}}},
		{"github token after text", "token: " + testGitHubPAT, []SecretSpan{{7, 7 + len(testGitHubPAT), kindGitHub}}},
		{"slack token", testSlack, []SecretSpan{{0, len(testSlack), kindSlack}}},
		{"pem header only", testPEM, []SecretSpan{{0, len(testPEM), kindPEM}}},
		{"jwt", testJWT, []SecretSpan{{0, len(testJWT), kindJWT}}},
		{"two secrets", testAWSKey + " " + testGitHubPAT, []SecretSpan{{0, 20, kindAWS}, {21, 21 + len(testGitHubPAT), kindGitHub}}},
		{"same kind twice", testAWSKey + "," + testAWSKey, []SecretSpan{{0, 20, kindAWS}, {21, 41, kindAWS}}},
		{"nothing", "nothing to see here at all", nil},
		{"too short to hold a secret", "AKIAIOSFODNN7", nil},
		{"empty", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FindSecrets(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("FindSecrets(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestFindSecretsMergesOverlaps(t *testing.T) {
	// An AWS-looking run inside a JWT payload: the JWT span swallows it.
	jwt := "eyJhbGciOiJIUzI1NiJ9." + "eyJrIjoi" + testAWSKey + "IiwiYSI6MX0." + "c2lnbmF0dXJlLXNpZ25hdHVyZQ"
	spans := FindSecrets(jwt)
	if len(spans) != 1 || spans[0].Start != 0 || spans[0].End != len(jwt) || spans[0].Kind != kindJWT {
		t.Fatalf("spans = %+v, want one JWT span over the whole string (%d bytes)", spans, len(jwt))
	}
}

// TestFindSecretsAgreesWithRedactSecrets: the spans cover exactly the strings
// RedactSecrets changes, and hiding them leaves nothing for it to find.
func TestFindSecretsAgreesWithRedactSecrets(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	pieces := append(testSecrets(), testPEM, "key=", " ", "\"", ":", "AKIA", "ghp_", "xoxb-", "eyJ", "plain words", "0123456789", "-----BEGIN ", "x")
	for range 3000 {
		var sb strings.Builder
		for range 1 + rng.Intn(6) {
			sb.WriteString(pieces[rng.Intn(len(pieces))])
		}
		s := sb.String()
		spans := FindSecrets(s)
		_, kinds := RedactSecrets(s)
		if (len(spans) > 0) != (len(kinds) > 0) {
			t.Fatalf("%q: %d spans but kinds %v", s, len(spans), kinds)
		}
		masked := []byte(s)
		prev := 0
		for _, sp := range spans {
			if sp.Start < prev || sp.End <= sp.Start || sp.End > len(s) {
				t.Fatalf("%q: bad or overlapping span %+v after %d", s, sp, prev)
			}
			prev = sp.End
			for i := sp.Start; i < sp.End; i++ {
				masked[i] = '*'
			}
		}
		if _, kinds := RedactSecrets(string(masked)); len(kinds) != 0 {
			t.Fatalf("%q: still finds %v after hiding %+v: %q", s, kinds, spans, masked)
		}
	}
}

func FuzzFindSecrets(f *testing.F) {
	for _, s := range testSecrets() {
		f.Add(s)
		f.Add("x=" + s + ";")
	}
	f.Add(testPEM)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		spans := FindSecrets(s)
		prev := 0
		for _, sp := range spans {
			if sp.Start < prev || sp.End <= sp.Start || sp.End > len(s) || sp.Kind == "" {
				t.Fatalf("bad span %+v for %q (previous end %d)", sp, s, prev)
			}
			prev = sp.End
		}
		if _, kinds := RedactSecrets(s); (len(kinds) > 0) != (len(spans) > 0) {
			t.Fatalf("spans %+v disagree with RedactSecrets kinds %v for %q", spans, kinds, s)
		}
	})
}
