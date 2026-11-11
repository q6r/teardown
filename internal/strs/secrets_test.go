package strs

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func itoa(n int) string { return strconv.Itoa(n) }

func TestRedact(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"aws key", testAWSKey, "AKIA…(20 chars)"},
		{"pem header", testPEM, "----…(31 chars)"},
		{"eight chars keep two", "abcdefgh", "ab…(8 chars)"},
		{"four chars keep one", "abcd", "a…(4 chars)"},
		{"three chars keep none", "abc", "…(3 chars)"},
		{"empty", "", "…(0 chars)"},
		{"unicode keeps whole runes", "héllo wörld, long secret", "héll…(24 chars)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.in); got != tc.want {
				t.Fatalf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		want      string
		wantKinds []string
	}{
		{"aws key", testAWSKey, "AKIA…(20 chars)", []string{kindAWS}},
		{"aws key in assignment", "key=" + testAWSKey + ";", "key=AKIA…(20 chars);", []string{kindAWS}},
		{"aws key glued to letters", "x" + testAWSKey + "x", "xAKIA…(20 chars)x", []string{kindAWS}},
		{"github token", testGitHubPAT, "ghp_…(40 chars)", []string{kindGitHub}},
		{"slack token", testSlack, "xoxb…(" + itoa(len(testSlack)) + " chars)", []string{kindSlack}},
		{"pem header", testPEM, "----…(31 chars)", []string{kindPEM}},
		{"jwt", testJWT, "eyJh…(" + itoa(len(testJWT)) + " chars)", []string{kindJWT}},
		{"two kinds sorted", testAWSKey + " " + testGitHubPAT, "AKIA…(20 chars) ghp_…(40 chars)", []string{kindAWS, kindGitHub}},
		{"same kind twice", testAWSKey + "," + testAWSKey, "AKIA…(20 chars),AKIA…(20 chars)", []string{kindAWS}},
		{"url with embedded token", "https://u:" + testGitHubPAT + "@h.example.com", "https://u:ghp_…(40 chars)@h.example.com", []string{kindGitHub}},
		{"nothing", "nothing to see here at all", "nothing to see here at all", nil},
		{"too short to hold a secret", "AKIAIOSFODNN7", "AKIAIOSFODNN7", nil},
		{"empty", "", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, kinds := RedactSecrets(tc.in)
			if got != tc.want {
				t.Fatalf("RedactSecrets(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !slices.Equal(kinds, tc.wantKinds) {
				t.Fatalf("kinds = %v, want %v", kinds, tc.wantKinds)
			}
		})
	}
}

func TestRedactSecretsNeverLeaksAndIsIdempotent(t *testing.T) {
	surroundings := []string{"%s", "pre %s post", "%s%s", `{"token":"%s"}`, "a=%s&b=%s", "%s\n%s"}
	for _, secret := range testSecrets() {
		for _, tmpl := range surroundings {
			in := strings.ReplaceAll(tmpl, "%s", secret)
			out, kinds := RedactSecrets(in)
			if strings.Contains(out, secret) {
				t.Errorf("secret survived in %q -> %q", in, out)
			}
			if len(kinds) == 0 {
				t.Errorf("no kind reported for %q", in)
			}
			again, kinds2 := RedactSecrets(out)
			if again != out || len(kinds2) != 0 {
				t.Errorf("not idempotent: %q -> %q (kinds %v)", out, again, kinds2)
			}
		}
	}
}
