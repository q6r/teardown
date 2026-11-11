package strs

import (
	"slices"
	"strings"
)

// registryRoots are the registry root names recognised by the registry matcher,
// with the hive reported as the kind. Long names also match without a trailing
// backslash because they are complete root names on their own.
var registryRoots = []struct {
	name string
	hive string
	long bool
}{
	{"HKEY_LOCAL_MACHINE", "hklm", true},
	{"HKEY_CURRENT_USER", "hkcu", true},
	{"HKEY_CLASSES_ROOT", "hkcr", true},
	{"HKEY_CURRENT_CONFIG", "hkcc", true},
	{"HKEY_USERS", "hku", true},
	{"HKLM", "hklm", false},
	{"HKCU", "hkcu", false},
	{"HKCR", "hkcr", false},
	{"HKCC", "hkcc", false},
	{"HKU", "hku", false},
}

// registryHive reports whether s names a registry key and returns the hive
// ("hklm", "hkcu", "hkcr", "hkcc", "hku", "nt" for \Registry\ paths) when known.
// It accepts a root name (HKEY_LOCAL_MACHINE\..., HKLM\...), the NT form
// (\Registry\Machine\...) and well-known unrooted keys that start with
// SOFTWARE\ or SYSTEM\CurrentControlSet\ and have at least one more component.
func registryHive(s string) (string, bool) {
	u := strings.ToUpper(s)
	for _, r := range registryRoots {
		from := 0
		for {
			i := strings.Index(u[from:], r.name)
			if i < 0 {
				break
			}
			i += from
			end := i + len(r.name)
			before := i == 0 || !isAlnum(u[i-1])
			after := (end < len(u) && u[end] == '\\') || (r.long && end == len(u))
			if before && after {
				return r.hive, true
			}
			from = end
		}
	}
	if strings.Contains(u, `\REGISTRY\`) {
		return "nt", true
	}
	for _, prefix := range []string{`SOFTWARE\`, `SYSTEM\CURRENTCONTROLSET\`, `SYSTEM\CONTROLSET`} {
		if strings.HasPrefix(u, prefix) && strings.Count(u, `\`) >= 2 {
			return "", true
		}
	}
	return "", false
}

// argRule decides whether the first argument (lower case) of a program turns a
// string into a command line.
type argRule func(arg string) bool

// commandRule describes a program that makes a string a command line when its
// first argument satisfies arg.
type commandRule struct {
	kind string
	arg  argRule
}

func argSlash(a string) bool  { return strings.HasPrefix(a, "/") }
func argDash(a string) bool   { return strings.HasPrefix(a, "-") }
func argSwitch(a string) bool { return argSlash(a) || argDash(a) }
func argAny(string) bool      { return true }

// argDLL accepts "shell32.dll,Entry" style arguments.
func argDLL(a string) bool { return strings.Contains(a, ".dll") || strings.Contains(a, ",") }

// argPathy accepts file names, paths and URLs.
func argPathy(a string) bool { return strings.ContainsAny(a, `:\/.`) }

func argOneOf(list ...string) argRule {
	return func(a string) bool { return slices.Contains(list, a) }
}

func argEither(rules ...argRule) argRule {
	return func(a string) bool {
		for _, r := range rules {
			if r(a) {
				return true
			}
		}
		return false
	}
}

// commandPrograms maps a lower-case program name (no directory) to its rule. A
// string is a command line when it starts with one of these followed by an
// argument that satisfies the rule: the rules are deliberately strict so that
// prose that happens to start with a program name ("CMD Internal Error",
// "PowerShell is not installed") is not flagged.
var commandPrograms = buildCommandPrograms()

func buildCommandPrograms() map[string]commandRule {
	m := make(map[string]commandRule)
	add := func(kind string, arg argRule, names ...string) {
		for _, n := range names {
			m[n] = commandRule{kind, arg}
		}
	}
	addExe := func(kind string, arg argRule, names ...string) {
		for _, n := range names {
			m[n] = commandRule{kind, arg}
			m[n+".exe"] = commandRule{kind, arg}
		}
	}
	addExe("cmd", argSlash, "cmd")
	addExe("powershell", argSwitch, "powershell", "pwsh")
	add("shell", argDash, "sh", "bash", "zsh", "dash", "ksh", "csh", "fish", "/bin/sh", "/bin/bash")
	addExe("download", argDash, "curl", "wget")
	addExe("lolbin", argSwitch, "certutil", "schtasks", "bitsadmin", "bcdedit", "msiexec", "cmstp", "taskkill")
	addExe("lolbin", argDLL, "rundll32")
	addExe("lolbin", argEither(argSwitch, argDLL), "regsvr32", "installutil")
	addExe("lolbin", argPathy, "mshta", "wscript", "cscript", "msbuild", "icacls", "takeown")
	addExe("lolbin", argEither(argSlash, argOneOf("process", "os", "useraccount", "shadowcopy", "service", "startup",
		"path", "computersystem", "product", "qfe", "nic", "bios", "cpu", "group", "logicaldisk", "volume")), "wmic")
	addExe("lolbin", argOneOf("delete", "list", "create", "resize", "add"), "vssadmin")
	addExe("lolbin", argOneOf("advfirewall", "firewall", "wlan", "interface", "winhttp", "int", "ipsec", "http"), "netsh")
	addExe("lolbin", argOneOf("user", "localgroup", "use", "view", "share", "accounts", "group", "session", "start", "stop"), "net", "net1")
	addExe("lolbin", argOneOf("add", "delete", "query", "export", "import", "save", "load", "copy"), "reg")
	addExe("lolbin", argOneOf("create", "config", "start", "stop", "delete", "query", "description", "failure"), "sc")
	add("shell", argOneOf("-rf", "-fr", "-r", "-f"), "rm")
	add("shell", argOneOf("+x", "777", "755", "-r", "u+x", "a+x", "+s", "4755"), "chmod")
	add("shell", argOneOf("-e", "-l", "-lvp", "-lvnp", "-c", "-nv"), "nc")
	add("shell", argOneOf("-e", "-l", "-c", "--exec", "--sh-exec"), "ncat")
	add("shell", argOneOf("-d", "--decode"), "base64")
	add("shell", argOneOf("-c"), "python", "python3")
	add("shell", argOneOf("-e"), "perl", "ruby")
	add("shell", argOneOf("-r"), "php")
	add("shell", argOneOf("-s", "-i", "-u", "-e", "-n", "-k", "su", "bash", "sh", "rm", "chmod", "chown", "apt",
		"apt-get", "yum", "systemctl", "service", "tee"), "sudo")
	add("shell", argAny, "nohup")
	return m
}

// commandCues are lower-case fragments that mark a command line when they occur
// anywhere in a string that contains a space.
var commandCues = []struct {
	cue  string
	kind string
}{
	{" -encodedcommand", "powershell"}, {" -enc ", "powershell"}, {"invoke-expression", "powershell"},
	{"iex(", "powershell"}, {"downloadstring(", "powershell"}, {"downloadfile(", "powershell"},
	{"frombase64string(", "powershell"}, {"-windowstyle hidden", "powershell"},
	{"-executionpolicy bypass", "powershell"}, {"-ep bypass", "powershell"},
	{"new-object net.webclient", "powershell"}, {"invoke-webrequest", "powershell"},
	{"cmd.exe /c", "cmd"}, {"cmd /c", "cmd"}, {"cmd.exe /k", "cmd"}, {"%comspec% /", "cmd"},
	{"| sh", "shell"}, {"|sh", "shell"}, {"| bash", "shell"}, {"|bash", "shell"},
	{"/dev/tcp/", "shell"}, {"bash -i", "shell"}, {"sh -c ", "shell"},
	{"regsvr32 /", "lolbin"}, {"certutil -", "lolbin"}, {"schtasks /create", "lolbin"},
}

// maxCommandProbe bounds how much of a string is inspected for command cues.
const maxCommandProbe = 1024

// commandKind reports whether s is a shell, cmd, PowerShell or living-off-the-
// land command line and returns its kind ("cmd", "powershell", "shell",
// "download", "lolbin"). Detection is heuristic: it looks at the program name
// that starts the string and at a short list of telltale fragments.
func commandKind(s string) (string, bool) {
	prog, arg := firstTokens(s)
	if prog != "" && arg != "" {
		if rule, ok := commandPrograms[prog]; ok && rule.arg(arg) {
			return rule.kind, true
		}
	}
	probe := s
	if len(probe) > maxCommandProbe {
		probe = probe[:maxCommandProbe]
	}
	lower := strings.ToLower(probe)
	for _, c := range commandCues {
		if strings.Contains(lower, c.cue) {
			return c.kind, true
		}
	}
	return "", false
}

// firstTokens returns the program name (lower case, without quotes or
// directory) and the first argument (lower case) of a command-line-like string.
func firstTokens(s string) (prog, arg string) {
	s = strings.TrimLeft(s, " \t\"'")
	end := strings.IndexAny(s, " \t")
	if end <= 0 {
		return "", ""
	}
	first := strings.TrimRight(s[:end], "\"'")
	if i := strings.LastIndexAny(first, `\/`); i >= 0 && !isShellPath(first) {
		first = first[i+1:]
	}
	rest := strings.TrimLeft(s[end:], " \t")
	if e := strings.IndexAny(rest, " \t"); e >= 0 {
		rest = rest[:e]
	}
	return strings.ToLower(first), strings.ToLower(strings.Trim(rest, "\"'"))
}

// isShellPath keeps the full path for the two absolute shell names that are
// listed with their directory.
func isShellPath(p string) bool { return p == "/bin/sh" || p == "/bin/bash" }

// userAgentTokens are product tokens that identify an HTTP user agent. When
// digit is set the token must be followed by a digit (a version number).
var userAgentTokens = []struct {
	token string
	kind  string
	digit bool
}{
	{"Mozilla/", "browser", true}, {"Opera/", "browser", true}, {"AppleWebKit/", "browser", true},
	{"Trident/", "browser", true}, {"MSIE ", "browser", true},
	{"curl/", "tool", true}, {"Wget/", "tool", true}, {"python-requests/", "tool", true},
	{"python-urllib/", "tool", true}, {"Python-urllib/", "tool", true}, {"Go-http-client/", "tool", true},
	{"okhttp/", "tool", true}, {"libwww-perl/", "tool", true}, {"Apache-HttpClient/", "tool", true},
	{"Java/", "tool", true}, {"axios/", "tool", true}, {"Dalvik/", "tool", true},
	{"CFNetwork/", "tool", true}, {"Microsoft-CryptoAPI/", "tool", true},
	{"WinHTTP", "tool", false}, {"User-Agent:", "header", false},
}

// userAgentKind reports whether s contains an HTTP user-agent product token and
// returns "browser", "tool" or "header".
func userAgentKind(s string) (string, bool) {
	for _, t := range userAgentTokens {
		for from := 0; from < len(s); {
			i := strings.Index(s[from:], t.token)
			if i < 0 {
				break
			}
			i += from
			end := i + len(t.token)
			startOK := i == 0 || !isAlnum(s[i-1])
			endOK := !t.digit || (end < len(s) && isDigit(s[end]))
			if startOK && endOK {
				return t.kind, true
			}
			from = end
		}
	}
	return "", false
}

// unixRoots are the top-level directories that make a single-component absolute
// path ("/tmp") credible on its own.
var unixRoots = map[string]struct{}{
	"bin": {}, "boot": {}, "dev": {}, "etc": {}, "home": {}, "lib": {}, "lib32": {}, "lib64": {},
	"media": {}, "mnt": {}, "opt": {}, "proc": {}, "root": {}, "run": {}, "sbin": {}, "srv": {},
	"sys": {}, "tmp": {}, "usr": {}, "var": {}, "Applications": {}, "Library": {}, "System": {},
	"Users": {}, "Volumes": {}, "private": {}, "data": {}, "system": {}, "sdcard": {}, "storage": {},
}

// windowsRelativeRoots are directory names that start credible relative Windows
// paths such as "Windows\System32\drivers".
var windowsRelativeRoots = []string{
	`windows\`, `program files\`, `program files (x86)\`, `programdata\`, `users\`, `system32\`,
	`syswow64\`, `appdata\`, `documents and settings\`, `winnt\`,
}

// pathKind reports whether s starts with a file system path and returns
// "windows" (drive, environment-variable, NT or well-known relative form),
// "unc" or "unix".
func pathKind(s string) (string, bool) {
	t := strings.TrimLeft(s, "\"'")
	switch {
	case isDrivePath(t):
		return "windows", true
	case strings.HasPrefix(t, `\\`):
		rest := strings.TrimLeft(t, `\`)
		if rest != "" && (strings.ContainsRune(rest, '\\') || strings.HasPrefix(t, `\\?\`) || strings.HasPrefix(t, `\\.\`)) {
			return "unc", true
		}
		return "", false
	case strings.HasPrefix(t, `\??\`), hasPrefixFold(t, `\Device\`), hasPrefixFold(t, `\SystemRoot\`):
		return "windows", true
	case strings.HasPrefix(t, "%") && envPrefix(t):
		return "windows", true
	case hasWindowsRelativeRoot(t):
		return "windows", true
	case len(t) > 2 && t[0] == '/' && isUnixPath(t):
		return "unix", true
	case hasUnixRelativePrefix(t):
		return "unix", true
	}
	return embeddedDrivePath(t)
}

// isDrivePath reports whether t starts with X:\ or X:/ followed by a character.
func isDrivePath(t string) bool {
	return len(t) >= 4 && isLetter(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/') && t[3] > ' '
}

// envPrefix reports whether t starts with %NAME%\ or %NAME%/.
func envPrefix(t string) bool {
	end := strings.IndexByte(t[1:], '%')
	if end <= 0 || end > 32 {
		return false
	}
	rest := t[end+2:]
	return len(rest) > 1 && (rest[0] == '\\' || rest[0] == '/')
}

func hasWindowsRelativeRoot(t string) bool {
	for _, root := range windowsRelativeRoots {
		if hasPrefixFold(t, root) && len(t) > len(root) {
			return true
		}
	}
	return false
}

// isUnixPath decides whether t, which starts with a slash, is a path: the first
// word must have two or more components or start with a well-known root. "//"
// comments, bare "/x" switches and lone slashes are rejected.
func isUnixPath(t string) bool {
	if t[1] == '/' {
		return false
	}
	head := t[1:]
	if sp := strings.IndexAny(head, " \t"); sp >= 0 {
		head = head[:sp]
	}
	first, rest, _ := strings.Cut(head, "/")
	if first == "" {
		return false
	}
	if strings.Trim(rest, "/") != "" {
		return true
	}
	_, known := unixRoots[first]
	return known
}

// hasUnixRelativePrefix reports whether t starts with ~/, ./ or ../ followed by
// at least one more character.
func hasUnixRelativePrefix(t string) bool {
	for _, p := range []string{"~/", "./", "../"} {
		if strings.HasPrefix(t, p) && len(t) > len(p) {
			return true
		}
	}
	return false
}

// embeddedDrivePath finds an X:\ drive path inside a longer string.
func embeddedDrivePath(t string) (string, bool) {
	for from := 0; from < len(t); {
		i := strings.Index(t[from:], `:\`)
		if i < 0 {
			return "", false
		}
		i += from
		if i >= 1 && isLetter(t[i-1]) && (i == 1 || !isAlnum(t[i-2])) && i+2 < len(t) && t[i+2] > ' ' {
			return "windows", true
		}
		from = i + 2
	}
	return "", false
}

// hasPrefixFold is a case-insensitive (ASCII) strings.HasPrefix.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
