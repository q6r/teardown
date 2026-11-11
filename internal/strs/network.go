package strs

import (
	"net/netip"
	"strings"
)

// urlSchemes are the URL schemes recognised by the url matcher (lower case).
var urlSchemes = map[string]struct{}{
	"http": {}, "https": {}, "ftp": {}, "ftps": {}, "sftp": {}, "ws": {}, "wss": {}, "file": {},
	"ssh": {}, "smb": {}, "ldap": {}, "ldaps": {}, "tcp": {}, "udp": {}, "git": {}, "svn": {},
	"rtsp": {}, "rtmp": {}, "rtmps": {}, "telnet": {}, "vnc": {}, "rdp": {}, "irc": {}, "ircs": {},
	"socks": {}, "socks4": {}, "socks5": {}, "socks5h": {}, "tftp": {}, "nfs": {}, "s3": {}, "gs": {},
	"mongodb": {}, "mysql": {}, "postgres": {}, "postgresql": {}, "redis": {}, "rediss": {},
	"amqp": {}, "amqps": {}, "mqtt": {}, "mqtts": {}, "jdbc": {}, "imap": {}, "imaps": {},
	"pop3": {}, "pop3s": {}, "smtp": {}, "smtps": {},
}

// maxSchemeLen bounds how far back from "://" a scheme is searched.
const maxSchemeLen = 12

// urlScheme reports whether s contains scheme://authority with a recognised
// scheme and returns the scheme in lower case. A bare "http://" does not count.
func urlScheme(s string) (string, bool) {
	scheme, _, _, ok := findURL(s)
	return scheme, ok
}

// findURL locates the first recognised URL in s: its lower-case scheme and the
// span [start, end) of the URL token, which runs from the scheme to the first
// space, quote, angle bracket, backslash or control character.
func findURL(s string) (scheme string, start, end int, ok bool) {
	for off := 0; off < len(s); {
		i := strings.Index(s[off:], "://")
		if i < 0 {
			return "", 0, 0, false
		}
		i += off
		start = i
		for start > 0 && i-start < maxSchemeLen && isSchemeChar(s[start-1]) {
			start--
		}
		for start < i && !isLetter(s[start]) {
			start++
		}
		scheme = strings.ToLower(s[start:i])
		if _, known := urlSchemes[scheme]; known && authorityFollows(s[i+3:], scheme) {
			end = i + 3
			for end < len(s) && !isURLDelimiter(s[end]) {
				end++
			}
			return scheme, start, end, true
		}
		off = i + 3
	}
	return "", 0, 0, false
}

func isURLDelimiter(c byte) bool {
	return c <= ' ' || c == 0x7f || c == '"' || c == '\'' || c == '<' || c == '>' || c == '\\' || c == '`'
}

// authorityFollows reports whether rest looks like the start of a URL authority
// (or, for file URLs, an absolute path).
func authorityFollows(rest, scheme string) bool {
	if rest == "" {
		return false
	}
	switch c := rest[0]; {
	case c == '/':
		return scheme == "file"
	case c <= ' ' || c == 0x7f, c == '"', c == '\'', c == '<', c == '>', c == '\\':
		return false
	}
	return true
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool  { return isLetter(c) || isDigit(c) }
func isSchemeChar(c byte) bool {
	return isAlnum(c) || c == '+' || c == '-' || c == '.'
}

// maxLocalPart is the longest local part (before the @) considered for an email.
const maxLocalPart = 64

// hasEmail reports whether s contains local@domain with a plausible domain.
func hasEmail(s string) bool {
	for off := 0; off < len(s); {
		i := strings.IndexByte(s[off:], '@')
		if i < 0 {
			return false
		}
		i += off
		l := i
		for l > 0 && i-l < maxLocalPart && isEmailLocalChar(s[l-1]) {
			l--
		}
		for l < i && !isAlnum(s[l]) {
			l++
		}
		r := i + 1
		for r < len(s) && (isAlnum(s[r]) || s[r] == '.' || s[r] == '-') {
			r++
		}
		if l < i && r > i+1 {
			domain := strings.TrimRight(s[i+1:r], ".-")
			if _, ok := validDomainName(strings.ToLower(domain)); ok {
				return true
			}
		}
		off = i + 1
	}
	return false
}

func isEmailLocalChar(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

// validDomainName reports whether d (already lower case) is a plausible host
// name whose last label is an allowed TLD, and returns that TLD. d must consist
// of letters, digits, dots and hyphens only.
func validDomainName(d string) (tld string, ok bool) {
	if len(d) < 4 || len(d) > 253 {
		return "", false
	}
	dot := strings.LastIndexByte(d, '.')
	if dot <= 0 || dot == len(d)-1 {
		return "", false
	}
	tld = d[dot+1:]
	if !tldAllowed(tld) {
		return "", false
	}
	for label := range strings.SplitSeq(d[:dot], ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
	}
	return tld, true
}

// domainTLD reports whether the whole of s is a host name under an allowed
// TLD. Names that mix upper and lower case letters (Microsoft.NET) are
// rejected: they are almost always type or namespace names, not host names.
func domainTLD(s string, f uint32) (string, bool) {
	if f&fUpper != 0 && f&fLower != 0 {
		return "", false
	}
	return validDomainName(strings.ToLower(s))
}

// ipKind returns "ipv4" or "ipv6" when s contains an IPv4 address or is an IPv6
// literal, and "" otherwise.
func ipKind(s string, f uint32) string {
	if f&fDot != 0 && f&fDigit != 0 && hasIPv4(s) {
		return "ipv4"
	}
	if f&fColon != 0 && isIPv6(s) {
		return "ipv6"
	}
	return ""
}

// hasIPv4 reports whether s contains a dotted quad with valid octets that is
// not glued to a longer token. Version-like quads are rejected: octets with
// leading zeros, a leading 0 (except 0.0.0.0) and N.N.0.0 forms outside the
// private, loopback, link-local and multicast ranges. The version heuristic
// trades a little recall (a public address ending in .0.0 is missed) for far
// fewer false positives on assembly versions such as 2.1.0.0.
func hasIPv4(s string) bool {
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && (isDigit(s[j]) || s[j] == '.') {
			j++
		}
		tok := strings.TrimRight(s[i:j], ".")
		glued := (i > 0 && isIPv4Glue(s[i-1])) || (j < len(s) && isIPv4Glue(s[j]))
		if !glued {
			if oct, ok := parseQuad(tok); ok && !versionLike(oct) {
				return true
			}
		}
		i = j
	}
	return false
}

func isIPv4Glue(c byte) bool { return isLetter(c) || c == '_' || c == '-' }

// parseQuad parses "a.b.c.d" with every octet 0..255 and no leading zeros.
func parseQuad(tok string) ([4]int, bool) {
	var oct [4]int
	n := 0
	for part := range strings.SplitSeq(tok, ".") {
		if n == 4 || part == "" || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return oct, false
		}
		v := 0
		for k := 0; k < len(part); k++ {
			v = v*10 + int(part[k]-'0')
		}
		if v > 255 {
			return oct, false
		}
		oct[n] = v
		n++
	}
	return oct, n == 4
}

func versionLike(o [4]int) bool {
	if o[0] == 0 {
		return o != [4]int{}
	}
	if o[2] == 0 && o[3] == 0 {
		switch first := o[0]; {
		case first == 10, first == 127, first == 169, first == 172, first == 192, first >= 224:
			return false
		}
		return true
	}
	return false
}

// isIPv6 reports whether the whole of s is a plausible IPv6 literal,
// optionally in brackets with a port. Beyond parsing as an address it must have
// at least three explicit hextets (an embedded IPv4 tail counts as two) and at
// least one hextet of three or more hex digits (or an IPv4 tail). That rejects
// C++ scopes and identifiers such as "a::b" and "7::ff", loopback and other
// very short forms such as "::1" and "fe80::1", time-like strings (12:34:56)
// and MAC- or EUI-64-like strings (aa:bb:cc:dd:ee:ff:00:11), none of which are
// useful indicators.
func isIPv6(s string) bool {
	if len(s) < 3 || len(s) > 64 || strings.Count(s, ":") < 2 {
		return false
	}
	host := s
	if s[0] == '[' {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return false
		}
		if rest := s[end+1:]; rest != "" && !isPortSuffix(rest) {
			return false
		}
		host = s[1:end]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() {
		return false
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	hextets, wide := 0, false
	for group := range strings.SplitSeq(host, ":") {
		switch {
		case group == "":
		case strings.Contains(group, "."):
			hextets, wide = hextets+2, true
		default:
			hextets++
			wide = wide || len(group) >= 3
		}
	}
	return hextets >= 3 && wide
}

func isPortSuffix(s string) bool {
	if len(s) < 2 || len(s) > 6 || s[0] != ':' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
