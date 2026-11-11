// Package apiname folds the names of imported functions into one comparable
// form, so that the rules that flag APIs by name and the code views that look
// for their call sites agree on what "the same function" means.
//
// The folding is deliberately forgiving: it ignores case, the decoration
// compilers add ("_name@12", "name@GLIBC_2.2.5", "__imp_name"), the ANSI and
// wide suffix (CreateProcessA and CreateProcessW are both "createprocess") and
// the Zw spelling of native calls (ZwQueryInformationProcess is
// "ntqueryinformationprocess"). It is a matching aid, not a symbol resolver.
package apiname

import "strings"

// Canonical returns the comparable form of an imported function name: lower
// case, cut at the first '@' (calling-convention and symbol-version
// decoration), without an "__imp_" prefix and leading underscores, with Zw
// folded into Nt. An import by ordinal ("#23") keeps its form.
func Canonical(name string) string {
	n := strings.ToLower(name)
	if i := strings.IndexByte(n, '@'); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimPrefix(n, "__imp_")
	n = strings.TrimLeft(n, "_")
	if strings.HasPrefix(n, "zw") {
		n = "nt" + n[2:]
	}
	return n
}

// Stem returns the canonical name without its trailing ANSI or wide suffix ('a'
// or 'w'), and whether there was one to remove. A name of one or two characters
// has no suffix: "wa" is not an A variant of anything.
func Stem(canonical string) (string, bool) {
	n := len(canonical)
	if n > 2 && (canonical[n-1] == 'a' || canonical[n-1] == 'w') {
		return canonical[:n-1], true
	}
	return canonical, false
}

// Keys returns the names under which a function is looked up: its canonical
// form and, when that form ends in 'a' or 'w', the form without it.
func Keys(name string) []string {
	c := Canonical(name)
	if stem, ok := Stem(c); ok {
		return []string{c, stem}
	}
	return []string{c}
}
