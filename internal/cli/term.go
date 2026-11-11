package cli

import (
	"io"
	"os"
	"strings"
)

// isTerminal reports whether w is a character device (an interactive terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// colorEnabled decides whether to emit ANSI colours for the --color mode.
// "auto" follows https://no-color.org: any non-empty NO_COLOR disables colour,
// and so do dumb terminals and non-terminals.
func colorEnabled(mode string, env Env, w io.Writer) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if env.Getenv("NO_COLOR") != "" || env.Getenv("TERM") == "dumb" {
		return false
	}
	return env.IsTTY(w)
}

// asciiOnly reports whether to avoid unicode symbols: when asked to, on dumb
// terminals, and when the locale explicitly selects the C/POSIX charset.
func asciiOnly(flag bool, env Env) bool {
	if flag || env.Getenv("TEARDOWN_ASCII") != "" || env.Getenv("TERM") == "dumb" {
		return true
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := env.Getenv(k); v != "" {
			l := strings.ToLower(v)
			return l == "c" || l == "posix"
		}
	}
	return false
}

// terminalWidth returns COLUMNS when it is a sane number, else 0 (use the default).
func terminalWidth(env Env) int {
	n := 0
	for _, c := range env.Getenv("COLUMNS") {
		if c < '0' || c > '9' || n > 1000 {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if n < 40 || n > 400 {
		return 0
	}
	return n
}
