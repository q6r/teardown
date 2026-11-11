package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// flagSpec describes one flag for help and shell completion.
type flagSpec struct {
	name    string
	short   string
	meta    string // placeholder for the value, "" for booleans
	usage   string
	def     string
	group   string
	allowed []string // values offered by shell completion
	file    bool     // the value is a file path
	dir     bool     // the value is a directory path
	boolean bool
	repeat  bool
}

// flagSet wraps flag.FlagSet with aliases, groups, interspersed parsing and
// help rendering.
type flagSet struct {
	fs    *flag.FlagSet
	specs []flagSpec
	group string
}

func newFlagSet(name string) *flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return &flagSet{fs: fs}
}

// Group sets the heading under which the following flags are listed.
func (f *flagSet) Group(name string) { f.group = name }

func (f *flagSet) add(s flagSpec, v flag.Value) {
	s.group = f.group
	f.specs = append(f.specs, s)
	f.fs.Var(v, s.name, s.usage)
	if s.short != "" {
		f.fs.Var(v, s.short, s.usage)
	}
}

// Bool registers a boolean flag.
func (f *flagSet) Bool(p *bool, name, short, usage string) {
	f.add(flagSpec{name: name, short: short, usage: usage, boolean: true}, (*boolValue)(p))
}

// String registers a string flag; allowed lists completion candidates.
func (f *flagSet) String(p *string, name, short, meta, def, usage string, allowed ...string) {
	*p = def
	f.add(flagSpec{name: name, short: short, meta: meta, usage: usage, def: def, allowed: allowed}, (*stringValue)(p))
}

// Path registers a string flag whose value is a file path.
func (f *flagSet) Path(p *string, name, short, meta, usage string) {
	f.add(flagSpec{name: name, short: short, meta: meta, usage: usage, file: true}, (*stringValue)(p))
}

// Int registers an integer flag.
func (f *flagSet) Int(p *int, name, short, meta string, def int, usage string) {
	*p = def
	shown := ""
	if def != 0 {
		shown = strconv.Itoa(def)
	}
	f.add(flagSpec{name: name, short: short, meta: meta, usage: usage, def: shown}, (*intValue)(p))
}

// Duration registers a duration flag.
func (f *flagSet) Duration(p *time.Duration, name, meta string, def time.Duration, usage string) {
	*p = def
	f.add(flagSpec{name: name, meta: meta, usage: usage, def: def.String()}, (*durationValue)(p))
}

// Size registers a byte-size flag such as 256MiB.
func (f *flagSet) Size(p *int64, name, meta string, def int64, usage string) {
	*p = def
	f.add(flagSpec{name: name, meta: meta, usage: usage, def: formatSize(def)}, (*sizeValue)(p))
}

// List registers a repeatable flag; each use appends one value.
func (f *flagSet) List(p *[]string, name, short, meta, usage string, dir bool) {
	f.add(flagSpec{name: name, short: short, meta: meta, usage: usage, repeat: true, dir: dir}, (*listValue)(p))
}

// Parse parses args allowing flags before, between and after positional
// arguments ("--" ends flag parsing) and returns the positional arguments.
func (f *flagSet) Parse(args []string) ([]string, error) {
	var positional []string
	for {
		if err := f.fs.Parse(args); err != nil {
			return nil, err
		}
		rest := f.fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// helpRequested reports whether err is the flag package's -h/--help signal.
func helpRequested(err error) bool { return errors.Is(err, flag.ErrHelp) }

// Help writes the flag reference, grouped, with defaults.
func (f *flagSet) Help(w io.Writer) {
	var groups []string
	byGroup := map[string][]flagSpec{}
	for _, s := range f.specs {
		if _, ok := byGroup[s.group]; !ok {
			groups = append(groups, s.group)
		}
		byGroup[s.group] = append(byGroup[s.group], s)
	}
	for _, g := range groups {
		title := g
		if title == "" {
			title = "Flags"
		}
		fmt.Fprintf(w, "%s:\n", title)
		for _, s := range byGroup[g] {
			left := "  "
			if s.short != "" {
				left += "-" + s.short + ", "
			} else {
				left += "    "
			}
			left += "--" + s.name
			if s.meta != "" {
				left += " " + s.meta
			}
			usage := s.usage
			if s.def != "" && !s.boolean {
				usage += " (default " + s.def + ")"
			}
			if len(left) < 30 {
				fmt.Fprintf(w, "%-30s%s\n", left, usage)
			} else {
				fmt.Fprintf(w, "%s\n%30s%s\n", left, "", usage)
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  -h, --help                  Show this help\n")
}

type boolValue bool

func (b *boolValue) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("expected true or false")
	}
	*b = boolValue(v)
	return nil
}
func (b *boolValue) String() string   { return strconv.FormatBool(bool(*b)) }
func (b *boolValue) IsBoolFlag() bool { return true }

type stringValue string

func (s *stringValue) Set(v string) error { *s = stringValue(v); return nil }
func (s *stringValue) String() string     { return string(*s) }

type intValue int

func (i *intValue) Set(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%q is not a whole number", s)
	}
	*i = intValue(v)
	return nil
}
func (i *intValue) String() string { return strconv.Itoa(int(*i)) }

type durationValue time.Duration

func (d *durationValue) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%q is not a duration such as 30s or 2m", s)
	}
	*d = durationValue(v)
	return nil
}
func (d *durationValue) String() string { return time.Duration(*d).String() }

type listValue []string

func (l *listValue) Set(s string) error { *l = append(*l, s); return nil }
func (l *listValue) String() string     { return strings.Join(*l, ",") }

type sizeValue int64

func (s *sizeValue) Set(v string) error {
	n, err := parseSize(v)
	if err != nil {
		return err
	}
	*s = sizeValue(n)
	return nil
}
func (s *sizeValue) String() string { return formatSize(int64(*s)) }

// maxSize bounds size flags (1 TiB) so arithmetic on them cannot overflow.
const maxSize = 1 << 40

// parseSize parses sizes such as 1048576, 64k, 256MiB, 1.5GiB or 100MB. K/M/G and
// KiB/MiB/GiB are powers of 1024; KB/MB/GB are powers of 1000.
func parseSize(s string) (int64, error) {
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))
	units := []struct {
		suffix string
		mult   float64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"kb", 1e3}, {"mb", 1e6}, {"gb", 1e9},
		{"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"b", 1},
	}
	mult := 1.0
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || v != v {
		return 0, fmt.Errorf("%q is not a size such as 64KiB, 256MiB or 1GiB", orig)
	}
	n := v * mult
	if n < 1 || n > maxSize {
		return 0, fmt.Errorf("size %q is out of range (1 byte to 1 TiB)", orig)
	}
	return int64(n), nil
}

// formatSize renders a size the way parseSize accepts it.
func formatSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dGiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// splitList splits a comma-separated flag value, trimming blanks and dropping empties.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
