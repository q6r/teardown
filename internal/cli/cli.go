// Package cli implements the teardown command line: subcommands, flags, help,
// shell completion, exit codes and output selection. It is a thin layer over
// the analyze, render, diff, server and mcp packages and is fully testable
// through [Run] with in-memory streams.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Exit codes.
const (
	exitOK     = 0 // success
	exitError  = 1 // the operation failed
	exitUsage  = 2 // bad command line
	exitFailOn = 3 // --fail-on threshold reached
)

// Env carries everything the CLI needs from its surroundings so tests can
// substitute it.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Getenv looks up an environment variable (default os.Getenv).
	Getenv func(string) string
	// IsTTY reports whether w is an interactive terminal (default: character-device check).
	IsTTY func(io.Writer) bool
	// Now supplies the clock for reports.
	Now func() time.Time
}

// OSEnv returns the real process environment.
func OSEnv() Env {
	return Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, IsTTY: isTerminal, Now: time.Now}
}

func (e Env) withDefaults() Env {
	if e.Stdin == nil {
		e.Stdin = strings.NewReader("")
	}
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.IsTTY == nil {
		e.IsTTY = isTerminal
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	return e
}

// runner executes a parsed command and returns its exit code.
type runner func(ctx context.Context, env Env, positional []string) int

// command is one subcommand. register declares its flags on f and returns the
// function that runs once they are parsed; help and completion call register
// with a throw-away flag set.
type command struct {
	name     string
	summary  string
	args     string
	long     string
	examples []string
	register func(f *flagSet) runner
}

// commands lists the subcommands in display order.
func commands() []command {
	return []command{
		analyzeCommand(), stringsCommand(), hashCommand(), diffCommand(),
		serveCommand(), mcpCommand(), completionCommand(), versionCommand(),
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// Run executes the command line (without the program name) and returns the
// process exit code: 0 success, 1 error, 2 usage error, 3 --fail-on reached.
func Run(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	if len(args) == 0 {
		printHelp(env.Stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "-help":
		printHelp(env.Stdout)
		return exitOK
	case "help":
		return runHelp(env, args[1:])
	case "-V", "--version", "-version":
		args = []string{"version"}
	}
	cmd, ok := findCommand(args[0])
	if !ok {
		msg := fmt.Sprintf("unknown command %q", args[0])
		if s := suggest(args[0]); s != "" {
			msg += fmt.Sprintf(" (did you mean %q?)", s)
		}
		fmt.Fprintf(env.Stderr, "teardown: %s\nRun 'teardown --help' for the list of commands.\n", msg)
		return exitUsage
	}
	fs := newFlagSet(cmd.name)
	run := cmd.register(fs)
	positional, err := fs.Parse(args[1:])
	switch {
	case helpRequested(err):
		printCommandHelp(env.Stdout, cmd, fs)
		return exitOK
	case err != nil:
		return usageError(env, cmd.name, "%v", err)
	}
	return run(ctx, env, positional)
}

// usageError reports a command-line mistake and returns the usage exit code.
func usageError(env Env, command, format string, a ...any) int {
	fmt.Fprintf(env.Stderr, "teardown %s: %s\nRun 'teardown %s --help' for usage.\n", command, fmt.Sprintf(format, a...), command)
	return exitUsage
}

// failure reports a runtime error and returns the error exit code.
func failure(env Env, command string, err error) int {
	fmt.Fprintf(env.Stderr, "teardown %s: %v\n", command, err)
	return exitError
}

func runHelp(env Env, args []string) int {
	if len(args) == 0 {
		printHelp(env.Stdout)
		return exitOK
	}
	cmd, ok := findCommand(args[0])
	if !ok {
		fmt.Fprintf(env.Stderr, "teardown: unknown command %q\nRun 'teardown --help' for the list of commands.\n", args[0])
		return exitUsage
	}
	fs := newFlagSet(cmd.name)
	cmd.register(fs)
	printCommandHelp(env.Stdout, cmd, fs)
	return exitOK
}

func printHelp(w io.Writer) {
	var sb strings.Builder
	sb.WriteString("teardown: static triage for binaries and apps. It never executes the target.\n\n")
	sb.WriteString("Usage:\n  teardown <command> [flags] [arguments]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&sb, "  %-11s %s\n", c.name, c.summary)
	}
	sb.WriteString(`
Run 'teardown <command> --help' for the flags and examples of one command.

Quick start:
  teardown analyze app.exe                  Human-readable report in the terminal
  teardown analyze app.exe --json           The full report as JSON (schema teardown.report/v1)
  teardown analyze app.exe --html out.html  A self-contained HTML report
  teardown analyze app.exe --fail-on high   Exit 3 when a finding of severity high or worse exists
  teardown serve                            Dashboard and JSON API on http://127.0.0.1:7777
  teardown mcp --root .                     MCP server on stdio for AI agents, limited to this folder

Exit codes:
  0  success    1  error    2  usage error    3  --fail-on threshold reached

Environment:
  NO_COLOR        any non-empty value disables colour (see https://no-color.org)
  TEARDOWN_ASCII  any non-empty value replaces unicode bars and symbols with ASCII
  COLUMNS         line width of the human output (default 100)

Every conclusion ships with evidence and stated limitations; the risk score is a
triage aid, not a verdict. See https://github.com/q6r/teardown for the documentation.
`)
	io.WriteString(w, sb.String())
}

func printCommandHelp(w io.Writer, c command, fs *flagSet) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "teardown %s: %s\n\nUsage:\n  teardown %s %s[flags]\n\n", c.name, c.summary, c.name, withSpace(c.args))
	if c.long != "" {
		sb.WriteString(strings.TrimSpace(c.long) + "\n\n")
	}
	io.WriteString(w, sb.String())
	fs.Help(w)
	if len(c.examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		for _, e := range c.examples {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

func withSpace(s string) string {
	if s == "" {
		return ""
	}
	return s + " "
}

// suggest returns the command closest to name when it is a plausible typo.
func suggest(name string) string {
	best, bestDist := "", 3
	for _, c := range commands() {
		if d := editDistance(name, c.name); d < bestDist {
			best, bestDist = c.name, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// sortedCommandNames returns the subcommand names, for completion scripts.
func sortedCommandNames() []string {
	var names []string
	for _, c := range commands() {
		names = append(names, c.name)
	}
	sort.Strings(names)
	return names
}
