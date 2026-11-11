package analyze

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/q6r/teardown/internal/binio"
)

// panicError wraps a recovered panic together with where it happened.
type panicError struct {
	value    any
	location string
}

func (e *panicError) Error() string { return fmt.Sprintf("internal error: %v", e.value) }

// guard runs fn and converts a panic into a *panicError, so a bug in one format
// parser degrades to a "parser.error" finding instead of crashing the process.
func guard(fn func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &panicError{value: p, location: panicLocation(debug.Stack())}
		}
	}()
	return fn()
}

// panicLocation extracts the innermost teardown frame ("function (file:line)")
// from a stack trace captured inside the deferred recover.
func panicLocation(stack []byte) string {
	lines := strings.Split(string(stack), "\n")
	for i := 0; i+1 < len(lines); i++ {
		fn := strings.TrimSpace(lines[i])
		if !strings.Contains(fn, "teardown/internal/") || strings.Contains(fn, "internal/analyze.guard") || strings.Contains(fn, "internal/analyze.panicLocation") {
			continue
		}
		file := strings.TrimSpace(lines[i+1])
		if j := strings.LastIndex(file, " +0x"); j >= 0 {
			file = file[:j]
		}
		if j := strings.Index(fn, "("); j > 0 {
			fn = fn[:j]
		}
		if j := strings.LastIndex(file, "teardown/"); j >= 0 {
			file = file[j+len("teardown/"):]
		}
		return fn + " (" + file + ")"
	}
	return "unknown"
}

// safeMessage makes an error message safe to store in a report.
func safeMessage(err error) string { return binio.Printable(err.Error(), 300) }
