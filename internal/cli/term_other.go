//go:build !windows

package cli

// PrepareConsole is a no-op outside Windows: terminals interpret ANSI and UTF-8
// natively. The returned function restores nothing.
func PrepareConsole() (restore func()) { return func() {} }
