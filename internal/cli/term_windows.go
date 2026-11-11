//go:build windows

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	enableVirtualTerminalProcessing = 0x0004
	cpUTF8                          = 65001
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procGetOutputCP    = kernel32.NewProc("GetConsoleOutputCP")
	procSetOutputCP    = kernel32.NewProc("SetConsoleOutputCP")
)

// PrepareConsole turns on ANSI escape processing and UTF-8 output for the
// console attached to stdout, and returns a function that restores the previous
// code page. It does nothing when stdout is not a console.
func PrepareConsole() (restore func()) {
	restore = func() {}
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return restore // not a console (redirected)
	}
	// Best effort: a console that cannot process escape sequences (older than
	// Windows 10) shows them as text, and --color never or NO_COLOR avoids that.
	_, _, _ = procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	if prev, _, _ := procGetOutputCP.Call(); prev != 0 && prev != cpUTF8 {
		if r, _, _ := procSetOutputCP.Call(cpUTF8); r != 0 {
			restore = func() {
				_, _, _ = procSetOutputCP.Call(prev) // on the way out: a failure leaves nothing to act on
			}
		}
	}
	return restore
}
