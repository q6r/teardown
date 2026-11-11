// Package testfixtures builds tiny, valid, fully deterministic sample files
// (PE, ELF, Mach-O, ZIP, ASAR, WebAssembly, GGUF, ...) in memory so tests and
// examples never depend on third-party binaries.
//
// Every builder returns a []byte, takes an options struct whose zero value
// yields a sensible minimal file, and never uses randomness or the clock.
// Nothing here is meant for production code paths.
package testfixtures
