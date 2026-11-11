// Command teardown is a static-triage tool for binaries and apps: a CLI, an
// HTTP API with an embedded web dashboard, and an MCP server over stdio, all in
// one static binary. It never executes the files it analyses.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/q6r/teardown/internal/cli"
)

func main() {
	restore := cli.PrepareConsole()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.OSEnv())
	stop()
	restore()
	os.Exit(code)
}
