package cli

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/q6r/teardown/internal/mcp"
	"github.com/q6r/teardown/internal/server"
	"github.com/q6r/teardown/internal/version"
)

func serveCommand() command {
	return command{
		name:    "serve",
		summary: "Start the HTTP API and the web dashboard (loopback only by default)",
		long: `Serves the dashboard at / and a JSON API under /api (see /api/openapi.json).
Uploads are streamed into a private temporary directory, analysed and deleted
immediately; they are never executed. The server has no authentication, so it
binds to 127.0.0.1 by default and prints a loud warning for any other address.
Stop it with Ctrl+C.`,
		examples: []string{
			"teardown serve",
			"teardown serve --addr 127.0.0.1:9000 --max-upload 64MiB --keep 20",
			"curl -F file=@app.exe http://127.0.0.1:7777/api/analyze",
		},
		register: func(f *flagSet) runner {
			var (
				addr      string
				maxUpload int64
				keep      int
			)
			f.Group("Server")
			f.String(&addr, "addr", "", "HOST:PORT", server.DefaultAddr, "Address to listen on")
			f.Size(&maxUpload, "max-upload", "SIZE", server.DefaultMaxUpload, "Largest accepted upload (for example 64MiB or 1GiB)")
			f.Int(&keep, "keep", "", "N", server.DefaultKeep, "Analyses kept in memory (oldest are dropped)")

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) != 0 {
					return usageError(env, "serve", "unexpected argument %q", pos[0])
				}
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return usageError(env, "serve", "--addr must look like HOST:PORT, for example 127.0.0.1:7777 (%v)", err)
				}
				if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
					return usageError(env, "serve", "--addr port %q is not a number between 0 and 65535", port)
				}
				if keep < 1 || keep > 10_000 {
					return usageError(env, "serve", "--keep must be between 1 and 10000")
				}
				if err := server.Run(ctx, server.Config{Addr: addr, MaxUpload: maxUpload, Keep: keep, Stderr: env.Stderr}); err != nil {
					return failure(env, "serve", err)
				}
				return exitOK
			}
		},
	}
}

func mcpCommand() command {
	return command{
		name:    "mcp",
		summary: "Start the MCP server on stdio so AI agents can analyse files",
		long: `Speaks the Model Context Protocol (newline-delimited JSON-RPC on stdin/stdout)
and exposes the tools analyze_file, list_strings, hash_file, entropy_profile and
diff_files. Files are readable only below the --root directories (default: the
current directory); symlinks that escape, directories and devices are refused.
Nothing is ever executed. Logs go to stderr; stdout carries protocol messages only.`,
		examples: []string{
			"teardown mcp --root .",
			"teardown mcp --root ~/samples --root /tmp/downloads",
			"claude mcp add teardown -- teardown mcp --root .",
		},
		register: func(f *flagSet) runner {
			var roots []string
			f.Group("Access")
			f.List(&roots, "root", "", "DIR", "Directory files may be read from; repeat for several (default: the current directory)", true)

			return func(ctx context.Context, env Env, pos []string) int {
				if len(pos) != 0 {
					return usageError(env, "mcp", "unexpected argument %q", pos[0])
				}
				if err := mcp.Serve(ctx, env.Stdin, env.Stdout, mcp.Config{Roots: roots, Stderr: env.Stderr}); err != nil && ctx.Err() == nil {
					return failure(env, "mcp", err)
				}
				return exitOK
			}
		},
	}
}

func versionCommand() command {
	return command{
		name:    "version",
		summary: "Print version information",
		register: func(f *flagSet) runner {
			var asJSON bool
			f.Bool(&asJSON, "json", "", "Print JSON")
			return func(_ context.Context, env Env, pos []string) int {
				if len(pos) != 0 {
					return usageError(env, "version", "unexpected argument %q", pos[0])
				}
				info := version.Get()
				if asJSON {
					if err := writeJSON(env.Stdout, info); err != nil {
						return failure(env, "version", err)
					}
					return exitOK
				}
				line := "teardown " + info.Version
				if info.Commit != "" {
					line += " (" + shortCommit(info.Commit) + ")"
				}
				fmt.Fprintf(env.Stdout, "%s %s/%s %s\n", line, info.OS, info.Arch, info.Go)
				return exitOK
			}
		},
	}
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}
