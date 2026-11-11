# Contributing

Thanks for helping. teardown is small on purpose: standard library only, one binary, static analysis
only. Changes that keep it that way are very welcome.

## Setup

```bash
git clone https://github.com/q6r/teardown && cd teardown
go version        # 1.24 or newer
make build        # bin/teardown (or: go build -o bin/teardown ./cmd/teardown)
make test         # go test ./... (offline, well under a minute)
```

No third-party modules are allowed: `go.mod` must keep zero `require` lines. Build tools such as
golangci-lint run in CI and are not dependencies of the module.

## Before you open a pull request

```bash
make fmt          # gofmt -w .
make vet          # go vet ./...
make lint         # golangci-lint (config in .golangci.yml)
make test         # unit tests
make race         # race detector, one package at a time (needs cgo; CI runs it on every push)
make fuzz FUZZTIME=20s   # every fuzz target, 20 seconds each
make web-check    # node --check on the dashboard scripts (only when you touched web/)
```

If you touch `internal/disasm`, also run the decoder oracle against the Go toolchain's disassembler; the
commands are in [docs/code-evidence.md](docs/code-evidence.md#how-it-was-checked).

The dashboard is built on the Aurora UI kit: `web/aurora.css`, `web/aurora.js` and `web/aurora-charts.js`
(zero dependencies, MIT, part of this repository). Project-specific styling and behaviour belong in
`web/app.css` and `web/app.js` (the dashboard), `web/report-view.*` (the report page, shared by the dashboard
and `analyze --html`) and `web/report-boot.js` (the exported file). The kit files are small and
dependency-free and may be edited with care. Keep the rules the tests enforce: text only (no `innerHTML`,
never markup built from data), no inline `style` attribute or inline script, colours only from the kit's
tokens (no raw hex in the project CSS or scripts) and no external requests.

CI also builds for several operating systems, runs `govulncheck` and checks the embedded dashboard assets.

## Project layout

```
cmd/teardown/        entry point (a dozen lines)
internal/analyze/    the pipeline: sniff -> one-pass hash/entropy/strings -> parser -> rules -> report
internal/report/     the teardown.report/v1 contract (leaf package)
internal/sniff/      content-type detection
internal/format/*/   one parser per format: pe, elf, macho, goinfo, archive, asar, wasm, gguf
internal/disasm/     x86 and x86-64 decoder; internal/hexdump/ bounded hex windows
internal/xref/       call sites of the imports of a PE image; internal/codeview/ windows behind disasm, hexdump and the MCP code tools
internal/rules/      findings engine and risk score (docs/rules.md is generated from it)
internal/server/     HTTP API; internal/mcp/ MCP over stdio; internal/cli/ subcommands
internal/testfixtures/  programmatic builders for tiny valid sample files
web/                 embedded dashboard, the Aurora UI kit and the report view that `analyze --html` inlines
```

## Adding a format parser

1. Create `internal/format/<name>` with `Parse(ctx, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error)`.
   Validate every count, offset and size against `size` before allocating, cap every list with
   `lim.MaxList`, poll `ctx.Err()` in loops, and return partial results plus `Notes` for malformed input.
2. Add a builder to `internal/testfixtures` and table-driven tests, including a "never panics" sweep
   (every prefix length, byte corruption) and a `FuzzParse` target with seed corpus.
3. Teach `internal/sniff` the magic bytes and wire the parser in `internal/analyze/parse.go`.
4. Document the new `details.<format>` keys in `docs/api/schema.md`.

## Adding a rule

Rules live in `internal/rules` and are pure functions of the report. Every finding needs evidence and
at least one limitation (a test enforces both). Register the rule in the catalogue, then run
`make rules-doc` to regenerate `docs/rules.md`; a test fails when the file is stale.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/): `feat(pe): parse delay-load imports`,
`fix(archive): reject overlapping local headers`, `docs: ...`, `test: ...`, `chore: ...`. Keep commits
focused and mention the user-visible effect in the body when it is not obvious.

## Security

Never add code that executes, loads or evaluates analysed content. Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).
