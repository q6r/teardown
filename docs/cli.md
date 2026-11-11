# Command-line reference

```text
teardown <command> [flags] [arguments]
```

Every command has `--help` with its flags and examples. The help text, the shell completion
scripts and this page all describe the same command table.

| Command | What it does |
|---|---|
| [`analyze`](#analyze) | One file: type, hashes, entropy, structure, strings, findings and risk |
| [`strings`](#strings) | The strings of a file, classified (URLs, IPs, paths, commands, secrets, ...) |
| [`hash`](#hash) | MD5, SHA-1 and SHA-256 of files, plus the PE import hash and entropy |
| [`diff`](#diff) | Compare two files: sections, imports, strings, hardening, findings, risk |
| [`serve`](#serve) | HTTP API and web dashboard, loopback only by default ([HTTP API](api/http.md)) |
| [`mcp`](#mcp) | MCP server on stdio for AI agents ([MCP guide](mcp.md)) |
| [`completion`](#completion) | Shell completion script for bash, zsh, fish or PowerShell |
| `version` | Version, Go version, OS and architecture (`--json` for machines) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The command failed (file not found, unreadable, analysis error, interrupted) |
| 2 | Usage error: wrong flags or arguments; the message names the fix |
| 3 | `analyze --fail-on <severity>`: a finding at or above that severity exists |

## Environment

| Variable | Effect |
|---|---|
| `NO_COLOR` | Any non-empty value disables colour ([no-color.org](https://no-color.org)) |
| `TEARDOWN_ASCII` | Any non-empty value replaces unicode bars and symbols with ASCII |
| `COLUMNS` | Line width of the human output (default 100) |

Colour is on when stdout is a terminal; `--color always|never|auto` overrides it.

## analyze

```text
teardown analyze <file> [flags]
```

| Flag | Meaning |
|---|---|
| `--json` | The full report as JSON, schema `teardown.report/v1` ([reference](api/schema.md)) |
| `--md` | The report as Markdown |
| `--sarif` | The findings as SARIF 2.1.0 for code-scanning dashboards ([details](#sarif)) |
| `--html FILE` | A self-contained HTML report written to `FILE` ([details](#the-html-report)) |
| `-o, --output FILE` | Write to `FILE` instead of stdout (not with `--html`) |
| `--color WHEN` | `auto`, `always` or `never` |
| `--ascii` | ASCII bars and symbols |
| `-v, --verbose` | Show the risk arithmetic, all evidence and all limitations |
| `--width N` | Line width of the terminal output |
| `--min-string N` | Minimum string length (default 5, 1 to 4096) |
| `--max-strings N` | String items kept in the report (default 2000, up to 1,000,000) |
| `--timeout DURATION` | Give up after this long (default 1m) |
| `--fail-on SEVERITY` | Exit 3 when a finding of at least this severity exists: `info`, `low`, `medium`, `high`, `critical` |

`--json`, `--md`, `--sarif` and `--html` are mutually exclusive. The gate prints what tripped it on stderr:

```console
$ teardown analyze examples/samples/upx-like.exe --fail-on high    # medium findings only: exit 0
$ teardown analyze examples/samples/upx-like.exe --fail-on medium > /dev/null
teardown analyze: --fail-on medium: 2 finding(s) at or above medium: packing.upx (medium), structure.rwx-section (medium)
$ echo $?
3
```

[`examples/ci-gate.sh`](../examples/ci-gate.sh) and [`examples/ci-gate.ps1`](../examples/ci-gate.ps1)
wrap this for a CI job.

### The HTML report

`--html report.html` writes one file that opens from disk, offline: the Aurora UI kit (styles and
scripts), the layout and report page that the web dashboard uses (a navigation rail, a top bar, section
tabs as `#fragment` links and a status bar), and the report itself as an inert JSON island.
It makes no network request, and a Content-Security-Policy `<meta>` tag forbids any. With scripting
disabled the page falls back to a plain readable summary. Hostile file names and strings cannot
break out of the island: `<`, `>`, `&`, U+2028, U+2029 and invisible format characters (such as a
right-to-left override) are escaped as JSON unicode escapes.

### SARIF

`--sarif` prints the findings as a SARIF 2.1.0 log, the interchange format of code-scanning tools (GitHub
code scanning reads it through its `upload-sarif` action). Each distinct finding id becomes a rule, each
finding a result attached to the analysed file by base name, and the severity maps to the SARIF level:
critical and high are errors, medium is a warning, low and info are notes. Evidence, confidence and
limitations travel in the result's `properties`. Tests cover the structure of the log; it has not been
checked against the official SARIF schema validator or uploaded to a code-scanning service.

```console
$ teardown analyze examples/samples/upx-like.exe --sarif -o app.sarif
```

## strings

```text
teardown strings <file> [flags]
```

| Flag | Meaning |
|---|---|
| `-c, --category LIST` | Only these categories, comma separated: `secret`, `url`, `email`, `ip`, `registry`, `command`, `useragent`, `path`, `domain`, `api`, `base64`, `hex`, `plain` |
| `-n, --min N` | Minimum string length (default 5) |
| `--max N` | Maximum strings to extract (default 20000); classified strings are kept first |
| `--json` | JSON instead of one string per line |
| `-o, --output FILE` | Write to `FILE` |

Secrets (AWS access key IDs, GitHub and Slack tokens, PEM private key headers, JWTs) are never
printed in full: the first four characters and the length are kept.

```console
$ teardown strings dropper.bin --category url,ip,secret,command
0x00000e00 a url       https://update.example.test/gate.php
0x00000e25 a url       http://198.51.100.23:8080/beacon
0x00000e46 a ip        203.0.113.7
0x00000e63 a command   cmd.exe /c whoami /all
0x00000e7a a command   powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
0x00000f5e a secret    AKIA…(20 chars)
0x00000f73 a secret    ghp_…(40 chars)
7 of 93 strings shown (minimum length 5, list truncated: raise --max-strings or narrow with --category)
```

(`dropper.bin` is generated by `go run ./examples/gensamples -dropper`; it is a harmless file that
only looks like a dropper to a static scanner.) The column after the offset is the encoding:
`a` for ASCII, `u` for UTF-16LE.

## hash

```text
teardown hash <file>... [flags]
```

Digests and entropy in one pass per file; PE files add the import hash. `--json` prints one object
for one file and an array for several.

```console
$ teardown hash examples/samples/hello.exe examples/samples/upx-like.exe
hello.exe  2.0 KiB · PE32+ executable for Windows (x86-64, console)
  md5      6951e556ec33f990b7285ac0e55f656c
  sha1     6c822f5535a50a6f2dbadfec79c0eb469181d50d
  sha256   6d3bd25d10c80d4c64ea8419f1bcf82dec72c8ea6c71cfe3be33a1a29d2f9fa5
  imphash  ddb7af50933d415b075f5644747fcaed
  entropy  ███████░░░░░░░░░░░░░░░░░ 2.21
upx-like.exe  4.5 KiB · PE32+ executable for Windows (x86-64, console)
  md5      5e29588c93216679780cbf11abc9a3ae
  sha1     255349854c4bbf6f34f3ea5e95c458b74203f28b
  sha256   118218b6f8fdf30ae055ff248bf64fa3e155c3b4ec34aaadaae97b266fca3d21
  imphash  f9ade0aa18f660a34a4fa23392e21838
  entropy  ███░░░░░░░░░░░░░░░░░░░░░ 1.01
```

## diff

```text
teardown diff <a> <b> [flags]
```

Analyses both files and reports what changed from `a` to `b`. `--json` prints the comparison
(schema `teardown.diff/v1`).

```console
$ teardown diff examples/samples/hello.exe examples/samples/upx-like.exe
teardown diff

a  hello.exe  2.0 KiB · PE32+ executable for Windows (x86-64, console) · risk 8
   sha256 6d3bd25d10c80d4c64ea8419f1bcf82dec72c8ea6c71cfe3be33a1a29d2f9fa5
b  upx-like.exe  4.5 KiB · PE32+ executable for Windows (x86-64, console) · risk 27
   sha256 118218b6f8fdf30ae055ff248bf64fa3e155c3b4ec34aaadaae97b266fca3d21

── Summary
  · SHA-256 differs
  · size 2048 -> 4608 bytes (+2560)
  · tags added: upx
  · import hash changed: the import table differs
  · 2 section(s) added: UPX0, UPX1
  · section .rdata entropy 2.33 -> 0.62
  · imports: +0 -3 functions
  · strings: +1 new, -5 gone
  · new finding packing.upx (medium)
  · new finding structure.rwx-section (medium)
  · new finding structure.suspicious-section (low)
  · finding gone privacy.pdb-path (low)
  · risk 8 (low) -> 27 (medium), +19
  ...
```

(The output continues with the added sections, findings, removed imports and new strings.)

## serve

```text
teardown serve [--addr HOST:PORT] [--max-upload SIZE] [--keep N]
```

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:7777` | Address to listen on; anything but loopback prints a warning |
| `--max-upload` | `256MiB` | Largest accepted upload (`64MiB`, `1GiB`, ...) |
| `--keep` | `50` | Analyses kept in memory; the oldest is dropped first (at most 10000) |

Serves the dashboard at `/` and the JSON API under `/api`. The full reference, the security model
and the limits are in [api/http.md](api/http.md).

## mcp

```text
teardown mcp [--root DIR]...
```

Newline-delimited JSON-RPC on stdin and stdout; logs go to stderr. Files are readable only below
the `--root` directories (default: the current directory). Setup for Claude Desktop and Claude
Code is in the [MCP guide](mcp.md).

## completion

```text
teardown completion <bash|zsh|fish|powershell>
```

| Shell | Install |
|---|---|
| bash | `source <(teardown completion bash)` |
| zsh | `teardown completion zsh > "${fpath[1]}/_teardown"` |
| fish | `teardown completion fish > ~/.config/fish/completions/teardown.fish` |
| PowerShell | `teardown completion powershell \| Out-String \| Invoke-Expression` (add to `$PROFILE` to keep it) |
