# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). The report schema (`teardown.report/v1`) is additive-only.

## [Unreleased]

### Added

- Code evidence: a finding can show the code behind it. `findings[].code` is a new optional list of blocks
  (kind `disasm`, `hex` or `source`; lines with address, file offset, bytes, text, note and a flagged line;
  `truncated`; `limitations`, never empty). The schema stays `teardown.report/v1`: the key is omitted when a
  finding has no code, so documents without it are unchanged. Blocks are bounded (12 per finding, 64 lines each,
  200 characters per line) and every renderer applies the caps again. See `docs/code-evidence.md`.
- An x86 and x86-64 decoder (`internal/disasm`), Intel syntax, written for this project with no third-party
  code: legacy prefixes, REX, ModRM and SIB (RIP-relative and absolute operands), the one-byte and two-byte opcode
  maps, x87, SSE to SSE4.2, AES-NI, SHA and BMI, and the correct length of VEX and EVEX encodings. Bytes it does
  not understand become `db 0xNN`. It never panics, never reads past its input and has a fuzz target.
- Two developer tests check the decoder against the Go toolchain (`TestOracle`, `TestOracleAsm`; they run only
  when `TEARDOWN_DISASM_ORACLE=1`, see the headers of `internal/disasm/oracle_test.go` and
  `oracle_asm_test.go`). Against `go tool objdump` over `cmd/gofmt` and `cmd/go` built for Windows on amd64 and
  386 they compare 4,318,469 instructions, agree on the length of all of them and fall back to `db` for none.
  The instructions that the Go toolchain itself cannot decode (AVX-512, for example), and those that follow them
  in the same function, are left out of that figure: 18,994 in the two amd64 programs. Against the encoding tests
  of the Go assembler the length agreement is 99.9914% for `amd64enc.s` (the one miss is `ud1`) and 100% for the
  other files.
- Call sites of imports for PE images, x86-64 and 32-bit (`internal/xref`): a bounded sweep of the executable
  sections finds the calls through the import address table, through import thunks and jumps through the slots,
  with the instructions around each. The import findings (process injection, keylogging, anti-debug, crypto,
  networking, download-and-execute, service manipulation, token privileges and the minimal import table) attach
  them: up to 6 call sites per function and 12 blocks per finding, with an evidence line that counts them and a
  limitation that names the functions that have none. ELF and Mach-O call sites are not implemented; 32-bit PE
  images are tested only with a hand-made image.
- Hex windows behind the findings made from strings (`secrets.*`, `indicators.network`,
  `indicators.suspicious-commands`, `indicators.persistence-registry`), with every byte of a credential masked
  (`2a` in the hex column, `*` in the ASCII column), and source lines with line numbers and three lines of
  context for the strings that sit in text entries of ASAR archives, stored ZIP entries and text files, and for
  `application.electron-risky-settings`. Deflated ZIP entries are not scanned, so they give no source lines.
- `teardown hexdump`, `teardown disasm` and `teardown xrefs`: a hex and ASCII window at a file offset, the
  instructions at an address, an offset or the entry point (PE, ELF, Mach-O and raw bytes), and the call sites of
  one import or the list of called imports. Each has `--json`; they are bounded (4096 bytes, 256 instructions,
  100 call sites) and exit 2 on bad flags and 1 on a request the file cannot serve.
- `analyze` prints the first 3 code blocks of each finding, 24 lines each; `--code-all` prints them all and
  `--no-code` leaves the code out of every output (terminal, JSON, Markdown, SARIF, HTML).
- MCP tools `read_bytes`, `disassemble` and `find_calls` (the server now offers eight), with the same roots,
  size limits and output trimming as the others. `analyze_file` keeps its summary small by trimming the code to
  the first 3 blocks of each finding and the 24 lines around the flagged one.
- A Code panel inside each finding of the dashboard and of the single-file HTML report: monospace tables with
  address, bytes, instruction and note columns, the flagged line marked, a Copy button, a notice for a block
  shown in part, the limitations once per finding, and the same panel in the light and dark themes. The Markdown
  report shows each block as a fenced listing and SARIF carries the flagged line of the first five blocks of each
  finding.
- OpenAPI: the `Finding.code` field with the `CodeBlock`, `CodeLine` and `CodeAddress` schemas.
- `go run ./examples/gensamples -dropper` writes `dropper.bin`, a harmless PE whose imports cover the
  process-injection chain and whose code calls them the way compilers do, for trying all of the above. It is
  generated on demand and not committed, because antivirus products may flag a file that imports those functions.

### Changed

- Import findings of PE images gain an evidence line (`code: 4 call sites in .text (see the code blocks)`) and,
  when the functions that triggered them are never called, a limitation that says so.
- The documentation no longer says that teardown cannot disassemble: it has a small decoder for code evidence,
  and still no decompiler, emulator or unpacker.
- The dashboard and the single-file HTML report moved to Aurora 2.0, the bundled UI kit: a navigation
  rail, a top bar with breadcrumbs, search and the live indicator, a sub bar with tab pills, flat cards
  on one ground and a status bar, in the Prism Classic palette (Prism Daylight in the light theme).
- Home page: a hero with the drop zone, and one list of recent analyses that replaces the table and the
  live feed. It can be filtered by name or type and ordered by age or by risk, and it updates live:
  an analysis from another client shows up as "Analysing" and then with its risk.
- Report page: the sections stack at full width, the section links became tab pills in the sub bar
  (with their counts, following the scroll) and the risk, size and type sit in pills at its right.
  In the exported file the pills are `#fragment` links, so they work from disk.
- The exported report grows to about 260 KB, because the page now carries the whole layout kit and the Code panel.
- Output files named with `-o`, `--json`, `--md` or `--html` are created readable by their owner only
  (mode 0600): a report quotes what was found in the analysed file.

### Fixed

- Strings: the base64 body lines of a private key written over several lines (a PEM block) were listed as
  plain strings in `strings.items`, in the JSON and the HTML report, next to the redacted header. The scanner now
  follows the key from its header, in ASCII and in UTF-16LE, and drops its body lines (up to 256 lines, until
  the END marker or the first line that is not base64).
- MCP: a path that named a place inside a root by another name was refused as outside the roots: through
  a symbolic link above it (`/var` against `/private/var` on macOS) or, on Windows, through an 8.3 short
  name (`RUNNER~1` against `runneradmin`) or another letter case. Such paths are now matched in their
  resolved form. Containment is unchanged (the read still goes through `os.Root`), and a path on a
  Windows volume that no root is on, such as a `\\host\share` path, is refused without being looked up.
- Server: stopping it while a browser held a spare connection that never sent a request waited more than
  five seconds, because `net/http` counts such a connection as busy until it is that old. These
  connections are now closed when the shutdown starts; requests in flight still get the grace period.
- Server: an uploaded file name cut to 255 bytes could be left as nothing but dots and spaces and was
  replaced by `upload.bin` only when it was sanitized a second time. The fallback now applies at once, so
  sanitizing a name twice gives the same result as once.

## [0.1.0] - 2026-11-10

First release.

### Added

- Single static binary, standard library only, with three surfaces: CLI, HTTP API with an embedded
  dashboard, and an MCP server over stdio.
- `teardown analyze` (human, `--json`, `--md`, `--html`), `strings`, `hash`, `diff`, `serve`, `mcp`,
  `version` and `completion` (bash, zsh, fish, PowerShell); exit codes 0/1/2 and 3 for `--fail-on`.
- Content-type detection by magic bytes and structure: PE (EXE, DLL, driver, .NET), ELF, Mach-O (incl.
  fat), Java class, Python bytecode, ZIP family by content (JAR, APK, AAB, Office, ODF, EPUB, NuGet,
  wheel, VSIX), ASAR, WebAssembly, PDF, SQLite, compression formats, images, GGUF, safetensors, scripts.
- One-pass MD5, SHA-1, SHA-256, PE imphash, Shannon entropy and a windowed entropy profile.
- String extraction (ASCII and UTF-16LE) with classification (URL, domain, IP, e-mail, path, registry,
  command, base64, hex, API, user agent) and secret detection with redaction in every output.
- Format parsers: PE (sections, imports, exports, PDB path, Authenticode presence, overlay, hardening),
  ELF (built-in checksec), Mach-O (incl. fat), Go build information, ZIP/JAR/APK/AAB (zip-slip and bomb
  heuristics, manifest facts, heuristic Android permissions), ASAR/Electron, WebAssembly and GGUF
  headers. Types that are only recognised (safetensors, SQLite, PDF, images, ...) get the generic
  analysis and a report limitation that says no format-specific parser exists.
- Findings engine with a documented, deterministic 0-100 risk score (`docs/rules.md`).
- HTTP API: analyze, list, get, delete, paginated strings, server-sent events, OpenAPI 3.1 document.
- Web dashboard (Aurora UI kit, offline, light and dark): drop a file anywhere on the page with
  upload progress, recent analyses, a live feed of every client's analyses, the report page (risk ring and
  arithmetic, hashes with copy buttons, findings with evidence and limitations, hardening, entropy
  profile, sections, imports with cited functions highlighted, strings with search and filters, format
  details) and a command palette.
- `analyze --sarif`: the findings as a SARIF 2.1.0 log for code-scanning dashboards.
- Single-file HTML report (`analyze --html`) built from the same report view: opens offline from disk,
  escapes hostile names and strings in its JSON island, carries a Content-Security-Policy that allows no
  network access, and falls back to a plain summary without scripting.
- MCP tools: `analyze_file`, `list_strings`, `hash_file`, `entropy_profile`, `diff_files`.
- Native Go fuzz targets with seed corpora for the sniffer and every parser.

### Security

- The target is never executed. Parsers are bounded, cancellable and panic-safe; uploads go to a
  private temporary directory and are deleted right after analysis; the server binds to loopback by
  default with strict security headers, Host and Origin checks; MCP file access is confined to the
  configured roots.
