# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). The report schema (`teardown.report/v1`) is additive-only.

## [Unreleased]

### Changed

- The dashboard and the single-file HTML report moved to Aurora 2.0, the bundled UI kit: a navigation
  rail, a top bar with breadcrumbs, search and the live indicator, a sub bar with tab pills, flat cards
  on one ground and a status bar, in the Prism Classic palette (Prism Daylight in the light theme).
- Home page: a hero with the drop zone, and one list of recent analyses that replaces the table and the
  live feed. It can be filtered by name or type and ordered by age or by risk, and it updates live:
  an analysis from another client shows up as "Analysing" and then with its risk.
- Report page: the sections stack at full width, the section links became tab pills in the sub bar
  (with their counts, following the scroll) and the risk, size and type sit in pills at its right.
  In the exported file the pills are `#fragment` links, so they work from disk.
- The exported report grows to about 240 KB, because the page now carries the whole layout kit.

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
