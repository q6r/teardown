# Schema reference: `teardown.report/v1`

One analysis produces one JSON document. The same document comes out of every surface:
`teardown analyze --json`, `GET /api/analyses/{id}` (and the `report` field of
`POST /api/analyze`), the `analyze_file` MCP tool, the JSON island inside `analyze --html`,
and the Go type `report.Report` in `internal/report`.

## Conventions

- Keys are `camelCase`. Timestamps are RFC 3339 in UTC. Sizes are bytes.
- The schema is **additive-only**: a later release may add keys, but an existing key never
  changes type or meaning. Consumers should ignore keys they do not know.
- Collections are never `null`: an empty list is `[]` and an empty map is `{}`.
- `file.name` is the base name only, never a directory, so a document is safe to share.
- Anything that came out of the analysed file (names, strings, evidence) is untrusted text.
  Render it as text, never as markup.
- Secrets are redacted before they reach the document: the first four characters and the length
  are kept (`AKIA…(20 chars)`), the middle is gone.

## Top level

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | Always `teardown.report/v1` |
| `tool` | object | `{name, version}` of the program that produced the document |
| `generatedAt` | string | When the analysis finished |
| `durationMs` | integer | How long the analysis took |
| `file` | object | `{name, size}` of the analysed input |
| `type` | object | The detected content type |
| `hashes` | object | MD5, SHA-1, SHA-256 and the PE import hash |
| `entropy` | object | Overall Shannon entropy plus a windowed profile |
| `sections` | array | Sections or segments of an executable, or the top-level parts of a container |
| `imports` | array | Imported libraries and functions |
| `exports` | array | Exported names |
| `strings` | object | Extracted and classified strings |
| `hardening` | array | Exploit-mitigation and integrity features |
| `details` | object | Format-specific facts, keyed by format (see [Details](#details)) |
| `findings` | array | Conclusions, each with evidence and limitations |
| `risk` | object | The deterministic 0-100 triage score and its arithmetic |
| `limitations` | array | What this analysis could not see; the first entry is always the static-only note |

## `type`

| Key | Meaning |
|---|---|
| `id` | Stable token: `pe`, `dos`, `elf`, `macho`, `macho-fat`, `class`, `dex`, `wasm`, `pyc`, `luac`, `zip`, `jar`, `apk`, `aab`, `docx`, `xlsx`, `pptx`, `odf`, `epub`, `nupkg`, `wheel`, `vsix`, `asar`, `pdf`, `rtf`, `ole`, `sqlite`, `gzip`, `bzip2`, `xz`, `zstd`, `7z`, `rar`, `tar`, `png`, `jpeg`, `gif`, `webp`, `gguf`, `safetensors`, `script`, `text`, `data` |
| `family` | `executable`, `bytecode`, `archive`, `package`, `document`, `image`, `database`, `model`, `script`, `text` or `data` |
| `label` | Human-readable description, for example `PE32+ executable for Windows (x86-64, console)` |
| `mime` | Closest media type, `application/octet-stream` when unknown |
| `confidence` | `low`, `medium` or `high` |
| `tags` | Extra facts: `dll`, `dotnet`, `upx`, `go`, `64-bit`, `java-21`, ... |

## `hashes`

`md5`, `sha1`, `sha256` are lower-case hex. `imphash` is the PE import hash, or `""` when the
file has no PE import table. MD5 and SHA-1 are reported for compatibility with threat-intel
tooling; they are not used for any security decision.

## `entropy`

| Key | Meaning |
|---|---|
| `overall` | Shannon entropy of the whole file, 0 to 8 bits per byte |
| `windowSize` | Bytes per window (every window except possibly the last) |
| `windows` | Entropy of each window, at most 512 values. The value at index `i` covers the bytes from `i * windowSize` |

Values near 8 mean compressed or encrypted data. The packing rules fire from 7.2 for sections
(see [rules](../rules.md)).

## `sections`

| Key | Meaning |
|---|---|
| `name` | Section name (printable form) |
| `virtualSize`, `rawSize`, `offset` | Sizes in memory and in the file, and the file offset |
| `entropy` | Entropy of the section's raw bytes |
| `flags` | A subset of `R`, `W`, `X`, in that order |
| `suspicious` | `true` when a section heuristic fired |
| `reasons` | Why, one string per heuristic (omitted when empty) |

## `imports` and `exports`

Each import is `{library, count, functions}`. `count` is the true number of imported functions
even when `functions` was capped. Imports the format does not attribute to a library use the
library name `(unspecified)`. `exports` is a list of names.

## `strings`

| Key | Meaning |
|---|---|
| `total` | Strings found; can exceed `items.length` |
| `minLength` | Minimum length used (default 5) |
| `truncated` | `true` when `items` does not hold every string found; classified strings are kept first |
| `byCategory` | Count per category over everything found |
| `items` | `{value, offset, encoding, category, redacted, kind?}`, ordered by file offset |

Categories: `secret`, `url`, `email`, `ip`, `registry`, `command`, `useragent`, `path`,
`domain`, `api`, `base64`, `hex`, `plain`. `encoding` is `ascii` or `utf16le`. For `secret`
items `value` is the redacted form, `redacted` is `true` and `kind` names the pattern
(`aws-access-key-id`, `github-token`, `slack-token`, `pem-private-key`, `jwt`, ...).

## `hardening`

`{id, label, status, detail}`. `status` is `enabled`, `disabled`, `unknown` or `n/a`.
Identifiers: `aslr`, `high-entropy-va`, `dep`, `cfg`, `seh`, `force-integrity` (PE); `signed`
(an Authenticode or macOS code signature is present, not verified); `pie` (ELF and Mach-O);
`nx`, `relro`, `canary`, `fortify` (ELF); `encrypted` (Mach-O). A disabled mitigation describes how hard the file is to exploit, not whether it is malicious.

## `findings`

| Key | Meaning |
|---|---|
| `id` | Stable dotted identifier such as `packing.upx` or `hardening.no-aslr` |
| `title` | One-line description |
| `severity` | `info`, `low`, `medium`, `high` or `critical` |
| `category` | `packing`, `structure`, `hardening`, `imports`, `secrets`, `archive`, `signature`, `privacy`, `build`, `indicators`, `application`, `parser` or `file` |
| `confidence` | How sure the engine is that the evidence supports the title: `low`, `medium`, `high` |
| `evidence` | What was seen, one string per observation |
| `limitations` | How the finding can be wrong or incomplete; never empty |

Findings are sorted by severity, highest first. The full catalogue is in [rules.md](../rules.md).
Use `id` and `severity` to gate CI (`teardown analyze --fail-on high`).

## `risk`

`{score, label, basis}`. `score` is 0 to 100, `label` is `low` (below 20), `medium` (below 45),
`high` (below 70) or `critical`. `basis` lists, line by line, how the score was computed. The score
orders a review queue; it is not a verdict.

## Details

`details` holds one object per format that has a parser. Keys are camelCase; the lists below
name the facts, and a format may add keys over time.

| Key | Present for | Contents |
|---|---|---|
| `pe` | PE files | `kind` (exe, dll, driver), `machine`, `bits`, `subsystem`, `subsystemVersion`, `osVersion`, `linkerVersion`, `timestamp`, `timestampRaw`, `entryPoint`, `entrySection`, `imageBase`, `sizeOfImage`, `checksum`, `characteristics`, `dllCharacteristics`, `signed`, `signatureType`, `signatureSize`, `overlaySize`, `pdbPath`, `pdbGuid`, `pdbAge`, `reproducible`, `securityCookie`, `tlsCallbacks`, `importCount`, `delayImportLibraries`, `exportCount`, `exportName`, `dotNet`, `dotNetVersion`, `dotNetFlags`, `packerHints` |
| `elf` | ELF files | `class`, `endian`, `osAbi`, `abiVersion`, `type`, `machine`, `entry`, `linking`, `interpreter`, `needed`, `soname`, `rpath`, `runpath`, `buildId`, `stripped`, `hasDebugInfo`, `sectionCount`, `segmentCount`, `segments` (`{type, flags, offset, vaddr, fileSize, memSize}`), `rwxSegments`, `symbolCount`, `dynamicSymbolCount`, `importCount`, `exportCount` |
| `macho` | Mach-O and fat binaries | `fat`, `primarySlice`, `slices` (one per architecture: `cpu`, `type`, `bits`, `endian`, `flags`, `dylibs`, `rpaths`, `installName`, `uuid`, `signed`, `encrypted`, `platform`, `minOS`, `sdk`, `entryOffset`, `segments`, `loadCommands`, `symbolCount`, `error`), `importCount`, `exportCount` |
| `go` | PE, ELF and Mach-O built with Go | `goVersion`, `path`, `main`, `deps` (`{path, version, sum, replace}`), `depCount`, `buildMode`, `compiler`, `cgo`, `goos`, `goarch`, `trimpath`, `vcs` (`system`, `revision`, `time`, `modified`), `settings`, `flags` |
| `archive` | ZIP and ZIP-based formats (JAR, APK, AAB, Office, ODF, EPUB, NuGet, wheel, VSIX) | `kind`, `entryCount`, `entries` (`{name, size, compressedSize, method, dir, encrypted}`), `entriesTruncated`, `totalCompressed`, `totalUncompressed`, `ratio`, `maxRatio`, `maxRatioEntry`, `signed`, `encryptedEntries`, `duplicateNames`, `overlappingEntries`, `unsafeCount`, `unsafeNames`, `nested`, `nestedCount`, `classCount`, `comment`, `prefixBytes`, `recovered`, `manifest`, and for APK and AAB an `android` object (`permissions`, `permissionsHeuristic`, `abis`, `dexFiles`, `nativeLibs`, `hasResourcesArsc`, `manifestPresent`, `signingBlock`) |
| `asar` | Electron ASAR archives | `headerSize`, `dataOffset`, `fileCount`, `directoryCount`, `unpackedCount`, `totalSize`, `files`, `filesTruncated`, `package` (the application's `package.json` facts), `hints` (`{id, evidence}` for risky Electron settings) |
| `wasm` | WebAssembly modules | `kind`, `version`, `sectionCount`, `typeCount`, `functionCount`, `importCount`, `exportCount`, `globals`, `tables`, `memories`, `dataSegments`, `elementSegments`, `start`, `customSections`, `hasNameSection`, `features`, `producers` |
| `gguf` | GGUF model files | `version`, `tensorCount`, `kvCount`, `architecture`, `name`, `contextLength`, `fileType`, `fileTypeName`, `quantizationVersion`, `alignment`, `tokenizerModel`, `license`, `author`, `sizeLabel`, `parameterCount`, `tensorTypes`, `tensors`, `tensorsTruncated`, `metadata`, `metadataTruncated`, `headerSize`, `dataOffset` |

Types that are only recognised (safetensors, SQLite, PDF, images, compression formats, ...) have
no `details` entry. Their documents still carry the hashes, entropy, strings and the generic
rules, and `limitations` says that no format-specific parser exists.

Sections, imports, exports and hardening come from the PE, ELF, Mach-O and WebAssembly parsers.
