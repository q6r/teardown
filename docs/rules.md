# Finding catalogue

<!-- Generated from internal/rules by `go test ./internal/rules -run TestCatalogDoc -update`. Do not edit by hand. -->

Every finding is `{id, title, severity, category, confidence, evidence[], limitations[]}`. A finding without evidence or without limitations is a bug (a test enforces both). Findings are leads for a human, not verdicts: each one states how it can be wrong.

Use the `id` to gate CI (`teardown analyze --fail-on high`) or to filter dashboards. IDs are stable; new ones may be added in later releases.

## Risk score

The score is deterministic and explained line by line in `risk.basis`:

1. Every finding earns `severity points x confidence factor`, rounded: info 0, low 4, medium 10, high 20, critical 40 points; confidence low x0.4, medium x0.7, high x1.0.
2. The points of one category are capped so a pile of weak signals in one area cannot outweigh independent evidence elsewhere: packing 30, structure 30, hardening 15, signature 6, indicators 20, application 30, build 0, privacy 6, file 30 (other categories 40).
3. The capped category totals are summed and limited to 100.
4. Label: low below 20, medium below 45, high below 70, critical from 70.

The score orders a review queue; it says nothing about intent.

## Thresholds

- High-entropy section: entropy >= 7.2 bits per byte on at least 1024 raw bytes (executable sections raise severity and confidence).
- High-entropy file without parsed sections: overall entropy >= 7.5.
- Zip bomb: declared total >= 1.0 GiB with ratio >= 100:1, or a per-entry ratio >= 1000:1 with at least 100.0 MiB declared, or any overlapping entries.
- PE overlay: at least 4.0 KiB.

## Packing and packaging

| Finding | Severity | What it looks for |
|---|---|---|
| `packing.high-entropy-section` | low-medium | Executable sections of at least 1 KiB whose entropy is >= 7.2 bits per byte. |
| `packing.high-entropy-file` | low | An executable with no parsed sections whose overall entropy is >= 7.5. |
| `packing.upx` | medium | UPX packer markers (UPX0/UPX1 sections or the UPX! signature). |
| `packing.known-packer` | medium | PE section names used by known packers and protectors (ASPack, Themida, VMProtect, MPRESS, ...). |
| `packaging.pyinstaller` | info | PyInstaller bundle cookie: a Python application packaged as a native executable. |

## File structure

| Finding | Severity | What it looks for |
|---|---|---|
| `structure.rwx-section` | medium | Sections that are both writable and executable. |
| `structure.rwx-segment` | medium | ELF program headers that map memory writable and executable. |
| `structure.suspicious-section` | low | Sections the format parser flagged for a structural reason other than RWX (odd name, empty executable section, huge virtual size). |
| `structure.entry-point-anomaly` | low-medium | PE entry point outside every section, in a non-executable section, or in the last section. |
| `structure.overlay` | info-low | Data appended after the end of the PE image (overlay) of at least 4 KiB. |
| `structure.timestamp-anomaly` | info | PE link timestamp in the future or before the format existed. |
| `structure.insecure-rpath` | low | ELF RPATH/RUNPATH entries that are relative or point into world-writable locations. |

## Hardening

| Finding | Severity | What it looks for |
|---|---|---|
| `hardening.no-aslr`<br>`hardening.no-canary`<br>`hardening.no-cfg`<br>`hardening.no-dep`<br>`hardening.no-fortify`<br>`hardening.no-high-entropy-va`<br>`hardening.no-nx`<br>`hardening.no-pie`<br>`hardening.no-relro`<br>`hardening.no-seh-protection`<br>`hardening.partial-relro` | info-medium | A mitigation the format parser reported as disabled (ASLR, DEP, PIE, NX, RELRO, stack canary, SafeSEH, CFG, ...); partial RELRO is reported at info level. |

## Signatures

| Finding | Severity | What it looks for |
|---|---|---|
| `signature.unsigned` | low | No Authenticode signature (PE), code signature (Mach-O) or APK signature was found. |

## Imports

| Finding | Severity | What it looks for |
|---|---|---|
| `imports.process-injection` | medium-high | Imports covering at least two stages of remote memory allocation, writing and thread/APC execution. |
| `imports.keylogging` | medium | Keyboard hooks or key-state polling combined with window-context APIs. |
| `imports.anti-debug` | low-medium | Two or more debugger-detection APIs. |
| `imports.crypto` | info | Two or more cryptographic APIs (CryptoAPI, CNG, OpenSSL). |
| `imports.networking` | info | Two or more networking APIs (sockets, WinINet, WinHTTP). |
| `imports.download-and-execute` | medium | URLDownloadToFile-style download APIs together with process-launch APIs. |
| `imports.service-manipulation` | low | Service-control-manager APIs that create or reconfigure services. |
| `imports.token-privileges` | low | Access-token and privilege manipulation APIs. |
| `imports.minimal-import-table` | low | A PE whose import table holds almost nothing but LoadLibrary/GetProcAddress. |
| `imports.reverse-shell-pattern` | medium | socket + connect + dup2 + exec-family imports in a Unix executable. |

## Secrets

| Finding | Severity | What it looks for |
|---|---|---|
| `secrets.aws-access-key-id`<br>`secrets.github-token`<br>`secrets.jwt`<br>`secrets.pem-private-key`<br>`secrets.slack-token`<br>`secrets.unclassified` | medium-high | Strings that match credential formats (AWS access key IDs, GitHub and Slack tokens, PEM private key headers, JWTs). Values are redacted everywhere. |

## Indicators in strings

| Finding | Severity | What it looks for |
|---|---|---|
| `indicators.network` | info-low | Hard-coded URLs, public IP addresses, domains and e-mail addresses. |
| `indicators.suspicious-commands` | low-medium | Embedded shell, PowerShell and living-off-the-land command lines. |
| `indicators.persistence-registry` | low | Registry paths used for autostart, logon hooks and image hijacking. |

## Archives

| Finding | Severity | What it looks for |
|---|---|---|
| `archive.zip-slip` | high | Entry names with parent-directory segments, absolute paths, drive letters or UNC prefixes. |
| `archive.zip-bomb` | medium-high | Declared sizes or overlapping entries consistent with a decompression bomb. |
| `archive.nested-archives` | info | Archives, packages or executables stored inside the archive. |
| `archive.encrypted-entries` | low | Password-protected entries whose contents cannot be inspected. |
| `archive.duplicate-names` | low | Several entries with the same name (ambiguous extraction). |

## Applications

| Finding | Severity | What it looks for |
|---|---|---|
| `android.sensitive-permissions` | info-medium | Sensitive Android permissions recovered heuristically from the manifest string pool. |
| `application.electron-app` | info | An Electron ASAR archive: package name, version, main script and Electron version. |
| `application.electron-risky-settings` | low | Textual hints in bundled JavaScript for Electron settings such as nodeIntegration: true or contextIsolation: false (evidence only). |

## Build metadata

| Finding | Severity | What it looks for |
|---|---|---|
| `build.go-vcs` | info | A Go binary that embeds version-control revision, time and dirty-tree state. |

## Privacy

| Finding | Severity | What it looks for |
|---|---|---|
| `privacy.pdb-path` | low | A PDB debug path embedded in a PE, which can leak the build machine's directory layout and user name. |

## File name and type

| Finding | Severity | What it looks for |
|---|---|---|
| `file.type-mismatch` | medium | A file name with a document, image or media extension whose content is an executable or package. |
| `file.double-extension` | medium | A name such as invoice.pdf.exe that hides a launchable extension behind a document one. |

## Added by the analyzer

| Finding | Severity | When |
|---|---|---|
| `parser.error` | low | A format parser failed or panicked; results for that format are incomplete. |
| `parser.warning` | info | A parser recovered from malformed structures and lists what it skipped. |
| `analysis.incomplete` | low | The analysis deadline was reached before every stage finished. |
