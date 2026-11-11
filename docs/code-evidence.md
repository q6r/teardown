# Code evidence

A finding says what teardown noticed. Code evidence shows the thing it noticed: the instructions around a
call to `VirtualAllocEx`, the bytes around a URL, the source lines of an Electron setting. It is for the
developer who wants to look at the real thing before deciding what a finding means.

It is a view of the code, not an analysis of it. teardown has a small x86 and x86-64 decoder, and that is all:
no decompiler, no emulator, nothing is ever executed, a block never changes a severity or the risk score, and
every block lists what it cannot show.

## The three kinds of block

A finding carries zero or more blocks in `findings[].code` ([schema](api/schema.md#findingscode)). Each block
has a `kind`:

| Kind | What it shows | Columns |
|---|---|---|
| `disasm` | x86 or x86-64 instructions in Intel syntax around a place in the code, decoded by the built-in decoder. The line the finding is about is flagged. | address, bytes, instruction, note (the import a call goes through) |
| `hex` | A window of raw bytes, 16 to a row, with the printable ASCII beside it. The rows that hold the string the finding is about are flagged. | file offset, bytes, ASCII |
| `source` | Lines of a text file, with their numbers and three lines of context on each side. The lines that match are flagged. | line number, text |

One of each, from the demo files (`dropper.bin` is generated on demand with
`go run ./examples/gensamples -dropper`; the others are in `examples/samples/`):

```text
call to KERNEL32.dll!VirtualAllocEx in .text  (.text · 0x1400010bd · x86-64)
    0x1400010d5  41 b8 00 10 00 00        mov r8d, 0x1000
    0x1400010db  41 b9 00 30 00 00        mov r9d, 0x3000
    0x1400010e1  c7 44 24 20 40 00 00 00  mov dword ptr [rsp+0x20], 0x40
  > 0x1400010e9  ff 15 b1 10 00 00        call qword ptr [rip+0x10b1]  ; KERNEL32.dll!VirtualAllocEx
    0x1400010ef  48 89 44 24 50           mov qword ptr [rsp+0x50], rax
```

```text
Bytes around the AWS access key ID at file offset 0xf5e (value masked)  (.config · file offset 0xf10)
    00000f40  69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65  |in64; x64) Apple|
  > 00000f50  57 65 62 4b 69 74 2f 35 33 37 2e 33 36 00 2a 2a  |WebKit/537.36.**|
  > 00000f60  2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a  |****************|
```

```text
Source lines for node-integration, context-isolation-disabled, web-security-disabled and 4 more  (main.js)
     5 |   const win = new BrowserWindow({
     6 |     webPreferences: {
  >  7 |       nodeIntegration: true,
  >  8 |       contextIsolation: false,
```

(The second and third examples are cut to a few rows; `electron.asar` is a sample of this repository.)
In the terminal a flagged line starts with `>`. In the dashboard it has an arrow and a tinted row, and the
arrow comes with a hidden label for screen readers, so the mark does not depend on colour.

## What each finding shows

| Finding | Block | What is in it |
|---|---|---|
| `imports.process-injection`, `imports.keylogging`, `imports.anti-debug`, `imports.crypto`, `imports.networking`, `imports.download-and-execute`, `imports.service-manipulation`, `imports.token-privileges`, `imports.minimal-import-table` | `disasm` | The call sites of the imported functions that triggered the finding, in PE images for x86-64 or x86: 8 instructions before the call, the call (flagged, with the import named in the note) and 4 after. At most 6 call sites per function and 12 blocks per finding, one call of every function before a second call of any, the function that matters most (for process injection: allocate, write, run) first. An evidence line says how many call sites there are and where, and a function with no call site is named in the limitations. |
| `secrets.*` | `hex` | A window of 64 bytes before and after the string, rounded out to whole rows, with the credential masked (see [Secrets](#secrets-and-hostile-text)). |
| `indicators.network`, `indicators.suspicious-commands`, `indicators.persistence-registry` | `hex` | The same window around the strings behind the finding, most telling first (URLs before public IP addresses, domains and e-mail addresses; command lines with download, encoding or hidden-execution patterns before the others), each distinct value once. Up to 8 strings per finding; windows that touch are merged into one block. |
| a string finding whose string sits in a text entry of an ASAR archive, in a stored ZIP entry or in a text file | `source` | The lines that hold the string instead of a hex window, in the entry that holds it (`file` names the entry). At most 6 blocks per finding. |
| `application.electron-risky-settings` | `source` | The lines of the bundled scripts of an ASAR archive that name the settings (`nodeIntegration: true`, `contextIsolation: false`, ...). |

Only the entries that hold plain text give source lines. teardown does not decompress archive entries, so the
text of a deflated ZIP entry is never scanned and no rule can point at it: **only stored (not deflated) ZIP
entries and ASAR entries produce source blocks.** An entry that is not text, or whose text is UTF-16, gets a
hex window.

`imports.reverse-shell-pattern` applies to Unix executables, whose call sites are not implemented (see
[What it does not show](#what-it-does-not-show)), so it carries no code. The other findings (hardening,
packing, structure, signatures, archives, privacy, file name and type) carry none either: there is no
single place in the file to show for them.

## Bounds

| What | Limit |
|---|---|
| Blocks per finding (every output) | 12 |
| Lines per block | 64 (a longer block keeps the window around its flagged line and says `truncated`) |
| Characters per line, per title, per note | 200 (a longer line is cut with an ellipsis; minified code is cut around the match) |
| Limitations per block | 8, of at most 400 characters |
| `analyze` in the terminal | the first 3 blocks of each finding, 24 lines each; `--code-all` shows every block in full, `--no-code` none |
| `analyze_file` over MCP (`summary` detail) | the first 3 blocks of each finding, 24 lines around the flagged one; `read_bytes`, `disassemble` and `find_calls` read any part of the file |
| Hex window around a string | 64 bytes on each side; at most 3 hex blocks per finding |
| Source lines | 3 lines of context on each side; at most the first 4 MiB of an entry is read; at most 8 lines of one match are flagged |
| `hexdump` and `read_bytes` | 4096 bytes per call (128 by default) |
| `disasm` and `disassemble` | 256 instructions per call (24 by default), never past the end of the section |
| `xrefs` and `find_calls` | 100 call sites per call (10 by default), 40 instructions before and 20 after each |
| The scan for call sites | 32 MiB of executable bytes per image, 16 MiB per section, 8 million instructions, 256 call sites kept per imported function (the true count is still reported). A scan that reaches a limit says so in the report's `limitations` and in a note of `xrefs`. |

Every renderer applies the block caps again to what it is given, so a report that came from somewhere else
cannot make an output grow without bound.

## What it does not show

- **x86 and x86-64 only.** Code for ARM64 and other instruction sets is not decoded; ARM64 comes later.
- **A linear sweep.** The decoder reads the bytes one after another. Data inside a code section can be shown
  as instructions, and one wrong byte can shift everything after it. Bytes it does not understand are shown
  as `db 0xNN` and the sweep goes on one byte later.
- **Call sites of imports, in PE images, through the import table.** A call is found when it goes through the
  import address table (`call qword ptr [rip+disp]`, `call dword ptr [abs]` in 32-bit code), through a thunk
  that jumps through it (one level), or as a jump through it. Functions a program resolves at run time
  (`GetProcAddress`, delay-load helpers) are invisible, and packed or protected files hide their real code.
- **PE only for call sites.** ELF (PLT and GOT) and Mach-O call sites are not implemented yet; ELF is the next
  step. `disasm` and `disassemble` do read ELF and Mach-O images (an address is mapped through the program
  headers or the section table, and a call through a PLT or GOT slot gets no import note), but only small
  generated files have tested that. 32-bit PE images are handled for call sites too, and have been tested only
  with a small hand-made image, not with the output of a real 32-bit compiler.
- **No decompiler, no emulator, no unpacking.** The code shows what is called, not why or in what order at
  run time.
- **No deflated ZIP entries** (see above).
- **No verdict.** A block does not call anything malicious and does not move the score. The risk arithmetic
  is the one in [rules.md](rules.md).

The same sentences, in the words of each block, are in its `limitations`; every output shows them.

## Secrets and hostile text

Secrets stay redacted in every output, and a window of raw bytes is an output:

- In a **hex window** every byte of every credential-like value is replaced by `2a` in the hex column and by
  `*` in the ASCII column, so no byte of the value can be recovered from either; what is left is the width of
  the run and the place it sits in. The masking applies to every window, not only to those of secret
  findings, because a credential can sit next to a URL or a command line. After a private-key header the key
  material follows and matches no pattern, so every printable byte from the header to the end of the region
  read is masked too.
- In **source lines** a credential is redacted as everywhere else (the first four characters and the length),
  and the lines of a private key body are replaced by a note that says how many characters were hidden.
- A last pass over the titles, file names and line text of every block redacts anything secret-looking that got
  there by another route.

Everything in a block comes from the analysed file, so it is untrusted: control characters, invalid UTF-8 and
invisible formatting characters are spelled out (`\x1b`, `[U+202E]`), tabs are expanded, and the dashboard shows
every part as text, never as markup.

## The decoder

`internal/disasm` decodes the legacy prefixes, REX, ModRM and SIB addressing (including RIP-relative operands
and absolute 32-bit operands), the whole one-byte opcode map, x87, the two-byte map with SSE and SSE2 and the
common SSE3 to SSE4.2, AES-NI, PCLMULQDQ, SHA and BMI instructions, and gives VEX and EVEX encodings their
correct length (the common AVX2, FMA and BMI forms also get a name). It is written from the architecture
manuals, never panics, never reads outside its input, never looks at more than 15 bytes of one instruction,
and has a fuzz target and table-driven tests with encodings checked by hand.

### How it was checked

The length of every instruction is what a linear sweep depends on: a wrong length means the sweep loses its
place. The Go toolchain ships a disassembler of its own, `go tool objdump`, which prints every instruction of
a Go executable with its bytes. A developer test compares the two over the whole code of real programs. It is
not part of `go test`: it runs only when asked, and it never executes the program, because `objdump` only
reads it.

Run it from the repository root. PowerShell:

```powershell
$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o $env:TEMP\oracle64.exe cmd/gofmt
Remove-Item Env:GOOS, Env:GOARCH
$env:TEARDOWN_DISASM_ORACLE = "1"
$env:TEARDOWN_DISASM_ORACLE_BIN = "$env:TEMP\oracle64.exe"
go test ./internal/disasm -run 'TestOracle$' -v -count=1
```

bash or zsh:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /tmp/oracle64.exe cmd/gofmt
TEARDOWN_DISASM_ORACLE=1 TEARDOWN_DISASM_ORACLE_BIN=/tmp/oracle64.exe \
  go test ./internal/disasm -run 'TestOracle$' -v -count=1
```

`GOARCH=386` with `TEARDOWN_DISASM_ORACLE_MODE=32` checks the 32-bit mode, and `cmd/go` makes a bigger
program than `cmd/gofmt`. The other variables (`TEARDOWN_DISASM_ORACLE_MIN`, `TEARDOWN_DISASM_ORACLE_SAMPLES`)
are described at the top of `internal/disasm/oracle_test.go`. This output is from `gofmt` built for
Windows on amd64 (Go 1.26.5):

```text
instructions compared:      360610
not compared:               644 instructions the toolchain prints as unknown (?), 80 it misreads (VEX or EVEX it does not know), 2462 that follow either in the same function
length agreement:           100.0000% (360610 of 360610)
fell back to db:            0.0000% (0)
```

Over `cmd/gofmt` and `cmd/go`, each built for Windows on amd64 and on 386, the four runs compare 4,318,469
instructions, agree on the length of all of them and fall back to `db` for none. The caveat matters: the
comparison covers the instructions the Go toolchain can decode itself. In the two amd64 programs 18,994
instructions were left out, because `go tool objdump` prints them as unknown (AVX-512, for example), misreads
VEX or EVEX encodings it does not know, or follows one of those in the same function; the 386 programs had
none. It also covers the code that the Go compiler emits and nothing else: hand-written assembly, other
compilers and obfuscated code may look different. The operation, register and number columns of the
same test are only a loose cross-check (100.000% of 307,429 mapped operations and 99.998% of the registers for
the `gofmt` run above); the length is the verdict.

A second developer test, `TestOracleAsm`, reads the encoding tests of the Go assembler from the local toolchain
(`go env GOROOT`, `src/cmd/asm/internal/asm/testdata`; nothing is copied into this repository): thousands of
instructions paired with their machine code by an independent encoder, including AVX and AVX-512. Set
`TEARDOWN_DISASM_ORACLE_ASM` to a file or a directory of them (see the top of
`internal/disasm/oracle_asm_test.go`). The length agreement is 99.9914% for `amd64enc.s` (11,580 of 11,581; the
one miss is `ud1`, which the decoder does not know and shows as `db`), 100% for `amd64enc_extra.s` (1,233),
for the `avx512enc` directory (17,155) and for `386enc.s` (23).

## Where to see it

| Surface | How |
|---|---|
| Terminal | `teardown analyze file` prints the first blocks under each finding; `--code-all` prints all of them, `--no-code` none ([`analyze`](cli.md#analyze)). `teardown disasm`, `xrefs` and `hexdump` read any part of a file ([commands](cli.md)). |
| JSON | `findings[].code` in `analyze --json`, the HTTP API and the MCP `analyze_file` tool ([schema](api/schema.md#findingscode)). |
| Markdown, SARIF | `analyze --md` writes a fenced block per code block. `analyze --sarif` carries the flagged line of the first five blocks of each finding in the `code` property of the result. |
| HTML report, dashboard | A **Code** group inside each finding: the first three blocks open and the rest behind **Show N more code blocks**, the first 24 lines of a block (the window around the flagged one) with **Show N more lines** for the rest, a **Copy** button that copies the block as plain text, a notice when a block is only a window, and what the blocks do not show. The panel is reachable with the keyboard: the disclosure, each **Copy** button, each table (a focusable, scrollable region) and the **Show** buttons are in the tab order. |
| MCP | `read_bytes`, `disassemble` and `find_calls` ([MCP guide](mcp.md)). |

`--no-code` leaves the code out of every output of `analyze`, so a report can be shared without it.
