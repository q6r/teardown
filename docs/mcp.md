# MCP guide

`teardown mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server on stdio. An AI
agent can ask it what a file is, what is inside and what looks wrong, and gets the same findings
(with their evidence and limitations) that the CLI and the dashboard show. It can also ask for the
code behind a finding: the bytes at an offset, the instructions at an address, the places that call an
import ([code evidence](code-evidence.md)). The files are never executed.

```text
teardown mcp [--root DIR]...
```

- Transport: newline-delimited JSON-RPC 2.0 on stdin and stdout. Logs go to stderr; stdout carries
  protocol messages only.
- Protocol versions: 2024-11-05, 2025-03-26 and 2025-06-18, negotiated at `initialize`.
- Access: files are readable only below the `--root` directories (default: the current directory).
  Roots are opened with `os.Root`, so `..` and symbolic links or junctions that leave a root are not
  followed. Directories and devices are refused. Output is capped (256 KiB per answer) and every
  call has a one-minute limit.
- Names of a place: a path may name a place inside a root by any of the names the operating system
  gives it. The directories above the file are resolved first, so `/var/...` and `/private/var/...`
  (macOS temporary folders) are the same place, and on Windows so are an 8.3 short name such as
  `RUNNER~1` and the long name, in any letter case. A path on a Windows volume that no root is on
  (another drive, `\\host\share`) is refused without being looked up, and the read itself always goes
  through `os.Root`, whatever the spelling.
- Failures are returned as tool results with `isError: true` and a message the agent can act on.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `analyze_file` | `path`, `minString` (3-256), `maxStrings` (1-10000), `detail` (`summary` or `full`) | The `teardown.report/v1` document. `summary` (the default) trims long lists and says what it cut in `note` and `trimmed` |
| `list_strings` | `path`, `category` (one or a comma-separated list), `query`, `minLength`, `limit`, `offset` | Classified strings with offsets and encodings, filtered and paged; secrets are redacted |
| `hash_file` | `path` | MD5, SHA-1, SHA-256 and the PE import hash, plus the detected type. Cheaper than `analyze_file` |
| `entropy_profile` | `path` | Overall entropy, up to 512 windows and the entropy of each section |
| `diff_files` | `a`, `b` | What changed between two files: hashes, type, sections, imports, strings, hardening, findings, risk |
| `disassemble` | `path`, `address` or `offset`, `count` (1-256), `arch` | x86 and x86-64 instructions as a code block of kind `disasm`, with the address to continue from ([details](#disassemble)) |
| `find_calls` | `path`, `api`, `before` (0-40), `after` (0-20), `max` (1-100) | The call sites of an imported function in a PE image, each with the instructions around it ([details](#find_calls)) |
| `read_bytes` | `path`, `offset`, `length` (1-4096) | A hex and ASCII window as a code block of kind `hex`, with the offset to continue from ([details](#read_bytes)) |

All eight tools are read-only: from protocol version 2025-03-26 on their annotations say so (`readOnlyHint`,
idempotent, not destructive, not open-world), and they open files only through the roots.

## Code tools

The report that `analyze_file` returns already carries the code behind its findings in `findings[].code`, in
the default `summary` detail the first 3 blocks of each finding with the 24 lines around the flagged one
(the `trimmed` and `note` members say what was cut). The three code tools read any part of a file, so an agent
can follow a finding to the bytes, the instructions or the callers behind it. Their results use the same
`code` block as the report ([schema](api/schema.md#findingscode)): every block states its limitations, and the
instructions are decoded by a linear sweep with a small built-in decoder, so data can be shown as code, only
x86 and x86-64 are understood, and none of it is a decompilation.

The examples use `dropper.bin`, generated on demand with `go run ./examples/gensamples -dropper` (it is a
harmless file that only looks like a dropper to a static scanner, so it is not committed; antivirus products
may flag a file that imports process-injection functions). The server runs with `--root examples/samples`.
Small objects are folded onto one row in the examples; the server prints one member per row.

### read_bytes

| Argument | Meaning |
|---|---|
| `path` | The file (required) |
| `offset` | File offset of the first byte, 0 or more, inside the file (default 0) |
| `length` | Bytes to read, 1 to 4096 (default 128); the window is cut short by the end of the file |

Result members: `file`, `length` (bytes in the window), `code` (kind `hex`: one line per row of 16 bytes, with
`offset`, `bytes` and the ASCII in `text`; `section` names the section a PE, ELF or Mach-O image holds the
window in), `next` (the offset to continue from, present when the file goes on) and `truncated`.

```text
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_bytes","arguments":{"path":"dropper.bin","offset":1257,"length":16}}}
```

```json
{
  "file": { "name": "dropper.bin", "size": 19200 },
  "length": 16,
  "code": {
    "kind": "hex",
    "title": "dropper.bin: bytes at file offset 0x4e9",
    "section": ".text",
    "offset": 1257,
    "lines": [
      {
        "offset": 1257,
        "bytes": "ff 15 b1 10 00 00 48 89 44 24 50 48 8b 4c 24 48",
        "text": "......H.D$PH.L$H"
      }
    ],
    "truncated": true,
    "limitations": [
      "Raw bytes as stored in the file: they show what is there, not what it means. Packed or encrypted data looks like noise."
    ]
  },
  "next": { "offset": 1273 },
  "truncated": false
}
```

(`code.truncated` says that the file goes on after the window; the `truncated` of the result says that the
result itself was shortened to fit the output cap.)

### disassemble

| Argument | Meaning |
|---|---|
| `path` | The file (required) |
| `address` | Virtual address to start at, as a string: `0x` and hexadecimal digits, or decimal digits (a JSON number cannot hold every 64-bit address). It is mapped through the section table of a PE or Mach-O image or the program headers of an ELF image, so it is an address the report shows |
| `offset` | File offset to start at. Not together with `address` |
| `count` | Instructions to decode, 1 to 256 (default 24) |
| `arch` | `x86` or `x86-64`. Taken from the file header by default; required for raw bytes, and overrides the header when given |

With neither `address` nor `offset` the window starts at the entry point. Result members: `file`, `start` (how
the first instruction was chosen: `address`, `offset`, `entry point` or `start of file`), `code` (kind `disasm`:
one line per instruction with `address`, `offset`, `bytes`, `text` and, in a PE image, a `note` that names the
import behind a call or a jump through the import table) and `next` (where to continue: `offset` and, for an
image, `address`).

```text
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"disassemble","arguments":{"path":"dropper.bin","address":"0x1400010e9","count":3}}}
```

```json
{
  "file": { "name": "dropper.bin", "size": 19200 },
  "start": "address",
  "code": {
    "kind": "disasm",
    "title": "dropper.bin: disassembly at 0x1400010e9",
    "section": ".text",
    "offset": 1257,
    "address": "0x1400010e9",
    "arch": "x86-64",
    "lines": [
      { "address": "0x1400010e9", "offset": 1257, "bytes": "ff 15 b1 10 00 00", "text": "call qword ptr [rip+0x10b1]", "note": "KERNEL32.dll!VirtualAllocEx" },
      { "address": "0x1400010ef", "offset": 1263, "bytes": "48 89 44 24 50", "text": "mov qword ptr [rsp+0x50], rax" },
      { "address": "0x1400010f4", "offset": 1268, "bytes": "48 8b 4c 24 48", "text": "mov rcx, qword ptr [rsp+0x48]" }
    ],
    "truncated": true,
    "limitations": [
      "Linear sweep: the bytes are decoded one after another, so data can be shown as code and the sweep can lose sync.",
      "x86 and x86-64 only; bytes that are not understood are shown as db. Not a decompiler: nothing is executed, emulated or resolved."
    ]
  },
  "next": { "offset": 1273, "address": "0x1400010f9" },
  "truncated": false
}
```

Asking for both `address` and `offset` is refused (`give either argument "address" or argument "offset", not both`), as
is an address that no section holds (the message lists the mapped ranges), an offset outside the file, and a
file for another instruction set (ARM64 included).

### find_calls

| Argument | Meaning |
|---|---|
| `path` | The file, a PE image for x86-64 or x86 (required) |
| `api` | The imported function (required, at most 256 characters): `Library!Function` or just `Function`, in any case. A name without a library matches the function of every library, and the ANSI and wide spellings together (`CreateProcess` finds `CreateProcessA` and `CreateProcessW`) |
| `before` | Instructions to show before each call, 0 to 40 (default 8) |
| `after` | Instructions to show after each call, 0 to 20 (default 4) |
| `max` | Call sites to return, 1 to 100 (default 10), the best first: calls through the import table, then calls and jumps through thunks |

Result members: `file`, `api` (as asked), `imports` (the imports the name matched), `arch`, `total` (the call
sites the scan found, which can exceed what is returned), `sites` (each with `api`, `kind` (`call`,
`call-thunk`, `jump-thunk`, `jump` or `load`), `address`, `offset`, `section`, `via` (the thunk a thunk call
goes through) and `code`, the block of the window with the call flagged), `scanComplete` (false when the scan of the code was cut short
by its limits: a call that is not listed may then simply not have been reached), `scanNotes` and `truncated`.

```text
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_calls","arguments":{"path":"dropper.bin","api":"VirtualAllocEx","before":3,"after":2}}}
```

```json
{
  "file": { "name": "dropper.bin", "size": 19200 },
  "api": "VirtualAllocEx",
  "imports": ["KERNEL32.dll!VirtualAllocEx"],
  "arch": "x86-64",
  "total": 1,
  "sites": [
    {
      "api": "KERNEL32.dll!VirtualAllocEx",
      "kind": "call",
      "address": "0x1400010e9",
      "offset": 1257,
      "section": ".text",
      "code": {
        "kind": "disasm",
        "title": "call to KERNEL32.dll!VirtualAllocEx in .text",
        "section": ".text",
        "offset": 1237,
        "address": "0x1400010d5",
        "arch": "x86-64",
        "lines": [
          { "address": "0x1400010d5", "offset": 1237, "bytes": "41 b8 00 10 00 00", "text": "mov r8d, 0x1000" },
          { "address": "0x1400010db", "offset": 1243, "bytes": "41 b9 00 30 00 00", "text": "mov r9d, 0x3000" },
          { "address": "0x1400010e1", "offset": 1249, "bytes": "c7 44 24 20 40 00 00 00", "text": "mov dword ptr [rsp+0x20], 0x40" },
          { "address": "0x1400010e9", "offset": 1257, "bytes": "ff 15 b1 10 00 00", "text": "call qword ptr [rip+0x10b1]", "note": "KERNEL32.dll!VirtualAllocEx", "highlight": true },
          { "address": "0x1400010ef", "offset": 1263, "bytes": "48 89 44 24 50", "text": "mov qword ptr [rsp+0x50], rax" },
          { "address": "0x1400010f4", "offset": 1268, "bytes": "48 8b 4c 24 48", "text": "mov rcx, qword ptr [rsp+0x48]" }
        ],
        "limitations": [
          "x86-64 code decoded as a linear sweep (ARM64 and other instruction sets are not supported): data inside a code section can be read as instructions, and one wrong byte shifts what follows.",
          "Only calls through the import table and import thunks are found: functions resolved at run time are invisible, and packed or protected code hides its real calls.",
          "A view of the code, not a decompiler, an emulator or a verdict: nothing was executed, and the code shows what is called, not why."
        ]
      }
    }
  ],
  "scanComplete": true,
  "truncated": false
}
```

A function the file imports but nothing calls is not an error: `total` is 0 and `sites` is empty (the last
call of the [transcript](#transcript) shows it). A name that matches no import is an error that names the
imports that are called, so a misspelling is easy to fix:

```text
no import of this file matches "NoSuchApi"; imports with call sites include KERNEL32.dll!ExitProcess, KERNEL32.dll!GetProcAddress, KERNEL32.dll!LoadLibraryA, KERNEL32.dll!VirtualAllocEx, KERNEL32.dll!WriteProcessMemory, KERNEL32.dll!CreateRemoteThread, KERNEL32.dll!OpenProcess, KERNEL32.dll!IsDebuggerPresent and 7 more (analyze_file lists every import)
```

The tool finds calls in PE images for x86 and x86-64 only; an ELF or Mach-O file, another instruction set or
another file type is refused with a message that says so.

### Limits and trimming

The three tools use the same machinery as the others: the roots (`..` escapes, symbolic links that leave a
root, directories and devices are refused; a path outside the roots is an error that says so), the one-minute
limit of a call, and the output cap (256 KiB of text per answer). Arguments are checked strictly: an unknown
argument, a value outside its range or of the wrong type is an error that names the argument. A result that
would exceed the cap is shortened, never cut in the middle: `read_bytes` and `disassemble` give up lines (and
then say where to continue in `next`), `find_calls` first shortens the window around each call and then drops
the last sites, and `trimmed` and `note` say what was cut. The offsets, counts and sizes a request names are
checked against the file before anything is read. `read_bytes` and `disassemble` read only the bytes of their
window; `find_calls` sweeps the executable sections of the image within the [bounds of the scan](code-evidence.md#bounds).

## Connect a client

The server side is covered by the test suite and the transcript below. The client configuration
snippets follow each client's documented format; treat them as a starting point and check your
client's documentation if a setting is rejected.

### Claude Code

```bash
claude mcp add teardown -- teardown mcp --root .
```

This is the command that `teardown mcp --help` prints as an example. To share the setup with a
team, put the server in `.mcp.json` at the root of the project:

```json
{
  "mcpServers": {
    "teardown": {
      "command": "teardown",
      "args": ["mcp", "--root", "."]
    }
  }
}
```

### Claude Desktop

Add the server to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`,
Windows: `%APPDATA%\Claude\`) and restart the app. Use absolute paths there, because the app does
not start in your project directory:

```json
{
  "mcpServers": {
    "teardown": {
      "command": "/usr/local/bin/teardown",
      "args": ["mcp", "--root", "/home/me/samples", "--root", "/tmp/downloads"]
    }
  }
}
```

On Windows write the paths with doubled backslashes in JSON, for example
`"C:\\tools\\teardown.exe"`.

Then ask for something concrete: "Analyse `suspicious.exe` with teardown and tell me what to look at
first", or "Compare `app-1.0.exe` and `app-1.1.exe` and say what changed".

## Transcript

A real session, produced with
`teardown mcp --root examples/samples < examples/mcp-session.jsonl`. Responses are shortened with `…`, and the
absolute path that the server includes in its refusal message is elided. The server runs calls
concurrently and writes each answer when it is ready, so answers can arrive out of order (the refusal of
call 5 comes before the answer of call 3): match them by `id`.

Handshake and the list of tools:

```text
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"example-client","version":"0.0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

```text
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"teardown","title":"teardown static triage","version":"dev"},"instructions":"teardown is a static triage tool for binaries and app packages … It never executes the …"}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"analyze_file", …}, {"name":"list_strings", …}, {"name":"hash_file", …}, {"name":"entropy_profile", …}, {"name":"diff_files", …}, {"name":"disassemble", …}, {"name":"find_calls", …}, {"name":"read_bytes", …}]}}
```

Hash a file:

```text
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hash_file","arguments":{"path":"hello.exe"}}}
```

The answer's text content is:

```json
{
  "file": { "name": "hello.exe", "size": 2048 },
  "type": {
    "id": "pe",
    "family": "executable",
    "label": "PE32+ executable for Windows (x86-64, console)",
    "mime": "application/vnd.microsoft.portable-executable",
    "confidence": "high",
    "tags": ["64-bit", "exe", "x86-64"]
  },
  "hashes": {
    "md5": "6951e556ec33f990b7285ac0e55f656c",
    "sha1": "6c822f5535a50a6f2dbadfec79c0eb469181d50d",
    "sha256": "6d3bd25d10c80d4c64ea8419f1bcf82dec72c8ea6c71cfe3be33a1a29d2f9fa5",
    "imphash": "ddb7af50933d415b075f5644747fcaed"
  }
}
```

A path outside the roots is refused with an actionable message, and the session goes on:

```text
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"analyze_file","arguments":{"path":"../etc/passwd"}}}
{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"path \"../etc/passwd\" is outside the allowed roots; only files inside … can be analysed"}],"isError":true}}
```

Look at the first instructions of a file, at its entry point (call 6), and at its first 32 bytes (call 7):

```text
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"disassemble","arguments":{"path":"hello.exe","count":3}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_bytes","arguments":{"path":"hello.exe","offset":0,"length":32}}}
```

The text content of the answer to call 6 (`next` says where to continue; `hello.exe` has no code beyond `xor eax, eax`
and `ret`, and `int3` is the padding after them):

```json
{
  "file": { "name": "hello.exe", "size": 2048 },
  "start": "entry point",
  "code": {
    "kind": "disasm",
    "title": "hello.exe: disassembly at 0x140001000",
    "section": ".text",
    "offset": 512,
    "address": "0x140001000",
    "arch": "x86-64",
    "lines": [
      { "address": "0x140001000", "offset": 512, "bytes": "31 c0", "text": "xor eax, eax" },
      { "address": "0x140001002", "offset": 514, "bytes": "c3", "text": "ret" },
      { "address": "0x140001003", "offset": 515, "bytes": "cc", "text": "int3" }
    ],
    "truncated": true,
    "limitations": [
      "Linear sweep: the bytes are decoded one after another, so data can be shown as code and the sweep can lose sync.",
      "x86 and x86-64 only; bytes that are not understood are shown as db. Not a decompiler: nothing is executed, emulated or resolved."
    ]
  },
  "next": { "offset": 516, "address": "0x140001004" },
  "truncated": false
}
```

And the answer to call 7:

```json
{
  "file": { "name": "hello.exe", "size": 2048 },
  "length": 32,
  "code": {
    "kind": "hex",
    "title": "hello.exe: bytes at file offset 0x0",
    "offset": 0,
    "lines": [
      { "offset": 0, "bytes": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00", "text": "MZ.............." },
      { "offset": 16, "bytes": "b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00", "text": "........@......." }
    ],
    "truncated": true,
    "limitations": [
      "Raw bytes as stored in the file: they show what is there, not what it means. Packed or encrypted data looks like noise."
    ]
  },
  "next": { "offset": 32 },
  "truncated": false
}
```

Ask who calls an import (call 8). `hello.exe` imports `ExitProcess` but its code does not call it, which is a
result and not an error:

```text
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"find_calls","arguments":{"path":"hello.exe","api":"ExitProcess"}}}
```

```json
{
  "file": { "name": "hello.exe", "size": 2048 },
  "api": "ExitProcess",
  "imports": ["KERNEL32.dll!ExitProcess"],
  "arch": "x86-64",
  "total": 0,
  "sites": [],
  "scanComplete": true,
  "truncated": false
}
```

The complete request file is [`examples/mcp-session.jsonl`](../examples/mcp-session.jsonl). Two more calls, which
are not in that file, on `upx-like.exe` (calls 9 and 10):

```text
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_strings","arguments":{"path":"upx-like.exe","category":"api"}}}
```

```json
{
  "file": { "name": "upx-like.exe", "size": 4608 },
  "minLength": 5,
  "stringsFound": 7,
  "scanTruncated": false,
  "byCategory": { "api": 1, "plain": 6 },
  "category": ["api"],
  "total": 1,
  "offset": 0,
  "limit": 100,
  "items": [
    { "value": "ExitProcess", "offset": 1594, "encoding": "ascii", "category": "api", "redacted": false, "kind": "system" }
  ],
  "returned": 1,
  "truncated": false
}
```

```text
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"entropy_profile","arguments":{"path":"upx-like.exe"}}}
```

```json
{
  "file": { "name": "upx-like.exe", "size": 4608 },
  "type": { "id": "pe", "label": "PE32+ executable for Windows (x86-64, console)" },
  "scale": "bits per byte: 0 = constant data, 8 = uniformly random; compressed, encrypted or packed data is typically above 7.2, code and text well below",
  "overall": 1.013,
  "windowSize": 256,
  "windows": [3.064, 1.189, 0.642, 0, 0.111, 0, 1.099, 0, 0.564, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "sections": [ { "name": ".text", "entropy": 0.061, "rawSize": 512 }, … ],
  "truncated": false
}
```

## Notes for agent authors

- Start with `hash_file` or `analyze_file` with the default `summary` detail; ask for `detail: "full"`
  or `list_strings` only when you need more.
- Findings and the risk score are triage hints. Each finding lists its `evidence` and its
  `limitations`: quote both when you report a finding to a person.
- The report says what could not be seen in `limitations`, for example that packed code is invisible
  to static analysis or that no parser exists for the file type.
- A finding that is made from imports, strings or script settings can carry the code behind it in
  `findings[].code`. To see more than the report shows, use `find_calls` with a function the finding names, then
  `disassemble` at an address it returns (or `read_bytes` at an offset a string or section names). Follow `next`
  to continue a window.
- Code blocks show what the file contains, not what it does: they come from a linear sweep, they cover x86 and
  x86-64 only, and a function that a program resolves at run time never appears. Quote the `limitations` of a
  block when you report from it, and do not call code malicious on the strength of a call site.
