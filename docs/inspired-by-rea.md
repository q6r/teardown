# Inspired by REA

teardown exists because of a good idea in [REA](https://github.com/morluto/rea): give AI agents (and
humans) a tool that looks inside software and answers in **findings that carry their evidence and
their limitations**, over a protocol agents already speak (MCP), with a CLI next to it.

teardown is an **independent, clean-room project**. It is **not affiliated with, endorsed by or derived
from REA**. We took the idea and rebuilt it from scratch with a different structure, a different
language and a different scope; we did not read, copy, translate or run REA's source code. If you need
what REA offers, use REA. If you want a small, dependable first look that fits in one binary, this is
for that.

> What follows describes REA as it is publicly presented (an MIT-licensed TypeScript project that
> exposes reverse-engineering workflows to AI agents through MCP and a CLI, integrating tools such as
> Ghidra, Hopper and IDA and covering many artefact types). Check its repository for current facts;
> we may be out of date and we make no claims about its internals.

## The same idea

| Idea | In teardown |
|---|---|
| An MCP server so an AI agent can analyse files | `teardown mcp` (stdio, protocol versions 2024-11-05, 2025-03-26, 2025-06-18) with eight tools, three of them for the code behind a finding |
| A CLI for humans and CI next to it | `teardown analyze / strings / hash / diff / disasm / xrefs / hexdump / serve / mcp` |
| Results as findings with **evidence and limitations**, not bare verdicts | every finding is `{id, title, severity, category, confidence, evidence[], limitations[]}`; a test fails if one lacks evidence or limitations |
| One analysis engine behind every surface | the CLI, the HTTP API and the MCP tools all call the same `internal/analyze` pipeline |

## Deliberately different

| | REA (as we understand it) | teardown |
|---|---|---|
| Language and runtime | TypeScript on Node.js, installed through npm | Go, **one static binary** with nothing to install |
| Dependencies | the npm dependency tree | **standard library only** (`go.mod` has no `require` lines), which is a feature: a short supply-chain story and reproducible builds |
| Footprint | a large repository | a small, flat codebase: `internal/<package>` with one responsibility each, no framework |
| Analysis depth | deep tooling: disassembly and decompilation through Ghidra, Hopper, IDA, instrumentation | **static triage with code evidence**: formats, structure, hashes, entropy, imports, hardening, strings, findings, and a small x86 and x86-64 decoder, written for this project with no third-party code, that shows the code behind a finding: the call sites of imports in PE images, the bytes around a string, the source lines of a script. It is a linear sweep, not a full disassembler. No decompiler, emulator, unpacker or debugger, and no ARM64 yet |
| Breadth | many artefact families (native, Electron/JS, .NET, APK, captures, models, firmware, ...) | the common ones, each at triage depth: PE, ELF, Mach-O (incl. fat), Go build info, ZIP family (JAR, APK, AAB, Office, wheels, ...), ASAR, WebAssembly, GGUF headers (safetensors, SQLite and PDF are only recognised, not parsed) |
| Safety stance | whatever its integrations require | the target is **never executed**, uploads are deleted right after analysis, every parser is bounded and panic-safe |
| UI | CLI and MCP | CLI, an HTTP API, an **embedded web dashboard** and a self-contained HTML report, all from the same binary |

## What teardown is not

- Not a decompiler, a full disassembler or a sandbox, and not a replacement for any of them. It has a small
  built-in decoder for x86 and x86-64 so that a finding can show the code around a suspicious import (a linear
  sweep: data can be read as code and the sweep can lose its place), and it never executes the file. It does not
  decompile, emulate, unpack or debug, it does not read ARM64 code, and it finds call sites only in PE images
  (ELF and Mach-O call sites are not implemented yet). See [code evidence](code-evidence.md) for what it shows
  and what it cannot.
- Not an antivirus or a malware verdict engine. The risk score (0-100) is a deterministic triage aid
  whose arithmetic is printed with the result; labels such as "high" mean "look at this sooner".
- Not exhaustive: HAR files, packet captures, EVM bytecode, firmware unpacking and most of REA's other
  workflows are out of scope.

## When to reach for which

- **teardown** for the first five minutes: what is this file, how is it built, what hardening does it
  have, what strings and imports stand out, what the code around a suspicious import looks like, did
  anything change between two builds, and an automated gate in CI (`--fail-on high`) or an agent
  pre-screening files before deeper work.
- **A full reverse-engineering toolchain** (REA with its integrations, Ghidra, IDA, Hopper, a debugger)
  when triage says the file deserves real analysis.

## Credit

Thank you to the REA author for showing that evidence-and-limitations findings over MCP are a useful
shape. The README credits REA under "Inspired by REA". teardown is MIT-licensed; the name and the binary
are deliberately different so the two projects cannot be confused.
