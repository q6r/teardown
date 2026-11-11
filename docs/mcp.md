# MCP guide

`teardown mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server on stdio. An AI
agent can ask it what a file is, what is inside and what looks wrong, and gets the same findings
(with their evidence and limitations) that the CLI and the dashboard show. The files are never
executed.

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
- Failures are returned as tool results with `isError: true` and a message the agent can act on.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `analyze_file` | `path`, `minString` (3-256), `maxStrings` (1-10000), `detail` (`summary` or `full`) | The `teardown.report/v1` document. `summary` (the default) trims long lists and says what it cut in `note` and `trimmed` |
| `list_strings` | `path`, `category` (one or a comma-separated list), `query`, `minLength`, `limit`, `offset` | Classified strings with offsets and encodings, filtered and paged; secrets are redacted |
| `hash_file` | `path` | MD5, SHA-1, SHA-256 and the PE import hash, plus the detected type. Cheaper than `analyze_file` |
| `entropy_profile` | `path` | Overall entropy, up to 512 windows and the entropy of each section |
| `diff_files` | `a`, `b` | What changed between two files: hashes, type, sections, imports, strings, hardening, findings, risk |

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
`teardown mcp --root examples/samples < session.jsonl`. Responses are shortened with `…`, and the
absolute path that the server includes in its refusal message is elided.

Handshake:

```text
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"example-client","version":"0.0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

```text
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"teardown","title":"teardown static triage","version":"dev"},"instructions":"teardown is a static triage tool for binaries and app packages … It never executes the …"}}
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

List one category of strings:

```text
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_strings","arguments":{"path":"upx-like.exe","category":"api"}}}
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

Look at the entropy:

```text
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"entropy_profile","arguments":{"path":"upx-like.exe"}}}
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

A path outside the roots is refused with an actionable message, and the session goes on:

```text
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"analyze_file","arguments":{"path":"../etc/passwd"}}}
{"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"path \"../etc/passwd\" is outside the allowed roots; only files inside … can be analysed"}],"isError":true}}
```

The complete request file is [`examples/mcp-session.jsonl`](../examples/mcp-session.jsonl).

## Notes for agent authors

- Start with `hash_file` or `analyze_file` with the default `summary` detail; ask for `detail: "full"`
  or `list_strings` only when you need more.
- Findings and the risk score are triage hints. Each finding lists its `evidence` and its
  `limitations`: quote both when you report a finding to a person.
- The report says what could not be seen in `limitations`, for example that packed code is invisible
  to static analysis or that no parser exists for the file type.
