# HTTP API

`teardown serve` starts a small HTTP server with two jobs: it serves the embedded
dashboard, and it exposes a JSON API for uploading a file and reading back its
[`teardown.report/v1`](schema.md) report. The server never executes what it
analyses.

```text
teardown serve                                   # http://127.0.0.1:7777
teardown serve --addr 127.0.0.1:9000 --max-upload 64MiB --keep 20
```

| Flag           | Default          | Meaning                                                        |
| -------------- | ---------------- | -------------------------------------------------------------- |
| `--addr`       | `127.0.0.1:7777` | Address to listen on. Anything but loopback prints a warning.   |
| `--max-upload` | `256MiB`         | Largest accepted upload (`64MiB`, `1GiB`, ...).                 |
| `--keep`       | `50`             | Analyses kept in memory; the oldest is dropped first (max 10000). |

At start-up the server prints where it listens:

```text
teardown dashboard: http://127.0.0.1:7777
listening on the loopback interface only; press Ctrl+C to stop
```

The examples below use `curl`. In Windows PowerShell `curl` is an alias for
`Invoke-WebRequest`; type `curl.exe` instead. Reports are kept **in memory only**:
restart the server and they are gone. The outputs are real, captured from a running
server and analysing the read-only Windows system files `notepad.exe` and `cmd.exe`;
ids, timestamps and durations differ on every run, and long bodies are trimmed.

## Conventions

- JSON in and out, UTF-8, camelCase keys, timestamps in RFC 3339 UTC.
- An analysis id is `an_` followed by 12 lowercase hex characters, e.g. `an_ce8d6a437380`.
- Every non-2xx answer from the API (and from the dashboard routes) has the same
  envelope, so a client needs one error path:

  ```json
  {"error":{"code":"too_large","message":"the upload exceeds the limit of 1 MiB; start the server with a larger --max-upload to analyse bigger files"}}
  ```

  `code` is a stable snake_case token (table below); `message` is for humans.
- A path that exists with another method answers `405` with an `Allow` header;
  an unknown path under `/api` answers `404 not_found`.
- The machine-readable description is [`GET /api/openapi.json`](#get-apiopenapijson) (OpenAPI 3.1).

## Routes

| Method   | Path                                 | Purpose                                | Success |
| -------- | ------------------------------------ | -------------------------------------- | ------- |
| `GET`    | `/api/health`                        | Liveness and version                   | 200     |
| `POST`   | `/api/analyze`                       | Upload a file and analyse it           | 201     |
| `GET`    | `/api/analyses`                      | List stored analyses, newest first     | 200     |
| `GET`    | `/api/analyses/{id}`                 | Fetch a stored report                  | 200     |
| `DELETE` | `/api/analyses/{id}`                 | Delete a stored report                 | 204     |
| `GET`    | `/api/analyses/{id}/strings`         | Filter and page the strings of a report | 200     |
| `GET`    | `/api/events`                        | Server-sent events about analyses      | 200     |
| `GET`    | `/api/openapi.json`                  | OpenAPI 3.1 description                | 200     |
| `GET`    | `/`                                  | The embedded dashboard                 | 200     |

## `GET /api/health`

```console
$ curl -s http://127.0.0.1:7777/api/health
{"status":"ok","version":"dev"}
```

`version` is the version stamped into the binary (`dev` for an unstamped build).

## `POST /api/analyze`

Send the file as `multipart/form-data` in a field named `file`. The request must
contain exactly one part.

```console
$ curl -s -i -F "file=@C:\Windows\System32\notepad.exe" http://127.0.0.1:7777/api/analyze
HTTP/1.1 201 Created
Cache-Control: no-store
Content-Length: 170191
Content-Security-Policy: default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
Content-Type: application/json; charset=utf-8
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Location: /api/analyses/an_a0c162d32941
Permissions-Policy: camera=(), microphone=(), geolocation=()
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Date: Wed, 11 Nov 2026 00:28:33 GMT

{"id":"an_a0c162d32941","report":{"schema":"teardown.report/v1","tool":{"name":"teardown","version":"dev"},"generatedAt":"2026-11-11T00:28:33.077Z","durationMs":40,"file":{"name":"notepad.exe","size":360448},"type":{"id":"pe","family":"executable","label":"PE32+ executable for Windows (x86-64, GUI)","mime":"application/vnd.microsoft.portable-executable","confidence":"high","tags":["64-bit","exe","x86-64"]},"hashes":{"md5":"8a1d8175ccca97054cdb25acbb4cc07e","sha1":"76cd26b59923157e09d2bc927ba8fb059f3155dc","sha256":"468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e","imphash":"aa9e7e1bd35e47c6de05df960241a986"},"entropy":{"overall":6.483,"windowSize":1024,"windows":[3.123,0,0,0,5.629,4.324,5.9,5.666, … 352 windows … ]},"sections":[{"name":".text","virtualSize":157666,"rawSize":159744,"offset":4096,"entropy":6.238,"flags":["R","X"],"suspicious":false}, … ],"imports":[{"library":"GDI32.dll","count":25,"functions":["SetMapMode", … ]}, … ],"exports":[],"strings":{"total":1549,"minLength":5,"truncated":false,"byCategory":{"api":67,"plain":1477,"registry":2,"url":3},"items":[ … ]},"hardening":[{"id":"aslr","label":"ASLR (DYNAMIC_BASE)","status":"enabled", … }, … ],"details":{"pe":{ … }},"findings":[{"id":"imports.anti-debug","severity":"low", … }, … ],"risk":{"score":13,"label":"low","basis":[ … ]},"limitations":[ … ]}}
```

(The body is shown trimmed; the real answer is the whole report, 170 KB for this
file. Field meanings are in [schema.md](schema.md).)

What the server does with the upload:

1. Takes a free analysis slot (waiting up to 30 s, see [Limits](#limits-and-behaviour)),
   then streams the part into a private temporary directory under a random name.
   The client's file name is **never** used as a path.
2. Enforces the size limit exactly: the byte after `--max-upload` already fails with `413`.
3. Analyses the file, then deletes it immediately, before the answer is written.
4. Keeps the report in the in-memory ring and answers `201` with `Location: /api/analyses/{id}`.

The name inside the report (`file.name`) is a sanitised display label: the part after
the last `/` or `\`, control characters and bidirectional overrides removed,
whitespace collapsed, at most 255 bytes (a long name keeps its extension), and
`upload.bin` when nothing usable is left. A client that sends
`filename="..\..\Windows\evil.exe"` gets a report named `evil.exe`.

An empty file is valid and is analysed like any other.

| Status | `code`                   | When                                                                             |
| ------ | ------------------------ | -------------------------------------------------------------------------------- |
| 201    |                          | Analysed and stored                                                              |
| 400    | `bad_multipart`          | Missing boundary, malformed or truncated multipart body                          |
| 400    | `missing_file`           | The first part is not a form field named `file` (or the body has no parts)       |
| 400    | `unexpected_part`        | More than one part                                                               |
| 403    | `forbidden_host`/`forbidden_origin` | See [Security model](#security-model)                                 |
| 413    | `too_large`              | The upload exceeds `--max-upload`                                                |
| 415    | `unsupported_media_type` | The request is not `multipart/form-data`                                         |
| 500    | `analysis_failed`        | The analyzer failed (details are in the server log, not in the response)         |
| 500    | `internal_error`         | The upload could not be stored on the server                                     |
| 503    | `busy`                   | Every analysis slot stayed busy for 30 s, or 64 uploads are already queued; carries `Retry-After` |
| 504    | `analysis_timeout`       | The analysis exceeded its time limit (60 s)                                      |

## `GET /api/analyses`

Summaries of the stored analyses, newest first. An empty ring is `[]`.

```console
$ curl -s http://127.0.0.1:7777/api/analyses
[{"id":"an_ce8d6a437380","name":"notepad.exe","size":360448,"type":"pe","typeLabel":"PE32+ executable for Windows (x86-64, GUI)","risk":{"score":13,"label":"low"},"createdAt":"2026-11-11T00:20:51.11Z"}]
```

| Field       | Meaning                                                    |
| ----------- | ---------------------------------------------------------- |
| `id`        | Analysis id                                                |
| `name`      | Sanitised display name of the upload                       |
| `size`      | Size in bytes                                              |
| `type`      | Detected type id (`pe`, `elf`, `apk`, `data`, ...)         |
| `typeLabel` | Human-readable type                                        |
| `risk`      | `{score, label}`: the triage score, 0-100, and its label    |
| `createdAt` | When the analysis finished                                 |

## `GET /api/analyses/{id}` and `DELETE /api/analyses/{id}`

`GET` returns the full report (the same document that `POST /api/analyze` returned
under `report`). `DELETE` removes it and answers `204 No Content`.

```console
$ curl -s http://127.0.0.1:7777/api/analyses/an_a0c162d32941 | head -c 330
{"schema":"teardown.report/v1","tool":{"name":"teardown","version":"dev"},"generatedAt":"2026-11-11T00:28:33.077Z","durationMs":40,"file":{"name":"notepad.exe","size":360448},"type":{"id":"pe","family":"executable","label":"PE32+ executable for Windows (x86-64, GUI)","mime":"application/vnd.microsoft.portable-executable","confid

$ curl -s -o /dev/null -w "%{http_code}\n" -X DELETE http://127.0.0.1:7777/api/analyses/an_ef5391ca3b9b
204
$ curl -s -o /dev/null -w "%{http_code}\n" -X DELETE http://127.0.0.1:7777/api/analyses/an_ef5391ca3b9b
404
```

An id that is unknown, malformed, deleted or evicted answers `404 not_found`; the id
is never echoed back.

### Code evidence in a report

A finding made from imports, strings or script settings carries the code behind it in `findings[].code`: the
instructions around a call, a hex and ASCII window, or source lines ([code evidence](../code-evidence.md),
[schema](schema.md#findingscode)). It is part of the report, so it comes with `POST /api/analyze` and
`GET /api/analyses/{id}` and there is no route for it. Blocks are bounded (at most 12 per finding, 64 lines of
200 characters each), so a report grows by a bounded amount: the 19 KB `dropper.bin` of this repository
(generated on demand with `go run ./examples/gensamples -dropper`) answers with about 67 KB of JSON. Secrets
are masked in the blocks as everywhere else. A fragment of the answer for that file, trimmed with `…`:

```console
$ curl -s -F file=@examples/samples/dropper.bin http://127.0.0.1:7777/api/analyze
{"id":"an_c92dc18b6444","report":{"schema":"teardown.report/v1", … "findings":[{"id":"imports.process-injection","title":"Imports cover the full process-injection chain (allocate, write, execute)","severity":"high","category":"imports","confidence":"medium","evidence":["allocate or map memory in another process: KERNEL32.dll!VirtualAllocEx", … ,"code: 4 call sites in .text (see the code blocks)"],"code":[{"kind":"disasm","title":"call to KERNEL32.dll!VirtualAllocEx in .text","section":".text","offset":1213,"address":"0x1400010bd","arch":"x86-64","lines":[{"address":"0x1400010bd","offset":1213,"bytes":"41 b8 a4 01 00 00","text":"mov r8d, 0x1a4"},{"address":"0x1400010c3","offset":1219,"bytes":"ff 15 ef 10 00 00","text":"call qword ptr [rip+0x10ef]","note":"KERNEL32.dll!OpenProcess"}, … ],"limitations":[ … ]}, … ],"limitations":[ … ]}, … ]}}
```

The server deletes an upload as soon as its analysis ends, so the API cannot read more of a file than the
report already holds. To follow a finding further, use the `teardown hexdump`, `disasm` and `xrefs` commands on
the file or the `read_bytes`, `disassemble` and `find_calls` [MCP tools](../mcp.md). The OpenAPI document
describes the field (`Finding.code`, with the schemas `CodeBlock`, `CodeLine` and `CodeAddress`).

## `GET /api/analyses/{id}/strings`

Filters and pages `strings.items` of a stored report. Secret values are already
redacted in the report (first four characters plus the length), so they are redacted
here too, and searching for the real secret finds nothing.

| Parameter  | Default | Meaning                                                                                  |
| ---------- | ------- | ---------------------------------------------------------------------------------------- |
| `category` | all     | Comma-separated list (or repeated parameter) of `secret`, `url`, `email`, `ip`, `registry`, `command`, `useragent`, `path`, `domain`, `api`, `base64`, `hex`, `plain` |
| `q`        |         | Case-insensitive substring of the (redacted) value, at most 256 bytes                    |
| `limit`    | `100`   | Page size, 1-1000                                                                        |
| `offset`   | `0`     | Matches to skip                                                                          |

```console
$ curl -s "http://127.0.0.1:7777/api/analyses/an_ce8d6a437380/strings?category=registry,url&q=microsoft&limit=2"
{"total":5,"offset":0,"limit":2,"items":[{"value":"https://go.microsoft.com/fwlink/?LinkId=834783","offset":176432,"encoding":"utf16le","category":"url","redacted":false,"kind":"https"},{"value":"Software\\Microsoft\\Notepad\\DefaultFonts","offset":178272,"encoding":"utf16le","category":"registry","redacted":false}]}
```

`total` is the number of matches, so a client pages with `offset += limit` until
`items` is empty. Order is the report's own order (by file offset). The endpoint pages over what the
report kept: when `strings.truncated` is `true` in the report, more strings existed
than the analyzer retained. Bad parameters answer `400 invalid_parameter`.

## `GET /api/events`

A `text/event-stream` for live updates, so a dashboard can show an analysis as it
starts and finishes (also for uploads made by other clients).

```console
$ curl -sN http://127.0.0.1:7777/api/events
: stream open

event: analysis.started
data: {"id":"an_ebbfc26564f5","name":"cmd.exe","size":339968}

event: analysis.completed
data: {"id":"an_ebbfc26564f5","name":"cmd.exe","size":339968,"type":"pe","typeLabel":"PE32+ executable for Windows (x86-64, console)","risk":{"score":15,"label":"low"},"createdAt":"2026-11-11T00:23:35.662Z","durationMs":149}
```

| Event                | Payload                                                                             |
| -------------------- | ----------------------------------------------------------------------------------- |
| `analysis.started`   | `{id, name, size}`: the upload arrived and analysis begins                           |
| `analysis.completed` | an analysis summary (as in `GET /api/analyses`) plus `durationMs`                     |
| `analysis.failed`    | `{id, name, error}`: `error` is a short reason (`analysis failed`, `analysis timed out`, `analysis canceled`), never a server path |

Each event is one `event:` line, one `data:` line holding a JSON object, and a blank
line. A comment frame (`: keep-alive`) arrives every 15 s on a quiet stream. A client
that falls more than 32 events behind is disconnected (it can reconnect and re-read
`GET /api/analyses`); other clients are unaffected. Streams end when the server
shuts down.

## `GET /api/openapi.json`

The hand-written OpenAPI 3.1 document for everything on this page, including the
report shape. It is plain JSON, so any OpenAPI 3.1 tool or code generator can read
it. A test keeps it honest: every route in the server's route table must be
documented, every documented operation must be routable, every status the server
returns in the tests must be listed, and the schemas must match the real JSON keys.

```console
$ curl -s http://127.0.0.1:7777/api/openapi.json | head -c 250
{
  "openapi": "3.1.0",
  "info": {
    "title": "teardown HTTP API",
    "version": "1.0.0",
    "summary": "Static triage of binaries and apps over HTTP.",
    "description": "Upload a file, get back a teardown.report/v1 report. The server never ex
```

## The dashboard

`GET /` serves `index.html` from the dashboard embedded in the binary, and other
paths serve the file of that name (`/app.js`, `/aurora.css`, ...). There is no
directory listing and no fallback: an unknown file is a `404` with the usual JSON
envelope. Responses carry `Cache-Control: no-cache`, and the content types of the
common web assets (`.js`, `.css`, `.svg`, ...) are pinned by the server instead of
the operating system's MIME registry, which on Windows can map `.js` to
`text/plain` and make a browser refuse the script.

```console
$ curl -s -i http://127.0.0.1:7777/ | head -5
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: no-cache
Content-Length: 831
Content-Security-Policy: default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

The page uses only the routes above (`POST /api/analyze` with `XMLHttpRequest` for upload progress,
`GET /api/analyses`, `GET` and `DELETE /api/analyses/{id}`, `GET /api/analyses/{id}/strings`,
`GET /api/health` for the version in its status bar, and the `GET /api/events` stream), loads every
script and style from its own origin, and needs no inline
script or style, so the policy above is enough. The files are `index.html`, `app.js`, `app.css`,
`report-view.js`, `report-view.css`, `favicon.svg` and the bundled Aurora UI kit
(`aurora.css`, `aurora.js`, `aurora-charts.js`). The page itself is almost empty: `app.js` builds the
layout (rail, top bar, sub bar, status bar) and the two routes, `#/` (the upload zone and the list of
analyses) and `#/analysis/<id>` (the report).

## Errors

| Status | `code`                   | Meaning                                                                  |
| ------ | ------------------------ | ------------------------------------------------------------------------ |
| 400    | `bad_multipart`          | Malformed, truncated or boundary-less multipart body                     |
| 400    | `missing_file`           | No form field named `file` as the first part                             |
| 400    | `unexpected_part`        | More than one part                                                       |
| 400    | `invalid_parameter`      | A query parameter is out of range or unknown (`category`)                |
| 403    | `forbidden_host`         | The `Host` header is not a loopback name                                 |
| 403    | `forbidden_origin`       | A cross-origin state-changing request                                    |
| 404    | `not_found`              | Unknown analysis, file or endpoint                                       |
| 405    | `method_not_allowed`     | Wrong method for the path; `Allow` lists the right ones                   |
| 413    | `too_large`              | Upload above `--max-upload`                                              |
| 415    | `unsupported_media_type` | Not `multipart/form-data`                                                |
| 500    | `analysis_failed`        | The analyzer failed                                                      |
| 500    | `internal_error`         | The server could not store the upload or hit an unexpected error         |
| 503    | `busy`                   | All analysis slots busy for 30 s, or the upload queue or the event-stream limit is full (with `Retry-After`), or the server is shutting down |
| 504    | `analysis_timeout`       | The analysis exceeded its time limit                                     |

Real answers from a running server:

```console
$ curl -s -X POST -H "Content-Type: application/json" -d "{}" http://127.0.0.1:7777/api/analyze
{"error":{"code":"unsupported_media_type","message":"send the file as multipart/form-data in a field named \"file\", for example: curl -F file=@sample.bin http://127.0.0.1:7777/api/analyze"}}

$ curl -s -F "upload=@C:\Windows\System32\notepad.exe" http://127.0.0.1:7777/api/analyze
{"error":{"code":"missing_file","message":"the first multipart part must be a form field named \"file\""}}

$ curl -s http://127.0.0.1:7777/api/analyses/an_000000000000
{"error":{"code":"not_found","message":"no analysis with that id; it may have been deleted or evicted from the in-memory ring (see GET /api/analyses)"}}

$ curl -s -i -X OPTIONS http://127.0.0.1:7777/api/analyze | grep -iE "^HTTP|^Allow|access-control"
HTTP/1.1 405 Method Not Allowed
Allow: POST
```

## Limits and behaviour

| What                        | Value                                                                                  |
| --------------------------- | -------------------------------------------------------------------------------------- |
| Upload size                 | `--max-upload`, default 256 MiB, applied to the file's bytes and enforced to the byte while streaming; a request whose `Content-Length` already exceeds it by more than 1 MiB (the multipart framing allowance) is refused before its body is read |
| Request header              | 10 s to send, at most 64 KiB                                                            |
| Upload stalls               | An upload with no bytes for 30 s, or running longer than 15 minutes in total, is dropped |
| Simultaneous analyses       | `min(4, CPU count)`; further uploads queue for up to 30 s, then get `503` with `Retry-After`; at most 64 uploads queue, the rest get `503` at once |
| Analysis time               | 60 s per file (`504 analysis_timeout` when exceeded); a client that disconnects cancels its analysis |
| Stored analyses             | `--keep`, default 50, at most 10000; the oldest is evicted first; all are lost on restart |
| Event streams               | At most 64 open at once (then `503`); 32 queued events per client; keep-alive every 15 s |
| Strings page                | `limit` 1-1000 (default 100), `q` at most 256 bytes                                     |
| Display name                | At most 255 bytes                                                                       |
| Shutdown                    | `Ctrl+C` stops accepting connections, closes those that have not sent a request yet (browsers keep spare ones) and ends event streams at once, gives running requests 10 s, and removes the private upload directory |

Uploads live in a directory created at start-up inside the system temporary
directory (`teardown-<random>`, mode 0700 on Unix), under random file names, and exist only while
their analysis runs. If the process is killed, that directory can be left behind;
it contains at most the uploads that were in flight.

## Security model

The server is **unauthenticated by design**: it is a local tool, like a language
server. Everything below protects a single user on their own machine; none of it
replaces authentication.

**Loopback by default.** `--addr` defaults to `127.0.0.1:7777`. Binding anything else
prints a multi-line warning at start-up (`the API is unauthenticated: anyone who can
connect may upload files for analysis, read every stored report and use this
machine's disk, CPU and memory`). Do not expose it to a network you do not trust;
if you must share it, put an authenticating reverse proxy in front and keep teardown
on loopback.

**DNS-rebinding defence (Host allow-list).** A web page on `attacker.example` whose
DNS record points at `127.0.0.1` can make a browser talk to this server, but the
request still says `Host: attacker.example`. While the server is bound to a loopback
address it only answers requests whose `Host` is `localhost`, `127.0.0.1`/any loopback
IP address, or `[::1]` (with any port); everything else, including the dashboard, gets
`403 forbidden_host`. A reverse proxy in front must therefore forward a loopback
`Host`. The allow-list is switched off when the server is deliberately bound to a
non-loopback address, because the legitimate names cannot be known (the warning at
start-up says so).

**CSRF defence (Origin check).** `POST` and `DELETE` requests that carry an `Origin`
header must name this server's own origin; `Origin: null`, other hosts, other ports
and `Sec-Fetch-Site: cross-site` / `same-site` are refused with `403 forbidden_origin`.
Requests without those headers (curl, scripts, the CLI) are unaffected. Reads are not
subject to the check but no browser can read a cross-origin answer, because:

**No CORS.** The server never sends an `Access-Control-*` header and answers
`OPTIONS` with `405`, so a cross-origin page cannot make a preflighted request or read
a response.

**Headers on every response** (errors, static files and event streams included):

| Header                         | Value                                                                    |
| ------------------------------ | ------------------------------------------------------------------------ |
| `Content-Security-Policy`      | `default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options`       | `nosniff`                                                                |
| `X-Frame-Options`              | `DENY`                                                                   |
| `Referrer-Policy`              | `no-referrer`                                                            |
| `Cross-Origin-Opener-Policy`   | `same-origin`                                                            |
| `Cross-Origin-Resource-Policy` | `same-origin`                                                            |
| `Permissions-Policy`           | `camera=(), microphone=(), geolocation=()`                               |
| `Cache-Control`                | `no-store` on `/api/*`, `no-cache` on dashboard files                     |

**Hostile uploads.** The body is streamed (never buffered whole, never parsed by
`ParseMultipartForm`) into a private directory under random names, size-capped, never
made executable, never run, and deleted as soon as the analysis ends. The analysers
read bytes and never execute them. Client-supplied names are display labels only
and cannot reach the file system. A crash inside an analyser is contained: the
request fails with `500` and the server keeps serving.

**Information hygiene.** Error messages never contain server paths or the text of
internal errors (those go to the server log), and ids are never echoed. Reports
contain redacted secrets only: the analyser hides the middle of anything that looks
like a key or token (see the report schema).

What is **not** covered: authentication, TLS, per-client rate limits and isolation
between users. Any local process, and any user who can reach the port, can use the
server and read every stored report.

## Recipes

Upload a file and print only the verdict-style summary, from PowerShell:

```console
PS> $r = curl.exe -s -F "file=@C:\Windows\System32\notepad.exe" http://127.0.0.1:7777/api/analyze | ConvertFrom-Json
PS> $r.report.type.label; $r.report.risk.score; $r.report.risk.label
PE32+ executable for Windows (x86-64, GUI)
13
low
```

Fetch the report again later and list its findings:

```console
PS> (curl.exe -s "http://127.0.0.1:7777/api/analyses/$($r.id)" | ConvertFrom-Json).findings | Select-Object severity, id

severity id
-------- --
low      imports.anti-debug
low      privacy.pdb-path
low      signature.unsigned
low      structure.suspicious-section
info     indicators.network
info     structure.timestamp-anomaly
```

For CI gating prefer `teardown analyze <file> --fail-on high` (exit code 3 when the
threshold is met): it needs no server.

## Embedding

The server is an ordinary Go package, `github.com/q6r/teardown/internal/server`
(internal to the module, so it is for this repository's binary and its tests):

```go
srv, err := server.New(server.Config{Keep: 20})
if err != nil { /* ... */ }
defer srv.Close()
http.ListenAndServe("127.0.0.1:7777", srv.Handler())
```

`server.Run` and `server.Serve` add the listener, the start-up banner, graceful
shutdown and the exposure warning. `Config` also takes `TempDir`, `Concurrency`,
`AnalyzeTimeout`, `Stderr`, `Logger` and an `Analyze` function that replaces
`analyze.File` (the tests use it to inject slow or failing analysers).
