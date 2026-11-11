package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// Tool names.
const (
	toolAnalyze     = "analyze_file"
	toolStrings     = "list_strings"
	toolHash        = "hash_file"
	toolEntropy     = "entropy_profile"
	toolDiff        = "diff_files"
	toolDisassemble = "disassemble"
	toolFindCalls   = "find_calls"
	toolReadBytes   = "read_bytes"
)

// Protocol versions in which optional descriptor and result members appeared.
const (
	annotationsSince = "2025-03-26"
	titlesSince      = "2025-06-18"
	structuredSince  = "2025-06-18"
)

const pathDescription = "Path of the file. It must lie inside one of the allowed root directories; relative paths are resolved against the roots in order. Symbolic links or junctions that leave a root are not followed."

// toolOutput is what a tool handler returns: the result tree and how to fit it
// under the output cap.
type toolOutput struct {
	tree *node
	spec fitSpec
}

// tool describes one MCP tool and implements it.
type tool struct {
	name        string
	title       string
	description string
	schema      json.RawMessage
	run         func(s *server, ctx context.Context, args json.RawMessage) (*toolOutput, error)
}

// toolAnnotations are the behaviour hints of a tool (MCP 2025-03-26 and later).
type toolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// toolDescriptor is the tools/list entry for a tool.
type toolDescriptor struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description"`
	InputSchema json.RawMessage  `json:"inputSchema"`
	Annotations *toolAnnotations `json:"annotations,omitempty"`
}

// descriptor renders the tool for the negotiated protocol version, leaving out
// members the version does not define.
func (t *tool) descriptor(protocol string) toolDescriptor {
	d := toolDescriptor{Name: t.name, Description: t.description, InputSchema: t.schema}
	if protocol >= titlesSince {
		d.Title = t.title
	}
	if protocol >= annotationsSince {
		d.Annotations = &toolAnnotations{
			Title:           t.title,
			ReadOnlyHint:    true,
			DestructiveHint: false,
			IdempotentHint:  true,
			OpenWorldHint:   false,
		}
	}
	return d
}

// newTools returns the tools in the order tools/list reports them.
func newTools() []*tool {
	return []*tool{
		{
			name:  toolAnalyze,
			title: "Analyse a file (static triage)",
			description: "Statically analyse one file without ever executing it: native executables (PE, ELF, Mach-O), .NET and Go binaries, " +
				"APK/AAB/JAR packages, Electron ASAR archives, ZIP-family archives, WebAssembly, GGUF/safetensors models, SQLite, PDF and more. " +
				"Returns a teardown.report/v1 document: detected type, MD5/SHA-1/SHA-256 (and imphash for PE), entropy profile, sections, " +
				"imports and exports, classified strings (secrets are redacted), hardening flags (ASLR, DEP, PIE, RELRO, canary, signature), " +
				"findings that each carry evidence and limitations, and a 0-100 triage risk score. Findings and the score are triage hints, not verdicts. " +
				"With detail=summary (the default) long lists are trimmed; the 'note' and 'trimmed' members say what was cut.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"},
    "minString": {"type": "integer", "minimum": 3, "maximum": 256, "default": 5, "description": "Minimum length of extracted strings (ASCII and UTF-16LE)."},
    "maxStrings": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 2000, "description": "Maximum number of string items the analysis keeps."},
    "detail": {"type": "string", "enum": ["summary", "full"], "default": "summary", "description": "summary trims long lists (40 most interesting strings, 25 functions per import library, 50 entries per list) to keep the response small; full returns everything that fits the server's output cap."}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).analyzeFile,
		},
		{
			name:  toolStrings,
			title: "List extracted strings",
			description: "List the strings extracted from a file (ASCII and UTF-16LE) with category, file offset and encoding. " +
				"Categories: url, domain, ip, email, path, registry, command, base64, hex, api, useragent, secret, plain. " +
				"Secrets are redacted (first four characters and length only). Filter with category and query, page with limit and offset.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"},
    "category": {"type": "string", "description": "Only strings of these categories: one value or a comma-separated list of url, domain, ip, email, path, registry, command, base64, hex, api, useragent, secret, plain."},
    "query": {"type": "string", "description": "Case-insensitive substring the string must contain. Secrets are matched in their redacted form."},
    "minLength": {"type": "integer", "minimum": 3, "maximum": 256, "default": 5, "description": "Minimum string length."},
    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100, "description": "Page size."},
    "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "Number of matching strings to skip."}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).listStrings,
		},
		{
			name:  toolHash,
			title: "Hash a file",
			description: "Compute MD5, SHA-1 and SHA-256 of a file in one pass, plus the PE import hash (imphash) when the file is a PE with imports, " +
				"and report the detected file type. Cheaper than analyze_file.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).hashFile,
		},
		{
			name:  toolEntropy,
			title: "Entropy profile of a file",
			description: "Shannon entropy (bits per byte, 0 to 8) of the whole file and of at most 512 equal windows, plus the entropy of each section of an executable. " +
				"Values above about 7.2 suggest compressed, encrypted or packed data; code and text are usually well below 7. " +
				"This runs the full analysis and projects its entropy parts.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).entropyProfile,
		},
		{
			name:  toolDiff,
			title: "Compare two files",
			description: "Compare two files, for example two builds of one program, and describe what changed: hashes, detected type, sections, imports, exports, " +
				"strings, hardening flags, findings and risk score. Both files must lie inside the allowed roots.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "a": {"type": "string", "minLength": 1, "description": "The earlier or reference file. ` + pathDescription + `"},
    "b": {"type": "string", "minLength": 1, "description": "The later or changed file. ` + pathDescription + `"}
  },
  "required": ["a", "b"],
  "additionalProperties": false
}`),
			run: (*server).diffFiles,
		},
		{
			name:  toolDisassemble,
			title: "Disassemble x86 code",
			description: "Disassemble x86 and x86-64 machine code from a file without executing it: Intel syntax, at most 256 instructions per call. " +
				"Start at a virtual address (address, as 0x and hexadecimal digits or as decimal digits; PE, ELF and Mach-O images are mapped through " +
				"their section table or program headers, so the addresses are the ones the report shows), at a file offset (offset), or at neither to start " +
				"at the entry point. The instruction set comes from the file header; pass arch for raw bytes or to override the header. ARM64 and other " +
				"instruction sets are not supported. The result is a code block of kind disasm: lines with address, offset, bytes and text, and limitations " +
				"that say what it cannot show. In a PE image a line that calls or jumps through the import table carries a note naming the import " +
				"(\"KERNEL32.dll!VirtualAllocEx\"), as in the findings and in find_calls. " +
				"It is a linear sweep, so data can be shown as code and the sweep can lose sync; it is not a decompiler. " +
				"'next' says where to continue.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"},
    "address": {"type": "string", "pattern": "^(0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$", "description": "Virtual address to start at: 0x and hexadecimal digits, or decimal digits. It is a string because a JSON number cannot hold every 64-bit address. Not together with offset."},
    "offset": {"type": "integer", "minimum": 0, "description": "File offset to start at. Not together with address."},
    "count": {"type": "integer", "minimum": 1, "maximum": 256, "default": 24, "description": "Number of instructions to decode."},
    "arch": {"type": "string", "enum": ["x86", "x86-64"], "description": "Instruction set. By default it comes from the file header; it is required for raw bytes (a file that is not a PE, ELF or Mach-O image) and overrides the header when given."}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).disassemble,
		},
		{
			name:  toolFindCalls,
			title: "Find the calls to an imported function",
			description: "Find the places in the code of a PE image (x86 or x86-64) that call an imported function, without executing the file: for each call site " +
				"its address, file offset and section, how it refers to the import (a call through the import address table, through a thunk, a jump) and the " +
				"instructions around it, so the way the arguments are set up is visible. Name the function as the findings of analyze_file do, with or without " +
				"the library (\"KERNEL32.dll!VirtualAllocEx\" or \"VirtualAllocEx\"), in any case; the ANSI and wide spellings match together. " +
				"At most 100 sites per call; 'total' counts all of them. The result is a list of sites, each with a code block of kind disasm. " +
				"It is a linear sweep with a small built-in decoder: data can be shown as code, imports resolved at run time (GetProcAddress) are invisible, " +
				"packed code hides its calls, and it is not a decompiler. ELF, Mach-O and other instruction sets are not supported.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"},
    "api": {"type": "string", "minLength": 1, "maxLength": 256, "description": "The imported function to look for: 'Library!Function' or just 'Function', in any case. A name without a library matches the function of every library, and the ANSI and wide spellings (CreateProcessA, CreateProcessW) together."},
    "before": {"type": "integer", "minimum": 0, "maximum": 40, "default": 8, "description": "Instructions to show before each call."},
    "after": {"type": "integer", "minimum": 0, "maximum": 20, "default": 4, "description": "Instructions to show after each call."},
    "max": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10, "description": "Call sites to return; the best first (calls through the import table, then calls through thunks)."}
  },
  "required": ["path", "api"],
  "additionalProperties": false
}`),
			run: (*server).findCalls,
		},
		{
			name:  toolReadBytes,
			title: "Read raw bytes of a file",
			description: "Read a bounded window of the raw bytes of a file and return it as hex and ASCII rows of 16 bytes, at most 4096 bytes per call. " +
				"Use it to look at the bytes behind a finding, a string offset or a section reported by analyze_file. The result is a code block of kind hex " +
				"(offset, hex bytes and ASCII text per row), with the section the window starts in when the file is a PE, ELF or Mach-O image; 'next' says " +
				"where to continue. The file is read and never executed.",
			schema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {"type": "string", "minLength": 1, "description": "` + pathDescription + `"},
    "offset": {"type": "integer", "minimum": 0, "default": 0, "description": "File offset of the first byte of the window. It must lie inside the file."},
    "length": {"type": "integer", "minimum": 1, "maximum": 4096, "default": 128, "description": "Number of bytes to read; the window is cut short by the end of the file."}
  },
  "required": ["path"],
  "additionalProperties": false
}`),
			run: (*server).readBytes,
		},
	}
}

// decodeArgs strictly decodes tool arguments into dst (a pointer to a struct).
// Absent or null arguments decode as an empty object. Problems are returned as
// user errors that name the offending argument.
func decodeArgs(raw json.RawMessage, dst any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &typeErr):
			return userErrorf("argument %q must be %s (got %s)", typeErr.Field, jsonTypeName(typeErr.Type), typeErr.Value)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			name := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return userErrorf("unknown argument %s; check the tool's inputSchema", name)
		default:
			return userErrorf("invalid arguments: %s", err.Error())
		}
	}
	return nil
}

func jsonTypeName(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "a string"
	case reflect.Int, reflect.Int64, reflect.Int32:
		return "an integer"
	case reflect.Bool:
		return "a boolean"
	default:
		return t.String()
	}
}

// requireString returns the value of a required string argument.
func requireString(v *string, name string) (string, error) {
	if v == nil {
		return "", userErrorf("missing required argument %q", name)
	}
	return *v, nil
}

// int64Arg is intArg for 64-bit values such as file offsets.
func int64Arg(v *int64, name string, def, lo, hi int64) (int64, error) {
	if v == nil {
		return def, nil
	}
	if *v < lo || *v > hi {
		return 0, userErrorf("argument %q must be between %d and %d (got %d)", name, lo, hi, *v)
	}
	return *v, nil
}

// intArg returns an optional integer argument, checking its range.
func intArg(v *int, name string, def, lo, hi int) (int, error) {
	if v == nil {
		return def, nil
	}
	if *v < lo || *v > hi {
		return 0, userErrorf("argument %q must be between %d and %d (got %d)", name, lo, hi, *v)
	}
	return *v, nil
}
