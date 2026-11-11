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
	toolAnalyze = "analyze_file"
	toolStrings = "list_strings"
	toolHash    = "hash_file"
	toolEntropy = "entropy_profile"
	toolDiff    = "diff_files"
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
