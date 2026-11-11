// Package asar reads Electron ASAR archives: the JSON file index, the
// application's package.json and, as evidence only, text in the application's
// own JavaScript that points at risky Electron settings.
//
// An ASAR file is a Chromium pickle holding a JSON index followed by the packed
// file contents. Nothing is extracted and nothing is executed; the index is
// streamed with fixed nesting and size limits so a hostile header costs little.
package asar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
)

const (
	// framingSize is the fixed prefix: pickle size, header size, payload size, JSON length.
	framingSize = 16
	// maxDepth bounds the nesting of the JSON index.
	maxDepth = 64
	// maxNameLen bounds a recorded path.
	maxNameLen = 512
)

// Result is the outcome of [Parse]. Details is stored under report.details["asar"].
type Result struct {
	Details Details
	// Notes lists non-fatal problems met while parsing.
	Notes []string
	// Limitations qualify the facts (for example how the hints were found). They
	// belong in the report's limitations rather than among its warnings.
	Limitations []string
}

// Details are the ASAR-specific facts.
type Details struct {
	// HeaderSize is the header size field of the size pickle; file data starts
	// at offset DataOffset (8 + HeaderSize).
	HeaderSize int64 `json:"headerSize"`
	DataOffset int64 `json:"dataOffset"`
	// FileCount and DirectoryCount are the true numbers of entries in the index.
	FileCount      int `json:"fileCount"`
	DirectoryCount int `json:"directoryCount"`
	// Files lists file paths in index order, capped by limits.MaxList.
	Files          []string `json:"files"`
	FilesTruncated bool     `json:"filesTruncated"`
	// UnpackedCount counts files kept outside the archive (app.asar.unpacked).
	UnpackedCount int `json:"unpackedCount"`
	// TotalSize sums the declared sizes of all files, packed and unpacked.
	TotalSize uint64 `json:"totalSize"`
	// Package is the application's package.json, or null when none was found
	// or it could not be read.
	Package *Package `json:"package"`
	// Hints are evidence only: text found in the application's JavaScript that
	// matches risky Electron settings. They prove nothing about behaviour.
	Hints []Hint `json:"hints"`
}

// Package holds the fields of the application's package.json that matter for triage.
type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Main        string `json:"main"`
	Description string `json:"description"`
	// Electron is the version range declared for "electron" in dependencies or
	// devDependencies ("" when absent).
	Electron string `json:"electron"`
	// Dependencies lists the names of runtime dependencies, sorted.
	Dependencies []string `json:"dependencies"`
}

// Hint is one piece of evidence. ID is one of node-integration,
// context-isolation-disabled, web-security-disabled, remote-module-enabled,
// insecure-content, no-sandbox or child-process; Evidence is "<file>: <matched
// text>" where the matched text is only the flag itself.
type Hint struct {
	ID       string `json:"id"`
	Evidence string `json:"evidence"`
}

// Parse analyses the ASAR archive in r (size bytes). It returns (nil, err) when
// r is not an ASAR archive; a damaged index yields a partial result with notes.
// When ctx ends mid-way the partial result is returned with ctx's error.
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	lim = lim.Normalize()
	head, err := binio.ReadAt(r, size, 0, framingSize)
	if err != nil {
		return nil, fmt.Errorf("asar: %d bytes is too small to hold the 16-byte header", size)
	}
	c := binio.NewCursor(head, binary.LittleEndian)
	pickle, headerSize, payload, jsonLen := c.U32(), int64(c.U32()), int64(c.U32()), int64(c.U32())
	if pickle != 4 {
		return nil, errors.New("asar: not an ASAR archive (the size pickle must start with the value 4)")
	}
	if jsonLen <= 0 || jsonLen > size-framingSize {
		return nil, fmt.Errorf("asar: the index length %d does not fit the %d byte file", jsonLen, size)
	}
	if jsonLen > lim.MaxMeta {
		return nil, fmt.Errorf("asar: the index is %d bytes, above the %d byte limit", jsonLen, lim.MaxMeta)
	}

	res := &Result{
		Details: Details{
			HeaderSize: headerSize, DataOffset: 8 + headerSize,
			Files: []string{}, Hints: []Hint{},
		},
		Limitations: []string{
			fmt.Sprintf("Electron hints are textual matches in at most %d application scripts (the first %d KiB of each); code under node_modules is not scanned, minified or obfuscated code can hide settings, and a match does not show that the setting is in effect.", maxJSFiles, maxScriptScan>>10),
		},
	}
	if payload != headerSize-4 || payload < 4+jsonLen {
		res.Notes = append(res.Notes, fmt.Sprintf("the header sizes are inconsistent (header %d, payload %d, index %d)", headerSize, payload, jsonLen))
	}
	if res.Details.DataOffset < framingSize+jsonLen {
		res.Details.DataOffset = framingSize + (jsonLen+3)&^3
		res.Notes = append(res.Notes, fmt.Sprintf("the header size %d cannot hold the index; file data is assumed to start at %d", headerSize, res.Details.DataOffset))
	}
	if res.Details.DataOffset > size {
		res.Notes = append(res.Notes, fmt.Sprintf("the file data would start at %d, beyond the end of the %d byte file: the archive is truncated", res.Details.DataOffset, size))
	}

	index, err := binio.ReadAt(r, size, framingSize, jsonLen)
	if err != nil {
		return nil, fmt.Errorf("asar: reading the index: %w", err)
	}
	if depth := jsonDepth(index, maxDepth); depth > maxDepth {
		res.Notes = append(res.Notes, fmt.Sprintf("the index nests deeper than %d levels and was not parsed", maxDepth))
		return res, nil
	}

	w := newWalker(r, size, lim, &res.Details)
	if err := w.run(ctx, index); err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		res.Notes = append(res.Notes, fmt.Sprintf("the index could not be fully parsed: %v", err))
	}
	res.Notes = append(res.Notes, w.notes()...)
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	res.Notes = append(res.Notes, w.inspect(ctx)...)
	return res, ctx.Err()
}

// jsonDepth returns the nesting depth of braces and brackets outside strings,
// stopping as soon as it exceeds limit (the value returned is then limit+1).
func jsonDepth(b []byte, limit int) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range b {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			deepest = max(deepest, depth)
			if deepest > limit {
				return deepest
			}
		case '}', ']':
			depth = max(depth-1, 0)
		}
	}
	return deepest
}
