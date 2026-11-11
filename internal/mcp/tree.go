package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxTreeDepth bounds recursion while parsing a document into a tree.
const maxTreeDepth = 128

type nodeKind uint8

const (
	kindScalar nodeKind = iota
	kindObject
	kindArray
)

// node is an order-preserving JSON document tree. Tool results are converted to
// a tree so they can be trimmed to the output cap and pretty-printed without
// losing the field order of the report (a map[string]any would sort the keys).
type node struct {
	kind nodeKind
	raw  []byte   // scalar: the JSON text
	keys []string // object: member names, parallel to kids
	kids []*node  // object members or array elements
}

// parseTree parses one JSON document. Numbers keep their exact text.
func parseTree(data []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	n, err := readNode(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return n, nil
}

// treeOf converts any JSON-marshalable value to a tree.
func treeOf(v any) (*node, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return parseTree(data)
}

func readNode(dec *json.Decoder, depth int) (*node, error) {
	if depth > maxTreeDepth {
		return nil, errors.New("JSON nesting is too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return readObject(dec, depth)
		case '[':
			return readArray(dec, depth)
		}
	case string:
		return &node{kind: kindScalar, raw: appendQuoted(nil, t)}, nil
	case json.Number:
		return &node{kind: kindScalar, raw: []byte(t.String())}, nil
	case bool:
		return &node{kind: kindScalar, raw: []byte(strconv.FormatBool(t))}, nil
	case nil:
		return &node{kind: kindScalar, raw: []byte("null")}, nil
	}
	return nil, fmt.Errorf("unexpected JSON token %v", tok)
}

func readObject(dec *json.Decoder, depth int) (*node, error) {
	n := &node{kind: kindObject}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("object key is %T, want a string", kt)
		}
		v, err := readNode(dec, depth+1)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.kids = append(n.kids, v)
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	return n, nil
}

func readArray(dec *json.Decoder, depth int) (*node, error) {
	n := &node{kind: kindArray}
	for dec.More() {
		v, err := readNode(dec, depth+1)
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, v)
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return nil, err
	}
	return n, nil
}

// Constructors for values added while decorating a result.

func stringNode(s string) *node { return &node{kind: kindScalar, raw: appendQuoted(nil, s)} }
func boolNode(b bool) *node     { return &node{kind: kindScalar, raw: []byte(strconv.FormatBool(b))} }
func intNode(i int) *node       { return &node{kind: kindScalar, raw: []byte(strconv.Itoa(i))} }

func int64Node(i int64) *node { return &node{kind: kindScalar, raw: []byte(strconv.FormatInt(i, 10))} }

// child returns the object member with the given key, or nil.
func (n *node) child(key string) *node {
	if n == nil || n.kind != kindObject {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.kids[i]
		}
	}
	return nil
}

// at follows a path of object keys.
func (n *node) at(path ...string) *node {
	for _, key := range path {
		n = n.child(key)
		if n == nil {
			return nil
		}
	}
	return n
}

// setKey replaces the member with the given key or appends it.
func (n *node) setKey(key string, v *node) {
	for i, k := range n.keys {
		if k == key {
			n.kids[i] = v
			return
		}
	}
	n.keys = append(n.keys, key)
	n.kids = append(n.kids, v)
}

// delKey removes the member with the given key.
func (n *node) delKey(key string) {
	for i, k := range n.keys {
		if k == key {
			n.keys = append(n.keys[:i], n.keys[i+1:]...)
			n.kids = append(n.kids[:i], n.kids[i+1:]...)
			return
		}
	}
}

// stringValue returns the decoded value of a string scalar.
func (n *node) stringValue() (string, bool) {
	if n == nil || n.kind != kindScalar || len(n.raw) == 0 || n.raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(n.raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// weight returns the number of nodes in the subtree, a cheap size proxy.
func (n *node) weight() int {
	w := 1
	for _, k := range n.kids {
		w += k.weight()
	}
	return w
}

// compact serialises the tree without whitespace.
func (n *node) compact() []byte {
	var b bytes.Buffer
	n.writeCompact(&b)
	return b.Bytes()
}

// writeQuoted writes s as a JSON string literal straight into the buffer.
func writeQuoted(b *bytes.Buffer, s string) {
	b.Write(appendQuoted(b.AvailableBuffer(), s))
}

func (n *node) writeCompact(b *bytes.Buffer) {
	switch n.kind {
	case kindScalar:
		b.Write(n.raw)
	case kindObject:
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeQuoted(b, k)
			b.WriteByte(':')
			n.kids[i].writeCompact(b)
		}
		b.WriteByte('}')
	case kindArray:
		b.WriteByte('[')
		for i, k := range n.kids {
			if i > 0 {
				b.WriteByte(',')
			}
			k.writeCompact(b)
		}
		b.WriteByte(']')
	}
}

// pretty serialises the tree with two-space indentation. Short arrays of
// scalars stay on one line so entropy windows and name lists remain readable.
func (n *node) pretty() string {
	var b bytes.Buffer
	n.writePretty(&b, 0)
	return b.String()
}

func writeIndent(b *bytes.Buffer, depth int) {
	for range depth {
		b.WriteString("  ")
	}
}

func (n *node) writePretty(b *bytes.Buffer, depth int) {
	switch n.kind {
	case kindScalar:
		b.Write(n.raw)
	case kindObject:
		if len(n.kids) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range n.keys {
			writeIndent(b, depth+1)
			writeQuoted(b, k)
			b.WriteString(": ")
			n.kids[i].writePretty(b, depth+1)
			if i < len(n.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		writeIndent(b, depth)
		b.WriteByte('}')
	case kindArray:
		if len(n.kids) == 0 {
			b.WriteString("[]")
			return
		}
		if n.inline() {
			b.WriteByte('[')
			for i, k := range n.kids {
				if i > 0 {
					b.WriteString(", ")
				}
				b.Write(k.raw)
			}
			b.WriteByte(']')
			return
		}
		b.WriteString("[\n")
		for i, k := range n.kids {
			writeIndent(b, depth+1)
			k.writePretty(b, depth+1)
			if i < len(n.kids)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		writeIndent(b, depth)
		b.WriteByte(']')
	}
}

// inline reports whether an array is printed on a single line: it holds only
// scalars and is either all non-strings (numbers, booleans) or short.
func (n *node) inline() bool {
	width := 0
	nonStrings := true
	for _, k := range n.kids {
		if k.kind != kindScalar {
			return false
		}
		if len(k.raw) > 0 && k.raw[0] == '"' {
			nonStrings = false
		}
		width += len(k.raw) + 2
	}
	return nonStrings || width <= 100
}

// appendQuoted appends s as a JSON string literal. Unlike encoding/json it does
// not HTML-escape <, > and &, which keeps URLs and command lines readable. The
// line and paragraph separators U+2028 and U+2029 are escaped so a document
// stays safe for line-oriented readers and for embedding in scripts.
func appendQuoted(dst []byte, s string) []byte {
	const (
		hexDigits     = "0123456789abcdef"
		lineSeparator = 0x2028
		paraSeparator = 0x2029
	)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	dst = append(dst, '"')
	for _, r := range s {
		switch {
		case r == '"':
			dst = append(dst, '\\', '"')
		case r == '\\':
			dst = append(dst, '\\', '\\')
		case r == '\n':
			dst = append(dst, '\\', 'n')
		case r == '\r':
			dst = append(dst, '\\', 'r')
		case r == '\t':
			dst = append(dst, '\\', 't')
		case r == lineSeparator:
			dst = append(dst, '\\', 'u', '2', '0', '2', '8')
		case r == paraSeparator:
			dst = append(dst, '\\', 'u', '2', '0', '2', '9')
		case r < 0x20 || r == 0x7f:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[r>>4], hexDigits[r&0xf])
		default:
			dst = utf8.AppendRune(dst, r)
		}
	}
	return append(dst, '"')
}
