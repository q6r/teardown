package server

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

// schemaProperty returns the schema of one property of a component schema.
func schemaProperty(t *testing.T, doc apiDoc, schema, prop string) map[string]any {
	t.Helper()
	var node map[string]any
	if err := json.Unmarshal(doc.Components.Schemas[schema], &node); err != nil {
		t.Fatalf("schema %s: %v", schema, err)
	}
	props, _ := node["properties"].(map[string]any)
	p, _ := props[prop].(map[string]any)
	if p == nil {
		t.Fatalf("schema %s has no property %q", schema, prop)
	}
	return p
}

// schemaRequired returns the sorted required members of a component schema.
func schemaRequired(t *testing.T, doc apiDoc, schema string) []string {
	t.Helper()
	var node struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(doc.Components.Schemas[schema], &node); err != nil {
		t.Fatal(err)
	}
	return sorted(node.Required)
}

// schemaPattern compiles the pattern of a component schema (the patterns used
// here are in the common subset of ECMAScript and RE2).
func schemaPattern(t *testing.T, doc apiDoc, schema string) *regexp.Regexp {
	t.Helper()
	var node struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(doc.Components.Schemas[schema], &node); err != nil || node.Pattern == "" {
		t.Fatalf("schema %s has no pattern (%v)", schema, err)
	}
	return regexp.MustCompile(node.Pattern)
}

func TestOpenAPIDescribesTheCodeBlocks(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)

	t.Run("kinds and bounds agree with the model", func(t *testing.T) {
		want := sorted([]string{report.CodeKindDisasm, report.CodeKindHex, report.CodeKindSource})
		if got := schemaEnum(t, doc, "CodeBlock", "kind"); !slices.Equal(got, want) {
			t.Errorf("kinds: document %v, model %v", got, want)
		}
		if got := schemaProperty(t, doc, "Finding", "code")["maxItems"]; got != float64(report.MaxCodeBlocks) {
			t.Errorf("Finding.code maxItems = %v, the model allows %d blocks", got, report.MaxCodeBlocks)
		}
		if got := schemaProperty(t, doc, "CodeBlock", "lines")["maxItems"]; got != float64(report.MaxCodeLines) {
			t.Errorf("CodeBlock.lines maxItems = %v, the model allows %d lines", got, report.MaxCodeLines)
		}
		if got := schemaProperty(t, doc, "CodeBlock", "limitations")["minItems"]; got != float64(1) {
			t.Errorf("a block always states a limitation, minItems = %v", got)
		}
	})

	t.Run("required members are the ones the model always writes", func(t *testing.T) {
		block, err := json.Marshal(report.CodeBlock{Kind: report.CodeKindHex, Lines: []report.CodeLine{{Text: "x"}}, Limitations: []string{"l"}})
		if err != nil {
			t.Fatal(err)
		}
		var blockKeys, lineKeys map[string]any
		if err := json.Unmarshal(block, &blockKeys); err != nil {
			t.Fatal(err)
		}
		line, _ := json.Marshal(report.CodeLine{Text: "x"})
		if err := json.Unmarshal(line, &lineKeys); err != nil {
			t.Fatal(err)
		}
		if got, want := schemaRequired(t, doc, "CodeBlock"), keysOf(blockKeys); !slices.Equal(got, want) {
			t.Errorf("CodeBlock required %v, a minimal block emits %v", got, want)
		}
		if got, want := schemaRequired(t, doc, "CodeLine"), keysOf(lineKeys); !slices.Equal(got, want) {
			t.Errorf("CodeLine required %v, a minimal line emits %v", got, want)
		}
	})

	t.Run("addresses are hexadecimal strings", func(t *testing.T) {
		re := schemaPattern(t, doc, "CodeAddress")
		for _, a := range []report.Addr{0, 0x1000, 0x140001042, 0xffffffffffffffff} {
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			var text string
			if err := json.Unmarshal(raw, &text); err != nil || !re.MatchString(text) {
				t.Errorf("%#x is written as %s, which the schema pattern %s rejects (%v)", uint64(a), raw, re, err)
			}
		}
		for _, bad := range []string{"140001042", "0x", "0x12345678901234567", "0xg", "", "-0x1", "0x 1"} {
			if re.MatchString(bad) {
				t.Errorf("the schema pattern accepts %q", bad)
			}
		}
		if got := schemaProperty(t, doc, "CodeBlock", "address")["$ref"]; got != "#/components/schemas/CodeAddress" {
			t.Errorf("CodeBlock.address is %v, not a CodeAddress", got)
		}
		if got := schemaProperty(t, doc, "CodeLine", "address")["$ref"]; got != "#/components/schemas/CodeAddress" {
			t.Errorf("CodeLine.address is %v, not a CodeAddress", got)
		}
	})

	t.Run("bytes are hex pairs", func(t *testing.T) {
		re := regexp.MustCompile(schemaProperty(t, doc, "CodeLine", "bytes")["pattern"].(string))
		for _, ok := range []string{"", "ff", "ff 15 b7 1f 00 00", "FF 15", strings.TrimSpace(strings.Repeat("ab ", 16))} {
			if !re.MatchString(ok) {
				t.Errorf("the pattern rejects %q", ok)
			}
			if (&report.CodeBlock{Kind: report.CodeKindHex, Lines: []report.CodeLine{{Bytes: ok, Text: "x"}}, Limitations: []string{"l"}}).Validate() != nil {
				t.Errorf("the model rejects %q", ok)
			}
		}
		for _, bad := range []string{"f", "ff  15", "ff 15 ", " ff", "gg", strings.TrimSpace(strings.Repeat("ab ", 17)), "ff-15"} {
			if re.MatchString(bad) {
				t.Errorf("the pattern accepts %q", bad)
			}
		}
	})
}
