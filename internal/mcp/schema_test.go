package mcp

import (
	"fmt"
	"math"
	"slices"
	"sort"
)

// validateSchema checks v (decoded JSON) against the JSON Schema subset the
// tool schemas use: type, enum, minimum, maximum, minLength, required,
// properties and additionalProperties:false. It returns the violations found.
func validateSchema(schema map[string]any, v any) []string {
	var out []string
	check(schema, v, "$", &out)
	return out
}

func check(schema map[string]any, v any, path string, out *[]string) {
	if typ, ok := schema["type"].(string); ok && !hasType(typ, v) {
		*out = append(*out, fmt.Sprintf("%s: want %s, got %T", path, typ, v))
		return
	}
	if enum, ok := schema["enum"].([]any); ok && !slices.Contains(enum, v) {
		*out = append(*out, fmt.Sprintf("%s: %v is not one of %v", path, v, enum))
	}
	if f, ok := v.(float64); ok {
		if m, ok := schema["minimum"].(float64); ok && f < m {
			*out = append(*out, fmt.Sprintf("%s: %v < minimum %v", path, f, m))
		}
		if m, ok := schema["maximum"].(float64); ok && f > m {
			*out = append(*out, fmt.Sprintf("%s: %v > maximum %v", path, f, m))
		}
	}
	if s, ok := v.(string); ok {
		if m, ok := schema["minLength"].(float64); ok && float64(len([]rune(s))) < m {
			*out = append(*out, fmt.Sprintf("%s: shorter than minLength %v", path, m))
		}
	}
	obj, isObj := v.(map[string]any)
	if !isObj {
		return
	}
	props, _ := schema["properties"].(map[string]any)
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if _, present := obj[r.(string)]; !present {
				*out = append(*out, fmt.Sprintf("%s: missing required property %q", path, r))
			}
		}
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sub, known := props[k].(map[string]any)
		if !known {
			if ap, ok := schema["additionalProperties"].(bool); ok && !ap {
				*out = append(*out, fmt.Sprintf("%s: additional property %q is not allowed", path, k))
			}
			continue
		}
		check(sub, obj[k], path+"."+k, out)
	}
}

func hasType(typ string, v any) bool {
	switch typ {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	}
	return false
}
