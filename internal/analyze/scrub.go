package analyze

import (
	"bytes"
	"encoding/json"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/strs"
)

// scrubSecrets is the last line of defence for the promise that secrets are
// redacted in every output. The string scanner already redacts the strings it
// classifies; this pass also covers values that reach the report by other
// routes (Go linker flags, manifest attributes, package.json fields, archive
// entry names, GGUF metadata, ...) by replacing any secret-looking substring in
// the format details and in the findings.
func scrubSecrets(rep *report.Report) {
	for key, v := range rep.Details {
		rep.Details[key] = scrubValue(v)
	}
	for i := range rep.Findings {
		f := &rep.Findings[i]
		f.Title, _ = strs.RedactSecrets(f.Title)
		for j, e := range f.Evidence {
			f.Evidence[j], _ = strs.RedactSecrets(e)
		}
	}
}

// scrubValue converts a typed details value to its generic JSON form (keeping
// numbers exact) with every string redacted.
func scrubValue(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return v
	}
	return scrubWalk(generic)
}

func scrubWalk(v any) any {
	switch t := v.(type) {
	case string:
		s, _ := strs.RedactSecrets(t)
		return s
	case []any:
		for i := range t {
			t[i] = scrubWalk(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = scrubWalk(t[k])
		}
		return t
	default:
		return v
	}
}
