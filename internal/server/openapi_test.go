package server

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

// apiDoc is the part of the OpenAPI document the tests look at.
type apiDoc struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
	raw map[string]any
}

// operation is one HTTP operation of the document.
type operation struct {
	OperationID string                     `json:"operationId"`
	Summary     string                     `json:"summary"`
	Tags        []string                   `json:"tags"`
	Parameters  []map[string]any           `json:"parameters"`
	Responses   map[string]json.RawMessage `json:"responses"`
}

var openAPIMethods = map[string]string{
	"get": http.MethodGet, "put": http.MethodPut, "post": http.MethodPost, "delete": http.MethodDelete,
	"options": http.MethodOptions, "head": http.MethodHead, "patch": http.MethodPatch, "trace": http.MethodTrace,
}

func fetchDoc(t *testing.T, s *Server) (apiDoc, []byte) {
	t.Helper()
	rec := do(t, s.Handler(), http.MethodGet, "/api/openapi.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	var doc apiDoc
	decode(t, rec, &doc)
	decode(t, rec, &doc.raw)
	return doc, rec.Body.Bytes()
}

func TestOpenAPIIsServedAndParses(t *testing.T) {
	s := newTestServer(t)
	doc, body := fetchDoc(t, s)
	if !bytes.Equal(body, openAPIDocument) {
		t.Error("the served document differs from the embedded one")
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q, want 3.1.0", doc.OpenAPI)
	}
	if doc.Info.Title == "" || doc.Info.Version == "" || len(doc.Paths) == 0 || len(doc.Components.Schemas) == 0 {
		t.Errorf("incomplete document: %+v", doc.Info)
	}
}

func TestOpenAPIAndRouteTableDescribeTheSameRoutes(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)

	documented := map[string]bool{}
	for path, item := range doc.Paths {
		for key := range item {
			method, ok := openAPIMethods[key]
			if !ok {
				continue // "parameters", "summary", ...
			}
			pattern := method + " " + path
			documented[pattern] = true
			target := strings.ReplaceAll(path, "{id}", "an_000000000000")
			_, matched := s.mux.Handler(httptest.NewRequest(method, target, nil))
			if matched != pattern {
				t.Errorf("documented operation %q is not routed: the mux matched %q", pattern, matched)
			}
		}
	}
	for _, rt := range s.table {
		if !documented[rt.pattern()] {
			t.Errorf("route %q is registered but not documented in openapi.json", rt.pattern())
		}
	}
	if len(documented) != len(s.table) {
		t.Errorf("the document has %d operations, the route table %d", len(documented), len(s.table))
	}
}

func TestOpenAPIOperationsAreWellFormed(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)
	ids := map[string]string{}
	for path, item := range doc.Paths {
		var pathParams []map[string]any
		if raw, ok := item["parameters"]; ok {
			if err := json.Unmarshal(raw, &pathParams); err != nil {
				t.Fatalf("%s: parameters: %v", path, err)
			}
		}
		for key, raw := range item {
			method, ok := openAPIMethods[key]
			if !ok {
				continue
			}
			var op operation
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			label := method + " " + path
			if op.OperationID == "" || op.Summary == "" || len(op.Tags) == 0 {
				t.Errorf("%s lacks operationId, summary or tags", label)
			}
			if other, dup := ids[op.OperationID]; dup {
				t.Errorf("operationId %q is used by %s and %s", op.OperationID, other, label)
			}
			ids[op.OperationID] = label
			hasSuccess := false
			for status := range op.Responses {
				if strings.HasPrefix(status, "2") {
					hasSuccess = true
				}
			}
			if !hasSuccess {
				t.Errorf("%s documents no 2xx response", label)
			}
			// Every {template} segment is a declared required path parameter.
			declared := map[string]bool{}
			for _, p := range append(slices.Clone(pathParams), op.Parameters...) {
				if p["$ref"] != nil {
					name := strings.TrimPrefix(p["$ref"].(string), "#/components/parameters/")
					declared[strings.ToLower(name)] = true
					continue
				}
				if p["in"] == "path" && p["required"] == true {
					declared[strings.ToLower(p["name"].(string))] = true
				}
			}
			for _, seg := range strings.Split(path, "/") {
				if strings.HasPrefix(seg, "{") {
					name := strings.ToLower(strings.Trim(seg, "{}"))
					if !declared[name] && !declared["analysisid"] {
						t.Errorf("%s: path parameter %s is not declared", label, seg)
					}
				}
			}
		}
	}
}

func TestOpenAPIReferencesResolve(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)
	refs := 0
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "$ref" {
					ref, _ := child.(string)
					refs++
					if !strings.HasPrefix(ref, "#/") {
						t.Errorf("unsupported $ref %q", ref)
						continue
					}
					var cur any = doc.raw
					for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
						m, ok := cur.(map[string]any)
						if !ok || m[part] == nil {
							t.Errorf("$ref %q does not resolve (stopped at %q)", ref, part)
							break
						}
						cur = m[part]
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc.raw)
	if refs < 20 {
		t.Errorf("only %d $refs found; the walk is probably broken", refs)
	}
}

// keysOf returns the sorted keys of a JSON object.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// schemaProps returns the sorted property names of a component schema,
// following allOf.
func schemaProps(t *testing.T, doc apiDoc, name string) []string {
	t.Helper()
	raw, ok := doc.Components.Schemas[name]
	if !ok {
		t.Fatalf("schema %q is missing", name)
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
		AllOf      []struct {
			Ref        string         `json:"$ref"`
			Properties map[string]any `json:"properties"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	props := map[string]any{}
	for k, v := range schema.Properties {
		props[k] = v
	}
	for _, part := range schema.AllOf {
		for k, v := range part.Properties {
			props[k] = v
		}
		if part.Ref != "" {
			for _, k := range schemaProps(t, doc, strings.TrimPrefix(part.Ref, "#/components/schemas/")) {
				props[k] = nil
			}
		}
	}
	return keysOf(props)
}

// schemaEnum returns the enum of a (possibly nested) schema property path.
func schemaEnum(t *testing.T, doc apiDoc, schema string, path ...string) []string {
	t.Helper()
	var node any
	if err := json.Unmarshal(doc.Components.Schemas[schema], &node); err != nil {
		t.Fatal(err)
	}
	for _, p := range path {
		m, _ := node.(map[string]any)
		props, _ := m["properties"].(map[string]any)
		if p == "items" {
			node = m["items"]
			continue
		}
		node = props[p]
	}
	m, _ := node.(map[string]any)
	if m == nil {
		t.Fatalf("schema %s %v not found", schema, path)
	}
	if ref, _ := m["$ref"].(string); ref != "" {
		return schemaEnum(t, doc, strings.TrimPrefix(ref, "#/components/schemas/"))
	}
	if items, ok := m["items"].(map[string]any); ok && m["enum"] == nil {
		if ref, _ := items["$ref"].(string); ref != "" {
			return schemaEnum(t, doc, strings.TrimPrefix(ref, "#/components/schemas/"))
		}
		m = items
	}
	var out []string
	for _, v := range m["enum"].([]any) {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}

func TestOpenAPISchemasMatchTheReportContract(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)

	// A fully populated report, so omitempty keys appear too.
	r := fakeReport("x.bin", 1)
	r.Sections = []report.Section{{Name: ".text", Flags: []string{report.FlagR}, Reasons: []string{"why"}}}
	r.Imports = []report.Import{{Library: "k.dll", Count: 1, Functions: []string{"f"}}}
	r.Strings.Items = []report.StringItem{{Value: "v", Kind: "k"}}
	r.Hardening = []report.Hardening{{ID: report.HardenASLR, Status: report.StatusEnabled}}
	r.Findings = []report.Finding{{ID: "a.b", Severity: report.SeverityLow}}
	r.Normalize()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	first := func(v any) map[string]any { return v.([]any)[0].(map[string]any) }
	obj := func(v any) map[string]any { return v.(map[string]any) }
	strs := obj(m["strings"])

	reportShapes := map[string]map[string]any{
		"Report":      m,
		"Tool":        obj(m["tool"]),
		"File":        obj(m["file"]),
		"ContentType": obj(m["type"]),
		"Hashes":      obj(m["hashes"]),
		"Entropy":     obj(m["entropy"]),
		"Section":     first(m["sections"]),
		"Import":      first(m["imports"]),
		"Strings":     strs,
		"StringItem":  first(strs["items"]),
		"Hardening":   first(m["hardening"]),
		"Finding":     first(m["findings"]),
		"Risk":        obj(m["risk"]),
	}
	for name, shape := range reportShapes {
		if got, want := schemaProps(t, doc, name), keysOf(shape); !slices.Equal(got, want) {
			t.Errorf("schema %s documents %v, the report emits %v", name, got, want)
		}
	}

	// The server's own payloads.
	own := map[string]any{
		"Health":          healthBody{},
		"AnalyzeResponse": analyzeResponse{},
		"AnalysisSummary": summary{},
		"RiskBrief":       riskBrief{},
		"StringsPage":     stringsPage{Items: []report.StringItem{}},
		"EventStarted":    startedEvent{},
		"EventCompleted":  completedEvent{},
		"EventFailed":     failedEvent{},
	}
	for name, v := range own {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var shape map[string]any
		if err := json.Unmarshal(b, &shape); err != nil {
			t.Fatal(err)
		}
		if got, want := schemaProps(t, doc, name), keysOf(shape); !slices.Equal(got, want) {
			t.Errorf("schema %s documents %v, the server emits %v", name, got, want)
		}
	}

	// Enumerations agree with the code.
	sev := make([]string, 0, 5)
	for _, v := range report.Severities() {
		sev = append(sev, string(v))
	}
	enums := []struct {
		name string
		got  []string
		want []string
	}{
		{"string categories", schemaEnum(t, doc, "StringCategory"), sorted(report.StringCategories())},
		{"finding severity", schemaEnum(t, doc, "Finding", "severity"), sorted(sev)},
		{"finding confidence", schemaEnum(t, doc, "Finding", "confidence"), []string{"high", "low", "medium"}},
		{"risk label", schemaEnum(t, doc, "Risk", "label"), sorted([]string{report.RiskLow, report.RiskMedium, report.RiskHigh, report.RiskCritical})},
		{"summary risk label", schemaEnum(t, doc, "RiskBrief", "label"), sorted([]string{report.RiskLow, report.RiskMedium, report.RiskHigh, report.RiskCritical})},
		{"hardening status", schemaEnum(t, doc, "Hardening", "status"), sorted([]string{report.StatusEnabled, report.StatusDisabled, report.StatusUnknown, report.StatusNA})},
		{"section flags", schemaEnum(t, doc, "Section", "flags", "items"), []string{report.FlagR, report.FlagW, report.FlagX}},
		{"string encoding", schemaEnum(t, doc, "StringItem", "encoding"), []string{"ascii", "utf16le"}},
	}
	for _, e := range enums {
		if !slices.Equal(e.got, e.want) {
			t.Errorf("%s: document %v, code %v", e.name, e.got, e.want)
		}
	}
}

// errorCodeConstants reads the code* string constants from respond.go.
func errorCodeConstants(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "respond.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || !strings.HasPrefix(spec.Names[0].Name, "code") || len(spec.Values) != 1 {
			return true
		}
		if lit, ok := spec.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, value)
		}
		return true
	})
	sort.Strings(out)
	return out
}

func TestOpenAPIListsEveryErrorCode(t *testing.T) {
	s := newTestServer(t)
	doc, _ := fetchDoc(t, s)
	codes := errorCodeConstants(t)
	if len(codes) < 10 {
		t.Fatalf("found only %d error code constants: %v", len(codes), codes)
	}
	var node struct {
		Properties struct {
			Error struct {
				Properties struct {
					Code struct {
						Enum []string `json:"enum"`
					} `json:"code"`
				} `json:"properties"`
			} `json:"error"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(doc.Components.Schemas["Error"], &node); err != nil {
		t.Fatal(err)
	}
	if got := sorted(node.Properties.Error.Properties.Code.Enum); !slices.Equal(got, codes) {
		t.Errorf("Error.code enum %v differs from the code constants %v", got, codes)
	}
}

// TestOpenAPIDocumentsTheStatusesTheServerReturns drives every operation into
// each status it can return and checks the document lists it.
func TestOpenAPIDocumentsTheStatusesTheServerReturns(t *testing.T) {
	normal := newTestServer(t, withAnalyzer(stringsAnalyzer))
	small := newTestServer(t, func(c *Config) { c.MaxUpload = 10 }, withAnalyzer(echoAnalyzer))
	timeout := newTestServer(t, withAnalyzer(func(context.Context, string, analyze.Options) (*report.Report, error) {
		return nil, context.DeadlineExceeded
	}))
	failing := newTestServer(t, withAnalyzer(func(context.Context, string, analyze.Options) (*report.Report, error) {
		return nil, context.Canceled
	}))
	g := newGatedAnalyzer()
	busy := newTestServer(t, func(c *Config) { c.Concurrency = 1 }, withAnalyzer(g.analyze))
	busy.queueWait = 20 * time.Millisecond
	noStreams := newTestServer(t)
	noStreams.hub = newHub(0)
	doc, _ := fetchDoc(t, normal)

	id := mustUpload(t, normal.Handler(), "doc.bin", sampleBytes(10)).ID
	wrongHost := func(target, method string) *httptest.ResponseRecorder {
		req := newRequest(method, target, nil)
		req.Host = "evil.example"
		rec := httptest.NewRecorder()
		normal.Handler().ServeHTTP(rec, req)
		return rec
	}
	upload := func(s *Server) *httptest.ResponseRecorder {
		return postUpload(t, s.Handler(), "x.bin", sampleBytes(100))
	}
	ordinary := func(method, target string) *httptest.ResponseRecorder {
		return do(t, normal.Handler(), method, target, nil)
	}

	// Occupy the only slot of the busy server so its next upload times out in the queue.
	go func() { _, _ = uploadAsync(busy.Handler(), "hold.bin", sampleBytes(10)) }()
	<-g.started
	t.Cleanup(func() { close(g.gate) })

	emptyBody := func() *httptest.ResponseRecorder {
		return do(t, normal.Handler(), http.MethodPost, "/api/analyze", strings.NewReader("--b--\r\n"), "Content-Type", "multipart/form-data; boundary=b")
	}
	observed := []struct {
		method, template string
		rec              *httptest.ResponseRecorder
	}{
		{"GET", "/api/health", ordinary("GET", "/api/health")},
		{"GET", "/api/health", wrongHost("/api/health", "GET")},
		{"POST", "/api/analyze", upload(normal)},
		{"POST", "/api/analyze", emptyBody()},
		{"POST", "/api/analyze", do(t, normal.Handler(), "POST", "/api/analyze", strings.NewReader("{}"), "Content-Type", "application/json")},
		{"POST", "/api/analyze", upload(small)},
		{"POST", "/api/analyze", upload(timeout)},
		{"POST", "/api/analyze", upload(failing)},
		{"POST", "/api/analyze", upload(busy)},
		{"POST", "/api/analyze", do(t, normal.Handler(), "POST", "/api/analyze", nil, "Origin", "http://evil.example")},
		{"GET", "/api/analyses", ordinary("GET", "/api/analyses")},
		{"GET", "/api/analyses/{id}", ordinary("GET", "/api/analyses/"+id)},
		{"GET", "/api/analyses/{id}", ordinary("GET", "/api/analyses/an_000000000000")},
		{"DELETE", "/api/analyses/{id}", ordinary("DELETE", "/api/analyses/an_000000000000")},
		{"GET", "/api/analyses/{id}/strings", ordinary("GET", "/api/analyses/"+id+"/strings")},
		{"GET", "/api/analyses/{id}/strings", ordinary("GET", "/api/analyses/"+id+"/strings?limit=0")},
		{"GET", "/api/analyses/{id}/strings", ordinary("GET", "/api/analyses/an_000000000000/strings")},
		{"GET", "/api/events", do(t, noStreams.Handler(), "GET", "/api/events", nil)},
		{"GET", "/api/openapi.json", ordinary("GET", "/api/openapi.json")},
		{"GET", "/", ordinary("GET", "/")},
		{"GET", "/", ordinary("GET", "/missing.txt")},
		{"DELETE", "/api/analyses/{id}", ordinary("DELETE", "/api/analyses/"+id)}, // last: it removes the report
	}
	for _, o := range observed {
		var op operation
		raw, ok := doc.Paths[o.template][strings.ToLower(o.method)]
		if !ok {
			t.Errorf("%s %s is not documented", o.method, o.template)
			continue
		}
		if err := json.Unmarshal(raw, &op); err != nil {
			t.Fatal(err)
		}
		if _, ok := op.Responses[strconv.Itoa(o.rec.Code)]; !ok {
			t.Errorf("%s %s answered %d, which the document does not list (it lists %v)", o.method, o.template, o.rec.Code, keysOfRaw(op.Responses))
		}
	}
}

func keysOfRaw(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestOpenAPIExampleIDMatchesThePattern(t *testing.T) {
	// The documented identifier example and pattern must agree with the real format.
	re := regexp.MustCompile(`"examples": \["(an_[0-9a-f]+)"\]`)
	for _, m := range re.FindAllSubmatch(openAPIDocument, -1) {
		if !idPattern.Match(m[1]) {
			t.Errorf("example id %q does not match %s", m[1], idPattern)
		}
	}
}
