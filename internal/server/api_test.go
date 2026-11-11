package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

func listSummaries(t *testing.T, s *Server) []summary {
	t.Helper()
	rec := do(t, s.Handler(), http.MethodGet, "/api/analyses", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", rec.Code, rec.Body.String())
	}
	var out []summary
	decode(t, rec, &out)
	return out
}

func TestListGetDelete(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	fixed := time.Date(2026, 11, 10, 14, 3, 5, 123_456_789, time.UTC)
	s.now = func() time.Time { return fixed }
	h := s.Handler()

	// An empty ring is an empty JSON array, never null.
	empty := do(t, h, http.MethodGet, "/api/analyses", nil)
	if got := strings.TrimSpace(empty.Body.String()); got != "[]" {
		t.Fatalf("empty list = %q, want []", got)
	}

	first := mustUpload(t, h, "first.bin", sampleBytes(100))
	second := mustUpload(t, h, "second.bin", sampleBytes(250))

	list := listSummaries(t, s)
	if len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
		t.Fatalf("list must be newest first: %+v", list)
	}
	want := summary{
		ID: second.ID, Name: "second.bin", Size: 250, Type: report.TypePE, TypeLabel: "PE32+ executable (test)",
		Risk:      riskBrief{Score: 42, Label: report.RiskMedium},
		CreatedAt: fixed.Truncate(time.Millisecond),
	}
	if !reflect.DeepEqual(list[0], want) {
		t.Errorf("summary =\n %+v\nwant\n %+v", list[0], want)
	}

	// The summary has exactly the documented keys.
	raw := do(t, h, http.MethodGet, "/api/analyses", nil)
	var generic []map[string]any
	decode(t, raw, &generic)
	for _, key := range []string{"id", "name", "size", "type", "typeLabel", "risk", "createdAt"} {
		if _, ok := generic[0][key]; !ok {
			t.Errorf("summary lacks %q", key)
		}
	}
	if risk, _ := generic[0]["risk"].(map[string]any); len(risk) != 2 {
		t.Errorf("risk = %v, want exactly score and label", risk)
	}

	// Get.
	got := do(t, h, http.MethodGet, "/api/analyses/"+first.ID, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get status %d", got.Code)
	}
	var rep report.Report
	decode(t, got, &rep)
	if rep.File.Name != "first.bin" || rep.File.Size != 100 {
		t.Errorf("fetched report = %+v", rep.File)
	}

	// Delete, then it is gone; deleting again is a 404.
	del := do(t, h, http.MethodDelete, "/api/analyses/"+first.ID, nil)
	if del.Code != http.StatusNoContent || del.Body.Len() != 0 {
		t.Errorf("delete = %d with %q", del.Code, del.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		rec := do(t, h, method, "/api/analyses/"+first.ID, nil)
		if rec.Code != http.StatusNotFound || errorCode(t, rec) != codeNotFound {
			t.Errorf("%s after delete = %d: %s", method, rec.Code, rec.Body.String())
		}
	}
	if after := listSummaries(t, s); len(after) != 1 || after[0].ID != second.ID {
		t.Errorf("list after delete = %+v", after)
	}
}

func TestUnknownAndMalformedIDsAre404(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	known := mustUpload(t, s.Handler(), "a.bin", sampleBytes(10))
	ids := []string{
		"an_000000000000",                      // well-formed but unknown
		"an_zzzzzzzzzzzz",                      // not hex
		strings.ToUpper(known.ID),              // case matters
		"an_" + strings.Repeat("a", 13),        // too long
		"an_abc",                               // too short
		"..%2F..%2Fetc%2Fpasswd",               // traversal attempt
		"%00",                                  // NUL
		"an_000000000000%0d%0aX-Injected:%201", // header injection attempt
		"%3Cscript%3Ealert(1)%3C%2Fscript%3E",  // markup
	}
	for _, id := range ids {
		for _, suffix := range []string{"", "/strings"} {
			rec := do(t, s.Handler(), http.MethodGet, "/api/analyses/"+id+suffix, nil)
			if rec.Code != http.StatusNotFound || errorCode(t, rec) != codeNotFound {
				t.Errorf("GET %q%s = %d: %.120s", id, suffix, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "script") || rec.Header().Get("X-Injected") != "" {
				t.Errorf("GET %q%s echoed attacker input: %s", id, suffix, rec.Body.String())
			}
		}
	}
}

func TestRingEviction(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Keep = 3 }, withAnalyzer(echoAnalyzer))
	h := s.Handler()
	var ids []string
	for i := range 5 {
		ids = append(ids, mustUpload(t, h, fmt.Sprintf("f%d.bin", i), sampleBytes(10+i)).ID)
	}
	list := listSummaries(t, s)
	var names []string
	for _, e := range list {
		names = append(names, e.Name)
	}
	if !reflect.DeepEqual(names, []string{"f4.bin", "f3.bin", "f2.bin"}) {
		t.Fatalf("ring after 5 uploads with Keep=3: %v", names)
	}
	for i, id := range ids {
		rec := do(t, h, http.MethodGet, "/api/analyses/"+id, nil)
		wantStatus := http.StatusNotFound
		if i >= 2 {
			wantStatus = http.StatusOK
		}
		if rec.Code != wantStatus {
			t.Errorf("GET upload %d = %d, want %d", i, rec.Code, wantStatus)
		}
	}
}

// stringsAnalyzer returns a report with a fixed, varied set of strings.
func stringsAnalyzer(_ context.Context, _ string, opts analyze.Options) (*report.Report, error) {
	r := fakeReport(opts.Name, 0)
	r.Strings = report.Strings{
		Total: 7, MinLength: 5,
		ByCategory: map[string]int{report.CatURL: 2, report.CatIP: 1, report.CatSecret: 1, report.CatPlain: 2, report.CatPath: 1},
		Items: []report.StringItem{
			{Value: "kernel32.dll", Offset: 10, Encoding: "ascii", Category: report.CatPlain},
			{Value: "https://Example.com/a", Offset: 40, Encoding: "ascii", Category: report.CatURL},
			{Value: "10.0.0.7", Offset: 90, Encoding: "ascii", Category: report.CatIP},
			{Value: "AKIA…(20 chars)", Offset: 120, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"},
			{Value: `C:\Windows\System32`, Offset: 160, Encoding: "utf16le", Category: report.CatPath},
			{Value: "http://evil.example/payload", Offset: 220, Encoding: "ascii", Category: report.CatURL},
			{Value: "hello world", Offset: 300, Encoding: "ascii", Category: report.CatPlain},
		},
	}
	return r, nil
}

func TestStringsEndpoint(t *testing.T) {
	s := newTestServer(t, withAnalyzer(stringsAnalyzer))
	h := s.Handler()
	id := mustUpload(t, h, "s.bin", sampleBytes(10)).ID
	base := "/api/analyses/" + id + "/strings"

	values := func(p stringsPage) []string {
		out := make([]string, 0, len(p.Items))
		for _, it := range p.Items {
			out = append(out, it.Value)
		}
		return out
	}
	tests := []struct {
		name      string
		query     string
		wantTotal int
		wantLimit int
		wantOff   int
		wantItems []string
	}{
		{"everything, in report order", "", 7, 100, 0, []string{"kernel32.dll", "https://Example.com/a", "10.0.0.7", "AKIA…(20 chars)", `C:\Windows\System32`, "http://evil.example/payload", "hello world"}},
		{"one category", "category=url", 2, 100, 0, []string{"https://Example.com/a", "http://evil.example/payload"}},
		{"comma separated categories", "category=url,ip", 3, 100, 0, []string{"https://Example.com/a", "10.0.0.7", "http://evil.example/payload"}},
		{"repeated category parameter", "category=url&category=ip", 3, 100, 0, []string{"https://Example.com/a", "10.0.0.7", "http://evil.example/payload"}},
		{"category is case-insensitive and tolerates blanks", "category=URL,,%20ip%20", 3, 100, 0, []string{"https://Example.com/a", "10.0.0.7", "http://evil.example/payload"}},
		{"substring search ignores case", "q=EXAMPLE", 2, 100, 0, []string{"https://Example.com/a", "http://evil.example/payload"}},
		{"search plus category", "q=example&category=url", 2, 100, 0, []string{"https://Example.com/a", "http://evil.example/payload"}},
		{"search with no match", "q=nothing-like-this", 0, 100, 0, []string{}},
		{"the raw secret cannot be found, only its redaction", "q=AKIAIOSFODNN7EXAMPLE", 0, 100, 0, []string{}},
		{"the redaction can be found", "q=chars", 1, 100, 0, []string{"AKIA…(20 chars)"}},
		{"first page", "limit=3", 7, 3, 0, []string{"kernel32.dll", "https://Example.com/a", "10.0.0.7"}},
		{"second page", "limit=3&offset=3", 7, 3, 3, []string{"AKIA…(20 chars)", `C:\Windows\System32`, "http://evil.example/payload"}},
		{"last partial page", "limit=3&offset=6", 7, 3, 6, []string{"hello world"}},
		{"offset past the end", "limit=3&offset=70", 7, 3, 70, []string{}},
		{"offset applies after filtering", "category=plain&offset=1", 2, 100, 1, []string{"hello world"}},
		{"unknown parameters are ignored", "bogus=1", 7, 100, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, base+"?"+tc.query, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var page stringsPage
			decode(t, rec, &page)
			if page.Total != tc.wantTotal || page.Limit != tc.wantLimit || page.Offset != tc.wantOff {
				t.Errorf("total/limit/offset = %d/%d/%d, want %d/%d/%d", page.Total, page.Limit, page.Offset, tc.wantTotal, tc.wantLimit, tc.wantOff)
			}
			if page.Items == nil {
				t.Error("items must be an array, never null")
			}
			if tc.wantItems != nil && !reflect.DeepEqual(values(page), tc.wantItems) {
				t.Errorf("items = %q, want %q", values(page), tc.wantItems)
			}
		})
	}

	t.Run("items keep every field", func(t *testing.T) {
		var page stringsPage
		decode(t, do(t, h, http.MethodGet, base+"?category=secret", nil), &page)
		want := report.StringItem{Value: "AKIA…(20 chars)", Offset: 120, Encoding: "ascii", Category: report.CatSecret, Redacted: true, Kind: "aws-access-key-id"}
		if len(page.Items) != 1 || page.Items[0] != want {
			t.Errorf("items = %+v", page.Items)
		}
	})

	t.Run("paging visits every string once", func(t *testing.T) {
		var seen []string
		for off := 0; ; off += 2 {
			var page stringsPage
			decode(t, do(t, h, http.MethodGet, fmt.Sprintf("%s?limit=2&offset=%d", base, off), nil), &page)
			if len(page.Items) == 0 {
				break
			}
			seen = append(seen, values(page)...)
		}
		if len(seen) != 7 {
			t.Errorf("paged through %d strings, want 7: %q", len(seen), seen)
		}
	})
}

func TestStringsEndpointRejectsBadParameters(t *testing.T) {
	s := newTestServer(t, withAnalyzer(stringsAnalyzer))
	id := mustUpload(t, s.Handler(), "s.bin", sampleBytes(10)).ID
	base := "/api/analyses/" + id + "/strings?"
	tests := []struct {
		name  string
		query string
	}{
		{"unknown category", "category=nope"},
		{"one bad category among good ones", "category=url,nope"},
		{"hostile category is clipped, not echoed whole", "category=" + url.QueryEscape(strings.Repeat("x", 500))},
		{"limit zero", "limit=0"},
		{"limit negative", "limit=-5"},
		{"limit too large", "limit=1001"},
		{"limit not a number", "limit=ten"},
		{"limit empty-ish float", "limit=1.5"},
		{"offset negative", "offset=-1"},
		{"offset not a number", "offset=first"},
		{"offset overflow", "offset=99999999999999999999999"},
		{"query too long", "q=" + strings.Repeat("a", maxQueryBytes+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, s.Handler(), http.MethodGet, base+tc.query, nil)
			if rec.Code != http.StatusBadRequest || errorCode(t, rec) != codeInvalidParameter {
				t.Fatalf("status %d: %.200s", rec.Code, rec.Body.String())
			}
			if len(rec.Body.String()) > 600 {
				t.Errorf("error message is %d bytes; hostile input must be clipped", rec.Body.Len())
			}
		})
	}
	// The maximum limit and a query of exactly the maximum length are fine.
	for _, q := range []string{"limit=1000", "q=" + strings.Repeat("a", maxQueryBytes)} {
		if rec := do(t, s.Handler(), http.MethodGet, base+q, nil); rec.Code != http.StatusOK {
			t.Errorf("%.40s: status %d", q, rec.Code)
		}
	}
}
