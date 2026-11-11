package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/q6r/teardown/internal/report"
)

type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID            string `json:"id"`
					DefaultConfig struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Artifacts []struct {
			Location struct {
				URI string `json:"uri"`
			} `json:"location"`
			Hashes map[string]string `json:"hashes"`
		} `json:"artifacts"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI   string `json:"uri"`
						Index int    `json:"index"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, rep *report.Report) (sarifDoc, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	return doc, buf.String()
}

func TestSARIFMapsFindingsToRulesAndResults(t *testing.T) {
	rep := sampleReport()
	finding := func(id string, sev report.Severity) report.Finding {
		return report.Finding{ID: id, Title: "title of " + id, Severity: sev, Category: report.CategoryStructure, Confidence: report.ConfidenceHigh, Evidence: []string{"seen " + id}, Limitations: []string{"may be wrong"}}
	}
	rep.Findings = []report.Finding{
		finding("a.critical", report.SeverityCritical), finding("b.high", report.SeverityHigh), finding("c.medium", report.SeverityMedium),
		finding("d.low", report.SeverityLow), finding("e.info", report.SeverityInfo), finding("a.critical", report.SeverityCritical),
	}
	doc, _ := decodeSARIF(t, rep)

	if doc.Version != "2.1.0" || doc.Schema == "" || len(doc.Runs) != 1 {
		t.Fatalf("not a SARIF 2.1.0 log: %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "teardown" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 5 || len(run.Results) != 6 {
		t.Fatalf("%d rules and %d results, want 5 and 6 (one rule per distinct id)", len(run.Tool.Driver.Rules), len(run.Results))
	}
	wantLevel := map[string]string{"a.critical": "error", "b.high": "error", "c.medium": "warning", "d.low": "note", "e.info": "note"}
	for i, res := range run.Results {
		if res.Level != wantLevel[res.RuleID] {
			t.Errorf("result %d (%s) has level %q, want %q", i, res.RuleID, res.Level, wantLevel[res.RuleID])
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d points at rule %q instead of %q", i, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
		if res.Message.Text == "" || len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "sample.exe" {
			t.Errorf("result %d lacks its message or location: %+v", i, res)
		}
	}
	if len(run.Artifacts) != 1 || run.Artifacts[0].Hashes["sha-256"] != rep.Hashes.SHA256 {
		t.Errorf("the analysed file is not described as an artifact with its hash: %+v", run.Artifacts)
	}
}

func TestSARIFWithoutFindingsStillHasEmptyLists(t *testing.T) {
	rep := sampleReport()
	rep.Findings = nil
	_, raw := decodeSARIF(t, rep)
	for _, want := range []string{`"rules": []`, `"results": []`} {
		if !bytes.Contains([]byte(raw), []byte(want)) {
			t.Errorf("a report without findings must produce %s (not null):\n%s", want, raw)
		}
	}
}

func TestSARIFNeutralisesHostileText(t *testing.T) {
	rep := sampleReport()
	rep.File.Name = "a b/<script>" + hostile + ".exe"
	rep.Findings[0].Title = hostile
	rep.Findings[0].Evidence = []string{hostile}
	doc, raw := decodeSARIF(t, rep)
	if bytes.ContainsRune([]byte(raw), 0x1b) {
		t.Error("a raw escape byte reached the SARIF output")
	}
	uri := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if bytes.ContainsAny([]byte(uri), " <>`|") {
		t.Errorf("the artifact URI %q is not escaped", uri)
	}
}
