package analyze

import (
	"fmt"

	"github.com/q6r/teardown/internal/report"
)

// parsedType reports whether the content type has a format parser. Types that
// are only recognised (safetensors, SQLite, PDF, images, ...) get the generic
// analysis plus a limitation that says so.
func parsedType(id string) bool {
	switch id {
	case report.TypePE, report.TypeELF, report.TypeMachO, report.TypeMachOFat, report.TypeAsar, report.TypeWasm,
		report.TypeGGUF,
		report.TypeZip, report.TypeJar, report.TypeAPK, report.TypeAAB, report.TypeDocx, report.TypeXlsx,
		report.TypePptx, report.TypeODF, report.TypeEPUB, report.TypeNupkg, report.TypeWheel, report.TypeVSIX:
		return true
	}
	return false
}

// addLimitations states, report-wide, what this analysis could not see.
func addLimitations(rep *report.Report) {
	rep.AddLimitation("Findings are leads, not verdicts: each one states its evidence and how it can be wrong, and the risk score only orders a review queue.")
	switch rep.Type.Family {
	case report.FamilyExecutable:
		rep.AddLimitation("Imports resolved at run time, and code hidden by packers or protectors, are invisible to static analysis.")
	case report.FamilyArchive, report.FamilyPackage:
		rep.AddLimitation("Archive members are listed but not extracted or analysed; nested files need their own analysis.")
	}
	if !parsedType(rep.Type.ID) && rep.Type.ID != report.TypeData && rep.Type.ID != report.TypeText {
		rep.AddLimitation(fmt.Sprintf("No format-specific parser exists for %s: only the hashes, entropy, strings and the generic rules were applied.", rep.Type.Label))
	}
	if rep.Strings.Truncated {
		if len(rep.Strings.Items) < rep.Strings.Total {
			rep.AddLimitation(fmt.Sprintf("The string list holds %d of %d strings; classified strings (URLs, addresses, secrets, ...) are kept first.", len(rep.Strings.Items), rep.Strings.Total))
		} else {
			rep.AddLimitation("Some very long strings were split into fragments at the scanner's length cap, so they appear as several shorter strings.")
		}
	}
	for _, f := range rep.Findings {
		if f.ID == "parser.error" || f.ID == "analysis.incomplete" {
			rep.AddLimitation("Format-specific parsing was incomplete; see the parser findings before relying on the lists in this report.")
			break
		}
	}
}
