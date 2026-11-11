package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/report"
)

// Zip-bomb heuristics (declared sizes; nothing is decompressed).
const (
	bombTotalBytes = 1 << 30 // 1 GiB declared in total
	bombTotalRatio = 100.0
	bombEntryRatio = 1000.0
	bombEntryBytes = 100 << 20 // 100 MiB declared in total, for the per-entry ratio rule
)

type androidFacts struct {
	Permissions  []string `json:"permissions"`
	SigningBlock bool     `json:"signingBlock"`
}

type archiveFacts struct {
	Kind               string        `json:"kind"`
	EntryCount         int           `json:"entryCount"`
	TotalCompressed    uint64        `json:"totalCompressed"`
	TotalUncompressed  uint64        `json:"totalUncompressed"`
	Ratio              float64       `json:"ratio"`
	MaxRatio           float64       `json:"maxRatio"`
	MaxRatioEntry      string        `json:"maxRatioEntry"`
	UnsafeNames        []string      `json:"unsafeNames"`
	Nested             []string      `json:"nested"`
	EncryptedEntries   int           `json:"encryptedEntries"`
	OverlappingEntries int           `json:"overlappingEntries"`
	DuplicateNames     int           `json:"duplicateNames"`
	Signed             bool          `json:"signed"`
	Android            *androidFacts `json:"android"`
}

func archiveRules() []rule {
	return []rule{
		{info: Info{IDs: []string{"archive.zip-slip"}, Category: report.CategoryArchive, Severity: "high",
			Summary: "Entry names with parent-directory segments, absolute paths, drive letters or UNC prefixes."},
			run: ruleZipSlip},
		{info: Info{IDs: []string{"archive.zip-bomb"}, Category: report.CategoryArchive, Severity: "medium-high",
			Summary: "Declared sizes or overlapping entries consistent with a decompression bomb."},
			run: ruleZipBomb},
		{info: Info{IDs: []string{"archive.nested-archives"}, Category: report.CategoryArchive, Severity: "info",
			Summary: "Archives, packages or executables stored inside the archive."},
			run: ruleNested},
		{info: Info{IDs: []string{"archive.encrypted-entries"}, Category: report.CategoryArchive, Severity: "low",
			Summary: "Password-protected entries whose contents cannot be inspected."},
			run: ruleEncryptedEntries},
		{info: Info{IDs: []string{"archive.duplicate-names"}, Category: report.CategoryArchive, Severity: "low",
			Summary: "Several entries with the same name (ambiguous extraction)."},
			run: ruleDuplicateNames},
		{info: Info{IDs: []string{"android.sensitive-permissions"}, Category: report.CategoryApp, Severity: "info-medium",
			Summary: "Sensitive Android permissions recovered heuristically from the manifest string pool."},
			run: ruleAndroidPermissions},
	}
}

func archiveOf(in *input) (archiveFacts, bool) { return detail[archiveFacts](in.rep, "archive") }

func ruleZipSlip(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok || len(a.UnsafeNames) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "archive.zip-slip", Title: fmt.Sprintf("%d entry names would escape the extraction directory", len(a.UnsafeNames)),
		Severity: report.SeverityHigh, Category: report.CategoryArchive, Confidence: report.ConfidenceHigh,
		Evidence: sample(a.UnsafeNames, 8),
		Limitations: []string{
			"Only extractors that fail to validate entry paths are affected; most mainstream tools reject or strip these names.",
			"The names show the archive is crafted for traversal; they do not show what the escaped files contain. Nothing was extracted.",
		},
	}}
}

func ruleZipBomb(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok {
		return nil
	}
	var evidence []string
	sev, conf := report.SeverityMedium, report.ConfidenceMedium
	if a.OverlappingEntries > 0 {
		evidence = append(evidence, fmt.Sprintf("%d entries share compressed data (overlapping local headers)", a.OverlappingEntries))
		sev, conf = report.SeverityHigh, report.ConfidenceHigh
	}
	if a.TotalUncompressed >= bombTotalBytes && a.Ratio >= bombTotalRatio {
		evidence = append(evidence, fmt.Sprintf("declared %s uncompressed from %s compressed (ratio %.0f:1)", humanBytes(a.TotalUncompressed), humanBytes(a.TotalCompressed), a.Ratio))
	}
	if a.MaxRatio >= bombEntryRatio && a.TotalUncompressed >= bombEntryBytes {
		evidence = append(evidence, fmt.Sprintf("entry %q declares a ratio of %.0f:1", clip(a.MaxRatioEntry, 80), a.MaxRatio))
	}
	if len(evidence) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "archive.zip-bomb", Title: "Archive is consistent with a decompression bomb", Severity: sev,
		Category: report.CategoryArchive, Confidence: conf, Evidence: evidence,
		Limitations: []string{
			"Based on sizes declared in the headers, which can be wrong in either direction; no entry was inflated beyond small metadata files.",
			"Legitimately sparse data (disk images, zero-filled databases) compresses at extreme ratios.",
		},
	}}
}

func ruleNested(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok || len(a.Nested) == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "archive.nested-archives", Title: fmt.Sprintf("%d nested archives or executables inside the archive", len(a.Nested)),
		Severity: report.SeverityInfo, Category: report.CategoryArchive, Confidence: report.ConfidenceMedium,
		Evidence: sample(a.Nested, 8),
		Limitations: []string{
			"Nested files are listed by name or magic bytes but not extracted or analysed: analyse them separately.",
			"Packages such as APKs and JARs routinely contain nested libraries and bundled tools.",
		},
	}}
}

func ruleEncryptedEntries(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok || a.EncryptedEntries == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "archive.encrypted-entries", Title: fmt.Sprintf("%d of %d entries are password-protected", a.EncryptedEntries, a.EntryCount),
		Severity: report.SeverityLow, Category: report.CategoryArchive, Confidence: report.ConfidenceHigh,
		Evidence: []string{fmt.Sprintf("%d encrypted entries flagged in the central directory", a.EncryptedEntries)},
		Limitations: []string{
			"Encrypted contents are invisible to static triage, which is also why malware uses them to evade scanners; plenty of legitimate archives are password-protected too.",
		},
	}}
}

func ruleDuplicateNames(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok || a.DuplicateNames == 0 {
		return nil
	}
	return []report.Finding{{
		ID: "archive.duplicate-names", Title: "Archive contains duplicate entry names", Severity: report.SeverityLow,
		Category: report.CategoryArchive, Confidence: report.ConfidenceHigh,
		Evidence: []string{fmt.Sprintf("%d duplicate names", a.DuplicateNames)},
		Limitations: []string{
			"Different extractors keep different duplicates, which can hide content from reviewers; appended-update archives also produce duplicates innocently.",
		},
	}}
}

// sensitivePermissions are short permission names (after the last dot) that
// deserve a mention when an app requests several of them.
var sensitivePermissions = map[string]bool{
	"READ_SMS": true, "SEND_SMS": true, "RECEIVE_SMS": true, "RECEIVE_MMS": true, "RECEIVE_WAP_PUSH": true,
	"READ_CONTACTS": true, "WRITE_CONTACTS": true, "READ_CALL_LOG": true, "WRITE_CALL_LOG": true,
	"PROCESS_OUTGOING_CALLS": true, "CALL_PHONE": true, "ANSWER_PHONE_CALLS": true,
	"RECORD_AUDIO": true, "CAMERA": true,
	"ACCESS_FINE_LOCATION": true, "ACCESS_COARSE_LOCATION": true, "ACCESS_BACKGROUND_LOCATION": true,
	"SYSTEM_ALERT_WINDOW": true, "REQUEST_INSTALL_PACKAGES": true, "BIND_ACCESSIBILITY_SERVICE": true,
	"BIND_DEVICE_ADMIN": true, "MANAGE_EXTERNAL_STORAGE": true, "READ_PHONE_STATE": true,
	"RECEIVE_BOOT_COMPLETED": true, "WRITE_SETTINGS": true, "QUERY_ALL_PACKAGES": true,
	"PACKAGE_USAGE_STATS": true, "READ_PHONE_NUMBERS": true, "GET_ACCOUNTS": true,
}

func ruleAndroidPermissions(in *input) []report.Finding {
	a, ok := archiveOf(in)
	if !ok || a.Android == nil {
		return nil
	}
	var sensitive []string
	powerful := false
	for _, p := range a.Android.Permissions {
		short := p[strings.LastIndexByte(p, '.')+1:]
		if sensitivePermissions[short] {
			sensitive = append(sensitive, p)
			if short == "BIND_ACCESSIBILITY_SERVICE" || short == "BIND_DEVICE_ADMIN" {
				powerful = true
			}
		}
	}
	if len(sensitive) == 0 {
		return nil
	}
	slices.Sort(sensitive)
	sev := report.SeverityInfo
	switch {
	case powerful || len(sensitive) >= 8:
		sev = report.SeverityMedium
	case len(sensitive) >= 3:
		sev = report.SeverityLow
	}
	return []report.Finding{{
		ID: "android.sensitive-permissions", Title: fmt.Sprintf("%d sensitive Android permissions appear in the manifest", len(sensitive)),
		Severity: sev, Category: report.CategoryApp, Confidence: report.ConfidenceLow, Evidence: sample(sensitive, 12),
		Limitations: []string{
			"Recovered heuristically from the binary manifest's string pool, not from a full AXML decode: a string present in the pool may be a declared custom permission or unrelated text rather than a requested permission.",
			"Permissions describe what an app may ask for, not what it does; messaging, navigation and security apps legitimately request many of these.",
		},
	}}
}
