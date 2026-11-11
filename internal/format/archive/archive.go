// Package archive extracts triage facts from ZIP-based containers: plain ZIP,
// JAR, APK, AAB and the document and package formats built on ZIP (OOXML, ODF,
// EPUB, NuGet, wheel, VSIX).
//
// Nothing is extracted to disk and nothing is executed. Entries are never
// inflated except for a handful of small, well-known members (the JAR manifest,
// the Android manifest), each read under a hard size limit, so zip bombs cost
// nothing to analyse.
package archive

import (
	"context"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/zipscan"
)

// memberLimit caps how many bytes of a single member (manifest, Android
// manifest) are ever inflated, on top of the caller's limits.
const memberLimit = 8 << 20

// Result is the outcome of [Parse]. Details is stored under
// report.details["archive"].
type Result struct {
	Details Details
	// Notes lists non-fatal problems met while parsing (damage, capped lists).
	Notes []string
	// Limitations qualify the facts, for example that sizes are the declared
	// ones or that Android permissions are heuristic. They belong in the
	// report's limitations rather than among its warnings.
	Limitations []string
}

// Details are the format-specific facts of a ZIP-based container.
type Details struct {
	// Kind is the container type the caller asked for (a report.Type* id).
	Kind string `json:"kind"`
	// EntryCount is the number of central-directory records walked.
	EntryCount int `json:"entryCount"`
	// Entries lists the first entries in archive order, capped by limits.MaxList.
	Entries          []Entry `json:"entries"`
	EntriesTruncated bool    `json:"entriesTruncated"`
	// TotalCompressed and TotalUncompressed sum the declared sizes of all entries.
	TotalCompressed   uint64 `json:"totalCompressed"`
	TotalUncompressed uint64 `json:"totalUncompressed"`
	// Ratio is TotalUncompressed/TotalCompressed (0 when unknown); MaxRatio is the
	// highest ratio of a single entry and MaxRatioEntry names it. Declared sizes
	// are used, so a lying archive can understate them.
	Ratio         float64 `json:"ratio"`
	MaxRatio      float64 `json:"maxRatio"`
	MaxRatioEntry string  `json:"maxRatioEntry"`
	// UnsafeNames lists entry names that would escape an extraction root
	// ("zip-slip"): parent-directory segments, absolute paths, drive letters,
	// UNC prefixes and NUL bytes. Checked on every entry, capped when listed.
	UnsafeNames []string `json:"unsafeNames"`
	// UnsafeCount is the true number of such entries.
	UnsafeCount int `json:"unsafeCount"`
	// Nested lists entries that are archives, installers or executables
	// themselves, by extension or by magic number. NestedCount is the true number.
	Nested      []string `json:"nested"`
	NestedCount int      `json:"nestedCount"`
	// EncryptedEntries counts entries marked as encrypted.
	EncryptedEntries int `json:"encryptedEntries"`
	// OverlappingEntries counts entries whose data overlaps an earlier entry,
	// the signature of overlapping-entry zip bombs.
	OverlappingEntries int `json:"overlappingEntries"`
	// DuplicateNames counts entries repeating an earlier name.
	DuplicateNames int `json:"duplicateNames"`
	// Comment is the archive comment, made printable.
	Comment string `json:"comment"`
	// PrefixBytes is the size of data before the first entry (an extractor stub).
	PrefixBytes int64 `json:"prefixBytes"`
	// Recovered is true when the central directory was damaged and the entries
	// were recovered by other means.
	Recovered bool `json:"recovered"`
	// Signed is true when META-INF holds a signature block file (.SF, .RSA,
	// .DSA or .EC), which is the JAR/APK v1 scheme. Presence only; nothing is verified.
	Signed bool `json:"signed"`
	// Manifest holds the main-section attributes of META-INF/MANIFEST.MF.
	Manifest map[string]string `json:"manifest"`
	// ClassCount is the number of .class entries.
	ClassCount int `json:"classCount"`
	// Android is present for APK and AAB containers.
	Android *Android `json:"android,omitempty"`
	// Office is present for OOXML documents (docx, xlsx, pptx).
	Office *Office `json:"office,omitempty"`
}

// Entry is one listed archive member.
type Entry struct {
	Name           string `json:"name"`
	Size           uint64 `json:"size"`
	CompressedSize uint64 `json:"compressedSize"`
	// Method is "stored", "deflate", ... or "method-N".
	Method    string `json:"method"`
	Encrypted bool   `json:"encrypted"`
	Dir       bool   `json:"dir"`
}

// Android holds facts about an APK or AAB.
//
// Permissions are recovered HEURISTICALLY. For an APK only the string pool of the
// binary AndroidManifest.xml is read, and for an AAB (whose manifest is a
// protocol buffer) the raw bytes are scanned for permission-shaped strings.
// Attributes and values are not decoded, so the list cannot tell a requested
// permission from a declared custom permission or from a string that merely
// appears in the manifest.
type Android struct {
	ManifestPresent bool `json:"manifestPresent"`
	// Permissions is sorted and de-duplicated.
	Permissions []string `json:"permissions"`
	// PermissionsHeuristic is always true: see the type documentation.
	PermissionsHeuristic bool `json:"permissionsHeuristic"`
	// DexFiles counts classes*.dex files.
	DexFiles int `json:"dexFiles"`
	// NativeLibs lists lib/<abi>/*.so entries (sorted, capped) and ABIs the
	// distinct <abi> directories.
	NativeLibs       []string `json:"nativeLibs"`
	ABIs             []string `json:"abis"`
	HasResourcesArsc bool     `json:"hasResourcesArsc"`
	// SigningBlock is true when the APK Signing Block magic sits right before
	// the central directory, which means a v2 or later signature exists. Presence only.
	SigningBlock bool `json:"signingBlock"`
}

// Office holds name-based facts about an OOXML document. Nothing is read from
// the document parts.
type Office struct {
	// Macros is true when a VBA project (vbaProject.bin) is embedded.
	Macros bool `json:"macros"`
	// EmbeddedObjects counts parts under an embeddings directory.
	EmbeddedObjects int `json:"embeddedObjects"`
	// ActiveX is true when ActiveX controls are embedded.
	ActiveX bool `json:"activeX"`
}

// Parse analyses the ZIP-based container in r. kind is the detected type (a
// report.Type* id such as "apk" or "jar") and only selects which extra facts are
// gathered. It returns (nil, err) when r is not a ZIP archive at all; for
// damaged archives it returns what could be recovered plus notes. When ctx ends
// mid-way the partial result is returned together with ctx's error.
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits, kind string) (*Result, error) {
	lim = lim.Normalize()
	st := newState(kind, lim)
	dir, err := zipscan.Walk(ctx, r, size, lim.MaxList, st.visit)
	if dir == nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	notes := slices.Clone(dir.Warnings)
	if dir.Recovered {
		notes = append(notes, "the archive is damaged or incomplete: its entry list was recovered rather than read from a valid central directory")
	}
	if dir.Count > len(dir.Entries) {
		notes = append(notes, fmt.Sprintf("entry list limited to the first %d of %d entries; counts and path-safety checks cover all of them", len(dir.Entries), dir.Count))
	}
	limitations := []string{"Sizes, ratios and totals are the ones the archive declares; a crafted archive can understate them. Nothing was extracted or inflated except small manifest files."}
	if err == nil {
		memberNotes, memberLimits := st.inspectMembers(ctx, r, size, dir)
		notes = append(notes, memberNotes...)
		limitations = append(limitations, memberLimits...)
		err = ctx.Err()
	}
	return &Result{Details: st.details(dir), Notes: notes, Limitations: limitations}, err
}

// details assembles the entry-independent part of the result.
func (s *state) details(dir *zipscan.Directory) Details {
	d := Details{
		Kind:               s.kind,
		EntryCount:         dir.Count,
		Entries:            make([]Entry, 0, len(dir.Entries)),
		EntriesTruncated:   dir.Truncated,
		TotalCompressed:    dir.TotalCompressed,
		TotalUncompressed:  dir.TotalUncompressed,
		MaxRatio:           round3(dir.MaxRatio),
		MaxRatioEntry:      dir.MaxRatioEntry,
		UnsafeNames:        s.unsafe,
		UnsafeCount:        s.unsafeCount,
		Nested:             s.nested,
		NestedCount:        s.nestedCount,
		EncryptedEntries:   s.encrypted,
		OverlappingEntries: dir.Overlapping,
		DuplicateNames:     dir.Duplicates,
		Comment:            dir.Comment,
		PrefixBytes:        dir.PrefixBytes,
		Recovered:          dir.Recovered,
		Signed:             s.signed,
		Manifest:           s.manifestAttrs,
		ClassCount:         s.classes,
	}
	if dir.TotalCompressed > 0 {
		d.Ratio = round3(float64(dir.TotalUncompressed) / float64(dir.TotalCompressed))
	}
	for _, e := range dir.Entries {
		d.Entries = append(d.Entries, Entry{
			Name: e.Name, Size: e.UncompressedSize, CompressedSize: e.CompressedSize,
			Method: methodName(e.Method), Encrypted: e.Encrypted, Dir: e.IsDir,
		})
	}
	if s.isAndroid() {
		d.Android = s.android()
	}
	if s.isOffice() {
		d.Office = &s.office
	}
	return d
}

func methodName(m uint16) string {
	switch m {
	case 0:
		return "stored"
	case 8:
		return "deflate"
	case 9:
		return "deflate64"
	case 12:
		return "bzip2"
	case 14:
		return "lzma"
	case 93:
		return "zstd"
	case 95:
		return "xz"
	case 98:
		return "ppmd"
	case 99:
		return "aes"
	default:
		return fmt.Sprintf("method-%d", m)
	}
}

func round3(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 0
	}
	return math.Round(x*1000) / 1000
}

func (s *state) isAndroid() bool { return s.kind == report.TypeAPK || s.kind == report.TypeAAB }

func (s *state) isOffice() bool {
	switch s.kind {
	case report.TypeDocx, report.TypeXlsx, report.TypePptx:
		return true
	}
	return false
}

// cleanKind normalises the kind string used in messages.
func cleanKind(kind string) string {
	if kind == "" {
		return report.TypeZip
	}
	return strings.ToLower(kind)
}
