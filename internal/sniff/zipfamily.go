package sniff

import (
	"context"
	"strings"

	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/zipscan"
)

const (
	mimeZip     = "application/zip"
	mimeOffice  = "application/vnd.openxmlformats-officedocument."
	odfMimeBase = "application/vnd.oasis.opendocument."
)

// detectPK recognises ZIP archives and classifies the ZIP-based formats (JAR,
// APK, AAB, Office Open XML, OpenDocument, EPUB, NuGet, wheel, VSIX) by looking
// at the member names, not at the file name.
func detectPK(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 4 || h[0] != 'P' || h[1] != 'K' {
		return report.Type{}, false
	}
	switch {
	case h[2] == 3 && h[3] == 4: // local file header
	case h[2] == 7 && h[3] == 8: // marker of a split archive
	case h[2] == 5 && h[3] == 6: // end of central directory first: an empty archive
		empty := len(h) >= 22 && h[8] == 0 && h[9] == 0 && h[10] == 0 && h[11] == 0
		return newType(report.TypeZip, report.FamilyArchive, "ZIP archive (empty)", mimeZip,
			confidenceIf(empty), tagEmpty), true
	default:
		return report.Type{}, false
	}

	var facts zipFacts
	dir, err := zipscan.Walk(context.Background(), p.r, p.size, 0, facts.visit)
	if dir == nil || dir.Count == 0 {
		return newType(report.TypeZip, report.FamilyArchive, "ZIP archive (central directory unreadable)", mimeZip,
			report.ConfidenceMedium), true
	}
	t := facts.classify(p)
	if err != nil || dir.Recovered || dir.Count >= zipscan.MaxRecords {
		// The listing is incomplete or was rebuilt from local headers, so a
		// marker that was not seen proves little. (Truncated is no help here:
		// Walk is told to retain no entries, so it is always set.)
		t.Confidence = report.ConfidenceMedium
	}
	return t, true
}

// zipFacts records which well-known members an archive contains. It is filled
// by visiting every record, so it needs constant memory however large the
// archive is.
type zipFacts struct {
	seen        int
	mimetype    zipscan.Entry
	mimetypeAt  int
	hasMimetype bool

	manifest, androidManifest, classesDex, resourcesArsc bool
	bundleConfig, baseManifest                           bool
	contentTypes, word, xl, ppt                          bool
	nuspec, wheel, vsixManifest, vscodePackage           bool
	classFiles, webInf, applicationXML, classesJar       bool
}

// visit is the zipscan.Walk callback.
func (f *zipFacts) visit(e zipscan.Entry) {
	name := strings.ToLower(strings.ReplaceAll(e.Name, `\`, "/"))
	if name == "mimetype" && !f.hasMimetype {
		f.mimetype, f.mimetypeAt, f.hasMimetype = e, f.seen, true
	}
	f.seen++

	switch name {
	case "meta-inf/manifest.mf":
		f.manifest = true
	case "androidmanifest.xml":
		f.androidManifest = true
	case "classes.dex":
		f.classesDex = true
	case "resources.arsc":
		f.resourcesArsc = true
	case "bundleconfig.pb":
		f.bundleConfig = true
	case "base/manifest/androidmanifest.xml":
		f.baseManifest = true
	case "[content_types].xml":
		f.contentTypes = true
	case "extension.vsixmanifest":
		f.vsixManifest = true
	case "extension/package.json":
		f.vscodePackage = true
	case "meta-inf/application.xml":
		f.applicationXML = true
	case "classes.jar":
		f.classesJar = true
	}
	switch {
	case strings.HasPrefix(name, "word/"):
		f.word = true
	case strings.HasPrefix(name, "xl/"):
		f.xl = true
	case strings.HasPrefix(name, "ppt/"):
		f.ppt = true
	case strings.HasPrefix(name, "web-inf/"):
		f.webInf = true
	}
	if strings.HasSuffix(name, ".class") {
		f.classFiles = true
	}
	if !strings.Contains(name, "/") && strings.HasSuffix(name, ".nuspec") {
		f.nuspec = true
	}
	if isWheelMetadata(name) {
		f.wheel = true
	}
}

// isWheelMetadata matches "<name>-<version>.dist-info/wheel" at the top level.
func isWheelMetadata(name string) bool {
	dir, file, ok := strings.Cut(name, "/")
	return ok && file == "wheel" && strings.HasSuffix(dir, ".dist-info")
}

// classify chooses the most specific type the collected facts allow. The order
// matters: an APK and an AAB also contain META-INF/MANIFEST.MF, a NuGet package
// and a VSIX also contain [Content_Types].xml.
func (f *zipFacts) classify(p *probe) report.Type {
	if f.hasMimetype {
		if t, ok := f.classifyMimetype(p); ok {
			return t
		}
	}
	high := report.ConfidenceHigh
	switch {
	case f.bundleConfig || f.baseManifest:
		return newType(report.TypeAAB, report.FamilyPackage, "Android App Bundle (AAB)", mimeZip, high, "android")
	case f.androidManifest && (f.classesDex || f.resourcesArsc):
		return newType(report.TypeAPK, report.FamilyPackage, "Android package (APK)",
			"application/vnd.android.package-archive", high, "android")
	case f.nuspec:
		return newType(report.TypeNupkg, report.FamilyPackage, "NuGet package", mimeZip, high, "dotnet")
	case f.wheel:
		return newType(report.TypeWheel, report.FamilyPackage, "Python wheel", "application/x-wheel+zip", high, "python")
	case f.vsixManifest:
		if f.vscodePackage {
			return newType(report.TypeVSIX, report.FamilyPackage, "Visual Studio Code extension (VSIX)",
				"application/vsix", high, "vscode")
		}
		return newType(report.TypeVSIX, report.FamilyPackage, "Visual Studio extension (VSIX)",
			"application/vsix", high, "visualstudio")
	case f.contentTypes && f.word:
		return newType(report.TypeDocx, report.FamilyDocument, "Word document (DOCX)",
			mimeOffice+"wordprocessingml.document", high, "office")
	case f.contentTypes && f.xl:
		return newType(report.TypeXlsx, report.FamilyDocument, "Excel workbook (XLSX)",
			mimeOffice+"spreadsheetml.sheet", high, "office")
	case f.contentTypes && f.ppt:
		return newType(report.TypePptx, report.FamilyDocument, "PowerPoint presentation (PPTX)",
			mimeOffice+"presentationml.presentation", high, "office")
	case f.webInf && f.manifest:
		return newType(report.TypeJar, report.FamilyPackage, "Java web application archive (WAR)",
			"application/java-archive", high, "java", "war")
	case f.applicationXML && f.manifest:
		return newType(report.TypeJar, report.FamilyPackage, "Java enterprise archive (EAR)",
			"application/java-archive", high, "java", "ear")
	case f.manifest:
		return newType(report.TypeJar, report.FamilyPackage, "Java archive (JAR)", "application/java-archive", high, "java")
	case f.classFiles:
		// Class files without a manifest: a hand-made or stripped jar.
		return newType(report.TypeJar, report.FamilyPackage, "Java archive (JAR, no manifest)",
			"application/java-archive", report.ConfidenceMedium, "java")
	case f.androidManifest && f.classesJar:
		return newType(report.TypeZip, report.FamilyArchive, "Android library (AAR)", mimeZip, high, "aar", "android")
	case f.contentTypes:
		return newType(report.TypeZip, report.FamilyArchive, "ZIP archive (Open Packaging Conventions)", mimeZip, high, "opc")
	}
	return newType(report.TypeZip, report.FamilyArchive, "ZIP archive", mimeZip, high)
}

// classifyMimetype reads the stored "mimetype" member that OpenDocument and EPUB
// containers use to declare their type.
func (f *zipFacts) classifyMimetype(p *probe) (report.Type, bool) {
	data, err := zipscan.Peek(p.r, p.size, f.mimetype, 128)
	if err != nil && len(data) == 0 {
		return report.Type{}, false
	}
	mt := strings.TrimSpace(string(data))
	// The specifications require the mimetype member to be first and stored.
	conf := confidenceIf(f.mimetypeAt == 0 && f.mimetype.Method == 0)
	if mt == "application/epub+zip" {
		return newType(report.TypeEPUB, report.FamilyDocument, "EPUB e-book", mt, conf), true
	}
	kind, ok := strings.CutPrefix(mt, odfMimeBase)
	if !ok || kind == "" || !isMimeToken(mt) {
		return report.Type{}, false
	}
	base, template := strings.CutSuffix(kind, "-template")
	label := "OpenDocument " + odfKindLabel(base)
	tags := []string{"office", base}
	if template {
		label += " template"
		tags = append(tags, "template")
	}
	return newType(report.TypeODF, report.FamilyDocument, label, mt, conf, tags...), true
}

func odfKindLabel(kind string) string {
	switch kind {
	case "text":
		return "text document (ODT)"
	case "spreadsheet":
		return "spreadsheet (ODS)"
	case "presentation":
		return "presentation (ODP)"
	case "graphics":
		return "drawing (ODG)"
	}
	return kind
}

// isMimeToken reports whether s is a short, plain media type that is safe to
// copy into a report.
func isMimeToken(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '+' && c != '-' && c != '/' {
			return false
		}
	}
	return true
}
