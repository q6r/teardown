package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
	"github.com/q6r/teardown/internal/zipscan"
)

const (
	// magicBudget bounds how many entries are opened to look at their magic number.
	magicBudget = 256
	// maxAndroidManifests bounds how many manifests (an AAB has one per module) are read.
	maxAndroidManifests = 8
)

// state accumulates facts while the central directory is walked and while the
// few members of interest are read afterwards.
type state struct {
	kind string
	lim  limits.Limits

	unsafe      []string
	unsafeCount int
	nested      []string
	nestedCount int
	encrypted   int
	classes     int
	signed      bool

	manifest         *zipscan.Entry
	manifestAttrs    map[string]string
	androidManifests []zipscan.Entry
	manifestPresent  bool
	dex              int
	libs             []string
	abis             map[string]struct{}
	hasResources     bool
	signingBlock     bool
	permissions      []string

	office Office

	magic       []zipscan.Entry
	magicBudget int
}

func newState(kind string, lim limits.Limits) *state {
	return &state{
		kind:          cleanKind(kind),
		lim:           lim,
		unsafe:        []string{},
		nested:        []string{},
		manifestAttrs: map[string]string{},
		abis:          map[string]struct{}{},
		magicBudget:   magicBudget,
	}
}

// visit classifies one central-directory record. It runs for every record, so
// it only does constant-time work and capped appends.
func (s *state) visit(e zipscan.Entry) {
	if e.Encrypted {
		s.encrypted++
	}
	if unsafePath(e.RawName) {
		s.unsafeCount++
		if len(s.unsafe) < s.lim.MaxList {
			s.unsafe = append(s.unsafe, e.Name)
		}
	}
	if e.IsDir {
		return
	}
	lower := strings.ToLower(e.RawName)
	ext := path.Ext(lower)
	if ext == ".class" {
		s.classes++
		return
	}
	switch {
	case lower == "meta-inf/manifest.mf":
		if s.manifest == nil {
			m := e
			s.manifest = &m
		}
	case strings.HasPrefix(lower, "meta-inf/") && strings.Count(lower, "/") == 1 && isSignatureExt(ext):
		s.signed = true
	}
	s.classifyAndroid(lower, ext, e)
	s.classifyOffice(lower)

	switch {
	case nestedExts[ext]:
		s.addNested(e.Name)
	case s.magicBudget > 0 && e.UncompressedSize >= 4 && !benignExts[ext]:
		s.magicBudget--
		s.magic = append(s.magic, e)
	}
}

func (s *state) addNested(name string) {
	s.nestedCount++
	if len(s.nested) < s.lim.MaxList {
		s.nested = append(s.nested, name)
	}
}

func (s *state) classifyAndroid(lower, ext string, e zipscan.Entry) {
	if !s.isAndroid() {
		return
	}
	p := strings.ReplaceAll(lower, `\`, "/")
	base := path.Base(p)
	switch {
	case p == "androidmanifest.xml" || (s.kind == report.TypeAAB && strings.HasSuffix(p, "/manifest/androidmanifest.xml")):
		s.manifestPresent = true
		if len(s.androidManifests) < maxAndroidManifests {
			s.androidManifests = append(s.androidManifests, e)
		}
	case ext == ".dex" && isClassesDex(base):
		s.dex++
	case base == "resources.arsc" || base == "resources.pb":
		s.hasResources = true
	case ext == ".so":
		if abi, ok := nativeABI(e.RawName, s.kind == report.TypeAAB); ok {
			s.abis[binio.Printable(abi, 32)] = struct{}{}
			if len(s.libs) < s.lim.MaxList {
				s.libs = append(s.libs, e.Name)
			}
		}
	}
}

func (s *state) classifyOffice(lower string) {
	if !s.isOffice() {
		return
	}
	switch {
	case strings.HasSuffix(lower, "vbaproject.bin"):
		s.office.Macros = true
	case strings.Contains(lower, "/embeddings/"):
		s.office.EmbeddedObjects++
	case strings.Contains(lower, "/activex/"):
		s.office.ActiveX = true
	}
}

// android builds the Android facts once members have been inspected.
func (s *state) android() *Android {
	a := &Android{
		ManifestPresent:      s.manifestPresent,
		Permissions:          s.permissions,
		PermissionsHeuristic: true,
		DexFiles:             s.dex,
		NativeLibs:           append([]string{}, s.libs...),
		ABIs:                 make([]string, 0, len(s.abis)),
		HasResourcesArsc:     s.hasResources,
		SigningBlock:         s.signingBlock,
	}
	if a.Permissions == nil {
		a.Permissions = []string{}
	}
	for abi := range s.abis {
		a.ABIs = append(a.ABIs, abi)
	}
	slices.Sort(a.ABIs)
	slices.Sort(a.NativeLibs)
	return a
}

// inspectMembers reads the few members that carry facts (manifests, entries
// whose magic number is worth a look) and returns notes about problems and
// limitations that qualify what was found.
func (s *state) inspectMembers(ctx context.Context, r io.ReaderAt, size int64, dir *zipscan.Directory) (notes, limitations []string) {
	limit := min(s.lim.MaxMeta, memberLimit)

	for _, e := range s.magic {
		if ctx.Err() != nil {
			return notes, limitations
		}
		if b, err := zipscan.Peek(r, size, e, 8); err == nil && looksLikeContainer(b) {
			s.addNested(e.Name)
		}
	}

	if s.manifest != nil && ctx.Err() == nil {
		data, err := zipscan.Read(r, size, *s.manifest, limit)
		if len(data) == 0 && err != nil {
			notes = append(notes, fmt.Sprintf("META-INF/MANIFEST.MF could not be read: %v", err))
		} else {
			s.manifestAttrs = parseManifest(data)
			if err != nil {
				notes = append(notes, "META-INF/MANIFEST.MF is larger than the read limit; only its beginning was parsed")
			}
		}
	}

	if s.isAndroid() {
		androidNotes := s.inspectAndroid(ctx, r, size, dir, limit)
		notes = append(notes, androidNotes...)
		limitations = append(limitations,
			"Android permissions are recovered heuristically from the manifest's strings, not from a full decode of the binary XML: the list may include declared custom permissions or strings that are not requested permissions, and attribute values (such as whether the app is debuggable) are not decoded.",
			"Signature facts are presence checks only: no signature, certificate or digest was verified.")
	}
	return notes, limitations
}

// inspectAndroid recovers permissions heuristically and checks for the APK
// signing block.
func (s *state) inspectAndroid(ctx context.Context, r io.ReaderAt, size int64, dir *zipscan.Directory, limit int64) []string {
	var notes []string
	seen := map[string]struct{}{}
	for _, e := range s.androidManifests {
		if ctx.Err() != nil {
			break
		}
		data, err := zipscan.Read(r, size, e, limit)
		if len(data) == 0 {
			notes = append(notes, fmt.Sprintf("%s could not be read: %v", e.Name, err))
			continue
		}
		if errors.Is(err, zipscan.ErrTooLarge) {
			notes = append(notes, fmt.Sprintf("%s is larger than the read limit; only its beginning was scanned", e.Name))
		}
		perms, ok := manifestPermissions(data)
		if !ok && s.kind == report.TypeAPK {
			notes = append(notes, fmt.Sprintf("%s has no readable string pool; its raw bytes were scanned instead", e.Name))
		}
		for _, p := range perms {
			seen[p] = struct{}{}
		}
	}
	s.permissions = make([]string, 0, len(seen))
	for p := range seen {
		s.permissions = append(s.permissions, p)
	}
	slices.Sort(s.permissions)
	if len(s.permissions) > s.lim.MaxList {
		s.permissions = s.permissions[:s.lim.MaxList]
	}
	if s.kind == report.TypeAPK {
		s.signingBlock = hasSigningBlock(r, size, dir.CDOffset)
	}
	return notes
}

// signingBlockMagic ends the APK Signing Block that v2+ signatures live in.
const signingBlockMagic = "APK Sig Block 42"

func hasSigningBlock(r io.ReaderAt, size, cdOffset int64) bool {
	b, err := binio.ReadAt(r, size, cdOffset-int64(len(signingBlockMagic)), int64(len(signingBlockMagic)))
	return err == nil && string(b) == signingBlockMagic
}

// isSignatureExt reports whether ext is a JAR signature block file extension.
func isSignatureExt(ext string) bool {
	switch ext {
	case ".sf", ".rsa", ".dsa", ".ec":
		return true
	}
	return false
}

// isClassesDex matches classes.dex, classes2.dex, ...
func isClassesDex(base string) bool {
	digits, ok := strings.CutPrefix(base, "classes")
	if !ok {
		return false
	}
	digits, ok = strings.CutSuffix(digits, ".dex")
	if !ok {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// nativeABI extracts <abi> from lib/<abi>/x.so (APK) or <module>/lib/<abi>/x.so (AAB).
func nativeABI(raw string, bundle bool) (string, bool) {
	parts := strings.Split(strings.ReplaceAll(raw, `\`, "/"), "/")
	lib := 0
	if bundle {
		lib = 1
	}
	if len(parts) < lib+3 || !strings.EqualFold(parts[lib], "lib") || parts[lib+1] == "" {
		return "", false
	}
	return parts[lib+1], true
}
