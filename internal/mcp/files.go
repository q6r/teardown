package mcp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/q6r/teardown/internal/binio"
)

// maxPathBytes is the longest path a client may supply.
const maxPathBytes = 4096

// userError is a failure whose message is written for the model or the user and
// is safe to return verbatim as a tool result.
type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func userErrorf(format string, a ...any) error {
	return &userError{msg: fmt.Sprintf(format, a...)}
}

// rootEntry is one allowed directory.
type rootEntry struct {
	abs   string   // physical location, symlinks resolved
	given string   // absolute location as configured (lexical form)
	root  *os.Root // traversal-resistant handle
}

// relative returns the path of clean (an absolute, cleaned path) relative to the
// root, matching either the physical or the configured spelling of the root.
func (r *rootEntry) relative(clean string) (string, bool) {
	for _, base := range []string{r.abs, r.given} {
		rel, err := filepath.Rel(base, clean)
		if err != nil {
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return rel, true
	}
	return "", false
}

// rootSet is the set of directories the server may read from.
type rootSet struct {
	entries []*rootEntry
	// resolve gives the physical location of a directory: symbolic links followed
	// and, on Windows, 8.3 short names expanded and letter case fixed. The roots
	// are stored in that form, and a requested path that is not inside a root as
	// spelled is put into it too (see respell). It is filepath.EvalSymlinks;
	// tests substitute their own to stand in for links they cannot create.
	resolve func(string) (string, error)
}

// openRoots validates and opens the allowed directories. With no directories the
// current working directory is used.
func openRoots(dirs []string) (*rootSet, error) {
	return openRootsResolving(dirs, filepath.EvalSymlinks)
}

// openRootsResolving is openRoots with the directory resolver spelled out.
func openRootsResolving(dirs []string, resolve func(string) (string, error)) (*rootSet, error) {
	if len(dirs) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("mcp: cannot determine the working directory: %w", err)
		}
		dirs = []string{wd}
	}
	rs := &rootSet{resolve: resolve}
	seen := map[string]bool{}
	for _, d := range dirs {
		given, err := filepath.Abs(d)
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("mcp: root %q: %w", d, err)
		}
		abs, err := resolve(given)
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("mcp: root %q: %w", d, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("mcp: root %q: %w", d, err)
		}
		if !info.IsDir() {
			rs.Close()
			return nil, fmt.Errorf("mcp: root %q is not a directory", d)
		}
		key := abs
		if runtime.GOOS == "windows" {
			key = strings.ToLower(abs)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		root, err := os.OpenRoot(abs)
		if err != nil {
			rs.Close()
			return nil, fmt.Errorf("mcp: root %q: %w", d, err)
		}
		rs.entries = append(rs.entries, &rootEntry{abs: abs, given: given, root: root})
	}
	return rs, nil
}

// Close releases every root handle.
func (rs *rootSet) Close() {
	for _, e := range rs.entries {
		e.root.Close()
	}
}

// names lists the physical root directories.
func (rs *rootSet) names() []string {
	out := make([]string, len(rs.entries))
	for i, e := range rs.entries {
		out[i] = e.abs
	}
	return out
}

// openedFile is a regular file opened inside a root. The caller owns the file.
type openedFile struct {
	*os.File
	size int64
	name string // base name, used as the report's file name
}

// candidate is a root together with the path of the requested file relative to it.
type candidate struct {
	root *rootEntry
	rel  string
}

// open resolves p against the roots and opens it for reading. Every access goes
// through os.Root, so symbolic links and junctions that leave a root are refused
// by the operating system layer rather than by string checks. Only regular files
// are returned; directories, devices, pipes and sockets are rejected before the
// file is opened (opening a FIFO could block forever) and again on the open handle.
func (rs *rootSet) open(p string) (*openedFile, error) {
	if err := checkRawPath(p); err != nil {
		return nil, err
	}
	cands, err := rs.candidates(p)
	if err != nil {
		return nil, err
	}
	notFound := false
	for _, c := range cands {
		before, err := c.root.root.Stat(c.rel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				notFound = true
				continue
			}
			return nil, rs.classify(p, err)
		}
		if !before.Mode().IsRegular() {
			return nil, userErrorf("%q is %s, not a regular file", p, describeMode(before.Mode()))
		}
		f, err := c.root.root.Open(c.rel)
		if err != nil {
			return nil, rs.classify(p, err)
		}
		after, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, userErrorf("cannot read the metadata of %q: %s", p, shortError(err))
		}
		if !after.Mode().IsRegular() {
			f.Close()
			return nil, userErrorf("%q is %s, not a regular file", p, describeMode(after.Mode()))
		}
		return &openedFile{File: f, size: after.Size(), name: filepath.Base(c.rel)}, nil
	}
	if notFound {
		return nil, userErrorf("file not found: %q (searched inside: %s)", p, strings.Join(rs.names(), ", "))
	}
	return nil, rs.outside(p)
}

// outside builds the error for a path that cannot be inside any root.
func (rs *rootSet) outside(p string) error {
	return userErrorf("path %q is outside the allowed roots; only files inside %s can be analysed", p, strings.Join(rs.names(), ", "))
}

// classify turns an operating-system error from a root operation into a message
// that never echoes resolved locations outside the roots.
func (rs *rootSet) classify(p string, err error) error {
	switch {
	case strings.Contains(err.Error(), "path escapes"):
		return userErrorf("%q leaves the allowed roots (a symbolic link or junction pointing outside a root is not followed); only files inside %s can be analysed", p, strings.Join(rs.names(), ", "))
	case errors.Is(err, fs.ErrPermission):
		return userErrorf("permission denied while opening %q", p)
	default:
		return userErrorf("cannot open %q: %s", p, shortError(err))
	}
}

// shortError returns the innermost message of an error, without the operation
// and path prefix of an *fs.PathError.
func shortError(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return binio.Printable(err.Error(), 200)
}

func describeMode(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeSymlink != 0:
		return "a symbolic link"
	case m&fs.ModeDevice != 0:
		return "a device"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	default:
		return "not an ordinary file (special file, junction or reparse point)"
	}
}

// checkRawPath rejects paths that are malformed regardless of the roots.
func checkRawPath(p string) error {
	switch {
	case strings.TrimSpace(p) == "":
		return userErrorf("the path is empty")
	case len(p) > maxPathBytes:
		return userErrorf("the path is longer than %d bytes", maxPathBytes)
	case strings.IndexByte(p, 0) >= 0:
		return userErrorf("the path contains a NUL byte")
	case !utf8.ValidString(p):
		return userErrorf("the path is not valid UTF-8")
	case strings.HasPrefix(strings.ToLower(p), "file:"):
		return userErrorf("%q looks like a URI; pass a plain file system path", binio.Printable(p, 80))
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return userErrorf("the path contains control characters")
		}
	}
	return nil
}

// candidates maps the requested path to the roots it could live in: for an
// absolute path, the roots that contain it (as spelled, or else in its physical
// spelling); for a relative path, every root in order (the first root that has
// the file wins).
func (rs *rootSet) candidates(p string) ([]candidate, error) {
	native := filepath.FromSlash(p)
	if runtime.GOOS == "windows" {
		if problem := windowsPathProblem(native); problem != "" {
			return nil, userErrorf("%q is not accepted: %s", p, problem)
		}
	}
	if filepath.IsAbs(native) {
		clean := filepath.Clean(native)
		out := rs.containing(clean)
		if len(out) == 0 {
			if alt := rs.respell(clean); alt != "" && alt != clean {
				out = rs.containing(alt)
			}
		}
		if len(out) == 0 {
			return nil, rs.outside(p)
		}
		if runtime.GOOS == "windows" {
			if name := reservedWindowsComponent(out[0].rel); name != "" {
				return nil, userErrorf("%q is not accepted: %q is a reserved Windows device name", p, name)
			}
		}
		return out, nil
	}
	rel := filepath.Clean(native)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, rs.outside(p)
	}
	if runtime.GOOS == "windows" {
		if name := reservedWindowsComponent(rel); name != "" {
			return nil, userErrorf("%q is not accepted: %q is a reserved Windows device name", p, name)
		}
	}
	out := make([]candidate, len(rs.entries))
	for i, e := range rs.entries {
		out[i] = candidate{root: e, rel: rel}
	}
	return out, nil
}

// containing returns, in order, every root that lexically contains clean (an
// absolute, cleaned path) together with clean's path relative to it.
func (rs *rootSet) containing(clean string) []candidate {
	var out []candidate
	for _, e := range rs.entries {
		if rel, ok := e.relative(clean); ok {
			out = append(out, candidate{root: e, rel: rel})
		}
	}
	return out
}

// respell returns clean (an absolute, cleaned path) spelled the way the roots
// are stored, so that two names of one place compare equal. A place has several
// names: on macOS the temporary directory is reached as /var/... and as
// /private/var/..., any platform has symbolic links, and on Windows a directory
// is also known by its 8.3 short name (RUNNER~1 for runneradmin) and in any
// letter case. The roots are stored fully resolved, so the directory part of
// the request is resolved with the same function.
//
// Only the directory part is resolved. The last element is left alone: if it is
// a link, os.Root decides whether it may be followed. Resolution only chooses
// which root to ask and which relative path to hand it; the read itself still
// goes through os.Root, so a link swapped in meanwhile cannot lead out of a root.
//
// The result is empty when clean cannot be resolved to a place inside a root:
// its directory does not exist, it is on a volume no root is on, or it names a
// Windows device. The volume rule matters on Windows: resolving \\host\share\...
// would make the machine connect to a host of the caller's choosing (and offer
// it the user's credentials), which a path outside every root must never do.
func (rs *rootSet) respell(clean string) string {
	if !rs.onRootVolume(clean) {
		return ""
	}
	if runtime.GOOS == "windows" && reservedWindowsComponent(strings.TrimPrefix(clean, filepath.VolumeName(clean))) != "" {
		return ""
	}
	dir, err := rs.resolve(filepath.Dir(clean))
	if err != nil {
		return ""
	}
	return filepath.Join(dir, filepath.Base(clean))
}

// onRootVolume reports whether p is on the same volume (Windows drive letter or
// UNC share; there is only one volume elsewhere) as at least one root.
func (rs *rootSet) onRootVolume(p string) bool {
	volume := filepath.VolumeName(p)
	for _, e := range rs.entries {
		if strings.EqualFold(volume, filepath.VolumeName(e.abs)) {
			return true
		}
	}
	return false
}

// windowsPathProblem explains why a native Windows path is rejected before any
// lookup, or returns "" when it is acceptable. It is a pure function so it can
// be tested on every platform.
func windowsPathProblem(p string) string {
	if strings.HasPrefix(p, `\\.\`) || strings.HasPrefix(p, `\\?\`) {
		return "device and extended-length (\\\\.\\ and \\\\?\\) paths are not allowed"
	}
	drive := len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0])
	rest := p
	if drive {
		rest = p[2:]
		if !strings.HasPrefix(rest, `\`) {
			return "drive-relative paths such as C:file are ambiguous; use an absolute path or a path relative to a root"
		}
	} else if strings.HasPrefix(p, `\`) && !strings.HasPrefix(p, `\\`) {
		return "paths rooted without a drive letter are ambiguous; use an absolute path or a path relative to a root"
	}
	if strings.Contains(rest, ":") {
		return "alternate data streams (name:stream) are not supported"
	}
	return ""
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// reservedWindowsComponent returns the first path component that names a
// reserved Windows device, or "".
func reservedWindowsComponent(rel string) string {
	for _, comp := range strings.FieldsFunc(rel, func(r rune) bool { return r == '\\' || r == '/' }) {
		if isReservedWindowsName(comp) {
			return comp
		}
	}
	return ""
}

// isReservedWindowsName reports whether a single path component refers to a
// reserved Windows device name. Windows ignores trailing dots and spaces and any
// extension, so "nul", "NUL.txt" and "nul ." are all the NUL device.
func isReservedWindowsName(comp string) bool {
	c := strings.TrimRight(comp, ". ")
	if i := strings.IndexByte(c, '.'); i >= 0 {
		c = c[:i]
	}
	c = strings.ToUpper(strings.TrimRight(c, " "))
	switch c {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	runes := []rune(c)
	if len(runes) == 4 && (string(runes[:3]) == "COM" || string(runes[:3]) == "LPT") {
		switch last := runes[3]; {
		case last >= '0' && last <= '9', last == '¹', last == '²', last == '³':
			return true
		}
	}
	return false
}
