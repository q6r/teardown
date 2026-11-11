package asar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
)

const (
	// maxJSFiles bounds how many application scripts are scanned for hints.
	maxJSFiles = 50
	// maxExamples bounds the offending paths quoted in a note.
	maxExamples = 3
	// maxPathBytes bounds the length of a path kept while walking the index.
	maxPathBytes = 4096
)

var (
	errDepth = errors.New("the index nests too deeply")
	// errStop ends a walk that the visitor asked to stop; it is not a failure.
	errStop = errors.New("the walk was stopped by its caller")
)

// fileRef locates a packed file: off is relative to the start of the file data.
type fileRef struct {
	path string
	off  int64
	size int64
}

// nodeAttrs are the attributes of one index node that the walker cares about.
type nodeAttrs struct {
	dir      bool
	size     int64
	offset   string
	unpacked bool
	link     bool
}

// walker streams the JSON index and fills in Details without building the tree.
type walker struct {
	r        io.ReaderAt
	size     int64
	dataSize int64
	lim      limits.Limits
	d        *Details
	dec      *json.Decoder
	ctx      context.Context
	nodes    int

	badOffsets  int
	badExamples []string
	pkg         map[string]fileRef
	scripts     []fileRef

	// visit, when set, receives every packed file with a valid location; it
	// returns false to stop the walk.
	visit func(File) bool
}

func newWalker(r io.ReaderAt, size int64, lim limits.Limits, d *Details) *walker {
	return &walker{
		r: r, size: size, lim: lim, d: d,
		dataSize: max(size-d.DataOffset, 0),
		pkg:      map[string]fileRef{},
	}
}

// run walks the index. It returns the first structural error; everything
// recorded before it is kept.
func (w *walker) run(ctx context.Context, index []byte) error {
	w.ctx = ctx
	w.dec = json.NewDecoder(bytes.NewReader(index))
	w.dec.UseNumber()
	if err := w.expect('{'); err != nil {
		return err
	}
	for w.dec.More() {
		key, err := w.key()
		if err != nil {
			return err
		}
		if key != "files" {
			if err := w.skip(); err != nil {
				return err
			}
			continue
		}
		if err := w.dir("", 1); err != nil {
			return err
		}
	}
	return nil
}

// dir parses the value of a "files" key: an object mapping names to nodes.
func (w *walker) dir(prefix string, depth int) error {
	if depth > maxDepth {
		return errDepth
	}
	if err := w.expect('{'); err != nil {
		return err
	}
	for w.dec.More() {
		name, err := w.key()
		if err != nil {
			return err
		}
		if err := w.node(clip(prefix+clip(name)), depth+1); err != nil {
			return err
		}
	}
	_, err := w.dec.Token() // closing brace
	return err
}

// clip bounds a path so that a hostile index with enormous names cannot make
// every descendant's path copy them again.
func clip(s string) string {
	if len(s) > maxPathBytes {
		return s[:maxPathBytes]
	}
	return s
}

// node parses one entry: a directory ({"files": ...}) or a file.
func (w *walker) node(path string, depth int) error {
	w.nodes++
	if w.nodes&1023 == 0 {
		if err := w.ctx.Err(); err != nil {
			return err
		}
	}
	if depth > maxDepth {
		return errDepth
	}
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim || delim != '{' {
		if isDelim && delim == '[' {
			return w.skipRest()
		}
		return nil // a scalar where a node was expected: ignore it
	}
	var n nodeAttrs
	for w.dec.More() {
		key, err := w.key()
		if err != nil {
			return err
		}
		switch key {
		case "files":
			n.dir = true
			if err := w.dir(clip(path+"/"), depth+1); err != nil {
				return err
			}
		case "size":
			tok, err := w.scalar()
			if err != nil {
				return err
			}
			n.size = -1
			if num, ok := tok.(json.Number); ok {
				if v, err := num.Int64(); err == nil {
					n.size = v
				}
			}
		case "offset":
			tok, err := w.scalar()
			if err != nil {
				return err
			}
			n.offset, _ = tok.(string)
		case "unpacked":
			tok, err := w.scalar()
			if err != nil {
				return err
			}
			n.unpacked, _ = tok.(bool)
		case "link":
			if err := w.skip(); err != nil {
				return err
			}
			n.link = true
		default:
			if err := w.skip(); err != nil {
				return err
			}
		}
	}
	if _, err := w.dec.Token(); err != nil { // closing brace
		return err
	}
	if n.dir {
		w.d.DirectoryCount++
		return nil
	}
	return w.file(path, n)
}

// file records a file node and validates its offset against the archive. It
// returns errStop when the visitor asked to stop.
func (w *walker) file(path string, n nodeAttrs) error {
	d := w.d
	d.FileCount++
	if len(d.Files) < w.lim.MaxList {
		d.Files = append(d.Files, binio.Printable(path, maxNameLen))
	} else {
		d.FilesTruncated = true
	}
	if n.size > 0 {
		if sum := d.TotalSize + uint64(n.size); sum >= d.TotalSize {
			d.TotalSize = sum
		} else {
			d.TotalSize = math.MaxUint64
		}
	}
	switch {
	case n.link:
		return nil
	case n.unpacked:
		d.UnpackedCount++
		return nil
	}
	off, err := strconv.ParseInt(n.offset, 10, 64)
	if err != nil || off < 0 || n.size < 0 || off > w.dataSize || n.size > w.dataSize-off {
		w.badOffsets++
		if len(w.badExamples) < maxExamples {
			w.badExamples = append(w.badExamples, binio.Printable(path, 80))
		}
		return nil
	}
	ref := fileRef{path: path, off: off, size: n.size}
	switch {
	case isPackageJSON(path):
		if _, seen := w.pkg[path]; !seen {
			w.pkg[path] = ref
		}
	case isScript(path) && !underNodeModules(path) && len(w.scripts) < maxJSFiles:
		w.scripts = append(w.scripts, ref)
	}
	if w.visit != nil && !w.visit(w.fileOf(ref)) {
		return errStop
	}
	return nil
}

// fileOf describes a located file for a visitor.
func (w *walker) fileOf(ref fileRef) File {
	return File{Path: binio.Printable(ref.path, maxNameLen), Offset: w.d.DataOffset + ref.off, Size: ref.size}
}

// notes reports index-level problems found by the walk.
func (w *walker) notes() []string {
	if w.badOffsets == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d file entries point outside the archive data, so the file is truncated or corrupt (for example %s)",
		w.badOffsets, strings.Join(w.badExamples, ", "))}
}

func (w *walker) expect(want json.Delim) error {
	tok, err := w.dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q in the index, found %v", rune(want), tok)
	}
	return nil
}

func (w *walker) key() (string, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return "", err
	}
	s, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected a name in the index, found %v", tok)
	}
	return s, nil
}

// scalar reads the next value; objects and arrays are consumed and reported as nil.
func (w *walker) scalar() (json.Token, error) {
	tok, err := w.dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		return nil, w.skipRest()
	}
	return tok, nil
}

// skip consumes the next value whatever it is.
func (w *walker) skip() error {
	_, err := w.scalar()
	return err
}

// skipRest consumes tokens up to the delimiter that closes one already opened.
func (w *walker) skipRest() error {
	for depth := 1; depth > 0; {
		tok, err := w.dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func isPackageJSON(path string) bool {
	return path == "package.json" || path == "app/package.json" || path == "resources/app/package.json"
}

func isScript(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".cjs") || strings.HasSuffix(p, ".mjs")
}

func underNodeModules(path string) bool {
	return strings.HasPrefix(path, "node_modules/") || strings.Contains(path, "/node_modules/")
}
