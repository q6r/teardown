// Package analyze is the pipeline: it sniffs the file type, runs the single
// hashing/entropy/strings pass, dispatches to the format parser, evaluates the
// rules and assembles the final [report.Report]. It never executes the analysed
// file, and every parser runs behind a recover so a bug in one format cannot
// take the analysis down.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

// DefaultTimeout bounds one analysis unless [Options.Timeout] says otherwise.
const DefaultTimeout = 60 * time.Second

// Defaults for string extraction.
const (
	DefaultMinString  = 5
	DefaultMaxStrings = 2000
)

// maxNameRunes bounds the file name recorded in a report.
const maxNameRunes = 255

// Options tunes an analysis. The zero value is valid.
type Options struct {
	// Name overrides the file name recorded in the report (uploads pass the
	// client's sanitised name). [File] defaults it to the base name of the path.
	Name string
	// MinString is the minimum string length (default [DefaultMinString]).
	MinString int
	// MaxStrings caps the string items kept in the report (default [DefaultMaxStrings]).
	MaxStrings int
	// Timeout bounds the whole analysis (default [DefaultTimeout]).
	Timeout time.Duration
	// Now supplies the clock; tests inject a fixed one.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.MinString <= 0 {
		o.MinString = DefaultMinString
	}
	if o.MaxStrings <= 0 {
		o.MaxStrings = DefaultMaxStrings
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Name == "" {
		o.Name = "(unnamed)"
	}
	o.Name = binio.Printable(o.Name, maxNameRunes)
	return o
}

// File analyses the regular file at path.
func File(ctx context.Context, path string, opts Options) (*report.Report, error) {
	f, size, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opts.Name == "" {
		opts.Name = filepath.Base(path)
	}
	return Reader(ctx, f, size, opts)
}

// Summary is the cheap result of [Quick]: identity, type, hashes and entropy.
type Summary struct {
	File    report.File    `json:"file"`
	Type    report.Type    `json:"type"`
	Hashes  report.Hashes  `json:"hashes"`
	Entropy report.Entropy `json:"entropy"`
}

// QuickFile computes the [Summary] of the regular file at path.
func QuickFile(ctx context.Context, path string, opts Options) (*Summary, error) {
	f, size, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opts.Name == "" {
		opts.Name = filepath.Base(path)
	}
	return Quick(ctx, f, size, opts)
}

// StringsResult is the outcome of [StringsFile].
type StringsResult struct {
	File    report.File    `json:"file"`
	Strings report.Strings `json:"strings"`
}

// StringsFile extracts and classifies the strings of the regular file at path.
func StringsFile(ctx context.Context, path string, opts Options) (*StringsResult, error) {
	f, size, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opts.Name == "" {
		opts.Name = filepath.Base(path)
	}
	opts = opts.withDefaults()
	s, err := Strings(ctx, f, size, opts)
	if err != nil {
		return nil, err
	}
	return &StringsResult{File: report.File{Name: opts.Name, Size: size}, Strings: s}, nil
}

// open opens path and checks that it is a regular file.
func open(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, 0, errors.New(path + " is not a regular file")
	}
	return f, st.Size(), nil
}

// timeoutError explains a deadline that expired before the file was read.
func timeoutError(name string, d time.Duration, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("analysis of %s timed out after %s while reading the file", name, d)
	}
	return fmt.Errorf("reading %s: %w", name, err)
}
