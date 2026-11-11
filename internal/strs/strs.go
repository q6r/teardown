// Package strs extracts printable strings from binary data and classifies them.
//
// A [Scanner] is a byte-at-a-time state machine that finds printable-ASCII runs
// and UTF-16LE runs (a printable ASCII code unit followed by 0x00, at any
// alignment) while the data streams past, so it can sit next to the hashing
// pass and works the same however the stream is chunked. Every string is
// classified into exactly one category (see [Classify]); secrets are redacted
// before they are stored and never leave the scanner in full.
//
// Hard limits keep memory bounded for any input: a single string holds at most
// [MaxStringLen] bytes (longer runs are split), at most [MaxTotal] strings are
// counted, and at most 2*MaxItems strings are retained.
package strs

import (
	"context"
	"errors"
	"io"

	"github.com/q6r/teardown/internal/report"
)

// Limits and defaults.
const (
	// DefaultMinLength is the minimum string length when Options.MinLength is 0.
	DefaultMinLength = 5
	// MinLengthFloor is the smallest accepted minimum length; lower values are raised to it.
	MinLengthFloor = 3
	// DefaultMaxItems is the number of items kept when Options.MaxItems is 0.
	DefaultMaxItems = 2000
	// MaxItemsCeiling caps Options.MaxItems so retained memory stays bounded.
	MaxItemsCeiling = 250_000
	// MaxStringLen is the longest single string in bytes; longer runs are split.
	MaxStringLen = 4096
	// MaxTotal is the number of strings after which scanning stops.
	MaxTotal = 5_000_000
)

// chunkSize is the read size used by [Extract].
const chunkSize = 256 << 10

// Options configures a [Scanner]. The zero value is valid.
type Options struct {
	// MinLength is the minimum string length in characters (default
	// [DefaultMinLength], floor [MinLengthFloor]).
	MinLength int
	// MaxItems is the maximum number of items kept in the result (default
	// [DefaultMaxItems], ceiling [MaxItemsCeiling]).
	MaxItems int
}

func (o Options) normalize() Options {
	switch {
	case o.MinLength <= 0:
		o.MinLength = DefaultMinLength
	case o.MinLength < MinLengthFloor:
		o.MinLength = MinLengthFloor
	}
	switch {
	case o.MaxItems <= 0:
		o.MaxItems = DefaultMaxItems
	case o.MaxItems > MaxItemsCeiling:
		o.MaxItems = MaxItemsCeiling
	}
	return o
}

// Extract reads r to the end, feeding a [Scanner], and returns its result. It
// checks ctx between reads.
func Extract(ctx context.Context, r io.Reader, opts Options) (report.Strings, error) {
	s := NewScanner(opts)
	buf := make([]byte, chunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return report.Strings{}, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = s.Write(buf[:n])
		}
		if errors.Is(err, io.EOF) {
			return s.Result(), nil
		}
		if err != nil {
			return report.Strings{}, err
		}
	}
}
