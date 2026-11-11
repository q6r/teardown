// Package hashing computes the file digests and the entropy profile in one
// streaming pass over the input.
package hashing

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/q6r/teardown/internal/entropy"
	"github.com/q6r/teardown/internal/report"
)

// chunkSize is the read size of the streaming pass; the context is checked
// between chunks so a large file can be cancelled promptly.
const chunkSize = 256 << 10

// Result is the outcome of a [Stream] pass.
type Result struct {
	// Hashes holds MD5, SHA-1 and SHA-256; Imphash is left empty (it comes from the PE parser).
	Hashes  report.Hashes
	Entropy report.Entropy
	// Size is the number of bytes read.
	Size int64
}

// Stream reads r once and feeds every byte to MD5, SHA-1, SHA-256, the entropy
// profile and any extra sinks (for example the string scanner). size is the
// expected length and only sizes the entropy windows; the stream may be longer
// or shorter. Sinks must not fail: a sink error aborts the pass.
func Stream(ctx context.Context, r io.Reader, size int64, sinks ...io.Writer) (Result, error) {
	// MD5 and SHA-1 are reported for compatibility with threat-intel feeds, not used for security.
	h5, h1, h256 := md5.New(), sha1.New(), sha256.New()
	prof := entropy.NewProfile(size)
	writers := append([]io.Writer{h5, h1, h256, prof}, sinks...)
	w := io.MultiWriter(writers...)

	buf := make([]byte, chunkSize)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return Result{}, werr
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Result{}, err
		}
	}
	return Result{
		Hashes: report.Hashes{
			MD5:    hex.EncodeToString(h5.Sum(nil)),
			SHA1:   hex.EncodeToString(h1.Sum(nil)),
			SHA256: hex.EncodeToString(h256.Sum(nil)),
		},
		Entropy: prof.Result(),
		Size:    total,
	}, nil
}
