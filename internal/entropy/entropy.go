// Package entropy computes Shannon entropy (bits per byte, 0..8) for whole
// files, byte ranges (sections) and fixed-count windowed profiles.
//
// Every value returned by an exported function except [Shannon] is rounded to
// three decimals so that reports are stable and compact.
package entropy

import (
	"errors"
	"io"
	"math"

	"github.com/q6r/teardown/internal/report"
)

// MaxWindows is the maximum number of windows in a profile.
const MaxWindows = 512

const (
	minWindow = 256
	blockSize = 64 << 10
	// MaxSample bounds how many bytes [Range] reads for one range; larger ranges
	// are sampled with evenly spaced blocks.
	MaxSample = 32 << 20
)

// Shannon returns the entropy in bits per byte of a byte histogram, in [0, 8].
func Shannon(counts *[256]uint64) float64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	n := float64(total)
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return math.Min(math.Max(h, 0), 8)
}

// Round rounds an entropy value to three decimals.
func Round(h float64) float64 { return math.Round(h*1000) / 1000 }

// Bytes returns the entropy of b.
func Bytes(b []byte) float64 {
	var counts [256]uint64
	for _, v := range b {
		counts[v]++
	}
	return Round(Shannon(&counts))
}

// Range returns the entropy of n bytes at offset off in r. Ranges larger than
// [MaxSample] are estimated from evenly spaced 64 KiB blocks. A source that is
// shorter than n is measured over the bytes that exist.
func Range(r io.ReaderAt, off, n int64) (float64, error) {
	if n <= 0 || off < 0 {
		return 0, nil
	}
	var counts [256]uint64
	buf := make([]byte, min(n, blockSize)) // small sections need small buffers

	scan := func(at, length int64) error {
		for length > 0 {
			chunk := min(length, int64(len(buf)))
			got, err := r.ReadAt(buf[:chunk], at)
			for _, v := range buf[:got] {
				counts[v]++
			}
			if int64(got) < chunk {
				if err == nil || errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			at += chunk
			length -= chunk
		}
		return nil
	}

	if n <= MaxSample {
		if err := scan(off, n); err != nil {
			return 0, err
		}
		return Round(Shannon(&counts)), nil
	}
	blocks := int64(MaxSample / blockSize)
	stride := (n - blockSize) / (blocks - 1)
	for i := range blocks {
		if err := scan(off+i*stride, blockSize); err != nil {
			return 0, err
		}
	}
	return Round(Shannon(&counts)), nil
}

// WindowSize returns the window size used for a stream of the given length: the
// smallest power of two (at least 256 bytes) that yields at most [MaxWindows]
// windows.
func WindowSize(size int64) int64 {
	w := int64(minWindow)
	for (size+w-1)/w > MaxWindows && w < math.MaxInt64/2 {
		w <<= 1
	}
	return w
}

// Profile accumulates the overall entropy and a windowed profile of a byte
// stream in a single pass. It implements [io.Writer] so it can be fed by an
// [io.MultiWriter] next to the hashes.
type Profile struct {
	window  int64
	cur     [256]uint64
	inCur   int64
	total   [256]uint64
	windows []float64
	done    bool
}

// NewProfile returns a profile for a stream of the expected length.
func NewProfile(size int64) *Profile {
	return &Profile{window: WindowSize(size), windows: make([]float64, 0, 16)}
}

// Write consumes stream bytes. It never fails.
func (p *Profile) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		chunk := b
		if room := p.window - p.inCur; int64(len(chunk)) > room {
			chunk = chunk[:room]
		}
		for _, v := range chunk {
			p.cur[v]++
		}
		p.inCur += int64(len(chunk))
		b = b[len(chunk):]
		if p.inCur == p.window {
			p.flush()
		}
	}
	return n, nil
}

func (p *Profile) flush() {
	if p.inCur == 0 {
		return
	}
	if len(p.windows) < MaxWindows {
		p.windows = append(p.windows, Round(Shannon(&p.cur)))
	}
	for i, c := range &p.cur {
		p.total[i] += c
	}
	p.cur = [256]uint64{}
	p.inCur = 0
}

// Result finalises the profile. Calling it more than once returns the same data;
// writing after Result is not supported.
func (p *Profile) Result() report.Entropy {
	if !p.done {
		p.flush()
		p.done = true
	}
	return report.Entropy{
		Overall:    Round(Shannon(&p.total)),
		WindowSize: p.window,
		Windows:    append([]float64{}, p.windows...),
	}
}
