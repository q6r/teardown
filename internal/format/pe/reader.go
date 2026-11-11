package pe

import (
	"errors"
	"io"
)

const (
	// cacheBlock and cacheSlots size the structure reader's cache: 64 direct
	// mapped blocks of one page each.
	cacheBlock = 4 << 10
	cacheSlots = 64
	// readBudget bounds the bytes the parser may pull through its structure
	// reader. Legitimate import, export and directory tables need a few
	// megabytes at most; a crafted image that scatters thousands of pointers over
	// a huge file must not make the parser read gigabytes.
	readBudget = 64 << 20
)

// errReadBudget is returned once the structure reader has used up its budget.
var errReadBudget = errors.New("pe: read budget for structure data exhausted")

type cacheSlot struct {
	block int64
	data  []byte // nil when the slot is empty
}

// blockReader adds a small block cache and a read budget to an io.ReaderAt. The
// parser issues many small reads that alternate between a handful of regions
// (export pointer tables, name strings, forwarder strings, import thunks and
// hint/name entries); a direct-mapped cache of page-sized blocks turns them into
// few real reads. Reads larger than two blocks bypass the cache. It is not
// safe for concurrent use.
type blockReader struct {
	r      io.ReaderAt
	size   int64
	slots  [cacheSlots]cacheSlot
	budget int64
	denied bool
}

func newBlockReader(r io.ReaderAt, size, budget int64) *blockReader {
	return &blockReader{r: r, size: size, budget: budget}
}

// spend charges n bytes against the budget. A read is allowed while any budget
// is left, so the last one may overshoot it.
func (b *blockReader) spend(n int64) error {
	if b.budget <= 0 {
		b.denied = true
		return errReadBudget
	}
	b.budget -= n
	return nil
}

// ReadAt implements io.ReaderAt.
func (b *blockReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 || off >= b.size {
		return 0, io.EOF
	}
	if len(p) > 2*cacheBlock {
		if err := b.spend(int64(len(p))); err != nil {
			return 0, err
		}
		return b.r.ReadAt(p, off)
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= b.size {
			return n, io.EOF
		}
		data, err := b.block(pos / cacheBlock)
		if err != nil {
			return n, err
		}
		rel := int(pos % cacheBlock)
		if rel >= len(data) {
			return n, io.EOF
		}
		n += copy(p[n:], data[rel:])
	}
	return n, nil
}

// block returns the data of block idx, reading it on a cache miss.
func (b *blockReader) block(idx int64) ([]byte, error) {
	s := &b.slots[idx%cacheSlots]
	if s.data != nil && s.block == idx {
		return s.data, nil
	}
	start := idx * cacheBlock
	want := int(min(int64(cacheBlock), b.size-start))
	if err := b.spend(int64(want)); err != nil {
		return nil, err
	}
	if cap(s.data) < want {
		s.data = make([]byte, want)
	}
	buf := s.data[:want]
	n, err := b.r.ReadAt(buf, start)
	if err != nil && !errors.Is(err, io.EOF) {
		s.data = nil
		return nil, err
	}
	if n == 0 {
		s.data = nil
		return nil, io.EOF
	}
	s.block, s.data = idx, buf[:n]
	return s.data, nil
}
