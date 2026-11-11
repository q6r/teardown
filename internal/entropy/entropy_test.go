package entropy

import (
	"bytes"
	"math"
	"testing"
)

func TestBytes(t *testing.T) {
	uniform := make([]byte, 0, 256*4)
	for range 4 {
		for i := range 256 {
			uniform = append(uniform, byte(i))
		}
	}
	tests := []struct {
		name string
		in   []byte
		want float64
	}{
		{"empty", nil, 0},
		{"single value", bytes.Repeat([]byte{7}, 1000), 0},
		{"two values evenly", bytes.Repeat([]byte{0, 1}, 500), 1},
		{"four values evenly", bytes.Repeat([]byte{0, 1, 2, 3}, 250), 2},
		{"all byte values", uniform, 8},
		{"skewed", append(bytes.Repeat([]byte{0}, 3), 1), 0.811},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Bytes(tc.in); math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("Bytes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRange(t *testing.T) {
	data := append(bytes.Repeat([]byte{0}, 1000), bytes.Repeat([]byte{0, 1}, 500)...)
	r := bytes.NewReader(data)
	tests := []struct {
		name   string
		off, n int64
		want   float64
	}{
		{"zeros", 0, 1000, 0},
		{"two symbols", 1000, 1000, 1},
		{"whole", 0, 2000, 0.811},
		{"empty range", 5, 0, 0},
		{"negative offset", -1, 10, 0},
		{"range longer than source measures what exists", 1000, 5000, 1},
		{"offset beyond source", 9000, 10, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Range(r, tc.off, tc.n)
			if err != nil || math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("Range = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// patterned produces a deterministic, highly compressible stream of a given length.
type patterned struct{ n int64 }

func (p *patterned) ReadAt(b []byte, off int64) (int, error) {
	if off >= p.n {
		return 0, bytes.ErrTooLarge
	}
	n := int64(len(b))
	if off+n > p.n {
		n = p.n - off
	}
	for i := range n {
		b[i] = byte((off + i) / blockSize % 2) // alternates 0/1 per block
	}
	return int(n), nil
}

func TestRangeSamplesLargeRanges(t *testing.T) {
	// 4 GiB virtual source: must be answered by sampling, quickly, without reading it all.
	src := &patterned{n: 4 << 30}
	got, err := Range(src, 0, src.n)
	if err != nil {
		t.Fatal(err)
	}
	// Blocks alternate between all-0 and all-1, so the estimate is close to 1 bit.
	if got < 0.9 || got > 1.0 {
		t.Fatalf("sampled entropy = %v, want about 1", got)
	}
}

func TestWindowSizeBoundsWindowCount(t *testing.T) {
	tests := []struct {
		size int64
		want int64
	}{
		{0, 256},
		{1, 256},
		{256 * 512, 256},
		{256*512 + 1, 512},
		{1 << 20, 2048},
		{100 << 20, 256 << 10},
	}
	for _, tc := range tests {
		got := WindowSize(tc.size)
		if got != tc.want {
			t.Errorf("WindowSize(%d) = %d, want %d", tc.size, got, tc.want)
		}
		if windows := (tc.size + got - 1) / got; windows > MaxWindows {
			t.Errorf("WindowSize(%d) yields %d windows", tc.size, windows)
		}
	}
}

func TestProfile(t *testing.T) {
	// 4 windows of 256 bytes: zeros, two symbols, four symbols, all symbols.
	var data []byte
	data = append(data, bytes.Repeat([]byte{0}, 256)...)
	data = append(data, bytes.Repeat([]byte{0, 1}, 128)...)
	data = append(data, bytes.Repeat([]byte{0, 1, 2, 3}, 64)...)
	for i := range 256 {
		data = append(data, byte(i))
	}
	p := NewProfile(int64(len(data)))
	// Feed in awkward, window-straddling chunks.
	for off := 0; off < len(data); {
		n := min(97, len(data)-off)
		if _, err := p.Write(data[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	res := p.Result()
	if res.WindowSize != 256 {
		t.Fatalf("WindowSize = %d", res.WindowSize)
	}
	want := []float64{0, 1, 2, 8}
	if len(res.Windows) != len(want) {
		t.Fatalf("windows = %v", res.Windows)
	}
	for i, w := range want {
		if math.Abs(res.Windows[i]-w) > 1e-9 {
			t.Errorf("window %d = %v, want %v", i, res.Windows[i], w)
		}
	}
	if got := Bytes(data); res.Overall != got {
		t.Errorf("overall = %v, want %v", res.Overall, got)
	}
	again := p.Result()
	if again.Overall != res.Overall || len(again.Windows) != len(res.Windows) {
		t.Error("Result must be idempotent")
	}
}

func TestProfilePartialLastWindowAndEmpty(t *testing.T) {
	p := NewProfile(300)
	_, _ = p.Write(bytes.Repeat([]byte{1}, 300))
	res := p.Result()
	if len(res.Windows) != 2 {
		t.Fatalf("300 bytes at window 256 must give 2 windows, got %v", res.Windows)
	}
	empty := NewProfile(0).Result()
	if empty.Overall != 0 || len(empty.Windows) != 0 || empty.Windows == nil {
		t.Fatalf("empty profile = %+v (Windows must be a non-nil empty slice)", empty)
	}
}

func TestProfileNeverExceedsMaxWindows(t *testing.T) {
	// Declared size is tiny but the stream is much longer (a file that grew).
	p := NewProfile(256)
	chunk := make([]byte, 1<<20)
	for range 4 {
		_, _ = p.Write(chunk)
	}
	res := p.Result()
	if len(res.Windows) != MaxWindows {
		t.Fatalf("windows = %d, want capped at %d", len(res.Windows), MaxWindows)
	}
	if res.Overall != 0 {
		t.Fatalf("overall of zeros = %v", res.Overall)
	}
}
