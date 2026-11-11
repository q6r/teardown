package strs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/q6r/teardown/internal/report"
)

// feed writes data to s in chunks of the given size (the whole slice when chunk <= 0).
func feed(s *Scanner, data []byte, chunk int) {
	if chunk <= 0 || chunk > len(data) {
		chunk = max(len(data), 1)
	}
	for off := 0; off < len(data); off += chunk {
		_, _ = s.Write(data[off:min(off+chunk, len(data))])
	}
}

func scan(data []byte, opts Options, chunk int) report.Strings {
	s := NewScanner(opts)
	feed(s, data, chunk)
	return s.Result()
}

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

type wantItem struct {
	value  string
	offset int64
	enc    string
}

func gotItems(r report.Strings) []wantItem {
	out := make([]wantItem, len(r.Items))
	for i, it := range r.Items {
		out[i] = wantItem{it.Value, it.Offset, it.Encoding}
	}
	return out
}

func TestScannerExtraction(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		opts Options
		want []wantItem
	}{
		{
			name: "ascii runs split by control and high bytes",
			data: []byte("\x00\x00hello world\x00ab\x00tab\tinside\n\x80\xffxyz12345"),
			want: []wantItem{{"hello world", 2, "ascii"}, {"tab\tinside", 17, "ascii"}, {"xyz12345", 30, "ascii"}},
		},
		{
			name: "minimum length is honoured",
			data: []byte("abcd\x00abc\x00abcde"),
			opts: Options{MinLength: 4},
			want: []wantItem{{"abcd", 0, "ascii"}, {"abcde", 9, "ascii"}},
		},
		{
			name: "minimum length floor is three",
			data: []byte("ab\x00abc"),
			opts: Options{MinLength: 1},
			want: []wantItem{{"abc", 3, "ascii"}},
		},
		{
			name: "utf16 at an odd offset and a terminator",
			data: join([]byte{1}, utf16le("Hello"), []byte{0, 0, 0}, utf16le("World!")),
			want: []wantItem{{"Hello", 1, "utf16le"}, {"World!", 14, "utf16le"}},
		},
		{
			name: "utf16 never starts right after a printable byte",
			data: join([]byte("A"), utf16le("BCDEF")),
			opts: Options{MinLength: 4},
			want: []wantItem{{"CDEF", 3, "utf16le"}},
		},
		{
			name: "ascii terminator does not glue its last character to a following wide string",
			data: join([]byte("abc\x00"), utf16le("defgh"), []byte{0, 0}),
			want: []wantItem{{"defgh", 4, "utf16le"}},
		},
		{
			name: "wide string after a non-printable byte keeps its first character",
			data: join([]byte{0x01}, utf16le("ABCDE")),
			want: []wantItem{{"ABCDE", 1, "utf16le"}},
		},
		{
			name: "dangling low byte at the end is dropped",
			data: join(utf16le("ABCD"), []byte("E")),
			opts: Options{MinLength: 4},
			want: []wantItem{{"ABCD", 0, "utf16le"}},
		},
		{
			name: "ascii and utf16 interleaved come out in offset order",
			data: join([]byte("plain text here"), []byte{0}, utf16le("wide text"), []byte{0, 0}, []byte("more plain")),
			want: []wantItem{{"plain text here", 0, "ascii"}, {"wide text", 16, "utf16le"}, {"more plain", 36, "ascii"}},
		},
		{
			name: "noise is dropped",
			data: join([]byte("AAAAAAAA\x00ababababab\x00"), []byte(strings.Repeat("ab", 10)), []byte("\x00"), []byte(strings.Repeat("A", 24)), []byte("\x00realstring")),
			want: []wantItem{{strings.Repeat("ab", 10), 20, "ascii"}, {"realstring", 66, "ascii"}},
		},
		{
			name: "empty input",
			data: nil,
		},
		{
			name: "no strings at all",
			data: bytes.Repeat([]byte{0x00, 0x01, 0x80, 0xff}, 100),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunk := range []int{0, 1, 3} {
				got := gotItems(scan(tc.data, tc.opts, chunk))
				if len(got) != len(tc.want) {
					t.Fatalf("chunk %d: got %v, want %v", chunk, got, tc.want)
				}
				for i := range got {
					if got[i] != tc.want[i] {
						t.Fatalf("chunk %d: item %d = %+v, want %+v", chunk, i, got[i], tc.want[i])
					}
				}
			}
		})
	}
}

func TestScannerResultMetadata(t *testing.T) {
	data := []byte("see https://example.com/a and /usr/lib/x and plain words here\x00192.168.1.1\x00hello there")
	res := scan(data, Options{MinLength: 1}, 0)
	if res.MinLength != MinLengthFloor {
		t.Errorf("MinLength = %d, want %d", res.MinLength, MinLengthFloor)
	}
	if res.ByCategory == nil {
		t.Fatal("ByCategory must never be nil")
	}
	sum := 0
	for _, n := range res.ByCategory {
		sum += n
	}
	if sum != res.Total || res.Total != 3 {
		t.Errorf("Total = %d, sum of categories = %d, want 3", res.Total, sum)
	}
	if res.ByCategory[report.CatURL] != 1 || res.ByCategory[report.CatIP] != 1 || res.ByCategory[report.CatPlain] != 1 {
		t.Errorf("ByCategory = %v", res.ByCategory)
	}
	if res.Truncated {
		t.Error("nothing was dropped, Truncated must be false")
	}
	empty := scan(nil, Options{}, 0)
	if empty.Items == nil || empty.ByCategory == nil || empty.MinLength != DefaultMinLength {
		t.Errorf("empty result must have allocated collections and default min length: %+v", empty)
	}
}

func TestScannerKeepsRedactedSecretsOnly(t *testing.T) {
	var data []byte
	for _, s := range testSecrets() {
		data = append(data, s...)
		data = append(data, 0)
	}
	data = append(data, utf16le("key="+testAWSKey)...)
	data = append(data, 0, 0)
	data = append(data, testPEM...)
	data = append(data, '\n')

	for _, chunk := range []int{0, 1, 5} {
		res := scan(data, Options{}, chunk)
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range append(testSecrets(), testPEM) {
			if bytes.Contains(raw, []byte(s)) {
				t.Fatalf("chunk %d: raw secret %q leaked into the result", chunk, s[:6])
			}
		}
		secrets := 0
		for _, it := range res.Items {
			if it.Category != report.CatSecret {
				continue
			}
			secrets++
			if !it.Redacted || it.Kind == "" || !strings.Contains(it.Value, "…(") {
				t.Errorf("secret item is not properly redacted: %+v", it)
			}
		}
		if secrets != len(testSecrets())+2 {
			t.Errorf("chunk %d: found %d secrets, want %d", chunk, secrets, len(testSecrets())+2)
		}
		if res.ByCategory[report.CatSecret] != secrets {
			t.Errorf("ByCategory[secret] = %d, want %d", res.ByCategory[report.CatSecret], secrets)
		}
	}
	// The same key found as UTF-16 is redacted too and keeps its encoding.
	res := scan(join(utf16le(testAWSKey), []byte{0, 0}), Options{}, 3)
	if len(res.Items) != 1 || res.Items[0].Encoding != "utf16le" || res.Items[0].Value != "AKIA…(20 chars)" {
		t.Fatalf("utf16 secret = %+v", res.Items)
	}
}

func TestScannerRetentionPrioritisesClassifiedStrings(t *testing.T) {
	var data []byte
	for i := range 6 {
		data = append(data, "/usr/lib/lib"+string(rune('a'+i))+".so"...)
		data = append(data, 0)
	}
	data = append(data, testAWSKey...)
	data = append(data, 0)
	for _, w := range []string{"plain one", "plain two", "plain three"} {
		data = append(data, w...)
		data = append(data, 0)
	}
	res := scan(data, Options{MaxItems: 3}, 0)
	var values []string
	for _, it := range res.Items {
		values = append(values, it.Value)
	}
	want := []string{"/usr/lib/liba.so", "/usr/lib/libb.so", "AKIA…(20 chars)"}
	if !slices.Equal(values, want) {
		t.Fatalf("items = %q, want %q (secret evicts the latest path, plain strings get no room)", values, want)
	}
	if res.Total != 10 || !res.Truncated {
		t.Errorf("Total = %d, Truncated = %v; want 10 and true", res.Total, res.Truncated)
	}
	if res.ByCategory[report.CatPath] != 6 || res.ByCategory[report.CatPlain] != 3 {
		t.Errorf("counts must cover every string, got %v", res.ByCategory)
	}
}

func TestScannerPlainStringsFillRemainingRoom(t *testing.T) {
	var data []byte
	data = append(data, "https://example.com/x\x00"...)
	data = append(data, "10.1.2.3\x00"...)
	for i := range 10 {
		data = append(data, "plain string number "+string(rune('a'+i))+"\x00"...)
	}
	res := scan(data, Options{MaxItems: 5}, 0)
	if len(res.Items) != 5 {
		t.Fatalf("items = %d, want 5", len(res.Items))
	}
	for i, wantCat := range []string{report.CatURL, report.CatIP, report.CatPlain, report.CatPlain, report.CatPlain} {
		if res.Items[i].Category != wantCat {
			t.Errorf("item %d category = %q, want %q", i, res.Items[i].Category, wantCat)
		}
	}
	if res.Items[2].Value != "plain string number a" || !res.Truncated || res.Total != 12 {
		t.Errorf("plain strings must be the earliest ones: %+v total=%d truncated=%v", res.Items[2], res.Total, res.Truncated)
	}
}

func TestScannerMaxItemsIsClamped(t *testing.T) {
	if got := (Options{MaxItems: MaxItemsCeiling * 10}).normalize().MaxItems; got != MaxItemsCeiling {
		t.Errorf("MaxItems = %d, want ceiling %d", got, MaxItemsCeiling)
	}
	if got := (Options{MaxItems: -3}).normalize().MaxItems; got != DefaultMaxItems {
		t.Errorf("MaxItems = %d, want default %d", got, DefaultMaxItems)
	}
}

func TestScannerStopsAtTheTotalCap(t *testing.T) {
	if MaxTotal != 5_000_000 {
		t.Fatalf("MaxTotal = %d, the brief pins 5,000,000", MaxTotal)
	}
	var data []byte
	for i := range 20 {
		data = append(data, "string number "+string(rune('a'+i))+"\x00"...)
	}
	for _, chunk := range []int{0, 1, 13} {
		s := newScanner(Options{}, 5)
		feed(s, data, chunk)
		res := s.Result()
		if res.Total != 5 || !res.Truncated || len(res.Items) != 5 {
			t.Fatalf("chunk %d: total=%d truncated=%v items=%d; want 5, true, 5", chunk, res.Total, res.Truncated, len(res.Items))
		}
		if last := res.Items[4].Value; last != "string number e" {
			t.Errorf("chunk %d: last item = %q", chunk, last)
		}
	}
	// Exactly at the cap is not truncated.
	s := newScanner(Options{}, 20)
	feed(s, data, 0)
	if res := s.Result(); res.Total != 20 || res.Truncated {
		t.Errorf("exactly maxTotal strings: total=%d truncated=%v", res.Total, res.Truncated)
	}
}

func TestScannerSplitsLongRuns(t *testing.T) {
	t.Run("prefers delimiters", func(t *testing.T) {
		word := "word "
		data := []byte(strings.Repeat(word, 2000)) // 10,000 bytes, no terminator inside
		res := scan(data, Options{MaxItems: 100}, 0)
		if !res.Truncated {
			t.Error("a split run must mark the result truncated")
		}
		var rebuilt strings.Builder
		next := int64(0)
		for _, it := range res.Items {
			if len(it.Value) > MaxStringLen {
				t.Fatalf("piece of %d bytes exceeds the cap", len(it.Value))
			}
			if it.Offset != next {
				t.Fatalf("piece offset %d, want contiguous %d", it.Offset, next)
			}
			next += int64(len(it.Value))
			rebuilt.WriteString(it.Value)
		}
		if rebuilt.String() != string(data) {
			t.Fatalf("pieces do not rebuild the original run (%d vs %d bytes)", rebuilt.Len(), len(data))
		}
		if len(res.Items) < 3 {
			t.Errorf("expected at least 3 pieces, got %d", len(res.Items))
		}
		for _, it := range res.Items[:len(res.Items)-1] {
			if !strings.HasSuffix(it.Value, " ") {
				t.Errorf("piece %q does not end at a delimiter", it.Value[len(it.Value)-6:])
			}
		}
	})
	t.Run("hard cut without delimiters", func(t *testing.T) {
		alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		data := []byte(strings.Repeat(alphabet, 162)[:10000])
		res := scan(data, Options{}, 7)
		sizes := make([]int, len(res.Items))
		for i, it := range res.Items {
			sizes[i] = len(it.Value)
		}
		if !slices.Equal(sizes, []int{4096, 4096, 1808}) {
			t.Fatalf("piece sizes = %v, want [4096 4096 1808]", sizes)
		}
	})
	t.Run("utf16 runs split with correct offsets", func(t *testing.T) {
		text := strings.Repeat("segment ", 700) // 5,600 chars
		res := scan(utf16le(text), Options{MaxItems: 10}, 0)
		next := int64(0)
		var rebuilt strings.Builder
		for _, it := range res.Items {
			if it.Encoding != "utf16le" || it.Offset != next {
				t.Fatalf("piece %+v, want utf16le at %d", it, next)
			}
			next += 2 * int64(len(it.Value))
			rebuilt.WriteString(it.Value)
		}
		if rebuilt.String() != text {
			t.Fatal("utf16 pieces do not rebuild the original text")
		}
	})
	t.Run("a huge run stays linear", func(t *testing.T) {
		data := []byte(strings.Repeat("lorem ipsum dolor ", 60_000)) // ~1 MiB
		res := scan(data, Options{MaxItems: 5}, 0)
		if !res.Truncated || len(res.Items) != 5 {
			t.Fatalf("items = %d truncated = %v", len(res.Items), res.Truncated)
		}
	})
}

func TestScannerResultIsIdempotentAndIsolated(t *testing.T) {
	s := NewScanner(Options{})
	feed(s, []byte("first string\x00second string"), 0)
	a := s.Result()
	b := s.Result()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("Result must be idempotent")
	}
	a.Items[0].Value = "mutated"
	a.ByCategory["plain"] = 99
	if c := s.Result(); c.Items[0].Value != "first string" || c.ByCategory["plain"] != 2 {
		t.Fatal("mutating a returned Result must not affect later calls")
	}
	// Writes after Result are ignored and report success.
	n, err := s.Write([]byte("\x00late string appended"))
	if n != len("\x00late string appended") || err != nil {
		t.Fatalf("Write after Result = %d, %v", n, err)
	}
	if got := s.Result(); got.Total != 2 {
		t.Fatalf("late write changed the result: %+v", got)
	}
	if n, err := NewScanner(Options{}).Write(nil); n != 0 || err != nil {
		t.Fatalf("empty Write = %d, %v", n, err)
	}
}

// sampleStream builds a deterministic blob that mixes random bytes, plain and
// classified strings, secrets, UTF-16 text and noise.
func sampleStream(seed uint64, pieces int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	samples := []string{
		"hello world", "https://example.com/a/b?c=d", "C:\\Windows\\System32\\cmd.exe", "/usr/lib/x86_64-linux-gnu/libc.so.6",
		"CreateRemoteThread", "admin@example.org", "192.168.0.1", testAWSKey, "token=" + testGitHubPAT, testJWT,
		"HKLM\\Software\\Vendor\\App", "cmd.exe /c whoami", "Mozilla/5.0 (X11; Linux x86_64)", "d41d8cd98f00b204e9800998ecf8427e",
		"AAAAAAAAAAAA", "ab", "plain text with spaces", testPEM, "example.com", strings.Repeat("longrun ", 700),
	}
	var out []byte
	for range pieces {
		switch rng.IntN(5) {
		case 0:
			junk := make([]byte, rng.IntN(40))
			for i := range junk {
				junk[i] = byte(rng.IntN(256))
			}
			out = append(out, junk...)
		case 1, 2:
			out = append(out, samples[rng.IntN(len(samples))]...)
			out = append(out, byte(rng.IntN(3))) // 0, 1 or 2: terminator or control byte
		case 3:
			out = append(out, utf16le(samples[rng.IntN(len(samples))])...)
			out = append(out, 0, 0)
		default:
			out = append(out, 0, 0, 0)
		}
	}
	return out
}

func TestScannerResultDoesNotDependOnChunking(t *testing.T) {
	configs := []struct {
		name string
		make func() *Scanner
	}{
		{"defaults", func() *Scanner { return NewScanner(Options{}) }},
		{"tiny retention", func() *Scanner { return NewScanner(Options{MaxItems: 7, MinLength: 4}) }},
		{"total cap", func() *Scanner { return newScanner(Options{}, 50) }},
	}
	for seed := uint64(1); seed <= 3; seed++ {
		data := sampleStream(seed, 400)
		for _, cfg := range configs {
			whole := cfg.make()
			feed(whole, data, 0)
			want := whole.Result()
			if want.Total == 0 {
				t.Fatalf("seed %d: sample stream produced no strings", seed)
			}
			for _, chunk := range []int{1, 2, 3, 7, 64, 65, 4096, len(data) - 1} {
				s := cfg.make()
				feed(s, data, chunk)
				if got := s.Result(); !reflect.DeepEqual(got, want) {
					t.Fatalf("seed %d, %s, chunk %d: results differ (total %d vs %d, items %d vs %d)",
						seed, cfg.name, chunk, got.Total, want.Total, len(got.Items), len(want.Items))
				}
			}
		}
	}
}

func TestScannerIsDeterministicAndOrdered(t *testing.T) {
	data := sampleStream(42, 300)
	a, b := scan(data, Options{}, 0), scan(data, Options{}, 0)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("two runs over the same data differ")
	}
	for i := 1; i < len(a.Items); i++ {
		prev, cur := a.Items[i-1], a.Items[i]
		if cur.Offset < prev.Offset {
			t.Fatalf("items %d and %d are out of order: %d after %d", i-1, i, cur.Offset, prev.Offset)
		}
	}
	for _, it := range a.Items {
		if it.Offset < 0 || it.Offset >= int64(len(data)) {
			t.Fatalf("offset %d outside the stream", it.Offset)
		}
		if it.Encoding != "ascii" && it.Encoding != "utf16le" {
			t.Fatalf("encoding %q", it.Encoding)
		}
	}
}

func TestExtract(t *testing.T) {
	data := sampleStream(7, 200)
	want := scan(data, Options{}, 0)

	got, err := Extract(context.Background(), iotest.OneByteReader(bytes.NewReader(data[:2000])), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, scan(data[:2000], Options{}, 0)) {
		t.Error("Extract over a one-byte reader differs from scanning the same bytes")
	}
	full, err := Extract(context.Background(), bytes.NewReader(data), Options{})
	if err != nil || !reflect.DeepEqual(full, want) {
		t.Errorf("Extract over the whole stream differs: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Extract(ctx, bytes.NewReader(data), Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: err = %v", err)
	}
	boom := errors.New("boom")
	if _, err := Extract(context.Background(), iotest.ErrReader(boom), Options{}); !errors.Is(err, boom) {
		t.Errorf("read error: err = %v", err)
	}
	res, err := Extract(context.Background(), iotest.DataErrReader(strings.NewReader("last words")), Options{})
	if err != nil || len(res.Items) != 1 || res.Items[0].Value != "last words" {
		t.Errorf("data returned together with EOF must be scanned: %+v, %v", res, err)
	}
}

// TestScannerAdversarialInputsStayFast feeds pathological repetitions to the
// scanner and the classifier; none of them may take noticeable time.
func TestScannerAdversarialInputsStayFast(t *testing.T) {
	const size = 512 << 10
	patterns := []string{
		"@", "a@", ".", "1.", "1.1.1.1.", "http://", "://", `\`, `C:\`, "/a", "/", "AKIA", "AKIAIOSFODNN7EXAMPLE",
		"eyJ", "eyJhbGciOi.", "ghp_", "xox", "xoxb-", "-----BEGIN ", "HKLM\\", "HKEY_", "Mozilla/", "curl/7.",
		"cmd.exe /c ", "| sh ", "::", "1:", "A\x00", "\x00A", "\x00", "ab", "aaaa ", "=", "+/", "-_",
	}
	for _, p := range patterns {
		data := []byte(strings.Repeat(p, size/len(p)+1))[:size]
		start := time.Now()
		scan(data, Options{MaxItems: 50}, 0)
		scan(utf16le(string(data[:size/2])), Options{MaxItems: 50}, 4096)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("pattern %q took %v", p, d)
		}
	}
}
