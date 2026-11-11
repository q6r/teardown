package hashing

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestStreamKnownVectors(t *testing.T) {
	tests := []struct {
		name              string
		in                string
		md5, sha1, sha256 string
	}{
		{
			"empty", "",
			"d41d8cd98f00b204e9800998ecf8427e",
			"da39a3ee5e6b4b0d3255bfef95601890afd80709",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"abc", "abc",
			"900150983cd24fb0d6963f7d28e17f72",
			"a9993e364706816aba3e25717850c26c9cd0d89d",
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Stream(context.Background(), strings.NewReader(tc.in), int64(len(tc.in)))
			if err != nil {
				t.Fatal(err)
			}
			if res.Hashes.MD5 != tc.md5 || res.Hashes.SHA1 != tc.sha1 || res.Hashes.SHA256 != tc.sha256 {
				t.Fatalf("hashes = %+v", res.Hashes)
			}
			if res.Hashes.Imphash != "" {
				t.Fatal("Stream must not set the imphash")
			}
			if res.Size != int64(len(tc.in)) {
				t.Fatalf("Size = %d", res.Size)
			}
		})
	}
}

func TestStreamEntropyAndSinksSeeEveryByte(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 3}, 4096) // 16 KiB, entropy exactly 2
	var sink bytes.Buffer
	// OneByteReader and DataErrReader exercise short reads and EOF returned with data.
	res, err := Stream(context.Background(), iotest.DataErrReader(iotest.OneByteReader(bytes.NewReader(data[:300]))), 300, &sink)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.Bytes(), data[:300]) {
		t.Fatal("sink did not receive every byte, in order")
	}
	res2, err := Stream(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Entropy.Overall != 2 {
		t.Fatalf("entropy = %v, want 2", res2.Entropy.Overall)
	}
	if res2.Entropy.WindowSize != 256 || len(res2.Entropy.Windows) != 64 {
		t.Fatalf("windows = %d of %d bytes", len(res2.Entropy.Windows), res2.Entropy.WindowSize)
	}
	if res.Size != 300 {
		t.Fatalf("Size = %d", res.Size)
	}
}

func TestStreamHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Stream(ctx, bytes.NewReader(make([]byte, 1<<20)), 1<<20)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestStreamPropagatesReadAndSinkErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Stream(context.Background(), iotest.ErrReader(boom), 10); !errors.Is(err, boom) {
		t.Fatalf("read error: got %v", err)
	}
	if _, err := Stream(context.Background(), strings.NewReader("abc"), 3, failingWriter{boom}); !errors.Is(err, boom) {
		t.Fatalf("sink error: got %v", err)
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

var _ io.Writer = failingWriter{}

func BenchmarkStream(b *testing.B) {
	data := make([]byte, 8<<20)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := Stream(context.Background(), bytes.NewReader(data), int64(len(data))); err != nil {
			b.Fatal(err)
		}
	}
}
