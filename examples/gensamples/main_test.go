package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCommittedSamplesAreCurrent keeps the files of examples/samples in step
// with the builders that generate them: a sample that is present must be what
// `go run ./examples/gensamples -dropper` writes today, byte for byte. A sample
// that is absent is skipped (dropper.bin is optional).
func TestCommittedSamplesAreCurrent(t *testing.T) {
	seen := 0
	for _, s := range buildSamples(true) {
		got, err := os.ReadFile(filepath.Join("..", "samples", s.name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		seen++
		if !bytes.Equal(got, s.data) {
			t.Errorf("examples/samples/%s is out of date: regenerate it with `go run ./examples/gensamples -dropper`", s.name)
		}
	}
	if seen == 0 {
		t.Skip("no sample file is present")
	}
}

func TestDropperIsOptionalAndLast(t *testing.T) {
	without, with := buildSamples(false), buildSamples(true)
	if len(with) != len(without)+1 || with[len(with)-1].name != "dropper.bin" {
		t.Fatalf("%d samples without the dropper, %d with it, last %q", len(without), len(with), with[len(with)-1].name)
	}
	for _, s := range without {
		if s.name == "dropper.bin" {
			t.Error("dropper.bin must only be written when asked for")
		}
	}
	for _, s := range with {
		if len(s.data) == 0 {
			t.Errorf("%s is empty", s.name)
		}
	}
}
