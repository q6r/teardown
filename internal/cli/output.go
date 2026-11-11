package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/q6r/teardown/internal/render"
)

// writeJSON writes v as indented JSON. HTML escaping is off: the output is for
// machines and terminals, not for embedding in a page.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// destination is where a command writes its main output.
type destination struct {
	w     io.Writer
	file  *os.File
	isOut bool // stdout (not a file chosen with -o)
}

func (d destination) close() error {
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

// openDestination returns stdout, or the file at path (created or truncated). It
// refuses to overwrite any of the input files.
func openDestination(env Env, path string, inputs ...string) (destination, error) {
	if path == "" {
		return destination{w: env.Stdout, isOut: true}, nil
	}
	if err := refuseOverwrite(path, inputs); err != nil {
		return destination{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return destination{}, fmt.Errorf("cannot write %s: %w", path, err)
	}
	return destination{w: f, file: f}, nil
}

func refuseOverwrite(out string, inputs []string) error {
	outInfo, err := os.Stat(out)
	if err != nil {
		return nil // does not exist yet
	}
	for _, in := range inputs {
		if inInfo, err := os.Stat(in); err == nil && os.SameFile(outInfo, inInfo) {
			return fmt.Errorf("refusing to overwrite the input file %s", in)
		}
	}
	return nil
}

// renderOptions derives terminal rendering options from the common flags.
func renderOptions(env Env, w io.Writer, color string, ascii, verbose bool, width int) render.Options {
	if width == 0 {
		width = terminalWidth(env)
	}
	return render.Options{
		Color:   colorEnabled(color, env, w),
		ASCII:   asciiOnly(ascii, env),
		Width:   width,
		Verbose: verbose,
	}
}
