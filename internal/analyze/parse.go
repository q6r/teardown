package analyze

import (
	"context"
	"io"
	"slices"

	"github.com/q6r/teardown/internal/format/archive"
	"github.com/q6r/teardown/internal/format/asar"
	"github.com/q6r/teardown/internal/format/elf"
	"github.com/q6r/teardown/internal/format/goinfo"
	"github.com/q6r/teardown/internal/format/macho"
	"github.com/q6r/teardown/internal/format/pe"
	"github.com/q6r/teardown/internal/format/wasm"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

// parse runs a format parser behind the recover and records its notes.
func (s *stages) parse(name string, fn func() ([]string, error)) {
	var notes []string
	s.run(name, func() (err error) {
		notes, err = fn()
		return err
	})
	s.notes(name, notes)
}

// parseFormat dispatches on the sniffed type to the matching parser and merges
// the result into the report. Types without a parser keep only the generic facts.
func parseFormat(s *stages, r io.ReaderAt, size int64, lim limits.Limits) {
	rep := s.rep
	switch rep.Type.ID {
	case report.TypePE:
		s.parse("pe", func() ([]string, error) { return parsePE(s.ctx, rep, r, size, lim) })
	case report.TypeELF:
		s.parse("elf", func() ([]string, error) { return parseELF(s.ctx, rep, r, size, lim) })
	case report.TypeMachO, report.TypeMachOFat:
		s.parse("macho", func() ([]string, error) { return parseMachO(s.ctx, rep, r, size, lim) })
	case report.TypeZip, report.TypeJar, report.TypeAPK, report.TypeAAB, report.TypeDocx, report.TypeXlsx,
		report.TypePptx, report.TypeODF, report.TypeEPUB, report.TypeNupkg, report.TypeWheel, report.TypeVSIX:
		s.parse("archive", func() ([]string, error) {
			res, err := archive.Parse(s.ctx, r, size, lim, rep.Type.ID)
			if res == nil {
				return nil, err
			}
			rep.Details["archive"] = res.Details
			addParserLimitations(rep, res.Limitations)
			return res.Notes, err
		})
	case report.TypeAsar:
		s.parse("asar", func() ([]string, error) {
			res, err := asar.Parse(s.ctx, r, size, lim)
			if res == nil {
				return nil, err
			}
			rep.Details["asar"] = res.Details
			addParserLimitations(rep, res.Limitations)
			return res.Notes, err
		})
	case report.TypeWasm:
		s.parse("wasm", func() ([]string, error) {
			res, err := wasm.Parse(s.ctx, r, size, lim)
			if res == nil {
				return nil, err
			}
			rep.Sections, rep.Imports, rep.Exports = res.Sections, res.Imports, res.Exports
			rep.Details["wasm"] = res.Details
			return res.Notes, err
		})
	default:
		parseDataFormat(s, r, size, lim)
	}

	// Go build information is embedded in PE, ELF and Mach-O executables alike.
	switch rep.Type.ID {
	case report.TypePE, report.TypeELF, report.TypeMachO, report.TypeMachOFat:
		s.run("go", func() error {
			if info, ok := goinfo.Read(r); ok {
				rep.Details["go"] = info
				rep.Type.Tags = addTag(rep.Type.Tags, "go")
			}
			return nil
		})
	}
}

func parsePE(ctx context.Context, rep *report.Report, r io.ReaderAt, size int64, lim limits.Limits) ([]string, error) {
	res, err := pe.Parse(ctx, r, size, lim)
	if res == nil {
		return nil, err
	}
	rep.Sections, rep.Imports, rep.Exports, rep.Hardening = res.Sections, res.Imports, res.Exports, res.Hardening
	rep.Hashes.Imphash = res.ImpHash
	rep.Details["pe"] = res.Details
	return res.Notes, err
}

func parseELF(ctx context.Context, rep *report.Report, r io.ReaderAt, size int64, lim limits.Limits) ([]string, error) {
	res, err := elf.Parse(ctx, r, size, lim)
	if res == nil {
		return nil, err
	}
	rep.Sections, rep.Imports, rep.Exports, rep.Hardening = res.Sections, res.Imports, res.Exports, res.Hardening
	rep.Details["elf"] = res.Details
	return res.Notes, err
}

func parseMachO(ctx context.Context, rep *report.Report, r io.ReaderAt, size int64, lim limits.Limits) ([]string, error) {
	res, err := macho.Parse(ctx, r, size, lim)
	if res == nil {
		return nil, err
	}
	rep.Sections, rep.Imports, rep.Exports, rep.Hardening = res.Sections, res.Imports, res.Exports, res.Hardening
	rep.Details["macho"] = res.Details
	return res.Notes, err
}

// addParserLimitations records parser-supplied limitations at report level.
func addParserLimitations(rep *report.Report, limitations []string) {
	for _, l := range limitations {
		rep.AddLimitation(l)
	}
}

// addTag returns tags with tag added, keeping the list sorted and unique.
func addTag(tags []string, tag string) []string {
	if slices.Contains(tags, tag) {
		return tags
	}
	out := append(slices.Clone(tags), tag)
	slices.Sort(out)
	return out
}
