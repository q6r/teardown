package analyze

import (
	"io"

	"github.com/q6r/teardown/internal/format/gguf"
	"github.com/q6r/teardown/internal/limits"
	"github.com/q6r/teardown/internal/report"
)

// parseDataFormat handles the data and model formats that have a parser
// (GGUF). Types without one keep only the generic facts, and addLimitations
// says so in the report.
func parseDataFormat(s *stages, r io.ReaderAt, size int64, lim limits.Limits) {
	rep := s.rep
	if rep.Type.ID != report.TypeGGUF {
		return
	}
	s.parse("gguf", func() ([]string, error) {
		res, err := gguf.Parse(s.ctx, r, size, lim)
		if res == nil {
			return nil, err
		}
		rep.Details["gguf"] = res.Details
		return res.Notes, err
	})
}
