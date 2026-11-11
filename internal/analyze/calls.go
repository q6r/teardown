package analyze

import (
	"errors"
	"io"

	"github.com/q6r/teardown/internal/rules"
	"github.com/q6r/teardown/internal/xref"
)

// partialScanLimitation is added to the report when the scan for call sites did
// not cover all the code.
const partialScanLimitation = "The scan for the code behind imported functions covered only part of the executable sections (it is bounded), so an imported function whose calls are not shown may still be called."

// callSites scans the executable sections of the parsed PE image for the calls
// to its imports, so that the import findings can show the code behind them. It
// returns nil when there is nothing to show: the file is not a PE image, has no
// imports, or its code is not x86 or x86-64. The scan runs behind the recover
// and the analysis deadline like every parser, and never executes the file.
func (s *stages) callSites(r io.ReaderAt, size int64) rules.CodeSource {
	if s.layout == nil || len(s.layout.Slots) == 0 {
		return nil
	}
	var ix *xref.Index
	s.run("code", func() error {
		var err error
		ix, err = xref.Find(s.ctx, r, size, *s.layout, xref.Options{})
		if errors.Is(err, xref.ErrUnsupported) {
			ix = nil // another instruction set: there is no code to show, and that is not a failure
			return nil
		}
		return err
	})
	if ix == nil {
		return nil
	}
	if !ix.Complete() {
		s.rep.AddLimitation(partialScanLimitation)
	}
	return ix
}
