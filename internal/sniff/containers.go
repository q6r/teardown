package sniff

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/report"
)

// detectASAR recognises Electron ASAR archives. They have no magic number, only
// Chromium pickle framing: a uint32 4, the header size, the header pickle's
// payload size, the JSON length, and then the JSON index starting {"files":.
func detectASAR(p *probe) (report.Type, bool) {
	const jsonStart = 16
	index := []byte(`{"files":`)
	h := p.head
	if len(h) < jsonStart+len(index) || binary.LittleEndian.Uint32(h) != 4 {
		return report.Type{}, false
	}
	headerSize := int64(binary.LittleEndian.Uint32(h[4:]))
	payload := int64(binary.LittleEndian.Uint32(h[8:]))
	jsonLen := int64(binary.LittleEndian.Uint32(h[12:]))
	// The pickle payload is the 4-byte string length followed by the JSON padded to
	// a multiple of four bytes.
	if payload != headerSize-4 || jsonLen <= int64(len(index)) || payload < 4+jsonLen || payload-4-jsonLen > 3 {
		return report.Type{}, false
	}
	if !bytes.HasPrefix(h[jsonStart:], index) {
		return report.Type{}, false
	}
	return newType(report.TypeAsar, report.FamilyPackage, "Electron ASAR archive", mimeOctet,
		confidenceIf(8+headerSize <= p.size), "electron"), true
}

// Bounds for safetensors detection.
const (
	safetensorsMaxHeader = 100 << 20 // headers above this are not believed
	safetensorsMaxProbe  = 16 << 20  // headers above this are accepted on framing alone
)

// detectSafetensors recognises Hugging Face safetensors files: a little-endian
// uint64 header length followed by a JSON object that describes the tensors.
func detectSafetensors(p *probe) (report.Type, bool) {
	h := p.head
	if len(h) < 9 || h[8] != '{' {
		return report.Type{}, false
	}
	n := binary.LittleEndian.Uint64(h)
	if n < 2 || n > safetensorsMaxHeader || int64(n) > p.size-8 {
		return report.Type{}, false
	}
	if n > safetensorsMaxProbe {
		// Too large to decode while sniffing: accept the framing (the header must
		// end with a closing brace, possibly followed by padding spaces).
		end, err := binio.ReadAt(p.r, p.size, 8+int64(n)-1, 1)
		if err != nil || (end[0] != '}' && end[0] != ' ') {
			return report.Type{}, false
		}
		return newType(report.TypeSafetensors, report.FamilyModel, "Safetensors model", mimeOctet,
			report.ConfidenceMedium), true
	}
	buf, err := binio.ReadAt(p.r, p.size, 8, int64(n))
	if err != nil {
		return report.Type{}, false
	}
	tensors, ok := safetensorsTensors(buf)
	if !ok {
		return report.Type{}, false
	}
	conf := report.ConfidenceMedium
	if tensors > 0 {
		conf = report.ConfidenceHigh
	}
	return newType(report.TypeSafetensors, report.FamilyModel, fmt.Sprintf("Safetensors model (%d tensors)", tensors),
		mimeOctet, conf), true
}

// safetensorsTensors validates a safetensors JSON header and counts its tensors.
// Every entry other than __metadata__ must carry a dtype and two data offsets.
func safetensorsTensors(header []byte) (int, bool) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(header, &entries); err != nil {
		return 0, false
	}
	tensors := 0
	for name, raw := range entries {
		if name == "__metadata__" {
			continue
		}
		var t struct {
			DType   string  `json:"dtype"`
			Offsets []int64 `json:"data_offsets"`
		}
		if json.Unmarshal(raw, &t) != nil || t.DType == "" || len(t.Offsets) != 2 {
			return 0, false
		}
		tensors++
	}
	return tensors, true
}
