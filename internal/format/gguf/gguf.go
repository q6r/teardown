// Package gguf reads the header of GGUF model files (the llama.cpp format):
// version, counts, metadata key/value pairs and tensor descriptions. It never
// loads tensor data and its memory use does not depend on the header size:
// arrays are skipped, long strings are cut and recorded lists are capped.
package gguf

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"strconv"
	"strings"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/limits"
)

// Result is the outcome of [Parse].
type Result struct {
	// Details is stored under details["gguf"] in the report.
	Details Details
	// Notes lists non-fatal problems met while parsing.
	Notes []string
}

// Details are the GGUF facts recorded in the report (JSON keys are camelCase).
type Details struct {
	// Version is the GGUF format version (1, 2 or 3).
	Version uint32 `json:"version"`
	// TensorCount and KVCount are the counts declared by the header.
	TensorCount uint64 `json:"tensorCount"`
	KVCount     uint64 `json:"kvCount"`
	// Architecture is general.architecture, Name is general.name.
	Architecture string `json:"architecture,omitempty"`
	Name         string `json:"name,omitempty"`
	// ContextLength is "<architecture>.context_length" (0 when absent).
	ContextLength uint64 `json:"contextLength,omitempty"`
	// FileType is general.file_type; FileTypeName names it when it is a known llama.cpp value.
	FileType     *int64 `json:"fileType,omitempty"`
	FileTypeName string `json:"fileTypeName,omitempty"`
	// QuantizationVersion is general.quantization_version.
	QuantizationVersion *uint64 `json:"quantizationVersion,omitempty"`
	// Alignment is the tensor data alignment (general.alignment, default 32).
	Alignment uint64 `json:"alignment"`
	// TokenizerModel is tokenizer.ggml.model; License, Author and SizeLabel come from general.*.
	TokenizerModel string `json:"tokenizerModel,omitempty"`
	License        string `json:"license,omitempty"`
	Author         string `json:"author,omitempty"`
	SizeLabel      string `json:"sizeLabel,omitempty"`
	// ParameterCount is the sum of the element counts of all tensors; 0 when the
	// tensor descriptions could not be read completely.
	ParameterCount uint64 `json:"parameterCount"`
	// TensorTypes counts tensors per ggml type name ("F32", "Q4_K", ...).
	TensorTypes map[string]int `json:"tensorTypes"`
	// Tensors samples the first tensors; TensorsTruncated says more exist.
	Tensors          []Tensor `json:"tensors"`
	TensorsTruncated bool     `json:"tensorsTruncated"`
	// Metadata holds scalar and short string values; arrays appear as "array<type>[length]".
	Metadata          map[string]any `json:"metadata"`
	MetadataTruncated bool           `json:"metadataTruncated"`
	// HeaderSize is the number of bytes up to the end of the tensor descriptions
	// and DataOffset the aligned offset where tensor data starts.
	HeaderSize int64 `json:"headerSize"`
	DataOffset int64 `json:"dataOffset"`
}

// Tensor describes one tensor.
type Tensor struct {
	Name string   `json:"name"`
	Dims []uint64 `json:"dims"`
	Type string   `json:"type"`
}

// Limits of what is recorded.
const (
	magic            = "GGUF"
	maxVersion       = 3
	defaultAlignment = 32
	maxAlignment     = 1 << 30
	maxKeptString    = 256
	maxDims          = 8
	maxSampledTensor = 64
	pollEvery        = 512
	maxArrayDepth    = 4
)

// GGUF metadata value types.
const (
	tUint8 = iota
	tInt8
	tUint16
	tInt16
	tUint32
	tInt32
	tFloat32
	tBool
	tString
	tArray
	tUint64
	tInt64
	tFloat64
)

var valueTypeNames = [...]string{
	"uint8", "int8", "uint16", "int16", "uint32", "int32", "float32", "bool", "string", "array",
	"uint64", "int64", "float64",
}

// scalarSizes holds the byte size of fixed-size value types (0 for string and array).
var scalarSizes = [...]uint64{1, 1, 2, 2, 4, 4, 4, 1, 0, 0, 8, 8, 8}

// tensorTypeNames maps ggml tensor type ids to names.
var tensorTypeNames = map[uint32]string{
	0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1", 8: "Q8_0", 9: "Q8_1",
	10: "Q2_K", 11: "Q3_K", 12: "Q4_K", 13: "Q5_K", 14: "Q6_K", 15: "Q8_K", 16: "IQ2_XXS",
	17: "IQ2_XS", 18: "IQ3_XXS", 19: "IQ1_S", 20: "IQ4_NL", 21: "IQ3_S", 22: "IQ2_S", 23: "IQ4_XS",
	24: "I8", 25: "I16", 26: "I32", 27: "I64", 28: "F64", 29: "IQ1_M", 30: "BF16",
}

// fileTypeNames maps llama.cpp general.file_type values to names (the values
// this package is sure about; others are reported by number only).
var fileTypeNames = map[int64]string{
	0: "ALL_F32", 1: "MOSTLY_F16", 2: "MOSTLY_Q4_0", 3: "MOSTLY_Q4_1", 7: "MOSTLY_Q8_0",
	8: "MOSTLY_Q5_0", 9: "MOSTLY_Q5_1", 10: "MOSTLY_Q2_K", 11: "MOSTLY_Q3_K_S", 12: "MOSTLY_Q3_K_M",
	13: "MOSTLY_Q3_K_L", 14: "MOSTLY_Q4_K_S", 15: "MOSTLY_Q4_K_M", 16: "MOSTLY_Q5_K_S",
	17: "MOSTLY_Q5_K_M", 18: "MOSTLY_Q6_K", 32: "MOSTLY_BF16",
}

// Parse reads the GGUF header of the size bytes in r. It returns an error only
// when the magic or version are unusable; truncated or corrupt metadata yields a
// partial result and Notes.
func Parse(ctx context.Context, r io.ReaderAt, size int64, lim limits.Limits) (*Result, error) {
	lim = lim.Normalize()
	rd := &reader{
		ctx:  ctx,
		br:   bufio.NewReaderSize(io.NewSectionReader(r, 0, size), 64<<10),
		size: size,
	}
	head := rd.fixed(4)
	if head == nil || string(head) != magic {
		return nil, errors.New("not a GGUF file: missing GGUF magic")
	}
	version := rd.u32()
	switch {
	case rd.err != nil:
		return nil, errors.New("not a GGUF file: truncated before the version field")
	case version == 0:
		return nil, errors.New("unsupported GGUF file: version 0")
	case version > maxVersion && bits.ReverseBytes32(version) <= maxVersion:
		return nil, fmt.Errorf("unsupported GGUF file: version field %#x looks big-endian, which is not supported", version)
	case version > maxVersion:
		return nil, fmt.Errorf("unsupported GGUF version %d (this build reads versions 1 to %d)", version, maxVersion)
	}
	rd.version = version

	p := &parser{rd: rd, lim: lim, res: &Result{}, ctxLens: map[string]uint64{}}
	p.res.Details = Details{
		Version:     version,
		Alignment:   defaultAlignment,
		TensorTypes: map[string]int{},
		Tensors:     []Tensor{},
		Metadata:    map[string]any{},
	}
	d := &p.res.Details
	d.TensorCount = rd.count()
	d.KVCount = rd.count()
	if rd.err != nil {
		p.note("file ends inside the header counts")
		return p.res, nil
	}
	p.readMetadata()
	if rd.err == nil {
		p.readTensors()
	}
	if rd.err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return p.finish(), ctxErr
		}
		if !errors.Is(rd.err, errStop) {
			p.note("stopped early: " + describe(rd.err))
		}
	}
	return p.finish(), nil
}

func describe(err error) string {
	if errors.Is(err, binio.ErrTruncated) {
		return "the file ends before the header does (truncated file?)"
	}
	return err.Error()
}

// parser carries the state of one Parse call.
type parser struct {
	rd      *reader
	lim     limits.Limits
	res     *Result
	ctxLens map[string]uint64

	tensorsRead  uint64
	paramsTotal  uint64
	maxTensorOff uint64
	// lastBytes is the data size of the tensor with the highest offset, when it
	// can be computed from its type and dimensions.
	lastBytes uint64
	lastKnown bool
	notes     int
}

// maxNotes caps the number of notes so a corrupt file cannot flood a report.
const maxNotes = 20

func (p *parser) note(s string) {
	if p.notes < maxNotes {
		p.res.Notes = append(p.res.Notes, s)
	}
	p.notes++
}

func (p *parser) readMetadata() {
	rd, d := p.rd, &p.res.Details
	for i := uint64(0); i < d.KVCount; i++ {
		if !rd.tick() {
			return
		}
		key, _ := rd.str()
		typ := rd.u32()
		if rd.err != nil {
			return
		}
		if typ >= uint32(len(valueTypeNames)) {
			rd.fail(fmt.Errorf("metadata key %q has unknown value type %d", key, typ))
			return
		}
		v := rd.value(typ, 0)
		if rd.err != nil {
			return
		}
		p.record(key, v)
	}
}

// record files one metadata pair: special keys feed Details fields, everything
// goes into the capped metadata map.
func (p *parser) record(key string, v any) {
	d := &p.res.Details
	str, isStr := v.(string)
	n, isNum := asUint(v)
	switch key {
	case "general.architecture":
		if isStr {
			d.Architecture = str
		}
	case "general.name":
		if isStr {
			d.Name = str
		}
	case "general.file_type":
		if i, ok := asInt(v); ok {
			d.FileType = &i
			d.FileTypeName = fileTypeNames[i]
		}
	case "general.quantization_version":
		if isNum {
			d.QuantizationVersion = &n
		}
	case "general.alignment":
		switch {
		case isNum && n != 0 && n&(n-1) == 0 && n <= maxAlignment:
			d.Alignment = n
		case isNum:
			p.note("general.alignment " + strconv.FormatUint(n, 10) + " is not a power of two up to 1 GiB; using " + strconv.Itoa(defaultAlignment))
		}
	case "tokenizer.ggml.model":
		if isStr {
			d.TokenizerModel = str
		}
	case "general.license":
		if isStr {
			d.License = str
		}
	case "general.author":
		if isStr {
			d.Author = str
		}
	case "general.size_label":
		if isStr {
			d.SizeLabel = str
		}
	}
	if isNum && strings.HasSuffix(key, ".context_length") && len(p.ctxLens) < p.lim.MaxList {
		p.ctxLens[key] = n
	}
	if len(d.Metadata) < p.lim.MaxList {
		d.Metadata[key] = v
	} else {
		d.MetadataTruncated = true
	}
}

func (p *parser) readTensors() {
	rd, d := p.rd, &p.res.Details
	for i := uint64(0); i < d.TensorCount; i++ {
		if !rd.tick() {
			return
		}
		name, _ := rd.str()
		nd := rd.u32()
		if rd.err != nil {
			return
		}
		if nd > maxDims {
			p.note(fmt.Sprintf("tensor %q declares %d dimensions (at most %d are supported); tensor list stopped", name, nd, maxDims))
			rd.fail(errStop)
			return
		}
		dims := make([]uint64, nd)
		elems := uint64(1)
		for k := range dims {
			dims[k] = rd.count()
			elems = satMul(elems, dims[k])
		}
		typ := rd.u32()
		off := rd.u64()
		if rd.err != nil {
			return
		}
		typeName, ok := tensorTypeNames[typ]
		if !ok {
			typeName = "type" + strconv.FormatUint(uint64(typ), 10)
		}
		d.TensorTypes[typeName]++
		p.paramsTotal = satAdd(p.paramsTotal, elems)
		if off >= p.maxTensorOff {
			p.maxTensorOff = off
			p.lastBytes, p.lastKnown = tensorBytes(typ, dims)
		}
		p.tensorsRead++
		if len(d.Tensors) < min(maxSampledTensor, p.lim.MaxList) {
			d.Tensors = append(d.Tensors, Tensor{Name: name, Dims: dims, Type: typeName})
		}
	}
}

// errStop ends parsing early without an additional note (the cause was noted).
var errStop = errors.New("stop")

// finish derives the summary fields and the consistency notes.
func (p *parser) finish() *Result {
	d := &p.res.Details
	d.TensorsTruncated = uint64(len(d.Tensors)) < d.TensorCount
	d.ContextLength = p.ctxLens[d.Architecture+".context_length"]
	if p.tensorsRead == d.TensorCount {
		d.ParameterCount = p.paramsTotal
	} else if p.tensorsRead > 0 {
		p.note(fmt.Sprintf("read %d of %d tensor descriptions; the parameter count is unknown", p.tensorsRead, d.TensorCount))
	}
	if p.rd.err == nil {
		d.HeaderSize = p.rd.pos
		align := int64(d.Alignment)
		d.DataOffset = (d.HeaderSize + align - 1) / align * align
		switch dataLen := p.rd.size - d.DataOffset; {
		case d.TensorCount == 0:
		case dataLen < 0:
			p.note("the file ends before the tensor data starts (truncated file?)")
		case p.maxTensorOff >= uint64(dataLen):
			p.note("a tensor offset points past the end of the file (truncated file?)")
		case p.lastKnown && satAdd(p.maxTensorOff, p.lastBytes) > uint64(dataLen):
			p.note(fmt.Sprintf("tensor data is cut short by %d bytes (truncated file?)", satAdd(p.maxTensorOff, p.lastBytes)-uint64(dataLen)))
		}
	}
	if len(p.res.Notes) == 0 {
		p.res.Notes = nil
	}
	if p.notes > maxNotes {
		p.res.Notes = append(p.res.Notes, fmt.Sprintf("%d more notes omitted", p.notes-maxNotes))
	}
	return p.res
}

// blockSizes gives, for block-quantised ggml types, the elements per block and
// the bytes per block.
var blockSizes = map[uint32][2]uint64{
	2: {32, 18}, 3: {32, 20}, 6: {32, 22}, 7: {32, 24}, 8: {32, 34}, 9: {32, 36},
	10: {256, 84}, 11: {256, 110}, 12: {256, 144}, 13: {256, 176}, 14: {256, 210}, 15: {256, 292},
}

// elementSizes gives the bytes per element of plain ggml types.
var elementSizes = map[uint32]uint64{0: 4, 1: 2, 24: 1, 25: 2, 26: 4, 27: 8, 28: 8, 30: 2}

// tensorBytes returns the data size of a tensor when its type is one of the
// well-known fixed-size or block-quantised types and the dimensions fit.
func tensorBytes(typ uint32, dims []uint64) (uint64, bool) {
	if len(dims) == 0 {
		return 0, false
	}
	rows := uint64(1)
	for _, d := range dims[1:] {
		rows = satMul(rows, d)
	}
	if size, ok := elementSizes[typ]; ok {
		return satMul(satMul(dims[0], rows), size), true
	}
	if blk, ok := blockSizes[typ]; ok && dims[0]%blk[0] == 0 {
		return satMul(satMul(dims[0]/blk[0], blk[1]), rows), true
	}
	return 0, false
}

// asUint returns an unsigned or non-negative signed integer value.
func asUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		if x >= 0 {
			return uint64(x), true
		}
	}
	return 0, false
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x), true
		}
	}
	return 0, false
}

func satMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}

func satAdd(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return sum
}

// reader decodes the header sequentially with a sticky error. Every length is
// checked against the bytes that remain before anything is read or skipped.
type reader struct {
	ctx     context.Context
	br      *bufio.Reader
	pos     int64
	size    int64
	version uint32
	err     error
	scratch [8]byte
	ticks   int
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// tick counts one loop iteration and reports false once the context is done or
// an error is pending.
func (r *reader) tick() bool {
	if r.err != nil {
		return false
	}
	r.ticks++
	if r.ticks%pollEvery == 0 {
		if err := r.ctx.Err(); err != nil {
			r.fail(err)
			return false
		}
	}
	return true
}

func (r *reader) remaining() uint64 { return uint64(r.size - r.pos) }

// fixed reads n (at most 8) bytes into the scratch buffer.
func (r *reader) fixed(n int) []byte {
	if r.err != nil {
		return nil
	}
	if uint64(n) > r.remaining() {
		r.fail(binio.ErrTruncated)
		return nil
	}
	if _, err := io.ReadFull(r.br, r.scratch[:n]); err != nil {
		r.fail(binio.ErrTruncated)
		return nil
	}
	r.pos += int64(n)
	return r.scratch[:n]
}

func (r *reader) u8() uint8 {
	if b := r.fixed(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.fixed(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.fixed(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

// count reads a count or length: 32-bit in version 1, 64-bit afterwards.
func (r *reader) count() uint64 {
	if r.version == 1 {
		return uint64(r.u32())
	}
	return r.u64()
}

// skip discards n bytes after checking that they exist.
func (r *reader) skip(n uint64) {
	if r.err != nil {
		return
	}
	if n > r.remaining() {
		r.fail(binio.ErrTruncated)
		return
	}
	for n > 0 {
		step := int(min(n, 1<<30))
		got, err := r.br.Discard(step)
		r.pos += int64(got)
		n -= uint64(got)
		if err != nil {
			r.fail(binio.ErrTruncated)
			return
		}
	}
}

// str reads a length-prefixed string, keeping at most maxKeptString bytes. The
// returned flag tells whether the string was longer.
func (r *reader) str() (string, bool) {
	n := r.count()
	if r.err != nil {
		return "", false
	}
	if n > r.remaining() {
		r.fail(binio.ErrTruncated)
		return "", false
	}
	keep := min(n, maxKeptString)
	buf := make([]byte, keep)
	if _, err := io.ReadFull(r.br, buf); err != nil {
		r.fail(binio.ErrTruncated)
		return "", false
	}
	r.pos += int64(keep)
	r.skip(n - keep)
	s := binio.Printable(strings.ToValidUTF8(string(buf), "?"), 0)
	if n > keep {
		s += "…"
	}
	return s, n > keep
}

// value reads one metadata value. Scalars and strings are returned as uint64,
// int64, float64 (finite) or string, bool; arrays are skipped and summarised.
func (r *reader) value(typ uint32, depth int) any {
	switch typ {
	case tUint8:
		return uint64(r.u8())
	case tInt8:
		return int64(int8(r.u8()))
	case tUint16:
		if b := r.fixed(2); b != nil {
			return uint64(binary.LittleEndian.Uint16(b))
		}
	case tInt16:
		if b := r.fixed(2); b != nil {
			return int64(int16(binary.LittleEndian.Uint16(b)))
		}
	case tUint32:
		return uint64(r.u32())
	case tInt32:
		return int64(int32(r.u32()))
	case tFloat32:
		return finite(float64(math.Float32frombits(r.u32())))
	case tBool:
		return r.u8() != 0
	case tString:
		s, _ := r.str()
		return s
	case tUint64:
		return r.u64()
	case tInt64:
		return int64(r.u64())
	case tFloat64:
		return finite(math.Float64frombits(r.u64()))
	case tArray:
		return r.array(depth)
	}
	return nil
}

// finite keeps JSON encodable: NaN and infinities become strings.
func finite(f float64) any {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return f
}

// array skips an array value and returns its "array<type>[length]" summary.
func (r *reader) array(depth int) string {
	elem := r.u32()
	n := r.count()
	if r.err != nil {
		return ""
	}
	if elem >= uint32(len(valueTypeNames)) {
		r.fail(fmt.Errorf("array has unknown element type %d", elem))
		return ""
	}
	if depth >= maxArrayDepth {
		r.fail(errors.New("arrays are nested too deeply"))
		return ""
	}
	switch size := scalarSizes[elem]; {
	case size > 0:
		if n > r.remaining()/size {
			r.fail(binio.ErrTruncated)
			return ""
		}
		r.skip(n * size)
	case elem == tString:
		for i := uint64(0); i < n && r.tick(); i++ {
			ln := r.count()
			r.skip(ln)
		}
	default:
		for i := uint64(0); i < n && r.tick(); i++ {
			r.array(depth + 1)
		}
	}
	return "array<" + valueTypeNames[elem] + ">[" + strconv.FormatUint(n, 10) + "]"
}
