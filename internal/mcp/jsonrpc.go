package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"sync"
)

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// maxLine is the longest accepted input line (one JSON-RPC message), in bytes.
const maxLine = 8 << 20

// rpcError is the error member of a JSON-RPC response.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// response is a JSON-RPC response. A nil ID encodes as null.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func okResponse(id json.RawMessage, result any) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func errResponse(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// message is one parsed inbound JSON-RPC message.
type message struct {
	ID     json.RawMessage // nil for notifications
	Method string
	Params json.RawMessage
}

// isRequest reports whether the message expects a response.
func (m *message) isRequest() bool { return m.ID != nil }

// rawMessage mirrors the wire form so presence of members can be told apart.
type rawMessage struct {
	JSONRPC *string         `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// parseMessage validates one JSON-RPC message. It returns either the message,
// or an error response to send, or neither (a response from the client, which a
// server that issues no requests of its own ignores).
func parseMessage(raw []byte) (*message, *response) {
	if !json.Valid(raw) {
		return nil, errResponse(nil, codeParseError, "parse error: the line is not valid JSON")
	}
	var rm rawMessage
	if err := json.Unmarshal(raw, &rm); err != nil {
		return nil, errResponse(bestEffortID(raw), codeInvalidRequest, "invalid request: a JSON-RPC message must be an object with string \"jsonrpc\", \"method\", object \"params\" and a string or number \"id\"")
	}
	if rm.JSONRPC == nil || *rm.JSONRPC != "2.0" {
		return nil, errResponse(validID(rm.ID), codeInvalidRequest, "invalid request: \"jsonrpc\" must be \"2.0\"")
	}
	if rm.Method == nil {
		if rm.Result != nil || rm.Error != nil {
			return nil, nil
		}
		return nil, errResponse(validID(rm.ID), codeInvalidRequest, "invalid request: missing \"method\"")
	}
	if *rm.Method == "" {
		return nil, errResponse(validID(rm.ID), codeInvalidRequest, "invalid request: \"method\" is empty")
	}
	if rm.ID != nil && validID(rm.ID) == nil {
		return nil, errResponse(nil, codeInvalidRequest, "invalid request: \"id\" must be a string or a number")
	}
	return &message{ID: rm.ID, Method: *rm.Method, Params: rm.Params}, nil
}

// splitBatch splits a JSON array into its elements.
func splitBatch(line []byte) ([]json.RawMessage, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(line, &elems); err != nil {
		return nil, err
	}
	return elems, nil
}

// validID returns id when it is a JSON string or number, otherwise nil.
func validID(id json.RawMessage) json.RawMessage {
	id = bytes.TrimSpace(id)
	if len(id) == 0 {
		return nil
	}
	if id[0] == '"' || id[0] == '-' || (id[0] >= '0' && id[0] <= '9') {
		return id
	}
	return nil
}

// bestEffortID recovers the id of a message that failed structural decoding so
// the error response can still be correlated by the client.
func bestEffortID(raw []byte) json.RawMessage {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return nil
	}
	return validID(probe.ID)
}

// normID turns a request id into a map key: "s<text>" for strings, "n<integer>"
// for integral numbers and "n<literal>" otherwise.
func normID(id json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(id))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return "s" + t
	case json.Number:
		if f, err := t.Float64(); err == nil && f == math.Trunc(f) && math.Abs(f) < 1e15 {
			return "n" + strconv.FormatInt(int64(f), 10)
		}
		return "n" + t.String()
	}
	return ""
}

// lineEvent is one unit read from the input stream.
type lineEvent struct {
	line    []byte
	tooLong bool  // the line exceeded maxLine and was discarded
	err     error // a non-EOF read error; the stream is finished
}

// readLines reads newline-delimited messages until EOF, sending them on out.
// Lines longer than limit are dropped without being buffered and reported once
// as tooLong. It returns when the input ends or done is closed.
func readLines(br *bufio.Reader, limit int, out chan<- lineEvent, done <-chan struct{}) {
	defer close(out)
	send := func(ev lineEvent) bool {
		select {
		case out <- ev:
			return true
		case <-done:
			return false
		}
	}
	for {
		line, tooLong, err := readLine(br, limit)
		if len(line) > 0 || tooLong {
			if !send(lineEvent{line: line, tooLong: tooLong}) {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				send(lineEvent{err: err})
			}
			return
		}
	}
}

// readLine reads one line without the line terminator. At most limit bytes are
// kept; the remainder of an over-long line is consumed and discarded.
func readLine(br *bufio.Reader, limit int) (line []byte, tooLong bool, err error) {
	for {
		frag, e := br.ReadSlice('\n')
		complete := e == nil
		if complete {
			frag = frag[:len(frag)-1]
		}
		if !tooLong {
			if len(line)+len(frag) > limit {
				tooLong, line = true, nil
			} else {
				line = append(line, frag...)
			}
		}
		switch {
		case complete:
			return bytes.TrimSuffix(line, []byte{'\r'}), tooLong, nil
		case errors.Is(e, bufio.ErrBufferFull):
			continue
		default:
			return bytes.TrimSuffix(line, []byte{'\r'}), tooLong, e
		}
	}
}

// lineWriter serialises responses as one JSON document per line. Writes are
// atomic with respect to each other so concurrent tool calls never interleave.
type lineWriter struct {
	mu     sync.Mutex
	w      io.Writer
	err    error
	onFail func(error)
}

// send marshals v and writes it followed by a newline. The first write error is
// remembered, reported through onFail and returned by every later call.
func (lw *lineWriter) send(v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		if r, ok := v.(*response); ok {
			buf.Reset()
			if enc.Encode(errResponse(r.ID, codeInternalError, "internal error: the result could not be encoded")) != nil {
				return err
			}
		} else {
			return err
		}
	}
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.err != nil {
		return lw.err
	}
	if _, err := lw.w.Write(buf.Bytes()); err != nil {
		lw.err = err
		if lw.onFail != nil {
			lw.onFail(err)
		}
		return err
	}
	return nil
}

// failed returns the first write error.
func (lw *lineWriter) failed() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.err
}
