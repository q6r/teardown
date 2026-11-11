package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/q6r/teardown/internal/binio"
	"github.com/q6r/teardown/internal/version"
)

// instructions is shown to the model by clients that surface server instructions.
const instructions = "teardown is a static triage tool for binaries and app packages (PE, ELF, Mach-O, .NET, Go, APK/AAB/JAR, Electron ASAR, " +
	"ZIP-family archives, WebAssembly, GGUF/safetensors, SQLite and more). It never executes the files it analyses. " +
	"Start with analyze_file (type, hashes, entropy, sections, imports, hardening, findings with evidence and limitations, 0-100 triage risk). " +
	"Use list_strings to page through extracted strings (secrets are redacted), hash_file for digests only, entropy_profile to look for packed regions, " +
	"and diff_files to compare two builds. Paths must lie inside the directories the server was started with (--root); relative paths resolve against them. " +
	"Findings and the risk score are triage hints, not verdicts: read each finding's limitations."

// errCallTimeout is the cancellation cause of a call that ran out of time.
var errCallTimeout = errors.New("tool call timed out")

// errPanic marks a tool that panicked.
var errPanic = errors.New("tool panicked")

// call is a registered, cancellable tools/call request.
type call struct {
	key    string
	ctx    context.Context
	cancel context.CancelCauseFunc
}

// prepared is a parsed message ready to execute.
type prepared struct {
	msg  *message
	resp *response // a ready-made response (invalid message, rejected call)
	call *call     // set for tools/call requests, registered before execution
}

// prepare parses one message and registers tools/call requests so that a
// cancellation arriving on the very next line can find them.
func (s *server) prepare(ctx context.Context, raw []byte) *prepared {
	msg, errResp := parseMessage(raw)
	if msg == nil {
		return &prepared{resp: errResp}
	}
	it := &prepared{msg: msg}
	if msg.Method == "tools/call" && msg.isRequest() {
		c, resp := s.beginCall(ctx, msg.ID)
		if resp != nil {
			it.resp = resp
			return it
		}
		it.call = c
	}
	return it
}

// execute handles a prepared message and returns the response to send, or nil.
func (s *server) execute(ctx context.Context, it *prepared) (resp *response) {
	if it.resp != nil {
		return it.resp
	}
	m := it.msg
	if m == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic while handling a request", "method", m.Method, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			if it.call != nil {
				s.finish(it.call)
			}
			resp = nil
			if m.isRequest() {
				resp = errResponse(m.ID, codeInternalError, "internal error")
			}
		}
	}()
	switch m.Method {
	case "initialize":
		if m.isRequest() {
			return s.initialize(m)
		}
	case "ping":
		if m.isRequest() {
			return okResponse(m.ID, struct{}{})
		}
	case "tools/list":
		if m.isRequest() {
			return okResponse(m.ID, s.toolsList())
		}
	case "tools/call":
		if m.isRequest() {
			return s.callTool(it)
		}
	case "notifications/cancelled":
		s.onCancelled(m)
	default:
		if m.isRequest() {
			return errResponse(m.ID, codeMethodNotFound, "method not found: "+binio.Printable(m.Method, 80))
		}
	}
	return nil
}

// decodeParams decodes params, which must be a JSON object, into dst.
func decodeParams(raw json.RawMessage, dst any) *rpcError {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return &rpcError{Code: codeInvalidParams, Message: "invalid params: expected a JSON object"}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return &rpcError{Code: codeInvalidParams, Message: "invalid params: " + binio.Printable(err.Error(), 200)}
	}
	return nil
}

// initializeResult is the result of the initialize request.
type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions"`
}

type capabilities struct {
	Tools toolsCapability `json:"tools"`
}

type toolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

func (s *server) initialize(m *message) *response {
	var p struct {
		ProtocolVersion *string `json:"protocolVersion"`
		ClientInfo      *struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	if rerr := decodeParams(m.Params, &p); rerr != nil {
		rerr.Message = "invalid params for initialize: expected {protocolVersion, capabilities, clientInfo}"
		return &response{JSONRPC: "2.0", ID: m.ID, Error: rerr}
	}
	if p.ProtocolVersion == nil || *p.ProtocolVersion == "" {
		return errResponse(m.ID, codeInvalidParams, "invalid params for initialize: missing protocolVersion")
	}
	negotiated := protocolLatest
	if supportedProtocol(*p.ProtocolVersion) {
		negotiated = *p.ProtocolVersion
	}
	s.setProtocol(negotiated)
	client := ""
	if p.ClientInfo != nil {
		client = binio.Printable(p.ClientInfo.Name+" "+p.ClientInfo.Version, 100)
	}
	s.log.Info("initialize", "client", client, "requested", binio.Printable(*p.ProtocolVersion, 40), "negotiated", negotiated)
	info := serverInfo{Name: "teardown", Version: version.String()}
	if negotiated >= titlesSince {
		info.Title = "teardown static triage"
	}
	return okResponse(m.ID, initializeResult{
		ProtocolVersion: negotiated,
		Capabilities:    capabilities{Tools: toolsCapability{ListChanged: false}},
		ServerInfo:      info,
		Instructions:    instructions,
	})
}

func (s *server) setProtocol(v string) {
	s.mu.Lock()
	s.protocol = v
	s.mu.Unlock()
}

func (s *server) negotiated() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.protocol
}

func (s *server) toolsList() any {
	protocol := s.negotiated()
	descs := make([]toolDescriptor, len(s.tools))
	for i, t := range s.tools {
		descs[i] = t.descriptor(protocol)
	}
	return struct {
		Tools []toolDescriptor `json:"tools"`
	}{descs}
}

// content is one block of tool output.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the result of tools/call.
type toolResult struct {
	Content           []content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError"`
}

func textError(msg string) *toolResult {
	return &toolResult{Content: []content{{Type: "text", Text: msg}}, IsError: true}
}

// callTool handles tools/call.
func (s *server) callTool(it *prepared) *response {
	m, c := it.msg, it.call
	defer s.finish(c)
	var p struct {
		Name      *string         `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if rerr := decodeParams(m.Params, &p); rerr != nil {
		return &response{JSONRPC: "2.0", ID: m.ID, Error: rerr}
	}
	if p.Name == nil || *p.Name == "" {
		return errResponse(m.ID, codeInvalidParams, "invalid params: missing tool name")
	}
	var t *tool
	for _, cand := range s.tools {
		if cand.name == *p.Name {
			t = cand
			break
		}
	}
	if t == nil {
		return errResponse(m.ID, codeInvalidParams, "unknown tool: "+binio.Printable(*p.Name, 80))
	}
	if args := bytes.TrimSpace(p.Arguments); len(args) > 0 && args[0] != '{' && !bytes.Equal(args, []byte("null")) {
		return errResponse(m.ID, codeInvalidParams, "invalid params: arguments must be an object")
	}
	res := s.runTool(c, t, p.Arguments)
	if res == nil {
		return nil
	}
	return okResponse(m.ID, res)
}

// runTool runs a tool under a concurrency slot and a deadline. It returns nil
// when the call was cancelled, in which case no response is sent.
func (s *server) runTool(c *call, t *tool, args json.RawMessage) *toolResult {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-c.ctx.Done():
		return nil
	}
	start := time.Now()
	ctx, cancel := context.WithTimeoutCause(c.ctx, s.cfg.Timeout, errCallTimeout)
	defer cancel()

	res, err := s.safeRun(ctx, t, args)
	if c.ctx.Err() != nil {
		return nil
	}
	if err != nil {
		res = s.failure(ctx, t, err)
	}
	s.log.Info("tool call", "tool", t.name, "ms", time.Since(start).Milliseconds(), "isError", res.IsError)
	return res
}

// safeRun runs the tool and renders its output, converting a panic into an error.
func (s *server) safeRun(ctx context.Context, t *tool, args json.RawMessage) (res *toolResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in a tool", "tool", t.name, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			res, err = nil, errPanic
		}
	}()
	out, err := t.run(s, ctx, args)
	if err != nil {
		return nil, err
	}
	text, compact, _, err := fit(out.tree, out.spec, s.cfg.MaxOutput)
	if err != nil {
		return nil, err
	}
	res = &toolResult{Content: []content{{Type: "text", Text: text}}}
	if s.negotiated() >= structuredSince {
		res.StructuredContent = compact
	}
	return res, nil
}

// failure converts an error from a tool into an isError result whose message
// helps the caller fix the problem.
func (s *server) failure(ctx context.Context, t *tool, err error) *toolResult {
	var ue *userError
	switch {
	case errors.As(err, &ue):
		return textError(ue.msg)
	case errors.Is(err, errTooLarge):
		return textError(fmt.Sprintf("the %s result does not fit the server's %d-byte output limit even after trimming; raise the server's output limit or use a narrower tool (list_strings pages through strings, hash_file returns digests only)", t.name, s.cfg.MaxOutput))
	case errors.Is(err, errPanic):
		return textError("internal error while running " + t.name + "; the failure was logged by the server")
	case errors.Is(context.Cause(ctx), errCallTimeout) || errors.Is(err, context.DeadlineExceeded):
		return textError(fmt.Sprintf("the analysis did not finish within %s and was stopped; the file may be very large or malformed", s.cfg.Timeout))
	default:
		return textError("analysis failed: " + binio.Printable(err.Error(), 400))
	}
}

// beginCall registers a tools/call request so it can be cancelled.
func (s *server) beginCall(parent context.Context, id json.RawMessage) (*call, *response) {
	key := normID(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.calls[key]; dup {
		return nil, errResponse(id, codeInvalidRequest, "invalid request: a request with this id is already in progress")
	}
	if len(s.calls) >= maxInFlight {
		return nil, okResponse(id, textError("the server is busy: too many requests are in progress; retry shortly"))
	}
	ctx, cancel := context.WithCancelCause(parent)
	c := &call{key: key, ctx: ctx, cancel: cancel}
	s.calls[key] = c
	return c, nil
}

// finish unregisters a call and releases its context. It is idempotent.
func (s *server) finish(c *call) {
	s.mu.Lock()
	if s.calls[c.key] == c {
		delete(s.calls, c.key)
	}
	s.mu.Unlock()
	c.cancel(nil)
}

// cancelAll cancels every registered call (used at shutdown).
func (s *server) cancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		c.cancel(context.Canceled)
	}
}

// onCancelled handles notifications/cancelled: the matching call stops and, as
// the specification asks, sends no response.
func (s *server) onCancelled(m *message) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(m.Params, &p) != nil || validID(p.RequestID) == nil {
		return
	}
	s.mu.Lock()
	c := s.calls[normID(p.RequestID)]
	s.mu.Unlock()
	if c != nil {
		c.cancel(errClientCancelled)
	}
}
