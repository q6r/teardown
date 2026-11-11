package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Error codes carried in the JSON error envelope. They are part of the API
// contract documented in openapi.json and docs/api/http.md.
const (
	codeBadMultipart     = "bad_multipart"
	codeMissingFile      = "missing_file"
	codeUnexpectedPart   = "unexpected_part"
	codeInvalidParameter = "invalid_parameter"
	codeForbiddenHost    = "forbidden_host"
	codeForbiddenOrigin  = "forbidden_origin"
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeTooLarge         = "too_large"
	codeUnsupportedMedia = "unsupported_media_type"
	codeInternal         = "internal_error"
	codeAnalysisFailed   = "analysis_failed"
	codeBusy             = "busy"
	codeAnalysisTimeout  = "analysis_timeout"
)

// writeTimeout bounds how long a single response may take to reach the client.
const writeTimeout = 60 * time.Second

// errorEnvelope is the body of every non-2xx JSON response.
type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// apiError is an error that knows how it must be reported over HTTP.
type apiError struct {
	status  int
	code    string
	message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

// errClientGone marks a request whose client disconnected; nothing is written.
var errClientGone = errors.New("client disconnected")

// writeError sends the JSON error envelope.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorEnvelope{Error: errorDetail{Code: code, Message: message}})
}

// writeAPIError sends an apiError.
func writeAPIError(w http.ResponseWriter, e *apiError) {
	writeError(w, e.status, e.code, e.message)
}

// writeJSON encodes v completely before touching the response so an encoding
// failure can still produce a clean 500.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":{"code":"` + codeInternal + `","message":"the response could not be encoded"}}`)
	}
	extendWriteDeadline(w, writeTimeout)
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// extendWriteDeadline pushes the connection's write deadline d into the future.
// It is best effort: recorders and test writers do not support deadlines.
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
}
