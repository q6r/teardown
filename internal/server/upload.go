package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

const (
	// uploadIdleTimeout is how long an upload may stall before it is abandoned.
	uploadIdleTimeout = 30 * time.Second
	// uploadTotalTimeout bounds a whole upload however steadily it trickles in.
	uploadTotalTimeout = 15 * time.Minute
	// retryAfter is the Retry-After value (seconds) sent with 503 responses.
	retryAfter = "5"
	// removeAttempts and removePause retry deleting an upload: on Windows a
	// virus scanner can hold a freshly written file for a moment.
	removeAttempts = 5
	removePause    = 25 * time.Millisecond
)

// errBusy means every analysis slot stayed occupied for the whole queue wait.
var errBusy = errors.New("all analysis slots are busy")

type analyzeResponse struct {
	ID     string         `json:"id"`
	Report *report.Report `json:"report"`
}

// upload is a received file waiting in the private directory.
type upload struct {
	path string
	name string // sanitised display name
	size int64
}

// handleAnalyze implements POST /api/analyze: stream the single multipart "file"
// part into the private directory, analyse it, delete it, store the report.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	boundary, aerr := multipartBoundary(r)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	if r.ContentLength > s.cfg.MaxUpload+multipartOverhead {
		writeAPIError(w, s.tooLarge())
		return
	}

	// A slot is taken before the body is read so that at most Concurrency
	// uploads occupy the disk at any time.
	release, err := s.acquire(r.Context())
	switch {
	case errors.Is(err, errBusy):
		w.Header().Set("Retry-After", retryAfter)
		writeError(w, http.StatusServiceUnavailable, codeBusy, "all analysis slots are busy; retry shortly")
		return
	case err != nil:
		return // the client left while queued
	}
	defer release()

	up, err := s.receive(w, r, boundary)
	if err != nil {
		s.fail(w, err)
		return
	}
	id, err := s.store.reserve()
	if err != nil {
		s.removeFile(up.path)
		s.fail(w, err)
		return
	}

	s.hub.publish(eventStarted, startedEvent{ID: id, Name: up.name, Size: up.size})
	start := time.Now()
	rep, err := s.safeAnalyze(r.Context(), up.path, analyze.Options{Name: up.name, Timeout: s.cfg.AnalyzeTimeout})
	s.removeFile(up.path)
	release()
	elapsed := time.Since(start)

	if err != nil {
		s.hub.publish(eventFailed, failedEvent{ID: id, Name: up.name, Error: failureText(err)})
		switch {
		case r.Context().Err() != nil:
			s.log.Info("analysis abandoned: client disconnected", "id", id, "name", up.name)
		case errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusGatewayTimeout, codeAnalysisTimeout,
				fmt.Sprintf("the analysis exceeded the %s time limit", s.cfg.AnalyzeTimeout))
		default:
			s.log.Error("analysis failed", "id", id, "name", up.name, "error", err)
			writeError(w, http.StatusInternalServerError, codeAnalysisFailed, "the analysis failed; see the server log for details")
		}
		return
	}

	rec := &record{id: id, report: rep, createdAt: s.now().UTC().Truncate(time.Millisecond)}
	s.store.add(rec)
	s.log.Info("analysis completed",
		"id", id, "name", up.name, "size", up.size, "type", rep.Type.ID, "risk", rep.Risk.Score, "ms", elapsed.Milliseconds())
	s.hub.publish(eventCompleted, completedEvent{summary: rec.summary(), DurationMs: elapsed.Milliseconds()})

	w.Header().Set("Location", "/api/analyses/"+id)
	writeJSON(w, http.StatusCreated, analyzeResponse{ID: id, Report: rep})
}

// multipartBoundary validates the request's Content-Type and returns its boundary.
func multipartBoundary(r *http.Request) (string, *apiError) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		return "", &apiError{
			status:  http.StatusUnsupportedMediaType,
			code:    codeUnsupportedMedia,
			message: `send the file as multipart/form-data in a field named "file", for example: curl -F file=@sample.bin http://127.0.0.1:7777/api/analyze`,
		}
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", &apiError{status: http.StatusBadRequest, code: codeBadMultipart, message: "the multipart Content-Type has no boundary parameter"}
	}
	return boundary, nil
}

// acquire takes an analysis slot, waiting for at most s.queueWait. The returned
// release function is idempotent.
func (s *Server) acquire(ctx context.Context) (release func(), err error) {
	var once sync.Once
	release = func() { once.Do(func() { <-s.sem }) }
	select {
	case s.sem <- struct{}{}:
		return release, nil
	default:
	}
	if int(s.waiting.Add(1)) > s.maxQueued {
		s.waiting.Add(-1)
		return nil, errBusy
	}
	defer s.waiting.Add(-1)
	timer := time.NewTimer(s.queueWait)
	defer timer.Stop()
	select {
	case s.sem <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errBusy
	}
}

// receive streams the multipart body's single "file" part into a new file in the
// private directory. On any failure the partial file is removed and the returned
// error is an *apiError (or errClientGone).
func (s *Server) receive(w http.ResponseWriter, r *http.Request, boundary string) (*upload, error) {
	body := &deadlineReader{
		r:     http.MaxBytesReader(baseWriter(w), r.Body, s.cfg.MaxUpload+multipartOverhead),
		rc:    http.NewResponseController(w),
		start: time.Now(),
		log:   s.log,
	}
	// The read deadline must be cleared before analysis starts: an expired
	// deadline would make net/http cancel the request context mid-analysis.
	defer body.finish()

	mr := multipart.NewReader(body, boundary)
	part, err := mr.NextPart()
	if err == io.EOF {
		return nil, &apiError{status: http.StatusBadRequest, code: codeMissingFile, message: `the multipart body is empty; send the file in a field named "file"`}
	}
	if err != nil {
		return nil, s.readFailure(r, err)
	}
	if part.FormName() != "file" {
		return nil, &apiError{status: http.StatusBadRequest, code: codeMissingFile, message: `the first multipart part must be a form field named "file"`}
	}
	name := sanitizeName(partFilename(part))

	f, err := os.CreateTemp(s.tempDir, "upload-*")
	if err != nil {
		s.log.Error("cannot create upload file", "error", err)
		return nil, errStore
	}
	path := f.Name()
	n, copyErr := io.Copy(f, io.LimitReader(part, s.cfg.MaxUpload+1))
	closeErr := f.Close()
	fail := func(err error) (*upload, error) {
		s.removeFile(path)
		return nil, err
	}
	var writeErr *fs.PathError
	switch {
	case errors.As(copyErr, &writeErr):
		s.log.Error("cannot write upload file", "error", copyErr)
		return fail(errStore)
	case copyErr != nil:
		return fail(s.readFailure(r, copyErr))
	case n > s.cfg.MaxUpload:
		return fail(s.tooLarge())
	case closeErr != nil:
		s.log.Error("cannot finish upload file", "error", closeErr)
		return fail(errStore)
	}

	// Exactly one part is accepted; anything after it must be the closing boundary.
	switch _, err := mr.NextPart(); {
	case err == nil:
		return fail(&apiError{status: http.StatusBadRequest, code: codeUnexpectedPart, message: `the request must contain exactly one part, named "file"`})
	case err != io.EOF:
		return fail(s.readFailure(r, err))
	}
	return &upload{path: path, name: name, size: n}, nil
}

// errStore reports that the server could not keep the upload on disk.
var errStore = &apiError{status: http.StatusInternalServerError, code: codeInternal, message: "the upload could not be stored on the server; see its log"}

// readFailure classifies an error met while reading the request body.
func (s *Server) readFailure(r *http.Request, err error) error {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		return s.tooLarge()
	case r.Context().Err() != nil:
		return errClientGone
	default:
		return &apiError{
			status:  http.StatusBadRequest,
			code:    codeBadMultipart,
			message: "the request body is not valid multipart/form-data or was cut off: " + clip(err.Error(), 120),
		}
	}
}

func (s *Server) tooLarge() *apiError {
	return &apiError{
		status:  http.StatusRequestEntityTooLarge,
		code:    codeTooLarge,
		message: "the upload exceeds the limit of " + formatBytes(s.cfg.MaxUpload) + "; start the server with a larger --max-upload to analyse bigger files",
	}
}

// fail answers a request that failed before analysis started.
func (s *Server) fail(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		writeAPIError(w, ae)
	case errors.Is(err, errClientGone):
	default:
		s.log.Error("request failed", "error", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "the server hit an unexpected error; see its log")
	}
}

// safeAnalyze runs the analyzer and converts a panic into an error, so a parser
// bug can never take the server down or leak the upload.
func (s *Server) safeAnalyze(ctx context.Context, path string, opts analyze.Options) (rep *report.Report, err error) {
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("analyzer panic", "panic", fmt.Sprint(p))
			rep, err = nil, fmt.Errorf("analyzer panic: %v", p)
		}
	}()
	rep, err = s.cfg.Analyze(ctx, path, opts)
	if err == nil && rep == nil {
		err = errors.New("analyzer returned no report")
	}
	return rep, err
}

// failureText is the short, path-free reason published with analysis.failed.
func failureText(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "analysis timed out"
	case errors.Is(err, context.Canceled):
		return "analysis canceled"
	default:
		return "analysis failed"
	}
}

// removeFile deletes an upload, retrying briefly (see removeAttempts).
func (s *Server) removeFile(path string) {
	var err error
	for range removeAttempts {
		err = os.Remove(path)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return
		}
		time.Sleep(removePause)
	}
	s.log.Warn("could not delete an analysed upload", "error", err)
}

// deadlineReader pushes the connection's read deadline forward on every read, so
// an upload fails when it stalls (uploadIdleTimeout) or drags on for too long
// (uploadTotalTimeout) instead of pinning a slot forever.
type deadlineReader struct {
	r           io.Reader
	rc          *http.ResponseController
	start       time.Time
	log         *slog.Logger
	unsupported bool
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if !d.unsupported {
		deadline := time.Now().Add(uploadIdleTimeout)
		if limit := d.start.Add(uploadTotalTimeout); deadline.After(limit) {
			deadline = limit
		}
		if err := d.rc.SetReadDeadline(deadline); err != nil {
			d.unsupported = true
			if !errors.Is(err, http.ErrNotSupported) {
				d.log.Warn("cannot set the upload read deadline", "error", err)
			}
		}
	}
	return d.r.Read(p)
}

// finish clears the read deadline.
func (d *deadlineReader) finish() {
	if !d.unsupported {
		_ = d.rc.SetReadDeadline(time.Time{})
	}
}

// formatBytes renders a byte count in binary units ("256 MiB", "1.5 KiB").
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	if n%div == 0 {
		return fmt.Sprintf("%d %ciB", n/div, "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
