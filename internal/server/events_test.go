package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/q6r/teardown/internal/analyze"
	"github.com/q6r/teardown/internal/report"
)

// mustSubscribe subscribes or fails the test.
func mustSubscribe(t *testing.T, h *hub) *subscriber {
	t.Helper()
	sub, err := h.subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	return sub
}

func TestHubFanOutAndLifecycle(t *testing.T) {
	h := newHub(maxSubscribers)
	a, b := mustSubscribe(t, h), mustSubscribe(t, h)
	if h.count() != 2 {
		t.Fatalf("count = %d", h.count())
	}
	h.publish("demo", map[string]int{"n": 1})
	for _, sub := range []*subscriber{a, b} {
		select {
		case ev := <-sub.ch:
			if ev.name != "demo" || string(ev.data) != `{"n":1}` {
				t.Errorf("event = %q %s", ev.name, ev.data)
			}
		default:
			t.Error("a subscriber missed the event")
		}
	}

	h.unsubscribe(a)
	h.unsubscribe(a) // double unsubscribe must be harmless
	if h.count() != 1 {
		t.Errorf("count after unsubscribe = %d", h.count())
	}
	if _, ok := <-a.ch; ok {
		t.Error("an unsubscribed channel must be closed")
	}

	h.publish("unencodable", make(chan int)) // dropped silently, must not panic
	h.close()
	if _, err := h.subscribe(); h.count() != 0 || !errors.Is(err, errHubClosed) {
		t.Errorf("a closed hub has no subscribers and refuses new ones (err %v)", err)
	}
	h.publish("late", 1) // must not panic
	h.close()            // idempotent
}

func TestHubLimitsSubscribers(t *testing.T) {
	h := newHub(2)
	a := mustSubscribe(t, h)
	mustSubscribe(t, h)
	if _, err := h.subscribe(); !errors.Is(err, errHubFull) {
		t.Fatalf("third subscriber: err = %v, want errHubFull", err)
	}
	h.unsubscribe(a) // a freed slot can be taken again
	if _, err := h.subscribe(); err != nil {
		t.Fatalf("after unsubscribe: %v", err)
	}
}

func TestHubDropsSlowSubscribersOnly(t *testing.T) {
	h := newHub(maxSubscribers)
	slow, fast := mustSubscribe(t, h), mustSubscribe(t, h)
	delivered := 0
	for i := range subscriberBuffer + 5 {
		h.publish("tick", i)
		select { // the fast consumer keeps up
		case <-fast.ch:
			delivered++
		default:
		}
	}
	if delivered != subscriberBuffer+5 {
		t.Fatalf("the fast subscriber got %d events, want %d", delivered, subscriberBuffer+5)
	}
	if h.count() != 1 {
		t.Fatalf("subscribers = %d, want only the fast one left", h.count())
	}
	buffered := 0
	for range slow.ch { // closed after the drop: drains what was buffered, then ends
		buffered++
	}
	if buffered != subscriberBuffer {
		t.Errorf("the dropped subscriber had %d buffered events, want %d", buffered, subscriberBuffer)
	}
}

// sseClient reads server-sent events from a real HTTP connection.
type sseClient struct {
	resp   *http.Response
	lines  chan string
	cancel context.CancelFunc
}

// connectSSE opens GET /api/events on ts and registers cleanup that closes it.
func connectSSE(t *testing.T, ts *httptest.Server) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{resp: resp, lines: make(chan string, 256), cancel: cancel}
	go c.pump(resp.Body)
	t.Cleanup(func() {
		cancel()
		resp.Body.Close()
	})
	return c
}

// pump delivers the lines of the stream to c.lines until the body ends.
func (c *sseClient) pump(body io.Reader) {
	defer close(c.lines)
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		c.lines <- sc.Text()
	}
}

// frame reads one blank-line-terminated frame and returns its lines.
func (c *sseClient) frame(t *testing.T) []string {
	t.Helper()
	var lines []string
	for {
		select {
		case line, ok := <-c.lines:
			if !ok {
				t.Fatalf("stream ended inside a frame (so far %q)", lines)
			}
			if line == "" {
				return lines
			}
			lines = append(lines, line)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for an SSE frame (so far %q)", lines)
		}
	}
}

// event reads the next frame, which must be a named event, and returns its name
// and decoded JSON data.
func (c *sseClient) event(t *testing.T) (string, map[string]any) {
	t.Helper()
	lines := c.frame(t)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
		t.Fatalf("not an event/data frame: %q", lines)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &data); err != nil {
		t.Fatalf("event data is not JSON: %v: %q", err, lines[1])
	}
	return strings.TrimPrefix(lines[0], "event: "), data
}

// newHTTPTestServer serves s on a real loopback port. Registered before any SSE
// client, its cleanup runs after theirs.
func newHTTPTestServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestEventsStream(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	ts := newHTTPTestServer(t, s)
	c := connectSSE(t, ts)

	if c.resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", c.resp.StatusCode)
	}
	if ct := c.resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := c.resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if got := c.frame(t); len(got) != 1 || !strings.HasPrefix(got[0], ":") {
		t.Fatalf("the first frame must be a comment, got %q", got)
	}
	waitFor(t, 2*time.Second, "the subscriber to register", func() bool { return s.hub.count() == 1 })

	body, ctype := formUpload(t, "file", "watched.bin", sampleBytes(321))
	resp, err := http.Post(ts.URL+"/api/analyze", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	var posted uploadResult
	if err := json.NewDecoder(resp.Body).Decode(&posted); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: status %d, err %v", resp.StatusCode, err)
	}
	resp.Body.Close()

	name, started := c.event(t)
	if name != eventStarted {
		t.Fatalf("first event = %q, want %q", name, eventStarted)
	}
	if started["id"] != posted.ID || started["name"] != "watched.bin" || started["size"] != float64(321) {
		t.Errorf("started payload = %v", started)
	}

	name, completed := c.event(t)
	if name != eventCompleted {
		t.Fatalf("second event = %q, want %q", name, eventCompleted)
	}
	for _, key := range []string{"id", "name", "size", "type", "typeLabel", "risk", "createdAt", "durationMs"} {
		if _, ok := completed[key]; !ok {
			t.Errorf("completed payload lacks %q: %v", key, completed)
		}
	}
	if completed["id"] != posted.ID || completed["type"] != report.TypePE {
		t.Errorf("completed payload = %v", completed)
	}
	if risk, _ := completed["risk"].(map[string]any); risk["score"] != float64(42) || risk["label"] != report.RiskMedium {
		t.Errorf("completed risk = %v", completed["risk"])
	}

	c.cancel() // the client disconnects: the server must forget the subscriber
	waitFor(t, 3*time.Second, "the subscriber to be removed", func() bool { return s.hub.count() == 0 })
}

func TestEventsReportFailures(t *testing.T) {
	boom := errors.New("open /var/secret/path: boom")
	s := newTestServer(t, withAnalyzer(func(context.Context, string, analyze.Options) (*report.Report, error) { return nil, boom }))
	ts := newHTTPTestServer(t, s)
	c := connectSSE(t, ts)
	c.frame(t) // stream open
	waitFor(t, 2*time.Second, "the subscriber to register", func() bool { return s.hub.count() == 1 })

	body, ctype := formUpload(t, "file", "bad.bin", sampleBytes(10))
	resp, err := http.Post(ts.URL+"/api/analyze", ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d", resp.StatusCode)
	}

	if name, _ := c.event(t); name != eventStarted {
		t.Fatalf("first event = %q", name)
	}
	name, failed := c.event(t)
	if name != eventFailed || failed["name"] != "bad.bin" || failed["error"] != "analysis failed" || failed["id"] == "" {
		t.Fatalf("failed event = %q %v", name, failed)
	}
	if strings.Contains(strings.ToLower(failed["error"].(string)), "secret") {
		t.Error("the failure event leaks server internals")
	}
}

func TestEventsKeepAlive(t *testing.T) {
	s := newTestServer(t)
	s.keepAlive = 20 * time.Millisecond
	ts := newHTTPTestServer(t, s)
	c := connectSSE(t, ts)
	c.frame(t) // stream open
	if got := c.frame(t); len(got) != 1 || got[0] != ": keep-alive" {
		t.Fatalf("keep-alive frame = %q", got)
	}
}

func TestEventsReachEverySubscriber(t *testing.T) {
	s := newTestServer(t, withAnalyzer(echoAnalyzer))
	ts := newHTTPTestServer(t, s)
	clients := []*sseClient{connectSSE(t, ts), connectSSE(t, ts), connectSSE(t, ts)}
	for _, c := range clients {
		c.frame(t)
	}
	waitFor(t, 2*time.Second, "all subscribers", func() bool { return s.hub.count() == 3 })
	mustUpload(t, s.Handler(), "multi.bin", sampleBytes(10))
	for i, c := range clients {
		if name, _ := c.event(t); name != eventStarted {
			t.Errorf("client %d: first event %q", i, name)
		}
		if name, _ := c.event(t); name != eventCompleted {
			t.Errorf("client %d: second event %q", i, name)
		}
	}
}

func TestEventsRefuseTooManyStreams(t *testing.T) {
	s := newTestServer(t)
	s.hub = newHub(1)
	ts := newHTTPTestServer(t, s)
	connectSSE(t, ts).frame(t)
	waitFor(t, 2*time.Second, "the subscriber to register", func() bool { return s.hub.count() == 1 })

	resp, err := http.Get(ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second stream: status %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	var env errorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil || env.Error.Code != codeBusy {
		t.Fatalf("envelope = %+v (%v)", env, err)
	}
}

func TestEventsHeadReturnsImmediately(t *testing.T) {
	s := newTestServer(t)
	ts := newHTTPTestServer(t, s)
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodHead, ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD /api/events must not stream: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("HEAD = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if n := s.hub.count(); n != 0 {
		t.Errorf("a HEAD request left %d subscribers behind", n)
	}
}

func TestEventsEndWhenServerCloses(t *testing.T) {
	s := newTestServer(t)
	ts := newHTTPTestServer(t, s)
	c := connectSSE(t, ts)
	c.frame(t)
	waitFor(t, 2*time.Second, "the subscriber to register", func() bool { return s.hub.count() == 1 })

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-c.lines:
		if ok {
			t.Fatal("unexpected data after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event stream stayed open after Close")
	}
	// New subscribers are refused once closed.
	rec := do(t, s.Handler(), http.MethodGet, "/api/events", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("events after Close = %d", rec.Code)
	}
}
