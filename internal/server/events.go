package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// maxSubscribers bounds the simultaneously open event streams.
	maxSubscribers = 64
	// subscriberBuffer is how many events may queue for one SSE client before it
	// is considered too slow and dropped.
	subscriberBuffer = 32
	// keepAliveEvery is the interval of SSE comment frames that keep proxies and
	// idle-timeouts from closing a quiet stream.
	keepAliveEvery = 15 * time.Second
	// eventWriteTimeout bounds one SSE write so a client that stopped reading
	// cannot pin a goroutine.
	eventWriteTimeout = 10 * time.Second
)

// Event names published on GET /api/events.
const (
	eventStarted   = "analysis.started"
	eventCompleted = "analysis.completed"
	eventFailed    = "analysis.failed"
)

type startedEvent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type completedEvent struct {
	summary
	DurationMs int64 `json:"durationMs"`
}

type failedEvent struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Error string `json:"error"`
}

// sseEvent is one pre-encoded server-sent event.
type sseEvent struct {
	name string
	data []byte
}

// subscriber is one connected SSE client.
type subscriber struct {
	ch     chan sseEvent
	closed bool // guarded by hub.mu
}

// Reasons a subscription is refused.
var (
	errHubClosed = errors.New("the server is shutting down")
	errHubFull   = errors.New("too many event streams are open; close one and retry")
)

// hub fans events out to SSE subscribers. A subscriber that cannot keep up is
// dropped; publishing never blocks and never affects other subscribers.
type hub struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	limit  int
	closed bool
}

// newHub returns a hub that accepts at most limit simultaneous subscribers.
func newHub(limit int) *hub {
	return &hub{subs: make(map[*subscriber]struct{}), limit: limit}
}

// subscribe registers a new subscriber. It fails once the hub is closed or when
// the subscriber limit is reached.
func (h *hub) subscribe() (*subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return nil, errHubClosed
	case len(h.subs) >= h.limit:
		return nil, errHubFull
	}
	sub := &subscriber{ch: make(chan sseEvent, subscriberBuffer)}
	h.subs[sub] = struct{}{}
	return sub, nil
}

// unsubscribe removes sub and closes its channel (once).
func (h *hub) unsubscribe(sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(sub)
}

func (h *hub) dropLocked(sub *subscriber) {
	delete(h.subs, sub)
	if !sub.closed {
		sub.closed = true
		close(sub.ch)
	}
}

// publish encodes payload once and offers it to every subscriber without blocking.
func (h *hub) publish(name string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ev := sseEvent{name: name, data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		select {
		case sub.ch <- ev:
		default:
			h.dropLocked(sub)
		}
	}
}

// close drops every subscriber and refuses new ones.
func (h *hub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for sub := range h.subs {
		h.dropLocked(sub)
	}
}

// count returns the number of connected subscribers.
func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// handleEvents streams analysis events as text/event-stream.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		return
	}
	rc := http.NewResponseController(w)
	sub, err := s.hub.subscribe()
	if err != nil {
		if errors.Is(err, errHubFull) {
			w.Header().Set("Retry-After", retryAfter)
		}
		writeError(w, http.StatusServiceUnavailable, codeBusy, err.Error())
		return
	}
	defer s.hub.unsubscribe(sub)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := sendFrame(w, rc, ": stream open\n\n"); err != nil {
		return
	}

	ticker := time.NewTicker(s.keepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case ev, ok := <-sub.ch:
			if !ok {
				return
			}
			if err := sendFrame(w, rc, fmt.Sprintf("event: %s\ndata: %s\n\n", ev.name, ev.data)); err != nil {
				return
			}
		case <-ticker.C:
			if err := sendFrame(w, rc, ": keep-alive\n\n"); err != nil {
				return
			}
		}
	}
}

// sendFrame writes one SSE frame and flushes it, under a fresh write deadline.
func sendFrame(w http.ResponseWriter, rc *http.ResponseController, frame string) error {
	_ = rc.SetWriteDeadline(time.Now().Add(eventWriteTimeout))
	if _, err := fmt.Fprint(w, frame); err != nil {
		return err
	}
	return rc.Flush()
}
