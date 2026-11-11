package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/q6r/teardown/internal/report"
)

// idPattern matches every identifier newID can produce.
var idPattern = regexp.MustCompile(`^an_[0-9a-f]{12}$`)

// newID returns "an_" followed by 12 lowercase hex characters from crypto/rand.
func newID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate analysis id: %w", err)
	}
	return "an_" + hex.EncodeToString(b[:]), nil
}

// riskBrief is the compact risk shown in listings and events.
type riskBrief struct {
	Score int    `json:"score"`
	Label string `json:"label"`
}

// summary is one entry of GET /api/analyses and the base of the completed event.
type summary struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Type      string    `json:"type"`
	TypeLabel string    `json:"typeLabel"`
	Risk      riskBrief `json:"risk"`
	CreatedAt time.Time `json:"createdAt"`
}

// record is a stored analysis. The report is immutable once stored.
type record struct {
	id        string
	report    *report.Report
	createdAt time.Time
}

func (r *record) summary() summary {
	return summary{
		ID:        r.id,
		Name:      r.report.File.Name,
		Size:      r.report.File.Size,
		Type:      r.report.Type.ID,
		TypeLabel: r.report.Type.Label,
		Risk:      riskBrief{Score: r.report.Risk.Score, Label: r.report.Risk.Label},
		CreatedAt: r.createdAt,
	}
}

// store is a bounded in-memory ring of analyses: adding beyond capacity evicts
// the oldest entry.
type store struct {
	mu    sync.RWMutex
	keep  int
	items map[string]*record
	order []string // oldest first
}

func newStore(keep int) *store {
	return &store{keep: keep, items: make(map[string]*record, keep)}
}

// reserve returns a fresh identifier that is not in use.
func (s *store) reserve() (string, error) {
	for range 8 {
		id, err := newID()
		if err != nil {
			return "", err
		}
		s.mu.RLock()
		_, taken := s.items[id]
		s.mu.RUnlock()
		if !taken {
			return id, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique analysis id")
}

// add stores rec and returns the ids that were evicted to make room.
func (s *store) add(rec *record) (evicted []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[rec.id] = rec
	s.order = append(s.order, rec.id)
	for len(s.order) > s.keep {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
		evicted = append(evicted, oldest)
	}
	return evicted
}

func (s *store) get(id string) (*record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.items[id]
	return rec, ok
}

func (s *store) remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false
	}
	delete(s.items, id)
	if i := slices.Index(s.order, id); i >= 0 {
		s.order = slices.Delete(s.order, i, i+1)
	}
	return true
}

// summaries returns the stored analyses, newest first; never nil.
func (s *store) summaries() []summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]summary, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		out = append(out, s.items[s.order[i]].summary())
	}
	return out
}

func (s *store) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}
