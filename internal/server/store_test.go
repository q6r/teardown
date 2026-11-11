package server

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func rec(id string) *record {
	r := fakeReport(id+".bin", 1)
	return &record{id: id, report: r, createdAt: time.Unix(0, 0).UTC()}
}

func TestStoreEvictsOldest(t *testing.T) {
	s := newStore(3)
	var evicted []string
	for i := range 5 {
		evicted = append(evicted, s.add(rec(fmt.Sprintf("an_%012d", i)))...)
	}
	if !reflect.DeepEqual(evicted, []string{"an_000000000000", "an_000000000001"}) {
		t.Errorf("evicted = %v", evicted)
	}
	if s.len() != 3 {
		t.Errorf("len = %d", s.len())
	}
	var ids []string
	for _, e := range s.summaries() {
		ids = append(ids, e.ID)
	}
	if !reflect.DeepEqual(ids, []string{"an_000000000004", "an_000000000003", "an_000000000002"}) {
		t.Errorf("summaries (newest first) = %v", ids)
	}
	if _, ok := s.get("an_000000000000"); ok {
		t.Error("evicted entry is still retrievable")
	}
}

func TestStoreRemove(t *testing.T) {
	s := newStore(5)
	for i := range 3 {
		s.add(rec(fmt.Sprintf("an_%012d", i)))
	}
	if !s.remove("an_000000000001") {
		t.Fatal("remove of an existing entry must report true")
	}
	if s.remove("an_000000000001") || s.remove("an_ffffffffffff") {
		t.Fatal("remove of a missing entry must report false")
	}
	var ids []string
	for _, e := range s.summaries() {
		ids = append(ids, e.ID)
	}
	if !reflect.DeepEqual(ids, []string{"an_000000000002", "an_000000000000"}) {
		t.Errorf("summaries after remove = %v", ids)
	}
	// A removed entry frees its slot: two more additions evict nothing.
	if ev := s.add(rec("an_00000000000a")); len(ev) != 0 {
		t.Errorf("unexpected eviction %v", ev)
	}
	if ev := s.add(rec("an_00000000000b")); len(ev) != 0 {
		t.Errorf("unexpected eviction %v", ev)
	}
}

func TestStoreEmptySummariesIsNotNil(t *testing.T) {
	if got := newStore(2).summaries(); got == nil || len(got) != 0 {
		t.Fatalf("summaries of an empty store = %#v, want a non-nil empty slice", got)
	}
}

func TestStoreConcurrentUse(t *testing.T) {
	s := newStore(10)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				id, err := s.reserve()
				if err != nil {
					t.Error(err)
					return
				}
				s.add(rec(id))
				s.get(id)
				s.summaries()
				if j%3 == 0 {
					s.remove(id)
				}
				_ = i
			}
		}()
	}
	wg.Wait()
	if n := s.len(); n > 10 {
		t.Errorf("store holds %d entries, capacity is 10", n)
	}
}

func TestNewIDFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for range 2000 {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if !idPattern.MatchString(id) {
			t.Fatalf("id %q does not match %s", id, idPattern)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q in 2000 draws", id)
		}
		seen[id] = true
	}
}

func TestReserveSkipsIDsInUse(t *testing.T) {
	s := newStore(5)
	id, err := s.reserve()
	if err != nil {
		t.Fatal(err)
	}
	s.add(rec(id))
	next, err := s.reserve()
	if err != nil || next == id {
		t.Fatalf("reserve returned %q (err %v) while %q is in use", next, err, id)
	}
}
