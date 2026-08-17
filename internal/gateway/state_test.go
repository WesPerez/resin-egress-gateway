package gateway

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStatePersistsAndNeverMovesBackward(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewStateStore(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := store.Current("route"); err != nil || current != 0 {
		t.Fatalf("initial generation = %d err=%v", current, err)
	}
	if next, err := store.Advance("route", 0); err != nil || next != 1 {
		t.Fatalf("next generation = %d err=%v", next, err)
	}
	if err := store.Touch("route", 0); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewStateStore(path, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := reloaded.Current("route"); err != nil || current != 1 {
		t.Fatalf("reloaded generation = %d err=%v", current, err)
	}
}

func TestConcurrentAdvanceAllocatesDistinctGenerations(t *testing.T) {
	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan uint64, 2)
	for range 2 {
		go func() {
			next, advanceErr := store.Advance("route", 0)
			if advanceErr != nil {
				t.Errorf("advance: %v", advanceErr)
			}
			results <- next
		}()
	}
	first, second := <-results, <-results
	if first == second {
		t.Fatalf("concurrent generations collided: %d", first)
	}
}
