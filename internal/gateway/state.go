package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateVersion = 1

type routeState struct {
	Generation uint64    `json:"generation"`
	LastUsed   time.Time `json:"last_used"`
}

type persistedState struct {
	Version int                   `json:"version"`
	Routes  map[string]routeState `json:"routes"`
}

type StateStore struct {
	mu     sync.Mutex
	path   string
	ttl    time.Duration
	routes map[string]routeState
	now    func() time.Time
}

func NewStateStore(path string, ttl time.Duration) (*StateStore, error) {
	store := &StateStore{
		path:   path,
		ttl:    ttl,
		routes: make(map[string]routeState),
		now:    time.Now,
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *StateStore) Current(route string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.pruneLocked(now)
	entry := s.routes[route]
	entry.LastUsed = now
	s.routes[route] = entry
	return entry.Generation, s.saveLocked()
}

func (s *StateStore) Advance(route string, attempted uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.pruneLocked(now)
	entry := s.routes[route]
	if entry.Generation < attempted {
		entry.Generation = attempted
	}
	entry.Generation++
	entry.LastUsed = now
	s.routes[route] = entry
	return entry.Generation, s.saveLocked()
}

func (s *StateStore) Touch(route string, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.pruneLocked(now)
	entry := s.routes[route]
	if entry.Generation < generation {
		entry.Generation = generation
	}
	entry.LastUsed = now
	s.routes[route] = entry
	return s.saveLocked()
}

func (s *StateStore) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read gateway state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode gateway state: %w", err)
	}
	if state.Version != stateVersion {
		return errStateVersion
	}
	if state.Routes != nil {
		s.routes = state.Routes
	}
	s.pruneLocked(s.now().UTC())
	return nil
}

func (s *StateStore) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.ttl)
	for route, entry := range s.routes {
		if !entry.LastUsed.IsZero() && entry.LastUsed.Before(cutoff) {
			delete(s.routes, route)
		}
	}
}

func (s *StateStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create gateway state directory: %w", err)
	}
	data, err := json.Marshal(persistedState{Version: stateVersion, Routes: s.routes})
	if err != nil {
		return fmt.Errorf("encode gateway state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return fmt.Errorf("create gateway state temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod gateway state temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write gateway state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync gateway state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close gateway state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("replace gateway state: %w", err)
	}
	return nil
}
