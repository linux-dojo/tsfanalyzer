// Package store defines the file registry. Phase 1 ships an in-memory
// implementation; phase 2 adds a Postgres/TimescaleDB implementation
// behind the same interface.
package store

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var ErrNotFound = errors.New("file not found")

type TechSupportFile struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	SizeBytes  int64     `json:"size_bytes"`
	Status     string    `json:"status"` // uploaded | parsing | parsed | failed
	UploadedAt time.Time `json:"uploaded_at"`
	StoragePath string   `json:"-"`
}

type Store interface {
	Create(f TechSupportFile) error
	List() ([]TechSupportFile, error)
	Get(id string) (TechSupportFile, error)
	Delete(id string) error
}

type Memory struct {
	mu    sync.RWMutex
	files map[string]TechSupportFile
}

func NewMemory() *Memory {
	return &Memory{files: make(map[string]TechSupportFile)}
}

func (m *Memory) Create(f TechSupportFile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[f.ID] = f
	return nil
}

func (m *Memory) List() ([]TechSupportFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]TechSupportFile, 0, len(m.files))
	for _, f := range m.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UploadedAt.After(out[j].UploadedAt) })
	return out, nil
}

func (m *Memory) Get(id string) (TechSupportFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.files[id]
	if !ok {
		return TechSupportFile{}, ErrNotFound
	}
	return f, nil
}

func (m *Memory) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[id]; !ok {
		return ErrNotFound
	}
	delete(m.files, id)
	return nil
}
