// Package store defines the file registry. Phase 1 ships an in-memory
// implementation; phase 2 adds a Postgres/TimescaleDB implementation
// behind the same interface.
package store

import (
	"errors"
	"sort"
	"sync"
	"time"

	"pan-ts-analyzer/internal/parser"
)

var ErrNotFound = errors.New("file not found")

type TechSupportFile struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	SizeBytes  int64     `json:"size_bytes"`
	Status     string    `json:"status"` // uploaded | parsing | parsed | failed
	Error      string    `json:"error,omitempty"` // why parsing failed
	UploadedAt time.Time `json:"uploaded_at"`
	StoragePath string   `json:"-"`
}

type Store interface {
	Create(f TechSupportFile) error
	List() ([]TechSupportFile, error)
	Get(id string) (TechSupportFile, error)
	Delete(id string) error
	SetStatus(id, status, errMsg string) error
	SaveSystemInfo(fileID string, info []parser.KV) error
	SystemInfo(fileID string) ([]parser.KV, error)
	SaveArchiveIndex(fileID string, entries []parser.ArchiveEntry) error
	ArchiveIndex(fileID string) ([]parser.ArchiveEntry, error)
	SaveConfig(fileID string, cfg *parser.ConfigDoc) error
	Config(fileID string) (*parser.ConfigDoc, error)
	SaveAnomalies(fileID string, groups []parser.AnomalyGroup) error
	Anomalies(fileID string) ([]parser.AnomalyGroup, error)
	SaveAppStats(fileID string, st *parser.AppStats) error
	AppStats(fileID string) (*parser.AppStats, error)
	SaveLicenses(fileID string, lics []parser.License) error
	Licenses(fileID string) ([]parser.License, error)
	SaveMemory(fileID string, m MemoryReport) error
	MemoryFor(fileID string) (MemoryReport, error)
	SaveCounters(fileID string, series parser.Series) error
	CounterNames(fileID string) ([]CounterMeta, error)
	CounterSeries(fileID string, names []string, from, to time.Time) (map[string][]parser.Point, error)
}

// MemoryReport is the memory/OOM verdict for a file: one analysis per
// plane, plus config-size findings that apply to the device as a whole.
type MemoryReport struct {
	MP     parser.MemoryAnalysis `json:"mp"`
	DP     parser.MemoryAnalysis `json:"dp"`
	Config []parser.Finding      `json:"config"`
}

// CounterMeta describes one available counter series, including its value
// range so the UI can filter counters by value (e.g. "v > 10000").
type CounterMeta struct {
	Name   string  `json:"name"`
	Points int     `json:"points"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type Memory struct {
	mu        sync.RWMutex
	files     map[string]TechSupportFile
	sysinfo   map[string][]parser.KV
	archive   map[string][]parser.ArchiveEntry
	config    map[string]*parser.ConfigDoc
	anomalies map[string][]parser.AnomalyGroup
	appstats  map[string]*parser.AppStats
	licenses  map[string][]parser.License
	memory    map[string]MemoryReport
	counters  map[string]parser.Series
}

func NewMemory() *Memory {
	return &Memory{
		files:     make(map[string]TechSupportFile),
		sysinfo:   make(map[string][]parser.KV),
		archive:   make(map[string][]parser.ArchiveEntry),
		config:    make(map[string]*parser.ConfigDoc),
		anomalies: make(map[string][]parser.AnomalyGroup),
		appstats:  make(map[string]*parser.AppStats),
		licenses:  make(map[string][]parser.License),
		memory:    make(map[string]MemoryReport),
		counters:  make(map[string]parser.Series),
	}
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
	delete(m.sysinfo, id) // cascade: extracted data goes with the file
	delete(m.archive, id)
	delete(m.config, id)
	delete(m.anomalies, id)
	delete(m.appstats, id)
	delete(m.licenses, id)
	delete(m.memory, id)
	delete(m.counters, id)
	return nil
}

func (m *Memory) SaveAppStats(fileID string, st *parser.AppStats) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.appstats[fileID] = st
	return nil
}

func (m *Memory) AppStats(fileID string) (*parser.AppStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st, ok := m.appstats[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return st, nil
}

func (m *Memory) SaveLicenses(fileID string, lics []parser.License) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.licenses[fileID] = lics
	return nil
}

func (m *Memory) Licenses(fileID string) ([]parser.License, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lics, ok := m.licenses[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return lics, nil
}

func (m *Memory) SaveMemory(fileID string, rep MemoryReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.memory[fileID] = rep
	return nil
}

func (m *Memory) MemoryFor(fileID string) (MemoryReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rep, ok := m.memory[fileID]
	if !ok {
		return MemoryReport{}, ErrNotFound
	}
	return rep, nil
}

func (m *Memory) SaveAnomalies(fileID string, groups []parser.AnomalyGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.anomalies[fileID] = groups
	return nil
}

func (m *Memory) Anomalies(fileID string) ([]parser.AnomalyGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	groups, ok := m.anomalies[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return groups, nil
}

func (m *Memory) SaveConfig(fileID string, cfg *parser.ConfigDoc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.config[fileID] = cfg
	return nil
}

func (m *Memory) Config(fileID string) (*parser.ConfigDoc, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.config[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return cfg, nil
}

// SaveCounters stores the series exactly as the parser produced it: already
// name-keyed and sorted. Regrouping it here used to hold a second full copy
// of every sample, which on a large archive was hundreds of megabytes.
func (m *Memory) SaveCounters(fileID string, series parser.Series) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.counters[fileID] = series
	return nil
}

func (m *Memory) CounterNames(fileID string) ([]CounterMeta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byName, ok := m.counters[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]CounterMeta, 0, len(byName))
	for name, ss := range byName {
		meta := CounterMeta{Name: name, Points: len(ss)}
		for i, s := range ss {
			if i == 0 || s.Value < meta.Min {
				meta.Min = s.Value
			}
			if i == 0 || s.Value > meta.Max {
				meta.Max = s.Value
			}
		}
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) CounterSeries(fileID string, names []string, from, to time.Time) (map[string][]parser.Point, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byName, ok := m.counters[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	out := make(map[string][]parser.Point, len(names))
	for _, name := range names {
		var sel []parser.Point
		for _, s := range byName[name] {
			if !from.IsZero() && s.Ts.Before(from) {
				continue
			}
			if !to.IsZero() && s.Ts.After(to) {
				continue
			}
			sel = append(sel, s)
		}
		out[name] = sel
	}
	return out, nil
}

func (m *Memory) SaveArchiveIndex(fileID string, entries []parser.ArchiveEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.archive[fileID] = entries
	return nil
}

func (m *Memory) ArchiveIndex(fileID string) ([]parser.ArchiveEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries, ok := m.archive[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return entries, nil
}

func (m *Memory) SetStatus(id, status, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[id]
	if !ok {
		return ErrNotFound
	}
	f.Status = status
	f.Error = errMsg
	m.files[id] = f
	return nil
}

func (m *Memory) SaveSystemInfo(fileID string, info []parser.KV) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[fileID]; !ok {
		return ErrNotFound
	}
	m.sysinfo[fileID] = info
	return nil
}

func (m *Memory) SystemInfo(fileID string) ([]parser.KV, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.sysinfo[fileID]
	if !ok {
		return nil, ErrNotFound
	}
	return info, nil
}
