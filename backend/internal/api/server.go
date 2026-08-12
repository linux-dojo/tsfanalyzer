package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"pan-ts-analyzer/internal/parser"
	"pan-ts-analyzer/internal/store"
)

const maxUploadBytes = 512 << 20 // 512 MiB

type Server struct {
	store     store.Store
	uploadDir string
	mux       *http.ServeMux

	// Parsing one archive peaks at hundreds of megabytes, so archives are
	// parsed one at a time. Uploading several at once previously multiplied
	// that peak and got the container OOM-killed.
	parseSlot chan struct{}

	// Config trees are rebuilt per request rather than retained (see
	// parser.ConfigDoc); this caches the most recent one so clicking around
	// the Config tab doesn't re-parse tens of megabytes each time.
	cfgMu    sync.Mutex
	cfgID    string
	cfgTree  *parser.ConfigNode
}

func NewServer(st store.Store, uploadDir string) *Server {
	s := &Server{
		store:     st,
		uploadDir: uploadDir,
		mux:       http.NewServeMux(),
		parseSlot: make(chan struct{}, 1),
	}
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/files", s.handleUpload)
	s.mux.HandleFunc("GET /api/v1/files", s.handleList)
	s.mux.HandleFunc("GET /api/v1/files/{id}", s.handleGet)
	s.mux.HandleFunc("GET /api/v1/files/{id}/system-info", s.handleSystemInfo)
	s.mux.HandleFunc("GET /api/v1/files/{id}/archive", s.handleArchive)
	s.mux.HandleFunc("GET /api/v1/files/{id}/config", s.handleConfig)
	s.mux.HandleFunc("GET /api/v1/files/{id}/anomalies", s.handleAnomalies)
	s.mux.HandleFunc("GET /api/v1/files/{id}/memory", s.handleMemory)
	s.mux.HandleFunc("GET /api/v1/files/{id}/content", s.handleContent)
	s.mux.HandleFunc("GET /api/v1/files/{id}/search", s.handleSearch)
	s.mux.HandleFunc("GET /api/v1/files/{id}/counters", s.handleCounters)
	s.mux.HandleFunc("GET /api/v1/files/{id}/counters/data", s.handleCounterData)
	s.mux.HandleFunc("DELETE /api/v1/files/{id}", s.handleDelete)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, header, err := r.FormFile("file")
	if err != nil {
		httpError(w, http.StatusBadRequest, "expected multipart field 'file'")
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".tgz") &&
		!strings.HasSuffix(strings.ToLower(header.Filename), ".tar.gz") {
		httpError(w, http.StatusUnsupportedMediaType, "only .tgz / .tar.gz tech-support files are accepted")
		return
	}

	id := newID()
	dst := filepath.Join(s.uploadDir, id+".tgz")
	out, err := os.Create(dst)
	if err != nil {
		log.Printf("upload: create %s: %v", dst, err)
		httpError(w, http.StatusInternalServerError, "could not store file: "+err.Error())
		return
	}
	defer out.Close()

	size, err := io.Copy(out, file)
	if err != nil {
		log.Printf("upload: write %s: %v", dst, err)
		os.Remove(dst)
		httpError(w, http.StatusInternalServerError, "could not store file: "+err.Error())
		return
	}

	rec := store.TechSupportFile{
		ID:          id,
		Filename:    filepath.Base(header.Filename),
		SizeBytes:   size,
		Status:      "parsing",
		UploadedAt:  time.Now().UTC(),
		StoragePath: dst,
	}
	if err := s.store.Create(rec); err != nil {
		httpError(w, http.StatusInternalServerError, "could not register file")
		return
	}
	log.Printf("uploaded %s (%d bytes) as %s", rec.Filename, size, id)

	// Parse in the background; clients poll the list/status endpoints.
	// (Phase 3 moves this into the dedicated worker via the job queue.)
	go s.parseArchive(rec)
	writeJSON(w, http.StatusCreated, rec)
}

// parseArchive runs the extractors over a stored .tgz and returns the new status.
// The archive index is mandatory; system info is best-effort (some archives
// may lack a CLI dump, the file is still browsable).
func (s *Server) parseArchive(rec store.TechSupportFile) string {
	// one archive at a time: peak memory is per-parse, not per-request
	s.parseSlot <- struct{}{}
	defer func() { <-s.parseSlot }()

	status := "parsed"
	errMsg := ""

	// pass 1: index every file in the archive
	f, err := os.Open(rec.StoragePath)
	if err != nil {
		status, errMsg = "failed", "open stored archive: "+err.Error()
	} else {
		idx, ierr := parser.IndexArchive(f)
		f.Close()
		switch {
		case ierr != nil:
			status, errMsg = "failed", "read archive: "+ierr.Error()
		case len(idx) == 0:
			status, errMsg = "failed", "archive contains no files (is this a tech-support .tgz?)"
		default:
			if err := s.store.SaveArchiveIndex(rec.ID, idx); err != nil {
				status, errMsg = "failed", "save index: "+err.Error()
			} else {
				log.Printf("parse %s: indexed %d files", rec.ID, len(idx))
			}
		}
	}

	// pass 2: system info block (best-effort — file stays browsable without it)
	if status == "parsed" {
		f2, err := os.Open(rec.StoragePath)
		if err == nil {
			if info, perr := parser.ExtractSystemInfo(f2); perr == nil {
				_ = s.store.SaveSystemInfo(rec.ID, info)
				log.Printf("parse %s: system info extracted (%d fields)", rec.ID, len(info))
			} else {
				log.Printf("parse %s: system info: %v", rec.ID, perr)
			}
			f2.Close()
		}
	}

	// pass 3: counter time series from dp-monitor / mp-monitor logs
	var samples parser.Series
	if status == "parsed" {
		f3, err := os.Open(rec.StoragePath)
		if err == nil {
			if got, cerr := parser.CollectAllCounters(f3); cerr == nil && len(got) > 0 {
				samples = got
				_ = s.store.SaveCounters(rec.ID, got)
				log.Printf("parse %s: collected %d counter samples", rec.ID, len(got))
			} else if cerr != nil {
				log.Printf("parse %s: counters: %v", rec.ID, cerr)
			}
			f3.Close()
		}
	}

	// pass 4: PAN-OS running config (best-effort — powers the Config tab)
	if status == "parsed" {
		f4, err := os.Open(rec.StoragePath)
		if err == nil {
			if doc, cerr := parser.ExtractConfig(f4); cerr == nil {
				_ = s.store.SaveConfig(rec.ID, doc)
				log.Printf("parse %s: config from %s (%d bytes, panorama=%v, %d candidates)",
					rec.ID, doc.Path, doc.Size, doc.PanoramaManaged, len(doc.Candidates))
			} else {
				log.Printf("parse %s: config: %v", rec.ID, cerr)
			}
			f4.Close()
		}
	}

	// pass 5: anomalies — recurring system-log events plus counter threshold
	// breaches and trends, merged into one list (best-effort)
	if status == "parsed" {
		var groups []parser.AnomalyGroup
		f5, err := os.Open(rec.StoragePath)
		if err == nil {
			if logGroups, aerr := parser.ExtractAnomalies(f5); aerr == nil {
				groups = append(groups, logGroups...)
			} else {
				log.Printf("parse %s: log anomalies: %v", rec.ID, aerr)
			}
			f5.Close()
		}
		fromCounters := parser.CounterAnomalies(samples)
		groups = append(groups, fromCounters...)
		groups = parser.SortAnomalies(groups)
		if len(groups) > 0 {
			_ = s.store.SaveAnomalies(rec.ID, groups)
		} else {
			// still store the empty result so the tab reports "none found"
			// rather than a 404
			_ = s.store.SaveAnomalies(rec.ID, []parser.AnomalyGroup{})
		}
		log.Printf("parse %s: %d anomaly groups (%d from counters)", rec.ID, len(groups), len(fromCounters))
	}

	// pass 6: OOM detection + memory-leak attribution (best-effort — powers
	// the Graphs > Memory / OOM tab). Needs the counters from pass 3 and the
	// archive index from pass 1, so it runs last.
	if status == "parsed" {
		f6, err := os.Open(rec.StoragePath)
		if err == nil {
			oom, oerr := parser.FindOOMEvents(f6)
			f6.Close()
			if oerr != nil {
				log.Printf("parse %s: oom scan: %v", rec.ID, oerr)
			}
			idx, _ := s.store.ArchiveIndex(rec.ID)
			rep := store.MemoryReport{
				MP:     parser.AnalyzeMemory(samples, oom, "mp"),
				DP:     parser.AnalyzeMemory(samples, oom, "dp"),
				Config: parser.ConfigSizeRisk(idx, samples, "mp"),
			}
			_ = s.store.SaveMemory(rec.ID, rep)
			log.Printf("parse %s: memory analysis (%d OOM events, %d mp suspects)",
				rec.ID, len(oom), len(rep.MP.Suspects))
		}
	}

	if errMsg != "" {
		log.Printf("parse %s FAILED: %s", rec.ID, errMsg)
	}
	_ = s.store.SetStatus(rec.ID, status, errMsg)
	return status
}

func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	entries, err := s.store.ArchiveIndex(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no archive index for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "entries": entries})
}

// parseTimeParam accepts RFC3339 and the HTML datetime-local formats.
func parseTimeParam(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (s *Server) handleContent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.store.Get(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		httpError(w, http.StatusBadRequest, "missing ?path= parameter")
		return
	}
	from, okF := parseTimeParam(r.URL.Query().Get("from"))
	to, okT := parseTimeParam(r.URL.Query().Get("to"))
	if !okF || !okT {
		httpError(w, http.StatusBadRequest, "bad from/to timestamp (use YYYY-MM-DDTHH:MM)")
		return
	}

	src, err := os.Open(rec.StoragePath)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not open stored archive")
		return
	}
	defer src.Close()

	entry, err := parser.EntryReader(src, path)
	if errors.Is(err, parser.ErrEntryNotFound) {
		httpError(w, http.StatusNotFound, "no such file in archive: "+path)
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not read archive")
		return
	}

	// structured mode: timestamp + label + message JSON entries, paged so
	// huge logs don't produce huge responses
	if r.URL.Query().Get("format") == "structured" {
		const pageLimit = 50000
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		entries, total := parser.StructureLogPage(entry, from, to, offset, pageLimit)
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": entries, "total": total, "offset": offset, "limit": pageLimit,
		})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if from.IsZero() && to.IsZero() {
		_, _ = io.Copy(w, entry)
		return
	}
	if err := parser.FilterLines(entry, w, from, to); err != nil {
		log.Printf("filter %s %s: %v", id, path, err)
	}
}

func (s *Server) handleCounters(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	metas, err := s.store.CounterNames(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no counters for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "counters": metas})
}

func (s *Server) handleCounterData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	names := strings.Split(r.URL.Query().Get("names"), "|")
	clean := names[:0]
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		httpError(w, http.StatusBadRequest, "missing ?names= parameter (| separated)")
		return
	}
	// generous: the UI no longer caps how many counters may be plotted, and
	// batches its requests, so this only guards against absurd URLs
	if len(clean) > 200 {
		httpError(w, http.StatusBadRequest, "at most 200 counters per request")
		return
	}
	from, okF := parseTimeParam(r.URL.Query().Get("from"))
	to, okT := parseTimeParam(r.URL.Query().Get("to"))
	if !okF || !okT {
		httpError(w, http.StatusBadRequest, "bad from/to timestamp (use YYYY-MM-DDTHH:MM)")
		return
	}
	series, err := s.store.CounterSeries(id, clean, from, to)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no counters for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "series": series})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.store.Get(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		httpError(w, http.StatusBadRequest, "query must be at least 2 characters")
		return
	}
	src, err := os.Open(rec.StoragePath)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not open stored archive")
		return
	}
	defer src.Close()

	results, err := parser.SearchArchive(src, q, 200)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "search failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": results})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	doc, err := s.store.Config(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no config extracted for this file")
		return
	}
	rec, rerr := s.store.Get(id)
	if rerr != nil {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}

	tree, terr := s.configTree(id, rec.StoragePath, doc.Path)
	if terr != nil {
		log.Printf("config %s: parse %s: %v", id, doc.Path, terr)
		httpError(w, http.StatusInternalServerError, "could not parse "+doc.Path)
		return
	}

	// copy the metadata and attach the freshly parsed tree for this response
	out := *doc
	out.Root = tree
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "config": out})
}

// configTree parses the config for a file, caching the most recent one. The
// tree is not kept in the store: one Panorama merged config per uploaded file
// was enough to exhaust the container.
func (s *Server) configTree(id, storagePath, cfgPath string) (*parser.ConfigNode, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfgID == id && s.cfgTree != nil {
		return s.cfgTree, nil
	}
	f, err := os.Open(storagePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tree, err := parser.ParseConfigTree(f, cfgPath)
	if err != nil {
		return nil, err
	}
	// hold only one at a time
	s.cfgID, s.cfgTree = id, tree
	return tree, nil
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	groups, err := s.store.Anomalies(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no anomalies extracted for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "anomalies": groups})
}

func (s *Server) handleMemory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rep, err := s.store.MemoryFor(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no memory analysis for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "memory": rep})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, err := s.store.SystemInfo(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no system info for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "info": info})
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	files, err := s.store.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not list files")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.Get(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := s.store.Get(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	// Delete blob first, then registry entry (phase 2: also cascade-delete parsed data).
	if f.StoragePath != "" {
		os.Remove(f.StoragePath)
	}
	if err := s.store.Delete(id); err != nil {
		httpError(w, http.StatusInternalServerError, "could not delete file")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
