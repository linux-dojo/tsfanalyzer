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
	"time"

	"pan-ts-analyzer/internal/parser"
	"pan-ts-analyzer/internal/store"
)

const maxUploadBytes = 512 << 20 // 512 MiB

type Server struct {
	store     store.Store
	uploadDir string
	mux       *http.ServeMux
}

func NewServer(st store.Store, uploadDir string) *Server {
	s := &Server{store: st, uploadDir: uploadDir, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/files", s.handleUpload)
	s.mux.HandleFunc("GET /api/v1/files", s.handleList)
	s.mux.HandleFunc("GET /api/v1/files/{id}", s.handleGet)
	s.mux.HandleFunc("GET /api/v1/files/{id}/system-info", s.handleSystemInfo)
	s.mux.HandleFunc("GET /api/v1/files/{id}/archive", s.handleArchive)
	s.mux.HandleFunc("GET /api/v1/files/{id}/config", s.handleConfig)
	s.mux.HandleFunc("GET /api/v1/files/{id}/anomalies", s.handleAnomalies)
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
	if status == "parsed" {
		f3, err := os.Open(rec.StoragePath)
		if err == nil {
			if samples, cerr := parser.CollectAllCounters(f3); cerr == nil && len(samples) > 0 {
				_ = s.store.SaveCounters(rec.ID, samples)
				log.Printf("parse %s: collected %d counter samples", rec.ID, len(samples))
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
			if cfg, cerr := parser.ExtractConfig(f4); cerr == nil {
				_ = s.store.SaveConfig(rec.ID, cfg)
				log.Printf("parse %s: config extracted (root <%s>, %d top-level children)", rec.ID, cfg.Tag, len(cfg.Children))
			} else {
				log.Printf("parse %s: config: %v", rec.ID, cerr)
			}
			f4.Close()
		}
	}

	// pass 5: system log anomalies (best-effort — powers the Graphs > Anomalies tab)
	if status == "parsed" {
		f5, err := os.Open(rec.StoragePath)
		if err == nil {
			if groups, aerr := parser.ExtractAnomalies(f5); aerr == nil {
				_ = s.store.SaveAnomalies(rec.ID, groups)
				log.Printf("parse %s: %d recurring anomaly groups extracted", rec.ID, len(groups))
			} else {
				log.Printf("parse %s: anomalies: %v", rec.ID, aerr)
			}
			f5.Close()
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
	if len(clean) > 12 {
		httpError(w, http.StatusBadRequest, "at most 12 counters per request")
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
	cfg, err := s.store.Config(id)
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, "no config extracted for this file")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_id": id, "config": cfg})
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
