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
	"strings"
	"time"

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
		httpError(w, http.StatusInternalServerError, "could not store file")
		return
	}
	defer out.Close()

	size, err := io.Copy(out, file)
	if err != nil {
		os.Remove(dst)
		httpError(w, http.StatusInternalServerError, "could not store file")
		return
	}

	rec := store.TechSupportFile{
		ID:          id,
		Filename:    filepath.Base(header.Filename),
		SizeBytes:   size,
		Status:      "uploaded",
		UploadedAt:  time.Now().UTC(),
		StoragePath: dst,
	}
	if err := s.store.Create(rec); err != nil {
		httpError(w, http.StatusInternalServerError, "could not register file")
		return
	}
	log.Printf("uploaded %s (%d bytes) as %s", rec.Filename, size, id)
	writeJSON(w, http.StatusCreated, rec)
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
