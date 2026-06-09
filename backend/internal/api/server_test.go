package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"pan-ts-analyzer/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(store.NewMemory(), t.TempDir())
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestUploadListDelete(t *testing.T) {
	srv := newTestServer(t)

	// upload
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "techsupport.tgz")
	fw.Write([]byte("fake-tgz-content"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var created store.TechSupportFile
	json.Unmarshal(rec.Body.Bytes(), &created)

	// list
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/files", nil))
	var listed struct {
		Files []store.TechSupportFile `json:"files"`
	}
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed.Files) != 1 {
		t.Fatalf("list: got %d files, want 1", len(listed.Files))
	}

	// delete
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/files/"+created.ID, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204", rec.Code)
	}
}

func TestUploadRejectsNonTgz(t *testing.T) {
	srv := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "notes.txt")
	fw.Write([]byte("hello"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got %d, want 415", rec.Code)
	}
}
