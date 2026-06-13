package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pan-ts-analyzer/internal/parser"
	"pan-ts-analyzer/internal/store"
)

// buildTechSupportTgz builds a minimal valid tech-support archive.
func buildTechSupportTgz(t *testing.T) []byte {
	t.Helper()
	content := " > show system info\n\nhostname: PA-TEST\nserial: 007\nsw-version: 10.2.4\nuptime: 1 day\ndevice-certificate-status: None\n"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "tmp/cli/techsupport.txt", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(content))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

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
	fw.Write(buildTechSupportTgz(t))
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
	if created.Status != "parsing" {
		t.Fatalf("status = %q, want parsing", created.Status)
	}

	// parsing happens async; wait for it to finish
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec = httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/files/"+created.ID, nil))
		var f store.TechSupportFile
		json.Unmarshal(rec.Body.Bytes(), &f)
		if f.Status == "parsed" {
			break
		}
		if f.Status == "failed" || time.Now().After(deadline) {
			t.Fatalf("file never reached parsed state (status=%q)", f.Status)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// system info extracted on upload
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/files/"+created.ID+"/system-info", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("system-info: got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var si struct {
		Info []parser.KV `json:"info"`
	}
	json.Unmarshal(rec.Body.Bytes(), &si)
	if len(si.Info) != 5 || si.Info[0].Key != "hostname" || si.Info[0].Value != "PA-TEST" {
		t.Fatalf("system-info payload: %+v", si.Info)
	}

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
