package main

import (
	"log"
	"net/http"
	"os"

	"pan-ts-analyzer/internal/api"
	"pan-ts-analyzer/internal/store"
)

func main() {
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8081"
	}
	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "./data/uploads"
	}
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		log.Fatalf("create upload dir: %v", err)
	}

	// Phase 1: in-memory registry. Phase 2 swaps this for Postgres.
	st := store.NewMemory()
	srv := api.NewServer(st, uploadDir)

	log.Printf("api listening on :%s", port)
	if err := http.ListenAndServe(":"+port, srv); err != nil {
		log.Fatal(err)
	}
}
