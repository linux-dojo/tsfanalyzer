package main

import (
	"log"
	"net/http"
	"os"
	"time"

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

	// http.ListenAndServe applies no timeouts at all, so a client that opens
	// connections and then sends its request headers one byte at a time holds
	// a goroutine and a file descriptor each, indefinitely — slowloris. A few
	// thousand such connections exhaust the process without transferring any
	// meaningful data.
	//
	// ReadHeaderTimeout is the one that closes that hole. ReadTimeout and
	// WriteTimeout are deliberately generous rather than absent, because real
	// requests here are genuinely long: a 512 MiB upload over a slow link, and
	// a search that runs to its own 20-second deadline and then streams a
	// large result.
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           srv,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       30 * time.Minute,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("api listening on :%s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
