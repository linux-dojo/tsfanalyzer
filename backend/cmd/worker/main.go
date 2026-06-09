package main

import (
	"log"
	"time"
)

// Phase 1 placeholder. Phase 3 replaces this with an asynq consumer that
// extracts .tgz archives and runs the regex parser pipeline.
func main() {
	log.Println("worker started (phase 1 stub) — waiting for parse jobs")
	for {
		time.Sleep(30 * time.Second)
	}
}
