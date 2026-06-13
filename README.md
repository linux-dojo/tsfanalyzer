# PAN TechSupport Analyzer

Browser-based tool to upload, parse, and analyze Palo Alto Networks firewall tech-support files (`.tgz`).

## Architecture

```
browser ── nginx ──► api (Go) ──► postgres + timescaledb   (metadata, parsed values, counter time-series)
                       │     ──► minio                     (raw .tgz blobs)
                       └────────► redis ──► worker (Go)    (async extraction + regex parsers)
```

- **api** — Go HTTP API: uploads, file registry, parsed-data queries, graph data
- **worker** — Go: extracts `.tgz`, runs pluggable regex parsers, writes results to DB
- **postgres (TimescaleDB)** — file metadata, system info, logs index, counter hypertables
- **minio** — S3-compatible object storage for raw uploads
- **redis** — job queue (asynq)
- **frontend** — React + TypeScript (Vite), tabs: System Info · Logs · Graphs · Config · My Files

> **Current state (vs. target above).** The diagram is the target. As built today,
> the **api** is the only backend process doing real work: it stores raw `.tgz` files
> on a **local disk volume** (not MinIO), keeps the file registry and all parsed data
> in an **in-memory store** (not Postgres/TimescaleDB), and runs the parsers **inline
> in a goroutine** right after upload (not via Redis/asynq in the **worker**, which is
> still a stub). The store sits behind a `store.Store` interface so a Postgres-backed
> implementation can drop in without touching the API or parsers. The Go backend is
> currently **stdlib-only** (empty `go.mod` dependencies).

## Quickstart (dev)

```bash
cp .env.example .env
docker compose up --build
# frontend: http://localhost:8080   api: http://localhost:8081/healthz
```

Without Docker:

```bash
cd backend && go run ./cmd/api      # api on :8081
cd frontend && npm install && npm run dev
```

## Roadmap

Legend: `[x]` done · `[~]` partial (works in-memory; production backing store still pending) · `[ ]` not started

- [x] Phase 1 — scaffold, CI, stub upload endpoint, frontend shell
- [~] Phase 2 — file registry + upload storage
  - [x] file registry behind `store.Store` interface, upload/list/get/delete API
  - [ ] back the registry with Postgres and move raw blobs to MinIO (today: in-memory + local disk)
- [~] Phase 3 — extraction + system-info parser
  - [x] archive indexer, `show system info` extractor (version, serial, licenses, …)
  - [ ] move extraction into the **worker** via Redis/asynq (today: inline goroutine in the api)
- [x] Phase 4 — log viewer + log parsing (archive browser, search, monitor-log structurer, time-range filter, virtualized viewer)
- [~] Phase 5 — counters → graphs
  - [x] counter parsers (global/per-task/CPU/cache/ifconfig/memory/logrcvr/netstat) and ECharts plotting
  - [ ] persist counters to a TimescaleDB hypertable (today: in-memory series)
- [ ] Phase 6 — config tab, cascade delete, auth/quotas

## Repository layout

```
backend/    Go API (active) + worker (stub). Currently stdlib-only;
            pgx/asynq/minio land when Phases 2–3 move off the in-memory store.
frontend/   React + TS (Vite)
.github/    CI pipeline
```
