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

- [x] Phase 1 — scaffold, CI, stub upload endpoint, frontend shell
- [ ] Phase 2 — upload → MinIO, file registry in Postgres
- [ ] Phase 3 — async extraction + system-info parser (version, serial, licenses)
- [ ] Phase 4 — log viewer + log parsing
- [ ] Phase 5 — counters → TimescaleDB → graphs (ECharts)
- [ ] Phase 6 — config tab, cascade delete, auth/quotas

## Repository layout

```
backend/    Go API + worker (stdlib-only in phase 1; chi/pgx/asynq arrive in phase 2)
frontend/   React + TS (Vite)
.github/    CI pipeline
```
